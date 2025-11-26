mod engine;
mod proxy;

use pingora::server::Server;
use pingora::proxy::http_proxy_service;
use std::sync::Arc;
use dashmap::DashMap;
use env_logger;
use log::info;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    info!("Starting Advanced WAF...");

    let mut server = Server::new(None).unwrap();
    server.bootstrap();

    let bridge = Arc::new(engine::PythonWafBridge::new());
    let rate_limiter = Arc::new(DashMap::new());

    let waf_logic = proxy::WafProxy { 
        bridge, 
        rate_limiter 
    };
    
    let mut service = http_proxy_service(&server.configuration, waf_logic);
    service.add_tcp("0.0.0.0:6188");

    info!("WAF Listening on port 6188");
    server.add_service(service);
    server.run_forever();
}
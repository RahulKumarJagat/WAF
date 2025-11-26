use async_trait::async_trait;
use pingora::prelude::*;
use pingora::protocols::l4::socket::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use dashmap::DashMap;
use crate::engine::PythonWafBridge;
use log::{info, warn};
use serde_json::json;
use regex::Regex;
use std::sync::LazyLock;


static STATIC_ASSETS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\.(jpg|jpeg|png|gif|css|js|ico|woff|ttf|svg)$").unwrap()
});

static SQLI_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(union\s+select|select\s+.*\s+from|drop\s+table)").unwrap()
});

pub struct WafProxy {
    pub bridge: Arc<PythonWafBridge>,
    
    pub rate_limiter: Arc<DashMap<String, (Instant, u32)>>,
}

impl WafProxy {
    
    fn check_rate_limit(&self, client_ip: &str) -> bool {
        const MAX_REQUESTS: u32 = 100; 
        const WINDOW: Duration = Duration::from_secs(60);

        let mut entry = self.rate_limiter.entry(client_ip.to_string()).or_insert((Instant::now(), 0));
        let (last_time, count) = entry.value_mut();

        if last_time.elapsed() > WINDOW {
            *last_time = Instant::now();
            *count = 1;
            false
        } else {
            *count += 1;
            *count > MAX_REQUESTS
        }
    }
}

#[async_trait]
impl ProxyHttp for WafProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {
        ()
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        
        let client_ip = match session.client_addr() {
            Some(SocketAddr::Inet(addr)) => addr.ip().to_string(),
            _ => "unknown".to_string(),
        };
        
        if self.check_rate_limit(&client_ip) {
            let log = json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "action": "BLOCK_DDOS",
                "client_ip": client_ip,
                "reason": "Rate Limit Exceeded"
            });
            warn!("{}", log.to_string());
            let _ = session.respond_error(429).await;
            return Ok(true); 
        }

        let req_header = session.req_header();
        let method = req_header.method.as_str();
        let uri = req_header.uri.path_and_query()
            .map(|x| x.as_str())
            .unwrap_or(req_header.uri.path());

        
        if STATIC_ASSETS.is_match(uri) {
            return Ok(false);
        }

        
        if SQLI_PATTERN.is_match(uri) {
            let log = json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "action": "BLOCK_SQLI_REGEX",
                "client_ip": client_ip,
                "uri": uri,
                "reason": "Signature Match"
            });
            warn!("{}", log.to_string());
            let _ = session.respond_error(403).await;
            return Ok(true);
        }

        
        let ua = req_header.headers.get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();

        if ua.contains("python-requests") || ua.contains("nessus") || ua.contains("nmap") || ua.contains("nikto") {
            let log = json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "action": "BLOCK_BOT",
                "client_ip": client_ip,
                "user_agent": ua,
                "reason": "Suspicious User Agent"
            });
            warn!("{}", log.to_string());
            let _ = session.respond_error(403).await;
            return Ok(true);
        }

        
        let headers_json = json!({ "user-agent": ua }).to_string();
        let body_preview = ""; 

        
        let risk_score = self.bridge.analyze(method, uri, &headers_json, body_preview);

        
        let log_entry = json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "client_ip": client_ip,
            "method": method,
            "uri": uri,
            "ai_risk_score": risk_score,
            "action": if risk_score > 0.85 { "BLOCK_AI" } else { "ALLOW" }
        });

        if risk_score > 0.85 {
            warn!("{}", log_entry.to_string());
            let _ = session.respond_error(403).await; 
            return Ok(true); 
        }

        info!("{}", log_entry.to_string());
        Ok(false) 
    }

    async fn upstream_peer(&self, _session: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        
        let addr = ("142.250.193.206", 443); 
        let mut peer = Box::new(HttpPeer::new(addr, true, "google.com".to_string()));
        peer.sni = "google.com".to_string(); 
        Ok(peer)
    }
}

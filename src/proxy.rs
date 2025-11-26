use async_trait::async_trait;
use pingora::prelude::*;
use std::sync::Arc;
use std::time::{Duration, Instant};
use dashmap::DashMap;
use crate::engine::PythonWafBridge;
use log::{info, warn};
use serde_json::json;
use chrono;

pub struct WafProxy {
    pub bridge: Arc<PythonWafBridge>,
    // IP -> (Last Request Time, Request Count)
    pub rate_limiter: Arc<DashMap<String, (Instant, u32)>>,
}

impl WafProxy {
    // DDoS Logic
    fn check_rate_limit(&self, client_ip: &str) -> bool {
        // ALLOW: 60 requests per minute
        const MAX_REQUESTS: u32 = 60;
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
        let req_header = session.req_header();
        
        // --- LAYER 1: DDoS PROTECTION ---
        // In real prod, use session.client_addr() logic. For dev, we simulate localhost.
        let client_ip = "127.0.0.1"; 
        
        if self.check_rate_limit(client_ip) {
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

        // --- LAYER 2: ANTI-BOT ---
        let ua = req_header.headers.get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();

        if ua.contains("python-requests") || ua.contains("wget") || ua.contains("scrapy") {
            let log = json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "action": "BLOCK_BOT",
                "user_agent": ua,
                "reason": "Suspicious User Agent"
            });
            warn!("{}", log.to_string());
            let _ = session.respond_error(403).await;
            return Ok(true);
        }

        // --- LAYER 3: AI BRAIN ---
        let method = req_header.method.as_str();
        let uri = req_header.uri.path_and_query()
            .map(|x| x.as_str())
            .unwrap_or(req_header.uri.path());

        let headers_json = json!({ "user-agent": ua }).to_string();
        let body_preview = ""; // In Phase 2, buffer body here

        // Analyze
        let risk_score = self.bridge.analyze(method, uri, &headers_json, body_preview);

        // Structured Log Entry
        let log_entry = json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "client_ip": client_ip,
            "method": method,
            "uri": uri,
            "risk_score": risk_score,
            "action": if risk_score > 0.0 { "BLOCK_AI" } else { "ALLOW" }
        });

        if risk_score > 0.0 {
            warn!("{}", log_entry.to_string());
            let _ = session.respond_error(403).await; 
            return Ok(true); 
        }

        info!("{}", log_entry.to_string());
        Ok(false) 
    }

    async fn upstream_peer(&self, _session: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        // Forward to Google for testing connectivity
        let addr = ("142.250.193.206", 80); 
        let mut peer = Box::new(HttpPeer::new(addr, false, "google.com".to_string()));
        peer.sni = "google.com".to_string(); 
        Ok(peer)
    }
}
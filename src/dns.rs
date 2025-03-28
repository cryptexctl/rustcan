use anyhow::{Result, Context};
use std::net::IpAddr;
use tokio::net::lookup_host;

pub async fn resolve_domain(domain: &str) -> Result<Vec<IpAddr>> {
    match lookup_host(domain).await {
        Ok(ips) => {
            let ips: Vec<IpAddr> = ips.map(|s| s.ip()).collect();
            if ips.is_empty() {
                Err(anyhow::anyhow!("No IP addresses found for domain: {}", domain))
            } else {
                Ok(ips)
            }
        }
        Err(e) => Err(anyhow::anyhow!("Failed to resolve domain {}: {}", domain, e))
    }
} 
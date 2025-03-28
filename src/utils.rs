use anyhow::{Result, Context};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use tokio::net::lookup_host;
use crate::types::ScanResult;

pub async fn get_target_ips(target: &str) -> Result<Vec<IpAddr>> {
    // Try to parse as IP address first
    if let Ok(ip) = IpAddr::from_str(target) {
        return Ok(vec![ip]);
    }

    // Try to parse as CIDR
    if target.contains('/') {
        let parts: Vec<&str> = target.split('/').collect();
        if parts.len() == 2 {
            if let Ok(ip) = IpAddr::from_str(parts[0]) {
                if let Ok(prefix) = parts[1].parse::<u8>() {
                    match ip {
                        IpAddr::V4(ipv4) => {
                            if prefix <= 32 {
                                return Ok(get_cidr_ips_v4(ipv4, prefix));
                            }
                        }
                        IpAddr::V6(ipv6) => {
                            if prefix <= 128 {
                                return Ok(get_cidr_ips_v6(ipv6, prefix));
                            }
                        }
                    }
                }
            }
        }
        return Err(anyhow::anyhow!("Invalid CIDR notation: {}", target));
    }

    // If not IP or CIDR, treat as domain name
    match lookup_host(format!("{}:0", target)).await {
        Ok(ips) => {
            let ips: Vec<IpAddr> = ips.map(|s| s.ip()).collect();
            if ips.is_empty() {
                Err(anyhow::anyhow!("No IP addresses found for domain: {}", target))
            } else {
                Ok(ips)
            }
        }
        Err(e) => Err(anyhow::anyhow!("Failed to resolve domain {}: {}", target, e))
    }
}

fn get_cidr_ips_v4(ip: Ipv4Addr, prefix: u8) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    let mask = if prefix == 32 {
        0xFFFFFFFF
    } else {
        !((1u32 << (32 - prefix)) - 1)
    };
    let network = u32::from(ip) & mask;
    let host_count = 1u32 << (32 - prefix);

    for i in 0..host_count {
        let addr = network | i;
        ips.push(IpAddr::V4(Ipv4Addr::from(addr)));
    }

    ips
}

fn get_cidr_ips_v6(ip: Ipv6Addr, prefix: u8) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    let mask = if prefix == 128 {
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    } else {
        !((1u128 << (128 - prefix)) - 1)
    };
    let network = u128::from(ip) & mask;
    let host_count = 1u128 << (128 - prefix);

    for i in 0..host_count {
        let addr = network | i;
        ips.push(IpAddr::V6(Ipv6Addr::from(addr)));
    }

    ips
}

pub fn format_scan_result(result: &ScanResult) -> String {
    let mut output = format!("{}:{}", result.ip, result.port);
    
    if let Some(service) = &result.service {
        output.push_str(&format!("\n  Service: {}", service.name));
        if let Some(version) = &service.version {
            output.push_str(&format!("\n  Version: {}", version));
        }
        if let Some(product) = &service.product {
            output.push_str(&format!("\n  Product: {}", product));
        }
        if let Some(os_type) = &service.os_type {
            output.push_str(&format!("\n  OS Type: {}", os_type));
        }
        if let Some(extra_info) = &service.extra_info {
            output.push_str(&format!("\n  Extra Info: {}", extra_info));
        }
    }
    
    output
} 
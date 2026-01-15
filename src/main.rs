mod scanner;
mod service_detection;
mod utils;
mod types;
mod patterns;

use std::net::IpAddr;
use std::str::FromStr;
use clap::Parser;
use anyhow::Result;
use std::collections::HashMap;
use crate::scanner::Scanner;
use crate::types::ScanResult;
use crate::utils::get_mac_vendor_for_ip;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, required = true)]
    targets: Vec<String>,

    #[arg(short, long, default_value = "1000-2000")]
    ports: String,

    #[arg(short, long, default_value = "1000")]
    concurrency: usize,

    #[arg(short, long, default_value = "1000")]
    timeout: u64,

    #[arg(long)]
    service_detection: bool,
}

fn parse_port_range(ports: &str) -> Result<std::ops::RangeInclusive<u16>> {
    let parts: Vec<&str> = ports.split('-').collect();
    if parts.len() != 2 {
        return Err(anyhow::anyhow!("Invalid port range format"));
    }

    let start = parts[0].parse::<u16>()?;
    let end = parts[1].parse::<u16>()?;

    if start > end {
        return Err(anyhow::anyhow!("Start port must be less than or equal to end port"));
    }

    Ok(start..=end)
}

fn format_scan_result(result: &ScanResult) -> String {
    let mut output = format!("[+] {}:{} is open", result.ip, result.port);
    
    if let Some(service) = &result.service {
        output.push_str(&format!("\n    Service: {}", service.name));
        if let Some(version) = &service.version {
            output.push_str(&format!("\n    Version: {}", version));
        }
        if let Some(product) = &service.product {
            output.push_str(&format!("\n    Product: {}", product));
        }
        if let Some(os_type) = &service.os_type {
            output.push_str(&format!("\n    OS: {}", os_type));
        }
        if let Some(extra_info) = &service.extra_info {
            output.push_str(&format!("\n    Extra Info: {}", extra_info));
        }
    }

    output
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let port_range = parse_port_range(&args.ports)?;

    let scanner = Scanner::new(
        args.targets,
        port_range,
        args.concurrency,
        args.timeout,
        args.service_detection,
    );

    let results = scanner.run().await?;

    if !results.is_empty() {
        let mut mac_cache: HashMap<IpAddr, String> = HashMap::new();
        // Собираем MAC-вендоров по уникальным IP
        for result in &results {
            if mac_cache.contains_key(&result.ip) {
                continue;
            }
            if let Ok(ip) = IpAddr::from_str(&result.ip.to_string()) {
                if let Some(vendor) = get_mac_vendor_for_ip(ip) {
                    mac_cache.insert(ip, vendor);
                }
            }
        }

        println!("\nScan Results:");
        for result in &results {
            println!("{}", format_scan_result(result));
        }

        let mut service_stats: HashMap<String, u32> = HashMap::new();
        for result in &results {
            if let Some(service) = &result.service {
                *service_stats.entry(service.name.clone()).or_insert(0) += 1;
            }
        }

        println!("\nService Statistics:");
        for (service, count) in service_stats {
            println!("  {}: {}", service, count);
        }

        if !mac_cache.is_empty() {
            println!("\nHost MAC Vendors:");
            for (ip, vendor) in mac_cache {
                println!("  {}: {}", ip, vendor);
            }
        }
    } else {
        println!("No open ports found");
    }

    Ok(())
}

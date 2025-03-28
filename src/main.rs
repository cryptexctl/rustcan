mod scanner;
mod service_detection;
mod utils;
mod types;

use anyhow::Result;
use clap::Parser;
use std::sync::Arc;
use tokio::time::Duration;
use crate::scanner::Scanner;
use crate::service_detection::ServiceDetector;
use crate::utils::{get_target_ips, format_scan_result};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Target IP address, CIDR notation or domain name
    #[arg(short, long)]
    target: String,

    /// Port range (e.g. 1-1000)
    #[arg(short, long, default_value = "1-1000")]
    ports: String,

    /// Number of concurrent scans
    #[arg(short, long, default_value = "1000")]
    concurrency: usize,

    /// Enable service detection
    #[arg(short, long)]
    service_detection: bool,

    /// Output format (text or json)
    #[arg(short, long, default_value = "text")]
    output_format: String,

    /// Timeout in milliseconds
    #[arg(short, long, default_value = "1000")]
    timeout: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    // Parse port range
    let (start_port, end_port) = parse_port_range(&args.ports)?;
    
    // Get target IPs
    let target_ips = get_target_ips(&args.target).await?;
    println!("Starting scan on {} targets...", target_ips.len());
    
    // Initialize service detector if needed
    let service_detector = if args.service_detection {
        Some(Arc::new(ServiceDetector::new()))
    } else {
        None
    };

    // Create scanner
    let scanner = Scanner::new(
        target_ips,
        start_port,
        end_port,
        args.concurrency,
        Duration::from_millis(args.timeout),
        service_detector,
        args.output_format.clone(),
    );

    // Run scan
    let results = scanner.run().await?;

    // Print results
    for result in results {
        println!("{}", format_scan_result(&result));
    }

    Ok(())
}

fn parse_port_range(ports: &str) -> Result<(u16, u16)> {
    let parts: Vec<&str> = ports.split('-').collect();
    if parts.len() != 2 {
        return Err(anyhow::anyhow!("Invalid port range format. Use start-end (e.g. 1-1000)"));
    }

    let start = parts[0].parse::<u16>()?;
    let end = parts[1].parse::<u16>()?;

    if start > end || start == 0 || end > 65535 {
        return Err(anyhow::anyhow!("Invalid port range"));
    }

    Ok((start, end))
}

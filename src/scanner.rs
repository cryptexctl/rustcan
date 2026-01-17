use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::ops::RangeInclusive;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use futures::stream::StreamExt;
use anyhow::{Result, anyhow};
use ipnetwork::IpNetwork;
use indicatif::{ProgressBar, ProgressStyle};
use crate::types::ScanResult;
use crate::service_detection::detect_service;
use std::sync::Arc;
use tokio::sync::Semaphore;

const MAX_RETRIES: u32 = 2;
const RETRY_DELAY: u64 = 100;
const CHUNK_SIZE: usize = 1000;
const SUBNET_CHUNK_SIZE: usize = 100;
const MAX_CONCURRENCY: usize = 1000;
const MAX_CIDR_HOSTS: u32 = 65536;

pub struct Scanner {
    targets: Vec<String>,
    port_range: RangeInclusive<u16>,
    concurrency: usize,
    timeout: u64,
    service_detection: bool,
}

impl Scanner {
    pub fn new(
        targets: Vec<String>,
        port_range: RangeInclusive<u16>,
        concurrency: usize,
        timeout: u64,
        service_detection: bool,
    ) -> Self {
        let concurrency = concurrency.min(MAX_CONCURRENCY);
        let timeout = timeout.max(500);

        Self {
            targets,
            port_range,
            concurrency,
            timeout,
            service_detection,
        }
    }

    async fn resolve_target(target: &str) -> Result<Vec<IpAddr>> {
        let mut ips = Vec::new();
        
        if let Ok(ip) = target.parse::<IpAddr>() {
            ips.push(ip);
            return Ok(ips);
        }

        if target.contains('/') {
            match target.parse::<IpNetwork>() {
                Ok(network) => {
                    let host_count = match network {
                        IpNetwork::V4(net) => {
                            let prefix_len = net.prefix();
                            if prefix_len > 31 {
                                1u64
                            } else {
                                1u64 << (32 - prefix_len)
                            }
                        }
                        IpNetwork::V6(net) => {
                            let prefix_len = net.prefix();
                            if prefix_len > 127 {
                                1u64
                            } else if prefix_len < 64 {
                                // very large IPv6 ranges
                                u64::MAX
                            } else {
                                1u64 << (128 - prefix_len).min(63)
                            }
                        }
                    };

                    if host_count > MAX_CIDR_HOSTS as u64 {
                        return Err(anyhow!(
                            "CIDR range {} too large ({} hosts). Max: {} (/16 for IPv4)",
                            target, host_count, MAX_CIDR_HOSTS
                        ));
                    }
                    return Ok(network.iter().collect());
                }
                Err(e) => {
                    return Err(anyhow!("Invalid CIDR notation '{}': {}", target, e));
                }
            }
        }

        let socket_addr = format!("{}:80", target);
        match socket_addr.to_socket_addrs() {
            Ok(addrs) => {
                for addr in addrs {
                    ips.push(addr.ip());
                }
                if !ips.is_empty() {
                    Ok(ips)
                } else {
                    Err(anyhow!("Could not resolve hostname: {}", target))
                }
            }
            Err(e) => Err(anyhow!("Failed to resolve hostname {}: {}", target, e)),
        }
    }

    async fn try_connect(addr: SocketAddr, timeout_ms: u64) -> Result<Option<TcpStream>> {
        let mut attempts = 0;

        while attempts <= MAX_RETRIES {
            match timeout(
                Duration::from_millis(timeout_ms),
                TcpStream::connect(addr),
            ).await {
                Ok(Ok(stream)) => {
                    stream.set_nodelay(true)?;
                    return Ok(Some(stream));
                }
                Ok(Err(e)) => {
                    if e.kind() == std::io::ErrorKind::ConnectionRefused {
                        return Ok(None);
                    }
                }
                Err(_) => {}
            }

            attempts += 1;

            if attempts <= MAX_RETRIES {
                tokio::time::sleep(Duration::from_millis(RETRY_DELAY)).await;
            }
        }

        Ok(None)
    }

    async fn scan_addr(&self, addr: SocketAddr) -> Result<Option<ScanResult>> {
        if let Ok(Some(mut stream)) = Self::try_connect(addr, self.timeout).await {
            let mut service = None;

            if self.service_detection {
                if let Ok(detected_service) = detect_service(&mut stream, addr.port()).await {
                    service = detected_service;
                }
            }

            Ok(Some(ScanResult {
                ip: addr.ip(),
                port: addr.port(),
                service,
            }))
        } else {
            Ok(None)
        }
    }

    async fn scan_ip_chunk(&self, ips: &[IpAddr], pb: &ProgressBar) -> Vec<ScanResult> {
        let mut results = Vec::new();
        let semaphore = Arc::new(Semaphore::new(self.concurrency));
        let mut futures = Vec::with_capacity(ips.len() * self.port_range.clone().count());

        for ip in ips {
            for port in self.port_range.clone() {
                let addr = SocketAddr::new(*ip, port);
                let scanner = self.clone();
                let sem = semaphore.clone();
                let pb = pb.clone();

                futures.push(async move {
                    let _permit = sem.acquire().await.unwrap();
                    let result = scanner.scan_addr(addr).await;
                    pb.inc(1);
                    result
                });
            }
        }

        let stream = futures::stream::iter(futures)
            .buffer_unordered(self.concurrency);

        let mut stream_results = stream.collect::<Vec<_>>().await;
        results.extend(stream_results.drain(..).filter_map(|r| r.unwrap_or(None)));

        results
    }

    pub async fn run(&self) -> Result<Vec<ScanResult>> {
        let mut all_results = Vec::new();
        let mut resolved_ips = Vec::new();

        for target in &self.targets {
            match Self::resolve_target(target).await {
                Ok(ips) => {
                    println!("Resolved {} to {} IPs", target, ips.len());
                    for ip in &ips {
                        println!("  {}", ip);
                    }
                    resolved_ips.extend(ips);
                }
                Err(e) => eprintln!("Warning: {}", e),
            }
        }

        if resolved_ips.is_empty() {
            return Err(anyhow!("No valid IP addresses found for any target"));
        }

        let total_ips = resolved_ips.len();
        let total_ports = self.port_range.end() - self.port_range.start() + 1;
        let total_addrs = (total_ports as usize) * total_ips;

        println!("\nScan configuration:");
        println!("  Timeout: {}ms", self.timeout);
        println!("  Concurrency: {}", self.concurrency);
        println!("  Service detection: {}", self.service_detection);
        println!("  Total addresses to scan: {}", total_addrs);

        let pb = ProgressBar::new(total_addrs as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("#>-"));

        let chunk_size = if total_ips > 1 {
            SUBNET_CHUNK_SIZE
        } else {
            CHUNK_SIZE
        };

        for chunk in resolved_ips.chunks(chunk_size) {
            let chunk_results = self.scan_ip_chunk(chunk, &pb).await;
            all_results.extend(chunk_results);
        }

        pb.finish_with_message("Scan completed");
        println!("\nFound {} open ports", all_results.len());

        Ok(all_results)
    }
}

impl Clone for Scanner {
    fn clone(&self) -> Self {
        Self {
            targets: self.targets.clone(),
            port_range: self.port_range.clone(),
            concurrency: self.concurrency,
            timeout: self.timeout,
            service_detection: self.service_detection,
        }
    }
} 


use anyhow::Result;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::time::Duration;
use indicatif::{ProgressBar, ProgressStyle};
use serde_json;
use crate::service_detection::ServiceDetector;
use crate::types::ScanResult;

pub struct Scanner {
    target_ips: Vec<IpAddr>,
    start_port: u16,
    end_port: u16,
    concurrency: usize,
    timeout: Duration,
    service_detector: Option<Arc<ServiceDetector>>,
    output_format: String,
}

impl Scanner {
    pub fn new(
        target_ips: Vec<IpAddr>,
        start_port: u16,
        end_port: u16,
        concurrency: usize,
        timeout: Duration,
        service_detector: Option<Arc<ServiceDetector>>,
        output_format: String,
    ) -> Self {
        Self {
            target_ips,
            start_port,
            end_port,
            concurrency,
            timeout,
            service_detector,
            output_format,
        }
    }

    pub async fn run(&self) -> Result<Vec<ScanResult>> {
        let mut results = Vec::new();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.concurrency));
        let mut handles = Vec::new();

        let total_tasks = (self.target_ips.len() * ((self.end_port - self.start_port + 1) as usize)) as u64;
        let pb = ProgressBar::new(total_tasks);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
                .unwrap()
                .progress_chars("#>-"),
        );

        for ip in &self.target_ips {
            for port in self.start_port..=self.end_port {
                let sem = semaphore.clone();
                let ip = *ip;
                let port = port;
                let timeout = self.timeout;
                let service_detector = self.service_detector.clone();
                let pb = pb.clone();

                let handle = tokio::spawn(async move {
                    let _permit = sem.acquire().await?;
                    let result = scan_port(ip, port, timeout, service_detector).await;
                    pb.inc(1);
                    result
                });

                handles.push(handle);
            }
        }

        for handle in handles {
            if let Ok(Ok(Some(result))) = handle.await {
                results.push(result);
            }
        }

        pb.finish_with_message("Scan completed!");

        if self.output_format == "json" {
            println!("{}", serde_json::to_string_pretty(&results)?);
        } else {
            for result in &results {
                println!("{}:{}", result.ip, result.port);
                if let Some(service) = &result.service {
                    println!("  Service: {}", service.name);
                    if let Some(version) = &service.version {
                        println!("  Version: {}", version);
                    }
                    if let Some(product) = &service.product {
                        println!("  Product: {}", product);
                    }
                    if let Some(os_type) = &service.os_type {
                        println!("  OS Type: {}", os_type);
                    }
                    if let Some(extra_info) = &service.extra_info {
                        println!("  Extra Info: {}", extra_info);
                    }
                }
                println!();
            }
        }

        Ok(results)
    }
}

async fn scan_port(
    ip: IpAddr,
    port: u16,
    timeout_duration: Duration,
    service_detector: Option<Arc<ServiceDetector>>,
) -> Result<Option<ScanResult>> {
    let addr = SocketAddr::new(ip, port);
    
    match tokio::time::timeout(timeout_duration, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => {
            let mut result = ScanResult {
                ip,
                port,
                service: None,
            };

            if let Some(detector) = service_detector {
                if let Ok(Some(service)) = detector.detect_service(stream, port, false).await {
                    result.service = Some(service);
                }
            }

            Ok(Some(result))
        }
        _ => Ok(None),
    }
} 

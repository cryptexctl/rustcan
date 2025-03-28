use std::net::{IpAddr, SocketAddr};
use std::ops::RangeInclusive;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use indicatif::{ProgressBar, ProgressStyle};
use futures::stream::{self, StreamExt};
use anyhow::Result;
use crossbeam_channel::bounded;
use crate::types::ScanResult;
use crate::service_detection::detect_service;

const MAX_RETRIES: u32 = 2;
const RETRY_DELAY: u64 = 500;
const CHUNK_SIZE: usize = 1000;
const SUBNET_CHUNK_SIZE: usize = 100;

pub struct Scanner {
    targets: Vec<IpAddr>,
    port_range: RangeInclusive<u16>,
    concurrency: usize,
    timeout: u64,
    service_detection: bool,
}

impl Scanner {
    pub fn new(
        targets: Vec<IpAddr>,
        port_range: RangeInclusive<u16>,
        concurrency: usize,
        timeout: u64,
        service_detection: bool,
    ) -> Self {
        Self {
            targets,
            port_range,
            concurrency,
            timeout,
            service_detection,
        }
    }

    async fn try_connect(addr: SocketAddr, timeout_ms: u64) -> Result<Option<TcpStream>> {
        for retry in 0..MAX_RETRIES {
            match timeout(
                Duration::from_millis(timeout_ms),
                TcpStream::connect(addr),
            ).await {
                Ok(Ok(stream)) => return Ok(Some(stream)),
                Ok(Err(_)) => return Ok(None),
                Err(_) if retry < MAX_RETRIES - 1 => {
                    tokio::time::sleep(Duration::from_millis(RETRY_DELAY)).await;
                    continue;
                }
                Err(_) => return Ok(None),
            }
        }
        Ok(None)
    }

    async fn scan_addr(&self, addr: SocketAddr) -> Result<Option<ScanResult>> {
        if let Ok(Some(mut stream)) = Self::try_connect(addr, self.timeout).await {
            let mut service = None;
            let mut raw_response = String::new();

            if self.service_detection {
                if let Ok((detected_service, response)) = detect_service(&mut stream).await {
                    service = detected_service;
                    raw_response = response;
                }
            }

            Ok(Some(ScanResult {
                ip: addr.ip(),
                port: addr.port(),
                service,
                raw_response,
            }))
        } else {
            Ok(None)
        }
    }

    async fn scan_ip_chunk(&self, ips: &[IpAddr]) -> Vec<ScanResult> {
        let mut results = Vec::new();
        let mut addrs = Vec::new();

        for &ip in ips {
            for port in self.port_range.clone() {
                addrs.push(SocketAddr::new(ip, port));
            }
        }

        let (progress_tx, progress_rx) = bounded::<(SocketAddr, bool)>(1000);
        let progress_bar = ProgressBar::new(addrs.len() as u64);
        progress_bar.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) Scanning {msg}")
                .unwrap()
                .progress_chars("#>-"),
        );

        let progress_bar_clone = progress_bar.clone();
        std::thread::spawn(move || {
            while let Ok((addr, _)) = progress_rx.recv() {
                progress_bar_clone.set_message(format!("{}", addr.ip()));
                progress_bar_clone.inc(1);
            }
        });

        let mut stream = stream::iter(addrs)
            .map(|addr| {
                let progress_tx = progress_tx.clone();
                async move {
                    let result = self.scan_addr(addr).await;
                    let _ = progress_tx.send((addr, result.is_ok()));
                    result
                }
            })
            .buffer_unordered(self.concurrency);

        while let Some(result) = stream.next().await {
            if let Ok(Some(scan_result)) = result {
                results.push(scan_result);
            }
        }

        progress_bar.finish_and_clear();
        results
    }

    pub async fn run(&self) -> Vec<ScanResult> {
        let mut all_results = Vec::new();
        let total_ips = self.targets.len();
        let total_ports = self.port_range.end() - self.port_range.start() + 1;
        let total_addrs = (total_ports as usize) * total_ips;

        println!("Total addresses to scan: {}", total_addrs);

        let chunk_size = if total_ips > 1 {
            SUBNET_CHUNK_SIZE
        } else {
            CHUNK_SIZE
        };

        for chunk in self.targets.chunks(chunk_size) {
            let chunk_results = self.scan_ip_chunk(chunk).await;
            all_results.extend(chunk_results);
        }

        all_results
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

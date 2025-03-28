use anyhow::Result;
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use regex::Regex;
use crate::types::ServiceInfo;

pub struct ServicePattern {
    name: String,
    pattern: Regex,
    probe: Vec<u8>,
}

pub struct ServiceDetector {
    patterns: HashMap<u16, Vec<ServicePattern>>,
}

impl ServiceDetector {
    pub fn new() -> Self {
        let mut patterns = HashMap::new();

        // HTTP
        patterns.insert(80, vec![
            ServicePattern {
                name: "HTTP".to_string(),
                pattern: Regex::new(r"^HTTP/\d\.\d").unwrap(),
                probe: b"GET / HTTP/1.0\r\n\r\n".to_vec(),
            }
        ]);

        // HTTPS
        patterns.insert(443, vec![
            ServicePattern {
                name: "HTTPS".to_string(),
                pattern: Regex::new(r"^\x16\x03").unwrap(),
                probe: vec![],
            }
        ]);

        // SSH
        patterns.insert(22, vec![
            ServicePattern {
                name: "SSH".to_string(),
                pattern: Regex::new(r"^SSH-\d\.\d").unwrap(),
                probe: vec![],
            }
        ]);

        // FTP
        patterns.insert(21, vec![
            ServicePattern {
                name: "FTP".to_string(),
                pattern: Regex::new(r"^220.*FTP").unwrap(),
                probe: vec![],
            }
        ]);

        // SMTP
        patterns.insert(25, vec![
            ServicePattern {
                name: "SMTP".to_string(),
                pattern: Regex::new(r"^220.*SMTP").unwrap(),
                probe: vec![],
            }
        ]);

        // DNS
        patterns.insert(53, vec![
            ServicePattern {
                name: "DNS".to_string(),
                pattern: Regex::new(r"^\x00\x00").unwrap(),
                probe: vec![],
            }
        ]);

        Self { patterns }
    }

    pub async fn detect_service(&self, mut stream: TcpStream, port: u16, _enhanced: bool) -> Result<Option<ServiceInfo>> {
        if let Some(patterns) = self.patterns.get(&port) {
            for pattern in patterns {
                if !pattern.probe.is_empty() {
                    stream.write_all(&pattern.probe).await?;
                }

                let mut buf = vec![0; 1024];
                match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
                    Ok(Ok(n)) if n > 0 => {
                        let response = String::from_utf8_lossy(&buf[..n]);
                        if pattern.pattern.is_match(&response) {
                            return Ok(Some(ServiceInfo {
                                name: pattern.name.clone(),
                                version: extract_version(&response),
                                product: extract_product(&response),
                                os_type: extract_os(&response),
                                extra_info: Some(response.to_string()),
                            }));
                        }
                    }
                    _ => continue,
                }
            }
        }

        Ok(None)
    }
}

fn extract_version(response: &str) -> Option<String> {
    let version_pattern = Regex::new(r"(?i)version[:\s]+([^\s]+)").unwrap();
    version_pattern.captures(response)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
}

fn extract_product(response: &str) -> Option<String> {
    let product_pattern = Regex::new(r"(?i)server:\s+([^\r\n]+)").unwrap();
    product_pattern.captures(response)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
}

fn extract_os(response: &str) -> Option<String> {
    let os_pattern = Regex::new(r"(?i)\((.*?)\)").unwrap();
    os_pattern.captures(response)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
}
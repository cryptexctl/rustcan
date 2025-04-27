use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use anyhow::Result;
use crate::types::Service;
use crate::patterns::get_all_patterns;

pub async fn detect_service(stream: &mut TcpStream) -> Result<(Option<Service>, String)> {
    let mut buffer = [0u8; 1024];
    let mut raw_response = String::new();
    let patterns = get_all_patterns();    
    let mut probe = Vec::new();
    for pattern in &patterns {
        if !pattern.probe.is_empty() {
            probe.extend_from_slice(pattern.probe.as_bytes());
        }
    }

    stream.write_all(&probe).await?;
    stream.flush().await?;

    let mut response = Vec::new();
    let mut total_read = 0;
    let timeout = std::time::Duration::from_secs(2);

    while total_read < buffer.len() {
        match tokio::time::timeout(timeout, stream.read(&mut buffer[total_read..])).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                total_read += n;
                response.extend_from_slice(&buffer[..n]);
            }
            Ok(Err(e)) if e.kind() == io::ErrorKind::WouldBlock => break,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => break,
        }
    }

    if !response.is_empty() {
        raw_response = String::from_utf8_lossy(&response).to_string();
    }

    for pattern in patterns {
        if pattern.regex.is_match(&raw_response) {
            let mut service = Service {
                name: pattern.name.clone(),
                version: None,
                product: None,
                os_type: None,
                extra_info: None,
                cpe: None,
            };

            if let Some(version_regex) = pattern.version_regex {
                if let Some(caps) = version_regex.captures(&raw_response) {
                    service.version = caps.get(1).map(|m| m.as_str().to_string());
                }
            }

            if let Some(product_regex) = pattern.product_regex {
                if let Some(caps) = product_regex.captures(&raw_response) {
                    service.product = caps.get(1).map(|m| m.as_str().to_string());
                }
            }

            if let Some(os_regex) = pattern.os_regex {
                if let Some(caps) = os_regex.captures(&raw_response) {
                    service.os_type = caps.get(1).map(|m| m.as_str().to_string());
                }
            }

            if let Some(extra_info_regex) = pattern.extra_info_regex {
                if let Some(caps) = extra_info_regex.captures(&raw_response) {
                    service.extra_info = caps.get(1).map(|m| m.as_str().to_string());
                }
            }

            if let Some(cpe_regex) = pattern.cpe_regex {
                if let Some(caps) = cpe_regex.captures(&raw_response) {
                    service.cpe = caps.get(1).map(|m| m.as_str().to_string());
                }
            }

            return Ok((Some(service), raw_response));
        }
    }

    Ok((None, raw_response))
}
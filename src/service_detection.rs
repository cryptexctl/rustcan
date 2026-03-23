use crate::patterns::{get_all_patterns, get_services_by_port};
use crate::types::{Service, ServicePattern};
use anyhow::Result;
use std::io;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn read_response(stream: &mut TcpStream, timeout: Duration) -> Result<String> {
    let mut buffer = [0u8; 4096];
    let mut response = Vec::with_capacity(4096);
    let mut total_read = 0;

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
        Ok(String::from_utf8_lossy(&response).to_string())
    } else {
        Ok(String::new())
    }
}

fn extract_service_info(pattern: &ServicePattern, response: &str) -> Service {
    let mut service = Service {
        name: pattern.name.clone(),
        version: None,
        product: None,
        os_type: None,
        extra_info: None,
        cpe: None,
    };

    if let Some(version_regex) = &pattern.version_regex {
        if let Some(caps) = version_regex.captures(response) {
            service.version = caps.get(1).map(|m| m.as_str().to_string());
        }
    }

    if let Some(product_regex) = &pattern.product_regex {
        if let Some(caps) = product_regex.captures(response) {
            service.product = caps.get(1).map(|m| m.as_str().to_string());
        }
    }

    if let Some(os_regex) = &pattern.os_regex {
        if let Some(caps) = os_regex.captures(response) {
            service.os_type = caps.get(1).map(|m| m.as_str().to_string());
        }
    }

    if let Some(extra_info_regex) = &pattern.extra_info_regex {
        if let Some(caps) = extra_info_regex.captures(response) {
            service.extra_info = caps.get(1).map(|m| m.as_str().to_string());
        }
    }

    if let Some(cpe_regex) = &pattern.cpe_regex {
        if let Some(caps) = cpe_regex.captures(response) {
            service.cpe = caps.get(1).map(|m| m.as_str().to_string());
        }
    }

    service
}

pub async fn detect_service(stream: &mut TcpStream, port: u16) -> Result<Option<Service>> {
    let patterns = get_all_patterns();
    let timeout = Duration::from_millis(2000);

    let mut unique_probes: Vec<&ServicePattern> = Vec::new();
    let mut seen_probes = std::collections::HashSet::new();

    for pattern in &patterns {
        if !pattern.probe.is_empty() && !seen_probes.contains(&pattern.probe) {
            seen_probes.insert(pattern.probe.clone());
            unique_probes.push(pattern);
        }
    }

    let mut probe_data = Vec::new();
    for pattern in &unique_probes {
        probe_data.extend_from_slice(pattern.probe.as_bytes());
        probe_data.extend_from_slice(b"\r\n");
    }

    if !probe_data.is_empty() {
        let _ = stream.write_all(&probe_data).await;
        let _ = stream.flush().await;
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    let all_responses = read_response(stream, timeout).await?;

    if !all_responses.is_empty() {
        for pattern in &patterns {
            if pattern.regex.is_match(&all_responses) {
                let service = extract_service_info(pattern, &all_responses);
                return Ok(Some(service));
            }
        }
    }

    if let Some(services) = get_services_by_port(port) {
        if let Some(nmap_service) = services.iter().find(|s| s.protocol == "tcp") {
            let service = Service {
                name: nmap_service.name.clone(),
                version: None,
                product: None,
                os_type: None,
                extra_info: None,
                cpe: None,
            };
            return Ok(Some(service));
        }
    }

    Ok(None)
}

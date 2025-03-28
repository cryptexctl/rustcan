use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use anyhow::Result;
use crate::types::Service;
use crate::patterns::{get_ssh_patterns, get_http_patterns, get_ftp_patterns, get_mysql_patterns, get_redis_patterns};

pub async fn detect_service(stream: &mut TcpStream) -> Result<(Option<Service>, String)> {
    let mut buffer = [0u8; 1024];
    let mut raw_response = String::new();

    let mut probe = Vec::new();
    probe.extend_from_slice(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    probe.extend_from_slice(b"SSH-2.0-OpenSSH_8.2p1\r\n");
    probe.extend_from_slice(b"USER anonymous\r\n");
    probe.extend_from_slice(b"\x4a\x00\x00\x00\x0a\x35\x2e\x35\x2e\x35");
    probe.extend_from_slice(b"PING\r\n");

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

    let patterns = [
        get_ssh_patterns(),
        get_http_patterns(),
        get_ftp_patterns(),
        get_mysql_patterns(),
        get_redis_patterns(),
    ];

    for pattern_group in patterns.iter() {
        for pattern in pattern_group {
            if pattern.regex.is_match(&raw_response) {
                return Ok((Some(Service {
                    name: pattern.name.clone(),
                    version: None,
                    product: None,
                    os_type: None,
                    extra_info: None,
                }), raw_response));
            }
        }
    }

    Ok((None, raw_response))
}
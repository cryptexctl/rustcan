use regex::Regex;
use std::fs;
use std::path::Path;
use anyhow::Result;
use crate::types::{ServicePattern, NmapService, NmapProbe, NmapMatch};

pub fn get_ssh_patterns() -> Vec<ServicePattern> {
    vec![
        ServicePattern {
            name: "SSH".to_string(),
            regex: Regex::new(r"^SSH-\d\.\d").unwrap(),
            probe: "SSH-2.0-OpenSSH_8.2p1\r\n".to_string(),
            version_regex: Some(Regex::new(r"SSH-(\d\.\d)").unwrap()),
            product_regex: Some(Regex::new(r"OpenSSH_([^\r\n]+)").unwrap()),
            os_regex: Some(Regex::new(r"OpenSSH.*?([^\r\n]+)").unwrap()),
            extra_info_regex: None,
            cpe_regex: None,
            vulnerability_patterns: vec![],
            total_wait_ms: 6000,
            tcp_wrapped_ms: 3000,
        },
    ]
}

pub fn get_http_patterns() -> Vec<ServicePattern> {
    vec![
        ServicePattern {
            name: "HTTP".to_string(),
            regex: Regex::new(r"^HTTP/\d\.\d").unwrap(),
            probe: "HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n".to_string(),
            version_regex: Some(Regex::new(r"HTTP/(\d\.\d)").unwrap()),
            product_regex: Some(Regex::new(r"Server: ([^\r\n]+)").unwrap()),
            os_regex: None,
            extra_info_regex: None,
            cpe_regex: None,
            vulnerability_patterns: vec![],
            total_wait_ms: 6000,
            tcp_wrapped_ms: 3000,
        },
    ]
}

pub fn get_ftp_patterns() -> Vec<ServicePattern> {
    vec![
        ServicePattern {
            name: "FTP".to_string(),
            regex: Regex::new(r"^220").unwrap(),
            probe: "USER anonymous\r\n".to_string(),
            version_regex: Some(Regex::new(r"220 ([^\r\n]+)").unwrap()),
            product_regex: None,
            os_regex: None,
            extra_info_regex: None,
            cpe_regex: None,
            vulnerability_patterns: vec![],
            total_wait_ms: 6000,
            tcp_wrapped_ms: 3000,
        },
    ]
}

pub fn get_mysql_patterns() -> Vec<ServicePattern> {
    vec![
        ServicePattern {
            name: "MySQL".to_string(),
            regex: Regex::new(r"^\x00").unwrap(),
            probe: "\x4a\x00\x00\x00\x0a\x35\x2e\x35\x2e\x35".to_string(),
            version_regex: Some(Regex::new(r"(\d+\.\d+\.\d+)").unwrap()),
            product_regex: None,
            os_regex: None,
            extra_info_regex: None,
            cpe_regex: None,
            vulnerability_patterns: vec![],
            total_wait_ms: 6000,
            tcp_wrapped_ms: 3000,
        },
    ]
}

pub fn get_redis_patterns() -> Vec<ServicePattern> {
    vec![
        ServicePattern {
            name: "Redis".to_string(),
            regex: Regex::new(r"^[+\$\*:-]").unwrap(),
            probe: "PING\r\n".to_string(),
            version_regex: Some(Regex::new(r"redis_version:(\d+\.\d+\.\d+)").unwrap()),
            product_regex: None,
            os_regex: None,
            extra_info_regex: None,
            cpe_regex: None,
            vulnerability_patterns: vec![],
            total_wait_ms: 6000,
            tcp_wrapped_ms: 3000,
        },
    ]
}

pub fn load_nmap_services(file_path: &str) -> Result<Vec<NmapService>> {
    let path = Path::new(file_path);
    if !path.exists() {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(path)?;
    let mut services = Vec::new();

    for line in content.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            let name = parts[0].to_string();
            let port = parts[1].split('/').next().unwrap_or("0").parse::<u16>().unwrap_or(0);
            let protocol = parts[1].split('/').nth(1).unwrap_or("tcp").to_string();
            let description = if parts.len() > 2 {
                Some(parts[2..].join(" "))
            } else {
                None
            };

            services.push(NmapService {
                name,
                port,
                protocol,
                description,
            });
        }
    }

    Ok(services)
}

pub fn load_nmap_probes(file_path: &str) -> Result<Vec<NmapProbe>> {
    let path = Path::new(file_path);
    if !path.exists() {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(path)?;
    let mut probes = Vec::new();
    let mut current_probe: Option<NmapProbe> = None;

    for line in content.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }

        if line.starts_with("Probe ") {
            if let Some(probe) = current_probe.take() {
                probes.push(probe);
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let name = parts[1].to_string();
                let protocol = parts[2].to_string();
                let probe_string = parts[3].trim_matches(|c| c == 'q' || c == '|').to_string();

                current_probe = Some(NmapProbe {
                    name,
                    protocol,
                    probe_string,
                    total_wait_ms: 6000,
                    tcp_wrapped_ms: 3000,
                    matches: Vec::new(),
                });
            }
        } else if line.starts_with("match ") {
            if let Some(probe) = &mut current_probe {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let service = parts[1].to_string();
                    let pattern = parts[2].trim_matches(|c| c == 'm' || c == '|').to_string();
                    
                    if pattern.contains("**") || pattern.contains("\\") || pattern.contains("^") {
                        continue;
                    }

                    let mut version_info = None;
                    let mut product_info = None;
                    let mut os_info = None;
                    let mut extra_info = None;
                    let mut cpe = None;

                    for part in parts.iter().skip(3) {
                        if part.starts_with("v/") {
                            version_info = Some(part[2..].to_string());
                        } else if part.starts_with("p/") {
                            product_info = Some(part[2..].to_string());
                        } else if part.starts_with("o/") {
                            os_info = Some(part[2..].to_string());
                        } else if part.starts_with("i/") {
                            extra_info = Some(part[2..].to_string());
                        } else if part.starts_with("cpe:/") {
                            cpe = Some(part.to_string());
                        }
                    }

                    probe.matches.push(NmapMatch {
                        service,
                        pattern,
                        version_info,
                        product_info,
                        os_info,
                        extra_info,
                        cpe,
                    });
                }
            }
        } else if line.starts_with("totalwaitms ") {
            if let Some(probe) = &mut current_probe {
                if let Ok(ms) = line.split_whitespace().nth(1).unwrap_or("6000").parse::<u64>() {
                    probe.total_wait_ms = ms;
                }
            }
        } else if line.starts_with("tcpwrappedms ") {
            if let Some(probe) = &mut current_probe {
                if let Ok(ms) = line.split_whitespace().nth(1).unwrap_or("3000").parse::<u64>() {
                    probe.tcp_wrapped_ms = ms;
                }
            }
        }
    }

    if let Some(probe) = current_probe.take() {
        probes.push(probe);
    }

    Ok(probes)
}

pub fn get_all_patterns() -> Vec<ServicePattern> {
    let mut patterns = Vec::new();
    
    patterns.extend(get_ssh_patterns());
    patterns.extend(get_http_patterns());
    patterns.extend(get_ftp_patterns());
    patterns.extend(get_mysql_patterns());
    patterns.extend(get_redis_patterns());
    
    if let Ok(probes) = load_nmap_probes("src/assets/nmap-service-probes") {
        for probe in probes {
            for nmap_match in probe.matches {
                if nmap_match.pattern.contains("**") || nmap_match.pattern.contains("\\") || nmap_match.pattern.contains("^") {
                    continue;
                }

                if let Ok(regex) = Regex::new(&nmap_match.pattern) {
                    let pattern = ServicePattern {
                        name: nmap_match.service.clone(),
                        regex,
                        probe: probe.probe_string.clone(),
                        version_regex: nmap_match.version_info.as_ref().and_then(|v| Regex::new(v).ok()),
                        product_regex: nmap_match.product_info.as_ref().and_then(|p| Regex::new(p).ok()),
                        os_regex: nmap_match.os_info.as_ref().and_then(|o| Regex::new(o).ok()),
                        extra_info_regex: nmap_match.extra_info.as_ref().and_then(|i| Regex::new(i).ok()),
                        cpe_regex: nmap_match.cpe.as_ref().and_then(|c| Regex::new(c).ok()),
                        vulnerability_patterns: vec![],
                        total_wait_ms: probe.total_wait_ms,
                        tcp_wrapped_ms: probe.tcp_wrapped_ms,
                    };
                    patterns.push(pattern);
                }
            }
        }
    }
    
    patterns
} 
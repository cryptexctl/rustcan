use regex::Regex;
use std::fs;
use std::path::Path;
use anyhow::Result;
use std::collections::HashMap;
use crate::types::{ServicePattern, NmapService, NmapProbe, NmapMatch, Protocol, MacPrefix, RpcInfo};

lazy_static::lazy_static! {
    static ref PROTOCOLS: HashMap<String, Protocol> = {
        let mut map = HashMap::new();
        if let Ok(protocols) = load_protocols("src/assets/nmap-protocols") {
            for protocol in protocols {
                map.insert(protocol.name.clone(), protocol);
            }
        }
        map
    };

    static ref MAC_PREFIXES: HashMap<String, String> = {
        let mut map = HashMap::new();
        if let Ok(prefixes) = load_mac_prefixes("src/assets/nmap-mac-prefixes") {
            for prefix in prefixes {
                map.insert(prefix.prefix, prefix.vendor);
            }
        }
        map
    };

    static ref RPC_INFO: HashMap<(String, String), RpcInfo> = {
        let mut map = HashMap::new();
        if let Ok(info) = load_rpc_info("src/assets/nmap-rpc") {
            for rpc in info {
                map.insert((rpc.program.clone(), rpc.version.clone()), rpc);
            }
        }
        map
    };

    static ref NMAP_SERVICES: HashMap<u16, Vec<NmapService>> = {
        let mut map = HashMap::new();
        if let Ok(services) = load_nmap_services("src/assets/nmap-services") {
            for service in services {
                map.entry(service.port).or_insert_with(Vec::new).push(service);
            }
        }
        map
    };

    static ref SERVICE_PATTERNS: Vec<ServicePattern> = {
        let mut patterns = Vec::with_capacity(1000);
        
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
    };
}

pub fn get_all_patterns() -> Vec<ServicePattern> {
    SERVICE_PATTERNS.clone()
}

pub fn get_protocol(name: &str) -> Option<&Protocol> {
    PROTOCOLS.get(name)
}

pub fn get_mac_vendor(prefix: &str) -> Option<&String> {
    MAC_PREFIXES.get(prefix)
}

pub fn get_rpc_info<'a>(program: &'a str, version: &'a str) -> Option<&'static RpcInfo> {
    RPC_INFO.get(&(program.to_string(), version.to_string()))
}

pub fn get_services_by_port(port: u16) -> Option<&'static Vec<NmapService>> {
    NMAP_SERVICES.get(&port)
}

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

pub fn load_protocols(file_path: &str) -> Result<Vec<Protocol>> {
    let path = Path::new(file_path);
    if !path.exists() {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(path)?;
    let mut protocols = Vec::new();

    for line in content.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let name = parts[0].to_string();
            if let Ok(number) = parts[1].parse::<u8>() {
                let aliases = if parts.len() > 2 {
                    parts[2..].iter().map(|&s| s.to_string()).collect()
                } else {
                    Vec::new()
                };

                protocols.push(Protocol {
                    name,
                    number,
                    aliases,
                });
            }
        }
    }

    Ok(protocols)
}

pub fn load_mac_prefixes(file_path: &str) -> Result<Vec<MacPrefix>> {
    let path = Path::new(file_path);
    if !path.exists() {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(path)?;
    let mut prefixes = Vec::new();

    for line in content.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let prefix = parts[0].to_string();
            let vendor = parts[1..].join(" ");

            prefixes.push(MacPrefix {
                prefix,
                vendor,
            });
        }
    }

    Ok(prefixes)
}

pub fn load_rpc_info(file_path: &str) -> Result<Vec<RpcInfo>> {
    let path = Path::new(file_path);
    if !path.exists() {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(path)?;
    let mut rpc_info = Vec::new();

    for line in content.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            let program = parts[0].to_string();
            let version = parts[1].to_string();
            let protocol = parts[2].to_string();
            let port = parts.get(3).and_then(|p| p.parse::<u16>().ok());
            let description = if parts.len() > 4 {
                Some(parts[4..].join(" "))
            } else {
                None
            };

            rpc_info.push(RpcInfo {
                program,
                version,
                protocol,
                port,
                description,
            });
        }
    }

    Ok(rpc_info)
} 
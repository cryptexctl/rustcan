use serde::Serialize;
use regex::Regex;

#[derive(Debug, Clone, Serialize)]
pub struct Service {
    pub name: String,
    pub version: Option<String>,
    pub product: Option<String>,
    pub os_type: Option<String>,
    pub extra_info: Option<String>,
    pub cpe: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ServicePattern {
    pub name: String,
    pub regex: Regex,
    pub probe: String,
    pub version_regex: Option<Regex>,
    pub product_regex: Option<Regex>,
    pub os_regex: Option<Regex>,
    pub extra_info_regex: Option<Regex>,
    pub cpe_regex: Option<Regex>,
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub ip: std::net::IpAddr,
    pub port: u16,
    pub service: Option<Service>,
}

#[derive(Debug, Clone)]
pub struct NmapService {
    pub name: String,
    pub port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone)]
pub struct NmapProbe {
    pub probe_string: String,
    pub matches: Vec<NmapMatch>,
    pub total_wait_ms: u64,
    pub tcp_wrapped_ms: u64,
}

#[derive(Debug, Clone)]
pub struct NmapMatch {
    pub service: String,
    pub pattern: String,
    pub version_info: Option<String>,
    pub product_info: Option<String>,
    pub os_info: Option<String>,
    pub extra_info: Option<String>,
    pub cpe: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MacPrefix {
    pub prefix: String,
    pub vendor: String,
}


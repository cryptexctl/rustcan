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
    pub vulnerability_patterns: Vec<Regex>,
    pub total_wait_ms: u64,
    pub tcp_wrapped_ms: u64,
}

#[derive(Debug)]
pub struct ScanResult {
    pub ip: std::net::IpAddr,
    pub port: u16,
    pub service: Option<Service>,
    pub raw_response: String,
}

#[derive(Debug)]
pub struct NmapService {
    pub name: String,
    pub port: u16,
    pub protocol: String,
    pub description: Option<String>,
}

#[derive(Debug)]
pub struct NmapProbe {
    pub name: String,
    pub protocol: String,
    pub probe_string: String,
    pub total_wait_ms: u64,
    pub tcp_wrapped_ms: u64,
    pub matches: Vec<NmapMatch>,
}

#[derive(Debug)]
pub struct NmapMatch {
    pub service: String,
    pub pattern: String,
    pub version_info: Option<String>,
    pub product_info: Option<String>,
    pub os_info: Option<String>,
    pub extra_info: Option<String>,
    pub cpe: Option<String>,
}
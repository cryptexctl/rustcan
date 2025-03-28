use serde::Serialize;
use regex::Regex;

#[derive(Debug, Clone, Serialize)]
pub struct Service {
    pub name: String,
    pub version: Option<String>,
    pub product: Option<String>,
    pub os_type: Option<String>,
    pub extra_info: Option<String>,
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
    pub vulnerability_patterns: Vec<Regex>,
}

#[derive(Debug)]
pub struct ScanResult {
    pub ip: std::net::IpAddr,
    pub port: u16,
    pub service: Option<Service>,
    pub raw_response: String,
}
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ServiceInfo {
    pub name: String,
    pub version: Option<String>,
    pub product: Option<String>,
    pub os_type: Option<String>,
    pub extra_info: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub ip: std::net::IpAddr,
    pub port: u16,
    pub service: Option<ServiceInfo>,
}

#[derive(Debug, Clone)]
pub struct ServicePattern {
    pub name: String,
    pub regex: regex::Regex,
    pub probe: Vec<u8>,
    pub version_regex: Option<regex::Regex>,
    pub product_regex: Option<regex::Regex>,
    pub os_regex: Option<regex::Regex>,
    pub extra_info_regex: Option<regex::Regex>,
    pub vulnerability_patterns: Option<Vec<(regex::Regex, String)>>,
}
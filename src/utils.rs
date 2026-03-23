use crate::patterns::get_mac_vendor;
use regex::Regex;
use std::net::IpAddr;
use std::process::Command;

fn extract_mac_from_arp(output: &str) -> Option<String> {
    let re = Regex::new(r"(?i)([0-9a-f]{2}(?::[0-9a-f]{2}){5})").ok()?;
    let caps = re.captures(output)?;
    Some(caps.get(1)?.as_str().to_string())
}

pub fn get_mac_vendor_for_ip(ip: IpAddr) -> Option<String> {
    let output = Command::new("arp")
        .arg("-n")
        .arg(ip.to_string())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mac = extract_mac_from_arp(&stdout)?;

    let hex: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_uppercase();

    if hex.len() < 6 {
        return None;
    }

    let prefix = &hex[0..6];
    get_mac_vendor(prefix).cloned()
}

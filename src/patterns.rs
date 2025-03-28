use regex::Regex;
use crate::types::ServicePattern;

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
            vulnerability_patterns: vec![],
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
            vulnerability_patterns: vec![],
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
            vulnerability_patterns: vec![],
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
            vulnerability_patterns: vec![],
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
            vulnerability_patterns: vec![],
        },
    ]
} 
use crate::types::ServicePattern;
use regex::Regex;

pub fn get_ssh_patterns() -> Vec<ServicePattern> {
    vec![
        ServicePattern {
            name: "SSH".to_string(),
            regex: Regex::new(r"^SSH-\d\.\d").unwrap(),
            probe: b"SSH-2.0-Rustcan\r\n".to_vec(),
            version_regex: Some(Regex::new(r"^SSH-(\d\.\d+)").unwrap()),
            product_regex: Some(Regex::new(r"(?i)(openssh|dropbear|libssh)").unwrap()),
            os_regex: Some(Regex::new(r"(?i)(ubuntu|debian|centos|rhel|alpine)").unwrap()),
            extra_info_regex: Some(Regex::new(r"(?i)(compression|encryption|mac)").unwrap()),
            vulnerability_patterns: None,
        },
    ]
}

pub fn get_enhanced_ssh_patterns() -> Vec<ServicePattern> {
    vec![
        ServicePattern {
            name: "SSH".to_string(),
            regex: Regex::new(r"^SSH-\d\.\d").unwrap(),
            probe: b"SSH-2.0-Rustcan\r\n".to_vec(),
            version_regex: Some(Regex::new(r"^SSH-(\d\.\d+)(?:-(\w+))?").unwrap()),
            product_regex: Some(Regex::new(r"(?i)(openssh|dropbear|libssh)").unwrap()),
            os_regex: Some(Regex::new(r"(?i)(ubuntu|debian|centos|rhel|alpine)").unwrap()),
            extra_info_regex: Some(Regex::new(r"(?i)(compression|encryption|mac)").unwrap()),
            vulnerability_patterns: Some(vec![
                (Regex::new(r"(?i)openssh.*7\.2").unwrap(), "CVE-2016-6210: User enumeration vulnerability".to_string()),
                (Regex::new(r"(?i)dropbear.*2016").unwrap(), "CVE-2016-7408: Buffer overflow vulnerability".to_string()),
            ]),
        },
    ]
}

pub fn get_http_patterns() -> Vec<ServicePattern> {
    vec![
        ServicePattern {
            name: "HTTP".to_string(),
            regex: Regex::new(r"^HTTP/\d\.\d").unwrap(),
            probe: b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Rustcan/1.0\r\nAccept: */*\r\n\r\n".to_vec(),
            version_regex: Some(Regex::new(r"Server: ([^\r\n]+)").unwrap()),
            product_regex: Some(Regex::new(r"(?i)(apache|nginx|iis|lighttpd|tomcat|uhttpd)").unwrap()),
            os_regex: Some(Regex::new(r"(?i)(linux|windows|macos|bsd)").unwrap()),
            extra_info_regex: Some(Regex::new(r"(?i)(x-powered-by|x-aspnet-version|x-aspnetmvc-version)").unwrap()),
            vulnerability_patterns: None,
        },
    ]
}

pub fn get_enhanced_http_patterns() -> Vec<ServicePattern> {
    vec![
        ServicePattern {
            name: "HTTP".to_string(),
            regex: Regex::new(r"^HTTP/\d\.\d").unwrap(),
            probe: b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Rustcan/1.0\r\nAccept: */*\r\n\r\n".to_vec(),
            version_regex: Some(Regex::new(r"Server: ([^\r\n]+)").unwrap()),
            product_regex: Some(Regex::new(r"(?i)(apache|nginx|iis|lighttpd|tomcat|jetty|glassfish|uhttpd|busybox)").unwrap()),
            os_regex: Some(Regex::new(r"(?i)(linux|windows|macos|bsd|solaris|openwrt)").unwrap()),
            extra_info_regex: Some(Regex::new(r"(?i)(x-powered-by|x-aspnet-version|x-aspnetmvc-version|php|python|ruby)").unwrap()),
            vulnerability_patterns: Some(vec![
                (Regex::new(r"(?i)apache.*2\.4\.49").unwrap(), "CVE-2021-41773: Path traversal vulnerability".to_string()),
                (Regex::new(r"(?i)nginx.*1\.16\.1").unwrap(), "CVE-2019-9511: HTTP/2 DoS vulnerability".to_string()),
                (Regex::new(r"(?i)uhttpd.*1\.0").unwrap(), "CVE-2018-20148: Buffer overflow vulnerability".to_string()),
            ]),
        },
    ]
}

pub fn get_ftp_patterns() -> Vec<ServicePattern> {
    vec![
        ServicePattern {
            name: "FTP".to_string(),
            regex: Regex::new(r"^220").unwrap(),
            probe: b"USER anonymous\r\n".to_vec(),
            version_regex: Some(Regex::new(r"^220 ([^\r\n]+)").unwrap()),
            product_regex: Some(Regex::new(r"(?i)(vsftpd|proftpd|pure-ftpd|filezilla)").unwrap()),
            os_regex: Some(Regex::new(r"(?i)(linux|windows|macos|bsd)").unwrap()),
            extra_info_regex: Some(Regex::new(r"(?i)(ready|welcome)").unwrap()),
            vulnerability_patterns: None,
        },
    ]
}

pub fn get_smtp_patterns() -> Vec<ServicePattern> {
    vec![
        ServicePattern {
            name: "SMTP".to_string(),
            regex: Regex::new(r"^220").unwrap(),
            probe: b"EHLO localhost\r\n".to_vec(),
            version_regex: Some(Regex::new(r"^220 ([^\r\n]+)").unwrap()),
            product_regex: Some(Regex::new(r"(?i)(postfix|sendmail|exim|qmail)").unwrap()),
            os_regex: Some(Regex::new(r"(?i)(linux|windows|macos|bsd)").unwrap()),
            extra_info_regex: Some(Regex::new(r"(?i)(smtp|esmtp|auth)").unwrap()),
            vulnerability_patterns: None,
        },
    ]
}

pub fn get_dns_patterns() -> Vec<ServicePattern> {
    vec![
        ServicePattern {
            name: "DNS".to_string(),
            regex: Regex::new(r"^\x00").unwrap(),
            probe: vec![0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            version_regex: Some(Regex::new(r"(?i)version: ([^\r\n]+)").unwrap()),
            product_regex: Some(Regex::new(r"(?i)(bind|unbound|powerdns|dnsmasq)").unwrap()),
            os_regex: None,
            extra_info_regex: Some(Regex::new(r"(?i)(recursion|dnssec)").unwrap()),
            vulnerability_patterns: None,
        },
    ]
}

pub fn get_mysql_patterns() -> Vec<ServicePattern> {
    vec![
        ServicePattern {
            name: "MySQL".to_string(),
            regex: Regex::new(r"^\x4a").unwrap(),
            probe: vec![0x4a, 0x00, 0x00, 0x00, 0x0a],
            version_regex: Some(Regex::new(r"([0-9.]+)").unwrap()),
            product_regex: Some(Regex::new(r"(?i)(mysql|mariadb|percona)").unwrap()),
            os_regex: None,
            extra_info_regex: Some(Regex::new(r"(?i)(character_set|collation)").unwrap()),
            vulnerability_patterns: None,
        },
    ]
}

pub fn get_postgresql_patterns() -> Vec<ServicePattern> {
    vec![
        ServicePattern {
            name: "PostgreSQL".to_string(),
            regex: Regex::new(r"^N").unwrap(),
            probe: vec![0x4e, 0x00, 0x00, 0x00, 0x08],
            version_regex: Some(Regex::new(r"([0-9.]+)").unwrap()),
            product_regex: Some(Regex::new(r"(?i)(postgresql)").unwrap()),
            os_regex: None,
            extra_info_regex: Some(Regex::new(r"(?i)(encoding|timezone)").unwrap()),
            vulnerability_patterns: None,
        },
    ]
}

pub fn get_redis_patterns() -> Vec<ServicePattern> {
    vec![
        ServicePattern {
            name: "Redis".to_string(),
            regex: Regex::new(r"^\+").unwrap(),
            probe: b"PING\r\n".to_vec(),
            version_regex: Some(Regex::new(r"redis_version:([^\r\n]+)").unwrap()),
            product_regex: Some(Regex::new(r"(?i)(redis)").unwrap()),
            os_regex: None,
            extra_info_regex: Some(Regex::new(r"(?i)(os|arch|gcc|jemalloc)").unwrap()),
            vulnerability_patterns: None,
        },
    ]
} 
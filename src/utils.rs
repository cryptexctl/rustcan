use crate::types::ScanResult;

pub fn format_scan_result(result: &ScanResult) -> String {
    let mut output = format!("[+] {}:{} is open", result.ip, result.port);
    
    if let Some(service) = &result.service {
        output.push_str(&format!("\n    Service: {}", service.name));
        if let Some(version) = &service.version {
            output.push_str(&format!("\n    Version: {}", version));
        }
        if let Some(product) = &service.product {
            output.push_str(&format!("\n    Product: {}", product));
        }
        if let Some(os_type) = &service.os_type {
            output.push_str(&format!("\n    OS: {}", os_type));
        }
        if let Some(extra_info) = &service.extra_info {
            if !extra_info.is_empty() && extra_info.len() < 100 {
                output.push_str(&format!("\n    Extra: {}", extra_info));
            }
        }
    } else {
        output.push_str("\n    Service: unknown (please report fingerprint on issues)");
    }
    
    output
} 
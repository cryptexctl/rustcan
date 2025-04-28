# Rustcan Implementation Guide

## Core Scanning Functionality

### Scanner Implementation
Located in `scanner.rs`, the scanner module provides:
- Async TCP connection scanning
- Concurrent port scanning
- Timeout handling
- Resource management

### Service Detection
Located in `service_detection.rs`, implements:
- Protocol-specific probes
- Response pattern matching
- Service fingerprinting
- Version detection

### Pattern Matching
Located in `patterns.rs`, handles:
- Scanning pattern definitions
- Response analysis
- Service identification
- Protocol detection

## Key Components

### 1. Scanner Engine
```rust
pub struct Scanner {
    target: Target,
    ports: PortRange,
    concurrency: usize,
    timeout: Duration,
}
```

Features:
- Async scanning with Tokio
- Concurrent connection handling
- Resource management
- Progress reporting

### 2. Service Detection
```rust
pub struct ServiceDetector {
    patterns: Vec<ServicePattern>,
    timeout: Duration,
}
```

Features:
- Protocol-specific probes
- Pattern matching
- Service identification
- Version detection

### 3. DNS Resolution
```rust
pub struct DnsResolver {
    resolver: AsyncResolver,
}
```

Features:
- Async DNS resolution
- Hostname validation
- IP range expansion
- Reverse DNS lookups

## Implementation Patterns

### 1. Async/Await Pattern
```rust
async fn scan_port(&self, target: IpAddr, port: u16) -> Result<ScanResult> {
    let socket = TcpStream::connect((target, port)).await?;
    // ... scanning logic
}
```

### 2. Concurrent Scanning
```rust
async fn scan_range(&self, targets: Vec<IpAddr>, ports: PortRange) -> Vec<ScanResult> {
    let mut results = Vec::new();
    let semaphore = Arc::new(Semaphore::new(self.concurrency));
    
    for target in targets {
        for port in ports {
            let permit = semaphore.clone().acquire_owned().await?;
            // ... scanning logic
        }
    }
    results
}
```

### 3. Service Detection
```rust
async fn detect_service(&self, target: IpAddr, port: u16) -> Result<ServiceInfo> {
    let mut socket = TcpStream::connect((target, port)).await?;
    // ... service detection logic
}
```

## Error Handling

### 1. Custom Error Types
```rust
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("Connection failed: {0}")]
    ConnectionError(#[from] std::io::Error),
    #[error("Timeout: {0}")]
    TimeoutError(String),
    // ... other error variants
}
```

### 2. Error Propagation
```rust
async fn scan(&self) -> Result<Vec<ScanResult>> {
    let results = self.scan_range().await?;
    Ok(results)
}
```

## Logging and Monitoring

### 1. Structured Logging
```rust
tracing::info!("Starting scan for target: {}", target);
tracing::debug!("Scanning port {} on {}", port, target);
```

### 2. Progress Reporting
```rust
let progress = ProgressBar::new(total_ports as u64);
progress.set_style(ProgressStyle::default_bar()
    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
    .progress_chars("#>-"));
```

## Testing

### 1. Unit Tests
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_port_scan() {
        // ... test implementation
    }
}
```

### 2. Integration Tests
```rust
#[cfg(test)]
mod integration {
    use super::*;
    
    #[tokio::test]
    async fn test_full_scan() {
        // ... test implementation
    }
}
```

## Performance Optimization

1. **Concurrency Control**
   - Semaphore-based limiting
   - Resource management
   - Backpressure handling

2. **Memory Management**
   - Efficient data structures
   - Stream processing
   - Buffer management

3. **Network Optimization**
   - Connection pooling
   - Timeout handling
   - Retry mechanisms 
# Rustcan

A fast port scanner written in Rust, inspired by Nmap and Masscan.

## Features

- Fast asynchronous port scanning
- DNS resolution support
- CIDR notation support
- Service detection for common protocols (HTTP, HTTPS, SSH, FTP, SMTP, DNS)
- Progress bar with ETA
- JSON output format
- Configurable concurrency and timeout

## Installation

```bash
cargo install --path .
```

## Usage

Basic scan:
```bash
rustcan --target example.com --ports 1-1000
```

Scan with service detection:
```bash
rustcan --target example.com --ports 80-443 --service-detection
```

Scan subnet:
```bash
rustcan --target 192.168.1.1 --ports 1-65535 --service-detection --subnet
```

## Options

- `--target`: Target IP address, CIDR notation, or domain name
- `--ports`: Port range (e.g. 1-1000)
- `--concurrency`: Number of concurrent scans (default: 1000)
- `--service-detection`: Enable service detection
- `--output-format`: Output format (text or json, default: text)
- `--timeout`: Timeout in milliseconds (default: 1000)

## License

MIT 

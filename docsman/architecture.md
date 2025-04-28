# Rustcan Architecture

## System Overview

Rustcan is a high-performance port scanner built with Rust, utilizing modern async programming patterns and efficient network scanning techniques.

## Core Components

### 1. Scanner Engine
- Located in `scanner.rs`
- Implements the core scanning functionality
- Uses async/await for concurrent scanning
- Supports various scanning patterns and techniques

### 2. Service Detection
- Located in `service_detection.rs`
- Implements service fingerprinting
- Uses pattern matching to identify services
- Supports multiple protocol detection

### 3. Pattern Matching
- Located in `patterns.rs`
- Defines scanning patterns and strategies
- Implements service detection patterns
- Handles response analysis

### 4. DNS Resolution
- Located in `dns.rs`
- Handles hostname resolution
- Uses trust-dns-resolver for async DNS queries
- Supports both IPv4 and IPv6

### 5. CLI Interface
- Located in `main.rs`
- Implements command-line interface
- Uses clap for argument parsing
- Provides progress reporting and output formatting

## Async Runtime

The project uses Tokio as its async runtime, providing:
- Efficient task scheduling
- Non-blocking I/O operations
- Concurrent scanning capabilities
- Resource management

## Concurrency Model

- Uses async/await for concurrent operations
- Implements worker pools for scanning tasks
- Utilizes channels for communication between components
- Implements backpressure mechanisms

## Network Scanning Patterns

1. **TCP Connect Scan**
   - Standard TCP connection attempt
   - Reliable but slower than other methods

2. **Service Detection**
   - Protocol-specific probes
   - Response pattern matching
   - Version detection

3. **DNS Resolution**
   - Async hostname resolution
   - Reverse DNS lookups
   - IP range expansion

## Data Flow

1. Input Processing
   - Command-line arguments
   - Target specification
   - Scan options

2. Target Resolution
   - DNS resolution
   - IP range expansion
   - Port specification

3. Scanning Process
   - Concurrent connection attempts
   - Response collection
   - Service detection

4. Output Generation
   - Progress reporting
   - Result formatting
   - Error handling

## Error Handling

- Uses anyhow for error propagation
- Implements custom error types
- Provides detailed error messages
- Graceful error recovery

## Logging and Monitoring

- Uses tracing for structured logging
- Implements progress reporting
- Provides detailed scan statistics
- Supports different log levels 
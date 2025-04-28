# Rustcan Documentation

This directory contains comprehensive documentation about Rustcan, a fast and efficient port scanner written in Rust.

## Table of Contents

1. [Architecture Overview](architecture.md)
   - System design and components
   - Async runtime and concurrency model
   - Network scanning patterns

2. [Implementation Guide](implementation.md)
   - Core scanning functionality
   - Service detection
   - DNS resolution
   - Pattern matching

3. [Technical Details](technical.md)
   - Network protocols support
   - Async programming with Tokio
   - Error handling and logging
   - Performance optimizations

4. [Performance Analysis](performance.md)
   - Benchmarking results
   - Comparison with other tools
   - Optimization techniques

5. [Security Considerations](security.md)
   - Network security implications
   - Best practices
   - Legal considerations

6. [Contributing Guide](contributing.md)
   - How to contribute
   - Code style guide
   - Testing guidelines

## Project Structure

- `src/`
  - `main.rs` - CLI interface and main program logic
  - `scanner.rs` - Core scanning functionality
  - `patterns.rs` - Pattern matching and service detection
  - `service_detection.rs` - Service detection logic
  - `dns.rs` - DNS resolution utilities
  - `types.rs` - Common types and structures
  - `utils.rs` - Utility functions
  - `lib.rs` - Library interface

## Dependencies

- tokio - Async runtime
- clap - Command-line argument parsing
- anyhow - Error handling
- indicatif - Progress reporting
- serde - Serialization
- tracing - Logging
- trust-dns-resolver - DNS resolution
- ipnetwork - IP address handling

## Quick Links

- [Main Project README](../README.md)
- [GitHub Repository](https://github.com/systemxplore/rustcan)
- [Issue Tracker](https://github.com/systemxplore/rustcan/issues) 
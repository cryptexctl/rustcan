# Contributing to Rustcan

## Development Setup

### 1. Prerequisites
- Rust 1.70 or later
- Cargo
- Git
- Basic understanding of networking concepts

### 2. Getting Started
```bash
# Clone the repository
git clone https://github.com/systemxplore/rustcan.git
cd rustcan

# Install dependencies
cargo build

# Run tests
cargo test
```

### 3. Development Environment
- Recommended IDE: VS Code with Rust Analyzer
- Code formatting: rustfmt
- Linting: clippy
- Documentation: rustdoc

## Code Style Guide

### 1. Rust Conventions
```rust
// Use snake_case for functions and variables
fn scan_port(target: &str, port: u16) -> Result<()> {
    // ...
}

// Use PascalCase for types and traits
struct Scanner {
    // ...
}

// Use SCREAMING_SNAKE_CASE for constants
const MAX_CONNECTIONS: usize = 1000;
```

### 2. Documentation
```rust
/// Scans a single port on the target host.
///
/// # Arguments
///
/// * `target` - The target host to scan
/// * `port` - The port number to scan
///
/// # Returns
///
/// Returns `Ok(())` if the port is open, `Err` otherwise.
pub async fn scan_port(target: &str, port: u16) -> Result<()> {
    // ...
}
```

### 3. Error Handling
```rust
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("Connection failed: {0}")]
    ConnectionError(#[from] std::io::Error),
    #[error("Timeout: {0}")]
    TimeoutError(String),
}
```

## Testing Guidelines

### 1. Unit Tests
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_port_scan() {
        let scanner = Scanner::new(/* ... */);
        let result = scanner.scan_port(/* ... */).await;
        assert!(result.is_ok());
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
        let scanner = Scanner::new(/* ... */);
        let results = scanner.scan().await;
        assert!(!results.is_empty());
    }
}
```

### 3. Performance Tests
```rust
#[cfg(test)]
mod benchmarks {
    use super::*;
    use test::Bencher;
    
    #[bench]
    fn bench_port_scan(b: &mut Bencher) {
        b.iter(|| {
            // Benchmark code
        });
    }
}
```

## Pull Request Process

### 1. Before Submitting
- Run all tests
- Check code formatting
- Update documentation
- Add new tests if needed

### 2. Pull Request Template
```markdown
## Description
[Description of changes]

## Related Issues
[Link to related issues]

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Performance tests added/updated

## Documentation
- [ ] Code comments added/updated
- [ ] Documentation updated
- [ ] README updated if needed
```

### 3. Review Process
- Code review by maintainers
- CI/CD pipeline checks
- Performance impact assessment
- Security review

## Development Workflow

### 1. Branching Strategy
- `main` - Stable release branch
- `develop` - Development branch
- `feature/*` - Feature branches
- `bugfix/*` - Bug fix branches

### 2. Commit Messages
```
feat: add new scanning feature
fix: resolve connection timeout issue
docs: update API documentation
test: add integration tests
chore: update dependencies
```

### 3. Release Process
- Version bump
- Changelog update
- Documentation update
- Release notes

## Project Structure

### 1. Source Code
```
src/
├── main.rs         # CLI interface
├── scanner.rs      # Core scanning logic
├── patterns.rs     # Pattern matching
├── service_detection.rs # Service detection
├── dns.rs          # DNS resolution
├── types.rs        # Common types
├── utils.rs        # Utility functions
└── lib.rs          # Library interface
```

### 2. Tests
```
tests/
├── unit/           # Unit tests
├── integration/    # Integration tests
└── benchmarks/     # Performance tests
```

### 3. Documentation
```
docs/
├── api/            # API documentation
├── examples/       # Code examples
└── guides/         # User guides
```

## Community Guidelines

### 1. Communication
- Use GitHub issues for bug reports
- Use discussions for questions
- Follow the code of conduct
- Be respectful and professional

### 2. Contribution Types
- Bug reports
- Feature requests
- Documentation updates
- Code improvements
- Performance optimizations

### 3. Getting Help
- Check documentation
- Search existing issues
- Ask in discussions
- Contact maintainers 
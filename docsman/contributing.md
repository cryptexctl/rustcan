# Contributing Guide

## Getting Started

### 1. Prerequisites
- Rust 1.70 or later
- Git
- Basic understanding of network programming
- Familiarity with async programming

### 2. Development Setup
```bash
# Clone the repository
git clone https://github.com/yourusername/rustcan.git
cd rustcan

# Install dependencies
cargo build

# Run tests
cargo test
```

## Code Style

### 1. Rust Style Guide
- Follow Rust standard style guide
- Use `rustfmt` for formatting
- Follow clippy recommendations
- Document public APIs

### 2. Code Organization
```
src/
├── main.rs           # Entry point
├── scanner/          # Core scanning logic
├── network/          # Network operations
├── utils/           # Utility functions
└── error.rs         # Error handling
```

### 3. Documentation
```rust
/// Scans a single port on the target host
///
/// # Arguments
///
/// * `addr` - The target address to scan
/// * `timeout` - Connection timeout duration
///
/// # Returns
///
/// * `Result<Option<u16>>` - The open port number if found
///
/// # Examples
///
/// ```
/// let addr = "127.0.0.1:80".parse().unwrap();
/// let result = scan_port(addr, Duration::from_secs(1)).await?;
/// ```
```

## Testing

### 1. Unit Tests
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_port_scan() {
        let addr = "127.0.0.1:80".parse().unwrap();
        let result = scan_port(addr, Duration::from_secs(1)).await.unwrap();
        assert!(result.is_some());
    }
}
```

### 2. Integration Tests
```rust
#[tokio::test]
async fn test_full_scan() {
    let scanner = Scanner::new("127.0.0.1", 80..81);
    let results = scanner.run().await.unwrap();
    assert!(!results.is_empty());
}
```

### 3. Performance Tests
```rust
#[tokio::test]
async fn test_performance() {
    let start = std::time::Instant::now();
    let scanner = Scanner::new("127.0.0.1", 1..1024);
    scanner.run().await.unwrap();
    assert!(start.elapsed() < Duration::from_secs(5));
}
```

## Pull Request Process

### 1. Before Submitting
- Update documentation
- Add tests
- Run linter
- Check formatting

### 2. Pull Request Template
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added
- [ ] Integration tests added
- [ ] Performance tests added

## Checklist
- [ ] Code follows style guide
- [ ] Documentation updated
- [ ] Tests pass
- [ ] No breaking changes
```

### 3. Review Process
- Code review
- Performance review
- Security review
- Documentation review

## Feature Development

### 1. Feature Branch
```bash
git checkout -b feature/new-feature
```

### 2. Development Cycle
1. Write tests
2. Implement feature
3. Run tests
4. Update documentation
5. Create pull request

### 3. Code Review
- Follow review guidelines
- Address feedback
- Update code as needed
- Resolve conflicts

## Release Process

### 1. Version Bumping
```bash
# Update version in Cargo.toml
cargo version patch  # or minor/major
```

### 2. Release Checklist
- [ ] Update version
- [ ] Update changelog
- [ ] Run all tests
- [ ] Build release
- [ ] Create tag
- [ ] Push release

### 3. Documentation Updates
- Update README
- Update API docs
- Update examples
- Update changelog

## Community Guidelines

### 1. Communication
- Be respectful
- Be constructive
- Follow code of conduct
- Help others

### 2. Issue Reporting
- Use issue template
- Provide reproduction steps
- Include system info
- Add logs if relevant

### 3. Code Review
- Be thorough
- Be constructive
- Explain suggestions
- Follow guidelines

## Resources

### 1. Documentation
- [Rust Book](https://doc.rust-lang.org/book/)
- [Tokio Guide](https://tokio.rs/tokio/tutorial)
- [Async Book](https://rust-lang.github.io/async-book/)

### 2. Tools
- [rustfmt](https://github.com/rust-lang/rustfmt)
- [clippy](https://github.com/rust-lang/rust-clippy)
- [cargo-edit](https://github.com/killercup/cargo-edit)

### 3. Community
- [Rust Users Forum](https://users.rust-lang.org/)
- [Rust Discord](https://discord.gg/rust-lang)
- [Rust Reddit](https://www.reddit.com/r/rust/) 
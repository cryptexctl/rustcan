# Rustcan Architecture Overview

## System Design

Rustcan is designed with a focus on performance, reliability, and extensibility. The architecture follows these key principles:

1. **Asynchronous First**
   - Built on Tokio runtime for efficient async I/O
   - Non-blocking network operations
   - Efficient resource utilization

2. **Modular Design**
   - Clear separation of concerns
   - Pluggable components
   - Easy to extend functionality

3. **Resource Management**
   - Controlled concurrency
   - Memory efficiency
   - Graceful error handling

## Core Components

### 1. Scanner Engine
```rust
pub struct Scanner {
    target: Target,
    ports: PortRange,
    concurrency: usize,
    timeout: Duration,
}
```

- Handles the core scanning logic
- Manages concurrent connections
- Implements timeout handling
- Controls resource usage

### 2. Target Management
```rust
pub enum Target {
    Single(IpAddr),
    Network(IpNetwork),
    File(PathBuf),
}
```

- Supports various target types
- Handles IP address parsing
- Manages CIDR notation
- Supports file-based input

### 3. Port Management
```rust
pub struct PortRange {
    start: u16,
    end: u16,
}
```

- Manages port ranges
- Validates port numbers
- Handles port scanning strategies

## Data Flow

1. **Input Processing**
   ```
   Command Line Args → Target Parser → IP List
   ```

2. **Scanning Process**
   ```
   IP List → Port Range → Concurrent Tasks → Results
   ```

3. **Output Generation**
   ```
   Results → Progress Bar → Console Output
   ```

## Key Design Decisions

### 1. Async/Await Pattern
- Uses Tokio for async runtime
- Efficient resource utilization
- Non-blocking I/O operations

### 2. Concurrency Control
- Semaphore-based concurrency limiting
- Controlled resource usage
- Prevents system overload

### 3. Error Handling
- Graceful error recovery
- Detailed error reporting
- User-friendly error messages

## Future Extensions

1. **Protocol Support**
   - UDP scanning
   - Custom protocols
   - Service detection

2. **Output Formats**
   - JSON output
   - XML output
   - Custom formats

3. **Advanced Features**
   - OS detection
   - Service versioning
   - Vulnerability scanning 
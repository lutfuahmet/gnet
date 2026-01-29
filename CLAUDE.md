# CLAUDE.md - gnet Developer Guide

## Project Overview

gnet is a high-performance, lightweight, non-blocking, event-driven networking framework written in pure Go. It's built from scratch using epoll (Linux) and kqueue (macOS/BSD) for efficient network I/O.

**Key characteristics:**
- Event-driven architecture with multiple event-loops
- Lock-free during entire runtime
- Supports TCP, UDP, and Unix Domain Sockets
- Non-blocking TLS support with buffer-based I/O
- Cross-platform: Linux, macOS, Windows, BSD variants
- Ranked #1 in Go on TechEmpower Benchmarks

gnet is not designed to replace Go's standard `net` library but to provide an alternative for performance-critical network services where developers implement application-layer protocols (HTTP, RPC, WebSocket, Redis) on top.

## Architecture

### Core Components

```
┌─────────────────────────────────────────────────────────┐
│                       Engine                             │
│  (Manages event-loops, listeners, load balancing)        │
├─────────────────────────────────────────────────────────┤
│     EventLoop 1    │    EventLoop 2    │   EventLoop N  │
│   ┌───────────┐    │  ┌───────────┐    │ ┌───────────┐  │
│   │  Poller   │    │  │  Poller   │    │ │  Poller   │  │
│   │(epoll/kq) │    │  │(epoll/kq) │    │ │(epoll/kq) │  │
│   └───────────┘    │  └───────────┘    │ └───────────┘  │
│   ┌───────────┐    │  ┌───────────┐    │ ┌───────────┐  │
│   │   Conns   │    │  │   Conns   │    │ │   Conns   │  │
│   └───────────┘    │  └───────────┘    │ └───────────┘  │
├─────────────────────────────────────────────────────────┤
│                    Listeners                             │
│           (Accept connections, load balance)             │
└─────────────────────────────────────────────────────────┘
```

### Key Interfaces

1. **EventHandler** - Main interface for application logic:
   - `OnBoot(eng Engine)` - Called when engine starts
   - `OnShutdown(eng Engine)` - Called when engine stops
   - `OnOpen(c Conn)` - Called when connection opens
   - `OnClose(c Conn, err error)` - Called when connection closes
   - `OnTraffic(c Conn)` - Called when data arrives
   - `OnTick()` - Called on timer intervals

2. **Conn** - Connection interface combining Reader, Writer, and Socket interfaces

3. **Engine** - Main engine interface for connection management and shutdown

4. **EventLoop** - Per-loop interface for registering and managing connections

## Directory Structure

```
gnet/
├── *.go                    # Core implementation files
├── internal/
│   └── gfd/                # Gnet File Descriptor wrapper
├── pkg/
│   ├── buffer/             # Buffer implementations
│   │   ├── ring/           # Circular ring buffer
│   │   ├── elastic/        # Elastic ring and mixed buffers
│   │   └── linkedlist/     # Linked-list buffer
│   ├── errors/             # Error types and constants
│   ├── io/                 # Platform-specific I/O operations
│   ├── logging/            # Zap-based logging with rotation
│   ├── math/               # Utility math functions
│   ├── netpoll/            # Event polling (epoll/kqueue)
│   ├── pool/               # Object pooling
│   │   ├── bytebuffer/     # Byte buffer pool
│   │   ├── byteslice/      # Byte slice pool
│   │   ├── goroutine/      # Goroutine pool (ants)
│   │   └── ringbuffer/     # Ring buffer pool
│   ├── queue/              # Lock-free queue implementations
│   ├── socket/             # Socket operations and wrappers
│   └── bs/                 # Byte string utilities
└── .github/
    └── workflows/          # CI/CD pipelines
```

## Key Files

| File | Description |
|------|-------------|
| `gnet.go` | Main API: interfaces, types, Run/Stop functions |
| `options.go` | Configuration options (30+ settings) |
| `connection_unix.go` | Unix connection implementation |
| `eventloop_unix.go` | Event loop implementation |
| `engine_unix.go` | Engine implementation |
| `listener_unix.go` | Listener/acceptor logic |
| `client_unix.go` | Client functionality |
| `load_balancer.go` | Load balancing algorithms |
| `acceptor_unix.go` | Connection acceptance |
| `tls.go` | TLS types and interfaces |
| `tls_nonblocking.go` | Non-blocking TLS implementation |
| `connection_tls.go` | TLS handshake functions |
| `pkg/netpoll/poller_*.go` | Platform-specific polling |

## Build Commands

```bash
# Build
go build ./...

# Run tests
go test $(go list ./... | tail -n +2)

# Run tests with race detection and coverage
go test -v -race -coverprofile="codecov.report" -covermode=atomic -timeout 15m

# Run specific package tests
go test ./pkg/buffer/ring
go test ./pkg/netpoll

# Lint (requires golangci-lint)
golangci-lint run -v -E gocritic -E misspell -E revive -E godot --timeout 5m
```

**Requirements:** Go 1.20+

## Development Workflow

### Branch Strategy
- `dev` - Main development branch
- `master` - Stable releases
- `1.x` - Legacy v1 branch

### CI/CD Pipelines
- **test.yml** - Primary testing (Go 1.20, 1.25 on Linux/macOS/Windows)
- **codeql.yml** - Security analysis
- **test_poll_opt.yml** - Polling optimization tests
- **cross-compile-bsd.yml** - BSD cross-compilation

### Testing Patterns

Tests use testify for assertions and cover:
- TCP, UDP, Unix socket protocols
- Single and multi-loop configurations
- Async and sync writes
- Various client counts and payloads
- Race conditions (via `-race` flag)

## Code Patterns

### Options Pattern
```go
type Option func(opts *Options)
func Run(eventHandler EventHandler, protoAddr string, opts ...Option) error
```

### Platform Abstraction
- Build tags separate platform code: `_unix.go`, `_windows.go`, `_linux.go`, `_bsd.go`
- netpoll package abstracts epoll/kqueue
- socket package wraps platform syscalls

### Memory Management
- Buffer pooling (bytebuffer, byteslice, ringbuffer)
- Elastic buffer growth (4KB threshold)
- Connection matrix for O(1) lookups

### Concurrency
- Lock-free design during runtime
- Queue-based cross-loop communication
- Goroutine pool via ants library

### Logging
Configure via environment variables:
- `GNET_LOGGING_LEVEL` - debug/info/warn/error
- `GNET_LOGGING_FILE` - Optional file path

## TLS Support

gnet provides non-blocking TLS support that maintains the event-driven architecture without blocking the event loop.

### TLS Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Event Loop (Non-blocking)                      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  READ PATH:                                                             │
│  ┌──────────┐    ┌───────────────┐    ┌──────────────┐    ┌──────────┐ │
│  │ Socket   │───>│ bufferConn    │───>│ TLS Record   │───>│ tls.Conn │ │
│  │ unix.Read│    │ (ring buffer) │    │ Parser       │    │ .Read()  │ │
│  │ EAGAIN OK│    └───────────────┘    │ (complete?)  │    │(buffered)│ │
│  └──────────┘           │             └──────┬───────┘    └────┬─────┘ │
│                         │                    │                  │       │
│                         │             NO: wait│         YES: decrypt    │
│                         └────────────────────┘                  │       │
│                                                                 v       │
│  WRITE PATH:                                           ┌──────────────┐ │
│  ┌──────────┐    ┌───────────────┐    ┌──────────────┐ │ OnTraffic()  │ │
│  │ App data │───>│ tls.Conn      │───>│ bufferConn   │ │ c.Read()     │ │
│  │ Write()  │    │ encrypts      │    │ .writeBuf    │ └──────────────┘ │
│  └──────────┘    └───────────────┘    └──────┬───────┘                  │
│                                              │                          │
│                                              v                          │
│                                      ┌──────────────┐    ┌──────────┐  │
│                                      │ outbound     │───>│ Socket   │  │
│                                      │ buffer       │    │unix.Write│  │
│                                      └──────────────┘    │EAGAIN OK │  │
│                                                          └──────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

### Key Components

| Component | File | Description |
|-----------|------|-------------|
| `tlsNonBlockingState` | `tls_nonblocking.go` | Manages non-blocking TLS I/O state |
| `bufferConn` | `tls_nonblocking.go` | `net.Conn` backed by elastic buffers |
| `checkCompleteRecord` | `tls_nonblocking.go` | TLS record framing for complete records |
| `TLSState` | `tls.go` | Connection TLS state enum |
| `TLSConn` | `tls.go` | Interface for TLS-enabled connections |

### Server Usage

```go
// Generate or load TLS certificate
cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
if err != nil {
    log.Fatal(err)
}

tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
}

// Start server with TLS
err = gnet.Run(handler, "tcp://:8443",
    gnet.WithTLSConfig(tlsConfig),
    gnet.WithTLSHandshakeTimeout(30*time.Second),
)
```

### Client Usage

```go
tlsConfig := &tls.Config{
    InsecureSkipVerify: true, // For testing only
}

client, err := gnet.NewClient(handler,
    gnet.WithTLSConfig(tlsConfig),
)
if err != nil {
    log.Fatal(err)
}

client.Start()
defer client.Stop()

// Connect with TLS
conn, err := client.Dial("tcp", "localhost:8443")

// Or use explicit TLS dial
conn, err := client.DialTLS("tcp", "localhost:8443", tlsConfig)
```

### TLS Options

| Option | Description | Default |
|--------|-------------|---------|
| `WithTLSConfig(config)` | Set TLS configuration | `nil` (no TLS) |
| `WithTLSHandshakeTimeout(d)` | Maximum handshake duration | 30 seconds |

### TLS Connection State

```go
// Check TLS state via type assertion
if tc, ok := conn.(gnet.TLSConn); ok {
    state := tc.TLSState()
    switch state {
    case gnet.TLSStateNone:
        // No TLS
    case gnet.TLSStateHandshaking:
        // Handshake in progress
    case gnet.TLSStateComplete:
        // TLS established
        connState := tc.TLSConnectionState()
        fmt.Println("Protocol:", connState.NegotiatedProtocol)
    case gnet.TLSStateFailed:
        // Handshake failed
    }
}
```

### Implementation Notes

1. **Handshake**: Performed in goroutine pool to avoid blocking event loop
2. **Post-handshake I/O**: Uses buffer-based non-blocking approach
3. **Record framing**: Only decrypts when complete TLS records are available
4. **EAGAIN handling**: Properly handles non-blocking socket operations

## Using This Fork

This fork includes non-blocking TLS support not yet available in the upstream gnet. To use it in your project:

### Add to go.mod

```go
module your-project

go 1.20

require (
    github.com/panjf2000/gnet/v2 v2.7.2
)

replace github.com/panjf2000/gnet/v2 => github.com/lutfuahmet/gnet/v2 v2.7.2
```

### Or use go get

```bash
# Get the latest from dev branch
go get github.com/lutfuahmet/gnet/v2@dev

# Then add replace directive
```

### Import in your code

```go
import "github.com/panjf2000/gnet/v2"

// The replace directive ensures it uses the fork
```

### Update to latest

```bash
go get github.com/lutfuahmet/gnet/v2@dev
go mod tidy
```

## Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/panjf2000/ants/v2` | Goroutine pool |
| `github.com/stretchr/testify` | Testing assertions |
| `github.com/valyala/bytebufferpool` | Byte buffer pooling |
| `go.uber.org/zap` | Structured logging |
| `golang.org/x/sync` | Synchronization primitives |
| `golang.org/x/sys` | System calls |
| `gopkg.in/natefinch/lumberjack.v2` | Log rotation |

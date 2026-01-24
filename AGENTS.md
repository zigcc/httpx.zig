# AGENTS.md - httpx.zig LLM Code Modification Guide

## Project Overview

**httpx.zig** is a production-ready, high-performance HTTP server library for Zig, supporting HTTP/1.1, HTTP/2, HTTP/3 (experimental), and WebSocket protocols.

### Key Characteristics
- **Language**: Zig (requires 0.15.0+)
- **Architecture**: Modular design with clear separation of concerns
- **Paradigm**: Zero-allocation where possible, explicit memory management
- **Style**: Compile-time string conversion, fluent builder APIs

---
## Testing Guidelines

### Writing Tests

```zig
test "descriptive test name" {
    const allocator = std.testing.allocator;
    
    // Setup
    var obj = MyStruct.init(allocator);
    defer obj.deinit();
    
    // Action
    const result = try obj.doSomething();
    
    // Assert
    try std.testing.expectEqual(expected, result);
    try std.testing.expectEqualStrings("expected", actual);
    try std.testing.expect(condition);
    try std.testing.expectError(error.SomeError, fallible_call());
}
```

### Running Tests

```bash
# Run all tests
zig build test

# Run with verbose output
zig build test -- --verbose
```

### Running Benchmarks

```bash
zig build bench
```

---

## Build Commands

```bash
# Build library
zig build

# Build and run specific example
zig build run-simple_server
zig build run-websocket_server
zig build run-router_example

# Run all non-blocking examples
zig build run-all-examples

# Build for specific target
zig build -Dtarget=x86_64-linux
zig build -Dtarget=aarch64-macos

# Build all cross-compilation targets
zig build build-all-targets

# Generate documentation
zig build docs
```

---

## Platform-Specific Notes

### Windows
- Requires linking `ws2_32` and `mswsock` system libraries
- Uses IOCP for async I/O (in io/poller.zig)

### Linux
- Uses epoll for async I/O
- Supports io_uring (if available)

### macOS
- Uses kqueue for async I/O

this library is not for http client, just for http server

---

## Important Type Exports

The main `src/httpx.zig` file exports all public types. When adding new types:

1. Import the module:
```zig
pub const my_module = @import("path/to/module.zig");
```

2. Export specific types:
```zig
pub const MyType = my_module.MyType;
pub const myFunction = my_module.myFunction;
```

---

## WebSocket Implementation Notes

### Frame Structure (RFC 6455)
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-------+-+-------------+-------------------------------+
|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
|N|V|V|V|       |S|             |   (if payload len==126/127)   |
| |1|2|3|       |K|             |                               |
+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
```

### Key Constants
- `WEBSOCKET_GUID`: Magic string for handshake
- `MAX_CONTROL_FRAME_PAYLOAD`: 125 bytes
- `DEFAULT_MAX_PAYLOAD_SIZE`: 16 MB

---

## HTTP/2 Implementation Notes

### HPACK Header Compression
- Static table: 61 predefined headers
- Dynamic table: configurable size (default 4096 bytes)
- Huffman encoding support

### Stream Management
- Stream states: idle, open, half-closed, closed
- Flow control with window updates
- Priority handling

---

## Code Review Checklist

Before submitting changes:

- [ ] All tests pass (`zig build test`)
- [ ] No memory leaks (use `std.testing.allocator`)
- [ ] Proper error handling (no silent failures)
- [ ] Documentation comments for public APIs
- [ ] Consistent naming conventions
- [ ] No `@import("std").debug.print` in production code paths
- [ ] Proper `defer`/`errdefer` for resource cleanup
- [ ] Cross-platform compatibility considered

---

## Common Pitfalls

1. **Forgetting to deinit**: Always pair `init()` with `defer obj.deinit()`

2. **Memory ownership**: Be clear about who owns allocated memory; use `*_owned` flags

3. **Slice lifetimes**: Slices don't own data; ensure underlying data outlives the slice

4. **Error union propagation**: Use `try` or handle errors explicitly

5. **Comptime vs runtime**: Be aware of when values are known at compile time

6. **Cross-platform differences**: Test on multiple platforms or use abstraction layers


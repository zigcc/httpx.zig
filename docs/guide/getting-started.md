# Getting Started

`httpx.zig` is a modern, feature-rich HTTP library for the Zig programming language. It is designed to be production-ready, supporting robust client and server implementations with focus on performance and developer experience.

## Features

- **Protocol Support**: HTTP/1.0, HTTP/1.1, HTTP/2, and HTTP/3 (QUIC).
- **Cross-Platform**: Works on Linux, Windows, macOS, and BSDs.
- **Client**:
    - Connection pooling and keep-alive.
    - Automatic retries with exponential backoff.
    - Request/Response interceptors.
    - Cookie management.
- **Server**:
    - Express.js inspired routing.
    - Middleware architecture.
    - Static file serving.
    - JSON helpers.
- **Concurrency**: Built-in thread pool and async primitives (`all`, `any`, `race`).
- **Security**: TLS/SSL support (via `std.crypto` or system libraries) with custom CA handling.

## Requirements

- **Zig Version**: 0.15.0 or later (tested on 0.15.2).
- **Operating System**: Windows, Linux, or macOS.

## Platform Support

| Platform | x86_64 | aarch64 |
|----------|--------|---------|
| Linux    | ✅     | ✅      |
| Windows  | ✅     | ✅      |
| macOS    | ✅     | ✅      |

## Next Steps

- Check out the [Installation](/guide/installation) guide to add `httpx.zig` to your project.
- Learn how to make [Basic Requests](/guide/client-basics) with the client.
- Set up a simple [Server](/guide/routing).

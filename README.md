# httpx.zig

This is a fork of https://github.com/muhammad-fiaz/httpx.zig !

**httpx.zig** is a production-ready, high-performance HTTP client and server library for the Zig programming language, designed for building modern, robust, and scalable networked applications.

---

## Features

- **Comprehensive HTTP Support**: Full implementation of HTTP/1.1, HTTP/2, and experimental HTTP/3.
- **Client & Server**: Includes both a high-level client and a flexible server implementation.
- **WebSocket API**: Full-featured client and server WebSocket support.
- **Asynchronous Core**: Built for high-concurrency and non-blocking I/O.
- **TLS/SSL**: Integrated TLS support for secure connections.
- **Extensible**: Support for middleware and interceptors to customize request/response handling.
- **Modern Zig API**: Designed with a focus on clarity, safety, and performance.

## Installation

To add `httpx.zig` to your project, add it as a dependency in your `build.zig.zon` file:

```zon
.{
    .name = "my-project",
    .version = "0.1.0",
    .dependencies = .{
        .httpx = .{
            .url = "https://github.com/zigcc/httpx.zig/archive/main.tar.gz",
            .hash = "<hash_of_the_tarball>", // Replace with the actual hash
        },
    },
}
```

Then, in your `build.zig`, add the dependency to your executable:

```zig
const httpx_dep = b.dependency("httpx", .{});
const httpx_module = httpx_dep.module("httpx");
exe.addModule("httpx", httpx_module);
```

## Quick Start

Here is a simple example of making a GET request:

```zig
const std = @import("std");
const httpx = @import("httpx");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize the client
    var client = httpx.Client.init(allocator);
    defer client.deinit();

    // Create a new GET request
    var request = try httpx.Request.init(allocator, .GET, "https://httpbin.org/get");
    defer request.deinit();

    // Add custom headers
    try request.headers.set("Accept", "application/json");
    try request.headers.set("User-Agent", "httpx.zig/1.0");

    // Send the request and get the response
    var response = try client.send(&request);
    defer response.deinit();

    // Print response details
    std.debug.print("Status: {}\n", .{response.status});
    const body = try response.body_string();
    std.debug.print("Body: {s}\n", .{body});
}
```

## API Overview

The library is structured into several key components:

- `httpx.Client`: A high-level client for sending HTTP requests.
- `httpx.Server`: A server for handling incoming HTTP connections.
- `httpx.Request`: Represents an HTTP request.
- `httpx.Response`: Represents an HTTP response.
- `httpx.Router`: A flexible router for mapping paths to handlers in the server.
- `httpx.websocket`: Provides WebSocket client and server functionality.

## License

MIT License - see [LICENSE](LICENSE) for details.

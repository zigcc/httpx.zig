# httpx.zig

This is a fork of https://github.com/muhammad-fiaz/httpx.zig !

**httpx.zig** is a production-ready, high-performance HTTP server library for the Zig programming language, designed for building modern, robust, and scalable networked applications.

---

## Features

- **Comprehensive HTTP Support**: Full implementation of HTTP/1.1, HTTP/2, and experimental HTTP/3.
- **WebSocket Server**: Full-featured WebSocket support (RFC 6455).
- **Asynchronous Core**: Built for high-concurrency and non-blocking I/O.
- **TLS/SSL**: Integrated TLS support for secure connections.
- **Extensible**: Support for middleware to customize request/response handling.
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

`httpx.zig` now uses ZIO as its async backend by default.
You can inspect this via `httpx.selectedAsyncBackend` and `httpx.zioEnabled`,
and access ZIO APIs directly from `httpx.zio`.

Legacy event-loop modules are removed; use `httpx.Server` with
`server.enableThreading(.{ .num_workers = ... })` for concurrency tuning.

## Quick Start

Here is a simple example of creating an HTTP server:

```zig
const std = @import("std");
const httpx = @import("httpx");

fn handleHello(ctx: *httpx.Context) !void {
    try ctx.json(.{ .message = "Hello, World!" }, .{});
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var server = try httpx.Server.init(allocator, .{ .port = 8080 });
    defer server.deinit();

    try server.get("/hello", handleHello);

    std.debug.print("Server listening on http://localhost:8080\n", .{});
    try server.listen();
}
```

## API Overview

The library is structured into several key components:

- `httpx.Server`: A server for handling incoming HTTP connections.
- `httpx.Request`: Represents an HTTP request.
- `httpx.Response`: Represents an HTTP response.
- `httpx.Router`: A flexible router for mapping paths to handlers in the server.
- `httpx.WebSocketConnection`: Server-side WebSocket connection handler.

## License

MIT License - see [LICENSE](LICENSE) for details.

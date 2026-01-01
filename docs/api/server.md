# Server API

The `httpx.zig` server module provides a robust, Express-inspired HTTP server with middleware support, routing, and proper context handling.

## Server

The `Server` struct manages the listener, router, and middleware processing.

### Initialization

```zig
const httpx = @import("httpx");

// Initialize with default config
var server = httpx.Server.init(allocator);
defer server.deinit();

// Initialize with custom config
var server = httpx.Server.initWithConfig(allocator, .{
    .port = 3000,
    .max_body_size = 1048576, // 1MB
});
```

### Configuration (`ServerConfig`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `host` | `[]const u8` | `"127.0.0.1"` | Interface to bind to. |
| `port` | `u16` | `8080` | Port to listen on. |
| `max_body_size` | `usize` | `10MB` | Max request body size. |
| `request_timeout_ms` | `u64` | `30000` | Timeout for request processing. |
| `keep_alive` | `bool` | `true` | Enable HTTP Keep-Alive. |
| `max_connections` | `u32` | `1000` | Max concurrent connections. |

### Methods

#### `listen`

Starts the server. This method blocks.

```zig
try server.listen();
```

#### `stop`

Stops the server gracefully.

```zig
server.stop();
```

#### `use`

Adds a middleware to the global stack.

```zig
try server.use(httpx.middleware.logger());
```

#### Routing

Methods to register route handlers:

- `get(path: []const u8, handler: Handler)`
- `post(path: []const u8, handler: Handler)`
- `put(path: []const u8, handler: Handler)`
- `delete(path: []const u8, handler: Handler)`
- `patch(path: []const u8, handler: Handler)`
- `route(method: Method, path: []const u8, handler: Handler)`

#### Route Groups

Organize routes with a common prefix.

```zig
var api = server.router.group("/api/v1");
try api.get("/users", listUsers);
try api.post("/users", createUser);
```

#### Custom 404 Handler

```zig
server.router.setNotFound(myNotFoundHandler);
```

## Context

The `Context` struct is passed to every route handler and middleware. It wraps the request and response objects.

### Fields

- `request`: Pointer to the `Request` object.
- `response`: `ResponseBuilder` for constructing the reply.
- `allocator`: Request-scoped allocator.

### Methods

#### Request Accessors

- `param(name: []const u8) ?[]const u8`: Get URL path parameter.
- `query(name: []const u8) ?[]const u8`: Get query parameter.
- `header(name: []const u8) ?[]const u8`: Get request header.

#### Response Helpers

These methods allow fluent response chaining.

- `status(code: u16) *Context`: Set status code.
- `setHeader(name: []const u8, value: []const u8) !void`: Set response header.
- `json(value: anytype) !Response`: Send JSON response.
- `text(data: []const u8) !Response`: Send plain text response.
- `html(data: []const u8) !Response`: Send HTML response.
- `file(path: []const u8) !Response`: Stream a file.
- `redirect(url: []const u8, code: u16) !Response`: Send redirect.

## Handlers

Handlers are functions that take a `*Context` and return a `!Response`.

```zig
fn myHandler(ctx: *httpx.Context) !httpx.Response {
    return ctx.json(.{ .message = "Hello World" });
}
```

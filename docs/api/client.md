# Client API

The `httpx.zig` client provides a powerful interface for making HTTP requests with support for HTTP/1.1, HTTP/2, and HTTP/3.

## Client

The `Client` struct is the main entry point for making requests. It manages connection pooling, cookies, and interceptors.

### Initialization

```zig
const httpx = @import("httpx");

// Initialize with default configuration
var client = httpx.Client.init(allocator);
defer client.deinit();

// Initialize with custom configuration
var client = httpx.Client.initWithConfig(allocator, .{
    .base_url = "https://api.example.com",
    .identify_user_agent = true,
});
defer client.deinit();
```

### Configuration (`ClientConfig`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `base_url` | `?[]const u8` | `null` | Base URL prepended to all requests. |
| `timeouts` | `Timeouts` | `{}` | Connection and read/write timeouts. |
| `retry_policy` | `RetryPolicy` | `{}` | Configuration for automatic retries. |
| `redirect_policy` | `RedirectPolicy` | `{}` | Configuration for handling redirects. |
| `default_headers` | `?[]const [2][]const u8` | `null` | Headers added to every request. |
| `user_agent` | `[]const u8` | `"httpx.zig/1.0"` | User-Agent header value. |
| `max_response_size` | `usize` | `100MB` | Maximum allowed response body size. |
| `follow_redirects` | `bool` | `true` | Whether to automatically follow redirects. |
| `verify_ssl` | `bool` | `true` | Whether to verify SSL certificates. |
| `http2_enabled` | `bool` | `true` | Enable HTTP/2 support. |
| `http3_enabled` | `bool` | `false` | Enable HTTP/3 support (experimental). |
| `pool_max_connections` | `u32` | `20` | Maximum connections in the pool. |
| `pool_max_per_host` | `u32` | `5` | Maximum connections to a single host. |

### methods

#### `request`

Makes a generic HTTP request.

```zig
pub fn request(self: *Self, method: Method, url: []const u8, options: RequestOptions) !Response
```

#### Convenience Methods

- `get(url: []const u8, options: RequestOptions) !Response`
- `post(url: []const u8, options: RequestOptions) !Response`
- `put(url: []const u8, options: RequestOptions) !Response`
- `delete(url: []const u8, options: RequestOptions) !Response`
- `patch(url: []const u8, options: RequestOptions) !Response`
- `head(url: []const u8, options: RequestOptions) !Response`
- `httpOptions(url: []const u8, options: RequestOptions) !Response`
- `addInterceptor(interceptor: Interceptor) !void`

### Request Options (`RequestOptions`)

Per-request overrides for configuration.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `headers` | `?[]const [2][]const u8` | `null` | Additional headers for this request. |
| `body` | `?[]const u8` | `null` | Raw request body. |
| `json` | `?[]const u8` | `null` | JSON string body (sets Content-Type). |
| `timeout_ms` | `?u64` | `null` | Request-specific timeout. |
| `follow_redirects` | `?bool` | `null` | Override client redirect setting. |

## Interceptors

Interceptors allow you to modify requests before they are sent or responses before they are returned.

### structure

```zig
pub const RequestInterceptor = *const fn (*Request, ?*anyopaque) anyerror!void;
pub const ResponseInterceptor = *const fn (*Response, ?*anyopaque) anyerror!void;

pub const Interceptor = struct {
    request_fn: ?RequestInterceptor = null,
    response_fn: ?ResponseInterceptor = null,
    context: ?*anyopaque = null,
};
```

### Usage

```zig
// Add an interceptor
try client.addInterceptor(.{
    .request_fn = myRequestInterceptor,
    .response_fn = myResponseInterceptor,
});
```

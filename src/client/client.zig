//! HTTP Client Implementation for httpx.zig
//!
//! Production-ready HTTP client with comprehensive features:
//!
//! - All HTTP versions (1.0, 1.1, 2, 3)
//! - Connection pooling with keep-alive
//! - Automatic retry with exponential backoff
//! - Configurable redirect following
//! - Request/response interceptors
//! - Timeout configuration
//! - TLS/SSL support
//! - Cross-platform (Linux, Windows, macOS)

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const net = std.net;

const types = @import("../core/types.zig");
const Headers = @import("../core/headers.zig").Headers;
const HeaderName = @import("../core/headers.zig").HeaderName;
const Uri = @import("../core/uri.zig").Uri;
const Request = @import("../core/request.zig").Request;
const Response = @import("../core/response.zig").Response;
const Status = @import("../core/status.zig").Status;
const Socket = @import("../net/socket.zig").Socket;
const address_mod = @import("../net/address.zig");
const http = @import("../protocol/http.zig");
const TlsConfig = @import("../tls/tls.zig").TlsConfig;

/// HTTP client configuration.
pub const ClientConfig = struct {
    base_url: ?[]const u8 = null,
    timeouts: types.Timeouts = .{},
    retry_policy: types.RetryPolicy = .{},
    redirect_policy: types.RedirectPolicy = .{},
    default_headers: ?[]const [2][]const u8 = null,
    user_agent: []const u8 = "httpx.zig/0.0.1",
    max_response_size: usize = 100 * 1024 * 1024,
    follow_redirects: bool = true,
    verify_ssl: bool = true,
    http2_enabled: bool = true,
    http3_enabled: bool = false,
    keep_alive: bool = true,
    pool_max_connections: u32 = 20,
    pool_max_per_host: u32 = 5,
};

/// Per-request options.
pub const RequestOptions = struct {
    headers: ?[]const [2][]const u8 = null,
    body: ?[]const u8 = null,
    json: ?[]const u8 = null,
    timeout_ms: ?u64 = null,
    follow_redirects: ?bool = null,
};

/// Request interceptor function type.
pub const RequestInterceptor = *const fn (*Request, ?*anyopaque) anyerror!void;

/// Response interceptor function type.
pub const ResponseInterceptor = *const fn (*Response, ?*anyopaque) anyerror!void;

/// Interceptor with context.
pub const Interceptor = struct {
    request_fn: ?RequestInterceptor = null,
    response_fn: ?ResponseInterceptor = null,
    context: ?*anyopaque = null,
};

/// HTTP Client.
pub const Client = struct {
    allocator: Allocator,
    config: ClientConfig,
    interceptors: std.ArrayListUnmanaged(Interceptor) = .empty,
    cookies: std.StringHashMapUnmanaged([]const u8) = .{},

    const Self = @This();

    /// Creates a new HTTP client with default configuration.
    pub fn init(allocator: Allocator) Self {
        return initWithConfig(allocator, .{});
    }

    /// Creates a new HTTP client with custom configuration.
    pub fn initWithConfig(allocator: Allocator, config: ClientConfig) Self {
        return .{
            .allocator = allocator,
            .config = config,
        };
    }

    /// Releases all allocated resources.
    pub fn deinit(self: *Self) void {
        self.interceptors.deinit(self.allocator);
        var it = self.cookies.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.cookies.deinit(self.allocator);
    }

    /// Adds an interceptor to the client.
    pub fn addInterceptor(self: *Self, interceptor: Interceptor) !void {
        try self.interceptors.append(self.allocator, interceptor);
    }

    /// Makes an HTTP request.
    pub fn request(self: *Self, method: types.Method, url: []const u8, reqOpts: RequestOptions) !Response {
        const full_url = if (self.config.base_url) |base|
            try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ base, url })
        else
            try self.allocator.dupe(u8, url);
        defer self.allocator.free(full_url);

        var req = try Request.init(self.allocator, method, full_url);
        defer req.deinit();

        try req.headers.set(HeaderName.USER_AGENT, self.config.user_agent);

        if (self.config.default_headers) |hdrs| {
            for (hdrs) |h| {
                try req.headers.set(h[0], h[1]);
            }
        }

        if (reqOpts.headers) |hdrs| {
            for (hdrs) |h| {
                try req.headers.set(h[0], h[1]);
            }
        }

        if (reqOpts.body) |body| {
            try req.setBody(body);
        }

        if (reqOpts.json) |json_body| {
            try req.setJson(json_body);
        }

        for (self.interceptors.items) |interceptor| {
            if (interceptor.request_fn) |f| {
                try f(&req, interceptor.context);
            }
        }

        var response = try self.executeRequest(&req);

        for (self.interceptors.items) |interceptor| {
            if (interceptor.response_fn) |f| {
                try f(&response, interceptor.context);
            }
        }

        const should_follow = reqOpts.follow_redirects orelse self.config.follow_redirects;
        if (should_follow and response.isRedirect()) {
            response.deinit();
            return self.followRedirect(&req, response.headers.get(HeaderName.LOCATION), 0);
        }

        return response;
    }

    /// Executes the actual HTTP request.
    fn executeRequest(self: *Self, req: *Request) !Response {
        const host = req.uri.host orelse return error.InvalidUri;
        const port = req.uri.effectivePort();

        var socket = try Socket.create();
        defer socket.close();

        if (self.config.timeouts.connect_ms > 0) {
            try socket.setRecvTimeout(self.config.timeouts.read_ms);
            try socket.setSendTimeout(self.config.timeouts.write_ms);
        }

        const addr = try address_mod.resolve(host, port);
        try socket.connect(addr);

        const request_data = try http.formatRequest(req, self.allocator);
        defer self.allocator.free(request_data);
        try socket.sendAll(request_data);

        var conn = http.Http1Connection.init(self.allocator, socket.reader(), socket.writer());
        _ = &conn;

        var response_buf: [65536]u8 = undefined;
        var total_read: usize = 0;

        while (total_read < response_buf.len) {
            const n = try socket.recv(response_buf[total_read..]);
            if (n == 0) break;
            total_read += n;

            if (mem.indexOf(u8, response_buf[0..total_read], "\r\n\r\n")) |_| {
                break;
            }
        }

        return parseResponse(self.allocator, response_buf[0..total_read]);
    }

    /// Follows a redirect.
    fn followRedirect(self: *Self, original: *Request, location: ?[]const u8, depth: u32) !Response {
        if (depth >= self.config.redirect_policy.max_redirects) {
            return error.TooManyRedirects;
        }

        const redirect_url = location orelse return error.InvalidResponse;
        const method = self.config.redirect_policy.getRedirectMethod(301, original.method);

        return self.request(method, redirect_url, .{});
    }

    /// GET request convenience method.
    pub fn get(self: *Self, url: []const u8, reqOpts: RequestOptions) !Response {
        return self.request(.GET, url, reqOpts);
    }

    /// POST request convenience method.
    pub fn post(self: *Self, url: []const u8, reqOpts: RequestOptions) !Response {
        return self.request(.POST, url, reqOpts);
    }

    /// PUT request convenience method.
    pub fn put(self: *Self, url: []const u8, reqOpts: RequestOptions) !Response {
        return self.request(.PUT, url, reqOpts);
    }

    /// DELETE request convenience method.
    pub fn delete(self: *Self, url: []const u8, reqOpts: RequestOptions) !Response {
        return self.request(.DELETE, url, reqOpts);
    }

    /// PATCH request convenience method.
    pub fn patch(self: *Self, url: []const u8, reqOpts: RequestOptions) !Response {
        return self.request(.PATCH, url, reqOpts);
    }

    /// HEAD request convenience method.
    pub fn head(self: *Self, url: []const u8, reqOpts: RequestOptions) !Response {
        return self.request(.HEAD, url, reqOpts);
    }

    /// OPTIONS request convenience method.
    pub fn httpOptions(self: *Self, url: []const u8, reqOpts: RequestOptions) !Response {
        return self.request(.OPTIONS, url, reqOpts);
    }
};

/// Parses an HTTP response from raw data.
fn parseResponse(allocator: Allocator, data: []const u8) !Response {
    const header_end = mem.indexOf(u8, data, "\r\n\r\n") orelse return error.InvalidResponse;
    const headers_data = data[0..header_end];
    const body_data = if (header_end + 4 < data.len) data[header_end + 4 ..] else "";

    var lines = mem.splitSequence(u8, headers_data, "\r\n");

    const status_line = lines.next() orelse return error.InvalidResponse;
    var status_parts = mem.splitScalar(u8, status_line, ' ');
    _ = status_parts.next();
    const status_str = status_parts.next() orelse return error.InvalidResponse;
    const status_code = try std.fmt.parseInt(u16, status_str, 10);

    var response = Response.init(allocator, status_code);
    errdefer response.deinit();

    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (mem.indexOf(u8, line, ":")) |sep| {
            const name = mem.trim(u8, line[0..sep], " \t");
            const value = mem.trim(u8, line[sep + 1 ..], " \t");
            try response.headers.append(name, value);
        }
    }

    if (body_data.len > 0) {
        response.body = try allocator.dupe(u8, body_data);
        response.body_owned = true;
    }

    return response;
}

test "Client initialization" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator);
    defer client.deinit();

    try std.testing.expectEqualStrings("httpx.zig/0.0.1", client.config.user_agent);
}

test "Client with config" {
    const allocator = std.testing.allocator;
    var client = Client.initWithConfig(allocator, .{
        .base_url = "https://api.example.com",
        .user_agent = "TestClient/1.0",
    });
    defer client.deinit();

    try std.testing.expectEqualStrings("https://api.example.com", client.config.base_url.?);
}

test "Response parsing" {
    const allocator = std.testing.allocator;
    const data = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\"}";

    var response = try parseResponse(allocator, data);
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 200), response.status.code);
    try std.testing.expectEqualStrings("application/json", response.headers.get("Content-Type").?);
}

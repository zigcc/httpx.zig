//! HTTP Client Implementation for httpx.zig
//!
//! HTTP/1.1 client over TCP with optional TLS (HTTPS).
//!
//! ## Features
//! - Connection pooling with keep-alive
//! - Automatic retry with exponential backoff
//! - Redirect following with configurable policies
//! - Request/response interceptors
//! - Automatic cookie management (CookieJar)
//! - Content-Encoding decompression (gzip, deflate)
//! - Basic/Digest/Bearer authentication
//! - HTTP proxy support with CONNECT tunneling
//! - Multipart form data uploads
//!
//! Notes:
//! - HTTP/2 and HTTP/3 types exist in `src/protocol/http.zig`, but this client
//!   currently speaks HTTP/1.1.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const net = std.net;

const types = @import("../core/types.zig");
const HttpError = types.HttpError;
const Headers = @import("../core/headers.zig").Headers;
const HeaderName = @import("../core/headers.zig").HeaderName;
const Uri = @import("../core/uri.zig").Uri;
const Request = @import("../core/request.zig").Request;
const Response = @import("../core/response.zig").Response;
const Status = @import("../core/status.zig").Status;
const Socket = @import("../net/socket.zig").Socket;
const SocketIoReader = @import("../net/socket.zig").SocketIoReader;
const SocketIoWriter = @import("../net/socket.zig").SocketIoWriter;
const address_mod = @import("../net/address.zig");
const http = @import("../protocol/http.zig");
const Parser = @import("../protocol/parser.zig").Parser;
const ParseError = @import("../protocol/parser.zig").ParseError;
const TlsConfig = @import("../tls/tls.zig").TlsConfig;
const TlsSession = @import("../tls/tls.zig").TlsSession;
const ConnectionPool = @import("pool.zig").ConnectionPool;

// New feature imports
const CookieJar = @import("../core/cookie.zig").CookieJar;
const compression = @import("../util/compression.zig");
const auth_mod = @import("../core/auth.zig");
const proxy_mod = @import("proxy.zig");
const multipart = @import("../core/multipart.zig");

/// Client error type - combines HTTP errors with system/network errors.
pub const ClientError = HttpError || Allocator.Error || std.posix.ConnectError || std.posix.SetSockOptError || std.posix.SendError || std.posix.RecvError || ParseError;

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
    http2_enabled: bool = false,
    http3_enabled: bool = false,
    keep_alive: bool = true,
    pool_max_connections: u32 = 20,
    pool_max_per_host: u32 = 5,

    // New HTTP/1.1 features
    /// Enable automatic cookie management
    enable_cookies: bool = true,
    /// Enable automatic Content-Encoding decompression
    auto_decompress: bool = true,
    /// Send Accept-Encoding header for compression
    accept_encoding: bool = true,
    /// HTTP proxy configuration
    proxy: ?proxy_mod.ProxyConfig = null,
    /// Basic authentication credentials (username, password)
    basic_auth: ?struct { username: []const u8, password: []const u8 } = null,
    /// Bearer token for authentication
    bearer_token: ?[]const u8 = null,
};

/// Per-request options.
pub const RequestOptions = struct {
    headers: ?[]const [2][]const u8 = null,
    body: ?[]const u8 = null,
    json: ?[]const u8 = null,
    timeout_ms: ?u64 = null,
    follow_redirects: ?bool = null,
    /// Basic auth for this request only
    basic_auth: ?struct { username: []const u8, password: []const u8 } = null,
    /// Bearer token for this request only
    bearer_token: ?[]const u8 = null,
    /// Multipart form data
    multipart_form: ?*multipart.MultipartForm = null,
    /// URL-encoded form data
    form_data: ?*multipart.UrlEncodedForm = null,
    /// Skip automatic decompression for this request
    skip_decompress: bool = false,
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
    cookie_jar: CookieJar,
    pool: ConnectionPool,
    authenticator: auth_mod.Authenticator,

    const Self = @This();

    /// Creates a new HTTP client with default configuration.
    pub fn init(allocator: Allocator) Self {
        return initWithConfig(allocator, .{});
    }

    /// Creates a new HTTP client with custom configuration.
    pub fn initWithConfig(allocator: Allocator, config: ClientConfig) Self {
        var client = Self{
            .allocator = allocator,
            .config = config,
            .pool = ConnectionPool.initWithConfig(allocator, .{
                .max_connections = config.pool_max_connections,
                .max_per_host = config.pool_max_per_host,
            }),
            .cookie_jar = CookieJar.init(allocator),
            .authenticator = auth_mod.Authenticator.init(allocator),
        };

        // Set up basic auth if configured
        if (config.basic_auth) |ba| {
            client.authenticator.setCredentials(ba.username, ba.password);
        }

        return client;
    }

    /// Releases all allocated resources.
    pub fn deinit(self: *Self) void {
        self.interceptors.deinit(self.allocator);
        self.cookie_jar.deinit();
        self.pool.deinit();
    }

    /// Gets the cookie jar for manual cookie management.
    pub fn getCookieJar(self: *Self) *CookieJar {
        return &self.cookie_jar;
    }

    /// Sets basic authentication credentials.
    pub fn setBasicAuth(self: *Self, username: []const u8, password: []const u8) void {
        self.authenticator.setCredentials(username, password);
    }

    /// Adds an interceptor to the client.
    pub fn addInterceptor(self: *Self, interceptor: Interceptor) !void {
        try self.interceptors.append(self.allocator, interceptor);
    }

    /// Makes an HTTP request.
    /// Returns ClientError on failures including connection, TLS, or parsing errors.
    pub fn request(self: *Self, method: types.Method, url: []const u8, reqOpts: RequestOptions) ClientError!Response {
        return self.requestInternal(method, url, reqOpts, 0);
    }

    fn requestInternal(self: *Self, method: types.Method, url: []const u8, reqOpts: RequestOptions, depth: u32) ClientError!Response {
        const full_url = if (self.config.base_url) |base|
            try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ base, url })
        else
            try self.allocator.dupe(u8, url);
        defer self.allocator.free(full_url);

        var req = try Request.init(self.allocator, method, full_url);
        defer req.deinit();

        // Set User-Agent
        try req.headers.set(HeaderName.USER_AGENT, self.config.user_agent);

        // Add Accept-Encoding header for automatic decompression
        if (self.config.accept_encoding and self.config.auto_decompress) {
            try req.headers.set(HeaderName.ACCEPT_ENCODING, compression.acceptEncodingHeader());
        }

        // Add default headers
        if (self.config.default_headers) |hdrs| {
            for (hdrs) |h| {
                try req.headers.set(h[0], h[1]);
            }
        }

        // Add request-specific headers
        if (reqOpts.headers) |hdrs| {
            for (hdrs) |h| {
                try req.headers.set(h[0], h[1]);
            }
        }

        // Handle authentication
        if (reqOpts.bearer_token orelse self.config.bearer_token) |token| {
            const auth_header = try auth_mod.bearerAuth(self.allocator, token);
            defer self.allocator.free(auth_header);
            try req.headers.set("Authorization", auth_header);
        } else if (reqOpts.basic_auth) |ba| {
            const auth_header = try auth_mod.basicAuth(self.allocator, ba.username, ba.password);
            defer self.allocator.free(auth_header);
            try req.headers.set("Authorization", auth_header);
        } else if (self.authenticator.credentials != null) {
            if (try self.authenticator.getAuthHeader(method.toString(), req.uri.path)) |auth_header| {
                defer self.allocator.free(auth_header);
                try req.headers.set("Authorization", auth_header);
            }
        }

        // Add cookies from cookie jar
        if (self.config.enable_cookies) {
            if (req.uri.host) |host| {
                const is_secure = req.uri.isTls();
                if (try self.cookie_jar.getCookieHeader(self.allocator, host, req.uri.path, is_secure)) |cookie_header| {
                    defer self.allocator.free(cookie_header);
                    try req.headers.set(HeaderName.COOKIE, cookie_header);
                }
            }
        }

        // Handle body content
        if (reqOpts.multipart_form) |form| {
            // Multipart form data
            const body = try form.encode();
            defer self.allocator.free(body);
            req.body = try self.allocator.dupe(u8, body);
            req.body_owned = true;
            const ct = try form.getContentTypeHeader(self.allocator);
            defer self.allocator.free(ct);
            try req.headers.set(HeaderName.CONTENT_TYPE, ct);
            var len_buf: [32]u8 = undefined;
            const len_str = std.fmt.bufPrint(&len_buf, "{d}", .{body.len}) catch unreachable;
            try req.headers.set(HeaderName.CONTENT_LENGTH, len_str);
        } else if (reqOpts.form_data) |form| {
            // URL-encoded form data
            const body = try form.encode();
            defer self.allocator.free(body);
            req.body = try self.allocator.dupe(u8, body);
            req.body_owned = true;
            try req.headers.set(HeaderName.CONTENT_TYPE, multipart.UrlEncodedForm.contentType());
            var len_buf: [32]u8 = undefined;
            const len_str = std.fmt.bufPrint(&len_buf, "{d}", .{body.len}) catch unreachable;
            try req.headers.set(HeaderName.CONTENT_LENGTH, len_str);
        } else if (reqOpts.body) |body| {
            try req.setBody(body);
        } else if (reqOpts.json) |json_body| {
            try req.setJson(json_body);
        }

        // Run request interceptors
        for (self.interceptors.items) |interceptor| {
            if (interceptor.request_fn) |f| {
                try f(&req, interceptor.context);
            }
        }

        // Execute request
        var response = try self.executeRequest(&req, reqOpts.skip_decompress);

        // Process Set-Cookie headers
        if (self.config.enable_cookies) {
            if (req.uri.host) |host| {
                try self.cookie_jar.processResponse(response.headers, host);
            }
        }

        // Run response interceptors
        for (self.interceptors.items) |interceptor| {
            if (interceptor.response_fn) |f| {
                try f(&response, interceptor.context);
            }
        }

        // Handle redirects
        const should_follow = reqOpts.follow_redirects orelse self.config.follow_redirects;
        if (should_follow and response.isRedirect()) {
            if (depth >= self.config.redirect_policy.max_redirects) {
                response.deinit();
                return HttpError.TooManyRedirects;
            }

            const location = response.headers.get(HeaderName.LOCATION) orelse {
                response.deinit();
                return HttpError.InvalidResponse;
            };

            const next_url = try self.resolveRedirectUrl(req.uri, location);
            defer self.allocator.free(next_url);

            const next_method = self.config.redirect_policy.getRedirectMethod(response.status.code, req.method);
            response.deinit();
            return self.requestInternal(next_method, next_url, reqOpts, depth + 1);
        }

        // Handle 401 Unauthorized - extract challenge for Digest auth
        if (response.status.code == 401) {
            if (response.headers.get("WWW-Authenticate")) |www_auth| {
                self.authenticator.handleChallenge(www_auth);
            }
        }

        return response;
    }

    /// Executes the actual HTTP request.
    fn executeRequest(self: *Self, req: *Request, skip_decompress: bool) ClientError!Response {
        const policy = self.config.retry_policy;
        const can_retry_method = (!policy.retry_only_idempotent) or req.method.isIdempotent();

        var attempt: u32 = 0;
        while (true) {
            var res = self.executeRequestOnce(req) catch |err| {
                if (policy.retry_on_connection_error and can_retry_method and attempt < policy.max_retries) {
                    attempt += 1;
                    const delay_ms = policy.calculateDelay(attempt);
                    if (delay_ms > 0) std.time.sleep(delay_ms * std.time.ns_per_ms);
                    continue;
                }
                return err;
            };

            if (can_retry_method and attempt < policy.max_retries and policy.shouldRetryStatus(res.status.code)) {
                res.deinit();
                attempt += 1;
                const delay_ms = policy.calculateDelay(attempt);
                if (delay_ms > 0) std.time.sleep(delay_ms * std.time.ns_per_ms);
                continue;
            }

            // Auto-decompress response body if enabled
            if (self.config.auto_decompress and !skip_decompress and res.body != null) {
                const content_encoding = res.headers.get(HeaderName.CONTENT_ENCODING);
                if (content_encoding != null) {
                    if (compression.decompressAuto(self.allocator, res.body.?, content_encoding)) |decompressed| {
                        // Replace body with decompressed data
                        if (res.body_owned) {
                            self.allocator.free(res.body.?);
                        }
                        res.body = decompressed;
                        res.body_owned = true;
                        // Remove Content-Encoding header as body is now decompressed
                        res.headers.removeAll(HeaderName.CONTENT_ENCODING);
                    } else |_| {
                        // Decompression failed, keep original body
                    }
                }
            }

            return res;
        }
    }

    fn executeRequestOnce(self: *Self, req: *Request) ClientError!Response {
        const host = req.uri.host orelse return HttpError.InvalidUri;
        const port = req.uri.effectivePort();

        const request_data = try http.formatRequest(req, self.allocator);
        defer self.allocator.free(request_data);

        if (req.uri.isTls()) {
            // TLS pooling requires keeping a live TLS session; not implemented yet.
            const addr = try address_mod.resolve(host, port);

            var socket = try Socket.createForAddress(addr);
            defer socket.close();

            if (self.config.timeouts.read_ms > 0) {
                try socket.setRecvTimeout(self.config.timeouts.read_ms);
            }
            if (self.config.timeouts.write_ms > 0) {
                try socket.setSendTimeout(self.config.timeouts.write_ms);
            }

            try socket.connect(addr);

            return self.executeTlsHttp(&socket, host, request_data);
        }

        if (self.config.keep_alive) {
            var conn = try self.pool.getConnection(host, port);
            errdefer conn.close();
            defer self.pool.releaseConnection(conn);

            if (self.config.timeouts.read_ms > 0) {
                try conn.socket.setRecvTimeout(self.config.timeouts.read_ms);
            }
            if (self.config.timeouts.write_ms > 0) {
                try conn.socket.setSendTimeout(self.config.timeouts.write_ms);
            }
            try conn.socket.setKeepAlive(true);

            try conn.socket.sendAll(request_data);
            var res = try self.readResponseFromTcp(&conn.socket);
            if (!res.headers.isKeepAlive(.HTTP_1_1)) {
                conn.close();
            }
            return res;
        }

        const addr = try address_mod.resolve(host, port);

        var socket = try Socket.createForAddress(addr);
        defer socket.close();

        if (self.config.timeouts.read_ms > 0) {
            try socket.setRecvTimeout(self.config.timeouts.read_ms);
        }
        if (self.config.timeouts.write_ms > 0) {
            try socket.setSendTimeout(self.config.timeouts.write_ms);
        }

        try socket.connect(addr);

        try socket.sendAll(request_data);
        return self.readResponseFromTcp(&socket);
    }

    fn executeTlsHttp(self: *Self, socket: *Socket, host: []const u8, request_data: []const u8) ClientError!Response {
        const tls_cfg = if (self.config.verify_ssl) TlsConfig.init(self.allocator) else TlsConfig.insecure(self.allocator);

        var session = TlsSession.init(tls_cfg);
        defer session.deinit();
        session.attachSocket(socket);
        try session.handshake(host);

        const w = try session.getWriter();
        try w.writeAll(request_data);

        const r = try session.getReader();
        return self.readResponseFromIo(r);
    }

    fn readResponseFromTcp(self: *Self, socket: *Socket) ClientError!Response {
        var parser = Parser.initResponse(self.allocator);
        defer parser.deinit();

        var buf: [16 * 1024]u8 = undefined;
        while (!parser.isComplete()) {
            const n = try socket.recv(&buf);
            if (n == 0) break;
            _ = try parser.feed(buf[0..n]);
        }

        parser.finishEof();

        if (!parser.isComplete()) return HttpError.InvalidResponse;
        return self.responseFromParser(&parser);
    }

    fn readResponseFromIo(self: *Self, r: *std.Io.Reader) ClientError!Response {
        var parser = Parser.initResponse(self.allocator);
        defer parser.deinit();

        var buf: [16 * 1024]u8 = undefined;
        while (!parser.isComplete()) {
            var iov = [_][]u8{buf[0..]};
            const n = r.readVec(&iov) catch |err| switch (err) {
                error.EndOfStream => 0,
                else => return err,
            };
            if (n == 0) break;
            _ = try parser.feed(buf[0..n]);
        }

        parser.finishEof();

        if (!parser.isComplete()) return HttpError.InvalidResponse;
        return self.responseFromParser(&parser);
    }

    fn responseFromParser(self: *Self, parser: *Parser) ClientError!Response {
        _ = self;
        const code = parser.status_code orelse return HttpError.InvalidResponse;
        var res = Response.init(parser.allocator, code);
        errdefer res.deinit();

        // Move headers ownership from parser to response.
        res.headers.deinit();
        res.headers = parser.headers;
        parser.headers = Headers.init(parser.allocator);

        if (parser.getBody().len > 0) {
            res.body = try parser.allocator.dupe(u8, parser.getBody());
            res.body_owned = true;
        }

        return res;
    }

    fn resolveRedirectUrl(self: *Self, base: Uri, location: []const u8) ClientError![]u8 {
        // Absolute URL.
        if (mem.indexOf(u8, location, "://") != null) {
            return self.allocator.dupe(u8, location);
        }

        const scheme = base.scheme orelse "http";
        const host = base.host orelse return HttpError.InvalidUri;
        const port = base.effectivePort();

        if (location.len > 0 and location[0] == '/') {
            return std.fmt.allocPrint(self.allocator, "{s}://{s}:{d}{s}", .{ scheme, host, port, location });
        }

        // Relative to current path.
        const base_path = base.path;
        const slash = mem.lastIndexOfScalar(u8, base_path, '/') orelse 0;
        const prefix = base_path[0 .. slash + 1];
        return std.fmt.allocPrint(self.allocator, "{s}://{s}:{d}{s}{s}", .{ scheme, host, port, prefix, location });
    }

    /// GET request convenience method.
    pub fn get(self: *Self, url: []const u8, reqOpts: RequestOptions) ClientError!Response {
        return self.request(.GET, url, reqOpts);
    }

    /// POST request convenience method.
    pub fn post(self: *Self, url: []const u8, reqOpts: RequestOptions) ClientError!Response {
        return self.request(.POST, url, reqOpts);
    }

    /// PUT request convenience method.
    pub fn put(self: *Self, url: []const u8, reqOpts: RequestOptions) ClientError!Response {
        return self.request(.PUT, url, reqOpts);
    }

    /// DELETE request convenience method.
    pub fn delete(self: *Self, url: []const u8, reqOpts: RequestOptions) ClientError!Response {
        return self.request(.DELETE, url, reqOpts);
    }

    /// PATCH request convenience method.
    pub fn patch(self: *Self, url: []const u8, reqOpts: RequestOptions) ClientError!Response {
        return self.request(.PATCH, url, reqOpts);
    }

    /// HEAD request convenience method.
    pub fn head(self: *Self, url: []const u8, reqOpts: RequestOptions) ClientError!Response {
        return self.request(.HEAD, url, reqOpts);
    }

    /// OPTIONS request convenience method.
    pub fn httpOptions(self: *Self, url: []const u8, reqOpts: RequestOptions) ClientError!Response {
        return self.request(.OPTIONS, url, reqOpts);
    }
};

/// Parses an HTTP response from raw data.
fn parseResponse(allocator: Allocator, data: []const u8) ClientError!Response {
    var parser = Parser.initResponse(allocator);
    defer parser.deinit();

    _ = try parser.feed(data);
    if (!parser.isComplete()) return HttpError.InvalidResponse;

    const code = parser.status_code orelse return HttpError.InvalidResponse;
    var res = Response.init(allocator, code);
    errdefer res.deinit();

    // Move headers ownership from parser to response.
    res.headers.deinit();
    res.headers = parser.headers;
    parser.headers = Headers.init(allocator);

    if (parser.getBody().len > 0) {
        res.body = try allocator.dupe(u8, parser.getBody());
        res.body_owned = true;
    }

    return res;
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

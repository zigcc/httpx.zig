//! HTTP Server Implementation for httpx.zig
//!
//! Gin-style HTTP server with:
//!
//! - Radix tree routing with path parameters
//! - Middleware onion model (global + group-level)
//! - Context-based request handling with abort support
//! - JSON request binding and response helpers
//! - Query string parsing
//! - Static file/directory serving
//! - 405 Method Not Allowed detection
//! - Multi-threaded request handling (optional)
//! - Cross-platform (Linux, Windows, macOS)
//!
//! ## Quick Start
//!
//! ```zig
//! var server = Server.init(allocator);
//! try server.use(httpx.logger());
//! try server.get("/hello", helloHandler);
//! try server.listen();
//! ```

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const zio = @import("zio");

const types = @import("../core/types.zig");
const Request = @import("../core/request.zig").Request;
const Response = @import("../core/response.zig").Response;
const ResponseBuilder = @import("../core/response.zig").ResponseBuilder;
const Headers = @import("../core/headers.zig").Headers;
const HeaderName = @import("../core/headers.zig").HeaderName;
const Parser = @import("../protocol/parser.zig").Parser;
const http = @import("../protocol/http.zig");
const socket_mod = @import("../net/socket.zig");
const websocket = @import("../protocol/websocket.zig");
const Router = @import("router.zig").Router;
const RouteGroup = @import("router.zig").RouteGroup;
const FindResult = @import("router.zig").FindResult;
const RouteParam = @import("router.zig").RouteParam;
const MAX_ROUTE_PARAMS = @import("router.zig").MAX_PARAMS;
const Middleware = @import("middleware.zig").Middleware;
const MiddlewareChain = @import("middleware.zig").MiddlewareChain;
const chainNext = @import("middleware.zig").chainNext;
const ws_handler = @import("ws_handler.zig");
const WebSocketHandler = ws_handler.WebSocketHandler;
const Json = @import("../util/json.zig");
const MimeType = @import("../core/multipart.zig").MimeType;
const uri_mod = @import("../core/uri.zig");
const cookie_mod = @import("../core/cookie.zig");
const tls_client = @import("../tls/tls.zig");
const tls_server = @import("../tls/server.zig");

/// TLS 1.2 server config for HTTPS mode.
pub const Tls12Config = struct {
    cert_chain_der: []const []const u8,
    private_key_der: []const u8,
    supported_alpn_protocols: []const []const u8 = &.{},
};

/// TLS 1.2 PEM config for HTTPS mode.
pub const Tls12PemConfig = struct {
    cert_chain_pem: []const []const u8,
    private_key_pem: []const u8,
    supported_alpn_protocols: []const []const u8 = &.{},
};

const OwnedTls12Config = struct {
    cert_chain_der: []const []const u8,
    private_key_der: []const u8,
};

/// Server configuration.
pub const ServerConfig = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = 8080,
    max_body_size: usize = 10 * 1024 * 1024,
    request_timeout_ms: u64 = 30_000,
    keep_alive_timeout_ms: u64 = 60_000,
    max_connections: u32 = 1000,
    keep_alive: bool = true,
    threads: u32 = 0,
    /// Trusted proxy IP addresses/CIDRs. When set, X-Forwarded-For and X-Real-IP
    /// headers will only be trusted from these addresses.
    /// Empty list means trust all proxies (default, insecure for production).
    trusted_proxies: []const []const u8 = &.{},
    /// Headers to check for client IP (in priority order).
    remote_ip_headers: []const []const u8 = &.{ "X-Forwarded-For", "X-Real-Ip" },
    /// Graceful shutdown timeout in milliseconds.
    /// When stop() is called, the server waits up to this duration for
    /// active connections to finish before closing.
    shutdown_timeout_ms: u64 = 5_000,
    /// Optional TLS 1.2 settings. When set, server speaks HTTPS.
    tls12: ?Tls12Config = null,
};

/// Config for tuning concurrent request processing.
pub const ThreadingConfig = struct {
    /// Number of ZIO executors used by the runtime.
    /// 0 means auto-detect CPU count.
    num_workers: u32 = 0,
};

/// Runtime statistics snapshot.
pub const RuntimeStats = struct {
    requests_handled: u64,
    active_requests: u64,
    total_errors: u64,
    executors: u32,
};

/// Handler function type.
pub const Handler = *const fn (*Context) anyerror!Response;

/// Next function type for middleware.
pub const Next = @import("middleware.zig").Next;

// ============================================================================
// Error Types — Gin-style structured error collection
// ============================================================================

/// Error type classification (mirrors Gin's ErrorType).
pub const ErrorType = enum {
    /// Binding error (e.g., JSON parse failure).
    bind,
    /// Rendering error (e.g., template error).
    render,
    /// Private error — not shown to the client (e.g., database errors).
    private,
    /// Public error — safe to expose to the client.
    public,
};

/// A structured error attached to a request context.
/// Gin-style error collection: handlers and middleware can attach errors
/// using `ctx.addError()`, and later inspect them via `ctx.errors`.
pub const HandlerError = struct {
    err: anyerror,
    err_type: ErrorType = .private,
    message: ?[]const u8 = null,
    /// Whether `message` is heap-allocated and should be freed.
    message_owned: bool = false,

    pub fn deinit(self: *HandlerError, allocator: Allocator) void {
        if (self.message_owned) {
            if (self.message) |msg| {
                allocator.free(msg);
            }
        }
    }

    /// Returns the error message, or the error name if no message was set.
    pub fn getMessage(self: *const HandlerError) []const u8 {
        return self.message orelse @errorName(self.err);
    }

    /// Returns true if this error has the given type.
    pub fn isType(self: *const HandlerError, t: ErrorType) bool {
        return self.err_type == t;
    }
};

// ============================================================================
// Context — Gin-style request context
// ============================================================================

/// Request context passed to handlers and middleware.
///
/// Provides access to the request, response builder, path parameters,
/// query parameters, and user data. Also supports abort/middleware chain control.
///
/// ## Example
/// ```zig
/// fn handler(ctx: *Context) anyerror!Response {
///     const id = ctx.param("id") orelse return ctx.status(400).text("missing id");
///     const page = ctx.query("page") orelse "1";
///     return ctx.json(.{ .id = id, .page = page });
/// }
/// ```
pub const Context = struct {
    allocator: Allocator,
    request: *Request,
    response: ResponseBuilder,
    params: std.StringHashMap([]const u8),
    data: std.StringHashMap(*anyopaque),

    // -- Middleware chain state (set by MiddlewareChain.execute) --
    chain_handlers: Handler = undefined,
    chain_global_mw: []const Middleware = &.{},
    chain_route_mw: []const Middleware = &.{},
    chain_index: usize = 0,

    // -- Abort support --
    is_aborted: bool = false,
    abort_response: ?Response = null,

    // -- Cached query parameters --
    query_cache: ?std.StringHashMap([]const u8) = null,

    // -- Matched route pattern (e.g., "/users/:id") --
    matched_path: ?[]const u8 = null,

    // -- Response cookies to set --
    response_cookies: std.ArrayListUnmanaged(cookie_mod.Cookie) = .empty,

    // -- Error collection (Gin-style c.Error / c.Errors) --
    errors: std.ArrayListUnmanaged(HandlerError) = .empty,

    // -- Server config reference (for trusted proxies etc.) --
    server_config: ?*const ServerConfig = null,

    const Self = @This();

    /// Creates a new context for a request.
    pub fn init(allocator: Allocator, req: *Request) Self {
        return .{
            .allocator = allocator,
            .request = req,
            .response = ResponseBuilder.init(allocator),
            .params = std.StringHashMap([]const u8).init(allocator),
            .data = std.StringHashMap(*anyopaque).init(allocator),
        };
    }

    /// Releases context resources.
    pub fn deinit(self: *Self) void {
        self.response.deinit();
        self.params.deinit();
        self.data.deinit();
        if (self.abort_response) |*r| {
            r.deinit();
            self.abort_response = null;
        }
        if (self.query_cache) |*cache| {
            // Free decoded values
            var it = cache.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                self.allocator.free(entry.value_ptr.*);
            }
            cache.deinit();
            self.query_cache = null;
        }
        for (self.response_cookies.items) |*c| {
            c.deinit(self.allocator);
        }
        self.response_cookies.deinit(self.allocator);
        // Free error collection
        for (self.errors.items) |*e| {
            e.deinit(self.allocator);
        }
        self.errors.deinit(self.allocator);
    }

    // -- Parameter access --

    /// Returns a URL path parameter by name (e.g., `:id`).
    pub fn param(self: *const Self, name: []const u8) ?[]const u8 {
        return self.params.get(name);
    }

    /// Returns a query string parameter by name.
    ///
    /// Parses the query string from the request URI on each call.
    /// For repeated access, consider caching the result.
    pub fn query(self: *const Self, name: []const u8) ?[]const u8 {
        const qs = self.request.uri.query orelse return null;
        return getQueryParam(qs, name);
    }

    /// Returns a query parameter with a default value if not present.
    pub fn queryDefault(self: *const Self, name: []const u8, default: []const u8) []const u8 {
        return self.query(name) orelse default;
    }

    /// Returns a request header by name.
    pub fn header(self: *const Self, name: []const u8) ?[]const u8 {
        return self.request.headers.get(name);
    }

    // -- Response helpers --

    /// Sets the response status code. Returns self for chaining.
    pub fn status(self: *Self, code: u16) *Self {
        _ = self.response.status(code);
        return self;
    }

    /// Sets a response header.
    pub fn setHeader(self: *Self, name: []const u8, value: []const u8) !void {
        _ = try self.response.header(name, value);
    }

    /// Sends a plain text response.
    pub fn text(self: *Self, content: []const u8) !Response {
        _ = try self.response.header(HeaderName.CONTENT_TYPE, "text/plain; charset=utf-8");
        _ = self.response.body(content);
        return self.response.build();
    }

    /// Sends an HTML response.
    pub fn html(self: *Self, content: []const u8) !Response {
        _ = try self.response.header(HeaderName.CONTENT_TYPE, "text/html; charset=utf-8");
        _ = self.response.body(content);
        return self.response.build();
    }

    /// Sends a file response with auto-detected Content-Type. Returns 404 if file not found.
    pub fn file(self: *Self, path: []const u8) !Response {
        const f = std.fs.cwd().openFile(path, .{}) catch return self.status(404).text("Not Found");
        defer f.close();

        const stat = try f.stat();
        const content = try self.allocator.alloc(u8, @intCast(stat.size));
        _ = try f.readAll(content);

        // Auto-detect content type from file path
        const ct = MimeType.fromFilename(path);

        // Build response manually to transfer ownership of content without duping
        var response = Response.init(self.allocator, self.response.status_code);
        for (self.response.headers.entries.items) |h| {
            try response.headers.append(h.name, h.value);
        }
        try response.headers.set(HeaderName.CONTENT_TYPE, ct);
        response.body = content;
        response.body_owned = true;

        var len_buf: [32]u8 = undefined;
        const len_str = std.fmt.bufPrint(&len_buf, "{d}", .{content.len}) catch unreachable;
        try response.headers.set(HeaderName.CONTENT_LENGTH, len_str);
        return response;
    }

    /// Sends a JSON response from any Zig value.
    pub fn json(self: *Self, value: anytype) !Response {
        _ = try self.response.json(value);
        return self.response.build();
    }

    /// Sends a redirect response.
    pub fn redirect(self: *Self, url: []const u8, code: u16) !Response {
        _ = self.response.status(code);
        _ = try self.response.header(HeaderName.LOCATION, url);
        return self.response.build();
    }

    // -- Request body binding --

    /// Binds the JSON request body to a Zig struct type.
    /// Returns the parsed struct or an error.
    ///
    /// Example:
    /// ```zig
    /// const User = struct { name: []const u8, age: u32 };
    /// const user = try ctx.bind(User);
    /// ```
    pub fn bind(self: *Self, comptime T: type) !T {
        const body = self.request.body orelse return error.EmptyBody;
        return std.json.parseFromSlice(T, self.allocator, body, .{
            .ignore_unknown_fields = true,
        }) catch return error.InvalidJson;
    }

    /// Binds JSON request body, returning null on failure instead of error.
    pub fn shouldBind(self: *Self, comptime T: type) ?T {
        return self.bind(T) catch null;
    }

    // -- Abort --

    /// Aborts the middleware chain with a status code and message.
    /// Subsequent middleware and the handler will not execute.
    pub fn abort(self: *Self, code: u16, message: []const u8) void {
        self.is_aborted = true;
        var resp = Response.init(self.allocator, code);
        resp.body = self.allocator.dupe(u8, message) catch null;
        resp.body_owned = true;
        self.abort_response = resp;
    }

    /// Aborts with a status code only (no body).
    pub fn abortWithStatus(self: *Self, code: u16) void {
        self.is_aborted = true;
        self.abort_response = Response.init(self.allocator, code);
    }

    /// Aborts with a JSON response body.
    pub fn abortWithJSON(self: *Self, code: u16, value: anytype) void {
        self.is_aborted = true;
        var resp = Response.init(self.allocator, code);
        const json_str = std.json.stringifyAlloc(self.allocator, value, .{}) catch {
            resp.body = null;
            self.abort_response = resp;
            return;
        };
        resp.body = json_str;
        resp.body_owned = true;
        resp.headers.set(HeaderName.CONTENT_TYPE, "application/json; charset=utf-8") catch {};
        self.abort_response = resp;
    }

    // -- User data store --

    /// Stores a value in the context (like Gin's `c.Set()`).
    pub fn set(self: *Self, key: []const u8, ptr: *anyopaque) !void {
        try self.data.put(key, ptr);
    }

    /// Retrieves a value from the context (like Gin's `c.Get()`).
    pub fn get(self: *const Self, key: []const u8) ?*anyopaque {
        return self.data.get(key);
    }

    /// Calls next middleware in the chain. Use this inside middleware handlers.
    pub fn next(self: *Self) anyerror!Response {
        return chainNext(self);
    }

    // -- Cookie support (Gin-style c.Cookie / c.SetCookie) --

    /// Returns a request cookie value by name.
    /// Parses the Cookie header on first access.
    pub fn getCookie(self: *const Self, name: []const u8) ?[]const u8 {
        const cookie_header = self.request.headers.get("Cookie") orelse return null;
        var it = mem.splitSequence(u8, cookie_header, "; ");
        while (it.next()) |pair| {
            if (mem.indexOfScalar(u8, pair, '=')) |eq_pos| {
                const key = mem.trim(u8, pair[0..eq_pos], " ");
                if (mem.eql(u8, key, name)) {
                    return mem.trim(u8, pair[eq_pos + 1 ..], " ");
                }
            }
        }
        return null;
    }

    /// Sets a response cookie. The cookie will be added as Set-Cookie header
    /// when the response is built.
    pub fn setCookie(
        self: *Self,
        name: []const u8,
        value: []const u8,
        max_age: ?i32,
        path: ?[]const u8,
        domain: ?[]const u8,
        secure: bool,
        http_only: bool,
    ) !void {
        // Build Set-Cookie header value
        var buf = std.ArrayListUnmanaged(u8){};
        defer buf.deinit(self.allocator);

        try buf.appendSlice(self.allocator, name);
        try buf.append(self.allocator, '=');
        try buf.appendSlice(self.allocator, value);

        if (path) |p| {
            try buf.appendSlice(self.allocator, "; Path=");
            try buf.appendSlice(self.allocator, p);
        }
        if (domain) |d| {
            try buf.appendSlice(self.allocator, "; Domain=");
            try buf.appendSlice(self.allocator, d);
        }
        if (max_age) |age| {
            var age_buf: [16]u8 = undefined;
            const age_str = std.fmt.bufPrint(&age_buf, "{d}", .{age}) catch "0";
            try buf.appendSlice(self.allocator, "; Max-Age=");
            try buf.appendSlice(self.allocator, age_str);
        }
        if (secure) {
            try buf.appendSlice(self.allocator, "; Secure");
        }
        if (http_only) {
            try buf.appendSlice(self.allocator, "; HttpOnly");
        }

        _ = try self.response.header("Set-Cookie", buf.items);
    }

    // -- Form data access --

    /// Returns a URL-encoded form field value from the request body.
    /// Parses application/x-www-form-urlencoded body.
    pub fn postForm(self: *Self, name: []const u8) ?[]const u8 {
        const body = self.request.body orelse return null;
        const ct = self.request.headers.get(HeaderName.CONTENT_TYPE) orelse return null;
        if (!mem.startsWith(u8, ct, "application/x-www-form-urlencoded")) return null;
        return getQueryParam(body, name);
    }

    /// Returns a form field with a default value if not present.
    pub fn postFormDefault(self: *Self, name: []const u8, default: []const u8) []const u8 {
        return self.postForm(name) orelse default;
    }

    // -- Client IP --

    /// Returns the client IP address, checking configured proxy headers.
    /// Respects trusted_proxies and remote_ip_headers from ServerConfig.
    /// If trusted_proxies is non-empty, proxy headers (X-Forwarded-For etc.)
    /// are only trusted when the direct connection comes from a listed proxy.
    /// When trusted_proxies is empty (default), all proxy headers are trusted.
    pub fn clientIP(self: *const Self) ?[]const u8 {
        const cfg = self.server_config;
        const ip_headers = if (cfg) |c| c.remote_ip_headers else &[_][]const u8{ "X-Forwarded-For", "X-Real-Ip" };
        const trusted = if (cfg) |c| c.trusted_proxies else &[_][]const u8{};

        // If trusted_proxies is configured, we must verify the direct peer
        // before trusting proxy headers. Since we don't have the peer address
        // in Context yet, we use a simpler approach: check if the first
        // X-Forwarded-For entry is from a trusted proxy (rightmost-trusted).
        // When trusted_proxies is empty, trust all proxy headers.
        if (trusted.len > 0) {
            // Check if any proxy header value's source is trusted
            if (self.request.headers.get("X-Forwarded-For")) |xff| {
                // Walk from right to left (rightmost is closest proxy)
                var last_trusted_ip: ?[]const u8 = null;
                var iter = mem.splitScalar(u8, xff, ',');
                var ips_buf: [16][]const u8 = undefined;
                var ip_count: usize = 0;
                while (iter.next()) |part| {
                    if (ip_count < 16) {
                        ips_buf[ip_count] = mem.trim(u8, part, " ");
                        ip_count += 1;
                    }
                }
                // Walk from rightmost (direct peer) leftward
                if (ip_count > 0) {
                    var i = ip_count;
                    while (i > 0) {
                        i -= 1;
                        const ip = ips_buf[i];
                        if (isTrustedProxy(trusted, ip)) {
                            continue; // This is a proxy, keep going left
                        }
                        last_trusted_ip = ip; // First non-proxy IP = real client
                        break;
                    }
                    if (last_trusted_ip) |lip| return lip;
                    // All IPs are trusted proxies; fall through
                }
            }
            // Trusted proxies configured but no valid proxy header found
            return null;
        }

        // No trusted_proxies restriction — trust all proxy headers
        for (ip_headers) |hdr_name| {
            if (self.request.headers.get(hdr_name)) |value| {
                if (mem.indexOfScalar(u8, value, ',')) |comma_pos| {
                    const first_ip = mem.trim(u8, value[0..comma_pos], " ");
                    if (first_ip.len > 0) return first_ip;
                }
                const trimmed = mem.trim(u8, value, " ");
                if (trimmed.len > 0) return trimmed;
            }
        }
        return null;
    }

    /// Checks if an IP address is in the trusted proxy list.
    fn isTrustedProxy(trusted: []const []const u8, ip: []const u8) bool {
        for (trusted) |t| {
            if (mem.eql(u8, t, ip)) return true;
        }
        return false;
    }

    // -- Request metadata helpers --

    /// Returns the Content-Type of the request.
    pub fn contentType(self: *const Self) ?[]const u8 {
        return self.request.headers.get(HeaderName.CONTENT_TYPE);
    }

    /// Returns the matched route pattern (e.g., "/users/:id").
    pub fn fullPath(self: *const Self) ?[]const u8 {
        return self.matched_path;
    }

    /// Returns true if this is a WebSocket upgrade request.
    pub fn isWebsocket(self: *const Self) bool {
        return ws_handler.isUpgradeRequest(self.request);
    }

    // -- Improved query param access with caching and decoding --

    /// Returns a query parameter, with percent-decoding applied.
    /// Results are cached on first access for performance.
    pub fn queryDecoded(self: *Self, name: []const u8) ?[]const u8 {
        // Build cache on first call
        if (self.query_cache == null) {
            self.buildQueryCache();
        }
        if (self.query_cache) |cache| {
            return cache.get(name);
        }
        return null;
    }

    fn buildQueryCache(self: *Self) void {
        const qs = self.request.uri.query orelse return;
        var cache = std.StringHashMap([]const u8).init(self.allocator);
        var iter = mem.splitScalar(u8, qs, '&');
        while (iter.next()) |pair| {
            if (pair.len == 0) continue;
            if (mem.indexOfScalar(u8, pair, '=')) |eq_pos| {
                const raw_key = pair[0..eq_pos];
                const raw_value = pair[eq_pos + 1 ..];
                const decoded_key = uri_mod.decodeFormUrlencoded(self.allocator, raw_key) catch continue;
                const decoded_value = uri_mod.decodeFormUrlencoded(self.allocator, raw_value) catch {
                    self.allocator.free(decoded_key);
                    continue;
                };
                cache.put(decoded_key, decoded_value) catch {
                    self.allocator.free(decoded_key);
                    self.allocator.free(decoded_value);
                    continue;
                };
            } else {
                const decoded_key = uri_mod.decodeFormUrlencoded(self.allocator, pair) catch continue;
                const empty = self.allocator.dupe(u8, "") catch {
                    self.allocator.free(decoded_key);
                    continue;
                };
                cache.put(decoded_key, empty) catch {
                    self.allocator.free(decoded_key);
                    self.allocator.free(empty);
                    continue;
                };
            }
        }
        self.query_cache = cache;
    }

    // -- Type-safe data store --

    /// Retrieves a typed value from the context data store.
    /// Returns null if the key doesn't exist.
    pub fn getTyped(self: *const Self, comptime T: type, key: []const u8) ?*T {
        const ptr = self.data.get(key) orelse return null;
        return @ptrCast(@alignCast(ptr));
    }

    // -- Additional response helpers --

    /// Sends a raw data response with explicit content type.
    pub fn dataResponse(self: *Self, code: u16, content_type_val: []const u8, content: []const u8) !Response {
        _ = self.response.status(code);
        _ = try self.response.header(HeaderName.CONTENT_TYPE, content_type_val);
        _ = self.response.body(content);
        return self.response.build();
    }

    /// Sends a file as a download attachment with Content-Disposition header.
    pub fn fileAttachment(self: *Self, path: []const u8, filename: []const u8) !Response {
        const f = std.fs.cwd().openFile(path, .{}) catch return self.status(404).text("Not Found");
        defer f.close();

        const stat = try f.stat();
        const content = try self.allocator.alloc(u8, @intCast(stat.size));
        _ = try f.readAll(content);

        // Auto-detect content type from filename
        const ct = MimeType.fromFilename(filename);

        // Set Content-Disposition for download
        var disp_buf = std.ArrayListUnmanaged(u8){};
        defer disp_buf.deinit(self.allocator);
        try disp_buf.appendSlice(self.allocator, "attachment; filename=\"");
        try disp_buf.appendSlice(self.allocator, filename);
        try disp_buf.appendSlice(self.allocator, "\"");

        // Build response manually to transfer ownership of content without duping
        var response = Response.init(self.allocator, self.response.status_code);
        for (self.response.headers.entries.items) |h| {
            try response.headers.append(h.name, h.value);
        }
        try response.headers.set(HeaderName.CONTENT_TYPE, ct);
        try response.headers.set("Content-Disposition", disp_buf.items);
        response.body = content;
        response.body_owned = true;

        var len_buf: [32]u8 = undefined;
        const len_str = std.fmt.bufPrint(&len_buf, "{d}", .{content.len}) catch unreachable;
        try response.headers.set(HeaderName.CONTENT_LENGTH, len_str);
        return response;
    }

    // -- SSE response helpers --

    /// Sends a Server-Sent Events response with initial data.
    /// The response uses text/event-stream Content-Type and includes
    /// Cache-Control and Connection headers for SSE.
    pub fn sseResponse(self: *Self, events: []const u8) !Response {
        _ = self.response.status(200);
        _ = try self.response.header(HeaderName.CONTENT_TYPE, "text/event-stream");
        _ = try self.response.header("Cache-Control", "no-cache");
        _ = try self.response.header(HeaderName.CONNECTION, "keep-alive");
        _ = self.response.body(events);
        return self.response.build();
    }

    /// Builds an SSE event and returns it as a response.
    /// Convenience method combining formatSSEvent + sseResponse.
    pub fn ssEvent(self: *Self, name: ?[]const u8, data: []const u8) !Response {
        const event_data = try formatSSEvent(self.allocator, name, data);
        defer self.allocator.free(event_data);
        return self.sseResponse(event_data);
    }

    // -- Error collection (Gin-style c.Error / c.Errors) --

    /// Attaches an error to the context (like Gin's `c.Error()`).
    /// Errors can be inspected later by middleware or error handlers.
    pub fn addError(self: *Self, err: anyerror) !*HandlerError {
        try self.errors.append(self.allocator, .{ .err = err });
        return &self.errors.items[self.errors.items.len - 1];
    }

    /// Attaches an error with a message.
    pub fn addErrorWithMsg(self: *Self, err: anyerror, message: []const u8) !*HandlerError {
        const msg_copy = try self.allocator.dupe(u8, message);
        try self.errors.append(self.allocator, .{
            .err = err,
            .message = msg_copy,
            .message_owned = true,
        });
        return &self.errors.items[self.errors.items.len - 1];
    }

    /// Returns the last error attached to this context, or null.
    pub fn lastError(self: *const Self) ?*const HandlerError {
        if (self.errors.items.len == 0) return null;
        return &self.errors.items[self.errors.items.len - 1];
    }

    /// Returns true if any errors have been attached.
    pub fn hasErrors(self: *const Self) bool {
        return self.errors.items.len > 0;
    }

    /// Returns errors filtered by type.
    /// Caller owns the returned slice and must free it.
    pub fn errorsByType(self: *Self, err_type: ErrorType) ![]const HandlerError {
        var results = std.ArrayListUnmanaged(HandlerError){};
        for (self.errors.items) |e| {
            if (e.err_type == err_type) {
                try results.append(self.allocator, e);
            }
        }
        return results.toOwnedSlice(self.allocator);
    }

    /// Serializes all public errors as a JSON array string.
    /// Private errors are excluded. Caller owns the returned slice.
    pub fn errorsJSON(self: *Self) ![]u8 {
        var buf = std.ArrayListUnmanaged(u8){};
        errdefer buf.deinit(self.allocator);

        try buf.append(self.allocator, '[');
        var first = true;
        for (self.errors.items) |e| {
            if (e.err_type == .private) continue;
            if (!first) try buf.append(self.allocator, ',');
            first = false;
            try buf.appendSlice(self.allocator, "{\"error\":\"");
            try buf.appendSlice(self.allocator, e.getMessage());
            try buf.appendSlice(self.allocator, "\",\"type\":\"");
            try buf.appendSlice(self.allocator, @tagName(e.err_type));
            try buf.appendSlice(self.allocator, "\"}");
        }
        try buf.append(self.allocator, ']');

        return buf.toOwnedSlice(self.allocator);
    }

    // -- Abort helpers --

    /// Returns true if the middleware chain has been aborted.
    pub fn isAborted(self: *const Self) bool {
        return self.is_aborted;
    }

    // -- Raw body access --

    /// Returns the raw request body bytes (like Gin's `c.GetRawData()`).
    pub fn getRawData(self: *const Self) ?[]const u8 {
        return self.request.body;
    }

    // -- Query array access --

    /// Returns all values for a query parameter with the same name.
    /// Caller owns the returned slice and must free it.
    pub fn queryArray(self: *Self, name: []const u8) ![]const []const u8 {
        const qs = self.request.uri.query orelse return self.allocator.alloc([]const u8, 0);
        var results = std.ArrayListUnmanaged([]const u8){};
        var iter = mem.splitScalar(u8, qs, '&');
        while (iter.next()) |pair| {
            if (pair.len == 0) continue;
            if (mem.indexOfScalar(u8, pair, '=')) |eq_pos| {
                const key = pair[0..eq_pos];
                if (mem.eql(u8, key, name)) {
                    try results.append(self.allocator, pair[eq_pos + 1 ..]);
                }
            }
        }
        return results.toOwnedSlice(self.allocator);
    }

    // -- Form array access --

    /// Returns all values for a form field with the same name.
    /// Caller owns the returned slice and must free it.
    pub fn postFormArray(self: *Self, name: []const u8) ![]const []const u8 {
        const body = self.request.body orelse return self.allocator.alloc([]const u8, 0);
        const ct = self.request.headers.get(HeaderName.CONTENT_TYPE) orelse return self.allocator.alloc([]const u8, 0);
        if (!mem.startsWith(u8, ct, "application/x-www-form-urlencoded")) return self.allocator.alloc([]const u8, 0);
        var results = std.ArrayListUnmanaged([]const u8){};
        var iter = mem.splitScalar(u8, body, '&');
        while (iter.next()) |pair| {
            if (pair.len == 0) continue;
            if (mem.indexOfScalar(u8, pair, '=')) |eq_pos| {
                const key = pair[0..eq_pos];
                if (mem.eql(u8, key, name)) {
                    try results.append(self.allocator, pair[eq_pos + 1 ..]);
                }
            }
        }
        return results.toOwnedSlice(self.allocator);
    }

    // -- File upload helpers --

    /// Represents an uploaded file from a multipart form.
    pub const UploadedFile = struct {
        filename: []const u8,
        content_type: []const u8,
        data: []const u8,
    };

    /// Parses a multipart form upload and returns the first file matching `field_name`.
    /// Returns null if no file is found or the request is not multipart.
    pub fn formFile(self: *Self, field_name: []const u8) ?UploadedFile {
        const ct = self.request.headers.get(HeaderName.CONTENT_TYPE) orelse return null;
        if (!mem.startsWith(u8, ct, "multipart/form-data")) return null;
        const body = self.request.body orelse return null;

        // Extract boundary from Content-Type
        const boundary = extractBoundary(ct) orelse return null;

        // Parse multipart parts
        return parseMultipartFile(body, boundary, field_name);
    }

    /// Saves an uploaded file to the given destination path.
    pub fn saveUploadedFile(self: *Self, uploaded: UploadedFile, dest_path: []const u8) !void {
        _ = self;
        const f = try std.fs.cwd().createFile(dest_path, .{});
        defer f.close();
        try f.writeAll(uploaded.data);
    }
};

// ============================================================================
// SSE (Server-Sent Events) helpers
// ============================================================================

/// Formats a Server-Sent Event message.
/// Returns the formatted SSE data that can be sent to the client.
/// Caller owns the returned slice.
pub fn formatSSEvent(allocator: Allocator, name: ?[]const u8, data: []const u8) ![]u8 {
    var buf = std.ArrayListUnmanaged(u8){};
    errdefer buf.deinit(allocator);

    if (name) |event_name| {
        try buf.appendSlice(allocator, "event: ");
        try buf.appendSlice(allocator, event_name);
        try buf.appendSlice(allocator, "\n");
    }

    // Split data by newlines and prefix each line with "data: "
    var lines = mem.splitScalar(u8, data, '\n');
    while (lines.next()) |line| {
        try buf.appendSlice(allocator, "data: ");
        try buf.appendSlice(allocator, line);
        try buf.appendSlice(allocator, "\n");
    }

    // Empty line terminates the event
    try buf.appendSlice(allocator, "\n");

    return buf.toOwnedSlice(allocator);
}

/// Formats an SSE event with an id field.
pub fn formatSSEventWithId(allocator: Allocator, name: ?[]const u8, data: []const u8, id: []const u8) ![]u8 {
    var buf = std.ArrayListUnmanaged(u8){};
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, "id: ");
    try buf.appendSlice(allocator, id);
    try buf.appendSlice(allocator, "\n");

    if (name) |event_name| {
        try buf.appendSlice(allocator, "event: ");
        try buf.appendSlice(allocator, event_name);
        try buf.appendSlice(allocator, "\n");
    }

    var lines = mem.splitScalar(u8, data, '\n');
    while (lines.next()) |line| {
        try buf.appendSlice(allocator, "data: ");
        try buf.appendSlice(allocator, line);
        try buf.appendSlice(allocator, "\n");
    }

    try buf.appendSlice(allocator, "\n");

    return buf.toOwnedSlice(allocator);
}

// ============================================================================
// Internal helpers
// ============================================================================

/// Extract boundary string from Content-Type header.
fn extractBoundary(content_type: []const u8) ?[]const u8 {
    const needle = "boundary=";
    const idx = mem.indexOf(u8, content_type, needle) orelse return null;
    var boundary = content_type[idx + needle.len ..];
    // Remove surrounding quotes if present
    if (boundary.len >= 2 and boundary[0] == '"') {
        boundary = boundary[1..];
        if (mem.indexOfScalar(u8, boundary, '"')) |end| {
            boundary = boundary[0..end];
        }
    }
    // Trim at semicolon
    if (mem.indexOfScalar(u8, boundary, ';')) |semi| {
        boundary = boundary[0..semi];
    }
    return if (boundary.len > 0) boundary else null;
}

/// Parse a single file from multipart body.
fn parseMultipartFile(body: []const u8, boundary: []const u8, field_name: []const u8) ?Context.UploadedFile {
    // Multipart delimiter: --boundary
    var delim_buf: [256]u8 = undefined;
    if (boundary.len + 2 > delim_buf.len) return null;
    delim_buf[0] = '-';
    delim_buf[1] = '-';
    @memcpy(delim_buf[2 .. 2 + boundary.len], boundary);
    const delim = delim_buf[0 .. 2 + boundary.len];

    var parts = mem.splitSequence(u8, body, delim);
    while (parts.next()) |part| {
        if (part.len < 4) continue;
        // Each part starts with \r\n, then headers, then \r\n\r\n, then data
        const header_end = mem.indexOf(u8, part, "\r\n\r\n") orelse continue;
        const part_headers = part[0..header_end];
        const part_body_raw = part[header_end + 4 ..];

        // Trim trailing \r\n from part body
        const part_body = if (part_body_raw.len >= 2 and
            part_body_raw[part_body_raw.len - 2] == '\r' and
            part_body_raw[part_body_raw.len - 1] == '\n')
            part_body_raw[0 .. part_body_raw.len - 2]
        else
            part_body_raw;

        // Check Content-Disposition for our field name
        const disp_needle = "Content-Disposition:";
        const disp_idx = mem.indexOf(u8, part_headers, disp_needle) orelse continue;
        const disp_line_start = part_headers[disp_idx + disp_needle.len ..];
        const disp_line_end = mem.indexOf(u8, disp_line_start, "\r\n") orelse disp_line_start.len;
        const disp_line = disp_line_start[0..disp_line_end];

        // Check name="field_name"
        var name_needle_buf: [256]u8 = undefined;
        const name_prefix = "name=\"";
        if (field_name.len + name_prefix.len + 1 > name_needle_buf.len) continue;
        @memcpy(name_needle_buf[0..name_prefix.len], name_prefix);
        @memcpy(name_needle_buf[name_prefix.len .. name_prefix.len + field_name.len], field_name);
        name_needle_buf[name_prefix.len + field_name.len] = '"';
        const name_needle = name_needle_buf[0 .. name_prefix.len + field_name.len + 1];

        if (mem.indexOf(u8, disp_line, name_needle) == null) continue;

        // Extract filename
        const fn_needle = "filename=\"";
        const fn_idx = mem.indexOf(u8, disp_line, fn_needle) orelse continue;
        const fn_start = disp_line[fn_idx + fn_needle.len ..];
        const fn_end = mem.indexOfScalar(u8, fn_start, '"') orelse continue;
        const filename = fn_start[0..fn_end];

        // Extract Content-Type of this part
        const ct_needle = "Content-Type:";
        var part_ct: []const u8 = "application/octet-stream";
        if (mem.indexOf(u8, part_headers, ct_needle)) |ct_idx| {
            const ct_start = part_headers[ct_idx + ct_needle.len ..];
            const ct_end = mem.indexOf(u8, ct_start, "\r\n") orelse ct_start.len;
            part_ct = mem.trim(u8, ct_start[0..ct_end], " ");
        }

        return .{
            .filename = filename,
            .content_type = part_ct,
            .data = part_body,
        };
    }
    return null;
}

/// Parse a single query parameter from a query string.
/// This is a zero-allocation lookup; it does NOT decode percent-encoding.
fn getQueryParam(qs: []const u8, name: []const u8) ?[]const u8 {
    var iter = mem.splitScalar(u8, qs, '&');
    while (iter.next()) |pair| {
        if (pair.len == 0) continue;
        if (mem.indexOfScalar(u8, pair, '=')) |eq_pos| {
            const key = pair[0..eq_pos];
            const value = pair[eq_pos + 1 ..];
            if (mem.eql(u8, key, name)) {
                return value;
            }
        } else {
            // key with no value
            if (mem.eql(u8, pair, name)) {
                return "";
            }
        }
    }
    return null;
}

// ============================================================================
// Server
// ============================================================================

/// HTTP Server.
pub const Server = struct {
    allocator: Allocator,
    config: ServerConfig,
    router: Router,
    middleware: std.ArrayListUnmanaged(Middleware) = .empty,
    ws_handlers: std.StringHashMapUnmanaged(WebSocketHandler) = .{},
    static_dirs: std.StringHashMapUnmanaged([]const u8) = .{},
    listener: ?zio.net.Server = null,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    tls12_owned: ?OwnedTls12Config = null,

    // Runtime concurrency preference
    threading_enabled: bool = false,

    // Runtime stats
    requests_handled: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    active_requests: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    total_errors: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    const Self = @This();

    /// Creates a server with default configuration.
    pub fn init(allocator: Allocator) Self {
        return initWithConfig(allocator, .{});
    }

    /// Creates a server with custom configuration.
    pub fn initWithConfig(allocator: Allocator, config: ServerConfig) Self {
        return .{
            .allocator = allocator,
            .config = config,
            .router = Router.init(allocator),
        };
    }

    /// Releases all server resources.
    pub fn deinit(self: *Self) void {
        self.stop();
        self.clearOwnedTls12Config();
        self.router.deinit();
        self.middleware.deinit(self.allocator);
        self.ws_handlers.deinit(self.allocator);
        {
            var it = self.static_dirs.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                self.allocator.free(entry.value_ptr.*);
            }
            self.static_dirs.deinit(self.allocator);
        }
    }

    /// Enables multi-threaded request handling.
    pub fn enableThreading(self: *Self, config: ThreadingConfig) void {
        self.threading_enabled = true;
        self.config.threads = config.num_workers;
    }

    /// Disables multi-threaded request handling.
    pub fn disableThreading(self: *Self) void {
        self.threading_enabled = false;
        self.config.threads = 1;
    }

    /// Returns true if multi-threading is enabled.
    pub fn isThreadingEnabled(self: *const Self) bool {
        return self.threading_enabled;
    }

    /// Enables TLS 1.2 HTTPS mode.
    pub fn enableTls12(self: *Self, config: Tls12Config) void {
        self.clearOwnedTls12Config();
        self.config.tls12 = config;
    }

    /// Disables TLS and serves plain HTTP.
    pub fn disableTls(self: *Self) void {
        self.clearOwnedTls12Config();
        self.config.tls12 = null;
    }

    /// Enables TLS 1.2 HTTPS mode from PEM-encoded cert/key.
    pub fn enableTls12Pem(self: *Self, config: Tls12PemConfig) !void {
        self.clearOwnedTls12Config();

        var cert_chain_der = try self.allocator.alloc([]const u8, config.cert_chain_pem.len);
        errdefer self.allocator.free(cert_chain_der);

        for (config.cert_chain_pem, 0..) |pem, i| {
            cert_chain_der[i] = try pemToDerAlloc(self.allocator, pem);
        }
        errdefer {
            for (cert_chain_der) |cert_der| self.allocator.free(cert_der);
        }

        const private_key_der = try pemToDerAlloc(self.allocator, config.private_key_pem);
        errdefer self.allocator.free(private_key_der);

        self.tls12_owned = .{
            .cert_chain_der = cert_chain_der,
            .private_key_der = private_key_der,
        };
        self.config.tls12 = .{
            .cert_chain_der = cert_chain_der,
            .private_key_der = private_key_der,
            .supported_alpn_protocols = config.supported_alpn_protocols,
        };
    }

    /// Returns runtime statistics.
    pub fn getStats(self: *const Self) RuntimeStats {
        return .{
            .requests_handled = self.requests_handled.load(.acquire),
            .active_requests = self.active_requests.load(.acquire),
            .total_errors = self.total_errors.load(.acquire),
            .executors = self.config.threads,
        };
    }

    // -- Middleware --

    /// Adds global middleware to the server (applies to all routes).
    pub fn use(self: *Self, mw: Middleware) !void {
        try self.middleware.append(self.allocator, mw);
    }

    // -- Route registration --

    /// Registers a route handler.
    pub fn route(self: *Self, method: types.Method, path: []const u8, handler: Handler) !void {
        try self.router.add(method, path, handler);
    }

    /// Registers a GET route.
    pub fn get(self: *Self, path: []const u8, handler: Handler) !void {
        try self.route(.GET, path, handler);
    }

    /// Registers a POST route.
    pub fn post(self: *Self, path: []const u8, handler: Handler) !void {
        try self.route(.POST, path, handler);
    }

    /// Registers a PUT route.
    pub fn put(self: *Self, path: []const u8, handler: Handler) !void {
        try self.route(.PUT, path, handler);
    }

    /// Registers a DELETE route.
    pub fn delete(self: *Self, path: []const u8, handler: Handler) !void {
        try self.route(.DELETE, path, handler);
    }

    /// Registers a PATCH route.
    pub fn patch(self: *Self, path: []const u8, handler: Handler) !void {
        try self.route(.PATCH, path, handler);
    }

    /// Registers a HEAD route.
    pub fn head(self: *Self, path: []const u8, handler: Handler) !void {
        try self.route(.HEAD, path, handler);
    }

    /// Registers an OPTIONS route.
    pub fn options(self: *Self, path: []const u8, handler: Handler) !void {
        try self.route(.OPTIONS, path, handler);
    }

    /// Registers a handler for all HTTP methods on the given path.
    pub fn any(self: *Self, path: []const u8, handler: Handler) !void {
        const methods = [_]types.Method{ .GET, .POST, .PUT, .DELETE, .PATCH, .HEAD, .OPTIONS };
        for (methods) |method| {
            try self.route(method, path, handler);
        }
    }

    // -- Per-route middleware (Gin-style r.GET("/path", mw1, mw2, handler)) --

    /// Registers a route handler with per-route middleware.
    pub fn routeWithMiddleware(self: *Self, method: types.Method, path: []const u8, mw: []const Middleware, handler: Handler) !void {
        try self.router.addWithMiddleware(method, path, handler, mw);
    }

    /// Registers a GET route with per-route middleware.
    pub fn getWith(self: *Self, path: []const u8, mw: []const Middleware, handler: Handler) !void {
        try self.routeWithMiddleware(.GET, path, mw, handler);
    }

    /// Registers a POST route with per-route middleware.
    pub fn postWith(self: *Self, path: []const u8, mw: []const Middleware, handler: Handler) !void {
        try self.routeWithMiddleware(.POST, path, mw, handler);
    }

    /// Registers a PUT route with per-route middleware.
    pub fn putWith(self: *Self, path: []const u8, mw: []const Middleware, handler: Handler) !void {
        try self.routeWithMiddleware(.PUT, path, mw, handler);
    }

    /// Registers a DELETE route with per-route middleware.
    pub fn deleteWith(self: *Self, path: []const u8, mw: []const Middleware, handler: Handler) !void {
        try self.routeWithMiddleware(.DELETE, path, mw, handler);
    }

    /// Registers a PATCH route with per-route middleware.
    pub fn patchWith(self: *Self, path: []const u8, mw: []const Middleware, handler: Handler) !void {
        try self.routeWithMiddleware(.PATCH, path, mw, handler);
    }

    /// Sets the 404 Not Found handler.
    pub fn noRoute(self: *Self, handler: Handler) void {
        self.router.setNotFound(handler);
    }

    /// Sets the 405 Method Not Allowed handler.
    pub fn noMethod(self: *Self, handler: Handler) void {
        self.router.setMethodNotAllowed(handler);
    }

    /// Creates a route group with a prefix.
    pub fn group(self: *Self, prefix: []const u8) RouteGroup {
        return self.router.group(prefix);
    }

    // -- Static file serving --

    /// Serves static files from a directory.
    ///
    /// Example:
    /// ```zig
    /// try server.static("/assets", "./public");
    /// ```
    pub fn static(self: *Self, url_prefix: []const u8, dir_path: []const u8) !void {
        // Register a catch-all route under the prefix
        const handler = struct {
            fn h(ctx: *Context) anyerror!Response {
                const filepath = ctx.param("filepath") orelse return ctx.status(404).text("Not Found");

                // Look up the static base directory from context data
                const base_dir: []const u8 = if (ctx.get("_static_dir")) |ptr|
                    @as(*const []const u8, @ptrCast(@alignCast(ptr))).*
                else
                    ".";

                // Build full path: base_dir/filepath
                var full_path = std.ArrayListUnmanaged(u8){};
                defer full_path.deinit(ctx.allocator);
                full_path.appendSlice(ctx.allocator, base_dir) catch return ctx.status(500).text("Internal Server Error");
                if (base_dir.len > 0 and base_dir[base_dir.len - 1] != '/') {
                    full_path.append(ctx.allocator, '/') catch return ctx.status(500).text("Internal Server Error");
                }
                full_path.appendSlice(ctx.allocator, filepath) catch return ctx.status(500).text("Internal Server Error");

                return ctx.file(full_path.items);
            }
        }.h;

        // Build pattern: /assets/*filepath
        var pattern = std.ArrayListUnmanaged(u8){};
        defer pattern.deinit(self.allocator);
        try pattern.appendSlice(self.allocator, url_prefix);
        try pattern.appendSlice(self.allocator, "/*filepath");
        const owned_pattern = try self.allocator.dupe(u8, pattern.items);
        // Track the pattern allocation for cleanup
        try self.router.trackOwnedPath(owned_pattern);

        // Store prefix -> dir_path mapping
        const owned_prefix = try self.allocator.dupe(u8, url_prefix);
        errdefer self.allocator.free(owned_prefix);
        const owned_dir = try self.allocator.dupe(u8, dir_path);
        errdefer self.allocator.free(owned_dir);
        try self.static_dirs.put(self.allocator, owned_prefix, owned_dir);

        try self.router.add(.GET, owned_pattern, handler);
        // Also serve HEAD requests for static files
        try self.router.add(.HEAD, owned_pattern, handler);
    }

    // -- WebSocket --

    /// Registers a WebSocket handler for a path.
    pub fn websocket(self: *Self, path: []const u8, handler: WebSocketHandler) !void {
        try self.ws_handlers.put(self.allocator, path, handler);
    }

    /// Alias for websocket() - registers a WebSocket handler.
    pub fn ws(self: *Self, path: []const u8, handler: WebSocketHandler) !void {
        try self.websocket(path, handler);
    }

    // -- Server lifecycle --

    /// Starts the server and begins accepting connections.
    pub fn listen(self: *Self) !void {
        if (self.running.load(.acquire)) return;
        self.running.store(true, .release);

        const executors = self.resolveExecutorCount();
        const rt = try zio.Runtime.init(self.allocator, .{ .executors = .exact(executors) });
        defer rt.deinit();

        const addr = try zio.net.IpAddress.parseIp(self.config.host, self.config.port);
        self.listener = try addr.listen(.{});
        defer {
            if (self.listener) |listener_val| {
                listener_val.close();
            }
            self.listener = null;
            self.running.store(false, .release);
        }

        std.debug.print("Server listening on {s}:{d} (zio async, {d} executors)\n", .{
            self.config.host,
            self.config.port,
            executors,
        });

        var io_group: zio.Group = .init;
        defer io_group.cancel();

        while (self.running.load(.acquire)) {
            const listener_val = self.listener orelse break;
            const conn = listener_val.accept() catch |err| {
                if (!self.running.load(.acquire)) break;
                std.debug.print("Accept error: {}\n", .{err});
                continue;
            };

            const max_connections: u64 = if (self.config.max_connections == 0)
                std.math.maxInt(u64)
            else
                self.config.max_connections;
            const prev_active = self.active_requests.fetchAdd(1, .monotonic);
            if (prev_active >= max_connections) {
                _ = self.active_requests.fetchSub(1, .monotonic);
                _ = self.total_errors.fetchAdd(1, .monotonic);
                self.sendErrorStream(conn, 503, .none) catch {};
                conn.close();
                continue;
            }

            errdefer conn.close();

            io_group.spawn(handleConnectionTask, .{ self, conn }) catch |err| {
                std.debug.print("Spawn error: {}\n", .{err});
                _ = self.active_requests.fetchSub(1, .monotonic);
                _ = self.total_errors.fetchAdd(1, .monotonic);
                conn.close();
                continue;
            };
        }

        io_group.wait() catch {};
    }

    /// Stops the server gracefully.
    /// Waits up to `shutdown_timeout_ms` for active connections to finish
    /// before closing the listener. If timeout expires, connections are
    /// dropped immediately.
    pub fn stop(self: *Self) void {
        self.running.store(false, .release);

        // Wait for active connections to drain (graceful shutdown)
        const timeout_ms = self.config.shutdown_timeout_ms;
        if (timeout_ms > 0 and self.active_requests.load(.acquire) > 0) {
            const start = std.time.milliTimestamp();
            while (self.active_requests.load(.acquire) > 0) {
                const elapsed = std.time.milliTimestamp() - start;
                if (elapsed >= @as(i64, @intCast(timeout_ms))) break;
                std.Thread.sleep(1 * std.time.ns_per_ms);
            }
        }

        if (self.listener) |listener_val| {
            listener_val.close();
            self.listener = null;
        }
    }

    fn handleConnectionTask(self: *Self, stream: zio.net.Stream) anyerror!void {
        defer _ = self.active_requests.fetchSub(1, .monotonic);

        var conn_stream = stream;
        var should_close_stream = true;
        var tls_conn_storage: tls_server.TlsServer(zio.net.Stream) = undefined;
        var tls_conn: ?*tls_server.TlsServer(zio.net.Stream) = null;
        const request_timeout = self.requestIoTimeout();
        const keep_alive_timeout = self.keepAliveIoTimeout();

        if (self.config.tls12) |tls_cfg| {
            tls_conn_storage = tls_server.TlsServer(zio.net.Stream).init(conn_stream, self.allocator);
            tls_conn_storage.setReadTimeout(request_timeout);
            tls_conn_storage.setWriteTimeout(request_timeout);
            tls_conn_storage.handshake(.{
                .cert_chain = tls_cfg.cert_chain_der,
                .private_key_der = tls_cfg.private_key_der,
                .supported_alpn_protocols = tls_cfg.supported_alpn_protocols,
                .allocator = self.allocator,
            }) catch |err| {
                _ = self.total_errors.fetchAdd(1, .monotonic);
                switch (err) {
                    error.ConnectionClosed,
                    error.WriteFailed,
                    error.BadRecordMac,
                    error.DecodeError,
                    error.UnsupportedCipherSuite,
                    error.UnsupportedProtocolVersion,
                    => {},
                    else => std.debug.print("TLS handshake failed: {}\n", .{err}),
                }
                return;
            };
            tls_conn = &tls_conn_storage;
        }

        defer {
            if (should_close_stream) {
                if (tls_conn) |t| {
                    t.close();
                }
                conn_stream.close();
            }
        }

        var buffer: [8192]u8 = undefined;
        var parser = Parser.init(self.allocator);
        defer parser.deinit();
        parser.max_body_size = self.config.max_body_size;

        var pending = std.ArrayListUnmanaged(u8){};
        defer pending.deinit(self.allocator);
        var pending_offset: usize = 0;

        while (self.running.load(.acquire)) {
            parser.reset();

            var waiting_for_first_byte = pending_offset >= pending.items.len;

            while (!parser.isComplete() and !parser.isError()) {
                if (pending_offset < pending.items.len) {
                    const consumed = parser.feed(pending.items[pending_offset..]) catch |err| {
                        _ = self.total_errors.fetchAdd(1, .monotonic);
                        self.sendErrorConnection(&conn_stream, tls_conn, statusCodeForParseError(err), request_timeout) catch {};
                        return;
                    };

                    if (consumed > 0) {
                        waiting_for_first_byte = false;
                    }

                    pending_offset += consumed;
                    if (pending_offset == pending.items.len) {
                        pending.clearRetainingCapacity();
                        pending_offset = 0;
                    } else if (pending_offset >= 4096) {
                        compactPendingBuffer(&pending, &pending_offset);
                    }

                    if (parser.isComplete() or parser.isError()) {
                        break;
                    }

                    if (consumed > 0) {
                        continue;
                    }
                }

                const read_timeout = if (waiting_for_first_byte) keep_alive_timeout else request_timeout;
                const n = if (tls_conn) |t|
                    blk: {
                        t.setReadTimeout(read_timeout);
                        break :blk t.read(&buffer) catch |err| {
                            _ = self.total_errors.fetchAdd(1, .monotonic);
                            if (waiting_for_first_byte and err == tls_server.TlsError.ConnectionClosed) {
                                return;
                            }
                            return err;
                        };
                    }
                else
                    conn_stream.read(&buffer, read_timeout) catch |err| switch (err) {
                        error.Timeout => {
                            if (waiting_for_first_byte) {
                                return;
                            }
                            _ = self.total_errors.fetchAdd(1, .monotonic);
                            self.sendErrorConnection(&conn_stream, tls_conn, 408, request_timeout) catch {};
                            return;
                        },
                        else => {
                            _ = self.total_errors.fetchAdd(1, .monotonic);
                            return err;
                        },
                    };

                if (n == 0) {
                    return;
                }

                waiting_for_first_byte = false;
                try pending.appendSlice(self.allocator, buffer[0..n]);
            }

            if (parser.isError()) {
                _ = self.total_errors.fetchAdd(1, .monotonic);
                try self.sendErrorConnection(&conn_stream, tls_conn, 400, request_timeout);
                return;
            }

            var req = try Request.init(
                self.allocator,
                parser.method orelse .GET,
                parser.path orelse "/",
            );
            defer req.deinit();

            req.version = parser.version;

            for (parser.headers.entries.items) |h| {
                try req.headers.append(h.name, h.value);
            }

            if (parser.getBody().len > 0) {
                req.body = parser.getBody();
            }

            if (ws_handler.isUpgradeRequest(&req)) {
                if (self.ws_handlers.get(req.uri.path)) |ws_h| {
                    var ws_conn = if (tls_conn) |tls_stream|
                        ws_handler.acceptUpgradeTlsStream(self.allocator, tls_stream, &req, null) catch |err| {
                            _ = self.total_errors.fetchAdd(1, .monotonic);
                            return err;
                        }
                    else
                        ws_handler.acceptUpgradeStream(self.allocator, conn_stream, &req, null) catch |err| {
                            _ = self.total_errors.fetchAdd(1, .monotonic);
                            return err;
                        };

                    if (pending_offset < pending.items.len) {
                        try ws_conn.frame_reader.feed(pending.items[pending_offset..]);
                        pending.clearRetainingCapacity();
                        pending_offset = 0;
                    }

                    if (tls_conn == null) {
                        should_close_stream = false;
                    }
                    defer ws_conn.deinit();

                    ws_h(&ws_conn) catch |err| {
                        std.debug.print("WebSocket handler error: {}\n", .{err});
                        _ = self.total_errors.fetchAdd(1, .monotonic);
                    };
                    return;
                }

                try self.sendErrorConnection(&conn_stream, tls_conn, 404, request_timeout);
                return;
            }

            // -- Route lookup with 405 support --
            var ctx = Context.init(self.allocator, &req);
            ctx.server_config = &self.config;
            defer ctx.deinit();

            var route_params_buf: [MAX_ROUTE_PARAMS]RouteParam = undefined;
            const find_result = self.router.findEx(req.method, req.uri.path, &route_params_buf);

            // Handle OPTIONS auto-response before route dispatch
            if (req.method == .OPTIONS and self.router.handle_options_auto) {
                const allowed = self.router.allowedMethods(req.uri.path);
                var any_allowed = false;
                for (allowed) |a| {
                    if (a) {
                        any_allowed = true;
                        break;
                    }
                }
                if (any_allowed) {
                    var options_resp = Response.init(self.allocator, 204);
                    defer options_resp.deinit();
                    var allow_buf: [128]u8 = undefined;
                    options_resp.headers.set("Allow", Router.formatAllowedMethods(allowed, &allow_buf)) catch {};
                    options_resp.headers.set(HeaderName.CONTENT_LENGTH, "0") catch {};
                    const formatted = try http.formatResponse(&options_resp, self.allocator);
                    defer self.allocator.free(formatted);
                    try writeConnection(&conn_stream, tls_conn, formatted, request_timeout);
                    _ = self.requests_handled.fetchAdd(1, .monotonic);
                    if (!self.shouldKeepAlive(&req)) return;
                    continue;
                }
            }

            switch (find_result) {
                .trailing_slash_redirect => {
                    // Send 301 redirect to path with/without trailing slash
                    const path = req.uri.path;
                    var redirect_resp = Response.init(self.allocator, 301);
                    defer redirect_resp.deinit();
                    if (path.len > 1 and path[path.len - 1] == '/') {
                        redirect_resp.headers.set(HeaderName.LOCATION, path[0 .. path.len - 1]) catch {};
                    } else {
                        var redir_buf: [2048]u8 = undefined;
                        if (path.len < redir_buf.len - 1) {
                            @memcpy(redir_buf[0..path.len], path);
                            redir_buf[path.len] = '/';
                            redirect_resp.headers.set(HeaderName.LOCATION, redir_buf[0 .. path.len + 1]) catch {};
                        }
                    }
                    redirect_resp.headers.set(HeaderName.CONTENT_LENGTH, "0") catch {};
                    const formatted = try http.formatResponse(&redirect_resp, self.allocator);
                    defer self.allocator.free(formatted);
                    try writeConnection(&conn_stream, tls_conn, formatted, request_timeout);
                    _ = self.requests_handled.fetchAdd(1, .monotonic);
                    if (!self.shouldKeepAlive(&req)) return;
                    continue;
                },
                .not_found => {
                    if (self.router.not_found_handler) |nf_handler| {
                        var response = nf_handler(&ctx) catch |err| {
                            std.debug.print("NotFound handler error: {}\n", .{err});
                            _ = self.total_errors.fetchAdd(1, .monotonic);
                            try self.sendErrorConnection(&conn_stream, tls_conn, 500, request_timeout);
                            if (!self.shouldKeepAlive(&req)) return;
                            continue;
                        };
                        defer response.deinit();
                        const formatted = try http.formatResponse(&response, self.allocator);
                        defer self.allocator.free(formatted);
                        try writeConnection(&conn_stream, tls_conn, formatted, request_timeout);
                        _ = self.requests_handled.fetchAdd(1, .monotonic);
                    } else {
                        try self.sendErrorConnection(&conn_stream, tls_conn, 404, request_timeout);
                    }
                    if (!self.shouldKeepAlive(&req)) return;
                    continue;
                },
                .method_not_allowed => {
                    if (self.router.method_not_allowed_handler) |mna_handler| {
                        var response = mna_handler(&ctx) catch |err| {
                            std.debug.print("MethodNotAllowed handler error: {}\n", .{err});
                            _ = self.total_errors.fetchAdd(1, .monotonic);
                            try self.sendErrorConnection(&conn_stream, tls_conn, 500, request_timeout);
                            if (!self.shouldKeepAlive(&req)) return;
                            continue;
                        };
                        defer response.deinit();
                        const formatted = try http.formatResponse(&response, self.allocator);
                        defer self.allocator.free(formatted);
                        try writeConnection(&conn_stream, tls_conn, formatted, request_timeout);
                        _ = self.requests_handled.fetchAdd(1, .monotonic);
                    } else {
                        try self.sendErrorConnection(&conn_stream, tls_conn, 405, request_timeout);
                    }
                    if (!self.shouldKeepAlive(&req)) return;
                    continue;
                },
                .matched => |matched| {
                    // Populate context params
                    for (matched.params) |p| {
                        try ctx.params.put(p.name, p.value);
                    }
                    ctx.matched_path = matched.full_pattern;

                    // Inject static directory base path if this is a static file route
                    var static_dir_ptr: []const u8 = undefined;
                    {
                        var sd_it = self.static_dirs.iterator();
                        while (sd_it.next()) |entry| {
                            if (mem.startsWith(u8, req.uri.path, entry.key_ptr.*)) {
                                static_dir_ptr = entry.value_ptr.*;
                                try ctx.set("_static_dir", @ptrCast(@constCast(&static_dir_ptr)));
                                break;
                            }
                        }
                    }

                    // Execute middleware chain: global + route middleware + handler
                    var response = MiddlewareChain.execute(
                        &ctx,
                        self.middleware.items,
                        matched.middleware,
                        matched.handler,
                    ) catch |err| {
                        std.debug.print("Handler error: {}\n", .{err});
                        _ = self.total_errors.fetchAdd(1, .monotonic);
                        try self.sendErrorConnection(&conn_stream, tls_conn, 500, request_timeout);
                        if (!self.shouldKeepAlive(&req)) return;
                        continue;
                    };

                    defer response.deinit();

                    const formatted = try http.formatResponse(&response, self.allocator);
                    defer self.allocator.free(formatted);

                    try writeConnection(&conn_stream, tls_conn, formatted, request_timeout);
                    _ = self.requests_handled.fetchAdd(1, .monotonic);
                },
            }

            if (!self.shouldKeepAlive(&req)) {
                return;
            }
        }
    }

    fn sendErrorConnection(
        self: *Self,
        stream: *zio.net.Stream,
        tls_conn: ?*tls_server.TlsServer(zio.net.Stream),
        code: u16,
        timeout_val: zio.Timeout,
    ) !void {
        var resp = Response.init(self.allocator, code);
        defer resp.deinit();

        const formatted = try http.formatResponse(&resp, self.allocator);
        defer self.allocator.free(formatted);

        try writeConnection(stream, tls_conn, formatted, timeout_val);
    }

    fn writeConnection(
        stream: *zio.net.Stream,
        tls_conn: ?*tls_server.TlsServer(zio.net.Stream),
        data: []const u8,
        timeout_val: zio.Timeout,
    ) !void {
        if (tls_conn) |t| {
            t.setWriteTimeout(timeout_val);
            try t.writeAll(data);
        } else {
            try stream.writeAll(data, timeout_val);
        }
    }

    fn sendErrorStream(self: *Self, stream: zio.net.Stream, code: u16, timeout_val: zio.Timeout) !void {
        var resp = Response.init(self.allocator, code);
        defer resp.deinit();

        const formatted = try http.formatResponse(&resp, self.allocator);
        defer self.allocator.free(formatted);

        try stream.writeAll(formatted, timeout_val);
    }

    fn requestIoTimeout(self: *const Self) zio.Timeout {
        return timeoutFromMs(self.config.request_timeout_ms);
    }

    fn keepAliveIoTimeout(self: *const Self) zio.Timeout {
        return timeoutFromMs(self.config.keep_alive_timeout_ms);
    }

    fn timeoutFromMs(ms: u64) zio.Timeout {
        if (ms == 0) return .none;
        return zio.Timeout.fromMilliseconds(ms);
    }

    fn clearOwnedTls12Config(self: *Self) void {
        if (self.tls12_owned) |owned| {
            for (owned.cert_chain_der) |cert_der| {
                self.allocator.free(cert_der);
            }
            self.allocator.free(owned.cert_chain_der);
            self.allocator.free(owned.private_key_der);
            self.tls12_owned = null;
        }
    }

    fn shouldKeepAlive(self: *const Self, req: *const Request) bool {
        if (!self.config.keep_alive) return false;

        if (req.headers.get(HeaderName.CONNECTION)) |connection| {
            if (connectionHeaderHasToken(connection, "close")) return false;
            if (connectionHeaderHasToken(connection, "keep-alive")) return true;
        }

        return req.version == .HTTP_1_1;
    }

    fn connectionHeaderHasToken(value: []const u8, token: []const u8) bool {
        var iter = mem.splitScalar(u8, value, ',');
        while (iter.next()) |part| {
            const trimmed = mem.trim(u8, part, " \t");
            if (std.ascii.eqlIgnoreCase(trimmed, token)) return true;
        }
        return false;
    }

    fn resolveExecutorCount(self: *const Self) u6 {
        var count: u32 = self.config.threads;

        if (count == 0) {
            if (self.threading_enabled) {
                count = @intCast(std.Thread.getCpuCount() catch 1);
            } else {
                count = 1;
            }
        }

        count = @max(@as(u32, 1), count);
        count = @min(@as(u32, 63), count);
        return @intCast(count);
    }
};

fn statusCodeForParseError(err: anyerror) u16 {
    return switch (err) {
        types.HttpError.RequestTooLarge => 413,
        types.HttpError.HeaderTooLarge,
        types.HttpError.TooManyHeaders,
        => 431,
        else => 400,
    };
}

fn compactPendingBuffer(buffer_list: *std.ArrayListUnmanaged(u8), offset: *usize) void {
    if (offset.* == 0) return;

    const remaining = buffer_list.items.len - offset.*;
    if (remaining > 0) {
        std.mem.copyForwards(u8, buffer_list.items[0..remaining], buffer_list.items[offset.*..]);
    }
    buffer_list.shrinkRetainingCapacity(remaining);
    offset.* = 0;
}

// ============================================================================
// Test helpers
// ============================================================================

const ListenThreadContext = struct {
    server: *Server,
    err: ?anyerror = null,
};

const ClientThreadContext = struct {
    port: u16,
    err: ?anyerror = null,
    ok: bool = false,
};

fn runServerInThread(ctx: *ListenThreadContext) void {
    ctx.server.listen() catch |err| {
        ctx.err = err;
    };
}

fn runConcurrentClient(ctx: *ClientThreadContext) void {
    const addr = std.net.Address.parseIp("127.0.0.1", ctx.port) catch |err| {
        ctx.err = err;
        return;
    };

    var socket = socket_mod.Socket.createForAddress(addr) catch |err| {
        ctx.err = err;
        return;
    };
    defer socket.close();

    socket.setRecvTimeout(2000) catch {};
    socket.setSendTimeout(2000) catch {};

    socket.connect(addr) catch |err| {
        ctx.err = err;
        return;
    };

    socket.sendAll(
        "GET /concurrent HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "Connection: close\r\n" ++
            "\r\n",
    ) catch |err| {
        ctx.err = err;
        return;
    };

    var recv_buffer: [2048]u8 = undefined;
    const n = socket.recv(&recv_buffer) catch |err| {
        ctx.err = err;
        return;
    };

    if (n == 0) {
        ctx.err = error.UnexpectedEof;
        return;
    }

    if (std.mem.indexOf(u8, recv_buffer[0..n], "HTTP/1.1 200 OK") == null) {
        ctx.err = error.BadHttpResponse;
        return;
    }

    ctx.ok = true;
}

fn reserveTestPort() !u16 {
    var tcp_listener = try socket_mod.TcpListener.init(try std.net.Address.parseIp("127.0.0.1", 0));
    defer tcp_listener.deinit();

    const addr = try tcp_listener.getLocalAddress();
    return addr.getPort();
}

fn waitForServerReady(port: u16, timeout_ms: u64) !void {
    const addr = try std.net.Address.parseIp("127.0.0.1", port);
    const deadline = std.time.milliTimestamp() + @as(i64, @intCast(timeout_ms));

    while (std.time.milliTimestamp() < deadline) {
        var probe = socket_mod.Socket.createForAddress(addr) catch {
            std.Thread.sleep(5 * std.time.ns_per_ms);
            continue;
        };
        defer probe.close();

        probe.setRecvTimeout(50) catch {};
        probe.setSendTimeout(50) catch {};

        if (probe.connect(addr)) {
            return;
        } else |_| {
            std.Thread.sleep(5 * std.time.ns_per_ms);
            continue;
        }
    }

    return error.ServerStartTimeout;
}

fn parseContentLength(raw_headers: []const u8) ?usize {
    var lines = std.mem.splitSequence(u8, raw_headers, "\r\n");
    while (lines.next()) |line| {
        if (line.len == 0) break;

        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " ");
        if (!std.ascii.eqlIgnoreCase(name, "Content-Length")) continue;

        const value = std.mem.trim(u8, line[colon + 1 ..], " ");
        return std.fmt.parseUnsigned(usize, value, 10) catch null;
    }
    return null;
}

fn readHttpResponse(allocator: Allocator, socket: *socket_mod.Socket) ![]u8 {
    var resp = std.ArrayListUnmanaged(u8){};
    errdefer resp.deinit(allocator);

    while (true) {
        if (std.mem.indexOf(u8, resp.items, "\r\n\r\n")) |headers_end| {
            const header_len = headers_end + 4;
            const content_len = parseContentLength(resp.items[0..header_len]) orelse 0;
            const total_len = header_len + content_len;

            if (resp.items.len >= total_len) {
                const out = try allocator.alloc(u8, total_len);
                @memcpy(out, resp.items[0..total_len]);
                resp.deinit(allocator);
                return out;
            }
        }

        var buf: [1024]u8 = undefined;
        const n = try socket.recv(&buf);
        if (n == 0) return error.UnexpectedEof;
        try resp.appendSlice(allocator, buf[0..n]);
    }
}

fn readHttpResponseTls(allocator: Allocator, session: *tls_client.TlsSession) ![]u8 {
    var resp = std.ArrayListUnmanaged(u8){};
    errdefer resp.deinit(allocator);

    while (true) {
        if (std.mem.indexOf(u8, resp.items, "\r\n\r\n")) |headers_end| {
            const header_len = headers_end + 4;
            const content_len = parseContentLength(resp.items[0..header_len]) orelse 0;
            const total_len = header_len + content_len;

            if (resp.items.len >= total_len) {
                const out = try allocator.alloc(u8, total_len);
                @memcpy(out, resp.items[0..total_len]);
                resp.deinit(allocator);
                return out;
            }
        }

        var buf: [1024]u8 = undefined;
        const n = try session.read(&buf);
        if (n == 0) return error.UnexpectedEof;
        try resp.appendSlice(allocator, buf[0..n]);
    }
}

fn waitForTlsServerReady(port: u16, timeout_ms: u64) !void {
    const deadline = std.time.milliTimestamp() + @as(i64, @intCast(timeout_ms));
    const addr = try std.net.Address.parseIp("127.0.0.1", port);

    while (std.time.milliTimestamp() < deadline) {
        var socket = socket_mod.Socket.createForAddress(addr) catch {
            std.Thread.sleep(5 * std.time.ns_per_ms);
            continue;
        };
        defer socket.close();

        socket.setRecvTimeout(200) catch {};
        socket.setSendTimeout(200) catch {};

        if (socket.connect(addr)) {
            var tls_cfg = tls_client.TlsConfig.insecure(std.heap.page_allocator);
            tls_cfg.setServerName("localhost");
            var session = tls_client.TlsSession.init(tls_cfg);
            defer session.deinit();
            session.attachSocket(&socket);
            if (session.handshake("localhost")) {
                return;
            } else |_| {
                std.Thread.sleep(5 * std.time.ns_per_ms);
                continue;
            }
        } else |_| {
            std.Thread.sleep(5 * std.time.ns_per_ms);
            continue;
        }
    }

    return error.ServerStartTimeout;
}

fn decodeBase64Alloc(allocator: Allocator, b64: []const u8) ![]u8 {
    const out_len = try std.base64.standard.Decoder.calcSizeForSlice(b64);
    const out = try allocator.alloc(u8, out_len);
    errdefer allocator.free(out);
    _ = try std.base64.standard.Decoder.decode(out, b64);
    return out;
}

fn pemToDerAlloc(allocator: Allocator, pem_or_der: []const u8) ![]u8 {
    const begin_prefix = "-----BEGIN ";
    const end_prefix = "-----END ";

    const begin_idx = mem.indexOf(u8, pem_or_der, "-----BEGIN ") orelse {
        return allocator.dupe(u8, pem_or_der);
    };

    const begin_line = pem_or_der[begin_idx + begin_prefix.len ..];
    const begin_label_end = mem.indexOf(u8, begin_line, "-----") orelse return error.InvalidPem;
    const begin_label = begin_line[0..begin_label_end];
    if (begin_label.len == 0) return error.InvalidPem;

    const begin_line_end_rel = mem.indexOfScalar(u8, begin_line, '\n') orelse return error.InvalidPem;
    const payload_start = begin_idx + begin_prefix.len + begin_line_end_rel + 1;

    const end_idx_rel = mem.indexOf(u8, pem_or_der[payload_start..], "-----END ") orelse return error.InvalidPem;
    const end_marker_start = payload_start + end_idx_rel;
    const end_line = pem_or_der[end_marker_start + end_prefix.len ..];
    const end_label_end = mem.indexOf(u8, end_line, "-----") orelse return error.InvalidPem;
    const end_label = end_line[0..end_label_end];

    if (!mem.eql(u8, begin_label, end_label)) return error.InvalidPem;

    const payload = pem_or_der[payload_start..end_marker_start];

    var b64 = std.ArrayListUnmanaged(u8){};
    defer b64.deinit(allocator);

    for (payload) |ch| {
        switch (ch) {
            ' ', '\t', '\r', '\n' => continue,
            else => try b64.append(allocator, ch),
        }
    }

    if (b64.items.len == 0) return error.InvalidPem;

    return decodeBase64Alloc(allocator, b64.items);
}

// ============================================================================
// Tests
// ============================================================================

test "Server initialization" {
    const allocator = std.testing.allocator;
    var server = Server.init(allocator);
    defer server.deinit();

    try std.testing.expectEqual(@as(u16, 8080), server.config.port);
}

test "Context response helpers" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/test");
    defer req.deinit();

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    _ = ctx.status(201);
    try std.testing.expectEqual(@as(u16, 201), ctx.response.status_code);
}

test "Context query parameter parsing" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/search?q=hello&page=2&empty=");
    defer req.deinit();

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    try std.testing.expectEqualStrings("hello", ctx.query("q").?);
    try std.testing.expectEqualStrings("2", ctx.query("page").?);
    try std.testing.expectEqualStrings("", ctx.query("empty").?);
    try std.testing.expect(ctx.query("missing") == null);
    try std.testing.expectEqualStrings("1", ctx.queryDefault("missing", "1"));
}

test "Context abort" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/test");
    defer req.deinit();

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    ctx.abort(403, "Forbidden");
    try std.testing.expect(ctx.is_aborted);
    try std.testing.expect(ctx.abort_response != null);
    try std.testing.expectEqual(@as(u16, 403), ctx.abort_response.?.status.code);
}

test "Server with config" {
    const allocator = std.testing.allocator;
    var server = Server.initWithConfig(allocator, .{
        .host = "0.0.0.0",
        .port = 3000,
    });
    defer server.deinit();

    try std.testing.expectEqual(@as(u16, 3000), server.config.port);
    try std.testing.expectEqualStrings("0.0.0.0", server.config.host);
}

test "Server TLS config enable and disable" {
    const allocator = std.testing.allocator;
    var server = Server.init(allocator);
    defer server.deinit();

    const cert_chain = [_][]const u8{&[_]u8{ 0x30, 0x82, 0x01, 0x0A }};
    const key_der = [_]u8{ 0x30, 0x82, 0x01, 0x01 };

    server.enableTls12(.{
        .cert_chain_der = &cert_chain,
        .private_key_der = &key_der,
    });

    try std.testing.expect(server.config.tls12 != null);
    try std.testing.expectEqual(@as(usize, 1), server.config.tls12.?.cert_chain_der.len);
    try std.testing.expectEqualSlices(u8, &key_der, server.config.tls12.?.private_key_der);

    server.disableTls();
    try std.testing.expect(server.config.tls12 == null);
}

test "Server TLS PEM config enable and disable" {
    const allocator = std.testing.allocator;
    var server = Server.init(allocator);
    defer server.deinit();

    const cert_pem =
        "-----BEGIN CERTIFICATE-----\n" ++
        "MIICBDCCAW2gAwIBAgIUaTlW0t+judN+kkLViTuiJNv8dCEwDQYJKoZIhvcNAQEL\n" ++
        "BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDIwNjE5MjQwMloXDTI2MDIw\n" ++
        "NzE5MjQwMlowFDESMBAGA1UEAwwJbG9jYWxob3N0MIGfMA0GCSqGSIb3DQEBAQUA\n" ++
        "A4GNADCBiQKBgQC11T3uGGnh794tn4bUobJcpCAW8s/bpIUkxtGfTiYxc5hOgq+G\n" ++
        "+cSjM61Sr6gP+s5ebOWbfxNs7NwJxpZLofAKsILI6KY3ouukUYpXcRXyqPuORaPa\n" ++
        "bwOBzZl281K0vk80XVAozY5MWN7PZ9/7+L1wjjDLzDHOK02+SD8FEp6DcwIDAQAB\n" ++
        "o1MwUTAdBgNVHQ4EFgQU4f4vQMNSbPsiMJYpT3At0o/FTlwwHwYDVR0jBBgwFoAU\n" ++
        "4f4vQMNSbPsiMJYpT3At0o/FTlwwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B\n" ++
        "AQsFAAOBgQAnDkVqOOiYb/PDiNm+5/1deRmQJZ36vjdLWpQ5iCrXZoPr5eyqjXqi\n" ++
        "qvllooY9dMCwo9YE28Kq2F/uR3vciveqoIbU5hMzb1qL2KypCA+CeJn7swDBxZT9\n" ++
        "oRXTMD+vljJfyJngiVHXTlccOkPDv7SIyoys/NPIjyuba8zu+P+qiQ==\n" ++
        "-----END CERTIFICATE-----\n";

    const key_pem =
        "-----BEGIN PRIVATE KEY-----\n" ++
        "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALXVPe4YaeHv3i2f\n" ++
        "htShslykIBbyz9ukhSTG0Z9OJjFzmE6Cr4b5xKMzrVKvqA/6zl5s5Zt/E2zs3AnG\n" ++
        "lkuh8Aqwgsjopjei66RRildxFfKo+45Fo9pvA4HNmXbzUrS+TzRdUCjNjkxY3s9n\n" ++
        "3/v4vXCOMMvMMc4rTb5IPwUSnoNzAgMBAAECgYAu8/iA8ebtg74Qc+AiKfrftzXe\n" ++
        "FycbZXlIDNr2UvzDykCrDU38AaUIK4D3GArCzZXahi4oIAFJIESVdaU7tH5CJE8a\n" ++
        "zF6wXj5AfHlxqHq+krWOYuxv7d+Cd61Pbn8yg9DJ2TlJgD765hDP3wabFaM/kfXn\n" ++
        "v87W993n9KnIxiRVwQJBAPAt1GYX2eu3xq0tWrD+1cvv/FRURO1Fj/CEdj7KvuMn\n" ++
        "d8ApQTVABeFJPWdm01dwwh1ljxNFvgUQ74ooMTxtbJMCQQDBz4PlFpd87DYvv2N/\n" ++
        "FP5++z8Jm6lhIssqP/42TI4c0YQZEra9nh18iQfchgPpjszEi/qipVDeWrOvrT9F\n" ++
        "rbmhAkAAtvIx15JTbDmQHFlvu2Jhd/ZVPebymcli2tILP8kvnddyX+0MvoMF95TS\n" ++
        "MPEiCnjZY4r4cLWvCCzeSV5UIrM3AkAIsD7fdEXSSdycA154gf5uvuCyk5HiUub8\n" ++
        "u+WvlXsBe7sKTLZ4hbAYtyPtFOzz+Xzgis3voK2hajuH8qJVg1ZBAkEAs3XDARhj\n" ++
        "0tVrWkKDi1vQn9VgQGHIvftO5v94Ibxbd1ceGsyDKNMkJXhHadaSKy2lxSQI24MI\n" ++
        "NEaEJIuPClOWqg==\n" ++
        "-----END PRIVATE KEY-----\n";

    const cert_chain = [_][]const u8{cert_pem};
    try server.enableTls12Pem(.{
        .cert_chain_pem = &cert_chain,
        .private_key_pem = key_pem,
    });

    try std.testing.expect(server.config.tls12 != null);
    try std.testing.expect(server.tls12_owned != null);
    try std.testing.expect(server.config.tls12.?.cert_chain_der[0].len > 0);
    try std.testing.expect(server.config.tls12.?.private_key_der.len > 0);
    try std.testing.expectEqual(@as(u8, 0x30), server.config.tls12.?.cert_chain_der[0][0]);
    try std.testing.expectEqual(@as(u8, 0x30), server.config.tls12.?.private_key_der[0]);

    server.disableTls();
    try std.testing.expect(server.config.tls12 == null);
    try std.testing.expect(server.tls12_owned == null);
}

test "pemToDerAlloc rejects mismatched PEM labels" {
    const allocator = std.testing.allocator;

    const bad_pem =
        "-----BEGIN CERTIFICATE-----\n" ++
        "Zm9v\n" ++
        "-----END PRIVATE KEY-----\n";

    try std.testing.expectError(error.InvalidPem, pemToDerAlloc(allocator, bad_pem));
}

test "Server threading config updates executor count" {
    const allocator = std.testing.allocator;
    var server = Server.init(allocator);
    defer server.deinit();

    try std.testing.expectEqual(@as(u6, 1), server.resolveExecutorCount());

    server.enableThreading(.{ .num_workers = 4 });
    try std.testing.expect(server.isThreadingEnabled());
    try std.testing.expectEqual(@as(u6, 4), server.resolveExecutorCount());

    server.disableThreading();
    try std.testing.expect(!server.isThreadingEnabled());
    try std.testing.expectEqual(@as(u6, 1), server.resolveExecutorCount());
}

test "Server resolveExecutorCount clamps upper bound" {
    const allocator = std.testing.allocator;
    var server = Server.initWithConfig(allocator, .{ .threads = 1000 });
    defer server.deinit();

    try std.testing.expectEqual(@as(u6, 63), server.resolveExecutorCount());
}

test "Server shouldKeepAlive honors version and connection header" {
    const allocator = std.testing.allocator;
    var server = Server.init(allocator);
    defer server.deinit();

    var req = try Request.init(allocator, .GET, "/");
    defer req.deinit();

    req.version = .HTTP_1_1;
    try std.testing.expect(server.shouldKeepAlive(&req));

    try req.headers.set(HeaderName.CONNECTION, "close");
    try std.testing.expect(!server.shouldKeepAlive(&req));

    _ = req.headers.remove(HeaderName.CONNECTION);
    req.version = .HTTP_1_0;
    try std.testing.expect(!server.shouldKeepAlive(&req));

    try req.headers.set(HeaderName.CONNECTION, "keep-alive");
    try std.testing.expect(server.shouldKeepAlive(&req));

    try req.headers.set(HeaderName.CONNECTION, "upgrade, close");
    try std.testing.expect(!server.shouldKeepAlive(&req));

    try req.headers.set(HeaderName.CONNECTION, "foo, Keep-Alive");
    try std.testing.expect(server.shouldKeepAlive(&req));
}

test "Server getStats returns snapshot" {
    const allocator = std.testing.allocator;
    var server = Server.initWithConfig(allocator, .{ .threads = 6 });
    defer server.deinit();

    _ = server.requests_handled.fetchAdd(10, .monotonic);
    _ = server.active_requests.fetchAdd(3, .monotonic);
    _ = server.total_errors.fetchAdd(2, .monotonic);

    const stats = server.getStats();
    try std.testing.expectEqual(@as(u64, 10), stats.requests_handled);
    try std.testing.expectEqual(@as(u64, 3), stats.active_requests);
    try std.testing.expectEqual(@as(u64, 2), stats.total_errors);
    try std.testing.expectEqual(@as(u32, 6), stats.executors);
}

test "Server handles keep-alive requests on same connection" {
    const allocator = std.testing.allocator;
    const port = try reserveTestPort();

    var server = Server.initWithConfig(allocator, .{
        .host = "127.0.0.1",
        .port = port,
    });
    defer server.deinit();

    try server.get("/ka", struct {
        fn handler(ctx: *Context) anyerror!Response {
            return ctx.text("keepalive-ok");
        }
    }.handler);

    var listen_ctx = ListenThreadContext{ .server = &server };
    var listen_thread = try std.Thread.spawn(.{}, runServerInThread, .{&listen_ctx});
    var joined = false;
    defer {
        server.stop();
        if (!joined) {
            listen_thread.join();
        }
    }

    try waitForServerReady(port, 2000);

    const addr = try std.net.Address.parseIp("127.0.0.1", port);
    var client = try socket_mod.Socket.createForAddress(addr);
    defer client.close();

    try client.setRecvTimeout(2000);
    try client.setSendTimeout(2000);
    try client.connect(addr);

    try client.sendAll(
        "GET /ka HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "Connection: keep-alive\r\n" ++
            "\r\n",
    );

    const resp1 = try readHttpResponse(allocator, &client);
    defer allocator.free(resp1);

    try std.testing.expect(std.mem.indexOf(u8, resp1, "HTTP/1.1 200 OK") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp1, "keepalive-ok") != null);

    try client.sendAll(
        "GET /ka HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "Connection: close\r\n" ++
            "\r\n",
    );

    const resp2 = try readHttpResponse(allocator, &client);
    defer allocator.free(resp2);

    try std.testing.expect(std.mem.indexOf(u8, resp2, "HTTP/1.1 200 OK") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp2, "keepalive-ok") != null);

    server.stop();
    listen_thread.join();
    joined = true;

    if (listen_ctx.err) |err| {
        return err;
    }

    const stats = server.getStats();
    try std.testing.expectEqual(@as(u64, 2), stats.requests_handled);
    try std.testing.expectEqual(@as(u64, 0), stats.total_errors);
}

test "Server handles pipelined requests in single packet" {
    const allocator = std.testing.allocator;
    const port = try reserveTestPort();

    var server = Server.initWithConfig(allocator, .{
        .host = "127.0.0.1",
        .port = port,
    });
    defer server.deinit();

    try server.get("/pipe", struct {
        fn handler(ctx: *Context) anyerror!Response {
            return ctx.text("pipe-ok");
        }
    }.handler);

    var listen_ctx = ListenThreadContext{ .server = &server };
    var listen_thread = try std.Thread.spawn(.{}, runServerInThread, .{&listen_ctx});
    var joined = false;
    defer {
        server.stop();
        if (!joined) {
            listen_thread.join();
        }
    }

    try waitForServerReady(port, 2000);

    const addr = try std.net.Address.parseIp("127.0.0.1", port);
    var client = try socket_mod.Socket.createForAddress(addr);
    defer client.close();

    try client.setRecvTimeout(2000);
    try client.setSendTimeout(2000);
    try client.connect(addr);

    try client.sendAll(
        "GET /pipe HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "Connection: keep-alive\r\n" ++
            "\r\n" ++
            "GET /pipe HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "Connection: close\r\n" ++
            "\r\n",
    );

    const resp1 = try readHttpResponse(allocator, &client);
    defer allocator.free(resp1);
    try std.testing.expect(std.mem.indexOf(u8, resp1, "HTTP/1.1 200 OK") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp1, "pipe-ok") != null);

    const resp2 = try readHttpResponse(allocator, &client);
    defer allocator.free(resp2);
    try std.testing.expect(std.mem.indexOf(u8, resp2, "HTTP/1.1 200 OK") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp2, "pipe-ok") != null);

    server.stop();
    listen_thread.join();
    joined = true;

    if (listen_ctx.err) |err| {
        return err;
    }

    const stats = server.getStats();
    try std.testing.expectEqual(@as(u64, 2), stats.requests_handled);
}

test "Server serves HTTPS with TLS 1.2 config" {
    const allocator = std.testing.allocator;
    const port = try reserveTestPort();

    const cert_der_b64 = "MIICBDCCAW2gAwIBAgIUD+8k3RJkaBpoLo1CQD+IkI8bR2MwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDIwNjE5MDU0NVoXDTI2MDIwNzE5MDU0NVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC11T3uGGnh794tn4bUobJcpCAW8s/bpIUkxtGfTiYxc5hOgq+G+cSjM61Sr6gP+s5ebOWbfxNs7NwJxpZLofAKsILI6KY3ouukUYpXcRXyqPuORaPabwOBzZl281K0vk80XVAozY5MWN7PZ9/7+L1wjjDLzDHOK02+SD8FEp6DcwIDAQABo1MwUTAdBgNVHQ4EFgQU4f4vQMNSbPsiMJYpT3At0o/FTlwwHwYDVR0jBBgwFoAU4f4vQMNSbPsiMJYpT3At0o/FTlwwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOBgQBk8gVrSf8lAkFRMEP1n1KHI418lXltdfDrIJhUkyuZD4GglaeGW4qn8yAOJniZJvpcRUtIzUe8qYYI+Ost90KH88W/IKkuM8xIYND99djWvV5ikYkFzmZWy4b/MA/0IOXvYUvG6ra0DGTMJmGiQ+qMRpJqegjBWAz83SQAab1aNQ==";
    const key_der_b64 = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALXVPe4YaeHv3i2fhtShslykIBbyz9ukhSTG0Z9OJjFzmE6Cr4b5xKMzrVKvqA/6zl5s5Zt/E2zs3AnGlkuh8Aqwgsjopjei66RRildxFfKo+45Fo9pvA4HNmXbzUrS+TzRdUCjNjkxY3s9n3/v4vXCOMMvMMc4rTb5IPwUSnoNzAgMBAAECgYAu8/iA8ebtg74Qc+AiKfrftzXeFycbZXlIDNr2UvzDykCrDU38AaUIK4D3GArCzZXahi4oIAFJIESVdaU7tH5CJE8azF6wXj5AfHlxqHq+krWOYuxv7d+Cd61Pbn8yg9DJ2TlJgD765hDP3wabFaM/kfXnv87W993n9KnIxiRVwQJBAPAt1GYX2eu3xq0tWrD+1cvv/FRURO1Fj/CEdj7KvuMnd8ApQTVABeFJPWdm01dwwh1ljxNFvgUQ74ooMTxtbJMCQQDBz4PlFpd87DYvv2N/FP5++z8Jm6lhIssqP/42TI4c0YQZEra9nh18iQfchgPpjszEi/qipVDeWrOvrT9FrbmhAkAAtvIx15JTbDmQHFlvu2Jhd/ZVPebymcli2tILP8kvnddyX+0MvoMF95TSMPEiCnjZY4r4cLWvCCzeSV5UIrM3AkAIsD7fdEXSSdycA154gf5uvuCyk5HiUub8u+WvlXsBe7sKTLZ4hbAYtyPtFOzz+Xzgis3voK2hajuH8qJVg1ZBAkEAs3XDARhj0tVrWkKDi1vQn9VgQGHIvftO5v94Ibxbd1ceGsyDKNMkJXhHadaSKy2lxSQI24MINEaEJIuPClOWqg==";

    const cert_der = try decodeBase64Alloc(allocator, cert_der_b64);
    defer allocator.free(cert_der);
    const key_der = try decodeBase64Alloc(allocator, key_der_b64);
    defer allocator.free(key_der);

    var server = Server.initWithConfig(allocator, .{
        .host = "127.0.0.1",
        .port = port,
    });
    defer server.deinit();

    const cert_chain = [_][]const u8{cert_der};
    server.enableTls12(.{
        .cert_chain_der = &cert_chain,
        .private_key_der = key_der,
    });

    try server.get("/secure", struct {
        fn handler(ctx: *Context) anyerror!Response {
            return ctx.text("secure-ok");
        }
    }.handler);

    var listen_ctx = ListenThreadContext{ .server = &server };
    var listen_thread = try std.Thread.spawn(.{}, runServerInThread, .{&listen_ctx});
    var joined = false;
    defer {
        server.stop();
        if (!joined) {
            listen_thread.join();
        }
    }

    try waitForTlsServerReady(port, 2000);

    const addr = try std.net.Address.parseIp("127.0.0.1", port);
    var client = try socket_mod.Socket.createForAddress(addr);
    defer client.close();
    try client.setRecvTimeout(2000);
    try client.setSendTimeout(2000);
    try client.connect(addr);

    var tls_cfg = tls_client.TlsConfig.insecure(allocator);
    tls_cfg.setServerName("localhost");
    var session = tls_client.TlsSession.init(tls_cfg);
    defer session.deinit();
    session.attachSocket(&client);
    try session.handshake("localhost");

    _ = try session.write(
        "GET /secure HTTP/1.1\r\n" ++
            "Host: localhost\r\n" ++
            "Connection: close\r\n" ++
            "\r\n",
    );

    const resp = try readHttpResponseTls(allocator, &session);
    defer allocator.free(resp);

    try std.testing.expect(std.mem.indexOf(u8, resp, "HTTP/1.1 200 OK") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp, "secure-ok") != null);

    server.stop();
    listen_thread.join();
    joined = true;

    if (listen_ctx.err) |err| {
        return err;
    }
}

test "Server returns 400 for malformed request" {
    const allocator = std.testing.allocator;
    const port = try reserveTestPort();

    var server = Server.initWithConfig(allocator, .{
        .host = "127.0.0.1",
        .port = port,
    });
    defer server.deinit();

    var listen_ctx = ListenThreadContext{ .server = &server };
    var listen_thread = try std.Thread.spawn(.{}, runServerInThread, .{&listen_ctx});
    var joined = false;
    defer {
        server.stop();
        if (!joined) {
            listen_thread.join();
        }
    }

    try waitForServerReady(port, 2000);

    const addr = try std.net.Address.parseIp("127.0.0.1", port);
    var client = try socket_mod.Socket.createForAddress(addr);
    defer client.close();

    try client.setRecvTimeout(2000);
    try client.setSendTimeout(2000);
    try client.connect(addr);

    try client.sendAll("BROKEN\r\n\r\n");

    const resp_data = try readHttpResponse(allocator, &client);
    defer allocator.free(resp_data);

    try std.testing.expect(std.mem.indexOf(u8, resp_data, "HTTP/1.1 400 Bad Request") != null);

    server.stop();
    listen_thread.join();
    joined = true;

    if (listen_ctx.err) |err| {
        return err;
    }
}

test "Server enforces max body size" {
    const allocator = std.testing.allocator;
    const port = try reserveTestPort();

    var server = Server.initWithConfig(allocator, .{
        .host = "127.0.0.1",
        .port = port,
        .max_body_size = 4,
    });
    defer server.deinit();

    var listen_ctx = ListenThreadContext{ .server = &server };
    var listen_thread = try std.Thread.spawn(.{}, runServerInThread, .{&listen_ctx});
    var joined = false;
    defer {
        server.stop();
        if (!joined) {
            listen_thread.join();
        }
    }

    try waitForServerReady(port, 2000);

    const addr = try std.net.Address.parseIp("127.0.0.1", port);
    var client = try socket_mod.Socket.createForAddress(addr);
    defer client.close();

    try client.setRecvTimeout(2000);
    try client.setSendTimeout(2000);
    try client.connect(addr);

    try client.sendAll(
        "POST /upload HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "Content-Length: 10\r\n" ++
            "Connection: close\r\n" ++
            "\r\n" ++
            "0123456789",
    );

    const resp_data = try readHttpResponse(allocator, &client);
    defer allocator.free(resp_data);

    try std.testing.expect(std.mem.indexOf(u8, resp_data, "HTTP/1.1 413 Payload Too Large") != null);

    server.stop();
    listen_thread.join();
    joined = true;

    if (listen_ctx.err) |err| {
        return err;
    }
}

test "Server enforces max connections" {
    const allocator = std.testing.allocator;
    const port = try reserveTestPort();

    var server = Server.initWithConfig(allocator, .{
        .host = "127.0.0.1",
        .port = port,
        .max_connections = 1,
        .keep_alive_timeout_ms = 1000,
    });
    defer server.deinit();

    try server.get("/hold", struct {
        fn handler(ctx: *Context) anyerror!Response {
            return ctx.text("held");
        }
    }.handler);

    var listen_ctx = ListenThreadContext{ .server = &server };
    var listen_thread = try std.Thread.spawn(.{}, runServerInThread, .{&listen_ctx});
    var joined = false;
    defer {
        server.stop();
        if (!joined) {
            listen_thread.join();
        }
    }

    try waitForServerReady(port, 2000);

    const addr = try std.net.Address.parseIp("127.0.0.1", port);

    var client1 = try socket_mod.Socket.createForAddress(addr);
    defer client1.close();
    try client1.setRecvTimeout(2000);
    try client1.setSendTimeout(2000);
    try client1.connect(addr);

    try client1.sendAll(
        "GET /hold HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "Connection: keep-alive\r\n" ++
            "\r\n",
    );

    const held_resp = try readHttpResponse(allocator, &client1);
    defer allocator.free(held_resp);
    try std.testing.expect(std.mem.indexOf(u8, held_resp, "HTTP/1.1 200 OK") != null);

    var client2 = try socket_mod.Socket.createForAddress(addr);
    defer client2.close();
    try client2.setRecvTimeout(2000);
    try client2.setSendTimeout(2000);
    try client2.connect(addr);

    try client2.sendAll(
        "GET /hold HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "Connection: close\r\n" ++
            "\r\n",
    );

    const limited_resp = try readHttpResponse(allocator, &client2);
    defer allocator.free(limited_resp);
    try std.testing.expect(std.mem.indexOf(u8, limited_resp, "HTTP/1.1 503 Service Unavailable") != null);

    server.stop();
    listen_thread.join();
    joined = true;

    if (listen_ctx.err) |err| {
        return err;
    }
}

test "Server websocket upgrade and echo on zio stream" {
    const allocator = std.testing.allocator;
    const port = try reserveTestPort();

    var server = Server.initWithConfig(allocator, .{
        .host = "127.0.0.1",
        .port = port,
    });
    defer server.deinit();

    try server.ws("/ws", struct {
        fn handler(conn: *ws_handler.WebSocketConnection) anyerror!void {
            const msg = try conn.receive();
            defer conn.allocator.free(msg.payload);
            try conn.send(msg.payload, msg.opcode);
        }
    }.handler);

    var listen_ctx = ListenThreadContext{ .server = &server };
    var listen_thread = try std.Thread.spawn(.{}, runServerInThread, .{&listen_ctx});
    var joined = false;
    defer {
        server.stop();
        if (!joined) {
            listen_thread.join();
        }
    }

    try waitForServerReady(port, 2000);

    const addr = try std.net.Address.parseIp("127.0.0.1", port);
    var client = try socket_mod.Socket.createForAddress(addr);
    defer client.close();

    try client.setRecvTimeout(2000);
    try client.setSendTimeout(2000);
    try client.connect(addr);

    const ws_key = "dGhlIHNhbXBsZSBub25jZQ==";
    try client.sendAll(
        "GET /ws HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: " ++ ws_key ++ "\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "\r\n",
    );

    const handshake = try readHttpResponse(allocator, &client);
    defer allocator.free(handshake);

    try std.testing.expect(std.mem.indexOf(u8, handshake, "HTTP/1.1 101 Switching Protocols") != null);

    const accept = websocket.computeAccept(ws_key);
    var accept_line_buf: [128]u8 = undefined;
    const accept_line = try std.fmt.bufPrint(&accept_line_buf, "Sec-WebSocket-Accept: {s}\r\n", .{&accept});
    try std.testing.expect(std.mem.indexOf(u8, handshake, accept_line) != null);

    const encoded = try websocket.encodeFrame(allocator, .{
        .opcode = .text,
        .mask = .{ 0x01, 0x02, 0x03, 0x04 },
        .payload = "zio-echo",
    }, true);
    defer allocator.free(encoded);

    try client.sendAll(encoded);

    var frame_bytes = std.ArrayListUnmanaged(u8){};
    defer frame_bytes.deinit(allocator);

    var decoded: ?websocket.DecodeResult = null;
    while (decoded == null) {
        var chunk: [256]u8 = undefined;
        const n = try client.recv(&chunk);
        if (n == 0) return error.UnexpectedEof;

        try frame_bytes.appendSlice(allocator, chunk[0..n]);
        decoded = try websocket.decodeFrame(allocator, frame_bytes.items, websocket.DEFAULT_MAX_PAYLOAD_SIZE);
    }

    const echo = decoded.?;
    defer allocator.free(echo.payload_owned);

    try std.testing.expectEqual(websocket.Opcode.text, echo.frame.opcode);
    try std.testing.expectEqualStrings("zio-echo", echo.frame.payload);

    server.stop();
    listen_thread.join();
    joined = true;

    if (listen_ctx.err) |err| {
        return err;
    }

    const stats = server.getStats();
    try std.testing.expectEqual(@as(u64, 0), stats.total_errors);
}

test "Server websocket upgrade and echo over TLS (wss)" {
    const allocator = std.testing.allocator;
    const port = try reserveTestPort();

    const cert_der_b64 = "MIICBDCCAW2gAwIBAgIUD+8k3RJkaBpoLo1CQD+IkI8bR2MwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDIwNjE5MDU0NVoXDTI2MDIwNzE5MDU0NVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC11T3uGGnh794tn4bUobJcpCAW8s/bpIUkxtGfTiYxc5hOgq+G+cSjM61Sr6gP+s5ebOWbfxNs7NwJxpZLofAKsILI6KY3ouukUYpXcRXyqPuORaPabwOBzZl281K0vk80XVAozY5MWN7PZ9/7+L1wjjDLzDHOK02+SD8FEp6DcwIDAQABo1MwUTAdBgNVHQ4EFgQU4f4vQMNSbPsiMJYpT3At0o/FTlwwHwYDVR0jBBgwFoAU4f4vQMNSbPsiMJYpT3At0o/FTlwwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOBgQBk8gVrSf8lAkFRMEP1n1KHI418lXltdfDrIJhUkyuZD4GglaeGW4qn8yAOJniZJvpcRUtIzUe8qYYI+Ost90KH88W/IKkuM8xIYND99djWvV5ikYkFzmZWy4b/MA/0IOXvYUvG6ra0DGTMJmGiQ+qMRpJqegjBWAz83SQAab1aNQ==";
    const key_der_b64 = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALXVPe4YaeHv3i2fhtShslykIBbyz9ukhSTG0Z9OJjFzmE6Cr4b5xKMzrVKvqA/6zl5s5Zt/E2zs3AnGlkuh8Aqwgsjopjei66RRildxFfKo+45Fo9pvA4HNmXbzUrS+TzRdUCjNjkxY3s9n3/v4vXCOMMvMMc4rTb5IPwUSnoNzAgMBAAECgYAu8/iA8ebtg74Qc+AiKfrftzXeFycbZXlIDNr2UvzDykCrDU38AaUIK4D3GArCzZXahi4oIAFJIESVdaU7tH5CJE8azF6wXj5AfHlxqHq+krWOYuxv7d+Cd61Pbn8yg9DJ2TlJgD765hDP3wabFaM/kfXnv87W993n9KnIxiRVwQJBAPAt1GYX2eu3xq0tWrD+1cvv/FRURO1Fj/CEdj7KvuMnd8ApQTVABeFJPWdm01dwwh1ljxNFvgUQ74ooMTxtbJMCQQDBz4PlFpd87DYvv2N/FP5++z8Jm6lhIssqP/42TI4c0YQZEra9nh18iQfchgPpjszEi/qipVDeWrOvrT9FrbmhAkAAtvIx15JTbDmQHFlvu2Jhd/ZVPebymcli2tILP8kvnddyX+0MvoMF95TSMPEiCnjZY4r4cLWvCCzeSV5UIrM3AkAIsD7fdEXSSdycA154gf5uvuCyk5HiUub8u+WvlXsBe7sKTLZ4hbAYtyPtFOzz+Xzgis3voK2hajuH8qJVg1ZBAkEAs3XDARhj0tVrWkKDi1vQn9VgQGHIvftO5v94Ibxbd1ceGsyDKNMkJXhHadaSKy2lxSQI24MINEaEJIuPClOWqg==";

    const cert_der = try decodeBase64Alloc(allocator, cert_der_b64);
    defer allocator.free(cert_der);
    const key_der = try decodeBase64Alloc(allocator, key_der_b64);
    defer allocator.free(key_der);

    var server = Server.initWithConfig(allocator, .{
        .host = "127.0.0.1",
        .port = port,
    });
    defer server.deinit();

    const cert_chain = [_][]const u8{cert_der};
    server.enableTls12(.{
        .cert_chain_der = &cert_chain,
        .private_key_der = key_der,
    });

    try server.ws("/ws", struct {
        fn handler(conn: *ws_handler.WebSocketConnection) anyerror!void {
            const msg = try conn.receive();
            defer conn.allocator.free(msg.payload);
            try conn.send(msg.payload, msg.opcode);
        }
    }.handler);

    var listen_ctx = ListenThreadContext{ .server = &server };
    var listen_thread = try std.Thread.spawn(.{}, runServerInThread, .{&listen_ctx});
    var joined = false;
    defer {
        server.stop();
        if (!joined) {
            listen_thread.join();
        }
    }

    try waitForTlsServerReady(port, 2000);

    const addr = try std.net.Address.parseIp("127.0.0.1", port);
    var client = try socket_mod.Socket.createForAddress(addr);
    defer client.close();
    try client.setRecvTimeout(2000);
    try client.setSendTimeout(2000);
    try client.connect(addr);

    var tls_cfg = tls_client.TlsConfig.insecure(allocator);
    tls_cfg.setServerName("localhost");
    var session = tls_client.TlsSession.init(tls_cfg);
    defer session.deinit();
    session.attachSocket(&client);
    try session.handshake("localhost");

    const ws_key = "dGhlIHNhbXBsZSBub25jZQ==";
    _ = try session.write(
        "GET /ws HTTP/1.1\r\n" ++
            "Host: localhost\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: " ++ ws_key ++ "\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "\r\n",
    );

    const handshake = try readHttpResponseTls(allocator, &session);
    defer allocator.free(handshake);
    try std.testing.expect(std.mem.indexOf(u8, handshake, "HTTP/1.1 101 Switching Protocols") != null);

    const encoded = try websocket.encodeFrame(allocator, .{
        .opcode = .text,
        .mask = .{ 0x01, 0x02, 0x03, 0x04 },
        .payload = "wss-echo",
    }, true);
    defer allocator.free(encoded);
    _ = try session.write(encoded);

    var frame_bytes = std.ArrayListUnmanaged(u8){};
    defer frame_bytes.deinit(allocator);
    var decoded_result: ?websocket.DecodeResult = null;

    while (decoded_result == null) {
        var chunk: [256]u8 = undefined;
        const n = try session.read(&chunk);
        if (n == 0) return error.UnexpectedEof;
        try frame_bytes.appendSlice(allocator, chunk[0..n]);
        decoded_result = try websocket.decodeFrame(allocator, frame_bytes.items, websocket.DEFAULT_MAX_PAYLOAD_SIZE);
    }

    const echo = decoded_result.?;
    defer allocator.free(echo.payload_owned);
    try std.testing.expectEqual(websocket.Opcode.text, echo.frame.opcode);
    try std.testing.expectEqualStrings("wss-echo", echo.frame.payload);

    server.stop();
    listen_thread.join();
    joined = true;

    if (listen_ctx.err) |err| {
        return err;
    }
}

test "Server websocket upgrade preserves same-packet frame bytes" {
    const allocator = std.testing.allocator;
    const port = try reserveTestPort();

    var server = Server.initWithConfig(allocator, .{
        .host = "127.0.0.1",
        .port = port,
    });
    defer server.deinit();

    try server.ws("/ws", struct {
        fn handler(conn: *ws_handler.WebSocketConnection) anyerror!void {
            const msg = try conn.receive();
            defer conn.allocator.free(msg.payload);
            try conn.send(msg.payload, msg.opcode);
        }
    }.handler);

    var listen_ctx = ListenThreadContext{ .server = &server };
    var listen_thread = try std.Thread.spawn(.{}, runServerInThread, .{&listen_ctx});
    var joined = false;
    defer {
        server.stop();
        if (!joined) {
            listen_thread.join();
        }
    }

    try waitForServerReady(port, 2000);

    const addr = try std.net.Address.parseIp("127.0.0.1", port);
    var client = try socket_mod.Socket.createForAddress(addr);
    defer client.close();

    try client.setRecvTimeout(2000);
    try client.setSendTimeout(2000);
    try client.connect(addr);

    const ws_key = "dGhlIHNhbXBsZSBub25jZQ==";
    const encoded = try websocket.encodeFrame(allocator, .{
        .opcode = .text,
        .mask = .{ 0x09, 0x08, 0x07, 0x06 },
        .payload = "same-packet",
    }, true);
    defer allocator.free(encoded);

    var request_and_frame = std.ArrayListUnmanaged(u8){};
    defer request_and_frame.deinit(allocator);
    try request_and_frame.appendSlice(
        allocator,
        "GET /ws HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: " ++ ws_key ++ "\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "\r\n",
    );
    try request_and_frame.appendSlice(allocator, encoded);

    try client.sendAll(request_and_frame.items);

    const handshake = try readHttpResponse(allocator, &client);
    defer allocator.free(handshake);
    try std.testing.expect(std.mem.indexOf(u8, handshake, "HTTP/1.1 101 Switching Protocols") != null);

    var frame_bytes = std.ArrayListUnmanaged(u8){};
    defer frame_bytes.deinit(allocator);

    var decoded_result: ?websocket.DecodeResult = null;
    while (decoded_result == null) {
        var chunk: [256]u8 = undefined;
        const n = try client.recv(&chunk);
        if (n == 0) return error.UnexpectedEof;
        try frame_bytes.appendSlice(allocator, chunk[0..n]);
        decoded_result = try websocket.decodeFrame(allocator, frame_bytes.items, websocket.DEFAULT_MAX_PAYLOAD_SIZE);
    }

    const echo = decoded_result.?;
    defer allocator.free(echo.payload_owned);
    try std.testing.expectEqual(websocket.Opcode.text, echo.frame.opcode);
    try std.testing.expectEqualStrings("same-packet", echo.frame.payload);

    server.stop();
    listen_thread.join();
    joined = true;

    if (listen_ctx.err) |err| {
        return err;
    }
}

test "Server handles concurrent requests and updates stats" {
    const allocator = std.testing.allocator;
    const port = try reserveTestPort();

    var server = Server.initWithConfig(allocator, .{
        .host = "127.0.0.1",
        .port = port,
    });
    defer server.deinit();

    server.enableThreading(.{ .num_workers = 4 });

    try server.get("/concurrent", struct {
        fn handler(ctx: *Context) anyerror!Response {
            std.Thread.sleep(10 * std.time.ns_per_ms);
            return ctx.text("ok");
        }
    }.handler);

    var listen_ctx = ListenThreadContext{ .server = &server };
    var listen_thread = try std.Thread.spawn(.{}, runServerInThread, .{&listen_ctx});
    var joined = false;
    defer {
        server.stop();
        if (!joined) {
            listen_thread.join();
        }
    }

    try waitForServerReady(port, 2000);

    const client_count = 12;
    var client_ctxs: [client_count]ClientThreadContext = undefined;
    var client_threads: [client_count]std.Thread = undefined;

    for (0..client_count) |i| {
        client_ctxs[i] = .{ .port = port };
        client_threads[i] = try std.Thread.spawn(.{}, runConcurrentClient, .{&client_ctxs[i]});
    }

    for (client_threads) |thread| {
        thread.join();
    }

    server.stop();
    listen_thread.join();
    joined = true;

    if (listen_ctx.err) |err| {
        return err;
    }

    for (client_ctxs) |ctx| {
        if (ctx.err) |err| return err;
        try std.testing.expect(ctx.ok);
    }

    const stats = server.getStats();
    try std.testing.expect(stats.requests_handled >= client_count);
    try std.testing.expectEqual(@as(u64, 0), stats.total_errors);
}

test "Context error collection" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/test");
    defer req.deinit();

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    try std.testing.expect(!ctx.hasErrors());
    try std.testing.expect(ctx.lastError() == null);

    const err1 = try ctx.addError(error.InvalidJson);
    try std.testing.expect(ctx.hasErrors());
    try std.testing.expectEqual(@as(usize, 1), ctx.errors.items.len);
    try std.testing.expect(err1.isType(.private));
    try std.testing.expectEqualStrings("InvalidJson", err1.getMessage());

    _ = try ctx.addErrorWithMsg(error.EmptyBody, "request body was empty");
    try std.testing.expectEqual(@as(usize, 2), ctx.errors.items.len);
    const last = ctx.lastError().?;
    try std.testing.expectEqualStrings("request body was empty", last.getMessage());
}

test "Context abortWithStatus" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/test");
    defer req.deinit();

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    ctx.abortWithStatus(403);
    try std.testing.expect(ctx.is_aborted);
    try std.testing.expect(ctx.abort_response != null);
    try std.testing.expectEqual(@as(u16, 403), ctx.abort_response.?.status.code);
}

test "Context abortWithJSON" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/test");
    defer req.deinit();

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    ctx.abortWithJSON(422, .{ .error_field = "invalid" });
    try std.testing.expect(ctx.is_aborted);
    try std.testing.expect(ctx.abort_response != null);
    try std.testing.expectEqual(@as(u16, 422), ctx.abort_response.?.status.code);
    try std.testing.expect(ctx.abort_response.?.body != null);
}

test "Context getRawData" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .POST, "/data");
    defer req.deinit();
    req.body = "raw body content";

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    try std.testing.expectEqualStrings("raw body content", ctx.getRawData().?);
}

test "Context queryArray" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/search?tag=zig&tag=http&tag=server");
    defer req.deinit();

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    const tags = try ctx.queryArray("tag");
    defer allocator.free(tags);

    try std.testing.expectEqual(@as(usize, 3), tags.len);
    try std.testing.expectEqualStrings("zig", tags[0]);
    try std.testing.expectEqualStrings("http", tags[1]);
    try std.testing.expectEqualStrings("server", tags[2]);
}

test "Context postForm" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .POST, "/form");
    defer req.deinit();
    try req.headers.set("Content-Type", "application/x-www-form-urlencoded");
    req.body = "name=jin&age=30";

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    try std.testing.expectEqualStrings("jin", ctx.postForm("name").?);
    try std.testing.expectEqualStrings("30", ctx.postForm("age").?);
    try std.testing.expect(ctx.postForm("missing") == null);
    try std.testing.expectEqualStrings("default", ctx.postFormDefault("missing", "default"));
}

test "Context cookie support" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/test");
    defer req.deinit();
    try req.headers.set("Cookie", "session=abc123; theme=dark");

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    try std.testing.expectEqualStrings("abc123", ctx.getCookie("session").?);
    try std.testing.expectEqualStrings("dark", ctx.getCookie("theme").?);
    try std.testing.expect(ctx.getCookie("missing") == null);
}

test "Context contentType and isWebsocket" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/test");
    defer req.deinit();
    try req.headers.set("Content-Type", "application/json");

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    try std.testing.expectEqualStrings("application/json", ctx.contentType().?);
    try std.testing.expect(!ctx.isWebsocket());
}

test "Server per-route middleware registration" {
    const allocator = std.testing.allocator;
    var server = Server.init(allocator);
    defer server.deinit();

    const handler = struct {
        fn h(_: *Context) anyerror!Response {
            unreachable;
        }
    }.h;

    const mw = Middleware{
        .name = "test_mw",
        .handler = struct {
            fn h(_: ?*const anyopaque, _: *Context, _: @import("middleware.zig").Next) anyerror!Response {
                unreachable;
            }
        }.h,
    };

    try server.getWith("/protected", &[_]Middleware{mw}, handler);

    var pb: [MAX_ROUTE_PARAMS]RouteParam = undefined;
    const result = server.router.findEx(.GET, "/protected", &pb);
    try std.testing.expect(result == .matched);
    try std.testing.expectEqual(@as(usize, 1), result.matched.middleware.len);
    try std.testing.expectEqualStrings("test_mw", result.matched.middleware[0].name);
}

test "extractBoundary parses multipart boundary" {
    const ct1 = "multipart/form-data; boundary=----WebKitFormBoundary";
    try std.testing.expectEqualStrings("----WebKitFormBoundary", extractBoundary(ct1).?);

    const ct2 = "multipart/form-data; boundary=\"quoted-boundary\"";
    try std.testing.expectEqualStrings("quoted-boundary", extractBoundary(ct2).?);
}

test "formatSSEvent basic" {
    const allocator = std.testing.allocator;
    const event = try formatSSEvent(allocator, "message", "hello world");
    defer allocator.free(event);

    try std.testing.expectEqualStrings("event: message\ndata: hello world\n\n", event);
}

test "formatSSEvent without name" {
    const allocator = std.testing.allocator;
    const event = try formatSSEvent(allocator, null, "just data");
    defer allocator.free(event);

    try std.testing.expectEqualStrings("data: just data\n\n", event);
}

test "formatSSEventWithId" {
    const allocator = std.testing.allocator;
    const event = try formatSSEventWithId(allocator, "update", "new data", "42");
    defer allocator.free(event);

    try std.testing.expectEqualStrings("id: 42\nevent: update\ndata: new data\n\n", event);
}

test "formatSSEvent multiline data" {
    const allocator = std.testing.allocator;
    const event = try formatSSEvent(allocator, null, "line1\nline2\nline3");
    defer allocator.free(event);

    try std.testing.expectEqualStrings("data: line1\ndata: line2\ndata: line3\n\n", event);
}

test "Context clientIP with custom headers" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/test");
    defer req.deinit();
    try req.headers.set("X-Forwarded-For", "1.2.3.4, 5.6.7.8");

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    try std.testing.expectEqualStrings("1.2.3.4", ctx.clientIP().?);
}

test "Context clientIP with X-Real-Ip" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/test");
    defer req.deinit();
    try req.headers.set("X-Real-Ip", "10.0.0.1");

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    try std.testing.expectEqualStrings("10.0.0.1", ctx.clientIP().?);
}

test "Context queryDecoded percent-decoding" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/search?q=hello%20world");
    defer req.deinit();

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    const decoded = ctx.queryDecoded("q");
    try std.testing.expect(decoded != null);
    try std.testing.expectEqualStrings("hello world", decoded.?);
}

test "Context getTyped" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/test");
    defer req.deinit();

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    var my_value: u32 = 42;
    try ctx.set("counter", @ptrCast(&my_value));

    const retrieved = ctx.getTyped(u32, "counter");
    try std.testing.expect(retrieved != null);
    try std.testing.expectEqual(@as(u32, 42), retrieved.?.*);
}

test "ServerConfig defaults include new fields" {
    const config = ServerConfig{};
    try std.testing.expectEqual(@as(u64, 5_000), config.shutdown_timeout_ms);
    try std.testing.expectEqual(@as(usize, 0), config.trusted_proxies.len);
    try std.testing.expectEqual(@as(usize, 2), config.remote_ip_headers.len);
}

// ==========================================================================
// Additional tests for complete coverage
// ==========================================================================

test "Context isAborted method" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/test");
    defer req.deinit();

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    try std.testing.expect(!ctx.isAborted());
    ctx.abortWithStatus(500);
    try std.testing.expect(ctx.isAborted());
}

test "Context error collection - deinit frees owned messages" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/test");
    defer req.deinit();

    var ctx = Context.init(allocator, &req);
    // addErrorWithMsg dupes the message, so deinit must free it
    _ = try ctx.addErrorWithMsg(error.OutOfMemory, "a longer message that is heap allocated");
    _ = try ctx.addErrorWithMsg(error.InvalidJson, "another heap message to free");
    // deinit should not leak
    ctx.deinit();
}

test "Context errorsByType filters correctly" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/test");
    defer req.deinit();

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    const e1 = try ctx.addError(error.InvalidJson);
    e1.err_type = .bind;
    _ = try ctx.addError(error.OutOfMemory); // default .private
    const e3 = try ctx.addError(error.EmptyBody);
    e3.err_type = .public;
    const e4 = try ctx.addError(error.InvalidJson);
    e4.err_type = .bind;

    const bind_errors = try ctx.errorsByType(.bind);
    defer allocator.free(bind_errors);
    try std.testing.expectEqual(@as(usize, 2), bind_errors.len);

    const public_errors = try ctx.errorsByType(.public);
    defer allocator.free(public_errors);
    try std.testing.expectEqual(@as(usize, 1), public_errors.len);

    const private_errors = try ctx.errorsByType(.private);
    defer allocator.free(private_errors);
    try std.testing.expectEqual(@as(usize, 1), private_errors.len);
}

test "Context errorsJSON serializes public errors" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/test");
    defer req.deinit();

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    // Private error - should be excluded
    _ = try ctx.addError(error.OutOfMemory);

    // Public error - should be included
    const e2 = try ctx.addErrorWithMsg(error.InvalidJson, "bad input");
    e2.err_type = .public;

    const json_str = try ctx.errorsJSON();
    defer allocator.free(json_str);

    // Should contain the public error but not the private one
    try std.testing.expect(mem.indexOf(u8, json_str, "bad input") != null);
    try std.testing.expect(mem.indexOf(u8, json_str, "OutOfMemory") == null);
    // Verify it's valid-ish JSON array
    try std.testing.expect(json_str[0] == '[');
    try std.testing.expect(json_str[json_str.len - 1] == ']');
}

test "Context errorsJSON empty when no public errors" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/test");
    defer req.deinit();

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    _ = try ctx.addError(error.OutOfMemory); // private only

    const json_str = try ctx.errorsJSON();
    defer allocator.free(json_str);
    try std.testing.expectEqualStrings("[]", json_str);
}

test "HandlerError getMessage falls back to error name" {
    var err = HandlerError{ .err = error.InvalidJson };
    try std.testing.expectEqualStrings("InvalidJson", err.getMessage());

    var err2 = HandlerError{ .err = error.EmptyBody, .message = "custom msg" };
    try std.testing.expectEqualStrings("custom msg", err2.getMessage());
}

test "HandlerError isType" {
    var err = HandlerError{ .err = error.InvalidJson, .err_type = .bind };
    try std.testing.expect(err.isType(.bind));
    try std.testing.expect(!err.isType(.public));
    try std.testing.expect(!err.isType(.private));
}

test "Context setCookie builds correct header" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/test");
    defer req.deinit();

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    try ctx.setCookie("session", "abc123", 3600, "/", null, true, true);

    // The Set-Cookie header should be set on the response builder
    const resp = ctx.response.build();
    defer {
        var r = resp;
        r.deinit();
    }
    const set_cookie = resp.headers.get("Set-Cookie");
    try std.testing.expect(set_cookie != null);
    const val = set_cookie.?;
    try std.testing.expect(mem.startsWith(u8, val, "session=abc123"));
    try std.testing.expect(mem.indexOf(u8, val, "Path=/") != null);
    try std.testing.expect(mem.indexOf(u8, val, "Secure") != null);
    try std.testing.expect(mem.indexOf(u8, val, "HttpOnly") != null);
    try std.testing.expect(mem.indexOf(u8, val, "Max-Age=3600") != null);
}

test "Context postFormArray returns multiple values" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .POST, "/form");
    defer req.deinit();
    try req.headers.set("Content-Type", "application/x-www-form-urlencoded");
    req.body = "color=red&color=blue&color=green&name=test";

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    const colors = try ctx.postFormArray("color");
    defer allocator.free(colors);
    try std.testing.expectEqual(@as(usize, 3), colors.len);
    try std.testing.expectEqualStrings("red", colors[0]);
    try std.testing.expectEqualStrings("blue", colors[1]);
    try std.testing.expectEqualStrings("green", colors[2]);

    const names = try ctx.postFormArray("name");
    defer allocator.free(names);
    try std.testing.expectEqual(@as(usize, 1), names.len);
}

test "Context postFormArray returns empty for wrong content type" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .POST, "/form");
    defer req.deinit();
    try req.headers.set("Content-Type", "application/json");
    req.body = "color=red&color=blue";

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    const result = try ctx.postFormArray("color");
    defer allocator.free(result);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "Context postForm returns null for missing body" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .POST, "/form");
    defer req.deinit();
    try req.headers.set("Content-Type", "application/x-www-form-urlencoded");
    // body is null

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    try std.testing.expect(ctx.postForm("name") == null);
}

test "Context formFile returns null for non-multipart" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .POST, "/upload");
    defer req.deinit();
    try req.headers.set("Content-Type", "application/json");
    req.body = "{}";

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    try std.testing.expect(ctx.formFile("file") == null);
}

test "Context formFile parses multipart upload" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .POST, "/upload");
    defer req.deinit();
    try req.headers.set("Content-Type", "multipart/form-data; boundary=----TestBound");
    req.body = "------TestBound\r\n" ++
        "Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "\r\n" ++
        "hello file content\r\n" ++
        "------TestBound--\r\n";

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    const uploaded = ctx.formFile("file");
    try std.testing.expect(uploaded != null);
    try std.testing.expectEqualStrings("test.txt", uploaded.?.filename);
    try std.testing.expectEqualStrings("text/plain", uploaded.?.content_type);
    try std.testing.expectEqualStrings("hello file content", uploaded.?.data);
}

test "Context formFile returns null for wrong field name" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .POST, "/upload");
    defer req.deinit();
    try req.headers.set("Content-Type", "multipart/form-data; boundary=----TestBound");
    req.body = "------TestBound\r\n" ++
        "Content-Disposition: form-data; name=\"avatar\"; filename=\"pic.png\"\r\n" ++
        "Content-Type: image/png\r\n" ++
        "\r\n" ++
        "PNG DATA\r\n" ++
        "------TestBound--\r\n";

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    try std.testing.expect(ctx.formFile("file") == null); // looking for "file" not "avatar"
    try std.testing.expect(ctx.formFile("avatar") != null);
}

test "Context dataResponse" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/data");
    defer req.deinit();

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    var resp = try ctx.dataResponse(201, "application/pdf", "PDF content here");
    defer resp.deinit();

    try std.testing.expectEqual(@as(u16, 201), resp.status.code);
    try std.testing.expectEqualStrings("application/pdf", resp.headers.get("Content-Type").?);
}

test "Context clientIP with no proxy headers returns null" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/test");
    defer req.deinit();

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    try std.testing.expect(ctx.clientIP() == null);
}

test "Context clientIP with trusted proxies" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/test");
    defer req.deinit();
    // XFF: client -> proxy1 -> proxy2 (rightmost is closest to server)
    try req.headers.set("X-Forwarded-For", "1.1.1.1, 10.0.0.1, 10.0.0.2");

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    // Configure trusted proxies (our internal proxies)
    const cfg = ServerConfig{
        .trusted_proxies = &[_][]const u8{ "10.0.0.1", "10.0.0.2" },
    };
    ctx.server_config = &cfg;

    // Should return 1.1.1.1 (first non-trusted IP from the right)
    const ip = ctx.clientIP();
    try std.testing.expect(ip != null);
    try std.testing.expectEqualStrings("1.1.1.1", ip.?);
}

test "Context clientIP trusted proxies ignores untrusted" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/test");
    defer req.deinit();
    // Spoofed XFF from untrusted client
    try req.headers.set("X-Forwarded-For", "fake.ip.1.1");

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    const cfg = ServerConfig{
        .trusted_proxies = &[_][]const u8{"192.168.1.1"},
    };
    ctx.server_config = &cfg;

    // "fake.ip.1.1" is not trusted, so it IS the client IP
    // (it's the only entry and not in trusted list)
    const ip = ctx.clientIP();
    try std.testing.expect(ip != null);
    try std.testing.expectEqualStrings("fake.ip.1.1", ip.?);
}

test "Context query with key-only (no value)" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/search?verbose&q=test");
    defer req.deinit();

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    // key with no '=' should return ""
    try std.testing.expectEqualStrings("", ctx.query("verbose").?);
    try std.testing.expectEqualStrings("test", ctx.query("q").?);
}

test "Context queryArray with no matches returns empty" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/search?q=test");
    defer req.deinit();

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    const result = try ctx.queryArray("nonexistent");
    defer allocator.free(result);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "Context queryArray with no query string returns empty" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/search");
    defer req.deinit();

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    const result = try ctx.queryArray("q");
    defer allocator.free(result);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "Context fullPath returns matched route pattern" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/users/42");
    defer req.deinit();

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    try std.testing.expect(ctx.fullPath() == null);
    ctx.matched_path = "/users/:id";
    try std.testing.expectEqualStrings("/users/:id", ctx.fullPath().?);
}

test "noRoute and noMethod set custom handlers on router" {
    const allocator = std.testing.allocator;
    var server = Server.init(allocator);
    defer server.deinit();

    const custom_404 = struct {
        fn h(ctx: *Context) anyerror!Response {
            return ctx.status(404).json(.{ .error_field = "not found" });
        }
    }.h;

    const custom_405 = struct {
        fn h(ctx: *Context) anyerror!Response {
            return ctx.status(405).text("method not allowed");
        }
    }.h;

    server.noRoute(custom_404);
    server.noMethod(custom_405);

    try std.testing.expect(server.router.not_found_handler != null);
    try std.testing.expect(server.router.method_not_allowed_handler != null);
    try std.testing.expect(server.router.not_found_handler.? == custom_404);
    try std.testing.expect(server.router.method_not_allowed_handler.? == custom_405);
}

test "isTrustedProxy matches exact IPs" {
    const trusted = &[_][]const u8{ "10.0.0.1", "10.0.0.2", "192.168.1.1" };
    try std.testing.expect(Context.isTrustedProxy(trusted, "10.0.0.1"));
    try std.testing.expect(Context.isTrustedProxy(trusted, "192.168.1.1"));
    try std.testing.expect(!Context.isTrustedProxy(trusted, "1.2.3.4"));
    try std.testing.expect(!Context.isTrustedProxy(trusted, "10.0.0.3"));
}

test "Context abort middleware chain integration" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/test");
    defer req.deinit();

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    // Simulate abort before chain execution
    ctx.abort(403, "Forbidden");
    try std.testing.expect(ctx.isAborted());

    // chainNext should return the abort response
    const resp = try chainNext(&ctx);
    try std.testing.expectEqual(@as(u16, 403), resp.status.code);
}

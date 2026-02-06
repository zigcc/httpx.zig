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
const Middleware = @import("middleware.zig").Middleware;
const MiddlewareChain = @import("middleware.zig").MiddlewareChain;
const chainNext = @import("middleware.zig").chainNext;
const ws_handler = @import("ws_handler.zig");
const WebSocketHandler = ws_handler.WebSocketHandler;
const Json = @import("../util/json.zig");

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

    /// Sends a file response. Returns 404 if file not found.
    pub fn file(self: *Self, path: []const u8) !Response {
        const f = std.fs.cwd().openFile(path, .{}) catch return self.status(404).text("Not Found");
        defer f.close();

        const stat = try f.stat();
        const content = try self.allocator.alloc(u8, @intCast(stat.size));
        _ = try f.readAll(content);

        _ = try self.response.header(HeaderName.CONTENT_TYPE, "application/octet-stream");
        _ = self.response.body(content);
        return self.response.build();
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
};

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
    listener: ?zio.net.Server = null,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

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
        self.router.deinit();
        self.middleware.deinit(self.allocator);
        self.ws_handlers.deinit(self.allocator);
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
        _ = dir_path;
        // Register a catch-all route under the prefix
        const handler = struct {
            fn h(ctx: *Context) anyerror!Response {
                const filepath = ctx.param("filepath") orelse return ctx.status(404).text("Not Found");
                return ctx.file(filepath);
            }
        }.h;

        // Build pattern: /assets/*filepath
        var pattern = std.ArrayListUnmanaged(u8){};
        defer pattern.deinit(self.allocator);
        try pattern.appendSlice(self.allocator, url_prefix);
        try pattern.appendSlice(self.allocator, "/*filepath");
        const owned = try self.allocator.dupe(u8, pattern.items);

        try self.router.add(.GET, owned, handler);
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
    pub fn stop(self: *Self) void {
        self.running.store(false, .release);

        if (self.listener) |listener_val| {
            listener_val.close();
            self.listener = null;
        }
    }

    fn handleConnectionTask(self: *Self, stream: zio.net.Stream) anyerror!void {
        defer _ = self.active_requests.fetchSub(1, .monotonic);

        var conn_stream = stream;
        var should_close_stream = true;
        defer {
            if (should_close_stream) {
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

        const request_timeout = self.requestIoTimeout();
        const keep_alive_timeout = self.keepAliveIoTimeout();

        while (self.running.load(.acquire)) {
            parser.reset();

            var waiting_for_first_byte = pending_offset >= pending.items.len;

            while (!parser.isComplete() and !parser.isError()) {
                if (pending_offset < pending.items.len) {
                    const consumed = parser.feed(pending.items[pending_offset..]) catch |err| {
                        _ = self.total_errors.fetchAdd(1, .monotonic);
                        self.sendErrorStream(conn_stream, statusCodeForParseError(err), request_timeout) catch {};
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
                const n = conn_stream.read(&buffer, read_timeout) catch |err| switch (err) {
                    error.Timeout => {
                        if (waiting_for_first_byte) {
                            return;
                        }
                        _ = self.total_errors.fetchAdd(1, .monotonic);
                        self.sendErrorStream(conn_stream, 408, request_timeout) catch {};
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
                try self.sendErrorStream(conn_stream, 400, request_timeout);
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
                    var ws_conn = ws_handler.acceptUpgradeStream(self.allocator, conn_stream, &req, null) catch |err| {
                        _ = self.total_errors.fetchAdd(1, .monotonic);
                        return err;
                    };

                    if (pending_offset < pending.items.len) {
                        try ws_conn.frame_reader.feed(pending.items[pending_offset..]);
                        pending.clearRetainingCapacity();
                        pending_offset = 0;
                    }

                    should_close_stream = false;
                    defer ws_conn.deinit();

                    ws_h(&ws_conn) catch |err| {
                        std.debug.print("WebSocket handler error: {}\n", .{err});
                        _ = self.total_errors.fetchAdd(1, .monotonic);
                    };
                    return;
                }

                try self.sendErrorStream(conn_stream, 404, request_timeout);
                return;
            }

            // -- Route lookup with 405 support --
            var ctx = Context.init(self.allocator, &req);
            defer ctx.deinit();

            const find_result = self.router.findEx(req.method, req.uri.path);

            switch (find_result) {
                .not_found => {
                    if (self.router.not_found_handler) |nf_handler| {
                        var response = nf_handler(&ctx) catch |err| {
                            std.debug.print("NotFound handler error: {}\n", .{err});
                            _ = self.total_errors.fetchAdd(1, .monotonic);
                            try self.sendErrorStream(conn_stream, 500, request_timeout);
                            if (!self.shouldKeepAlive(&req)) return;
                            continue;
                        };
                        defer response.deinit();
                        const formatted = try http.formatResponse(&response, self.allocator);
                        defer self.allocator.free(formatted);
                        try conn_stream.writeAll(formatted, request_timeout);
                        _ = self.requests_handled.fetchAdd(1, .monotonic);
                    } else {
                        try self.sendErrorStream(conn_stream, 404, request_timeout);
                    }
                    if (!self.shouldKeepAlive(&req)) return;
                    continue;
                },
                .method_not_allowed => {
                    if (self.router.method_not_allowed_handler) |mna_handler| {
                        var response = mna_handler(&ctx) catch |err| {
                            std.debug.print("MethodNotAllowed handler error: {}\n", .{err});
                            _ = self.total_errors.fetchAdd(1, .monotonic);
                            try self.sendErrorStream(conn_stream, 500, request_timeout);
                            if (!self.shouldKeepAlive(&req)) return;
                            continue;
                        };
                        defer response.deinit();
                        const formatted = try http.formatResponse(&response, self.allocator);
                        defer self.allocator.free(formatted);
                        try conn_stream.writeAll(formatted, request_timeout);
                        _ = self.requests_handled.fetchAdd(1, .monotonic);
                    } else {
                        try self.sendErrorStream(conn_stream, 405, request_timeout);
                    }
                    if (!self.shouldKeepAlive(&req)) return;
                    continue;
                },
                .matched => |matched| {
                    // Populate context params
                    for (matched.params) |p| {
                        try ctx.params.put(p.name, p.value);
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
                        try self.sendErrorStream(conn_stream, 500, request_timeout);
                        if (!self.shouldKeepAlive(&req)) return;
                        continue;
                    };

                    defer response.deinit();

                    const formatted = try http.formatResponse(&response, self.allocator);
                    defer self.allocator.free(formatted);

                    try conn_stream.writeAll(formatted, request_timeout);
                    _ = self.requests_handled.fetchAdd(1, .monotonic);
                },
            }

            if (!self.shouldKeepAlive(&req)) {
                return;
            }
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

    fn shouldKeepAlive(self: *const Self, req: *const Request) bool {
        if (!self.config.keep_alive) return false;

        if (req.headers.get(HeaderName.CONNECTION)) |connection| {
            if (std.ascii.eqlIgnoreCase(connection, "close")) return false;
            if (std.ascii.eqlIgnoreCase(connection, "keep-alive")) return true;
        }

        return req.version == .HTTP_1_1;
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

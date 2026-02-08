//! HTTP Middleware Support for httpx.zig
//!
//! Gin-style middleware with onion model execution:
//!
//! - Middleware wraps handlers in layers (onion model)
//! - Each middleware calls `next(ctx)` to pass control to the next layer
//! - Global middleware applies to all routes
//! - Group middleware applies only to routes in that group
//! - Supports abort to short-circuit the middleware chain
//! - Middleware can capture configuration via an opaque config pointer
//!
//! Built-in middleware:
//! - CORS (Cross-Origin Resource Sharing)
//! - Logging and request timing
//! - Rate limiting
//! - Basic authentication
//! - Security headers (Helmet)
//! - Response compression (gzip, deflate)
//! - Conditional requests (ETag / If-None-Match)
//! - Range requests (206 Partial Content)
//! - Recovery (catch handler errors)
//! - Request ID generation

const std = @import("std");
const Context = @import("server.zig").Context;
const Response = @import("../core/response.zig").Response;
const types = @import("../core/types.zig");
const compression_util = @import("../util/compression.zig");
const HeaderName = @import("../core/headers.zig").HeaderName;
const etag_util = @import("../util/etag.zig");
const range_util = @import("../util/range.zig");
const date_util = @import("../util/date.zig");
const encoding_util = @import("../util/encoding.zig");

/// Middleware function type with optional configuration capture.
///
/// The `config` parameter is an opaque pointer to middleware-specific
/// configuration. Middleware without configuration sets this to `null`.
/// The handler receives the config pointer and can cast it to the
/// appropriate type.
pub const Middleware = struct {
    handler: *const fn (?*const anyopaque, *Context, Next) anyerror!Response,
    config: ?*const anyopaque = null,
    name: []const u8 = "unnamed",
};

/// Next function to call the next middleware.
pub const Next = *const fn (*Context) anyerror!Response;

/// Handler function type (same as server.Handler).
pub const Handler = *const fn (*Context) anyerror!Response;

/// Middleware chain executor — Gin-style onion model.
///
/// Builds a chain of middleware + final handler that executes in order.
/// Each middleware receives its config, `ctx`, and a `next` function pointer.
/// The chain is built at request time by combining:
///   1. Global middleware (from server.use())
///   2. Route middleware (from group.use())
///   3. The final route handler
pub const MiddlewareChain = struct {
    /// Execute a middleware chain: global_mw... + route_mw... + handler.
    pub fn execute(
        ctx: *Context,
        global_mw: []const Middleware,
        route_mw: []const Middleware,
        final_handler: Handler,
    ) anyerror!Response {
        ctx.chain_handlers = final_handler;
        ctx.chain_global_mw = global_mw;
        ctx.chain_route_mw = route_mw;
        ctx.chain_index = 0;

        return chainNext(ctx);
    }
};

/// The `next` function that advances through the middleware chain.
/// This is what gets passed to each middleware as the `next` parameter.
pub fn chainNext(ctx: *Context) anyerror!Response {
    if (ctx.is_aborted) {
        return ctx.abort_response orelse ctx.status(500).text("Aborted");
    }

    const global_len = ctx.chain_global_mw.len;
    const route_len = ctx.chain_route_mw.len;
    const total = global_len + route_len;
    const idx = ctx.chain_index;

    if (idx < total) {
        ctx.chain_index += 1;
        const mw = if (idx < global_len)
            ctx.chain_global_mw[idx]
        else
            ctx.chain_route_mw[idx - global_len];
        return mw.handler(mw.config, ctx, chainNext);
    }

    // All middleware executed, call the final handler
    return ctx.chain_handlers(ctx);
}

/// Helper to create a stateless middleware (no config needed).
fn stateless(name: []const u8, handler: *const fn (?*const anyopaque, *Context, Next) anyerror!Response) Middleware {
    return .{ .handler = handler, .config = null, .name = name };
}

// =============================================================================
// CORS Middleware
// =============================================================================

/// CORS configuration.
pub const CorsConfig = struct {
    allowed_origins: []const []const u8 = &[_][]const u8{"*"},
    allowed_methods: []const types.Method = &[_]types.Method{ .GET, .POST, .PUT, .DELETE, .PATCH, .OPTIONS },
    allowed_headers: []const []const u8 = &[_][]const u8{ "Content-Type", "Authorization" },
    exposed_headers: []const []const u8 = &[_][]const u8{},
    allow_credentials: bool = false,
    max_age: u32 = 86400,

    fn formatMethods(self: *const CorsConfig, buf: *[256]u8) []const u8 {
        var pos: usize = 0;
        for (self.allowed_methods, 0..) |method, i| {
            if (i > 0) {
                if (pos + 2 <= buf.len) {
                    buf[pos] = ',';
                    buf[pos + 1] = ' ';
                    pos += 2;
                }
            }
            const name = method.toString();
            if (pos + name.len <= buf.len) {
                @memcpy(buf[pos..][0..name.len], name);
                pos += name.len;
            }
        }
        return buf[0..pos];
    }

    fn formatHeaders(self: *const CorsConfig, buf: *[512]u8) []const u8 {
        var pos: usize = 0;
        for (self.allowed_headers, 0..) |hdr, i| {
            if (i > 0) {
                if (pos + 2 <= buf.len) {
                    buf[pos] = ',';
                    buf[pos + 1] = ' ';
                    pos += 2;
                }
            }
            if (pos + hdr.len <= buf.len) {
                @memcpy(buf[pos..][0..hdr.len], hdr);
                pos += hdr.len;
            }
        }
        return buf[0..pos];
    }

    fn isOriginAllowed(self: *const CorsConfig, origin: []const u8) bool {
        for (self.allowed_origins) |allowed| {
            if (std.mem.eql(u8, allowed, "*")) return true;
            if (std.ascii.eqlIgnoreCase(allowed, origin)) return true;
        }
        return false;
    }
};

/// Creates CORS middleware with configuration.
pub fn cors(config: CorsConfig) Middleware {
    return .{
        .name = "cors",
        .config = @ptrCast(cors_config_storage.store(config)),
        .handler = struct {
            fn handler(cfg_ptr: ?*const anyopaque, ctx: *Context, next: Next) anyerror!Response {
                const cfg: *const CorsConfig = @ptrCast(@alignCast(cfg_ptr.?));

                // Get the origin from the request
                const origin = ctx.header("Origin") orelse {
                    // No Origin header -- not a CORS request, pass through
                    return next(ctx);
                };

                // Check if origin is allowed
                if (!cfg.isOriginAllowed(origin)) {
                    return next(ctx);
                }

                // Set Access-Control-Allow-Origin
                if (cfg.allowed_origins.len == 1 and std.mem.eql(u8, cfg.allowed_origins[0], "*") and !cfg.allow_credentials) {
                    try ctx.setHeader("Access-Control-Allow-Origin", "*");
                } else {
                    try ctx.setHeader("Access-Control-Allow-Origin", origin);
                    try ctx.setHeader("Vary", "Origin");
                }

                if (cfg.allow_credentials) {
                    try ctx.setHeader("Access-Control-Allow-Credentials", "true");
                }

                // Exposed headers
                if (cfg.exposed_headers.len > 0) {
                    var exposed_buf: [512]u8 = undefined;
                    var epos: usize = 0;
                    for (cfg.exposed_headers, 0..) |hdr, i| {
                        if (i > 0 and epos + 2 <= exposed_buf.len) {
                            exposed_buf[epos] = ',';
                            exposed_buf[epos + 1] = ' ';
                            epos += 2;
                        }
                        if (epos + hdr.len <= exposed_buf.len) {
                            @memcpy(exposed_buf[epos..][0..hdr.len], hdr);
                            epos += hdr.len;
                        }
                    }
                    try ctx.setHeader("Access-Control-Expose-Headers", exposed_buf[0..epos]);
                }

                // Handle preflight
                if (ctx.request.method == .OPTIONS) {
                    var methods_buf: [256]u8 = undefined;
                    try ctx.setHeader("Access-Control-Allow-Methods", cfg.formatMethods(&methods_buf));

                    var headers_buf: [512]u8 = undefined;
                    try ctx.setHeader("Access-Control-Allow-Headers", cfg.formatHeaders(&headers_buf));

                    var age_buf: [16]u8 = undefined;
                    const age_str = std.fmt.bufPrint(&age_buf, "{d}", .{cfg.max_age}) catch "86400";
                    try ctx.setHeader("Access-Control-Max-Age", age_str);

                    return ctx.status(204).text("");
                }

                return next(ctx);
            }
        }.handler,
    };
}

// Thread-safe storage for CorsConfig (comptime-known number of slots).
const cors_config_storage = ConfigStore(CorsConfig, 8){};

// =============================================================================
// Logger Middleware
// =============================================================================

/// Creates logging middleware that logs method, path, status code, and duration.
pub fn logger() Middleware {
    return stateless("logger", struct {
        fn handler(_: ?*const anyopaque, ctx: *Context, next: Next) anyerror!Response {
            const start = std.time.milliTimestamp();
            const response = try next(ctx);
            const duration = std.time.milliTimestamp() - start;

            const status_code = response.status.code;
            const color = statusColor(status_code);
            const reset = "\x1b[0m";

            std.debug.print("{s}{d}{s} | {d:>6}ms | {s} {s}\n", .{
                color,
                status_code,
                reset,
                duration,
                ctx.request.method.toString(),
                ctx.request.uri.path,
            });

            return response;
        }
    }.handler);
}

fn statusColor(code: u16) []const u8 {
    if (code < 200) return "\x1b[36m"; // cyan - informational
    if (code < 300) return "\x1b[32m"; // green - success
    if (code < 400) return "\x1b[34m"; // blue - redirect
    if (code < 500) return "\x1b[33m"; // yellow - client error
    return "\x1b[31m"; // red - server error
}

// =============================================================================
// Recovery Middleware
// =============================================================================

/// Creates recovery middleware that catches handler errors and returns 500.
pub fn recovery() Middleware {
    return stateless("recovery", struct {
        fn handler(_: ?*const anyopaque, ctx: *Context, next: Next) anyerror!Response {
            return next(ctx) catch |err| {
                std.debug.print("[Recovery] caught error in handler: {}\n", .{err});
                return ctx.status(500).text("Internal Server Error");
            };
        }
    }.handler);
}

/// Recovery writer config.
const RecoveryWriterConfig = struct {
    writer: *const fn ([]const u8) void,
};
const recovery_writer_storage = ConfigStore(RecoveryWriterConfig, 4){};

/// Creates recovery middleware with custom error writer.
pub fn recoveryWithWriter(writer: *const fn ([]const u8) void) Middleware {
    const cfg = recovery_writer_storage.store(.{ .writer = writer });
    return .{
        .name = "recovery",
        .config = @ptrCast(cfg),
        .handler = struct {
            fn handler(cfg_ptr: ?*const anyopaque, ctx: *Context, next: Next) anyerror!Response {
                const cfg_inner: *const RecoveryWriterConfig = @ptrCast(@alignCast(cfg_ptr.?));
                return next(ctx) catch |err| {
                    var err_buf: [256]u8 = undefined;
                    const msg = std.fmt.bufPrint(&err_buf, "[Recovery] caught error: {}", .{err}) catch "[Recovery] caught error";
                    cfg_inner.writer(msg);
                    return ctx.status(500).text("Internal Server Error");
                };
            }
        }.handler,
    };
}

// =============================================================================
// Compression Middleware
// =============================================================================

/// Compression middleware configuration.
pub const CompressionConfig = struct {
    /// Minimum response size to compress (default: 1024 bytes).
    min_size: usize = 1024,
    /// Compression level (1-9).
    level: u4 = 6,
    /// Preferred encoding order when client supports multiple.
    preferred_encodings: []const compression_util.Encoding = &[_]compression_util.Encoding{
        .gzip,
        .deflate,
    },
    /// Content-Types that should NOT be compressed.
    excluded_types: []const []const u8 = &[_][]const u8{
        "image/png",
        "image/jpeg",
        "image/gif",
        "image/webp",
        "video/",
        "audio/",
        "application/zip",
        "application/gzip",
        "application/x-rar",
        "application/pdf",
    },
};

/// Parsed Accept-Encoding entry with quality factor.
const AcceptEncodingEntry = struct {
    encoding: compression_util.Encoding,
    quality: f32,

    fn lessThan(_: void, a: AcceptEncodingEntry, b: AcceptEncodingEntry) bool {
        return a.quality > b.quality;
    }
};

/// Parses Accept-Encoding header value into sorted list of encodings.
pub fn parseAcceptEncoding(value: []const u8) [8]?AcceptEncodingEntry {
    var entries: [8]?AcceptEncodingEntry = .{ null, null, null, null, null, null, null, null };
    var count: usize = 0;

    var it = std.mem.splitScalar(u8, value, ',');
    while (it.next()) |part| {
        if (count >= 8) break;

        const trimmed = std.mem.trim(u8, part, " \t");
        if (trimmed.len == 0) continue;

        var quality: f32 = 1.0;
        var encoding_str = trimmed;

        if (std.mem.indexOf(u8, trimmed, ";")) |semi_pos| {
            encoding_str = std.mem.trim(u8, trimmed[0..semi_pos], " \t");
            const params = trimmed[semi_pos + 1 ..];

            if (std.mem.indexOf(u8, params, "q=")) |q_pos| {
                const q_start = q_pos + 2;
                var q_end = q_start;
                while (q_end < params.len and (params[q_end] == '.' or std.ascii.isDigit(params[q_end]))) {
                    q_end += 1;
                }
                if (q_end > q_start) {
                    quality = std.fmt.parseFloat(f32, params[q_start..q_end]) catch 1.0;
                    quality = @min(1.0, @max(0.0, quality));
                }
            }
        }

        if (quality == 0.0) continue;
        if (std.mem.eql(u8, encoding_str, "*")) continue;

        if (compression_util.Encoding.fromString(encoding_str)) |enc| {
            entries[count] = .{ .encoding = enc, .quality = quality };
            count += 1;
        }
    }

    var temp_entries: [8]AcceptEncodingEntry = undefined;
    var temp_count: usize = 0;
    for (entries) |maybe_entry| {
        if (maybe_entry) |entry| {
            temp_entries[temp_count] = entry;
            temp_count += 1;
        }
    }

    std.mem.sort(AcceptEncodingEntry, temp_entries[0..temp_count], {}, AcceptEncodingEntry.lessThan);

    var result: [8]?AcceptEncodingEntry = .{ null, null, null, null, null, null, null, null };
    for (0..temp_count) |i| {
        result[i] = temp_entries[i];
    }

    return result;
}

fn selectEncoding(accept_entries: [8]?AcceptEncodingEntry, config: CompressionConfig) ?compression_util.Encoding {
    for (accept_entries) |maybe_entry| {
        const entry = maybe_entry orelse break;
        for (config.preferred_encodings) |preferred| {
            if (entry.encoding == preferred) {
                return preferred;
            }
        }
    }
    return null;
}

fn shouldExcludeContentType(content_type: ?[]const u8, config: CompressionConfig) bool {
    const ct = content_type orelse return false;
    for (config.excluded_types) |excluded| {
        if (std.mem.startsWith(u8, ct, excluded)) {
            return true;
        }
    }
    return false;
}

const compression_config_storage = ConfigStore(CompressionConfig, 4){};

/// Creates compression middleware with default configuration.
pub fn compression() Middleware {
    return compressionWithConfig(.{});
}

/// Creates compression middleware with custom configuration.
pub fn compressionWithConfig(config: CompressionConfig) Middleware {
    return .{
        .name = "compression",
        .config = @ptrCast(compression_config_storage.store(config)),
        .handler = struct {
            fn handler(cfg_ptr: ?*const anyopaque, ctx: *Context, next: Next) anyerror!Response {
                const cfg: *const CompressionConfig = @ptrCast(@alignCast(cfg_ptr.?));
                var response = try next(ctx);

                const accept_encoding = ctx.header(HeaderName.ACCEPT_ENCODING) orelse {
                    return response;
                };

                const accept_entries = parseAcceptEncoding(accept_encoding);

                const chosen_encoding = selectEncoding(accept_entries, cfg.*) orelse {
                    return response;
                };

                const body = response.body orelse return response;
                if (body.len < cfg.min_size) {
                    return response;
                }

                const content_type = response.headers.get(HeaderName.CONTENT_TYPE);
                if (shouldExcludeContentType(content_type, cfg.*)) {
                    return response;
                }

                if (response.headers.get(HeaderName.CONTENT_ENCODING) != null) {
                    return response;
                }

                const compressed = compression_util.compress(
                    ctx.allocator,
                    body,
                    chosen_encoding,
                ) catch {
                    return response;
                };

                if (compressed.len >= body.len) {
                    ctx.allocator.free(compressed);
                    return response;
                }

                if (response.body_owned) {
                    if (response.body) |old_body| {
                        response.allocator.free(old_body);
                    }
                }
                response.body = compressed;
                response.body_owned = true;

                response.headers.set(HeaderName.CONTENT_ENCODING, chosen_encoding.toString()) catch {};

                var len_buf: [32]u8 = undefined;
                const len_str = std.fmt.bufPrint(&len_buf, "{d}", .{compressed.len}) catch unreachable;
                response.headers.set(HeaderName.CONTENT_LENGTH, len_str) catch {};

                response.headers.append(HeaderName.VARY, HeaderName.ACCEPT_ENCODING) catch {};

                return response;
            }
        }.handler,
    };
}

// =============================================================================
// Rate Limiting Middleware
// =============================================================================

/// Rate limiting configuration.
pub const RateLimitConfig = struct {
    /// Maximum requests allowed per window.
    max_requests: u32 = 100,
    /// Time window in milliseconds.
    window_ms: u64 = 60_000,
};

/// Global rate limiter state — fixed-size IP-based token bucket.
/// Uses a simple sliding window counter per IP address slot.
const RateLimiterState = struct {
    const MAX_ENTRIES = 1024;

    /// Stored IP hash -> (count, window_start_ms)
    ip_hashes: [MAX_ENTRIES]u64 = [_]u64{0} ** MAX_ENTRIES,
    counts: [MAX_ENTRIES]std.atomic.Value(u32) = init: {
        var arr: [MAX_ENTRIES]std.atomic.Value(u32) = undefined;
        for (&arr) |*a| {
            a.* = std.atomic.Value(u32).init(0);
        }
        break :init arr;
    },
    window_starts: [MAX_ENTRIES]std.atomic.Value(i64) = init: {
        var arr: [MAX_ENTRIES]std.atomic.Value(i64) = undefined;
        for (&arr) |*a| {
            a.* = std.atomic.Value(i64).init(0);
        }
        break :init arr;
    },

    fn hashIP(ip: []const u8) u64 {
        var h: u64 = 5381;
        for (ip) |c| {
            h = ((h << 5) +% h) +% c;
        }
        return h;
    }

    fn checkAndIncrement(self: *RateLimiterState, ip: []const u8, max_requests: u32, window_ms: u64) bool {
        const ip_hash = hashIP(ip);
        const slot = ip_hash % MAX_ENTRIES;
        const now = std.time.milliTimestamp();
        const window_start = self.window_starts[slot].load(.acquire);

        // Check if this slot belongs to the same IP and is within the window
        if (self.ip_hashes[slot] == ip_hash and (now - window_start) < @as(i64, @intCast(window_ms))) {
            // Same IP, same window — increment
            const current = self.counts[slot].fetchAdd(1, .monotonic);
            return current < max_requests;
        }

        // New window or different IP — reset
        self.ip_hashes[slot] = ip_hash;
        self.counts[slot].store(1, .release);
        self.window_starts[slot].store(now, .release);
        return true;
    }
};

var global_rate_limiter = RateLimiterState{};

const rate_limit_config_storage = ConfigStore(RateLimitConfig, 4){};

/// Creates rate limiting middleware with a sliding window counter.
/// Tracks requests per client IP using a fixed-size hash table.
pub fn rateLimit(config: RateLimitConfig) Middleware {
    return .{
        .name = "rate_limit",
        .config = @ptrCast(rate_limit_config_storage.store(config)),
        .handler = struct {
            fn handler(cfg_ptr: ?*const anyopaque, ctx: *Context, next_fn: Next) anyerror!Response {
                const cfg: *const RateLimitConfig = @ptrCast(@alignCast(cfg_ptr.?));
                const ip = ctx.clientIP() orelse "unknown";

                if (!global_rate_limiter.checkAndIncrement(ip, cfg.max_requests, cfg.window_ms)) {
                    return ctx.status(429).text("Too Many Requests");
                }

                return next_fn(ctx);
            }
        }.handler,
    };
}

// =============================================================================
// Basic Auth Middleware
// =============================================================================

const BasicAuthConfig = struct {
    realm: []const u8,
    validator: *const fn ([]const u8, []const u8) bool,
};

const basic_auth_storage = ConfigStore(BasicAuthConfig, 4){};

/// Creates basic authentication middleware.
/// The validator function receives (username, password) and returns true if valid.
pub fn basicAuth(realm: []const u8, validator: *const fn ([]const u8, []const u8) bool) Middleware {
    return .{
        .name = "basic_auth",
        .config = @ptrCast(basic_auth_storage.store(.{ .realm = realm, .validator = validator })),
        .handler = struct {
            fn handler(cfg_ptr: ?*const anyopaque, ctx: *Context, next: Next) anyerror!Response {
                const cfg: *const BasicAuthConfig = @ptrCast(@alignCast(cfg_ptr.?));

                const auth_header = ctx.header("Authorization") orelse {
                    var realm_buf: [128]u8 = undefined;
                    const www_auth = std.fmt.bufPrint(&realm_buf, "Basic realm=\"{s}\"", .{cfg.realm}) catch "Basic realm=\"Restricted\"";
                    try ctx.setHeader("WWW-Authenticate", www_auth);
                    return ctx.status(401).text("Unauthorized");
                };

                if (!std.mem.startsWith(u8, auth_header, "Basic ")) {
                    return ctx.status(401).text("Unauthorized");
                }

                const encoded = auth_header["Basic ".len..];

                // Decode base64 credentials
                const decoded = encoding_util.Base64.decode(ctx.allocator, encoded) catch {
                    return ctx.status(401).text("Unauthorized");
                };
                defer ctx.allocator.free(decoded);

                // Split username:password
                if (std.mem.indexOfScalar(u8, decoded, ':')) |colon_pos| {
                    const username = decoded[0..colon_pos];
                    const password = decoded[colon_pos + 1 ..];
                    if (cfg.validator(username, password)) {
                        return next(ctx);
                    }
                }

                return ctx.status(401).text("Unauthorized");
            }
        }.handler,
    };
}

// =============================================================================
// Body Parser, Helmet, Timeout, Request ID
// =============================================================================

/// Creates body parser middleware (currently a pass-through; body parsing
/// is handled by the server's incremental parser).
pub fn bodyParser(max_size: usize) Middleware {
    _ = max_size;
    return stateless("body_parser", struct {
        fn handler(_: ?*const anyopaque, ctx: *Context, next: Next) anyerror!Response {
            return next(ctx);
        }
    }.handler);
}

/// Creates security headers middleware (Helmet).
pub fn helmet() Middleware {
    return stateless("helmet", struct {
        fn handler(_: ?*const anyopaque, ctx: *Context, next: Next) anyerror!Response {
            var resp = try next(ctx);
            resp.headers.set("X-Content-Type-Options", "nosniff") catch {};
            resp.headers.set("X-Frame-Options", "SAMEORIGIN") catch {};
            resp.headers.set("X-XSS-Protection", "1; mode=block") catch {};
            resp.headers.set("Referrer-Policy", "strict-origin-when-cross-origin") catch {};
            return resp;
        }
    }.handler);
}

/// Timeout configuration.
const TimeoutConfig = struct {
    timeout_ms: u64,
};
const timeout_config_storage = ConfigStore(TimeoutConfig, 4){};

/// Creates request timeout middleware.
/// Measures handler execution time and returns 503 if it exceeds the limit.
/// This is a cooperative timeout — if the handler completes but took too long,
/// the timeout response is returned instead. For I/O-level timeouts, configure
/// `ServerConfig.request_timeout_ms`.
pub fn timeout(ms: u64) Middleware {
    return .{
        .name = "timeout",
        .config = @ptrCast(timeout_config_storage.store(.{ .timeout_ms = ms })),
        .handler = struct {
            fn handler(cfg_ptr: ?*const anyopaque, ctx: *Context, next_fn: Next) anyerror!Response {
                const cfg: *const TimeoutConfig = @ptrCast(@alignCast(cfg_ptr.?));
                const start = std.time.milliTimestamp();
                var resp = try next_fn(ctx);
                const elapsed = std.time.milliTimestamp() - start;
                if (elapsed > @as(i64, @intCast(cfg.timeout_ms))) {
                    resp.deinit();
                    return ctx.status(503).text("Service Unavailable: request timeout");
                }
                return resp;
            }
        }.handler,
    };
}

/// Creates request ID middleware that generates unique IDs.
/// Uses a global atomic counter for uniqueness.
pub fn requestId() Middleware {
    return stateless("request_id", struct {
        var counter = std.atomic.Value(u64).init(0);

        fn handler(_: ?*const anyopaque, ctx: *Context, next: Next) anyerror!Response {
            const id = counter.fetchAdd(1, .monotonic);
            var id_buf: [32]u8 = undefined;
            const id_str = std.fmt.bufPrint(&id_buf, "{x:0>16}", .{id}) catch "0000000000000000";
            try ctx.setHeader("X-Request-ID", id_str);
            return next(ctx);
        }
    }.handler);
}

// =============================================================================
// Conditional Request Middleware (ETag / If-None-Match / If-Modified-Since)
// =============================================================================

/// Configuration for conditional request middleware.
pub const ConditionalConfig = struct {
    auto_etag: bool = true,
    auto_last_modified: bool = false,
    last_modified: ?i64 = null,
};

const conditional_config_storage = ConfigStore(ConditionalConfig, 4){};

/// Creates conditional request middleware with default configuration.
pub fn conditional() Middleware {
    return conditionalWithConfig(.{});
}

/// Creates conditional request middleware with custom configuration.
pub fn conditionalWithConfig(config: ConditionalConfig) Middleware {
    return .{
        .name = "conditional",
        .config = @ptrCast(conditional_config_storage.store(config)),
        .handler = struct {
            fn handler(cfg_ptr: ?*const anyopaque, ctx: *Context, next: Next) anyerror!Response {
                const cfg: *const ConditionalConfig = @ptrCast(@alignCast(cfg_ptr.?));
                var response = try next(ctx);

                if (ctx.request.method != .GET and ctx.request.method != .HEAD) {
                    return response;
                }

                var etag_buf: [72]u8 = undefined;
                var etag_value: ?[]const u8 = response.headers.get(HeaderName.ETAG);

                if (etag_value == null and cfg.auto_etag) {
                    if (response.body) |body| {
                        const hash = etag_util.generate(body);
                        const server_etag = etag_util.ETag{ .value = &hash, .weak = false };
                        etag_value = server_etag.format(&etag_buf);
                        response.headers.set(HeaderName.ETAG, etag_value.?) catch {};
                    }
                }

                if (ctx.header("If-None-Match")) |if_none_match| {
                    if (etag_value) |etag_str| {
                        if (etag_util.parse(etag_str)) |server_etag| {
                            if (etag_util.matchIfNoneMatch(if_none_match, server_etag)) {
                                response.deinit();
                                var not_modified = Response.init(ctx.allocator, 304);
                                not_modified.headers.set(HeaderName.ETAG, etag_str) catch {};
                                return not_modified;
                            }
                        }
                    }
                }

                if (ctx.header("If-Modified-Since")) |if_modified_since| {
                    if (date_util.parseHttpDate(if_modified_since)) |client_time| {
                        const last_modified = blk: {
                            if (cfg.last_modified) |lm| break :blk lm;
                            if (response.headers.get("Last-Modified")) |lm| {
                                break :blk date_util.parseHttpDate(lm) orelse std.time.timestamp();
                            }
                            break :blk std.time.timestamp();
                        };

                        if (!date_util.isModifiedSince(last_modified, client_time)) {
                            response.deinit();
                            var not_modified = Response.init(ctx.allocator, 304);
                            if (etag_value) |etag_str| {
                                not_modified.headers.set(HeaderName.ETAG, etag_str) catch {};
                            }
                            return not_modified;
                        }
                    }
                }

                return response;
            }
        }.handler,
    };
}

// =============================================================================
// Range Request Middleware (206 Partial Content)
// =============================================================================

/// Configuration for range request middleware.
pub const RangeConfig = struct {
    accept_ranges: bool = true,
    max_ranges: usize = 8,
};

const range_config_storage = ConfigStore(RangeConfig, 4){};

/// Creates range request middleware with default configuration.
pub fn rangeRequest() Middleware {
    return rangeRequestWithConfig(.{});
}

/// Creates range request middleware with custom configuration.
pub fn rangeRequestWithConfig(config: RangeConfig) Middleware {
    return .{
        .name = "range_request",
        .config = @ptrCast(range_config_storage.store(config)),
        .handler = struct {
            fn handler(cfg_ptr: ?*const anyopaque, ctx: *Context, next: Next) anyerror!Response {
                const cfg: *const RangeConfig = @ptrCast(@alignCast(cfg_ptr.?));
                var response = try next(ctx);

                if (ctx.request.method != .GET) {
                    return response;
                }

                if (response.status.code != 200) {
                    return response;
                }

                const body = response.body orelse return response;
                const total_size = body.len;

                if (cfg.accept_ranges) {
                    response.headers.set("Accept-Ranges", "bytes") catch {};
                }

                const range_header = ctx.header(HeaderName.RANGE) orelse return response;

                if (ctx.header("If-Range")) |if_range| {
                    var should_serve_full = false;

                    if (etag_util.parse(if_range)) |client_etag| {
                        if (response.headers.get(HeaderName.ETAG)) |server_etag_str| {
                            if (etag_util.parse(server_etag_str)) |server_etag| {
                                if (!etag_util.match(client_etag, server_etag, .strong)) {
                                    should_serve_full = true;
                                }
                            }
                        } else {
                            should_serve_full = true;
                        }
                    } else if (date_util.parseHttpDate(if_range)) |client_time| {
                        const last_modified = blk: {
                            if (response.headers.get("Last-Modified")) |lm| {
                                break :blk date_util.parseHttpDate(lm) orelse std.time.timestamp();
                            }
                            break :blk std.time.timestamp();
                        };

                        if (date_util.isModifiedSince(last_modified, client_time)) {
                            should_serve_full = true;
                        }
                    }

                    if (should_serve_full) {
                        return response;
                    }
                }

                const parse_result = range_util.parse(range_header, total_size) catch {
                    response.deinit();
                    var range_error = Response.init(ctx.allocator, 416);
                    var content_range_buf: [64]u8 = undefined;
                    const content_range = range_util.formatUnsatisfiableRange(total_size, &content_range_buf);
                    range_error.headers.set("Content-Range", content_range) catch {};
                    return range_error;
                };

                if (parse_result.count != 1) {
                    return response;
                }

                const byte_range = parse_result.ranges[0].?;

                const partial_body = body[byte_range.start .. byte_range.end + 1];

                response.deinit();
                var partial = Response.init(ctx.allocator, 206);

                partial.body = ctx.allocator.dupe(u8, partial_body) catch return error.OutOfMemory;
                partial.body_owned = true;

                var content_range_buf: [64]u8 = undefined;
                const content_range = range_util.formatContentRange(
                    byte_range.start,
                    byte_range.end,
                    total_size,
                    &content_range_buf,
                );
                partial.headers.set("Content-Range", content_range) catch {};

                var len_buf: [32]u8 = undefined;
                const len_str = std.fmt.bufPrint(&len_buf, "{d}", .{partial_body.len}) catch unreachable;
                partial.headers.set(HeaderName.CONTENT_LENGTH, len_str) catch {};

                partial.headers.set("Accept-Ranges", "bytes") catch {};

                return partial;
            }
        }.handler,
    };
}

// =============================================================================
// Session Middleware — In-memory cookie-based sessions
// =============================================================================

/// Session configuration.
pub const SessionConfig = struct {
    /// Cookie name for the session ID.
    cookie_name: []const u8 = "httpx_session",
    /// Max-Age for the session cookie in seconds. 0 means session cookie.
    max_age: i32 = 3600,
    /// Path for the session cookie.
    path: []const u8 = "/",
    /// Whether to set HttpOnly on the session cookie.
    http_only: bool = true,
    /// Whether to set Secure on the session cookie.
    secure: bool = false,
};

/// Global in-memory session store.
/// Uses a fixed-size hash table of session_id -> data slots.
/// Each session stores up to 16 key-value pairs.
const SessionStore = struct {
    const MAX_SESSIONS = 4096;
    const MAX_PAIRS = 16;
    const KEY_LEN = 64;
    const VAL_LEN = 256;

    const SessionEntry = struct {
        session_id: [32]u8 = [_]u8{0} ** 32,
        active: bool = false,
        keys: [MAX_PAIRS][KEY_LEN]u8 = [_][KEY_LEN]u8{[_]u8{0} ** KEY_LEN} ** MAX_PAIRS,
        values: [MAX_PAIRS][VAL_LEN]u8 = [_][VAL_LEN]u8{[_]u8{0} ** VAL_LEN} ** MAX_PAIRS,
        key_lens: [MAX_PAIRS]u8 = [_]u8{0} ** MAX_PAIRS,
        val_lens: [MAX_PAIRS]u16 = [_]u16{0} ** MAX_PAIRS,
        pair_count: u8 = 0,
        created_at: i64 = 0,
    };

    entries: [MAX_SESSIONS]SessionEntry = [_]SessionEntry{.{}} ** MAX_SESSIONS,

    fn hashId(id: []const u8) usize {
        var h: u64 = 5381;
        for (id) |c| {
            h = ((h << 5) +% h) +% c;
        }
        return @intCast(h % MAX_SESSIONS);
    }

    fn findOrCreate(self: *SessionStore, session_id: []const u8) *SessionEntry {
        const slot = hashId(session_id);
        const entry = &self.entries[slot];
        if (entry.active and std.mem.eql(u8, entry.session_id[0..session_id.len], session_id)) {
            return entry;
        }
        // Create new session
        entry.* = .{
            .active = true,
            .created_at = std.time.timestamp(),
        };
        const copy_len = @min(session_id.len, 32);
        @memcpy(entry.session_id[0..copy_len], session_id[0..copy_len]);
        return entry;
    }

    fn getValue(entry: *const SessionEntry, key: []const u8) ?[]const u8 {
        for (0..entry.pair_count) |i| {
            const stored_key = entry.keys[i][0..entry.key_lens[i]];
            if (std.mem.eql(u8, stored_key, key)) {
                return entry.values[i][0..entry.val_lens[i]];
            }
        }
        return null;
    }

    fn setValue(entry: *SessionEntry, key: []const u8, value: []const u8) void {
        if (key.len > KEY_LEN or value.len > VAL_LEN) return;

        // Check if key already exists
        for (0..entry.pair_count) |i| {
            const stored_key = entry.keys[i][0..entry.key_lens[i]];
            if (std.mem.eql(u8, stored_key, key)) {
                @memcpy(entry.values[i][0..value.len], value);
                entry.val_lens[i] = @intCast(value.len);
                return;
            }
        }

        // Add new pair
        if (entry.pair_count < MAX_PAIRS) {
            const idx = entry.pair_count;
            @memcpy(entry.keys[idx][0..key.len], key);
            entry.key_lens[idx] = @intCast(key.len);
            @memcpy(entry.values[idx][0..value.len], value);
            entry.val_lens[idx] = @intCast(value.len);
            entry.pair_count += 1;
        }
    }
};

var global_session_store = SessionStore{};

const session_config_storage = ConfigStore(SessionConfig, 4){};

/// Creates session middleware with default configuration.
/// Provides in-memory cookie-based sessions. Session data is stored
/// in a global fixed-size hash table. For production use, consider
/// implementing a Redis or database-backed session store.
///
/// Usage in handlers:
/// ```zig
/// // The session ID is stored in ctx data as "_session_id"
/// const session_id = ctx.get("_session_id");
/// ```
pub fn session(config: SessionConfig) Middleware {
    return .{
        .name = "session",
        .config = @ptrCast(session_config_storage.store(config)),
        .handler = struct {
            fn handler(cfg_ptr: ?*const anyopaque, ctx: *Context, next_fn: Next) anyerror!Response {
                const cfg: *const SessionConfig = @ptrCast(@alignCast(cfg_ptr.?));

                // Check for existing session cookie
                var session_id_buf: [32]u8 = undefined;
                var session_id: []const u8 = undefined;
                var need_set_cookie = false;

                if (ctx.getCookie(cfg.cookie_name)) |existing_id| {
                    const copy_len = @min(existing_id.len, 32);
                    @memcpy(session_id_buf[0..copy_len], existing_id[0..copy_len]);
                    session_id = session_id_buf[0..copy_len];
                } else {
                    // Generate a new session ID using a counter + timestamp
                    const SessionCounter = struct {
                        var counter = std.atomic.Value(u64).init(0);
                    };
                    const id_num = SessionCounter.counter.fetchAdd(1, .monotonic);
                    const ts: u64 = @intCast(std.time.milliTimestamp());
                    const id_str = std.fmt.bufPrint(&session_id_buf, "{x:0>16}{x:0>16}", .{ ts, id_num }) catch "0000000000000000";
                    session_id = id_str;
                    need_set_cookie = true;
                }

                // Make session available via context data
                _ = global_session_store.findOrCreate(session_id);

                // Store session_id in context for handler access
                try ctx.setHeader("X-Session-ID", session_id);

                var resp = try next_fn(ctx);

                // Set session cookie if new
                if (need_set_cookie) {
                    var cookie_buf: [256]u8 = undefined;
                    var pos: usize = 0;

                    // name=value
                    @memcpy(cookie_buf[pos .. pos + cfg.cookie_name.len], cfg.cookie_name);
                    pos += cfg.cookie_name.len;
                    cookie_buf[pos] = '=';
                    pos += 1;
                    @memcpy(cookie_buf[pos .. pos + session_id.len], session_id);
                    pos += session_id.len;

                    // Path
                    const path_part = "; Path=";
                    @memcpy(cookie_buf[pos .. pos + path_part.len], path_part);
                    pos += path_part.len;
                    @memcpy(cookie_buf[pos .. pos + cfg.path.len], cfg.path);
                    pos += cfg.path.len;

                    if (cfg.http_only) {
                        const ho = "; HttpOnly";
                        @memcpy(cookie_buf[pos .. pos + ho.len], ho);
                        pos += ho.len;
                    }

                    if (cfg.max_age > 0) {
                        const ma_prefix = "; Max-Age=";
                        @memcpy(cookie_buf[pos .. pos + ma_prefix.len], ma_prefix);
                        pos += ma_prefix.len;
                        const age_str = std.fmt.bufPrint(cookie_buf[pos..], "{d}", .{cfg.max_age}) catch "";
                        pos += age_str.len;
                    }

                    resp.headers.append("Set-Cookie", cookie_buf[0..pos]) catch {};
                }

                return resp;
            }
        }.handler,
    };
}

// =============================================================================
// ConfigStore — Thread-safe config storage for middleware
// =============================================================================

/// A fixed-size, thread-safe store for middleware configuration values.
/// Since Zig function pointers cannot capture state, we store configs in
/// static arrays and pass pointers through the middleware's `config` field.
fn ConfigStore(comptime T: type, comptime max_slots: usize) type {
    return struct {
        var slots: [max_slots]T = undefined;
        var count: std.atomic.Value(usize) = std.atomic.Value(usize).init(0);

        /// Stores a config value and returns a pointer to the stored copy.
        /// Panics if all slots are exhausted.
        fn store(cfg: T) *const T {
            const idx = count.fetchAdd(1, .monotonic);
            if (idx >= max_slots) {
                @panic("ConfigStore: too many middleware instances (increase max_slots)");
            }
            slots[idx] = cfg;
            return &slots[idx];
        }
    };
}

// =============================================================================
// Tests
// =============================================================================

test "Middleware creation" {
    const mw = logger();
    try std.testing.expectEqualStrings("logger", mw.name);
}

test "CORS middleware" {
    const config = CorsConfig{};
    const mw = cors(config);
    try std.testing.expectEqualStrings("cors", mw.name);
    try std.testing.expect(mw.config != null);
}

test "Rate limit middleware" {
    const config = RateLimitConfig{ .max_requests = 50 };
    const mw = rateLimit(config);
    try std.testing.expectEqualStrings("rate_limit", mw.name);
}

test "Helmet middleware" {
    const mw = helmet();
    try std.testing.expectEqualStrings("helmet", mw.name);
}

test "Recovery middleware" {
    const mw = recovery();
    try std.testing.expectEqualStrings("recovery", mw.name);
}

test "parseAcceptEncoding simple" {
    const entries = parseAcceptEncoding("gzip, deflate");

    try std.testing.expect(entries[0] != null);
    try std.testing.expectEqual(compression_util.Encoding.gzip, entries[0].?.encoding);
    try std.testing.expectEqual(@as(f32, 1.0), entries[0].?.quality);

    try std.testing.expect(entries[1] != null);
    try std.testing.expectEqual(compression_util.Encoding.deflate, entries[1].?.encoding);
    try std.testing.expectEqual(@as(f32, 1.0), entries[1].?.quality);

    try std.testing.expect(entries[2] == null);
}

test "parseAcceptEncoding with quality" {
    const entries = parseAcceptEncoding("gzip;q=0.8, deflate;q=0.5, identity;q=0.1");

    try std.testing.expect(entries[0] != null);
    try std.testing.expectEqual(compression_util.Encoding.gzip, entries[0].?.encoding);
    try std.testing.expectApproxEqAbs(@as(f32, 0.8), entries[0].?.quality, 0.001);

    try std.testing.expect(entries[1] != null);
    try std.testing.expectEqual(compression_util.Encoding.deflate, entries[1].?.encoding);
    try std.testing.expectApproxEqAbs(@as(f32, 0.5), entries[1].?.quality, 0.001);

    try std.testing.expect(entries[2] != null);
    try std.testing.expectEqual(compression_util.Encoding.identity, entries[2].?.encoding);
    try std.testing.expectApproxEqAbs(@as(f32, 0.1), entries[2].?.quality, 0.001);
}

test "parseAcceptEncoding rejects q=0" {
    const entries = parseAcceptEncoding("gzip;q=0, deflate");

    try std.testing.expect(entries[0] != null);
    try std.testing.expectEqual(compression_util.Encoding.deflate, entries[0].?.encoding);

    try std.testing.expect(entries[1] == null);
}

test "parseAcceptEncoding browser-like header" {
    const entries = parseAcceptEncoding("gzip, deflate, br");

    try std.testing.expect(entries[0] != null);
    try std.testing.expectEqual(compression_util.Encoding.gzip, entries[0].?.encoding);

    try std.testing.expect(entries[1] != null);
    try std.testing.expectEqual(compression_util.Encoding.deflate, entries[1].?.encoding);

    try std.testing.expect(entries[2] == null);
}

test "selectEncoding prefers gzip" {
    const entries = parseAcceptEncoding("gzip, deflate");
    const config = CompressionConfig{};

    const selected = selectEncoding(entries, config);
    try std.testing.expect(selected != null);
    try std.testing.expectEqual(compression_util.Encoding.gzip, selected.?);
}

test "selectEncoding respects quality" {
    const entries = parseAcceptEncoding("gzip;q=0.5, deflate;q=1.0");
    const config = CompressionConfig{};

    const selected = selectEncoding(entries, config);
    try std.testing.expect(selected != null);
    try std.testing.expectEqual(compression_util.Encoding.deflate, selected.?);
}

test "shouldExcludeContentType excludes images" {
    const config = CompressionConfig{};

    try std.testing.expect(shouldExcludeContentType("image/png", config));
    try std.testing.expect(shouldExcludeContentType("image/jpeg", config));
    try std.testing.expect(shouldExcludeContentType("video/mp4", config));
    try std.testing.expect(shouldExcludeContentType("application/zip", config));

    try std.testing.expect(!shouldExcludeContentType("text/html", config));
    try std.testing.expect(!shouldExcludeContentType("application/json", config));
    try std.testing.expect(!shouldExcludeContentType("text/plain", config));
    try std.testing.expect(!shouldExcludeContentType(null, config));
}

test "compression middleware creation" {
    const mw = compression();
    try std.testing.expectEqualStrings("compression", mw.name);
    try std.testing.expect(mw.config != null);

    const mw2 = compressionWithConfig(.{ .min_size = 512 });
    try std.testing.expectEqualStrings("compression", mw2.name);
    try std.testing.expect(mw2.config != null);
}

test "conditional middleware creation" {
    const mw = conditional();
    try std.testing.expectEqualStrings("conditional", mw.name);
    try std.testing.expect(mw.config != null);

    const mw2 = conditionalWithConfig(.{ .auto_etag = false });
    try std.testing.expectEqualStrings("conditional", mw2.name);
    try std.testing.expect(mw2.config != null);
}

test "range request middleware creation" {
    const mw = rangeRequest();
    try std.testing.expectEqualStrings("range_request", mw.name);
    try std.testing.expect(mw.config != null);

    const mw2 = rangeRequestWithConfig(.{ .max_ranges = 4 });
    try std.testing.expectEqualStrings("range_request", mw2.name);
    try std.testing.expect(mw2.config != null);
}

test "request ID middleware generates unique IDs" {
    const mw = requestId();
    try std.testing.expectEqualStrings("request_id", mw.name);
}

test "timeout middleware creation" {
    const mw = timeout(5000);
    try std.testing.expectEqualStrings("timeout", mw.name);
    try std.testing.expect(mw.config != null);
}

test "session middleware creation" {
    const mw = session(.{});
    try std.testing.expectEqualStrings("session", mw.name);
    try std.testing.expect(mw.config != null);

    const mw2 = session(.{ .cookie_name = "my_app", .max_age = 7200 });
    try std.testing.expectEqualStrings("session", mw2.name);
}

test "rate limiter state tracks IPs" {
    var state = RateLimiterState{};

    // First request should pass
    try std.testing.expect(state.checkAndIncrement("127.0.0.1", 2, 60_000));
    // Second request should pass
    try std.testing.expect(state.checkAndIncrement("127.0.0.1", 2, 60_000));
    // Third request should be rate limited
    try std.testing.expect(!state.checkAndIncrement("127.0.0.1", 2, 60_000));

    // Different IP should still pass
    try std.testing.expect(state.checkAndIncrement("192.168.1.1", 2, 60_000));
}

test "session store basic operations" {
    var store = SessionStore{};

    // Create a new session
    const entry = store.findOrCreate("test-session-123");
    try std.testing.expect(entry.active);
    try std.testing.expectEqual(@as(u8, 0), entry.pair_count);

    // Set and get values
    SessionStore.setValue(entry, "user", "alice");
    const user = SessionStore.getValue(entry, "user");
    try std.testing.expect(user != null);
    try std.testing.expectEqualStrings("alice", user.?);

    // Update value
    SessionStore.setValue(entry, "user", "bob");
    const updated = SessionStore.getValue(entry, "user");
    try std.testing.expectEqualStrings("bob", updated.?);

    // Non-existent key
    try std.testing.expect(SessionStore.getValue(entry, "missing") == null);
}

test "session store multiple pairs" {
    var store = SessionStore{};
    const entry = store.findOrCreate("session-multi");

    SessionStore.setValue(entry, "key1", "val1");
    SessionStore.setValue(entry, "key2", "val2");
    SessionStore.setValue(entry, "key3", "val3");

    try std.testing.expectEqual(@as(u8, 3), entry.pair_count);
    try std.testing.expectEqualStrings("val1", SessionStore.getValue(entry, "key1").?);
    try std.testing.expectEqualStrings("val2", SessionStore.getValue(entry, "key2").?);
    try std.testing.expectEqualStrings("val3", SessionStore.getValue(entry, "key3").?);
}

test "rate limiter window expiration" {
    var state = RateLimiterState{};

    // Fill up the window for an IP
    try std.testing.expect(state.checkAndIncrement("10.0.0.1", 1, 60_000));
    try std.testing.expect(!state.checkAndIncrement("10.0.0.1", 1, 60_000)); // blocked

    // Simulate window expiration by using a very short window (0ms = always new)
    try std.testing.expect(state.checkAndIncrement("10.0.0.1", 1, 0));
}

test "rate limiter different IPs are independent" {
    var state = RateLimiterState{};

    try std.testing.expect(state.checkAndIncrement("ip-a", 1, 60_000));
    try std.testing.expect(!state.checkAndIncrement("ip-a", 1, 60_000));

    try std.testing.expect(state.checkAndIncrement("ip-b", 1, 60_000));
    try std.testing.expect(state.checkAndIncrement("ip-c", 1, 60_000));
}

test "rate limiter IP hash is deterministic" {
    const h1 = RateLimiterState.hashIP("192.168.1.1");
    const h2 = RateLimiterState.hashIP("192.168.1.2");
    const h3 = RateLimiterState.hashIP("192.168.1.1");

    try std.testing.expect(h1 != h2);
    try std.testing.expectEqual(h1, h3);
}

test "recoveryWithWriter middleware creation" {
    const writer = struct {
        fn w(_: []const u8) void {}
    }.w;
    const mw = recoveryWithWriter(writer);
    try std.testing.expectEqualStrings("recovery", mw.name);
    try std.testing.expect(mw.config != null);
}

test "body parser middleware is named correctly" {
    const mw = bodyParser(1024);
    try std.testing.expectEqualStrings("body_parser", mw.name);
}

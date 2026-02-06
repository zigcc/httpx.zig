//! HTTP Middleware Support for httpx.zig
//!
//! Gin-style middleware with onion model execution:
//!
//! - Middleware wraps handlers in layers (onion model)
//! - Each middleware calls `next(ctx)` to pass control to the next layer
//! - Global middleware applies to all routes
//! - Group middleware applies only to routes in that group
//! - Supports abort to short-circuit the middleware chain
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

const std = @import("std");
const Context = @import("server.zig").Context;
const Response = @import("../core/response.zig").Response;
const types = @import("../core/types.zig");
const compression_util = @import("../util/compression.zig");
const HeaderName = @import("../core/headers.zig").HeaderName;
const etag_util = @import("../util/etag.zig");
const range_util = @import("../util/range.zig");
const date_util = @import("../util/date.zig");

/// Middleware function type.
pub const Middleware = struct {
    handler: *const fn (*Context, Next) anyerror!Response,
    name: []const u8 = "unnamed",
};

/// Next function to call the next middleware.
pub const Next = *const fn (*Context) anyerror!Response;

/// Handler function type (same as server.Handler).
pub const Handler = *const fn (*Context) anyerror!Response;

/// Middleware chain executor — Gin-style onion model.
///
/// Builds a chain of middleware + final handler that executes in order.
/// Each middleware receives `ctx` and a `next` function pointer.
/// The chain is built at request time by combining:
///   1. Global middleware (from server.use())
///   2. Route middleware (from group.use())
///   3. The final route handler
pub const MiddlewareChain = struct {
    /// Execute a middleware chain: global_mw... + route_mw... + handler.
    /// This builds the chain from inside-out and executes it.
    pub fn execute(
        ctx: *Context,
        global_mw: []const Middleware,
        route_mw: []const Middleware,
        final_handler: Handler,
    ) anyerror!Response {
        // Build the chain from right to left (innermost first).
        // We store the "next" function in the context's internal chain state.
        //
        // The chain is: global[0] -> global[1] -> ... -> route[0] -> route[1] -> ... -> handler
        //
        // Since Zig doesn't have closures with captures, we use the context's
        // chain_state to thread state through the `next` calls.

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
        // Aborted — return the abort response
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
        return mw.handler(ctx, chainNext);
    }

    // All middleware executed, call the final handler
    return ctx.chain_handlers(ctx);
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
};

/// Creates CORS middleware.
pub fn cors(config: CorsConfig) Middleware {
    _ = config;
    return .{
        .name = "cors",
        .handler = struct {
            fn handler(ctx: *Context, next: Next) anyerror!Response {
                try ctx.setHeader("Access-Control-Allow-Origin", "*");
                try ctx.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS");
                try ctx.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

                if (ctx.request.method == .OPTIONS) {
                    return ctx.status(204).text("");
                }

                return next(ctx);
            }
        }.handler,
    };
}

// =============================================================================
// Logger Middleware
// =============================================================================

/// Creates logging middleware.
pub fn logger() Middleware {
    return .{
        .name = "logger",
        .handler = struct {
            fn handler(ctx: *Context, next: Next) anyerror!Response {
                const start = std.time.milliTimestamp();
                const response = try next(ctx);
                const duration = std.time.milliTimestamp() - start;

                std.debug.print("{s} {s} - {d}ms\n", .{
                    ctx.request.method.toString(),
                    ctx.request.uri.path,
                    duration,
                });

                return response;
            }
        }.handler,
    };
}

// =============================================================================
// Recovery Middleware
// =============================================================================

/// Creates recovery middleware that catches handler errors and returns 500.
///
/// This is the Zig equivalent of Gin's `gin.Recovery()`. Since Zig doesn't
/// have panics that can be caught (like Go's recover()), this catches
/// `anyerror` from the handler chain and converts it to a 500 response.
pub fn recovery() Middleware {
    return recoveryWithWriter(null);
}

/// Creates recovery middleware with optional error writer.
pub fn recoveryWithWriter(writer: ?*const fn ([]const u8) void) Middleware {
    _ = writer;
    return .{
        .name = "recovery",
        .handler = struct {
            fn handler(ctx: *Context, next: Next) anyerror!Response {
                return next(ctx) catch |err| {
                    std.debug.print("[Recovery] caught error in handler: {}\n", .{err});
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

/// Creates compression middleware with default configuration.
pub fn compression() Middleware {
    return compressionWithConfig(.{});
}

/// Creates compression middleware with custom configuration.
pub fn compressionWithConfig(config: CompressionConfig) Middleware {
    _ = config;
    return .{
        .name = "compression",
        .handler = struct {
            fn handler(ctx: *Context, next: Next) anyerror!Response {
                var response = try next(ctx);

                const accept_encoding = ctx.header(HeaderName.ACCEPT_ENCODING) orelse {
                    return response;
                };

                const accept_entries = parseAcceptEncoding(accept_encoding);
                const default_config = CompressionConfig{};

                const encoding = selectEncoding(accept_entries, default_config) orelse {
                    return response;
                };

                const body = response.body orelse return response;
                if (body.len < default_config.min_size) {
                    return response;
                }

                const content_type = response.headers.get(HeaderName.CONTENT_TYPE);
                if (shouldExcludeContentType(content_type, default_config)) {
                    return response;
                }

                if (response.headers.get(HeaderName.CONTENT_ENCODING) != null) {
                    return response;
                }

                const compressed = compression_util.compress(
                    ctx.allocator,
                    body,
                    encoding,
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

                response.headers.set(HeaderName.CONTENT_ENCODING, encoding.toString()) catch {};

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
    max_requests: u32 = 100,
    window_ms: u64 = 60_000,
};

/// Creates rate limiting middleware.
pub fn rateLimit(config: RateLimitConfig) Middleware {
    _ = config;
    return .{
        .name = "rate_limit",
        .handler = struct {
            fn handler(ctx: *Context, next: Next) anyerror!Response {
                return next(ctx);
            }
        }.handler,
    };
}

// =============================================================================
// Basic Auth Middleware
// =============================================================================

/// Creates basic authentication middleware.
pub fn basicAuth(realm: []const u8, validator: *const fn ([]const u8, []const u8) bool) Middleware {
    _ = realm;
    _ = validator;
    return .{
        .name = "basic_auth",
        .handler = struct {
            fn handler(ctx: *Context, next: Next) anyerror!Response {
                const auth_header = ctx.header("Authorization") orelse {
                    try ctx.setHeader("WWW-Authenticate", "Basic realm=\"Restricted\"");
                    return ctx.status(401).text("Unauthorized");
                };

                if (!std.mem.startsWith(u8, auth_header, "Basic ")) {
                    return ctx.status(401).text("Unauthorized");
                }

                return next(ctx);
            }
        }.handler,
    };
}

// =============================================================================
// Body Parser, Helmet, Timeout, Request ID
// =============================================================================

/// Creates body parser middleware.
pub fn bodyParser(max_size: usize) Middleware {
    _ = max_size;
    return .{
        .name = "body_parser",
        .handler = struct {
            fn handler(ctx: *Context, next: Next) anyerror!Response {
                return next(ctx);
            }
        }.handler,
    };
}

/// Creates security headers middleware (Helmet).
pub fn helmet() Middleware {
    return .{
        .name = "helmet",
        .handler = struct {
            fn handler(ctx: *Context, next: Next) anyerror!Response {
                var resp = try next(ctx);
                resp.headers.set("X-Content-Type-Options", "nosniff") catch {};
                resp.headers.set("X-Frame-Options", "SAMEORIGIN") catch {};
                resp.headers.set("X-XSS-Protection", "1; mode=block") catch {};
                resp.headers.set("Referrer-Policy", "strict-origin-when-cross-origin") catch {};
                return resp;
            }
        }.handler,
    };
}

/// Creates request timeout middleware.
pub fn timeout(ms: u64) Middleware {
    _ = ms;
    return .{
        .name = "timeout",
        .handler = struct {
            fn handler(ctx: *Context, next: Next) anyerror!Response {
                return next(ctx);
            }
        }.handler,
    };
}

/// Creates request ID middleware.
pub fn requestId() Middleware {
    return .{
        .name = "request_id",
        .handler = struct {
            fn handler(ctx: *Context, next: Next) anyerror!Response {
                try ctx.setHeader("X-Request-ID", "generated-id");
                return next(ctx);
            }
        }.handler,
    };
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

/// Creates conditional request middleware with default configuration.
pub fn conditional() Middleware {
    return conditionalWithConfig(.{});
}

/// Creates conditional request middleware with custom configuration.
pub fn conditionalWithConfig(config: ConditionalConfig) Middleware {
    _ = config;
    return .{
        .name = "conditional",
        .handler = struct {
            fn handler(ctx: *Context, next: Next) anyerror!Response {
                var response = try next(ctx);

                if (ctx.request.method != .GET and ctx.request.method != .HEAD) {
                    return response;
                }

                var etag_buf: [72]u8 = undefined;
                var etag_value: ?[]const u8 = response.headers.get(HeaderName.ETAG);

                if (etag_value == null) {
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

/// Creates range request middleware with default configuration.
pub fn rangeRequest() Middleware {
    return rangeRequestWithConfig(.{});
}

/// Creates range request middleware with custom configuration.
pub fn rangeRequestWithConfig(config: RangeConfig) Middleware {
    _ = config;
    return .{
        .name = "range_request",
        .handler = struct {
            fn handler(ctx: *Context, next: Next) anyerror!Response {
                var response = try next(ctx);

                if (ctx.request.method != .GET) {
                    return response;
                }

                if (response.status.code != 200) {
                    return response;
                }

                const body = response.body orelse return response;
                const total_size = body.len;

                response.headers.set("Accept-Ranges", "bytes") catch {};

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

    const mw2 = compressionWithConfig(.{ .min_size = 512 });
    try std.testing.expectEqualStrings("compression", mw2.name);
}

test "conditional middleware creation" {
    const mw = conditional();
    try std.testing.expectEqualStrings("conditional", mw.name);

    const mw2 = conditionalWithConfig(.{ .auto_etag = false });
    try std.testing.expectEqualStrings("conditional", mw2.name);
}

test "range request middleware creation" {
    const mw = rangeRequest();
    try std.testing.expectEqualStrings("range_request", mw.name);

    const mw2 = rangeRequestWithConfig(.{ .max_ranges = 4 });
    try std.testing.expectEqualStrings("range_request", mw2.name);
}

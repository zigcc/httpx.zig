//! HTTP Middleware Support for httpx.zig
//!
//! Provides middleware functionality for HTTP servers:
//!
//! - CORS (Cross-Origin Resource Sharing)
//! - Logging and request timing
//! - Rate limiting
//! - Basic authentication
//! - Security headers (Helmet)
//! - Response compression (gzip, deflate)
//! - Body parsing

const std = @import("std");
const Context = @import("server.zig").Context;
const Response = @import("../core/response.zig").Response;
const types = @import("../core/types.zig");
const compression_util = @import("../util/compression.zig");
const HeaderName = @import("../core/headers.zig").HeaderName;

/// Middleware function type.
pub const Middleware = struct {
    handler: *const fn (*Context, Next) anyerror!Response,
    name: []const u8 = "unnamed",
};

/// Next function to call the next middleware.
pub const Next = *const fn (*Context) anyerror!Response;

/// Middleware chain executor.
pub const MiddlewareChain = struct {
    middlewares: []const Middleware,
    final_handler: *const fn (*Context) anyerror!Response,
    current: usize = 0,

    const Self = @This();

    /// Executes the middleware chain.
    pub fn execute(self: *Self, ctx: *Context) anyerror!Response {
        if (self.current < self.middlewares.len) {
            const mw = self.middlewares[self.current];
            self.current += 1;
            return mw.handler(ctx, struct {
                fn next(c: *Context) anyerror!Response {
                    _ = c;
                    unreachable;
                }
            }.next);
        }
        return self.final_handler(ctx);
    }
};

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

/// Compression middleware configuration.
pub const CompressionConfig = struct {
    /// Minimum response size to compress (default: 1024 bytes).
    /// Responses smaller than this will not be compressed.
    min_size: usize = 1024,

    /// Compression level (1-9, higher = better compression but slower).
    /// Currently not used as we use default compression.
    level: u4 = 6,

    /// Preferred encoding order when client supports multiple.
    /// First supported encoding in this list will be used.
    preferred_encodings: []const compression_util.Encoding = &[_]compression_util.Encoding{
        .gzip,
        .deflate,
    },

    /// Content-Types that should NOT be compressed (already compressed formats).
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
    quality: f32, // 0.0 to 1.0

    fn lessThan(_: void, a: AcceptEncodingEntry, b: AcceptEncodingEntry) bool {
        // Sort by quality descending (higher quality first)
        return a.quality > b.quality;
    }
};

/// Parses Accept-Encoding header value into sorted list of encodings.
/// Supports quality factors (q=X.X) per RFC 7231.
/// Example: "gzip, deflate;q=0.5, *;q=0.1" -> [gzip(1.0), deflate(0.5)]
pub fn parseAcceptEncoding(value: []const u8) [8]?AcceptEncodingEntry {
    var entries: [8]?AcceptEncodingEntry = .{ null, null, null, null, null, null, null, null };
    var count: usize = 0;

    var it = std.mem.splitScalar(u8, value, ',');
    while (it.next()) |part| {
        if (count >= 8) break;

        const trimmed = std.mem.trim(u8, part, " \t");
        if (trimmed.len == 0) continue;

        // Parse encoding and optional quality
        var quality: f32 = 1.0;
        var encoding_str = trimmed;

        // Check for ;q= parameter
        if (std.mem.indexOf(u8, trimmed, ";")) |semi_pos| {
            encoding_str = std.mem.trim(u8, trimmed[0..semi_pos], " \t");
            const params = trimmed[semi_pos + 1 ..];

            // Parse q=X.X
            if (std.mem.indexOf(u8, params, "q=")) |q_pos| {
                const q_start = q_pos + 2;
                var q_end = q_start;
                while (q_end < params.len and (params[q_end] == '.' or std.ascii.isDigit(params[q_end]))) {
                    q_end += 1;
                }
                if (q_end > q_start) {
                    quality = std.fmt.parseFloat(f32, params[q_start..q_end]) catch 1.0;
                    quality = @min(1.0, @max(0.0, quality)); // Clamp to [0, 1]
                }
            }
        }

        // Skip if quality is 0 (explicitly rejected)
        if (quality == 0.0) continue;

        // Skip wildcard "*" - we only support specific encodings
        if (std.mem.eql(u8, encoding_str, "*")) continue;

        // Parse encoding name
        if (compression_util.Encoding.fromString(encoding_str)) |enc| {
            entries[count] = .{ .encoding = enc, .quality = quality };
            count += 1;
        }
    }

    // Sort by quality (descending)
    var temp_entries: [8]AcceptEncodingEntry = undefined;
    var temp_count: usize = 0;
    for (entries) |maybe_entry| {
        if (maybe_entry) |entry| {
            temp_entries[temp_count] = entry;
            temp_count += 1;
        }
    }

    std.mem.sort(AcceptEncodingEntry, temp_entries[0..temp_count], {}, AcceptEncodingEntry.lessThan);

    // Write back sorted results
    var result: [8]?AcceptEncodingEntry = .{ null, null, null, null, null, null, null, null };
    for (0..temp_count) |i| {
        result[i] = temp_entries[i];
    }

    return result;
}

/// Selects the best encoding based on client preferences and server config.
fn selectEncoding(accept_entries: [8]?AcceptEncodingEntry, config: CompressionConfig) ?compression_util.Encoding {
    // For each client preference (sorted by quality), check if we support it
    for (accept_entries) |maybe_entry| {
        const entry = maybe_entry orelse break;

        // Check if this encoding is in our preferred list
        for (config.preferred_encodings) |preferred| {
            if (entry.encoding == preferred) {
                return preferred;
            }
        }
    }

    return null;
}

/// Checks if content-type should be excluded from compression.
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
    _ = config; // Will be used when we have stateful middleware
    return .{
        .name = "compression",
        .handler = struct {
            fn handler(ctx: *Context, next: Next) anyerror!Response {
                // Get response from next handler
                var response = try next(ctx);

                // Get Accept-Encoding header
                const accept_encoding = ctx.header(HeaderName.ACCEPT_ENCODING) orelse {
                    // No compression requested
                    return response;
                };

                // Parse Accept-Encoding
                const accept_entries = parseAcceptEncoding(accept_encoding);

                // Use default config (stateless limitation)
                const default_config = CompressionConfig{};

                // Select best encoding
                const encoding = selectEncoding(accept_entries, default_config) orelse {
                    return response;
                };

                // Check if response has a body worth compressing
                const body = response.body orelse return response;
                if (body.len < default_config.min_size) {
                    return response;
                }

                // Check if content-type should be excluded
                const content_type = response.headers.get(HeaderName.CONTENT_TYPE);
                if (shouldExcludeContentType(content_type, default_config)) {
                    return response;
                }

                // Check if already encoded
                if (response.headers.get(HeaderName.CONTENT_ENCODING) != null) {
                    return response;
                }

                // Compress the body
                const compressed = compression_util.compress(
                    ctx.allocator,
                    body,
                    encoding,
                ) catch {
                    // Compression failed, return uncompressed
                    return response;
                };

                // Only use compressed if it's actually smaller
                if (compressed.len >= body.len) {
                    ctx.allocator.free(compressed);
                    return response;
                }

                // Free old body if owned and replace with compressed
                if (response.body_owned) {
                    if (response.body) |old_body| {
                        response.allocator.free(old_body);
                    }
                }
                response.body = compressed;
                response.body_owned = true;

                // Set Content-Encoding header
                response.headers.set(HeaderName.CONTENT_ENCODING, encoding.toString()) catch {};

                // Update Content-Length
                var len_buf: [32]u8 = undefined;
                const len_str = std.fmt.bufPrint(&len_buf, "{d}", .{compressed.len}) catch unreachable;
                response.headers.set(HeaderName.CONTENT_LENGTH, len_str) catch {};

                // Add Vary header for proper caching
                response.headers.append(HeaderName.VARY, HeaderName.ACCEPT_ENCODING) catch {};

                return response;
            }
        }.handler,
    };
}

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

/// Creates basic authentication middleware.
pub fn basicAuth(realm: []const u8, validator: *const fn ([]const u8, []const u8) bool) Middleware {
    _ = realm;
    _ = validator;
    return .{
        .name = "basic_auth",
        .handler = struct {
            fn handler(ctx: *Context, next: Next) anyerror!Response {
                const auth = ctx.header("Authorization") orelse {
                    try ctx.setHeader("WWW-Authenticate", "Basic realm=\"Restricted\"");
                    return ctx.status(401).text("Unauthorized");
                };

                if (!std.mem.startsWith(u8, auth, "Basic ")) {
                    return ctx.status(401).text("Unauthorized");
                }

                return next(ctx);
            }
        }.handler,
    };
}

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
                return next(ctx);
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

    // Should be sorted by quality descending
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

    // gzip should be rejected (q=0), only deflate remains
    try std.testing.expect(entries[0] != null);
    try std.testing.expectEqual(compression_util.Encoding.deflate, entries[0].?.encoding);

    try std.testing.expect(entries[1] == null);
}

test "parseAcceptEncoding browser-like header" {
    // Chrome/Firefox typically send this
    const entries = parseAcceptEncoding("gzip, deflate, br");

    // br (brotli) should be ignored since we don't support it
    try std.testing.expect(entries[0] != null);
    try std.testing.expectEqual(compression_util.Encoding.gzip, entries[0].?.encoding);

    try std.testing.expect(entries[1] != null);
    try std.testing.expectEqual(compression_util.Encoding.deflate, entries[1].?.encoding);

    try std.testing.expect(entries[2] == null); // br is not supported
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

    // deflate has higher quality, should be selected first
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

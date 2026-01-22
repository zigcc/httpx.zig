//! Core HTTP Types for httpx.zig
//!
//! This module provides fundamental HTTP type definitions including methods,
//! protocol versions (HTTP/1.0, HTTP/1.1, HTTP/2, HTTP/3), error types,
//! content types, and configuration structures for timeouts, retries, and redirects.
//!
//! All types are designed for zero-allocation operation where possible and
//! provide compile-time string conversion for maximum performance.

const std = @import("std");

/// HTTP request methods as defined in RFC 7231 and RFC 5789.
/// Supports all standard methods plus a CUSTOM variant for extensions.
pub const Method = enum {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    HEAD,
    OPTIONS,
    TRACE,
    CONNECT,
    CUSTOM,
    // NOTE: in the production code, we should not enable trace

    /// Converts the method to its canonical string representation.
    pub fn toString(self: Method) []const u8 {
        return switch (self) {
            .GET => "GET",
            .POST => "POST",
            .PUT => "PUT",
            .DELETE => "DELETE",
            .PATCH => "PATCH",
            .HEAD => "HEAD",
            .OPTIONS => "OPTIONS",
            .TRACE => "TRACE",
            .CONNECT => "CONNECT",
            .CUSTOM => "CUSTOM",
        };
    }

    const methods = [_]struct { name: []const u8, method: Method }{
        .{ .name = "GET", .method = .GET },
        .{ .name = "POST", .method = .POST },
        .{ .name = "PUT", .method = .PUT },
        .{ .name = "DELETE", .method = .DELETE },
        .{ .name = "PATCH", .method = .PATCH },
        .{ .name = "HEAD", .method = .HEAD },
        .{ .name = "OPTIONS", .method = .OPTIONS },
        .{ .name = "TRACE", .method = .TRACE },
        .{ .name = "CONNECT", .method = .CONNECT },
    };

    /// Parses a string into a Method enum value.
    /// Returns null for unrecognized method strings.
    pub fn fromString(str: []const u8) ?Method {
        inline for (methods) |m| {
            if (std.mem.eql(u8, str, m.name)) return m.method;
        }
        return null;
    }

    /// Returns true if the method is idempotent per RFC 7231.
    /// Idempotent methods can be safely retried without side effects.
    pub fn isIdempotent(self: Method) bool {
        return switch (self) {
            .GET, .HEAD, .PUT, .DELETE, .OPTIONS, .TRACE => true,
            .POST, .PATCH, .CONNECT, .CUSTOM => false,
        };
    }

    /// Returns true if the method is considered safe per RFC 7231.
    /// Safe methods should not cause side effects on the server.
    pub fn isSafe(self: Method) bool {
        return switch (self) {
            .GET, .HEAD, .OPTIONS, .TRACE => true,
            else => false,
        };
    }

    /// Returns true if the method typically includes a request body.
    pub fn hasRequestBody(self: Method) bool {
        return switch (self) {
            .POST, .PUT, .PATCH => true,
            else => false,
        };
    }

    /// Returns true if the method expects a response body.
    pub fn hasResponseBody(self: Method) bool {
        return switch (self) {
            .HEAD => false,
            else => true,
        };
    }
};

/// HTTP protocol versions including HTTP/2 and HTTP/3 (QUIC).
pub const Version = enum {
    HTTP_1_0,
    HTTP_1_1,
    HTTP_2,
    HTTP_3,

    /// Returns the canonical string representation of the version.
    pub fn toString(self: Version) []const u8 {
        return switch (self) {
            .HTTP_1_0 => "HTTP/1.0",
            .HTTP_1_1 => "HTTP/1.1",
            .HTTP_2 => "HTTP/2",
            .HTTP_3 => "HTTP/3",
        };
    }

    /// Parses a version string into a Version enum.
    pub fn fromString(str: []const u8) ?Version {
        if (std.mem.eql(u8, str, "HTTP/1.0")) return .HTTP_1_0;
        if (std.mem.eql(u8, str, "HTTP/1.1")) return .HTTP_1_1;
        if (std.mem.eql(u8, str, "HTTP/2") or std.mem.eql(u8, str, "HTTP/2.0")) return .HTTP_2;
        if (std.mem.eql(u8, str, "HTTP/3") or std.mem.eql(u8, str, "HTTP/3.0")) return .HTTP_3;
        return null;
    }

    /// Returns true if the version supports multiplexing.
    pub fn supportsMultiplexing(self: Version) bool {
        return self == .HTTP_2 or self == .HTTP_3;
    }

    /// Returns true if the version supports server push.
    /// Note: HTTP/3 spec includes server push but major browsers disabled it.
    pub fn supportsServerPush(self: Version) bool {
        return self == .HTTP_2;
    }

    /// Returns true if the version uses QUIC transport.
    pub fn usesQuic(self: Version) bool {
        return self == .HTTP_3;
    }

    /// Returns true if the version requires TLS by specification.
    pub fn requiresTls(self: Version) bool {
        return self == .HTTP_2 or self == .HTTP_3;
    }
};

/// HTTP error types with context information for debugging.
/// Organized by category for clarity.
pub const HttpError = error{
    // ===== Connection Errors =====
    /// Failed to establish connection to the server.
    ConnectionFailed,
    /// Connection was reset by the peer (TCP RST).
    ConnectionReset,
    /// Connection was closed gracefully by the peer.
    ConnectionClosed,
    /// Connection attempt timed out.
    ConnectionTimeout,
    /// Target host is unreachable (network/routing issue).
    HostUnreachable,
    /// DNS lookup failed to resolve hostname.
    DnsResolutionFailed,

    // ===== URI/URL Errors =====
    /// Malformed or invalid URI format.
    InvalidUri,
    /// URI scheme not supported (e.g., ftp://).
    UnsupportedScheme,

    // ===== TLS/SSL Errors =====
    /// TLS handshake failed.
    TlsHandshakeFailed,
    /// TLS certificate validation failed.
    TlsCertificateError,
    /// General TLS protocol error.
    TlsError,

    // ===== HTTP Parsing Errors =====
    /// Malformed HTTP response.
    InvalidResponse,
    /// Malformed HTTP header.
    InvalidHeader,
    /// Single header exceeds maximum allowed size.
    HeaderTooLarge,
    /// Too many headers in the message.
    TooManyHeaders,
    /// Invalid chunk size in chunked transfer encoding.
    InvalidChunkSize,
    /// Invalid chunk encoding format.
    InvalidChunkEncoding,

    // ===== Request/Response Limits =====
    /// Response body exceeds maximum allowed size.
    ResponseTooLarge,
    /// Request body exceeds maximum allowed size.
    RequestTooLarge,
    /// Exceeded maximum number of redirects.
    TooManyRedirects,
    /// Operation timed out.
    Timeout,

    // ===== Protocol Errors =====
    /// General HTTP protocol violation.
    ProtocolError,
    /// Stream-level error (HTTP/2, HTTP/3).
    StreamError,
    /// Flow control violation (HTTP/2, HTTP/3).
    FlowControlError,
    /// Invalid frame format (HTTP/2, HTTP/3).
    FrameError,
    /// Header compression error (HPACK/QPACK).
    CompressionError,
    /// HTTP/2 specific protocol error.
    Http2Error,
    /// HTTP/3 specific protocol error.
    Http3Error,
    /// QUIC transport layer error.
    QuicError,

    // ===== Proxy Errors =====
    /// Proxy connection or communication failed.
    ProxyError,
    /// Proxy authentication required or failed.
    ProxyAuthenticationRequired,

    // ===== WebSocket Errors =====
    /// WebSocket handshake failed.
    HandshakeFailed,
    /// WebSocket connection is not open.
    ConnectionNotOpen,

    // ===== Resource Errors =====
    /// Memory allocation failed.
    OutOfMemory,
    /// Buffer too small for operation.
    BufferTooSmall,
    /// Unexpected end of stream/data.
    UnexpectedEof,
};

/// Common MIME content types for HTTP messages.
pub const ContentType = enum {
    // Text types
    text_plain,
    text_html,
    text_css,
    text_javascript,
    text_xml,
    text_csv,
    text_markdown,

    // Application types
    application_json,
    application_xml,
    application_octet_stream,
    application_form_urlencoded,
    application_pdf,
    application_zip,
    application_gzip,

    // Multipart types
    multipart_form_data,

    // Image types
    image_png,
    image_jpeg,
    image_gif,
    image_webp,
    image_svg,

    // Video types
    video_mp4,
    video_webm,

    // Audio types
    audio_mpeg,
    audio_wav,

    // Font types
    font_woff,
    font_woff2,

    /// Returns the MIME type string.
    pub fn toString(self: ContentType) []const u8 {
        return switch (self) {
            // Text types
            .text_plain => "text/plain",
            .text_html => "text/html",
            .text_css => "text/css",
            .text_javascript => "text/javascript",
            .text_xml => "text/xml",
            .text_csv => "text/csv",
            .text_markdown => "text/markdown",

            // Application types
            .application_json => "application/json",
            .application_xml => "application/xml",
            .application_octet_stream => "application/octet-stream",
            .application_form_urlencoded => "application/x-www-form-urlencoded",
            .application_pdf => "application/pdf",
            .application_zip => "application/zip",
            .application_gzip => "application/gzip",

            // Multipart types
            .multipart_form_data => "multipart/form-data",

            // Image types
            .image_png => "image/png",
            .image_jpeg => "image/jpeg",
            .image_gif => "image/gif",
            .image_webp => "image/webp",
            .image_svg => "image/svg+xml",

            // Video types
            .video_mp4 => "video/mp4",
            .video_webm => "video/webm",

            // Audio types
            .audio_mpeg => "audio/mpeg",
            .audio_wav => "audio/wav",

            // Font types
            .font_woff => "font/woff",
            .font_woff2 => "font/woff2",
        };
    }

    /// Parses a MIME type string into a ContentType enum.
    pub fn fromString(str: []const u8) ?ContentType {
        const types = [_]struct { name: []const u8, ct: ContentType }{
            // Text types
            .{ .name = "text/plain", .ct = .text_plain },
            .{ .name = "text/html", .ct = .text_html },
            .{ .name = "text/css", .ct = .text_css },
            .{ .name = "text/javascript", .ct = .text_javascript },
            .{ .name = "text/xml", .ct = .text_xml },
            .{ .name = "text/csv", .ct = .text_csv },
            .{ .name = "text/markdown", .ct = .text_markdown },

            // Application types
            .{ .name = "application/json", .ct = .application_json },
            .{ .name = "application/xml", .ct = .application_xml },
            .{ .name = "application/octet-stream", .ct = .application_octet_stream },
            .{ .name = "application/x-www-form-urlencoded", .ct = .application_form_urlencoded },
            .{ .name = "application/pdf", .ct = .application_pdf },
            .{ .name = "application/zip", .ct = .application_zip },
            .{ .name = "application/gzip", .ct = .application_gzip },

            // Multipart types
            .{ .name = "multipart/form-data", .ct = .multipart_form_data },

            // Image types
            .{ .name = "image/png", .ct = .image_png },
            .{ .name = "image/jpeg", .ct = .image_jpeg },
            .{ .name = "image/gif", .ct = .image_gif },
            .{ .name = "image/webp", .ct = .image_webp },
            .{ .name = "image/svg+xml", .ct = .image_svg },

            // Video types
            .{ .name = "video/mp4", .ct = .video_mp4 },
            .{ .name = "video/webm", .ct = .video_webm },

            // Audio types
            .{ .name = "audio/mpeg", .ct = .audio_mpeg },
            .{ .name = "audio/wav", .ct = .audio_wav },

            // Font types
            .{ .name = "font/woff", .ct = .font_woff },
            .{ .name = "font/woff2", .ct = .font_woff2 },
        };
        for (types) |t| {
            if (std.mem.startsWith(u8, str, t.name)) return t.ct;
        }
        return null;
    }
};

/// Transfer-Encoding header values (RFC 7230 Section 4).
/// Used for hop-by-hop transfer codings applied during message transfer.
pub const TransferEncoding = enum {
    /// No transformation (deprecated in HTTP/1.1).
    identity,
    /// Chunked transfer coding - data sent in chunks.
    chunked,
    /// Gzip compression.
    gzip,
    /// Deflate compression.
    deflate,
    /// LZW compression (rarely used).
    compress,

    pub fn toString(self: TransferEncoding) []const u8 {
        return switch (self) {
            .identity => "identity",
            .chunked => "chunked",
            .gzip => "gzip",
            .deflate => "deflate",
            .compress => "compress",
        };
    }

    pub fn fromString(str: []const u8) ?TransferEncoding {
        if (std.mem.eql(u8, str, "identity")) return .identity;
        if (std.mem.eql(u8, str, "chunked")) return .chunked;
        if (std.mem.eql(u8, str, "gzip")) return .gzip;
        if (std.mem.eql(u8, str, "deflate")) return .deflate;
        if (std.mem.eql(u8, str, "compress")) return .compress;
        return null;
    }
};

/// Content-Encoding header values (RFC 7231, RFC 7932, RFC 8878).
/// Used for end-to-end content codings applied to the message payload.
pub const ContentEncoding = enum {
    /// No transformation.
    identity,
    /// Gzip compression (RFC 1952).
    gzip,
    /// Deflate compression (RFC 1951).
    deflate,
    /// Brotli compression (RFC 7932).
    br,
    /// LZW compression (rarely used).
    compress,
    /// Zstandard compression (RFC 8878).
    zstd,

    pub fn toString(self: ContentEncoding) []const u8 {
        return switch (self) {
            .identity => "identity",
            .gzip => "gzip",
            .deflate => "deflate",
            .br => "br",
            .compress => "compress",
            .zstd => "zstd",
        };
    }

    pub fn fromString(str: []const u8) ?ContentEncoding {
        if (std.mem.eql(u8, str, "identity")) return .identity;
        if (std.mem.eql(u8, str, "gzip")) return .gzip;
        if (std.mem.eql(u8, str, "deflate")) return .deflate;
        if (std.mem.eql(u8, str, "br")) return .br;
        if (std.mem.eql(u8, str, "compress")) return .compress;
        if (std.mem.eql(u8, str, "zstd")) return .zstd;
        return null;
    }
};

/// Timeout configuration for HTTP operations in milliseconds.
pub const Timeouts = struct {
    connect_ms: u64 = 30_000,
    read_ms: u64 = 30_000,
    write_ms: u64 = 30_000,
    keep_alive_ms: u64 = 60_000,
    idle_ms: u64 = 120_000,
    request_ms: u64 = 0,

    /// Creates a timeout configuration with all values set uniformly.
    pub fn uniform(ms: u64) Timeouts {
        return .{
            .connect_ms = ms,
            .read_ms = ms,
            .write_ms = ms,
            .keep_alive_ms = ms * 2,
            .idle_ms = ms * 4,
        };
    }

    /// Creates timeouts optimized for fast operations.
    pub fn fast() Timeouts {
        return uniform(5_000);
    }

    /// Creates timeouts for long-running operations.
    pub fn slow() Timeouts {
        return uniform(120_000);
    }

    /// Disables all timeouts (use with caution).
    pub fn none() Timeouts {
        return .{
            .connect_ms = 0,
            .read_ms = 0,
            .write_ms = 0,
            .keep_alive_ms = 0,
            .idle_ms = 0,
        };
    }
};

/// Retry policy configuration with exponential backoff support.
pub const RetryPolicy = struct {
    max_retries: u32 = 3,
    initial_delay_ms: u64 = 1000,
    max_delay_ms: u64 = 30_000,
    backoff_multiplier: f64 = 2.0,
    retry_on_status: []const u16 = &[_]u16{ 429, 500, 502, 503, 504 },
    retry_on_connection_error: bool = true,
    retry_only_idempotent: bool = true,

    /// Calculates the delay for a given retry attempt using exponential backoff.
    pub fn calculateDelay(self: RetryPolicy, attempt: u32) u64 {
        if (attempt == 0) return 0;
        const multiplier = std.math.pow(f64, self.backoff_multiplier, @as(f64, @floatFromInt(attempt - 1)));
        const delay = @as(u64, @intFromFloat(@as(f64, @floatFromInt(self.initial_delay_ms)) * multiplier));
        return @min(delay, self.max_delay_ms);
    }

    /// Returns true if the given status code should trigger a retry.
    pub fn shouldRetryStatus(self: RetryPolicy, status: u16) bool {
        for (self.retry_on_status) |s| {
            if (s == status) return true;
        }
        return false;
    }

    /// Creates a policy that never retries.
    pub fn noRetry() RetryPolicy {
        return .{ .max_retries = 0 };
    }

    /// Creates an aggressive retry policy for critical requests.
    pub fn aggressive() RetryPolicy {
        return .{
            .max_retries = 5,
            .initial_delay_ms = 500,
            .backoff_multiplier = 1.5,
        };
    }
};

/// Redirect policy configuration for HTTP clients.
pub const RedirectPolicy = struct {
    max_redirects: u32 = 10,
    follow_redirects: bool = true,
    preserve_method: bool = false,
    preserve_headers: bool = true,
    allow_cross_origin: bool = true,

    /// Returns the appropriate method to use after a redirect.
    pub fn getRedirectMethod(self: RedirectPolicy, status: u16, original: Method) Method {
        if (self.preserve_method) return original;
        return switch (status) {
            301, 302 => .GET,
            303 => .GET,
            307, 308 => original,
            else => original,
        };
    }

    /// Creates a policy that doesn't follow redirects.
    pub fn noFollow() RedirectPolicy {
        return .{ .follow_redirects = false };
    }

    /// Creates a strict policy that preserves method on redirects.
    pub fn strict() RedirectPolicy {
        return .{ .preserve_method = true };
    }
};

/// HTTP/2 specific settings as defined in RFC 7540.
pub const Http2Settings = struct {
    header_table_size: u32 = 4096,
    enable_push: bool = true,
    max_concurrent_streams: u32 = 100,
    initial_window_size: u32 = 65535,
    max_frame_size: u32 = 16384,
    max_header_list_size: u32 = 8192,
};

/// HTTP/3 and QUIC specific settings.
pub const Http3Settings = struct {
    max_field_section_size: u64 = 8192,
    qpack_max_table_capacity: u64 = 4096,
    qpack_blocked_streams: u64 = 100,
    enable_connect_protocol: bool = true,
    enable_datagrams: bool = false,
};

test "Method.fromString" {
    try std.testing.expectEqual(Method.GET, Method.fromString("GET").?);
    try std.testing.expectEqual(Method.POST, Method.fromString("POST").?);
    try std.testing.expect(Method.fromString("INVALID") == null);
}

test "Method properties" {
    try std.testing.expect(Method.GET.isIdempotent());
    try std.testing.expect(Method.GET.isSafe());
    try std.testing.expect(!Method.POST.isIdempotent());
    try std.testing.expect(Method.POST.hasRequestBody());
}

test "Version.fromString" {
    try std.testing.expectEqual(Version.HTTP_1_1, Version.fromString("HTTP/1.1").?);
    try std.testing.expectEqual(Version.HTTP_2, Version.fromString("HTTP/2").?);
    try std.testing.expectEqual(Version.HTTP_3, Version.fromString("HTTP/3").?);
}

test "Version properties" {
    try std.testing.expect(Version.HTTP_2.supportsMultiplexing());
    try std.testing.expect(Version.HTTP_3.usesQuic());
    try std.testing.expect(!Version.HTTP_1_1.supportsMultiplexing());
}

test "ContentType.fromString" {
    try std.testing.expectEqual(ContentType.application_json, ContentType.fromString("application/json").?);
    try std.testing.expectEqual(ContentType.text_html, ContentType.fromString("text/html; charset=utf-8").?);
}

test "RetryPolicy.calculateDelay" {
    const policy = RetryPolicy{};
    try std.testing.expectEqual(@as(u64, 0), policy.calculateDelay(0));
    try std.testing.expectEqual(@as(u64, 1000), policy.calculateDelay(1));
    try std.testing.expectEqual(@as(u64, 2000), policy.calculateDelay(2));
}

test "RedirectPolicy.getRedirectMethod" {
    const policy = RedirectPolicy{};
    try std.testing.expectEqual(Method.GET, policy.getRedirectMethod(301, .POST));
    try std.testing.expectEqual(Method.POST, policy.getRedirectMethod(307, .POST));
}

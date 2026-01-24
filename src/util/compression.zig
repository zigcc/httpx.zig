//! HTTP Content-Encoding Compression/Decompression for httpx.zig
//!
//! Provides automatic content encoding handling as specified in RFC 7231.
//! Supports gzip, deflate, and identity encodings.
//!
//! ## Supported Encodings
//! - `gzip`: RFC 1952 gzip compression/decompression
//! - `deflate`: RFC 1951 deflate/zlib compression/decompression
//! - `identity`: No transformation (passthrough)
//!
//! ## Implementation Notes
//! - Decompression uses Zig's std.compress.flate.Decompress
//! - Compression uses a custom pure-Zig DEFLATE implementation (deflate_encoder.zig)
//!   since Zig 0.15's std.compress.flate.Compress is incomplete.
//!
//! ## Usage
//! ```zig
//! const compression = @import("util/compression.zig");
//!
//! // Decompress response body
//! const decompressed = try compression.decompress(allocator, compressed_data, .gzip);
//! defer allocator.free(decompressed);
//!
//! // Compress request body
//! const compressed = try compression.compress(allocator, data, .gzip);
//! defer allocator.free(compressed);
//! ```

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const flate = std.compress.flate;
const Decompress = flate.Decompress;
const Container = flate.Container;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

// Custom DEFLATE encoder (pure Zig implementation)
const deflate_encoder = @import("deflate_encoder.zig");

/// Content-Encoding types as specified in RFC 7231.
pub const Encoding = enum {
    identity,
    gzip,
    deflate,
    // Note: brotli (br) requires external library, not in std

    pub fn fromString(str: []const u8) ?Encoding {
        if (str.len > 32) return null;
        if (std.ascii.eqlIgnoreCase(str, "gzip") or std.ascii.eqlIgnoreCase(str, "x-gzip")) return .gzip;
        if (std.ascii.eqlIgnoreCase(str, "deflate")) return .deflate;
        if (std.ascii.eqlIgnoreCase(str, "identity")) return .identity;
        return null;
    }

    pub fn toString(self: Encoding) []const u8 {
        return switch (self) {
            .identity => "identity",
            .gzip => "gzip",
            .deflate => "deflate",
        };
    }

    fn toContainer(self: Encoding) Container {
        return switch (self) {
            .identity => .raw,
            .gzip => .gzip,
            .deflate => .zlib,
        };
    }
};

/// Compression error types.
pub const CompressionError = error{
    InvalidData,
    DataCorrupted,
    UnsupportedEncoding,
    OutOfMemory,
    StreamEnd,
};

/// Decompresses data based on the specified encoding.
/// Returns owned slice that must be freed by the caller.
pub fn decompress(allocator: Allocator, data: []const u8, encoding: Encoding) CompressionError![]u8 {
    return switch (encoding) {
        .identity => allocator.dupe(u8, data) catch return CompressionError.OutOfMemory,
        .gzip => decompressWithContainer(allocator, data, .gzip),
        .deflate => decompressDeflate(allocator, data),
    };
}

/// Compresses data using the specified encoding.
/// Returns owned slice that must be freed by the caller.
///
/// Uses a custom pure-Zig DEFLATE implementation since Zig 0.15's
/// std.compress.flate.Compress is incomplete.
pub fn compress(allocator: Allocator, data: []const u8, encoding: Encoding) CompressionError![]u8 {
    return switch (encoding) {
        .identity => allocator.dupe(u8, data) catch return CompressionError.OutOfMemory,
        .gzip => deflate_encoder.compressGzip(allocator, data) catch return CompressionError.DataCorrupted,
        .deflate => deflate_encoder.compressZlib(allocator, data) catch return CompressionError.DataCorrupted,
    };
}

/// Decompresses data using the specified container format.
fn decompressWithContainer(allocator: Allocator, data: []const u8, container: Container) CompressionError![]u8 {
    var input: Reader = .fixed(data);
    var output: Writer.Allocating = .init(allocator);
    errdefer output.deinit();

    var decompressor: Decompress = .init(&input, container, &.{});

    _ = decompressor.reader.streamRemaining(&output.writer) catch {
        // Check for specific decompression error
        if (decompressor.err) |_| {
            return CompressionError.DataCorrupted;
        }
        return CompressionError.InvalidData;
    };

    const result = output.written();
    // Transfer ownership - we need to copy since Allocating doesn't have toOwnedSlice
    const owned = allocator.dupe(u8, result) catch return CompressionError.OutOfMemory;
    output.deinit();
    return owned;
}

/// Decompresses deflate/zlib-encoded data.
/// Tries zlib format first, then falls back to raw deflate.
fn decompressDeflate(allocator: Allocator, data: []const u8) CompressionError![]u8 {
    if (data.len < 2) return CompressionError.InvalidData;

    // Check for zlib wrapper (CMF/FLG bytes)
    const cmf = data[0];
    const flg = data[1];

    // Zlib check: ((CMF * 256 + FLG) % 31 == 0) and CMF & 0x0F == 8
    const is_zlib = (((@as(u16, cmf) << 8) | flg) % 31 == 0) and ((cmf & 0x0F) == 8);

    if (is_zlib) {
        return decompressWithContainer(allocator, data, .zlib);
    }

    // Try raw deflate
    return decompressWithContainer(allocator, data, .raw);
}

// Compression is implemented in deflate_encoder.zig using a custom pure-Zig
// DEFLATE implementation, since Zig 0.15's std.compress.flate.Compress is incomplete.

/// Auto-detects encoding from Content-Encoding header value and decompresses.
pub fn decompressAuto(allocator: Allocator, data: []const u8, content_encoding: ?[]const u8) CompressionError![]u8 {
    const enc_str = content_encoding orelse return allocator.dupe(u8, data) catch return CompressionError.OutOfMemory;

    // Handle multiple encodings (comma-separated, applied in reverse order)
    var it = mem.splitScalar(u8, enc_str, ',');
    var encodings: [8]Encoding = undefined;
    var count: usize = 0;

    while (it.next()) |part| {
        const trimmed = mem.trim(u8, part, " \t");
        if (trimmed.len == 0) continue;
        const enc = Encoding.fromString(trimmed) orelse return CompressionError.UnsupportedEncoding;
        if (count >= encodings.len) return CompressionError.UnsupportedEncoding;
        encodings[count] = enc;
        count += 1;
    }

    if (count == 0) {
        return allocator.dupe(u8, data) catch return CompressionError.OutOfMemory;
    }

    // Apply decompression in reverse order
    var current = allocator.dupe(u8, data) catch return CompressionError.OutOfMemory;
    errdefer allocator.free(current);

    var i: usize = count;
    while (i > 0) {
        i -= 1;
        const next = try decompress(allocator, current, encodings[i]);
        allocator.free(current);
        current = next;
    }

    return current;
}

/// Returns the Accept-Encoding header value for supported encodings.
pub fn acceptEncodingHeader() []const u8 {
    return "gzip, deflate, identity";
}

// =============================================================================
// Tests
// =============================================================================

// Pre-compressed test data (generated externally since Zig 0.15 lacks compression)
// "Hello, World!" gzip compressed
const gzip_hello_world = [_]u8{
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, // gzip header
    0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0xd7, 0x51, 0x08, 0xcf, 0x2f, // deflate data
    0xca, 0x49, 0x51, 0x04, 0x00, 0xd0, 0xc3, 0x4a, 0xd9, 0x0d, // + crc32 + size
    0x00, 0x00, 0x00,
};
const gzip_hello_world_plain = "Hello, World!";

// "Hello, World!" zlib compressed
const zlib_hello_world = [_]u8{
    0x78, 0x9c, // zlib header (deflate, default compression)
    0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0xd7, 0x51, 0x08, 0xcf, 0x2f, // deflate data
    0xca, 0x49, 0x51, 0x04, 0x00, 0x1f, 0x9e, 0x04, 0x6a, // + adler32
};
const zlib_hello_world_plain = "Hello, World!";

test "gzip decompression" {
    const allocator = std.testing.allocator;

    const decompressed = try decompress(allocator, &gzip_hello_world, .gzip);
    defer allocator.free(decompressed);

    try std.testing.expectEqualStrings(gzip_hello_world_plain, decompressed);
}

test "deflate/zlib decompression" {
    const allocator = std.testing.allocator;

    const decompressed = try decompress(allocator, &zlib_hello_world, .deflate);
    defer allocator.free(decompressed);

    try std.testing.expectEqualStrings(zlib_hello_world_plain, decompressed);
}

test "identity passthrough" {
    const allocator = std.testing.allocator;
    const original = "No compression needed.";

    const result = try decompress(allocator, original, .identity);
    defer allocator.free(result);

    try std.testing.expectEqualStrings(original, result);
}

test "Encoding.fromString" {
    try std.testing.expectEqual(Encoding.gzip, Encoding.fromString("gzip").?);
    try std.testing.expectEqual(Encoding.gzip, Encoding.fromString("x-gzip").?);
    try std.testing.expectEqual(Encoding.gzip, Encoding.fromString("GZIP").?);
    try std.testing.expectEqual(Encoding.deflate, Encoding.fromString("deflate").?);
    try std.testing.expectEqual(Encoding.identity, Encoding.fromString("identity").?);
    try std.testing.expect(Encoding.fromString("unknown") == null);
}

test "decompressAuto with gzip encoding header" {
    const allocator = std.testing.allocator;

    const decompressed = try decompressAuto(allocator, &gzip_hello_world, "gzip");
    defer allocator.free(decompressed);

    try std.testing.expectEqualStrings(gzip_hello_world_plain, decompressed);
}

test "decompressAuto with no encoding" {
    const allocator = std.testing.allocator;
    const original = "Plain text without encoding.";

    const result = try decompressAuto(allocator, original, null);
    defer allocator.free(result);

    try std.testing.expectEqualStrings(original, result);
}

test "Encoding.toString" {
    try std.testing.expectEqualStrings("gzip", Encoding.gzip.toString());
    try std.testing.expectEqualStrings("deflate", Encoding.deflate.toString());
    try std.testing.expectEqualStrings("identity", Encoding.identity.toString());
}

test "gzip round-trip compression" {
    const allocator = std.testing.allocator;
    const original = "Hello, World! This is a test of gzip compression.";

    const compressed = try compress(allocator, original, .gzip);
    defer allocator.free(compressed);

    // Verify gzip magic number
    try std.testing.expectEqual(@as(u8, 0x1f), compressed[0]);
    try std.testing.expectEqual(@as(u8, 0x8b), compressed[1]);

    const decompressed = try decompress(allocator, compressed, .gzip);
    defer allocator.free(decompressed);

    try std.testing.expectEqualStrings(original, decompressed);
}

test "deflate round-trip compression" {
    const allocator = std.testing.allocator;
    const original = "Hello, World! This is a test of deflate compression.";

    const compressed = try compress(allocator, original, .deflate);
    defer allocator.free(compressed);

    // Verify zlib header
    try std.testing.expectEqual(@as(u8, 0x78), compressed[0]);

    const decompressed = try decompress(allocator, compressed, .deflate);
    defer allocator.free(decompressed);

    try std.testing.expectEqualStrings(original, decompressed);
}

test "compress identity passthrough" {
    const allocator = std.testing.allocator;
    const original = "Test data";

    const result = try compress(allocator, original, .identity);
    defer allocator.free(result);

    try std.testing.expectEqualStrings(original, result);
}

test "compress longer text with LZ77 matches" {
    const allocator = std.testing.allocator;
    // Repetitive text to test LZ77 matching
    const original = "The quick brown fox jumps over the lazy dog. " ** 5;

    const compressed = try compress(allocator, original, .gzip);
    defer allocator.free(compressed);

    // Should achieve some compression on repetitive data
    try std.testing.expect(compressed.len < original.len);

    const decompressed = try decompress(allocator, compressed, .gzip);
    defer allocator.free(decompressed);

    try std.testing.expectEqualStrings(original, decompressed);
}

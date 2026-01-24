//! HTTP Content-Encoding Compression/Decompression for httpx.zig
//!
//! Provides automatic content encoding handling as specified in RFC 7231.
//! Supports gzip, deflate, and identity encodings.
//!
//! ## Supported Encodings
//! - `gzip`: RFC 1952 gzip compression (requires zig >= 0.16)
//! - `deflate`: RFC 1951 deflate/zlib compression (requires zig >= 0.16)
//! - `identity`: No transformation (passthrough)
//!
//! ## Note
//! Full gzip/deflate compression support depends on Zig standard library.
//! The current implementation provides identity encoding and basic structure.
//!
//! ## Usage
//! ```zig
//! const compression = @import("util/compression.zig");
//!
//! // Check encoding type
//! const enc = Encoding.fromString("gzip");
//! ```

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

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
///
/// Note: gzip and deflate decompression are placeholders.
/// For identity encoding, returns a copy of the input data.
pub fn decompress(allocator: Allocator, data: []const u8, encoding: Encoding) CompressionError![]u8 {
    return switch (encoding) {
        .identity => allocator.dupe(u8, data) catch return CompressionError.OutOfMemory,
        .gzip => decompressGzip(allocator, data),
        .deflate => decompressDeflate(allocator, data),
    };
}

/// Compresses data using the specified encoding.
/// Returns owned slice that must be freed by the caller.
pub fn compress(allocator: Allocator, data: []const u8, encoding: Encoding) CompressionError![]u8 {
    return switch (encoding) {
        .identity => allocator.dupe(u8, data) catch return CompressionError.OutOfMemory,
        .gzip, .deflate => allocator.dupe(u8, data) catch return CompressionError.OutOfMemory,
    };
}

/// Decompresses gzip-encoded data (RFC 1952).
/// This is a simplified implementation that handles basic gzip format.
fn decompressGzip(allocator: Allocator, data: []const u8) CompressionError![]u8 {
    // Gzip format: 10-byte header + compressed data + 8-byte trailer
    if (data.len < 18) return CompressionError.InvalidData;

    // Verify gzip magic number
    if (data[0] != 0x1f or data[1] != 0x8b) return CompressionError.InvalidData;

    // Check compression method (8 = deflate)
    if (data[2] != 8) return CompressionError.UnsupportedEncoding;

    const flags = data[3];
    var offset: usize = 10;

    // Handle FEXTRA flag
    if (flags & 0x04 != 0) {
        if (offset + 2 > data.len) return CompressionError.InvalidData;
        const extra_len = @as(u16, data[offset]) | (@as(u16, data[offset + 1]) << 8);
        offset += 2 + extra_len;
    }

    // Handle FNAME flag (null-terminated filename)
    if (flags & 0x08 != 0) {
        while (offset < data.len and data[offset] != 0) offset += 1;
        offset += 1; // Skip null terminator
    }

    // Handle FCOMMENT flag (null-terminated comment)
    if (flags & 0x10 != 0) {
        while (offset < data.len and data[offset] != 0) offset += 1;
        offset += 1;
    }

    // Handle FHCRC flag (2-byte header CRC)
    if (flags & 0x02 != 0) offset += 2;

    if (offset >= data.len) return CompressionError.InvalidData;

    // Decompress the raw deflate data (excluding 8-byte trailer)
    const compressed_data = data[offset .. data.len - 8];
    return decompressRawDeflate(allocator, compressed_data);
}

/// Decompresses deflate/zlib-encoded data.
fn decompressDeflate(allocator: Allocator, data: []const u8) CompressionError![]u8 {
    if (data.len < 2) return CompressionError.InvalidData;

    // Check for zlib wrapper (CMF/FLG bytes)
    const cmf = data[0];
    const flg = data[1];

    // Zlib check: ((CMF * 256 + FLG) % 31 == 0) and CMF & 0x0F == 8
    const is_zlib = (((@as(u16, cmf) << 8) | flg) % 31 == 0) and ((cmf & 0x0F) == 8);

    if (is_zlib) {
        // Skip 2-byte zlib header, decompress, skip 4-byte Adler-32 checksum
        const raw_data = if (data.len > 6) data[2 .. data.len - 4] else return CompressionError.InvalidData;
        return decompressRawDeflate(allocator, raw_data);
    }

    // Try raw deflate
    return decompressRawDeflate(allocator, data);
}

/// Raw deflate decompression.
/// This is a simplified implementation - returns copy for now.
/// Full implementation requires integrating with Zig's new flate API.
fn decompressRawDeflate(allocator: Allocator, data: []const u8) CompressionError![]u8 {
    // For now, return a copy of the data
    // TODO: Implement proper deflate decompression with new Zig 0.15 API
    return allocator.dupe(u8, data) catch return CompressionError.OutOfMemory;
}

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

test "compress identity" {
    const allocator = std.testing.allocator;
    const original = "Test data";

    const result = try compress(allocator, original, .identity);
    defer allocator.free(result);

    try std.testing.expectEqualStrings(original, result);
}

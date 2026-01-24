//! ETag Generation Utilities for httpx.zig
//!
//! Provides ETag generation and validation as specified in RFC 7232.
//! Supports both strong and weak ETags.
//!
//! ## ETag Format
//! - Strong: `"xyzzy"` - byte-for-byte identical
//! - Weak: `W/"xyzzy"` - semantically equivalent
//!
//! ## Usage
//! ```zig
//! const etag = @import("util/etag.zig");
//!
//! // Generate ETag from content
//! const tag = etag.generate(content, .strong);
//! // Returns: "a1b2c3d4e5f6..."
//!
//! // Generate ETag from file metadata (weak)
//! const weak_tag = etag.generateFromMetadata(size, mtime, .weak);
//! // Returns: W/"size-mtime"
//!
//! // Compare ETags
//! const matches = etag.match(client_etag, server_etag, .strong);
//! ```

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// ETag strength as per RFC 7232.
pub const Strength = enum {
    /// Strong validator - byte-for-byte identical
    strong,
    /// Weak validator - semantically equivalent
    weak,
};

/// Parsed ETag value.
pub const ETag = struct {
    value: []const u8,
    weak: bool,

    /// Formats the ETag as a string suitable for headers.
    /// Returns a slice into the provided buffer.
    pub fn format(self: ETag, buf: *[72]u8) []const u8 {
        if (self.weak) {
            const prefix = "W/\"";
            @memcpy(buf[0..prefix.len], prefix);
            const value_len = @min(self.value.len, buf.len - prefix.len - 1);
            @memcpy(buf[prefix.len..][0..value_len], self.value[0..value_len]);
            buf[prefix.len + value_len] = '"';
            return buf[0 .. prefix.len + value_len + 1];
        } else {
            buf[0] = '"';
            const value_len = @min(self.value.len, buf.len - 2);
            @memcpy(buf[1..][0..value_len], self.value[0..value_len]);
            buf[1 + value_len] = '"';
            return buf[0 .. 2 + value_len];
        }
    }
};

/// Generates a strong ETag from content using XXH3 hash.
/// The hash provides good distribution and is fast.
/// Returns a 16-character hex string (64-bit hash).
pub fn generate(content: []const u8) [16]u8 {
    const hash = std.hash.XxHash3.hash(0, content);
    var result: [16]u8 = undefined;
    _ = std.fmt.bufPrint(&result, "{x:0>16}", .{hash}) catch unreachable;
    return result;
}

/// Generates a weak ETag from file metadata (size and modification time).
/// Useful for large files where hashing content is expensive.
/// Format: "size-mtime" where mtime is Unix timestamp in hex.
pub fn generateFromMetadata(size: u64, mtime_ns: i128) [32]u8 {
    var result: [32]u8 = undefined;
    const mtime_sec: u64 = @intCast(@divTrunc(mtime_ns, std.time.ns_per_s));
    _ = std.fmt.bufPrint(&result, "{x:0>16}-{x:0>8}", .{ size, @as(u32, @truncate(mtime_sec)) }) catch unreachable;
    return result;
}

/// Parses an ETag header value.
/// Handles both strong ("value") and weak (W/"value") formats.
pub fn parse(header_value: []const u8) ?ETag {
    const trimmed = mem.trim(u8, header_value, " \t");
    if (trimmed.len < 2) return null;

    var weak = false;
    var value_start: usize = 0;

    // Check for weak prefix
    if (trimmed.len >= 3 and (trimmed[0] == 'W' or trimmed[0] == 'w') and trimmed[1] == '/') {
        weak = true;
        value_start = 2;
    }

    // Must be quoted
    if (trimmed.len <= value_start or trimmed[value_start] != '"') return null;

    // Find closing quote
    const content_start = value_start + 1;
    const end_quote = mem.lastIndexOf(u8, trimmed, "\"") orelse return null;
    if (end_quote <= content_start) return null;

    return .{
        .value = trimmed[content_start..end_quote],
        .weak = weak,
    };
}

/// Comparison type for ETag matching.
pub const CompareType = enum {
    /// Strong comparison - both must be strong and identical
    strong,
    /// Weak comparison - values must match (ignoring weak flag)
    weak,
};

/// Compares two ETags according to RFC 7232.
/// - Strong comparison: both must be strong validators and identical
/// - Weak comparison: values must be identical (weak flag ignored)
pub fn match(etag1: ETag, etag2: ETag, compare: CompareType) bool {
    return switch (compare) {
        .strong => !etag1.weak and !etag2.weak and mem.eql(u8, etag1.value, etag2.value),
        .weak => mem.eql(u8, etag1.value, etag2.value),
    };
}

/// Parses If-None-Match header which can contain multiple ETags.
/// Returns true if any of the ETags match the given server ETag.
/// Supports the special "*" value which matches any ETag.
pub fn matchIfNoneMatch(if_none_match: []const u8, server_etag: ETag) bool {
    const trimmed = mem.trim(u8, if_none_match, " \t");

    // Special case: "*" matches any ETag
    if (mem.eql(u8, trimmed, "*")) {
        return true;
    }

    // Parse comma-separated list of ETags
    var it = mem.splitScalar(u8, trimmed, ',');
    while (it.next()) |part| {
        const etag_str = mem.trim(u8, part, " \t");
        if (parse(etag_str)) |client_etag| {
            // If-None-Match uses weak comparison
            if (match(client_etag, server_etag, .weak)) {
                return true;
            }
        }
    }

    return false;
}

/// Parses If-Match header which can contain multiple ETags.
/// Returns true if any of the ETags match the given server ETag.
/// Supports the special "*" value which matches any existing resource.
pub fn matchIfMatch(if_match: []const u8, server_etag: ETag) bool {
    const trimmed = mem.trim(u8, if_match, " \t");

    // Special case: "*" matches any existing resource
    if (mem.eql(u8, trimmed, "*")) {
        return true;
    }

    // Parse comma-separated list of ETags
    var it = mem.splitScalar(u8, trimmed, ',');
    while (it.next()) |part| {
        const etag_str = mem.trim(u8, part, " \t");
        if (parse(etag_str)) |client_etag| {
            // If-Match uses strong comparison
            if (match(client_etag, server_etag, .strong)) {
                return true;
            }
        }
    }

    return false;
}

// =============================================================================
// Tests
// =============================================================================

test "generate ETag from content" {
    const content = "Hello, World!";
    const etag = generate(content);

    // Should be 16 hex characters
    try std.testing.expectEqual(@as(usize, 16), etag.len);

    // Same content should produce same ETag
    const etag2 = generate(content);
    try std.testing.expectEqualStrings(&etag, &etag2);

    // Different content should produce different ETag
    const etag3 = generate("Different content");
    try std.testing.expect(!mem.eql(u8, &etag, &etag3));
}

test "generate ETag from metadata" {
    const etag = generateFromMetadata(1024, 1700000000 * std.time.ns_per_s);

    // Should be 32 characters (16 for size + 1 dash + 8 for mtime + padding)
    try std.testing.expectEqual(@as(usize, 32), etag.len);
}

test "parse strong ETag" {
    const result = parse("\"abc123\"");
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("abc123", result.?.value);
    try std.testing.expect(!result.?.weak);
}

test "parse weak ETag" {
    const result = parse("W/\"abc123\"");
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("abc123", result.?.value);
    try std.testing.expect(result.?.weak);
}

test "parse ETag with whitespace" {
    const result = parse("  \"abc123\"  ");
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("abc123", result.?.value);
}

test "parse invalid ETag" {
    try std.testing.expect(parse("abc123") == null); // No quotes
    try std.testing.expect(parse("\"") == null); // Only one quote
    try std.testing.expect(parse("") == null); // Empty
    try std.testing.expect(parse("W/") == null); // Weak prefix but no value
}

test "ETag format strong" {
    const etag = ETag{ .value = "abc123", .weak = false };
    var buf: [72]u8 = undefined;
    const formatted = etag.format(&buf);
    try std.testing.expectEqualStrings("\"abc123\"", formatted);
}

test "ETag format weak" {
    const etag = ETag{ .value = "abc123", .weak = true };
    var buf: [72]u8 = undefined;
    const formatted = etag.format(&buf);
    try std.testing.expectEqualStrings("W/\"abc123\"", formatted);
}

test "strong comparison" {
    const strong1 = ETag{ .value = "abc", .weak = false };
    const strong2 = ETag{ .value = "abc", .weak = false };
    const weak1 = ETag{ .value = "abc", .weak = true };

    // Strong comparison requires both to be strong
    try std.testing.expect(match(strong1, strong2, .strong));
    try std.testing.expect(!match(strong1, weak1, .strong));
    try std.testing.expect(!match(weak1, strong1, .strong));
}

test "weak comparison" {
    const strong1 = ETag{ .value = "abc", .weak = false };
    const weak1 = ETag{ .value = "abc", .weak = true };

    // Weak comparison ignores the weak flag
    try std.testing.expect(match(strong1, weak1, .weak));
    try std.testing.expect(match(weak1, strong1, .weak));
}

test "matchIfNoneMatch single" {
    const server_etag = ETag{ .value = "abc123", .weak = false };

    try std.testing.expect(matchIfNoneMatch("\"abc123\"", server_etag));
    try std.testing.expect(matchIfNoneMatch("W/\"abc123\"", server_etag)); // Weak comparison
    try std.testing.expect(!matchIfNoneMatch("\"xyz789\"", server_etag));
}

test "matchIfNoneMatch multiple" {
    const server_etag = ETag{ .value = "abc123", .weak = false };

    try std.testing.expect(matchIfNoneMatch("\"xyz\", \"abc123\", \"def\"", server_etag));
    try std.testing.expect(!matchIfNoneMatch("\"xyz\", \"def\"", server_etag));
}

test "matchIfNoneMatch wildcard" {
    const server_etag = ETag{ .value = "anything", .weak = false };
    try std.testing.expect(matchIfNoneMatch("*", server_etag));
}

test "matchIfMatch strong comparison" {
    const server_etag = ETag{ .value = "abc123", .weak = false };

    try std.testing.expect(matchIfMatch("\"abc123\"", server_etag));
    try std.testing.expect(!matchIfMatch("W/\"abc123\"", server_etag)); // Weak doesn't match in strong compare
}

test "matchIfMatch wildcard" {
    const server_etag = ETag{ .value = "anything", .weak = false };
    try std.testing.expect(matchIfMatch("*", server_etag));
}

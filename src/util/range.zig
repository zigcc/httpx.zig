//! HTTP Range Request Utilities for httpx.zig
//!
//! Provides Range header parsing and Content-Range generation as specified in RFC 7233.
//!
//! ## Range Header Format
//! - `bytes=0-499` - First 500 bytes
//! - `bytes=500-999` - Second 500 bytes
//! - `bytes=-500` - Last 500 bytes
//! - `bytes=500-` - From byte 500 to end
//! - `bytes=0-0,-1` - First and last byte (multipart)
//!
//! ## Content-Range Format
//! - `bytes 0-499/1234` - Bytes 0-499 of 1234 total
//! - `bytes */1234` - Unsatisfiable range response
//!
//! ## Usage
//! ```zig
//! const range = @import("util/range.zig");
//!
//! // Parse Range header
//! const ranges = range.parse("bytes=0-499, 1000-1499", file_size);
//!
//! // Generate Content-Range header
//! var buf: [64]u8 = undefined;
//! const header = range.formatContentRange(0, 499, 1234, &buf);
//! // Returns: "bytes 0-499/1234"
//! ```

const std = @import("std");
const mem = std.mem;

/// A single byte range specification.
pub const ByteRange = struct {
    /// Start byte position (inclusive).
    start: u64,
    /// End byte position (inclusive).
    end: u64,

    /// Returns the length of this range in bytes.
    pub fn length(self: ByteRange) u64 {
        return self.end - self.start + 1;
    }

    /// Checks if this range is valid for a resource of the given size.
    pub fn isValid(self: ByteRange, total_size: u64) bool {
        return self.start <= self.end and self.start < total_size;
    }

    /// Clamps the range to fit within the resource size.
    pub fn clamp(self: ByteRange, total_size: u64) ByteRange {
        return .{
            .start = self.start,
            .end = @min(self.end, total_size - 1),
        };
    }
};

/// Result of parsing a Range header.
pub const ParseResult = struct {
    /// Parsed ranges (up to 8).
    ranges: [8]?ByteRange,
    /// Number of valid ranges.
    count: usize,
    /// True if any range was unsatisfiable.
    has_unsatisfiable: bool,
};

/// Errors that can occur during range parsing.
pub const ParseError = error{
    /// Range header is malformed.
    InvalidFormat,
    /// Range unit is not "bytes".
    UnsupportedUnit,
    /// No valid ranges found.
    NoValidRanges,
};

/// Parses an HTTP Range header value.
///
/// Supports the following formats:
/// - `bytes=0-499` - Byte range from 0 to 499
/// - `bytes=-500` - Last 500 bytes
/// - `bytes=500-` - From byte 500 to end
/// - `bytes=0-499, 1000-1499` - Multiple ranges
///
/// Returns up to 8 ranges. Additional ranges are ignored.
pub fn parse(header_value: []const u8, total_size: u64) ParseError!ParseResult {
    const trimmed = mem.trim(u8, header_value, " \t");

    // Must start with "bytes="
    if (!std.ascii.startsWithIgnoreCase(trimmed, "bytes=")) {
        return ParseError.UnsupportedUnit;
    }

    const ranges_part = trimmed[6..]; // Skip "bytes="
    if (ranges_part.len == 0) {
        return ParseError.InvalidFormat;
    }

    var result = ParseResult{
        .ranges = .{ null, null, null, null, null, null, null, null },
        .count = 0,
        .has_unsatisfiable = false,
    };

    // Parse comma-separated ranges
    var it = mem.splitScalar(u8, ranges_part, ',');
    while (it.next()) |part| {
        if (result.count >= 8) break;

        const range_str = mem.trim(u8, part, " \t");
        if (range_str.len == 0) continue;

        if (parseOneRange(range_str, total_size)) |byte_range| {
            result.ranges[result.count] = byte_range;
            result.count += 1;
        } else {
            result.has_unsatisfiable = true;
        }
    }

    if (result.count == 0) {
        return ParseError.NoValidRanges;
    }

    return result;
}

/// Parses a single range specification.
fn parseOneRange(range_str: []const u8, total_size: u64) ?ByteRange {
    // Find the hyphen
    const hyphen_pos = mem.indexOf(u8, range_str, "-") orelse return null;

    const start_str = mem.trim(u8, range_str[0..hyphen_pos], " \t");
    const end_str = mem.trim(u8, range_str[hyphen_pos + 1 ..], " \t");

    // Case 1: "-500" (suffix range - last N bytes)
    if (start_str.len == 0) {
        const suffix_length = std.fmt.parseInt(u64, end_str, 10) catch return null;
        if (suffix_length == 0) return null;
        if (suffix_length >= total_size) {
            // Request entire file
            return ByteRange{ .start = 0, .end = total_size - 1 };
        }
        return ByteRange{
            .start = total_size - suffix_length,
            .end = total_size - 1,
        };
    }

    const start = std.fmt.parseInt(u64, start_str, 10) catch return null;

    // Case 2: "500-" (from start to end)
    if (end_str.len == 0) {
        if (start >= total_size) return null; // Unsatisfiable
        return ByteRange{
            .start = start,
            .end = total_size - 1,
        };
    }

    // Case 3: "0-499" (explicit range)
    const end = std.fmt.parseInt(u64, end_str, 10) catch return null;

    // Validate range
    if (start > end) return null;
    if (start >= total_size) return null; // Unsatisfiable

    return ByteRange{
        .start = start,
        .end = @min(end, total_size - 1),
    };
}

/// Formats a Content-Range header value.
/// Format: "bytes start-end/total"
pub fn formatContentRange(start: u64, end: u64, total: u64, buf: *[64]u8) []const u8 {
    const len = std.fmt.bufPrint(buf, "bytes {d}-{d}/{d}", .{ start, end, total }) catch unreachable;
    return buf[0..len.len];
}

/// Formats an unsatisfiable Content-Range header value.
/// Format: "bytes */total"
pub fn formatUnsatisfiableRange(total: u64, buf: *[64]u8) []const u8 {
    const len = std.fmt.bufPrint(buf, "bytes */{d}", .{total}) catch unreachable;
    return buf[0..len.len];
}

/// Checks if ranges can be coalesced (overlapping or adjacent).
pub fn canCoalesce(r1: ByteRange, r2: ByteRange) bool {
    // Check if ranges overlap or are adjacent
    return r1.start <= r2.end + 1 and r2.start <= r1.end + 1;
}

/// Coalesces two overlapping or adjacent ranges.
pub fn coalesce(r1: ByteRange, r2: ByteRange) ByteRange {
    return .{
        .start = @min(r1.start, r2.start),
        .end = @max(r1.end, r2.end),
    };
}

/// Determines if a single-part or multipart response should be used.
/// Returns true if multipart response is needed.
pub fn needsMultipart(result: ParseResult) bool {
    return result.count > 1;
}

/// Calculates the total bytes to be sent for all ranges.
pub fn totalBytes(result: ParseResult) u64 {
    var total: u64 = 0;
    for (result.ranges) |maybe_range| {
        if (maybe_range) |range| {
            total += range.length();
        }
    }
    return total;
}

// =============================================================================
// Tests
// =============================================================================

test "parse simple range" {
    const result = try parse("bytes=0-499", 1000);
    try std.testing.expectEqual(@as(usize, 1), result.count);
    try std.testing.expectEqual(@as(u64, 0), result.ranges[0].?.start);
    try std.testing.expectEqual(@as(u64, 499), result.ranges[0].?.end);
}

test "parse suffix range" {
    const result = try parse("bytes=-100", 1000);
    try std.testing.expectEqual(@as(usize, 1), result.count);
    try std.testing.expectEqual(@as(u64, 900), result.ranges[0].?.start);
    try std.testing.expectEqual(@as(u64, 999), result.ranges[0].?.end);
}

test "parse suffix range larger than file" {
    const result = try parse("bytes=-2000", 1000);
    try std.testing.expectEqual(@as(usize, 1), result.count);
    try std.testing.expectEqual(@as(u64, 0), result.ranges[0].?.start);
    try std.testing.expectEqual(@as(u64, 999), result.ranges[0].?.end);
}

test "parse open-ended range" {
    const result = try parse("bytes=500-", 1000);
    try std.testing.expectEqual(@as(usize, 1), result.count);
    try std.testing.expectEqual(@as(u64, 500), result.ranges[0].?.start);
    try std.testing.expectEqual(@as(u64, 999), result.ranges[0].?.end);
}

test "parse multiple ranges" {
    const result = try parse("bytes=0-99, 200-299, 400-499", 1000);
    try std.testing.expectEqual(@as(usize, 3), result.count);
    try std.testing.expectEqual(@as(u64, 0), result.ranges[0].?.start);
    try std.testing.expectEqual(@as(u64, 99), result.ranges[0].?.end);
    try std.testing.expectEqual(@as(u64, 200), result.ranges[1].?.start);
    try std.testing.expectEqual(@as(u64, 299), result.ranges[1].?.end);
}

test "parse range clamped to file size" {
    const result = try parse("bytes=500-2000", 1000);
    try std.testing.expectEqual(@as(usize, 1), result.count);
    try std.testing.expectEqual(@as(u64, 500), result.ranges[0].?.start);
    try std.testing.expectEqual(@as(u64, 999), result.ranges[0].?.end);
}

test "parse unsatisfiable range" {
    const result = parse("bytes=2000-3000", 1000);
    try std.testing.expectError(ParseError.NoValidRanges, result);
}

test "parse invalid unit" {
    const result = parse("pages=0-10", 1000);
    try std.testing.expectError(ParseError.UnsupportedUnit, result);
}

test "parse case insensitive" {
    const result = try parse("BYTES=0-499", 1000);
    try std.testing.expectEqual(@as(usize, 1), result.count);
}

test "formatContentRange" {
    var buf: [64]u8 = undefined;
    const result = formatContentRange(0, 499, 1234, &buf);
    try std.testing.expectEqualStrings("bytes 0-499/1234", result);
}

test "formatUnsatisfiableRange" {
    var buf: [64]u8 = undefined;
    const result = formatUnsatisfiableRange(1234, &buf);
    try std.testing.expectEqualStrings("bytes */1234", result);
}

test "ByteRange length" {
    const range = ByteRange{ .start = 0, .end = 499 };
    try std.testing.expectEqual(@as(u64, 500), range.length());
}

test "ByteRange clamp" {
    const range = ByteRange{ .start = 500, .end = 2000 };
    const clamped = range.clamp(1000);
    try std.testing.expectEqual(@as(u64, 500), clamped.start);
    try std.testing.expectEqual(@as(u64, 999), clamped.end);
}

test "needsMultipart" {
    var single = ParseResult{
        .ranges = .{ ByteRange{ .start = 0, .end = 99 }, null, null, null, null, null, null, null },
        .count = 1,
        .has_unsatisfiable = false,
    };
    try std.testing.expect(!needsMultipart(single));

    single.ranges[1] = ByteRange{ .start = 200, .end = 299 };
    single.count = 2;
    try std.testing.expect(needsMultipart(single));
}

test "totalBytes" {
    const result = ParseResult{
        .ranges = .{
            ByteRange{ .start = 0, .end = 99 },
            ByteRange{ .start = 200, .end = 299 },
            null,
            null,
            null,
            null,
            null,
            null,
        },
        .count = 2,
        .has_unsatisfiable = false,
    };
    try std.testing.expectEqual(@as(u64, 200), totalBytes(result));
}

test "canCoalesce overlapping" {
    const r1 = ByteRange{ .start = 0, .end = 100 };
    const r2 = ByteRange{ .start = 50, .end = 150 };
    try std.testing.expect(canCoalesce(r1, r2));
}

test "canCoalesce adjacent" {
    const r1 = ByteRange{ .start = 0, .end = 99 };
    const r2 = ByteRange{ .start = 100, .end = 199 };
    try std.testing.expect(canCoalesce(r1, r2));
}

test "canCoalesce separate" {
    const r1 = ByteRange{ .start = 0, .end = 99 };
    const r2 = ByteRange{ .start = 200, .end = 299 };
    try std.testing.expect(!canCoalesce(r1, r2));
}

test "coalesce" {
    const r1 = ByteRange{ .start = 0, .end = 100 };
    const r2 = ByteRange{ .start = 50, .end = 150 };
    const merged = coalesce(r1, r2);
    try std.testing.expectEqual(@as(u64, 0), merged.start);
    try std.testing.expectEqual(@as(u64, 150), merged.end);
}

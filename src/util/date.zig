//! HTTP Date Utilities for httpx.zig
//!
//! Provides HTTP-date formatting and parsing as specified in RFC 7231.
//!
//! ## Preferred Format (RFC 7231)
//! ```
//! Sun, 06 Nov 1994 08:49:37 GMT
//! ```
//!
//! ## Also Supported for Parsing (obsolete formats)
//! - RFC 850: `Sunday, 06-Nov-94 08:49:37 GMT`
//! - ANSI C asctime: `Sun Nov  6 08:49:37 1994`
//!
//! ## Usage
//! ```zig
//! const date = @import("util/date.zig");
//!
//! // Format current time
//! var buf: [32]u8 = undefined;
//! const http_date = date.formatHttpDate(timestamp, &buf);
//! // Returns: "Sun, 06 Nov 1994 08:49:37 GMT"
//!
//! // Parse HTTP date
//! const timestamp = date.parseHttpDate("Sun, 06 Nov 1994 08:49:37 GMT");
//! ```

const std = @import("std");
const mem = std.mem;

/// Day names for HTTP-date format.
const day_names = [_][]const u8{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

/// Full day names for RFC 850 format.
const full_day_names = [_][]const u8{ "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday" };

/// Month names for HTTP-date format.
const month_names = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

/// Epoch-based date components.
pub const DateTime = struct {
    year: u16,
    month: u8, // 1-12
    day: u8, // 1-31
    hour: u8, // 0-23
    minute: u8, // 0-59
    second: u8, // 0-59
    weekday: u8, // 0-6 (Sunday = 0)
};

/// Converts a Unix timestamp (seconds since epoch) to DateTime.
pub fn fromTimestamp(timestamp: i64) DateTime {
    // Algorithm based on Howard Hinnant's date algorithms
    // http://howardhinnant.github.io/date_algorithms.html
    const z = @divFloor(timestamp, 86400) + 719468;
    const era: i64 = @divFloor(if (z >= 0) z else z - 146096, 146097);
    const doe: u64 = @intCast(z - era * 146097);
    const yoe: u64 = @divFloor(doe - @divFloor(doe, 1460) + @divFloor(doe, 36524) - @divFloor(doe, 146096), 365);
    const y: i64 = @as(i64, @intCast(yoe)) + era * 400;
    const doy: u64 = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp: u64 = @divFloor(5 * doy + 2, 153);
    const d: u8 = @intCast(doy - @divFloor(153 * mp + 2, 5) + 1);
    const m: u8 = @intCast(if (mp < 10) mp + 3 else mp - 9);
    const year: u16 = @intCast(y + @as(i64, if (m <= 2) @as(i64, 1) else @as(i64, 0)));

    const day_seconds: u64 = @intCast(@mod(timestamp, 86400));
    const hour: u8 = @intCast(@divFloor(day_seconds, 3600));
    const minute: u8 = @intCast(@divFloor(@mod(day_seconds, 3600), 60));
    const second: u8 = @intCast(@mod(day_seconds, 60));

    // Calculate day of week (0 = Sunday)
    const days_since_epoch = @divFloor(timestamp, 86400);
    const weekday: u8 = @intCast(@mod(days_since_epoch + 4, 7)); // 1970-01-01 was Thursday (4)

    return .{
        .year = year,
        .month = m,
        .day = d,
        .hour = hour,
        .minute = minute,
        .second = second,
        .weekday = weekday,
    };
}

/// Converts DateTime to Unix timestamp (seconds since epoch).
pub fn toTimestamp(dt: DateTime) i64 {
    // Algorithm based on Howard Hinnant's date algorithms
    const y: i64 = @as(i64, dt.year) - @as(i64, if (dt.month <= 2) @as(i64, 1) else @as(i64, 0));
    const era: i64 = @divFloor(if (y >= 0) y else y - 399, 400);
    const yoe: u64 = @intCast(y - era * 400);
    const m: u64 = dt.month;
    const doy: u64 = @divFloor(153 * (if (m > 2) m - 3 else m + 9) + 2, 5) + dt.day - 1;
    const doe: u64 = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    const days: i64 = era * 146097 + @as(i64, @intCast(doe)) - 719468;

    return days * 86400 + @as(i64, dt.hour) * 3600 + @as(i64, dt.minute) * 60 + @as(i64, dt.second);
}

/// Formats a Unix timestamp as an HTTP-date string (RFC 7231).
/// Example: "Sun, 06 Nov 1994 08:49:37 GMT"
pub fn formatHttpDate(timestamp: i64, buf: *[32]u8) []const u8 {
    const dt = fromTimestamp(timestamp);

    const result = std.fmt.bufPrint(buf, "{s}, {d:0>2} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} GMT", .{
        day_names[dt.weekday],
        dt.day,
        month_names[dt.month - 1],
        dt.year,
        dt.hour,
        dt.minute,
        dt.second,
    }) catch unreachable;

    return result;
}

/// Formats a DateTime as an HTTP-date string.
pub fn formatDateTime(dt: DateTime, buf: *[32]u8) []const u8 {
    const result = std.fmt.bufPrint(buf, "{s}, {d:0>2} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} GMT", .{
        day_names[dt.weekday],
        dt.day,
        month_names[dt.month - 1],
        dt.year,
        dt.hour,
        dt.minute,
        dt.second,
    }) catch unreachable;

    return result;
}

/// Parses an HTTP-date string to Unix timestamp.
/// Supports RFC 7231, RFC 850, and ANSI C formats.
pub fn parseHttpDate(date_str: []const u8) ?i64 {
    const trimmed = mem.trim(u8, date_str, " \t");

    // Try RFC 7231 / RFC 1123 format: "Sun, 06 Nov 1994 08:49:37 GMT"
    if (parseRfc7231(trimmed)) |ts| return ts;

    // Try RFC 850 format: "Sunday, 06-Nov-94 08:49:37 GMT"
    if (parseRfc850(trimmed)) |ts| return ts;

    // Try ANSI C asctime format: "Sun Nov  6 08:49:37 1994"
    if (parseAsctime(trimmed)) |ts| return ts;

    return null;
}

/// Parses RFC 7231 / RFC 1123 format.
fn parseRfc7231(s: []const u8) ?i64 {
    // "Sun, 06 Nov 1994 08:49:37 GMT"
    // Minimum length check
    if (s.len < 29) return null;

    // Skip day name and ", "
    const after_comma = mem.indexOf(u8, s, ", ") orelse return null;
    const rest = s[after_comma + 2 ..];

    // Parse "06 Nov 1994 08:49:37 GMT" (24 chars)
    if (rest.len < 20) return null;

    const day = std.fmt.parseInt(u8, rest[0..2], 10) catch return null;
    const month = parseMonth(rest[3..6]) orelse return null;
    const year = std.fmt.parseInt(u16, rest[7..11], 10) catch return null;
    const hour = std.fmt.parseInt(u8, rest[12..14], 10) catch return null;
    const minute = std.fmt.parseInt(u8, rest[15..17], 10) catch return null;
    const second = std.fmt.parseInt(u8, rest[18..20], 10) catch return null;

    const dt = DateTime{
        .year = year,
        .month = month,
        .day = day,
        .hour = hour,
        .minute = minute,
        .second = second,
        .weekday = 0, // Not used for timestamp calculation
    };

    return toTimestamp(dt);
}

/// Parses RFC 850 format.
fn parseRfc850(s: []const u8) ?i64 {
    // "Sunday, 06-Nov-94 08:49:37 GMT"
    const after_comma = mem.indexOf(u8, s, ", ") orelse return null;
    const rest = s[after_comma + 2 ..];

    if (rest.len < 22) return null;

    const day = std.fmt.parseInt(u8, rest[0..2], 10) catch return null;
    const month = parseMonth(rest[3..6]) orelse return null;

    // Two-digit year
    const year_2digit = std.fmt.parseInt(u8, rest[7..9], 10) catch return null;
    const year: u16 = if (year_2digit >= 70) 1900 + @as(u16, year_2digit) else 2000 + @as(u16, year_2digit);

    const hour = std.fmt.parseInt(u8, rest[10..12], 10) catch return null;
    const minute = std.fmt.parseInt(u8, rest[13..15], 10) catch return null;
    const second = std.fmt.parseInt(u8, rest[16..18], 10) catch return null;

    const dt = DateTime{
        .year = year,
        .month = month,
        .day = day,
        .hour = hour,
        .minute = minute,
        .second = second,
        .weekday = 0,
    };

    return toTimestamp(dt);
}

/// Parses ANSI C asctime format.
fn parseAsctime(s: []const u8) ?i64 {
    // "Sun Nov  6 08:49:37 1994"
    if (s.len < 24) return null;

    const month = parseMonth(s[4..7]) orelse return null;

    // Day can be " 6" or "06"
    const day_str = mem.trim(u8, s[8..10], " ");
    const day = std.fmt.parseInt(u8, day_str, 10) catch return null;

    const hour = std.fmt.parseInt(u8, s[11..13], 10) catch return null;
    const minute = std.fmt.parseInt(u8, s[14..16], 10) catch return null;
    const second = std.fmt.parseInt(u8, s[17..19], 10) catch return null;
    const year = std.fmt.parseInt(u16, s[20..24], 10) catch return null;

    const dt = DateTime{
        .year = year,
        .month = month,
        .day = day,
        .hour = hour,
        .minute = minute,
        .second = second,
        .weekday = 0,
    };

    return toTimestamp(dt);
}

/// Parses a 3-letter month name to month number (1-12).
fn parseMonth(s: []const u8) ?u8 {
    if (s.len < 3) return null;
    const month_str = s[0..3];

    for (month_names, 1..) |name, i| {
        if (std.ascii.eqlIgnoreCase(month_str, name)) {
            return @intCast(i);
        }
    }
    return null;
}

/// Returns the current time as an HTTP-date string.
pub fn now(buf: *[32]u8) []const u8 {
    const timestamp = std.time.timestamp();
    return formatHttpDate(timestamp, buf);
}

/// Compares two timestamps for If-Modified-Since checking.
/// Returns true if the resource has been modified since the given time.
pub fn isModifiedSince(resource_mtime: i64, if_modified_since: i64) bool {
    return resource_mtime > if_modified_since;
}

/// Compares two timestamps for If-Unmodified-Since checking.
/// Returns true if the resource has not been modified since the given time.
pub fn isUnmodifiedSince(resource_mtime: i64, if_unmodified_since: i64) bool {
    return resource_mtime <= if_unmodified_since;
}

// =============================================================================
// Tests
// =============================================================================

test "fromTimestamp Unix epoch" {
    const dt = fromTimestamp(0);
    try std.testing.expectEqual(@as(u16, 1970), dt.year);
    try std.testing.expectEqual(@as(u8, 1), dt.month);
    try std.testing.expectEqual(@as(u8, 1), dt.day);
    try std.testing.expectEqual(@as(u8, 0), dt.hour);
    try std.testing.expectEqual(@as(u8, 0), dt.minute);
    try std.testing.expectEqual(@as(u8, 0), dt.second);
    try std.testing.expectEqual(@as(u8, 4), dt.weekday); // Thursday
}

test "fromTimestamp known date" {
    // 1994-11-06 08:49:37 UTC (from RFC 7231 example)
    const timestamp: i64 = 784111777;
    const dt = fromTimestamp(timestamp);
    try std.testing.expectEqual(@as(u16, 1994), dt.year);
    try std.testing.expectEqual(@as(u8, 11), dt.month);
    try std.testing.expectEqual(@as(u8, 6), dt.day);
    try std.testing.expectEqual(@as(u8, 8), dt.hour);
    try std.testing.expectEqual(@as(u8, 49), dt.minute);
    try std.testing.expectEqual(@as(u8, 37), dt.second);
    try std.testing.expectEqual(@as(u8, 0), dt.weekday); // Sunday
}

test "toTimestamp round-trip" {
    const original: i64 = 784111777;
    const dt = fromTimestamp(original);
    const back = toTimestamp(dt);
    try std.testing.expectEqual(original, back);
}

test "formatHttpDate" {
    var buf: [32]u8 = undefined;
    const timestamp: i64 = 784111777;
    const result = formatHttpDate(timestamp, &buf);
    try std.testing.expectEqualStrings("Sun, 06 Nov 1994 08:49:37 GMT", result);
}

test "formatHttpDate epoch" {
    var buf: [32]u8 = undefined;
    const result = formatHttpDate(0, &buf);
    try std.testing.expectEqualStrings("Thu, 01 Jan 1970 00:00:00 GMT", result);
}

test "parseHttpDate RFC 7231" {
    const timestamp = parseHttpDate("Sun, 06 Nov 1994 08:49:37 GMT");
    try std.testing.expect(timestamp != null);
    try std.testing.expectEqual(@as(i64, 784111777), timestamp.?);
}

test "parseHttpDate RFC 850" {
    const timestamp = parseHttpDate("Sunday, 06-Nov-94 08:49:37 GMT");
    try std.testing.expect(timestamp != null);
    try std.testing.expectEqual(@as(i64, 784111777), timestamp.?);
}

test "parseHttpDate ANSI C" {
    const timestamp = parseHttpDate("Sun Nov  6 08:49:37 1994");
    try std.testing.expect(timestamp != null);
    try std.testing.expectEqual(@as(i64, 784111777), timestamp.?);
}

test "parseHttpDate invalid" {
    try std.testing.expect(parseHttpDate("invalid date") == null);
    try std.testing.expect(parseHttpDate("") == null);
    try std.testing.expect(parseHttpDate("Sun, 99 Xyz 1994 08:49:37 GMT") == null);
}

test "parseMonth" {
    try std.testing.expectEqual(@as(?u8, 1), parseMonth("Jan"));
    try std.testing.expectEqual(@as(?u8, 6), parseMonth("Jun"));
    try std.testing.expectEqual(@as(?u8, 12), parseMonth("Dec"));
    try std.testing.expectEqual(@as(?u8, 1), parseMonth("JAN")); // Case insensitive
    try std.testing.expect(parseMonth("Xyz") == null);
}

test "isModifiedSince" {
    try std.testing.expect(isModifiedSince(1000, 500)); // Modified after
    try std.testing.expect(!isModifiedSince(500, 1000)); // Not modified after
    try std.testing.expect(!isModifiedSince(1000, 1000)); // Same time
}

test "isUnmodifiedSince" {
    try std.testing.expect(!isUnmodifiedSince(1000, 500)); // Modified after
    try std.testing.expect(isUnmodifiedSince(500, 1000)); // Not modified after
    try std.testing.expect(isUnmodifiedSince(1000, 1000)); // Same time
}

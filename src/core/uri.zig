//! URI Parsing and Manipulation for httpx.zig
//!
//! Implements URI parsing according to RFC 3986 with support for:
//!
//! - Full URI parsing (scheme, userinfo, host, port, path, query, fragment)
//! - Percent-encoding and decoding
//! - Path normalization
//! - Query string building
//! - Automatic port detection for common schemes

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// Parsed URI structure per RFC 3986.
pub const Uri = struct {
    scheme: ?[]const u8 = null,
    userinfo: ?[]const u8 = null,
    host: ?[]const u8 = null,
    port: ?u16 = null,
    path: []const u8 = "/",
    query: ?[]const u8 = null,
    fragment: ?[]const u8 = null,
    raw: []const u8,
    /// True if host is an IPv6 address (was enclosed in brackets).
    is_ipv6_host: bool = false,

    const Self = @This();

    /// Parses a URI string into its components.
    pub fn parse(uri_string: []const u8) !Self {
        var uri = Self{ .raw = uri_string };
        var remaining = uri_string;

        if (mem.indexOf(u8, remaining, "://")) |scheme_end| {
            uri.scheme = remaining[0..scheme_end];
            remaining = remaining[scheme_end + 3 ..];
        }

        if (mem.indexOf(u8, remaining, "#")) |frag_start| {
            uri.fragment = remaining[frag_start + 1 ..];
            remaining = remaining[0..frag_start];
        }

        if (mem.indexOf(u8, remaining, "?")) |query_start| {
            uri.query = remaining[query_start + 1 ..];
            remaining = remaining[0..query_start];
        }

        if (mem.indexOf(u8, remaining, "/")) |path_start| {
            uri.path = remaining[path_start..];
            remaining = remaining[0..path_start];
        } else {
            uri.path = "/";
        }

        if (mem.indexOf(u8, remaining, "@")) |auth_end| {
            uri.userinfo = remaining[0..auth_end];
            remaining = remaining[auth_end + 1 ..];
        }

        if (remaining.len > 0 and remaining[0] == '[') {
            if (mem.indexOf(u8, remaining, "]")) |bracket_end| {
                uri.host = remaining[1..bracket_end];
                uri.is_ipv6_host = true;
                remaining = remaining[bracket_end + 1 ..];
            }
        }

        if (mem.lastIndexOf(u8, remaining, ":")) |port_sep| {
            if (std.fmt.parseInt(u16, remaining[port_sep + 1 ..], 10)) |port| {
                uri.port = port;
                remaining = remaining[0..port_sep];
            } else |_| {}
        }

        if (remaining.len > 0 and uri.host == null) {
            uri.host = remaining;
        }

        return uri;
    }

    /// Returns the effective port, using scheme defaults if not specified.
    pub fn effectivePort(self: Self) u16 {
        if (self.port) |p| return p;
        if (self.scheme) |s| {
            if (mem.eql(u8, s, "https")) return 443;
            if (mem.eql(u8, s, "http")) return 80;
            if (mem.eql(u8, s, "ws")) return 80;
            if (mem.eql(u8, s, "wss")) return 443;
            if (mem.eql(u8, s, "ftp")) return 21;
        }
        return 80;
    }

    /// Returns true if the scheme requires TLS.
    pub fn isTls(self: Self) bool {
        if (self.scheme) |s| {
            return mem.eql(u8, s, "https") or mem.eql(u8, s, "wss");
        }
        return false;
    }

    /// Returns true if this is a WebSocket URI.
    pub fn isWebSocket(self: Self) bool {
        if (self.scheme) |s| {
            return mem.eql(u8, s, "ws") or mem.eql(u8, s, "wss");
        }
        return false;
    }

    /// Builds the request path including query string.
    pub fn requestPath(self: Self, allocator: Allocator) ![]u8 {
        if (self.query) |q| {
            return std.fmt.allocPrint(allocator, "{s}?{s}", .{ self.path, q });
        }
        return allocator.dupe(u8, self.path);
    }

    /// Normalizes the path by removing dot segments (. and ..) per RFC 3986 Section 5.2.4.
    pub fn normalizePath(self: *Self, allocator: Allocator) !void {
        const normalized = try removeDotSegments(allocator, self.path);
        self.path = normalized;
    }

    /// Reconstructs the full URI string.
    pub fn format(self: Self, allocator: Allocator) ![]u8 {
        var buffer = std.ArrayListUnmanaged(u8){};
        const writer = buffer.writer(allocator);

        if (self.scheme) |s| try writer.print("{s}://", .{s});
        if (self.userinfo) |u| try writer.print("{s}@", .{u});
        if (self.host) |h| {
            if (self.is_ipv6_host) {
                try writer.print("[{s}]", .{h});
            } else {
                try writer.print("{s}", .{h});
            }
        }
        if (self.port) |p| try writer.print(":{d}", .{p});
        try writer.print("{s}", .{self.path});
        if (self.query) |q| try writer.print("?{s}", .{q});
        if (self.fragment) |f| try writer.print("#{s}", .{f});

        return buffer.toOwnedSlice(allocator);
    }

    /// Returns the authority component (userinfo@host:port).
    pub fn authority(self: Self, allocator: Allocator) ![]u8 {
        var buffer = std.ArrayListUnmanaged(u8){};
        const writer = buffer.writer(allocator);

        if (self.userinfo) |u| try writer.print("{s}@", .{u});
        if (self.host) |h| {
            if (self.is_ipv6_host) {
                try writer.print("[{s}]", .{h});
            } else {
                try writer.print("{s}", .{h});
            }
        }
        if (self.port) |p| try writer.print(":{d}", .{p});

        return buffer.toOwnedSlice(allocator);
    }
};

/// Characters that don't need percent encoding in URIs.
const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

/// Percent-encodes a string for URI inclusion.
pub fn encode(allocator: Allocator, input: []const u8) ![]u8 {
    var result = std.ArrayListUnmanaged(u8){};
    const writer = result.writer(allocator);

    for (input) |c| {
        if (mem.indexOfScalar(u8, unreserved, c) != null) {
            try writer.writeByte(c);
        } else {
            try writer.print("%{X:0>2}", .{c});
        }
    }

    return result.toOwnedSlice(allocator);
}

/// Decodes a percent-encoded string (RFC 3986).
/// Note: Does NOT decode '+' as space. Use decodeFormUrlencoded for that.
pub fn decode(allocator: Allocator, input: []const u8) ![]u8 {
    var result = std.ArrayListUnmanaged(u8){};

    var i: usize = 0;
    while (i < input.len) {
        if (input[i] == '%' and i + 2 < input.len) {
            const hex = input[i + 1 .. i + 3];
            if (std.fmt.parseInt(u8, hex, 16)) |byte| {
                try result.append(allocator, byte);
                i += 3;
                continue;
            } else |_| {}
        }
        try result.append(allocator, input[i]);
        i += 1;
    }

    return result.toOwnedSlice(allocator);
}

/// Decodes a form-urlencoded string (application/x-www-form-urlencoded).
/// Treats '+' as space, unlike RFC 3986 percent-encoding.
pub fn decodeFormUrlencoded(allocator: Allocator, input: []const u8) ![]u8 {
    var result = std.ArrayListUnmanaged(u8){};

    var i: usize = 0;
    while (i < input.len) {
        if (input[i] == '%' and i + 2 < input.len) {
            const hex = input[i + 1 .. i + 3];
            if (std.fmt.parseInt(u8, hex, 16)) |byte| {
                try result.append(allocator, byte);
                i += 3;
                continue;
            } else |_| {}
        }
        if (input[i] == '+') {
            try result.append(allocator, ' ');
        } else {
            try result.append(allocator, input[i]);
        }
        i += 1;
    }

    return result.toOwnedSlice(allocator);
}

/// Encodes query parameters as a query string.
pub fn encodeQueryParams(allocator: Allocator, params: []const struct { []const u8, []const u8 }) ![]u8 {
    var result = std.ArrayListUnmanaged(u8){};
    const writer = result.writer(allocator);

    for (params, 0..) |param, idx| {
        if (idx > 0) try writer.writeByte('&');
        const key = try encode(allocator, param[0]);
        defer allocator.free(key);
        const value = try encode(allocator, param[1]);
        defer allocator.free(value);
        try writer.print("{s}={s}", .{ key, value });
    }

    return result.toOwnedSlice(allocator);
}

/// Removes dot segments from a path per RFC 3986 Section 5.2.4.
/// Handles "." (current directory) and ".." (parent directory) segments.
pub fn removeDotSegments(allocator: Allocator, path: []const u8) ![]u8 {
    var output = std.ArrayListUnmanaged(u8){};
    var input = path;

    while (input.len > 0) {
        // A: Remove prefix "../" or "./"
        if (mem.startsWith(u8, input, "../")) {
            input = input[3..];
            continue;
        }
        if (mem.startsWith(u8, input, "./")) {
            input = input[2..];
            continue;
        }

        // B: Remove prefix "/./" or "/." at end
        if (mem.startsWith(u8, input, "/./")) {
            input = input[2..];
            continue;
        }
        if (mem.eql(u8, input, "/.")) {
            break; // Nothing left to process
        }

        // C: Remove prefix "/../" or "/.." at end, and remove last output segment
        if (mem.startsWith(u8, input, "/../")) {
            input = input[3..];
            removeLastSegment(&output);
            continue;
        }
        if (mem.eql(u8, input, "/..")) {
            removeLastSegment(&output);
            break; // Nothing left to process
        }

        // D: Remove "." or ".." if that's all that's left
        if (mem.eql(u8, input, ".") or mem.eql(u8, input, "..")) {
            break;
        }

        // E: Move first path segment (including initial "/" if any) to output
        var seg_end: usize = 0;
        if (input[0] == '/') {
            seg_end = 1;
        }
        while (seg_end < input.len and input[seg_end] != '/') {
            seg_end += 1;
        }
        try output.appendSlice(allocator, input[0..seg_end]);
        input = input[seg_end..];
    }

    // Ensure path starts with "/" if it was originally absolute
    if (output.items.len == 0 and path.len > 0 and path[0] == '/') {
        try output.append(allocator, '/');
    }

    return output.toOwnedSlice(allocator);
}

/// Helper to remove the last segment from output buffer (for ".." handling).
fn removeLastSegment(output: *std.ArrayListUnmanaged(u8)) void {
    if (output.items.len == 0) return;

    // Find the last "/" and truncate there
    var i = output.items.len;
    while (i > 0) {
        i -= 1;
        if (output.items[i] == '/') {
            output.items.len = i;
            return;
        }
    }
    // No "/" found, clear everything
    output.items.len = 0;
}

test "URI parsing basic" {
    const uri = try Uri.parse("https://example.com/path");
    try std.testing.expectEqualStrings("https", uri.scheme.?);
    try std.testing.expectEqualStrings("example.com", uri.host.?);
    try std.testing.expectEqualStrings("/path", uri.path);
}

test "URI parsing with port" {
    const uri = try Uri.parse("http://localhost:8080/api");
    try std.testing.expectEqualStrings("localhost", uri.host.?);
    try std.testing.expectEqual(@as(u16, 8080), uri.port.?);
}

test "URI parsing with query and fragment" {
    const uri = try Uri.parse("https://example.com/search?q=test#results");
    try std.testing.expectEqualStrings("q=test", uri.query.?);
    try std.testing.expectEqualStrings("results", uri.fragment.?);
}

test "URI effective port" {
    const https = try Uri.parse("https://example.com/");
    try std.testing.expectEqual(@as(u16, 443), https.effectivePort());

    const http = try Uri.parse("http://example.com/");
    try std.testing.expectEqual(@as(u16, 80), http.effectivePort());
}

test "URI TLS detection" {
    const https = try Uri.parse("https://example.com/");
    try std.testing.expect(https.isTls());

    const http = try Uri.parse("http://example.com/");
    try std.testing.expect(!http.isTls());
}

test "Percent encoding" {
    const allocator = std.testing.allocator;

    const encoded = try encode(allocator, "hello world");
    defer allocator.free(encoded);
    try std.testing.expectEqualStrings("hello%20world", encoded);
}

test "Percent decoding" {
    const allocator = std.testing.allocator;

    const decoded = try decode(allocator, "hello%20world");
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("hello world", decoded);
}

test "Percent decoding preserves plus sign (RFC 3986)" {
    const allocator = std.testing.allocator;

    const decoded = try decode(allocator, "hello+world");
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("hello+world", decoded);
}

test "Form URL decoding converts plus to space" {
    const allocator = std.testing.allocator;

    const decoded = try decodeFormUrlencoded(allocator, "hello+world");
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("hello world", decoded);
}

test "URI parsing IPv6 address" {
    const uri = try Uri.parse("http://[::1]:8080/path");
    try std.testing.expectEqualStrings("::1", uri.host.?);
    try std.testing.expectEqual(@as(u16, 8080), uri.port.?);
    try std.testing.expect(uri.is_ipv6_host);
}

test "URI parsing IPv6 address without port" {
    const uri = try Uri.parse("http://[2001:db8::1]/path");
    try std.testing.expectEqualStrings("2001:db8::1", uri.host.?);
    try std.testing.expectEqual(@as(?u16, null), uri.port);
    try std.testing.expect(uri.is_ipv6_host);
}

test "URI format IPv6 address" {
    const allocator = std.testing.allocator;

    const uri = try Uri.parse("http://[::1]:8080/path");
    const formatted = try uri.format(allocator);
    defer allocator.free(formatted);
    try std.testing.expectEqualStrings("http://[::1]:8080/path", formatted);
}

test "Remove dot segments - RFC 3986 examples" {
    const allocator = std.testing.allocator;

    // RFC 3986 Section 5.2.4 examples
    const t1 = try removeDotSegments(allocator, "/a/b/c/./../../g");
    defer allocator.free(t1);
    try std.testing.expectEqualStrings("/a/g", t1);

    const t2 = try removeDotSegments(allocator, "mid/content=5/../6");
    defer allocator.free(t2);
    try std.testing.expectEqualStrings("mid/6", t2);

    const t3 = try removeDotSegments(allocator, "/a/b/../../../g");
    defer allocator.free(t3);
    try std.testing.expectEqualStrings("/g", t3);
}

test "Remove dot segments - edge cases" {
    const allocator = std.testing.allocator;

    // Single dot
    const t1 = try removeDotSegments(allocator, "/./a");
    defer allocator.free(t1);
    try std.testing.expectEqualStrings("/a", t1);

    // Double dot at end
    const t2 = try removeDotSegments(allocator, "/a/b/..");
    defer allocator.free(t2);
    try std.testing.expectEqualStrings("/a", t2);

    // Empty path
    const t3 = try removeDotSegments(allocator, "");
    defer allocator.free(t3);
    try std.testing.expectEqualStrings("", t3);

    // Root only
    const t4 = try removeDotSegments(allocator, "/");
    defer allocator.free(t4);
    try std.testing.expectEqualStrings("/", t4);
}

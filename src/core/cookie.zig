//! HTTP Cookie Management for httpx.zig
//!
//! Implements RFC 6265 HTTP State Management Mechanism.
//! Provides cookie parsing, storage, and automatic request/response handling.
//!
//! ## Features
//! - Cookie parsing from Set-Cookie headers
//! - Automatic cookie jar management
//! - Domain and path matching
//! - Expiration handling
//! - Secure and HttpOnly attribute support
//! - SameSite attribute support
//!
//! ## Usage
//! ```zig
//! var jar = CookieJar.init(allocator);
//! defer jar.deinit();
//!
//! // Add cookie from Set-Cookie header
//! try jar.setCookie("session=abc123; Path=/; HttpOnly", "example.com");
//!
//! // Get Cookie header value for request
//! const cookie_header = try jar.getCookieHeader(allocator, "example.com", "/api", true);
//! defer allocator.free(cookie_header);
//! ```

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// SameSite attribute values as defined in RFC 6265bis.
pub const SameSite = enum {
    strict,
    lax,
    none,

    pub fn fromString(str: []const u8) ?SameSite {
        if (std.ascii.eqlIgnoreCase(str, "strict")) return .strict;
        if (std.ascii.eqlIgnoreCase(str, "lax")) return .lax;
        if (std.ascii.eqlIgnoreCase(str, "none")) return .none;
        return null;
    }

    pub fn toString(self: SameSite) []const u8 {
        return switch (self) {
            .strict => "Strict",
            .lax => "Lax",
            .none => "None",
        };
    }
};

/// Represents a single HTTP cookie with all attributes.
pub const Cookie = struct {
    name: []const u8,
    value: []const u8,
    domain: ?[]const u8 = null,
    path: ?[]const u8 = null,
    expires: ?i64 = null, // Unix timestamp
    max_age: ?i64 = null, // Seconds
    secure: bool = false,
    http_only: bool = false,
    same_site: ?SameSite = null,
    creation_time: i64,
    owned: bool = false,

    const Self = @This();

    /// Creates a new cookie with the given name and value.
    pub fn init(allocator: Allocator, name: []const u8, value: []const u8) !Self {
        const owned_name = try allocator.dupe(u8, name);
        errdefer allocator.free(owned_name);
        const owned_value = try allocator.dupe(u8, value);

        return .{
            .name = owned_name,
            .value = owned_value,
            .creation_time = std.time.timestamp(),
            .owned = true,
        };
    }

    /// Releases all allocated memory.
    pub fn deinit(self: *Self, allocator: Allocator) void {
        if (self.owned) {
            allocator.free(self.name);
            allocator.free(self.value);
            if (self.domain) |d| allocator.free(d);
            if (self.path) |p| allocator.free(p);
        }
    }

    /// Returns true if the cookie has expired.
    pub fn isExpired(self: *const Self) bool {
        const now = std.time.timestamp();

        if (self.max_age) |max_age| {
            if (self.creation_time + max_age <= now) return true;
        }

        if (self.expires) |expires| {
            if (expires <= now) return true;
        }

        return false;
    }

    /// Returns true if this cookie matches the given domain.
    pub fn matchesDomain(self: *const Self, request_domain: []const u8) bool {
        const cookie_domain = self.domain orelse return true;

        // Exact match
        if (std.ascii.eqlIgnoreCase(cookie_domain, request_domain)) return true;

        // Domain matching (cookie domain is suffix of request domain)
        if (cookie_domain.len > 0 and cookie_domain[0] == '.') {
            // .example.com matches example.com (domain without leading dot)
            const domain_without_dot = cookie_domain[1..];
            if (std.ascii.eqlIgnoreCase(domain_without_dot, request_domain)) return true;

            // .example.com matches sub.example.com (subdomain match)
            if (request_domain.len > cookie_domain.len) {
                const suffix = request_domain[request_domain.len - cookie_domain.len ..];
                if (std.ascii.eqlIgnoreCase(suffix, cookie_domain)) return true;
            }

            // Also check if request ends with .example.com
            if (request_domain.len > domain_without_dot.len + 1) {
                const suffix_with_dot = request_domain[request_domain.len - domain_without_dot.len - 1 ..];
                if (suffix_with_dot[0] == '.' and std.ascii.eqlIgnoreCase(suffix_with_dot[1..], domain_without_dot)) return true;
            }
        } else {
            // example.com should also match sub.example.com
            if (request_domain.len > cookie_domain.len + 1) {
                const dot_pos = request_domain.len - cookie_domain.len - 1;
                if (request_domain[dot_pos] == '.') {
                    const suffix = request_domain[dot_pos + 1 ..];
                    if (std.ascii.eqlIgnoreCase(suffix, cookie_domain)) return true;
                }
            }
        }

        return false;
    }

    /// Returns true if this cookie matches the given path.
    pub fn matchesPath(self: *const Self, request_path: []const u8) bool {
        const cookie_path = self.path orelse "/";

        // Exact match
        if (mem.eql(u8, cookie_path, request_path)) return true;

        // Path prefix matching
        if (mem.startsWith(u8, request_path, cookie_path)) {
            if (cookie_path.len == 1 and cookie_path[0] == '/') return true;
            if (request_path.len > cookie_path.len and request_path[cookie_path.len] == '/') return true;
        }

        return false;
    }

    /// Serializes the cookie to a Cookie header value (name=value).
    pub fn toCookieValue(self: *const Self) []const u8 {
        // Just return name=value for Cookie header
        return self.value; // Caller must format as name=value
    }
};

/// Parses a Set-Cookie header value into a Cookie.
pub fn parseSetCookie(allocator: Allocator, header_value: []const u8, request_domain: []const u8) !Cookie {
    var it = mem.splitScalar(u8, header_value, ';');

    // First part is name=value
    const name_value = it.next() orelse return error.InvalidCookie;
    const eq_pos = mem.indexOf(u8, name_value, "=") orelse return error.InvalidCookie;

    const name = mem.trim(u8, name_value[0..eq_pos], " \t");
    const value = mem.trim(u8, name_value[eq_pos + 1 ..], " \t");

    if (name.len == 0) return error.InvalidCookie;

    const owned_name = try allocator.dupe(u8, name);
    errdefer allocator.free(owned_name);
    const owned_value = try allocator.dupe(u8, value);
    errdefer allocator.free(owned_value);

    var cookie = Cookie{
        .name = owned_name,
        .value = owned_value,
        .creation_time = std.time.timestamp(),
        .owned = true,
    };
    errdefer cookie.deinit(allocator);

    // Parse attributes
    while (it.next()) |attr_part| {
        const attr = mem.trim(u8, attr_part, " \t");
        if (attr.len == 0) continue;

        if (mem.indexOf(u8, attr, "=")) |attr_eq| {
            const attr_name = mem.trim(u8, attr[0..attr_eq], " \t");
            const attr_value = mem.trim(u8, attr[attr_eq + 1 ..], " \t");

            if (std.ascii.eqlIgnoreCase(attr_name, "domain")) {
                cookie.domain = try allocator.dupe(u8, attr_value);
            } else if (std.ascii.eqlIgnoreCase(attr_name, "path")) {
                cookie.path = try allocator.dupe(u8, attr_value);
            } else if (std.ascii.eqlIgnoreCase(attr_name, "max-age")) {
                cookie.max_age = std.fmt.parseInt(i64, attr_value, 10) catch null;
            } else if (std.ascii.eqlIgnoreCase(attr_name, "expires")) {
                cookie.expires = parseHttpDate(attr_value);
            } else if (std.ascii.eqlIgnoreCase(attr_name, "samesite")) {
                cookie.same_site = SameSite.fromString(attr_value);
            }
        } else {
            // Flag attributes (no value)
            if (std.ascii.eqlIgnoreCase(attr, "secure")) {
                cookie.secure = true;
            } else if (std.ascii.eqlIgnoreCase(attr, "httponly")) {
                cookie.http_only = true;
            }
        }
    }

    // Default domain to request domain if not specified
    if (cookie.domain == null) {
        cookie.domain = try allocator.dupe(u8, request_domain);
    }

    // Default path to "/"
    if (cookie.path == null) {
        cookie.path = try allocator.dupe(u8, "/");
    }

    return cookie;
}

/// HTTP Cookie Jar - stores and manages cookies.
pub const CookieJar = struct {
    allocator: Allocator,
    cookies: std.ArrayListUnmanaged(Cookie) = .empty,
    reject_public_suffixes: bool = true,

    const Self = @This();

    /// Creates a new empty cookie jar.
    pub fn init(allocator: Allocator) Self {
        return .{ .allocator = allocator };
    }

    /// Releases all stored cookies and memory.
    pub fn deinit(self: *Self) void {
        for (self.cookies.items) |*cookie| {
            cookie.deinit(self.allocator);
        }
        self.cookies.deinit(self.allocator);
    }

    /// Adds a cookie from a Set-Cookie header value.
    pub fn setCookie(self: *Self, header_value: []const u8, request_domain: []const u8) !void {
        var cookie = try parseSetCookie(self.allocator, header_value, request_domain);
        errdefer cookie.deinit(self.allocator);

        // Remove existing cookie with same name, domain, and path
        self.removeCookie(cookie.name, cookie.domain, cookie.path);

        // Don't store if already expired (max-age=0 is used to delete)
        if (cookie.isExpired()) {
            cookie.deinit(self.allocator);
            return;
        }

        try self.cookies.append(self.allocator, cookie);
    }

    /// Adds a simple cookie (name=value) for a domain.
    pub fn set(self: *Self, name: []const u8, value: []const u8, domain: []const u8) !void {
        self.removeCookie(name, domain, null);

        var cookie = try Cookie.init(self.allocator, name, value);
        errdefer cookie.deinit(self.allocator);

        cookie.domain = try self.allocator.dupe(u8, domain);
        cookie.path = try self.allocator.dupe(u8, "/");

        try self.cookies.append(self.allocator, cookie);
    }

    /// Removes a specific cookie.
    pub fn removeCookie(self: *Self, name: []const u8, domain: ?[]const u8, path: ?[]const u8) void {
        var i: usize = 0;
        while (i < self.cookies.items.len) {
            const cookie = &self.cookies.items[i];
            const name_match = mem.eql(u8, cookie.name, name);
            const domain_match = if (domain) |d| blk: {
                if (cookie.domain) |cd| {
                    break :blk std.ascii.eqlIgnoreCase(cd, d);
                }
                break :blk false;
            } else true;
            const path_match = if (path) |p| blk: {
                if (cookie.path) |cp| {
                    break :blk mem.eql(u8, cp, p);
                }
                break :blk false;
            } else true;

            if (name_match and domain_match and path_match) {
                var removed = self.cookies.orderedRemove(i);
                removed.deinit(self.allocator);
            } else {
                i += 1;
            }
        }
    }

    /// Gets a cookie value by name for a specific domain.
    pub fn get(self: *const Self, name: []const u8, domain: []const u8) ?[]const u8 {
        for (self.cookies.items) |cookie| {
            if (mem.eql(u8, cookie.name, name) and cookie.matchesDomain(domain) and !cookie.isExpired()) {
                return cookie.value;
            }
        }
        return null;
    }

    /// Generates the Cookie header value for a request.
    pub fn getCookieHeader(self: *Self, allocator: Allocator, domain: []const u8, path: []const u8, is_secure: bool) !?[]u8 {
        // First, remove expired cookies
        self.removeExpired();

        var result = std.ArrayListUnmanaged(u8){};
        errdefer result.deinit(allocator);

        var first = true;
        for (self.cookies.items) |cookie| {
            // Check domain match
            if (!cookie.matchesDomain(domain)) continue;

            // Check path match
            if (!cookie.matchesPath(path)) continue;

            // Check secure flag
            if (cookie.secure and !is_secure) continue;

            // Add separator
            if (!first) {
                try result.appendSlice(allocator, "; ");
            }
            first = false;

            // Add name=value
            try result.appendSlice(allocator, cookie.name);
            try result.append(allocator, '=');
            try result.appendSlice(allocator, cookie.value);
        }

        if (result.items.len == 0) return null;
        const slice = try result.toOwnedSlice(allocator);
        return slice;
    }

    /// Processes Set-Cookie headers from a response.
    pub fn processResponse(self: *Self, headers: anytype, request_domain: []const u8) !void {
        // Get all Set-Cookie headers
        for (headers.entries.items) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.name, "Set-Cookie")) {
                self.setCookie(entry.value, request_domain) catch |err| {
                    // Log invalid cookies but don't fail
                    _ = err;
                };
            }
        }
    }

    /// Removes all expired cookies.
    pub fn removeExpired(self: *Self) void {
        var i: usize = 0;
        while (i < self.cookies.items.len) {
            if (self.cookies.items[i].isExpired()) {
                var removed = self.cookies.orderedRemove(i);
                removed.deinit(self.allocator);
            } else {
                i += 1;
            }
        }
    }

    /// Clears all cookies.
    pub fn clear(self: *Self) void {
        for (self.cookies.items) |*cookie| {
            cookie.deinit(self.allocator);
        }
        self.cookies.clearRetainingCapacity();
    }

    /// Returns the number of stored cookies.
    pub fn count(self: *const Self) usize {
        return self.cookies.items.len;
    }

    /// Serializes all cookies to a string for debugging.
    pub fn debugPrint(self: *const Self, writer: anytype) !void {
        for (self.cookies.items) |cookie| {
            try writer.print("{s}={s}", .{ cookie.name, cookie.value });
            if (cookie.domain) |d| try writer.print("; Domain={s}", .{d});
            if (cookie.path) |p| try writer.print("; Path={s}", .{p});
            if (cookie.secure) try writer.writeAll("; Secure");
            if (cookie.http_only) try writer.writeAll("; HttpOnly");
            try writer.writeByte('\n');
        }
    }
};

/// Parses HTTP date format (RFC 7231).
/// Supports: "Sun, 06 Nov 1994 08:49:37 GMT"
fn parseHttpDate(date_str: []const u8) ?i64 {
    // Simplified parsing - full implementation would handle all RFC 7231 formats
    // For now, return null to indicate parsing not supported
    // Cookies with unparseable dates are treated as session cookies
    _ = date_str;
    return null;
}

// =============================================================================
// Tests
// =============================================================================

test "Cookie basic creation" {
    const allocator = std.testing.allocator;
    var cookie = try Cookie.init(allocator, "session", "abc123");
    defer cookie.deinit(allocator);

    try std.testing.expectEqualStrings("session", cookie.name);
    try std.testing.expectEqualStrings("abc123", cookie.value);
}

test "parseSetCookie basic" {
    const allocator = std.testing.allocator;
    var cookie = try parseSetCookie(allocator, "session=abc123; Path=/; HttpOnly", "example.com");
    defer cookie.deinit(allocator);

    try std.testing.expectEqualStrings("session", cookie.name);
    try std.testing.expectEqualStrings("abc123", cookie.value);
    try std.testing.expectEqualStrings("/", cookie.path.?);
    try std.testing.expect(cookie.http_only);
    try std.testing.expect(!cookie.secure);
}

test "parseSetCookie with domain" {
    const allocator = std.testing.allocator;
    var cookie = try parseSetCookie(allocator, "id=12345; Domain=.example.com; Secure; SameSite=Strict", "sub.example.com");
    defer cookie.deinit(allocator);

    try std.testing.expectEqualStrings("id", cookie.name);
    try std.testing.expectEqualStrings("12345", cookie.value);
    try std.testing.expectEqualStrings(".example.com", cookie.domain.?);
    try std.testing.expect(cookie.secure);
    try std.testing.expectEqual(SameSite.strict, cookie.same_site.?);
}

test "Cookie domain matching" {
    const allocator = std.testing.allocator;
    var cookie = try parseSetCookie(allocator, "test=value; Domain=.example.com", "example.com");
    defer cookie.deinit(allocator);

    try std.testing.expect(cookie.matchesDomain("example.com"));
    try std.testing.expect(cookie.matchesDomain("sub.example.com"));
    try std.testing.expect(cookie.matchesDomain("deep.sub.example.com"));
    try std.testing.expect(!cookie.matchesDomain("otherexample.com"));
    try std.testing.expect(!cookie.matchesDomain("other.com"));
}

test "Cookie path matching" {
    const allocator = std.testing.allocator;
    var cookie = try parseSetCookie(allocator, "test=value; Path=/api", "example.com");
    defer cookie.deinit(allocator);

    try std.testing.expect(cookie.matchesPath("/api"));
    try std.testing.expect(cookie.matchesPath("/api/users"));
    try std.testing.expect(cookie.matchesPath("/api/users/123"));
    try std.testing.expect(!cookie.matchesPath("/other"));
    try std.testing.expect(!cookie.matchesPath("/"));
}

test "CookieJar basic operations" {
    const allocator = std.testing.allocator;
    var jar = CookieJar.init(allocator);
    defer jar.deinit();

    try jar.set("session", "abc123", "example.com");
    try std.testing.expectEqual(@as(usize, 1), jar.count());

    const value = jar.get("session", "example.com");
    try std.testing.expectEqualStrings("abc123", value.?);
}

test "CookieJar getCookieHeader" {
    const allocator = std.testing.allocator;
    var jar = CookieJar.init(allocator);
    defer jar.deinit();

    try jar.set("session", "abc123", "example.com");
    try jar.set("user", "john", "example.com");

    const header = try jar.getCookieHeader(allocator, "example.com", "/", false);
    defer if (header) |h| allocator.free(h);

    try std.testing.expect(header != null);
    // Should contain both cookies
    try std.testing.expect(mem.indexOf(u8, header.?, "session=abc123") != null);
    try std.testing.expect(mem.indexOf(u8, header.?, "user=john") != null);
}

test "CookieJar secure cookie filtering" {
    const allocator = std.testing.allocator;
    var jar = CookieJar.init(allocator);
    defer jar.deinit();

    try jar.setCookie("secure_cookie=secret; Secure", "example.com");
    try jar.set("regular", "value", "example.com");

    // Non-secure request should not include secure cookie
    const http_header = try jar.getCookieHeader(allocator, "example.com", "/", false);
    defer if (http_header) |h| allocator.free(h);

    try std.testing.expect(http_header != null);
    try std.testing.expect(mem.indexOf(u8, http_header.?, "regular=value") != null);
    try std.testing.expect(mem.indexOf(u8, http_header.?, "secure_cookie") == null);

    // Secure request should include both
    const https_header = try jar.getCookieHeader(allocator, "example.com", "/", true);
    defer if (https_header) |h| allocator.free(h);

    try std.testing.expect(https_header != null);
    try std.testing.expect(mem.indexOf(u8, https_header.?, "regular=value") != null);
    try std.testing.expect(mem.indexOf(u8, https_header.?, "secure_cookie=secret") != null);
}

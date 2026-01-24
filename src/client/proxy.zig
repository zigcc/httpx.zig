//! HTTP Proxy Support for httpx.zig
//!
//! Implements HTTP proxy tunneling including:
//! - HTTP CONNECT method for HTTPS tunneling (RFC 7231)
//! - Basic/Digest proxy authentication
//! - SOCKS5 proxy support (basic)
//!
//! ## Usage
//! ```zig
//! const proxy = @import("client/proxy.zig");
//!
//! var config = ProxyConfig{
//!     .host = "proxy.example.com",
//!     .port = 8080,
//!     .username = "user",
//!     .password = "pass",
//! };
//!
//! var tunnel = try ProxyTunnel.connect(allocator, config, "target.com", 443);
//! defer tunnel.deinit();
//! ```

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const Socket = @import("../net/socket.zig").Socket;
const address_mod = @import("../net/address.zig");
const types = @import("../core/types.zig");
const HttpError = types.HttpError;
const auth = @import("../core/auth.zig");

/// Proxy type enumeration.
pub const ProxyType = enum {
    http,
    https,
    socks5,
};

/// Proxy configuration.
pub const ProxyConfig = struct {
    proxy_type: ProxyType = .http,
    host: []const u8,
    port: u16,
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,
    no_proxy: ?[]const []const u8 = null, // Hosts to bypass proxy

    /// Checks if the given host should bypass the proxy.
    pub fn shouldBypass(self: *const ProxyConfig, target_host: []const u8) bool {
        const no_proxy_list = self.no_proxy orelse return false;

        for (no_proxy_list) |pattern| {
            // Exact match
            if (std.ascii.eqlIgnoreCase(pattern, target_host)) return true;

            // Wildcard suffix match (*.example.com)
            if (pattern.len > 1 and pattern[0] == '*' and pattern[1] == '.') {
                const suffix = pattern[1..]; // .example.com
                if (target_host.len >= suffix.len) {
                    const host_suffix = target_host[target_host.len - suffix.len ..];
                    if (std.ascii.eqlIgnoreCase(suffix, host_suffix)) return true;
                }
            }

            // Localhost variants
            if (std.ascii.eqlIgnoreCase(pattern, "localhost") or mem.eql(u8, pattern, "127.0.0.1")) {
                if (std.ascii.eqlIgnoreCase(target_host, "localhost") or mem.eql(u8, target_host, "127.0.0.1")) {
                    return true;
                }
            }
        }

        return false;
    }
};

/// HTTP CONNECT tunnel through a proxy.
pub const ProxyTunnel = struct {
    allocator: Allocator,
    socket: Socket,
    target_host: []const u8,
    target_port: u16,

    const Self = @This();

    /// Establishes a tunnel through an HTTP proxy using CONNECT method.
    pub fn connect(
        allocator: Allocator,
        config: ProxyConfig,
        target_host: []const u8,
        target_port: u16,
    ) !Self {
        // Connect to proxy server
        const proxy_addr = try address_mod.resolve(config.host, config.port);
        var socket = try Socket.createForAddress(proxy_addr);
        errdefer socket.close();

        try socket.connect(proxy_addr);

        // Send CONNECT request
        var request_buf: [1024]u8 = undefined;
        const request = try std.fmt.bufPrint(&request_buf, "CONNECT {s}:{d} HTTP/1.1\r\nHost: {s}:{d}\r\n", .{
            target_host,
            target_port,
            target_host,
            target_port,
        });

        // Add proxy authentication if provided
        var auth_header_buf: [256]u8 = undefined;
        var auth_len: usize = 0;

        if (config.username) |user| {
            if (config.password) |pass| {
                const auth_value = try auth.basicAuth(allocator, user, pass);
                defer allocator.free(auth_value);

                auth_len = (std.fmt.bufPrint(&auth_header_buf, "Proxy-Authorization: {s}\r\n", .{auth_value}) catch return HttpError.BufferTooSmall).len;
            }
        }

        // Send request
        try socket.sendAll(request);
        if (auth_len > 0) {
            try socket.sendAll(auth_header_buf[0..auth_len]);
        }
        try socket.sendAll("\r\n");

        // Read response
        var response_buf: [1024]u8 = undefined;
        const n = try socket.recv(&response_buf);
        if (n == 0) return HttpError.ConnectionClosed;

        const response = response_buf[0..n];

        // Parse status line
        const status_line_end = mem.indexOf(u8, response, "\r\n") orelse return HttpError.InvalidResponse;
        const status_line = response[0..status_line_end];

        // Extract status code
        var parts = mem.splitScalar(u8, status_line, ' ');
        _ = parts.next(); // HTTP/1.x
        const status_str = parts.next() orelse return HttpError.InvalidResponse;
        const status_code = std.fmt.parseInt(u16, status_str, 10) catch return HttpError.InvalidResponse;

        if (status_code == 407) {
            // Proxy Authentication Required
            return HttpError.ProxyAuthenticationRequired;
        }

        if (status_code < 200 or status_code >= 300) {
            return HttpError.ProxyError;
        }

        // Tunnel established
        return .{
            .allocator = allocator,
            .socket = socket,
            .target_host = target_host,
            .target_port = target_port,
        };
    }

    /// Returns the underlying socket for further communication.
    pub fn getSocket(self: *Self) *Socket {
        return &self.socket;
    }

    /// Closes the tunnel.
    pub fn deinit(self: *Self) void {
        self.socket.close();
    }
};

/// Parses proxy URL (e.g., "http://user:pass@proxy:8080").
pub fn parseProxyUrl(url: []const u8) ?ProxyConfig {
    var config = ProxyConfig{
        .host = undefined,
        .port = 0,
    };

    var remaining = url;

    // Parse scheme
    if (mem.startsWith(u8, remaining, "http://")) {
        config.proxy_type = .http;
        remaining = remaining[7..];
        config.port = 80;
    } else if (mem.startsWith(u8, remaining, "https://")) {
        config.proxy_type = .https;
        remaining = remaining[8..];
        config.port = 443;
    } else if (mem.startsWith(u8, remaining, "socks5://")) {
        config.proxy_type = .socks5;
        remaining = remaining[9..];
        config.port = 1080;
    } else {
        config.proxy_type = .http;
        config.port = 80;
    }

    // Parse username:password@
    if (mem.indexOf(u8, remaining, "@")) |at_pos| {
        const auth_part = remaining[0..at_pos];
        remaining = remaining[at_pos + 1 ..];

        if (mem.indexOf(u8, auth_part, ":")) |colon_pos| {
            config.username = auth_part[0..colon_pos];
            config.password = auth_part[colon_pos + 1 ..];
        } else {
            config.username = auth_part;
        }
    }

    // Parse host:port
    if (mem.indexOf(u8, remaining, ":")) |colon_pos| {
        config.host = remaining[0..colon_pos];
        config.port = std.fmt.parseInt(u16, remaining[colon_pos + 1 ..], 10) catch return null;
    } else {
        config.host = remaining;
    }

    if (config.host.len == 0) return null;

    return config;
}

/// Parses NO_PROXY environment variable format.
pub fn parseNoProxy(allocator: Allocator, no_proxy_str: []const u8) ![][]const u8 {
    var list = std.ArrayListUnmanaged([]const u8){};
    errdefer list.deinit(allocator);

    var it = mem.splitAny(u8, no_proxy_str, ", ");
    while (it.next()) |part| {
        const trimmed = mem.trim(u8, part, " \t");
        if (trimmed.len > 0) {
            try list.append(allocator, trimmed);
        }
    }

    return list.toOwnedSlice(allocator);
}

/// Gets proxy configuration from environment variables.
pub fn getProxyFromEnv(allocator: Allocator, is_https: bool) !?ProxyConfig {
    const env_var = if (is_https) "HTTPS_PROXY" else "HTTP_PROXY";
    const env_var_lower = if (is_https) "https_proxy" else "http_proxy";

    const proxy_url = std.posix.getenv(env_var) orelse std.posix.getenv(env_var_lower) orelse return null;

    var config = parseProxyUrl(proxy_url) orelse return null;

    // Parse NO_PROXY
    if (std.posix.getenv("NO_PROXY") orelse std.posix.getenv("no_proxy")) |no_proxy| {
        const list = try parseNoProxy(allocator, no_proxy);
        config.no_proxy = list;
    }

    return config;
}

// =============================================================================
// Tests
// =============================================================================

test "parseProxyUrl basic" {
    const config = parseProxyUrl("http://proxy.example.com:8080").?;
    try std.testing.expectEqualStrings("proxy.example.com", config.host);
    try std.testing.expectEqual(@as(u16, 8080), config.port);
    try std.testing.expectEqual(ProxyType.http, config.proxy_type);
    try std.testing.expect(config.username == null);
}

test "parseProxyUrl with auth" {
    const config = parseProxyUrl("http://user:pass@proxy.example.com:8080").?;
    try std.testing.expectEqualStrings("proxy.example.com", config.host);
    try std.testing.expectEqual(@as(u16, 8080), config.port);
    try std.testing.expectEqualStrings("user", config.username.?);
    try std.testing.expectEqualStrings("pass", config.password.?);
}

test "parseProxyUrl socks5" {
    const config = parseProxyUrl("socks5://localhost:1080").?;
    try std.testing.expectEqualStrings("localhost", config.host);
    try std.testing.expectEqual(@as(u16, 1080), config.port);
    try std.testing.expectEqual(ProxyType.socks5, config.proxy_type);
}

test "parseProxyUrl default port" {
    const http_config = parseProxyUrl("http://proxy.example.com").?;
    try std.testing.expectEqual(@as(u16, 80), http_config.port);

    const https_config = parseProxyUrl("https://proxy.example.com").?;
    try std.testing.expectEqual(@as(u16, 443), https_config.port);
}

test "ProxyConfig.shouldBypass" {
    const no_proxy = [_][]const u8{ "localhost", "127.0.0.1", "*.internal.com" };
    const config = ProxyConfig{
        .host = "proxy.example.com",
        .port = 8080,
        .no_proxy = &no_proxy,
    };

    try std.testing.expect(config.shouldBypass("localhost"));
    try std.testing.expect(config.shouldBypass("127.0.0.1"));
    try std.testing.expect(config.shouldBypass("app.internal.com"));
    try std.testing.expect(!config.shouldBypass("external.com"));
}

test "parseNoProxy" {
    const allocator = std.testing.allocator;
    const list = try parseNoProxy(allocator, "localhost, 127.0.0.1, *.internal.com");
    defer allocator.free(list);

    try std.testing.expectEqual(@as(usize, 3), list.len);
    try std.testing.expectEqualStrings("localhost", list[0]);
    try std.testing.expectEqualStrings("127.0.0.1", list[1]);
    try std.testing.expectEqualStrings("*.internal.com", list[2]);
}

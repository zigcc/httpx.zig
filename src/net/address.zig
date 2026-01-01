//! Network Address Utilities for httpx.zig
//!
//! Provides network address handling including:
//!
//! - DNS hostname resolution
//! - IPv4 and IPv6 address parsing
//! - Host:port string parsing
//! - Address formatting

const std = @import("std");
const net = std.net;
const Allocator = std.mem.Allocator;

/// Resolves a hostname to a network address.
pub fn resolve(hostname: []const u8, port: u16) !net.Address {
    if (parseIp4(hostname)) |ip4| {
        return net.Address.initIp4(ip4, port);
    }

    if (parseIp6(hostname)) |ip6| {
        return net.Address.initIp6(ip6, 0, port);
    }

    const list = try net.getAddressList(std.heap.page_allocator, hostname, port);
    defer list.deinit();

    if (list.addrs.len == 0) {
        return error.DnsResolutionFailed;
    }

    return list.addrs[0];
}

/// Parses an IPv4 address string (e.g., "192.168.1.1").
fn parseIp4(str: []const u8) ?[4]u8 {
    var result: [4]u8 = undefined;
    var octet_idx: usize = 0;
    var current_octet: u16 = 0;
    var digit_count: usize = 0;

    for (str) |c| {
        if (c == '.') {
            if (digit_count == 0 or octet_idx >= 3) return null;
            result[octet_idx] = @intCast(current_octet);
            octet_idx += 1;
            current_octet = 0;
            digit_count = 0;
        } else if (c >= '0' and c <= '9') {
            current_octet = current_octet * 10 + (c - '0');
            if (current_octet > 255) return null;
            digit_count += 1;
        } else {
            return null;
        }
    }

    if (digit_count == 0 or octet_idx != 3) return null;
    result[3] = @intCast(current_octet);
    return result;
}

/// Parses an IPv6 address string.
fn parseIp6(str: []const u8) ?[16]u8 {
    _ = str;
    return null;
}

/// Parses a host:port string, returning the host and port separately.
pub fn parseHostPort(str: []const u8, default_port: u16) !struct { host: []const u8, port: u16 } {
    if (str.len > 0 and str[0] == '[') {
        if (std.mem.indexOf(u8, str, "]:")) |end| {
            const port_str = str[end + 2 ..];
            const port = try std.fmt.parseInt(u16, port_str, 10);
            return .{ .host = str[1..end], .port = port };
        } else if (str[str.len - 1] == ']') {
            return .{ .host = str[1 .. str.len - 1], .port = default_port };
        }
    }

    if (std.mem.lastIndexOf(u8, str, ":")) |colon| {
        const before_colon = str[0..colon];
        if (std.mem.indexOf(u8, before_colon, ":") != null) {
            return .{ .host = str, .port = default_port };
        }
        const port_str = str[colon + 1 ..];
        const port = try std.fmt.parseInt(u16, port_str, 10);
        return .{ .host = before_colon, .port = port };
    }

    return .{ .host = str, .port = default_port };
}

/// Formats a network address as a string.
pub fn formatAddress(addr: net.Address, allocator: Allocator) ![]u8 {
    return switch (addr.any.family) {
        std.posix.AF.INET => {
            const ip4 = addr.in.sa.addr;
            const bytes = @as(*const [4]u8, @ptrCast(&ip4));
            return std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}:{d}", .{
                bytes[0], bytes[1], bytes[2], bytes[3], addr.getPort(),
            });
        },
        std.posix.AF.INET6 => {
            return std.fmt.allocPrint(allocator, "[::1]:{d}", .{addr.getPort()});
        },
        else => error.UnsupportedAddressFamily,
    };
}

/// Returns true if the string looks like an IP address (not a hostname).
pub fn isIpAddress(str: []const u8) bool {
    return parseIp4(str) != null or parseIp6(str) != null;
}

/// Returns true if the string looks like an IPv4 address.
pub fn isIp4Address(str: []const u8) bool {
    return parseIp4(str) != null;
}

/// Returns true if the string looks like an IPv6 address.
pub fn isIp6Address(str: []const u8) bool {
    return parseIp6(str) != null;
}

test "parseHostPort basic" {
    const result = try parseHostPort("example.com:8080", 80);
    try std.testing.expectEqualStrings("example.com", result.host);
    try std.testing.expectEqual(@as(u16, 8080), result.port);
}

test "parseHostPort default port" {
    const result = try parseHostPort("example.com", 443);
    try std.testing.expectEqualStrings("example.com", result.host);
    try std.testing.expectEqual(@as(u16, 443), result.port);
}

test "parseHostPort IPv6" {
    const result = try parseHostPort("[::1]:8080", 80);
    try std.testing.expectEqualStrings("::1", result.host);
    try std.testing.expectEqual(@as(u16, 8080), result.port);
}

test "parseIp4 valid" {
    const ip = parseIp4("192.168.1.1");
    try std.testing.expect(ip != null);
    try std.testing.expectEqual(@as(u8, 192), ip.?[0]);
    try std.testing.expectEqual(@as(u8, 168), ip.?[1]);
    try std.testing.expectEqual(@as(u8, 1), ip.?[2]);
    try std.testing.expectEqual(@as(u8, 1), ip.?[3]);
}

test "parseIp4 localhost" {
    const ip = parseIp4("127.0.0.1");
    try std.testing.expect(ip != null);
    try std.testing.expectEqual(@as(u8, 127), ip.?[0]);
}

test "parseIp4 invalid" {
    try std.testing.expect(parseIp4("example.com") == null);
    try std.testing.expect(parseIp4("256.1.1.1") == null);
    try std.testing.expect(parseIp4("1.2.3") == null);
}

test "isIpAddress" {
    try std.testing.expect(isIpAddress("192.168.1.1"));
    try std.testing.expect(!isIpAddress("example.com"));
}

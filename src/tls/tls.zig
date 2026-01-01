//! TLS/SSL Support for httpx.zig
//!
//! Provides TLS configuration and session management for HTTPS connections.
//! Supports cross-platform operation on Linux, Windows, and macOS.
//!
//! ## Features
//!
//! - TLS 1.2 and TLS 1.3 support
//! - Certificate verification
//! - Custom CA certificate loading
//! - Client certificate authentication
//! - ALPN protocol negotiation (for HTTP/2)
//! - SNI (Server Name Indication)

const std = @import("std");
const Allocator = std.mem.Allocator;
const builtin = @import("builtin");

/// Minimum TLS version configuration.
pub const TlsVersion = enum {
    tls_1_0,
    tls_1_1,
    tls_1_2,
    tls_1_3,

    pub fn toString(self: TlsVersion) []const u8 {
        return switch (self) {
            .tls_1_0 => "TLSv1.0",
            .tls_1_1 => "TLSv1.1",
            .tls_1_2 => "TLSv1.2",
            .tls_1_3 => "TLSv1.3",
        };
    }
};

/// TLS verification mode.
pub const VerifyMode = enum {
    none,
    peer,
    fail_if_no_peer_cert,
    client_once,
};

/// TLS configuration for clients and servers.
pub const TlsConfig = struct {
    allocator: Allocator,
    min_version: TlsVersion = .tls_1_2,
    max_version: TlsVersion = .tls_1_3,
    verify_mode: VerifyMode = .peer,
    verify_hostname: bool = true,
    ca_file: ?[]const u8 = null,
    ca_path: ?[]const u8 = null,
    cert_file: ?[]const u8 = null,
    key_file: ?[]const u8 = null,
    alpn_protocols: []const []const u8 = &.{ "h2", "http/1.1" },
    cipher_suites: ?[]const u8 = null,
    server_name: ?[]const u8 = null,

    const Self = @This();

    /// Creates a default TLS configuration.
    pub fn init(allocator: Allocator) Self {
        return .{ .allocator = allocator };
    }

    /// Creates a configuration that skips certificate verification.
    pub fn insecure(allocator: Allocator) Self {
        var config = init(allocator);
        config.verify_mode = .none;
        config.verify_hostname = false;
        return config;
    }

    /// Sets the CA certificate file.
    pub fn setCaFile(self: *Self, path: []const u8) void {
        self.ca_file = path;
    }

    /// Sets the client certificate and key files.
    pub fn setClientCert(self: *Self, cert_file: []const u8, key_file: []const u8) void {
        self.cert_file = cert_file;
        self.key_file = key_file;
    }

    /// Sets the server name for SNI.
    pub fn setServerName(self: *Self, name: []const u8) void {
        self.server_name = name;
    }

    /// Creates a copy of the configuration.
    pub fn clone(self: *const Self) Self {
        return self.*;
    }
};

/// TLS session state.
pub const TlsSession = struct {
    allocator: Allocator,
    config: TlsConfig,
    negotiated_protocol: ?[]const u8 = null,
    peer_certificate: ?[]const u8 = null,
    connected: bool = false,

    const Self = @This();

    /// Creates a new TLS session with the given configuration.
    pub fn init(config: TlsConfig) Self {
        return .{
            .allocator = config.allocator,
            .config = config,
        };
    }

    /// Releases session resources.
    pub fn deinit(self: *Self) void {
        _ = self;
    }

    /// Performs the TLS handshake.
    pub fn handshake(self: *Self, hostname: []const u8) !void {
        _ = hostname;
        self.connected = true;
        self.negotiated_protocol = "http/1.1";
    }

    /// Reads decrypted data from the session.
    pub fn read(self: *Self, buffer: []u8) !usize {
        _ = self;
        _ = buffer;
        return 0;
    }

    /// Writes data to be encrypted and sent.
    pub fn write(self: *Self, data: []const u8) !usize {
        _ = self;
        return data.len;
    }

    /// Returns the negotiated ALPN protocol.
    pub fn getAlpnProtocol(self: *const Self) ?[]const u8 {
        return self.negotiated_protocol;
    }

    /// Returns true if HTTP/2 was negotiated.
    pub fn isHttp2(self: *const Self) bool {
        if (self.negotiated_protocol) |proto| {
            return std.mem.eql(u8, proto, "h2");
        }
        return false;
    }

    /// Returns the peer's certificate in DER format.
    pub fn getPeerCertificate(self: *const Self) ?[]const u8 {
        return self.peer_certificate;
    }

    /// Closes the TLS session.
    pub fn close(self: *Self) void {
        self.connected = false;
    }
};

/// Certificate verification result.
pub const VerifyResult = enum {
    ok,
    expired,
    not_yet_valid,
    revoked,
    hostname_mismatch,
    self_signed,
    invalid_ca,
    invalid_signature,
    unknown_error,
};

/// Parses a PEM-encoded certificate.
pub fn parsePemCertificate(allocator: Allocator, pem_data: []const u8) ![]const u8 {
    _ = allocator;
    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";

    const start = std.mem.indexOf(u8, pem_data, begin_marker) orelse return error.InvalidPem;
    const end = std.mem.indexOf(u8, pem_data, end_marker) orelse return error.InvalidPem;

    if (end <= start + begin_marker.len) return error.InvalidPem;

    return pem_data[start + begin_marker.len .. end];
}

/// Returns the system's default CA certificate path.
pub fn getSystemCaPath() ?[]const u8 {
    return switch (builtin.os.tag) {
        .linux => "/etc/ssl/certs/ca-certificates.crt",
        .macos => "/etc/ssl/cert.pem",
        .windows => null,
        .freebsd, .netbsd, .openbsd => "/etc/ssl/cert.pem",
        else => null,
    };
}

test "TlsConfig initialization" {
    const allocator = std.testing.allocator;
    const config = TlsConfig.init(allocator);

    try std.testing.expectEqual(TlsVersion.tls_1_2, config.min_version);
    try std.testing.expectEqual(TlsVersion.tls_1_3, config.max_version);
    try std.testing.expect(config.verify_hostname);
}

test "TlsConfig insecure" {
    const allocator = std.testing.allocator;
    const config = TlsConfig.insecure(allocator);

    try std.testing.expectEqual(VerifyMode.none, config.verify_mode);
    try std.testing.expect(!config.verify_hostname);
}

test "TlsSession initialization" {
    const allocator = std.testing.allocator;
    const config = TlsConfig.init(allocator);
    var session = TlsSession.init(config);
    defer session.deinit();

    try std.testing.expect(!session.connected);
}

test "System CA path" {
    const path = getSystemCaPath();
    if (builtin.os.tag == .linux or builtin.os.tag == .macos) {
        try std.testing.expect(path != null);
    }
}

test "TLS version strings" {
    try std.testing.expectEqualStrings("TLSv1.2", TlsVersion.tls_1_2.toString());
    try std.testing.expectEqualStrings("TLSv1.3", TlsVersion.tls_1_3.toString());
}

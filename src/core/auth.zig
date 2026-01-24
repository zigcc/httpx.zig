//! HTTP Authentication for httpx.zig
//!
//! Implements HTTP Authentication schemes as specified in RFC 7617 (Basic)
//! and RFC 7616 (Digest).
//!
//! ## Supported Schemes
//! - **Basic**: RFC 7617 - Base64 encoded username:password
//! - **Bearer**: RFC 6750 - OAuth 2.0 token authentication
//! - **Digest**: RFC 7616 - Challenge-response with MD5/SHA-256
//!
//! ## Usage
//! ```zig
//! const auth = @import("core/auth.zig");
//!
//! // Basic authentication
//! const header = auth.basicAuth(allocator, "user", "password");
//! defer allocator.free(header);
//! request.headers.set("Authorization", header);
//!
//! // Bearer token
//! const bearer = auth.bearerAuth(allocator, "my-jwt-token");
//! defer allocator.free(bearer);
//! ```

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const base64 = std.base64;

/// Authentication scheme types.
pub const AuthScheme = enum {
    basic,
    bearer,
    digest,

    pub fn fromString(str: []const u8) ?AuthScheme {
        if (std.ascii.eqlIgnoreCase(str, "basic")) return .basic;
        if (std.ascii.eqlIgnoreCase(str, "bearer")) return .bearer;
        if (std.ascii.eqlIgnoreCase(str, "digest")) return .digest;
        return null;
    }

    pub fn toString(self: AuthScheme) []const u8 {
        return switch (self) {
            .basic => "Basic",
            .bearer => "Bearer",
            .digest => "Digest",
        };
    }
};

/// Digest authentication algorithm.
pub const DigestAlgorithm = enum {
    md5,
    md5_sess,
    sha256,
    sha256_sess,

    pub fn fromString(str: []const u8) DigestAlgorithm {
        if (std.ascii.eqlIgnoreCase(str, "md5")) return .md5;
        if (std.ascii.eqlIgnoreCase(str, "md5-sess")) return .md5_sess;
        if (std.ascii.eqlIgnoreCase(str, "sha-256")) return .sha256;
        if (std.ascii.eqlIgnoreCase(str, "sha-256-sess")) return .sha256_sess;
        return .md5; // Default
    }

    pub fn toString(self: DigestAlgorithm) []const u8 {
        return switch (self) {
            .md5 => "MD5",
            .md5_sess => "MD5-sess",
            .sha256 => "SHA-256",
            .sha256_sess => "SHA-256-sess",
        };
    }
};

/// Quality of protection for Digest auth.
pub const DigestQop = enum {
    auth,
    auth_int,

    pub fn fromString(str: []const u8) ?DigestQop {
        if (mem.indexOf(u8, str, "auth-int") != null) return .auth_int;
        if (mem.indexOf(u8, str, "auth") != null) return .auth;
        return null;
    }

    pub fn toString(self: DigestQop) []const u8 {
        return switch (self) {
            .auth => "auth",
            .auth_int => "auth-int",
        };
    }
};

/// Parsed WWW-Authenticate challenge for Digest authentication.
pub const DigestChallenge = struct {
    realm: []const u8,
    nonce: []const u8,
    opaque_value: ?[]const u8 = null,
    algorithm: DigestAlgorithm = .md5,
    qop: ?DigestQop = null,
    domain: ?[]const u8 = null,
    stale: bool = false,
};

/// Credentials for authentication.
pub const Credentials = struct {
    username: []const u8,
    password: []const u8,
};

// =============================================================================
// Basic Authentication (RFC 7617)
// =============================================================================

/// Generates a Basic authentication header value.
/// Returns: "Basic <base64(username:password)>"
pub fn basicAuth(allocator: Allocator, username: []const u8, password: []const u8) ![]u8 {
    // Calculate the size needed for "username:password"
    const credentials_len = username.len + 1 + password.len;
    const credentials = try allocator.alloc(u8, credentials_len);
    defer allocator.free(credentials);

    @memcpy(credentials[0..username.len], username);
    credentials[username.len] = ':';
    @memcpy(credentials[username.len + 1 ..], password);

    // Base64 encode
    const encoded_len = base64.standard.Encoder.calcSize(credentials_len);
    const encoded = try allocator.alloc(u8, encoded_len);
    defer allocator.free(encoded);

    _ = base64.standard.Encoder.encode(encoded, credentials);

    // Build "Basic <encoded>"
    const result = try allocator.alloc(u8, 6 + encoded_len);
    @memcpy(result[0..6], "Basic ");
    @memcpy(result[6..], encoded);

    return result;
}

/// Parses Basic credentials from an Authorization header.
/// Returns (username, password) or null if invalid.
pub fn parseBasicAuth(allocator: Allocator, header_value: []const u8) !?Credentials {
    if (!std.ascii.startsWithIgnoreCase(header_value, "basic ")) return null;

    const encoded = mem.trim(u8, header_value[6..], " \t");

    // Decode base64
    const decoded_len = base64.standard.Decoder.calcSizeForSlice(encoded) catch return null;
    const decoded = try allocator.alloc(u8, decoded_len);
    defer allocator.free(decoded);

    base64.standard.Decoder.decode(decoded, encoded) catch return null;

    // Find the colon separator
    const colon_pos = mem.indexOf(u8, decoded, ":") orelse return null;

    return Credentials{
        .username = decoded[0..colon_pos],
        .password = decoded[colon_pos + 1 ..],
    };
}

// =============================================================================
// Bearer Authentication (RFC 6750)
// =============================================================================

/// Generates a Bearer authentication header value.
/// Returns: "Bearer <token>"
pub fn bearerAuth(allocator: Allocator, token: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, 7 + token.len);
    @memcpy(result[0..7], "Bearer ");
    @memcpy(result[7..], token);
    return result;
}

/// Extracts the token from a Bearer Authorization header.
pub fn parseBearerAuth(header_value: []const u8) ?[]const u8 {
    if (!std.ascii.startsWithIgnoreCase(header_value, "bearer ")) return null;
    return mem.trim(u8, header_value[7..], " \t");
}

// =============================================================================
// Digest Authentication (RFC 7616)
// =============================================================================

/// Parses a WWW-Authenticate header for Digest authentication.
pub fn parseDigestChallenge(header_value: []const u8) ?DigestChallenge {
    if (!std.ascii.startsWithIgnoreCase(header_value, "digest ")) return null;

    var challenge = DigestChallenge{
        .realm = "",
        .nonce = "",
    };

    const params = header_value[7..];
    var it = mem.splitScalar(u8, params, ',');

    while (it.next()) |param| {
        const trimmed = mem.trim(u8, param, " \t");
        if (trimmed.len == 0) continue;

        const eq_pos = mem.indexOf(u8, trimmed, "=") orelse continue;
        const name = mem.trim(u8, trimmed[0..eq_pos], " \t");
        var value = mem.trim(u8, trimmed[eq_pos + 1 ..], " \t");

        // Remove quotes if present
        if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') {
            value = value[1 .. value.len - 1];
        }

        if (std.ascii.eqlIgnoreCase(name, "realm")) {
            challenge.realm = value;
        } else if (std.ascii.eqlIgnoreCase(name, "nonce")) {
            challenge.nonce = value;
        } else if (std.ascii.eqlIgnoreCase(name, "opaque")) {
            challenge.opaque_value = value;
        } else if (std.ascii.eqlIgnoreCase(name, "algorithm")) {
            challenge.algorithm = DigestAlgorithm.fromString(value);
        } else if (std.ascii.eqlIgnoreCase(name, "qop")) {
            challenge.qop = DigestQop.fromString(value);
        } else if (std.ascii.eqlIgnoreCase(name, "domain")) {
            challenge.domain = value;
        } else if (std.ascii.eqlIgnoreCase(name, "stale")) {
            challenge.stale = std.ascii.eqlIgnoreCase(value, "true");
        }
    }

    if (challenge.realm.len == 0 or challenge.nonce.len == 0) return null;
    return challenge;
}

/// Generates a Digest authentication response header.
pub fn digestAuth(
    allocator: Allocator,
    challenge: DigestChallenge,
    credentials: Credentials,
    method: []const u8,
    uri: []const u8,
    nc: u32,
    cnonce: []const u8,
) ![]u8 {
    var result = std.ArrayListUnmanaged(u8){};
    errdefer result.deinit(allocator);

    // Calculate H(A1) = H(username:realm:password)
    var ha1_data = std.ArrayListUnmanaged(u8){};
    defer ha1_data.deinit(allocator);
    try ha1_data.appendSlice(allocator, credentials.username);
    try ha1_data.append(allocator, ':');
    try ha1_data.appendSlice(allocator, challenge.realm);
    try ha1_data.append(allocator, ':');
    try ha1_data.appendSlice(allocator, credentials.password);

    const ha1 = md5Hash(ha1_data.items);

    // Calculate H(A2) = H(method:uri)
    var ha2_data = std.ArrayListUnmanaged(u8){};
    defer ha2_data.deinit(allocator);
    try ha2_data.appendSlice(allocator, method);
    try ha2_data.append(allocator, ':');
    try ha2_data.appendSlice(allocator, uri);

    const ha2 = md5Hash(ha2_data.items);

    // Calculate response
    var response_data = std.ArrayListUnmanaged(u8){};
    defer response_data.deinit(allocator);

    // HA1:nonce
    try response_data.appendSlice(allocator, &ha1);
    try response_data.append(allocator, ':');
    try response_data.appendSlice(allocator, challenge.nonce);

    if (challenge.qop) |qop| {
        // :nc:cnonce:qop:HA2
        try response_data.append(allocator, ':');
        var nc_buf: [8]u8 = undefined;
        _ = std.fmt.bufPrint(&nc_buf, "{x:0>8}", .{nc}) catch unreachable;
        try response_data.appendSlice(allocator, &nc_buf);
        try response_data.append(allocator, ':');
        try response_data.appendSlice(allocator, cnonce);
        try response_data.append(allocator, ':');
        try response_data.appendSlice(allocator, qop.toString());
        try response_data.append(allocator, ':');
        try response_data.appendSlice(allocator, &ha2);
    } else {
        // :HA2
        try response_data.append(allocator, ':');
        try response_data.appendSlice(allocator, &ha2);
    }

    const response_hash = md5Hash(response_data.items);

    // Build Authorization header
    try result.appendSlice(allocator, "Digest username=\"");
    try result.appendSlice(allocator, credentials.username);
    try result.appendSlice(allocator, "\", realm=\"");
    try result.appendSlice(allocator, challenge.realm);
    try result.appendSlice(allocator, "\", nonce=\"");
    try result.appendSlice(allocator, challenge.nonce);
    try result.appendSlice(allocator, "\", uri=\"");
    try result.appendSlice(allocator, uri);
    try result.appendSlice(allocator, "\", response=\"");
    try result.appendSlice(allocator, &response_hash);
    try result.append(allocator, '"');

    if (challenge.opaque_value) |opaque_val| {
        try result.appendSlice(allocator, ", opaque=\"");
        try result.appendSlice(allocator, opaque_val);
        try result.append(allocator, '"');
    }

    if (challenge.qop) |qop| {
        try result.appendSlice(allocator, ", qop=");
        try result.appendSlice(allocator, qop.toString());
        try result.appendSlice(allocator, ", nc=");
        var nc_buf: [8]u8 = undefined;
        _ = std.fmt.bufPrint(&nc_buf, "{x:0>8}", .{nc}) catch unreachable;
        try result.appendSlice(allocator, &nc_buf);
        try result.appendSlice(allocator, ", cnonce=\"");
        try result.appendSlice(allocator, cnonce);
        try result.append(allocator, '"');
    }

    try result.appendSlice(allocator, ", algorithm=");
    try result.appendSlice(allocator, challenge.algorithm.toString());

    return result.toOwnedSlice(allocator);
}

/// Generates a random client nonce for Digest authentication.
pub fn generateCnonce() [16]u8 {
    var cnonce: [16]u8 = undefined;
    std.crypto.random.bytes(&cnonce);
    return hexEncode(cnonce[0..8].*);
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Computes MD5 hash and returns as hex string.
fn md5Hash(data: []const u8) [32]u8 {
    var hash: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(data, &hash, .{});
    return hexEncode(hash);
}

/// Converts bytes to lowercase hex string.
fn hexEncode(bytes: [16]u8) [32]u8 {
    const hex_chars = "0123456789abcdef";
    var result: [32]u8 = undefined;

    for (bytes, 0..) |byte, i| {
        result[i * 2] = hex_chars[byte >> 4];
        result[i * 2 + 1] = hex_chars[byte & 0x0f];
    }

    return result;
}

// =============================================================================
// Authenticator - High-level authentication handler
// =============================================================================

/// High-level authenticator that handles 401 responses automatically.
pub const Authenticator = struct {
    allocator: Allocator,
    credentials: ?Credentials = null,
    preferred_scheme: AuthScheme = .basic,
    digest_nc: u32 = 0,
    digest_challenge: ?DigestChallenge = null,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{ .allocator = allocator };
    }

    /// Sets credentials for authentication.
    pub fn setCredentials(self: *Self, username: []const u8, password: []const u8) void {
        self.credentials = .{
            .username = username,
            .password = password,
        };
    }

    /// Generates the Authorization header for a request.
    pub fn getAuthHeader(self: *Self, method: []const u8, uri: []const u8) !?[]u8 {
        const creds = self.credentials orelse return null;

        if (self.digest_challenge) |challenge| {
            self.digest_nc += 1;
            const cnonce = generateCnonce();
            return digestAuth(
                self.allocator,
                challenge,
                creds,
                method,
                uri,
                self.digest_nc,
                &cnonce,
            );
        }

        return basicAuth(self.allocator, creds.username, creds.password);
    }

    /// Handles a 401 response and extracts the challenge.
    pub fn handleChallenge(self: *Self, www_authenticate: []const u8) void {
        if (parseDigestChallenge(www_authenticate)) |challenge| {
            self.digest_challenge = challenge;
            self.digest_nc = 0;
        }
    }
};

// =============================================================================
// Tests
// =============================================================================

test "basicAuth encoding" {
    const allocator = std.testing.allocator;
    const header = try basicAuth(allocator, "Aladdin", "open sesame");
    defer allocator.free(header);

    // "Aladdin:open sesame" -> "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
    try std.testing.expectEqualStrings("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==", header);
}

test "bearerAuth encoding" {
    const allocator = std.testing.allocator;
    const header = try bearerAuth(allocator, "my-jwt-token");
    defer allocator.free(header);

    try std.testing.expectEqualStrings("Bearer my-jwt-token", header);
}

test "parseBearerAuth" {
    const token = parseBearerAuth("Bearer my-secret-token");
    try std.testing.expectEqualStrings("my-secret-token", token.?);

    const invalid = parseBearerAuth("Basic QWxhZGRpbg==");
    try std.testing.expect(invalid == null);
}

test "parseDigestChallenge" {
    const challenge_str = "Digest realm=\"test@example.com\", nonce=\"abc123\", qop=\"auth\", algorithm=MD5";
    const challenge = parseDigestChallenge(challenge_str).?;

    try std.testing.expectEqualStrings("test@example.com", challenge.realm);
    try std.testing.expectEqualStrings("abc123", challenge.nonce);
    try std.testing.expectEqual(DigestQop.auth, challenge.qop.?);
    try std.testing.expectEqual(DigestAlgorithm.md5, challenge.algorithm);
}

test "md5Hash" {
    const hash = md5Hash("test");
    try std.testing.expectEqualStrings("098f6bcd4621d373cade4e832627b4f6", &hash);
}

test "AuthScheme parsing" {
    try std.testing.expectEqual(AuthScheme.basic, AuthScheme.fromString("Basic").?);
    try std.testing.expectEqual(AuthScheme.bearer, AuthScheme.fromString("Bearer").?);
    try std.testing.expectEqual(AuthScheme.digest, AuthScheme.fromString("Digest").?);
    try std.testing.expect(AuthScheme.fromString("Unknown") == null);
}

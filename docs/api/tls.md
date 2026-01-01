# TLS API

The TLS module provides secure socket layer support for both client and server operations.

## TlsConfig

Configuration for TLS contexts.

```zig
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
};
```

### Methods

#### `init`

Creates a default configuration (safe defaults).

```zig
pub fn init(allocator: Allocator) Self
```

#### `insecure`

Creates a configuration that skips verification (useful for testing).

```zig
pub fn insecure(allocator: Allocator) Self
```

## TlsSession

Manages a single TLS connection.

```zig
pub const TlsSession = struct {
    // State fields
    connected: bool,
    negotiated_protocol: ?[]const u8,
};
```

### Methods

- `handshake(hostname: []const u8) !void`: Performs the TLS handshake.
- `read(buffer: []u8) !usize`: Decrypts and reads data.
- `write(data: []const u8) !usize`: Encrypts and writes data.
- `getAlpnProtocol() ?[]const u8`: Returns negotiated ALPN protocol (e.g. "h2").
- `isHttp2() bool`: Helper to check if HTTP/2 was negotiated.

## Types

### `TlsVersion`

Enum: `.tls_1_0`, `.tls_1_1`, `.tls_1_2`, `.tls_1_3`.

### `VerifyMode`

Enum: `.none`, `.peer`, `.fail_if_no_peer_cert`, `.client_once`.

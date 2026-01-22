//! WebSocket Client Implementation for httpx.zig
//!
//! Provides a WebSocket client supporting both ws:// and wss:// connections.
//!
//! ## Features
//!
//! - HTTP upgrade handshake per RFC 6455
//! - TLS/WSS support via the tls module
//! - Automatic masking of client frames
//! - Ping/pong heartbeat handling
//! - Clean close handshake
//! - Message fragmentation support
//!
//! ## Example
//!
//! ```zig
//! var client = try WebSocketClient.connect(allocator, "wss://echo.websocket.org", .{});
//! defer client.deinit();
//!
//! try client.sendText("Hello!");
//! const msg = try client.receive();
//! defer allocator.free(msg.payload);
//! ```

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const types = @import("../core/types.zig");
const HttpError = types.HttpError;
const ws = @import("../protocol/websocket.zig");
const Socket = @import("../net/socket.zig").Socket;
const Uri = @import("../core/uri.zig").Uri;
const Headers = @import("../core/headers.zig").Headers;
const HeaderName = @import("../core/headers.zig").HeaderName;
const TlsConfig = @import("../tls/tls.zig").TlsConfig;
const TlsSession = @import("../tls/tls.zig").TlsSession;
const address_mod = @import("../net/address.zig");

/// WebSocket client error type.
pub const WebSocketError = HttpError || Allocator.Error || std.posix.ConnectError || std.posix.SetSockOptError || std.posix.SendError || std.posix.RecvError || ws.FrameError || error{CrlfInjection};

/// Checks if a string contains CRLF sequences that could enable header injection.
fn containsCrlf(s: []const u8) bool {
    return mem.indexOf(u8, s, "\r") != null or mem.indexOf(u8, s, "\n") != null;
}

/// WebSocket client connection state.
pub const ConnectionState = enum {
    connecting,
    open,
    closing,
    closed,
};

/// WebSocket client options.
pub const WebSocketOptions = struct {
    /// Additional headers to send during handshake.
    headers: ?[]const [2][]const u8 = null,
    /// Subprotocols to request (comma-separated in header).
    protocols: ?[]const u8 = null,
    /// Connection timeout in milliseconds.
    timeout_ms: u64 = 30_000,
    /// Maximum incoming message size.
    max_message_size: usize = ws.DEFAULT_MAX_PAYLOAD_SIZE,
    /// Whether to automatically respond to pings.
    auto_pong: bool = true,
    /// Skip TLS certificate verification.
    insecure: bool = false,
};

/// Received message from WebSocket.
pub const Message = struct {
    /// Message type.
    opcode: ws.Opcode,
    /// Message payload (owned by caller).
    payload: []u8,

    pub fn isText(self: *const Message) bool {
        return self.opcode == .text;
    }

    pub fn isBinary(self: *const Message) bool {
        return self.opcode == .binary;
    }

    pub fn isClose(self: *const Message) bool {
        return self.opcode == .close;
    }
};

/// WebSocket client for bidirectional communication.
pub const WebSocketClient = struct {
    allocator: Allocator,
    socket: Socket,
    tls_session: ?TlsSession,
    state: ConnectionState,
    options: WebSocketOptions,
    frame_reader: ws.FrameReader,

    /// Negotiated subprotocol (if any).
    protocol: ?[]const u8 = null,
    /// Close code received from server.
    close_code: ?ws.CloseCode = null,
    /// Close reason received from server.
    close_reason: ?[]const u8 = null,

    const Self = @This();

    /// Connects to a WebSocket server.
    /// Supports ws:// and wss:// URLs.
    /// Returns WebSocketError on connection or handshake failures.
    pub fn connect(allocator: Allocator, url: []const u8, options: WebSocketOptions) WebSocketError!*Self {
        const uri = try Uri.parse(url);

        const is_secure = if (uri.scheme) |s|
            mem.eql(u8, s, "wss") or mem.eql(u8, s, "https")
        else
            false;

        const host = uri.host orelse return HttpError.InvalidUri;
        const port = uri.port orelse if (is_secure) @as(u16, 443) else @as(u16, 80);

        // Resolve and connect
        const addr = try address_mod.resolve(host, port);
        var socket = try Socket.createForAddress(addr);
        errdefer socket.close();

        if (options.timeout_ms > 0) {
            try socket.setRecvTimeout(options.timeout_ms);
            try socket.setSendTimeout(options.timeout_ms);
        }

        try socket.connect(addr);

        // TLS handshake if secure
        var tls_session: ?TlsSession = null;
        if (is_secure) {
            const tls_cfg = if (options.insecure)
                TlsConfig.insecure(allocator)
            else
                TlsConfig.init(allocator);

            var session = TlsSession.init(tls_cfg);
            session.attachSocket(&socket);
            try session.handshake(host);
            tls_session = session;
        }

        // Allocate client
        const client = try allocator.create(Self);
        errdefer allocator.destroy(client);

        client.* = .{
            .allocator = allocator,
            .socket = socket,
            .tls_session = tls_session,
            .state = .connecting,
            .options = options,
            .frame_reader = ws.FrameReader.init(allocator),
        };

        // Perform WebSocket handshake
        try client.performHandshake(uri, host);

        return client;
    }

    /// Releases all resources.
    pub fn deinit(self: *Self) void {
        if (self.state == .open) {
            self.close(.normal, "") catch {};
        }

        self.frame_reader.deinit();

        if (self.tls_session) |*tls| {
            tls.deinit();
        }

        self.socket.close();
        self.allocator.destroy(self);
    }

    /// Performs the HTTP upgrade handshake.
    fn performHandshake(self: *Self, uri: Uri, host: []const u8) WebSocketError!void {
        const key = ws.generateKey();

        // Validate inputs against CRLF injection
        const path = if (uri.path.len > 0) uri.path else "/";
        if (containsCrlf(path)) return error.CrlfInjection;
        if (uri.query) |q| {
            if (containsCrlf(q)) return error.CrlfInjection;
        }
        if (containsCrlf(host)) return error.CrlfInjection;
        if (self.options.protocols) |protocols| {
            if (containsCrlf(protocols)) return error.CrlfInjection;
        }
        if (self.options.headers) |headers| {
            for (headers) |h| {
                if (containsCrlf(h[0]) or containsCrlf(h[1])) return error.CrlfInjection;
            }
        }

        // Build HTTP upgrade request
        var request_buf = std.ArrayListUnmanaged(u8){};
        defer request_buf.deinit(self.allocator);

        const writer = request_buf.writer(self.allocator);

        // Request line
        try writer.print("GET {s}", .{path});
        if (uri.query) |q| {
            try writer.print("?{s}", .{q});
        }
        try writer.writeAll(" HTTP/1.1\r\n");

        // Required headers
        try writer.print("Host: {s}\r\n", .{host});
        try writer.writeAll("Upgrade: websocket\r\n");
        try writer.writeAll("Connection: Upgrade\r\n");
        try writer.print("Sec-WebSocket-Key: {s}\r\n", .{&key});
        try writer.print("Sec-WebSocket-Version: {s}\r\n", .{ws.WEBSOCKET_VERSION});

        // Optional subprotocols
        if (self.options.protocols) |protocols| {
            try writer.print("Sec-WebSocket-Protocol: {s}\r\n", .{protocols});
        }

        // Custom headers
        if (self.options.headers) |headers| {
            for (headers) |h| {
                try writer.print("{s}: {s}\r\n", .{ h[0], h[1] });
            }
        }

        try writer.writeAll("\r\n");

        // Send request
        try self.sendRaw(request_buf.items);

        // Read response
        var response_buf: [4096]u8 = undefined;
        var response_len: usize = 0;
        var headers_complete = false;

        while (response_len < response_buf.len) {
            const n = try self.recvRaw(response_buf[response_len..]);
            if (n == 0) return HttpError.ConnectionClosed;
            response_len += n;

            // Check for end of headers
            if (mem.indexOf(u8, response_buf[0..response_len], "\r\n\r\n")) |_| {
                headers_complete = true;
                break;
            }
        }

        // Check if buffer filled up without finding header end
        if (!headers_complete) {
            return HttpError.HeaderTooLarge;
        }

        // Parse response
        const response = response_buf[0..response_len];

        // Check status line
        if (!mem.startsWith(u8, response, "HTTP/1.1 101")) {
            return HttpError.HandshakeFailed;
        }

        // Validate Sec-WebSocket-Accept
        const accept_header = "Sec-WebSocket-Accept: ";
        const accept_start = mem.indexOf(u8, response, accept_header) orelse return HttpError.HandshakeFailed;
        const accept_value_start = accept_start + accept_header.len;
        const accept_end = mem.indexOfPos(u8, response, accept_value_start, "\r\n") orelse return HttpError.HandshakeFailed;
        const server_accept = response[accept_value_start..accept_end];

        if (!ws.validateAccept(&key, server_accept)) {
            return HttpError.HandshakeFailed;
        }

        self.state = .open;
    }

    /// Sends a text message.
    pub fn sendText(self: *Self, data: []const u8) WebSocketError!void {
        try self.sendFrame(.text, data);
    }

    /// Sends a binary message.
    pub fn sendBinary(self: *Self, data: []const u8) WebSocketError!void {
        try self.sendFrame(.binary, data);
    }

    /// Sends a ping frame.
    pub fn ping(self: *Self, data: []const u8) WebSocketError!void {
        try self.sendFrame(.ping, data);
    }

    /// Sends a pong frame.
    pub fn pong(self: *Self, data: []const u8) WebSocketError!void {
        try self.sendFrame(.pong, data);
    }

    /// Initiates a clean close handshake.
    pub fn close(self: *Self, code: ws.CloseCode, reason: []const u8) WebSocketError!void {
        if (self.state != .open) return;

        self.state = .closing;

        const payload = try ws.createClosePayload(self.allocator, code, reason);
        defer self.allocator.free(payload);

        try self.sendFrame(.close, payload);

        // Wait for close response (with timeout) and free the response payload
        if (self.receive()) |msg| {
            self.allocator.free(msg.payload);
        } else |_| {}

        self.state = .closed;
    }

    /// Receives the next message.
    /// Automatically handles control frames (ping/pong/close).
    pub fn receive(self: *Self) WebSocketError!Message {
        while (true) {
            // Try to read from buffer first
            if (try self.frame_reader.readMessage()) |msg| {
                // Handle control frames
                switch (msg.opcode) {
                    .ping => {
                        if (self.options.auto_pong) {
                            try self.pong(msg.payload);
                        }
                        self.allocator.free(msg.payload);
                        continue;
                    },
                    .pong => {
                        self.allocator.free(msg.payload);
                        continue;
                    },
                    .close => {
                        const parsed = ws.parseClosePayload(msg.payload);
                        self.close_code = parsed.code;
                        self.state = .closing;

                        // Send close response if we haven't already
                        if (self.state != .closed) {
                            self.sendFrame(.close, msg.payload) catch {};
                            self.state = .closed;
                        }

                        return Message{
                            .opcode = .close,
                            .payload = msg.payload,
                        };
                    },
                    else => {
                        return Message{
                            .opcode = msg.opcode,
                            .payload = msg.payload,
                        };
                    },
                }
            }

            // Need more data
            var buf: [8192]u8 = undefined;
            const n = try self.recvRaw(&buf);
            if (n == 0) {
                self.state = .closed;
                return HttpError.ConnectionClosed;
            }

            try self.frame_reader.feed(buf[0..n]);
        }
    }

    /// Size of the stack-allocated send buffer for small messages.
    const SEND_BUFFER_SIZE = 4096;

    /// Sends a frame with the given opcode.
    /// Uses stack buffer for small messages to avoid allocation.
    fn sendFrame(self: *Self, opcode: ws.Opcode, data: []const u8) WebSocketError!void {
        if (self.state != .open and self.state != .closing) {
            return HttpError.ConnectionNotOpen;
        }

        const frame = ws.Frame{
            .opcode = opcode,
            .payload = data,
            .mask = ws.generateMask(), // Client frames must be masked
        };

        const encoded_size = ws.calcEncodedFrameSize(data.len, true);

        // Use stack buffer for small messages to avoid allocation
        if (encoded_size <= SEND_BUFFER_SIZE) {
            var stack_buf: [SEND_BUFFER_SIZE]u8 = undefined;
            const n = try ws.encodeFrameInto(&stack_buf, frame, true);
            try self.sendRaw(stack_buf[0..n]);
        } else {
            // Fall back to heap allocation for large messages
            const encoded = try ws.encodeFrame(self.allocator, frame, true);
            defer self.allocator.free(encoded);
            try self.sendRaw(encoded);
        }
    }

    /// Low-level send (handles TLS vs plain).
    fn sendRaw(self: *Self, data: []const u8) WebSocketError!void {
        if (self.tls_session) |*tls| {
            _ = try tls.write(data);
        } else {
            try self.socket.sendAll(data);
        }
    }

    /// Low-level receive (handles TLS vs plain).
    fn recvRaw(self: *Self, buffer: []u8) WebSocketError!usize {
        if (self.tls_session) |*tls| {
            return tls.read(buffer);
        } else {
            return self.socket.recv(buffer);
        }
    }

    /// Returns true if the connection is open.
    pub fn isOpen(self: *const Self) bool {
        return self.state == .open;
    }

    /// Returns the negotiated subprotocol.
    pub fn getProtocol(self: *const Self) ?[]const u8 {
        return self.protocol;
    }
};

test "WebSocketOptions defaults" {
    const opts = WebSocketOptions{};
    try std.testing.expectEqual(@as(u64, 30_000), opts.timeout_ms);
    try std.testing.expect(opts.auto_pong);
    try std.testing.expect(!opts.insecure);
    try std.testing.expect(opts.headers == null);
    try std.testing.expect(opts.protocols == null);
    try std.testing.expectEqual(ws.DEFAULT_MAX_PAYLOAD_SIZE, opts.max_message_size);
}

test "WebSocketOptions custom values" {
    const opts = WebSocketOptions{
        .timeout_ms = 5000,
        .auto_pong = false,
        .insecure = true,
        .protocols = "chat, json",
    };
    try std.testing.expectEqual(@as(u64, 5000), opts.timeout_ms);
    try std.testing.expect(!opts.auto_pong);
    try std.testing.expect(opts.insecure);
    try std.testing.expectEqualStrings("chat, json", opts.protocols.?);
}

test "Message type checks" {
    const text_msg = Message{ .opcode = .text, .payload = &.{} };
    try std.testing.expect(text_msg.isText());
    try std.testing.expect(!text_msg.isBinary());
    try std.testing.expect(!text_msg.isClose());

    const binary_msg = Message{ .opcode = .binary, .payload = &.{} };
    try std.testing.expect(binary_msg.isBinary());
    try std.testing.expect(!binary_msg.isText());
    try std.testing.expect(!binary_msg.isClose());

    const close_msg = Message{ .opcode = .close, .payload = &.{} };
    try std.testing.expect(close_msg.isClose());
    try std.testing.expect(!close_msg.isText());
    try std.testing.expect(!close_msg.isBinary());
}

test "ConnectionState enum values" {
    try std.testing.expect(ConnectionState.connecting != ConnectionState.open);
    try std.testing.expect(ConnectionState.open != ConnectionState.closing);
    try std.testing.expect(ConnectionState.closing != ConnectionState.closed);
}

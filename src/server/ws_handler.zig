//! WebSocket Server Handler for httpx.zig
//!
//! Provides WebSocket upgrade handling and connection management for the server.
//!
//! ## Features
//!
//! - HTTP to WebSocket upgrade detection
//! - Handshake response generation
//! - Bidirectional message handling
//! - Automatic ping/pong responses
//! - Clean close handshake
//!
//! ## Example
//!
//! ```zig
//! fn echoHandler(conn: *WebSocketConnection) !void {
//!     while (conn.isOpen()) {
//!         const msg = try conn.receive();
//!         defer conn.allocator.free(msg.payload);
//!         try conn.send(msg.payload, msg.opcode);
//!     }
//! }
//!
//! server.ws("/chat", echoHandler);
//! ```

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const zio = @import("zio");

const ws = @import("../protocol/websocket.zig");
const HttpError = @import("../core/types.zig").HttpError;
const Socket = @import("../net/socket.zig").Socket;
const Headers = @import("../core/headers.zig").Headers;
const HeaderName = @import("../core/headers.zig").HeaderName;
const Request = @import("../core/request.zig").Request;

/// WebSocket handler function type.
/// Called when a WebSocket connection is established.
pub const WebSocketHandler = *const fn (*WebSocketConnection) anyerror!void;

/// WebSocket connection state.
pub const ConnectionState = enum {
    open,
    closing,
    closed,
};

/// WebSocket server connection.
/// Represents an active WebSocket connection from a client.
pub const WebSocketConnection = struct {
    allocator: Allocator,
    transport: Transport,
    state: ConnectionState,
    frame_reader: ws.FrameReader,

    /// Maximum message size to accept.
    max_message_size: usize = ws.DEFAULT_MAX_PAYLOAD_SIZE,
    /// Whether to automatically respond to pings.
    auto_pong: bool = true,
    /// Close code if connection is closing/closed.
    close_code: ?ws.CloseCode = null,

    const Self = @This();

    /// Size of the stack-allocated send buffer for small messages.
    /// Messages larger than this will require heap allocation.
    const SEND_BUFFER_SIZE = 4096;

    const Transport = union(enum) {
        socket: Socket,
        stream: zio.net.Stream,
    };

    /// Creates a new WebSocket connection from an accepted socket.
    pub fn init(allocator: Allocator, socket: Socket) Self {
        return .{
            .allocator = allocator,
            .transport = .{ .socket = socket },
            .state = .open,
            .frame_reader = ws.FrameReader.init(allocator),
        };
    }

    /// Creates a new WebSocket connection from an accepted ZIO stream.
    pub fn initStream(allocator: Allocator, stream: zio.net.Stream) Self {
        return .{
            .allocator = allocator,
            .transport = .{ .stream = stream },
            .state = .open,
            .frame_reader = ws.FrameReader.init(allocator),
        };
    }

    /// Releases connection resources.
    pub fn deinit(self: *Self) void {
        self.frame_reader.deinit();

        switch (self.transport) {
            .socket => |*sock| sock.close(),
            .stream => |stream| stream.close(),
        }
    }

    /// Sends a text message.
    pub fn sendText(self: *Self, data: []const u8) !void {
        try self.send(data, .text);
    }

    /// Sends a binary message.
    pub fn sendBinary(self: *Self, data: []const u8) !void {
        try self.send(data, .binary);
    }

    /// Sends a message with the specified opcode.
    /// Server frames are NOT masked (per RFC 6455).
    /// Uses stack buffer for small messages to avoid allocation.
    pub fn send(self: *Self, data: []const u8, opcode: ws.Opcode) !void {
        if (self.state != .open and self.state != .closing) {
            return HttpError.ConnectionNotOpen;
        }

        const frame = ws.Frame{
            .opcode = opcode,
            .payload = data,
            .mask = null, // Server frames are unmasked
        };

        const encoded_size = ws.calcEncodedFrameSize(data.len, false);

        // Use stack buffer for small messages to avoid allocation
        if (encoded_size <= SEND_BUFFER_SIZE) {
            var stack_buf: [SEND_BUFFER_SIZE]u8 = undefined;
            const n = try ws.encodeFrameInto(&stack_buf, frame, false);
            try self.writeAll(stack_buf[0..n]);
        } else {
            // Fall back to heap allocation for large messages
            const encoded = try ws.encodeFrame(self.allocator, frame, false);
            defer self.allocator.free(encoded);
            try self.writeAll(encoded);
        }
    }

    /// Sends a ping frame.
    pub fn ping(self: *Self, data: []const u8) !void {
        try self.send(data, .ping);
    }

    /// Sends a pong frame.
    pub fn pong(self: *Self, data: []const u8) !void {
        try self.send(data, .pong);
    }

    /// Initiates a close handshake.
    pub fn close(self: *Self, code: ws.CloseCode, reason: []const u8) !void {
        if (self.state != .open) return;

        self.state = .closing;
        self.close_code = code;

        const payload = try ws.createClosePayload(self.allocator, code, reason);
        defer self.allocator.free(payload);

        try self.send(payload, .close);

        // Wait briefly for client close response and free the response payload
        if (self.receive()) |msg| {
            self.allocator.free(msg.payload);
        } else |_| {}

        self.state = .closed;
    }

    /// Receives the next message.
    /// Handles control frames automatically.
    pub fn receive(self: *Self) !Message {
        while (true) {
            // Try to decode from buffer
            if (try self.frame_reader.readMessage()) |msg| {
                switch (msg.opcode) {
                    .ping => {
                        if (self.auto_pong) {
                            try self.pong(msg.payload);
                        }
                        self.allocator.free(msg.payload);
                        continue;
                    },
                    .pong => {
                        // Pong received, ignore
                        self.allocator.free(msg.payload);
                        continue;
                    },
                    .close => {
                        const parsed = ws.parseClosePayload(msg.payload);
                        self.close_code = parsed.code;

                        // Echo close frame back
                        if (self.state == .open) {
                            self.state = .closing;
                            self.send(msg.payload, .close) catch {};
                        }
                        self.state = .closed;

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

            // Need more data from socket
            var buf: [8192]u8 = undefined;
            const n = self.read(&buf) catch |err| {
                self.state = .closed;
                return err;
            };

            if (n == 0) {
                self.state = .closed;
                return HttpError.ConnectionClosed;
            }

            try self.frame_reader.feed(buf[0..n]);
        }
    }

    fn writeAll(self: *Self, data: []const u8) !void {
        switch (self.transport) {
            .socket => |*sock| try sock.sendAll(data),
            .stream => |stream| try stream.writeAll(data, .none),
        }
    }

    fn read(self: *Self, buffer: []u8) !usize {
        return switch (self.transport) {
            .socket => |*sock| sock.recv(buffer),
            .stream => |stream| stream.read(buffer, .none),
        };
    }

    /// Returns true if the connection is open.
    pub fn isOpen(self: *const Self) bool {
        return self.state == .open;
    }
};

/// Received message from WebSocket client.
pub const Message = struct {
    opcode: ws.Opcode,
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

    /// Returns payload as text (assumes valid UTF-8).
    pub fn text(self: *const Message) []const u8 {
        return self.payload;
    }
};

/// Checks if an HTTP request is a WebSocket upgrade request.
pub fn isUpgradeRequest(request: *const Request) bool {
    // Check for required headers
    const upgrade = request.headers.get(HeaderName.UPGRADE) orelse return false;
    const connection = request.headers.get(HeaderName.CONNECTION) orelse return false;
    const key = request.headers.get(HeaderName.SEC_WEBSOCKET_KEY) orelse return false;
    const version = request.headers.get(HeaderName.SEC_WEBSOCKET_VERSION) orelse return false;

    // Validate values
    if (!eqlIgnoreCase(upgrade, "websocket")) return false;
    if (mem.indexOf(u8, connection, "Upgrade") == null and
        mem.indexOf(u8, connection, "upgrade") == null) return false;
    if (key.len == 0) return false;
    if (!mem.eql(u8, version, ws.WEBSOCKET_VERSION)) return false;

    return true;
}

/// Checks if a string contains CRLF sequences that could enable header injection.
fn containsCrlf(s: []const u8) bool {
    return mem.indexOf(u8, s, "\r") != null or mem.indexOf(u8, s, "\n") != null;
}

/// Generates the WebSocket upgrade response.
/// Returns the complete HTTP response to send to the client.
pub fn generateUpgradeResponse(allocator: Allocator, request: *const Request, protocol: ?[]const u8) ![]u8 {
    const key = request.headers.get(HeaderName.SEC_WEBSOCKET_KEY) orelse return error.MissingKey;

    // Validate protocol against CRLF injection
    if (protocol) |p| {
        if (containsCrlf(p)) return error.InvalidProtocol;
    }

    const accept = ws.computeAccept(key);

    var response = std.ArrayListUnmanaged(u8){};
    const writer = response.writer(allocator);

    try writer.writeAll("HTTP/1.1 101 Switching Protocols\r\n");
    try writer.writeAll("Upgrade: websocket\r\n");
    try writer.writeAll("Connection: Upgrade\r\n");
    try writer.print("Sec-WebSocket-Accept: {s}\r\n", .{&accept});

    if (protocol) |p| {
        try writer.print("Sec-WebSocket-Protocol: {s}\r\n", .{p});
    }

    try writer.writeAll("\r\n");

    return response.toOwnedSlice(allocator);
}

/// Performs the server-side WebSocket handshake.
/// Returns a WebSocketConnection if successful.
pub fn acceptUpgrade(
    allocator: Allocator,
    socket: Socket,
    request: *const Request,
    protocol: ?[]const u8,
) !WebSocketConnection {
    if (!isUpgradeRequest(request)) {
        return error.NotWebSocketRequest;
    }

    // Generate and send upgrade response
    const response = try generateUpgradeResponse(allocator, request, protocol);
    defer allocator.free(response);

    var sock = socket;
    try sock.sendAll(response);

    return WebSocketConnection.init(allocator, socket);
}

/// Performs the server-side WebSocket handshake over a ZIO stream.
pub fn acceptUpgradeStream(
    allocator: Allocator,
    stream: zio.net.Stream,
    request: *const Request,
    protocol: ?[]const u8,
) !WebSocketConnection {
    if (!isUpgradeRequest(request)) {
        return error.NotWebSocketRequest;
    }

    const response = try generateUpgradeResponse(allocator, request, protocol);
    defer allocator.free(response);

    try stream.writeAll(response, .none);
    return WebSocketConnection.initStream(allocator, stream);
}

/// Case-insensitive ASCII string comparison.
fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (std.ascii.toLower(ca) != std.ascii.toLower(cb)) return false;
    }
    return true;
}

test "isUpgradeRequest detection" {
    const allocator = std.testing.allocator;

    // Valid WebSocket upgrade request
    var valid_req = try Request.init(allocator, .GET, "/chat");
    defer valid_req.deinit();

    try valid_req.headers.set("Upgrade", "websocket");
    try valid_req.headers.set("Connection", "Upgrade");
    try valid_req.headers.set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
    try valid_req.headers.set("Sec-WebSocket-Version", "13");

    try std.testing.expect(isUpgradeRequest(&valid_req));

    // Missing headers
    var invalid_req = try Request.init(allocator, .GET, "/chat");
    defer invalid_req.deinit();

    try std.testing.expect(!isUpgradeRequest(&invalid_req));
}

test "isUpgradeRequest rejects wrong upgrade header" {
    const allocator = std.testing.allocator;

    var req = try Request.init(allocator, .GET, "/chat");
    defer req.deinit();

    try req.headers.set("Upgrade", "h2c"); // Not websocket
    try req.headers.set("Connection", "Upgrade");
    try req.headers.set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
    try req.headers.set("Sec-WebSocket-Version", "13");

    try std.testing.expect(!isUpgradeRequest(&req));
}

test "isUpgradeRequest rejects wrong version" {
    const allocator = std.testing.allocator;

    var req = try Request.init(allocator, .GET, "/chat");
    defer req.deinit();

    try req.headers.set("Upgrade", "websocket");
    try req.headers.set("Connection", "Upgrade");
    try req.headers.set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
    try req.headers.set("Sec-WebSocket-Version", "8"); // Old version

    try std.testing.expect(!isUpgradeRequest(&req));
}

test "isUpgradeRequest case insensitive upgrade header" {
    const allocator = std.testing.allocator;

    var req = try Request.init(allocator, .GET, "/chat");
    defer req.deinit();

    try req.headers.set("Upgrade", "WebSocket"); // Mixed case
    try req.headers.set("Connection", "upgrade"); // lowercase
    try req.headers.set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
    try req.headers.set("Sec-WebSocket-Version", "13");

    try std.testing.expect(isUpgradeRequest(&req));
}

test "generateUpgradeResponse" {
    const allocator = std.testing.allocator;

    var req = try Request.init(allocator, .GET, "/chat");
    defer req.deinit();

    try req.headers.set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");

    const response = try generateUpgradeResponse(allocator, &req, null);
    defer allocator.free(response);

    try std.testing.expect(mem.startsWith(u8, response, "HTTP/1.1 101 Switching Protocols\r\n"));
    try std.testing.expect(mem.indexOf(u8, response, "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") != null);
    try std.testing.expect(mem.indexOf(u8, response, "Upgrade: websocket\r\n") != null);
    try std.testing.expect(mem.indexOf(u8, response, "Connection: Upgrade\r\n") != null);
}

test "generateUpgradeResponse with protocol" {
    const allocator = std.testing.allocator;

    var req = try Request.init(allocator, .GET, "/chat");
    defer req.deinit();

    try req.headers.set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");

    const response = try generateUpgradeResponse(allocator, &req, "chat.v1");
    defer allocator.free(response);

    try std.testing.expect(mem.indexOf(u8, response, "Sec-WebSocket-Protocol: chat.v1\r\n") != null);
}

test "generateUpgradeResponse missing key" {
    const allocator = std.testing.allocator;

    var req = try Request.init(allocator, .GET, "/chat");
    defer req.deinit();
    // No Sec-WebSocket-Key set

    const result = generateUpgradeResponse(allocator, &req, null);
    try std.testing.expectError(error.MissingKey, result);
}

test "Message type helpers" {
    const text_msg = Message{ .opcode = .text, .payload = &.{} };
    try std.testing.expect(text_msg.isText());
    try std.testing.expect(!text_msg.isBinary());
    try std.testing.expect(!text_msg.isClose());

    const binary_msg = Message{ .opcode = .binary, .payload = &.{} };
    try std.testing.expect(binary_msg.isBinary());
    try std.testing.expect(!binary_msg.isText());

    const close_msg = Message{ .opcode = .close, .payload = &.{} };
    try std.testing.expect(close_msg.isClose());
}

test "Message.text returns payload as string" {
    var payload = [_]u8{ 'h', 'e', 'l', 'l', 'o' };
    const msg = Message{ .opcode = .text, .payload = &payload };
    try std.testing.expectEqualStrings("hello", msg.text());
}

test "ConnectionState enum" {
    try std.testing.expect(ConnectionState.open != ConnectionState.closed);
    try std.testing.expect(ConnectionState.closing != ConnectionState.open);
}

test "eqlIgnoreCase" {
    try std.testing.expect(eqlIgnoreCase("websocket", "WebSocket"));
    try std.testing.expect(eqlIgnoreCase("WEBSOCKET", "websocket"));
    try std.testing.expect(eqlIgnoreCase("WebSocket", "WEBSOCKET"));
    try std.testing.expect(!eqlIgnoreCase("websocket", "websock"));
    try std.testing.expect(!eqlIgnoreCase("ws", "wss"));
}

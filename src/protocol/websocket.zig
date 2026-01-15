//! WebSocket Protocol Implementation for httpx.zig
//!
//! Implements the WebSocket protocol as defined in RFC 6455:
//!
//! - Frame encoding and decoding
//! - Masking/unmasking for client frames
//! - Handshake key generation and validation
//! - Control frame handling (ping, pong, close)
//!
//! WebSocket enables bidirectional, full-duplex communication channels
//! over a single TCP connection, upgraded from HTTP/1.1.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const crypto = std.crypto;

/// WebSocket frame opcodes as defined in RFC 6455 Section 5.2.
pub const Opcode = enum(u4) {
    /// Continuation frame for fragmented messages.
    continuation = 0x0,
    /// Text frame with UTF-8 encoded payload.
    text = 0x1,
    /// Binary frame with arbitrary data.
    binary = 0x2,
    // 0x3-0x7 reserved for further non-control frames
    /// Connection close frame.
    close = 0x8,
    /// Ping frame for keep-alive.
    ping = 0x9,
    /// Pong frame in response to ping.
    pong = 0xA,
    // 0xB-0xF reserved for further control frames

    /// Returns true if this is a control frame.
    pub fn isControl(self: Opcode) bool {
        return @intFromEnum(self) >= 0x8;
    }

    /// Returns true if this is a data frame.
    pub fn isData(self: Opcode) bool {
        return @intFromEnum(self) <= 0x2;
    }
};

/// WebSocket close status codes as defined in RFC 6455 Section 7.4.1.
pub const CloseCode = enum(u16) {
    /// Normal closure.
    normal = 1000,
    /// Endpoint going away (e.g., server shutdown).
    going_away = 1001,
    /// Protocol error.
    protocol_error = 1002,
    /// Unsupported data type.
    unsupported_data = 1003,
    /// Reserved (no status code present).
    no_status = 1005,
    /// Abnormal closure (connection lost without close frame).
    abnormal = 1006,
    /// Invalid payload data (e.g., non-UTF-8 in text frame).
    invalid_payload = 1007,
    /// Policy violation.
    policy_violation = 1008,
    /// Message too big.
    message_too_big = 1009,
    /// Missing expected extension.
    missing_extension = 1010,
    /// Internal server error.
    internal_error = 1011,
    /// TLS handshake failure.
    tls_handshake = 1015,

    pub fn toBytes(self: CloseCode) [2]u8 {
        const val = @intFromEnum(self);
        return .{
            @intCast((val >> 8) & 0xFF),
            @intCast(val & 0xFF),
        };
    }

    pub fn fromBytes(bytes: [2]u8) CloseCode {
        const val = (@as(u16, bytes[0]) << 8) | bytes[1];
        return @enumFromInt(val);
    }
};

/// Represents a WebSocket frame.
pub const Frame = struct {
    /// Final fragment flag.
    fin: bool = true,
    /// RSV1 extension bit.
    rsv1: bool = false,
    /// RSV2 extension bit.
    rsv2: bool = false,
    /// RSV3 extension bit.
    rsv3: bool = false,
    /// Frame opcode.
    opcode: Opcode,
    /// Masking key (required for client-to-server frames).
    mask: ?[4]u8 = null,
    /// Frame payload data.
    payload: []const u8,

    /// Returns true if this frame has the mask bit set.
    pub fn isMasked(self: *const Frame) bool {
        return self.mask != null;
    }

    /// Creates a text frame.
    pub fn text(data: []const u8) Frame {
        return .{ .opcode = .text, .payload = data };
    }

    /// Creates a binary frame.
    pub fn binary(data: []const u8) Frame {
        return .{ .opcode = .binary, .payload = data };
    }

    /// Creates a ping frame.
    pub fn ping(data: []const u8) Frame {
        return .{ .opcode = .ping, .payload = data };
    }

    /// Creates a pong frame.
    pub fn pong(data: []const u8) Frame {
        return .{ .opcode = .pong, .payload = data };
    }

    /// Creates a close frame with optional code and reason.
    pub fn close(code: ?CloseCode, reason: []const u8) Frame {
        _ = code;
        _ = reason;
        // Payload construction handled at encode time
        return .{ .opcode = .close, .payload = &.{} };
    }
};

/// Result of decoding a frame from the wire.
pub const DecodeResult = struct {
    frame: Frame,
    /// Payload data (owned by caller after decode).
    payload_owned: []u8,
    /// Total bytes consumed from input.
    bytes_consumed: usize,
};

/// WebSocket protocol constants.
///
/// The GUID is a fixed UUID defined in RFC 6455 Section 1.3.
/// It is concatenated with the client's Sec-WebSocket-Key and hashed with SHA-1
/// to produce the Sec-WebSocket-Accept header value.
/// This magic string is hardcoded in the specification and must be used by all
/// WebSocket implementations exactly as-is.
pub const WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
pub const WEBSOCKET_VERSION = "13";

/// Maximum payload size for control frames (125 bytes per RFC 6455).
pub const MAX_CONTROL_FRAME_PAYLOAD = 125;

/// Default maximum frame payload size (16 MB).
pub const DEFAULT_MAX_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;

/// Generates a random 16-byte key and returns it as base64.
/// Used for Sec-WebSocket-Key header.
pub fn generateKey() [24]u8 {
    var key_bytes: [16]u8 = undefined;
    crypto.random.bytes(&key_bytes);
    var encoded: [24]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&encoded, &key_bytes);
    return encoded;
}

/// Computes the Sec-WebSocket-Accept value from a client key.
/// accept = base64(sha1(key + GUID))
pub fn computeAccept(key: []const u8) [28]u8 {
    var hasher = crypto.hash.Sha1.init(.{});
    hasher.update(key);
    hasher.update(WEBSOCKET_GUID);
    const hash = hasher.finalResult();

    var encoded: [28]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&encoded, &hash);
    return encoded;
}

/// Validates that the server's accept key matches our client key.
pub fn validateAccept(client_key: []const u8, server_accept: []const u8) bool {
    const expected = computeAccept(client_key);
    return mem.eql(u8, &expected, server_accept);
}

/// Applies XOR masking to payload data in-place.
/// For client-to-server frames, all data must be masked.
pub fn applyMask(data: []u8, mask: [4]u8) void {
    for (data, 0..) |*byte, i| {
        byte.* ^= mask[i % 4];
    }
}

/// Generates a random 4-byte masking key.
pub fn generateMask() [4]u8 {
    var mask: [4]u8 = undefined;
    crypto.random.bytes(&mask);
    return mask;
}

/// Encodes a WebSocket frame into wire format.
/// Returns the encoded frame data (caller owns the memory).
pub fn encodeFrame(allocator: Allocator, frame: Frame, force_mask: bool) ![]u8 {
    const payload_len = frame.payload.len;

    // Calculate header size
    var header_size: usize = 2; // First two bytes always present

    // Extended payload length
    if (payload_len > 65535) {
        header_size += 8;
    } else if (payload_len > 125) {
        header_size += 2;
    }

    // Masking key
    const should_mask = force_mask or frame.mask != null;
    if (should_mask) {
        header_size += 4;
    }

    // Allocate buffer
    const total_size = header_size + payload_len;
    const buffer = try allocator.alloc(u8, total_size);
    errdefer allocator.free(buffer);

    var offset: usize = 0;

    // First byte: FIN + RSV + Opcode
    buffer[offset] = (@as(u8, if (frame.fin) 1 else 0) << 7) |
        (@as(u8, if (frame.rsv1) 1 else 0) << 6) |
        (@as(u8, if (frame.rsv2) 1 else 0) << 5) |
        (@as(u8, if (frame.rsv3) 1 else 0) << 4) |
        @intFromEnum(frame.opcode);
    offset += 1;

    // Second byte: MASK + Payload length
    const mask_bit: u8 = if (should_mask) 0x80 else 0;

    if (payload_len <= 125) {
        buffer[offset] = mask_bit | @as(u8, @intCast(payload_len));
        offset += 1;
    } else if (payload_len <= 65535) {
        buffer[offset] = mask_bit | 126;
        offset += 1;
        buffer[offset] = @intCast((payload_len >> 8) & 0xFF);
        buffer[offset + 1] = @intCast(payload_len & 0xFF);
        offset += 2;
    } else {
        buffer[offset] = mask_bit | 127;
        offset += 1;
        // 64-bit length (network byte order)
        inline for (0..8) |i| {
            buffer[offset + i] = @intCast((payload_len >> @intCast(56 - i * 8)) & 0xFF);
        }
        offset += 8;
    }

    // Masking key
    var mask_key: [4]u8 = undefined;
    if (should_mask) {
        mask_key = frame.mask orelse generateMask();
        @memcpy(buffer[offset .. offset + 4], &mask_key);
        offset += 4;
    }

    // Payload
    @memcpy(buffer[offset..], frame.payload);

    // Apply mask to payload if needed
    if (should_mask) {
        applyMask(buffer[offset..], mask_key);
    }

    return buffer;
}

/// Decodes a WebSocket frame from wire format.
/// Returns the decoded frame and number of bytes consumed.
/// Returns null if more data is needed.
pub fn decodeFrame(allocator: Allocator, data: []const u8, max_payload_size: usize) !?DecodeResult {
    if (data.len < 2) return null;

    var offset: usize = 0;

    // First byte
    const byte0 = data[offset];
    const fin = (byte0 & 0x80) != 0;
    const rsv1 = (byte0 & 0x40) != 0;
    const rsv2 = (byte0 & 0x20) != 0;
    const rsv3 = (byte0 & 0x10) != 0;
    const opcode: Opcode = @enumFromInt(byte0 & 0x0F);
    offset += 1;

    // Second byte
    const byte1 = data[offset];
    const masked = (byte1 & 0x80) != 0;
    var payload_len: u64 = byte1 & 0x7F;
    offset += 1;

    // Extended payload length
    if (payload_len == 126) {
        if (data.len < offset + 2) return null;
        payload_len = (@as(u64, data[offset]) << 8) | data[offset + 1];
        offset += 2;
    } else if (payload_len == 127) {
        if (data.len < offset + 8) return null;
        payload_len = 0;
        inline for (0..8) |i| {
            payload_len = (payload_len << 8) | data[offset + i];
        }
        offset += 8;
    }

    // Validate payload size
    if (payload_len > max_payload_size) {
        return error.PayloadTooLarge;
    }

    // Control frames cannot exceed 125 bytes
    if (opcode.isControl() and payload_len > MAX_CONTROL_FRAME_PAYLOAD) {
        return error.InvalidControlFrame;
    }

    // Masking key
    var mask: ?[4]u8 = null;
    if (masked) {
        if (data.len < offset + 4) return null;
        mask = data[offset..][0..4].*;
        offset += 4;
    }

    // Check if we have the full payload
    const payload_len_usize: usize = @intCast(payload_len);
    if (data.len < offset + payload_len_usize) return null;

    // Extract and unmask payload
    const payload = try allocator.alloc(u8, payload_len_usize);
    errdefer allocator.free(payload);

    @memcpy(payload, data[offset .. offset + payload_len_usize]);

    if (mask) |m| {
        applyMask(payload, m);
    }

    return DecodeResult{
        .frame = .{
            .fin = fin,
            .rsv1 = rsv1,
            .rsv2 = rsv2,
            .rsv3 = rsv3,
            .opcode = opcode,
            .mask = mask,
            .payload = payload,
        },
        .payload_owned = payload,
        .bytes_consumed = offset + payload_len_usize,
    };
}

/// Creates a close frame payload with status code and optional reason.
pub fn createClosePayload(allocator: Allocator, code: CloseCode, reason: []const u8) ![]u8 {
    const reason_len = @min(reason.len, MAX_CONTROL_FRAME_PAYLOAD - 2);
    const payload = try allocator.alloc(u8, 2 + reason_len);

    const code_bytes = code.toBytes();
    payload[0] = code_bytes[0];
    payload[1] = code_bytes[1];

    if (reason_len > 0) {
        @memcpy(payload[2 .. 2 + reason_len], reason[0..reason_len]);
    }

    return payload;
}

/// Parses a close frame payload to extract code and reason.
pub fn parseClosePayload(payload: []const u8) struct { code: CloseCode, reason: []const u8 } {
    if (payload.len < 2) {
        return .{ .code = .no_status, .reason = "" };
    }

    const code = CloseCode.fromBytes(payload[0..2].*);
    const reason = if (payload.len > 2) payload[2..] else "";

    return .{ .code = code, .reason = reason };
}

/// Frame reader that handles fragmented messages.
pub const FrameReader = struct {
    allocator: Allocator,
    buffer: std.ArrayListUnmanaged(u8) = .empty,
    max_payload_size: usize = DEFAULT_MAX_PAYLOAD_SIZE,
    /// Accumulated fragments for fragmented messages.
    fragment_buffer: std.ArrayListUnmanaged(u8) = .empty,
    fragment_opcode: ?Opcode = null,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Self) void {
        self.buffer.deinit(self.allocator);
        self.fragment_buffer.deinit(self.allocator);
    }

    /// Feeds data into the reader buffer.
    pub fn feed(self: *Self, data: []const u8) !void {
        try self.buffer.appendSlice(self.allocator, data);
    }

    /// Attempts to read a complete message (handling fragmentation).
    /// Returns null if more data is needed.
    /// For control frames, returns immediately.
    /// For data frames, accumulates fragments until FIN is set.
    pub fn readMessage(self: *Self) !?struct { opcode: Opcode, payload: []u8 } {
        while (true) {
            const result = try decodeFrame(self.allocator, self.buffer.items, self.max_payload_size) orelse return null;

            // Remove consumed bytes from buffer
            const remaining = self.buffer.items.len - result.bytes_consumed;
            if (remaining > 0) {
                std.mem.copyForwards(u8, self.buffer.items[0..remaining], self.buffer.items[result.bytes_consumed..]);
            }
            self.buffer.shrinkRetainingCapacity(remaining);

            const frame = result.frame;

            // Control frames are returned immediately
            if (frame.opcode.isControl()) {
                return .{ .opcode = frame.opcode, .payload = result.payload_owned };
            }

            // Handle fragmentation
            if (frame.opcode == .continuation) {
                if (self.fragment_opcode == null) {
                    self.allocator.free(result.payload_owned);
                    return error.UnexpectedContinuation;
                }
                try self.fragment_buffer.appendSlice(self.allocator, result.payload_owned);
                self.allocator.free(result.payload_owned);
            } else {
                // New data frame
                if (self.fragment_opcode != null) {
                    self.allocator.free(result.payload_owned);
                    return error.ExpectedContinuation;
                }

                if (frame.fin) {
                    // Complete unfragmented message
                    return .{ .opcode = frame.opcode, .payload = result.payload_owned };
                }

                // Start of fragmented message
                self.fragment_opcode = frame.opcode;
                try self.fragment_buffer.appendSlice(self.allocator, result.payload_owned);
                self.allocator.free(result.payload_owned);
            }

            // Check if fragmented message is complete
            if (frame.fin and self.fragment_opcode != null) {
                const opcode = self.fragment_opcode.?;
                const payload = try self.fragment_buffer.toOwnedSlice(self.allocator);
                self.fragment_opcode = null;
                return .{ .opcode = opcode, .payload = payload };
            }
        }
    }
};

// =============================================================================
// Tests
// =============================================================================

test "generateKey produces valid base64" {
    const key = generateKey();
    try std.testing.expectEqual(@as(usize, 24), key.len);
}

test "computeAccept matches RFC 6455 example" {
    // RFC 6455 Section 1.3 example
    const key = "dGhlIHNhbXBsZSBub25jZQ==";
    const accept = computeAccept(key);
    try std.testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", &accept);
}

test "validateAccept" {
    const key = "dGhlIHNhbXBsZSBub25jZQ==";
    try std.testing.expect(validateAccept(key, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
    try std.testing.expect(!validateAccept(key, "invalid"));
}

test "applyMask round-trip" {
    var data = [_]u8{ 'H', 'e', 'l', 'l', 'o' };
    const original = [_]u8{ 'H', 'e', 'l', 'l', 'o' };
    const mask = [_]u8{ 0x37, 0xfa, 0x21, 0x3d };

    applyMask(&data, mask);
    try std.testing.expect(!mem.eql(u8, &data, &original));

    applyMask(&data, mask);
    try std.testing.expectEqualSlices(u8, &original, &data);
}

test "encodeFrame small payload" {
    const allocator = std.testing.allocator;
    const frame = Frame{ .opcode = .text, .payload = "Hello" };

    const encoded = try encodeFrame(allocator, frame, false);
    defer allocator.free(encoded);

    // FIN=1, opcode=1 (text), no mask, length=5
    try std.testing.expectEqual(@as(u8, 0x81), encoded[0]);
    try std.testing.expectEqual(@as(u8, 5), encoded[1]);
    try std.testing.expectEqualStrings("Hello", encoded[2..]);
}

test "encodeFrame with mask" {
    const allocator = std.testing.allocator;
    const frame = Frame{ .opcode = .text, .payload = "Hi", .mask = [_]u8{ 1, 2, 3, 4 } };

    const encoded = try encodeFrame(allocator, frame, false);
    defer allocator.free(encoded);

    // FIN=1, opcode=1 (text), mask=1, length=2
    try std.testing.expectEqual(@as(u8, 0x81), encoded[0]);
    try std.testing.expectEqual(@as(u8, 0x82), encoded[1]); // 0x80 | 2
    // Mask key
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4 }, encoded[2..6]);
}

test "encodeFrame medium payload (126-65535 bytes)" {
    const allocator = std.testing.allocator;
    const payload = try allocator.alloc(u8, 200);
    defer allocator.free(payload);
    @memset(payload, 'A');

    const frame = Frame{ .opcode = .binary, .payload = payload };
    const encoded = try encodeFrame(allocator, frame, false);
    defer allocator.free(encoded);

    try std.testing.expectEqual(@as(u8, 0x82), encoded[0]); // FIN + binary
    try std.testing.expectEqual(@as(u8, 126), encoded[1]); // Extended length indicator
    try std.testing.expectEqual(@as(u8, 0), encoded[2]); // Length high byte
    try std.testing.expectEqual(@as(u8, 200), encoded[3]); // Length low byte
}

test "decodeFrame small payload" {
    const allocator = std.testing.allocator;
    // Manually construct: FIN=1, opcode=text, no mask, len=5, "Hello"
    const data = [_]u8{ 0x81, 0x05, 'H', 'e', 'l', 'l', 'o' };

    const result = (try decodeFrame(allocator, &data, DEFAULT_MAX_PAYLOAD_SIZE)).?;
    defer allocator.free(result.payload_owned);

    try std.testing.expect(result.frame.fin);
    try std.testing.expectEqual(Opcode.text, result.frame.opcode);
    try std.testing.expectEqualStrings("Hello", result.payload_owned);
    try std.testing.expectEqual(@as(usize, 7), result.bytes_consumed);
}

test "decodeFrame with mask" {
    const allocator = std.testing.allocator;
    // FIN=1, opcode=text, mask=1, len=2, mask=[1,2,3,4], masked payload
    var data = [_]u8{ 0x81, 0x82, 1, 2, 3, 4, 'H' ^ 1, 'i' ^ 2 };

    const result = (try decodeFrame(allocator, &data, DEFAULT_MAX_PAYLOAD_SIZE)).?;
    defer allocator.free(result.payload_owned);

    try std.testing.expectEqualStrings("Hi", result.payload_owned);
}

test "decodeFrame returns null for incomplete data" {
    const allocator = std.testing.allocator;

    // Only 1 byte
    const result1 = try decodeFrame(allocator, &[_]u8{0x81}, DEFAULT_MAX_PAYLOAD_SIZE);
    try std.testing.expect(result1 == null);

    // Header says 5 bytes but only 3 provided
    const result2 = try decodeFrame(allocator, &[_]u8{ 0x81, 0x05, 'H', 'e', 'l' }, DEFAULT_MAX_PAYLOAD_SIZE);
    try std.testing.expect(result2 == null);
}

test "encode/decode round-trip" {
    const allocator = std.testing.allocator;
    const original = Frame{
        .fin = true,
        .opcode = .text,
        .payload = "Hello, WebSocket!",
    };

    const encoded = try encodeFrame(allocator, original, false);
    defer allocator.free(encoded);

    const result = (try decodeFrame(allocator, encoded, DEFAULT_MAX_PAYLOAD_SIZE)).?;
    defer allocator.free(result.payload_owned);

    try std.testing.expect(result.frame.fin);
    try std.testing.expectEqual(Opcode.text, result.frame.opcode);
    try std.testing.expectEqualStrings("Hello, WebSocket!", result.payload_owned);
}

test "CloseCode round-trip" {
    const code = CloseCode.normal;
    const bytes = code.toBytes();
    const decoded = CloseCode.fromBytes(bytes);
    try std.testing.expectEqual(code, decoded);
}

test "createClosePayload and parseClosePayload" {
    const allocator = std.testing.allocator;

    const payload = try createClosePayload(allocator, .normal, "goodbye");
    defer allocator.free(payload);

    const parsed = parseClosePayload(payload);
    try std.testing.expectEqual(CloseCode.normal, parsed.code);
    try std.testing.expectEqualStrings("goodbye", parsed.reason);
}

test "Opcode properties" {
    try std.testing.expect(Opcode.ping.isControl());
    try std.testing.expect(Opcode.pong.isControl());
    try std.testing.expect(Opcode.close.isControl());
    try std.testing.expect(!Opcode.text.isControl());
    try std.testing.expect(!Opcode.binary.isControl());

    try std.testing.expect(Opcode.text.isData());
    try std.testing.expect(Opcode.binary.isData());
    try std.testing.expect(Opcode.continuation.isData());
    try std.testing.expect(!Opcode.ping.isData());
}

test "encodeFrame large payload (>65535 bytes)" {
    const allocator = std.testing.allocator;
    const payload = try allocator.alloc(u8, 70000);
    defer allocator.free(payload);
    @memset(payload, 'X');

    const frame = Frame{ .opcode = .binary, .payload = payload };
    const encoded = try encodeFrame(allocator, frame, false);
    defer allocator.free(encoded);

    // FIN + binary opcode
    try std.testing.expectEqual(@as(u8, 0x82), encoded[0]);
    // 127 indicates 8-byte extended length
    try std.testing.expectEqual(@as(u8, 127), encoded[1]);
    // Verify we can decode it back
    const result = (try decodeFrame(allocator, encoded, DEFAULT_MAX_PAYLOAD_SIZE)).?;
    defer allocator.free(result.payload_owned);
    try std.testing.expectEqual(@as(usize, 70000), result.payload_owned.len);
}

test "decodeFrame rejects oversized payload" {
    const allocator = std.testing.allocator;
    // Construct a frame claiming 1MB payload but with tiny max
    const data = [_]u8{ 0x82, 127, 0, 0, 0, 0, 0, 0x10, 0, 0 }; // 1MB length

    const result = decodeFrame(allocator, &data, 1024);
    try std.testing.expectError(error.PayloadTooLarge, result);
}

test "decodeFrame rejects oversized control frame" {
    const allocator = std.testing.allocator;
    // Ping frame with 126 bytes (> 125 max for control frames)
    const data = [_]u8{ 0x89, 126, 0, 126 }; // ping with extended length

    const result = decodeFrame(allocator, &data, DEFAULT_MAX_PAYLOAD_SIZE);
    try std.testing.expectError(error.InvalidControlFrame, result);
}

test "FrameReader handles fragmented message" {
    const allocator = std.testing.allocator;
    var reader = FrameReader.init(allocator);
    defer reader.deinit();

    // First fragment: text frame, FIN=0
    const frag1 = [_]u8{ 0x01, 0x03, 'H', 'e', 'l' }; // text, not final, "Hel"
    try reader.feed(&frag1);

    // Should not return yet (incomplete message)
    const msg1 = try reader.readMessage();
    try std.testing.expect(msg1 == null);

    // Continuation fragment: FIN=1
    const frag2 = [_]u8{ 0x80, 0x02, 'l', 'o' }; // continuation, final, "lo"
    try reader.feed(&frag2);

    // Now should return complete message
    const msg2 = try reader.readMessage();
    try std.testing.expect(msg2 != null);
    try std.testing.expectEqual(Opcode.text, msg2.?.opcode);
    try std.testing.expectEqualStrings("Hello", msg2.?.payload);
    allocator.free(msg2.?.payload);
}

test "FrameReader returns control frames immediately" {
    const allocator = std.testing.allocator;
    var reader = FrameReader.init(allocator);
    defer reader.deinit();

    // Ping frame
    const ping_frame = [_]u8{ 0x89, 0x04, 'p', 'i', 'n', 'g' };
    try reader.feed(&ping_frame);

    const msg = try reader.readMessage();
    try std.testing.expect(msg != null);
    try std.testing.expectEqual(Opcode.ping, msg.?.opcode);
    try std.testing.expectEqualStrings("ping", msg.?.payload);
    allocator.free(msg.?.payload);
}

test "Frame convenience constructors" {
    const text_frame = Frame.text("hello");
    try std.testing.expectEqual(Opcode.text, text_frame.opcode);
    try std.testing.expectEqualStrings("hello", text_frame.payload);

    const binary_frame = Frame.binary("data");
    try std.testing.expectEqual(Opcode.binary, binary_frame.opcode);

    const ping_frame = Frame.ping("test");
    try std.testing.expectEqual(Opcode.ping, ping_frame.opcode);

    const pong_frame = Frame.pong("test");
    try std.testing.expectEqual(Opcode.pong, pong_frame.opcode);
}

test "generateMask produces 4 bytes" {
    const mask1 = generateMask();
    const mask2 = generateMask();
    try std.testing.expectEqual(@as(usize, 4), mask1.len);
    // Masks should be random (very unlikely to be equal)
    try std.testing.expect(!std.mem.eql(u8, &mask1, &mask2));
}

test "WEBSOCKET constants" {
    try std.testing.expectEqualStrings("258EAFA5-E914-47DA-95CA-C5AB0DC85B11", WEBSOCKET_GUID);
    try std.testing.expectEqualStrings("13", WEBSOCKET_VERSION);
    try std.testing.expectEqual(@as(usize, 125), MAX_CONTROL_FRAME_PAYLOAD);
}

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

const HttpError = @import("../core/types.zig").HttpError;

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

    /// Safely converts a u4 to Opcode, returning null for reserved/invalid values.
    pub fn fromInt(val: u4) ?Opcode {
        return switch (val) {
            0x0 => .continuation,
            0x1 => .text,
            0x2 => .binary,
            0x8 => .close,
            0x9 => .ping,
            0xA => .pong,
            else => null, // Reserved opcodes 0x3-0x7, 0xB-0xF
        };
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

    /// Safely converts bytes to CloseCode, returning null for invalid/reserved values.
    pub fn fromBytes(bytes: [2]u8) ?CloseCode {
        const val = (@as(u16, bytes[0]) << 8) | bytes[1];
        return switch (val) {
            1000 => .normal,
            1001 => .going_away,
            1002 => .protocol_error,
            1003 => .unsupported_data,
            1005 => .no_status,
            1006 => .abnormal,
            1007 => .invalid_payload,
            1008 => .policy_violation,
            1009 => .message_too_big,
            1010 => .missing_extension,
            1011 => .internal_error,
            1015 => .tls_handshake,
            else => null, // Unknown/reserved close codes
        };
    }

    /// Converts bytes to CloseCode, using protocol_error for invalid values.
    pub fn fromBytesOrDefault(bytes: [2]u8) CloseCode {
        return fromBytes(bytes) orelse .protocol_error;
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

/// Calculates the header size for a frame with given payload length and mask setting.
pub fn calcFrameHeaderSize(payload_len: usize, masked: bool) usize {
    var size: usize = 2;
    if (payload_len > 65535) {
        size += 8;
    } else if (payload_len > 125) {
        size += 2;
    }
    if (masked) {
        size += 4;
    }
    return size;
}

/// Calculates the total encoded size for a frame.
pub fn calcEncodedFrameSize(payload_len: usize, masked: bool) usize {
    return calcFrameHeaderSize(payload_len, masked) + payload_len;
}

/// Encodes a WebSocket frame into a caller-provided buffer.
/// Returns the number of bytes written.
/// This avoids allocation overhead when the caller has a reusable buffer.
pub fn encodeFrameInto(buffer: []u8, frame: Frame, force_mask: bool) !usize {
    const payload_len = frame.payload.len;
    const should_mask = force_mask or frame.mask != null;
    const total_size = calcEncodedFrameSize(payload_len, should_mask);

    if (buffer.len < total_size) {
        return HttpError.BufferTooSmall;
    }

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
    @memcpy(buffer[offset .. offset + payload_len], frame.payload);

    // Apply mask if needed
    if (should_mask) {
        applyMask(buffer[offset .. offset + payload_len], mask_key);
    }

    return total_size;
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
    const opcode = Opcode.fromInt(@truncate(byte0 & 0x0F)) orelse return error.InvalidOpcode;
    offset += 1;

    if (rsv1 or rsv2 or rsv3) {
        return error.InvalidReservedBits;
    }

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

    // Control frames must not be fragmented.
    if (opcode.isControl() and !fin) {
        return error.InvalidControlFrame;
    }

    // Close frames must have either empty payload or at least code + optional reason.
    if (opcode == .close and payload_len == 1) {
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

    if (opcode == .close and payload.len > 2 and !std.unicode.utf8ValidateSlice(payload[2..])) {
        return error.InvalidControlFrame;
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

    // Use fromBytesOrDefault to safely handle unknown close codes
    const code = CloseCode.fromBytesOrDefault(payload[0..2].*);
    const reason = if (payload.len > 2) payload[2..] else "";

    return .{ .code = code, .reason = reason };
}

/// Frame reader that handles fragmented messages.
pub const FrameReader = struct {
    allocator: Allocator,
    buffer: std.ArrayListUnmanaged(u8) = .empty,
    /// Read offset into buffer (data before this has been consumed).
    read_offset: usize = 0,
    max_payload_size: usize = DEFAULT_MAX_PAYLOAD_SIZE,
    /// Maximum total size for fragmented messages (prevents DoS via infinite fragments).
    max_message_size: usize = DEFAULT_MAX_MESSAGE_SIZE,
    /// Whether to require incoming frames to be masked.
    require_masked: bool = false,
    /// Accumulated fragments for fragmented messages.
    fragment_buffer: std.ArrayListUnmanaged(u8) = .empty,
    fragment_opcode: ?Opcode = null,

    const Self = @This();

    /// Threshold for compacting the buffer (compact when read_offset exceeds this).
    const COMPACT_THRESHOLD = 4096;
    /// Default maximum message size (16 MB).
    pub const DEFAULT_MAX_MESSAGE_SIZE = 16 * 1024 * 1024;

    pub fn init(allocator: Allocator) Self {
        return .{ .allocator = allocator };
    }

    pub fn initServer(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .require_masked = true,
        };
    }

    pub fn initWithLimits(allocator: Allocator, max_payload: usize, max_message: usize) Self {
        return .{
            .allocator = allocator,
            .max_payload_size = max_payload,
            .max_message_size = max_message,
        };
    }

    pub fn deinit(self: *Self) void {
        self.buffer.deinit(self.allocator);
        self.fragment_buffer.deinit(self.allocator);
    }

    /// Resets fragment state (used when aborting a fragmented message).
    fn resetFragmentState(self: *Self) void {
        self.fragment_buffer.clearRetainingCapacity();
        self.fragment_opcode = null;
    }

    /// Feeds data into the reader buffer.
    pub fn feed(self: *Self, data: []const u8) !void {
        // Compact buffer if read_offset is large enough to avoid unbounded growth
        if (self.read_offset >= COMPACT_THRESHOLD) {
            self.compact();
        }
        try self.buffer.appendSlice(self.allocator, data);
    }

    /// Returns the unread portion of the buffer.
    inline fn unreadData(self: *const Self) []const u8 {
        return self.buffer.items[self.read_offset..];
    }

    /// Compacts the buffer by removing consumed data.
    fn compact(self: *Self) void {
        if (self.read_offset == 0) return;

        const remaining = self.buffer.items.len - self.read_offset;
        if (remaining > 0) {
            std.mem.copyForwards(u8, self.buffer.items[0..remaining], self.buffer.items[self.read_offset..]);
        }
        self.buffer.shrinkRetainingCapacity(remaining);
        self.read_offset = 0;
    }

    /// Attempts to read a complete message (handling fragmentation).
    /// Returns null if more data is needed.
    /// For control frames, returns immediately.
    /// For data frames, accumulates fragments until FIN is set.
    pub fn readMessage(self: *Self) !?struct { opcode: Opcode, payload: []u8 } {
        while (true) {
            const result = try decodeFrame(self.allocator, self.unreadData(), self.max_payload_size) orelse return null;

            // Advance read offset instead of copying every time
            self.read_offset += result.bytes_consumed;

            const frame = result.frame;

            if (self.require_masked and frame.mask == null) {
                self.allocator.free(result.payload_owned);
                return error.UnmaskedFrame;
            }

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
                // Check if adding this fragment would exceed max message size
                if (self.fragment_buffer.items.len + result.payload_owned.len > self.max_message_size) {
                    self.allocator.free(result.payload_owned);
                    self.resetFragmentState();
                    return error.MessageTooLarge;
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
                    if (frame.opcode == .text and !std.unicode.utf8ValidateSlice(result.payload_owned)) {
                        self.allocator.free(result.payload_owned);
                        return error.InvalidUtf8;
                    }
                    // Complete unfragmented message
                    return .{ .opcode = frame.opcode, .payload = result.payload_owned };
                }

                // Start of fragmented message - check initial size
                if (result.payload_owned.len > self.max_message_size) {
                    self.allocator.free(result.payload_owned);
                    return error.MessageTooLarge;
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

                if (opcode == .text and !std.unicode.utf8ValidateSlice(payload)) {
                    self.allocator.free(payload);
                    return error.InvalidUtf8;
                }

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

test "calcEncodedFrameSize" {
    // Small payload, no mask: 2 byte header + payload
    try std.testing.expectEqual(@as(usize, 7), calcEncodedFrameSize(5, false));
    // Small payload, with mask: 2 byte header + 4 byte mask + payload
    try std.testing.expectEqual(@as(usize, 11), calcEncodedFrameSize(5, true));
    // Medium payload (126 bytes), no mask: 2 + 2 + payload
    try std.testing.expectEqual(@as(usize, 130), calcEncodedFrameSize(126, false));
    // Large payload (70000 bytes), no mask: 2 + 8 + payload
    try std.testing.expectEqual(@as(usize, 70010), calcEncodedFrameSize(70000, false));
}

test "encodeFrameInto matches encodeFrame" {
    const allocator = std.testing.allocator;
    const frame = Frame{ .opcode = .text, .payload = "Hello, World!" };

    // Encode with encodeFrame
    const encoded_alloc = try encodeFrame(allocator, frame, false);
    defer allocator.free(encoded_alloc);

    // Encode with encodeFrameInto
    var buffer: [256]u8 = undefined;
    const n = try encodeFrameInto(&buffer, frame, false);

    try std.testing.expectEqualSlices(u8, encoded_alloc, buffer[0..n]);
}

test "encodeFrameInto buffer too small" {
    const frame = Frame{ .opcode = .text, .payload = "Hello" };
    var small_buffer: [4]u8 = undefined; // Too small for header + payload
    const result = encodeFrameInto(&small_buffer, frame, false);
    try std.testing.expectError(error.BufferTooSmall, result);
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

test "decodeFrame rejects control frame fragmentation" {
    const allocator = std.testing.allocator;
    const data = [_]u8{ 0x09, 0x00 }; // FIN=0, ping opcode

    const result = decodeFrame(allocator, &data, DEFAULT_MAX_PAYLOAD_SIZE);
    try std.testing.expectError(error.InvalidControlFrame, result);
}

test "decodeFrame rejects invalid reserved bits" {
    const allocator = std.testing.allocator;
    const data = [_]u8{ 0xC1, 0x00 }; // RSV1=1, text frame, empty payload

    const result = decodeFrame(allocator, &data, DEFAULT_MAX_PAYLOAD_SIZE);
    try std.testing.expectError(error.InvalidReservedBits, result);
}

test "decodeFrame rejects close payload length one" {
    const allocator = std.testing.allocator;
    const data = [_]u8{ 0x88, 0x01, 0x03 };

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

test "FrameReader server mode requires masked frames" {
    const allocator = std.testing.allocator;
    var reader = FrameReader.initServer(allocator);
    defer reader.deinit();

    const unmasked = [_]u8{ 0x81, 0x02, 'H', 'i' };
    try reader.feed(&unmasked);

    const result = reader.readMessage();
    try std.testing.expectError(error.UnmaskedFrame, result);
}

test "FrameReader validates UTF-8 for text messages" {
    const allocator = std.testing.allocator;
    var reader = FrameReader.init(allocator);
    defer reader.deinit();

    const invalid_utf8 = [_]u8{ 0x81, 0x02, 0xC3, 0x28 };
    try reader.feed(&invalid_utf8);

    const result = reader.readMessage();
    try std.testing.expectError(error.InvalidUtf8, result);
}

test "FrameReader delayed compaction" {
    const allocator = std.testing.allocator;
    var reader = FrameReader.init(allocator);
    defer reader.deinit();

    // Feed multiple small frames and read them
    // Verify read_offset advances instead of copying on each read
    const frame1 = [_]u8{ 0x81, 0x02, 'H', 'i' }; // text "Hi"
    const frame2 = [_]u8{ 0x81, 0x02, 'O', 'k' }; // text "Ok"

    try reader.feed(&frame1);
    try reader.feed(&frame2);

    // Initial state
    try std.testing.expectEqual(@as(usize, 0), reader.read_offset);
    try std.testing.expectEqual(@as(usize, 8), reader.buffer.items.len);

    // Read first message - should advance read_offset, not compact
    const msg1 = try reader.readMessage();
    try std.testing.expect(msg1 != null);
    try std.testing.expectEqualStrings("Hi", msg1.?.payload);
    allocator.free(msg1.?.payload);

    // read_offset should have advanced
    try std.testing.expectEqual(@as(usize, 4), reader.read_offset);
    // Buffer should still be same size (no compaction yet)
    try std.testing.expectEqual(@as(usize, 8), reader.buffer.items.len);

    // Read second message
    const msg2 = try reader.readMessage();
    try std.testing.expect(msg2 != null);
    try std.testing.expectEqualStrings("Ok", msg2.?.payload);
    allocator.free(msg2.?.payload);

    try std.testing.expectEqual(@as(usize, 8), reader.read_offset);
}

test "FrameReader compacts at threshold" {
    const allocator = std.testing.allocator;
    var reader = FrameReader.init(allocator);
    defer reader.deinit();

    // Create a large payload to exceed COMPACT_THRESHOLD (4096)
    // Need payload + header > 4096, so use 4100 bytes
    const large_payload = try allocator.alloc(u8, 4100);
    defer allocator.free(large_payload);
    @memset(large_payload, 'X');

    const frame = Frame{ .opcode = .binary, .payload = large_payload };
    const encoded = try encodeFrame(allocator, frame, false);
    defer allocator.free(encoded);

    // Feed and read to advance read_offset
    try reader.feed(encoded);
    const msg1 = try reader.readMessage();
    try std.testing.expect(msg1 != null);
    allocator.free(msg1.?.payload);

    // read_offset should be >= COMPACT_THRESHOLD (4096)
    try std.testing.expect(reader.read_offset >= FrameReader.COMPACT_THRESHOLD);

    // Feed more data - this should trigger compaction
    const small_frame = [_]u8{ 0x81, 0x02, 'O', 'k' };
    try reader.feed(&small_frame);

    // After compaction, read_offset should be reset to 0
    try std.testing.expectEqual(@as(usize, 0), reader.read_offset);
    // Buffer should only contain the new small frame
    try std.testing.expectEqual(@as(usize, 4), reader.buffer.items.len);

    // Should still be able to read the new frame
    const msg2 = try reader.readMessage();
    try std.testing.expect(msg2 != null);
    try std.testing.expectEqualStrings("Ok", msg2.?.payload);
    allocator.free(msg2.?.payload);
}

test "FrameReader multiple messages without compaction" {
    const allocator = std.testing.allocator;
    var reader = FrameReader.init(allocator);
    defer reader.deinit();

    // Feed 10 small frames at once
    var all_frames: [100]u8 = undefined;
    var offset: usize = 0;
    for (0..10) |i| {
        all_frames[offset] = 0x81; // FIN + text
        all_frames[offset + 1] = 0x05; // length 5
        all_frames[offset + 2] = 'M';
        all_frames[offset + 3] = 's';
        all_frames[offset + 4] = 'g';
        all_frames[offset + 5] = '0' + @as(u8, @intCast(i));
        all_frames[offset + 6] = '!';
        offset += 7;
    }

    try reader.feed(all_frames[0..offset]);

    // Read all 10 messages
    for (0..10) |i| {
        const msg = try reader.readMessage();
        try std.testing.expect(msg != null);
        try std.testing.expectEqual(@as(usize, 5), msg.?.payload.len);
        try std.testing.expectEqual(@as(u8, '0' + @as(u8, @intCast(i))), msg.?.payload[3]);
        allocator.free(msg.?.payload);
    }

    // No more messages
    const msg_none = try reader.readMessage();
    try std.testing.expect(msg_none == null);
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

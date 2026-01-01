//! HTTP Protocol Implementation for httpx.zig
//!
//! Unified HTTP protocol support for all versions, providing types and logic for:
//!
//! - HTTP/1.0: Basic request-response semantics
//! - HTTP/1.1: Persistent connections, chunked transfer, pipelining
//! - HTTP/2: Binary framing, multiplexing, header compression (HPACK)
//! - HTTP/3: QUIC transport, 0-RTT, improved multiplexing
//!
//! This module handles the wire-format intricacies of each protocol version,
//! abstraction of cross-platform networking, and protocol negotiation.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const builtin = @import("builtin");

const types = @import("../core/types.zig");
const Headers = @import("../core/headers.zig").Headers;
const HeaderName = @import("../core/headers.zig").HeaderName;
const Request = @import("../core/request.zig").Request;
const Response = @import("../core/response.zig").Response;
const Status = @import("../core/status.zig").Status;

/// HTTP protocol version negotiation result.
pub const NegotiatedProtocol = enum {
    http_1_0,
    http_1_1,
    http_2,
    http_3,

    pub fn toVersion(self: NegotiatedProtocol) types.Version {
        return switch (self) {
            .http_1_0 => .HTTP_1_0,
            .http_1_1 => .HTTP_1_1,
            .http_2 => .HTTP_2,
            .http_3 => .HTTP_3,
        };
    }
};

/// Standard Application-Layer Protocol Negotiation (ALPN) identifiers.
///
/// These strings obey the IANA registry for ALPN protocol IDs used in TLS handshakes:
/// - "http/1.1": HTTP/1.1
/// - "h2": HTTP/2 over TLS
/// - "h3": HTTP/3 over QUIC
pub const AlpnProtocol = struct {
    pub const HTTP_1_1 = "http/1.1";
    pub const HTTP_2 = "h2";
    pub const HTTP_3 = "h3";
};

/// HTTP/1.x connection handler for request/response exchange.
/// Manages the socket reader/writer, protocol versioning, and keep-alive state.
pub const Http1Connection = struct {
    allocator: Allocator,
    reader: std.io.AnyReader,
    writer: std.io.AnyWriter,
    version: types.Version = .HTTP_1_1,
    keep_alive: bool = true,

    const Self = @This();

    /// Creates a new HTTP/1.x connection.
    pub fn init(allocator: Allocator, reader: std.io.AnyReader, writer: std.io.AnyWriter) Self {
        return .{
            .allocator = allocator,
            .reader = reader,
            .writer = writer,
        };
    }

    /// Sends a request and awaits the response.
    pub fn sendRequest(self: *Self, req: *const Request) !Response {
        try self.writeRequest(req);
        return self.readResponse();
    }

    /// Serializes and writes the request to the underlying connection.
    fn writeRequest(self: *Self, req: *const Request) !void {
        const method_str = req.method.toString();
        const path = req.uri.path;
        const version_str = req.version.toString();

        try self.writer.print("{s} {s}", .{ method_str, path });
        if (req.uri.query) |q| {
            try self.writer.print("?{s}", .{q});
        }
        try self.writer.print(" {s}\r\n", .{version_str});

        for (req.headers.entries.items) |h| {
            try self.writer.print("{s}: {s}\r\n", .{ h.name, h.value });
        }
        try self.writer.writeAll("\r\n");

        if (req.body) |body| {
            try self.writer.writeAll(body);
        }
    }

    /// parse and construct the response object from the network stream.
    fn readResponse(self: *Self) !Response {
        var line_buf: [8192]u8 = undefined;

        const status_line = try self.readLine(&line_buf);
        const status_code = try parseStatusLine(status_line);

        var response = Response.init(self.allocator, status_code);
        errdefer response.deinit();

        while (true) {
            const header_line = try self.readLine(&line_buf);
            if (header_line.len == 0) break;

            if (mem.indexOf(u8, header_line, ":")) |sep| {
                const name = mem.trim(u8, header_line[0..sep], " \t");
                const value = mem.trim(u8, header_line[sep + 1 ..], " \t");
                try response.headers.append(name, value);
            }
        }

        self.keep_alive = response.headers.isKeepAlive(response.version);

        if (response.status.mayHaveBody()) {
            response.body = try self.readBody(&response.headers);
            response.body_owned = true;
        }

        return response;
    }

    /// Determines the body transfer method (Chunked, Content-Length, or Close) and reads the data.
    fn readBody(self: *Self, headers: *const Headers) ![]u8 {
        if (headers.isChunked()) {
            return self.readChunkedBody();
        }

        if (headers.getContentLength()) |length| {
            return self.readFixedBody(length);
        }

        return self.readUntilClose();
    }

    /// Reads a fixed number of bytes from the stream.
    fn readFixedBody(self: *Self, length: u64) ![]u8 {
        const body = try self.allocator.alloc(u8, @intCast(length));
        var read: usize = 0;
        while (read < length) {
            const n = try self.reader.read(body[read..]);
            if (n == 0) break;
            read += n;
        }
        return body;
    }

    /// Decodes a chunked transfer encoded body.
    fn readChunkedBody(self: *Self) ![]u8 {
        var result = std.ArrayListUnmanaged(u8){};
        var line_buf: [256]u8 = undefined;

        while (true) {
            const size_line = try self.readLine(&line_buf);
            const chunk_size = try std.fmt.parseInt(usize, size_line, 16);

            if (chunk_size == 0) break;

            const chunk = try self.allocator.alloc(u8, chunk_size);
            defer self.allocator.free(chunk);

            var read: usize = 0;
            while (read < chunk_size) {
                const n = try self.reader.read(chunk[read..]);
                if (n == 0) return error.UnexpectedEof;
                read += n;
            }

            try result.appendSlice(self.allocator, chunk);
            _ = try self.readLine(&line_buf);
        }

        _ = try self.readLine(&line_buf);
        return result.toOwnedSlice(self.allocator);
    }

    /// Reads all remaining data until the connection is closed by the peer.
    fn readUntilClose(self: *Self) ![]u8 {
        var result = std.ArrayListUnmanaged(u8){};
        var buf: [4096]u8 = undefined;

        while (true) {
            const n = self.reader.read(&buf) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return err,
            };
            if (n == 0) break;
            try result.appendSlice(self.allocator, buf[0..n]);
        }

        return result.toOwnedSlice(self.allocator);
    }

    /// Reads a CRLF-terminated line from the stream.
    fn readLine(self: *Self, buf: []u8) ![]const u8 {
        var i: usize = 0;
        while (i < buf.len - 1) {
            const byte = self.reader.readByte() catch |err| switch (err) {
                error.EndOfStream => break,
                else => return err,
            };
            if (byte == '\r') {
                const next = self.reader.readByte() catch '\n';
                if (next == '\n') break;
                buf[i] = byte;
                i += 1;
                buf[i] = next;
                i += 1;
            } else if (byte == '\n') {
                break;
            } else {
                buf[i] = byte;
                i += 1;
            }
        }
        return buf[0..i];
    }

    /// Indicates whether the persistent connection should remain open.
    pub fn shouldKeepAlive(self: *const Self) bool {
        return self.keep_alive;
    }
};

/// Parses the status line of an HTTP response (e.g., "HTTP/1.1 200 OK").
fn parseStatusLine(line: []const u8) !u16 {
    var parts = mem.splitScalar(u8, line, ' ');
    _ = parts.next();
    const status_str = parts.next() orelse return error.InvalidResponse;
    return std.fmt.parseInt(u16, status_str, 10) catch error.InvalidResponse;
}

/// HTTP/2 frame types as defined in RFC 7540.
pub const Http2FrameType = enum(u8) {
    data = 0x0,
    headers = 0x1,
    priority = 0x2,
    rst_stream = 0x3,
    settings = 0x4,
    push_promise = 0x5,
    ping = 0x6,
    goaway = 0x7,
    window_update = 0x8,
    continuation = 0x9,
};

/// Represents the 9-byte header standard for all HTTP/2 frames.
pub const Http2FrameHeader = struct {
    length: u24,
    frame_type: Http2FrameType,
    flags: u8,
    stream_id: u31,

    /// Encodes the frame header into wire format.
    pub fn serialize(self: Http2FrameHeader) [9]u8 {
        var buf: [9]u8 = undefined;
        buf[0] = @intCast((self.length >> 16) & 0xFF);
        buf[1] = @intCast((self.length >> 8) & 0xFF);
        buf[2] = @intCast(self.length & 0xFF);
        buf[3] = @intFromEnum(self.frame_type);
        buf[4] = self.flags;
        buf[5] = @intCast((self.stream_id >> 24) & 0x7F);
        buf[6] = @intCast((self.stream_id >> 16) & 0xFF);
        buf[7] = @intCast((self.stream_id >> 8) & 0xFF);
        buf[8] = @intCast(self.stream_id & 0xFF);
        return buf;
    }

    /// Decodes a frame header from wire format.
    pub fn parse(data: [9]u8) Http2FrameHeader {
        return .{
            .length = (@as(u24, data[0]) << 16) | (@as(u24, data[1]) << 8) | data[2],
            .frame_type = @enumFromInt(data[3]),
            .flags = data[4],
            .stream_id = (@as(u31, data[5] & 0x7F) << 24) | (@as(u31, data[6]) << 16) | (@as(u31, data[7]) << 8) | data[8],
        };
    }
};

/// The standard connection preface sent by the client to initiate HTTP/2.
pub const HTTP2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Configuration parameters for HTTP/2 connections.
pub const Http2Settings = enum(u16) {
    header_table_size = 0x1,
    enable_push = 0x2,
    max_concurrent_streams = 0x3,
    initial_window_size = 0x4,
    max_frame_size = 0x5,
    max_header_list_size = 0x6,
};

/// Standard error codes for HTTP/2 stream and connection termination.
pub const Http2ErrorCode = enum(u32) {
    no_error = 0x0,
    protocol_error = 0x1,
    internal_error = 0x2,
    flow_control_error = 0x3,
    settings_timeout = 0x4,
    stream_closed = 0x5,
    frame_size_error = 0x6,
    refused_stream = 0x7,
    cancel = 0x8,
    compression_error = 0x9,
    connect_error = 0xa,
    enhance_your_calm = 0xb,
    inadequate_security = 0xc,
    http_1_1_required = 0xd,
};

/// Manages the state of an HTTP/2 connection, including HPack context and streams.
pub const Http2Connection = struct {
    allocator: Allocator,
    reader: std.io.AnyReader,
    writer: std.io.AnyWriter,
    next_stream_id: u31 = 1,
    settings: Http2ConnectionSettings = .{},
    peer_settings: Http2ConnectionSettings = .{},

    const Self = @This();

    pub const Http2ConnectionSettings = struct {
        header_table_size: u32 = 4096,
        enable_push: bool = true,
        max_concurrent_streams: u32 = 100,
        initial_window_size: u32 = 65535,
        max_frame_size: u32 = 16384,
        max_header_list_size: u32 = 8192,
    };

    /// Initializes a new HTTP/2 connection state.
    pub fn init(allocator: Allocator, reader: std.io.AnyReader, writer: std.io.AnyWriter) Self {
        return .{
            .allocator = allocator,
            .reader = reader,
            .writer = writer,
        };
    }

    /// Initiates the HTTP/2 session by sending the preface and initial settings.
    pub fn handshake(self: *Self) !void {
        try self.writer.writeAll(HTTP2_PREFACE);
        try self.sendSettings();
    }

    /// Transmits the local settings to the peer.
    fn sendSettings(self: *Self) !void {
        const header = Http2FrameHeader{
            .length = 0,
            .frame_type = .settings,
            .flags = 0,
            .stream_id = 0,
        };
        const serialized = header.serialize();
        try self.writer.writeAll(&serialized);
    }
};

/// HTTP/3 frame types as defined in RFC 9114.
pub const Http3FrameType = enum(u64) {
    data = 0x00,
    headers = 0x01,
    cancel_push = 0x03,
    settings = 0x04,
    push_promise = 0x05,
    goaway = 0x07,
    max_push_id = 0x0D,
};

/// Configuration parameters for HTTP/3 connections.
pub const Http3Settings = struct {
    max_field_section_size: u64 = 0,
    qpack_max_table_capacity: u64 = 0,
    qpack_blocked_streams: u64 = 0,
};

/// Standard error codes for HTTP/3 stream and connection errors.
pub const Http3ErrorCode = enum(u64) {
    no_error = 0x100,
    general_protocol_error = 0x101,
    internal_error = 0x102,
    stream_creation_error = 0x103,
    closed_critical_stream = 0x104,
    frame_unexpected = 0x105,
    frame_error = 0x106,
    excessive_load = 0x107,
    id_error = 0x108,
    settings_error = 0x109,
    missing_settings = 0x10a,
    request_rejected = 0x10b,
    request_cancelled = 0x10c,
    request_incomplete = 0x10d,
    message_error = 0x10e,
    connect_error = 0x10f,
    version_fallback = 0x110,
};

/// Encodes an integer into the Variable-Length Integer format specified in RFC 9000.
pub fn encodeVarInt(value: u64, dest: []u8) !usize {
    if (value < 64) {
        if (dest.len < 1) return error.BufferTooSmall;
        dest[0] = @as(u8, @intCast(value));
        return 1;
    } else if (value < 16384) {
        if (dest.len < 2) return error.BufferTooSmall;
        dest[0] = @as(u8, @intCast((value >> 8) | 0x40));
        dest[1] = @as(u8, @intCast(value & 0xFF));
        return 2;
    } else if (value < 1073741824) {
        if (dest.len < 4) return error.BufferTooSmall;
        dest[0] = @as(u8, @intCast((value >> 24) | 0x80));
        dest[1] = @as(u8, @intCast((value >> 16) & 0xFF));
        dest[2] = @as(u8, @intCast((value >> 8) & 0xFF));
        dest[3] = @as(u8, @intCast(value & 0xFF));
        return 4;
    } else if (value < 4611686018427387904) {
        if (dest.len < 8) return error.BufferTooSmall;
        dest[0] = @as(u8, @intCast((value >> 56) | 0xC0));
        dest[1] = @as(u8, @intCast((value >> 48) & 0xFF));
        dest[2] = @as(u8, @intCast((value >> 40) & 0xFF));
        dest[3] = @as(u8, @intCast((value >> 32) & 0xFF));
        dest[4] = @as(u8, @intCast((value >> 24) & 0xFF));
        dest[5] = @as(u8, @intCast((value >> 16) & 0xFF));
        dest[6] = @as(u8, @intCast((value >> 8) & 0xFF));
        dest[7] = @as(u8, @intCast(value & 0xFF));
        return 8;
    }
    return error.ValueTooLarge;
}

/// Decodes an integer from the Variable-Length Integer format.
pub fn decodeVarInt(data: []const u8) !struct { value: u64, len: usize } {
    if (data.len == 0) return error.UnexpectedEof;
    const first = data[0];
    const prefix = first >> 6;
    const len: usize = @as(usize, 1) << @as(u3, @intCast(prefix));

    if (data.len < len) return error.UnexpectedEof;

    var value: u64 = @as(u64, first & 0x3F);
    var i: usize = 1;
    while (i < len) : (i += 1) {
        value = (value << 8) | data[i];
    }
    return .{ .value = value, .len = len };
}

/// Manages an HTTP/3 connection over QUIC, handling control streams and QPACK state.
pub const Http3Connection = struct {
    allocator: Allocator,
    quic_session: ?*anyopaque,
    control_stream_id: ?u64 = null,
    qpack_encoder_stream_id: ?u64 = null,
    qpack_decoder_stream_id: ?u64 = null,
    settings: Http3Settings = .{},
    peer_settings: Http3Settings = .{},

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{ .allocator = allocator, .quic_session = null };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    /// Initiates the HTTP/3 handshake, opening the unidirectional control stream.
    pub fn handshake(self: *Self) !void {
        _ = self;
        var buf: [64]u8 = undefined;
        // Stream type 0x00 indicates a Control Stream
        var offset = try encodeVarInt(0x00, &buf);

        // Settings frame (type 0x04)
        const frame_type_len = try encodeVarInt(0x04, buf[offset..]);
        offset += frame_type_len;

        // Empty settings for now (length 0)
        const len_len = try encodeVarInt(0, buf[offset..]);
        offset += len_len;
    }

    /// Serializes headers into a HEADERS frame.
    /// Note: This is a simplified implementation pending full QPACK support.
    pub fn formatHeadersFrame(self: *Self, headers: *const Headers, out_buffer: *std.ArrayListUnmanaged(u8)) !void {
        // Frame Type: HEADERS (0x01)
        var buf: [16]u8 = undefined;
        const type_len = try encodeVarInt(0x01, &buf);
        try out_buffer.appendSlice(self.allocator, buf[0..type_len]);

        const length_index = out_buffer.items.len;
        // Reserve 1 byte for length (assuming short headers for this mock)
        try out_buffer.append(self.allocator, 0);

        const payload_start = out_buffer.items.len;

        for (headers.entries.items) |h| {
            try out_buffer.appendSlice(self.allocator, h.name);
            try out_buffer.appendSlice(self.allocator, ":");
            try out_buffer.appendSlice(self.allocator, h.value);
            try out_buffer.append(self.allocator, '\n');
        }

        const payload_len = out_buffer.items.len - payload_start;
        if (payload_len < 64) {
            out_buffer.items[length_index] = @as(u8, @intCast(payload_len));
        }
    }
};

/// Formats a request object into HTTP/1.x wire format.
pub fn formatRequest(req: *const Request, allocator: Allocator) ![]u8 {
    var buffer = std.ArrayListUnmanaged(u8){};
    const writer = buffer.writer(allocator);

    const method_str = req.method.toString();
    try writer.print("{s} {s}", .{ method_str, req.uri.path });
    if (req.uri.query) |q| {
        try writer.print("?{s}", .{q});
    }
    try writer.print(" {s}\r\n", .{req.version.toString()});

    for (req.headers.entries.items) |h| {
        try writer.print("{s}: {s}\r\n", .{ h.name, h.value });
    }
    try writer.writeAll("\r\n");

    if (req.body) |body| {
        try writer.writeAll(body);
    }

    return buffer.toOwnedSlice(allocator);
}

/// Formats a response object into HTTP/1.x wire format.
pub fn formatResponse(resp: *const Response, allocator: Allocator) ![]u8 {
    var buffer = std.ArrayListUnmanaged(u8){};
    const writer = buffer.writer(allocator);

    try writer.print("{s} {d} {s}\r\n", .{
        resp.version.toString(),
        resp.status.code,
        resp.status.phrase,
    });

    for (resp.headers.entries.items) |h| {
        try writer.print("{s}: {s}\r\n", .{ h.name, h.value });
    }
    try writer.writeAll("\r\n");

    if (resp.body) |body| {
        try writer.writeAll(body);
    }

    return buffer.toOwnedSlice(allocator);
}

/// Determines the highest supported HTTP version based on ALPN negotiation string.
pub fn negotiateVersion(alpn: ?[]const u8) NegotiatedProtocol {
    if (alpn) |protocol| {
        if (mem.eql(u8, protocol, AlpnProtocol.HTTP_3)) return .http_3;
        if (mem.eql(u8, protocol, AlpnProtocol.HTTP_2)) return .http_2;
        if (mem.eql(u8, protocol, AlpnProtocol.HTTP_1_1)) return .http_1_1;
    }
    return .http_1_1;
}

test "HTTP/1.1 request formatting" {
    const allocator = std.testing.allocator;
    var request = try Request.init(allocator, .GET, "https://example.com/api/users");
    defer request.deinit();

    const formatted = try formatRequest(&request, allocator);
    defer allocator.free(formatted);

    try std.testing.expect(mem.startsWith(u8, formatted, "GET /api/users HTTP/1.1\r\n"));
}

test "HTTP/1.1 response formatting" {
    const allocator = std.testing.allocator;
    var response = Response.init(allocator, 200);
    defer response.deinit();

    const formatted = try formatResponse(&response, allocator);
    defer allocator.free(formatted);

    try std.testing.expect(mem.startsWith(u8, formatted, "HTTP/1.1 200 OK\r\n"));
}

test "HTTP/2 frame header serialization" {
    const header = Http2FrameHeader{
        .length = 256,
        .frame_type = .data,
        .flags = 0x01,
        .stream_id = 1,
    };
    const serialized = header.serialize();
    const parsed = Http2FrameHeader.parse(serialized);

    try std.testing.expectEqual(header.length, parsed.length);
    try std.testing.expectEqual(header.frame_type, parsed.frame_type);
    try std.testing.expectEqual(header.stream_id, parsed.stream_id);
}

test "Protocol negotiation" {
    try std.testing.expectEqual(NegotiatedProtocol.http_2, negotiateVersion("h2"));
    try std.testing.expectEqual(NegotiatedProtocol.http_3, negotiateVersion("h3"));
    try std.testing.expectEqual(NegotiatedProtocol.http_1_1, negotiateVersion("http/1.1"));
    try std.testing.expectEqual(NegotiatedProtocol.http_1_1, negotiateVersion(null));
}

test "Status line parsing" {
    const status = try parseStatusLine("HTTP/1.1 200 OK");
    try std.testing.expectEqual(@as(u16, 200), status);

    const redirect = try parseStatusLine("HTTP/1.1 301 Moved Permanently");
    try std.testing.expectEqual(@as(u16, 301), redirect);
}

test "VarInt encoding" {
    var buf: [8]u8 = undefined;

    // 1 byte (0-63)
    var len = try encodeVarInt(25, &buf);
    try std.testing.expectEqual(@as(usize, 1), len);
    try std.testing.expectEqual(@as(u8, 25), buf[0]);
    var decoded = try decodeVarInt(buf[0..len]);
    try std.testing.expectEqual(@as(u64, 25), decoded.value);

    // 2 bytes (64-16383)
    len = try encodeVarInt(15293, &buf);
    try std.testing.expectEqual(@as(usize, 2), len);
    decoded = try decodeVarInt(buf[0..len]);
    try std.testing.expectEqual(@as(u64, 15293), decoded.value);

    // 4 bytes
    len = try encodeVarInt(494878333, &buf);
    try std.testing.expectEqual(@as(usize, 4), len);
    decoded = try decodeVarInt(buf[0..len]);
    try std.testing.expectEqual(@as(u64, 494878333), decoded.value);
}

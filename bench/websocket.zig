//! WebSocket Benchmarks
//!
//! Benchmarks for WebSocket protocol operations:
//! - Frame encoding (various sizes)
//! - Frame decoding
//! - Masking operations
//! - Key generation and accept computation

const std = @import("std");
const main = @import("main.zig");
const httpx = main.httpx;
const benchmark = main.benchmark;

var small_payload: [64]u8 = undefined;
var medium_payload: [1024]u8 = undefined;
var large_payload: [16384]u8 = undefined;
var encode_buffer: [32768]u8 = undefined;
var encoded_small: []u8 = undefined;
var encoded_medium: []u8 = undefined;

pub fn init() !void {
    @memset(&small_payload, 'A');
    @memset(&medium_payload, 'B');
    @memset(&large_payload, 'C');

    const small_frame = httpx.WsFrame{ .opcode = .text, .payload = &small_payload };
    encoded_small = try httpx.websocket.encodeFrame(main.allocator, small_frame, false);

    const medium_frame = httpx.WsFrame{ .opcode = .binary, .payload = &medium_payload };
    encoded_medium = try httpx.websocket.encodeFrame(main.allocator, medium_frame, false);
}

pub fn deinit() void {
    main.allocator.free(encoded_small);
    main.allocator.free(encoded_medium);
}

fn benchWsEncodeSmall() void {
    const frame = httpx.WsFrame{ .opcode = .text, .payload = &small_payload };
    _ = httpx.websocket.encodeFrameInto(&encode_buffer, frame, false) catch 0;
}

fn benchWsEncodeMedium() void {
    const frame = httpx.WsFrame{ .opcode = .binary, .payload = &medium_payload };
    _ = httpx.websocket.encodeFrameInto(&encode_buffer, frame, false) catch 0;
}

fn benchWsEncodeLarge() void {
    const frame = httpx.WsFrame{ .opcode = .binary, .payload = &large_payload };
    _ = httpx.websocket.encodeFrameInto(&encode_buffer, frame, false) catch 0;
}

fn benchWsEncodeMasked() void {
    const frame = httpx.WsFrame{
        .opcode = .text,
        .payload = &small_payload,
        .mask = .{ 0x12, 0x34, 0x56, 0x78 },
    };
    _ = httpx.websocket.encodeFrameInto(&encode_buffer, frame, true) catch 0;
}

fn benchWsDecodeSmall() void {
    _ = httpx.websocket.decodeFrame(main.allocator, encoded_small, 1024 * 1024) catch null;
}

fn benchWsDecodeMedium() void {
    _ = httpx.websocket.decodeFrame(main.allocator, encoded_medium, 1024 * 1024) catch null;
}

fn benchWsMask() void {
    var data: [1024]u8 = undefined;
    @memcpy(&data, &medium_payload);
    httpx.websocket.applyMask(&data, .{ 0x12, 0x34, 0x56, 0x78 });
}

fn benchWsComputeAccept() void {
    _ = httpx.websocket.computeAccept("dGhlIHNhbXBsZSBub25jZQ==");
}

fn benchWsGenerateKey() void {
    _ = httpx.websocket.generateKey();
}

pub fn run() void {
    std.debug.print("\nWebSocket:\n", .{});
    benchmark("ws_encode_small_64B", 1_000_000, benchWsEncodeSmall);
    benchmark("ws_encode_medium_1KB", 500_000, benchWsEncodeMedium);
    benchmark("ws_encode_large_16KB", 100_000, benchWsEncodeLarge);
    benchmark("ws_encode_masked_64B", 1_000_000, benchWsEncodeMasked);
    benchmark("ws_decode_small_64B", 1_000_000, benchWsDecodeSmall);
    benchmark("ws_decode_medium_1KB", 500_000, benchWsDecodeMedium);
    benchmark("ws_mask_1KB", 1_000_000, benchWsMask);
    benchmark("ws_compute_accept", 1_000_000, benchWsComputeAccept);
    benchmark("ws_generate_key", 1_000_000, benchWsGenerateKey);
}

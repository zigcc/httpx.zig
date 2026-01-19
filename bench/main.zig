//! httpx.zig Benchmarks
//!
//! Performance benchmarks for the HTTP library.

const std = @import("std");
const httpx = @import("httpx");

fn benchmark(name: []const u8, iterations: usize, func: *const fn () void) void {
    const start = std.time.nanoTimestamp();

    for (0..iterations) |_| {
        func();
    }

    const end = std.time.nanoTimestamp();
    const elapsed_ns = @as(u64, @intCast(end - start));
    const per_op_ns = elapsed_ns / iterations;
    const ops_per_sec = if (per_op_ns > 0) 1_000_000_000 / per_op_ns else 0;

    std.debug.print("  {s}: {d} ops, {d}ns/op, {d} ops/sec\n", .{
        name,
        iterations,
        per_op_ns,
        ops_per_sec,
    });
}

var bench_allocator: std.mem.Allocator = undefined;

fn benchHeadersParse() void {
    var headers = httpx.Headers.init(bench_allocator);
    defer headers.deinit();

    headers.append("Content-Type", "application/json") catch {};
    headers.append("Authorization", "Bearer token") catch {};
    headers.append("Accept", "application/json") catch {};
    headers.append("User-Agent", "benchmark") catch {};

    _ = headers.get("Content-Type");
    _ = headers.get("Authorization");
}

fn benchUriParse() void {
    _ = httpx.Uri.parse("https://api.example.com:8080/users/123?page=1&limit=10#section") catch {};
}

fn benchStatusLookup() void {
    _ = httpx.status.reasonPhrase(200);
    _ = httpx.status.reasonPhrase(404);
    _ = httpx.status.reasonPhrase(500);
}

fn benchBase64Encode() void {
    const data = "Hello, World! This is a test string for base64 encoding.";
    const encoded = httpx.Base64.encode(bench_allocator, data) catch return;
    bench_allocator.free(encoded);
}

fn benchJsonBuilder() void {
    var builder = httpx.json.JsonBuilder.init(bench_allocator);
    defer builder.deinit();

    builder.beginObject() catch {};
    builder.key("name") catch {};
    builder.string("John") catch {};
    builder.key("age") catch {};
    builder.number(30) catch {};
    builder.key("active") catch {};
    builder.boolean(true) catch {};
    builder.endObject() catch {};
}

fn benchMethodLookup() void {
    _ = httpx.Method.fromString("GET");
    _ = httpx.Method.fromString("POST");
    _ = httpx.Method.fromString("DELETE");
}

fn benchRequestBuild() void {
    var request = httpx.Request.init(bench_allocator, .GET, "https://api.example.com/users") catch return;
    defer request.deinit();

    request.headers.set("Accept", "application/json") catch {};
}

fn benchHttp2FrameHeader() void {
    const header = httpx.Http2FrameHeader{
        .length = 1024,
        .frame_type = .data,
        .flags = 0x01,
        .stream_id = 1,
    };
    const serialized = header.serialize();
    _ = httpx.Http2FrameHeader.parse(serialized);
}

fn benchVarIntEncoding() void {
    var buf: [8]u8 = undefined;
    _ = httpx.http.encodeVarInt(494878333, &buf) catch 0;
}

// WebSocket benchmarks
var ws_small_payload: [64]u8 = undefined;
var ws_medium_payload: [1024]u8 = undefined;
var ws_large_payload: [16384]u8 = undefined;
var ws_encode_buffer: [32768]u8 = undefined;
var ws_encoded_small: []u8 = undefined;
var ws_encoded_medium: []u8 = undefined;

fn benchWsEncodeSmall() void {
    const frame = httpx.WsFrame{ .opcode = .text, .payload = &ws_small_payload };
    _ = httpx.websocket.encodeFrameInto(&ws_encode_buffer, frame, false) catch 0;
}

fn benchWsEncodeMedium() void {
    const frame = httpx.WsFrame{ .opcode = .binary, .payload = &ws_medium_payload };
    _ = httpx.websocket.encodeFrameInto(&ws_encode_buffer, frame, false) catch 0;
}

fn benchWsEncodeLarge() void {
    const frame = httpx.WsFrame{ .opcode = .binary, .payload = &ws_large_payload };
    _ = httpx.websocket.encodeFrameInto(&ws_encode_buffer, frame, false) catch 0;
}

fn benchWsEncodeMasked() void {
    const frame = httpx.WsFrame{
        .opcode = .text,
        .payload = &ws_small_payload,
        .mask = .{ 0x12, 0x34, 0x56, 0x78 },
    };
    _ = httpx.websocket.encodeFrameInto(&ws_encode_buffer, frame, true) catch 0;
}

fn benchWsDecodeSmall() void {
    _ = httpx.websocket.decodeFrame(bench_allocator, ws_encoded_small, 1024 * 1024) catch null;
}

fn benchWsDecodeMedium() void {
    _ = httpx.websocket.decodeFrame(bench_allocator, ws_encoded_medium, 1024 * 1024) catch null;
}

fn benchWsMask() void {
    var data: [1024]u8 = undefined;
    @memcpy(&data, &ws_medium_payload);
    httpx.websocket.applyMask(&data, .{ 0x12, 0x34, 0x56, 0x78 });
}

fn benchWsComputeAccept() void {
    _ = httpx.websocket.computeAccept("dGhlIHNhbXBsZSBub25jZQ==");
}

fn benchWsGenerateKey() void {
    _ = httpx.websocket.generateKey();
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    bench_allocator = gpa.allocator();

    // Initialize WebSocket test data
    @memset(&ws_small_payload, 'A');
    @memset(&ws_medium_payload, 'B');
    @memset(&ws_large_payload, 'C');

    // Pre-encode frames for decode benchmarks
    const small_frame = httpx.WsFrame{ .opcode = .text, .payload = &ws_small_payload };
    ws_encoded_small = httpx.websocket.encodeFrame(bench_allocator, small_frame, false) catch &.{};
    defer bench_allocator.free(ws_encoded_small);

    const medium_frame = httpx.WsFrame{ .opcode = .binary, .payload = &ws_medium_payload };
    ws_encoded_medium = httpx.websocket.encodeFrame(bench_allocator, medium_frame, false) catch &.{};
    defer bench_allocator.free(ws_encoded_medium);

    std.debug.print("=== httpx.zig Benchmarks ===\n\n", .{});

    std.debug.print("Core Operations:\n", .{});
    benchmark("headers_parse", 100_000, benchHeadersParse);
    benchmark("uri_parse", 100_000, benchUriParse);
    benchmark("status_lookup", 1_000_000, benchStatusLookup);
    benchmark("method_lookup", 1_000_000, benchMethodLookup);

    std.debug.print("\nEncoding:\n", .{});
    benchmark("base64_encode", 100_000, benchBase64Encode);
    benchmark("json_builder", 100_000, benchJsonBuilder);

    std.debug.print("\nRequest Building:\n", .{});
    benchmark("request_build", 50_000, benchRequestBuild);

    std.debug.print("\nHTTP/2 & HTTP/3:\n", .{});
    benchmark("h2_frame_header", 1_000_000, benchHttp2FrameHeader);
    benchmark("h3_varint_encode", 10_000_000, benchVarIntEncoding);

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

    std.debug.print("\n=== Benchmark Complete ===\n", .{});
}

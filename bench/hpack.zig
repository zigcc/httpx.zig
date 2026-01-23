//! HPACK Benchmarks (HTTP/2 Header Compression)
//!
//! Benchmarks for RFC 7541 HPACK implementation:
//! - Header encoding/decoding
//! - Integer encoding/decoding
//! - Huffman encoding/decoding
//! - Dynamic table operations
//! - Frame header serialization

const std = @import("std");
const main = @import("main.zig");
const httpx = main.httpx;
const benchmark = main.benchmark;

var hpack_ctx: httpx.HpackContext = undefined;
var hpack_encoded_data: []u8 = undefined;

const test_headers = [_]httpx.hpack.HeaderEntry{
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":path", .value = "/index.html" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":authority", .value = "www.example.com" },
    .{ .name = "accept", .value = "application/json" },
    .{ .name = "user-agent", .value = "httpx.zig/1.0" },
    .{ .name = "accept-language", .value = "en-US,en;q=0.9" },
    .{ .name = "cache-control", .value = "no-cache" },
};

pub fn init() !void {
    hpack_ctx = httpx.HpackContext.init(main.allocator);
    hpack_encoded_data = try httpx.encodeHpackHeaders(&hpack_ctx, &test_headers, main.allocator);
}

pub fn deinit() void {
    main.allocator.free(hpack_encoded_data);
    hpack_ctx.deinit();
}

fn benchHpackEncode() void {
    var ctx = httpx.HpackContext.init(main.allocator);
    defer ctx.deinit();

    const encoded = httpx.encodeHpackHeaders(&ctx, &test_headers, main.allocator) catch return;
    main.allocator.free(encoded);
}

fn benchHpackDecode() void {
    var ctx = httpx.HpackContext.init(main.allocator);
    defer ctx.deinit();

    const headers = httpx.decodeHpackHeaders(&ctx, hpack_encoded_data, main.allocator) catch return;
    for (headers) |h| {
        main.allocator.free(h.name);
        main.allocator.free(h.value);
    }
    main.allocator.free(headers);
}

fn benchHpackIntegerEncode() void {
    var buf: [10]u8 = undefined;
    _ = httpx.hpack.encodeInteger(1337, 5, &buf) catch 0;
    _ = httpx.hpack.encodeInteger(42, 7, &buf) catch 0;
    _ = httpx.hpack.encodeInteger(65535, 4, &buf) catch 0;
}

fn benchHpackIntegerDecode() void {
    const data1 = [_]u8{ 31, 154, 10 }; // 1337 with 5-bit prefix
    _ = httpx.hpack.decodeInteger(&data1, 5) catch {};

    const data2 = [_]u8{42}; // 42 with 7-bit prefix
    _ = httpx.hpack.decodeInteger(&data2, 7) catch {};
}

fn benchHpackHuffmanEncode() void {
    const encoded = httpx.hpack.HuffmanCodec.encode("www.example.com", main.allocator) catch return;
    main.allocator.free(encoded);
}

fn benchHpackHuffmanDecode() void {
    // Pre-encoded "www.example.com"
    const huffman_data = [_]u8{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
    const decoded = httpx.hpack.HuffmanCodec.decode(&huffman_data, main.allocator) catch return;
    main.allocator.free(decoded);
}

fn benchHpackDynamicTableAdd() void {
    var table = httpx.HpackDynamicTable.init(main.allocator);
    defer table.deinit();

    table.add("x-custom-header-1", "value1") catch {};
    table.add("x-custom-header-2", "value2") catch {};
    table.add("x-custom-header-3", "value3") catch {};
    _ = table.get(0);
    _ = table.get(1);
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

pub fn run() void {
    std.debug.print("\nHTTP/2 (HPACK):\n", .{});
    benchmark("hpack_encode", 50_000, benchHpackEncode);
    benchmark("hpack_decode", 50_000, benchHpackDecode);
    benchmark("hpack_int_encode", 1_000_000, benchHpackIntegerEncode);
    benchmark("hpack_int_decode", 1_000_000, benchHpackIntegerDecode);
    benchmark("hpack_huffman_enc", 100_000, benchHpackHuffmanEncode);
    benchmark("hpack_huffman_dec", 100_000, benchHpackHuffmanDecode);
    benchmark("hpack_dyn_table", 100_000, benchHpackDynamicTableAdd);
    benchmark("h2_frame_header", 1_000_000, benchHttp2FrameHeader);
}

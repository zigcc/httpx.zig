//! QPACK Benchmarks (HTTP/3 Header Compression)
//!
//! Benchmarks for RFC 9204 QPACK implementation:
//! - Header encoding/decoding
//! - Static table lookup
//! - Variable-length integer encoding (QUIC)

const std = @import("std");
const main = @import("main.zig");
const httpx = main.httpx;
const benchmark = main.benchmark;

var qpack_encoded_data: []u8 = undefined;

const test_headers = [_]httpx.qpack.HeaderEntry{
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":authority", .value = "www.example.com" },
    .{ .name = "accept", .value = "*/*" },
    .{ .name = "user-agent", .value = "httpx.zig/1.0" },
};

pub fn init() !void {
    var ctx = httpx.QpackContext.init(main.allocator);
    defer ctx.deinit();
    qpack_encoded_data = try httpx.encodeQpackHeaders(&ctx, &test_headers, main.allocator);
}

pub fn deinit() void {
    main.allocator.free(qpack_encoded_data);
}

fn benchQpackEncode() void {
    var ctx = httpx.QpackContext.init(main.allocator);
    defer ctx.deinit();

    const encoded = httpx.encodeQpackHeaders(&ctx, &test_headers, main.allocator) catch return;
    main.allocator.free(encoded);
}

fn benchQpackDecode() void {
    var ctx = httpx.QpackContext.init(main.allocator);
    defer ctx.deinit();

    const headers = httpx.decodeQpackHeaders(&ctx, qpack_encoded_data, main.allocator) catch return;
    for (headers) |h| {
        main.allocator.free(h.name);
        main.allocator.free(h.value);
    }
    main.allocator.free(headers);
}

fn benchQpackStaticLookup() void {
    _ = httpx.QpackStaticTable.findNameValue(":method", "GET");
    _ = httpx.QpackStaticTable.findNameValue(":status", "200");
    _ = httpx.QpackStaticTable.findName("content-type");
    _ = httpx.QpackStaticTable.get(17); // :method GET
}

fn benchVarIntEncoding() void {
    var buf: [8]u8 = undefined;
    _ = httpx.http.encodeVarInt(494878333, &buf) catch 0;
}

pub fn run() void {
    std.debug.print("\nHTTP/3 (QPACK):\n", .{});
    benchmark("qpack_encode", 50_000, benchQpackEncode);
    benchmark("qpack_decode", 50_000, benchQpackDecode);
    benchmark("qpack_static_lookup", 1_000_000, benchQpackStaticLookup);
    benchmark("h3_varint_encode", 10_000_000, benchVarIntEncoding);
}

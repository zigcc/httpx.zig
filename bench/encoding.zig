//! Encoding Benchmarks
//!
//! Benchmarks for encoding/decoding operations:
//! - Base64 encode/decode
//! - Hex encode/decode
//! - Percent (URL) encoding
//! - JSON building

const std = @import("std");
const main = @import("main.zig");
const httpx = main.httpx;
const benchmark = main.benchmark;

const base64_test_data = "Hello, World! This is a test string for base64 encoding.";
var base64_encoded: []u8 = undefined;

pub fn init() !void {
    base64_encoded = try httpx.Base64.encode(main.allocator, base64_test_data);
}

pub fn deinit() void {
    main.allocator.free(base64_encoded);
}

fn benchBase64Encode() void {
    const data = "Hello, World! This is a test string for base64 encoding.";
    const encoded = httpx.Base64.encode(main.allocator, data) catch return;
    main.allocator.free(encoded);
}

fn benchBase64Decode() void {
    const decoded = httpx.Base64.decode(main.allocator, base64_encoded) catch return;
    main.allocator.free(decoded);
}

fn benchHexEncode() void {
    const data = "Hello, World!";
    const encoded = httpx.Hex.encode(main.allocator, data) catch return;
    main.allocator.free(encoded);
}

fn benchHexDecode() void {
    const hex = "48656c6c6f2c20576f726c6421"; // "Hello, World!"
    const decoded = httpx.Hex.decode(main.allocator, hex) catch return;
    main.allocator.free(decoded);
}

fn benchPercentEncode() void {
    const data = "Hello World! @#$%^&*()";
    const encoded = httpx.PercentEncoding.encode(main.allocator, data) catch return;
    main.allocator.free(encoded);
}

fn benchPercentDecode() void {
    const encoded = "Hello%20World%21%20%40%23%24%25%5E%26%2A%28%29";
    const decoded = httpx.PercentEncoding.decode(main.allocator, encoded) catch return;
    main.allocator.free(decoded);
}

fn benchJsonBuilder() void {
    var builder = httpx.json.JsonBuilder.init(main.allocator);
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

pub fn run() void {
    std.debug.print("\nEncoding:\n", .{});
    benchmark("base64_encode", 100_000, benchBase64Encode);
    benchmark("base64_decode", 100_000, benchBase64Decode);
    benchmark("hex_encode", 100_000, benchHexEncode);
    benchmark("hex_decode", 100_000, benchHexDecode);
    benchmark("percent_encode", 100_000, benchPercentEncode);
    benchmark("percent_decode", 100_000, benchPercentDecode);
    benchmark("json_builder", 100_000, benchJsonBuilder);
}

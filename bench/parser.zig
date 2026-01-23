//! HTTP Parser Benchmarks
//!
//! Benchmarks for HTTP/1.x message parsing:
//! - Simple request parsing
//! - Request with multiple headers
//! - Response parsing
//! - Parser reset and reuse

const std = @import("std");
const main = @import("main.zig");
const httpx = main.httpx;
const benchmark = main.benchmark;

const http_request_simple =
    "GET /index.html HTTP/1.1\r\n" ++
    "Host: www.example.com\r\n" ++
    "Accept: text/html\r\n" ++
    "\r\n";

const http_request_with_headers =
    "POST /api/users HTTP/1.1\r\n" ++
    "Host: api.example.com\r\n" ++
    "Content-Type: application/json\r\n" ++
    "Content-Length: 27\r\n" ++
    "Authorization: Bearer token123\r\n" ++
    "Accept: application/json\r\n" ++
    "User-Agent: httpx.zig/1.0\r\n" ++
    "Cache-Control: no-cache\r\n" ++
    "\r\n" ++
    "{\"name\":\"John\",\"age\":30}";

const http_response_simple =
    "HTTP/1.1 200 OK\r\n" ++
    "Content-Type: text/html\r\n" ++
    "Content-Length: 13\r\n" ++
    "\r\n" ++
    "Hello, World!";

fn benchParserSimpleRequest() void {
    var parser = httpx.Parser.init(main.allocator);
    defer parser.deinit();

    _ = parser.feed(http_request_simple) catch {};
}

fn benchParserRequestWithHeaders() void {
    var parser = httpx.Parser.init(main.allocator);
    defer parser.deinit();

    _ = parser.feed(http_request_with_headers) catch {};
}

fn benchParserResponse() void {
    var parser = httpx.Parser.initResponse(main.allocator);
    defer parser.deinit();

    _ = parser.feed(http_response_simple) catch {};
}

fn benchParserReset() void {
    var parser = httpx.Parser.init(main.allocator);
    defer parser.deinit();

    _ = parser.feed(http_request_simple) catch {};
    parser.reset();
    _ = parser.feed(http_request_simple) catch {};
}

pub fn run() void {
    std.debug.print("\nHTTP Parser:\n", .{});
    benchmark("parser_simple_req", 100_000, benchParserSimpleRequest);
    benchmark("parser_req_headers", 100_000, benchParserRequestWithHeaders);
    benchmark("parser_response", 100_000, benchParserResponse);
    benchmark("parser_reset_reuse", 50_000, benchParserReset);
}

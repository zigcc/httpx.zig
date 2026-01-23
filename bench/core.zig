//! Core Operations Benchmarks
//!
//! Benchmarks for fundamental HTTP operations:
//! - Headers parsing and lookup
//! - URI parsing
//! - Status code lookup
//! - HTTP method lookup

const main = @import("main.zig");
const httpx = main.httpx;
const benchmark = main.benchmark;

fn benchHeadersParse() void {
    var headers = httpx.Headers.init(main.allocator);
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

fn benchMethodLookup() void {
    _ = httpx.Method.fromString("GET");
    _ = httpx.Method.fromString("POST");
    _ = httpx.Method.fromString("DELETE");
}

fn benchRequestBuild() void {
    var request = httpx.Request.init(main.allocator, .GET, "https://api.example.com/users") catch return;
    defer request.deinit();

    request.headers.set("Accept", "application/json") catch {};
}

pub fn run() void {
    std.debug.print("Core Operations:\n", .{});
    benchmark("headers_parse", 100_000, benchHeadersParse);
    benchmark("uri_parse", 100_000, benchUriParse);
    benchmark("status_lookup", 1_000_000, benchStatusLookup);
    benchmark("method_lookup", 1_000_000, benchMethodLookup);

    std.debug.print("\nRequest Building:\n", .{});
    benchmark("request_build", 50_000, benchRequestBuild);
}

const std = @import("std");

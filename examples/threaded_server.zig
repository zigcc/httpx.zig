//! Multi-Threaded Server Example
//!
//! Demonstrates using multiple ZIO executors for concurrent request handling.
//!
//! This server can handle multiple requests simultaneously by dispatching
//! them across runtime executors.
//!
//! Run with: zig build run-threaded_server
//! Test with: curl http://localhost:8080/ or wrk -t4 -c100 http://localhost:8080/

const std = @import("std");
const httpx = @import("httpx");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== Multi-Threaded Server Example ===\n\n", .{});

    // Create server
    var server = httpx.Server.initWithConfig(allocator, .{
        .host = "127.0.0.1",
        .port = 8080,
    });
    defer server.deinit();

    // Enable concurrent execution with auto-detected executor count
    // (defaults to number of CPU cores)
    server.enableThreading(.{
        .num_workers = 0, // 0 = auto-detect CPU cores
    });

    std.debug.print("Threading enabled: {}\n", .{server.isThreadingEnabled()});

    // Register routes
    try server.get("/", handleRoot);
    try server.get("/slow", handleSlow);
    try server.get("/stats", handleStats);
    try server.get("/health", handleHealth);
    try server.post("/echo", handleEcho);

    std.debug.print("\nRoutes:\n", .{});
    std.debug.print("  GET  /       - Hello World\n", .{});
    std.debug.print("  GET  /slow   - Simulated slow response (100ms)\n", .{});
    std.debug.print("  GET  /stats  - Runtime statistics\n", .{});
    std.debug.print("  GET  /health - Health check\n", .{});
    std.debug.print("  POST /echo   - Echo request body\n", .{});
    std.debug.print("\n", .{});

    // Start server (this blocks)
    try server.listen();
}

fn handleRoot(ctx: *httpx.Context) !httpx.Response {
    return ctx.text("Hello from multi-threaded httpx.zig!");
}

fn handleSlow(ctx: *httpx.Context) !httpx.Response {
    // Simulate slow processing - in multi-threaded mode, other requests
    // can be handled while this one is "processing"
    std.Thread.sleep(100 * std.time.ns_per_ms);

    return ctx.text("Slow response completed after 100ms delay");
}

fn handleStats(ctx: *httpx.Context) !httpx.Response {
    return ctx.text("Runtime statistics: query from main thread via server.getStats()");
}

fn handleHealth(ctx: *httpx.Context) !httpx.Response {
    return ctx.text("healthy - threading enabled");
}

fn handleEcho(ctx: *httpx.Context) !httpx.Response {
    const body = ctx.request.body orelse "";
    return ctx.text(body);
}

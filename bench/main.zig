//! httpx.zig Benchmarks
//!
//! Performance benchmarks for the HTTP library.
//! Organized into separate modules for better readability.

const std = @import("std");
pub const httpx = @import("httpx");

// Import benchmark modules
const core = @import("core.zig");
const encoding = @import("encoding.zig");
const parser_bench = @import("parser.zig");
const hpack_bench = @import("hpack.zig");
const qpack_bench = @import("qpack.zig");
const router_bench = @import("router.zig");
const buffer_bench = @import("buffer.zig");
const websocket_bench = @import("websocket.zig");

// =============================================================================
// Benchmark Infrastructure
// =============================================================================

pub var allocator: std.mem.Allocator = undefined;

pub fn benchmark(name: []const u8, iterations: usize, func: *const fn () void) void {
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

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    allocator = gpa.allocator();

    // Initialize all benchmark modules
    try websocket_bench.init();
    defer websocket_bench.deinit();

    try hpack_bench.init();
    defer hpack_bench.deinit();

    try qpack_bench.init();
    defer qpack_bench.deinit();

    try router_bench.init();
    defer router_bench.deinit();

    try encoding.init();
    defer encoding.deinit();

    std.debug.print("=== httpx.zig Benchmarks ===\n\n", .{});

    // Run all benchmark categories
    core.run();
    encoding.run();
    parser_bench.run();
    hpack_bench.run();
    qpack_bench.run();
    router_bench.run();
    buffer_bench.run();
    websocket_bench.run();

    std.debug.print("\n=== Benchmark Complete ===\n", .{});
}

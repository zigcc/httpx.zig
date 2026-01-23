//! Buffer Benchmarks
//!
//! Benchmarks for buffer operations:
//! - Dynamic buffer append
//! - Buffer growth/reallocation
//! - Ring buffer read/write
//! - Fixed buffer operations

const std = @import("std");
const main = @import("main.zig");
const httpx = main.httpx;
const benchmark = main.benchmark;

fn benchBufferAppend() void {
    var buf = httpx.Buffer.init(main.allocator, 64) catch return;
    defer buf.deinit();

    buf.append("Hello, ") catch {};
    buf.append("World! ") catch {};
    buf.append("This is a test.") catch {};
    buf.appendByte('!') catch {};
}

fn benchBufferGrow() void {
    var buf = httpx.Buffer.init(main.allocator, 16) catch return;
    defer buf.deinit();

    // Force multiple grow operations
    for (0..20) |_| {
        buf.append("0123456789ABCDEF") catch {};
    }
}

fn benchRingBufferOps() void {
    var ring = httpx.RingBuffer.init(main.allocator, 256) catch return;
    defer ring.deinit();

    // Write and read operations
    _ = ring.writeBytes("Hello, World! This is test data.") catch 0;
    var read_buf: [16]u8 = undefined;
    _ = ring.readBytes(&read_buf);
    _ = ring.writeBytes("More data here.") catch 0;
    _ = ring.readBytes(&read_buf);
}

fn benchFixedBuffer() void {
    var buf = httpx.FixedBuffer(256){};

    buf.append("Hello, ") catch {};
    buf.append("World!") catch {};
    _ = buf.slice();
    buf.clear();
    buf.append("Reset and write again.") catch {};
}

pub fn run() void {
    std.debug.print("\nBuffers:\n", .{});
    benchmark("buffer_append", 100_000, benchBufferAppend);
    benchmark("buffer_grow", 50_000, benchBufferGrow);
    benchmark("ring_buffer_ops", 100_000, benchRingBufferOps);
    benchmark("fixed_buffer", 500_000, benchFixedBuffer);
}

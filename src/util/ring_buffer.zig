//! Lock-Free Ring Buffer for httpx.zig
//!
//! A fixed-capacity circular buffer providing O(1) push/pop operations.
//! Used in internal queues and buffering paths.
//!
//! ## Features
//! - O(1) push and pop operations
//! - Fixed capacity with overflow detection
//! - Memory-efficient (no allocations after init)
//! - Cache-friendly sequential access

const std = @import("std");
const Allocator = std.mem.Allocator;

/// A fixed-capacity ring buffer for FIFO operations.
/// Provides O(1) push and pop, unlike ArrayList's O(n) orderedRemove(0).
pub fn RingBuffer(comptime T: type) type {
    return struct {
        buffer: []T,
        head: usize, // Next position to read from
        tail: usize, // Next position to write to
        len: usize, // Current number of items
        allocator: Allocator,

        const Self = @This();

        /// Creates a ring buffer with the specified capacity.
        pub fn init(allocator: Allocator, cap: usize) !Self {
            const buffer = try allocator.alloc(T, cap);
            return .{
                .buffer = buffer,
                .head = 0,
                .tail = 0,
                .len = 0,
                .allocator = allocator,
            };
        }

        /// Releases buffer memory.
        pub fn deinit(self: *Self) void {
            self.allocator.free(self.buffer);
            self.buffer = &.{};
            self.head = 0;
            self.tail = 0;
            self.len = 0;
        }

        /// Returns the maximum capacity.
        pub fn capacity(self: *const Self) usize {
            return self.buffer.len;
        }

        /// Returns the current number of items.
        pub fn count(self: *const Self) usize {
            return self.len;
        }

        /// Returns true if the buffer is empty.
        pub fn isEmpty(self: *const Self) bool {
            return self.len == 0;
        }

        /// Returns true if the buffer is full.
        pub fn isFull(self: *const Self) bool {
            return self.len == self.buffer.len;
        }

        /// Pushes an item to the back of the queue. O(1).
        /// Returns error.Overflow if the buffer is full.
        pub fn push(self: *Self, item: T) !void {
            if (self.isFull()) {
                return error.Overflow;
            }

            self.buffer[self.tail] = item;
            self.tail = (self.tail + 1) % self.buffer.len;
            self.len += 1;
        }

        /// Pops an item from the front of the queue. O(1).
        /// Returns null if the buffer is empty.
        pub fn pop(self: *Self) ?T {
            if (self.isEmpty()) {
                return null;
            }

            const item = self.buffer[self.head];
            self.head = (self.head + 1) % self.buffer.len;
            self.len -= 1;
            return item;
        }

        /// Peeks at the front item without removing it.
        pub fn peek(self: *const Self) ?T {
            if (self.isEmpty()) {
                return null;
            }
            return self.buffer[self.head];
        }

        /// Clears all items from the buffer.
        pub fn clear(self: *Self) void {
            self.head = 0;
            self.tail = 0;
            self.len = 0;
        }

        /// Returns remaining capacity.
        pub fn available(self: *const Self) usize {
            return self.buffer.len - self.len;
        }
    };
}

// =============================================================================
// Tests
// =============================================================================

test "RingBuffer init/deinit" {
    const allocator = std.testing.allocator;
    var rb = try RingBuffer(u32).init(allocator, 16);
    defer rb.deinit();

    try std.testing.expectEqual(@as(usize, 16), rb.capacity());
    try std.testing.expectEqual(@as(usize, 0), rb.count());
    try std.testing.expect(rb.isEmpty());
}

test "RingBuffer push/pop" {
    const allocator = std.testing.allocator;
    var rb = try RingBuffer(u32).init(allocator, 4);
    defer rb.deinit();

    try rb.push(1);
    try rb.push(2);
    try rb.push(3);

    try std.testing.expectEqual(@as(usize, 3), rb.count());

    try std.testing.expectEqual(@as(u32, 1), rb.pop().?);
    try std.testing.expectEqual(@as(u32, 2), rb.pop().?);
    try std.testing.expectEqual(@as(u32, 3), rb.pop().?);
    try std.testing.expect(rb.pop() == null);
}

test "RingBuffer wrap-around" {
    const allocator = std.testing.allocator;
    var rb = try RingBuffer(u32).init(allocator, 4);
    defer rb.deinit();

    // Fill buffer
    try rb.push(1);
    try rb.push(2);
    try rb.push(3);
    try rb.push(4);

    try std.testing.expect(rb.isFull());
    try std.testing.expectError(error.Overflow, rb.push(5));

    // Pop two
    try std.testing.expectEqual(@as(u32, 1), rb.pop().?);
    try std.testing.expectEqual(@as(u32, 2), rb.pop().?);

    // Push two more (wraps around)
    try rb.push(5);
    try rb.push(6);

    // Should get 3, 4, 5, 6 in order
    try std.testing.expectEqual(@as(u32, 3), rb.pop().?);
    try std.testing.expectEqual(@as(u32, 4), rb.pop().?);
    try std.testing.expectEqual(@as(u32, 5), rb.pop().?);
    try std.testing.expectEqual(@as(u32, 6), rb.pop().?);
}

test "RingBuffer peek" {
    const allocator = std.testing.allocator;
    var rb = try RingBuffer(u32).init(allocator, 4);
    defer rb.deinit();

    try std.testing.expect(rb.peek() == null);

    try rb.push(42);
    try std.testing.expectEqual(@as(u32, 42), rb.peek().?);
    try std.testing.expectEqual(@as(usize, 1), rb.count()); // peek doesn't remove
}

test "RingBuffer clear" {
    const allocator = std.testing.allocator;
    var rb = try RingBuffer(u32).init(allocator, 4);
    defer rb.deinit();

    try rb.push(1);
    try rb.push(2);
    try rb.push(3);

    rb.clear();

    try std.testing.expect(rb.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), rb.count());
}

test "RingBuffer with struct" {
    const Item = struct {
        id: u32,
        value: []const u8,
    };

    const allocator = std.testing.allocator;
    var rb = try RingBuffer(Item).init(allocator, 8);
    defer rb.deinit();

    try rb.push(.{ .id = 1, .value = "hello" });
    try rb.push(.{ .id = 2, .value = "world" });

    const item1 = rb.pop().?;
    try std.testing.expectEqual(@as(u32, 1), item1.id);
    try std.testing.expectEqualStrings("hello", item1.value);
}

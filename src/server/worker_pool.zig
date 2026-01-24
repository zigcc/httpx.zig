//! Server Worker Pool for httpx.zig
//!
//! Provides multi-threaded request handling for HTTP servers:
//!
//! - Configurable worker thread count (defaults to CPU cores)
//! - Thread-safe task queue with bounded capacity
//! - Graceful shutdown with task draining
//! - Real-time statistics tracking
//!
//! ## Example
//!
//! ```zig
//! var pool = WorkerPool.init(allocator, .{ .num_workers = 4 });
//! defer pool.deinit();
//!
//! pool.setHandler(myHandler, context);
//! try pool.start();
//!
//! // Submit work items
//! try pool.submit(.{ .socket = conn.socket, ... });
//! ```

const std = @import("std");
const Thread = std.Thread;
const Allocator = std.mem.Allocator;
const net = std.net;

const Socket = @import("../net/socket.zig").Socket;

pub const WorkerPoolError = error{
    PoolStopped,
    QueueFull,
};

/// Configuration for the worker pool.
pub const WorkerPoolConfig = struct {
    /// Number of worker threads. 0 = auto-detect CPU cores.
    num_workers: u32 = 0,
    /// Maximum number of pending work items in the queue.
    max_queue_size: usize = 4096,
    /// Idle timeout for workers in milliseconds (reserved for future use).
    idle_timeout_ms: u64 = 60_000,
    /// Request processing timeout in milliseconds (reserved for future use).
    request_timeout_ms: u64 = 30_000,
};

/// A work item representing an accepted connection to be processed.
pub const WorkItem = struct {
    /// The client socket.
    socket: Socket,
    /// The client's address.
    client_addr: net.Address,
    /// Timestamp when the connection was accepted.
    accepted_at: i64,
};

/// Handler function type for processing work items.
pub const WorkHandler = *const fn (*WorkItem, ?*anyopaque) void;

/// Thread pool for handling HTTP connections concurrently.
pub const WorkerPool = struct {
    allocator: Allocator,
    config: WorkerPoolConfig,

    // Task queue (thread-safe)
    queue: std.ArrayListUnmanaged(WorkItem) = .empty,
    queue_mutex: Thread.Mutex = .{},
    queue_not_empty: Thread.Condition = .{},
    queue_not_full: Thread.Condition = .{},

    // Worker threads
    workers: []Thread = &.{},
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    // Statistics
    stats: Stats = .{},
    stats_mutex: Thread.Mutex = .{},

    // Request handler (set by Server)
    handler: ?WorkHandler = null,
    handler_ctx: ?*anyopaque = null,

    const Self = @This();

    /// Worker pool statistics.
    pub const Stats = struct {
        /// Total number of requests processed.
        total_requests: u64 = 0,
        /// Number of requests currently being processed.
        active_requests: u64 = 0,
        /// Current queue depth.
        queue_depth: u64 = 0,
        /// Total number of errors encountered.
        total_errors: u64 = 0,
    };

    /// Creates a new worker pool with the given configuration.
    pub fn init(allocator: Allocator, config: WorkerPoolConfig) Self {
        var cfg = config;
        if (cfg.num_workers == 0) {
            const cpu_count = Thread.getCpuCount() catch 4;
            cfg.num_workers = @max(1, @as(u32, @intCast(cpu_count)));
        }
        return .{
            .allocator = allocator,
            .config = cfg,
        };
    }

    /// Releases all resources associated with the worker pool.
    pub fn deinit(self: *Self) void {
        self.stop();
        self.queue.deinit(self.allocator);
        if (self.workers.len > 0) {
            self.allocator.free(self.workers);
            self.workers = &.{};
        }
    }

    /// Sets the handler function for processing work items.
    pub fn setHandler(self: *Self, handler: WorkHandler, ctx: ?*anyopaque) void {
        self.handler = handler;
        self.handler_ctx = ctx;
    }

    /// Starts all worker threads.
    pub fn start(self: *Self) !void {
        if (self.running.load(.acquire)) return;
        self.running.store(true, .release);

        self.workers = try self.allocator.alloc(Thread, self.config.num_workers);
        errdefer self.allocator.free(self.workers);

        var spawned: usize = 0;
        errdefer {
            self.running.store(false, .release);
            self.queue_mutex.lock();
            self.queue_not_empty.broadcast();
            self.queue_mutex.unlock();
            for (self.workers[0..spawned]) |worker| {
                worker.join();
            }
        }

        for (self.workers) |*worker| {
            worker.* = try Thread.spawn(.{}, workerLoop, .{self});
            spawned += 1;
        }
    }

    /// Stops all worker threads gracefully.
    pub fn stop(self: *Self) void {
        if (!self.running.swap(false, .acq_rel)) return;

        // Wake up all waiting workers
        self.queue_mutex.lock();
        self.queue_not_empty.broadcast();
        self.queue_not_full.broadcast();
        self.queue_mutex.unlock();

        // Wait for all workers to exit
        for (self.workers) |worker| {
            worker.join();
        }
    }

    /// Submits a new work item to the queue.
    /// Blocks if the queue is full until space becomes available.
    pub fn submit(self: *Self, item: WorkItem) WorkerPoolError!void {
        self.queue_mutex.lock();
        defer self.queue_mutex.unlock();

        // Wait if queue is full
        while (self.queue.items.len >= self.config.max_queue_size) {
            if (!self.running.load(.acquire)) return WorkerPoolError.PoolStopped;
            self.queue_not_full.wait(&self.queue_mutex);
        }

        if (!self.running.load(.acquire)) return WorkerPoolError.PoolStopped;

        self.queue.append(self.allocator, item) catch return WorkerPoolError.QueueFull;
        self.queue_not_empty.signal();

        // Update stats
        self.stats_mutex.lock();
        self.stats.queue_depth = self.queue.items.len;
        self.stats_mutex.unlock();
    }

    /// Tries to submit a work item without blocking.
    /// Returns error.QueueFull if the queue is at capacity.
    pub fn trySubmit(self: *Self, item: WorkItem) WorkerPoolError!void {
        self.queue_mutex.lock();
        defer self.queue_mutex.unlock();

        if (!self.running.load(.acquire)) return WorkerPoolError.PoolStopped;
        if (self.queue.items.len >= self.config.max_queue_size) return WorkerPoolError.QueueFull;

        self.queue.append(self.allocator, item) catch return WorkerPoolError.QueueFull;
        self.queue_not_empty.signal();

        self.stats_mutex.lock();
        self.stats.queue_depth = self.queue.items.len;
        self.stats_mutex.unlock();
    }

    /// Returns the current statistics snapshot.
    pub fn getStats(self: *Self) Stats {
        self.stats_mutex.lock();
        defer self.stats_mutex.unlock();
        return self.stats;
    }

    /// Returns true if the pool is currently running.
    pub fn isRunning(self: *const Self) bool {
        return self.running.load(.acquire);
    }

    /// Returns the number of configured workers.
    pub fn workerCount(self: *const Self) u32 {
        return self.config.num_workers;
    }

    fn workerLoop(self: *Self) void {
        while (self.running.load(.acquire)) {
            // Get a work item from the queue
            self.queue_mutex.lock();
            while (self.queue.items.len == 0 and self.running.load(.acquire)) {
                self.queue_not_empty.wait(&self.queue_mutex);
            }

            if (!self.running.load(.acquire) and self.queue.items.len == 0) {
                self.queue_mutex.unlock();
                break;
            }

            // Pop from front of queue (FIFO)
            const item = if (self.queue.items.len > 0)
                self.queue.orderedRemove(0)
            else {
                self.queue_mutex.unlock();
                continue;
            };

            self.queue_not_full.signal();
            self.queue_mutex.unlock();

            // Update active count
            self.stats_mutex.lock();
            self.stats.active_requests += 1;
            self.stats.queue_depth = self.queue.items.len;
            self.stats_mutex.unlock();

            // Process the work item
            if (self.handler) |h| {
                var work_item = item;
                h(&work_item, self.handler_ctx);
            } else {
                // No handler set, close the socket
                var sock = item.socket;
                sock.close();
            }

            // Update stats
            self.stats_mutex.lock();
            self.stats.active_requests -|= 1;
            self.stats.total_requests += 1;
            self.stats_mutex.unlock();
        }
    }

    /// Increments the error counter.
    pub fn recordError(self: *Self) void {
        self.stats_mutex.lock();
        defer self.stats_mutex.unlock();
        self.stats.total_errors += 1;
    }
};

// =============================================================================
// Tests
// =============================================================================

test "WorkerPool initialization" {
    const allocator = std.testing.allocator;
    var pool = WorkerPool.init(allocator, .{});
    defer pool.deinit();

    try std.testing.expect(pool.config.num_workers > 0);
    try std.testing.expect(!pool.isRunning());
}

test "WorkerPool with custom config" {
    const allocator = std.testing.allocator;
    var pool = WorkerPool.init(allocator, .{
        .num_workers = 8,
        .max_queue_size = 100,
    });
    defer pool.deinit();

    try std.testing.expectEqual(@as(u32, 8), pool.config.num_workers);
    try std.testing.expectEqual(@as(usize, 100), pool.config.max_queue_size);
}

test "WorkerPool start and stop" {
    const allocator = std.testing.allocator;
    var pool = WorkerPool.init(allocator, .{ .num_workers = 2 });
    defer pool.deinit();

    try pool.start();
    try std.testing.expect(pool.isRunning());

    pool.stop();
    try std.testing.expect(!pool.isRunning());
}

test "WorkerPool stats" {
    const allocator = std.testing.allocator;
    var pool = WorkerPool.init(allocator, .{});
    defer pool.deinit();

    const stats = pool.getStats();
    try std.testing.expectEqual(@as(u64, 0), stats.total_requests);
    try std.testing.expectEqual(@as(u64, 0), stats.active_requests);
}

//! Concurrent Request Patterns for httpx.zig
//!
//! Provides parallel request execution patterns:
//!
//! - `all`: Execute all requests, wait for all to complete
//! - `any`: Execute all requests, return first successful
//! - `race`: Execute all requests, return first to complete
//! - Batch request building

const std = @import("std");
const Allocator = std.mem.Allocator;
const Thread = std.Thread;

const Client = @import("../client/client.zig").Client;
const Response = @import("../core/response.zig").Response;
const types = @import("../core/types.zig");

/// Request specification for batch operations.
pub const RequestSpec = struct {
    method: types.Method = .GET,
    url: []const u8,
    body: ?[]const u8 = null,
    headers: ?[]const [2][]const u8 = null,
};

/// Result of a parallel request.
pub const RequestResult = union(enum) {
    success: Response,
    err: anyerror,

    pub fn isSuccess(self: RequestResult) bool {
        return self == .success;
    }

    pub fn getResponse(self: *RequestResult) ?*Response {
        switch (self) {
            .success => |*r| return r,
            .err => return null,
        }
    }

    pub fn deinit(self: *RequestResult) void {
        switch (self.*) {
            .success => |*r| r.deinit(),
            .err => {},
        }
    }
};

/// Batch request builder for parallel execution.
pub const BatchBuilder = struct {
    allocator: Allocator,
    requests: std.ArrayListUnmanaged(RequestSpec) = .empty,

    const Self = @This();

    /// Creates a new batch builder.
    pub fn init(allocator: Allocator) Self {
        return .{ .allocator = allocator };
    }

    /// Releases builder resources.
    pub fn deinit(self: *Self) void {
        self.requests.deinit(self.allocator);
    }

    /// Adds a GET request to the batch.
    pub fn get(self: *Self, url: []const u8) !*Self {
        try self.requests.append(self.allocator, .{ .method = .GET, .url = url });
        return self;
    }

    /// Adds a POST request to the batch.
    pub fn post(self: *Self, url: []const u8, body: ?[]const u8) !*Self {
        try self.requests.append(self.allocator, .{ .method = .POST, .url = url, .body = body });
        return self;
    }

    /// Adds a PUT request to the batch.
    pub fn put(self: *Self, url: []const u8, body: ?[]const u8) !*Self {
        try self.requests.append(self.allocator, .{ .method = .PUT, .url = url, .body = body });
        return self;
    }

    /// Adds a DELETE request to the batch.
    pub fn delete(self: *Self, url: []const u8) !*Self {
        try self.requests.append(self.allocator, .{ .method = .DELETE, .url = url });
        return self;
    }

    /// Adds a custom request to the batch.
    pub fn add(self: *Self, spec: RequestSpec) !*Self {
        try self.requests.append(self.allocator, spec);
        return self;
    }

    /// Returns the number of requests in the batch.
    pub fn count(self: *const Self) usize {
        return self.requests.items.len;
    }

    /// Clears all requests from the batch.
    pub fn clear(self: *Self) void {
        self.requests.clearRetainingCapacity();
    }
};

/// Default maximum concurrent requests (based on typical CPU core count).
pub const DEFAULT_MAX_CONCURRENCY: usize = 16;

/// Executes all requests with limited concurrency to avoid thread explosion.
/// This is more efficient than spawning one thread per request.
///
/// `max_concurrency`: Maximum number of concurrent threads (0 = use default).
pub fn allWithConcurrency(
    allocator: Allocator,
    client: *Client,
    specs: []const RequestSpec,
    max_concurrency: usize,
) ![]RequestResult {
    const results = try allocator.alloc(RequestResult, specs.len);
    errdefer allocator.free(results);

    if (specs.len == 0) return results;

    const concurrency = if (max_concurrency == 0) DEFAULT_MAX_CONCURRENCY else max_concurrency;
    const num_threads = @min(concurrency, specs.len);

    // Shared state for work distribution
    const SharedState = struct {
        client: *Client,
        specs: []const RequestSpec,
        results: []RequestResult,
        next_index: std.atomic.Value(usize),
        completed: std.atomic.Value(usize),
        mutex: Thread.Mutex,
        done_cond: Thread.Condition,

        fn workerFn(self: *@This()) void {
            while (true) {
                // Atomically claim next work item
                const idx = self.next_index.fetchAdd(1, .acq_rel);
                if (idx >= self.specs.len) break;

                // Execute request
                self.results[idx] = executeSpec(self.client, self.specs[idx]);

                // Signal completion
                const prev = self.completed.fetchAdd(1, .acq_rel);
                if (prev + 1 == self.specs.len) {
                    self.mutex.lock();
                    self.done_cond.signal();
                    self.mutex.unlock();
                }
            }
        }
    };

    var state = SharedState{
        .client = client,
        .specs = specs,
        .results = results,
        .next_index = std.atomic.Value(usize).init(0),
        .completed = std.atomic.Value(usize).init(0),
        .mutex = .{},
        .done_cond = .{},
    };

    var threads = try allocator.alloc(Thread, num_threads);
    defer allocator.free(threads);

    var spawned: usize = 0;
    errdefer {
        // Wait for all spawned threads on error
        for (threads[0..spawned]) |t| t.join();
    }

    // Spawn worker threads
    for (threads) |*t| {
        t.* = try Thread.spawn(.{}, SharedState.workerFn, .{&state});
        spawned += 1;
    }

    // Wait for all work to complete
    state.mutex.lock();
    while (state.completed.load(.acquire) < specs.len) {
        state.done_cond.wait(&state.mutex);
    }
    state.mutex.unlock();

    // Join all threads
    for (threads[0..spawned]) |t| t.join();

    return results;
}

/// Executes all requests and waits for all to complete.
/// Uses limited concurrency for efficiency (default: 16 concurrent threads).
/// For custom concurrency limit, use `allWithConcurrency`.
pub fn all(allocator: Allocator, client: *Client, specs: []const RequestSpec) ![]RequestResult {
    return allWithConcurrency(allocator, client, specs, DEFAULT_MAX_CONCURRENCY);
}

/// Executes all requests and returns results for each one.
///
/// Unlike `all`, this never fails due to a request error; request failures are
/// represented as `RequestResult.err` values.
pub fn allSettled(allocator: Allocator, client: *Client, specs: []const RequestSpec) ![]RequestResult {
    return all(allocator, client, specs);
}

/// Executes all requests and returns the first successful response.
/// Uses limited concurrency (default: 16 threads) to avoid thread explosion.
pub fn any(allocator: Allocator, client: *Client, specs: []const RequestSpec) !?Response {
    return anyWithConcurrency(allocator, client, specs, DEFAULT_MAX_CONCURRENCY);
}

/// Executes all requests with limited concurrency, returns first successful response.
pub fn anyWithConcurrency(
    allocator: Allocator,
    client: *Client,
    specs: []const RequestSpec,
    max_concurrency: usize,
) !?Response {
    _ = allocator;

    if (specs.len == 0) return null;

    const concurrency = if (max_concurrency == 0) DEFAULT_MAX_CONCURRENCY else max_concurrency;
    const num_threads = @min(concurrency, specs.len);

    const SharedState = struct {
        client: *Client,
        specs: []const RequestSpec,
        next_index: std.atomic.Value(usize),
        winner: std.atomic.Value(bool),
        result: ?Response,
        mutex: Thread.Mutex,
        cond: Thread.Condition,
        active_workers: std.atomic.Value(usize),

        fn workerFn(self: *@This()) void {
            defer {
                const prev = self.active_workers.fetchSub(1, .acq_rel);
                if (prev == 1) {
                    self.mutex.lock();
                    self.cond.signal();
                    self.mutex.unlock();
                }
            }

            while (!self.winner.load(.acquire)) {
                const idx = self.next_index.fetchAdd(1, .acq_rel);
                if (idx >= self.specs.len) break;

                var rr = executeSpec(self.client, self.specs[idx]);

                if (rr == .success and rr.success.status.isSuccess()) {
                    if (!self.winner.swap(true, .acq_rel)) {
                        self.mutex.lock();
                        self.result = rr.success;
                        rr = .{ .err = error.UnusedResult };
                        self.cond.signal();
                        self.mutex.unlock();
                    }
                }
                rr.deinit();
            }
        }
    };

    var state = SharedState{
        .client = client,
        .specs = specs,
        .next_index = std.atomic.Value(usize).init(0),
        .winner = std.atomic.Value(bool).init(false),
        .result = null,
        .mutex = .{},
        .cond = .{},
        .active_workers = std.atomic.Value(usize).init(num_threads),
    };

    var threads = try std.heap.page_allocator.alloc(Thread, num_threads);
    defer std.heap.page_allocator.free(threads);

    var spawned: usize = 0;
    errdefer {
        state.winner.store(true, .release); // Signal workers to stop
        for (threads[0..spawned]) |t| t.join();
        if (state.result) |*r| r.deinit();
    }

    for (threads) |*t| {
        t.* = try Thread.spawn(.{}, SharedState.workerFn, .{&state});
        spawned += 1;
    }

    // Wait until a success is found or all workers complete.
    state.mutex.lock();
    while (!state.winner.load(.acquire) and state.active_workers.load(.acquire) != 0) {
        state.cond.wait(&state.mutex);
    }
    state.mutex.unlock();

    // Signal remaining workers to stop and join
    state.winner.store(true, .release);
    for (threads[0..spawned]) |t| t.join();

    return state.result;
}

/// Executes all requests and returns the first to complete (success or failure).
/// Uses limited concurrency (default: 16 threads) to avoid thread explosion.
pub fn race(allocator: Allocator, client: *Client, specs: []const RequestSpec) !RequestResult {
    return raceWithConcurrency(allocator, client, specs, DEFAULT_MAX_CONCURRENCY);
}

/// Executes all requests with limited concurrency, returns first to complete.
pub fn raceWithConcurrency(
    allocator: Allocator,
    client: *Client,
    specs: []const RequestSpec,
    max_concurrency: usize,
) !RequestResult {
    _ = allocator;

    if (specs.len == 0) return .{ .err = error.NoRequests };

    const concurrency = if (max_concurrency == 0) DEFAULT_MAX_CONCURRENCY else max_concurrency;
    const num_threads = @min(concurrency, specs.len);

    const SharedState = struct {
        client: *Client,
        specs: []const RequestSpec,
        next_index: std.atomic.Value(usize),
        winner: std.atomic.Value(bool),
        result: RequestResult,
        mutex: Thread.Mutex,
        cond: Thread.Condition,
        active_workers: std.atomic.Value(usize),

        fn workerFn(self: *@This()) void {
            defer {
                const prev = self.active_workers.fetchSub(1, .acq_rel);
                if (prev == 1) {
                    self.mutex.lock();
                    self.cond.signal();
                    self.mutex.unlock();
                }
            }

            while (!self.winner.load(.acquire)) {
                const idx = self.next_index.fetchAdd(1, .acq_rel);
                if (idx >= self.specs.len) break;

                var rr = executeSpec(self.client, self.specs[idx]);

                if (!self.winner.swap(true, .acq_rel)) {
                    self.mutex.lock();
                    self.result = rr;
                    rr = .{ .err = error.UnusedResult };
                    self.cond.signal();
                    self.mutex.unlock();
                }
                rr.deinit();
            }
        }
    };

    var state = SharedState{
        .client = client,
        .specs = specs,
        .next_index = std.atomic.Value(usize).init(0),
        .winner = std.atomic.Value(bool).init(false),
        .result = .{ .err = error.NoRequests },
        .mutex = .{},
        .cond = .{},
        .active_workers = std.atomic.Value(usize).init(num_threads),
    };

    var threads = try std.heap.page_allocator.alloc(Thread, num_threads);
    defer std.heap.page_allocator.free(threads);

    var spawned: usize = 0;
    errdefer {
        state.winner.store(true, .release);
        for (threads[0..spawned]) |t| t.join();
        state.result.deinit();
    }

    for (threads) |*t| {
        t.* = try Thread.spawn(.{}, SharedState.workerFn, .{&state});
        spawned += 1;
    }

    // Wait until first result or all workers complete.
    state.mutex.lock();
    while (!state.winner.load(.acquire) and state.active_workers.load(.acquire) != 0) {
        state.cond.wait(&state.mutex);
    }
    state.mutex.unlock();

    // Signal remaining workers to stop and join
    state.winner.store(true, .release);
    for (threads[0..spawned]) |t| t.join();

    return state.result;
}

fn executeSpec(client: *Client, spec: RequestSpec) RequestResult {
    const result = client.request(spec.method, spec.url, .{
        .body = spec.body,
        .headers = spec.headers,
    });

    if (result) |response| {
        return .{ .success = response };
    } else |err| {
        return .{ .err = err };
    }
}

test "BatchBuilder" {
    const allocator = std.testing.allocator;
    var builder = BatchBuilder.init(allocator);
    defer builder.deinit();

    _ = try builder.get("https://api.example.com/users");
    _ = try builder.post("https://api.example.com/users", "{\"name\":\"test\"}");

    try std.testing.expectEqual(@as(usize, 2), builder.count());
}

test "BatchBuilder clear" {
    const allocator = std.testing.allocator;
    var builder = BatchBuilder.init(allocator);
    defer builder.deinit();

    _ = try builder.get("https://example.com");
    try std.testing.expectEqual(@as(usize, 1), builder.count());

    builder.clear();
    try std.testing.expectEqual(@as(usize, 0), builder.count());
}

test "RequestResult" {
    var success_result = RequestResult{ .err = error.OutOfMemory };
    try std.testing.expect(!success_result.isSuccess());

    success_result.deinit();
}

test "RequestSpec" {
    const spec = RequestSpec{
        .method = .POST,
        .url = "https://api.example.com",
        .body = "{\"key\":\"value\"}",
    };

    try std.testing.expectEqual(types.Method.POST, spec.method);
    try std.testing.expect(spec.body != null);
}

test "allSettled empty" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator);
    defer client.deinit();

    const results = try allSettled(allocator, &client, &.{});
    defer allocator.free(results);
    try std.testing.expectEqual(@as(usize, 0), results.len);
}

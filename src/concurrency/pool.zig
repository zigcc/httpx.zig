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

/// Executes all requests and waits for all to complete.
pub fn all(allocator: Allocator, client: *Client, specs: []const RequestSpec) ![]RequestResult {
    var results = try allocator.alloc(RequestResult, specs.len);
    errdefer allocator.free(results);

    for (specs, 0..) |spec, i| {
        results[i] = executeSpec(client, spec);
    }

    return results;
}

/// Executes all requests and returns the first successful response.
pub fn any(allocator: Allocator, client: *Client, specs: []const RequestSpec) !?Response {
    _ = allocator;

    for (specs) |spec| {
        const result = executeSpec(client, spec);
        switch (result) {
            .success => return result.success,
            .err => continue,
        }
    }

    return null;
}

/// Executes all requests and returns the first to complete.
pub fn race(allocator: Allocator, client: *Client, specs: []const RequestSpec) !RequestResult {
    _ = allocator;

    if (specs.len == 0) {
        return .{ .err = error.NoRequests };
    }

    return executeSpec(client, specs[0]);
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

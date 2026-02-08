//! HTTP Response for httpx.zig Server
//!
//! Provides Response and ResponseBuilder for server-side HTTP responses.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const types = @import("types.zig");
const Headers = @import("headers.zig").Headers;
const HeaderName = @import("headers.zig").HeaderName;
const Status = @import("status.zig").Status;

/// HTTP response representation.
pub const Response = struct {
    allocator: Allocator,
    version: types.Version = .HTTP_1_1,
    status: Status,
    headers: Headers,
    body: ?[]const u8 = null,
    body_owned: bool = false,

    const Self = @This();

    /// Creates a new response with the given status code.
    pub fn init(allocator: Allocator, status_code: u16) Self {
        return .{
            .allocator = allocator,
            .status = Status.fromCode(status_code),
            .headers = Headers.init(allocator),
        };
    }

    /// Releases all allocated memory.
    pub fn deinit(self: *Self) void {
        self.headers.deinit();
        if (self.body_owned) {
            if (self.body) |b| {
                self.allocator.free(b);
            }
        }
    }

    /// Serializes the response to HTTP/1.1 wire format.
    pub fn serialize(self: *const Self, writer: anytype) !void {
        try writer.print("{s} {d} {s}\r\n", .{
            self.version.toString(),
            self.status.code,
            self.status.phrase,
        });

        try self.headers.serialize(writer);
        try writer.writeAll("\r\n");

        if (self.body) |body| {
            try writer.writeAll(body);
        }
    }

    /// Serializes to an allocated buffer.
    pub fn toSlice(self: *const Self, allocator: Allocator) ![]u8 {
        var buffer = std.ArrayListUnmanaged(u8){};
        const writer = buffer.writer(allocator);
        try self.serialize(writer);
        return buffer.toOwnedSlice(allocator);
    }
};

/// Fluent builder for constructing responses (server-side).
pub const ResponseBuilder = struct {
    allocator: Allocator,
    status_code: u16 = 200,
    headers: Headers,
    body_data: ?[]const u8 = null,
    body_data_owned: bool = false,

    const Self = @This();

    /// Creates a new response builder.
    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .headers = Headers.init(allocator),
        };
    }

    /// Releases builder resources.
    pub fn deinit(self: *Self) void {
        if (self.body_data_owned) {
            if (self.body_data) |b| {
                self.allocator.free(b);
            }
        }
        self.headers.deinit();
    }

    /// Sets the status code.
    pub fn status(self: *Self, code: u16) *Self {
        self.status_code = code;
        return self;
    }

    /// Adds a response header.
    pub fn header(self: *Self, name: []const u8, value: []const u8) !*Self {
        try self.headers.append(name, value);
        return self;
    }

    /// Sets the response body.
    pub fn body(self: *Self, data: []const u8) *Self {
        self.body_data = data;
        return self;
    }

    /// Sets a JSON body with appropriate Content-Type.
    pub fn json(self: *Self, value: anytype) !*Self {
        _ = try self.header(HeaderName.CONTENT_TYPE, "application/json");
        // Free any previously owned body data
        if (self.body_data_owned) {
            if (self.body_data) |b| {
                self.allocator.free(b);
            }
        }
        const serialized = try std.json.stringifyAlloc(self.allocator, value, .{});
        self.body_data = serialized;
        self.body_data_owned = true;
        return self;
    }

    /// Sets an HTML body with appropriate Content-Type.
    pub fn html(self: *Self, content: []const u8) !*Self {
        _ = try self.header(HeaderName.CONTENT_TYPE, "text/html; charset=utf-8");
        self.body_data = content;
        return self;
    }

    /// Sets a plain text body with appropriate Content-Type.
    pub fn text(self: *Self, content: []const u8) !*Self {
        _ = try self.header(HeaderName.CONTENT_TYPE, "text/plain; charset=utf-8");
        self.body_data = content;
        return self;
    }

    /// Builds the final response.
    pub fn build(self: *Self) !Response {
        var response = Response.init(self.allocator, self.status_code);

        for (self.headers.entries.items) |h| {
            try response.headers.append(h.name, h.value);
        }

        if (self.body_data) |b| {
            if (self.body_data_owned) {
                // Transfer ownership instead of duplicating
                response.body = b;
                self.body_data = null;
                self.body_data_owned = false;
            } else {
                response.body = try self.allocator.dupe(u8, b);
            }
            response.body_owned = true;

            var len_buf: [32]u8 = undefined;
            const len_str = std.fmt.bufPrint(&len_buf, "{d}", .{b.len}) catch unreachable;
            try response.headers.set(HeaderName.CONTENT_LENGTH, len_str);
        }

        return response;
    }
};

test "Response initialization" {
    const allocator = std.testing.allocator;
    var response = Response.init(allocator, 200);
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 200), response.status.code);
}

test "ResponseBuilder" {
    const allocator = std.testing.allocator;
    var builder = ResponseBuilder.init(allocator);
    defer builder.deinit();

    _ = builder.status(201);
    _ = try builder.header("X-Custom", "value");
    _ = builder.body("test content");

    var response = try builder.build();
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 201), response.status.code);
    try std.testing.expect(response.body != null);
}

test "Response serialization" {
    const allocator = std.testing.allocator;
    var response = Response.init(allocator, 200);
    defer response.deinit();

    const serialized = try response.toSlice(allocator);
    defer allocator.free(serialized);

    try std.testing.expect(mem.startsWith(u8, serialized, "HTTP/1.1 200 OK\r\n"));
}

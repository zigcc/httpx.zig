//! High-Performance Radix Tree Router for httpx.zig
//!
//! Gin-style routing with O(k) path matching (k = path length):
//!
//! - Static path matching (/users, /api/posts)
//! - Dynamic parameters (/users/:id, /posts/:postId/comments/:commentId)
//! - Wildcard routes (/static/*filepath)
//! - Route groups with prefixes and group-level middleware
//! - Method-based routing
//! - 405 Method Not Allowed detection

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const types = @import("../core/types.zig");

const Context = @import("server.zig").Context;
const Response = @import("../core/response.zig").Response;
const Middleware = @import("middleware.zig").Middleware;

/// Route parameter extracted from the URL.
pub const RouteParam = struct {
    name: []const u8,
    value: []const u8,
};

/// Handler function type.
pub const Handler = *const fn (*Context) anyerror!Response;

/// Route match result containing the handler, extracted parameters, and middleware.
pub const RouteMatch = struct {
    handler: Handler,
    params: []const RouteParam,
    middleware: []const Middleware,
};

/// Result from route lookup — distinguishes "not found" from "method not allowed".
pub const FindResult = union(enum) {
    matched: struct {
        handler: Handler,
        params: []const RouteParam,
        middleware: []const Middleware,
    },
    method_not_allowed: void,
    not_found: void,
};

// ============================================================================
// Radix Tree Node
// ============================================================================

const NodeType = enum {
    static, // Normal path segment
    param, // :name parameter
    catch_all, // *name wildcard
};

/// A single node in the radix tree. Each HTTP method has its own tree.
const Node = struct {
    /// The path segment this node represents (for static nodes).
    /// For param nodes, this is ":" followed by the param name.
    /// For catch_all nodes, this is "*" followed by the param name.
    path: []const u8 = "",
    node_type: NodeType = .static,

    /// Handler registered at this node (null if this is an intermediate node).
    handler: ?Handler = null,
    /// Middleware chain for this route (from groups).
    route_middleware: std.ArrayListUnmanaged(Middleware) = .empty,

    /// Children nodes, sorted for binary search on first character.
    children: std.ArrayListUnmanaged(*Node) = .empty,
    /// Indices for quick lookup: first char -> child index.
    /// We store the first byte of each child's path for fast dispatch.
    indices: std.ArrayListUnmanaged(u8) = .empty,

    /// Parameter child (at most one :param child per node).
    param_child: ?*Node = null,
    /// Catch-all child (at most one *wildcard child per node).
    catch_all_child: ?*Node = null,

    /// Wildcard name (the part after : or *).
    wildcard_name: []const u8 = "",

    fn deinit(self: *Node, allocator: Allocator) void {
        for (self.children.items) |child| {
            child.deinit(allocator);
            allocator.destroy(child);
        }
        self.children.deinit(allocator);
        self.indices.deinit(allocator);

        if (self.param_child) |child| {
            child.deinit(allocator);
            allocator.destroy(child);
        }
        if (self.catch_all_child) |child| {
            child.deinit(allocator);
            allocator.destroy(child);
        }

        self.route_middleware.deinit(allocator);
    }

    /// Insert a route into the radix tree.
    fn addRoute(self: *Node, allocator: Allocator, path: []const u8, handler: Handler, mw: []const Middleware) !void {
        var current = self;
        var remaining = path;

        while (remaining.len > 0) {
            // Check for parameter segment
            if (remaining[0] == ':') {
                const param_end = mem.indexOfScalar(u8, remaining, '/') orelse remaining.len;
                const param_name = remaining[1..param_end];

                if (current.param_child == null) {
                    const child = try allocator.create(Node);
                    child.* = .{
                        .path = remaining[0..param_end],
                        .node_type = .param,
                        .wildcard_name = param_name,
                    };
                    current.param_child = child;
                }

                current = current.param_child.?;
                remaining = remaining[param_end..];
                continue;
            }

            // Check for catch-all segment
            if (remaining[0] == '*') {
                const wildcard_name = if (remaining.len > 1) remaining[1..] else "filepath";
                const child = try allocator.create(Node);
                child.* = .{
                    .path = remaining,
                    .node_type = .catch_all,
                    .wildcard_name = wildcard_name,
                    .handler = handler,
                };
                try child.route_middleware.appendSlice(allocator, mw);
                current.catch_all_child = child;
                return;
            }

            // Static segment — find common prefix with existing children
            const idx = self.findChildIndex(current, remaining[0]);
            if (idx) |i| {
                const child = current.children.items[i];
                const common_len = commonPrefixLen(child.path, remaining);

                if (common_len < child.path.len) {
                    // Split the existing node
                    try splitNode(allocator, current, i, common_len);
                }

                if (common_len < remaining.len) {
                    current = current.children.items[i];
                    remaining = remaining[common_len..];
                    continue;
                } else {
                    // Exact match on this node
                    current.children.items[i].handler = handler;
                    try current.children.items[i].route_middleware.appendSlice(allocator, mw);
                    return;
                }
            } else {
                // No matching child — create a new leaf
                const child = try allocator.create(Node);
                child.* = .{
                    .path = remaining,
                    .node_type = .static,
                    .handler = handler,
                };
                try child.route_middleware.appendSlice(allocator, mw);
                try current.children.append(allocator, child);
                try current.indices.append(allocator, remaining[0]);
                return;
            }
        }

        // We consumed the entire path and landed on `current`
        current.handler = handler;
        try current.route_middleware.appendSlice(allocator, mw);
    }

    fn findChildIndex(_: *Node, node: *Node, c: u8) ?usize {
        for (node.indices.items, 0..) |ch, i| {
            if (ch == c) return i;
        }
        return null;
    }

    /// Lookup a path in the radix tree.
    /// Returns the handler, populates params_buf, and sets param_count.
    /// `path_exists` is set to true if the path matched any method (for 405 detection).
    fn lookup(
        self: *Node,
        path: []const u8,
        params_buf: *[MAX_PARAMS]RouteParam,
        param_count: *usize,
    ) ?LookupResult {
        var current = self;
        var remaining = path;

        while (true) {
            if (remaining.len == 0) {
                if (current.handler) |h| {
                    return .{
                        .handler = h,
                        .middleware = current.route_middleware.items,
                    };
                }
                return null;
            }

            // Try static children first (highest priority)
            var found_static = false;
            for (current.indices.items, 0..) |ch, i| {
                if (ch == remaining[0]) {
                    const child = current.children.items[i];
                    if (remaining.len >= child.path.len and
                        mem.eql(u8, remaining[0..child.path.len], child.path))
                    {
                        current = child;
                        remaining = remaining[child.path.len..];
                        found_static = true;
                        break;
                    }
                }
            }
            if (found_static) continue;

            // Try parameter child
            if (current.param_child) |param_node| {
                // Parameter value is everything until next '/'
                const slash_pos = mem.indexOfScalar(u8, remaining, '/') orelse remaining.len;
                if (slash_pos > 0 and param_count.* < MAX_PARAMS) {
                    params_buf[param_count.*] = .{
                        .name = param_node.wildcard_name,
                        .value = remaining[0..slash_pos],
                    };
                    param_count.* += 1;

                    remaining = remaining[slash_pos..];
                    current = param_node;
                    continue;
                }
            }

            // Try catch-all child
            if (current.catch_all_child) |catch_node| {
                if (param_count.* < MAX_PARAMS) {
                    params_buf[param_count.*] = .{
                        .name = catch_node.wildcard_name,
                        .value = remaining,
                    };
                    param_count.* += 1;
                }
                if (catch_node.handler) |h| {
                    return .{
                        .handler = h,
                        .middleware = catch_node.route_middleware.items,
                    };
                }
                return null;
            }

            return null;
        }
    }

    /// Check if any handler is registered at this path (ignoring method).
    /// Used for 405 detection.
    fn pathExists(self: *Node, path: []const u8) bool {
        var current = self;
        var remaining = path;

        while (true) {
            if (remaining.len == 0) {
                return current.handler != null;
            }

            // Try static children
            var found_static = false;
            for (current.indices.items, 0..) |ch, i| {
                if (ch == remaining[0]) {
                    const child = current.children.items[i];
                    if (remaining.len >= child.path.len and
                        mem.eql(u8, remaining[0..child.path.len], child.path))
                    {
                        current = child;
                        remaining = remaining[child.path.len..];
                        found_static = true;
                        break;
                    }
                }
            }
            if (found_static) continue;

            if (current.param_child) |param_node| {
                const slash_pos = mem.indexOfScalar(u8, remaining, '/') orelse remaining.len;
                if (slash_pos > 0) {
                    remaining = remaining[slash_pos..];
                    current = param_node;
                    continue;
                }
            }

            if (current.catch_all_child) |catch_node| {
                return catch_node.handler != null;
            }

            return false;
        }
    }
};

const LookupResult = struct {
    handler: Handler,
    middleware: []const Middleware,
};

/// Split a static node at `pos` characters.
fn splitNode(allocator: Allocator, parent: *Node, child_idx: usize, pos: usize) !void {
    const child = parent.children.items[child_idx];

    // Create a new intermediate node with the common prefix
    const intermediate = try allocator.create(Node);
    intermediate.* = .{
        .path = child.path[0..pos],
        .node_type = .static,
    };

    // The original child keeps the suffix
    child.path = child.path[pos..];

    // intermediate's child is the original child
    try intermediate.children.append(allocator, child);
    try intermediate.indices.append(allocator, child.path[0]);

    // Replace the child in parent with the intermediate
    parent.children.items[child_idx] = intermediate;
    parent.indices.items[child_idx] = intermediate.path[0];
}

fn commonPrefixLen(a: []const u8, b: []const u8) usize {
    const max = @min(a.len, b.len);
    var i: usize = 0;
    while (i < max and a[i] == b[i]) : (i += 1) {}
    return i;
}

const MAX_PARAMS = 16;

// ============================================================================
// Method Trees — one radix tree per HTTP method
// ============================================================================

const NUM_METHODS = 10;

fn methodIndex(method: types.Method) usize {
    return switch (method) {
        .GET => 0,
        .POST => 1,
        .PUT => 2,
        .DELETE => 3,
        .PATCH => 4,
        .HEAD => 5,
        .OPTIONS => 6,
        .CONNECT => 7,
        .TRACE => 8,
        .CUSTOM => 9,
    };
}

// ============================================================================
// Router
// ============================================================================

/// High-performance HTTP Router with radix tree matching.
///
/// Routes are stored in per-method radix trees for O(k) lookup where k is the
/// path length. Supports path parameters (`:name`), catch-all wildcards (`*name`),
/// route groups with prefixes, and group-level middleware.
pub const Router = struct {
    allocator: Allocator,
    trees: [NUM_METHODS]?*Node = [_]?*Node{null} ** NUM_METHODS,
    not_found_handler: ?Handler = null,
    method_not_allowed_handler: ?Handler = null,
    global_middleware: std.ArrayListUnmanaged(Middleware) = .empty,

    const Self = @This();

    /// Creates a new router.
    pub fn init(allocator: Allocator) Self {
        return .{ .allocator = allocator };
    }

    /// Releases all allocated resources.
    pub fn deinit(self: *Self) void {
        for (&self.trees) |*tree| {
            if (tree.*) |root| {
                root.deinit(self.allocator);
                self.allocator.destroy(root);
                tree.* = null;
            }
        }
        self.global_middleware.deinit(self.allocator);
    }

    /// Adds a route to the router.
    pub fn add(self: *Self, method: types.Method, pattern: []const u8, handler: Handler) !void {
        try self.addWithMiddleware(method, pattern, handler, &.{});
    }

    /// Adds a route with associated middleware.
    pub fn addWithMiddleware(self: *Self, method: types.Method, pattern: []const u8, handler: Handler, mw: []const Middleware) !void {
        const idx = methodIndex(method);
        if (self.trees[idx] == null) {
            const root = try self.allocator.create(Node);
            root.* = .{};
            self.trees[idx] = root;
        }
        try self.trees[idx].?.addRoute(self.allocator, pattern, handler, mw);
    }

    /// Finds a matching route for the given method and path.
    /// Returns a struct compatible with the old API for backward compatibility.
    pub fn find(self: *Self, method: types.Method, path: []const u8) ?struct { handler: Handler, params: []const RouteParam } {
        var params_buf: [MAX_PARAMS]RouteParam = undefined;
        var param_count: usize = 0;

        const idx = methodIndex(method);
        if (self.trees[idx]) |root| {
            if (root.lookup(path, &params_buf, &param_count)) |result| {
                return .{
                    .handler = result.handler,
                    .params = params_buf[0..param_count],
                };
            }
        }
        return null;
    }

    /// Extended find that distinguishes not_found vs method_not_allowed,
    /// and returns associated route middleware.
    pub fn findEx(self: *Self, method: types.Method, path: []const u8) FindResult {
        var params_buf: [MAX_PARAMS]RouteParam = undefined;
        var param_count: usize = 0;

        const idx = methodIndex(method);
        if (self.trees[idx]) |root| {
            if (root.lookup(path, &params_buf, &param_count)) |result| {
                return .{ .matched = .{
                    .handler = result.handler,
                    .params = params_buf[0..param_count],
                    .middleware = result.middleware,
                } };
            }
        }

        // Path not matched on this method — check if other methods handle it
        for (self.trees, 0..) |tree_opt, i| {
            if (i == idx) continue;
            if (tree_opt) |root| {
                if (root.pathExists(path)) {
                    return .method_not_allowed;
                }
            }
        }

        return .not_found;
    }

    /// Sets the 404 handler.
    pub fn setNotFound(self: *Self, handler: Handler) void {
        self.not_found_handler = handler;
    }

    /// Sets the 405 Method Not Allowed handler.
    pub fn setMethodNotAllowed(self: *Self, handler: Handler) void {
        self.method_not_allowed_handler = handler;
    }

    /// Creates a route group with the given prefix.
    pub fn group(self: *Self, prefix: []const u8) RouteGroup {
        return RouteGroup.init(self, prefix);
    }
};

// ============================================================================
// Route Group — Gin-style group with prefix and middleware
// ============================================================================

/// Route group for organizing routes with a common prefix and shared middleware.
///
/// Example:
/// ```zig
/// var api = router.group("/api/v1");
/// api.use(authMiddleware);
/// try api.get("/users", listUsers);
/// try api.get("/users/:id", getUser);
/// ```
pub const RouteGroup = struct {
    router: *Router,
    prefix: []const u8,
    middleware: std.ArrayListUnmanaged(Middleware) = .empty,

    const Self = @This();

    /// Creates a new route group.
    pub fn init(router: *Router, prefix: []const u8) Self {
        return .{ .router = router, .prefix = prefix };
    }

    /// Adds middleware to this group. All routes in this group will use it.
    pub fn use(self: *Self, mw: Middleware) !void {
        try self.middleware.append(self.router.allocator, mw);
    }

    /// Releases group resources (middleware list).
    pub fn deinit(self: *Self) void {
        self.middleware.deinit(self.router.allocator);
    }

    /// Creates a sub-group with an additional prefix.
    pub fn subgroup(self: *Self, prefix: []const u8) !RouteGroup {
        var full_prefix = std.ArrayListUnmanaged(u8){};
        try full_prefix.appendSlice(self.router.allocator, self.prefix);
        try full_prefix.appendSlice(self.router.allocator, prefix);
        const owned = try full_prefix.toOwnedSlice(self.router.allocator);

        var sub = RouteGroup{
            .router = self.router,
            .prefix = owned,
        };
        // Inherit parent middleware
        try sub.middleware.appendSlice(self.router.allocator, self.middleware.items);
        return sub;
    }

    /// Adds a route to the group.
    pub fn add(self: *Self, method: types.Method, path: []const u8, handler: Handler) !void {
        // Build full path: prefix + path
        var full_path = std.ArrayListUnmanaged(u8){};
        defer full_path.deinit(self.router.allocator);
        try full_path.appendSlice(self.router.allocator, self.prefix);
        try full_path.appendSlice(self.router.allocator, path);

        // We must dupe the path because the radix tree stores slices
        const path_owned = try self.router.allocator.dupe(u8, full_path.items);

        try self.router.addWithMiddleware(method, path_owned, handler, self.middleware.items);
    }

    /// Adds a GET route.
    pub fn get(self: *Self, path: []const u8, handler: Handler) !void {
        try self.add(.GET, path, handler);
    }

    /// Adds a POST route.
    pub fn post(self: *Self, path: []const u8, handler: Handler) !void {
        try self.add(.POST, path, handler);
    }

    /// Adds a PUT route.
    pub fn put(self: *Self, path: []const u8, handler: Handler) !void {
        try self.add(.PUT, path, handler);
    }

    /// Adds a DELETE route.
    pub fn delete(self: *Self, path: []const u8, handler: Handler) !void {
        try self.add(.DELETE, path, handler);
    }

    /// Adds a PATCH route.
    pub fn patch(self: *Self, path: []const u8, handler: Handler) !void {
        try self.add(.PATCH, path, handler);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Router basic matching" {
    const allocator = std.testing.allocator;
    var router_inst = Router.init(allocator);
    defer router_inst.deinit();

    const handler = struct {
        fn h(_: *Context) anyerror!Response {
            unreachable;
        }
    }.h;

    try router_inst.add(.GET, "/users", handler);
    try router_inst.add(.GET, "/users/:id", handler);
    try router_inst.add(.POST, "/users", handler);

    const result1 = router_inst.find(.GET, "/users");
    try std.testing.expect(result1 != null);
    try std.testing.expectEqual(@as(usize, 0), result1.?.params.len);

    const result2 = router_inst.find(.GET, "/users/123");
    try std.testing.expect(result2 != null);
    try std.testing.expectEqual(@as(usize, 1), result2.?.params.len);
    try std.testing.expectEqualStrings("id", result2.?.params[0].name);
    try std.testing.expectEqualStrings("123", result2.?.params[0].value);

    const result3 = router_inst.find(.DELETE, "/users");
    try std.testing.expect(result3 == null);
}

test "Router multiple parameters" {
    const allocator = std.testing.allocator;
    var router_inst = Router.init(allocator);
    defer router_inst.deinit();

    const handler = struct {
        fn h(_: *Context) anyerror!Response {
            unreachable;
        }
    }.h;

    try router_inst.add(.GET, "/users/:userId/posts/:postId", handler);

    const result = router_inst.find(.GET, "/users/42/posts/99");
    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(usize, 2), result.?.params.len);
    try std.testing.expectEqualStrings("userId", result.?.params[0].name);
    try std.testing.expectEqualStrings("42", result.?.params[0].value);
    try std.testing.expectEqualStrings("postId", result.?.params[1].name);
    try std.testing.expectEqualStrings("99", result.?.params[1].value);
}

test "Router wildcard matching" {
    const allocator = std.testing.allocator;
    var router_inst = Router.init(allocator);
    defer router_inst.deinit();

    const handler = struct {
        fn h(_: *Context) anyerror!Response {
            unreachable;
        }
    }.h;

    try router_inst.add(.GET, "/static/*filepath", handler);

    const result = router_inst.find(.GET, "/static/css/style.css");
    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(usize, 1), result.?.params.len);
    try std.testing.expectEqualStrings("filepath", result.?.params[0].name);
    try std.testing.expectEqualStrings("css/style.css", result.?.params[0].value);
}

test "Router 405 Method Not Allowed detection" {
    const allocator = std.testing.allocator;
    var router_inst = Router.init(allocator);
    defer router_inst.deinit();

    const handler = struct {
        fn h(_: *Context) anyerror!Response {
            unreachable;
        }
    }.h;

    try router_inst.add(.GET, "/users", handler);
    try router_inst.add(.POST, "/users", handler);

    // DELETE /users should be 405, not 404
    const result = router_inst.findEx(.DELETE, "/users");
    try std.testing.expect(result == .method_not_allowed);

    // GET /nonexistent should be 404
    const result2 = router_inst.findEx(.GET, "/nonexistent");
    try std.testing.expect(result2 == .not_found);

    // GET /users should match
    const result3 = router_inst.findEx(.GET, "/users");
    try std.testing.expect(result3 == .matched);
}

test "Router radix tree prefix sharing" {
    const allocator = std.testing.allocator;
    var router_inst = Router.init(allocator);
    defer router_inst.deinit();

    const h1 = struct {
        fn h(_: *Context) anyerror!Response {
            unreachable;
        }
    }.h;
    const h2 = struct {
        fn h(_: *Context) anyerror!Response {
            unreachable;
        }
    }.h;

    // These paths share the "/api/" prefix
    try router_inst.add(.GET, "/api/users", h1);
    try router_inst.add(.GET, "/api/posts", h2);

    const r1 = router_inst.find(.GET, "/api/users");
    try std.testing.expect(r1 != null);
    try std.testing.expect(r1.?.handler == h1);

    const r2 = router_inst.find(.GET, "/api/posts");
    try std.testing.expect(r2 != null);
    try std.testing.expect(r2.?.handler == h2);
}

test "Router group with middleware" {
    const allocator = std.testing.allocator;
    var router_inst = Router.init(allocator);
    defer router_inst.deinit();

    const handler = struct {
        fn h(_: *Context) anyerror!Response {
            unreachable;
        }
    }.h;

    const dummy_mw = Middleware{
        .name = "test_mw",
        .handler = struct {
            fn h(_: *Context, _: @import("middleware.zig").Next) anyerror!Response {
                unreachable;
            }
        }.h,
    };

    var api = router_inst.group("/api/v1");
    defer api.deinit();
    try api.use(dummy_mw);
    try api.get("/users", handler);

    const result = router_inst.findEx(.GET, "/api/v1/users");
    try std.testing.expect(result == .matched);
    try std.testing.expectEqual(@as(usize, 1), result.matched.middleware.len);
    try std.testing.expectEqualStrings("test_mw", result.matched.middleware[0].name);
}

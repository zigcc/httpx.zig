//! Router Benchmarks
//!
//! Benchmarks for HTTP routing:
//! - Static path matching
//! - Dynamic parameter extraction
//! - Deep nested paths
//! - No-match scenarios

const std = @import("std");
const main = @import("main.zig");
const httpx = main.httpx;
const benchmark = main.benchmark;

var router: httpx.Router = undefined;

fn dummyHandler(_: *httpx.Context) anyerror!httpx.Response {
    return httpx.Response.init(main.allocator, 200);
}

pub fn init() !void {
    router = httpx.Router.init(main.allocator);
    try router.add(.GET, "/users", dummyHandler);
    try router.add(.GET, "/users/:id", dummyHandler);
    try router.add(.POST, "/users", dummyHandler);
    try router.add(.GET, "/posts", dummyHandler);
    try router.add(.GET, "/posts/:id", dummyHandler);
    try router.add(.GET, "/api/v1/users/:userId/posts/:postId/comments", dummyHandler);
    try router.add(.GET, "/static/*filepath", dummyHandler);
}

pub fn deinit() void {
    router.deinit();
}

fn benchRouterStaticMatch() void {
    _ = router.find(.GET, "/users");
}

fn benchRouterParamMatch() void {
    _ = router.find(.GET, "/users/12345");
}

fn benchRouterDeepMatch() void {
    _ = router.find(.GET, "/api/v1/users/12345/posts/67890/comments");
}

fn benchRouterNoMatch() void {
    _ = router.find(.GET, "/nonexistent/path/here");
}

pub fn run() void {
    std.debug.print("\nRouter:\n", .{});
    benchmark("router_static", 1_000_000, benchRouterStaticMatch);
    benchmark("router_param", 1_000_000, benchRouterParamMatch);
    benchmark("router_deep_path", 500_000, benchRouterDeepMatch);
    benchmark("router_no_match", 1_000_000, benchRouterNoMatch);
}

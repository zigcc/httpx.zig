//! WebSocket Client Example
//!
//! Demonstrates connecting to a WebSocket server and exchanging messages.
//!
//! Run with: zig build run-websocket_client
//!
//! Note: Requires a WebSocket server to connect to.
//! You can use the websocket_server example or a public echo server.

const std = @import("std");
const httpx = @import("httpx");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Connect to a local WebSocket server
    // Change this URL to connect to different servers
    const url = "ws://127.0.0.1:8080/ws";

    std.debug.print("Connecting to {s}...\n", .{url});

    var client = httpx.WebSocketClient.connect(allocator, url, .{
        .timeout_ms = 10_000,
    }) catch |err| {
        std.debug.print("Failed to connect: {}\n", .{err});
        std.debug.print("\nMake sure the WebSocket server is running:\n", .{});
        std.debug.print("  zig build run-websocket_server\n", .{});
        return;
    };
    defer client.deinit();

    std.debug.print("Connected!\n", .{});

    // Send a text message
    const message = "Hello from httpx.zig WebSocket client!";
    std.debug.print("Sending: {s}\n", .{message});
    try client.sendText(message);

    // Receive response
    const response = try client.receive();
    defer allocator.free(response.payload);

    std.debug.print("Received: {s}\n", .{response.payload});

    // Send a few more messages
    const messages = [_][]const u8{
        "Message 1",
        "Message 2",
        "Message 3",
    };

    for (messages) |msg| {
        try client.sendText(msg);
        std.debug.print("Sent: {s}\n", .{msg});

        const resp = try client.receive();
        defer allocator.free(resp.payload);
        std.debug.print("Echo: {s}\n", .{resp.payload});
    }

    // Clean close
    std.debug.print("Closing connection...\n", .{});
    try client.close(.normal, "goodbye");

    std.debug.print("Done!\n", .{});
}

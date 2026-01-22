//! WebSocket Server Example
//!
//! Demonstrates a simple WebSocket echo server that:
//! - Accepts WebSocket connections on /ws
//! - Echoes back any text or binary messages
//! - Handles ping/pong automatically
//! - Logs connection events
//!
//! Run with: zig build run-websocket_server
//! Connect with: websocat ws://127.0.0.1:8080/ws

const std = @import("std");
const httpx = @import("httpx");

/// Echo handler - echoes back any message received.
fn echoHandler(conn: *httpx.WebSocketConnection) anyerror!void {
    std.debug.print("[WS] Client connected\n", .{});

    while (conn.isOpen()) {
        const msg = conn.receive() catch |err| {
            std.debug.print("[WS] Receive error: {}\n", .{err});
            break;
        };

        switch (msg.opcode) {
            .text => {
                std.debug.print("[WS] Received text: {s}\n", .{msg.payload});
                // Echo back
                try conn.sendText(msg.payload);
            },
            .binary => {
                std.debug.print("[WS] Received binary: {} bytes\n", .{msg.payload.len});
                // Echo back
                try conn.sendBinary(msg.payload);
            },
            .close => {
                std.debug.print("[WS] Client initiated close\n", .{});
                break;
            },
            else => {},
        }

        conn.allocator.free(msg.payload);
    }

    std.debug.print("[WS] Client disconnected\n", .{});
}

/// Simple HTTP handler for the index page.
fn indexHandler(ctx: *httpx.Context) anyerror!httpx.Response {
    const html =
        \\<!DOCTYPE html>
        \\<html>
        \\<head><title>WebSocket Echo</title></head>
        \\<body>
        \\<h1>WebSocket Echo Server</h1>
        \\<p>Connect to <code>ws://localhost:8080/ws</code></p>
        \\<script>
        \\const ws = new WebSocket('ws://localhost:8080/ws');
        \\ws.onopen = () => { console.log('Connected'); ws.send('Hello!'); };
        \\ws.onmessage = (e) => console.log('Received:', e.data);
        \\ws.onclose = () => console.log('Disconnected');
        \\</script>
        \\</body>
        \\</html>
    ;
    return ctx.html(html);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var server = httpx.Server.initWithConfig(allocator, .{
        .host = "127.0.0.1",
        .port = 8080,
    });
    defer server.deinit();

    // HTTP route for index page
    try server.get("/", indexHandler);

    // WebSocket route
    try server.ws("/ws", echoHandler);

    std.debug.print("WebSocket server listening on ws://127.0.0.1:8080/ws\n", .{});
    std.debug.print("Open http://127.0.0.1:8080/ in your browser\n", .{});

    try server.listen();
}

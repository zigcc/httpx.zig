//! HTTPS + WSS (PEM) Example
//!
//! Demonstrates how to:
//! - Enable TLS 1.2 using PEM certificate/key
//! - Serve HTTPS endpoint on /
//! - Serve secure WebSocket (wss) echo endpoint on /ws
//!
//! Run with: zig build run-https_wss_pem
//! Open: https://127.0.0.1:8443/
//!
//! Note: This example uses a self-signed certificate, so browsers/clients
//! will warn unless you trust the cert.

const std = @import("std");
const httpx = @import("httpx");

const cert_pem =
    "-----BEGIN CERTIFICATE-----\n" ++
    "MIICBDCCAW2gAwIBAgIUaTlW0t+judN+kkLViTuiJNv8dCEwDQYJKoZIhvcNAQEL\n" ++
    "BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDIwNjE5MjQwMloXDTI2MDIw\n" ++
    "NzE5MjQwMlowFDESMBAGA1UEAwwJbG9jYWxob3N0MIGfMA0GCSqGSIb3DQEBAQUA\n" ++
    "A4GNADCBiQKBgQC11T3uGGnh794tn4bUobJcpCAW8s/bpIUkxtGfTiYxc5hOgq+G\n" ++
    "+cSjM61Sr6gP+s5ebOWbfxNs7NwJxpZLofAKsILI6KY3ouukUYpXcRXyqPuORaPa\n" ++
    "bwOBzZl281K0vk80XVAozY5MWN7PZ9/7+L1wjjDLzDHOK02+SD8FEp6DcwIDAQAB\n" ++
    "o1MwUTAdBgNVHQ4EFgQU4f4vQMNSbPsiMJYpT3At0o/FTlwwHwYDVR0jBBgwFoAU\n" ++
    "4f4vQMNSbPsiMJYpT3At0o/FTlwwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B\n" ++
    "AQsFAAOBgQAnDkVqOOiYb/PDiNm+5/1deRmQJZ36vjdLWpQ5iCrXZoPr5eyqjXqi\n" ++
    "qvllooY9dMCwo9YE28Kq2F/uR3vciveqoIbU5hMzb1qL2KypCA+CeJn7swDBxZT9\n" ++
    "oRXTMD+vljJfyJngiVHXTlccOkPDv7SIyoys/NPIjyuba8zu+P+qiQ==\n" ++
    "-----END CERTIFICATE-----\n";

const key_pem =
    "-----BEGIN PRIVATE KEY-----\n" ++
    "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALXVPe4YaeHv3i2f\n" ++
    "htShslykIBbyz9ukhSTG0Z9OJjFzmE6Cr4b5xKMzrVKvqA/6zl5s5Zt/E2zs3AnG\n" ++
    "lkuh8Aqwgsjopjei66RRildxFfKo+45Fo9pvA4HNmXbzUrS+TzRdUCjNjkxY3s9n\n" ++
    "3/v4vXCOMMvMMc4rTb5IPwUSnoNzAgMBAAECgYAu8/iA8ebtg74Qc+AiKfrftzXe\n" ++
    "FycbZXlIDNr2UvzDykCrDU38AaUIK4D3GArCzZXahi4oIAFJIESVdaU7tH5CJE8a\n" ++
    "zF6wXj5AfHlxqHq+krWOYuxv7d+Cd61Pbn8yg9DJ2TlJgD765hDP3wabFaM/kfXn\n" ++
    "v87W993n9KnIxiRVwQJBAPAt1GYX2eu3xq0tWrD+1cvv/FRURO1Fj/CEdj7KvuMn\n" ++
    "d8ApQTVABeFJPWdm01dwwh1ljxNFvgUQ74ooMTxtbJMCQQDBz4PlFpd87DYvv2N/\n" ++
    "FP5++z8Jm6lhIssqP/42TI4c0YQZEra9nh18iQfchgPpjszEi/qipVDeWrOvrT9F\n" ++
    "rbmhAkAAtvIx15JTbDmQHFlvu2Jhd/ZVPebymcli2tILP8kvnddyX+0MvoMF95TS\n" ++
    "MPEiCnjZY4r4cLWvCCzeSV5UIrM3AkAIsD7fdEXSSdycA154gf5uvuCyk5HiUub8\n" ++
    "u+WvlXsBe7sKTLZ4hbAYtyPtFOzz+Xzgis3voK2hajuH8qJVg1ZBAkEAs3XDARhj\n" ++
    "0tVrWkKDi1vQn9VgQGHIvftO5v94Ibxbd1ceGsyDKNMkJXhHadaSKy2lxSQI24MI\n" ++
    "NEaEJIuPClOWqg==\n" ++
    "-----END PRIVATE KEY-----\n";

fn indexHandler(ctx: *httpx.Context) anyerror!httpx.Response {
    const html =
        \\<!doctype html>
        \\<html>
        \\<head><meta charset="utf-8"><title>HTTPS + WSS</title></head>
        \\<body>
        \\  <h1>HTTPS + WSS Example</h1>
        \\  <p>Open devtools console to see echo output.</p>
        \\  <script>
        \\    const ws = new WebSocket("wss://127.0.0.1:8443/ws");
        \\    ws.onopen = () => { console.log("wss connected"); ws.send("hello over wss"); };
        \\    ws.onmessage = (ev) => console.log("wss echo:", ev.data);
        \\    ws.onerror = (ev) => console.log("wss error:", ev);
        \\    ws.onclose = () => console.log("wss closed");
        \\  </script>
        \\</body>
        \\</html>
    ;
    return ctx.html(html);
}

fn wsEchoHandler(conn: *httpx.WebSocketConnection) anyerror!void {
    while (conn.isOpen()) {
        const msg = conn.receive() catch break;
        defer conn.allocator.free(msg.payload);
        try conn.send(msg.payload, msg.opcode);
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var server = httpx.Server.initWithConfig(allocator, .{
        .host = "127.0.0.1",
        .port = 8443,
    });
    defer server.deinit();

    const cert_chain = [_][]const u8{cert_pem};
    try server.enableTls12Pem(.{
        .cert_chain_pem = &cert_chain,
        .private_key_pem = key_pem,
    });

    try server.get("/", indexHandler);
    try server.ws("/ws", wsEchoHandler);

    std.debug.print("HTTPS listening at https://127.0.0.1:8443/\n", .{});
    std.debug.print("WSS endpoint at wss://127.0.0.1:8443/ws\n", .{});
    try server.listen();
}

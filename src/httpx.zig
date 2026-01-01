//! httpx.zig - Production-Ready HTTP Library for Zig
//!
//! A comprehensive HTTP client and server library with support for all
//! HTTP protocol versions and modern features.
//!
//! ## Supported Protocols
//!
//! - **HTTP/1.0**: Basic request-response semantics
//! - **HTTP/1.1**: Persistent connections, chunked transfer, pipelining
//! - **HTTP/2**: Binary framing, multiplexing, header compression (HPACK), server push
//! - **HTTP/3**: QUIC transport, 0-RTT connections, improved multiplexing
//!
//! ## Platform Support
//!
//! - Linux (x86_64, aarch64)
//! - Windows (x86_64)
//! - macOS (x86_64, aarch64)
//! - FreeBSD, NetBSD, OpenBSD
//!
//! ## Features
//!
//! ### Client Features
//! - Connection pooling with keep-alive
//! - Automatic retry with exponential backoff
//! - Redirect following with configurable policies
//! - Request/response interceptors
//! - Concurrent request execution
//! - TLS/SSL support
//! - Timeout configuration
//! - Cookie handling
//!
//! ### Server Features
//! - Express-style routing with path parameters
//! - Middleware stack (CORS, logging, rate limiting, etc.)
//! - Static file serving
//! - JSON response helpers
//! - Request context with user data
//!
//! ## Quick Start
//!
//! ```zig
//! const httpx = @import("httpx");
//!
//! // Client usage
//! var client = httpx.Client.init(allocator);
//! defer client.deinit();
//! const response = try client.get("https://api.example.com/users", .{});
//!
//! // Server usage
//! var server = httpx.Server.init(allocator);
//! try server.get("/hello", helloHandler);
//! try server.listen();
//! ```

const std = @import("std");

pub const types = @import("core/types.zig");
pub const headers = @import("core/headers.zig");
pub const uri = @import("core/uri.zig");
pub const status = @import("core/status.zig");
pub const request = @import("core/request.zig");
pub const response = @import("core/response.zig");

pub const http = @import("protocol/http.zig");
pub const parser = @import("protocol/parser.zig");

pub const socket = @import("net/socket.zig");
pub const address = @import("net/address.zig");

pub const tls = @import("tls/tls.zig");

pub const client_mod = @import("client/client.zig");
pub const pool = @import("client/pool.zig");

pub const server_mod = @import("server/server.zig");
pub const router = @import("server/router.zig");
pub const middleware = @import("server/middleware.zig");

pub const buffer = @import("util/buffer.zig");
pub const encoding = @import("util/encoding.zig");
pub const json = @import("util/json.zig");

pub const executor = @import("concurrency/executor.zig");
pub const concurrency = @import("concurrency/pool.zig");

pub const Executor = executor.Executor;
pub const Task = executor.Task;

pub const Method = types.Method;
pub const Version = types.Version;
pub const HttpError = types.HttpError;
pub const ContentType = types.ContentType;
pub const Timeouts = types.Timeouts;
pub const RetryPolicy = types.RetryPolicy;
pub const RedirectPolicy = types.RedirectPolicy;
pub const Http2Settings = types.Http2Settings;
pub const Http3Settings = types.Http3Settings;

pub const Headers = headers.Headers;
pub const HeaderName = headers.HeaderName;
pub const Header = headers.Header;

pub const Uri = uri.Uri;

pub const Status = status.Status;
pub const StatusCode = status.StatusCode;

pub const Request = request.Request;
pub const RequestBuilder = request.RequestBuilder;

pub const Response = response.Response;
pub const ResponseBuilder = response.ResponseBuilder;

pub const Socket = socket.Socket;
pub const TcpListener = socket.TcpListener;

pub const Parser = parser.Parser;

pub const Http1Connection = http.Http1Connection;
pub const Http2Connection = http.Http2Connection;
pub const Http2FrameType = http.Http2FrameType;
pub const Http2FrameHeader = http.Http2FrameHeader;
pub const Http2ErrorCode = http.Http2ErrorCode;
pub const Http3FrameType = http.Http3FrameType;
pub const Http3ErrorCode = http.Http3ErrorCode;
pub const AlpnProtocol = http.AlpnProtocol;
pub const NegotiatedProtocol = http.NegotiatedProtocol;

pub const formatRequest = http.formatRequest;
pub const formatResponse = http.formatResponse;
pub const negotiateVersion = http.negotiateVersion;

pub const Client = client_mod.Client;
pub const ClientConfig = client_mod.ClientConfig;
pub const RequestOptions = client_mod.RequestOptions;
pub const Interceptor = client_mod.Interceptor;
pub const RequestInterceptor = client_mod.RequestInterceptor;
pub const ResponseInterceptor = client_mod.ResponseInterceptor;

pub const ConnectionPool = pool.ConnectionPool;
pub const PoolConfig = pool.PoolConfig;
pub const Connection = pool.Connection;

pub const Server = server_mod.Server;
pub const ServerConfig = server_mod.ServerConfig;
pub const Context = server_mod.Context;
pub const Handler = server_mod.Handler;

pub const Router = router.Router;
pub const RouteGroup = router.RouteGroup;
pub const RouteMatch = router.RouteMatch;

pub const Middleware = middleware.Middleware;
pub const Next = middleware.Next;
pub const cors = middleware.cors;
pub const logger = middleware.logger;
pub const compression = middleware.compression;
pub const rateLimit = middleware.rateLimit;
pub const basicAuth = middleware.basicAuth;
pub const helmet = middleware.helmet;

pub const Buffer = buffer.Buffer;
pub const RingBuffer = buffer.RingBuffer;
pub const FixedBuffer = buffer.FixedBuffer;

pub const Base64 = encoding.Base64;
pub const Hex = encoding.Hex;
pub const PercentEncoding = encoding.PercentEncoding;

pub const TlsConfig = tls.TlsConfig;
pub const TlsSession = tls.TlsSession;

/// Convenience function to create a GET request.
pub fn get(allocator: std.mem.Allocator, url: []const u8) !Response {
    var c = Client.init(allocator);
    defer c.deinit();
    return c.get(url, .{});
}

/// Convenience function to create a POST request with JSON body.
pub fn postJson(allocator: std.mem.Allocator, url: []const u8, body: []const u8) !Response {
    var c = Client.init(allocator);
    defer c.deinit();
    return c.post(url, .{ .json = body });
}

test "core types" {
    _ = types;
}

test "headers" {
    _ = headers;
}

test "uri" {
    _ = uri;
}

test "status" {
    _ = status;
}

test "request" {
    _ = request;
}

test "response" {
    _ = response;
}

test "http protocol" {
    _ = http;
}

test "parser" {
    _ = parser;
}

test "buffer" {
    _ = buffer;
}

test "encoding" {
    _ = encoding;
}

test "json" {
    _ = json;
}

test "socket" {
    _ = socket;
}

test "address" {
    _ = address;
}

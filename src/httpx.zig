//! httpx.zig - Production-Ready HTTP Server Library for Zig
//!
//! A high-performance HTTP server library with support for modern features.
//!
//! ## Supported Protocols
//!
//! - **HTTP/1.1**: Persistent connections, chunked transfer
//! - **HTTP/2**: HPACK compression, stream multiplexing, flow control
//! - **WebSocket**: Bidirectional real-time communication (RFC 6455)
//!
//! ## Features
//!
//! - Express-style routing with path parameters
//! - Middleware stack (CORS, logging, rate limiting, etc.)
//! - Static file serving
//! - JSON response helpers
//! - Request context with user data
//! - WebSocket endpoint handling with upgrade support
//! - TLS/SSL support
//!
//! ## Quick Start
//!
//! ```zig
//! const httpx = @import("httpx");
//!
//! var server = httpx.Server.init(allocator);
//! try server.get("/hello", helloHandler);
//! try server.listen();
//! ```

const std = @import("std");

// Core types
pub const types = @import("core/types.zig");
pub const headers = @import("core/headers.zig");
pub const uri = @import("core/uri.zig");
pub const status = @import("core/status.zig");
pub const request = @import("core/request.zig");
pub const response = @import("core/response.zig");
pub const cookie = @import("core/cookie.zig");
pub const auth = @import("core/auth.zig");
pub const multipart_mod = @import("core/multipart.zig");

// Protocol
pub const http = @import("protocol/http.zig");
pub const parser = @import("protocol/parser.zig");
pub const hpack = @import("protocol/hpack.zig");
pub const stream = @import("protocol/stream.zig");
pub const qpack = @import("protocol/qpack.zig");
pub const quic = @import("protocol/quic.zig");
pub const websocket = @import("protocol/websocket.zig");

// Network
pub const socket = @import("net/socket.zig");
pub const address = @import("net/address.zig");

// I/O subsystem
pub const io = struct {
    pub const poller = @import("io/poller.zig");
    pub const Poller = poller.Poller;
    pub const Event = poller.Event;
    pub const EventMask = poller.EventMask;
};

// TLS
pub const tls = @import("tls/tls.zig");
pub const tls_session_pool = @import("tls/session_pool.zig");

// Server
pub const server_mod = @import("server/server.zig");
pub const router = @import("server/router.zig");
pub const middleware = @import("server/middleware.zig");
pub const ws_handler = @import("server/ws_handler.zig");
pub const worker_pool = @import("server/worker_pool.zig");
pub const event_server = @import("server/event_server.zig");

// Utilities
pub const buffer = @import("util/buffer.zig");
pub const encoding = @import("util/encoding.zig");
pub const json = @import("util/json.zig");
pub const compression_mod = @import("util/compression.zig");

// Concurrency
pub const executor = @import("concurrency/executor.zig");

// ============================================================================
// Type Exports
// ============================================================================

// Core types
pub const Method = types.Method;
pub const Version = types.Version;
pub const HttpError = types.HttpError;
pub const ContentType = types.ContentType;
pub const Timeouts = types.Timeouts;
pub const Http2Settings = types.Http2Settings;
pub const TransferEncoding = types.TransferEncoding;
pub const ContentEncoding = types.ContentEncoding;

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

// Parser
pub const Parser = parser.Parser;
pub const ParseError = parser.ParseError;

// Network
pub const Socket = socket.Socket;
pub const TcpListener = socket.TcpListener;
pub const UdpSocket = socket.UdpSocket;

// HTTP protocol
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

// HTTP/2 HPACK
pub const HpackContext = hpack.HpackContext;
pub const HpackStaticTable = hpack.StaticTable;
pub const HpackDynamicTable = hpack.DynamicTable;
pub const encodeHpackHeaders = hpack.encodeHeaders;
pub const decodeHpackHeaders = hpack.decodeHeaders;

// HTTP/2 Stream
pub const Stream = stream.Stream;
pub const StreamState = stream.StreamState;
pub const StreamManager = stream.StreamManager;
pub const StreamPriority = stream.StreamPriority;

// HTTP/3 QPACK
pub const QpackContext = qpack.QpackContext;
pub const QpackStaticTable = qpack.StaticTable;
pub const encodeQpackHeaders = qpack.encodeHeaders;
pub const decodeQpackHeaders = qpack.decodeHeaders;

// QUIC
pub const QuicVersion = quic.Version;
pub const QuicLongHeader = quic.LongHeader;
pub const QuicShortHeader = quic.ShortHeader;
pub const QuicConnectionId = quic.ConnectionId;
pub const QuicFrameType = quic.FrameType;
pub const QuicTransportError = quic.TransportError;
pub const QuicStreamFrame = quic.StreamFrame;
pub const QuicCryptoFrame = quic.CryptoFrame;
pub const QuicAckFrame = quic.AckFrame;
pub const QuicTransportParameters = quic.TransportParameters;

// WebSocket (server-side)
pub const WebSocketConnection = ws_handler.WebSocketConnection;
pub const WebSocketHandler = ws_handler.WebSocketHandler;
pub const WsOpcode = websocket.Opcode;
pub const WsFrame = websocket.Frame;
pub const WsCloseCode = websocket.CloseCode;
pub const isWebSocketUpgrade = ws_handler.isUpgradeRequest;

// Server
pub const Server = server_mod.Server;
pub const ServerConfig = server_mod.ServerConfig;
pub const Context = server_mod.Context;
pub const Handler = server_mod.Handler;
pub const WorkerPool = server_mod.WorkerPool;
pub const WorkerPoolConfig = server_mod.WorkerPoolConfig;
pub const WorkItem = server_mod.WorkItem;

// Event-driven server
pub const EventServer = event_server.EventServer;
pub const EventServerConfig = event_server.EventServerConfig;
pub const EventConnection = event_server.Connection;
pub const EventConnectionState = event_server.ConnectionState;

// Router
pub const Router = router.Router;
pub const RouteGroup = router.RouteGroup;
pub const RouteMatch = router.RouteMatch;

// Middleware
pub const Middleware = middleware.Middleware;
pub const Next = middleware.Next;
pub const cors = middleware.cors;
pub const logger = middleware.logger;
pub const compression = middleware.compression;
pub const rateLimit = middleware.rateLimit;
pub const basicAuth = middleware.basicAuth;
pub const helmet = middleware.helmet;

// Buffer utilities
pub const Buffer = buffer.Buffer;
pub const RingBuffer = buffer.RingBuffer;
pub const FixedBuffer = buffer.FixedBuffer;

// Encoding utilities
pub const Base64 = encoding.Base64;
pub const Hex = encoding.Hex;
pub const PercentEncoding = encoding.PercentEncoding;

// TLS
pub const TlsConfig = tls.TlsConfig;
pub const TlsSession = tls.TlsSession;
pub const TlsSessionPool = tls_session_pool.TlsSessionPool;
pub const TlsSessionPoolConfig = tls_session_pool.TlsSessionPoolConfig;
pub const TlsSessionTicket = tls_session_pool.TlsSessionTicket;

// Cookie management (RFC 6265)
pub const Cookie = cookie.Cookie;
pub const CookieJar = cookie.CookieJar;
pub const SameSite = cookie.SameSite;
pub const parseSetCookie = cookie.parseSetCookie;

// Authentication (RFC 7617, RFC 7616, RFC 6750)
pub const AuthScheme = auth.AuthScheme;
pub const Credentials = auth.Credentials;
pub const Authenticator = auth.Authenticator;
pub const basicAuthHeader = auth.basicAuth;
pub const bearerAuthHeader = auth.bearerAuth;
pub const digestAuth = auth.digestAuth;
pub const DigestChallenge = auth.DigestChallenge;

// Multipart form data (RFC 2046)
pub const MultipartForm = multipart_mod.MultipartForm;
pub const UrlEncodedForm = multipart_mod.UrlEncodedForm;
pub const MimeType = multipart_mod.MimeType;

// Content-Encoding compression (RFC 7231)
pub const Compression = compression_mod;
pub const decompress = compression_mod.decompress;
pub const compress = compression_mod.compress;
pub const decompressAuto = compression_mod.decompressAuto;

// Executor
pub const Executor = executor.Executor;
pub const Task = executor.Task;

// ============================================================================
// Convenience Functions
// ============================================================================

/// Checks if an HTTP request is a WebSocket upgrade request.
pub fn isWsUpgrade(req: *const Request) bool {
    return ws_handler.isUpgradeRequest(req);
}

/// Generates the Sec-WebSocket-Accept header value from a client's key.
pub fn computeWsAcceptKey(client_key: []const u8) [28]u8 {
    return websocket.computeAccept(client_key);
}

// ============================================================================
// Tests
// ============================================================================

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

test "hpack" {
    _ = hpack;
}

test "stream" {
    _ = stream;
}

test "qpack" {
    _ = qpack;
}

test "quic" {
    _ = quic;
}

test "websocket" {
    _ = websocket;
}

test "ws_handler" {
    _ = ws_handler;
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

test "io poller" {
    _ = io.poller;
}

test "tls session pool" {
    _ = tls_session_pool;
}

test "event server" {
    _ = event_server;
}

test "cookie" {
    _ = cookie;
}

test "auth" {
    _ = auth;
}

test "multipart" {
    _ = multipart_mod;
}

test "compression" {
    _ = compression_mod;
}

//! Cross-Platform Socket Abstraction for httpx.zig
//!
//! Provides a unified socket interface for TCP networking across platforms:
//!
//! - Windows (Winsock2) and POSIX systems
//! - TCP client and server socket operations
//! - Configurable timeouts and socket options
//! - Reader/Writer interfaces for streaming

const std = @import("std");
const net = std.net;
const posix = std.posix;
const Allocator = std.mem.Allocator;
const builtin = @import("builtin");

const is_windows = builtin.os.tag == .windows;

const INVALID_SOCKET: posix.socket_t = if (is_windows)
    @ptrFromInt(~@as(usize, 0))
else
    -1;

/// TCP socket abstraction with cross-platform support.
pub const Socket = struct {
    handle: posix.socket_t,
    connected: bool = false,

    const Self = @This();

    /// Creates a new TCP socket.
    pub fn create() !Self {
        const handle = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
        return .{ .handle = handle };
    }

    /// Creates a socket from an existing handle.
    pub fn fromHandle(handle: posix.socket_t) Self {
        return .{ .handle = handle, .connected = true };
    }

    /// Closes the socket and releases resources.
    pub fn close(self: *Self) void {
        if (self.isValid()) {
            posix.close(self.handle);
            self.handle = INVALID_SOCKET;
            self.connected = false;
        }
    }

    /// Returns true if the socket handle is valid.
    pub fn isValid(self: *const Self) bool {
        return self.handle != INVALID_SOCKET;
    }

    /// Connects to the specified address.
    pub fn connect(self: *Self, addr: net.Address) !void {
        try posix.connect(self.handle, &addr.any, addr.getOsSockLen());
        self.connected = true;
    }

    /// Sends data through the socket, returning bytes sent.
    pub fn send(self: *Self, data: []const u8) !usize {
        return posix.send(self.handle, data, 0);
    }

    /// Sends all data, blocking until complete.
    pub fn sendAll(self: *Self, data: []const u8) !void {
        var sent: usize = 0;
        while (sent < data.len) {
            sent += try self.send(data[sent..]);
        }
    }

    /// Receives data into the buffer, returning bytes received.
    pub fn recv(self: *Self, buffer: []u8) !usize {
        return posix.recv(self.handle, buffer, 0);
    }

    /// Sets a socket option.
    pub fn setOption(self: *Self, level: u32, optname: u32, value: []const u8) !void {
        try posix.setsockopt(self.handle, level, optname, value);
    }

    /// Enables or disables TCP_NODELAY (Nagle's algorithm).
    pub fn setNoDelay(self: *Self, enable: bool) !void {
        const value: u32 = if (enable) 1 else 0;
        try posix.setsockopt(self.handle, posix.IPPROTO.TCP, posix.TCP.NODELAY, std.mem.asBytes(&value));
    }

    /// Sets the receive timeout in milliseconds.
    pub fn setRecvTimeout(self: *Self, ms: u64) !void {
        const tv = posix.timeval{
            .sec = @intCast(ms / 1000),
            .usec = @intCast((ms % 1000) * 1000),
        };
        try posix.setsockopt(self.handle, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv));
    }

    /// Sets the send timeout in milliseconds.
    pub fn setSendTimeout(self: *Self, ms: u64) !void {
        const tv = posix.timeval{
            .sec = @intCast(ms / 1000),
            .usec = @intCast((ms % 1000) * 1000),
        };
        try posix.setsockopt(self.handle, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&tv));
    }

    /// Enables or disables keep-alive probes.
    pub fn setKeepAlive(self: *Self, enable: bool) !void {
        const value: u32 = if (enable) 1 else 0;
        try posix.setsockopt(self.handle, posix.SOL.SOCKET, posix.SO.KEEPALIVE, std.mem.asBytes(&value));
    }

    /// Enables or disables address reuse.
    pub fn setReuseAddr(self: *Self, enable: bool) !void {
        const value: u32 = if (enable) 1 else 0;
        try posix.setsockopt(self.handle, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&value));
    }

    /// Binds the socket to an address.
    pub fn bind(self: *Self, addr: net.Address) !void {
        try posix.bind(self.handle, &addr.any, addr.getOsSockLen());
    }

    /// Starts listening for connections.
    pub fn listen(self: *Self, backlog: u31) !void {
        try posix.listen(self.handle, backlog);
    }

    /// Accepts an incoming connection.
    pub fn accept(self: *Self) !struct { socket: Socket, addr: net.Address } {
        var addr: posix.sockaddr = undefined;
        var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr);
        const handle = try posix.accept(self.handle, &addr, &addr_len);
        return .{
            .socket = Socket.fromHandle(handle),
            .addr = net.Address{ .any = addr },
        };
    }

    /// Returns a reader interface for the socket.
    pub fn reader(self: *Self) std.io.AnyReader {
        return .{
            .context = @ptrCast(self),
            .readFn = struct {
                fn read(ctx: *const anyopaque, buffer: []u8) !usize {
                    const s: *Socket = @ptrCast(@constCast(ctx));
                    return s.recv(buffer) catch |err| switch (err) {
                        error.WouldBlock => 0,
                        else => err,
                    };
                }
            }.read,
        };
    }

    /// Returns a writer interface for the socket.
    pub fn writer(self: *Self) std.io.AnyWriter {
        return .{
            .context = @ptrCast(self),
            .writeFn = struct {
                fn write(ctx: *const anyopaque, data: []const u8) !usize {
                    const s: *Socket = @ptrCast(@constCast(ctx));
                    return s.send(data);
                }
            }.write,
        };
    }
};

/// TCP listener for accepting incoming connections.
pub const TcpListener = struct {
    socket: Socket,

    const Self = @This();

    /// Creates and binds a TCP listener to the address.
    pub fn init(addr: net.Address) !Self {
        var socket = try Socket.create();
        errdefer socket.close();

        try socket.setReuseAddr(true);
        try socket.bind(addr);
        try socket.listen(128);

        return .{ .socket = socket };
    }

    /// Closes the listener.
    pub fn deinit(self: *Self) void {
        self.socket.close();
    }

    /// Accepts an incoming connection.
    pub fn accept(self: *Self) !struct { socket: Socket, addr: net.Address } {
        return self.socket.accept();
    }

    /// Returns the local address the listener is bound to.
    pub fn getLocalAddress(self: *Self) !net.Address {
        _ = self;
        return error.NotImplemented;
    }
};

test "Socket create and close" {
    var socket = try Socket.create();
    defer socket.close();
    try std.testing.expect(socket.isValid());
}

test "Socket options" {
    var socket = try Socket.create();
    defer socket.close();

    try socket.setNoDelay(true);
    try socket.setReuseAddr(true);
    try socket.setKeepAlive(true);
}

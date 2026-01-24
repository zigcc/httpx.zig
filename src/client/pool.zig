//! HTTP Connection Pool for httpx.zig
//!
//! Provides thread-safe connection pooling for HTTP clients:
//!
//! - Reusable TCP connections with keep-alive
//! - Per-host connection limits
//! - Automatic connection health checking
//! - Idle connection timeout and cleanup
//! - Thread-safe for concurrent access
//!
//! ## Thread Safety
//!
//! All public methods are thread-safe and can be called concurrently from
//! multiple threads. The pool uses a mutex to protect its internal state.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Thread = std.Thread;
const net = std.net;

const Socket = @import("../net/socket.zig").Socket;
const address_mod = @import("../net/address.zig");

pub const PoolError = error{
    PoolExhausted,
    PoolExhaustedForHost,
};

/// Pooled connection representing a reusable socket.
pub const Connection = struct {
    socket: Socket,
    host: []const u8,
    port: u16,
    in_use: bool = false,
    created_at: i64,
    last_used: i64,
    requests_made: u32 = 0,

    const Self = @This();

    /// Marks the connection as in use.
    pub fn acquire(self: *Self) void {
        self.in_use = true;
        self.last_used = std.time.milliTimestamp();
    }

    /// Releases the connection back to the pool.
    pub fn release(self: *Self) void {
        self.in_use = false;
        self.last_used = std.time.milliTimestamp();
        self.requests_made += 1;
    }

    /// Returns true if the connection is healthy and reusable.
    pub fn isHealthy(self: *const Self, max_idle_ms: i64) bool {
        if (self.in_use) return false;
        if (!self.socket.isValid()) return false;
        const idle_time = std.time.milliTimestamp() - self.last_used;
        return idle_time < max_idle_ms;
    }

    /// Returns true if this connection should be evicted from the pool.
    pub fn shouldEvict(self: *const Self, idle_timeout_ms: i64, max_requests_per_connection: u32) bool {
        if (self.in_use) return false;
        if (!self.socket.isValid()) return true;
        if (self.requests_made >= max_requests_per_connection) return true;
        const idle_time = std.time.milliTimestamp() - self.last_used;
        return idle_time >= idle_timeout_ms;
    }

    /// Closes the underlying socket.
    pub fn close(self: *Self) void {
        self.socket.close();
    }
};

/// Connection pool configuration.
pub const PoolConfig = struct {
    max_connections: u32 = 20,
    max_per_host: u32 = 5,
    idle_timeout_ms: i64 = 60_000,
    max_requests_per_connection: u32 = 1000,
    health_check_interval_ms: i64 = 30_000,
};

/// Thread-safe HTTP connection pool.
pub const ConnectionPool = struct {
    allocator: Allocator,
    config: PoolConfig,
    connections: std.ArrayListUnmanaged(Connection) = .empty,
    hosts_owned: std.ArrayListUnmanaged([]u8) = .empty,

    /// Mutex for thread-safe access.
    mutex: Thread.Mutex = .{},

    const Self = @This();

    /// Creates a new connection pool.
    pub fn init(allocator: Allocator) Self {
        return initWithConfig(allocator, .{});
    }

    /// Creates a connection pool with custom configuration.
    pub fn initWithConfig(allocator: Allocator, config: PoolConfig) Self {
        return .{
            .allocator = allocator,
            .config = config,
        };
    }

    /// Releases all pool resources.
    /// Note: This method is NOT thread-safe. Call only when no other threads
    /// are accessing the pool.
    pub fn deinit(self: *Self) void {
        for (self.connections.items) |*conn| {
            conn.close();
        }
        self.connections.deinit(self.allocator);

        for (self.hosts_owned.items) |host| {
            self.allocator.free(host);
        }
        self.hosts_owned.deinit(self.allocator);
    }

    /// Gets or creates a connection to the specified host.
    /// Thread-safe: can be called from multiple threads concurrently.
    pub fn getConnection(self: *Self, host: []const u8, port: u16) !*Connection {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.getConnectionLocked(host, port);
    }

    /// Internal: get connection while already holding the lock.
    fn getConnectionLocked(self: *Self, host: []const u8, port: u16) !*Connection {
        // Try to find an existing healthy connection
        for (self.connections.items) |*conn| {
            if (std.mem.eql(u8, conn.host, host) and conn.port == port) {
                if (conn.isHealthy(self.config.idle_timeout_ms) and conn.requests_made < self.config.max_requests_per_connection) {
                    conn.acquire();
                    return conn;
                }
            }
        }

        // Check global limit
        if (self.totalCountLocked() >= self.config.max_connections) {
            return PoolError.PoolExhausted;
        }

        // Check per-host limit
        var host_count: u32 = 0;
        for (self.connections.items) |conn| {
            if (std.mem.eql(u8, conn.host, host) and conn.port == port) {
                host_count += 1;
            }
        }
        if (host_count >= self.config.max_per_host) {
            return PoolError.PoolExhaustedForHost;
        }

        // Create new connection
        return self.createConnectionLocked(host, port);
    }

    /// Internal: create connection while already holding the lock.
    fn createConnectionLocked(self: *Self, host: []const u8, port: u16) !*Connection {
        const host_owned = try self.allocator.dupe(u8, host);
        errdefer self.allocator.free(host_owned);

        try self.hosts_owned.append(self.allocator, host_owned);

        const addr = try address_mod.resolve(host, port);

        var socket = try Socket.createForAddress(addr);
        errdefer socket.close();
        try socket.connect(addr);

        const now = std.time.milliTimestamp();

        try self.connections.append(self.allocator, .{
            .socket = socket,
            .host = host_owned,
            .port = port,
            .in_use = true,
            .created_at = now,
            .last_used = now,
        });

        return &self.connections.items[self.connections.items.len - 1];
    }

    /// Releases a connection back to the pool.
    /// Thread-safe: can be called from multiple threads concurrently.
    pub fn releaseConnection(self: *Self, conn: *Connection) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        conn.release();
    }

    /// Removes idle connections that have exceeded the timeout.
    /// Thread-safe: can be called from multiple threads concurrently.
    pub fn cleanup(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.cleanupLocked();
    }

    /// Internal: cleanup while already holding the lock.
    fn cleanupLocked(self: *Self) void {
        var i: usize = 0;
        while (i < self.connections.items.len) {
            const conn = &self.connections.items[i];
            if (conn.shouldEvict(self.config.idle_timeout_ms, self.config.max_requests_per_connection)) {
                conn.close();
                _ = self.connections.orderedRemove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Returns the number of active (in-use) connections.
    /// Thread-safe: can be called from multiple threads concurrently.
    pub fn activeCount(self: *Self) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        var count: usize = 0;
        for (self.connections.items) |conn| {
            if (conn.in_use) count += 1;
        }
        return count;
    }

    /// Returns the total number of connections in the pool.
    /// Thread-safe: can be called from multiple threads concurrently.
    pub fn totalCount(self: *Self) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.totalCountLocked();
    }

    /// Internal: total count while already holding the lock.
    fn totalCountLocked(self: *const Self) usize {
        return self.connections.items.len;
    }

    /// Returns the number of idle (not in-use) connections.
    /// Thread-safe: can be called from multiple threads concurrently.
    pub fn idleCount(self: *Self) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        var active: usize = 0;
        for (self.connections.items) |conn| {
            if (conn.in_use) active += 1;
        }
        return self.connections.items.len - active;
    }

    /// Returns a snapshot of pool statistics.
    /// Thread-safe: can be called from multiple threads concurrently.
    pub fn getStats(self: *Self) PoolStats {
        self.mutex.lock();
        defer self.mutex.unlock();

        var active: usize = 0;
        for (self.connections.items) |conn| {
            if (conn.in_use) active += 1;
        }

        return .{
            .total_connections = self.connections.items.len,
            .active_connections = active,
            .idle_connections = self.connections.items.len - active,
            .max_connections = self.config.max_connections,
            .max_per_host = self.config.max_per_host,
        };
    }
};

/// Pool statistics snapshot.
pub const PoolStats = struct {
    total_connections: usize,
    active_connections: usize,
    idle_connections: usize,
    max_connections: u32,
    max_per_host: u32,
};

test "ConnectionPool initialization" {
    const allocator = std.testing.allocator;
    var pool = ConnectionPool.init(allocator);
    defer pool.deinit();

    try std.testing.expectEqual(@as(usize, 0), pool.totalCount());
}

test "ConnectionPool config" {
    const allocator = std.testing.allocator;
    var pool = ConnectionPool.initWithConfig(allocator, .{
        .max_connections = 50,
        .max_per_host = 10,
    });
    defer pool.deinit();

    try std.testing.expectEqual(@as(u32, 50), pool.config.max_connections);
    try std.testing.expectEqual(@as(u32, 10), pool.config.max_per_host);
}

test "Connection health check" {
    var conn = Connection{
        .socket = try Socket.create(),
        .host = "localhost",
        .port = 8080,
        .created_at = std.time.milliTimestamp(),
        .last_used = std.time.milliTimestamp(),
    };
    defer conn.socket.close();

    try std.testing.expect(conn.isHealthy(60_000));

    conn.in_use = true;
    try std.testing.expect(!conn.isHealthy(60_000));
}

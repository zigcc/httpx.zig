//! TLS Session Pool for httpx.zig
//!
//! Provides TLS session ticket caching for faster TLS reconnections.
//! When connecting to the same host multiple times, cached session tickets
//! can be used to perform abbreviated TLS handshakes (0-RTT or 1-RTT).
//!
//! ## Thread Safety
//! This module is fully thread-safe and can be shared across multiple
//! client instances and threads.

const std = @import("std");
const Thread = std.Thread;
const Allocator = std.mem.Allocator;

/// A cached TLS session ticket
pub const TlsSessionTicket = struct {
    /// The session ticket data
    ticket: []u8,
    /// When the ticket was created (milliseconds since epoch)
    created_at: i64,
    /// When the ticket expires (milliseconds since epoch)
    expires_at: i64,
    /// The TLS version used for this session
    tls_version: u16,
    /// The cipher suite used for this session
    cipher_suite: u16,

    pub fn isExpired(self: *const TlsSessionTicket) bool {
        return std.time.milliTimestamp() >= self.expires_at;
    }

    pub fn timeToLive(self: *const TlsSessionTicket) i64 {
        const now = std.time.milliTimestamp();
        if (now >= self.expires_at) return 0;
        return self.expires_at - now;
    }
};

/// Configuration for the TLS session pool
pub const TlsSessionPoolConfig = struct {
    /// Maximum number of sessions to cache
    max_sessions: usize = 1000,
    /// Default session lifetime in milliseconds (1 hour)
    default_lifetime_ms: i64 = 3600_000,
    /// How often to run cleanup in milliseconds (5 minutes)
    cleanup_interval_ms: i64 = 300_000,
    /// Enable automatic cleanup of expired sessions
    auto_cleanup: bool = true,
};

/// Thread-safe TLS session ticket pool
pub const TlsSessionPool = struct {
    allocator: Allocator,
    sessions: std.StringHashMap(TlsSessionTicket),
    mutex: Thread.Mutex,
    config: TlsSessionPoolConfig,
    last_cleanup: i64,

    // Statistics
    stats: Stats,

    pub const Stats = struct {
        hits: std.atomic.Value(u64),
        misses: std.atomic.Value(u64),
        stores: std.atomic.Value(u64),
        evictions: std.atomic.Value(u64),
        expired_cleanups: std.atomic.Value(u64),

        pub fn init() Stats {
            return .{
                .hits = std.atomic.Value(u64).init(0),
                .misses = std.atomic.Value(u64).init(0),
                .stores = std.atomic.Value(u64).init(0),
                .evictions = std.atomic.Value(u64).init(0),
                .expired_cleanups = std.atomic.Value(u64).init(0),
            };
        }

        pub fn getHits(self: *const Stats) u64 {
            return self.hits.load(.acquire);
        }

        pub fn getMisses(self: *const Stats) u64 {
            return self.misses.load(.acquire);
        }

        pub fn getHitRate(self: *const Stats) f64 {
            const h = self.getHits();
            const m = self.getMisses();
            const total = h + m;
            if (total == 0) return 0.0;
            return @as(f64, @floatFromInt(h)) / @as(f64, @floatFromInt(total));
        }
    };

    const Self = @This();

    /// Initialize a new TLS session pool
    pub fn init(allocator: Allocator) Self {
        return initWithConfig(allocator, .{});
    }

    /// Initialize with custom configuration
    pub fn initWithConfig(allocator: Allocator, config: TlsSessionPoolConfig) Self {
        return .{
            .allocator = allocator,
            .sessions = std.StringHashMap(TlsSessionTicket).init(allocator),
            .mutex = .{},
            .config = config,
            .last_cleanup = std.time.milliTimestamp(),
            .stats = Stats.init(),
        };
    }

    /// Deinitialize and free all resources
    pub fn deinit(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.ticket);
        }
        self.sessions.deinit();
    }

    /// Save a TLS session ticket for a host
    pub fn saveSession(
        self: *Self,
        host: []const u8,
        ticket: []const u8,
        options: struct {
            lifetime_ms: ?i64 = null,
            tls_version: u16 = 0x0304, // TLS 1.3
            cipher_suite: u16 = 0,
        },
    ) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Run periodic cleanup if enabled
        if (self.config.auto_cleanup) {
            _ = self.cleanupExpiredLocked();
        }

        // Check if we need to evict entries
        if (self.sessions.count() >= self.config.max_sessions) {
            self.evictOldestLocked();
        }

        const now = std.time.milliTimestamp();
        const lifetime = options.lifetime_ms orelse self.config.default_lifetime_ms;

        // Check if we already have an entry for this host
        if (self.sessions.getPtr(host)) |existing| {
            // Update existing entry
            self.allocator.free(existing.ticket);
            existing.ticket = try self.allocator.dupe(u8, ticket);
            existing.created_at = now;
            existing.expires_at = now + lifetime;
            existing.tls_version = options.tls_version;
            existing.cipher_suite = options.cipher_suite;
        } else {
            // Create new entry
            const key = try self.allocator.dupe(u8, host);
            errdefer self.allocator.free(key);

            const ticket_copy = try self.allocator.dupe(u8, ticket);
            errdefer self.allocator.free(ticket_copy);

            try self.sessions.put(key, .{
                .ticket = ticket_copy,
                .created_at = now,
                .expires_at = now + lifetime,
                .tls_version = options.tls_version,
                .cipher_suite = options.cipher_suite,
            });
        }

        _ = self.stats.stores.fetchAdd(1, .monotonic);
    }

    /// Retrieve a cached session ticket for a host
    /// Returns null if no valid ticket exists
    pub fn getSession(self: *Self, host: []const u8) ?TlsSessionTicket {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.sessions.get(host)) |entry| {
            if (!entry.isExpired()) {
                _ = self.stats.hits.fetchAdd(1, .monotonic);
                return entry;
            }
            // Expired - remove it
            self.removeEntryLocked(host);
            _ = self.stats.expired_cleanups.fetchAdd(1, .monotonic);
        }

        _ = self.stats.misses.fetchAdd(1, .monotonic);
        return null;
    }

    /// Check if a valid session exists for a host (without retrieving it)
    pub fn hasSession(self: *Self, host: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.sessions.get(host)) |entry| {
            return !entry.isExpired();
        }
        return false;
    }

    /// Remove a session for a host
    pub fn removeSession(self: *Self, host: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.removeEntryLocked(host);
    }

    /// Clear all cached sessions
    pub fn clear(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.ticket);
        }
        self.sessions.clearRetainingCapacity();
    }

    /// Get the number of cached sessions
    pub fn count(self: *Self) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.sessions.count();
    }

    /// Get pool statistics
    pub fn getStats(self: *Self) Stats {
        return self.stats;
    }

    /// Manually trigger cleanup of expired sessions
    pub fn cleanup(self: *Self) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.cleanupExpiredLocked();
    }

    // Internal: Remove an entry (must be called with mutex held)
    fn removeEntryLocked(self: *Self, host: []const u8) void {
        if (self.sessions.fetchRemove(host)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value.ticket);
        }
    }

    // Internal: Cleanup expired sessions (must be called with mutex held)
    fn cleanupExpiredLocked(self: *Self) usize {
        const now = std.time.milliTimestamp();

        // Only run cleanup periodically
        if (now - self.last_cleanup < self.config.cleanup_interval_ms) {
            return 0;
        }
        self.last_cleanup = now;

        var to_remove: std.ArrayListUnmanaged([]const u8) = .empty;
        defer to_remove.deinit(self.allocator);

        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.isExpired()) {
                to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }

        for (to_remove.items) |key| {
            if (self.sessions.fetchRemove(key)) |kv| {
                self.allocator.free(kv.key);
                self.allocator.free(kv.value.ticket);
                _ = self.stats.expired_cleanups.fetchAdd(1, .monotonic);
            }
        }

        return to_remove.items.len;
    }

    // Internal: Evict oldest session (must be called with mutex held)
    fn evictOldestLocked(self: *Self) void {
        var oldest_key: ?[]const u8 = null;
        var oldest_time: i64 = std.math.maxInt(i64);

        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.created_at < oldest_time) {
                oldest_time = entry.value_ptr.created_at;
                oldest_key = entry.key_ptr.*;
            }
        }

        if (oldest_key) |key| {
            // Need to dupe because removeEntryLocked frees the key
            const key_copy = self.allocator.dupe(u8, key) catch return;
            defer self.allocator.free(key_copy);
            self.removeEntryLocked(key_copy);
            _ = self.stats.evictions.fetchAdd(1, .monotonic);
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

test "TlsSessionPool init/deinit" {
    const allocator = std.testing.allocator;
    var pool = TlsSessionPool.init(allocator);
    defer pool.deinit();

    try std.testing.expectEqual(@as(usize, 0), pool.count());
}

test "TlsSessionPool save and get" {
    const allocator = std.testing.allocator;
    var pool = TlsSessionPool.init(allocator);
    defer pool.deinit();

    const ticket = "test-session-ticket-data";
    try pool.saveSession("example.com", ticket, .{});

    try std.testing.expectEqual(@as(usize, 1), pool.count());
    try std.testing.expect(pool.hasSession("example.com"));

    const retrieved = pool.getSession("example.com");
    try std.testing.expect(retrieved != null);
    try std.testing.expectEqualStrings(ticket, retrieved.?.ticket);
}

test "TlsSessionPool miss" {
    const allocator = std.testing.allocator;
    var pool = TlsSessionPool.init(allocator);
    defer pool.deinit();

    const result = pool.getSession("nonexistent.com");
    try std.testing.expect(result == null);

    const stats = pool.getStats();
    try std.testing.expectEqual(@as(u64, 1), stats.getMisses());
}

test "TlsSessionPool update existing" {
    const allocator = std.testing.allocator;
    var pool = TlsSessionPool.init(allocator);
    defer pool.deinit();

    try pool.saveSession("example.com", "ticket-v1", .{});
    try pool.saveSession("example.com", "ticket-v2", .{});

    try std.testing.expectEqual(@as(usize, 1), pool.count());

    const retrieved = pool.getSession("example.com");
    try std.testing.expectEqualStrings("ticket-v2", retrieved.?.ticket);
}

test "TlsSessionPool remove" {
    const allocator = std.testing.allocator;
    var pool = TlsSessionPool.init(allocator);
    defer pool.deinit();

    try pool.saveSession("example.com", "ticket", .{});
    try std.testing.expect(pool.hasSession("example.com"));

    pool.removeSession("example.com");
    try std.testing.expect(!pool.hasSession("example.com"));
}

test "TlsSessionPool clear" {
    const allocator = std.testing.allocator;
    var pool = TlsSessionPool.init(allocator);
    defer pool.deinit();

    try pool.saveSession("a.com", "ticket-a", .{});
    try pool.saveSession("b.com", "ticket-b", .{});
    try pool.saveSession("c.com", "ticket-c", .{});

    try std.testing.expectEqual(@as(usize, 3), pool.count());

    pool.clear();
    try std.testing.expectEqual(@as(usize, 0), pool.count());
}

test "TlsSessionPool hit rate" {
    const allocator = std.testing.allocator;
    var pool = TlsSessionPool.init(allocator);
    defer pool.deinit();

    try pool.saveSession("example.com", "ticket", .{});

    // 2 hits
    _ = pool.getSession("example.com");
    _ = pool.getSession("example.com");

    // 2 misses
    _ = pool.getSession("other.com");
    _ = pool.getSession("another.com");

    const stats = pool.getStats();
    try std.testing.expectEqual(@as(u64, 2), stats.getHits());
    try std.testing.expectEqual(@as(u64, 2), stats.getMisses());
    try std.testing.expectApproxEqAbs(@as(f64, 0.5), stats.getHitRate(), 0.01);
}

test "TlsSessionTicket expiration check" {
    const now = std.time.milliTimestamp();

    // Not expired ticket
    const valid_ticket = TlsSessionTicket{
        .ticket = &[_]u8{},
        .created_at = now,
        .expires_at = now + 3600_000, // 1 hour from now
        .tls_version = 0x0304,
        .cipher_suite = 0,
    };
    try std.testing.expect(!valid_ticket.isExpired());
    try std.testing.expect(valid_ticket.timeToLive() > 0);

    // Expired ticket
    const expired_ticket = TlsSessionTicket{
        .ticket = &[_]u8{},
        .created_at = now - 7200_000, // 2 hours ago
        .expires_at = now - 3600_000, // 1 hour ago
        .tls_version = 0x0304,
        .cipher_suite = 0,
    };
    try std.testing.expect(expired_ticket.isExpired());
    try std.testing.expectEqual(@as(i64, 0), expired_ticket.timeToLive());
}

test "TlsSessionPool expired session returns null" {
    const allocator = std.testing.allocator;
    var pool = TlsSessionPool.initWithConfig(allocator, .{
        .default_lifetime_ms = 1, // 1ms lifetime - will expire immediately
        .auto_cleanup = false,
    });
    defer pool.deinit();

    try pool.saveSession("example.com", "ticket", .{ .lifetime_ms = 1 });

    // Wait for expiration
    std.Thread.sleep(2_000_000); // 2ms

    // Should return null because expired
    const result = pool.getSession("example.com");
    try std.testing.expect(result == null);
}

test "TlsSessionPool eviction when full" {
    const allocator = std.testing.allocator;
    var pool = TlsSessionPool.initWithConfig(allocator, .{
        .max_sessions = 2,
        .auto_cleanup = false,
    });
    defer pool.deinit();

    // Fill the pool
    try pool.saveSession("a.com", "ticket-a", .{});
    try pool.saveSession("b.com", "ticket-b", .{});
    try std.testing.expectEqual(@as(usize, 2), pool.count());

    // Add one more - should evict oldest
    try pool.saveSession("c.com", "ticket-c", .{});
    try std.testing.expectEqual(@as(usize, 2), pool.count());

    // c.com should exist
    try std.testing.expect(pool.hasSession("c.com"));
}

test "TlsSessionPool manual cleanup" {
    const allocator = std.testing.allocator;
    var pool = TlsSessionPool.initWithConfig(allocator, .{
        .cleanup_interval_ms = 0, // Always run cleanup
        .auto_cleanup = false,
    });
    defer pool.deinit();

    // Add a session with very short lifetime
    try pool.saveSession("example.com", "ticket", .{ .lifetime_ms = 1 });

    // Wait for expiration
    std.Thread.sleep(2_000_000); // 2ms

    // Manual cleanup should remove expired
    const cleaned = pool.cleanup();
    try std.testing.expect(cleaned >= 1);
    try std.testing.expectEqual(@as(usize, 0), pool.count());
}

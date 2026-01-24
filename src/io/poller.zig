//! Cross-Platform Event Poller
//!
//! Provides a unified event multiplexing interface:
//! - Linux: epoll
//! - macOS/BSD: kqueue
//! - Windows: IOCP
//!
//! This module enables non-blocking I/O for high-concurrency servers.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const Allocator = std.mem.Allocator;

/// Event returned by the poller
pub const Event = struct {
    fd: posix.fd_t,
    data: usize, // User-provided context pointer
    events: EventMask,
};

/// Bitmask of event types to monitor
pub const EventMask = packed struct(u32) {
    readable: bool = false,
    writable: bool = false,
    error_: bool = false,
    hangup: bool = false,
    _padding: u28 = 0,

    pub const read_write: EventMask = .{ .readable = true, .writable = true };
    pub const read_only: EventMask = .{ .readable = true };
    pub const write_only: EventMask = .{ .writable = true };
};

/// Cross-platform event poller
pub const Poller = struct {
    impl: PollerImpl,
    allocator: Allocator,

    const Self = @This();

    /// Initialize the poller
    pub fn init(allocator: Allocator) !Self {
        return .{
            .impl = try PollerImpl.init(),
            .allocator = allocator,
        };
    }

    /// Deinitialize the poller and release resources
    pub fn deinit(self: *Self) void {
        self.impl.deinit();
    }

    /// Register a file descriptor for event monitoring
    pub fn add(self: *Self, fd: posix.fd_t, events: EventMask, data: usize) !void {
        try self.impl.add(fd, events, data);
    }

    /// Modify the events being monitored for a file descriptor
    pub fn modify(self: *Self, fd: posix.fd_t, events: EventMask, data: usize) !void {
        try self.impl.modify(fd, events, data);
    }

    /// Remove a file descriptor from monitoring
    pub fn remove(self: *Self, fd: posix.fd_t) !void {
        try self.impl.remove(fd);
    }

    /// Wait for events (blocking)
    /// Returns the number of events that occurred
    pub fn wait(self: *Self, events: []Event, timeout_ms: ?i32) !usize {
        return self.impl.wait(events, timeout_ms);
    }

    /// Poll for events without blocking (timeout = 0)
    pub fn poll(self: *Self, events: []Event) !usize {
        return self.impl.wait(events, 0);
    }
};

// Platform-specific implementation selection
const PollerImpl = switch (builtin.os.tag) {
    .linux => LinuxEpoll,
    .macos, .ios, .freebsd, .netbsd, .openbsd, .dragonfly => BsdKqueue,
    .windows => WindowsIocp,
    else => @compileError("Unsupported platform for event polling"),
};

// ============================================================================
// Linux epoll Implementation
// ============================================================================
const LinuxEpoll = struct {
    epoll_fd: posix.fd_t,

    const Self = @This();

    pub fn init() !Self {
        // Use EPOLL_CLOEXEC flag (0x80000)
        const fd = try posix.epoll_create1(std.os.linux.EPOLL.CLOEXEC);
        return .{ .epoll_fd = fd };
    }

    pub fn deinit(self: *Self) void {
        posix.close(self.epoll_fd);
    }

    pub fn add(self: *Self, fd: posix.fd_t, events: EventMask, data: usize) !void {
        var ev = std.os.linux.epoll_event{
            .events = toEpollEvents(events),
            .data = .{ .ptr = data },
        };
        try posix.epoll_ctl(self.epoll_fd, std.os.linux.EPOLL.CTL_ADD, fd, &ev);
    }

    pub fn modify(self: *Self, fd: posix.fd_t, events: EventMask, data: usize) !void {
        var ev = std.os.linux.epoll_event{
            .events = toEpollEvents(events),
            .data = .{ .ptr = data },
        };
        try posix.epoll_ctl(self.epoll_fd, std.os.linux.EPOLL.CTL_MOD, fd, &ev);
    }

    pub fn remove(self: *Self, fd: posix.fd_t) !void {
        try posix.epoll_ctl(self.epoll_fd, std.os.linux.EPOLL.CTL_DEL, fd, null);
    }

    pub fn wait(self: *Self, events: []Event, timeout_ms: ?i32) !usize {
        var raw_events: [256]std.os.linux.epoll_event = undefined;
        const max_events = @min(events.len, raw_events.len);

        const n = posix.epoll_wait(
            self.epoll_fd,
            raw_events[0..max_events],
            timeout_ms orelse -1,
        );

        for (raw_events[0..n], 0..) |raw, i| {
            events[i] = .{
                .fd = undefined, // epoll doesn't return fd, use data instead
                .data = raw.data.ptr,
                .events = fromEpollEvents(raw.events),
            };
        }

        return n;
    }

    fn toEpollEvents(mask: EventMask) u32 {
        var result: u32 = 0;
        if (mask.readable) result |= std.os.linux.EPOLL.IN;
        if (mask.writable) result |= std.os.linux.EPOLL.OUT;
        // Always monitor for errors and hangups
        result |= std.os.linux.EPOLL.ERR | std.os.linux.EPOLL.HUP;
        return result;
    }

    fn fromEpollEvents(raw: u32) EventMask {
        return .{
            .readable = (raw & std.os.linux.EPOLL.IN) != 0,
            .writable = (raw & std.os.linux.EPOLL.OUT) != 0,
            .error_ = (raw & std.os.linux.EPOLL.ERR) != 0,
            .hangup = (raw & std.os.linux.EPOLL.HUP) != 0,
        };
    }
};

// ============================================================================
// macOS/BSD kqueue Implementation
// ============================================================================
const BsdKqueue = struct {
    kq: posix.fd_t,

    const Self = @This();

    pub fn init() !Self {
        const kq = try posix.kqueue();
        return .{ .kq = kq };
    }

    pub fn deinit(self: *Self) void {
        posix.close(self.kq);
    }

    pub fn add(self: *Self, fd: posix.fd_t, events: EventMask, data: usize) !void {
        var changelist: [2]posix.Kevent = undefined;
        var n: usize = 0;

        if (events.readable) {
            changelist[n] = makeKevent(fd, posix.system.EVFILT.READ, posix.system.EV.ADD | posix.system.EV.CLEAR, data);
            n += 1;
        }
        if (events.writable) {
            changelist[n] = makeKevent(fd, posix.system.EVFILT.WRITE, posix.system.EV.ADD | posix.system.EV.CLEAR, data);
            n += 1;
        }

        if (n > 0) {
            _ = try posix.kevent(self.kq, changelist[0..n], &.{}, null);
        }
    }

    pub fn modify(self: *Self, fd: posix.fd_t, events: EventMask, data: usize) !void {
        // In kqueue, modify is equivalent to re-adding
        try self.add(fd, events, data);
    }

    pub fn remove(self: *Self, fd: posix.fd_t) !void {
        var changelist = [_]posix.Kevent{
            makeKevent(fd, posix.system.EVFILT.READ, posix.system.EV.DELETE, 0),
            makeKevent(fd, posix.system.EVFILT.WRITE, posix.system.EV.DELETE, 0),
        };
        // Ignore errors since the fd might not be registered for both events
        _ = posix.kevent(self.kq, &changelist, &.{}, null) catch {};
    }

    pub fn wait(self: *Self, events: []Event, timeout_ms: ?i32) !usize {
        var raw_events: [256]posix.Kevent = undefined;
        const max_events = @min(events.len, raw_events.len);

        const ts: ?posix.timespec = if (timeout_ms) |ms| .{
            .sec = @divTrunc(ms, 1000),
            .nsec = @rem(ms, 1000) * 1_000_000,
        } else null;

        const n = try posix.kevent(self.kq, &.{}, raw_events[0..max_events], if (ts) |*t| t else null);

        for (raw_events[0..n], 0..) |raw, i| {
            events[i] = .{
                .fd = @intCast(raw.ident),
                .data = @intFromPtr(raw.udata),
                .events = fromKqueueFilter(raw.filter, raw.flags),
            };
        }

        return n;
    }

    fn makeKevent(fd: posix.fd_t, filter: posix.system.EVFILT, flags: u16, data: usize) posix.Kevent {
        return .{
            .ident = @intCast(fd),
            .filter = filter,
            .flags = flags,
            .fflags = 0,
            .data = 0,
            .udata = @ptrFromInt(data),
        };
    }

    fn fromKqueueFilter(filter: posix.system.EVFILT, flags: u16) EventMask {
        return .{
            .readable = filter == posix.system.EVFILT.READ,
            .writable = filter == posix.system.EVFILT.WRITE,
            .error_ = (flags & posix.system.EV.ERROR) != 0,
            .hangup = (flags & posix.system.EV.EOF) != 0,
        };
    }
};

// ============================================================================
// Windows IOCP Implementation
// ============================================================================
const WindowsIocp = struct {
    iocp: std.os.windows.HANDLE,

    const Self = @This();
    const windows = std.os.windows;
    const kernel32 = windows.kernel32;

    pub fn init() !Self {
        const iocp = kernel32.CreateIoCompletionPort(
            windows.INVALID_HANDLE_VALUE,
            null,
            0,
            0,
        ) orelse return error.IocpCreateFailed;
        return .{ .iocp = iocp };
    }

    pub fn deinit(self: *Self) void {
        windows.CloseHandle(self.iocp);
    }

    pub fn add(self: *Self, fd: posix.fd_t, events: EventMask, data: usize) !void {
        _ = events;
        // On Windows, fd_t is already HANDLE (pointer type), so cast directly
        const handle: windows.HANDLE = @ptrCast(fd);
        _ = kernel32.CreateIoCompletionPort(
            handle,
            self.iocp,
            data,
            0,
        ) orelse return error.IocpAssociateFailed;
    }

    pub fn modify(self: *Self, fd: posix.fd_t, events: EventMask, data: usize) !void {
        _ = self;
        _ = fd;
        _ = events;
        _ = data;
        // IOCP doesn't need modify - associations are permanent
    }

    pub fn remove(self: *Self, fd: posix.fd_t) !void {
        _ = self;
        _ = fd;
        // IOCP automatically removes handles when they're closed
    }

    pub fn wait(self: *Self, events: []Event, timeout_ms: ?i32) !usize {
        const timeout_dw: windows.DWORD = if (timeout_ms) |ms|
            if (ms < 0) windows.INFINITE else @intCast(@as(u32, @intCast(ms)))
        else
            windows.INFINITE;

        var bytes_transferred: windows.DWORD = 0;
        var completion_key: usize = 0;
        var overlapped: ?*windows.OVERLAPPED = null;

        const result = kernel32.GetQueuedCompletionStatus(
            self.iocp,
            &bytes_transferred,
            &completion_key,
            &overlapped,
            timeout_dw,
        );

        if (result == windows.FALSE) {
            const err = kernel32.GetLastError();
            if (err == @intFromEnum(windows.Win32Error.WAIT_TIMEOUT)) {
                return 0;
            }
            // Other errors - return 0 for now
            // TODO: Proper error handling
            return 0;
        }

        // Got one event
        if (events.len > 0) {
            events[0] = .{
                .fd = undefined,
                .data = completion_key,
                .events = .{ .readable = true, .writable = true },
            };
            return 1;
        }

        return 0;
    }
};

// ============================================================================
// Tests
// ============================================================================
test "Poller init/deinit" {
    var poller = try Poller.init(std.testing.allocator);
    defer poller.deinit();
}

test "EventMask constants" {
    const read_only = EventMask.read_only;
    try std.testing.expect(read_only.readable);
    try std.testing.expect(!read_only.writable);

    const read_write = EventMask.read_write;
    try std.testing.expect(read_write.readable);
    try std.testing.expect(read_write.writable);
}

test "Poller add and remove" {
    const net = std.net;
    var poller = try Poller.init(std.testing.allocator);
    defer poller.deinit();

    // Create a socket to register
    const addr = try net.Address.parseIp("127.0.0.1", 0);
    const sock = try posix.socket(addr.any.family, posix.SOCK.STREAM, 0);
    defer posix.close(sock);

    // Add socket to poller
    try poller.add(sock, .{ .readable = true }, 42);

    // Modify events
    try poller.modify(sock, .{ .readable = true, .writable = true }, 42);

    // Remove socket
    try poller.remove(sock);
}

test "Poller poll returns immediately with no events" {
    var poller = try Poller.init(std.testing.allocator);
    defer poller.deinit();

    var events: [16]Event = undefined;

    // Poll with 0 timeout should return immediately
    const n = try poller.poll(&events);
    try std.testing.expectEqual(@as(usize, 0), n);
}

test "Poller wait with timeout" {
    var poller = try Poller.init(std.testing.allocator);
    defer poller.deinit();

    var events: [16]Event = undefined;

    // Wait with short timeout should return after timeout
    const start = std.time.milliTimestamp();
    const n = try poller.wait(&events, 10); // 10ms timeout
    const elapsed = std.time.milliTimestamp() - start;

    try std.testing.expectEqual(@as(usize, 0), n);
    try std.testing.expect(elapsed >= 5); // Allow some tolerance
}

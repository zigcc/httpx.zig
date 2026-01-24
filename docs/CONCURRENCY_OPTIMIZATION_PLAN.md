# httpx.zig 并发优化方案

## 一、现状分析

### 1.1 当前架构瓶颈

| 组件 | 问题 | 影响 |
|------|------|------|
| **Server** | 单线程阻塞 accept 循环 | 无法并发处理请求，吞吐量受限 |
| **ConnectionPool** | 无锁保护 | 多线程访问会导致数据竞争 |
| **Socket I/O** | 阻塞模型 | 每个连接需要一个线程，扩展性差 |
| **TLS Session** | 不池化 | HTTPS 每次握手开销大 |

### 1.2 当前并发实现

已有的并发组件：

- `src/concurrency/executor.zig` - 线程池执行器
- `src/concurrency/pool.zig` - 并行请求模式 (all/any/race/allSettled)
- `src/client/pool.zig` - 连接池 (非线程安全)

使用的同步原语：

```zig
std.Thread.spawn()          // 创建线程
std.Thread.join()           // 等待线程
std.Thread.Mutex            // 互斥锁
std.Thread.Condition        // 条件变量
std.atomic.Value(T)         // 原子操作
```

### 1.3 平台支持现状

| 平台 | Socket | TLS | 线程 | 状态 |
|------|--------|-----|------|------|
| **Linux** (x86_64, aarch64, x86) | ✅ POSIX | ✅ | ✅ std.Thread | 完整支持 |
| **Windows** (x86_64, aarch64, x86) | ✅ Winsock2 | ✅ | ✅ std.Thread | 完整支持 |
| **macOS** (x86_64, aarch64) | ✅ POSIX | ✅ | ✅ std.Thread | 完整支持 |
| **FreeBSD/NetBSD/OpenBSD** | ✅ POSIX | ✅ | ✅ std.Thread | 基本支持 |

### 1.4 目标

| 指标 | 当前 | 目标 |
|------|------|------|
| 服务器并发连接 | 1 | 10,000+ |
| 平台支持 | ✅ Linux/Windows/macOS | 保持 |
| API 兼容性 | - | 向后兼容 |

---

## 二、优化方案总览

```
┌─────────────────────────────────────────────────────────────────┐
│                     Phase 1: 基础多线程                          │
│  • Server Worker Pool                                           │
│  • Thread-safe ConnectionPool                                   │
│  • 预计工作量: 3-5 天                                            │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                     Phase 2: 事件驱动 I/O                        │
│  • 跨平台 Poller 抽象层                                          │
│  • Linux: epoll / io_uring                                      │
│  • macOS: kqueue                                                │
│  • Windows: IOCP                                                │
│  • 预计工作量: 7-14 天                                           │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                     Phase 3: 高级优化                            │
│  • TLS Session 复用                                             │
│  • Zero-copy I/O                                                │
│  • Work-stealing 调度                                           │
│  • 预计工作量: 7-14 天                                           │
└─────────────────────────────────────────────────────────────────┘
```

---

## 三、Phase 1: 基础多线程支持

### 3.1 Server Worker Pool 设计

**目标**: 使 Server 能够并发处理多个连接

#### 新增文件: `src/server/worker_pool.zig`

```zig
//! Server Worker Pool
//!
//! 为 HTTP Server 提供多线程请求处理能力

const std = @import("std");
const Thread = std.Thread;
const Allocator = std.mem.Allocator;
const Socket = @import("../net/socket.zig").Socket;

pub const WorkerPoolConfig = struct {
    /// Worker 线程数，0 表示自动检测 CPU 核心数
    num_workers: u32 = 0,
    /// 任务队列最大长度
    max_queue_size: usize = 4096,
    /// Worker 空闲超时 (ms)
    idle_timeout_ms: u64 = 60_000,
    /// 单个请求处理超时 (ms)
    request_timeout_ms: u64 = 30_000,
};

pub const WorkItem = struct {
    socket: Socket,
    client_addr: std.net.Address,
    accepted_at: i64,
};

pub const WorkerPool = struct {
    allocator: Allocator,
    config: WorkerPoolConfig,
    
    // 任务队列 (线程安全)
    queue: std.ArrayListUnmanaged(WorkItem) = .empty,
    queue_mutex: Thread.Mutex = .{},
    queue_not_empty: Thread.Condition = .{},
    queue_not_full: Thread.Condition = .{},
    
    // Worker 线程
    workers: []Thread = &.{},
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    
    // 统计信息
    stats: Stats = .{},
    stats_mutex: Thread.Mutex = .{},
    
    // 请求处理器 (由 Server 设置)
    handler: ?*const fn (*WorkItem, *anyopaque) void = null,
    handler_ctx: ?*anyopaque = null,

    const Self = @This();

    pub const Stats = struct {
        total_requests: u64 = 0,
        active_requests: u64 = 0,
        queue_depth: u64 = 0,
        total_errors: u64 = 0,
    };

    pub fn init(allocator: Allocator, config: WorkerPoolConfig) Self {
        var cfg = config;
        if (cfg.num_workers == 0) {
            cfg.num_workers = @max(1, @as(u32, @intCast(Thread.getCpuCount() catch 4)));
        }
        return .{
            .allocator = allocator,
            .config = cfg,
        };
    }

    pub fn deinit(self: *Self) void {
        self.stop();
        self.queue.deinit(self.allocator);
        if (self.workers.len > 0) {
            self.allocator.free(self.workers);
        }
    }

    pub fn start(self: *Self) !void {
        if (self.running.load(.acquire)) return;
        self.running.store(true, .release);
        
        self.workers = try self.allocator.alloc(Thread, self.config.num_workers);
        
        for (self.workers, 0..) |*worker, i| {
            worker.* = try Thread.spawn(.{}, workerLoop, .{ self, i });
        }
    }

    pub fn stop(self: *Self) void {
        if (!self.running.swap(false, .acq_rel)) return;
        
        // 唤醒所有等待的 worker
        self.queue_mutex.lock();
        self.queue_not_empty.broadcast();
        self.queue_mutex.unlock();
        
        // 等待所有 worker 退出
        for (self.workers) |worker| {
            worker.join();
        }
    }

    /// 提交新连接到工作队列
    pub fn submit(self: *Self, item: WorkItem) !void {
        self.queue_mutex.lock();
        defer self.queue_mutex.unlock();
        
        // 队列满时等待
        while (self.queue.items.len >= self.config.max_queue_size) {
            self.queue_not_full.wait(&self.queue_mutex);
            if (!self.running.load(.acquire)) return error.PoolStopped;
        }
        
        try self.queue.append(self.allocator, item);
        self.queue_not_empty.signal();
        
        self.updateStats(.queue_depth, @intCast(self.queue.items.len));
    }

    fn workerLoop(self: *Self, worker_id: usize) void {
        _ = worker_id;
        
        while (self.running.load(.acquire)) {
            // 获取任务
            self.queue_mutex.lock();
            while (self.queue.items.len == 0 and self.running.load(.acquire)) {
                self.queue_not_empty.wait(&self.queue_mutex);
            }
            
            if (!self.running.load(.acquire)) {
                self.queue_mutex.unlock();
                break;
            }
            
            const item = self.queue.orderedRemove(0);
            self.queue_not_full.signal();
            self.queue_mutex.unlock();
            
            // 处理请求
            self.incrementStats(.active_requests);
            defer self.decrementStats(.active_requests);
            
            if (self.handler) |h| {
                var work_item = item;
                h(&work_item, self.handler_ctx.?);
            }
            
            self.incrementStats(.total_requests);
        }
    }

    fn updateStats(self: *Self, field: enum { queue_depth }, value: u64) void {
        self.stats_mutex.lock();
        defer self.stats_mutex.unlock();
        switch (field) {
            .queue_depth => self.stats.queue_depth = value,
        }
    }

    fn incrementStats(self: *Self, field: enum { active_requests, total_requests, total_errors }) void {
        self.stats_mutex.lock();
        defer self.stats_mutex.unlock();
        switch (field) {
            .active_requests => self.stats.active_requests += 1,
            .total_requests => self.stats.total_requests += 1,
            .total_errors => self.stats.total_errors += 1,
        }
    }

    fn decrementStats(self: *Self, field: enum { active_requests }) void {
        self.stats_mutex.lock();
        defer self.stats_mutex.unlock();
        switch (field) {
            .active_requests => self.stats.active_requests -|= 1,
        }
    }

    pub fn getStats(self: *Self) Stats {
        self.stats_mutex.lock();
        defer self.stats_mutex.unlock();
        return self.stats;
    }
};
```

#### 修改 `src/server/server.zig`

```zig
// 在 Server 结构体中添加
const WorkerPool = @import("worker_pool.zig").WorkerPool;
const WorkerPoolConfig = @import("worker_pool.zig").WorkerPoolConfig;

pub const Server = struct {
    // ... 现有字段 ...
    
    // 新增: Worker Pool
    worker_pool: ?WorkerPool = null,
    use_threading: bool = false,

    /// 启用多线程模式
    pub fn enableThreading(self: *Self, config: WorkerPoolConfig) !void {
        self.worker_pool = WorkerPool.init(self.allocator, config);
        self.worker_pool.?.handler = handleConnectionWrapper;
        self.worker_pool.?.handler_ctx = @ptrCast(self);
        self.use_threading = true;
    }

    /// 修改后的 listen 方法
    pub fn listen(self: *Self) !void {
        const addr = try net.Address.parseIp(self.config.host, self.config.port);
        self.listener = try TcpListener.init(addr);
        self.running = true;

        // 启动 worker pool
        if (self.worker_pool) |*pool| {
            try pool.start();
        }

        std.debug.print("Server listening on {s}:{d} (threading: {})\n", .{
            self.config.host, self.config.port, self.use_threading
        });

        while (self.running) {
            const conn = self.listener.?.accept() catch |err| {
                std.debug.print("Accept error: {}\n", .{err});
                continue;
            };

            if (self.use_threading) {
                // 多线程模式: 提交到 worker pool
                self.worker_pool.?.submit(.{
                    .socket = conn.socket,
                    .client_addr = conn.addr,
                    .accepted_at = std.time.milliTimestamp(),
                }) catch |err| {
                    std.debug.print("Submit error: {}\n", .{err});
                    var s = conn.socket;
                    s.close();
                };
            } else {
                // 单线程模式: 直接处理
                self.handleConnection(conn.socket) catch |err| {
                    std.debug.print("Handler error: {}\n", .{err});
                };
            }
        }
    }

    fn handleConnectionWrapper(item: *WorkerPool.WorkItem, ctx: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        self.handleConnection(item.socket) catch |err| {
            std.debug.print("Handler error: {}\n", .{err});
        };
    }
};
```

---

### 3.2 线程安全 ConnectionPool 设计

**目标**: 使 ConnectionPool 支持多线程并发访问

#### 修改 `src/client/pool.zig`

```zig
pub const ConnectionPool = struct {
    allocator: Allocator,
    config: PoolConfig,
    connections: std.ArrayListUnmanaged(Connection) = .empty,
    hosts_owned: std.ArrayListUnmanaged([]u8) = .empty,
    
    // 新增: 线程安全
    mutex: std.Thread.Mutex = .{},

    // ... 现有方法 ...

    /// 线程安全版本: 获取连接
    pub fn getConnection(self: *Self, host: []const u8, port: u16) !*Connection {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        return self.getConnectionUnsafe(host, port);
    }

    /// 非锁版本 (内部使用)
    fn getConnectionUnsafe(self: *Self, host: []const u8, port: u16) !*Connection {
        // 查找可复用连接
        for (self.connections.items) |*conn| {
            if (std.mem.eql(u8, conn.host, host) and conn.port == port) {
                if (conn.isHealthy(self.config.idle_timeout_ms) and 
                    conn.requests_made < self.config.max_requests_per_connection) {
                    conn.acquire();
                    return conn;
                }
            }
        }

        // 检查限制
        if (self.totalCountUnsafe() >= self.config.max_connections) {
            return PoolError.PoolExhausted;
        }

        var host_count: u32 = 0;
        for (self.connections.items) |conn| {
            if (std.mem.eql(u8, conn.host, host) and conn.port == port) {
                host_count += 1;
            }
        }
        if (host_count >= self.config.max_per_host) {
            return PoolError.PoolExhaustedForHost;
        }

        return self.createConnectionUnsafe(host, port);
    }

    /// 线程安全版本: 释放连接
    pub fn releaseConnection(self: *Self, conn: *Connection) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        conn.release();
    }

    /// 线程安全版本: 清理空闲连接
    pub fn cleanup(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.cleanupUnsafe();
    }

    fn cleanupUnsafe(self: *Self) void {
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

    fn totalCountUnsafe(self: *const Self) usize {
        return self.connections.items.len;
    }
};
```

---

## 四、Phase 2: 跨平台事件驱动 I/O

### 4.1 Poller 抽象层设计

**目标**: 提供统一的事件驱动 I/O 接口，底层适配各平台

#### 新增文件: `src/io/poller.zig`

```zig
//! Cross-Platform Event Poller
//!
//! 提供统一的事件多路复用接口:
//! - Linux: epoll (默认) 或 io_uring (可选)
//! - macOS/BSD: kqueue
//! - Windows: IOCP

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const Allocator = std.mem.Allocator;

pub const Event = struct {
    fd: posix.fd_t,
    data: usize,  // 用户数据
    events: EventMask,
};

pub const EventMask = packed struct {
    readable: bool = false,
    writable: bool = false,
    error_: bool = false,
    hangup: bool = false,
    _padding: u28 = 0,
};

pub const Poller = struct {
    impl: PollerImpl,
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator) !Self {
        return .{
            .impl = try PollerImpl.init(),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.impl.deinit();
    }

    /// 注册文件描述符
    pub fn add(self: *Self, fd: posix.fd_t, events: EventMask, data: usize) !void {
        try self.impl.add(fd, events, data);
    }

    /// 修改监听事件
    pub fn modify(self: *Self, fd: posix.fd_t, events: EventMask, data: usize) !void {
        try self.impl.modify(fd, events, data);
    }

    /// 移除文件描述符
    pub fn remove(self: *Self, fd: posix.fd_t) !void {
        try self.impl.remove(fd);
    }

    /// 等待事件 (阻塞)
    pub fn wait(self: *Self, events: []Event, timeout_ms: ?i32) !usize {
        return self.impl.wait(events, timeout_ms);
    }
};

// 平台特定实现
const PollerImpl = switch (builtin.os.tag) {
    .linux => LinuxEpoll,
    .macos, .freebsd, .netbsd, .openbsd => BsdKqueue,
    .windows => WindowsIocp,
    else => @compileError("Unsupported platform for event polling"),
};

// ============================================================================
// Linux epoll 实现
// ============================================================================
const LinuxEpoll = struct {
    epoll_fd: posix.fd_t,

    const Self = @This();

    pub fn init() !Self {
        const fd = try posix.epoll_create1(0);
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
        try posix.epoll_ctl(self.epoll_fd, .ADD, fd, &ev);
    }

    pub fn modify(self: *Self, fd: posix.fd_t, events: EventMask, data: usize) !void {
        var ev = std.os.linux.epoll_event{
            .events = toEpollEvents(events),
            .data = .{ .ptr = data },
        };
        try posix.epoll_ctl(self.epoll_fd, .MOD, fd, &ev);
    }

    pub fn remove(self: *Self, fd: posix.fd_t) !void {
        try posix.epoll_ctl(self.epoll_fd, .DEL, fd, null);
    }

    pub fn wait(self: *Self, events: []Event, timeout_ms: ?i32) !usize {
        var raw_events: [256]std.os.linux.epoll_event = undefined;
        const max_events = @min(events.len, raw_events.len);
        
        const n = try posix.epoll_wait(
            self.epoll_fd,
            raw_events[0..max_events],
            timeout_ms orelse -1,
        );
        
        for (raw_events[0..n], 0..) |raw, i| {
            events[i] = .{
                .fd = undefined, // epoll 不返回 fd，使用 data
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
// macOS/BSD kqueue 实现
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
            changelist[n] = makeKevent(fd, posix.system.EVFILT_READ, posix.system.EV_ADD, data);
            n += 1;
        }
        if (events.writable) {
            changelist[n] = makeKevent(fd, posix.system.EVFILT_WRITE, posix.system.EV_ADD, data);
            n += 1;
        }
        
        _ = try posix.kevent(self.kq, changelist[0..n], &.{}, null);
    }

    pub fn modify(self: *Self, fd: posix.fd_t, events: EventMask, data: usize) !void {
        // kqueue 中修改等同于重新添加
        try self.add(fd, events, data);
    }

    pub fn remove(self: *Self, fd: posix.fd_t) !void {
        var changelist = [_]posix.Kevent{
            makeKevent(fd, posix.system.EVFILT_READ, posix.system.EV_DELETE, 0),
            makeKevent(fd, posix.system.EVFILT_WRITE, posix.system.EV_DELETE, 0),
        };
        _ = posix.kevent(self.kq, &changelist, &.{}, null) catch {};
    }

    pub fn wait(self: *Self, events: []Event, timeout_ms: ?i32) !usize {
        var raw_events: [256]posix.Kevent = undefined;
        const max_events = @min(events.len, raw_events.len);
        
        const ts: ?posix.timespec = if (timeout_ms) |ms| .{
            .sec = @divTrunc(ms, 1000),
            .nsec = @rem(ms, 1000) * 1_000_000,
        } else null;
        
        const n = try posix.kevent(self.kq, &.{}, raw_events[0..max_events], ts);
        
        for (raw_events[0..n], 0..) |raw, i| {
            events[i] = .{
                .fd = @intCast(raw.ident),
                .data = raw.udata,
                .events = fromKqueueFilter(raw.filter, raw.flags),
            };
        }
        
        return n;
    }

    fn makeKevent(fd: posix.fd_t, filter: i16, flags: u16, data: usize) posix.Kevent {
        return .{
            .ident = @intCast(fd),
            .filter = filter,
            .flags = flags,
            .fflags = 0,
            .data = 0,
            .udata = data,
        };
    }

    fn fromKqueueFilter(filter: i16, flags: u16) EventMask {
        return .{
            .readable = filter == posix.system.EVFILT_READ,
            .writable = filter == posix.system.EVFILT_WRITE,
            .error_ = (flags & posix.system.EV_ERROR) != 0,
            .hangup = (flags & posix.system.EV_EOF) != 0,
        };
    }
};

// ============================================================================
// Windows IOCP 实现 (框架)
// ============================================================================
const WindowsIocp = struct {
    iocp: std.os.windows.HANDLE,

    const Self = @This();

    pub fn init() !Self {
        const iocp = std.os.windows.kernel32.CreateIoCompletionPort(
            std.os.windows.INVALID_HANDLE_VALUE,
            null,
            0,
            0,
        ) orelse return error.IocpCreateFailed;
        return .{ .iocp = iocp };
    }

    pub fn deinit(self: *Self) void {
        std.os.windows.CloseHandle(self.iocp);
    }

    pub fn add(self: *Self, fd: posix.fd_t, events: EventMask, data: usize) !void {
        _ = events;
        // Windows IOCP 使用完成端口模型，需要不同的 API 模式
        // 这里需要将 socket 关联到 IOCP
        _ = std.os.windows.kernel32.CreateIoCompletionPort(
            @ptrFromInt(@as(usize, @intCast(fd))),
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
        // IOCP 不需要 modify
    }

    pub fn remove(self: *Self, fd: posix.fd_t) !void {
        _ = self;
        _ = fd;
        // IOCP 在 socket 关闭时自动移除
    }

    pub fn wait(self: *Self, events: []Event, timeout_ms: ?i32) !usize {
        _ = events;
        const timeout_dw: std.os.windows.DWORD = if (timeout_ms) |ms|
            @intCast(ms)
        else
            std.os.windows.INFINITE;

        // TODO: 实现 GetQueuedCompletionStatusEx 批量获取
        var bytes_transferred: std.os.windows.DWORD = 0;
        var completion_key: usize = 0;
        var overlapped: ?*std.os.windows.OVERLAPPED = null;
        
        const result = std.os.windows.kernel32.GetQueuedCompletionStatus(
            self.iocp,
            &bytes_transferred,
            &completion_key,
            &overlapped,
            timeout_dw,
        );
        
        if (result == 0) {
            return 0;
        }
        
        return 1;
    }
};
```

### 4.2 事件驱动 Server 设计

```zig
//! Event-Driven Server
//! 
//! 使用 Poller 实现高并发非阻塞服务器

pub const EventServer = struct {
    allocator: Allocator,
    config: ServerConfig,
    poller: Poller,
    listener: TcpListener,
    connections: std.AutoHashMap(posix.fd_t, *ConnectionState),
    
    const Self = @This();

    pub const ConnectionState = struct {
        socket: Socket,
        read_buffer: []u8,
        write_buffer: []u8,
        state: enum { reading_request, writing_response, closed },
    };

    pub fn init(allocator: Allocator, config: ServerConfig) !Self {
        return .{
            .allocator = allocator,
            .config = config,
            .poller = try Poller.init(allocator),
            .listener = undefined,
            .connections = std.AutoHashMap(posix.fd_t, *ConnectionState).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.poller.deinit();
        // 清理所有连接
        var it = self.connections.iterator();
        while (it.next()) |entry| {
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.connections.deinit();
    }

    pub fn listen(self: *Self) !void {
        const addr = try std.net.Address.parseIp(self.config.host, self.config.port);
        self.listener = try TcpListener.init(addr);
        
        // 设置 listener 为非阻塞
        // 注册到 poller
        try self.poller.add(self.listener.socket.handle, .{ .readable = true }, 0);
        
        std.debug.print("EventServer listening on {s}:{d}\n", .{
            self.config.host, self.config.port
        });
        
        var events: [256]Event = undefined;
        
        while (true) {
            const n = try self.poller.wait(&events, null);
            
            for (events[0..n]) |event| {
                if (event.data == 0) {
                    // Listener 事件 - 新连接
                    try self.acceptConnection();
                } else {
                    // 客户端连接事件
                    try self.handleConnectionEvent(event);
                }
            }
        }
    }

    fn acceptConnection(self: *Self) !void {
        const conn = try self.listener.accept();
        
        // 设置为非阻塞
        // ... 实现 ...
        
        // 分配连接状态
        const state = try self.allocator.create(ConnectionState);
        state.* = .{
            .socket = conn.socket,
            .read_buffer = try self.allocator.alloc(u8, 8192),
            .write_buffer = try self.allocator.alloc(u8, 8192),
            .state = .reading_request,
        };
        
        try self.connections.put(conn.socket.handle, state);
        try self.poller.add(conn.socket.handle, .{ .readable = true }, @intFromPtr(state));
    }

    fn handleConnectionEvent(self: *Self, event: Event) !void {
        const state: *ConnectionState = @ptrFromInt(event.data);
        
        if (event.events.hangup or event.events.error_) {
            self.closeConnection(state);
            return;
        }
        
        switch (state.state) {
            .reading_request => {
                if (event.events.readable) {
                    try self.handleRead(state);
                }
            },
            .writing_response => {
                if (event.events.writable) {
                    try self.handleWrite(state);
                }
            },
            .closed => {},
        }
    }

    fn handleRead(self: *Self, state: *ConnectionState) !void {
        // 读取请求数据
        // 解析请求
        // 生成响应
        // 切换到写入状态
        _ = self;
        _ = state;
    }

    fn handleWrite(self: *Self, state: *ConnectionState) !void {
        // 写入响应数据
        // 完成后关闭或保持连接
        _ = self;
        _ = state;
    }

    fn closeConnection(self: *Self, state: *ConnectionState) void {
        _ = self.connections.remove(state.socket.handle);
        self.poller.remove(state.socket.handle) catch {};
        state.socket.close();
        self.allocator.free(state.read_buffer);
        self.allocator.free(state.write_buffer);
        self.allocator.destroy(state);
    }
};
```

---

## 五、Phase 3: 高级优化

### 5.1 TLS Session 复用

```zig
pub const TlsSessionPool = struct {
    allocator: Allocator,
    sessions: std.StringHashMap(TlsSessionTicket),
    mutex: Thread.Mutex = .{},
    max_sessions: usize = 1000,
    
    pub const TlsSessionTicket = struct {
        ticket: []u8,
        created_at: i64,
        expires_at: i64,
    };
    
    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .sessions = std.StringHashMap(TlsSessionTicket).init(allocator),
        };
    }
    
    pub fn deinit(self: *Self) void {
        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.ticket);
        }
        self.sessions.deinit();
    }
    
    /// 保存 TLS session ticket
    pub fn saveSession(self: *Self, host: []const u8, ticket: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        const now = std.time.milliTimestamp();
        const key = try self.allocator.dupe(u8, host);
        errdefer self.allocator.free(key);
        
        const ticket_copy = try self.allocator.dupe(u8, ticket);
        errdefer self.allocator.free(ticket_copy);
        
        try self.sessions.put(key, .{
            .ticket = ticket_copy,
            .created_at = now,
            .expires_at = now + 3600_000, // 1 hour
        });
    }
    
    /// 恢复 TLS session
    pub fn getSession(self: *Self, host: []const u8) ?[]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        if (self.sessions.get(host)) |entry| {
            const now = std.time.milliTimestamp();
            if (now < entry.expires_at) {
                return entry.ticket;
            }
            // 过期，移除
            _ = self.sessions.remove(host);
        }
        return null;
    }
    
    /// 清理过期 session
    pub fn cleanup(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        const now = std.time.milliTimestamp();
        var to_remove = std.ArrayList([]const u8).init(self.allocator);
        defer to_remove.deinit();
        
        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            if (now >= entry.value_ptr.expires_at) {
                to_remove.append(entry.key_ptr.*) catch continue;
            }
        }
        
        for (to_remove.items) |key| {
            if (self.sessions.fetchRemove(key)) |kv| {
                self.allocator.free(kv.key);
                self.allocator.free(kv.value.ticket);
            }
        }
    }
};
```

### 5.2 Linux io_uring 支持 (可选)

```zig
//! io_uring 支持 (Linux 5.1+)
//!
//! 提供真正的异步 I/O，避免系统调用开销

pub const IoUringPoller = struct {
    ring: std.os.linux.IoUring,
    allocator: Allocator,
    
    const Self = @This();

    pub fn init(allocator: Allocator, entries: u32) !Self {
        return .{
            .allocator = allocator,
            .ring = try std.os.linux.IoUring.init(entries, 0),
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.ring.deinit();
    }
    
    /// 提交异步读取
    pub fn submitRead(self: *Self, fd: posix.fd_t, buffer: []u8, user_data: u64) !void {
        _ = try self.ring.read(fd, buffer, 0, user_data);
    }
    
    /// 提交异步写入
    pub fn submitWrite(self: *Self, fd: posix.fd_t, buffer: []const u8, user_data: u64) !void {
        _ = try self.ring.write(fd, buffer, 0, user_data);
    }
    
    /// 提交异步 accept
    pub fn submitAccept(self: *Self, fd: posix.fd_t, user_data: u64) !void {
        _ = try self.ring.accept(fd, null, null, 0, user_data);
    }
    
    /// 提交所有操作
    pub fn submit(self: *Self) !void {
        _ = try self.ring.submit();
    }
    
    /// 等待完成事件
    pub fn waitCompletion(self: *Self, cqes: []std.os.linux.io_uring_cqe) !usize {
        return self.ring.copy_cqes(cqes, 1);
    }
};
```

### 5.3 Work-Stealing 调度器

```zig
//! Work-Stealing Thread Pool
//!
//! 每个 worker 有自己的本地队列，空闲时从其他 worker 窃取任务

pub const WorkStealingPool = struct {
    allocator: Allocator,
    workers: []Worker,
    global_queue: TaskQueue,
    running: std.atomic.Value(bool),
    
    const Self = @This();

    pub const Worker = struct {
        local_queue: TaskQueue,
        thread: Thread,
        pool: *Self,
        id: usize,
        
        fn run(self: *Worker) void {
            while (self.pool.running.load(.acquire)) {
                // 1. 先从本地队列取任务
                if (self.local_queue.pop()) |task| {
                    task.execute();
                    continue;
                }
                
                // 2. 从全局队列取任务
                if (self.pool.global_queue.pop()) |task| {
                    task.execute();
                    continue;
                }
                
                // 3. 从其他 worker 窃取任务
                if (self.stealFromOthers()) |task| {
                    task.execute();
                    continue;
                }
                
                // 4. 没有任务，短暂休眠
                std.time.sleep(1_000_000); // 1ms
            }
        }
        
        fn stealFromOthers(self: *Worker) ?*Task {
            const num_workers = self.pool.workers.len;
            var victim = (self.id + 1) % num_workers;
            
            for (0..num_workers - 1) |_| {
                if (self.pool.workers[victim].local_queue.steal()) |task| {
                    return task;
                }
                victim = (victim + 1) % num_workers;
            }
            
            return null;
        }
    };

    pub const TaskQueue = struct {
        // 使用 Chase-Lev deque 实现无锁窃取
        // ... 实现略 ...
    };
};
```

---

## 六、实施计划

### 6.1 里程碑

| 阶段 | 内容 | 工期 | 依赖 |
|------|------|------|------|
| **M1** | Server Worker Pool | 2-3 天 | 无 |
| **M2** | 线程安全 ConnectionPool | 1-2 天 | 无 |
| **M3** | Poller 抽象层 (epoll/kqueue) | 3-5 天 | 无 |
| **M4** | Windows IOCP 支持 | 3-5 天 | M3 |
| **M5** | 事件驱动 Server | 3-5 天 | M3 |
| **M6** | TLS Session 复用 | 2-3 天 | M2 |
| **M7** | io_uring 支持 (可选) | 3-5 天 | M3 |

### 6.2 测试计划

| 测试类型 | 内容 |
|----------|------|
| **单元测试** | WorkerPool, ThreadSafe ConnectionPool, Poller |
| **集成测试** | Multi-threaded Server, Concurrent Client |
| **压力测试** | wrk/ab 基准测试，10K+ 并发 |
| **跨平台测试** | Linux (x86_64, aarch64), Windows, macOS |

### 6.3 API 兼容性

所有优化保持向后兼容：

```zig
// 现有 API 继续工作 (单线程模式)
var server = Server.init(allocator);
try server.get("/hello", helloHandler);
try server.listen();

// 新增: 启用多线程模式
var server = Server.init(allocator);
try server.enableThreading(.{ .num_workers = 8 });
try server.get("/hello", helloHandler);
try server.listen();

// 新增: 事件驱动模式 (高并发)
var server = EventServer.init(allocator, .{});
try server.get("/hello", helloHandler);
try server.listen();
```

---

## 七、优先级建议

**推荐实施顺序**:

| 优先级 | 内容 | 理由 |
|--------|------|------|
| ⭐⭐⭐ | Phase 1.1: Server Worker Pool | 最大收益，最小改动 |
| ⭐⭐⭐ | Phase 1.2: 线程安全 ConnectionPool | 必要基础 |
| ⭐⭐ | Phase 2: epoll/kqueue Poller | 高并发基础 |
| ⭐ | Phase 3: IOCP/io_uring/TLS 复用 | 进阶优化 |

**如果时间有限**，只实施 Phase 1 即可获得显著性能提升：
- 从 1 并发 → CPU 核心数并发
- 预计性能提升 4-16x (取决于 CPU 核心数)

---

## 八、附录

### A. 性能基准测试命令

```bash
# 使用 wrk 进行压力测试
wrk -t12 -c400 -d30s http://localhost:8080/

# 使用 ab 进行压力测试
ab -n 100000 -c 100 http://localhost:8080/

# 使用 hey 进行压力测试
hey -n 100000 -c 200 http://localhost:8080/
```

### B. 参考资料

- [Zig std.Thread 文档](https://ziglang.org/documentation/master/std/#std.Thread)
- [Linux epoll(7) man page](https://man7.org/linux/man-pages/man7/epoll.7.html)
- [FreeBSD kqueue(2) man page](https://www.freebsd.org/cgi/man.cgi?query=kqueue)
- [Windows IOCP 文档](https://docs.microsoft.com/en-us/windows/win32/fileio/i-o-completion-ports)
- [io_uring 介绍](https://kernel.dk/io_uring.pdf)

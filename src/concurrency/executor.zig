//! Task Executor for httpx.zig (ZIO-backed).

const std = @import("std");
const Allocator = std.mem.Allocator;
const Thread = std.Thread;
const zio = @import("zio");

pub const ExecutorError = error{
    TaskQueueFull,
    ExecutorNotRunning,
};

/// Task function type.
pub const TaskFn = *const fn (?*anyopaque) void;

/// Task with function and context.
pub const Task = struct {
    func: TaskFn,
    context: ?*anyopaque = null,
    priority: u8 = 0,
};

/// Executor configuration.
pub const ExecutorConfig = struct {
    num_threads: u32 = 0,
    task_queue_size: usize = 1024,
    idle_timeout_ms: u64 = 60_000,
};

/// ZIO-backed executor.
pub const Executor = struct {
    allocator: Allocator,
    config: ExecutorConfig,
    tasks: std.ArrayListUnmanaged(Task) = .empty,
    runtime: ?*zio.Runtime = null,
    running: bool = false,
    mutex: Thread.Mutex = .{},

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: Allocator, config: ExecutorConfig) Self {
        var cfg = config;
        if (cfg.num_threads == 0) {
            const cpu_count = std.Thread.getCpuCount() catch 4;
            cfg.num_threads = @max(1, @as(u32, @intCast(cpu_count)));
        }
        return .{
            .allocator = allocator,
            .config = cfg,
        };
    }

    pub fn deinit(self: *Self) void {
        self.stop();
        self.tasks.deinit(self.allocator);
    }

    pub fn submit(self: *Self, task: Task) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.running and self.runtime != null) {
            try self.dispatch(task);
            return;
        }

        if (self.tasks.items.len >= self.config.task_queue_size) {
            return ExecutorError.TaskQueueFull;
        }

        try self.tasks.append(self.allocator, task);
    }

    pub fn execute(self: *Self, func: TaskFn, context: ?*anyopaque) !void {
        try self.submit(.{ .func = func, .context = context });
    }

    pub fn start(self: *Self) !void {
        if (self.running) return;

        const executors: u6 = @intCast(@min(@as(u32, 63), @max(@as(u32, 1), self.config.num_threads)));
        self.runtime = try zio.Runtime.init(self.allocator, .{ .executors = .exact(executors) });
        self.running = true;

        // Drain queued tasks now that runtime is available.
        while (self.tasks.items.len > 0) {
            const idx = self.tasks.items.len - 1;
            const task = self.tasks.items[idx];
            self.tasks.items.len = idx;
            try self.dispatch(task);
        }
    }

    pub fn stop(self: *Self) void {
        if (!self.running) return;
        self.running = false;

        if (self.runtime) |rt| {
            rt.deinit();
            self.runtime = null;
        }
    }

    pub fn pendingCount(self: *const Self) usize {
        return self.tasks.items.len;
    }

    pub fn runAll(self: *Self) void {
        while (true) {
            self.mutex.lock();
            if (self.tasks.items.len == 0) {
                self.mutex.unlock();
                break;
            }
            const idx = self.tasks.items.len - 1;
            const task = self.tasks.items[idx];
            self.tasks.items.len = idx;
            self.mutex.unlock();

            task.func(task.context);
        }
    }

    fn dispatch(self: *Self, task: Task) !void {
        const rt = self.runtime orelse return ExecutorError.ExecutorNotRunning;
        var handle = try rt.spawnBlocking(runTask, .{ task.func, task.context });
        handle.join();
    }

    fn runTask(func: TaskFn, context: ?*anyopaque) void {
        func(context);
    }
};

/// Future representing a pending result.
pub fn Future(comptime T: type) type {
    return struct {
        result: ?T = null,
        error_val: ?anyerror = null,
        completed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        mutex: Thread.Mutex = .{},
        cond: Thread.Condition = .{},

        const Self = @This();

        pub fn wait(self: *Self) !T {
            self.mutex.lock();
            defer self.mutex.unlock();

            while (!self.completed.load(.acquire)) {
                self.cond.wait(&self.mutex);
            }

            if (self.error_val) |err| {
                return err;
            }
            return self.result.?;
        }

        pub fn waitTimeout(self: *Self, timeout_ns: u64) !?T {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (!self.completed.load(.acquire)) {
                self.cond.timedWait(&self.mutex, timeout_ns) catch {};
            }

            if (!self.completed.load(.acquire)) {
                return null;
            }

            if (self.error_val) |err| {
                return err;
            }
            return self.result.?;
        }

        pub fn get(self: *Self) ?T {
            if (self.completed.load(.acquire) and self.error_val == null) {
                return self.result;
            }
            return null;
        }

        pub fn isDone(self: *const Self) bool {
            return self.completed.load(.acquire);
        }

        pub fn complete(self: *Self, value: T) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            self.result = value;
            self.completed.store(true, .release);
            self.cond.broadcast();
        }

        pub fn completeWithError(self: *Self, err: anyerror) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            self.error_val = err;
            self.completed.store(true, .release);
            self.cond.broadcast();
        }
    };
}

test "Executor initialization" {
    const allocator = std.testing.allocator;
    var exec = Executor.init(allocator);
    defer exec.deinit();

    try std.testing.expect(exec.config.num_threads > 0);
}

test "Executor task submission" {
    const allocator = std.testing.allocator;
    var exec = Executor.init(allocator);
    defer exec.deinit();

    var counter: u32 = 0;
    const Counter = struct {
        fn increment(ctx: ?*anyopaque) void {
            const c: *u32 = @ptrCast(@alignCast(ctx.?));
            c.* += 1;
        }
    };

    try exec.execute(Counter.increment, &counter);
    exec.runAll();

    try std.testing.expectEqual(@as(u32, 1), counter);
}

test "Future" {
    var future = Future(i32){};

    try std.testing.expect(!future.isDone());
    try std.testing.expect(future.get() == null);

    future.complete(42);

    try std.testing.expect(future.isDone());
    try std.testing.expectEqual(@as(i32, 42), future.get().?);
}

test "Future wait with thread" {
    var future = Future(i32){};

    const worker = try Thread.spawn(.{}, struct {
        fn run(f: *Future(i32)) void {
            Thread.sleep(10 * std.time.ns_per_ms);
            f.complete(123);
        }
    }.run, .{&future});

    const result = try future.wait();
    try std.testing.expectEqual(@as(i32, 123), result);

    worker.join();
}

test "Future waitTimeout" {
    var future = Future(i32){};

    const result = try future.waitTimeout(10 * std.time.ns_per_ms);
    try std.testing.expect(result == null);

    future.complete(456);
    const result2 = try future.waitTimeout(10 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(i32, 456), result2.?);
}

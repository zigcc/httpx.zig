# Installation

To use `httpx.zig` in your project, you need to add it as a dependency in your `build.zig.zon` file.

## 1. Add Dependency

Run the following command in your terminal to fetch the library:

```bash
zig fetch --save "https://github.com/muhammad-fiaz/httpx.zig/archive/refs/heads/main.tar.gz"
```

Or manually add it to your `build.zig.zon`:

```zig
.{
    .name = "my-project",
    .version = "0.0.1",
    .dependencies = .{
        .httpx = .{
            .url = "https://github.com/muhammad-fiaz/httpx.zig/archive/refs/heads/main.tar.gz",
            // .hash = "...", // Zig will suggest the hash
        },
    },
    .paths = .{
        "",
    },
}
```

## 2. Configure `build.zig`

Add the module to your `build.zig` file to expose it to your executable or library:

```zig
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // 1. Get the dependency
    const httpx_dep = b.dependency("httpx", .{
        .target = target,
        .optimize = optimize,
    });

    // 2. Get the module
    const httpx_mod = httpx_dep.module("httpx");

    // 3. Add to your executable
    const exe = b.addExecutable(.{
        .name = "my-app",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe.root_module.addImport("httpx", httpx_mod);

    b.installArtifact(exe);
}
```

## 3. Import in your code

You can now import the library in your Zig code:

```zig
const std = @import("std");
const httpx = @import("httpx");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Use the client
    var client = httpx.Client.init(allocator);
    defer client.deinit();
    
    // ...
}
```

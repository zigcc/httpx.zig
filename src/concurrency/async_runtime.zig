//! ZIO async runtime integration for httpx.zig.

const std = @import("std");

/// httpx.zig now uses ZIO as the async backend.
pub const Backend = enum {
    zio,
};

/// Compile-time selected backend.
pub const selected_backend: Backend = .zio;

/// Always true in the ZIO-only runtime model.
pub const zio_enabled = true;

/// Re-export ZIO module.
pub const zio = @import("zio");

pub fn backendName() []const u8 {
    return "zio";
}

test "backend is always zio" {
    try std.testing.expectEqual(Backend.zio, selected_backend);
    try std.testing.expect(zio_enabled);
    try std.testing.expectEqualStrings("zio", backendName());
}

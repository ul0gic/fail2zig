//! Native TOML config loader skeleton. Real implementation arrives in Phase 3.
//! This stub exists so the module graph compiles.

const std = @import("std");

pub const Error = error{
    NotImplemented,
    FileNotFound,
    InvalidConfig,
};

pub const Config = struct {
    memory_ceiling_mb: u32 = 64,

    pub fn load(allocator: std.mem.Allocator, path: []const u8) Error!Config {
        _ = allocator;
        _ = path;
        return error.NotImplemented;
    }
};

test "config: load returns NotImplemented" {
    try std.testing.expectError(
        error.NotImplemented,
        Config.load(std.testing.allocator, "/nonexistent/config.toml"),
    );
}

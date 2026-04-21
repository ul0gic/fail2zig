//! Log watcher skeleton. Real implementation arrives in Phase 2 (inotify +
//! rotation handling). This stub exists so the module graph compiles.

const std = @import("std");

pub const Error = error{NotImplemented};

pub const LogWatcher = struct {
    allocator: std.mem.Allocator,
    paths: []const []const u8,

    pub fn init(
        allocator: std.mem.Allocator,
        paths: []const []const u8,
    ) !LogWatcher {
        return .{ .allocator = allocator, .paths = paths };
    }

    pub fn deinit(self: *LogWatcher) void {
        _ = self;
    }

    pub fn watch(self: *LogWatcher) Error!void {
        _ = self;
        return error.NotImplemented;
    }
};

test "log_watcher: instantiates and watch returns NotImplemented" {
    const paths: []const []const u8 = &.{};
    var watcher = try LogWatcher.init(std.testing.allocator, paths);
    defer watcher.deinit();
    try std.testing.expectError(error.NotImplemented, watcher.watch());
}

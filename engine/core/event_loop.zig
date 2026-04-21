//! Event loop skeleton. Real implementation arrives in Phase 2 (epoll +
//! signalfd + timerfd). This stub exists so the module graph compiles.

const std = @import("std");

pub const Error = error{NotImplemented};

pub const EventLoop = struct {
    allocator: std.mem.Allocator,
    running: bool = false,

    pub fn init(allocator: std.mem.Allocator) !EventLoop {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *EventLoop) void {
        self.running = false;
    }

    pub fn run(self: *EventLoop) Error!void {
        _ = self;
        return error.NotImplemented;
    }

    pub fn stop(self: *EventLoop) void {
        self.running = false;
    }
};

test "event_loop: instantiates and run returns NotImplemented" {
    var loop = try EventLoop.init(std.testing.allocator);
    defer loop.deinit();
    try std.testing.expectError(error.NotImplemented, loop.run());
    loop.stop();
}

//! State tracker skeleton. Real implementation arrives in Phase 4 (fixed-size
//! hash map, findtime windows, eviction, ban-time increment, ignore lists).
//! This stub exists so the module graph compiles.

const std = @import("std");
const shared = @import("shared");

pub const Error = error{NotImplemented};

pub const Config = struct {
    max_entries: u32 = 10_000,
    findtime_seconds: u32 = 600,
    maxretry: u32 = 5,
};

pub const StateTracker = struct {
    allocator: std.mem.Allocator,
    config: Config,

    pub fn init(allocator: std.mem.Allocator, config: Config) StateTracker {
        return .{ .allocator = allocator, .config = config };
    }

    pub fn deinit(self: *StateTracker) void {
        _ = self;
    }

    pub fn recordAttempt(
        self: *StateTracker,
        ip: shared.IpAddress,
        jail: shared.JailId,
    ) Error!void {
        _ = self;
        _ = ip;
        _ = jail;
        return error.NotImplemented;
    }

    pub fn checkThreshold(
        self: *const StateTracker,
        ip: shared.IpAddress,
        jail: shared.JailId,
    ) Error!bool {
        _ = self;
        _ = ip;
        _ = jail;
        return error.NotImplemented;
    }
};

test "state: instantiates and recordAttempt returns NotImplemented" {
    var tracker = StateTracker.init(std.testing.allocator, .{});
    defer tracker.deinit();
    const ip = try shared.IpAddress.parse("127.0.0.1");
    const jail = try shared.JailId.fromSlice("sshd");
    try std.testing.expectError(error.NotImplemented, tracker.recordAttempt(ip, jail));
    try std.testing.expectError(error.NotImplemented, tracker.checkThreshold(ip, jail));
}

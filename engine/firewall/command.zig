// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const backend = @import("backend.zig");

pub const Result = struct {
    code: u8,
    stdout: []u8,
    stderr: []u8,

    pub fn deinit(self: Result, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
    }
};

pub fn run(allocator: std.mem.Allocator, argv: []const []const u8, timeout_ms: u64) backend.BackendError!Result {
    var child = std.process.Child.init(argv, allocator);
    child.stdin_behavior = .Close;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    child.spawn() catch |err| return if (err == error.AccessDenied) error.PermissionDenied else error.SystemError;
    var reaped = false;
    defer {
        if (!reaped) {
            std.posix.kill(child.id, std.posix.SIG.KILL) catch {};
            _ = std.posix.waitpid(child.id, 0);
        }
        if (child.stdout) |f| f.close();
        if (child.stderr) |f| f.close();
    }
    const files = [_]std.fs.File{ child.stdout.?, child.stderr.? };
    var buffers = [_]std.ArrayList(u8){ std.ArrayList(u8).init(allocator), std.ArrayList(u8).init(allocator) };
    defer for (&buffers) |*b| b.deinit();
    for (files) |file| {
        const flags = std.posix.fcntl(file.handle, std.posix.F.GETFL, 0) catch return error.SystemError;
        _ = std.posix.fcntl(file.handle, std.posix.F.SETFL, flags | @as(u32, @bitCast(std.posix.O{ .NONBLOCK = true }))) catch return error.SystemError;
    }
    var timer = std.time.Timer.start() catch return error.SystemError;
    var status: ?u32 = null;
    var eof = [_]bool{ false, false };
    while (true) {
        for (files, 0..) |file, i| {
            if (eof[i]) continue;
            var chunk: [4096]u8 = undefined;
            const n = std.posix.read(file.handle, &chunk) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => return error.SystemError,
            };
            if (n == 0) eof[i] = true;
            const limit: usize = if (i == 0) 1024 * 1024 else 4096;
            if (buffers[i].items.len + n > limit) return error.SystemError;
            buffers[i].appendSlice(chunk[0..n]) catch return error.OutOfMemory;
        }
        if (!reaped) {
            const result = std.posix.waitpid(child.id, std.posix.W.NOHANG);
            if (result.pid != 0) {
                status = result.status;
                reaped = true;
            }
        }
        if (reaped and eof[0] and eof[1]) break;
        if (timer.read() / std.time.ns_per_ms >= timeout_ms) return error.SystemError;
        var pollers = [_]std.posix.pollfd{
            .{ .fd = if (eof[0]) -1 else files[0].handle, .events = std.posix.POLL.IN, .revents = 0 },
            .{ .fd = if (eof[1]) -1 else files[1].handle, .events = std.posix.POLL.IN, .revents = 0 },
        };
        _ = std.posix.poll(&pollers, 10) catch return error.SystemError;
    }
    const code = if (std.posix.W.IFEXITED(status.?)) std.posix.W.EXITSTATUS(status.?) else return error.SystemError;
    const stdout = buffers[0].toOwnedSlice() catch return error.OutOfMemory;
    errdefer allocator.free(stdout);
    const stderr = buffers[1].toOwnedSlice() catch return error.OutOfMemory;
    return .{ .code = code, .stdout = stdout, .stderr = stderr };
}

test "firewall command: bounded output and nonzero status are captured" {
    const result = try run(std.testing.allocator, &.{ "/bin/sh", "-c", "printf out; printf err >&2; exit 3" }, 1000);
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u8, 3), result.code);
    try std.testing.expectEqualStrings("out", result.stdout);
    try std.testing.expectEqualStrings("err", result.stderr);
}

test "firewall command: a stalled process is killed within the deadline" {
    var timer = try std.time.Timer.start();
    try std.testing.expectError(error.SystemError, run(std.testing.allocator, &.{ "/bin/sleep", "5" }, 30));
    try std.testing.expect(timer.read() < std.time.ns_per_s);
}

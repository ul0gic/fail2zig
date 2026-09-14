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
    return runBounded(allocator, argv, timeout_ms, 1024 * 1024, 4096) catch |err| switch (err) {
        error.Timeout, error.OutputLimit, error.SpawnFailed => error.SystemError,
        else => |e| e,
    };
}

pub const BoundedError = backend.BackendError || error{ Timeout, OutputLimit, SpawnFailed };

pub fn runBounded(allocator: std.mem.Allocator, argv: []const []const u8, timeout_ms: u64, max_stdout: usize, max_stderr: usize) BoundedError!Result {
    if (max_stdout > 1024 * 1024 or max_stderr > 4096) return error.OutputLimit;
    var child = std.process.Child.init(argv, allocator);
    child.stdin_behavior = .Close;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    child.spawn() catch |err| return switch (err) {
        error.AccessDenied => error.PermissionDenied,
        error.OutOfMemory => error.OutOfMemory,
        else => error.SystemError,
    };
    var reaped = false;
    defer {
        if (!reaped) {
            std.posix.kill(child.id, std.posix.SIG.KILL) catch {};
            _ = std.posix.waitpid(child.id, 0);
        }
        if (child.stdout) |f| f.close();
        if (child.stderr) |f| f.close();
        if (child.err_pipe) |fd| std.posix.close(fd);
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
            const limit: usize = if (i == 0) max_stdout else max_stderr;
            if (n > limit - buffers[i].items.len) return error.OutputLimit;
            const needed = buffers[i].items.len + n;
            if (needed > buffers[i].capacity) {
                const capacity = @min(limit, buffers[i].capacity + buffers[i].capacity / 2 + 4096);
                buffers[i].ensureTotalCapacityPrecise(@max(needed, capacity)) catch return error.OutOfMemory;
            }
            buffers[i].appendSliceAssumeCapacity(chunk[0..n]);
        }
        if (!reaped) {
            const result = std.posix.waitpid(child.id, std.posix.W.NOHANG);
            if (result.pid != 0) {
                status = result.status;
                reaped = true;
            }
        }
        if (reaped and eof[0] and eof[1]) break;
        if (timer.read() / std.time.ns_per_ms >= timeout_ms) return error.Timeout;
        var pollers = [_]std.posix.pollfd{
            .{ .fd = if (eof[0]) -1 else files[0].handle, .events = std.posix.POLL.IN, .revents = 0 },
            .{ .fd = if (eof[1]) -1 else files[1].handle, .events = std.posix.POLL.IN, .revents = 0 },
        };
        _ = std.posix.poll(&pollers, 10) catch return error.SystemError;
    }
    // Zig0.14.1 Child reports pre-exec failures as one little-endian u64.
    // Never call its blocking waitForSpawn after our bounded wait: even a
    // retained writer must produce a bounded failure rather than hold us.
    if (child.err_pipe) |fd| try checkSpawnPipe(fd);
    const code = if (std.posix.W.IFEXITED(status.?)) std.posix.W.EXITSTATUS(status.?) else return error.SystemError;
    const stdout = buffers[0].toOwnedSlice() catch return error.OutOfMemory;
    errdefer allocator.free(stdout);
    const stderr = buffers[1].toOwnedSlice() catch return error.OutOfMemory;
    return .{ .code = code, .stdout = stdout, .stderr = stderr };
}

fn checkSpawnPipe(fd: std.posix.fd_t) BoundedError!void {
    const flags = std.posix.fcntl(fd, std.posix.F.GETFL, 0) catch return error.SystemError;
    _ = std.posix.fcntl(fd, std.posix.F.SETFL, flags | @as(u32, @bitCast(std.posix.O{ .NONBLOCK = true }))) catch return error.SystemError;
    var bytes: [9]u8 = undefined;
    const count = std.posix.read(fd, &bytes) catch return error.SpawnFailed;
    if (count == 0) return;
    if (count != 8) return error.SpawnFailed;
    const code = std.mem.readInt(u64, bytes[0..8], .little);
    if (code == @intFromError(error.AccessDenied)) return error.PermissionDenied;
    if (code == @intFromError(error.OutOfMemory)) return error.OutOfMemory;
    return error.SpawnFailed;
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

test "native firewall: command output cap refuses overflow and retains exact boundary" {
    const result = try runBounded(std.testing.allocator, &.{ "/bin/echo", "abc" }, 1000, 4, 0);
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("abc\n", result.stdout);
    try std.testing.expectError(error.OutputLimit, runBounded(std.testing.allocator, &.{ "/bin/echo", "abcd" }, 1000, 4, 0));
}

test "native firewall: bounded command deadline reaps a stalled helper" {
    var timer = try std.time.Timer.start();
    try std.testing.expectError(error.Timeout, runBounded(std.testing.allocator, &.{ "/bin/sleep", "5" }, 30, 16, 16));
    try std.testing.expect(timer.read() < std.time.ns_per_s);
}

fn descriptorCount() !usize {
    var directory = try std.fs.openDirAbsolute("/proc/self/fd", .{ .iterate = true });
    defer directory.close();
    var iterator = directory.iterate();
    var count: usize = 0;
    while (try iterator.next()) |_| count += 1;
    return count;
}
fn allocationCommand(allocator: std.mem.Allocator) !void {
    const result = try runBounded(allocator, &.{ "/bin/echo", "fixture" }, 1000, 16, 16);
    defer result.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), result.code);
}
test "native firewall: command FDs are stable across success spawn fail timeout caps and allocation failures" {
    const before = try descriptorCount();
    for (0..16) |_| {
        const result = try runBounded(std.testing.allocator, &.{"/bin/true"}, 1000, 16, 16);
        result.deinit(std.testing.allocator);
        try std.testing.expectError(error.SpawnFailed, runBounded(std.testing.allocator, &.{"/not/an/executable"}, 1000, 16, 16));
        try std.testing.expectError(error.Timeout, runBounded(std.testing.allocator, &.{ "/bin/sleep", "5" }, 10, 16, 16));
        try std.testing.expectError(error.OutputLimit, runBounded(std.testing.allocator, &.{ "/bin/echo", "overflow" }, 1000, 1, 16));
    }
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCommand, .{});
    try std.testing.expectEqual(before, try descriptorCount());
}
test "native firewall: incomplete spawn error protocol never waits for a retained writer" {
    const pipe = try std.posix.pipe2(.{ .CLOEXEC = true });
    defer for (pipe) |fd| std.posix.close(fd);
    try std.testing.expectError(error.SpawnFailed, checkSpawnPipe(pipe[0]));
    _ = try std.posix.write(pipe[1], &.{1});
    try std.testing.expectError(error.SpawnFailed, checkSpawnPipe(pipe[0]));
}

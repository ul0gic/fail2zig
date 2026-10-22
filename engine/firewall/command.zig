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

pub const max_stdout_bytes: usize = 8 * 1024 * 1024;

pub fn runBounded(allocator: std.mem.Allocator, argv: []const []const u8, timeout_ms: u64, max_stdout: usize, max_stderr: usize) BoundedError!Result {
    return runChild(allocator, argv, null, timeout_ms, max_stdout, max_stderr);
}

pub fn runBoundedInput(allocator: std.mem.Allocator, argv: []const []const u8, input: []const u8, timeout_ms: u64, max_stdout: usize, max_stderr: usize) BoundedError!Result {
    return runChild(allocator, argv, input, timeout_ms, max_stdout, max_stderr);
}

fn runChild(allocator: std.mem.Allocator, argv: []const []const u8, input: ?[]const u8, timeout_ms: u64, max_stdout: usize, max_stderr: usize) BoundedError!Result {
    if (max_stdout > max_stdout_bytes or max_stderr > 4096) return error.OutputLimit;
    var child = std.process.Child.init(argv, allocator);
    child.stdin_behavior = if (input == null) .Close else .Pipe;
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
        if (child.stdin) |f| f.close();
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
    var pending: []const u8 = input orelse &.{};
    if (child.stdin) |stdin| {
        const flags = std.posix.fcntl(stdin.handle, std.posix.F.GETFL, 0) catch return error.SystemError;
        _ = std.posix.fcntl(stdin.handle, std.posix.F.SETFL, flags | @as(u32, @bitCast(std.posix.O{ .NONBLOCK = true }))) catch return error.SystemError;
    }
    var timer = std.time.Timer.start() catch return error.SystemError;
    var status: ?u32 = null;
    var eof = [_]bool{ false, false };
    while (true) {
        if (child.stdin) |stdin| {
            const written = std.posix.write(stdin.handle, pending) catch |err| switch (err) {
                error.WouldBlock => 0,
                error.BrokenPipe => pending.len,
                else => return error.SystemError,
            };
            pending = pending[written..];
            if (pending.len == 0) {
                stdin.close();
                child.stdin = null;
            }
        }
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
            .{ .fd = if (child.stdin) |stdin| stdin.handle else -1, .events = std.posix.POLL.OUT, .revents = 0 },
        };
        _ = std.posix.poll(&pollers, 10) catch return error.SystemError;
    }
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

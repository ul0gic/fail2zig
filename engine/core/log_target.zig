// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

pub const max_line_bytes: usize = 4096;
pub const ring_capacity: usize = 256;
pub const truncation_marker = "...[truncated]\n";

pub const Target = union(enum) {
    stderr,
    file: []const u8,
};

pub const OpenError = error{
    PathNotAbsolute,
    ParentMissing,
    SymlinkRefused,
    NotRegularFile,
    AccessDenied,
    OpenFailed,
};

pub const PushResult = enum { queued, dropped };

pub const Stats = struct {
    queued: usize,
    dropped_total: u64,
    failed_total: u64,
    degraded: bool,
};

pub const Sink = struct {
    allocator: std.mem.Allocator,
    target: Target,
    fd: posix.fd_t,
    owns_fd: bool,
    mutex: std.Thread.Mutex = .{},
    ring: []u8,
    lens: [ring_capacity]u16 = [_]u16{0} ** ring_capacity,
    head: usize = 0,
    count: usize = 0,
    dropped_total: u64 = 0,
    failed_total: u64 = 0,
    degraded: bool = false,
    fallback_noticed: bool = false,

    pub fn init(allocator: std.mem.Allocator, target: Target) (OpenError || std.mem.Allocator.Error)!Sink {
        const ring = try allocator.alloc(u8, ring_capacity * max_line_bytes);
        errdefer allocator.free(ring);
        const fd: posix.fd_t = switch (target) {
            .stderr => posix.STDERR_FILENO,
            .file => |path| try openLogFile(path),
        };
        return .{
            .allocator = allocator,
            .target = target,
            .fd = fd,
            .owns_fd = target == .file,
            .ring = ring,
        };
    }

    pub fn deinit(self: *Sink) void {
        if (self.owns_fd and self.fd != -1) posix.close(self.fd);
        self.allocator.free(self.ring);
        self.* = undefined;
    }

    pub fn reopen(self: *Sink) OpenError!void {
        const path = switch (self.target) {
            .stderr => return,
            .file => |p| p,
        };
        const fresh = try openLogFile(path);
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.owns_fd and self.fd != -1) posix.close(self.fd);
        self.fd = fresh;
        self.owns_fd = true;
    }

    pub fn push(self: *Sink, line: []const u8) PushResult {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.count == ring_capacity) {
            self.dropped_total += 1;
            return .dropped;
        }
        const idx = (self.head + self.count) % ring_capacity;
        const slot = self.ring[idx * max_line_bytes ..][0..max_line_bytes];
        var n = line.len;
        if (n > max_line_bytes) {
            n = max_line_bytes - truncation_marker.len;
            @memcpy(slot[0..n], line[0..n]);
            @memcpy(slot[n .. n + truncation_marker.len], truncation_marker);
            n += truncation_marker.len;
        } else {
            @memcpy(slot[0..n], line);
        }
        self.lens[idx] = @intCast(n);
        self.count += 1;
        return .queued;
    }

    pub fn drain(self: *Sink) void {
        while (true) {
            var line_buf: [max_line_bytes]u8 = undefined;
            const line = self.take(&line_buf) orelse return;
            self.writeLine(line);
        }
    }

    fn take(self: *Sink, out: *[max_line_bytes]u8) ?[]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.count == 0) return null;
        const n: usize = self.lens[self.head];
        @memcpy(out[0..n], self.ring[self.head * max_line_bytes ..][0..n]);
        self.head = (self.head + 1) % ring_capacity;
        self.count -= 1;
        return out[0..n];
    }

    fn writeLine(self: *Sink, line: []const u8) void {
        var written: usize = 0;
        while (written < line.len) {
            const n = posix.write(self.fd, line[written..]) catch |err| {
                self.noteFailure(err);
                return;
            };
            if (n == 0) {
                self.noteFailure(error.ShortWrite);
                return;
            }
            written += n;
        }
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.degraded) {
            self.degraded = false;
            self.fallback_noticed = false;
        }
    }

    fn noteFailure(self: *Sink, err: anyerror) void {
        const notice_due = blk: {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.failed_total += 1;
            self.degraded = true;
            if (self.fallback_noticed) break :blk false;
            self.fallback_noticed = true;
            break :blk true;
        };
        if (!notice_due) return;
        if (self.fd == posix.STDERR_FILENO) return;
        var buf: [256]u8 = undefined;
        const notice = std.fmt.bufPrint(&buf, "fail2zig: log destination unavailable ({s}); lines are being dropped\n", .{@errorName(err)}) catch return;
        _ = posix.write(posix.STDERR_FILENO, notice) catch {};
    }

    pub fn stats(self: *Sink) Stats {
        self.mutex.lock();
        defer self.mutex.unlock();
        return .{
            .queued = self.count,
            .dropped_total = self.dropped_total,
            .failed_total = self.failed_total,
            .degraded = self.degraded,
        };
    }
};

var installed: std.atomic.Value(?*Sink) = std.atomic.Value(?*Sink).init(null);

pub fn install(sink: ?*Sink) void {
    installed.store(sink, .release);
}

pub fn logFn(
    comptime level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    const sink = installed.load(.acquire) orelse {
        std.log.defaultLog(level, scope, format, args);
        return;
    };
    const prefix = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
    var buf: [max_line_bytes]u8 = undefined;
    const line = formatLine(&buf, level.asText() ++ prefix ++ format ++ "\n", args);
    _ = sink.push(line);
}

fn formatLine(buf: *[max_line_bytes]u8, comptime format: []const u8, args: anytype) []const u8 {
    var stream = std.io.fixedBufferStream(buf);
    stream.writer().print(format, args) catch {
        const keep = max_line_bytes - truncation_marker.len;
        @memcpy(buf[keep..], truncation_marker);
        return buf[0..];
    };
    return stream.getWritten();
}

pub fn openLogFile(path: []const u8) OpenError!posix.fd_t {
    if (!std.fs.path.isAbsolute(path)) return error.PathNotAbsolute;
    const flags: posix.O = .{
        .ACCMODE = .WRONLY,
        .APPEND = true,
        .CREAT = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
        .NONBLOCK = true,
    };
    const fd = posix.openat(posix.AT.FDCWD, path, flags, 0o640) catch |err| return switch (err) {
        error.FileNotFound => error.ParentMissing,
        error.NotDir => error.ParentMissing,
        error.SymLinkLoop => error.SymlinkRefused,
        error.AccessDenied => error.AccessDenied,
        error.NoDevice => error.NotRegularFile,
        else => error.OpenFailed,
    };
    errdefer posix.close(fd);
    const st = posix.fstat(fd) catch return error.OpenFailed;
    if (!posix.S.ISREG(st.mode)) return error.NotRegularFile;
    return fd;
}

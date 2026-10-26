// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const LogFormat = @import("../config/native.zig").LogFormat;
const logger = @import("logger.zig");

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
    format: LogFormat,
    fd: posix.fd_t,
    owns_fd: bool,
    // Lock descriptor writes before queue/stat updates; producers take only mutex.
    write_mutex: std.Thread.Mutex = .{},
    mutex: std.Thread.Mutex = .{},
    ring: []u8,
    lens: [ring_capacity]u16 = [_]u16{0} ** ring_capacity,
    head: usize = 0,
    count: usize = 0,
    dropped_total: u64 = 0,
    failed_total: u64 = 0,
    degraded: bool = false,
    fallback_noticed: bool = false,

    pub fn init(allocator: std.mem.Allocator, target: Target, format: LogFormat) (OpenError || std.mem.Allocator.Error)!Sink {
        const ring = try allocator.alloc(u8, ring_capacity * max_line_bytes);
        errdefer allocator.free(ring);
        const fd: posix.fd_t = switch (target) {
            .stderr => posix.STDERR_FILENO,
            .file => |path| try openLogFile(path),
        };
        return .{
            .allocator = allocator,
            .target = target,
            .format = format,
            .fd = fd,
            .owns_fd = target == .file,
            .ring = ring,
        };
    }

    pub fn deinit(self: *Sink) void {
        self.write_mutex.lock();
        if (self.owns_fd and self.fd != -1) posix.close(self.fd);
        self.write_mutex.unlock();
        self.allocator.free(self.ring);
        self.* = undefined;
    }

    pub fn reopen(self: *Sink) OpenError!void {
        const path = switch (self.target) {
            .stderr => return,
            .file => |p| p,
        };
        const fresh = try openLogFile(path);
        self.write_mutex.lock();
        defer self.write_mutex.unlock();
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
        self.write_mutex.lock();
        defer self.write_mutex.unlock();
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

    // Called with write_mutex held, including the descriptor check and fallback write.
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
    var buf: [max_line_bytes]u8 = undefined;
    const line = switch (sink.format) {
        .text => formatLine(&buf, level.asText() ++ (if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ") ++ format ++ "\n", args),
        .json => jsonLine(&buf, @tagName(level), @tagName(scope), format, args),
    };
    _ = sink.push(line);
}

fn carriesFields(comptime Args: type) bool {
    const info = @typeInfo(Args);
    if (info != .@"struct" or !info.@"struct".is_tuple or info.@"struct".fields.len != 1) return false;
    const Arg = info.@"struct".fields[0].type;
    return @typeInfo(Arg) == .@"struct" and @hasDecl(Arg, "logFields");
}

const hex = "0123456789abcdef";

const json_close = "\",\"truncated\":true}\n";

const JsonLine = struct {
    buf: *[max_line_bytes]u8,
    len: usize = 0,
    truncated: bool = false,

    const limit = max_line_bytes - json_close.len;

    fn room(self: *const JsonLine) usize {
        return if (self.len >= limit) 0 else limit - self.len;
    }

    fn raw(self: *JsonLine, bytes: []const u8) bool {
        if (self.truncated or bytes.len > self.room()) {
            self.truncated = true;
            return false;
        }
        @memcpy(self.buf[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
        return true;
    }

    fn reserved(self: *JsonLine, bytes: []const u8) void {
        @memcpy(self.buf[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    fn stringBody(self: *JsonLine, s: []const u8) void {
        var i: usize = 0;
        while (i < s.len) {
            var unit: [6]u8 = undefined;
            var unit_len: usize = 1;
            var advance: usize = 1;
            const c = s[i];
            switch (c) {
                '"', '\\' => {
                    unit[0] = '\\';
                    unit[1] = c;
                    unit_len = 2;
                },
                '\n' => {
                    @memcpy(unit[0..2], "\\n");
                    unit_len = 2;
                },
                '\r' => {
                    @memcpy(unit[0..2], "\\r");
                    unit_len = 2;
                },
                '\t' => {
                    @memcpy(unit[0..2], "\\t");
                    unit_len = 2;
                },
                0x00...0x08, 0x0b, 0x0c, 0x0e...0x1f, 0x7f => {
                    unit = .{ '\\', 'u', '0', '0', hex[c >> 4], hex[c & 0x0f] };
                    unit_len = 6;
                },
                0x20...0x21, 0x23...0x5b, 0x5d...0x7e => unit[0] = c,
                0x80...0xff => {
                    const width = std.unicode.utf8ByteSequenceLength(c) catch 0;
                    if (width != 0 and i + width <= s.len and std.unicode.utf8ValidateSlice(s[i..][0..width])) {
                        @memcpy(unit[0..width], s[i..][0..width]);
                        unit_len = width;
                        advance = width;
                    } else {
                        @memcpy(unit[0..6], "\\ufffd");
                        unit_len = 6;
                    }
                },
            }
            if (!self.raw(unit[0..unit_len])) return;
            i += advance;
        }
    }

    fn field(self: *JsonLine, f: logger.Field) void {
        var head: [128]u8 = undefined;
        const text = switch (f.value) {
            .string => std.fmt.bufPrint(&head, ",\"{s}\":\"", .{f.key}),
            .int => |value| std.fmt.bufPrint(&head, ",\"{s}\":{d}", .{ f.key, value }),
            .uint => |value| std.fmt.bufPrint(&head, ",\"{s}\":{d}", .{ f.key, value }),
            .boolean => |value| std.fmt.bufPrint(&head, ",\"{s}\":{}", .{ f.key, value }),
            .float => |value| std.fmt.bufPrint(&head, ",\"{s}\":{d}", .{ f.key, value }),
        } catch {
            self.truncated = true;
            return;
        };
        if (!self.raw(text)) return;
        switch (f.value) {
            .string => |value| {
                self.stringBody(value);
                self.reserved("\"");
            },
            else => {},
        }
    }
};

fn jsonLine(buf: *[max_line_bytes]u8, comptime level: []const u8, comptime scope: []const u8, comptime format: []const u8, args: anytype) []const u8 {
    var msg_buf: [max_line_bytes]u8 = undefined;
    var msg_stream = std.io.fixedBufferStream(&msg_buf);
    const msg_cut = if (msg_stream.writer().print(format, args)) false else |_| true;

    var line = JsonLine{ .buf = buf };
    var ts_buf: [32]u8 = undefined;
    _ = line.raw("{\"ts\":\"");
    _ = line.raw(rfc3339Millis(&ts_buf, std.time.milliTimestamp()));
    _ = line.raw("\",\"level\":\"" ++ level ++ "\",\"scope\":\"" ++ scope ++ "\",\"msg\":\"");
    line.stringBody(msg_stream.getWritten());
    line.reserved("\"");
    if (comptime carriesFields(@TypeOf(args))) {
        for (args[0].logFields()) |f| line.field(f);
    }
    if (line.truncated or msg_cut) line.reserved(json_close[1 .. json_close.len - 2]);
    line.reserved("}\n");
    return buf[0..line.len];
}

fn rfc3339Millis(buf: *[32]u8, epoch_ms: i64) []const u8 {
    const ms: u64 = @intCast(@max(epoch_ms, 0));
    const es = std.time.epoch.EpochSeconds{ .secs = ms / 1000 };
    const ymd = es.getEpochDay().calculateYearDay();
    const month_day = ymd.calculateMonthDay();
    const time = es.getDaySeconds();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z", .{
        ymd.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        time.getHoursIntoDay(),
        time.getMinutesIntoHour(),
        time.getSecondsIntoMinute(),
        ms % 1000,
    }) catch buf[0..0];
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

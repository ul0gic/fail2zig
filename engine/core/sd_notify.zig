// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

pub const max_message_bytes: usize = 512;
pub const max_status_bytes: usize = 256;

pub const Result = enum { sent, disabled };

pub const Error = error{
    MessageTooLong,
    SendFailed,
};

pub const InitError = error{
    PathTooLong,
    SocketCreateFailed,
};

const sun_path_len: usize = 108;

pub const Notifier = struct {
    fd: posix.fd_t = -1,
    addr: linux.sockaddr.un = .{ .path = [_]u8{0} ** sun_path_len },
    addr_len: posix.socklen_t = 0,

    pub fn fromEnvironment() InitError!Notifier {
        const path = posix.getenv("NOTIFY_SOCKET") orelse return .{};
        if (path.len == 0) return .{};
        return initWithPath(path);
    }

    pub fn initWithPath(path: []const u8) InitError!Notifier {
        if (path.len == 0 or path.len >= sun_path_len) return error.PathTooLong;
        var self: Notifier = .{};
        @memcpy(self.addr.path[0..path.len], path);
        if (path[0] == '@') self.addr.path[0] = 0;
        self.addr_len = @intCast(@offsetOf(linux.sockaddr.un, "path") + path.len + @as(usize, if (path[0] == '@') 0 else 1));
        const stype: u32 = posix.SOCK.DGRAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK;
        self.fd = posix.socket(posix.AF.UNIX, stype, 0) catch return error.SocketCreateFailed;
        return self;
    }

    pub fn enabled(self: *const Notifier) bool {
        return self.fd != -1;
    }

    pub fn deinit(self: *Notifier) void {
        if (self.fd != -1) posix.close(self.fd);
        self.* = .{};
    }

    pub fn ready(self: *const Notifier) Error!Result {
        return self.send("READY=1\n");
    }

    pub fn stopping(self: *const Notifier) Error!Result {
        return self.send("STOPPING=1\n");
    }

    pub fn reloading(self: *const Notifier) Error!Result {
        return self.reloadingAt(monotonicUsec());
    }

    pub fn reloadingAt(self: *const Notifier, monotonic_usec: u64) Error!Result {
        var buf: [64]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "RELOADING=1\nMONOTONIC_USEC={d}\n", .{monotonic_usec}) catch return error.MessageTooLong;
        return self.send(msg);
    }

    pub fn status(self: *const Notifier, text: []const u8) Error!Result {
        if (text.len > max_status_bytes) return error.MessageTooLong;
        if (std.mem.indexOfScalar(u8, text, '\n') != null) return error.MessageTooLong;
        var buf: [max_message_bytes]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "STATUS={s}\n", .{text}) catch return error.MessageTooLong;
        return self.send(msg);
    }

    pub fn send(self: *const Notifier, message: []const u8) Error!Result {
        if (self.fd == -1) return .disabled;
        if (message.len > max_message_bytes) return error.MessageTooLong;
        const rc = linux.sendto(self.fd, message.ptr, message.len, linux.MSG.NOSIGNAL, @ptrCast(&self.addr), self.addr_len);
        switch (linux.E.init(rc)) {
            .SUCCESS => {
                if (rc != message.len) return error.SendFailed;
                return .sent;
            },
            else => return error.SendFailed,
        }
    }
};

/// Startup phases in the order construction reaches them.
pub const Phase = enum(u8) { admission, schema, migration, maintenance, recovery, readiness };

pub const ProgressTiming = struct {
    extension_usec: u64 = 30 * std.time.us_per_s,
    cadence_usec: u64 = 10 * std.time.us_per_s,
};

/// Extends the systemd start deadline only while startup completes work.
///
/// Progress is a later phase, or a completed-work count above the current phase's
/// high-water mark. A repeated or lower count (a retry, a wait, a component that
/// falls back) and an earlier phase are not progress. Each extension is
/// `extension_usec` minus the age of the progress it reports, so the outstanding
/// deadline is the latest reported progress plus `extension_usec`: a stall times out
/// once that runs out, and the unit's own TimeoutStartSec still applies first.
/// The first report always sends, which gives the first extension before the
/// initial deadline when it is made at the start of construction.
pub const Progress = struct {
    notifier: ?*const Notifier,
    timing: ProgressTiming = .{},
    clock_context: ?*anyopaque = null,
    /// Monotonic microseconds; null means the time is unknown and nothing is sent.
    clock: *const fn (?*anyopaque) ?u64 = monotonicClock,
    mutex: std.Thread.Mutex = .{},
    phase: ?Phase = null,
    high_water: u64 = 0,
    last_sent_usec: ?u64 = null,
    /// When the latest progress not yet reported was observed.
    unsent_usec: ?u64 = null,
    phase_unsent: bool = false,
    status_buf: [max_status_bytes]u8 = undefined,
    status_len: usize = 0,
    finished: bool = false,
    send_failed: bool = false,

    pub fn report(self: *Progress, phase: Phase, label: []const u8, done: u64, total: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.finished or self.notifier == null) return;
        const now = self.clock(self.clock_context) orelse return;
        const advanced = if (self.phase) |current|
            @intFromEnum(phase) > @intFromEnum(current) or (phase == current and done > self.high_water)
        else
            true;
        if (advanced) {
            if (self.phase != phase) self.phase_unsent = true;
            self.phase = phase;
            self.high_water = done;
            self.unsent_usec = now;
            self.formatStatus(label, done, total);
        }
        const observed = self.unsent_usec orelse return;
        const due = self.phase_unsent or self.last_sent_usec == null or now -| self.last_sent_usec.? >= self.timing.cadence_usec;
        if (!due) return;
        const age = now -| observed;
        self.unsent_usec = null;
        self.phase_unsent = false;
        if (age >= self.timing.extension_usec) return;
        self.send(self.timing.extension_usec - age);
        self.last_sent_usec = now;
    }

    /// Stops further extensions; call before READY or a fatal exit.
    pub fn finish(self: *Progress) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.finished = true;
    }

    /// Reports migration work through a hook that carries no systemd dependency.
    pub fn migrationHook(self: *Progress) Hook {
        return .{ .context = self, .report_fn = reportMigration };
    }

    fn reportMigration(context: *anyopaque, done: u64, total: u64) void {
        const self: *Progress = @ptrCast(@alignCast(context));
        self.report(.migration, "migration", done, total);
    }

    // Both buffers fit the longest message: a 64-byte label and two u64 counts.
    fn formatStatus(self: *Progress, label: []const u8, done: u64, total: u64) void {
        const safe = if (std.mem.indexOfScalar(u8, label, '\n') == null and label.len <= 64) label else "startup";
        const text = if (total == 0)
            std.fmt.bufPrint(&self.status_buf, "{s} {d}", .{ safe, done })
        else
            std.fmt.bufPrint(&self.status_buf, "{s} {d}/{d}", .{ safe, done, total });
        self.status_len = (text catch self.status_buf[0..0]).len;
    }

    fn send(self: *Progress, extension_usec: u64) void {
        var buf: [max_message_bytes]u8 = undefined;
        const message = std.fmt.bufPrint(&buf, "EXTEND_TIMEOUT_USEC={d}\nSTATUS={s}\n", .{ extension_usec, self.status_buf[0..self.status_len] }) catch return;
        _ = self.notifier.?.send(message) catch |err| {
            if (!self.send_failed) std.log.warn("sd_notify startup extension failed: {s}", .{@errorName(err)});
            self.send_failed = true;
        };
    }
};

/// Type-erased progress callback for code that must not depend on the notifier.
pub const Hook = struct {
    context: *anyopaque,
    report_fn: *const fn (*anyopaque, u64, u64) void,

    pub fn report(self: Hook, done: u64, total: u64) void {
        self.report_fn(self.context, done, total);
    }
};

fn monotonicClock(_: ?*anyopaque) ?u64 {
    const ts = posix.clock_gettime(.MONOTONIC) catch return null;
    const sec: u64 = @intCast(ts.sec);
    const nsec: u64 = @intCast(ts.nsec);
    return sec * std.time.us_per_s + nsec / std.time.ns_per_us;
}

fn monotonicUsec() u64 {
    const ts = posix.clock_gettime(.MONOTONIC) catch return 0;
    const sec: u64 = @intCast(ts.sec);
    const nsec: u64 = @intCast(ts.nsec);
    return sec * std.time.us_per_s + nsec / std.time.ns_per_us;
}

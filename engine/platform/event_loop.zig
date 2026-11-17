// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const linux = std.os.linux;

pub const Error = error{
    EpollCreateFailed,
    EventfdCreateFailed,
    SignalfdCreateFailed,
    TimerfdCreateFailed,
    EpollCtlFailed,
    TimerfdSetFailed,
    DuplicateFd,
    UnknownFd,
    OutOfMemory,
    SystemResources,
    NotLinux,
};

pub const EventCallback = *const fn (
    fd: posix.fd_t,
    events: u32,
    userdata: ?*anyopaque,
) void;

pub const SignalCallback = *const fn (
    siginfo: *const linux.signalfd_siginfo,
    userdata: ?*anyopaque,
) void;

pub const TimerCallback = *const fn (
    expirations: u64,
    userdata: ?*anyopaque,
) void;

const RegKind = enum { user_fd, signal, timer, wakeup };

const Registration = struct {
    kind: RegKind,
    user_cb: ?EventCallback = null,
    signal_cb: ?SignalCallback = null,
    timer_cb: ?TimerCallback = null,
    userdata: ?*anyopaque = null,
};

pub const TimerHandle = enum(u64) {
    invalid = 0,
    _,
};

pub const EventLoop = struct {
    allocator: Allocator,

    epoll_fd: posix.fd_t,
    wakeup_fd: posix.fd_t,
    registrations: std.AutoHashMap(posix.fd_t, Registration),
    running: std.atomic.Value(bool),
    next_timer_id: u64,

    pub fn init(allocator: Allocator) Error!EventLoop {
        if (builtin.os.tag != .linux) return error.NotLinux;

        const epfd = posix.epoll_create1(linux.EPOLL.CLOEXEC) catch
            return error.EpollCreateFailed;
        errdefer posix.close(epfd);

        const wake_flags = linux.EFD.CLOEXEC | linux.EFD.NONBLOCK;
        const wfd = posix.eventfd(0, wake_flags) catch
            return error.EventfdCreateFailed;
        errdefer posix.close(wfd);

        var map = std.AutoHashMap(posix.fd_t, Registration).init(allocator);
        errdefer map.deinit();

        var loop: EventLoop = .{
            .allocator = allocator,
            .epoll_fd = epfd,
            .wakeup_fd = wfd,
            .registrations = map,
            .running = std.atomic.Value(bool).init(false),
            .next_timer_id = 1,
        };

        var ev: linux.epoll_event = .{
            .events = linux.EPOLL.IN,
            .data = .{ .fd = wfd },
        };
        posix.epoll_ctl(epfd, linux.EPOLL.CTL_ADD, wfd, &ev) catch
            return error.EpollCtlFailed;

        try loop.registrations.put(wfd, .{ .kind = .wakeup });

        return loop;
    }

    pub fn deinit(self: *EventLoop) void {
        var it = self.registrations.iterator();
        while (it.next()) |entry| {
            switch (entry.value_ptr.kind) {
                .signal, .timer => posix.close(entry.key_ptr.*),
                .user_fd, .wakeup => {},
            }
        }

        self.registrations.deinit();
        posix.close(self.wakeup_fd);
        posix.close(self.epoll_fd);
        self.* = undefined;
    }

    pub fn addFd(
        self: *EventLoop,
        fd: posix.fd_t,
        events: u32,
        callback: EventCallback,
        userdata: ?*anyopaque,
    ) Error!void {
        if (self.registrations.contains(fd)) return error.DuplicateFd;

        var ev: linux.epoll_event = .{
            .events = events,
            .data = .{ .fd = fd },
        };
        posix.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_ADD, fd, &ev) catch
            return error.EpollCtlFailed;
        errdefer posix.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_DEL, fd, null) catch {};

        try self.registrations.put(fd, .{
            .kind = .user_fd,
            .user_cb = callback,
            .userdata = userdata,
        });
    }

    pub fn removeFd(self: *EventLoop, fd: posix.fd_t) Error!void {
        const entry = self.registrations.fetchRemove(fd) orelse
            return error.UnknownFd;
        _ = entry;
        posix.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_DEL, fd, null) catch
            return error.EpollCtlFailed;
    }

    pub fn addSignalHandler(
        self: *EventLoop,
        signo: u6,
        callback: SignalCallback,
        userdata: ?*anyopaque,
    ) Error!void {
        var mask = linux.empty_sigset;
        sigaddset(&mask, @as(u32, signo));
        posix.sigprocmask(linux.SIG.BLOCK, &mask, null);

        const sflags: u32 = linux.SFD.CLOEXEC | linux.SFD.NONBLOCK;
        const sfd = posix.signalfd(-1, &mask, sflags) catch
            return error.SignalfdCreateFailed;
        errdefer posix.close(sfd);

        var ev: linux.epoll_event = .{
            .events = linux.EPOLL.IN,
            .data = .{ .fd = sfd },
        };
        posix.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_ADD, sfd, &ev) catch
            return error.EpollCtlFailed;
        errdefer posix.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_DEL, sfd, null) catch {};

        try self.registrations.put(sfd, .{
            .kind = .signal,
            .signal_cb = callback,
            .userdata = userdata,
        });
    }

    pub fn addTimer(
        self: *EventLoop,
        interval_ms: u64,
        callback: TimerCallback,
        userdata: ?*anyopaque,
        one_shot: bool,
    ) Error!TimerHandle {
        const tflags: linux.TFD = .{ .CLOEXEC = true, .NONBLOCK = true };
        const tfd = posix.timerfd_create(.MONOTONIC, tflags) catch
            return error.TimerfdCreateFailed;
        errdefer posix.close(tfd);

        const secs: isize = @intCast(interval_ms / 1000);
        const nsecs: isize = @intCast((interval_ms % 1000) * std.time.ns_per_ms);
        const spec: linux.itimerspec = .{
            .it_value = .{ .sec = secs, .nsec = nsecs },
            .it_interval = if (one_shot)
                .{ .sec = 0, .nsec = 0 }
            else
                .{ .sec = secs, .nsec = nsecs },
        };
        posix.timerfd_settime(tfd, .{ .ABSTIME = false }, &spec, null) catch
            return error.TimerfdSetFailed;

        var ev: linux.epoll_event = .{
            .events = linux.EPOLL.IN,
            .data = .{ .fd = tfd },
        };
        posix.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_ADD, tfd, &ev) catch
            return error.EpollCtlFailed;
        errdefer posix.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_DEL, tfd, null) catch {};

        try self.registrations.put(tfd, .{
            .kind = .timer,
            .timer_cb = callback,
            .userdata = userdata,
        });

        self.next_timer_id += 1;
        const handle: TimerHandle = @enumFromInt(@as(u64, @intCast(tfd)));
        return handle;
    }

    pub fn cancelTimer(self: *EventLoop, handle: TimerHandle) Error!void {
        const raw: u64 = @intFromEnum(handle);
        if (raw == 0) return error.UnknownFd;
        const tfd: posix.fd_t = @intCast(raw);

        const entry = self.registrations.get(tfd) orelse return error.UnknownFd;
        if (entry.kind != .timer) return error.UnknownFd;

        posix.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_DEL, tfd, null) catch
            return error.EpollCtlFailed;
        _ = self.registrations.remove(tfd);
        posix.close(tfd);
    }

    pub fn run(self: *EventLoop) Error!void {
        self.running.store(true, .release);

        var events: [64]linux.epoll_event = undefined;
        while (self.running.load(.acquire)) {
            const n = posix.epoll_wait(self.epoll_fd, &events, -1);
            var i: usize = 0;
            while (i < n) : (i += 1) {
                const ev = events[i];
                const fd = ev.data.fd;
                const entry = self.registrations.get(fd) orelse continue;
                switch (entry.kind) {
                    .wakeup => drainWakeup(fd),
                    .user_fd => if (entry.user_cb) |cb|
                        cb(fd, ev.events, entry.userdata),
                    .signal => if (entry.signal_cb) |cb|
                        dispatchSignal(fd, cb, entry.userdata),
                    .timer => if (entry.timer_cb) |cb|
                        dispatchTimer(fd, cb, entry.userdata),
                }
            }
        }
    }

    pub fn stop(self: *EventLoop) void {
        self.running.store(false, .release);
        const one: u64 = 1;
        const bytes = std.mem.asBytes(&one);
        _ = posix.write(self.wakeup_fd, bytes) catch {};
    }
};

fn drainWakeup(fd: posix.fd_t) void {
    var buf: [8]u8 = undefined;
    _ = posix.read(fd, &buf) catch {};
}

fn dispatchSignal(
    fd: posix.fd_t,
    cb: SignalCallback,
    userdata: ?*anyopaque,
) void {
    while (true) {
        var siginfo: linux.signalfd_siginfo = undefined;
        const buf = std.mem.asBytes(&siginfo);
        const n = posix.read(fd, buf) catch |err| switch (err) {
            error.WouldBlock => return,
            else => return,
        };
        if (n == 0) return;
        if (n != buf.len) return;
        cb(&siginfo, userdata);
    }
}

fn dispatchTimer(
    fd: posix.fd_t,
    cb: TimerCallback,
    userdata: ?*anyopaque,
) void {
    var expirations: u64 = 0;
    const buf = std.mem.asBytes(&expirations);
    const n = posix.read(fd, buf) catch |err| switch (err) {
        error.WouldBlock => return,
        else => return,
    };
    if (n != buf.len) return;
    cb(expirations, userdata);
}

fn sigaddset(set: *linux.sigset_t, signo: u32) void {
    const s = signo - 1;
    const word = s / 32;
    const bit = @as(u32, 1) << @intCast(s & 31);
    set[word] |= bit;
}

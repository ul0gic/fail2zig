//! Epoll-based event loop for the fail2zig daemon.
//!
//! This is the universal fallback (Linux 2.6+). An io_uring backend will
//! be layered on top later; the interface here stays the same.
//!
//! Responsibilities:
//!   - Register arbitrary file descriptors with callbacks (`addFd`).
//!   - Dispatch `EPOLLIN`/`EPOLLHUP`/`EPOLLERR` to callbacks.
//!   - Break out of the wait on `stop()` via an internal wakeup eventfd
//!     plus an atomic `running` flag — safe to call from any thread and
//!     from signal handlers.
//!   - Manage signal handling via signalfd (`addSignalHandler`).
//!   - Manage timers via timerfd (`addTimer` / `cancelTimer`).
//!
//! Every FD the loop owns (epoll, wakeup, signalfd, timerfd) is created
//! with `CLOEXEC`. FDs passed in via `addFd` are NOT owned by the loop —
//! the caller created them and must close them after `removeFd`.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const linux = std.os.linux;

/// Raised for programmer errors we cannot handle (never raised under
/// normal operation; callers should propagate).
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

/// User-supplied callback invoked when a registered FD becomes ready.
/// `events` is the epoll-style mask (`EPOLLIN`, `EPOLLHUP`, `EPOLLERR`,
/// ...). `userdata` is whatever pointer the caller registered — usually
/// `*Self` for the component driving the FD.
pub const EventCallback = *const fn (
    fd: posix.fd_t,
    events: u32,
    userdata: ?*anyopaque,
) void;

/// Callback invoked when a subscribed signal is delivered. `siginfo` is
/// filled from the kernel's `signalfd_siginfo` read and is valid only
/// within the callback — do not store.
pub const SignalCallback = *const fn (
    siginfo: *const linux.signalfd_siginfo,
    userdata: ?*anyopaque,
) void;

/// Callback invoked when a timer fires. `expirations` is the number of
/// times the timer has expired since the last read (normally 1 for
/// healthy loops; > 1 indicates callback overrun). `userdata` is the
/// pointer registered with `addTimer`.
pub const TimerCallback = *const fn (
    expirations: u64,
    userdata: ?*anyopaque,
) void;

const RegKind = enum { user_fd, signal, timer, wakeup };

/// Internal registration entry stored per fd in the map.
const Registration = struct {
    kind: RegKind,
    user_cb: ?EventCallback = null,
    signal_cb: ?SignalCallback = null,
    timer_cb: ?TimerCallback = null,
    userdata: ?*anyopaque = null,
};

/// Opaque handle identifying a timer. Zero is never valid.
pub const TimerHandle = enum(u64) {
    invalid = 0,
    _,
};

pub const EventLoop = struct {
    allocator: Allocator,

    /// epoll instance FD (created with EPOLL_CLOEXEC).
    epoll_fd: posix.fd_t,
    /// Internal eventfd used to break out of `epoll_wait` on `stop()`.
    wakeup_fd: posix.fd_t,
    /// Fast lookup from FD to registration.
    registrations: std.AutoHashMap(posix.fd_t, Registration),
    /// When false, the next `epoll_wait` return causes `run()` to exit.
    running: std.atomic.Value(bool),
    /// Monotonic counter for generating opaque TimerHandle values.
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

        // Register the wakeup FD at the epoll level so `stop()` will
        // actually break us out of `epoll_wait`.
        var ev: linux.epoll_event = .{
            .events = linux.EPOLL.IN,
            .data = .{ .fd = wfd },
        };
        posix.epoll_ctl(epfd, linux.EPOLL.CTL_ADD, wfd, &ev) catch
            return error.EpollCtlFailed;

        try loop.registrations.put(wfd, .{ .kind = .wakeup });

        return loop;
    }

    /// Release all loop-owned resources. Closes epoll and wakeup FDs plus
    /// any signalfd/timerfd the loop owns. User-supplied FDs registered
    /// via `addFd` are NOT closed — the caller owns them.
    pub fn deinit(self: *EventLoop) void {
        // Close any signalfd / timerfd the loop owns. User FDs are left
        // alone per the contract.
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

    /// Register `fd` for epoll with `events` (e.g. `EPOLLIN`). The
    /// callback is invoked when any subset of the requested events
    /// fires; it is also invoked on `EPOLLHUP` / `EPOLLERR` which the
    /// loop always delivers (kernel always reports them, even when not
    /// requested).
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

    /// Remove a previously registered FD. Does NOT close it — the caller
    /// owns user FDs.
    pub fn removeFd(self: *EventLoop, fd: posix.fd_t) Error!void {
        const entry = self.registrations.fetchRemove(fd) orelse
            return error.UnknownFd;
        _ = entry;
        posix.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_DEL, fd, null) catch
            return error.EpollCtlFailed;
    }

    /// Subscribe to a signal. The loop creates a signalfd for `signo`
    /// (blocking the signal for the calling thread so the kernel delivers
    /// it via the FD rather than a handler) and registers it with epoll.
    ///
    /// For correct behavior in multi-threaded programs, the caller should
    /// block `signo` in all threads before any thread calls this — the
    /// usual pattern is to block the signals in the main thread before
    /// spawning any workers.
    pub fn addSignalHandler(
        self: *EventLoop,
        signo: u6,
        callback: SignalCallback,
        userdata: ?*anyopaque,
    ) Error!void {
        var mask = linux.empty_sigset;
        sigaddset(&mask, @as(u32, signo));
        // Block the signal on this thread so it is delivered via the fd.
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

    /// Register a timer. `interval_ms` is the first-fire delay (for
    /// `.one_shot`) or the recurring interval (for `.periodic`). Returns
    /// a `TimerHandle` the caller uses to cancel later.
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

        // The TimerHandle is simply the fd cast to the handle enum — this
        // keeps cancellation O(1) without a second map. We pack it along
        // with a generation bit to prevent ABA issues in higher layers
        // later; for now the fd is sufficient.
        self.next_timer_id += 1;
        const handle: TimerHandle = @enumFromInt(@as(u64, @intCast(tfd)));
        return handle;
    }

    /// Cancel a timer previously created with `addTimer`. Closes the
    /// underlying timerfd. Calling with an invalid handle is an error
    /// but does not corrupt loop state.
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

    /// Enter the event loop. Returns when `stop()` is called or on a
    /// non-recoverable error.
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

    /// Request the loop to exit at the next iteration. Safe to call from
    /// any thread (writes an atomic flag and pokes the wakeup eventfd).
    pub fn stop(self: *EventLoop) void {
        self.running.store(false, .release);
        // Best-effort poke of the eventfd. If the write fails we still
        // exit on the next natural wakeup; no need to propagate.
        const one: u64 = 1;
        const bytes = std.mem.asBytes(&one);
        _ = posix.write(self.wakeup_fd, bytes) catch {};
    }
};

// ============================================================================
// Helpers (file-private)
// ============================================================================

/// Drain the wakeup eventfd's counter so `epoll_wait` goes back to
/// blocking instead of spinning.
fn drainWakeup(fd: posix.fd_t) void {
    var buf: [8]u8 = undefined;
    _ = posix.read(fd, &buf) catch {};
}

/// Drain a signalfd: read any number of `signalfd_siginfo` records and
/// dispatch each to the callback. On EAGAIN we stop.
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

/// Drain a timerfd: read the expiration count and invoke the callback.
/// On EAGAIN (spurious wakeup) we stop.
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

/// Add a signal to a sigset. `std.os.linux` exposes `sigaddset` only as a
/// helper on libc platforms in some builds; we implement it directly on
/// the raw `sigset_t` layout used by the kernel — a flat bit array.
fn sigaddset(set: *linux.sigset_t, signo: u32) void {
    // sigset_t is [1024/32]u32 on Linux; bit N lives in word N/32 at
    // bit N&31. Signal numbers are 1-based so subtract 1.
    const s = signo - 1;
    const word = s / 32;
    const bit = @as(u32, 1) << @intCast(s & 31);
    set[word] |= bit;
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "event_loop: init and deinit cleanly" {
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();
    // Map contains just the internal wakeup registration.
    try testing.expectEqual(@as(usize, 1), loop.registrations.count());
}

// Shared state for callback-driven tests. Each test uses its own instance.
const FdCounter = struct {
    count: u32 = 0,
    last_events: u32 = 0,
    last_fd: posix.fd_t = -1,

    fn onEvent(fd: posix.fd_t, events: u32, ud: ?*anyopaque) void {
        const self: *FdCounter = @ptrCast(@alignCast(ud.?));
        self.count += 1;
        self.last_events = events;
        self.last_fd = fd;
        // Drain the eventfd so epoll returns to sleeping.
        var buf: [8]u8 = undefined;
        _ = posix.read(fd, &buf) catch {};
    }
};

test "event_loop: addFd dispatches on eventfd ready" {
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();

    const efd = try posix.eventfd(0, linux.EFD.CLOEXEC | linux.EFD.NONBLOCK);
    defer posix.close(efd);

    var counter = FdCounter{};
    try loop.addFd(efd, linux.EPOLL.IN, FdCounter.onEvent, &counter);

    // Arm the eventfd: writing increments its counter, making it
    // readable for epoll.
    const one: u64 = 1;
    _ = try posix.write(efd, std.mem.asBytes(&one));

    // Spawn a thread that stops the loop once the callback has fired.
    const Waiter = struct {
        fn run(l: *EventLoop, c: *FdCounter) void {
            // Poll for the callback to fire. Bounded by 1s so a busted
            // test never hangs CI.
            var tries: u32 = 0;
            while (tries < 100) : (tries += 1) {
                if (c.count > 0) break;
                std.time.sleep(10 * std.time.ns_per_ms);
            }
            l.stop();
        }
    };
    const th = try std.Thread.spawn(.{}, Waiter.run, .{ &loop, &counter });
    try loop.run();
    th.join();

    try testing.expect(counter.count >= 1);
    try testing.expectEqual(efd, counter.last_fd);
    try testing.expect((counter.last_events & linux.EPOLL.IN) != 0);

    try loop.removeFd(efd);
    try testing.expect(!loop.registrations.contains(efd));
}

test "event_loop: addFd rejects duplicate registration" {
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();

    const efd = try posix.eventfd(0, linux.EFD.CLOEXEC | linux.EFD.NONBLOCK);
    defer posix.close(efd);

    var counter = FdCounter{};
    try loop.addFd(efd, linux.EPOLL.IN, FdCounter.onEvent, &counter);
    defer loop.removeFd(efd) catch {};

    try testing.expectError(error.DuplicateFd, loop.addFd(
        efd,
        linux.EPOLL.IN,
        FdCounter.onEvent,
        &counter,
    ));
}

test "event_loop: removeFd errors on unknown fd" {
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();

    try testing.expectError(error.UnknownFd, loop.removeFd(9999));
}

test "event_loop: stop() breaks run() immediately" {
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();

    const th = try std.Thread.spawn(.{}, struct {
        fn kick(l: *EventLoop) void {
            // Give the main thread a moment to enter the loop.
            std.time.sleep(20 * std.time.ns_per_ms);
            l.stop();
        }
    }.kick, .{&loop});

    try loop.run();
    th.join();
    try testing.expectEqual(false, loop.running.load(.acquire));
}

// ---------- Signal handler tests ----------

const SignalCounter = struct {
    count: u32 = 0,
    last_signo: u32 = 0,

    fn onSignal(si: *const linux.signalfd_siginfo, ud: ?*anyopaque) void {
        const self: *SignalCounter = @ptrCast(@alignCast(ud.?));
        self.count += 1;
        self.last_signo = si.signo;
    }
};

test "event_loop: signalfd delivers SIGUSR1 via addSignalHandler" {
    // Must run on Linux and must be able to block SIGUSR1 — usually OK in
    // test environments but we skip on the off-chance signalfd is
    // sandboxed away.
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();

    var counter = SignalCounter{};
    loop.addSignalHandler(linux.SIG.USR1, SignalCounter.onSignal, &counter) catch |err| {
        std.log.warn("skipping signalfd test: {s}", .{@errorName(err)});
        return error.SkipZigTest;
    };

    const th = try std.Thread.spawn(.{}, struct {
        fn kick(l: *EventLoop, c: *SignalCounter) void {
            // Brief pause so the main thread is inside epoll_wait before
            // we send the signal. We use kill(getpid(), …) rather than
            // raise() because raise() delivers to the calling thread only
            // (pthread_kill semantics), and signalfd on the main thread
            // only reads signals directed at the process or the main
            // thread — not at the kicking thread.
            std.time.sleep(20 * std.time.ns_per_ms);
            std.posix.kill(std.os.linux.getpid(), linux.SIG.USR1) catch {};
            var tries: u32 = 0;
            while (tries < 100 and c.count == 0) : (tries += 1) {
                std.time.sleep(10 * std.time.ns_per_ms);
            }
            l.stop();
        }
    }.kick, .{ &loop, &counter });

    try loop.run();
    th.join();

    try testing.expect(counter.count >= 1);
    try testing.expectEqual(@as(u32, linux.SIG.USR1), counter.last_signo);
}

// ---------- Timer tests ----------

const TimerCounter = struct {
    count: u32 = 0,
    total_expirations: u64 = 0,

    fn onTimer(expirations: u64, ud: ?*anyopaque) void {
        const self: *TimerCounter = @ptrCast(@alignCast(ud.?));
        self.count += 1;
        self.total_expirations += expirations;
    }
};

test "event_loop: one-shot timer fires exactly once" {
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();

    var tc = TimerCounter{};
    const handle = loop.addTimer(50, TimerCounter.onTimer, &tc, true) catch |err| {
        std.log.warn("skipping timerfd test: {s}", .{@errorName(err)});
        return error.SkipZigTest;
    };
    _ = handle;

    const th = try std.Thread.spawn(.{}, struct {
        fn kick(l: *EventLoop, t: *TimerCounter) void {
            // Let the one-shot timer fire, then give it extra headroom
            // to prove it does NOT fire twice.
            var tries: u32 = 0;
            while (tries < 50 and t.count == 0) : (tries += 1) {
                std.time.sleep(5 * std.time.ns_per_ms);
            }
            std.time.sleep(150 * std.time.ns_per_ms);
            l.stop();
        }
    }.kick, .{ &loop, &tc });

    try loop.run();
    th.join();

    try testing.expectEqual(@as(u32, 1), tc.count);
    try testing.expectEqual(@as(u64, 1), tc.total_expirations);
}

test "event_loop: periodic timer fires multiple times, cancel stops it" {
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();

    var tc = TimerCounter{};
    const handle = loop.addTimer(20, TimerCounter.onTimer, &tc, false) catch |err| {
        std.log.warn("skipping timerfd test: {s}", .{@errorName(err)});
        return error.SkipZigTest;
    };

    const Ctx = struct {
        loop: *EventLoop,
        tc: *TimerCounter,
        handle: TimerHandle,
    };
    var ctx = Ctx{ .loop = &loop, .tc = &tc, .handle = handle };

    const th = try std.Thread.spawn(.{}, struct {
        fn kick(c: *Ctx) void {
            // Wait for at least 3 fires.
            var tries: u32 = 0;
            while (tries < 200 and c.tc.count < 3) : (tries += 1) {
                std.time.sleep(5 * std.time.ns_per_ms);
            }
            // Cancel and record the count, then wait extra time to prove
            // cancellation actually stops future fires.
            c.loop.cancelTimer(c.handle) catch {};
            const locked = c.tc.count;
            std.time.sleep(100 * std.time.ns_per_ms);
            // The count must not have grown after cancellation.
            std.debug.assert(c.tc.count == locked);
            c.loop.stop();
        }
    }.kick, .{&ctx});

    try loop.run();
    th.join();

    try testing.expect(tc.count >= 3);
}

test "event_loop: cancelTimer rejects invalid handle" {
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();

    try testing.expectError(error.UnknownFd, loop.cancelTimer(.invalid));
    try testing.expectError(
        error.UnknownFd,
        loop.cancelTimer(@enumFromInt(9999)),
    );
}

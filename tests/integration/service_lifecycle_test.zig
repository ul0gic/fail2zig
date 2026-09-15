// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

//! Foreground lifecycle of the one executable under a service manager contract: READY only
//! after admission, RELOADING/READY around SIGHUP, STOPPING on TERM/INT, SIGUSR1 log reopen,
//! and typed startup refusals. A datagram receiver in the temp dir stands in for systemd.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;
const harness = @import("harness.zig");

const t = std.testing;
const exe = "zig-out/bin/fail2zig";
const startup_timeout_ns: u64 = 10 * std.time.ns_per_s;

const Paths = struct {
    state_dir: []u8,
    state_file: []u8,
    log_target: []u8,
    notify: []u8,

    fn init(a: std.mem.Allocator, h: *const harness.Harness) !Paths {
        const state_dir = try std.fmt.allocPrint(a, "{s}/state", .{h.tmp_abs});
        errdefer a.free(state_dir);
        const state_file = try std.fmt.allocPrint(a, "{s}/state.bin", .{state_dir});
        errdefer a.free(state_file);
        const log_target = try std.fmt.allocPrint(a, "{s}/daemon.log", .{h.tmp_abs});
        errdefer a.free(log_target);
        const notify = try std.fmt.allocPrint(a, "{s}/notify", .{h.tmp_abs});
        errdefer a.free(notify);
        if (notify.len >= 108) return error.SkipZigTest;
        try std.fs.cwd().makePath(state_dir);
        return .{ .state_dir = state_dir, .state_file = state_file, .log_target = log_target, .notify = notify };
    }

    fn deinit(self: *Paths, a: std.mem.Allocator) void {
        posix.fchmodat(posix.AT.FDCWD, self.state_dir, 0o750, 0) catch {};
        a.free(self.state_dir);
        a.free(self.state_file);
        a.free(self.log_target);
        a.free(self.notify);
    }
};

const ConfigOptions = struct {
    bantime: u32 = 60,
    log_target: ?[]const u8 = null,
    state_file: ?[]const u8 = null,
    extra: []const u8 = "",
    journal: bool = false,
};

fn writeConfig(h: *harness.Harness, p: *const Paths, opts: ConfigOptions) !void {
    var file = try std.fs.cwd().createFile(h.config_path, .{ .mode = 0o600 });
    defer file.close();
    const w = file.writer();
    try w.print(
        \\[global]
        \\native_ingestion = true
        \\log_level = "info"
        \\log_target = "{s}"
        \\state_file = "{s}"
        \\socket_path = "{s}"
        \\metrics_enabled = false
        \\{s}
        \\[defaults]
        \\banaction = "log-only"
        \\maxretry = 3
        \\findtime = 600
        \\bantime = {d}
        \\
    , .{ opts.log_target orelse "stderr", opts.state_file orelse p.state_file, h.socket_path, opts.extra, opts.bantime });
    if (opts.journal) {
        try w.writeAll(
            \\[jails.sshd]
            \\filter = "sshd"
            \\source = "journald"
            \\journal_executables = ["/usr/bin/true"]
            \\
        );
    } else {
        try w.print(
            \\[jails.sshd]
            \\filter = "sshd"
            \\source = "file"
            \\timestamp = "undated"
            \\logpath = ["{s}"]
            \\
        , .{h.log_path});
    }
}

/// Stands in for the service manager's NOTIFY_SOCKET.
const NotifyReceiver = struct {
    fd: posix.fd_t,

    fn bind(path: []const u8) !NotifyReceiver {
        const fd = try posix.socket(posix.AF.UNIX, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK, 0);
        errdefer posix.close(fd);
        var addr: linux.sockaddr.un = .{ .path = [_]u8{0} ** 108 };
        @memcpy(addr.path[0..path.len], path);
        try posix.bind(fd, @ptrCast(&addr), @intCast(@offsetOf(linux.sockaddr.un, "path") + path.len + 1));
        return .{ .fd = fd };
    }

    fn deinit(self: NotifyReceiver) void {
        posix.close(self.fd);
    }

    /// Returns null when nothing arrived within the budget.
    fn next(self: NotifyReceiver, buf: []u8, timeout_ns: u64) !?[]const u8 {
        var timer = try std.time.Timer.start();
        while (true) {
            const n = posix.recvfrom(self.fd, buf, 0, null, null) catch |err| switch (err) {
                error.WouldBlock => {
                    if (timer.read() >= timeout_ns) return null;
                    std.time.sleep(10 * std.time.ns_per_ms);
                    continue;
                },
                else => return err,
            };
            return buf[0..n];
        }
    }

    fn expectNext(self: NotifyReceiver, buf: []u8, expected: []const u8, timeout_ns: u64) !void {
        const got = (try self.next(buf, timeout_ns)) orelse return error.NotifyTimeout;
        try t.expectEqualStrings(expected, got);
    }

    fn expectPrefixNext(self: NotifyReceiver, buf: []u8, prefix: []const u8, timeout_ns: u64) !void {
        const got = (try self.next(buf, timeout_ns)) orelse return error.NotifyTimeout;
        try t.expect(std.mem.startsWith(u8, got, prefix));
    }

    fn expectSilence(self: NotifyReceiver, buf: []u8, window_ns: u64) !void {
        if (try self.next(buf, window_ns)) |got| {
            std.debug.print("unexpected notification: {s}\n", .{got});
            return error.UnexpectedNotification;
        }
    }
};

const Daemon = struct {
    child: std.process.Child,
    env: std.process.EnvMap,

    fn spawn(a: std.mem.Allocator, h: *const harness.Harness, notify_path: []const u8, capture_stderr: bool) !Daemon {
        var env = try std.process.getEnvMap(a);
        errdefer env.deinit();
        try env.put("NOTIFY_SOCKET", notify_path);
        var child = std.process.Child.init(&.{ exe, "--foreground", "--config", h.config_path }, a);
        child.env_map = &env;
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Ignore;
        child.stderr_behavior = if (capture_stderr) .Pipe else .Inherit;
        try child.spawn();
        child.env_map = null;
        return .{ .child = child, .env = env };
    }

    fn signal(self: *Daemon, sig: u8) !void {
        try posix.kill(self.child.id, sig);
    }

    fn wait(self: *Daemon) !std.process.Child.Term {
        return self.child.wait();
    }

    /// Bounded wait so a hung daemon fails the test instead of the run.
    fn waitBounded(self: *Daemon, timeout_ns: u64) !std.process.Child.Term {
        var timer = try std.time.Timer.start();
        while (timer.read() < timeout_ns) {
            var status: u32 = 0;
            const pid = linux.wait4(self.child.id, &status, linux.W.NOHANG, null);
            if (@as(isize, @bitCast(pid)) == self.child.id) {
                self.child.id = 0;
                if (linux.W.IFEXITED(status)) return .{ .Exited = linux.W.EXITSTATUS(status) };
                if (linux.W.IFSIGNALED(status)) return .{ .Signal = linux.W.TERMSIG(status) };
                return .{ .Unknown = status };
            }
            std.time.sleep(20 * std.time.ns_per_ms);
        }
        return error.DaemonHung;
    }

    fn readStderr(self: *Daemon, a: std.mem.Allocator) ![]u8 {
        const f = self.child.stderr orelse return a.dupe(u8, "");
        return f.readToEndAlloc(a, 1 << 20);
    }

    fn deinit(self: *Daemon) void {
        if (self.child.id != 0) {
            posix.kill(self.child.id, posix.SIG.KILL) catch {};
            _ = self.child.wait() catch {};
        } else if (self.child.stderr) |f| f.close();
        self.env.deinit();
    }
};

fn storageHealthy(h: *harness.Harness) bool {
    const s = h.queryStatus() catch return false;
    defer t.allocator.free(s);
    return std.mem.indexOf(u8, s, "\"storage\":\"healthy\"") != null;
}

/// Storage passes through `recovering` after an applied reload; wait for it to settle.
fn waitStorageHealthy(h: *harness.Harness, timeout_ns: u64) !void {
    var timer = try std.time.Timer.start();
    while (timer.read() < timeout_ns) {
        if (storageHealthy(h)) return;
        std.time.sleep(25 * std.time.ns_per_ms);
    }
    return error.TimedOut;
}

/// Waits for admission while proving READY never precedes it.
fn waitReadyAfterAdmission(h: *harness.Harness, rx: NotifyReceiver) !void {
    var buf: [256]u8 = undefined;
    var timer = try std.time.Timer.start();
    var healthy_seen = false;
    while (timer.read() < startup_timeout_ns) {
        if (!healthy_seen and storageHealthy(h)) healthy_seen = true;
        if (try rx.next(&buf, 0)) |msg| {
            try t.expectEqualStrings("READY=1\n", msg);
            if (!healthy_seen and !storageHealthy(h)) return error.ReadyBeforeAdmission;
            return;
        }
        std.time.sleep(25 * std.time.ns_per_ms);
    }
    return error.TimedOut;
}

fn generation(a: std.mem.Allocator, h: *harness.Harness) ![]u8 {
    const s = try h.queryStatus();
    defer a.free(s);
    const needle = "\"generation\":\"";
    const start = (std.mem.indexOf(u8, s, needle) orelse return error.MissingField) + needle.len;
    const end = std.mem.indexOfScalarPos(u8, s, start, '"') orelse return error.MissingField;
    return a.dupe(u8, s[start..end]);
}

fn waitFileContains(path: []const u8, needle: []const u8, timeout_ns: u64) !void {
    var timer = try std.time.Timer.start();
    while (timer.read() < timeout_ns) {
        const bytes = std.fs.cwd().readFileAlloc(t.allocator, path, 1 << 20) catch |err| switch (err) {
            error.FileNotFound => {
                std.time.sleep(50 * std.time.ns_per_ms);
                continue;
            },
            else => return err,
        };
        defer t.allocator.free(bytes);
        if (std.mem.indexOf(u8, bytes, needle) != null) return;
        std.time.sleep(50 * std.time.ns_per_ms);
    }
    return error.TimedOut;
}

const Fixture = struct {
    h: harness.Harness,
    p: Paths,
    rx: NotifyReceiver,

    fn init(a: std.mem.Allocator) !Fixture {
        std.fs.cwd().access(exe, .{}) catch return error.SkipZigTest;
        var h = try harness.Harness.init(a, .{ .spawn_daemon = false });
        errdefer h.deinit();
        var p = try Paths.init(a, &h);
        errdefer p.deinit(a);
        const rx = try NotifyReceiver.bind(p.notify);
        return .{ .h = h, .p = p, .rx = rx };
    }

    fn deinit(self: *Fixture, a: std.mem.Allocator) void {
        self.rx.deinit();
        self.p.deinit(a);
        self.h.deinit();
    }
};

fn expectNoSocket(h: *const harness.Harness) !void {
    try t.expectError(error.FileNotFound, std.fs.cwd().access(h.socket_path, .{}));
}

test "lifecycle: READY only after admission, RELOADING/READY around SIGHUP, STOPPING and exit 0 on SIGTERM" {
    const a = t.allocator;
    var fx = try Fixture.init(a);
    defer fx.deinit(a);
    try writeConfig(&fx.h, &fx.p, .{});

    var d = try Daemon.spawn(a, &fx.h, fx.p.notify, false);
    defer d.deinit();
    var buf: [256]u8 = undefined;

    try fx.h.waitForSocket(5_000);
    try waitReadyAfterAdmission(&fx.h, fx.rx);
    try fx.rx.expectSilence(&buf, 300 * std.time.ns_per_ms);
    const g0 = try generation(a, &fx.h);
    defer a.free(g0);

    try writeConfig(&fx.h, &fx.p, .{ .bantime = 120 });
    try d.signal(posix.SIG.HUP);
    try fx.rx.expectPrefixNext(&buf, "RELOADING=1\nMONOTONIC_USEC=", 5 * std.time.ns_per_s);
    try fx.rx.expectNext(&buf, "READY=1\n", 5 * std.time.ns_per_s);
    const g1 = try generation(a, &fx.h);
    defer a.free(g1);
    try t.expect(!std.mem.eql(u8, g0, g1));

    // A rejected edit never reaches the worker, so the service manager sees no RELOADING
    // at all; the previous generation stays published and the daemon keeps serving.
    try writeConfig(&fx.h, &fx.p, .{ .bantime = 120, .extra = "bogus_key = 1" });
    try d.signal(posix.SIG.HUP);
    try fx.rx.expectSilence(&buf, 1 * std.time.ns_per_s);
    const g2 = try generation(a, &fx.h);
    defer a.free(g2);
    try t.expectEqualStrings(g1, g2);
    try waitStorageHealthy(&fx.h, 10 * std.time.ns_per_s);

    try d.signal(posix.SIG.TERM);
    try fx.rx.expectNext(&buf, "STOPPING=1\n", 5 * std.time.ns_per_s);
    try t.expectEqual(std.process.Child.Term{ .Exited = 0 }, try d.waitBounded(10 * std.time.ns_per_s));
    try expectNoSocket(&fx.h);
}

test "lifecycle: SIGINT stops cleanly with STOPPING and exit 0" {
    const a = t.allocator;
    var fx = try Fixture.init(a);
    defer fx.deinit(a);
    try writeConfig(&fx.h, &fx.p, .{});
    var d = try Daemon.spawn(a, &fx.h, fx.p.notify, false);
    defer d.deinit();
    var buf: [256]u8 = undefined;
    try fx.h.waitForSocket(5_000);
    try waitReadyAfterAdmission(&fx.h, fx.rx);
    try d.signal(posix.SIG.INT);
    try fx.rx.expectNext(&buf, "STOPPING=1\n", 5 * std.time.ns_per_s);
    try t.expectEqual(std.process.Child.Term{ .Exited = 0 }, try d.waitBounded(10 * std.time.ns_per_s));
    try expectNoSocket(&fx.h);
}

test "lifecycle: SIGUSR1 after rename reopens the log target and leaves the rotated file untouched" {
    const a = t.allocator;
    var fx = try Fixture.init(a);
    defer fx.deinit(a);
    try writeConfig(&fx.h, &fx.p, .{ .log_target = fx.p.log_target });
    var d = try Daemon.spawn(a, &fx.h, fx.p.notify, false);
    defer d.deinit();
    var buf: [256]u8 = undefined;
    try fx.h.waitForSocket(5_000);
    try waitReadyAfterAdmission(&fx.h, fx.rx);
    try waitFileContains(fx.p.log_target, "native: ready", 5 * std.time.ns_per_s);

    const rotated = try std.fmt.allocPrint(a, "{s}.1", .{fx.p.log_target});
    defer a.free(rotated);
    try std.fs.cwd().rename(fx.p.log_target, rotated);
    try d.signal(posix.SIG.USR1);
    std.time.sleep(300 * std.time.ns_per_ms);
    const old_len = (try std.fs.cwd().statFile(rotated)).size;

    // A no-op reload is logged but, like a rejection, sends no RELOADING/READY.
    try d.signal(posix.SIG.HUP);
    try fx.rx.expectSilence(&buf, 500 * std.time.ns_per_ms);
    try waitFileContains(fx.p.log_target, "native reload (SIGHUP): outcome=noop", 5 * std.time.ns_per_s);
    const fresh = try std.fs.cwd().statFile(fx.p.log_target);
    try t.expectEqual(@as(u32, 0o640), @as(u32, @intCast(fresh.mode & 0o777)));
    try t.expectEqual(old_len, (try std.fs.cwd().statFile(rotated)).size);
    const old = try std.fs.cwd().readFileAlloc(a, rotated, 1 << 20);
    defer a.free(old);
    try t.expect(std.mem.indexOf(u8, old, "outcome=noop") == null);

    try d.signal(posix.SIG.TERM);
    try fx.rx.expectNext(&buf, "STOPPING=1\n", 5 * std.time.ns_per_s);
    try t.expectEqual(std.process.Child.Term{ .Exited = 0 }, try d.waitBounded(10 * std.time.ns_per_s));
}

fn expectRefusal(a: std.mem.Allocator, fx: *Fixture, stderr_needle: []const u8) !void {
    var d = try Daemon.spawn(a, &fx.h, fx.p.notify, true);
    defer d.deinit();
    const stderr = try d.readStderr(a);
    defer a.free(stderr);
    const term = try d.waitBounded(10 * std.time.ns_per_s);
    try t.expectEqual(std.process.Child.Term{ .Exited = 1 }, term);
    if (std.mem.indexOf(u8, stderr, stderr_needle) == null) {
        std.debug.print("stderr was:\n{s}\n", .{stderr});
        return error.RefusalReasonMissing;
    }
    try t.expect(std.mem.indexOf(u8, stderr, "refusing to start") != null);
    var buf: [256]u8 = undefined;
    try fx.rx.expectSilence(&buf, 200 * std.time.ns_per_ms);
    try expectNoSocket(&fx.h);
}

test "lifecycle: BUG-026 startup refusal reaches the file log before exit" {
    const a = t.allocator;
    var fx = try Fixture.init(a);
    defer fx.deinit(a);
    // Opening a directory as the database fails even when the test runs as root.
    try writeConfig(&fx.h, &fx.p, .{ .log_target = fx.p.log_target, .state_file = fx.p.state_dir });
    var d = try Daemon.spawn(a, &fx.h, fx.p.notify, false);
    defer d.deinit();
    try t.expectEqual(std.process.Child.Term{ .Exited = 1 }, try d.waitBounded(startup_timeout_ns));
    const logged = try std.fs.cwd().readFileAlloc(a, fx.p.log_target, 1 << 20);
    defer a.free(logged);
    try t.expect(std.mem.indexOf(u8, logged, "native: startup failed:") != null);
    try t.expect(std.mem.indexOf(u8, logged, "refusing to start") != null);
    var buf: [256]u8 = undefined;
    try fx.rx.expectSilence(&buf, 200 * std.time.ns_per_ms);
    try expectNoSocket(&fx.h);
}

test "lifecycle: unwritable state directory is a typed refusal with exit 1 and no READY" {
    if (linux.geteuid() == 0) return error.SkipZigTest;
    const a = t.allocator;
    var fx = try Fixture.init(a);
    defer fx.deinit(a);
    try writeConfig(&fx.h, &fx.p, .{});
    try posix.fchmodat(posix.AT.FDCWD, fx.p.state_dir, 0o500, 0);
    defer posix.fchmodat(posix.AT.FDCWD, fx.p.state_dir, 0o750, 0) catch {};
    try expectRefusal(a, &fx, "native: startup failed:");
}

test "lifecycle: log target with a missing parent is refused before the daemon starts" {
    const a = t.allocator;
    var fx = try Fixture.init(a);
    defer fx.deinit(a);
    const missing = try std.fmt.allocPrint(a, "{s}/absent/daemon.log", .{fx.h.tmp_abs});
    defer a.free(missing);
    try writeConfig(&fx.h, &fx.p, .{ .log_target = missing });
    try expectRefusal(a, &fx, "log target");
}

test "lifecycle: journal jail without journalctl is refused naming the transport" {
    // The daemon resolves journalctl at the fixed path /usr/bin/journalctl, never PATH, so an
    // unprivileged run cannot hide it; the lab rehearsal covers this with InaccessiblePaths.
    if (std.fs.cwd().access("/usr/bin/journalctl", .{})) |_| return error.SkipZigTest else |_| {}
    const a = t.allocator;
    var fx = try Fixture.init(a);
    defer fx.deinit(a);
    try writeConfig(&fx.h, &fx.p, .{ .journal = true });
    try expectRefusal(a, &fx, "journalctl");
}

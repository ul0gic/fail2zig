// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;

const testing = std.testing;

const daemon_path = "zig-out/bin/fail2zig";
const client_path = "zig-out/bin/fail2zig-client";
const max_output_bytes: usize = 1 << 20;
const watchdog_timeout_ms: u64 = 10_000;
const startup_timeout_ms: u64 = 5_000;
const log_wait_ms: u64 = 5_000;
const settle_ms: u64 = 300;

const attacker_lines = [_][]const u8{
    "Failed password for root from 192.0.2.42 port 1 ssh2",
    "Failed password for root from 192.0.2.42 port 2 ssh2",
    "Failed password for root from 192.0.2.42 port 3 ssh2",
};

const Run = struct {
    term: std.process.Child.Term,
    stdout: []u8,
    stderr: []u8,

    fn deinit(self: *Run, a: std.mem.Allocator) void {
        a.free(self.stdout);
        a.free(self.stderr);
    }

    fn exitCode(self: *const Run) ?u8 {
        return switch (self.term) {
            .Exited => |code| code,
            else => null,
        };
    }
};

fn watchdog(pid: posix.pid_t, done: *std.atomic.Value(bool)) void {
    var waited: u64 = 0;
    while (waited < watchdog_timeout_ms) : (waited += 50) {
        if (done.load(.acquire)) return;
        std.time.sleep(50 * std.time.ns_per_ms);
    }
    posix.kill(pid, posix.SIG.KILL) catch {};
}

fn runToExit(a: std.mem.Allocator, argv: []const []const u8) !Run {
    var child = std.process.Child.init(argv, a);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    try child.spawn();

    var done = std.atomic.Value(bool).init(false);
    const guard = try std.Thread.spawn(.{}, watchdog, .{ child.id, &done });

    var out: std.ArrayListUnmanaged(u8) = .{};
    errdefer out.deinit(a);
    var err_out: std.ArrayListUnmanaged(u8) = .{};
    errdefer err_out.deinit(a);
    try child.collectOutput(a, &out, &err_out, max_output_bytes);
    const term = try child.wait();

    done.store(true, .release);
    guard.join();

    return .{
        .term = term,
        .stdout = try out.toOwnedSlice(a),
        .stderr = try err_out.toOwnedSlice(a),
    };
}

fn hasErrorReturnTrace(text: []const u8) bool {
    if (std.mem.indexOf(u8, text, "error return trace") != null) return true;
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, text, i, "0x")) |pos| {
        var j = pos + 2;
        while (j < text.len and std.ascii.isHex(text[j])) : (j += 1) {}
        if (j > pos + 2 and std.mem.startsWith(u8, text[j..], " in ")) return true;
        i = pos + 2;
    }
    return false;
}

fn expectContains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) == null) {
        std.debug.print("expected to find \"{s}\" in:\n{s}\n", .{ needle, haystack });
        return error.TestExpectedContains;
    }
}

fn expectNotContains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) != null) {
        std.debug.print("expected NOT to find \"{s}\" in:\n{s}\n", .{ needle, haystack });
        return error.TestUnexpectedContains;
    }
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    return std.ascii.indexOfIgnoreCase(haystack, needle) != null;
}

fn lineContaining(text: []const u8, needle: []const u8) ?[]const u8 {
    const pos = std.mem.indexOf(u8, text, needle) orelse return null;
    const start = if (std.mem.lastIndexOfScalar(u8, text[0..pos], '\n')) |i| i + 1 else 0;
    const end = std.mem.indexOfScalarPos(u8, text, pos, '\n') orelse text.len;
    return text[start..end];
}

fn expectSummaryLine(text: []const u8, outcome: []const u8) !void {
    const line = lineContaining(text, "no usable backend") orelse {
        std.debug.print("expected a \"no usable backend\" line in:\n{s}\n", .{text});
        return error.TestExpectedContains;
    };
    try expectContains(line, outcome);
    const open = std.mem.indexOfScalar(u8, line, '(') orelse return error.TestCauseMissing;
    const close = std.mem.indexOfScalarPos(u8, line, open, ')') orelse return error.TestCauseMissing;
    if (close <= open + 1) {
        std.debug.print("summary line has an empty cause: {s}\n", .{line});
        return error.TestCauseMissing;
    }
}

fn jsonStringField(json: []const u8, field: []const u8) ?[]const u8 {
    var key_buf: [64]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buf, "\"{s}\":\"", .{field}) catch return null;
    const start = (std.mem.indexOf(u8, json, key) orelse return null) + key.len;
    const end = std.mem.indexOfScalarPos(u8, json, start, '"') orelse return null;
    return json[start..end];
}

const StderrSink = struct {
    mutex: std.Thread.Mutex = .{},
    buf: std.ArrayListUnmanaged(u8) = .{},
    a: std.mem.Allocator,

    fn pump(self: *StderrSink, file: std.fs.File) void {
        var chunk: [4096]u8 = undefined;
        while (true) {
            const n = file.read(&chunk) catch return;
            if (n == 0) return;
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.buf.items.len + n <= max_output_bytes) {
                self.buf.appendSlice(self.a, chunk[0..n]) catch return;
            }
        }
    }

    fn contains(self: *StderrSink, needle: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return std.mem.indexOf(u8, self.buf.items, needle) != null;
    }

    fn snapshot(self: *StderrSink, a: std.mem.Allocator) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return a.dupe(u8, self.buf.items);
    }

    fn deinit(self: *StderrSink) void {
        self.buf.deinit(self.a);
    }
};

const LiveDaemon = struct {
    child: std.process.Child,
    sink: StderrSink,
    pump_thread: ?std.Thread = null,
    stopped: bool = false,

    fn start(a: std.mem.Allocator, config_path: []const u8) !*LiveDaemon {
        const self = try a.create(LiveDaemon);
        errdefer a.destroy(self);
        const argv = [_][]const u8{ daemon_path, "--foreground", "--config", config_path };
        self.* = .{
            .child = std.process.Child.init(&argv, a),
            .sink = .{ .a = a },
        };
        self.child.stdin_behavior = .Ignore;
        self.child.stdout_behavior = .Ignore;
        self.child.stderr_behavior = .Pipe;
        try self.child.spawn();
        errdefer {
            _ = self.child.kill() catch {};
        }
        self.pump_thread = try std.Thread.spawn(.{}, StderrSink.pump, .{ &self.sink, self.child.stderr.? });
        return self;
    }

    fn isAlive(self: *LiveDaemon) bool {
        if (self.stopped) return false;
        var status: u32 = 0;
        const rc = linux.waitpid(self.child.id, &status, linux.W.NOHANG);
        return rc == 0;
    }

    fn waitForStderr(self: *LiveDaemon, needle: []const u8, timeout_ms: u64) bool {
        var waited: u64 = 0;
        while (waited < timeout_ms) : (waited += 25) {
            if (self.sink.contains(needle)) return true;
            if (!self.isAlive()) return self.sink.contains(needle);
            std.time.sleep(25 * std.time.ns_per_ms);
        }
        return self.sink.contains(needle);
    }

    fn waitForSocket(self: *LiveDaemon, socket_path: []const u8, timeout_ms: u64) !void {
        var waited: u64 = 0;
        while (waited < timeout_ms) : (waited += 10) {
            if (!self.isAlive()) return error.DaemonExited;
            if (dialOnce(socket_path)) |fd| {
                posix.close(fd);
                return;
            } else |_| {}
            std.time.sleep(10 * std.time.ns_per_ms);
        }
        return error.SocketNeverAppeared;
    }

    fn stop(self: *LiveDaemon) !std.process.Child.Term {
        if (self.stopped) return .{ .Exited = 0 };
        self.stopped = true;
        posix.kill(self.child.id, posix.SIG.TERM) catch {};
        var done = std.atomic.Value(bool).init(false);
        const guard = try std.Thread.spawn(.{}, watchdog, .{ self.child.id, &done });
        const term = try self.child.wait();
        done.store(true, .release);
        guard.join();
        if (self.pump_thread) |t| t.join();
        self.pump_thread = null;
        return term;
    }

    fn destroy(self: *LiveDaemon, a: std.mem.Allocator) void {
        if (!self.stopped) {
            _ = self.child.kill() catch {};
            self.stopped = true;
            if (self.pump_thread) |t| t.join();
        }
        self.sink.deinit();
        a.destroy(self);
    }
};

fn dialOnce(path: []const u8) !posix.fd_t {
    const fd = try posix.socket(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    errdefer posix.close(fd);
    var addr: posix.sockaddr.un = .{ .family = posix.AF.UNIX, .path = undefined };
    if (path.len >= addr.path.len) return error.NameTooLong;
    @memcpy(addr.path[0..path.len], path);
    addr.path[path.len] = 0;
    const addr_len: posix.socklen_t = @intCast(@sizeOf(@TypeOf(addr.family)) + path.len + 1);
    try posix.connect(fd, @ptrCast(&addr), addr_len);
    return fd;
}

const Scenario = struct {
    a: std.mem.Allocator,
    tmp: std.testing.TmpDir,
    root: []const u8,
    config_path: []const u8,
    log_path: []const u8,
    socket_path: []const u8,
    metrics_port: u16,

    fn init(a: std.mem.Allocator) !Scenario {
        if (builtin.os.tag != .linux) return error.SkipZigTest;
        if (linux.geteuid() == 0) return error.SkipZigTest;
        std.fs.cwd().access(daemon_path, .{}) catch return error.SkipZigTest;

        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();

        var abs_buf: [std.fs.max_path_bytes]u8 = undefined;
        const abs = try tmp.dir.realpath(".", &abs_buf);
        const root = try a.dupe(u8, abs);
        errdefer a.free(root);
        const config_path = try std.fmt.allocPrint(a, "{s}/config.toml", .{root});
        errdefer a.free(config_path);
        const log_path = try std.fmt.allocPrint(a, "{s}/auth.log", .{root});
        errdefer a.free(log_path);
        const socket_path = try std.fmt.allocPrint(a, "{s}/sock/fail2zig.sock", .{root});
        errdefer a.free(socket_path);
        if (socket_path.len >= 108) return error.SkipZigTest;

        var f = try std.fs.cwd().createFile(log_path, .{});
        f.close();

        const h = std.hash.Wyhash.hash(0, root);
        const port: u16 = @intCast(49152 + (h % 16384));

        return .{
            .a = a,
            .tmp = tmp,
            .root = root,
            .config_path = config_path,
            .log_path = log_path,
            .socket_path = socket_path,
            .metrics_port = port,
        };
    }

    fn deinit(self: *Scenario) void {
        self.a.free(self.socket_path);
        self.a.free(self.log_path);
        self.a.free(self.config_path);
        self.a.free(self.root);
        self.tmp.cleanup();
        self.* = undefined;
    }

    fn writeConfig(self: *Scenario, global_extra: []const u8, banaction: []const u8) !void {
        const text = try std.fmt.allocPrint(self.a,
            \\[global]
            \\socket_path = "{s}"
            \\state_file = "{s}/state.bin"
            \\metrics_bind = "127.0.0.1"
            \\metrics_port = {d}
            \\memory_ceiling_mb = 64
            \\{s}
            \\
            \\[defaults]
            \\maxretry = 3
            \\findtime = 600
            \\bantime = 600
            \\banaction = "{s}"
            \\
            \\[jails.sshd]
            \\enabled = true
            \\filter = "sshd"
            \\source = "file"
            \\logpath = ["{s}"]
            \\
        , .{ self.socket_path, self.root, self.metrics_port, global_extra, banaction, self.log_path });
        defer self.a.free(text);

        var f = try std.fs.cwd().createFile(self.config_path, .{ .truncate = true, .mode = 0o640 });
        defer f.close();
        try f.writeAll(text);
        try f.chmod(0o640);
    }

    fn runDaemonToExit(self: *Scenario) !Run {
        const argv = [_][]const u8{ daemon_path, "--foreground", "--config", self.config_path };
        return runToExit(self.a, &argv);
    }

    fn appendLogLine(self: *Scenario, line: []const u8) !void {
        var f = try std.fs.cwd().openFile(self.log_path, .{ .mode = .write_only });
        defer f.close();
        try f.seekFromEnd(0);
        try f.writeAll(line);
        try f.writeAll("\n");
    }

    fn clientStatus(self: *Scenario, d: *LiveDaemon) ![]u8 {
        std.fs.cwd().access(client_path, .{}) catch return error.TestClientBinaryMissing;
        const argv = [_][]const u8{ client_path, "--socket", self.socket_path, "status" };
        var r = try runToExit(self.a, &argv);
        defer r.deinit(self.a);
        if (r.exitCode() != 0) {
            const rejected = d.waitForStderr("ipc: rejecting peer", 1_000);
            std.debug.print("client status failed (exit {?d}, peer rejected={}):\n{s}{s}\n", .{ r.exitCode(), rejected, r.stdout, r.stderr });
            return if (rejected) error.TestPeerRejected else error.TestClientStatusFailed;
        }
        return self.a.dupe(u8, r.stdout);
    }

    fn httpStatus(self: *Scenario) ![]u8 {
        const addr = try std.net.Address.parseIp4("127.0.0.1", self.metrics_port);
        var waited: u64 = 0;
        const stream = while (true) {
            if (std.net.tcpConnectToAddress(addr)) |st| break st else |err| switch (err) {
                error.ConnectionRefused => {
                    if (waited >= startup_timeout_ms) return error.TestHttpNeverListened;
                    std.time.sleep(10 * std.time.ns_per_ms);
                    waited += 10;
                },
                else => return err,
            }
        };
        defer stream.close();
        try stream.writer().writeAll("GET /api/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        var raw: std.ArrayListUnmanaged(u8) = .{};
        defer raw.deinit(self.a);
        var chunk: [4096]u8 = undefined;
        while (true) {
            const n = try stream.read(&chunk);
            if (n == 0) break;
            try raw.appendSlice(self.a, chunk[0..n]);
            if (raw.items.len > max_output_bytes) return error.TestResponseTooLarge;
            if (std.mem.indexOf(u8, raw.items, "\r\n\r\n")) |hdr_end| {
                if (std.mem.indexOfScalarPos(u8, raw.items, hdr_end, '}') != null) break;
            }
        }
        const hdr_end = std.mem.indexOf(u8, raw.items, "\r\n\r\n") orelse return error.TestMalformedHttp;
        try expectContains(raw.items[0..hdr_end], "200");
        return self.a.dupe(u8, raw.items[hdr_end + 4 ..]);
    }
};

test "integration: no backend (a) enforcing jail + default on_no_backend exits 1 naming the cause, no trace (SYS-014)" {
    const a = testing.allocator;
    var s = try Scenario.init(a);
    defer s.deinit();

    try s.writeConfig("", "nftables");

    var r = try s.runDaemonToExit();
    defer r.deinit(a);

    try testing.expectEqual(@as(?u8, 1), r.exitCode());
    try expectSummaryLine(r.stderr, "refusing to run unprotected");
    if (hasErrorReturnTrace(r.stderr)) {
        std.debug.print("error return trace leaked on a fail-closed exit:\n{s}\n", .{r.stderr});
        return error.TestErrorReturnTraceLeaked;
    }
}

test "integration: no backend (a') on_no_backend = \"fail-closed\" is the same as the default (SYS-014)" {
    const a = testing.allocator;
    var s = try Scenario.init(a);
    defer s.deinit();

    try s.writeConfig("on_no_backend = \"fail-closed\"", "nftables");

    var r = try s.runDaemonToExit();
    defer r.deinit(a);

    try testing.expectEqual(@as(?u8, 1), r.exitCode());
    try expectSummaryLine(r.stderr, "refusing to run unprotected");
    try testing.expect(!hasErrorReturnTrace(r.stderr));
}

test "integration: no backend (b) on_no_backend = \"log-only\" stays up DEGRADED with the cause; a would-ban logs and never enforces (SYS-014)" {
    const a = testing.allocator;
    var s = try Scenario.init(a);
    defer s.deinit();

    try s.writeConfig("on_no_backend = \"log-only\"", "nftables");

    const d = try LiveDaemon.start(a, s.config_path);
    defer d.destroy(a);

    d.waitForSocket(s.socket_path, startup_timeout_ms) catch |err| {
        const text = try d.sink.snapshot(a);
        defer a.free(text);
        std.debug.print("daemon did not come up ({s}); stderr:\n{s}\n", .{ @errorName(err), text });
        return error.TestDaemonDidNotStart;
    };
    try testing.expect(d.waitForStderr("no usable backend", log_wait_ms));
    {
        const early = try d.sink.snapshot(a);
        defer a.free(early);
        try expectSummaryLine(early, "running DEGRADED as log-only per on_no_backend");
    }

    const status = try s.httpStatus();
    defer a.free(status);
    try expectContains(status, "\"protection\":\"degraded\"");
    try expectContains(status, "\"backend\":\"none\"");
    const cause = jsonStringField(status, "protection_cause") orelse {
        std.debug.print("status lacks protection_cause:\n{s}\n", .{status});
        return error.TestCauseMissing;
    };
    try testing.expect(cause.len > 0);

    const table = try s.clientStatus(d);
    defer a.free(table);
    try expectContains(table, "Protection:  DEGRADED (PermissionDenied)");
    try expectContains(table, "Backend:     none");

    std.time.sleep(settle_ms * std.time.ns_per_ms);
    for (attacker_lines) |ln| try s.appendLogLine(ln);

    try testing.expect(d.waitForStderr("would-ban: jail='sshd' ip=192.0.2.42", log_wait_ms));
    try testing.expect(d.isAlive());

    const term = try d.stop();
    const text = try d.sink.snapshot(a);
    defer a.free(text);

    try testing.expectEqual(std.process.Child.Term{ .Exited = 0 }, term);
    try expectContains(text, "backend=none");
    try expectNotContains(text, "info: ban: jail=");
    try expectNotContains(text, "backend: ban failed");
    try expectNotContains(text, "refusing to run unprotected");
    try testing.expect(!hasErrorReturnTrace(text));
}

test "integration: no backend (c) all-log-only config runs non-root with Protection: log-only and no detect error (ENH-006)" {
    const a = testing.allocator;
    var s = try Scenario.init(a);
    defer s.deinit();

    try s.writeConfig("", "log-only");

    const d = try LiveDaemon.start(a, s.config_path);
    defer d.destroy(a);

    d.waitForSocket(s.socket_path, startup_timeout_ms) catch |err| {
        const text = try d.sink.snapshot(a);
        defer a.free(text);
        std.debug.print("daemon did not come up ({s}); stderr:\n{s}\n", .{ @errorName(err), text });
        return error.TestDaemonDidNotStart;
    };

    try testing.expect(d.waitForStderr("firewall: every enabled jail is log-only; backend detection skipped", log_wait_ms));

    const status = try s.httpStatus();
    defer a.free(status);
    try expectContains(status, "\"protection\":\"log-only\"");
    try expectContains(status, "\"backend\":\"none\"");
    try expectNotContains(status, "protection_cause");

    const table = try s.clientStatus(d);
    defer a.free(table);
    try expectContains(table, "Protection:  log-only");
    try expectContains(table, "Backend:     none");
    try expectNotContains(table, "DEGRADED");

    std.time.sleep(settle_ms * std.time.ns_per_ms);
    for (attacker_lines) |ln| try s.appendLogLine(ln);
    try testing.expect(d.waitForStderr("would-ban: jail='sshd' ip=192.0.2.42", log_wait_ms));
    try testing.expect(d.isAlive());

    const term = try d.stop();
    const text = try d.sink.snapshot(a);
    defer a.free(text);

    try testing.expectEqual(std.process.Child.Term{ .Exited = 0 }, term);
    try expectNotContains(text, "no usable backend");
    try expectNotContains(text, "nftables selected");
    try expectNotContains(text, "refusing to run unprotected");
    try expectNotContains(text, "error:");
    try expectNotContainsIgnoreCase(text, "degraded");
    try testing.expect(!hasErrorReturnTrace(text));
}

fn expectNotContainsIgnoreCase(haystack: []const u8, needle: []const u8) !void {
    if (containsIgnoreCase(haystack, needle)) {
        std.debug.print("expected NOT to find \"{s}\" (case-insensitive) in:\n{s}\n", .{ needle, haystack });
        return error.TestUnexpectedContains;
    }
}

test "integration: no backend helper: trace detector matches Zig frame lines and nothing else" {
    try testing.expect(hasErrorReturnTrace("error: PermissionDenied\n/x/main.zig:3:23: 0x10ddf13 in main (fail2zig)\n"));
    try testing.expect(!hasErrorReturnTrace("error: firewall: no usable backend (PermissionDenied) — refusing to run unprotected\n"));
}

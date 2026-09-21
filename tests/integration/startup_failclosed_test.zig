// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;

const testing = std.testing;

const daemon_path = "zig-out/bin/fail2zig";
const max_output_bytes: usize = 1 << 20;
const watchdog_timeout_ms: u64 = 10_000;

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

fn watchdog(pid: posix.pid_t, done: *std.atomic.Value(bool), timeout_ms: u64) void {
    var waited: u64 = 0;
    while (waited < timeout_ms) : (waited += 10) {
        if (done.load(.acquire)) return;
        std.time.sleep(10 * std.time.ns_per_ms);
    }
    posix.kill(pid, posix.SIG.KILL) catch {};
}

const RunFault = enum {
    none,
    watchdog_start,
    output_collection,
    output_eof,
};

fn terminateAndReap(child: *std.process.Child) void {
    posix.kill(child.id, posix.SIG.KILL) catch {};
    _ = child.wait() catch {
        // Zig 0.14.1 caches a post-fork exec error in child.term without
        // calling waitpid. Reap that known child and close its pipe handles.
        _ = posix.waitpid(child.id, 0);
        child.id = undefined;
        if (child.stdout) |*file| file.close();
        if (child.stderr) |*file| file.close();
        child.stdout = null;
        child.stderr = null;
    };
}

fn startWatchdog(pid: posix.pid_t, done: *std.atomic.Value(bool), timeout_ms: u64, fault: RunFault) !std.Thread {
    if (fault == .watchdog_start) return error.InjectedWatchdogStartFailure;
    return std.Thread.spawn(.{}, watchdog, .{ pid, done, timeout_ms });
}

fn waitForExitWithoutReaping(pid: posix.pid_t) !void {
    var info: linux.siginfo_t = undefined;
    while (true) switch (posix.errno(linux.waitid(.PID, pid, &info, linux.W.EXITED | linux.W.NOWAIT))) {
        .SUCCESS => return,
        .INTR => continue,
        else => |err| return posix.unexpectedErrno(err),
    };
}

fn collectChildOutput(
    child: *std.process.Child,
    a: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    err_out: *std.ArrayListUnmanaged(u8),
    fault: RunFault,
) !void {
    if (fault == .output_collection) return error.InjectedOutputCollectionFailure;
    if (fault == .output_eof) {
        child.stdout.?.close();
        child.stderr.?.close();
        child.stdout = null;
        child.stderr = null;
        return;
    }
    return child.collectOutput(a, out, err_out, max_output_bytes);
}

fn runDaemonWithFault(
    a: std.mem.Allocator,
    argv: []const []const u8,
    fault: RunFault,
    timeout_ms: u64,
    spawned_pid: ?*posix.pid_t,
) !Run {
    var child = std.process.Child.init(argv, a);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    try child.spawn();
    var child_needs_reap = true;
    errdefer if (child_needs_reap) terminateAndReap(&child);
    if (spawned_pid) |pid| pid.* = child.id;

    var done = std.atomic.Value(bool).init(false);
    const guard = try startWatchdog(child.id, &done, timeout_ms, fault);
    var guard_running = true;
    defer if (guard_running) {
        done.store(true, .release);
        guard.join();
    };

    var out: std.ArrayListUnmanaged(u8) = .{};
    errdefer out.deinit(a);
    var err_out: std.ArrayListUnmanaged(u8) = .{};
    errdefer err_out.deinit(a);
    try collectChildOutput(&child, a, &out, &err_out, fault);

    // Observe exit without reaping. The watchdog remains active through this
    // wait, while WNOWAIT reserves the PID until the guard has joined.
    try waitForExitWithoutReaping(child.id);
    done.store(true, .release);
    guard.join();
    guard_running = false;
    const term = try child.wait();
    child_needs_reap = false;

    const stdout = try out.toOwnedSlice(a);
    errdefer a.free(stdout);
    const stderr = try err_out.toOwnedSlice(a);

    return .{
        .term = term,
        .stdout = stdout,
        .stderr = stderr,
    };
}

fn runDaemon(a: std.mem.Allocator, argv: []const []const u8) !Run {
    return runDaemonWithFault(a, argv, .none, watchdog_timeout_ms, null);
}

fn expectReaped(pid: posix.pid_t) !void {
    try testing.expectError(error.ProcessNotFound, posix.kill(pid, 0));
}

fn expectFaultCleansUp(fault: RunFault, expected: anyerror) !void {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const sleep_path = "/usr/bin/sleep";
    std.fs.accessAbsolute(sleep_path, .{}) catch return error.SkipZigTest;

    var pid: posix.pid_t = undefined;
    var timer = try std.time.Timer.start();
    const result = runDaemonWithFault(
        testing.allocator,
        &.{ sleep_path, "30" },
        fault,
        watchdog_timeout_ms,
        &pid,
    );
    if (result) |run_value| {
        var run = run_value;
        run.deinit(testing.allocator);
        return error.ExpectedInjectedHarnessFailure;
    } else |err| try testing.expectEqual(expected, err);

    try testing.expect(timer.read() < 2 * std.time.ns_per_s);
    try expectReaped(pid);
}

test "startup harness reaps child on watchdog-start and output-collection failures" {
    try expectFaultCleansUp(.watchdog_start, error.InjectedWatchdogStartFailure);
    try expectFaultCleansUp(.output_collection, error.InjectedOutputCollectionFailure);
}

test "startup harness deadline covers EOF before child exit" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const sleep_path = "/usr/bin/sleep";
    std.fs.accessAbsolute(sleep_path, .{}) catch return error.SkipZigTest;

    var pid: posix.pid_t = undefined;
    var timer = try std.time.Timer.start();
    var run = try runDaemonWithFault(
        testing.allocator,
        &.{ sleep_path, "30" },
        .output_eof,
        200,
        &pid,
    );
    defer run.deinit(testing.allocator);

    try testing.expectEqual(std.process.Child.Term{ .Signal = posix.SIG.KILL }, run.term);
    try testing.expect(timer.read() < 2 * std.time.ns_per_s);
    try expectReaped(pid);
}

test "startup harness reaps a post-spawn exec failure" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = try tmp.dir.realpath(".", &path_buf);
    const missing = try std.fmt.allocPrint(testing.allocator, "{s}/missing-executable", .{root});
    defer testing.allocator.free(missing);

    var pid: posix.pid_t = undefined;
    const result = runDaemonWithFault(
        testing.allocator,
        &.{missing},
        .none,
        1_000,
        &pid,
    );
    if (result) |run_value| {
        var run = run_value;
        run.deinit(testing.allocator);
        return error.ExpectedExecFailure;
    } else |err| try testing.expectEqual(error.FileNotFound, err);
    try expectReaped(pid);
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

fn lineOf(text: []const u8, needle: []const u8) ?usize {
    const pos = std.mem.indexOf(u8, text, needle) orelse return null;
    return 1 + std.mem.count(u8, text[0..pos], "\n");
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

fn expectFailClosed(run: *const Run) !void {
    try expectFailClosedClass(run, 1);
}

fn expectFailClosedClass(run: *const Run, class: u8) !void {
    try testing.expectEqual(@as(?u8, class), run.exitCode());
    try testing.expect(run.stderr.len > 0);
    if (hasErrorReturnTrace(run.stderr)) {
        std.debug.print("error return trace leaked on a fail-closed exit:\n{s}\n", .{run.stderr});
        return error.TestErrorReturnTraceLeaked;
    }
}

const Scenario = struct {
    a: std.mem.Allocator,
    tmp: std.testing.TmpDir,
    root: []const u8,
    config_path: []const u8,
    log_path: []const u8,
    metrics_port: u16,

    fn init(a: std.mem.Allocator) !Scenario {
        if (builtin.os.tag != .linux) return error.SkipZigTest;
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
            .metrics_port = port,
        };
    }

    fn deinit(self: *Scenario) void {
        self.a.free(self.log_path);
        self.a.free(self.config_path);
        self.a.free(self.root);
        self.tmp.cleanup();
        self.* = undefined;
    }

    fn writeConfig(self: *Scenario, socket_path: []const u8, source_line: []const u8, mode: posix.mode_t) ![]u8 {
        const state_path = try std.fmt.allocPrint(self.a, "{s}/state.bin", .{self.root});
        defer self.a.free(state_path);
        return self.writeConfigWithState(socket_path, source_line, mode, state_path);
    }

    fn writeConfigWithState(self: *Scenario, socket_path: []const u8, source_line: []const u8, mode: posix.mode_t, state_path: []const u8) ![]u8 {
        const text = try std.fmt.allocPrint(self.a,
            \\[global]
            \\socket_path = "{s}"
            \\state_file = "{s}"
            \\metrics_bind = "127.0.0.1"
            \\metrics_port = {d}
            \\memory_ceiling_mb = 64
            \\
            \\[defaults]
            \\banaction = "log-only"
            \\
            \\[jails.sshd]
            \\enabled = true
            \\filter = "sshd"
            \\timestamp = "undated"
            \\{s}
            \\logpath = ["{s}"]
            \\
        , .{ socket_path, state_path, self.metrics_port, source_line, self.log_path });
        errdefer self.a.free(text);

        var f = try std.fs.cwd().createFile(self.config_path, .{ .truncate = true, .mode = 0o640 });
        defer f.close();
        try f.writeAll(text);
        try f.chmod(mode);
        return text;
    }

    fn defaultSocketPath(self: *Scenario) ![]u8 {
        return std.fmt.allocPrint(self.a, "{s}/sock/fail2zig.sock", .{self.root});
    }

    fn run(self: *Scenario) !Run {
        const argv = [_][]const u8{ daemon_path, "--foreground", "--config", self.config_path };
        return runDaemon(self.a, &argv);
    }
};

test "integration: fail-closed (a) socket dir with a missing parent exits 1 naming the dir, no trace" {
    const a = testing.allocator;
    var s = try Scenario.init(a);
    defer s.deinit();

    const sock = try std.fmt.allocPrint(a, "{s}/missing/deeper/fail2zig.sock", .{s.root});
    defer a.free(sock);
    const text = try s.writeConfig(sock, "source = \"file\"", 0o640);
    defer a.free(text);

    var r = try s.run();
    defer r.deinit(a);

    try expectFailClosed(&r);
    try expectContains(r.stderr, "socket");
    const missing_dir = try std.fmt.allocPrint(a, "{s}/missing/deeper", .{s.root});
    defer a.free(missing_dir);
    try expectContains(r.stderr, missing_dir);
}

test "integration: fail-closed (b) metrics port already bound exits 1 with a cause, no trace" {
    const a = testing.allocator;
    var s = try Scenario.init(a);
    defer s.deinit();

    const sock = try s.defaultSocketPath();
    defer a.free(sock);
    const text = try s.writeConfig(sock, "source = \"file\"", 0o640);
    defer a.free(text);

    const addr = try std.net.Address.parseIp4("127.0.0.1", s.metrics_port);
    var holder = try addr.listen(.{ .reuse_address = true });
    defer holder.deinit();

    var r = try s.run();
    defer r.deinit(a);

    try expectFailClosed(&r);

    const http_cause = try std.fmt.allocPrint(a, "native: HTTP listener 127.0.0.1:{d}: AddressInUse", .{s.metrics_port});
    defer a.free(http_cause);
    try expectContains(r.stderr, http_cause);
}

test "integration: fail-closed (c) world-writable config exits 2 naming the mode and the fix, no trace" {
    const a = testing.allocator;
    var s = try Scenario.init(a);
    defer s.deinit();

    const sock = try s.defaultSocketPath();
    defer a.free(sock);
    const text = try s.writeConfig(sock, "source = \"file\"", 0o666);
    defer a.free(text);

    var r = try s.run();
    defer r.deinit(a);

    try expectFailClosedClass(&r, 2);
    try expectContains(r.stderr, s.config_path);
    try expectContains(r.stderr, "world-writable (mode 0666)");
    try expectContains(r.stderr, "refusing to start");
    try expectContains(r.stderr, "chmod 0640");
}

test "integration: fail-closed (c') group-writable config with a non-root group is refused, 0640 is not" {
    const a = testing.allocator;
    var s = try Scenario.init(a);
    defer s.deinit();

    const sock = try s.defaultSocketPath();
    defer a.free(sock);

    const addr = try std.net.Address.parseIp4("127.0.0.1", s.metrics_port);
    var holder = try addr.listen(.{ .reuse_address = true });
    defer holder.deinit();

    {
        const text = try s.writeConfig(sock, "source = \"file\"", 0o660);
        defer a.free(text);
        const f = try std.fs.cwd().openFile(s.config_path, .{});
        const st = try posix.fstat(f.handle);
        f.close();

        var r = try s.run();
        defer r.deinit(a);
        try expectFailClosedClass(&r, 2);
        if (st.gid != 0) {
            try expectContains(r.stderr, "non-root group (mode 0660)");
            try expectContains(r.stderr, "refusing to start");
            try expectContains(r.stderr, "chmod 0640");
        } else {
            try expectNotContains(r.stderr, "mode 0660");
        }
    }

    {
        const text = try s.writeConfig(sock, "source = \"file\"", 0o640);
        defer a.free(text);
        var r = try s.run();
        defer r.deinit(a);
        try expectNotContains(r.stderr, "world-writable");
        try expectNotContains(r.stderr, "non-root group");
        try expectNotContains(r.stderr, "chmod 0640");
    }
}

test "integration: fail-closed (d) backend = \"bogus\" exits 2 with path:line:col, key and section, no trace" {
    const a = testing.allocator;
    var s = try Scenario.init(a);
    defer s.deinit();

    const sock = try s.defaultSocketPath();
    defer a.free(sock);
    const text = try s.writeConfig(sock, "backend = \"bogus\"", 0o640);
    defer a.free(text);
    const line = lineOf(text, "backend = \"bogus\"") orelse return error.TestBadFixture;

    var r = try s.run();
    defer r.deinit(a);

    try expectFailClosedClass(&r, 2);
    const position = try std.fmt.allocPrint(a, "config: {s}:{d}:11: InvalidValue", .{ s.config_path, line });
    defer a.free(position);
    try expectContains(r.stderr, position);
    try expectContains(r.stderr, "(key 'backend' in [jails.sshd])");
}

fn expectStorageRefusal(r: *const Run, socket_path: []const u8) !void {
    try expectFailClosed(r);
    try expectContains(r.stderr, "refusing to start");
    try expectNotContains(r.stderr, "firewall backend:");
    try expectNotContains(r.stderr, "scaffold installed");
    try expectNotContains(r.stderr, "no usable backend");
    try expectNotContains(r.stderr, "http:");
    try expectNotContains(r.stderr, "native: HTTP listener");
    try testing.expectError(error.FileNotFound, std.fs.cwd().access(socket_path, .{}));
}

test "integration: persistence missing parent refuses startup before backend and listeners" {
    const a = testing.allocator;
    var s = try Scenario.init(a);
    defer s.deinit();
    const sock = try s.defaultSocketPath();
    defer a.free(sock);
    const state_path = try std.fmt.allocPrint(a, "{s}/missing/state.bin", .{s.root});
    defer a.free(state_path);
    const text = try s.writeConfigWithState(sock, "source = \"file\"", 0o640, state_path);
    defer a.free(text);
    var r = try s.run();
    defer r.deinit(a);
    try expectStorageRefusal(&r, sock);
    try expectContains(r.stderr, state_path);
    try expectContains(r.stderr, "native: path admission");
    try expectContains(r.stderr, "FileNotFound");
}

test "integration: legacy state format refuses before SQLite and preserves saved bytes" {
    const a = testing.allocator;
    var s = try Scenario.init(a);
    defer s.deinit();
    const sock = try s.defaultSocketPath();
    defer a.free(sock);
    const text = try s.writeConfig(sock, "source = \"file\"", 0o640);
    defer a.free(text);
    {
        const file = try s.tmp.dir.createFile("state.bin", .{ .mode = 0o600 });
        defer file.close();
        try file.writeAll("F2ZS\x04retained legacy bytes");
    }
    try s.tmp.dir.makeDir("state.bin.tmp");
    var r = try s.run();
    defer r.deinit(a);
    try expectStorageRefusal(&r, sock);
    try expectContains(r.stderr, "native: state authority");
    try expectContains(r.stderr, "NativeStateMigrationRequired");
    var retained_sidecar = try s.tmp.dir.openDir("state.bin.tmp", .{});
    retained_sidecar.close();
    const saved = try s.tmp.dir.readFileAlloc(a, "state.bin", 100);
    defer a.free(saved);
    try testing.expectEqualStrings("F2ZS\x04retained legacy bytes", saved);
}

test "integration: unwritable persistence refuses startup then advances after repair" {
    if (std.os.linux.geteuid() == 0) return error.SkipZigTest;
    const a = testing.allocator;
    var s = try Scenario.init(a);
    defer s.deinit();
    const sock = try s.defaultSocketPath();
    defer a.free(sock);
    try s.tmp.dir.makeDir("storage");
    var storage = try s.tmp.dir.openDir("storage", .{ .iterate = true });
    defer storage.close();
    const state_path = try std.fmt.allocPrint(a, "{s}/storage/state.bin", .{s.root});
    defer a.free(state_path);
    const text = try s.writeConfigWithState(sock, "source = \"file\"", 0o640, state_path);
    defer a.free(text);
    const addr = try std.net.Address.parseIp4("127.0.0.1", s.metrics_port);
    var holder = try addr.listen(.{ .reuse_address = true });
    defer holder.deinit();
    try posix.fchmod(storage.fd, 0o500);
    defer posix.fchmod(storage.fd, 0o700) catch {};
    {
        var r = try s.run();
        defer r.deinit(a);
        try expectStorageRefusal(&r, sock);
        try expectContains(r.stderr, "native: state authority");
        try expectContains(r.stderr, state_path);
        try expectContains(r.stderr, "AccessDenied");
    }
    try posix.fchmod(storage.fd, 0o700);
    var repaired = try s.run();
    defer repaired.deinit(a);
    try expectFailClosed(&repaired);
    try expectContains(repaired.stderr, "native: HTTP listener");
    try expectNotContains(repaired.stderr, "startup check");
}

test "integration: state admission identifies foreign and unsupported databases without changing bytes" {
    const a = testing.allocator;
    const cases = .{
        .{ @as(u64, 68), @as(u32, 0x12345678), "ForeignDatabase" },
        .{ @as(u64, 60), @as(u32, 0x7fffffff), "UnsupportedSchema" },
    };
    inline for (cases) |case| {
        var s = try Scenario.init(a);
        defer s.deinit();
        const sock = try s.defaultSocketPath();
        defer a.free(sock);
        const text = try s.writeConfig(sock, "source = \"file\"", 0o640);
        defer a.free(text);
        const address = try std.net.Address.parseIp4("127.0.0.1", s.metrics_port);
        var holder = try address.listen(.{ .reuse_address = true });
        defer holder.deinit();
        // Obtain a real daemon-created database, then alter only the SQLite
        // header field under test while no daemon or database handle is open.
        var initial = try s.run();
        defer initial.deinit(a);
        try expectFailClosed(&initial);
        try expectContains(initial.stderr, "native: HTTP listener");
        {
            const file = try s.tmp.dir.openFile("state.bin", .{ .mode = .read_write });
            defer file.close();
            var value: [4]u8 = undefined;
            std.mem.writeInt(u32, &value, case[1], .big);
            try file.pwriteAll(&value, case[0]);
        }
        const before = try s.tmp.dir.readFileAlloc(a, "state.bin", 32 * 1024 * 1024);
        defer a.free(before);
        var refused = try s.run();
        defer refused.deinit(a);
        try expectStorageRefusal(&refused, sock);
        try expectContains(refused.stderr, "state installation snapshot failed");
        try expectContains(refused.stderr, case[2]);
        try expectContains(refused.stderr, "stage=schema_validation");
        try expectContains(refused.stderr, "posix_cause=none; sqlite_code=null");
        try expectNotContains(refused.stderr, "delete");
        const after = try s.tmp.dir.readFileAlloc(a, "state.bin", 32 * 1024 * 1024);
        defer a.free(after);
        try testing.expectEqualSlices(u8, before, after);
    }
}

test "integration: fail-closed helper: trace detector matches Zig frame lines and nothing else" {
    try testing.expect(hasErrorReturnTrace("error: AddressInUse\n/x/main.zig:3:23: 0x10ddf13 in main (fail2zig)\n"));
    try testing.expect(hasErrorReturnTrace("... error return trace ..."));
    try testing.expect(!hasErrorReturnTrace("error: http: init on 127.0.0.1:9100 failed: AddressInUse\n"));
    try testing.expect(!hasErrorReturnTrace("config: /etc/fail2zig/config.toml:37:1: UnknownKey (key 'x' in [global])\n"));
    try testing.expect(!hasErrorReturnTrace("0x in nothing"));
}

// Journal startup cases use isolated log-only state; no host firewall mutation.
fn writeJournalProfileConfig(s: *Scenario, source: []const u8, profile: []const u8) !void {
    var file = try std.fs.cwd().createFile(s.config_path, .{ .mode = 0o600 });
    defer file.close();
    try file.writer().print(
        \\[global]
        \\socket_path = "{s}/control.sock"
        \\state_file = "{s}/state.bin"
        \\metrics_bind = "127.0.0.1"
        \\metrics_port = {d}
        \\[defaults]
        \\enforce = false
        \\[jails.sshd]
        \\enabled = true
        \\filter = "sshd"
        \\{s}
        \\{s}
        \\
    , .{ s.root, s.root, s.metrics_port, source, profile });
}

fn requireJournalProfileHost() !void {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    // These are metadata fixtures, not SSH emitters; no detection claim follows
    // from admitting them. Fail rather than silently skipping an unsafe fixture.
    for ([_][]const u8{ "/usr/bin/true", "/usr/bin/false", "/usr/bin/journalctl" }) |path| {
        var file = std.fs.openFileAbsolute(path, .{}) catch |err| switch (err) {
            error.FileNotFound => return error.SkipZigTest,
            else => return err,
        };
        defer file.close();
        const stat = try posix.fstat(file.handle);
        try testing.expect(posix.S.ISREG(stat.mode));
        try testing.expectEqual(@as(u32, 0), stat.uid);
        try testing.expect(stat.mode & 0o022 == 0 and stat.mode & 0o111 != 0);
    }
}

test "integration: journal profile BUG-051 omitted auto and explicit sources pass source admission" {
    try requireJournalProfileHost();
    // This connected case needs an installed SSH daemon; resolver unit fixtures
    // cover absence independently. Genuine traffic is a separate isolated gate.
    std.fs.accessAbsolute("/usr/sbin/sshd", .{}) catch return error.SkipZigTest;
    const a = testing.allocator;
    for ([_][]const u8{ "", "source = \"journald\"" }) |source| {
        var s = try Scenario.init(a);
        defer s.deinit();
        const addr = try std.net.Address.parseIp4("127.0.0.1", s.metrics_port);
        var holder = try addr.listen(.{ .reuse_address = true });
        defer holder.deinit();
        try writeJournalProfileConfig(&s, source, "");
        var validation = try runDaemon(a, &.{ daemon_path, "--config", s.config_path, "--validate-config" });
        defer validation.deinit(a);
        try testing.expectEqual(@as(?u8, 0), validation.exitCode());
        var run = try s.run();
        defer run.deinit(a);
        try expectFailClosed(&run);
        try expectContains(run.stderr, "native: HTTP listener");
        try expectContains(run.stderr, "AddressInUse");
        try expectNotContains(run.stderr, "InvalidJournalExecutables");
        try s.tmp.dir.access("state.bin", .{});
        try testing.expectError(error.FileNotFound, s.tmp.dir.access("control.sock", .{}));
    }
}

test "integration: journal profile explicit empty missing duplicate and excessive lists refuse before state creation" {
    try requireJournalProfileHost();
    const a = testing.allocator;
    const cases = [_]struct { value: []const u8, cause: []const u8 }{
        .{ .value = "[]", .cause = "InvalidJournalExecutables" },
        .{ .value = "[\"/usr/bin/true\", \"/usr/bin/true\"]", .cause = "DuplicateJournalExecutable" },
        .{ .value = "[\"/usr/bin/true\",\"/usr/bin/true\",\"/usr/bin/true\",\"/usr/bin/true\",\"/usr/bin/true\",\"/usr/bin/true\",\"/usr/bin/true\",\"/usr/bin/true\",\"/usr/bin/true\"]", .cause = "InvalidJournalExecutables" },
    };
    for (cases) |case| {
        var s = try Scenario.init(a);
        defer s.deinit();
        const setting = try std.fmt.allocPrint(a, "journal_executables = {s}", .{case.value});
        defer a.free(setting);
        try writeJournalProfileConfig(&s, "source = \"journald\"", setting);
        var run = try s.run();
        defer run.deinit(a);
        try expectFailClosed(&run);
        try expectContains(run.stderr, case.cause);
        try testing.expectError(error.FileNotFound, s.tmp.dir.access("state.bin", .{}));
    }
    var s = try Scenario.init(a);
    defer s.deinit();
    const setting = try std.fmt.allocPrint(a, "journal_executables = [\"{s}/missing-sshd\"]", .{s.root});
    defer a.free(setting);
    try writeJournalProfileConfig(&s, "source = \"journald\"", setting);
    var run = try s.run();
    defer run.deinit(a);
    try expectFailClosed(&run);
    try expectContains(run.stderr, "FileNotFound");
    try testing.expectError(error.FileNotFound, s.tmp.dir.access("state.bin", .{}));
}

test "integration: journal profile custom rules cannot inherit automatic SSH trust" {
    try requireJournalProfileHost();
    const a = testing.allocator;
    var s = try Scenario.init(a);
    defer s.deinit();
    const rule =
        \\{"id":"login","source":"application","format":"json","subject":"peer","subject_kind":"ip","conditions":[{"field":"result","text":"denied"}]}
    ;
    try s.tmp.dir.writeFile(.{ .sub_path = "rule.json", .data = rule, .flags = .{ .mode = 0o600 } });
    const setting = try std.fmt.allocPrint(a, "rule_files = [\"{s}/rule.json\"]", .{s.root});
    defer a.free(setting);
    try writeJournalProfileConfig(&s, "source = \"journald\"", setting);
    var run = try s.run();
    defer run.deinit(a);
    try expectFailClosed(&run);
    try expectContains(run.stderr, "InvalidJournalExecutables");
    try expectContains(run.stderr, "nonempty explicit profile");
    try testing.expectError(error.FileNotFound, s.tmp.dir.access("state.bin", .{}));
}

test "integration: journal profile refuses unsafe file and directory origins" {
    try requireJournalProfileHost();
    const a = testing.allocator;
    var s = try Scenario.init(a);
    defer s.deinit();
    const setting = try std.fmt.allocPrint(a, "journal_executables = [\"{s}/origin\"]", .{s.root});
    defer a.free(setting);
    try writeJournalProfileConfig(&s, "source = \"journald\"", setting);
    // Under a non-root runner, file UID alone also makes these unsafe. This
    // proves refusal, not independent coverage of every mode predicate.
    for ([_]posix.mode_t{ 0o777, 0o644 }) |mode| {
        var file = try s.tmp.dir.createFile("origin", .{});
        try file.chmod(mode);
        file.close();
        var run = try s.run();
        defer run.deinit(a);
        try expectFailClosed(&run);
        try expectContains(run.stderr, "UnqualifiedJournalExecutable");
        try testing.expectError(error.FileNotFound, s.tmp.dir.access("state.bin", .{}));
    }
    try s.tmp.dir.deleteFile("origin");
    try s.tmp.dir.makeDir("origin");
    var run = try s.run();
    defer run.deinit(a);
    try expectFailClosed(&run);
    try expectContains(run.stderr, "UnqualifiedJournalExecutable");
    try testing.expectError(error.FileNotFound, s.tmp.dir.access("state.bin", .{}));
}

fn expectJournalStateClosed(s: *Scenario) !void {
    for ([_][]const u8{ "state.bin-wal", "state.bin-shm", "state.bin-journal" }) |name|
        try testing.expectError(error.FileNotFound, s.tmp.dir.access(name, .{}));
}

test "integration: journal profile changed ordering refuses while retaining database contents" {
    try requireJournalProfileHost();
    const a = testing.allocator;
    var s = try Scenario.init(a);
    defer s.deinit();
    // An occupied HTTP port terminates startup after source/state admission,
    // without ingesting the host journal or leaving a daemon behind.
    const addr = try std.net.Address.parseIp4("127.0.0.1", s.metrics_port);
    var holder = try addr.listen(.{ .reuse_address = true });
    defer holder.deinit();
    const original = "journal_executables = [\"/usr/bin/true\", \"/usr/bin/false\"]";
    try writeJournalProfileConfig(&s, "source = \"journald\"", original);
    {
        var run = try s.run();
        defer run.deinit(a);
        try expectFailClosed(&run);
        try expectContains(run.stderr, "native: HTTP listener");
        try expectContains(run.stderr, "AddressInUse");
    }
    try expectJournalStateClosed(&s);
    const before = try s.tmp.dir.readFileAlloc(a, "state.bin", 16 * 1024 * 1024);
    defer a.free(before);
    try writeJournalProfileConfig(&s, "source = \"journald\"", "journal_executables = [\"/usr/bin/false\", \"/usr/bin/true\"]");
    {
        var run = try s.run();
        defer run.deinit(a);
        try expectFailClosed(&run);
        try expectContains(run.stderr, "RetryGenerationMismatch");
    }
    try expectJournalStateClosed(&s);
    const after = try s.tmp.dir.readFileAlloc(a, "state.bin", 16 * 1024 * 1024);
    defer a.free(after);
    try testing.expect(before.len >= 100);
    try testing.expectEqual(before.len, after.len);
    // Store.open commits its application_id pragma before runtime admission.
    // SQLite may advance its two 4-byte header change counters (offsets 24/92;
    // vendor/sqlite/sqlite3.c pager_write_changecounter). Compare every other
    // byte, including all data pages, and require each counter pair to agree.
    try testing.expectEqualSlices(u8, before[24..28], before[92..96]);
    try testing.expectEqualSlices(u8, after[24..28], after[92..96]);
    try testing.expectEqualSlices(u8, before[0..24], after[0..24]);
    try testing.expectEqualSlices(u8, before[28..92], after[28..92]);
    try testing.expectEqualSlices(u8, before[96..], after[96..]);
    try writeJournalProfileConfig(&s, "source = \"journald\"", original);
    var restored = try s.run();
    defer restored.deinit(a);
    try expectFailClosed(&restored);
    try expectContains(restored.stderr, "native: HTTP listener");
    try expectContains(restored.stderr, "AddressInUse");
    try expectNotContains(restored.stderr, "RetryGenerationMismatch");
}

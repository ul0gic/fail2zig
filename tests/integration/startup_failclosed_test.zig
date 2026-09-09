// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const builtin = @import("builtin");
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

fn watchdog(pid: posix.pid_t, done: *std.atomic.Value(bool)) void {
    var waited: u64 = 0;
    while (waited < watchdog_timeout_ms) : (waited += 50) {
        if (done.load(.acquire)) return;
        std.time.sleep(50 * std.time.ns_per_ms);
    }
    posix.kill(pid, posix.SIG.KILL) catch {};
}

fn runDaemon(a: std.mem.Allocator, argv: []const []const u8) !Run {
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
    try testing.expectEqual(@as(?u8, 1), run.exitCode());
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
        const text = try std.fmt.allocPrint(self.a,
            \\[global]
            \\socket_path = "{s}"
            \\state_file = "{s}/state.bin"
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
            \\{s}
            \\logpath = ["{s}"]
            \\
        , .{ socket_path, self.root, self.metrics_port, source_line, self.log_path });
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

    const http_cause = try std.fmt.allocPrint(a, "http: init on 127.0.0.1:{d} failed", .{s.metrics_port});
    defer a.free(http_cause);
    if (std.os.linux.geteuid() == 0) {
        try expectContains(r.stderr, http_cause);
    } else if (std.mem.indexOf(u8, r.stderr, http_cause) == null) {
        try expectContains(r.stderr, "refusing to run unprotected");
    }
}

test "integration: fail-closed (c) world-writable config exits 1 naming the mode and the fix, no trace" {
    const a = testing.allocator;
    var s = try Scenario.init(a);
    defer s.deinit();

    const sock = try s.defaultSocketPath();
    defer a.free(sock);
    const text = try s.writeConfig(sock, "source = \"file\"", 0o666);
    defer a.free(text);

    var r = try s.run();
    defer r.deinit(a);

    try expectFailClosed(&r);
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
        try expectFailClosed(&r);
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

test "integration: fail-closed (d) backend = \"bogus\" exits 1 with path:line:col, key and section, no trace" {
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

    try expectFailClosed(&r);
    const position = try std.fmt.allocPrint(a, "config: {s}:{d}:11: InvalidValue", .{ s.config_path, line });
    defer a.free(position);
    try expectContains(r.stderr, position);
    try expectContains(r.stderr, "(key 'backend' in [jails.sshd])");
}

test "integration: fail-closed helper: trace detector matches Zig frame lines and nothing else" {
    try testing.expect(hasErrorReturnTrace("error: AddressInUse\n/x/main.zig:3:23: 0x10ddf13 in main (fail2zig)\n"));
    try testing.expect(hasErrorReturnTrace("... error return trace ..."));
    try testing.expect(!hasErrorReturnTrace("error: http: init on 127.0.0.1:9100 failed: AddressInUse\n"));
    try testing.expect(!hasErrorReturnTrace("config: /etc/fail2zig/config.toml:37:1: UnknownKey (key 'x' in [global])\n"));
    try testing.expect(!hasErrorReturnTrace("0x in nothing"));
}

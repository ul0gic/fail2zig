// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

const max_output_bytes: usize = 1 << 20;
const command_timeout_ms: u64 = 6_000;
const confirmation_timeout_ms: u64 = 7_000;
const tcp_probe_timeout_ms: i32 = 300;
const test_port: u16 = 18081;

const Run = struct {
    term: std.process.Child.Term,
    stdout: []u8,
    stderr: []u8,

    fn deinit(self: *Run, a: std.mem.Allocator) void {
        a.free(self.stdout);
        a.free(self.stderr);
        self.* = undefined;
    }

    fn exitCode(self: *const Run) ?u8 {
        return switch (self.term) {
            .Exited => |code| code,
            else => null,
        };
    }
};

const Response = struct {
    run: Run,
    parsed: std.json.Parsed(std.json.Value),

    fn deinit(self: *Response, a: std.mem.Allocator) void {
        self.parsed.deinit();
        self.run.deinit(a);
        self.* = undefined;
    }
};

fn watchdog(pid: posix.pid_t, done: *std.atomic.Value(bool), timeout_ms: u64) void {
    var waited: u64 = 0;
    while (waited < timeout_ms) : (waited += 25) {
        if (done.load(.acquire)) return;
        std.Thread.sleep(25 * std.time.ns_per_ms);
    }
    posix.kill(pid, posix.SIG.KILL) catch {};
}

fn runBounded(a: std.mem.Allocator, argv: []const []const u8, timeout_ms: u64) !Run {
    var child = std.process.Child.init(argv, a);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    try child.spawn();
    errdefer {
        _ = child.kill() catch {};
        _ = child.wait() catch {};
    }

    var done = std.atomic.Value(bool).init(false);
    const guard = try std.Thread.spawn(.{}, watchdog, .{ child.id, &done, timeout_ms });
    defer {
        done.store(true, .release);
        guard.join();
    }

    var out: std.ArrayListUnmanaged(u8) = .{};
    errdefer out.deinit(a);
    var err_out: std.ArrayListUnmanaged(u8) = .{};
    errdefer err_out.deinit(a);
    try child.collectOutput(a, &out, &err_out, max_output_bytes);
    const term = try child.wait();

    return .{
        .term = term,
        .stdout = try out.toOwnedSlice(a),
        .stderr = try err_out.toOwnedSlice(a),
    };
}

fn printArgv(argv: []const []const u8) void {
    std.debug.print("command=", .{});
    for (argv, 0..) |arg, i| {
        std.debug.print("{s}{s}", .{ if (i == 0) "" else " ", arg });
    }
    std.debug.print("\n", .{});
}

fn runExpected(a: std.mem.Allocator, argv: []const []const u8) !void {
    var result = try runBounded(a, argv, command_timeout_ms);
    defer result.deinit(a);
    if (result.exitCode() != 0) {
        printArgv(argv);
        std.debug.print("exit={?} stdout={s}\nstderr={s}\n", .{
            result.exitCode(),
            std.mem.trim(u8, result.stdout, " \t\r\n"),
            std.mem.trim(u8, result.stderr, " \t\r\n"),
        });
        return error.CommandFailed;
    }
}

const Client = struct {
    a: std.mem.Allocator,
    executable: []const u8,
    socket_path: []const u8,

    fn callWithReport(self: Client, args: []const []const u8, report: bool) !Response {
        var argv = std.ArrayList([]const u8).init(self.a);
        defer argv.deinit();
        try argv.appendSlice(&.{ self.executable, "--socket", self.socket_path, "--timeout", "5000", "--output", "json" });
        try argv.appendSlice(args);

        var result = try runBounded(self.a, argv.items, command_timeout_ms);
        errdefer result.deinit(self.a);
        if (report) {
            printArgv(argv.items);
            std.debug.print("exit={?} stdout={s}\n", .{
                result.exitCode(),
                std.mem.trim(u8, result.stdout, " \t\r\n"),
            });
            if (result.stderr.len != 0) {
                std.debug.print("stderr={s}\n", .{std.mem.trim(u8, result.stderr, " \t\r\n")});
            }
        }
        if (result.exitCode() != 0) return error.ClientCommandFailed;
        const parsed = try std.json.parseFromSlice(std.json.Value, self.a, result.stdout, .{ .max_value_len = max_output_bytes });
        return .{ .run = result, .parsed = parsed };
    }

    fn call(self: Client, args: []const []const u8) !Response {
        return self.callWithReport(args, true);
    }

    fn discard(self: Client, args: []const []const u8) !void {
        var response = try self.call(args);
        defer response.deinit(self.a);
    }

    fn expectListCount(self: Client, args: []const []const u8, expected: usize) !void {
        var response = try self.call(args);
        defer response.deinit(self.a);
        const count = switch (response.parsed.value) {
            .array => |array| array.items.len,
            else => return error.ExpectedJsonArray,
        };
        if (count != expected) {
            std.debug.print("FAIL list count: expected={d} actual={d}\n", .{ expected, count });
            return error.UnexpectedListCount;
        }
    }

    fn waitListCount(self: Client, args: []const []const u8, expected: usize) !void {
        var timer = try std.time.Timer.start();
        while (timer.read() < confirmation_timeout_ms * std.time.ns_per_ms) {
            var response = self.callWithReport(args, false) catch {
                std.Thread.sleep(50 * std.time.ns_per_ms);
                continue;
            };
            defer response.deinit(self.a);
            if (response.parsed.value == .array and response.parsed.value.array.items.len == expected) {
                return self.expectListCount(args, expected);
            }
            std.Thread.sleep(50 * std.time.ns_per_ms);
        }
        return self.expectListCount(args, expected);
    }

    fn expectInteger(self: Client, args: []const []const u8, field: []const u8, expected: i64) !void {
        var response = try self.call(args);
        defer response.deinit(self.a);
        const object = switch (response.parsed.value) {
            .object => |object| object,
            else => return error.ExpectedJsonObject,
        };
        const value = object.get(field) orelse return error.MissingJsonField;
        const actual = switch (value) {
            .integer => |integer| integer,
            else => return error.ExpectedJsonInteger,
        };
        if (actual != expected) {
            std.debug.print("FAIL field {s}: expected={d} actual={d}\n", .{ field, expected, actual });
            return error.UnexpectedJsonInteger;
        }
    }

    fn waitInteger(self: Client, args: []const []const u8, field: []const u8, expected: i64) !void {
        var timer = try std.time.Timer.start();
        while (timer.read() < confirmation_timeout_ms * std.time.ns_per_ms) {
            var response = self.callWithReport(args, false) catch {
                std.Thread.sleep(50 * std.time.ns_per_ms);
                continue;
            };
            defer response.deinit(self.a);
            const value = switch (response.parsed.value) {
                .object => |object| object.get(field),
                else => null,
            };
            if (value) |candidate| if (candidate == .integer and candidate.integer == expected) {
                return self.expectInteger(args, field, expected);
            };
            std.Thread.sleep(50 * std.time.ns_per_ms);
        }
        return self.expectInteger(args, field, expected);
    }

    fn expectString(self: Client, args: []const []const u8, field: []const u8, expected: []const u8) !void {
        var response = try self.call(args);
        defer response.deinit(self.a);
        const object = switch (response.parsed.value) {
            .object => |object| object,
            else => return error.ExpectedJsonObject,
        };
        const value = object.get(field) orelse return error.MissingJsonField;
        if (value != .string) return error.ExpectedJsonString;
        if (!std.mem.eql(u8, value.string, expected)) return error.UnexpectedJsonString;
    }

    fn waitString(self: Client, args: []const []const u8, field: []const u8, expected: []const u8) !void {
        var timer = try std.time.Timer.start();
        while (timer.read() < confirmation_timeout_ms * std.time.ns_per_ms) {
            var response = self.callWithReport(args, false) catch {
                std.Thread.sleep(50 * std.time.ns_per_ms);
                continue;
            };
            defer response.deinit(self.a);
            const value = switch (response.parsed.value) {
                .object => |object| object.get(field),
                else => null,
            };
            if (value) |candidate| if (candidate == .string and std.mem.eql(u8, candidate.string, expected)) {
                return self.expectString(args, field, expected);
            };
            std.Thread.sleep(50 * std.time.ns_per_ms);
        }
        return self.expectString(args, field, expected);
    }
};

const Daemon = struct {
    a: std.mem.Allocator,
    executable: []const u8,
    config_path: []const u8,
    child: ?std.process.Child = null,

    fn start(self: *Daemon) !void {
        if (self.child != null) return error.DaemonAlreadyRunning;
        var child = std.process.Child.init(&.{ self.executable, "--foreground", "--config", self.config_path }, self.a);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Inherit;
        child.stderr_behavior = .Inherit;
        try child.spawn();
        self.child = child;
    }

    fn stop(self: *Daemon) !void {
        const child = if (self.child) |*value| value else return;
        posix.kill(child.id, posix.SIG.TERM) catch |err| switch (err) {
            error.ProcessNotFound => {},
            else => return err,
        };
        var done = std.atomic.Value(bool).init(false);
        const guard = try std.Thread.spawn(.{}, watchdog, .{ child.id, &done, 5_000 });
        defer {
            done.store(true, .release);
            guard.join();
        }
        _ = try child.wait();
        self.child = null;
    }

    fn deinit(self: *Daemon) void {
        if (self.child) |*child| {
            posix.kill(child.id, posix.SIG.TERM) catch {};
            var done = std.atomic.Value(bool).init(false);
            const guard = std.Thread.spawn(.{}, watchdog, .{ child.id, &done, 5_000 }) catch {
                posix.kill(child.id, posix.SIG.KILL) catch {};
                _ = child.wait() catch {};
                self.child = null;
                return;
            };
            _ = child.wait() catch {};
            done.store(true, .release);
            guard.join();
            self.child = null;
        }
    }
};

const Listener = struct {
    fd: posix.socket_t,
    stop_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    failed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,

    fn init(ip: []const u8) !Listener {
        const address = try std.net.Address.parseIp(ip, test_port);
        const fd = try posix.socket(address.any.family, posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK, 0);
        errdefer posix.close(fd);
        try posix.bind(fd, &address.any, address.getOsSockLen());
        try posix.listen(fd, 16);
        return .{ .fd = fd };
    }

    fn start(self: *Listener) !void {
        if (self.thread != null) return error.ListenerAlreadyStarted;
        self.thread = try std.Thread.spawn(.{}, serve, .{self});
    }

    fn serve(self: *Listener) void {
        while (!self.stop_requested.load(.acquire)) {
            const peer = posix.accept(self.fd, null, null, posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK) catch |err| switch (err) {
                error.WouldBlock => {
                    std.Thread.sleep(10 * std.time.ns_per_ms);
                    continue;
                },
                error.ConnectionAborted, error.ConnectionResetByPeer => continue,
                else => {
                    self.failed.store(true, .release);
                    return;
                },
            };
            posix.close(peer);
        }
    }

    fn deinit(self: *Listener) void {
        self.stop_requested.store(true, .release);
        if (self.thread) |thread| thread.join();
        posix.close(self.fd);
        self.* = undefined;
    }
};

fn expectedBlockedError(err: anyerror) bool {
    return switch (err) {
        error.BlockedByFirewall,
        error.ConnectionRefused,
        error.ConnectionResetByPeer,
        error.ConnectionTimedOut,
        error.NetworkUnreachable,
        error.PermissionDenied,
        => true,
        else => false,
    };
}

fn tcpConnects(source_ip: ?[]const u8, target_ip: []const u8, port: u16) !bool {
    const target = try std.net.Address.parseIp(target_ip, port);
    const fd = try posix.socket(target.any.family, posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK, 0);
    defer posix.close(fd);
    if (source_ip) |source_text| {
        const source = try std.net.Address.parseIp(source_text, 0);
        try posix.bind(fd, &source.any, source.getOsSockLen());
    }

    posix.connect(fd, &target.any, target.getOsSockLen()) catch |err| switch (err) {
        error.WouldBlock, error.ConnectionPending => {},
        else => if (expectedBlockedError(err)) return false else return err,
    };
    var fds = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.OUT, .revents = 0 }};
    if (try posix.poll(&fds, tcp_probe_timeout_ms) == 0) return false;
    posix.getsockoptError(fd) catch |err| {
        if (expectedBlockedError(err)) return false;
        return err;
    };
    return true;
}

fn dialUnix(path: []const u8) !posix.socket_t {
    const fd = try posix.socket(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    errdefer posix.close(fd);
    var address: posix.sockaddr.un = .{ .family = posix.AF.UNIX, .path = undefined };
    if (path.len >= address.path.len) return error.NameTooLong;
    @memcpy(address.path[0..path.len], path);
    address.path[path.len] = 0;
    const length: posix.socklen_t = @intCast(@sizeOf(@TypeOf(address.family)) + path.len + 1);
    try posix.connect(fd, @ptrCast(&address), length);
    return fd;
}

fn waitDaemonReady(socket_path: []const u8, timeout_ms: u64) !void {
    var timer = try std.time.Timer.start();
    while (timer.read() < timeout_ms * std.time.ns_per_ms) {
        if (dialUnix(socket_path)) |fd| {
            posix.close(fd);
            return;
        } else |_| {}
        std.Thread.sleep(25 * std.time.ns_per_ms);
    }
    return error.DaemonDidNotBecomeReady;
}

fn waitConnectivity(source_ip: []const u8, target_ip: []const u8, expected: bool, timeout_ms: u64) !void {
    var timer = try std.time.Timer.start();
    while (timer.read() < timeout_ms * std.time.ns_per_ms) {
        if ((try tcpConnects(source_ip, target_ip, test_port)) == expected) return;
        std.Thread.sleep(100 * std.time.ns_per_ms);
    }
    return error.ConnectivityDidNotSettle;
}

fn require(ok: bool, label: []const u8) !void {
    if (ok) return;
    std.debug.print("FAIL {s}\n", .{label});
    return error.CheckFailed;
}

fn pass(label: []const u8) void {
    std.debug.print("PASS {s}\n", .{label});
}

fn createWorkDir(a: std.mem.Allocator) ![]u8 {
    var attempt: u8 = 0;
    while (attempt < 16) : (attempt += 1) {
        var random: [8]u8 = undefined;
        std.crypto.random.bytes(&random);
        const path = try std.fmt.allocPrint(a, "/tmp/f2z-acceptance-{s}", .{std.fmt.fmtSliceHexLower(&random)});
        std.fs.makeDirAbsolute(path) catch |err| switch (err) {
            error.PathAlreadyExists => {
                a.free(path);
                continue;
            },
            else => return err,
        };
        var dir = try std.fs.openDirAbsolute(path, .{ .iterate = true });
        defer dir.close();
        try dir.chmod(0o700);
        return path;
    }
    return error.TemporaryDirectoryCollision;
}

fn touch(path: []const u8) !void {
    var file = try std.fs.cwd().createFile(path, .{ .truncate = false, .mode = 0o600 });
    file.close();
}

fn appendFailures(path: []const u8) !void {
    var file = try std.fs.cwd().openFile(path, .{ .mode = .write_only });
    defer file.close();
    try file.seekFromEnd(0);
    const writer = file.writer();
    for ([_]u16{ 40001, 40002, 40003 }) |port| {
        try writer.print("Failed password for fixture-user from 192.0.2.42 port {d} ssh2\n", .{port});
    }
}

fn writeConfig(path: []const u8, work: []const u8, auth_log: []const u8, daemon_log: []const u8, backend: []const u8) !void {
    var file = try std.fs.cwd().createFile(path, .{ .truncate = true, .mode = 0o600 });
    defer file.close();
    try file.writer().print(
        \\[global]
        \\native_ingestion = true
        \\log_level = "info"
        \\log_target = "{s}"
        \\socket_path = "{s}/daemon.sock"
        \\state_file = "{s}/state.sqlite"
        \\metrics_enabled = false
        \\firewall = "{s}"
        \\firewall_namespace = "/proc/{d}/ns/net"
        \\[defaults]
        \\enforce = true
        \\maxretry = 3
        \\findtime = 60
        \\bantime = 30
        \\[jails.sshd]
        \\enabled = true
        \\filter = "sshd"
        \\source = "file"
        \\timestamp = "undated"
        \\logpath = ["{s}"]
        \\bantime = 5
        \\[jails.other]
        \\enabled = true
        \\filter = "sshd"
        \\source = "file"
        \\timestamp = "undated"
        \\logpath = ["{s}/other.log"]
        \\bantime = 7
        \\
    , .{ daemon_log, work, work, backend, std.os.linux.getpid(), auth_log, work });
}

fn dumpDaemonLog(a: std.mem.Allocator, path: []const u8) void {
    const bytes = std.fs.cwd().readFileAlloc(a, path, max_output_bytes) catch |err| {
        std.debug.print("daemon_log_unavailable={s}\n", .{@errorName(err)});
        return;
    };
    defer a.free(bytes);
    std.debug.print("daemon_log_begin\n{s}daemon_log_end\n", .{bytes});
}

const Profile = enum { deep, representative, overlap };

fn runOverlapLifecycle(client: Client, daemon: *Daemon) !void {
    try client.discard(&.{ "ban", "192.0.2.42", "--jail", "sshd", "--duration", "20" });
    try client.discard(&.{ "ban", "192.0.2.42", "--jail", "other", "--duration", "40" });
    try client.discard(&.{ "ban", "192.0.2.42", "--jail", "other", "--duration", "40" });
    try client.waitListCount(&.{"list"}, 2);
    try client.waitInteger(&.{"status"}, "active_bans", 2);
    std.Thread.sleep(21 * std.time.ns_per_s);
    try require(!(try tcpConnects("192.0.2.42", "127.0.0.1", test_port)), "short expiry preserves longer overlapping ownership");
    try client.waitListCount(&.{"list"}, 1);
    try daemon.stop();
    try daemon.start();
    try waitDaemonReady(client.socket_path, 8_000);
    try client.waitListCount(&.{ "list", "--jail", "other" }, 1);
    try require(!(try tcpConnects("192.0.2.42", "127.0.0.1", test_port)), "restart restores longer ownership");
    try client.discard(&.{ "unban", "192.0.2.42", "--jail", "other" });
    try require(try tcpConnects("192.0.2.42", "127.0.0.1", test_port), "final unban restores IPv4 TCP");
    try client.expectInteger(&.{"status"}, "active_bans", 0);
    try client.waitString(&.{"status"}, "protection", "active");
    pass("overlapping ownership, duplicate apply, restart and final unban");
}

fn runLifecycle(a: std.mem.Allocator, executable: []const u8, backend: []const u8, profile: Profile) !void {
    const work = try createWorkDir(a);
    defer a.free(work);
    std.debug.print("evidence_dir={s}\n", .{work});

    const auth_log = try std.fs.path.join(a, &.{ work, "auth.log" });
    defer a.free(auth_log);
    const other_log = try std.fs.path.join(a, &.{ work, "other.log" });
    defer a.free(other_log);
    const config_path = try std.fs.path.join(a, &.{ work, "config.toml" });
    defer a.free(config_path);
    const socket_path = try std.fs.path.join(a, &.{ work, "daemon.sock" });
    defer a.free(socket_path);
    const daemon_log = try std.fs.path.join(a, &.{ work, "daemon.log" });
    defer a.free(daemon_log);

    try runExpected(a, &.{ "ip", "link", "set", "lo", "up" });
    try runExpected(a, &.{ "ip", "address", "add", "192.0.2.42/32", "dev", "lo" });
    try runExpected(a, &.{ "ip", "-6", "address", "add", "2001:db8::42/128", "dev", "lo", "nodad" });
    try touch(auth_log);
    try touch(other_log);
    try writeConfig(config_path, work, auth_log, daemon_log, backend);

    var listener4 = try Listener.init("127.0.0.1");
    defer listener4.deinit();
    try listener4.start();
    var listener6 = try Listener.init("::1");
    defer listener6.deinit();
    try listener6.start();

    var daemon: Daemon = .{ .a = a, .executable = executable, .config_path = config_path };
    defer {
        daemon.deinit();
        dumpDaemonLog(a, daemon_log);
    }
    try daemon.start();
    try waitDaemonReady(socket_path, 8_000);

    const client: Client = .{ .a = a, .executable = executable, .socket_path = socket_path };
    try require(try tcpConnects("192.0.2.42", "127.0.0.1", test_port), "baseline IPv4 TCP connectivity");
    pass("baseline TCP connectivity");
    try client.discard(&.{"version"});
    try client.waitString(&.{"status"}, "protection", "active");

    if (profile == .overlap) {
        try runOverlapLifecycle(client, &daemon);
        try require(!listener4.failed.load(.acquire) and !listener6.failed.load(.acquire), "TCP fixture listeners remained healthy");
        pass("focused overlap lifecycle");
        return;
    }

    try appendFailures(auth_log);
    try waitConnectivity("192.0.2.42", "127.0.0.1", false, 3_000);
    pass("automatic fixture ban blocks TCP");
    try client.waitListCount(&.{"list"}, 1);
    try client.waitListCount(&.{ "list", "--jail", "sshd" }, 1);
    try client.waitInteger(&.{"status"}, "active_bans", 1);

    try waitConnectivity("192.0.2.42", "127.0.0.1", true, 8_000);
    pass("automatic expiry restores TCP");
    try client.waitListCount(&.{"list"}, 0);
    try client.waitString(&.{"status"}, "protection", "active");

    if (profile == .representative) {
        try require(!(try tcpConnects(null, "127.0.0.1", 9100)), "metrics disabled leaves no TCP listener");
        try require(!listener4.failed.load(.acquire) and !listener6.failed.load(.acquire), "TCP fixture listeners remained healthy");
        pass("representative backend lifecycle");
        return;
    }

    try client.discard(&.{ "ban", "192.0.2.42", "--jail", "sshd", "--duration", "8" });
    try require(!(try tcpConnects("192.0.2.42", "127.0.0.1", test_port)), "explicit-duration manual ban blocks IPv4 TCP");
    pass("explicit-duration manual ban blocks TCP");
    try client.waitListCount(&.{"list"}, 1);
    try client.waitInteger(&.{"status"}, "active_bans", 1);
    try waitConnectivity("192.0.2.42", "127.0.0.1", true, 15_000);
    pass("explicit-duration manual expiry restores TCP");
    try client.waitListCount(&.{"list"}, 0);
    try client.waitString(&.{"status"}, "protection", "active");

    const default_ban_started_us = std.time.microTimestamp();
    try client.discard(&.{ "ban", "192.0.2.42", "--jail", "sshd" });
    try client.waitListCount(&.{ "list", "--jail", "sshd" }, 1);
    {
        var listing = try client.call(&.{ "list", "--jail", "sshd" });
        defer listing.deinit(a);
        const items = switch (listing.parsed.value) {
            .array => |array| array.items,
            else => return error.ExpectedJsonArray,
        };
        if (items.len != 1 or items[0] != .object) return error.UnexpectedListCount;
        const expiry = items[0].object.get("expiry_us") orelse return error.MissingJsonField;
        if (expiry != .integer or
            expiry.integer < default_ban_started_us + 4 * std.time.us_per_s or
            expiry.integer > default_ban_started_us + 7 * std.time.us_per_s)
        {
            return error.UnexpectedDefaultExpiry;
        }
    }
    try require(!(try tcpConnects("192.0.2.42", "127.0.0.1", test_port)), "manual jail-default ban blocks IPv4 TCP");
    try client.discard(&.{ "unban", "192.0.2.42", "--jail", "sshd" });
    try require(try tcpConnects("192.0.2.42", "127.0.0.1", test_port), "manual unban restores IPv4 TCP");
    try client.waitListCount(&.{"list"}, 0);
    try client.waitString(&.{"status"}, "protection", "active");
    pass("manual jail default and unban");

    try runOverlapLifecycle(client, &daemon);

    try require(try tcpConnects("2001:db8::42", "::1", test_port), "baseline IPv6 TCP connectivity");
    try client.discard(&.{ "ban", "2001:db8::42", "--jail", "sshd", "--duration", "8" });
    try require(!(try tcpConnects("2001:db8::42", "::1", test_port)), "manual ban blocks IPv6 TCP");
    try client.waitListCount(&.{ "list", "--jail", "sshd" }, 1);
    try waitConnectivity("2001:db8::42", "::1", true, 15_000);
    try client.waitListCount(&.{ "list", "--jail", "sshd" }, 0);
    try client.waitString(&.{"status"}, "protection", "active");
    pass("IPv6 manual ban, listing and expiry");

    try require(!(try tcpConnects(null, "127.0.0.1", 9100)), "metrics disabled leaves no TCP listener");
    pass("metrics disabled: no listener");
    try require(!listener4.failed.load(.acquire) and !listener6.failed.load(.acquire), "TCP fixture listeners remained healthy");
}

fn usage() void {
    std.debug.print("usage: fail2zig-release-lifecycle ABSOLUTE_FAIL2ZIG_PATH (nftables|iptables|ipset) [representative|overlap]\n", .{});
}

fn program(a: std.mem.Allocator) !void {
    if (builtin.os.tag != .linux) return error.LinuxRequired;
    if (std.os.linux.geteuid() != 0) return error.RootRequired;

    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 3 and args.len != 4) {
        usage();
        return error.InvalidArguments;
    }
    const executable = args[1];
    const backend = args[2];
    if (!std.fs.path.isAbsolute(executable)) {
        usage();
        return error.AbsoluteExecutablePathRequired;
    }
    try posix.access(executable, posix.X_OK);
    if (!std.mem.eql(u8, backend, "nftables") and
        !std.mem.eql(u8, backend, "iptables") and
        !std.mem.eql(u8, backend, "ipset"))
    {
        usage();
        return error.UnsupportedBackend;
    }
    const profile: Profile = if (args.len == 3)
        .deep
    else if (std.mem.eql(u8, args[3], "representative"))
        .representative
    else if (std.mem.eql(u8, args[3], "overlap") and std.mem.eql(u8, backend, "nftables"))
        .overlap
    else {
        usage();
        return error.InvalidArguments;
    };
    try runLifecycle(a, executable, backend, profile);
}

pub fn main() void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    program(gpa.allocator()) catch |err| {
        std.debug.print("FAIL release lifecycle: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
}

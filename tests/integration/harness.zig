// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

const shared = @import("shared");
const engine = @import("engine");

const protocol = shared.protocol;

pub const default_daemon_path = "zig-out/bin/fail2zig";
pub const default_client_path = "zig-out/bin/fail2zig-client";

pub const HarnessError = error{
    DaemonBinaryMissing,
    ClientBinaryMissing,
    DaemonFailedToStart,
    DaemonUnavailable,
    SocketNeverAppeared,
    TimedOut,
    UnexpectedResponse,
    ConfigWriteFailed,
    OutOfMemory,
    NotRoot,
};

pub const JailSpec = struct {
    name: []const u8 = "sshd",
    filter: []const u8 = "sshd",
    maxretry: u32 = 3,
    findtime: u64 = 600,
    bantime: u64 = 60,
};

pub const Options = struct {
    daemon_path: []const u8 = default_daemon_path,
    client_path: []const u8 = default_client_path,
    jail: JailSpec = .{},
    startup_timeout_ms: u64 = 3_000,
    metrics_port: u16 = 0,
    spawn_daemon: bool = true,
    require_root: bool = false,
};

pub const Harness = struct {
    allocator: std.mem.Allocator,
    options: Options,

    tmp: std.testing.TmpDir,
    tmp_abs: []const u8,
    log_path: []const u8,
    config_path: []const u8,
    state_path: []const u8,
    socket_path: []const u8,
    pid_path: []const u8,

    child: ?std.process.Child = null,
    metrics_port: u16,

    pub fn init(allocator: std.mem.Allocator, options: Options) !Harness {
        if (builtin.os.tag != .linux) return error.SkipZigTest;

        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();

        var abs_buf: [std.fs.max_path_bytes]u8 = undefined;
        const abs_slice = try tmp.dir.realpath(".", &abs_buf);
        const tmp_abs = try allocator.dupe(u8, abs_slice);
        errdefer allocator.free(tmp_abs);

        const log_path = try std.fmt.allocPrint(allocator, "{s}/auth.log", .{tmp_abs});
        errdefer allocator.free(log_path);
        const config_path = try std.fmt.allocPrint(allocator, "{s}/config.toml", .{tmp_abs});
        errdefer allocator.free(config_path);
        const state_path = try std.fmt.allocPrint(allocator, "{s}/state.bin", .{tmp_abs});
        errdefer allocator.free(state_path);
        const socket_path = try std.fmt.allocPrint(allocator, "{s}/sock/fail2zig.sock", .{tmp_abs});
        errdefer allocator.free(socket_path);
        const pid_path = try std.fmt.allocPrint(allocator, "{s}/fail2zig.pid", .{tmp_abs});
        errdefer allocator.free(pid_path);

        {
            var f = try std.fs.cwd().createFile(log_path, .{ .truncate = true });
            f.close();
        }

        var port = options.metrics_port;
        if (port == 0) {
            const h = std.hash.Wyhash.hash(0, tmp_abs);
            port = @as(u16, @intCast(49152 + (h % 16384)));
        }

        const h: Harness = .{
            .allocator = allocator,
            .options = options,
            .tmp = tmp,
            .tmp_abs = tmp_abs,
            .log_path = log_path,
            .config_path = config_path,
            .state_path = state_path,
            .socket_path = socket_path,
            .pid_path = pid_path,
            .child = null,
            .metrics_port = port,
        };

        return h;
    }

    pub fn deinit(self: *Harness) void {
        if (self.child) |*c| {
            _ = c.kill() catch {};
            self.child = null;
        }

        self.allocator.free(self.log_path);
        self.allocator.free(self.config_path);
        self.allocator.free(self.state_path);
        self.allocator.free(self.socket_path);
        self.allocator.free(self.pid_path);
        self.allocator.free(self.tmp_abs);
        self.tmp.cleanup();
        self.* = undefined;
    }

    pub fn writeConfig(self: *Harness) HarnessError!void {
        var f = std.fs.cwd().createFile(self.config_path, .{ .truncate = true, .mode = 0o640 }) catch {
            return error.ConfigWriteFailed;
        };
        defer f.close();
        f.chmod(0o640) catch return error.ConfigWriteFailed;
        const w = f.writer();

        w.print(
            \\[global]
            \\log_level = "info"
            \\pid_file = "{s}"
            \\socket_path = "{s}"
            \\state_file = "{s}"
            \\memory_ceiling_mb = 64
            \\metrics_bind = "127.0.0.1"
            \\metrics_port = {d}
            \\
            \\[defaults]
            \\bantime = {d}
            \\findtime = {d}
            \\maxretry = {d}
            \\
            \\[jails.{s}]
            \\enabled = true
            \\filter = "{s}"
            \\logpath = ["{s}"]
            \\maxretry = {d}
            \\findtime = {d}
            \\bantime = {d}
            \\
        ,
            .{
                self.pid_path,
                self.socket_path,
                self.state_path,
                self.metrics_port,
                self.options.jail.bantime,
                self.options.jail.findtime,
                self.options.jail.maxretry,
                self.options.jail.name,
                self.options.jail.filter,
                self.log_path,
                self.options.jail.maxretry,
                self.options.jail.findtime,
                self.options.jail.bantime,
            },
        ) catch return error.ConfigWriteFailed;
    }

    pub fn startDaemon(self: *Harness) HarnessError!void {
        std.fs.cwd().access(self.options.daemon_path, .{}) catch {
            return error.DaemonBinaryMissing;
        };

        var argv = [_][]const u8{
            self.options.daemon_path,
            "--foreground",
            "--config",
            self.config_path,
        };

        var child = std.process.Child.init(&argv, self.allocator);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Ignore;
        child.stderr_behavior = .Inherit;
        child.spawn() catch {
            return error.DaemonFailedToStart;
        };
        self.child = child;

        self.waitForSocket(self.options.startup_timeout_ms) catch |err| switch (err) {
            error.SocketNeverAppeared => {
                if (self.child) |*c| {
                    const term = c.wait() catch return error.DaemonUnavailable;
                    self.child = null;
                    _ = term;
                    return error.DaemonUnavailable;
                }
                return error.DaemonUnavailable;
            },
            else => return err,
        };
    }

    pub fn stopDaemon(self: *Harness) !std.process.Child.Term {
        const c = if (self.child) |*cc| cc else return .{ .Exited = 0 };
        posix.kill(c.id, posix.SIG.TERM) catch {};
        const term = try c.wait();
        self.child = null;
        return term;
    }

    pub fn writeLine(self: *Harness, line: []const u8) !void {
        var f = try std.fs.cwd().openFile(self.log_path, .{ .mode = .write_only });
        defer f.close();
        try f.seekFromEnd(0);
        try f.writeAll(line);
        if (line.len == 0 or line[line.len - 1] != '\n') {
            try f.writeAll("\n");
        }
    }

    pub fn waitForBan(self: *Harness, ip: shared.IpAddress, timeout_ms: u64) HarnessError!void {
        var waited: u64 = 0;
        const step_ms: u64 = 25;
        while (waited < timeout_ms) : (waited += step_ms) {
            const active = self.queryActiveBans() catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {
                    std.time.sleep(step_ms * std.time.ns_per_ms);
                    continue;
                },
            };
            if (active > 0) {
                const found = self.queryListContains(ip) catch false;
                if (found) return;
            }
            std.time.sleep(step_ms * std.time.ns_per_ms);
        }
        return error.TimedOut;
    }

    pub fn waitForSocket(self: *Harness, timeout_ms: u64) HarnessError!void {
        var waited: u64 = 0;
        const step_ms: u64 = 10;
        while (waited < timeout_ms) : (waited += step_ms) {
            if (std.fs.cwd().access(self.socket_path, .{})) |_| {
                if (dialOnce(self.socket_path)) |fd| {
                    posix.close(fd);
                    return;
                } else |_| {}
            } else |_| {}
            std.time.sleep(step_ms * std.time.ns_per_ms);
        }
        return error.SocketNeverAppeared;
    }

    pub fn sendCommand(self: *Harness, cmd: shared.Command) HarnessError![]const u8 {
        const sock = dialOnce(self.socket_path) catch |err| switch (err) {
            error.FileNotFound => return error.SocketNeverAppeared,
            else => return error.UnexpectedResponse,
        };
        defer posix.close(sock);

        var wire: [4096]u8 = undefined;
        var ws = std.io.fixedBufferStream(&wire);
        protocol.serializeCommand(cmd, ws.writer()) catch return error.UnexpectedResponse;
        const framed = ws.getWritten();
        var written: usize = 0;
        while (written < framed.len) {
            const n = posix.write(sock, framed[written..]) catch return error.UnexpectedResponse;
            if (n == 0) return error.UnexpectedResponse;
            written += n;
        }

        var rbuf: [1 << 16]u8 = undefined;
        var total: usize = 0;
        var attempts: u32 = 0;
        while (attempts < 200) : (attempts += 1) {
            const n = posix.read(sock, rbuf[total..]) catch |err| switch (err) {
                error.WouldBlock => {
                    std.time.sleep(5 * std.time.ns_per_ms);
                    continue;
                },
                else => return error.UnexpectedResponse,
            };
            if (n == 0) break;
            total += n;
            if (total >= 4) {
                const payload_size = std.mem.readInt(u32, rbuf[0..4], .little);
                if (total >= 4 + payload_size) break;
            }
        }
        if (total < 5) return error.UnexpectedResponse;

        var rs = std.io.fixedBufferStream(rbuf[0..total]);
        const resp = protocol.deserializeResponse(rs.reader(), self.allocator) catch {
            return error.UnexpectedResponse;
        };
        return switch (resp) {
            .ok => |o| o.payload,
            .err => |e| {
                self.allocator.free(e.message);
                return error.UnexpectedResponse;
            },
        };
    }

    pub fn queryStatus(self: *Harness) HarnessError![]const u8 {
        return self.sendCommand(.{ .status = {} });
    }

    pub fn queryList(self: *Harness) HarnessError![]const u8 {
        return self.sendCommand(.{ .list = .{ .jail = null } });
    }

    pub fn unban(self: *Harness, ip: shared.IpAddress) HarnessError![]const u8 {
        return self.sendCommand(.{ .unban = .{ .ip = ip, .jail = null } });
    }

    fn queryActiveBans(self: *Harness) HarnessError!u32 {
        const payload = try self.queryStatus();
        defer self.allocator.free(payload);
        return parseJsonUintField(payload, "active_bans") orelse 0;
    }

    pub fn queryListContains(self: *Harness, ip: shared.IpAddress) HarnessError!bool {
        const payload = try self.queryList();
        defer self.allocator.free(payload);
        var ipbuf: [64]u8 = undefined;
        const ip_str = std.fmt.bufPrint(&ipbuf, "{}", .{ip}) catch return error.UnexpectedResponse;
        return std.mem.indexOf(u8, payload, ip_str) != null;
    }

    pub fn expectRoot() HarnessError!void {
        const geteuid_rc = std.os.linux.geteuid();
        if (geteuid_rc != 0) return error.NotRoot;
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

pub fn parseJsonUintField(json: []const u8, field: []const u8) ?u32 {
    var key_buf: [64]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buf, "\"{s}\":", .{field}) catch return null;
    const start_idx = std.mem.indexOf(u8, json, key) orelse return null;
    var i: usize = start_idx + key.len;
    var result: u32 = 0;
    var seen_digit = false;
    while (i < json.len) : (i += 1) {
        const c = json[i];
        if (c >= '0' and c <= '9') {
            seen_digit = true;
            result = result * 10 + @as(u32, c - '0');
        } else break;
    }
    return if (seen_digit) result else null;
}

const testing = std.testing;

test "harness: init + deinit cleans up without spawning daemon" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var h = try Harness.init(testing.allocator, .{ .spawn_daemon = false });
    defer h.deinit();

    try testing.expect(h.metrics_port >= 49152);

    try std.fs.cwd().access(h.log_path, .{});
}

test "harness: writeConfig emits a file the native parser accepts" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var h = try Harness.init(testing.allocator, .{ .spawn_daemon = false });
    defer h.deinit();

    try h.writeConfig();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const cfg = try engine.config_mod.Config.loadFile(arena.allocator(), h.config_path);

    try testing.expectEqual(@as(usize, 1), cfg.jails.len);
    try testing.expectEqualStrings("sshd", cfg.jails[0].name);
    try testing.expectEqual(@as(u32, 3), cfg.jails[0].maxretry.?);
    try testing.expectEqual(@as(u64, 600), cfg.jails[0].findtime.?);
    try testing.expectEqual(@as(u64, 60), cfg.jails[0].bantime.?);
    try testing.expectEqual(@as(usize, 1), cfg.jails[0].logpath.len);
    try testing.expectEqualStrings(h.log_path, cfg.jails[0].logpath[0]);
}

test "harness: writeLine appends and round-trips through the filesystem" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var h = try Harness.init(testing.allocator, .{ .spawn_daemon = false });
    defer h.deinit();

    try h.writeLine("line without newline");
    try h.writeLine("second line\n");
    try h.writeLine("third\n");

    const contents = try std.fs.cwd().readFileAlloc(testing.allocator, h.log_path, 4096);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings(
        "line without newline\nsecond line\nthird\n",
        contents,
    );
}

test "harness: parseJsonUintField extracts expected value" {
    const doc = "{\"version\":\"test\",\"active_bans\":7,\"jail_count\":1}";
    try testing.expectEqual(@as(?u32, 7), parseJsonUintField(doc, "active_bans"));
    try testing.expectEqual(@as(?u32, 1), parseJsonUintField(doc, "jail_count"));
    try testing.expectEqual(@as(?u32, null), parseJsonUintField(doc, "missing"));
    try testing.expectEqual(@as(?u32, null), parseJsonUintField(doc, "version"));
}

test "harness: HarnessError includes the documented skip reasons" {
    const names = @typeInfo(HarnessError).error_set.?;
    var saw_unavailable = false;
    var saw_binary_missing = false;
    var saw_not_root = false;
    inline for (names) |e| {
        if (std.mem.eql(u8, e.name, "DaemonUnavailable")) saw_unavailable = true;
        if (std.mem.eql(u8, e.name, "DaemonBinaryMissing")) saw_binary_missing = true;
        if (std.mem.eql(u8, e.name, "NotRoot")) saw_not_root = true;
    }
    try testing.expect(saw_unavailable);
    try testing.expect(saw_binary_missing);
    try testing.expect(saw_not_root);
}

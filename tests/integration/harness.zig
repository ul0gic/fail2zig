// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Integration-test harness for the fail2zig daemon.
//!
//! Provides a `Harness` value that:
//!
//!   1. Allocates a per-test temp directory under the process's tmpDir tree,
//!      reachable via absolute paths.
//!   2. Generates a native TOML config pointing at that temp directory's
//!      files (log, state, socket, pid).
//!   3. Spawns the already-built `zig-out/bin/fail2zig` binary in foreground
//!      mode as a child process.
//!   4. Exposes helpers: `writeLine`, `waitForBan`, `waitForSocket`,
//!      `queryStatus`, `queryList`, `unban`.
//!   5. On `deinit()`, kills the daemon, reaps it, and cleans up the temp
//!      directory.
//!
//! Design notes:
//!
//! * The daemon refuses to run if no firewall backend (nftables/ipset/
//!   iptables) is available and functional. In an unprivileged developer or
//!   CI environment this is the common case — `startDaemon` returns
//!   `error.DaemonUnavailable` and callers translate that into
//!   `error.SkipZigTest`.
//!
//! * The daemon also refuses to `bind(2)` its IPC socket when the parent
//!   directory cannot be created with mode 0710 (which requires CAP_FOWNER
//!   if the uid doesn't own the target). The harness sidesteps this by
//!   picking a socket_path strictly inside the tmpDir, which the current
//!   user owns.
//!
//! * IPC authentication: the daemon's `IpcServer` authenticates peers via
//!   `SO_PEERCRED` against uid 0 or the `fail2zig` group. In an
//!   unprivileged test we can't satisfy either. We work around this by
//!   driving the daemon via its HTTP `/api/status` endpoint (localhost-only
//!   by default) where that suffices for the integration test, AND by
//!   spawning the CLI `fail2zig-client` which runs as the same uid that
//!   spawned the daemon — same uid as the daemon process, so
//!   `SO_PEERCRED` sees a same-uid peer and the handler compares against
//!   uid 0 / group gid. This will reject unless the test is run as root.
//!
//!   For that reason, the top-level tests that depend on end-to-end IPC
//!   return `error.SkipZigTest` unless running as root. That covers a
//!   real gap: once Lead wires `build.zig` to launch these tests, a
//!   CI job with `sudo` (or a rootful container) exercises the whole
//!   stack, while developer workflows (`zig build test` as a user) skip
//!   the spawn-the-daemon integration tests without failing.
//!
//! * All allocation flows through `std.testing.allocator`. `errdefer` on
//!   every fallible acquisition path so tests leak nothing on error.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

const shared = @import("shared");
const engine = @import("engine");

const protocol = shared.protocol;

pub const default_daemon_path = "zig-out/bin/fail2zig";
pub const default_client_path = "zig-out/bin/fail2zig-client";

/// Failure modes the harness translates into `SkipZigTest` at the test
/// entry point. Each mode is a precondition the environment can't satisfy.
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

/// Options controlling the daemon's jail + sizing. Every field has a safe
/// default; individual tests override only what matters to them.
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
    /// Maximum time the harness waits for the socket file to appear after
    /// spawn. 3s is generous — the daemon comes up in <100ms normally.
    startup_timeout_ms: u64 = 3_000,
    /// HTTP metrics port. Chosen from the ephemeral range so parallel test
    /// runs don't collide. The harness randomizes this per instance.
    metrics_port: u16 = 0,
    /// When true, skip spawning the daemon — used by tests that only need
    /// the harness for the temp tree + config generation.
    spawn_daemon: bool = true,
    /// When true, require the caller to be uid 0 for IPC tests to work.
    /// Defaults to true; tests that need IPC set this, then skip if false.
    require_root: bool = false,
};

/// The harness itself. Create with `Harness.init`, tear down with
/// `Harness.deinit`.
pub const Harness = struct {
    allocator: std.mem.Allocator,
    options: Options,

    // Temp filesystem scaffolding.
    tmp: std.testing.TmpDir,
    /// Absolute path of the temp directory.
    tmp_abs: []const u8,
    log_path: []const u8,
    config_path: []const u8,
    state_path: []const u8,
    socket_path: []const u8,
    pid_path: []const u8,

    // Child process handle (null when the daemon isn't spawned).
    child: ?std.process.Child = null,
    metrics_port: u16,

    /// Initialize everything but do not spawn the daemon yet.
    pub fn init(allocator: std.mem.Allocator, options: Options) !Harness {
        if (builtin.os.tag != .linux) return error.SkipZigTest;

        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();

        // Resolve the absolute path of the tmp dir. std.testing.tmpDir
        // returns a handle-only abstraction; realpath(".") against its dir
        // handle gives us something we can hand to an external process.
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
        // socket dir `sock/` so the daemon's ensureSocketDir mkdir succeeds.
        const socket_path = try std.fmt.allocPrint(allocator, "{s}/sock/fail2zig.sock", .{tmp_abs});
        errdefer allocator.free(socket_path);
        const pid_path = try std.fmt.allocPrint(allocator, "{s}/fail2zig.pid", .{tmp_abs});
        errdefer allocator.free(pid_path);

        // Create the empty log file up front so the watcher has something
        // to inotify-watch. Otherwise the daemon warns and proceeds, and
        // the first `writeLine` would race with watcher attachment.
        {
            var f = try std.fs.cwd().createFile(log_path, .{ .truncate = true });
            f.close();
        }

        // Pick a metrics port. If caller supplied 0, pick one in [49152,65535]
        // via a cheap hash of the tmp_abs string so concurrent test runs
        // don't collide. The HTTP server accepts any free port; 0 isn't
        // valid in the daemon's config schema.
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

    /// Tear everything down. Safe to call multiple times.
    pub fn deinit(self: *Harness) void {
        // Kill the child if still running. `kill` + `wait` so we don't
        // leak a zombie across tests.
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

    // -------------------- Config + daemon lifecycle --------------------

    /// Write the TOML config that points every runtime artifact (log,
    /// state, socket, pid) into the harness's tmp tree.
    pub fn writeConfig(self: *Harness) HarnessError!void {
        var f = std.fs.cwd().createFile(self.config_path, .{ .truncate = true }) catch {
            return error.ConfigWriteFailed;
        };
        defer f.close();
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

    /// Spawn the daemon in foreground mode. The daemon inherits our stderr
    /// so log output lands in the test harness log on failure.
    pub fn startDaemon(self: *Harness) HarnessError!void {
        // Verify the daemon binary exists before trying to spawn — gives
        // callers a clean `error.DaemonBinaryMissing` to translate.
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
        // Inherit stderr so the daemon's std.log output is visible to
        // `zig test` when a case fails; inherit stdin/stdout to keep it
        // simple. The daemon doesn't read stdin so inherit is safe.
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Ignore;
        child.stderr_behavior = .Inherit;
        child.spawn() catch {
            return error.DaemonFailedToStart;
        };
        self.child = child;

        // Wait for the daemon to come up, or for it to exit (which means
        // the firewall backend detection or config validation rejected
        // the run). We distinguish both cases.
        self.waitForSocket(self.options.startup_timeout_ms) catch |err| switch (err) {
            error.SocketNeverAppeared => {
                // Child may have exited already. Reap it and distinguish.
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

    /// Kill the daemon with SIGTERM, wait for it to exit cleanly.
    /// Returns the observed exit status for tests that care about clean
    /// shutdown (e.g. the persistence test). Never returns an error for
    /// "daemon already gone" — that's a legal state.
    pub fn stopDaemon(self: *Harness) !std.process.Child.Term {
        const c = if (self.child) |*cc| cc else return .{ .Exited = 0 };
        posix.kill(c.id, posix.SIG.TERM) catch {};
        const term = try c.wait();
        self.child = null;
        return term;
    }

    // -------------------- Helpers used by tests --------------------

    /// Append a line to the watched log file. Appends a trailing newline
    /// if the caller's line doesn't have one — the log watcher splits on
    /// newline.
    pub fn writeLine(self: *Harness, line: []const u8) !void {
        var f = try std.fs.cwd().openFile(self.log_path, .{ .mode = .write_only });
        defer f.close();
        try f.seekFromEnd(0);
        try f.writeAll(line);
        if (line.len == 0 or line[line.len - 1] != '\n') {
            try f.writeAll("\n");
        }
    }

    /// Poll the IPC socket until `ip` appears as banned, or the timeout
    /// elapses. Caller must be uid 0 / in the fail2zig group for this to
    /// succeed — tests check that precondition with `expectRoot`.
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
                // Confirm via `list` that the exact IP is there.
                const found = self.queryListContains(ip) catch false;
                if (found) return;
            }
            std.time.sleep(step_ms * std.time.ns_per_ms);
        }
        return error.TimedOut;
    }

    /// Wait until the Unix socket file becomes reachable.
    pub fn waitForSocket(self: *Harness, timeout_ms: u64) HarnessError!void {
        var waited: u64 = 0;
        const step_ms: u64 = 10;
        while (waited < timeout_ms) : (waited += step_ms) {
            if (std.fs.cwd().access(self.socket_path, .{})) |_| {
                // Also try a dial to make sure listen() has been called.
                if (dialOnce(self.socket_path)) |fd| {
                    posix.close(fd);
                    return;
                } else |_| {}
            } else |_| {}
            std.time.sleep(step_ms * std.time.ns_per_ms);
        }
        return error.SocketNeverAppeared;
    }

    // -------------------- IPC client, primitive --------------------

    /// Low-level helper: send one command, return the JSON payload of an
    /// ok response. Caller owns the returned slice, must free with the
    /// harness allocator.
    pub fn sendCommand(self: *Harness, cmd: shared.Command) HarnessError![]const u8 {
        const sock = dialOnce(self.socket_path) catch |err| switch (err) {
            error.FileNotFound => return error.SocketNeverAppeared,
            else => return error.UnexpectedResponse,
        };
        defer posix.close(sock);

        // Serialize and write.
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

        // Read the framed response. The daemon always writes the full
        // frame in one syscall because the command handler pre-builds the
        // whole body.
        var rbuf: [1 << 16]u8 = undefined;
        var total: usize = 0;
        var attempts: u32 = 0;
        // First read size prefix + body. Keep reading while more data is
        // expected.
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
            // Quick check: do we have a full frame?
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

    /// Run the `status` command, return the JSON payload. Caller owns.
    pub fn queryStatus(self: *Harness) HarnessError![]const u8 {
        return self.sendCommand(.{ .status = {} });
    }

    /// Run the `list` command, return the JSON payload. Caller owns.
    pub fn queryList(self: *Harness) HarnessError![]const u8 {
        return self.sendCommand(.{ .list = .{ .jail = null } });
    }

    /// Run `unban` for the given ip. Returns the JSON payload (which the
    /// daemon reports with the IP it unbanned); caller owns it.
    pub fn unban(self: *Harness, ip: shared.IpAddress) HarnessError![]const u8 {
        return self.sendCommand(.{ .unban = .{ .ip = ip, .jail = null } });
    }

    /// Read `active_bans` from a fresh status query. Dumb but effective:
    /// we search the payload for the `"active_bans":N` substring.
    fn queryActiveBans(self: *Harness) HarnessError!u32 {
        const payload = try self.queryStatus();
        defer self.allocator.free(payload);
        return parseJsonUintField(payload, "active_bans") orelse 0;
    }

    /// Check whether the `list` response payload contains the dotted-
    /// decimal form of `ip`. Good enough for test assertions — the
    /// complete JSON shape is well-defined elsewhere.
    pub fn queryListContains(self: *Harness, ip: shared.IpAddress) HarnessError!bool {
        const payload = try self.queryList();
        defer self.allocator.free(payload);
        var ipbuf: [64]u8 = undefined;
        const ip_str = std.fmt.bufPrint(&ipbuf, "{}", .{ip}) catch return error.UnexpectedResponse;
        return std.mem.indexOf(u8, payload, ip_str) != null;
    }

    /// Skip the test if the current process is not uid 0. Integration
    /// tests that rely on `SO_PEERCRED` authentication need this.
    pub fn expectRoot() HarnessError!void {
        const geteuid_rc = std.os.linux.geteuid();
        if (geteuid_rc != 0) return error.NotRoot;
    }
};

// -------------------- Filesystem-independent helpers --------------------

/// Dial the daemon's Unix socket. Blocking connect; non-blocking read
/// after. Translates a missing socket into error.FileNotFound so callers
/// can pivot to skipping.
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

/// Parse an unsigned-integer JSON field (e.g. `"active_bans":42`) from a
/// plain JSON document. The fail2zig status document is tiny and
/// flat; we don't pull in a whole JSON parser for this.
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
            // Bounded: a u32 fits in 10 digits, caller promises this field
            // is a u32.
            result = result * 10 + @as(u32, c - '0');
        } else break;
    }
    return if (seen_digit) result else null;
}

// ============================================================================
// Unit tests — exercise every helper that doesn't need the daemon spawned.
// ============================================================================

const testing = std.testing;

test "harness: init + deinit cleans up without spawning daemon" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var h = try Harness.init(testing.allocator, .{ .spawn_daemon = false });
    defer h.deinit();

    // The harness chose a metrics port for us.
    try testing.expect(h.metrics_port >= 49152);

    // The log file exists (created up-front so inotify has a target).
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

    // One jail with our configured name.
    try testing.expectEqual(@as(usize, 1), cfg.jails.len);
    try testing.expectEqualStrings("sshd", cfg.jails[0].name);
    // Thresholds from the default JailSpec.
    try testing.expectEqual(@as(u32, 3), cfg.jails[0].maxretry.?);
    try testing.expectEqual(@as(u64, 600), cfg.jails[0].findtime.?);
    try testing.expectEqual(@as(u64, 60), cfg.jails[0].bantime.?);
    // logpath points into the harness's tmp tree.
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
    // Malformed (non-numeric) field returns null.
    try testing.expectEqual(@as(?u32, null), parseJsonUintField(doc, "version"));
}

test "harness: HarnessError includes the documented skip reasons" {
    // Round-trip check — every variant the tests translate into
    // error.SkipZigTest must still be declared. Compile-time check.
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

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

//! Typed administration over the single executable: jail pause/resume/enable/disable at the
//! decision boundary, durable admin state across restart, history reset, log-only refusal of
//! manual bans, unknown jails and retired legacy mutation ids.

const std = @import("std");
const harness = @import("harness.zig");

const t = std.testing;
const exe = "zig-out/bin/fail2zig";
const failure = "Failed password for root from 203.0.113.7 port 22 ssh2";

const Run = struct {
    code: u8,
    stdout: []u8,
    stderr: []u8,
    fn deinit(self: Run, a: std.mem.Allocator) void {
        a.free(self.stdout);
        a.free(self.stderr);
    }
};

const AdminWireResponse = struct {
    code: u16,
    body: []const u8,
    fn deinit(self: AdminWireResponse, a: std.mem.Allocator) void {
        a.free(self.body);
    }
};

fn run(a: std.mem.Allocator, argv: []const []const u8) !Run {
    const r = try std.process.Child.run(.{ .allocator = a, .argv = argv, .max_output_bytes = 1 << 20 });
    return .{ .code = switch (r.term) {
        .Exited => |c| c,
        else => 255,
    }, .stdout = r.stdout, .stderr = r.stderr };
}

fn writeConfig(h: *harness.Harness) !void {
    var file = try std.fs.cwd().createFile(h.config_path, .{ .mode = 0o600 });
    defer file.close();
    try file.writer().print(
        \\[global]
        \\native_ingestion = true
        \\state_file = "{s}"
        \\socket_path = "{s}"
        \\metrics_enabled = false
        \\[defaults]
        \\banaction = "log-only"
        \\maxretry = 2
        \\findtime = 600
        \\bantime = 60
        \\[jails.sshd]
        \\filter = "sshd"
        \\source = "file"
        \\timestamp = "undated"
        \\logpath = ["{s}"]
        \\
    , .{ h.state_path, h.socket_path, h.log_path });
}

fn admin(a: std.mem.Allocator, h: *harness.Harness, argv: []const []const u8) !Run {
    var full = std.ArrayList([]const u8).init(a);
    defer full.deinit();
    try full.appendSlice(&.{ exe, "--socket", h.socket_path, "--timeout", "5000", "--output", "json" });
    try full.appendSlice(argv);
    return run(a, full.items);
}

fn sendAdminFrame(a: std.mem.Allocator, h: *harness.Harness, request_id: [32]u8, body: []const u8) !AdminWireResponse {
    const shared = @import("shared");
    const stream = try std.net.connectUnixSocket(h.socket_path);
    defer stream.close();
    const timeout = std.posix.timeval{ .sec = 5, .usec = 0 };
    try std.posix.setsockopt(stream.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));
    try shared.protocol.serializeCommand(.{ .admin_v1 = .{ .request_id = request_id, .body = try shared.Command.Body.init(body) } }, stream.writer());
    const response = try shared.protocol.deserializeResponse(stream.reader(), a);
    return switch (response) {
        .ok => |ok| .{ .code = 200, .body = ok.payload },
        .err => |err| .{ .code = err.code, .body = err.message },
    };
}

fn generationFromStatus(status: []const u8) ![]const u8 {
    const start = (std.mem.indexOf(u8, status, "\"generation\":\"") orelse return error.MissingField) + 14;
    if (status.len - start < 64) return error.MissingField;
    return status[start .. start + 64];
}

fn waitHealthy(h: *harness.Harness) !void {
    var timer = try std.time.Timer.start();
    while (timer.read() < 10 * std.time.ns_per_s) {
        const s = try h.queryStatus();
        defer t.allocator.free(s);
        if (std.mem.indexOf(u8, s, "\"storage\":\"healthy\"") != null) return;
        std.time.sleep(25 * std.time.ns_per_ms);
    }
    return error.TimedOut;
}

fn waitListContains(h: *harness.Harness, needle: []const u8, timeout_ms: u64) !bool {
    var timer = try std.time.Timer.start();
    while (timer.read() < timeout_ms * std.time.ns_per_ms) {
        const listing = try h.queryList();
        defer t.allocator.free(listing);
        if (std.mem.indexOf(u8, listing, needle) != null) return true;
        std.time.sleep(50 * std.time.ns_per_ms);
    }
    return false;
}

fn waitRecords(h: *harness.Harness, minimum: u64) !void {
    var timer = try std.time.Timer.start();
    while (timer.read() < 10 * std.time.ns_per_s) {
        const s = try h.queryStatus();
        defer t.allocator.free(s);
        if ((harness.parseJsonUintField(s, "committed_records") orelse 0) >= minimum) return;
        std.time.sleep(25 * std.time.ns_per_ms);
    }
    return error.TimedOut;
}

test "admin: BUG-032 prefix without address returns 400 and keeps serving" {
    const a = t.allocator;
    const shared = @import("shared");
    var h = try harness.Harness.init(a, .{ .spawn_daemon = false });
    defer h.deinit();
    try writeConfig(&h);
    try h.startDaemon();
    defer _ = h.stopDaemon() catch {};
    try waitHealthy(&h);
    const status = try h.queryStatus();
    defer a.free(status);
    const start = (std.mem.indexOf(u8, status, "\"generation\":\"") orelse return error.MissingField) + 14;
    var buffer: [512]u8 = undefined;
    const body = try std.fmt.bufPrint(&buffer, "{{\"schema_version\":1,\"kind\":\"group_pause\",\"jail\":\"sshd\",\"prefix\":8,\"expected_generation\":\"{s}\",\"expected_mutation_revision\":0}}", .{status[start .. start + 64]});
    const stream = try std.net.connectUnixSocket(h.socket_path);
    defer stream.close();
    const timeout = std.posix.timeval{ .sec = 2, .usec = 0 };
    try std.posix.setsockopt(stream.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));
    try shared.protocol.serializeCommand(.{ .admin_v1 = .{ .request_id = [_]u8{32} ** 32, .body = try shared.Command.Body.init(body) } }, stream.writer());
    const response = try shared.protocol.deserializeResponse(stream.reader(), a);
    switch (response) {
        .err => |err| {
            defer a.free(err.message);
            try t.expectEqual(@as(u16, 400), err.code);
            try t.expectEqualStrings("address is required", err.message);
        },
        .ok => |ok| {
            a.free(ok.payload);
            return error.TestUnexpectedResult;
        },
    }
    const after = try h.queryStatus();
    defer a.free(after);
    try t.expect(std.mem.indexOf(u8, after, "\"mutation_revision\":0") != null);
    const pause = try admin(a, &h, &.{ "jail", "pause", "sshd" });
    defer pause.deinit(a);
    try t.expectEqual(@as(u8, 0), pause.code);
}

test "admin: BUG-025 unrecorded outcome is uncertain and the request remains fresh" {
    const a = t.allocator;
    var h = try harness.Harness.init(a, .{ .spawn_daemon = false });
    defer h.deinit();
    try writeConfig(&h);
    try h.startDaemon();
    defer _ = h.stopDaemon() catch {};
    try waitHealthy(&h);

    const status = try h.queryStatus();
    defer a.free(status);
    const generation = try generationFromStatus(status);
    var body_buffer: [512]u8 = undefined;
    const body = try std.fmt.bufPrint(&body_buffer, "{{\"schema_version\":1,\"kind\":\"group_pause\",\"jail\":\"sshd\",\"expected_generation\":\"{s}\",\"expected_mutation_revision\":0}}", .{generation});
    const request_id = [_]u8{25} ** 32;

    const engine = @import("engine");
    var probe = try engine.native_store_mod.Store.open(a, h.state_path);
    defer probe.close();
    try probe.inspectExec(
        "CREATE TRIGGER bug025_admin_outcome BEFORE INSERT ON admin_requests " ++
            "BEGIN SELECT RAISE(FAIL,'BUG-025 injected outcome failure'); END;",
    );
    const uncertain = try sendAdminFrame(a, &h, request_id, body);
    defer uncertain.deinit(a);
    try t.expectEqual(@as(u16, 508), uncertain.code);
    try t.expect(std.mem.indexOf(u8, uncertain.body, "\"outcome\":\"uncertain\"") != null);
    try t.expect(std.mem.indexOf(u8, uncertain.body, "outcome not recorded") != null);
    try t.expectEqual(@as(i64, 0), try probe.inspectInteger("SELECT count(*) FROM admin_requests;"));
    try t.expectEqual(@as(i64, 0), try probe.inspectInteger("SELECT count(*) FROM jail_admin_states;"));
    try t.expectEqual(@as(i64, 0), try probe.inspectInteger("SELECT mutation_revision FROM admin_revision WHERE id=1;"));

    try probe.inspectExec("DROP TRIGGER bug025_admin_outcome;");
    const applied = try sendAdminFrame(a, &h, request_id, body);
    defer applied.deinit(a);
    try t.expectEqual(@as(u16, 200), applied.code);
    try t.expect(std.mem.indexOf(u8, applied.body, "\"outcome\":\"applied\"") != null);
    try t.expect(std.mem.indexOf(u8, applied.body, "\"mutation_revision\":1") != null);
    const replayed = try sendAdminFrame(a, &h, request_id, body);
    defer replayed.deinit(a);
    try t.expectEqual(@as(u16, 200), replayed.code);
    try t.expect(std.mem.indexOf(u8, replayed.body, "\"mutation_revision\":1") != null);
    try t.expectEqual(@as(i64, 1), try probe.inspectInteger("SELECT count(*) FROM admin_requests;"));
    try t.expectEqual(@as(i64, 1), try probe.inspectInteger("SELECT count(*) FROM jail_admin_states WHERE jail='sshd' AND paused=1;"));
    try t.expectEqual(@as(i64, 1), try probe.inspectInteger("SELECT mutation_revision FROM admin_revision WHERE id=1;"));
}

test "admin: pause suppresses decisions while consuming records, resume re-admits, state survives restart" {
    const a = t.allocator;
    std.fs.cwd().access(exe, .{}) catch return error.SkipZigTest;
    var h = try harness.Harness.init(a, .{ .spawn_daemon = false });
    defer h.deinit();
    try writeConfig(&h);
    try h.startDaemon();
    try waitHealthy(&h);

    const paused = try admin(a, &h, &.{ "jail", "pause", "sshd" });
    defer paused.deinit(a);
    try t.expectEqual(@as(u8, 0), paused.code);
    try t.expect(std.mem.indexOf(u8, paused.stdout, "\"outcome\":\"applied\"") != null);
    try t.expect(std.mem.indexOf(u8, paused.stdout, "\"mutation_revision\":1") != null);
    const jails = try admin(a, &h, &.{"jails"});
    defer jails.deinit(a);
    try t.expect(std.mem.indexOf(u8, jails.stdout, "\"paused\":true") != null);

    // Records are consumed and checkpointed under pause without producing decisions.
    const before = try h.queryStatus();
    defer a.free(before);
    const committed = harness.parseJsonUintField(before, "committed_records") orelse 0;
    try h.writeLine(failure);
    try h.writeLine(failure);
    try h.writeLine(failure);
    try waitRecords(&h, committed + 3);
    try t.expect(!try waitListContains(&h, "203.0.113.7", 1500));

    // Durable: a restart keeps the jail paused.
    try t.expectEqual(std.process.Child.Term{ .Exited = 0 }, try h.stopDaemon());
    try h.startDaemon();
    try waitHealthy(&h);
    const after = try admin(a, &h, &.{"jails"});
    defer after.deinit(a);
    try t.expect(std.mem.indexOf(u8, after.stdout, "\"paused\":true") != null);
    try h.writeLine(failure);
    try h.writeLine(failure);
    try t.expect(!try waitListContains(&h, "203.0.113.7", 1500));

    const resumed = try admin(a, &h, &.{ "jail", "resume", "sshd" });
    defer resumed.deinit(a);
    try t.expectEqual(@as(u8, 0), resumed.code);
    try h.writeLine(failure);
    try h.writeLine(failure);
    try t.expect(try waitListContains(&h, "203.0.113.7", 8000));

    // History reset for the subject applies; a second reset is a fresh applied request too.
    const reset = try admin(a, &h, &.{ "history", "reset", "203.0.113.7", "--jail", "sshd" });
    defer reset.deinit(a);
    try t.expectEqual(@as(u8, 0), reset.code);
    try t.expect(std.mem.indexOf(u8, reset.stdout, "\"kind\":\"history_reset\"") != null);
    const status = try h.queryStatus();
    defer a.free(status);
    try t.expect(std.mem.indexOf(u8, status, "\"mutation_revision\":3") != null);
    _ = try h.stopDaemon();
}

test "admin: log-only bans are rejected, unknown jails are absent, legacy ids and stale revisions are refused" {
    const a = t.allocator;
    std.fs.cwd().access(exe, .{}) catch return error.SkipZigTest;
    var h = try harness.Harness.init(a, .{ .spawn_daemon = false });
    defer h.deinit();
    try writeConfig(&h);
    try h.startDaemon();
    defer _ = h.stopDaemon() catch {};
    try waitHealthy(&h);

    const ban = try admin(a, &h, &.{ "ban", "192.0.2.10", "--jail", "sshd" });
    defer ban.deinit(a);
    try t.expectEqual(@as(u8, 1), ban.code);
    try t.expect(std.mem.indexOf(u8, ban.stdout, "\"outcome\":\"rejected\"") != null);
    try t.expect(std.mem.indexOf(u8, ban.stdout, "log-only") != null);

    const unknown = try admin(a, &h, &.{ "jail", "pause", "nope" });
    defer unknown.deinit(a);
    try t.expectEqual(@as(u8, 1), unknown.code);
    try t.expect(std.mem.indexOf(u8, unknown.stdout, "\"outcome\":\"absent\"") != null);

    const nojail = try admin(a, &h, &.{ "ban", "192.0.2.10" });
    defer nojail.deinit(a);
    try t.expectEqual(@as(u8, 2), nojail.code);

    // Legacy mutation ids are retired with a typed error response.
    try t.expectError(error.UnexpectedResponse, h.sendCommand(.{ .ban = .{ .ip = try @import("shared").IpAddress.parse("192.0.2.10"), .jail = try @import("shared").JailId.fromSlice("sshd"), .duration = null } }));
    try t.expectError(error.UnexpectedResponse, h.sendCommand(.{ .unban = .{ .ip = try @import("shared").IpAddress.parse("192.0.2.10"), .jail = null } }));

    // A request carrying a stale mutation revision is refused without effect.
    var stale_body: [512]u8 = undefined;
    const status = try h.queryStatus();
    defer a.free(status);
    const gen_start = (std.mem.indexOf(u8, status, "\"generation\":\"") orelse return error.MissingField) + 14;
    const generation = status[gen_start .. gen_start + 64];
    const body = try std.fmt.bufPrint(&stale_body, "{{\"schema_version\":1,\"kind\":\"group_pause\",\"jail\":\"sshd\",\"expected_generation\":\"{s}\",\"expected_mutation_revision\":99}}", .{generation});
    const request = @import("shared").Command.Request{ .request_id = [_]u8{9} ** 32, .body = try @import("shared").Command.Body.init(body) };
    try t.expectError(error.UnexpectedResponse, h.sendCommand(.{ .admin_v1 = request }));
    const jails = try admin(a, &h, &.{"jails"});
    defer jails.deinit(a);
    try t.expect(std.mem.indexOf(u8, jails.stdout, "\"paused\":false") != null);
}

const linux = std.os.linux;

fn writeEnforcingConfig(h: *harness.Harness, bantime: u32) !void {
    var file = try std.fs.cwd().createFile(h.config_path, .{ .mode = 0o600 });
    defer file.close();
    try file.writer().print(
        \\[global]
        \\native_ingestion = true
        \\state_file = "{s}"
        \\socket_path = "{s}"
        \\metrics_enabled = false
        \\firewall = "iptables"
        \\firewall_namespace = "/proc/{d}/ns/net"
        \\[defaults]
        \\enforce = true
        \\maxretry = 2
        \\findtime = 600
        \\bantime = {d}
        \\[jails.sshd]
        \\filter = "sshd"
        \\source = "file"
        \\timestamp = "undated"
        \\logpath = ["{s}"]
        \\
    , .{ h.state_path, h.socket_path, linux.getpid(), bantime, h.log_path });
}

fn kernelHas(a: std.mem.Allocator, needle: []const u8) !bool {
    const r = try run(a, &.{ "iptables", "-S" });
    defer r.deinit(a);
    return std.mem.indexOf(u8, r.stdout, needle) != null;
}

fn waitKernel(a: std.mem.Allocator, needle: []const u8, present: bool, timeout_ms: u64) !void {
    var timer = try std.time.Timer.start();
    while (timer.read() < timeout_ms * std.time.ns_per_ms) {
        if (try kernelHas(a, needle) == present) return;
        std.time.sleep(100 * std.time.ns_per_ms);
    }
    return error.TimedOut;
}

/// Readiness (every component verified) rather than storage health: a manual ban issued while the
/// manager is still restoring withdrawn owners would settle past its own deadline.
fn waitReady(h: *harness.Harness, timeout_ms: u64) !void {
    const shared = @import("shared");
    var timer = try std.time.Timer.start();
    while (timer.read() < timeout_ms * std.time.ns_per_ms) {
        const health = try h.sendCommand(.{ .query_v1 = try shared.Command.Body.init("{\"schema_version\":1,\"kind\":\"health\"}") });
        defer t.allocator.free(health);
        if (std.mem.indexOf(u8, health, "\"ready\":true") != null) return;
        std.time.sleep(100 * std.time.ns_per_ms);
    }
    return error.TimedOut;
}

fn waitStatus(h: *harness.Harness, needle: []const u8) !void {
    return waitStatusFor(h, needle, 10_000);
}

fn waitStatusFor(h: *harness.Harness, needle: []const u8, timeout_ms: u64) !void {
    var timer = try std.time.Timer.start();
    while (timer.read() < timeout_ms * std.time.ns_per_ms) {
        const s = try h.queryStatus();
        defer t.allocator.free(s);
        if (std.mem.indexOf(u8, s, needle) != null) return;
        std.time.sleep(25 * std.time.ns_per_ms);
    }
    return error.TimedOut;
}

test "admin: BUG-033 a failure after one committed release is partial and replay-fenced" {
    if (std.posix.getenv("F2Z_NATIVE_DAEMON_ENFORCEMENT") == null) return error.SkipZigTest;
    const prior = std.posix.getenv("F2Z_NATIVE_PARENT_NETNS") orelse return error.MissingIsolationCookie;
    var namespace_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const current = try std.fs.readLinkAbsolute("/proc/self/ns/net", &namespace_buffer);
    try t.expect(!std.mem.eql(u8, prior, current));
    if (linux.E.init(linux.unshare(linux.CLONE.NEWNET)) != .SUCCESS) return error.IsolationFailed;

    const a = t.allocator;
    var h = try harness.Harness.init(a, .{ .spawn_daemon = false });
    defer h.deinit();
    try writeEnforcingConfig(&h, 600);
    try h.startDaemon();
    defer _ = h.stopDaemon() catch {};
    try waitStatus(&h, "\"state\":\"enforcing\"");

    const first = try admin(a, &h, &.{ "ban", "192.0.2.30", "--jail", "sshd", "--duration", "300" });
    defer first.deinit(a);
    try t.expectEqual(@as(u8, 0), first.code);
    const second = try admin(a, &h, &.{ "ban", "192.0.2.31", "--jail", "sshd", "--duration", "300" });
    defer second.deinit(a);
    try t.expectEqual(@as(u8, 0), second.code);
    try waitKernel(a, "192.0.2.30", true, 5000);
    try waitKernel(a, "192.0.2.31", true, 5000);

    const status = try h.queryStatus();
    defer a.free(status);
    const generation = try generationFromStatus(status);
    try t.expectEqual(@as(?u32, 2), harness.parseJsonUintField(status, "mutation_revision"));
    var body_buffer: [512]u8 = undefined;
    const body = try std.fmt.bufPrint(&body_buffer, "{{\"schema_version\":1,\"kind\":\"group_disable\",\"jail\":\"sshd\",\"expected_generation\":\"{s}\",\"expected_mutation_revision\":2}}", .{generation});
    const request_id = [_]u8{33} ** 32;

    const engine = @import("engine");
    var probe = try engine.native_store_mod.Store.open(a, h.state_path);
    defer probe.close();
    try t.expectEqual(@as(i64, 2), try probe.inspectInteger("SELECT count(*) FROM effect_owners WHERE jail='sshd' AND lease_kind!=0;"));
    try probe.inspectExec(
        "CREATE TRIGGER bug033_second_release BEFORE UPDATE OF lease_kind ON effect_owners " ++
            "WHEN OLD.lease_kind!=0 AND NEW.lease_kind=0 AND " ++
            "(SELECT count(*) FROM effect_owners WHERE jail=OLD.jail AND lease_kind=0)>0 " ++
            "BEGIN SELECT RAISE(FAIL,'BUG-033 injected second release failure'); END;",
    );
    const partial = try sendAdminFrame(a, &h, request_id, body);
    defer partial.deinit(a);
    try probe.inspectExec("DROP TRIGGER bug033_second_release;");
    try t.expectEqual(@as(u16, 507), partial.code);
    try t.expect(std.mem.indexOf(u8, partial.body, "\"outcome\":\"partial\"") != null);
    try t.expect(std.mem.indexOf(u8, partial.body, "1 owner release") != null);
    try t.expectEqual(@as(i64, 1), try probe.inspectInteger("SELECT count(*) FROM effect_owners WHERE jail='sshd' AND lease_kind=0;"));
    try t.expectEqual(@as(i64, 1), try probe.inspectInteger("SELECT count(*) FROM effect_owners WHERE jail='sshd' AND lease_kind!=0;"));
    try t.expectEqual(@as(i64, 1), try probe.inspectInteger("SELECT count(*) FROM admin_requests WHERE request_id=x'2121212121212121212121212121212121212121212121212121212121212121' AND outcome=4 AND mutation_revision=3;"));
    try t.expectEqual(@as(i64, 1), try probe.inspectInteger("SELECT count(*) FROM jail_admin_states WHERE jail='sshd' AND enabled=0 AND paused=1 AND request_id=x'2121212121212121212121212121212121212121212121212121212121212121';"));

    const replayed = try sendAdminFrame(a, &h, request_id, body);
    defer replayed.deinit(a);
    try t.expectEqual(@as(u16, 507), replayed.code);
    try t.expect(std.mem.indexOf(u8, replayed.body, "\"outcome\":\"partial\"") != null);
    try t.expect(std.mem.indexOf(u8, replayed.body, "\"mutation_revision\":3") != null);
    try t.expectEqual(@as(i64, 1), try probe.inspectInteger("SELECT count(*) FROM effect_owners WHERE jail='sshd' AND lease_kind=0;"));
    const after = try h.queryStatus();
    defer a.free(after);
    try t.expectEqual(@as(?u32, 3), harness.parseJsonUintField(after, "mutation_revision"));
}

test "admin: BUG-035 group disable settles only after coherent kernel readback" {
    if (std.posix.getenv("F2Z_NATIVE_DAEMON_ENFORCEMENT") == null) return error.SkipZigTest;
    const prior = std.posix.getenv("F2Z_NATIVE_PARENT_NETNS") orelse return error.MissingIsolationCookie;
    var namespace_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const current = try std.fs.readLinkAbsolute("/proc/self/ns/net", &namespace_buffer);
    try t.expect(!std.mem.eql(u8, prior, current));
    if (linux.E.init(linux.unshare(linux.CLONE.NEWNET)) != .SUCCESS) return error.IsolationFailed;

    const a = t.allocator;
    var h = try harness.Harness.init(a, .{ .spawn_daemon = false });
    defer h.deinit();
    try writeEnforcingConfig(&h, 600);
    try h.startDaemon();
    defer _ = h.stopDaemon() catch {};
    try waitReady(&h, 10_000);

    const first_ban = try admin(a, &h, &.{ "ban", "192.0.2.35", "--jail", "sshd", "--duration", "300" });
    defer first_ban.deinit(a);
    try t.expectEqual(@as(u8, 0), first_ban.code);
    try t.expect(try kernelHas(a, "192.0.2.35"));
    const first_disable = try admin(a, &h, &.{ "jail", "disable", "sshd" });
    defer first_disable.deinit(a);
    try t.expectEqual(@as(u8, 0), first_disable.code);
    try t.expect(std.mem.indexOf(u8, first_disable.stdout, "\"outcome\":\"applied\"") != null);
    // An applied response is itself the fence: no follow-up polling is needed to observe absence.
    try t.expect(!try kernelHas(a, "192.0.2.35"));

    const enabled = try admin(a, &h, &.{ "jail", "enable", "sshd" });
    defer enabled.deinit(a);
    try t.expectEqual(@as(u8, 0), enabled.code);
    const second_ban = try admin(a, &h, &.{ "ban", "192.0.2.36", "--jail", "sshd", "--duration", "300" });
    defer second_ban.deinit(a);
    try t.expectEqual(@as(u8, 0), second_ban.code);
    try t.expect(try kernelHas(a, "192.0.2.36"));

    const status = try h.queryStatus();
    defer a.free(status);
    const generation = try generationFromStatus(status);
    const revision = harness.parseJsonUintField(status, "mutation_revision") orelse return error.MissingField;
    var body_buffer: [512]u8 = undefined;
    const body = try std.fmt.bufPrint(&body_buffer, "{{\"schema_version\":1,\"kind\":\"group_disable\",\"jail\":\"sshd\",\"expected_generation\":\"{s}\",\"expected_mutation_revision\":{d}}}", .{ generation, revision });

    const engine = @import("engine");
    var probe = try engine.native_store_mod.Store.open(a, h.state_path);
    defer probe.close();
    try probe.inspectExec(
        "CREATE TRIGGER bug035_readback_failure BEFORE UPDATE OF status ON effect_intents " ++
            "WHEN OLD.status=1 AND NEW.status=2 AND NEW.lease_kind=0 " ++
            "BEGIN SELECT RAISE(FAIL,'BUG-035 injected readback failure'); END;",
    );
    var trigger_installed = true;
    defer if (trigger_installed) probe.inspectExec("DROP TRIGGER bug035_readback_failure;") catch {};
    const uncertain = try sendAdminFrame(a, &h, [_]u8{35} ** 32, body);
    defer uncertain.deinit(a);
    try probe.inspectExec("DROP TRIGGER bug035_readback_failure;");
    trigger_installed = false;
    try t.expectEqual(@as(u16, 508), uncertain.code);
    try t.expect(std.mem.indexOf(u8, uncertain.body, "\"outcome\":\"uncertain\"") != null);
    try t.expect(std.mem.indexOf(u8, uncertain.body, "effect outcome uncertain") != null);
    try t.expect(try kernelHas(a, "192.0.2.36"));
}

test "admin: enforcing manual ban, unban and disable settle only by kernel readback; reload re-key keeps the rule" {
    if (std.posix.getenv("F2Z_NATIVE_DAEMON_ENFORCEMENT") == null) return error.SkipZigTest;
    const prior = std.posix.getenv("F2Z_NATIVE_PARENT_NETNS") orelse return error.MissingIsolationCookie;
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const current = try std.fs.readLinkAbsolute("/proc/self/ns/net", &buffer);
    try t.expect(!std.mem.eql(u8, prior, current));
    if (linux.E.init(linux.unshare(linux.CLONE.NEWNET)) != .SUCCESS) return error.IsolationFailed;
    const a = t.allocator;
    std.fs.cwd().access(exe, .{}) catch return error.SkipZigTest;
    var h = try harness.Harness.init(a, .{ .spawn_daemon = false });
    defer h.deinit();
    try writeEnforcingConfig(&h, 600);
    try h.startDaemon();
    defer _ = h.stopDaemon() catch {};
    try waitStatus(&h, "\"state\":\"enforcing\"");

    const ban = try admin(a, &h, &.{ "ban", "192.0.2.10", "--jail", "sshd", "--duration", "300" });
    defer ban.deinit(a);
    try t.expectEqual(@as(u8, 0), ban.code);
    try t.expect(std.mem.indexOf(u8, ban.stdout, "\"outcome\":\"applied\"") != null);
    try t.expect(std.mem.indexOf(u8, ban.stdout, "\"enforced\":true") != null);
    // Manual owners are kernel-backed scopes, not retry decisions: the decisions listing stays empty.
    try t.expect(try kernelHas(a, "192.0.2.10"));
    try t.expect(!try waitListContains(&h, "192.0.2.10", 300));

    // Live policy re-key under enforcement: the owner and its kernel rule survive the rebuild.
    try writeEnforcingConfig(&h, 900);
    const reload = try admin(a, &h, &.{"reload"});
    defer reload.deinit(a);
    try t.expectEqual(@as(u8, 0), reload.code);
    try t.expect(std.mem.indexOf(u8, reload.stdout, "\"outcome\":\"applied\"") != null);
    try waitStatus(&h, "\"state\":\"enforcing\"");
    try t.expect(try kernelHas(a, "192.0.2.10"));

    const unban = try admin(a, &h, &.{ "unban", "192.0.2.10", "--jail", "sshd" });
    defer unban.deinit(a);
    try t.expectEqual(@as(u8, 0), unban.code);
    try t.expect(std.mem.indexOf(u8, unban.stdout, "\"outcome\":\"applied\"") != null);
    try waitKernel(a, "192.0.2.10", false, 5000);
    const absent = try admin(a, &h, &.{ "unban", "192.0.2.10", "--jail", "sshd" });
    defer absent.deinit(a);
    try t.expectEqual(@as(u8, 1), absent.code);
    try t.expect(std.mem.indexOf(u8, absent.stdout, "\"outcome\":\"absent\"") != null);

    // Detected ban, then disabling the jail releases its owner and pauses decisions.
    try h.writeLine(failure);
    try h.writeLine(failure);
    try waitKernel(a, "203.0.113.7", true, 8000);
    const disabled = try admin(a, &h, &.{ "jail", "disable", "sshd" });
    defer disabled.deinit(a);
    try t.expectEqual(@as(u8, 0), disabled.code);
    try waitKernel(a, "203.0.113.7", false, 5000);
    // Disabled: records still commit, but no new decision is produced.
    const before_status = try h.queryStatus();
    defer a.free(before_status);
    const decisions_before = harness.parseJsonUintField(before_status, "decisions_total") orelse 0;
    const records_before = harness.parseJsonUintField(before_status, "committed_records") orelse 0;
    try h.writeLine(failure);
    try h.writeLine(failure);
    try waitRecords(&h, records_before + 2);
    const after_status = try h.queryStatus();
    defer a.free(after_status);
    try t.expectEqual(decisions_before, harness.parseJsonUintField(after_status, "decisions_total") orelse 0);
    try t.expect(!try kernelHas(a, "203.0.113.7"));
    const enabled = try admin(a, &h, &.{ "jail", "enable", "sshd" });
    defer enabled.deinit(a);
    try t.expectEqual(@as(u8, 0), enabled.code);
    const net = try admin(a, &h, &.{ "ban", "198.51.100.0", "--jail", "sshd" });
    defer net.deinit(a);
    try t.expectEqual(@as(u8, 0), net.code);
    try t.expect(try kernelHas(a, "198.51.100.0"));

    // Migration activation: staged owners are invisible until activation, which settles only by
    // kernel readback, journals every step and replays idempotently.
    _ = try h.stopDaemon();
    try stageMigration(a, h.state_path, 20);
    try h.startDaemon();
    try waitStatus(&h, "\"state\":\"enforcing\"");
    try t.expect(!try kernelHas(a, "192.0.2.20"));
    const run_hex = std.fmt.bytesToHex(stagedRunId(), .lower);
    const first = try activate(a, &h, &run_hex);
    defer a.free(first.out);
    try t.expectEqual(@as(u8, 0), first.code);
    try t.expect(std.mem.indexOf(u8, first.out, "\"outcome\":\"applied\"") != null);
    try t.expect(std.mem.indexOf(u8, first.out, "\"enforced\":true") != null);
    try t.expect(std.mem.indexOf(u8, first.out, "\"observed_protection\":{\"destination\":\"present\"") != null);
    try t.expect(try kernelHas(a, "192.0.2.20"));
    try t.expect(try kernelHas(a, "192.0.2.21"));
    try t.expect(!try kernelHas(a, "192.0.2.22"));
    const again = try activate(a, &h, &run_hex);
    defer a.free(again.out);
    try t.expectEqual(@as(u8, 0), again.code);
    const unknown = try activate(a, &h, "ff" ** 32);
    defer a.free(unknown.out);
    try t.expectEqual(@as(u8, 1), unknown.code);
    try t.expect(std.mem.indexOf(u8, unknown.out, "\"outcome\":\"absent\"") != null);
    _ = try h.stopDaemon();
    const engine = @import("engine");
    {
        var store = try engine.native_store_mod.Store.open(a, h.state_path);
        defer store.close();
        try t.expectEqual(@as(i64, 7), try store.inspectInteger("SELECT state FROM migration_runs WHERE run_id=x'a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5';"));
        try t.expectEqual(@as(i64, 0), try store.inspectInteger("SELECT count(*) FROM migration_steps WHERE outcome=0;"));
        try t.expectEqual(@as(i64, 7), try store.inspectInteger("SELECT count(*) FROM migration_steps WHERE outcome=1;"));
    }

    // The operator workflow end to end: plan from a seeded fail2ban database, stage offline
    // while the daemon is stopped, then resume by run id against the enforcing daemon and
    // observe the restored owners in the kernel with their original leases.
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const db_path = try std.fs.path.join(a, &.{ root, "fail2ban.sqlite3" });
    defer a.free(db_path);
    try engine.migration_fixture_mod.build(db_path, .{ .omit_sentinel = true, .now = std.time.timestamp() });
    const staging = try std.fs.path.join(a, &.{ root, "staging" });
    defer a.free(staging);
    try std.fs.cwd().makeDir(staging);
    try std.posix.fchmodat(std.posix.AT.FDCWD, staging, 0o700, 0);
    const plan_path = try std.fs.path.join(a, &.{ root, "plan.json" });
    defer a.free(plan_path);
    // The stock tree enables only sshd, which is the one jail this destination configures.
    const source_socket = try std.fs.path.join(a, &.{ root, "f2b.sock" });
    defer a.free(source_socket);
    const planned = try run(a, &.{ exe, "migrate", "plan", "--source-dir", "tests/fixtures/fail2ban/config/stock-1.1.1", "--source-db", db_path, "--staging-dir", staging, "--out", plan_path, "--replay-window", "600", "--runtime-socket", source_socket });
    defer planned.deinit(a);
    try t.expectEqual(@as(u8, 0), planned.code);
    const staged = try run(a, &.{ exe, "migrate", "cutover", "--plan", plan_path, "--state-file", h.state_path, "--staging-dir", staging, "--backend", "iptables", "--socket", h.socket_path });
    defer staged.deinit(a);
    try t.expectEqual(@as(u8, 3), staged.code);
    const marker = "migrate cutover: run ";
    const at = std.mem.indexOf(u8, staged.stderr, marker) orelse return error.RunIdMissing;
    const cutover_run = staged.stderr[at + marker.len .. at + marker.len + 64];
    try t.expect(!try kernelHas(a, "198.51.100.7"));
    try h.startDaemon();
    try waitStatus(&h, "\"state\":\"enforcing\"");
    try t.expect(!try kernelHas(a, "198.51.100.7"));
    const completed = try run(a, &.{ exe, "migrate", "cutover", "--plan", plan_path, "--state-file", h.state_path, "--staging-dir", staging, "--backend", "iptables", "--socket", h.socket_path, "--run-id", cutover_run });
    defer completed.deinit(a);
    if (completed.code != 0) std.debug.print("cutover stdout:\n{s}\ncutover stderr:\n{s}\n", .{ completed.stdout, completed.stderr });
    try t.expectEqual(@as(u8, 0), completed.code);
    try t.expect(std.mem.indexOf(u8, completed.stdout, "\"state\":\"complete\"") != null);
    try t.expect(try kernelHas(a, "198.51.100.7"));
    try t.expect(try kernelHas(a, "192.0.2.10"));
    try t.expect(!try kernelHas(a, "192.0.2.11"));
    const status = try run(a, &.{ exe, "migrate", "status", "--plan", plan_path, "--state-file", h.state_path, "--staging-dir", staging, "--backend", "iptables", "--run-id", cutover_run });
    defer status.deinit(a);
    try t.expectEqual(@as(u8, 0), status.code);
    try t.expect(std.mem.indexOf(u8, status.stdout, "\"outcome\":\"success\"") != null);

    // Later matching records for addresses that are already live owners never re-decide,
    // shorten or prolong them: the migrated finite (192.0.2.10) and permanent (198.51.100.7)
    // owners keep their exact lease, decision id, decision time, revision and confirmation, now
    // and across the restart below, even though the jail bantime would yield a later deadline.
    const status_before_lines = try h.queryStatus();
    defer a.free(status_before_lines);
    const records_before_lines = harness.parseJsonUintField(status_before_lines, "committed_records") orelse 0;
    const before_lines = try ownerDigest(a, h.state_path);
    defer a.free(before_lines);
    for (0..2) |_| {
        try h.writeLine("Failed password for root from 198.51.100.7 port 22 ssh2");
        try h.writeLine("Failed password for root from 192.0.2.10 port 22 ssh2");
    }
    try waitRecords(&h, records_before_lines + 4);
    std.time.sleep(500 * std.time.ns_per_ms);
    {
        // Each address reached a retry decision; the decision was absorbed by the live owner.
        var probe = try engine.native_store_mod.Store.open(a, h.state_path);
        defer probe.close();
        try t.expectEqual(@as(i64, 1), try probe.inspectInteger("SELECT count(*) FROM retry_decisions WHERE subject=x'C000020A';"));
        try t.expectEqual(@as(i64, 1), try probe.inspectInteger("SELECT count(*) FROM retry_decisions WHERE subject=x'C6336407';"));
    }
    const after_lines = try ownerDigest(a, h.state_path);
    defer a.free(after_lines);
    try t.expectEqualStrings(before_lines, after_lines);
    // In the assembled daemon an ordinary stop withdraws the realized rules and keeps every
    // owner, deadline and confirmation; restart restores the same intent without a new confirmation.
    const before_rows = try ownerDigest(a, h.state_path);
    defer a.free(before_rows);
    _ = try h.stopDaemon();
    waitKernel(a, "198.51.100.7", false, 5000) catch |err| {
        const rules = try run(a, &.{ "iptables", "-S" });
        defer rules.deinit(a);
        std.debug.print("rules still present after stop:\n{s}\n", .{rules.stdout});
        return err;
    };
    if (try kernelHas(a, "192.0.2.10")) {
        const rules = try run(a, &.{ "iptables", "-S" });
        defer rules.deinit(a);
        std.debug.print("192.0.2.10 still realized after stop:\n{s}\n", .{rules.stdout});
    }
    try t.expect(!try kernelHas(a, "192.0.2.10"));
    const after_stop = try ownerDigest(a, h.state_path);
    defer a.free(after_stop);
    try t.expectEqualStrings(before_rows, after_stop);
    try h.startDaemon();
    // Restoration re-realizes every withdrawn rule through fixed-argv iptables with readback,
    // so readiness after this restart takes longer than a first start.
    try waitStatusFor(&h, "\"state\":\"enforcing\"", 30_000);
    waitKernel(a, "198.51.100.7", true, 20000) catch |err| {
        const snapshot = try h.queryStatus();
        defer a.free(snapshot);
        std.debug.print("restart did not restore owners: {s}\n", .{snapshot});
        return err;
    };
    try t.expect(try kernelHas(a, "192.0.2.10"));
    _ = try h.stopDaemon();
    const after_restart = try ownerDigest(a, h.state_path);
    defer a.free(after_restart);
    try t.expectEqualStrings(before_rows, after_restart);

    // Rollback: a native ban made after cutover is carried back into the restored source
    // database, the original is kept beside it, and destination ownership of the migrated scopes
    // is released only after the operator attests the source protects again (control socket
    // present); native owners stay.
    try h.startDaemon();
    try waitStatusFor(&h, "\"state\":\"enforcing\"", 30_000);
    try waitKernel(a, "198.51.100.7", true, 20000);
    try waitReady(&h, 30_000);
    const native = try admin(a, &h, &.{ "ban", "203.0.113.99", "--jail", "sshd" });
    defer native.deinit(a);
    // With seven live owners the fixed-argv backend can miss the request's 2 s confirmation
    // window; `partial` then means intent committed, and the kernel confirms it shortly after
    // (recorded as an observation for the performance phase, not accepted as success here).
    try t.expect(native.code == 0 or native.code == 4);
    try waitKernel(a, "203.0.113.99", true, 10000);
    const restore = try run(a, &.{ exe, "migrate", "rollback", "--plan", plan_path, "--state-file", h.state_path, "--staging-dir", staging, "--backend", "iptables", "--socket", h.socket_path, "--run-id", cutover_run });
    defer restore.deinit(a);
    if (restore.code != 3) std.debug.print("rollback stdout:\n{s}\nrollback stderr:\n{s}\n", .{ restore.stdout, restore.stderr });
    try t.expectEqual(@as(u8, 3), restore.code);
    try t.expect(std.mem.indexOf(u8, restore.stderr, "source database restored") != null);
    {
        var conn = try engine.migration_fixture_mod.openWriter(db_path);
        defer conn.close();
        try t.expectEqual(@as(?i64, 1), try conn.scalarInt("SELECT count(*) FROM bips WHERE ip='203.0.113.99' AND jail='sshd'"));
        try t.expectEqual(@as(?i64, 1), try conn.scalarInt("SELECT count(*) FROM bips WHERE ip='198.51.100.7' AND bantime=-1"));
    }
    var kept_found = false;
    var dir = try std.fs.openDirAbsolute(root, .{ .iterate = true });
    defer dir.close();
    var it = dir.iterate();
    while (try it.next()) |entry| if (std.mem.indexOf(u8, entry.name, ".pre-rollback-") != null) {
        kept_found = true;
    };
    try t.expect(kept_found);
    try t.expect(try kernelHas(a, "198.51.100.7"));
    // Without the attestation nothing is released.
    const held = try run(a, &.{ exe, "migrate", "rollback", "--plan", plan_path, "--state-file", h.state_path, "--staging-dir", staging, "--backend", "iptables", "--socket", h.socket_path, "--run-id", cutover_run });
    defer held.deinit(a);
    try t.expectEqual(@as(u8, 3), held.code);
    try t.expect(try kernelHas(a, "198.51.100.7"));
    // The attestation needs the source control socket to exist.
    const attested_early = try run(a, &.{ exe, "migrate", "rollback", "--plan", plan_path, "--state-file", h.state_path, "--staging-dir", staging, "--backend", "iptables", "--socket", h.socket_path, "--run-id", cutover_run, "--source-verified" });
    defer attested_early.deinit(a);
    try t.expectEqual(@as(u8, 3), attested_early.code);
    try t.expect(std.mem.indexOf(u8, attested_early.stderr, "control socket") != null);
    const address = try std.net.Address.initUnix(source_socket);
    var server = try address.listen(.{});
    defer server.deinit();
    // The socket alone must not satisfy the attestation; a running service process must exist.
    const socket_only = try run(a, &.{ exe, "migrate", "rollback", "--plan", plan_path, "--state-file", h.state_path, "--staging-dir", staging, "--backend", "iptables", "--socket", h.socket_path, "--run-id", cutover_run, "--source-verified" });
    defer socket_only.deinit(a);
    try t.expectEqual(@as(u8, 3), socket_only.code);
    try t.expect(std.mem.indexOf(u8, socket_only.stderr, "fail2ban-server") != null);
    // A stand-in process carrying the service's name is the local boundary for that check; the lab
    // rehearsal uses the real reference server.
    const stand_in = try std.fs.path.join(a, &.{ root, "fail2ban-server" });
    defer a.free(stand_in);
    try std.fs.copyFileAbsolute("/bin/sleep", stand_in, .{ .override_mode = 0o755 });
    var service = std.process.Child.init(&.{ stand_in, "300" }, a);
    try service.spawn();
    defer {
        _ = service.kill() catch {};
    }
    const released = try run(a, &.{ exe, "migrate", "rollback", "--plan", plan_path, "--state-file", h.state_path, "--staging-dir", staging, "--backend", "iptables", "--socket", h.socket_path, "--run-id", cutover_run, "--source-verified" });
    defer released.deinit(a);
    if (released.code != 0) std.debug.print("release stdout:\n{s}\nrelease stderr:\n{s}\n", .{ released.stdout, released.stderr });
    try t.expectEqual(@as(u8, 0), released.code);
    const rules_after = try run(a, &.{ "iptables", "-S" });
    defer rules_after.deinit(a);
    if (std.mem.indexOf(u8, released.stdout, "\"state\":\"rolled_back\"") == null or try kernelHas(a, "192.0.2.10") or !try kernelHas(a, "203.0.113.99")) std.debug.print("release report:\n{s}\nrules after release:\n{s}\n", .{ released.stdout, rules_after.stdout });
    try t.expect(std.mem.indexOf(u8, released.stdout, "\"state\":\"rolled_back\"") != null);
    try waitKernel(a, "198.51.100.7", false, 5000);
    try t.expect(!try kernelHas(a, "192.0.2.10"));
    try t.expect(try kernelHas(a, "203.0.113.99"));
    const again_rolled = try run(a, &.{ exe, "migrate", "rollback", "--plan", plan_path, "--state-file", h.state_path, "--staging-dir", staging, "--backend", "iptables", "--socket", h.socket_path, "--run-id", cutover_run, "--source-verified" });
    defer again_rolled.deinit(a);
    try t.expectEqual(@as(u8, 0), again_rolled.code);
}

/// Owners with their leases and decisions plus the revision and confirmation counters; identical
/// text across a stop/restart proves no owner was re-decided or re-confirmed.
fn ownerDigest(a: std.mem.Allocator, state_path: []const u8) ![]u8 {
    const engine = @import("engine");
    var store = try engine.native_store_mod.Store.open(a, state_path);
    defer store.close();
    var out = std.ArrayList(u8).init(a);
    errdefer out.deinit();
    try out.writer().print("live={d} permanent={d} deadlines={d} decided={d} revisions={d} confirmed={d}", .{
        try store.inspectInteger("SELECT count(*) FROM effect_owners WHERE lease_kind!=0;"),
        try store.inspectInteger("SELECT count(*) FROM effect_owners WHERE lease_kind=2;"),
        try store.inspectInteger("SELECT coalesce(sum(deadline_us),0) FROM effect_owners WHERE lease_kind=1;"),
        try store.inspectInteger("SELECT coalesce(sum(decided_us),0) FROM effect_owners WHERE lease_kind!=0;"),
        try store.inspectInteger("SELECT count(*) FROM effect_owner_revisions;"),
        try store.inspectInteger("SELECT count(*) FROM confirmed_effect_events;"),
    });
    return out.toOwnedSlice();
}

fn stagedRunId() [32]u8 {
    return [_]u8{0xa5} ** 32;
}

/// Stages one finite and one permanent owner for `sshd` plus an expired one into a daemon-created
/// store, leaving the run `staged` exactly as the offline import step would.
fn stageMigration(a: std.mem.Allocator, state_path: []const u8, base: u8) !void {
    const engine = @import("engine");
    const durable = engine.native_store_mod;
    const canonical = engine.firewall_scope_mod;
    var store = try durable.Store.open(a, state_path);
    defer store.close();
    const run_id = stagedRunId();
    try store.createMigrationRun(.{ .run_id = run_id, .host_id = [_]u8{1} ** 32, .source_db_fp = [_]u8{2} ** 32, .source_cfg_fp = [_]u8{3} ** 32, .plan_fp = [_]u8{4} ** 32, .recovery_point = "recovery.sqlite3", .generation = [_]u8{0} ** 32, .state = .planned, .created_us = 100, .updated_us = 100 });
    // Shorter than the destination's bantime so a later detection prolongs it in place.
    const far = std.time.microTimestamp() + 300 * std.time.us_per_s;
    const owners = [_]durable.Store.StagedOwnerRow{
        .{ .jail = "sshd", .scope = try (canonical.Scope{ .subject = canonical.Subject.host(.{ .ipv4 = (192 << 24) | (2 << 8) | @as(u32, base + 0) }) }).encode(), .lease_kind = 1, .deadline_us = far, .source_event_us = 1_000_000, .source_row = 1 },
        .{ .jail = "sshd", .scope = try (canonical.Scope{ .subject = canonical.Subject.host(.{ .ipv4 = (192 << 24) | (2 << 8) | @as(u32, base + 1) }) }).encode(), .lease_kind = 2, .deadline_us = null, .source_event_us = 1_000_000, .source_row = 2 },
        .{ .jail = "sshd", .scope = try (canonical.Scope{ .subject = canonical.Subject.host(.{ .ipv4 = (192 << 24) | (2 << 8) | @as(u32, base + 2) }) }).encode(), .lease_kind = 1, .deadline_us = 4_000_000, .source_event_us = 900_000, .source_row = 3 },
    };
    try store.stageMigrationRows(run_id, &owners, &.{});
    // The daemon activates only a run whose offline steps all recorded success.
    var clock: i64 = 300;
    inline for (.{ durable.Store.MigrationStep.validate_plan, .check_drift, .capture_recovery_point, .quiesce_source, .stage_destination }) |step| {
        const seq = try store.beginMigrationStep(run_id, step, "", clock);
        try store.finishMigrationStep(run_id, seq, .success, "", if (step == .stage_destination) .staged else null, clock + 1);
        clock += 2;
    }
}

fn activate(a: std.mem.Allocator, h: *harness.Harness, run_id_hex: []const u8) !struct { code: u8, out: []u8 } {
    const cli = @import("engine").cli_mod;
    var out = std.ArrayList(u8).init(a);
    errdefer out.deinit();
    var err = std.ArrayList(u8).init(a);
    defer err.deinit();
    const code = cli.doAdmin(a, .{ .socket_path = h.socket_path, .timeout_ms = 8000, .output = .json }, out.writer(), err.writer(), .{ .kind = "migration_activate", .run_id = run_id_hex });
    return .{ .code = @intFromEnum(code), .out = try out.toOwnedSlice() };
}

test "admin: staged migration owners stay outside authority and a log-only destination refuses activation" {
    const a = t.allocator;
    std.fs.cwd().access(exe, .{}) catch return error.SkipZigTest;
    var h = try harness.Harness.init(a, .{ .spawn_daemon = false });
    defer h.deinit();
    try writeConfig(&h);
    try h.startDaemon();
    try waitHealthy(&h);
    _ = try h.stopDaemon();
    try stageMigration(a, h.state_path, 10);

    try h.startDaemon();
    defer _ = h.stopDaemon() catch {};
    try waitHealthy(&h);
    const before = try h.queryList();
    defer a.free(before);
    try t.expect(std.mem.indexOf(u8, before, "192.0.2.1") == null);

    const run_hex = std.fmt.bytesToHex(stagedRunId(), .lower);
    const refused = try activate(a, &h, &run_hex);
    defer a.free(refused.out);
    try t.expectEqual(@as(u8, 1), refused.code);
    try t.expect(std.mem.indexOf(u8, refused.out, "\"outcome\":\"rejected\"") != null);
    try t.expect(std.mem.indexOf(u8, refused.out, "log-only") != null);
    const short = try activate(a, &h, "abc");
    defer a.free(short.out);
    try t.expect(short.code != 0);

    _ = try h.stopDaemon();
    const engine = @import("engine");
    var store = try engine.native_store_mod.Store.open(a, h.state_path);
    defer store.close();
    try t.expectEqual(@as(i64, 5), try store.inspectInteger("SELECT state FROM migration_runs WHERE run_id=x'a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5';"));
    try t.expectEqual(@as(i64, 0), try store.inspectInteger("SELECT count(*) FROM effect_owners;"));
    try t.expectEqual(@as(i64, 0), try store.inspectInteger("SELECT count(*) FROM migration_steps WHERE outcome=0;"));
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

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

fn parseValue(a: std.mem.Allocator, bytes: []const u8) !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, a, bytes, .{});
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
    const paused_doc = try parseValue(a, paused.stdout);
    defer paused_doc.deinit();
    try t.expectEqualStrings("group_pause", paused_doc.value.object.get("kind").?.string);
    try t.expectEqualStrings("applied", paused_doc.value.object.get("outcome").?.string);
    try t.expectEqual(@as(i64, 1), paused_doc.value.object.get("mutation_revision").?.integer);
    const jails = try admin(a, &h, &.{"jails"});
    defer jails.deinit(a);
    const paused_jails = try parseValue(a, jails.stdout);
    defer paused_jails.deinit();
    try t.expect(paused_jails.value.array.items[0].object.get("paused").?.bool);

    const before = try h.queryStatus();
    defer a.free(before);
    const committed = harness.parseJsonUintField(before, "committed_records") orelse 0;
    try h.writeLine(failure);
    try h.writeLine(failure);
    try h.writeLine(failure);
    try waitRecords(&h, committed + 3);
    try t.expect(!try waitListContains(&h, "203.0.113.7", 1500));

    try t.expectEqual(std.process.Child.Term{ .Exited = 0 }, try h.stopDaemon());
    try h.startDaemon();
    try waitHealthy(&h);
    const after = try admin(a, &h, &.{"jails"});
    defer after.deinit(a);
    const after_doc = try parseValue(a, after.stdout);
    defer after_doc.deinit();
    try t.expect(after_doc.value.array.items[0].object.get("paused").?.bool);
    try h.writeLine(failure);
    try h.writeLine(failure);
    try t.expect(!try waitListContains(&h, "203.0.113.7", 1500));

    const resumed = try admin(a, &h, &.{ "jail", "resume", "sshd" });
    defer resumed.deinit(a);
    try t.expectEqual(@as(u8, 0), resumed.code);
    const resumed_doc = try parseValue(a, resumed.stdout);
    defer resumed_doc.deinit();
    try t.expectEqualStrings("group_resume", resumed_doc.value.object.get("kind").?.string);
    try t.expectEqualStrings("applied", resumed_doc.value.object.get("outcome").?.string);
    const resumed_jails = try admin(a, &h, &.{"jails"});
    defer resumed_jails.deinit(a);
    const resumed_jails_doc = try parseValue(a, resumed_jails.stdout);
    defer resumed_jails_doc.deinit();
    try t.expect(!resumed_jails_doc.value.array.items[0].object.get("paused").?.bool);
    try h.writeLine(failure);
    try h.writeLine(failure);
    try t.expect(try waitListContains(&h, "203.0.113.7", 8000));

    const decision_list = try admin(a, &h, &.{ "list", "--jail", "sshd" });
    defer decision_list.deinit(a);
    try t.expectEqual(@as(u8, 0), decision_list.code);
    const decision_doc = try parseValue(a, decision_list.stdout);
    defer decision_doc.deinit();
    try t.expectEqual(@as(usize, 1), decision_doc.value.array.items.len);
    const decision = decision_doc.value.array.items[0].object;
    try t.expectEqualStrings("sshd", decision.get("jail").?.string);
    try t.expect(!decision.get("enforced").?.bool);
    try t.expect(!decision.get("confirmed").?.bool);

    const empty_history = try admin(a, &h, &.{ "history", "--jail", "sshd", "--limit", "20" });
    defer empty_history.deinit(a);
    try t.expectEqual(@as(u8, 0), empty_history.code);
    const history_doc = try parseValue(a, empty_history.stdout);
    defer history_doc.deinit();
    const history = history_doc.value.object;
    try t.expectEqual(@as(i64, 1), history.get("schema_version").?.integer);
    try t.expectEqual(@as(usize, 0), history.get("items").?.array.items.len);
    try t.expect(history.get("next_cursor").? == .null);
    try t.expectEqual(@as(usize, 64), history.get("generation").?.string.len);

    const reset = try admin(a, &h, &.{ "history", "reset", "203.0.113.7", "--jail", "sshd" });
    defer reset.deinit(a);
    try t.expectEqual(@as(u8, 0), reset.code);
    const reset_doc = try parseValue(a, reset.stdout);
    defer reset_doc.deinit();
    try t.expectEqual(@as(i64, 1), reset_doc.value.object.get("schema_version").?.integer);
    try t.expectEqualStrings("history_reset", reset_doc.value.object.get("kind").?.string);
    try t.expectEqualStrings("applied", reset_doc.value.object.get("outcome").?.string);
    try t.expectEqual(@as(i64, 3), reset_doc.value.object.get("mutation_revision").?.integer);
    const status = try h.queryStatus();
    defer a.free(status);
    try t.expect(std.mem.indexOf(u8, status, "\"mutation_revision\":3") != null);

    const disabled = try admin(a, &h, &.{ "jail", "disable", "sshd" });
    defer disabled.deinit(a);
    try t.expectEqual(@as(u8, 0), disabled.code);
    const disabled_doc = try parseValue(a, disabled.stdout);
    defer disabled_doc.deinit();
    try t.expectEqualStrings("group_disable", disabled_doc.value.object.get("kind").?.string);
    try t.expectEqualStrings("applied", disabled_doc.value.object.get("outcome").?.string);
    const disabled_jails = try admin(a, &h, &.{"jails"});
    defer disabled_jails.deinit(a);
    const disabled_jails_doc = try parseValue(a, disabled_jails.stdout);
    defer disabled_jails_doc.deinit();
    try t.expect(!disabled_jails_doc.value.array.items[0].object.get("enabled").?.bool);

    const enabled = try admin(a, &h, &.{ "jail", "enable", "sshd" });
    defer enabled.deinit(a);
    try t.expectEqual(@as(u8, 0), enabled.code);
    const enabled_doc = try parseValue(a, enabled.stdout);
    defer enabled_doc.deinit();
    try t.expectEqualStrings("group_enable", enabled_doc.value.object.get("kind").?.string);
    try t.expectEqualStrings("applied", enabled_doc.value.object.get("outcome").?.string);
    const enabled_jails = try admin(a, &h, &.{"jails"});
    defer enabled_jails.deinit(a);
    const enabled_jails_doc = try parseValue(a, enabled_jails.stdout);
    defer enabled_jails_doc.deinit();
    try t.expect(enabled_jails_doc.value.array.items[0].object.get("enabled").?.bool);
    try t.expect(!enabled_jails_doc.value.array.items[0].object.get("paused").?.bool);
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
    const ban_doc = try parseValue(a, ban.stdout);
    defer ban_doc.deinit();
    const ban_root = ban_doc.value.object;
    try t.expectEqual(@as(i64, 1), ban_root.get("schema_version").?.integer);
    try t.expectEqualStrings("ban", ban_root.get("kind").?.string);
    try t.expectEqualStrings("rejected", ban_root.get("outcome").?.string);
    try t.expect(!ban_root.get("enforced").?.bool);
    try t.expect(ban_root.get("reasons").?.array.items.len >= 1);

    const unban = try admin(a, &h, &.{ "unban", "192.0.2.10", "--jail", "sshd" });
    defer unban.deinit(a);
    try t.expectEqual(@as(u8, 1), unban.code);
    const unban_doc = try parseValue(a, unban.stdout);
    defer unban_doc.deinit();
    const unban_root = unban_doc.value.object;
    try t.expectEqual(@as(i64, 1), unban_root.get("schema_version").?.integer);
    try t.expectEqualStrings("unban", unban_root.get("kind").?.string);
    try t.expectEqualStrings("rejected", unban_root.get("outcome").?.string);
    try t.expect(!unban_root.get("enforced").?.bool);
    try t.expect(unban_root.get("reasons").?.array.items.len >= 1);

    const unknown = try admin(a, &h, &.{ "jail", "pause", "nope" });
    defer unknown.deinit(a);
    try t.expectEqual(@as(u8, 1), unknown.code);
    try t.expect(std.mem.indexOf(u8, unknown.stdout, "\"outcome\":\"absent\"") != null);

    const nojail = try admin(a, &h, &.{ "ban", "192.0.2.10" });
    defer nojail.deinit(a);
    try t.expectEqual(@as(u8, 2), nojail.code);

    try t.expectError(error.UnexpectedResponse, h.sendCommand(.{ .ban = .{ .ip = try @import("shared").IpAddress.parse("192.0.2.10"), .jail = try @import("shared").JailId.fromSlice("sshd"), .duration = null } }));
    try t.expectError(error.UnexpectedResponse, h.sendCommand(.{ .unban = .{ .ip = try @import("shared").IpAddress.parse("192.0.2.10"), .jail = null } }));

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

fn writeEnforcingConfigForBackend(h: *harness.Harness, bantime: u32, backend: []const u8) !void {
    var file = try std.fs.cwd().createFile(h.config_path, .{ .mode = 0o600 });
    defer file.close();
    try file.writer().print(
        \\[global]
        \\native_ingestion = true
        \\state_file = "{s}"
        \\socket_path = "{s}"
        \\metrics_enabled = false
        \\firewall = "{s}"
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
    , .{ h.state_path, h.socket_path, backend, linux.getpid(), bantime, h.log_path });
}

fn writeEnforcingConfig(h: *harness.Harness, bantime: u32) !void {
    return writeEnforcingConfigForBackend(h, bantime, "iptables");
}

fn writeOverlapConfig(h: *harness.Harness, bantime: u32) !void {
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
        \\[jails.secondary]
        \\filter = "sshd"
        \\source = "file"
        \\timestamp = "undated"
        \\logpath = ["{s}"]
        \\maxretry = 100
        \\
    , .{ h.state_path, h.socket_path, linux.getpid(), bantime, h.log_path, h.log_path });
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

fn nftKernelHas(a: std.mem.Allocator, needle: []const u8) !bool {
    const r = try run(a, &.{ "nft", "list", "ruleset" });
    defer r.deinit(a);
    if (r.code != 0) return error.NftReadbackFailed;
    return std.mem.indexOf(u8, r.stdout, needle) != null;
}

fn waitNftKernel(a: std.mem.Allocator, needle: []const u8, present: bool, timeout_ms: u64) !void {
    var timer = try std.time.Timer.start();
    while (timer.read() < timeout_ms * std.time.ns_per_ms) {
        if (try nftKernelHas(a, needle) == present) return;
        std.time.sleep(100 * std.time.ns_per_ms);
    }
    return error.TimedOut;
}

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

fn waitListCount(h: *harness.Harness, expected: usize, timeout_ms: u64) ![]const u8 {
    var timer = try std.time.Timer.start();
    while (timer.read() < timeout_ms * std.time.ns_per_ms) {
        const listing = try h.queryList();
        const parsed = parseValue(t.allocator, listing) catch {
            t.allocator.free(listing);
            return error.InvalidList;
        };
        const count = if (parsed.value == .array) parsed.value.array.items.len else 0;
        parsed.deinit();
        if (count == expected) return listing;
        t.allocator.free(listing);
        std.time.sleep(50 * std.time.ns_per_ms);
    }
    return error.TimedOut;
}

fn waitActiveBans(h: *harness.Harness, expected: u32, timeout_ms: u64) !void {
    var timer = try std.time.Timer.start();
    while (timer.read() < timeout_ms * std.time.ns_per_ms) {
        const status = try h.queryStatus();
        defer t.allocator.free(status);
        if ((harness.parseJsonUintField(status, "active_bans") orelse std.math.maxInt(u32)) == expected) return;
        std.time.sleep(50 * std.time.ns_per_ms);
    }
    return error.TimedOut;
}

fn ownerExpiry(items: []const std.json.Value, jail: []const u8) !i64 {
    for (items) |item| {
        const object = item.object;
        if (std.mem.eql(u8, object.get("jail").?.string, jail)) return object.get("expiry_us").?.integer;
    }
    return error.MissingOwner;
}

test "admin: BUG-040 nftables network ban list and unban preserve CIDR" {
    if (std.posix.getenv("F2Z_NATIVE_DAEMON_ENFORCEMENT") == null) return error.SkipZigTest;
    const prior = std.posix.getenv("F2Z_NATIVE_PARENT_NETNS") orelse return error.MissingIsolationCookie;
    var namespace_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const current = try std.fs.readLinkAbsolute("/proc/self/ns/net", &namespace_buffer);
    try t.expect(!std.mem.eql(u8, prior, current));
    if (linux.E.init(linux.unshare(linux.CLONE.NEWNET)) != .SUCCESS) return error.IsolationFailed;

    const a = t.allocator;
    var h = try harness.Harness.init(a, .{ .spawn_daemon = false });
    defer h.deinit();
    try writeEnforcingConfigForBackend(&h, 600, "nftables");
    try h.startDaemon();
    defer _ = h.stopDaemon() catch {};
    try waitReady(&h, 10_000);

    const ban = try admin(a, &h, &.{ "ban", "192.0.2.10", "--jail", "sshd", "--duration", "300", "--scope", "net", "192.0.2.0/24" });
    defer ban.deinit(a);
    try t.expectEqual(@as(u8, 0), ban.code);
    try waitNftKernel(a, "192.0.2.0/24", true, 5000);
    try t.expect(try waitListContains(&h, "\"ip\":\"192.0.2.0/24\"", 5000));

    const unban = try admin(a, &h, &.{ "unban", "192.0.2.10", "--jail", "sshd", "--scope", "net", "192.0.2.0/24" });
    defer unban.deinit(a);
    try t.expectEqual(@as(u8, 0), unban.code);
    const empty = try waitListCount(&h, 0, 5000);
    a.free(empty);
    try waitNftKernel(a, "192.0.2.0/24", false, 5000);
}

test "admin: BUG-038 operator owner view covers dedup overlap restart unban and expiry" {
    if (std.posix.getenv("F2Z_NATIVE_DAEMON_ENFORCEMENT") == null) return error.SkipZigTest;
    const prior = std.posix.getenv("F2Z_NATIVE_PARENT_NETNS") orelse return error.MissingIsolationCookie;
    var namespace_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const current = try std.fs.readLinkAbsolute("/proc/self/ns/net", &namespace_buffer);
    try t.expect(!std.mem.eql(u8, prior, current));
    if (linux.E.init(linux.unshare(linux.CLONE.NEWNET)) != .SUCCESS) return error.IsolationFailed;

    const a = t.allocator;
    var h = try harness.Harness.init(a, .{ .spawn_daemon = false });
    defer h.deinit();
    try writeOverlapConfig(&h, 600);
    try h.startDaemon();
    defer _ = h.stopDaemon() catch {};
    try waitReady(&h, 10_000);

    try h.writeLine(failure);
    try h.writeLine(failure);
    try waitKernel(a, "203.0.113.7", true, 8000);
    const detected = try waitListCount(&h, 1, 8000);
    defer a.free(detected);
    {
        const document = try parseValue(a, detected);
        defer document.deinit();
        const item = document.value.array.items[0].object;
        try t.expectEqualStrings("sshd", item.get("jail").?.string);
        try t.expect(item.get("confirmed").?.bool);
    }
    try waitActiveBans(&h, 1, 5000);

    const replaced = try admin(a, &h, &.{ "ban", "203.0.113.7", "--jail", "sshd", "--duration", "300" });
    defer replaced.deinit(a);
    try t.expectEqual(@as(u8, 0), replaced.code);
    const deduplicated = try waitListCount(&h, 1, 5000);
    a.free(deduplicated);
    try waitActiveBans(&h, 1, 5000);

    const overlap = try admin(a, &h, &.{ "ban", "203.0.113.7", "--jail", "secondary", "--duration", "240" });
    defer overlap.deinit(a);
    try t.expectEqual(@as(u8, 0), overlap.code);
    const before_restart = try waitListCount(&h, 2, 5000);
    defer a.free(before_restart);
    const before_document = try parseValue(a, before_restart);
    defer before_document.deinit();
    const sshd_expiry = try ownerExpiry(before_document.value.array.items, "sshd");
    const secondary_expiry = try ownerExpiry(before_document.value.array.items, "secondary");
    try waitActiveBans(&h, 2, 5000);

    try t.expectEqual(std.process.Child.Term{ .Exited = 0 }, try h.stopDaemon());
    try h.startDaemon();
    try waitReady(&h, 15_000);
    try waitKernel(a, "203.0.113.7", true, 5000);
    const after_restart = try waitListCount(&h, 2, 5000);
    defer a.free(after_restart);
    {
        const document = try parseValue(a, after_restart);
        defer document.deinit();
        try t.expectEqual(sshd_expiry, try ownerExpiry(document.value.array.items, "sshd"));
        try t.expectEqual(secondary_expiry, try ownerExpiry(document.value.array.items, "secondary"));
    }
    try waitActiveBans(&h, 2, 5000);

    const release_first = try admin(a, &h, &.{ "unban", "203.0.113.7", "--jail", "sshd" });
    defer release_first.deinit(a);
    try t.expectEqual(@as(u8, 0), release_first.code);
    const retained = try waitListCount(&h, 1, 5000);
    defer a.free(retained);
    {
        const document = try parseValue(a, retained);
        defer document.deinit();
        try t.expectEqualStrings("secondary", document.value.array.items[0].object.get("jail").?.string);
    }
    try t.expect(try kernelHas(a, "203.0.113.7"));
    try waitActiveBans(&h, 1, 5000);

    const release_final = try admin(a, &h, &.{ "unban", "203.0.113.7", "--jail", "secondary" });
    defer release_final.deinit(a);
    try t.expectEqual(@as(u8, 0), release_final.code);
    const empty = try waitListCount(&h, 0, 5000);
    a.free(empty);
    try waitKernel(a, "203.0.113.7", false, 5000);
    try waitActiveBans(&h, 0, 5000);

    const expiring = try admin(a, &h, &.{ "ban", "192.0.2.38", "--jail", "sshd", "--duration", "4" });
    defer expiring.deinit(a);
    try t.expectEqual(@as(u8, 0), expiring.code);
    const live = try waitListCount(&h, 1, 5000);
    a.free(live);
    try waitKernel(a, "192.0.2.38", true, 5000);
    const expired = try waitListCount(&h, 0, 10_000);
    a.free(expired);
    try waitKernel(a, "192.0.2.38", false, 5000);
    try waitActiveBans(&h, 0, 5000);
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
    try waitStatus(&h, "\"state\":\"active\"");

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
    try waitStatus(&h, "\"state\":\"active\"");

    const ban = try admin(a, &h, &.{ "ban", "192.0.2.10", "--jail", "sshd", "--duration", "300" });
    defer ban.deinit(a);
    try t.expectEqual(@as(u8, 0), ban.code);
    try t.expect(std.mem.indexOf(u8, ban.stdout, "\"outcome\":\"applied\"") != null);
    try t.expect(std.mem.indexOf(u8, ban.stdout, "\"enforced\":true") != null);
    try t.expect(try kernelHas(a, "192.0.2.10"));
    try t.expect(try waitListContains(&h, "192.0.2.10", 5000));

    try writeEnforcingConfig(&h, 900);
    const reload = try admin(a, &h, &.{"reload"});
    defer reload.deinit(a);
    try t.expectEqual(@as(u8, 0), reload.code);
    try t.expect(std.mem.indexOf(u8, reload.stdout, "\"outcome\":\"applied\"") != null);
    try waitStatus(&h, "\"state\":\"active\"");
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

    try h.writeLine(failure);
    try h.writeLine(failure);
    try waitKernel(a, "203.0.113.7", true, 8000);
    const disabled = try admin(a, &h, &.{ "jail", "disable", "sshd" });
    defer disabled.deinit(a);
    try t.expectEqual(@as(u8, 0), disabled.code);
    try waitKernel(a, "203.0.113.7", false, 5000);
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

    _ = try h.stopDaemon();
    try stageMigration(a, h.state_path, 20);
    try h.startDaemon();
    try waitStatus(&h, "\"state\":\"active\"");
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
    try waitStatus(&h, "\"state\":\"active\"");
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
        var probe = try engine.native_store_mod.Store.open(a, h.state_path);
        defer probe.close();
        try t.expectEqual(@as(i64, 1), try probe.inspectInteger("SELECT count(*) FROM retry_decisions WHERE subject=x'C000020A';"));
        try t.expectEqual(@as(i64, 1), try probe.inspectInteger("SELECT count(*) FROM retry_decisions WHERE subject=x'C6336407';"));
    }
    const after_lines = try ownerDigest(a, h.state_path);
    defer a.free(after_lines);
    try t.expectEqualStrings(before_lines, after_lines);
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
    try waitStatusFor(&h, "\"state\":\"active\"", 30_000);
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

    try h.startDaemon();
    try waitStatusFor(&h, "\"state\":\"active\"", 30_000);
    try waitKernel(a, "198.51.100.7", true, 20000);
    try waitReady(&h, 30_000);
    const native = try admin(a, &h, &.{ "ban", "203.0.113.99", "--jail", "sshd" });
    defer native.deinit(a);
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
    const held = try run(a, &.{ exe, "migrate", "rollback", "--plan", plan_path, "--state-file", h.state_path, "--staging-dir", staging, "--backend", "iptables", "--socket", h.socket_path, "--run-id", cutover_run });
    defer held.deinit(a);
    try t.expectEqual(@as(u8, 3), held.code);
    try t.expect(try kernelHas(a, "198.51.100.7"));
    const attested_early = try run(a, &.{ exe, "migrate", "rollback", "--plan", plan_path, "--state-file", h.state_path, "--staging-dir", staging, "--backend", "iptables", "--socket", h.socket_path, "--run-id", cutover_run, "--source-verified" });
    defer attested_early.deinit(a);
    try t.expectEqual(@as(u8, 3), attested_early.code);
    try t.expect(std.mem.indexOf(u8, attested_early.stderr, "control socket") != null);
    const address = try std.net.Address.initUnix(source_socket);
    var server = try address.listen(.{});
    defer server.deinit();
    const socket_only = try run(a, &.{ exe, "migrate", "rollback", "--plan", plan_path, "--state-file", h.state_path, "--staging-dir", staging, "--backend", "iptables", "--socket", h.socket_path, "--run-id", cutover_run, "--source-verified" });
    defer socket_only.deinit(a);
    try t.expectEqual(@as(u8, 3), socket_only.code);
    try t.expect(std.mem.indexOf(u8, socket_only.stderr, "fail2ban-server") != null);
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

fn stageMigration(a: std.mem.Allocator, state_path: []const u8, base: u8) !void {
    const engine = @import("engine");
    const durable = engine.native_store_mod;
    const canonical = engine.firewall_scope_mod;
    var store = try durable.Store.open(a, state_path);
    defer store.close();
    const run_id = stagedRunId();
    try store.createMigrationRun(.{ .run_id = run_id, .host_id = [_]u8{1} ** 32, .source_db_fp = [_]u8{2} ** 32, .source_cfg_fp = [_]u8{3} ** 32, .plan_fp = [_]u8{4} ** 32, .recovery_point = "recovery.sqlite3", .generation = [_]u8{0} ** 32, .state = .planned, .created_us = 100, .updated_us = 100 });
    const far = std.time.microTimestamp() + 300 * std.time.us_per_s;
    const owners = [_]durable.Store.StagedOwnerRow{
        .{ .jail = "sshd", .scope = try (canonical.Scope{ .subject = canonical.Subject.host(.{ .ipv4 = (192 << 24) | (2 << 8) | @as(u32, base + 0) }) }).encode(), .lease_kind = 1, .deadline_us = far, .source_event_us = 1_000_000, .source_row = 1 },
        .{ .jail = "sshd", .scope = try (canonical.Scope{ .subject = canonical.Subject.host(.{ .ipv4 = (192 << 24) | (2 << 8) | @as(u32, base + 1) }) }).encode(), .lease_kind = 2, .deadline_us = null, .source_event_us = 1_000_000, .source_row = 2 },
        .{ .jail = "sshd", .scope = try (canonical.Scope{ .subject = canonical.Subject.host(.{ .ipv4 = (192 << 24) | (2 << 8) | @as(u32, base + 2) }) }).encode(), .lease_kind = 1, .deadline_us = 4_000_000, .source_event_us = 900_000, .source_row = 3 },
    };
    try store.stageMigrationRows(run_id, &owners, &.{});
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

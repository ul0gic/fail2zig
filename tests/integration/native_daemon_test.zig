// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const t = std.testing;
const engine = @import("engine");
const harness = @import("harness.zig");
const linux = std.os.linux;
const failure = "Failed password for root from 203.0.113.7 port 22 ssh2";
const following_failure = "Failed password for root from 203.0.113.8 port 22 ssh2";
const portsentry_positive_body = "Scan from: [192.0.2.2] (192.0.2.2) protocol: [TCP] port: [23456] type: [Connect] IP opts: [unknown] ignored: [false] triggered: [true] noblock: [true] blocked: [false]";
const portsentry_ignored_body = "Scan from: [192.0.2.2] (192.0.2.2) protocol: [TCP] port: [23456] type: [Connect] IP opts: [unknown] ignored: [true] triggered: [unset] noblock: [unset] blocked: [unset]";
const portsentry_prethreshold_body = "Scan from: [192.0.2.2] (192.0.2.2) protocol: [TCP] port: [23456] type: [Connect] IP opts: [unknown] ignored: [false] triggered: [false] noblock: [unset] blocked: [unset]";
const portsentry_nonmatch_body = "PortSentry is now active and listening.";

const SqliteStatement = opaque {};
extern "c" fn sqlite3_prepare_v2(?*anyopaque, [*:0]const u8, c_int, *?*SqliteStatement, ?*?[*:0]const u8) c_int;
extern "c" fn sqlite3_step(*SqliteStatement) c_int;
extern "c" fn sqlite3_finalize(*SqliteStatement) c_int;
extern "c" fn sqlite3_column_text(*SqliteStatement, c_int) ?[*:0]const u8;
extern "c" fn sqlite3_column_blob(*SqliteStatement, c_int) ?*const anyopaque;
extern "c" fn sqlite3_column_bytes(*SqliteStatement, c_int) c_int;

fn writeConfig(h: *harness.Harness) !void {
    if (std.posix.getenv("F2Z_NATIVE_DAEMON_ENFORCEMENT") != null) return error.SkipZigTest;
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
        \\maxretry = 3
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
fn writeEnforcingConfig(h: *harness.Harness) !void {
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
        \\maxretry = 1
        \\findtime = 600
        \\bantime = 60
        \\[jails.sshd]
        \\filter = "sshd"
        \\source = "file"
        \\timestamp = "undated"
        \\logpath = ["{s}"]
        \\
    , .{ h.state_path, h.socket_path, linux.getpid(), h.log_path });
}
fn writePortSentryConfig(h: *harness.Harness) !void {
    if (std.posix.getenv("F2Z_NATIVE_DAEMON_ENFORCEMENT") != null) return error.SkipZigTest;
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
        \\maxretry = 1
        \\findtime = 600
        \\bantime = 60
        \\[jails.portsentry]
        \\filter = "portsentry"
        \\source = "file"
        \\timestamp = "iso8601"
        \\logpath = ["{s}"]
        \\
    , .{ h.state_path, h.socket_path, h.log_path });
}
fn writeEscalationCleanupConfig(h: *harness.Harness) !void {
    const enforcing = std.posix.getenv("F2Z_NATIVE_DAEMON_ENFORCEMENT") != null;
    var file = try std.fs.cwd().createFile(h.config_path, .{ .mode = 0o600 });
    defer file.close();
    try file.writer().print(
        \\[global]
        \\native_ingestion = true
        \\state_file = "{s}"
        \\socket_path = "{s}"
        \\metrics_enabled = false
        \\
    , .{ h.state_path, h.socket_path });
    if (enforcing) try file.writer().print(
        \\firewall = "nftables"
        \\firewall_namespace = "/proc/{d}/ns/net"
        \\
    , .{linux.getpid()});
    try file.writer().writeAll(
        \\[defaults]
        \\
    );
    if (enforcing) try file.writer().writeAll(
        \\enforce = true
        \\
    ) else try file.writer().writeAll(
        \\banaction = "log-only"
        \\
    );
    try file.writer().print(
        \\maxretry = 1
        \\findtime = 5
        \\bantime = 5
        \\bantime_increment_enabled = true
        \\[jails.sshd]
        \\filter = "sshd"
        \\source = "file"
        \\timestamp = "undated"
        \\logpath = ["{s}"]
        \\
    , .{h.log_path});
}
fn waitStatus(h: *harness.Harness, needle: []const u8) !void {
    var timer = try std.time.Timer.start();
    while (timer.read() < 8 * std.time.ns_per_s) {
        const result = try h.queryStatus();
        defer t.allocator.free(result);
        if (std.mem.indexOf(u8, result, needle) != null) return;
        std.time.sleep(20 * std.time.ns_per_ms);
    }
    const last = try h.queryStatus();
    defer t.allocator.free(last);
    std.debug.print("native daemon: missing {s}; last status {s}\n", .{ needle, last });
    return error.TimedOut;
}

fn waitReady(h: *harness.Harness) !void {
    const shared = @import("shared");
    var timer = try std.time.Timer.start();
    while (timer.read() < 8 * std.time.ns_per_s) {
        const result = try h.sendCommand(.{ .query_v1 = try shared.Command.Body.init("{\"schema_version\":1,\"kind\":\"health\"}") });
        defer t.allocator.free(result);
        if (std.mem.indexOf(u8, result, "\"ready\":true") != null) return;
        std.time.sleep(20 * std.time.ns_per_ms);
    }
    return error.TimedOut;
}

const MaintenanceSource = struct {
    source: []u8,
    generation: [32]u8,

    fn deinit(self: MaintenanceSource) void {
        t.allocator.free(self.source);
    }
};

fn maintenanceSource(store: *engine.native_store_mod.Store) !MaintenanceSource {
    var statement: ?*SqliteStatement = null;
    if (sqlite3_prepare_v2(@ptrCast(store.db), "SELECT source,generation FROM source_maintenance WHERE jail='sshd' ORDER BY source LIMIT 1;", -1, &statement, null) != 0 or statement == null) return error.TestSqlFailed;
    defer _ = sqlite3_finalize(statement.?);
    if (sqlite3_step(statement.?) != 100) return error.TestSqlFailed;
    const source_text = sqlite3_column_text(statement.?, 0) orelse return error.TestSqlFailed;
    const source_len = sqlite3_column_bytes(statement.?, 0);
    const generation_blob = sqlite3_column_blob(statement.?, 1) orelse return error.TestSqlFailed;
    const generation_len = sqlite3_column_bytes(statement.?, 1);
    if (source_len <= 0 or source_len > engine.native_store_mod.Limits.source_bytes or generation_len != 32) return error.TestSqlFailed;
    const source = try t.allocator.dupe(u8, @as([*]const u8, @ptrCast(source_text))[0..@intCast(source_len)]);
    errdefer t.allocator.free(source);
    var generation: [32]u8 = undefined;
    @memcpy(&generation, @as([*]const u8, @ptrCast(generation_blob))[0..generation.len]);
    if (sqlite3_step(statement.?) != 101) return error.TestSqlFailed;
    return .{ .source = source, .generation = generation };
}

fn waitEscalationCleanup(path: []const u8) !void {
    var timer = try std.time.Timer.start();
    while (timer.read() < 8 * std.time.ns_per_s) {
        var store = try engine.native_store_mod.Store.openReadOnly(t.allocator, path);
        defer store.close();
        if (try store.inspectInteger("SELECT count(*) FROM retry_decision_escalations;") == 0) {
            try t.expectEqual(@as(i64, 0), try store.inspectInteger("SELECT count(*) FROM pragma_foreign_key_check;"));
            return;
        }
        std.time.sleep(20 * std.time.ns_per_ms);
    }
    return error.TimedOut;
}

fn waitPastDeadline(deadline_us: i64) !void {
    var timer = try std.time.Timer.start();
    while (timer.read() < 8 * std.time.ns_per_s) {
        if (std.time.microTimestamp() > deadline_us) return;
        std.time.sleep(20 * std.time.ns_per_ms);
    }
    return error.TimedOut;
}

fn waitKernelAddresses(reader: *engine.firewall.inspection.Inspector, expected: []const @import("shared").IpAddress) !void {
    var timer = try std.time.Timer.start();
    while (timer.read() < 8 * std.time.ns_per_s) {
        var snapshot = reader.inspect() catch |cause| {
            if (cause == error.Changed) {
                std.time.sleep(20 * std.time.ns_per_ms);
                continue;
            }
            return cause;
        };
        defer snapshot.deinit();
        if (snapshot.state == .owned and snapshot.structure_proof == .exact_v1 and snapshot.entries.len == expected.len) {
            var complete = true;
            for (expected) |address| {
                var found = false;
                for (snapshot.entries) |entry| if (std.meta.eql(address, entry.address)) {
                    found = true;
                    break;
                };
                if (!found) {
                    complete = false;
                    break;
                }
            }
            if (complete) return;
        }
        std.time.sleep(20 * std.time.ns_per_ms);
    }
    return error.TimedOut;
}

fn enterNestedNetworkNamespace() !void {
    const parent = std.posix.getenv("F2Z_NATIVE_PARENT_NETNS") orelse return error.MissingIsolationCookie;
    var current_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const current = try std.fs.readLinkAbsolute("/proc/self/ns/net", &current_buffer);
    try t.expect(!std.mem.eql(u8, parent, current));
    if (linux.E.init(linux.unshare(linux.CLONE.NEWNET)) != .SUCCESS) return error.IsolationFailed;
}

fn expectUnhealthySourceSummary(text: []const u8) !void {
    const label = "Sources:";
    const position = std.mem.indexOf(u8, text, label) orelse return error.TestExpectedContains;
    const line_start = if (std.mem.lastIndexOfScalar(u8, text[0..position], '\n')) |index| index + 1 else 0;
    const line_end = std.mem.indexOfScalarPos(u8, text, position, '\n') orelse text.len;
    const value = std.mem.trim(u8, text[position + label.len .. line_end], " \t|");
    const narrow = std.mem.eql(u8, value, "1 unhealthy");
    const wide = std.mem.eql(u8, value, "1 unhealthy; inspect fail2zig jails");
    if (!narrow and !wide) {
        std.debug.print("native daemon: unhealthy source summary expected {s} or {s}; actual line {s}\n", .{ "1 unhealthy", "1 unhealthy; inspect fail2zig jails", text[line_start..line_end] });
        return error.TestExpectedEqual;
    }
}

fn expectContainsDiagnostic(context: []const u8, actual: []const u8, expected: []const u8) !void {
    if (std.mem.indexOf(u8, actual, expected) != null) return;
    const shown = actual[0..@min(actual.len, 2048)];
    std.debug.print("native daemon: {s} expected substring {s}; actual first {d}/{d} bytes: {s}\n", .{ context, expected, shown.len, actual.len, shown });
    return error.TestExpectedContains;
}
fn waitRevision(h: *harness.Harness, expected: u32) !void {
    var timer = try std.time.Timer.start();
    while (timer.read() < 8 * std.time.ns_per_s) {
        const result = try h.sendCommand(.{ .list_jails = {} });
        defer t.allocator.free(result);
        if ((harness.parseJsonUintField(result, "revision") orelse 0) >= expected) return;
        std.time.sleep(20 * std.time.ns_per_ms);
    }
    const last = try h.sendCommand(.{ .list_jails = {} });
    defer t.allocator.free(last);
    std.debug.print("native daemon: missing revision {d}; last jails {s}\n", .{ expected, last });
    return error.TimedOut;
}
fn savedDeadlineExpected(h: *harness.Harness, enforced: bool) !i64 {
    const result = try h.queryList();
    defer t.allocator.free(result);
    const parsed = try std.json.parseFromSlice([]struct { ip: []const u8, expiry_us: i64, enforced: bool, confirmed: bool }, t.allocator, result, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    try t.expectEqual(@as(usize, 1), parsed.value.len);
    try t.expectEqualStrings("203.0.113.7", parsed.value[0].ip);
    try t.expectEqual(enforced, parsed.value[0].enforced);
    try t.expectEqual(enforced, parsed.value[0].confirmed);
    return parsed.value[0].expiry_us;
}

fn savedDeadline(h: *harness.Harness) !i64 {
    return savedDeadlineExpected(h, false);
}

fn formatPortSentryTimestamp(buffer: []u8, timestamp_us: i64) ![]const u8 {
    if (timestamp_us < 0) return error.InvalidTestTimestamp;
    const millis: u64 = @intCast(@divFloor(timestamp_us, std.time.us_per_ms));
    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = millis / 1000 };
    const day_seconds = epoch_seconds.getDaySeconds();
    const year_day = epoch_seconds.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    return std.fmt.bufPrint(buffer, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}+0000", .{
        year_day.year,
        @intFromEnum(month_day.month),
        @as(u16, month_day.day_index) + 1,
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
        millis % 1000,
    });
}

fn expectPortSentryState(path: []const u8, cursor_offset: u64, original_us: i64, nonmatches: []const []const u8) !void {
    var store = try engine.native_store_mod.Store.openReadOnly(t.allocator, path);
    defer store.close();
    try t.expectEqual(@as(i64, 4), try store.inspectInteger("SELECT count(*) FROM records WHERE jail='portsentry' AND disposition='time-eligible-event';"));
    try t.expectEqual(@as(i64, 1), try store.inspectInteger("SELECT count(*) FROM record_detections WHERE jail='portsentry' AND filter='portsentry' AND kind=6 AND family=4 AND subject=x'C0000202';"));
    try t.expectEqual(@as(i64, 3), try store.inspectInteger("SELECT count(*) FROM record_detections WHERE jail='portsentry' AND filter='portsentry' AND kind=3;"));
    try t.expectEqual(@as(i64, 1), try store.inspectInteger("SELECT count(*) FROM retry_decisions WHERE jail='portsentry' AND family=4 AND subject=x'C0000202' AND enforce=0;"));
    const event_query = try std.fmt.allocPrintZ(t.allocator, "SELECT count(*) FROM records r JOIN record_detections d USING(jail,source,occurrence) WHERE r.jail='portsentry' AND d.kind=6 AND r.original_us={d} AND r.effective_us={d} AND r.receipt_us>r.original_us;", .{ original_us, original_us });
    defer t.allocator.free(event_query);
    try t.expectEqual(@as(i64, 1), try store.inspectInteger(event_query));
    for (nonmatches) |line| {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(line);
        hash.update("\n");
        var digest: [32]u8 = undefined;
        hash.final(&digest);
        const query = try std.fmt.allocPrintZ(t.allocator, "SELECT count(*) FROM records r JOIN record_detections d USING(jail,source,occurrence) WHERE r.jail='portsentry' AND r.disposition='time-eligible-event' AND d.kind=3 AND r.raw_hash=x'{s}';", .{std.fmt.fmtSliceHexLower(&digest)});
        defer t.allocator.free(query);
        try t.expectEqual(@as(i64, 1), try store.inspectInteger(query));
    }
    try t.expectEqual(@as(usize, 0), try store.pendingReceiptCount());

    var cursor: ?*SqliteStatement = null;
    if (sqlite3_prepare_v2(@ptrCast(store.db), "SELECT cursor FROM source_cursors WHERE jail='portsentry';", -1, &cursor, null) != 0 or cursor == null) return error.TestSqlFailed;
    defer _ = sqlite3_finalize(cursor.?);
    if (sqlite3_step(cursor.?) != 100) return error.TestSqlFailed;
    const bytes = sqlite3_column_blob(cursor.?, 0) orelse return error.TestSqlFailed;
    const len = sqlite3_column_bytes(cursor.?, 0);
    if (len <= 0 or len > 4096) return error.TestSqlFailed;
    const parsed = try std.json.parseFromSlice(struct { offset: u64 }, t.allocator, @as([*]const u8, @ptrCast(bytes))[0..@intCast(len)], .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    try t.expectEqual(cursor_offset, parsed.value.offset);
    if (sqlite3_step(cursor.?) != 101) return error.TestSqlFailed;
}

fn expectActionTargets(path: []const u8) !void {
    var store = try engine.native_store_mod.Store.open(t.allocator, path);
    defer store.close();
    var entries: [1]engine.native_effect_mod.Entry = undefined;
    const page = try store.effectPage(null, null, &entries);
    try t.expectEqual(@as(usize, 1), page.count);
    var owners: [1]engine.native_effect_mod.Owner = undefined;
    try t.expectEqual(@as(usize, 1), try store.effectOwners(entries[0].scope_key, entries[0].revision, &owners));
    var targets: [engine.native_action_outcome_mod.max_targets_per_action]engine.native_action_outcome_mod.Target = undefined;
    try t.expectEqual(@as(usize, 2), try store.actionTargets(owners[0].decision_id, &targets));
    try t.expectEqual(engine.native_action_outcome_mod.Status.confirmed, targets[0].status);
    try t.expectEqual(engine.native_action_outcome_mod.Status.confirmed, targets[1].status);
    try t.expectEqual(@as(u64, 1), try store.confirmedEffectEvents());
}

test "native daemon: enforcing source commits targets before ack and restart does not duplicate outcomes" {
    if (std.posix.getenv("F2Z_NATIVE_DAEMON_ENFORCEMENT") == null) return error.SkipZigTest;
    const prior = std.posix.getenv("F2Z_NATIVE_PARENT_NETNS") orelse return error.MissingIsolationCookie;
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const current = try std.fs.readLinkAbsolute("/proc/self/ns/net", &buffer);
    try t.expect(!std.mem.eql(u8, prior, current));
    if (linux.E.init(linux.unshare(linux.CLONE.NEWNET)) != .SUCCESS) return error.IsolationFailed;

    var h = try harness.Harness.init(t.allocator, .{ .spawn_daemon = false });
    defer h.deinit();
    try writeEnforcingConfig(&h);
    try h.startDaemon();
    try waitStatus(&h, "\"state\":\"active\"");
    try h.writeLine(failure);
    try waitStatus(&h, "\"decisions_total\":1");
    try h.waitForBan(try @import("shared").IpAddress.parse("203.0.113.7"), 8_000);
    try waitStatus(&h, "\"state\":\"active\"");
    try t.expectEqual(std.process.Child.Term{ .Exited = 0 }, try h.stopDaemon());
    try expectActionTargets(h.state_path);

    try h.startDaemon();
    try waitStatus(&h, "\"state\":\"active\"");
    try waitStatus(&h, "\"decisions_total\":1");
    try t.expectEqual(std.process.Child.Term{ .Exited = 0 }, try h.stopDaemon());
    try expectActionTargets(h.state_path);
}

test "native daemon: portsentry 2.x history file preserves whole record time and cursor" {
    var h = try harness.Harness.init(t.allocator, .{ .spawn_daemon = false });
    defer h.deinit();
    try writePortSentryConfig(&h);
    const positive_us = @divFloor(std.time.microTimestamp() - 5 * std.time.us_per_s, std.time.us_per_ms) * std.time.us_per_ms;
    const stamps_us = [_]i64{ positive_us, positive_us + std.time.us_per_s, positive_us + 2 * std.time.us_per_s, positive_us + 3 * std.time.us_per_s };
    var timestamp_buffers: [4][32]u8 = undefined;
    const positive = try std.fmt.allocPrint(t.allocator, "{s} {s}", .{ try formatPortSentryTimestamp(&timestamp_buffers[0], stamps_us[0]), portsentry_positive_body });
    defer t.allocator.free(positive);
    const ignored = try std.fmt.allocPrint(t.allocator, "{s} {s}", .{ try formatPortSentryTimestamp(&timestamp_buffers[1], stamps_us[1]), portsentry_ignored_body });
    defer t.allocator.free(ignored);
    const prethreshold = try std.fmt.allocPrint(t.allocator, "{s} {s}", .{ try formatPortSentryTimestamp(&timestamp_buffers[2], stamps_us[2]), portsentry_prethreshold_body });
    defer t.allocator.free(prethreshold);
    const nonmatch = try std.fmt.allocPrint(t.allocator, "{s} {s}", .{ try formatPortSentryTimestamp(&timestamp_buffers[3], stamps_us[3]), portsentry_nonmatch_body });
    defer t.allocator.free(nonmatch);
    const history = try std.fmt.allocPrint(t.allocator, "{s}\n{s}\n{s}\n{s}\n", .{ positive, ignored, prethreshold, nonmatch });
    defer t.allocator.free(history);
    try h.writeLine(history);
    try h.startDaemon();
    try waitStatus(&h, "\"state\":\"log-only\"");
    try waitRevision(&h, 5);
    try waitStatus(&h, "\"decisions_total\":1");
    try t.expectEqual(std.process.Child.Term{ .Exited = 0 }, try h.stopDaemon());
    try expectPortSentryState(h.state_path, history.len, positive_us, &.{ ignored, prethreshold, nonmatch });
}

test "native daemon: file retry history and original decision deadline survive graceful and killed restarts" {
    var h = try harness.Harness.init(t.allocator, .{ .spawn_daemon = false });
    defer h.deinit();
    try writeConfig(&h);
    try h.startDaemon();
    try waitStatus(&h, "\"state\":\"log-only\"");
    try h.writeLine(failure);
    try h.writeLine(failure);
    try waitRevision(&h, 3);
    try waitStatus(&h, "\"decisions_total\":0");
    try t.expectEqual(std.process.Child.Term{ .Exited = 0 }, try h.stopDaemon());
    try h.startDaemon();
    try waitRevision(&h, 3);
    try h.writeLine(failure);
    try waitStatus(&h, "\"decisions_total\":1");
    const expiry = try savedDeadline(&h);
    try std.posix.kill(h.child.?.id, std.posix.SIG.KILL);
    const killed = try h.child.?.wait();
    h.child = null;
    try t.expectEqual(std.process.Child.Term{ .Signal = std.posix.SIG.KILL }, killed);
    try h.startDaemon();
    try waitStatus(&h, "\"decisions_total\":1");
    try t.expectEqual(expiry, try savedDeadline(&h));
    try h.writeLine(failure);
    try waitRevision(&h, 5);
    try t.expectEqual(expiry, try savedDeadline(&h));
    try t.expectEqual(std.process.Child.Term{ .Exited = 0 }, try h.stopDaemon());
    var state = try std.fs.cwd().openFile(h.state_path, .{});
    defer state.close();
    var header: [16]u8 = undefined;
    try t.expectEqual(@as(usize, 16), try state.readAll(&header));
    try t.expectEqualStrings("SQLite format 3\x00", &header);
    var sidecar_buffer: [4096]u8 = undefined;
    const sidecar = try engine.journald_source_mod.cursorPath(h.state_path, &sidecar_buffer);
    try t.expectError(error.FileNotFound, std.fs.cwd().access(sidecar, .{}));
}

test "native daemon: schema23 resumes marked escalated cleanup and continues ingestion" {
    const enforcing = std.posix.getenv("F2Z_NATIVE_DAEMON_ENFORCEMENT") != null;
    if (enforcing) try enterNestedNetworkNamespace();
    var h = try harness.Harness.init(t.allocator, .{ .spawn_daemon = false });
    defer h.deinit();
    try writeEscalationCleanupConfig(&h);
    try h.startDaemon();
    try waitStatus(&h, if (enforcing) "\"state\":\"active\"" else "\"state\":\"log-only\"");
    try h.writeLine(failure ++ "\nignored");
    try waitRevision(&h, 3);
    try waitStatus(&h, "\"decisions_total\":1");
    var inspector: ?engine.firewall.inspection.Inspector = null;
    defer if (inspector) |*reader| reader.close();
    if (enforcing) {
        try waitReady(&h);
        const installation = blk: {
            var store = try engine.native_store_mod.Store.openReadOnly(t.allocator, h.state_path);
            defer store.close();
            break :blk (try store.readInstallation()).?;
        };
        try t.expectEqual(engine.native_effect_mod.Backend.nftables, installation.backend);
        inspector = try engine.firewall.inspection.Inspector.open(t.allocator, .{ .id = installation.id, .transport = .nftables }, .{});
        const first_address = try @import("shared").IpAddress.parse("203.0.113.7");
        if (inspector) |*reader| try waitKernelAddresses(reader, &.{first_address});
    }
    const deadline = try savedDeadlineExpected(&h, enforcing);
    try t.expectEqual(std.process.Child.Term{ .Exited = 0 }, try h.stopDaemon());
    try waitPastDeadline(deadline);
    if (inspector) |*reader| try waitKernelAddresses(reader, &.{});

    var source: MaintenanceSource = undefined;
    var marked: engine.native_store_mod.Store.CleanupToken = undefined;
    var marked_revision: u64 = undefined;
    {
        var store = try engine.native_store_mod.Store.open(t.allocator, h.state_path);
        defer store.close();
        try t.expectEqual(@as(i64, 23), store.schema_version);
        try t.expectEqual(@as(i64, 1), try store.inspectInteger("SELECT count(*) FROM retry_decision_escalations;"));
        try t.expectEqual(@as(i64, 0), try store.inspectInteger("SELECT count(*) FROM pragma_foreign_key_check;"));
        const escalated_sequence_value = try store.inspectInteger("SELECT r.source_sequence FROM records r JOIN retry_decision_escalations e USING(jail,source,occurrence) LIMIT 1;");
        try t.expect(escalated_sequence_value > 0);
        const escalated_sequence: u64 = @intCast(escalated_sequence_value);
        source = try maintenanceSource(&store);
        errdefer source.deinit();
        if (inspector) |*reader| {
            var entries: [1]engine.native_effect_mod.Entry = undefined;
            const page = try store.effectPage(null, null, &entries);
            try t.expectEqual(@as(usize, 1), page.count);
            try t.expect(!page.more);
            try t.expectEqual(engine.native_effect_mod.Status.applied, entries[0].status);
            try t.expectEqual(.finite, std.meta.activeTag(entries[0].desired));
            const expired = try store.prepareExpiry(entries[0].scope_key, entries[0].revision, .{ .prepared_us = std.time.microTimestamp() });
            try t.expectEqual(engine.native_effect_mod.Status.pending, expired.status);
            try t.expectEqual(.absent, std.meta.activeTag(expired.desired));
            try store.markDispatched(expired.token(), .{ .prepared_us = std.time.microTimestamp() });
            var observed = try reader.observeExact(.{
                .installation = reader.installation,
                .effect_id = expired.scope_key,
                .aggregate_revision = expired.revision,
                .scope = expired.scope.canonical,
                .operation = .ensure_absent,
            }, .{ .wall_us = std.time.microTimestamp() });
            defer observed.deinit();
            try t.expect(observed.matches_desired);
            try t.expectEqual(engine.native_effect_mod.Settlement.verified, try store.settleVerified(expired.token(), .{
                .installation = expired.installation.id,
                .scope_key = expired.scope_key,
                .fingerprint = observed.snapshot.fingerprint,
                .observed_us = observed.observed_wall_us,
                .qualification = .complete_owned,
                .state = .absent,
            }, .{ .prepared_us = observed.observed_wall_us }));
            var settled: [1]engine.native_effect_mod.Entry = undefined;
            const settled_page = try store.effectPage(null, null, &settled);
            try t.expectEqual(@as(usize, 1), settled_page.count);
            try t.expect(!settled_page.more);
            try t.expectEqual(engine.native_effect_mod.Status.absent, settled[0].status);
            try t.expectEqual(.absent, std.meta.activeTag(settled[0].desired));
        }
        const state = (try store.sourceMaintenance("sshd", source.source, source.generation)).?;
        marked_revision = try store.revision("sshd");
        var fence = engine.native_store_mod.Store.CleanupFence{
            .jail = "sshd",
            .source = source.source,
            .generation = source.generation,
            .jail_revision = marked_revision,
            .consumer_revision = try store.maintenanceConsumerRevision(),
            .effect_revision = try store.maintenanceEffectRevision(),
            .clock = .{ .prepared_us = std.time.microTimestamp() },
            .preparations = .released,
        };
        if (enforcing) {
            const installation = (try store.readInstallation()).?;
            const stream_revision_value = try store.inspectInteger("SELECT revision FROM confirmed_history_stream WHERE id=1;");
            const head_value = try store.inspectInteger("SELECT head FROM confirmed_history_stream WHERE id=1;");
            const retained_value = try store.inspectInteger("SELECT retained_from FROM confirmed_history_stream WHERE id=1;");
            try t.expect(stream_revision_value > 0 and head_value >= 0 and retained_value > 0);
            const head: u64 = @intCast(head_value);
            fence.history = .{
                .installation = installation.id,
                .stream_revision = @intCast(stream_revision_value),
                .head_sequence = head,
                .retained_from_sequence = @intCast(retained_value),
                .after_sequence = head,
                .last_sequence = head,
            };
        }
        marked = (try store.cleanupAdvance(fence, state, state.head_sequence)).?;
        try t.expect(marked.state.sweep_sequence < escalated_sequence);
        try t.expect(marked.state.reject_below_sequence > escalated_sequence);
        try t.expectEqual(@as(i64, 1), try store.inspectInteger("SELECT count(*) FROM retry_decision_escalations;"));
        try t.expectEqual(@as(i64, 0), try store.inspectInteger("SELECT count(*) FROM pragma_foreign_key_check;"));
    }
    defer source.deinit();

    try h.startDaemon();
    try waitEscalationCleanup(h.state_path);
    try waitReady(&h);
    try waitStatus(&h, "\"storage\":\"healthy\"");
    try waitStatus(&h, if (enforcing) "\"state\":\"active\"" else "\"state\":\"log-only\"");
    try h.writeLine(following_failure);
    try waitRevision(&h, @intCast(marked_revision + 1));
    try waitStatus(&h, "\"decisions_total\":2");
    try waitReady(&h);
    if (inspector) |*reader| {
        const second_address = try @import("shared").IpAddress.parse("203.0.113.8");
        try waitKernelAddresses(reader, &.{second_address});
    }
    try t.expectEqual(std.process.Child.Term{ .Exited = 0 }, try h.stopDaemon());

    var store = try engine.native_store_mod.Store.openReadOnly(t.allocator, h.state_path);
    defer store.close();
    try t.expectEqual(@as(i64, 0), try store.inspectInteger("SELECT count(*) FROM pragma_foreign_key_check;"));
    const state = (try store.sourceMaintenance("sshd", source.source, source.generation)).?;
    try t.expectEqual(marked_revision + 1, try store.revision("sshd"));
    try t.expectEqual(marked.state.head_sequence + 1, state.head_sequence);
    try t.expect(state.sweep_sequence >= marked.state.reject_below_sequence - 1);
}

test "native daemon: blocked SQLite writer leaves IPC responsive and resumes exact pending file" {
    var h = try harness.Harness.init(t.allocator, .{ .spawn_daemon = false });
    defer h.deinit();
    try writeConfig(&h);
    try h.startDaemon();
    try waitStatus(&h, "\"state\":\"log-only\"");
    try waitRevision(&h, 1);
    var blocker = try engine.native_store_mod.Store.open(t.allocator, h.state_path);
    defer blocker.close();
    try t.expectEqual(@as(c_int, 0), blocker.api.exec(blocker.db, "BEGIN IMMEDIATE;", null, null, null));
    var locked = true;
    defer if (locked) {
        _ = blocker.api.exec(blocker.db, "ROLLBACK;", null, null, null);
    };
    try h.writeLine(failure);
    try waitStatus(&h, "\"storage\":\"paused\"");
    try waitStatus(&h, "\"state\":\"degraded\"");
    const visible = try std.process.Child.run(.{ .allocator = t.allocator, .argv = &.{ "zig-out/bin/fail2zig", "--socket", h.socket_path, "--timeout", "1000", "--output", "plain", "status" }, .max_output_bytes = 65536 });
    defer t.allocator.free(visible.stdout);
    defer t.allocator.free(visible.stderr);
    try t.expectEqual(std.process.Child.Term{ .Exited = 0 }, visible.term);
    try t.expect(std.mem.indexOf(u8, visible.stdout, "storage\tpaused") != null);
    try t.expect(std.mem.indexOf(u8, visible.stdout, "cause\tBusy") != null);
    try t.expect(std.mem.indexOf(u8, visible.stdout, "sqlite_code\t5") != null);
    try t.expectEqual(@as(u64, 1), try blocker.revision("sshd"));
    try t.expectEqual(@as(c_int, 0), blocker.api.exec(blocker.db, "ROLLBACK;", null, null, null));
    locked = false;
    try waitStatus(&h, "\"state\":\"log-only\"");
    try waitRevision(&h, 2);
    try h.writeLine(failure);
    try h.writeLine(failure);
    try waitStatus(&h, "\"decisions_total\":1");
    _ = try savedDeadline(&h);
    try t.expectEqual(std.process.Child.Term{ .Exited = 0 }, try h.stopDaemon());
}

test "native daemon: invalid escalation refuses before state access and changed generations preserve history" {
    var h = try harness.Harness.init(t.allocator, .{ .spawn_daemon = false });
    defer h.deinit();
    try writeConfig(&h);
    const original = try std.fs.cwd().readFileAlloc(t.allocator, h.config_path, 8192);
    defer t.allocator.free(original);
    const unsupported = try std.mem.replaceOwned(u8, t.allocator, original, "bantime = 60", "bantime = \"permanent\"\nbantime_increment_enabled = true");
    defer t.allocator.free(unsupported);
    try std.fs.cwd().writeFile(.{ .sub_path = h.config_path, .data = unsupported });
    try t.expectError(error.DaemonUnavailable, h.startDaemon());
    try t.expectError(error.FileNotFound, std.fs.cwd().access(h.state_path, .{}));
    const supported = try std.mem.replaceOwned(u8, t.allocator, original, "banaction = \"log-only\"", "banaction = \"log-only\"\nbantime_increment_enabled = true");
    defer t.allocator.free(supported);
    try std.fs.cwd().writeFile(.{ .sub_path = h.config_path, .data = supported });
    try h.startDaemon();
    try h.writeLine(failure);
    try waitRevision(&h, 2);
    _ = try h.stopDaemon();
    const changed = try std.mem.replaceOwned(u8, t.allocator, supported, "maxretry = 3", "maxretry = 2");
    defer t.allocator.free(changed);
    try std.fs.cwd().writeFile(.{ .sub_path = h.config_path, .data = changed });
    try t.expectError(error.DaemonUnavailable, h.startDaemon());
    var store = try engine.native_store_mod.Store.open(t.allocator, h.state_path);
    defer store.close();
    try t.expectEqual(@as(u64, 2), try store.revision("sshd"));
    try t.expectEqual(@as(u16, 1), (try store.retryState("sshd", .{ .v4 = .{ 203, 0, 113, 7 } })).?.count);
}

test "native daemon: only explicit recidive may use the bounded internal source" {
    var h = try harness.Harness.init(t.allocator, .{ .spawn_daemon = false });
    defer h.deinit();
    try writeConfig(&h);
    const original = try std.fs.cwd().readFileAlloc(t.allocator, h.config_path, 8192);
    defer t.allocator.free(original);
    const invalid = try std.mem.replaceOwned(u8, t.allocator, original, "source = \"file\"", "source = \"internal\"");
    defer t.allocator.free(invalid);
    try std.fs.cwd().writeFile(.{ .sub_path = h.config_path, .data = invalid });
    try t.expectError(error.DaemonUnavailable, h.startDaemon());
    try t.expectError(error.FileNotFound, std.fs.cwd().access(h.state_path, .{}));

    {
        var file = try std.fs.cwd().createFile(h.config_path, .{ .mode = 0o600 });
        defer file.close();
        try file.writeAll(original);
        try file.writeAll(
            \\[jails.recidive]
            \\filter = "recidive"
            \\source = "internal"
            \\maxretry = 2
            \\findtime = 86400
            \\bantime = 3600
            \\
        );
    }
    try h.startDaemon();
    try waitStatus(&h, "\"state\":\"log-only\"");
    const jails = try h.sendCommand(.{ .list_jails = {} });
    defer t.allocator.free(jails);
    try t.expect(std.mem.indexOf(u8, jails, "\"name\":\"recidive\"") != null);
    try t.expect(std.mem.indexOf(u8, jails, "\"source\":\"internal\"") != null);
    try t.expectEqual(std.process.Child.Term{ .Exited = 0 }, try h.stopDaemon());
}

const malformed_line = "untrusted request \xff client: 203.0.113.99\n";
const dirty_failure = "Failed password for r\xffoot from 203.0.113.7 port 22 ssh2\n";
const damaged_ip_failure = "Failed password for root from 203.0.113.\xff99 port 22 ssh2\n";
// The live decision pins this source prefix so background cleanup cannot retire
// the diagnostic rows before their exact durable identity is inspected.
const damaged_prefix = dirty_failure ++ malformed_line ++ damaged_ip_failure;

fn expectMalformedDispositions(path: []const u8, decisions: i64) !void {
    var store = try engine.native_store_mod.Store.openReadOnly(t.allocator, path);
    defer store.close();
    try t.expectEqual(@as(i64, 6), try store.inspectInteger("SELECT count(*) FROM records WHERE disposition='time-eligible-receipt-encoding-replaced' AND receipt_us IS NOT NULL AND length(receipt_generation)=32;"));
    try t.expectEqual(@as(i64, 3), try store.inspectInteger("SELECT count(*) FROM records WHERE jail='sshd' AND disposition='time-eligible-receipt-encoding-replaced';"));
    try t.expectEqual(@as(i64, 3), try store.inspectInteger("SELECT count(*) FROM records WHERE jail='shared' AND disposition='time-eligible-receipt-encoding-replaced';"));
    try t.expectEqual(decisions, try store.inspectInteger("SELECT count(*) FROM retry_decisions;"));
    try t.expectEqual(@as(usize, 0), try store.pendingReceiptCount());
    try t.expectEqual(@as(i64, 0), try store.inspectInteger("SELECT count(*) FROM pragma_foreign_key_check;"));
    var expected_offset: u64 = 0;
    for ([_][]const u8{ dirty_failure, malformed_line, damaged_ip_failure }, 0..) |line, index| {
        expected_offset += line.len;
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(line, &hash, .{});
        const query = try std.fmt.allocPrintZ(t.allocator, "SELECT count(*) FROM records WHERE disposition='time-eligible-receipt-encoding-replaced' AND raw_hash=x'{s}';", .{std.fmt.fmtSliceHexLower(&hash)});
        defer t.allocator.free(query);
        try t.expectEqual(@as(i64, 2), try store.inspectInteger(query));
        const decision_query = try std.fmt.allocPrintZ(t.allocator, "SELECT count(*) FROM records r JOIN retry_decisions d USING(jail,source,occurrence) WHERE r.raw_hash=x'{s}';", .{std.fmt.fmtSliceHexLower(&hash)});
        defer t.allocator.free(decision_query);
        // Only the damaged username retains a valid failure and address. Damage
        // alone and a damaged address must never manufacture a decision.
        try t.expectEqual(@as(i64, if (index == 0) 2 else 0), try store.inspectInteger(decision_query));
        const cursor_query = try std.fmt.allocPrintZ(t.allocator, "SELECT cursor FROM records WHERE raw_hash=x'{s}';", .{std.fmt.fmtSliceHexLower(&hash)});
        defer t.allocator.free(cursor_query);
        var stmt: ?*SqliteStatement = null;
        if (sqlite3_prepare_v2(@ptrCast(store.db), cursor_query, -1, &stmt, null) != 0 or stmt == null) return error.TestSqlFailed;
        defer _ = sqlite3_finalize(stmt.?);
        for (0..2) |_| {
            if (sqlite3_step(stmt.?) != 100) return error.TestSqlFailed;
            const bytes = sqlite3_column_blob(stmt.?, 0) orelse return error.TestSqlFailed;
            const len = sqlite3_column_bytes(stmt.?, 0);
            if (len <= 0 or len > 4096) return error.TestSqlFailed;
            const parsed = try std.json.parseFromSlice(struct { offset: u64 }, t.allocator, @as([*]const u8, @ptrCast(bytes))[0..@intCast(len)], .{ .ignore_unknown_fields = true });
            defer parsed.deinit();
            try t.expectEqual(expected_offset, parsed.value.offset);
        }
        if (sqlite3_step(stmt.?) != 101) return error.TestSqlFailed;
    }

    try t.expect(try malformedCursorsComplete(&store, decisions == 6));
}

fn malformedCursorsComplete(store: *engine.native_store_mod.Store, after_restart: bool) !bool {
    var cursors: ?*SqliteStatement = null;
    if (sqlite3_prepare_v2(@ptrCast(store.db), "SELECT jail,cursor FROM source_cursors ORDER BY jail;", -1, &cursors, null) != 0 or cursors == null) return error.TestSqlFailed;
    defer _ = sqlite3_finalize(cursors.?);
    var complete = true;
    for ([_][]const u8{ "good", "shared", "sshd" }) |jail| {
        const step = sqlite3_step(cursors.?);
        if (step == 101) return false;
        if (step != 100) return error.TestSqlFailed;
        const name = sqlite3_column_text(cursors.?, 0) orelse return error.TestSqlFailed;
        try t.expectEqualStrings(jail, std.mem.span(name));
        const bytes = sqlite3_column_blob(cursors.?, 1) orelse return error.TestSqlFailed;
        const len = sqlite3_column_bytes(cursors.?, 1);
        if (len <= 0 or len > 4096) return error.TestSqlFailed;
        const parsed = try std.json.parseFromSlice(struct { offset: u64 }, t.allocator, @as([*]const u8, @ptrCast(bytes))[0..@intCast(len)], .{ .ignore_unknown_fields = true });
        defer parsed.deinit();
        const expected: u64 = (if (std.mem.eql(u8, jail, "good")) @as(u64, 0) else damaged_prefix.len) + failure.len + 1 + (if (after_restart) @as(u64, following_failure.len + 1) else 0);
        if (parsed.value.offset > expected) return error.UnexpectedSourceOffset;
        if (parsed.value.offset < expected) complete = false;
    }
    if (sqlite3_step(cursors.?) != 101) return error.TestSqlFailed;
    return complete;
}

fn waitMalformedCursors(path: []const u8, after_restart: bool) !void {
    var timer = try std.time.Timer.start();
    while (timer.read() < 8 * std.time.ns_per_s) {
        {
            var store = try engine.native_store_mod.Store.openReadOnly(t.allocator, path);
            defer store.close();
            if (try malformedCursorsComplete(&store, after_restart)) return;
        }
        std.time.sleep(20 * std.time.ns_per_ms);
    }
    return error.TimedOut;
}

test "native daemon: malformed shared source advances durably and stays ready across restart" {
    const enforcing = std.posix.getenv("F2Z_NATIVE_DAEMON_ENFORCEMENT") != null;
    if (enforcing) try enterNestedNetworkNamespace();
    var h = try harness.Harness.init(t.allocator, .{ .spawn_daemon = false });
    defer h.deinit();
    const good_path = try std.fmt.allocPrint(t.allocator, "{s}/good.log", .{h.tmp_abs});
    defer t.allocator.free(good_path);
    var good = try std.fs.cwd().createFile(good_path, .{});
    defer good.close();
    {
        var conf = try std.fs.cwd().createFile(h.config_path, .{ .mode = 0o600 });
        defer conf.close();
        try conf.writer().print(
            \\[global]
            \\native_ingestion = true
            \\state_file = "{s}"
            \\socket_path = "{s}"
            \\metrics_enabled = false
            \\
        , .{ h.state_path, h.socket_path });
        if (enforcing) try conf.writer().print(
            \\firewall = "nftables"
            \\firewall_namespace = "/proc/{d}/ns/net"
            \\
        , .{linux.getpid()});
        try conf.writeAll("[defaults]\nmaxretry = 1\nfindtime = 600\nbantime = 60\n");
        try conf.writeAll(if (enforcing) "enforce = true\n" else "banaction = \"log-only\"\n");
        for ([_][]const u8{ "sshd", "shared", "good" }) |name| try conf.writer().print(
            \\[jails.{s}]
            \\filter = "sshd"
            \\source = "file"
            \\timestamp = "undated"
            \\logpath = ["{s}"]
            \\
        , .{ name, if (std.mem.eql(u8, name, "good")) good_path else h.log_path });
    }
    try h.writeLine(damaged_prefix ++ failure);
    try good.writeAll(failure ++ "\n");
    try h.startDaemon();
    try waitStatus(&h, "\"decisions_total\":3");
    try waitMalformedCursors(h.state_path, false);
    try waitReady(&h);
    try waitStatus(&h, "\"unhealthy_sources\":0");
    var inspector: ?engine.firewall.inspection.Inspector = null;
    defer if (inspector) |*reader| reader.close();
    const first = try @import("shared").IpAddress.parse("203.0.113.7");
    const second = try @import("shared").IpAddress.parse("203.0.113.8");
    if (enforcing) {
        const installation = blk: {
            var store = try engine.native_store_mod.Store.openReadOnly(t.allocator, h.state_path);
            defer store.close();
            break :blk (try store.readInstallation()).?;
        };
        inspector = try engine.firewall.inspection.Inspector.open(t.allocator, .{ .id = installation.id, .transport = .nftables }, .{});
        if (inspector) |*reader| try waitKernelAddresses(reader, &.{first});
    }
    try t.expectEqual(std.process.Child.Term{ .Exited = 0 }, try h.stopDaemon());
    try expectMalformedDispositions(h.state_path, 3);
    try h.startDaemon();
    try waitReady(&h);
    try waitStatus(&h, "\"decisions_total\":3");
    try waitMalformedCursors(h.state_path, false);
    try h.writeLine(following_failure);
    try good.writeAll(following_failure ++ "\n");
    try waitStatus(&h, "\"decisions_total\":6");
    try waitMalformedCursors(h.state_path, true);
    try waitReady(&h);
    try waitStatus(&h, "\"unhealthy_sources\":0");
    if (inspector) |*reader| try waitKernelAddresses(reader, &.{ first, second });
    try t.expectEqual(std.process.Child.Term{ .Exited = 0 }, try h.stopDaemon());
    try expectMalformedDispositions(h.state_path, 6);
}

test "native daemon: oversized source isolates its jail while independent file decisions continue" {
    var h = try harness.Harness.init(t.allocator, .{ .spawn_daemon = false });
    defer h.deinit();
    try writeConfig(&h);
    const good_path = try std.fmt.allocPrint(t.allocator, "{s}/good.log", .{h.tmp_abs});
    defer t.allocator.free(good_path);
    var good = try std.fs.cwd().createFile(good_path, .{});
    defer good.close();
    var conf = try std.fs.cwd().openFile(h.config_path, .{ .mode = .write_only });
    try conf.seekFromEnd(0);
    try conf.writer().print(
        \\
        \\[jails.good]
        \\filter = "sshd"
        \\source = "file"
        \\timestamp = "undated"
        \\maxretry = 1
        \\logpath = ["{s}"]
        \\
    , .{good_path});
    conf.close();
    try h.startDaemon();
    try waitStatus(&h, "\"state\":\"log-only\"");
    try h.writeLine(&([_]u8{'x'} ** 2048));
    try waitStatus(&h, "\"state\":\"degraded\"");
    try good.writeAll(failure ++ "\n");
    try waitStatus(&h, "\"decisions_total\":1");
    try waitStatus(&h, "\"storage\":\"healthy\"");
    const jails = try h.sendCommand(.{ .list_jails = {} });
    defer t.allocator.free(jails);
    try expectContainsDiagnostic("raw jails unhealthy source state", jails, "\"name\":\"sshd\",\"healthy\":false");
    try expectContainsDiagnostic("raw jails independent source state", jails, "\"name\":\"good\",\"healthy\":true");
    try waitStatus(&h, "\"unhealthy_sources\":1");
    const CauseView = struct { name: []const u8, cause: []const u8 };
    const causes = try std.json.parseFromSlice([]const CauseView, t.allocator, jails, .{ .ignore_unknown_fields = true });
    defer causes.deinit();
    var source_cause: ?[]const u8 = null;
    for (causes.value) |entry| if (std.mem.eql(u8, entry.name, "sshd")) {
        source_cause = entry.cause;
    };
    if (source_cause == null) {
        std.debug.print("native daemon: expected sshd source cause; actual jails {s}\n", .{jails[0..@min(jails.len, 2048)]});
        return error.TestExpectedEqual;
    }
    if (std.mem.eql(u8, source_cause.?, "none")) {
        std.debug.print("native daemon: expected non-none sshd source cause; actual cause {s}; jails {s}\n", .{ source_cause.?, jails[0..@min(jails.len, 2048)] });
        return error.TestExpectedEqual;
    }
    var cause_buffer: [160]u8 = undefined;
    const cause_text = try std.fmt.bufPrint(&cause_buffer, "broken ({s}", .{source_cause.?});
    // Exercise the delivered formatter against the same actual daemon fault.
    const checks = [_]struct { format: []const u8, command: []const u8, needle: []const u8 }{
        .{ .format = "plain", .command = "status", .needle = "unhealthy_sources\t1" },
        .{ .format = "plain", .command = "status", .needle = "storage\thealthy" },
        .{ .format = "table", .command = "status", .needle = "" },
        .{ .format = "table", .command = "jails", .needle = cause_text },
    };
    for (checks) |check| {
        const result = try std.process.Child.run(.{ .allocator = t.allocator, .argv = &.{ "zig-out/bin/fail2zig", "--socket", h.socket_path, "--timeout", "1000", "--output", check.format, check.command }, .max_output_bytes = 65536 });
        defer t.allocator.free(result.stdout);
        defer t.allocator.free(result.stderr);
        if (!std.meta.eql(std.process.Child.Term{ .Exited = 0 }, result.term)) {
            std.debug.print("native daemon: delivered {s} {s} expected exit 0; actual term {any}; stderr first {d}/{d} bytes: {s}\n", .{ check.format, check.command, result.term, @min(result.stderr.len, 2048), result.stderr.len, result.stderr[0..@min(result.stderr.len, 2048)] });
            return error.TestExpectedEqual;
        }
        if (check.needle.len == 0)
            try expectUnhealthySourceSummary(result.stdout)
        else {
            var context_buffer: [96]u8 = undefined;
            const context = try std.fmt.bufPrint(&context_buffer, "delivered {s} {s}", .{ check.format, check.command });
            try expectContainsDiagnostic(context, result.stdout, check.needle);
        }
        if (std.mem.indexOf(u8, result.stdout, "could not parse") != null) {
            std.debug.print("native daemon: delivered {s} {s} unexpectedly reported a parse failure; stdout first {d}/{d} bytes: {s}\n", .{ check.format, check.command, @min(result.stdout.len, 2048), result.stdout.len, result.stdout[0..@min(result.stdout.len, 2048)] });
            return error.TestUnexpectedResult;
        }
    }
    _ = try h.stopDaemon();
}

test "native daemon: delivered client renders native status jails version and decision deadlines" {
    var h = try harness.Harness.init(t.allocator, .{ .spawn_daemon = false });
    defer h.deinit();
    try writeConfig(&h);
    try h.startDaemon();
    try waitStatus(&h, "\"state\":\"log-only\"");
    for (0..3) |_| try h.writeLine(failure);
    try waitStatus(&h, "\"decisions_total\":1");
    const commands = [_][]const u8{ "status", "jails", "version", "list" };
    const expected = [_][]const u8{ "log-only", "sshd", "daemon\t0.4.2", "203.0.113.7" };
    for (commands, expected) |command, text| {
        const result = try std.process.Child.run(.{ .allocator = t.allocator, .argv = &.{ "zig-out/bin/fail2zig", "--socket", h.socket_path, "--timeout", "1000", "--output", "plain", command }, .max_output_bytes = 65536 });
        defer t.allocator.free(result.stdout);
        defer t.allocator.free(result.stderr);
        try t.expectEqual(std.process.Child.Term{ .Exited = 0 }, result.term);
        try t.expect(std.mem.indexOf(u8, result.stdout, text) != null);
        try t.expect(std.mem.indexOf(u8, result.stdout, "could not parse") == null);
    }
    _ = try h.stopDaemon();
}

test "native daemon: retained rotation and detected copytruncate preserve retry state across restart" {
    var h = try harness.Harness.init(t.allocator, .{ .spawn_daemon = false });
    defer h.deinit();
    try writeConfig(&h);
    try h.startDaemon();
    try waitStatus(&h, "\"state\":\"log-only\"");
    try h.writeLine(failure);
    try h.writeLine(failure);
    try waitRevision(&h, 3);
    const rotated = try std.fmt.allocPrint(t.allocator, "{s}.1", .{h.log_path});
    defer t.allocator.free(rotated);
    var old = try std.fs.cwd().openFile(h.log_path, .{ .mode = .write_only });
    defer old.close();
    try old.seekFromEnd(0);
    try std.fs.cwd().rename(h.log_path, rotated);
    var replacement = try std.fs.cwd().createFile(h.log_path, .{});
    defer replacement.close();
    try old.writeAll(failure ++ "\n");
    try replacement.writeAll(failure ++ "\n");
    try waitRevision(&h, 6);
    try waitStatus(&h, "\"decisions_total\":1");
    const expiry = try savedDeadline(&h);
    try replacement.setEndPos(0);
    try replacement.seekTo(0);
    try replacement.writeAll("ignored\n");
    try waitRevision(&h, 8);
    try std.posix.kill(h.child.?.id, std.posix.SIG.KILL);
    try t.expectEqual(std.process.Child.Term{ .Signal = std.posix.SIG.KILL }, try h.child.?.wait());
    h.child = null;
    try h.startDaemon();
    try waitStatus(&h, "\"state\":\"log-only\"");
    try waitRevision(&h, 8);
    try t.expectEqual(expiry, try savedDeadline(&h));
    try old.writeAll("ignored\n");
    try waitRevision(&h, 9);
    try t.expectEqual(expiry, try savedDeadline(&h));
    _ = try h.stopDaemon();
    var store = try engine.native_store_mod.Store.open(t.allocator, h.state_path);
    defer store.close();
    try t.expectEqual(@as(u64, 9), try store.revision("sshd"));
    try t.expectEqual(@as(usize, 0), try store.pendingReceiptCount());
}

test "native daemon: killed writer pause and downtime rotation retain unacknowledged input" {
    var h = try harness.Harness.init(t.allocator, .{ .spawn_daemon = false });
    defer h.deinit();
    try writeConfig(&h);
    try h.startDaemon();
    try h.writeLine(failure);
    try h.writeLine(failure);
    try waitRevision(&h, 3);
    var blocker = try engine.native_store_mod.Store.open(t.allocator, h.state_path);
    defer blocker.close();
    try t.expectEqual(@as(c_int, 0), blocker.api.exec(blocker.db, "BEGIN IMMEDIATE;", null, null, null));
    var locked = true;
    defer if (locked) {
        _ = blocker.api.exec(blocker.db, "ROLLBACK;", null, null, null);
    };
    try h.writeLine(failure);
    try waitStatus(&h, "\"storage\":\"paused\"");
    try t.expectEqual(@as(u64, 3), try blocker.revision("sshd"));
    try std.posix.kill(h.child.?.id, std.posix.SIG.KILL);
    try t.expectEqual(std.process.Child.Term{ .Signal = std.posix.SIG.KILL }, try h.child.?.wait());
    h.child = null;
    const rotated = try std.fmt.allocPrint(t.allocator, "{s}.1", .{h.log_path});
    defer t.allocator.free(rotated);
    try std.fs.cwd().rename(h.log_path, rotated);
    const replacement = try std.fs.cwd().createFile(h.log_path, .{});
    replacement.close();
    try t.expectEqual(@as(c_int, 0), blocker.api.exec(blocker.db, "ROLLBACK;", null, null, null));
    locked = false;
    try h.startDaemon();
    try waitStatus(&h, "\"state\":\"log-only\"");
    try waitStatus(&h, "\"decisions_total\":1");
    try waitRevision(&h, 5);
    _ = try savedDeadline(&h);
    _ = try h.stopDaemon();
    try t.expectEqual(@as(u64, 5), try blocker.revision("sshd"));
    try t.expectEqual(@as(usize, 0), try blocker.pendingReceiptCount());
}

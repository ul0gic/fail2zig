// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const t = std.testing;
const engine = @import("engine");
const harness = @import("harness.zig");
const linux = std.os.linux;
const failure = "Failed password for root from 203.0.113.7 port 22 ssh2";

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
fn savedDeadline(h: *harness.Harness) !i64 {
    const result = try h.queryList();
    defer t.allocator.free(result);
    const parsed = try std.json.parseFromSlice([]struct { ip: []const u8, expiry_us: i64, enforced: bool, confirmed: bool }, t.allocator, result, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    try t.expectEqual(@as(usize, 1), parsed.value.len);
    try t.expectEqualStrings("203.0.113.7", parsed.value[0].ip);
    try t.expect(!parsed.value[0].enforced and !parsed.value[0].confirmed);
    return parsed.value[0].expiry_us;
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

test "native daemon: malformed source isolates its jail while independent file decisions continue" {
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
    try h.writeLine("\xff");
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

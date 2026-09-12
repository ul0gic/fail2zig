// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const t = std.testing;
const engine = @import("engine");
const harness = @import("harness.zig");
const failure = "Failed password for root from 203.0.113.7 port 22 ssh2";

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
fn waitRevision(h: *harness.Harness, expected: u32) !void {
    var timer = try std.time.Timer.start();
    while (timer.read() < 8 * std.time.ns_per_s) {
        const result = try h.sendCommand(.{ .list_jails = {} });
        defer t.allocator.free(result);
        if ((harness.parseJsonUintField(result, "revision") orelse 0) >= expected) return;
        std.time.sleep(20 * std.time.ns_per_ms);
    }
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

test "native daemon: file retry history and original decision deadline survive graceful and killed restarts" {
    var h = try harness.Harness.init(t.allocator, .{ .spawn_daemon = false });
    defer h.deinit();
    try writeConfig(&h);
    try h.startDaemon();
    try waitStatus(&h, "\"state\":\"log-only\"");
    try h.writeLine(failure);
    try h.writeLine(failure);
    try waitRevision(&h, 3); // Empty-file baseline plus two distinct occurrences.
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

test "native daemon: unsupported protection refuses before state access and changed generations preserve history" {
    var h = try harness.Harness.init(t.allocator, .{ .spawn_daemon = false });
    defer h.deinit();
    try writeConfig(&h);
    const original = try std.fs.cwd().readFileAlloc(t.allocator, h.config_path, 8192);
    defer t.allocator.free(original);
    const enforcing = try std.mem.replaceOwned(u8, t.allocator, original, "banaction = \"log-only\"", "banaction = \"nftables\"");
    defer t.allocator.free(enforcing);
    try std.fs.cwd().writeFile(.{ .sub_path = h.config_path, .data = enforcing });
    try t.expectError(error.DaemonUnavailable, h.startDaemon());
    try t.expectError(error.FileNotFound, std.fs.cwd().access(h.state_path, .{}));
    try writeConfig(&h);
    try h.startDaemon();
    try h.writeLine(failure);
    try waitRevision(&h, 2);
    _ = try h.stopDaemon();
    const changed = try std.mem.replaceOwned(u8, t.allocator, original, "maxretry = 3", "maxretry = 2");
    defer t.allocator.free(changed);
    try std.fs.cwd().writeFile(.{ .sub_path = h.config_path, .data = changed });
    try t.expectError(error.DaemonUnavailable, h.startDaemon());
    var store = try engine.native_store_mod.Store.open(t.allocator, h.state_path);
    defer store.close();
    try t.expectEqual(@as(u64, 2), try store.revision("sshd"));
    try t.expectEqual(@as(u16, 1), (try store.retryState("sshd", .{ .v4 = .{ 203, 0, 113, 7 } })).?.count);
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
    try t.expect(std.mem.indexOf(u8, jails, "\"name\":\"sshd\",\"healthy\":false") != null);
    try t.expect(std.mem.indexOf(u8, jails, "\"name\":\"good\",\"healthy\":true") != null);
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
    const expected = [_][]const u8{ "log-only", "sshd", "daemon\t0.3.1-dev", "203.0.113.7" };
    for (commands, expected) |command, text| {
        const result = try std.process.Child.run(.{ .allocator = t.allocator, .argv = &.{ "zig-out/bin/fail2zig-client", "--socket", h.socket_path, "--timeout", "1000", "--output", "plain", command }, .max_output_bytes = 65536 });
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
    // Two baselines and four records prove both incarnations were consumed.
    try waitRevision(&h, 6);
    try waitStatus(&h, "\"decisions_total\":1");
    const expiry = try savedDeadline(&h);
    // Observe a smaller, different prefix; this does not claim undetectable
    // truncate/regrow cycles with an identical prefix can be recovered.
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

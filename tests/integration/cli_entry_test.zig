// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const harness = @import("harness.zig");

const testing = std.testing;
const exe = "zig-out/bin/fail2zig";

const Run = struct {
    code: u8,
    stdout: []u8,
    stderr: []u8,
    fn deinit(self: Run, a: std.mem.Allocator) void {
        a.free(self.stdout);
        a.free(self.stderr);
    }
};

fn run(a: std.mem.Allocator, argv: []const []const u8) !Run {
    const r = try std.process.Child.run(.{ .allocator = a, .argv = argv, .max_output_bytes = 1 << 20 });
    const code: u8 = switch (r.term) {
        .Exited => |c| c,
        else => 255,
    };
    return .{ .code = code, .stdout = r.stdout, .stderr = r.stderr };
}

fn waitStatusContains(a: std.mem.Allocator, h: *harness.Harness, needle: []const u8) !Run {
    var timer = try std.time.Timer.start();
    while (timer.read() < 10 * std.time.ns_per_s) {
        const result = try run(a, &.{ exe, "--socket", h.socket_path, "--timeout", "2000", "--output", "json", "status" });
        if (result.code == 0 and std.mem.indexOf(u8, result.stdout, needle) != null) return result;
        result.deinit(a);
        std.time.sleep(50 * std.time.ns_per_ms);
    }
    return error.TimedOut;
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

test "cli entry: only one executable is installed" {
    std.fs.cwd().access(exe, .{}) catch return error.SkipZigTest;
    try testing.expectError(error.FileNotFound, std.fs.cwd().access("zig-out/bin/fail2zig-client", .{}));
}

test "cli entry: local help and version come from the same artifact and never name a second binary" {
    const a = testing.allocator;
    std.fs.cwd().access(exe, .{}) catch return error.SkipZigTest;
    const help = try run(a, &.{ exe, "--help" });
    defer help.deinit(a);
    try testing.expectEqual(@as(u8, 0), help.code);
    try testing.expect(std.mem.indexOf(u8, help.stdout, "fail2zig [daemon] [OPTIONS]") != null);
    try testing.expect(std.mem.indexOf(u8, help.stdout, "firewall") != null);
    try testing.expect(std.mem.indexOf(u8, help.stdout, "fail2zig-client") == null);
    const ver = try run(a, &.{ exe, "--version" });
    defer ver.deinit(a);
    try testing.expectEqual(@as(u8, 0), ver.code);
    try testing.expect(std.mem.startsWith(u8, ver.stdout, "fail2zig "));
    const ophelp = try run(a, &.{ exe, "help", "ban" });
    defer ophelp.deinit(a);
    try testing.expectEqual(@as(u8, 0), ophelp.code);
    try testing.expect(std.mem.indexOf(u8, ophelp.stdout, "fail2zig ban") != null);
    try testing.expect(std.mem.indexOf(u8, ophelp.stdout, "fail2zig-client") == null);
    const firewall_help = try run(a, &.{ exe, "help", "firewall" });
    defer firewall_help.deinit(a);
    try testing.expectEqual(@as(u8, 0), firewall_help.code);
    try testing.expect(std.mem.indexOf(u8, firewall_help.stdout, "fail2zig firewall show") != null);
    try testing.expect(std.mem.indexOf(u8, firewall_help.stdout, "--limit") != null);
    try testing.expect(std.mem.indexOf(u8, firewall_help.stdout, "--cursor") != null);
    const comp = try run(a, &.{ exe, "completions", "bash" });
    defer comp.deinit(a);
    try testing.expectEqual(@as(u8, 0), comp.code);
    try testing.expect(std.mem.indexOf(u8, comp.stdout, "fail2zig-client") == null);
    try testing.expect(std.mem.indexOf(u8, comp.stdout, "firewall") != null);
}

test "cli entry: --import-config preserves documented exit classes" {
    const a = testing.allocator;
    std.fs.cwd().access(exe, .{}) catch return error.SkipZigTest;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const source = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(source);

    try tmp.dir.writeFile(.{
        .sub_path = "jail.conf",
        .data =
        \\[DEFAULT]
        \\bantime = 600
        \\[sshd]
        \\enabled = true
        \\filter = sshd
        \\logpath = /var/log/auth.log
        ,
    });
    const enabled_output = try std.fs.path.join(a, &.{ source, "enabled.toml" });
    defer a.free(enabled_output);
    const enabled = try run(a, &.{ exe, "--import-config", source, "--import-output", enabled_output });
    defer enabled.deinit(a);
    try testing.expectEqual(@as(u8, 0), enabled.code);
    try std.fs.cwd().access(enabled_output, .{});

    try tmp.dir.writeFile(.{
        .sub_path = "jail.conf",
        .data =
        \\[DEFAULT]
        \\bantime = 600
        ,
    });
    const disabled_output = try std.fs.path.join(a, &.{ source, "disabled.toml" });
    defer a.free(disabled_output);
    const disabled = try run(a, &.{ exe, "--import-config", source, "--import-output", disabled_output });
    defer disabled.deinit(a);
    try testing.expectEqual(@as(u8, 1), disabled.code);

    try tmp.dir.writeFile(.{ .sub_path = "jail.conf", .data = "[sshd\n" });
    const invalid_output = try std.fs.path.join(a, &.{ source, "invalid.toml" });
    defer a.free(invalid_output);
    const invalid = try run(a, &.{ exe, "--import-config", source, "--import-output", invalid_output });
    defer invalid.deinit(a);
    try testing.expectEqual(@as(u8, 2), invalid.code);
    try testing.expectEqualStrings("import: failed: UnterminatedSection\n", invalid.stderr);
}

test "cli entry: usage failures are class 2 and absent service is class 3" {
    const a = testing.allocator;
    std.fs.cwd().access(exe, .{}) catch return error.SkipZigTest;
    const unknown = try run(a, &.{ exe, "bogus" });
    defer unknown.deinit(a);
    try testing.expectEqual(@as(u8, 2), unknown.code);
    const mixed = try run(a, &.{ exe, "--config", "/nonexistent.toml", "status" });
    defer mixed.deinit(a);
    try testing.expectEqual(@as(u8, 2), mixed.code);
    const badout = try run(a, &.{ exe, "--output", "xml", "status" });
    defer badout.deinit(a);
    try testing.expectEqual(@as(u8, 2), badout.code);
    const noban = try run(a, &.{ exe, "ban" });
    defer noban.deinit(a);
    try testing.expectEqual(@as(u8, 2), noban.code);
    const no_firewall_action = try run(a, &.{ exe, "firewall" });
    defer no_firewall_action.deinit(a);
    try testing.expectEqual(@as(u8, 2), no_firewall_action.code);
    const bad_firewall_action = try run(a, &.{ exe, "firewall", "inspect" });
    defer bad_firewall_action.deinit(a);
    try testing.expectEqual(@as(u8, 2), bad_firewall_action.code);
    const zero_firewall_limit = try run(a, &.{ exe, "firewall", "show", "--limit", "0" });
    defer zero_firewall_limit.deinit(a);
    try testing.expectEqual(@as(u8, 2), zero_firewall_limit.code);
    const large_firewall_limit = try run(a, &.{ exe, "firewall", "show", "--limit", "257" });
    defer large_firewall_limit.deinit(a);
    try testing.expectEqual(@as(u8, 2), large_firewall_limit.code);
    const missing_firewall_cursor = try run(a, &.{ exe, "firewall", "show", "--cursor" });
    defer missing_firewall_cursor.deinit(a);
    try testing.expectEqual(@as(u8, 2), missing_firewall_cursor.code);
    const firewall_jail_filter = try run(a, &.{ exe, "firewall", "show", "--jail", "sshd" });
    defer firewall_jail_filter.deinit(a);
    try testing.expectEqual(@as(u8, 2), firewall_jail_filter.code);
    const missing_cfg = try run(a, &.{ exe, "daemon", "--config", "/nonexistent/fail2zig.toml", "--validate-config" });
    defer missing_cfg.deinit(a);
    try testing.expectEqual(@as(u8, 2), missing_cfg.code);
    const absent = try run(a, &.{ exe, "--socket", "/nonexistent/fail2zig.sock", "--timeout", "500", "status" });
    defer absent.deinit(a);
    try testing.expectEqual(@as(u8, 3), absent.code);
    const absent_json = try run(a, &.{ exe, "--socket", "/nonexistent/fail2zig.sock", "--output", "json", "version" });
    defer absent_json.deinit(a);
    try testing.expectEqual(@as(u8, 3), absent_json.code);
    const absent_version = try run(a, &.{ exe, "--socket", "/nonexistent/fail2zig.sock", "--timeout", "500", "version" });
    defer absent_version.deinit(a);
    try testing.expectEqual(@as(u8, 3), absent_version.code);
    try testing.expectEqual(@as(usize, 0), absent_version.stdout.len);
}

test "cli entry: direct operator commands route through the client before trailing global flags" {
    const a = testing.allocator;
    std.fs.cwd().access(exe, .{}) catch return error.SkipZigTest;
    const missing_socket = "/nonexistent/fail2zig-direct-routing.sock";

    const firewall = try run(a, &.{ exe, "firewall", "show", "--socket", missing_socket });
    defer firewall.deinit(a);
    try testing.expectEqual(@as(u8, 3), firewall.code);

    const config = try run(a, &.{ exe, "config", "--socket", missing_socket });
    defer config.deinit(a);
    try testing.expectEqual(@as(u8, 3), config.code);

    const history = try run(a, &.{ exe, "history", "--limit", "1", "--socket", missing_socket });
    defer history.deinit(a);
    try testing.expectEqual(@as(u8, 3), history.code);

    const jail = try run(a, &.{ exe, "jail", "pause", "sshd", "--socket", missing_socket });
    defer jail.deinit(a);
    try testing.expectEqual(@as(u8, 3), jail.code);
}

test "cli entry: the same artifact starts the daemon and serves every retained operator spelling" {
    const a = testing.allocator;
    std.fs.cwd().access(exe, .{}) catch return error.SkipZigTest;
    var h = try harness.Harness.init(a, .{ .spawn_daemon = false });
    defer h.deinit();
    try writeConfig(&h);

    const validate = try run(a, &.{ exe, "daemon", "--config", h.config_path, "--validate-config" });
    defer validate.deinit(a);
    try testing.expectEqual(@as(u8, 0), validate.code);
    try testing.expect(std.mem.indexOf(u8, validate.stdout, "config: OK") != null);

    try h.startDaemon();
    defer _ = h.stopDaemon() catch {};

    const status = try waitStatusContains(a, &h, "\"protection\":\"log-only\"");
    defer status.deinit(a);
    const status_doc = try std.json.parseFromSlice(std.json.Value, a, status.stdout, .{});
    defer status_doc.deinit();
    const status_root = status_doc.value.object;
    try testing.expectEqualStrings("log-only", status_root.get("protection").?.string);
    try testing.expectEqualStrings("healthy", status_root.get("storage").?.string);
    try testing.expect(status_root.get("active_bans").? == .integer);
    try testing.expect(status_root.get("total_bans").? == .integer);
    try testing.expectEqual(@as(usize, 64), status_root.get("generation").?.string.len);
    try testing.expect(status_root.get("backend").? == .string);

    const plain = try run(a, &.{ exe, "--socket", h.socket_path, "--output", "plain", "status" });
    defer plain.deinit(a);
    try testing.expectEqual(@as(u8, 0), plain.code);
    try testing.expect(std.mem.indexOf(u8, plain.stdout, "protection\tlog-only\n") != null);

    const jails = try run(a, &.{ exe, "--socket", h.socket_path, "--timeout", "2000", "--output", "json", "jails" });
    defer jails.deinit(a);
    try testing.expectEqual(@as(u8, 0), jails.code);
    const jails_doc = try std.json.parseFromSlice(std.json.Value, a, jails.stdout, .{});
    defer jails_doc.deinit();
    try testing.expectEqual(@as(usize, 1), jails_doc.value.array.items.len);
    const jail = jails_doc.value.array.items[0].object;
    try testing.expectEqualStrings("sshd", jail.get("name").?.string);
    try testing.expect(jail.get("enabled").?.bool);
    try testing.expect(!jail.get("paused").?.bool);
    try testing.expect(!jail.get("enforcing").?.bool);
    try testing.expectEqualStrings("log-only", jail.get("action").?.string);
    try testing.expectEqual(@as(i64, 3), jail.get("maxretry").?.integer);
    try testing.expectEqual(@as(i64, 60), jail.get("bantime").?.integer);
    try testing.expectEqualStrings("file", jail.get("source").?.string);

    const list = try run(a, &.{ exe, "--socket", h.socket_path, "--timeout", "2000", "--output", "json", "list" });
    defer list.deinit(a);
    try testing.expectEqual(@as(u8, 0), list.code);
    const list_doc = try std.json.parseFromSlice(std.json.Value, a, list.stdout, .{});
    defer list_doc.deinit();
    try testing.expectEqual(@as(usize, 0), list_doc.value.array.items.len);

    const firewall_json = try run(a, &.{ exe, "--socket", h.socket_path, "--timeout", "2000", "--output", "json", "firewall", "show", "--limit", "1" });
    defer firewall_json.deinit(a);
    try testing.expectEqual(@as(u8, 0), firewall_json.code);
    const firewall_doc = try std.json.parseFromSlice(std.json.Value, a, firewall_json.stdout, .{});
    defer firewall_doc.deinit();
    const firewall_root = firewall_doc.value.object;
    try testing.expectEqual(@as(i64, 1), firewall_root.get("schema_version").?.integer);
    try testing.expectEqualStrings("firewall", firewall_root.get("kind").?.string);
    try testing.expect(!firewall_root.get("available").?.bool);
    try testing.expectEqualStrings("no_manager", firewall_root.get("unavailable_reason").?.string);
    try testing.expect(firewall_root.get("installation").? == .null);
    try testing.expect(firewall_root.get("observation").? == .null);
    try testing.expectEqualStrings("none", firewall_root.get("last_attempt").?.object.get("outcome").?.string);
    try testing.expectEqual(@as(usize, 0), firewall_root.get("items").?.array.items.len);
    try testing.expect(firewall_root.get("next_cursor").? == .null);

    const firewall_plain = try run(a, &.{ exe, "--socket", h.socket_path, "--timeout", "2000", "--output", "plain", "firewall", "show" });
    defer firewall_plain.deinit(a);
    try testing.expectEqual(@as(u8, 0), firewall_plain.code);
    try testing.expect(std.mem.indexOf(u8, firewall_plain.stdout, "available\tfalse") != null);
    try testing.expect(std.mem.indexOf(u8, firewall_plain.stdout, "unavailable_reason\tno_manager") != null);

    const firewall_table = try run(a, &.{ exe, "--socket", h.socket_path, "--timeout", "2000", "--no-color", "firewall", "show" });
    defer firewall_table.deinit(a);
    try testing.expectEqual(@as(u8, 0), firewall_table.code);
    try testing.expect(std.mem.indexOf(u8, firewall_table.stdout, "unavailable") != null);
    try testing.expect(std.mem.indexOf(u8, firewall_table.stdout, "no manager") != null or std.mem.indexOf(u8, firewall_table.stdout, "no_manager") != null);

    const version = try run(a, &.{ exe, "--socket", h.socket_path, "--timeout", "2000", "--output", "json", "version" });
    defer version.deinit(a);
    try testing.expectEqual(@as(u8, 0), version.code);
    const version_doc = try std.json.parseFromSlice(std.json.Value, a, version.stdout, .{});
    defer version_doc.deinit();
    const version_root = version_doc.value.object;
    try testing.expectEqualStrings(version_root.get("client_version").?.string, version_root.get("daemon").?.object.get("daemon_version").?.string);

    const version_table = try run(a, &.{ exe, "--socket", h.socket_path, "--timeout", "2000", "--no-color", "version" });
    defer version_table.deinit(a);
    try testing.expectEqual(@as(u8, 0), version_table.code);
    try testing.expect(std.mem.indexOf(u8, version_table.stdout, "(client and daemon)") != null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, version_table.stdout, "\n"));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, version_table.stdout, version_root.get("client_version").?.string));

    const config = try run(a, &.{ exe, "--socket", h.socket_path, "--timeout", "2000", "--output", "json", "config" });
    defer config.deinit(a);
    try testing.expectEqual(@as(u8, 0), config.code);
    const config_doc = try std.json.parseFromSlice(std.json.Value, a, config.stdout, .{});
    defer config_doc.deinit();
    const config_root = config_doc.value.object;
    try testing.expectEqual(@as(i64, 1), config_root.get("schema_version").?.integer);
    try testing.expectEqual(@as(usize, 64), config_root.get("generation").?.string.len);
    try testing.expectEqualStrings("sshd", config_root.get("jails").?.array.items[0].object.get("filter").?.string);
    try testing.expect(!config_root.get("global").?.object.get("metrics_enabled").?.bool);

    const table = try run(a, &.{ exe, "--socket", h.socket_path, "--no-color", "jails" });
    defer table.deinit(a);
    try testing.expectEqual(@as(u8, 0), table.code);

    const ban = try run(a, &.{ exe, "--socket", h.socket_path, "ban", "192.0.2.10", "--jail", "sshd" });
    defer ban.deinit(a);
    try testing.expectEqual(@as(u8, 1), ban.code);
    const unban = try run(a, &.{ exe, "--socket", h.socket_path, "unban", "192.0.2.10", "--jail", "sshd" });
    defer unban.deinit(a);
    try testing.expectEqual(@as(u8, 1), unban.code);
    const reload = try run(a, &.{ exe, "--socket", h.socket_path, "reload" });
    defer reload.deinit(a);
    try testing.expectEqual(@as(u8, 0), reload.code);
    try testing.expect(std.mem.indexOf(u8, reload.stdout, "outcome\tnoop") != null);
}

test "cli entry: migrate inspect and snapshot are read-only preparation with exact exit classes" {
    const a = testing.allocator;
    std.fs.cwd().access(exe, .{}) catch return error.SkipZigTest;
    const engine = @import("engine");

    const supported = try run(a, &.{ exe, "migrate", "inspect", "--source-dir", "tests/fixtures/fail2ban/config/supported" });
    defer supported.deinit(a);
    try testing.expectEqual(@as(u8, 0), supported.code);
    try testing.expect(std.mem.startsWith(u8, supported.stdout, "{\"schema_version\":1"));
    const again = try run(a, &.{ exe, "migrate", "inspect", "--source-dir", "tests/fixtures/fail2ban/config/supported" });
    defer again.deinit(a);
    try testing.expectEqualStrings(supported.stdout, again.stdout);
    const blocker = try run(a, &.{ exe, "migrate", "inspect", "--source-dir", "tests/fixtures/fail2ban/config/blocker", "--output", "table" });
    defer blocker.deinit(a);
    try testing.expectEqual(@as(u8, 1), blocker.code);
    const missing = try run(a, &.{ exe, "migrate", "inspect", "--source-dir", "/nonexistent-fail2ban" });
    defer missing.deinit(a);
    try testing.expectEqual(@as(u8, 2), missing.code);
    const usage = try run(a, &.{ exe, "migrate", "bogus" });
    defer usage.deinit(a);
    try testing.expectEqual(@as(u8, 2), usage.code);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const db_path = try std.fs.path.join(a, &.{ root, "fail2ban.sqlite3" });
    defer a.free(db_path);
    const staging = try std.fs.path.join(a, &.{ root, "staging" });
    defer a.free(staging);
    try std.fs.cwd().makeDir(staging);
    try std.posix.fchmodat(std.posix.AT.FDCWD, staging, 0o700, 0);
    const loose = try std.fs.path.join(a, &.{ root, "loose" });
    defer a.free(loose);
    try std.fs.cwd().makeDir(loose);
    try std.posix.fchmodat(std.posix.AT.FDCWD, loose, 0o750, 0);
    try engine.migration_fixture_mod.build(db_path, .{});
    const before = try engine.migration_snapshot_mod.sha256File(db_path);
    const refused = try run(a, &.{ exe, "migrate", "snapshot", "--source-db", db_path, "--staging-dir", loose });
    defer refused.deinit(a);
    try testing.expect(refused.code != 0);
    try testing.expectEqualSlices(u8, &before, &try engine.migration_snapshot_mod.sha256File(db_path));
    const snap = try run(a, &.{ exe, "migrate", "snapshot", "--source-db", db_path, "--staging-dir", staging });
    defer snap.deinit(a);
    try testing.expectEqual(@as(u8, 0), snap.code);
    try testing.expect(std.mem.indexOf(u8, snap.stdout, "\"version\":4") != null);
    try testing.expect(std.mem.indexOf(u8, snap.stdout, "\"destination_sha256\":\"") != null);
    try testing.expectEqualSlices(u8, &before, &try engine.migration_snapshot_mod.sha256File(db_path));
    const bad_path = try std.fs.path.join(a, &.{ root, "old.sqlite3" });
    defer a.free(bad_path);
    try engine.migration_fixture_mod.build(bad_path, .{ .version = 3 });
    const unsupported = try run(a, &.{ exe, "migrate", "snapshot", "--source-db", bad_path, "--staging-dir", staging, "--output", "table" });
    defer unsupported.deinit(a);
    try testing.expectEqual(@as(u8, 1), unsupported.code);
    const nofile = try run(a, &.{ exe, "migrate", "snapshot", "--source-db", "/nonexistent.sqlite3", "--staging-dir", staging });
    defer nofile.deinit(a);
    try testing.expectEqual(@as(u8, 2), nofile.code);

    const plan_path = try std.fs.path.join(a, &.{ root, "plan.json" });
    defer a.free(plan_path);
    const unbounded = try run(a, &.{ exe, "migrate", "plan", "--source-dir", "tests/fixtures/fail2ban/config/supported", "--out", plan_path });
    defer unbounded.deinit(a);
    try testing.expectEqual(@as(u8, 1), unbounded.code);
    try testing.expect(std.mem.indexOf(u8, unbounded.stdout, "replay-window-missing") != null);
    const planned = try run(a, &.{ exe, "migrate", "plan", "--source-dir", "tests/fixtures/fail2ban/config/supported", "--source-db", db_path, "--staging-dir", staging, "--out", plan_path, "--replay-window", "600" });
    defer planned.deinit(a);
    try testing.expectEqual(@as(u8, 0), planned.code);
    try testing.expect(std.mem.indexOf(u8, planned.stdout, "\"blockers\":[]") != null);
    try testing.expect(std.mem.indexOf(u8, planned.stdout, "non_lossless:true") != null);
    const valid = try run(a, &.{ exe, "migrate", "validate", "--plan", plan_path, "--source-dir", "tests/fixtures/fail2ban/config/supported" });
    defer valid.deinit(a);
    try testing.expectEqual(@as(u8, 0), valid.code);
    try testing.expect(std.mem.indexOf(u8, valid.stdout, "\"outcome\":\"valid\"") != null);
    const drifted = try run(a, &.{ exe, "migrate", "validate", "--plan", plan_path, "--source-dir", "tests/fixtures/fail2ban/config/operator-change", "--output", "table" });
    defer drifted.deinit(a);
    try testing.expectEqual(@as(u8, 1), drifted.code);
    try testing.expect(std.mem.indexOf(u8, drifted.stdout, "outcome\tdrifted") != null);
    const blocked_plan = try std.fs.path.join(a, &.{ root, "blocked.json" });
    defer a.free(blocked_plan);
    const blocked = try run(a, &.{ exe, "migrate", "plan", "--source-dir", "tests/fixtures/fail2ban/config/blocker", "--out", blocked_plan, "--continuity", "lossless" });
    defer blocked.deinit(a);
    try testing.expectEqual(@as(u8, 1), blocked.code);
    const blocked_validate = try run(a, &.{ exe, "migrate", "validate", "--plan", blocked_plan });
    defer blocked_validate.deinit(a);
    try testing.expectEqual(@as(u8, 1), blocked_validate.code);
    try testing.expect(std.mem.indexOf(u8, blocked_validate.stdout, "\"outcome\":\"blocked\"") != null);
    const noplan = try run(a, &.{ exe, "migrate", "validate", "--plan", "/nonexistent/plan.json" });
    defer noplan.deinit(a);
    try testing.expectEqual(@as(u8, 2), noplan.code);
}

test "cli entry: rule-test evaluates offline through the same artifact with exact exit classes" {
    const a = testing.allocator;
    std.fs.cwd().access(exe, .{}) catch return error.SkipZigTest;

    const matched = try run(a, &.{ exe, "rule-test", "--file", "tests/fixtures/rule-test/sshd.log", "--service", "sshd", "--output", "json" });
    defer matched.deinit(a);
    try testing.expectEqual(@as(u8, 0), matched.code);
    try testing.expect(std.mem.startsWith(u8, matched.stdout, "{\"schema_version\":1"));
    try testing.expect(std.mem.indexOf(u8, matched.stdout, "\"matched\":") != null);
    const again = try run(a, &.{ exe, "rule-test", "--file", "tests/fixtures/rule-test/sshd.log", "--service", "sshd", "--output", "json" });
    defer again.deinit(a);
    try testing.expectEqualStrings(matched.stdout, again.stdout);
    const missing = try run(a, &.{ exe, "rule-test", "--file", "/nonexistent-rule-test.log", "--service", "sshd" });
    defer missing.deinit(a);
    try testing.expectEqual(@as(u8, 1), missing.code);
    const usage = try run(a, &.{ exe, "rule-test" });
    defer usage.deinit(a);
    try testing.expectEqual(@as(u8, 2), usage.code);
    const unknown_service = try run(a, &.{ exe, "rule-test", "--record", "x", "--service", "no-such-service" });
    defer unknown_service.deinit(a);
    try testing.expect(unknown_service.code == 1 or unknown_service.code == 2);
}

test "cli entry: no systemd socket unit ships and no activation promise remains in operator documents" {
    const a = testing.allocator;
    try testing.expectError(error.FileNotFound, std.fs.cwd().access("deploy/fail2zig.socket", .{}));
    for ([_][]const u8{ "README.md", "deploy/fail2zig.service", "docs/man/fail2zig.1", "tests/e2e/README.md", ".github/workflows/release.yml" }) |path| {
        const text = try std.fs.cwd().readFileAlloc(a, path, 1 << 20);
        defer a.free(text);
        try testing.expect(std.mem.indexOf(u8, text, "fail2zig.socket") == null);
        try testing.expect(std.mem.indexOf(u8, text, "sockets.target") == null);
    }
    const unit = try std.fs.cwd().readFileAlloc(a, "deploy/fail2zig.service", 1 << 20);
    defer a.free(unit);
    try testing.expect(std.mem.indexOf(u8, unit, "Type=notify") != null);
    try testing.expect(std.mem.indexOf(u8, unit, "Requires=fail2zig.socket") == null);
}

fn waitHealthy(h: *harness.Harness) !void {
    var timer = try std.time.Timer.start();
    while (timer.read() < 10 * std.time.ns_per_s) {
        const s = try h.queryStatus();
        defer testing.allocator.free(s);
        if (std.mem.indexOf(u8, s, "\"storage\":\"healthy\"") != null) return;
        std.time.sleep(25 * std.time.ns_per_ms);
    }
    return error.TimedOut;
}

fn runIdFrom(stderr: []const u8) ?[]const u8 {
    const marker = "migrate cutover: run ";
    const at = std.mem.indexOf(u8, stderr, marker) orelse return null;
    const start = at + marker.len;
    if (stderr.len < start + 64) return null;
    return stderr[start .. start + 64];
}

test "cli entry: migrate cutover stages the destination offline, resumes by run id, binds to its plan and waits for the daemon" {
    const a = testing.allocator;
    std.fs.cwd().access(exe, .{}) catch return error.SkipZigTest;
    const engine = @import("engine");
    var h = try harness.Harness.init(a, .{ .spawn_daemon = false });
    defer h.deinit();
    try writeConfig(&h);
    try h.startDaemon();
    try waitHealthy(&h);
    _ = try h.stopDaemon();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const db_path = try std.fs.path.join(a, &.{ root, "fail2ban.sqlite3" });
    defer a.free(db_path);
    const staging = try std.fs.path.join(a, &.{ root, "staging" });
    defer a.free(staging);
    try std.fs.cwd().makeDir(staging);
    try std.posix.fchmodat(std.posix.AT.FDCWD, staging, 0o700, 0);
    const plan_path = try std.fs.path.join(a, &.{ root, "plan.json" });
    defer a.free(plan_path);

    try engine.migration_fixture_mod.build(db_path, .{});
    const blocked_plan = try std.fs.path.join(a, &.{ root, "blocked.json" });
    defer a.free(blocked_plan);
    const blocked_planned = try run(a, &.{ exe, "migrate", "plan", "--source-dir", "tests/fixtures/fail2ban/config/supported", "--source-db", db_path, "--staging-dir", staging, "--out", blocked_plan, "--replay-window", "600" });
    defer blocked_planned.deinit(a);
    try testing.expectEqual(@as(u8, 0), blocked_planned.code);
    const blocked = try run(a, &.{ exe, "migrate", "cutover", "--plan", blocked_plan, "--state-file", h.state_path, "--staging-dir", staging, "--backend", "nftables", "--socket", h.socket_path });
    defer blocked.deinit(a);
    try testing.expectEqual(@as(u8, 1), blocked.code);
    try testing.expect(std.mem.indexOf(u8, blocked.stderr, "bantime-unknown-sentinel:row:4") != null);
    try testing.expect(std.mem.indexOf(u8, blocked.stdout, "\"state\":\"failed\"") != null);

    try std.fs.cwd().deleteFile(db_path);
    try engine.migration_fixture_mod.build(db_path, .{ .omit_sentinel = true });
    const planned = try run(a, &.{ exe, "migrate", "plan", "--source-dir", "tests/fixtures/fail2ban/config/supported", "--source-db", db_path, "--staging-dir", staging, "--out", plan_path, "--replay-window", "600" });
    defer planned.deinit(a);
    try testing.expectEqual(@as(u8, 0), planned.code);

    const first = try run(a, &.{ exe, "migrate", "cutover", "--plan", plan_path, "--state-file", h.state_path, "--staging-dir", staging, "--backend", "nftables", "--socket", h.socket_path });
    defer first.deinit(a);
    if (first.code != 3) std.debug.print("cutover stdout:\n{s}\ncutover stderr:\n{s}\n", .{ first.stdout, first.stderr });
    try testing.expectEqual(@as(u8, 3), first.code);
    try testing.expect(std.mem.indexOf(u8, first.stdout, "\"state\":\"staged\"") != null);
    try testing.expect(std.mem.indexOf(u8, first.stderr, "not reachable") != null);
    const run_id = runIdFrom(first.stderr) orelse return error.RunIdMissing;

    const status = try run(a, &.{ exe, "migrate", "status", "--plan", plan_path, "--state-file", h.state_path, "--staging-dir", staging, "--backend", "nftables", "--run-id", run_id, "--output", "table" });
    defer status.deinit(a);
    try testing.expectEqual(@as(u8, 3), status.code);
    try testing.expect(std.mem.indexOf(u8, status.stdout, "state\tstaged") != null);
    try testing.expect(std.mem.indexOf(u8, status.stdout, "step\t5\tstage_destination\tsuccess") != null);

    const again = try run(a, &.{ exe, "migrate", "cutover", "--plan", plan_path, "--state-file", h.state_path, "--staging-dir", staging, "--backend", "nftables", "--socket", h.socket_path, "--run-id", run_id });
    defer again.deinit(a);
    try testing.expectEqual(@as(u8, 3), again.code);
    try testing.expect(std.mem.indexOf(u8, again.stdout, "step\t6") == null);
    try testing.expect(std.mem.indexOf(u8, again.stdout, "\"state\":\"staged\"") != null);

    const other_plan = try std.fs.path.join(a, &.{ root, "other.json" });
    defer a.free(other_plan);
    const replanned = try run(a, &.{ exe, "migrate", "plan", "--source-dir", "tests/fixtures/fail2ban/config/supported", "--source-db", db_path, "--staging-dir", staging, "--out", other_plan, "--replay-window", "300" });
    defer replanned.deinit(a);
    try testing.expectEqual(@as(u8, 0), replanned.code);
    const foreign = try run(a, &.{ exe, "migrate", "status", "--plan", other_plan, "--state-file", h.state_path, "--staging-dir", staging, "--backend", "nftables", "--run-id", run_id });
    defer foreign.deinit(a);
    try testing.expectEqual(@as(u8, 1), foreign.code);
    try testing.expect(std.mem.indexOf(u8, foreign.stderr, "IncompatiblePlan") != null);

    try h.startDaemon();
    defer _ = h.stopDaemon() catch {};
    try waitHealthy(&h);
    const refused = try run(a, &.{ exe, "migrate", "cutover", "--plan", plan_path, "--state-file", h.state_path, "--staging-dir", staging, "--backend", "nftables", "--socket", h.socket_path, "--run-id", run_id });
    defer refused.deinit(a);
    try testing.expectEqual(@as(u8, 1), refused.code);
    try testing.expect(std.mem.indexOf(u8, refused.stderr, "log-only") != null);
    const listing = try h.queryList();
    defer a.free(listing);
    try testing.expect(std.mem.indexOf(u8, listing, "192.0.2.") == null);
}

fn readHttpHealth(a: std.mem.Allocator, port: u16) ![]u8 {
    const stream = try std.net.tcpConnectToAddress(try std.net.Address.parseIp4("127.0.0.1", port));
    defer stream.close();
    const timeout = std.posix.timeval{ .sec = 2, .usec = 0 };
    try std.posix.setsockopt(stream.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));
    try stream.writeAll("GET /api/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    return stream.reader().readAllAlloc(a, 16 * 1024);
}

test "cli entry: BUG-027 versioned queries, readiness and a file log target with SIGUSR1 reopen" {
    const a = testing.allocator;
    std.fs.cwd().access(exe, .{}) catch return error.SkipZigTest;
    var h = try harness.Harness.init(a, .{ .spawn_daemon = false });
    defer h.deinit();
    const log_file = try std.fmt.allocPrint(a, "{s}/daemon.log", .{h.tmp_abs});
    defer a.free(log_file);
    var listener = try (try std.net.Address.parseIp4("127.0.0.1", 0)).listen(.{});
    const health_port = listener.listen_address.getPort();
    listener.deinit();
    {
        var file = try std.fs.cwd().createFile(h.config_path, .{ .mode = 0o600 });
        defer file.close();
        try file.writer().print(
            \\[global]
            \\native_ingestion = true
            \\state_file = "{s}"
            \\socket_path = "{s}"
            \\metrics_enabled = true
            \\metrics_bind = "127.0.0.1"
            \\metrics_port = {d}
            \\log_target = "{s}"
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
        , .{ h.state_path, h.socket_path, health_port, log_file, h.log_path });
    }
    try h.startDaemon();
    defer _ = h.stopDaemon() catch {};
    var timer = try std.time.Timer.start();
    while (timer.read() < 10 * std.time.ns_per_s) {
        const s = try h.queryStatus();
        defer a.free(s);
        if (std.mem.indexOf(u8, s, "\"storage\":\"healthy\"") != null) break;
        std.time.sleep(25 * std.time.ns_per_ms);
    }

    const config = try run(a, &.{ exe, "--socket", h.socket_path, "--output", "json", "config" });
    defer config.deinit(a);
    try testing.expectEqual(@as(u8, 0), config.code);
    try testing.expect(std.mem.indexOf(u8, config.stdout, "\"schema_version\":1") != null);
    try testing.expect(std.mem.indexOf(u8, config.stdout, "\"maxretry\":3") != null);
    const table = try run(a, &.{ exe, "--socket", h.socket_path, "--no-color", "config" });
    defer table.deinit(a);
    try testing.expectEqual(@as(u8, 0), table.code);
    const history = try run(a, &.{ exe, "--socket", h.socket_path, "--output", "json", "history", "--jail", "sshd", "--limit", "5" });
    defer history.deinit(a);
    try testing.expectEqual(@as(u8, 0), history.code);
    try testing.expect(std.mem.indexOf(u8, history.stdout, "\"schema_version\":1") != null);
    const bad_limit = try run(a, &.{ exe, "--socket", h.socket_path, "history", "--limit", "999" });
    defer bad_limit.deinit(a);
    try testing.expect(bad_limit.code != 0);

    const shared = @import("shared");
    var ready = false;
    var ready_wait = try std.time.Timer.start();
    while (ready_wait.read() < 10 * std.time.ns_per_s) {
        const health = try h.sendCommand(.{ .query_v1 = try shared.Command.Body.init("{\"schema_version\":1,\"kind\":\"health\"}") });
        defer a.free(health);
        try testing.expect(std.mem.indexOf(u8, health, "\"components\":{\"config\":") != null);
        if (std.mem.indexOf(u8, health, "\"ready\":true") != null) {
            ready = true;
            break;
        }
        std.time.sleep(50 * std.time.ns_per_ms);
    }
    try testing.expect(ready);
    const scopes = try h.sendCommand(.{ .query_v1 = try shared.Command.Body.init("{\"schema_version\":1,\"kind\":\"scopes\"}") });
    defer a.free(scopes);
    try testing.expect(std.mem.indexOf(u8, scopes, "\"items\"") != null);
    try testing.expectError(error.UnexpectedResponse, h.sendCommand(.{ .query_v1 = try shared.Command.Body.init("{\"schema_version\":1,\"kind\":\"nope\"}") }));

    const sock_dir = std.fs.path.dirname(h.socket_path).?;
    const before = (try std.fs.cwd().statFile(sock_dir)).mode & 0o7777;
    defer std.posix.fchmodat(std.posix.AT.FDCWD, sock_dir, before, 0) catch {};
    try std.posix.fchmodat(std.posix.AT.FDCWD, sock_dir, 0o777, 0);
    const refused = try run(a, &.{ exe, "--socket", h.socket_path, "--timeout", "2000", "--output", "json", "status" });
    defer refused.deinit(a);
    try testing.expect(refused.code != 0);
    const degraded = try readHttpHealth(a, health_port);
    defer a.free(degraded);
    try testing.expect(std.mem.indexOf(u8, degraded, "503") != null);
    try testing.expect(std.mem.indexOf(u8, degraded, "\"ready\":false") != null);
    try testing.expect(std.mem.indexOf(u8, degraded, "administrative socket refusing new connections") != null);
    try std.posix.fchmodat(std.posix.AT.FDCWD, sock_dir, before, 0);
    var recovered = false;
    var recover_wait = try std.time.Timer.start();
    while (recover_wait.read() < 5 * std.time.ns_per_s) {
        const again = try run(a, &.{ exe, "--socket", h.socket_path, "--timeout", "2000", "--output", "json", "status" });
        defer again.deinit(a);
        if (again.code == 0) {
            recovered = true;
            break;
        }
        std.time.sleep(100 * std.time.ns_per_ms);
    }
    try testing.expect(recovered);
    const health_after = try h.sendCommand(.{ .query_v1 = try shared.Command.Body.init("{\"schema_version\":1,\"kind\":\"health\"}") });
    defer a.free(health_after);
    try testing.expect(std.mem.indexOf(u8, health_after, "\"ready\":true") != null);

    var stat = try std.fs.cwd().statFile(log_file);
    try testing.expect(stat.size > 0);
    const rotated = try std.fmt.allocPrint(a, "{s}.1", .{log_file});
    defer a.free(rotated);
    try std.fs.cwd().rename(log_file, rotated);
    try std.posix.kill(h.child.?.id, std.posix.SIG.USR1);
    var reopened = false;
    var wait = try std.time.Timer.start();
    while (wait.read() < 5 * std.time.ns_per_s) {
        const poke = try run(a, &.{ exe, "--socket", h.socket_path, "--output", "json", "reload" });
        poke.deinit(a);
        stat = std.fs.cwd().statFile(log_file) catch {
            std.time.sleep(100 * std.time.ns_per_ms);
            continue;
        };
        if (stat.size > 0) {
            reopened = true;
            break;
        }
        std.time.sleep(100 * std.time.ns_per_ms);
    }
    try testing.expect(reopened);
}

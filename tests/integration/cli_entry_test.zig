// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

//! The one delivered `fail2zig` executable owns daemon startup, local diagnostics and
//! the retained operator spellings, with the frozen exit classes 0-3.

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
    const comp = try run(a, &.{ exe, "completions", "bash" });
    defer comp.deinit(a);
    try testing.expectEqual(@as(u8, 0), comp.code);
    try testing.expect(std.mem.indexOf(u8, comp.stdout, "fail2zig-client") == null);
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
    const missing_cfg = try run(a, &.{ exe, "daemon", "--config", "/nonexistent/fail2zig.toml", "--validate-config" });
    defer missing_cfg.deinit(a);
    try testing.expectEqual(@as(u8, 2), missing_cfg.code);
    const absent = try run(a, &.{ exe, "--socket", "/nonexistent/fail2zig.sock", "--timeout", "500", "status" });
    defer absent.deinit(a);
    try testing.expectEqual(@as(u8, 3), absent.code);
    const absent_json = try run(a, &.{ exe, "--socket", "/nonexistent/fail2zig.sock", "--output", "json", "version" });
    defer absent_json.deinit(a);
    try testing.expectEqual(@as(u8, 3), absent_json.code);
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

    const spellings = [_][]const u8{ "status", "jails", "list", "version" };
    for (spellings) |cmd| {
        const r = try run(a, &.{ exe, "--socket", h.socket_path, "--timeout", "2000", "--output", "json", cmd });
        defer r.deinit(a);
        try testing.expectEqual(@as(u8, 0), r.code);
        try testing.expect(r.stdout.len > 0 and r.stdout[0] == '{' or r.stdout[0] == '[');
    }
    const plain = try run(a, &.{ exe, "--socket", h.socket_path, "--output", "plain", "status" });
    defer plain.deinit(a);
    try testing.expectEqual(@as(u8, 0), plain.code);
    const table = try run(a, &.{ exe, "--socket", h.socket_path, "--no-color", "jails" });
    defer table.deinit(a);
    try testing.expectEqual(@as(u8, 0), table.code);

    // Mutation spellings reach the daemon and its current native refusal is a rejected class.
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
    // A permissive staging directory is refused before any snapshot is written (SEC-013).
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

    // Plan and validate: deterministic plan file, valid re-validation, drift and blocker classes.
    const plan_path = try std.fs.path.join(a, &.{ root, "plan.json" });
    defer a.free(plan_path);
    // A reset/replay compromise must name its window explicitly; it is reported as non-lossless.
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

    // A source row the importer must refuse (unknown bantime sentinel) fails the run before any
    // destination mutation, in the staging step, with the row named.
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

    // Offline steps run and the run stays staged because no daemon answers on the socket.
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

    // Resume classifies the journal instead of replaying: still staged, no extra steps.
    const again = try run(a, &.{ exe, "migrate", "cutover", "--plan", plan_path, "--state-file", h.state_path, "--staging-dir", staging, "--backend", "nftables", "--socket", h.socket_path, "--run-id", run_id });
    defer again.deinit(a);
    try testing.expectEqual(@as(u8, 3), again.code);
    try testing.expect(std.mem.indexOf(u8, again.stdout, "step\t6") == null);
    try testing.expect(std.mem.indexOf(u8, again.stdout, "\"state\":\"staged\"") != null);

    // A different plan file cannot drive the run.
    const other_plan = try std.fs.path.join(a, &.{ root, "other.json" });
    defer a.free(other_plan);
    const replanned = try run(a, &.{ exe, "migrate", "plan", "--source-dir", "tests/fixtures/fail2ban/config/supported", "--source-db", db_path, "--staging-dir", staging, "--out", other_plan, "--replay-window", "300" });
    defer replanned.deinit(a);
    try testing.expectEqual(@as(u8, 0), replanned.code);
    const foreign = try run(a, &.{ exe, "migrate", "status", "--plan", other_plan, "--state-file", h.state_path, "--staging-dir", staging, "--backend", "nftables", "--run-id", run_id });
    defer foreign.deinit(a);
    try testing.expectEqual(@as(u8, 1), foreign.code);
    try testing.expect(std.mem.indexOf(u8, foreign.stderr, "IncompatiblePlan") != null);

    // With a log-only daemon the activation is refused by the daemon and the run stays staged.
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

    // Readiness and scopes are versioned query kinds behind the same bounded frame.
    const shared = @import("shared");
    // Readiness is withheld until every source is admitted, even while storage is healthy.
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

    // A widened socket directory latches refusal on the next accept; restoring the mode is
    // re-verified on the following accept and service resumes with readiness intact.
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

    // The file log target received the startup lines; rotation + SIGUSR1 reopens the path.
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

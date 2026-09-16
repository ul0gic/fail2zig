// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const builtin = @import("builtin");

const engine = @import("engine");
const release_options = @import("release_migration_test_options");

const testing = std.testing;
const max_output_bytes: usize = 1 << 20;
const max_fixture_entries: usize = 64;
const fault_variable = "F2Z_MIGRATE_FAULT";

const Run = struct {
    term: std.process.Child.Term,
    stdout: []u8,
    stderr: []u8,

    fn deinit(self: Run, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
    }
};

fn runCommand(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    fault: ?[]const u8,
) !Run {
    var env = try std.process.getEnvMap(allocator);
    defer env.deinit();
    env.remove(fault_variable);
    if (fault) |name| try env.put(fault_variable, name);
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
        .env_map = &env,
        .max_output_bytes = max_output_bytes,
    });
    return .{ .term = result.term, .stdout = result.stdout, .stderr = result.stderr };
}

fn expectExit(run: Run, code: u8) !void {
    if (!std.meta.eql(run.term, std.process.Child.Term{ .Exited = code })) {
        std.debug.print(
            "unexpected command result: wanted exit {d}, got {any}\nstdout:\n{s}\nstderr:\n{s}\n",
            .{ code, run.term, run.stdout, run.stderr },
        );
        return error.TestUnexpectedExit;
    }
}

fn expectContains(text: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, text, needle) == null) {
        std.debug.print("expected to find {s} in:\n{s}\n", .{ needle, text });
        return error.TestExpectedContains;
    }
}

fn runIdFrom(stderr: []const u8) ![32]u8 {
    const marker = "migrate cutover: run ";
    const start = (std.mem.indexOf(u8, stderr, marker) orelse return error.TestRunIdMissing) + marker.len;
    if (stderr.len - start < 64) return error.TestRunIdMissing;
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, stderr[start .. start + 64]) catch return error.TestRunIdInvalid;
    return result;
}

fn copyFixtureTree(source_path: []const u8, destination_path: []const u8) !void {
    var source = try std.fs.openDirAbsolute(source_path, .{ .iterate = true });
    defer source.close();
    var destination = try std.fs.openDirAbsolute(destination_path, .{});
    defer destination.close();
    var walker = try source.walk(testing.allocator);
    defer walker.deinit();
    var entries: usize = 0;
    while (try walker.next()) |entry| {
        entries += 1;
        if (entries > max_fixture_entries) return error.TestFixtureTooLarge;
        switch (entry.kind) {
            .directory => try destination.makePath(entry.path),
            .file => {
                if (std.fs.path.dirname(entry.path)) |parent| try destination.makePath(parent);
                try entry.dir.copyFile(entry.basename, destination, entry.path, .{});
            },
            else => return error.TestFixtureEntryUnsupported,
        }
    }
}

fn initializeState(path: []const u8) !void {
    const durable = engine.native_store_mod;
    const effects = engine.native_effect_mod;
    var store = try durable.Store.open(testing.allocator, path);
    defer store.close();
    try store.enableReceipts(8);
    try store.enableNativeTime();
    try store.enableYearInference();
    try store.enableDetection();
    try store.enableClockRecovery();
    try store.enableJournalDetection();
    try store.enableRetry();
    try store.enableConsumers();
    try store.enableEffects();
    try store.admitInstallation(
        try effects.Installation.init([_]u8{7} ** 16, .nftables, "host-default"),
        .{ .selector = "host-default", .disposition = .verified_absent },
    );
    try store.enableTimeProvenance();
    try store.enableConsumerManifests();
    try store.enableConfirmedHistory();
    try store.enableMaintenance();
    try store.enableCleanup();
    try store.enableRetryLeases();
    try store.enableApplicationHistory();
    try store.enableEscalation();
    try store.enableCanonicalEffects();
    try store.enableHistoryResets();
    try store.enableActionTargets();
    try store.enableAdminState();
    try store.enableMigrationState();
    try testing.expectEqual(durable.latest_schema, store.schema_version);
}

const Fixture = struct {
    tmp: testing.TmpDir,
    arena: std.heap.ArenaAllocator,
    root: []const u8,
    source_dir: []const u8,
    source_db: []const u8,
    staging_dir: []const u8,
    plan_path: []const u8,
    state_path: []const u8,
    socket_path: []const u8,
    now_s: i64,

    fn init() !Fixture {
        if (builtin.os.tag != .linux) return error.SkipZigTest;
        std.fs.accessAbsolute(release_options.daemon_path, .{}) catch return error.TestDaemonBinaryMissing;

        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        errdefer arena.deinit();
        const allocator = arena.allocator();
        const root = try tmp.dir.realpathAlloc(allocator, ".");
        const source_dir = try std.fs.path.join(allocator, &.{ root, "source" });
        const source_db = try std.fs.path.join(allocator, &.{ root, "fail2ban.sqlite3" });
        const staging_dir = try std.fs.path.join(allocator, &.{ root, "staging" });
        const plan_path = try std.fs.path.join(allocator, &.{ root, "plan.json" });
        const state_path = try std.fs.path.join(allocator, &.{ root, "state.sqlite3" });
        const socket_path = try std.fs.path.join(allocator, &.{ root, "absent-source.sock" });
        try std.fs.makeDirAbsolute(source_dir);
        try std.fs.makeDirAbsolute(staging_dir);
        try std.posix.fchmodat(std.posix.AT.FDCWD, staging_dir, 0o700, 0);
        try copyFixtureTree(release_options.supported_fixture, source_dir);
        const now_s = std.time.timestamp();
        try engine.migration_fixture_mod.build(source_db, .{
            .profile = .delete,
            .now = now_s,
            .omit_sentinel = true,
        });
        try initializeState(state_path);
        return .{
            .tmp = tmp,
            .arena = arena,
            .root = root,
            .source_dir = source_dir,
            .source_db = source_db,
            .staging_dir = staging_dir,
            .plan_path = plan_path,
            .state_path = state_path,
            .socket_path = socket_path,
            .now_s = now_s,
        };
    }

    fn deinit(self: *Fixture) void {
        self.tmp.cleanup();
        self.arena.deinit();
        self.* = undefined;
    }

    fn plan(self: *const Fixture) !void {
        const run = try runCommand(testing.allocator, &.{
            release_options.daemon_path,
            "migrate",
            "plan",
            "--source-dir",
            self.source_dir,
            "--source-db",
            self.source_db,
            "--staging-dir",
            self.staging_dir,
            "--out",
            self.plan_path,
            "--replay-window",
            "600",
            "--runtime-socket",
            self.socket_path,
        }, null);
        defer run.deinit(testing.allocator);
        try expectExit(run, 0);
        try expectContains(run.stdout, "\"blockers\":[]");
        try expectContains(run.stdout, "non_lossless:true");
    }

    fn inspectStaged(self: *const Fixture, run_id: [32]u8) !engine.native_store_mod.Store.StagedCounts {
        var store = try engine.native_store_mod.Store.openReadOnly(testing.allocator, self.state_path);
        defer store.close();
        return store.stagedMigrationCounts(run_id);
    }
};

fn expectStagedOwnerMeaning(fixture: *const Fixture, run_id: [32]u8) !void {
    var store = try engine.native_store_mod.Store.openReadOnly(testing.allocator, fixture.state_path);
    defer store.close();
    const counts = try store.stagedMigrationCounts(run_id);
    try testing.expectEqual(@as(u64, 3), counts.owners);
    try testing.expect(counts.history > 0);

    const active_event_us = (fixture.now_s - 600) * std.time.us_per_s;
    const active_deadline_us = (fixture.now_s - 600 + 3600) * std.time.us_per_s;
    var sql: [512]u8 = undefined;
    const active = try std.fmt.bufPrintZ(
        &sql,
        "SELECT count(*) FROM migration_staged_owners WHERE jail='sshd' AND source_row=1 AND lease_kind=1 AND source_event_us={d} AND deadline_us={d};",
        .{ active_event_us, active_deadline_us },
    );
    try testing.expectEqual(@as(i64, 1), try store.inspectInteger(active));
    try testing.expectEqual(
        @as(i64, 1),
        try store.inspectInteger("SELECT count(*) FROM migration_staged_owners WHERE jail='sshd' AND source_row=3 AND lease_kind=2 AND deadline_us IS NULL;"),
    );
    const ipv6_event_us = (fixture.now_s - 60) * std.time.us_per_s;
    const ipv6_deadline_us = (fixture.now_s - 60 + 600) * std.time.us_per_s;
    var ipv6_sql: [512]u8 = undefined;
    const ipv6 = try std.fmt.bufPrintZ(
        &ipv6_sql,
        "SELECT count(*) FROM migration_staged_owners WHERE jail='sshd' AND source_row=4 AND lease_kind=1 AND source_event_us={d} AND deadline_us={d};",
        .{ ipv6_event_us, ipv6_deadline_us },
    );
    try testing.expectEqual(@as(i64, 1), try store.inspectInteger(ipv6));
    try testing.expectEqual(
        @as(i64, 0),
        try store.inspectInteger("SELECT count(*) FROM effect_owners WHERE lease_kind!=0;"),
    );
}

fn snapshotPathFromPlan(allocator: std.mem.Allocator, plan_path: []const u8) ![]u8 {
    const bytes = try std.fs.cwd().readFileAlloc(allocator, plan_path, 1 << 20);
    defer allocator.free(bytes);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
    defer parsed.deinit();
    const snapshot = parsed.value.object.get("snapshot") orelse return error.TestSnapshotMissing;
    if (snapshot != .object) return error.TestSnapshotMissing;
    const path = snapshot.object.get("path") orelse return error.TestSnapshotMissing;
    if (path != .string) return error.TestSnapshotMissing;
    return allocator.dupe(u8, path.string);
}

fn directoryEntries(path: []const u8) !usize {
    var directory = try std.fs.openDirAbsolute(path, .{ .iterate = true });
    defer directory.close();
    var iterator = directory.iterate();
    var count: usize = 0;
    while (try iterator.next()) |_| count += 1;
    return count;
}

test "release migration: prepare, stage, status, command restart and rollback refusal preserve source meaning" {
    var fixture = try Fixture.init();
    defer fixture.deinit();

    const before = try engine.migration_snapshot_mod.sha256File(fixture.source_db);
    const inspected = try runCommand(testing.allocator, &.{
        release_options.daemon_path,
        "migrate",
        "inspect",
        "--source-dir",
        fixture.source_dir,
    }, null);
    defer inspected.deinit(testing.allocator);
    try expectExit(inspected, 0);
    try expectContains(inspected.stdout, "\"schema_version\":1");
    try fixture.plan();

    const validated = try runCommand(testing.allocator, &.{
        release_options.daemon_path,
        "migrate",
        "validate",
        "--plan",
        fixture.plan_path,
    }, null);
    defer validated.deinit(testing.allocator);
    try expectExit(validated, 0);
    try expectContains(validated.stdout, "\"outcome\":\"valid\"");

    const staged = try runCommand(testing.allocator, &.{
        release_options.daemon_path,
        "migrate",
        "cutover",
        "--plan",
        fixture.plan_path,
        "--state-file",
        fixture.state_path,
        "--staging-dir",
        fixture.staging_dir,
        "--backend",
        "nftables",
        "--socket",
        fixture.socket_path,
    }, null);
    defer staged.deinit(testing.allocator);
    try expectExit(staged, 3);
    try expectContains(staged.stdout, "\"state\":\"staged\"");
    const run_id = try runIdFrom(staged.stderr);
    const run_hex = std.fmt.bytesToHex(run_id, .lower);
    try expectStagedOwnerMeaning(&fixture, run_id);

    const status = try runCommand(testing.allocator, &.{
        release_options.daemon_path,
        "migrate",
        "status",
        "--plan",
        fixture.plan_path,
        "--state-file",
        fixture.state_path,
        "--staging-dir",
        fixture.staging_dir,
        "--backend",
        "nftables",
        "--run-id",
        run_hex[0..],
    }, null);
    defer status.deinit(testing.allocator);
    try expectExit(status, 3);
    try expectContains(status.stdout, "\"state\":\"staged\"");
    try expectContains(status.stdout, "\"step\":\"stage_destination\",\"outcome\":\"success\"");

    const resumed = try runCommand(testing.allocator, &.{
        release_options.daemon_path,
        "migrate",
        "cutover",
        "--plan",
        fixture.plan_path,
        "--state-file",
        fixture.state_path,
        "--staging-dir",
        fixture.staging_dir,
        "--backend",
        "nftables",
        "--socket",
        fixture.socket_path,
        "--run-id",
        run_hex[0..],
    }, null);
    defer resumed.deinit(testing.allocator);
    try expectExit(resumed, 3);
    try expectStagedOwnerMeaning(&fixture, run_id);

    const rollback = try runCommand(testing.allocator, &.{
        release_options.daemon_path,
        "migrate",
        "rollback",
        "--plan",
        fixture.plan_path,
        "--state-file",
        fixture.state_path,
        "--staging-dir",
        fixture.staging_dir,
        "--backend",
        "nftables",
        "--socket",
        fixture.socket_path,
        "--run-id",
        run_hex[0..],
    }, null);
    defer rollback.deinit(testing.allocator);
    try expectExit(rollback, 1);
    try expectContains(rollback.stderr, "only an activated run needs rollback");
    try testing.expectEqualSlices(u8, &before, &try engine.migration_snapshot_mod.sha256File(fixture.source_db));
}

test "release migration: killed stage intent remains inspectable and resumes exactly once" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try fixture.plan();

    const killed = try runCommand(testing.allocator, &.{
        release_options.daemon_path,
        "migrate",
        "cutover",
        "--plan",
        fixture.plan_path,
        "--state-file",
        fixture.state_path,
        "--staging-dir",
        fixture.staging_dir,
        "--backend",
        "nftables",
        "--socket",
        fixture.socket_path,
    }, "stage_destination");
    defer killed.deinit(testing.allocator);
    try expectExit(killed, 137);
    const run_id = try runIdFrom(killed.stderr);
    const run_hex = std.fmt.bytesToHex(run_id, .lower);

    const interrupted_status = try runCommand(testing.allocator, &.{
        release_options.daemon_path,
        "migrate",
        "status",
        "--plan",
        fixture.plan_path,
        "--state-file",
        fixture.state_path,
        "--staging-dir",
        fixture.staging_dir,
        "--backend",
        "nftables",
        "--run-id",
        run_hex[0..],
    }, null);
    defer interrupted_status.deinit(testing.allocator);
    try expectExit(interrupted_status, 3);
    try expectContains(interrupted_status.stdout, "\"step\":\"stage_destination\",\"outcome\":\"pending\"");
    try testing.expectEqual(@as(u64, 0), (try fixture.inspectStaged(run_id)).owners);

    const resumed = try runCommand(testing.allocator, &.{
        release_options.daemon_path,
        "migrate",
        "cutover",
        "--plan",
        fixture.plan_path,
        "--state-file",
        fixture.state_path,
        "--staging-dir",
        fixture.staging_dir,
        "--backend",
        "nftables",
        "--socket",
        fixture.socket_path,
        "--run-id",
        run_hex[0..],
    }, null);
    defer resumed.deinit(testing.allocator);
    try expectExit(resumed, 3);
    try expectStagedOwnerMeaning(&fixture, run_id);

    const final_status = try runCommand(testing.allocator, &.{
        release_options.daemon_path,
        "migrate",
        "status",
        "--plan",
        fixture.plan_path,
        "--state-file",
        fixture.state_path,
        "--staging-dir",
        fixture.staging_dir,
        "--backend",
        "nftables",
        "--run-id",
        run_hex[0..],
    }, null);
    defer final_status.deinit(testing.allocator);
    try expectExit(final_status, 3);
    try expectContains(final_status.stdout, "\"state\":\"staged\"");
    try expectContains(final_status.stdout, "\"step\":\"stage_destination\",\"outcome\":\"success\"");
}

test "release migration: changed configuration and captured source invalidate the plan before staging" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try fixture.plan();

    const jail_local = try std.fs.path.join(testing.allocator, &.{ fixture.source_dir, "jail.d", "lab.conf" });
    defer testing.allocator.free(jail_local);
    {
        var file = try std.fs.openFileAbsolute(jail_local, .{ .mode = .write_only });
        defer file.close();
        try file.seekFromEnd(0);
        try file.writeAll("\n# changed after planning\n");
    }
    const snapshot_path = try snapshotPathFromPlan(testing.allocator, fixture.plan_path);
    defer testing.allocator.free(snapshot_path);
    {
        var file = try std.fs.openFileAbsolute(snapshot_path, .{ .mode = .write_only });
        defer file.close();
        try file.seekFromEnd(0);
        try file.writeAll("\n");
    }

    const validation = try runCommand(testing.allocator, &.{
        release_options.daemon_path,
        "migrate",
        "validate",
        "--plan",
        fixture.plan_path,
    }, null);
    defer validation.deinit(testing.allocator);
    try expectExit(validation, 1);
    try expectContains(validation.stdout, "\"outcome\":\"drifted\"");
    try expectContains(validation.stdout, "file-changed:");
    try expectContains(validation.stdout, "snapshot-changed");

    const refused = try runCommand(testing.allocator, &.{
        release_options.daemon_path,
        "migrate",
        "cutover",
        "--plan",
        fixture.plan_path,
        "--state-file",
        fixture.state_path,
        "--staging-dir",
        fixture.staging_dir,
        "--backend",
        "nftables",
        "--socket",
        fixture.socket_path,
    }, null);
    defer refused.deinit(testing.allocator);
    try expectExit(refused, 1);
    try expectContains(refused.stdout, "\"step\":\"validate_plan\",\"outcome\":\"validation_failed\"");
    try testing.expectEqual(@as(i64, 0), blk: {
        var store = try engine.native_store_mod.Store.openReadOnly(testing.allocator, fixture.state_path);
        defer store.close();
        break :blk try store.inspectInteger("SELECT count(*) FROM migration_staged_owners;");
    });
}

test "release migration: permissive staging is refused before durable or filesystem mutation" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try fixture.plan();

    const loose = try std.fs.path.join(testing.allocator, &.{ fixture.root, "loose" });
    defer testing.allocator.free(loose);
    try std.fs.makeDirAbsolute(loose);
    try std.posix.fchmodat(std.posix.AT.FDCWD, loose, 0o755, 0);
    const refused = try runCommand(testing.allocator, &.{
        release_options.daemon_path,
        "migrate",
        "cutover",
        "--plan",
        fixture.plan_path,
        "--state-file",
        fixture.state_path,
        "--staging-dir",
        loose,
        "--backend",
        "nftables",
        "--socket",
        fixture.socket_path,
    }, null);
    defer refused.deinit(testing.allocator);
    try expectExit(refused, 2);
    try expectContains(refused.stderr, "staging dir");
    try testing.expectEqual(@as(usize, 0), try directoryEntries(loose));
    var store = try engine.native_store_mod.Store.openReadOnly(testing.allocator, fixture.state_path);
    defer store.close();
    try testing.expectEqual(@as(i64, 0), try store.inspectInteger("SELECT count(*) FROM migration_runs;"));
}

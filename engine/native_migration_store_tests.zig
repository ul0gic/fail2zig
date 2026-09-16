// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const durable = @import("core/record_store.zig");
const effects = @import("core/native_effect.zig");
const canonical = @import("firewall/scope.zig");

const t = std.testing;

const Fixture = struct {
    tmp: t.TmpDir,
    path: []u8,
    store: durable.Store,
    fn init() !Fixture {
        var tmp = t.tmpDir(.{});
        errdefer tmp.cleanup();
        const root = try tmp.dir.realpathAlloc(t.allocator, ".");
        defer t.allocator.free(root);
        const path = try std.fs.path.join(t.allocator, &.{ root, "migration.sqlite" });
        errdefer t.allocator.free(path);
        var store = try durable.Store.open(t.allocator, path);
        errdefer store.close();
        try store.enableReceipts(8);
        try store.enableNativeTime();
        try store.enableYearInference();
        try store.enableDetection();
        try store.enableClockRecovery();
        try store.enableJournalDetection();
        try store.enableRetry();
        try store.enableConsumers();
        try store.enableEffects();
        try store.admitInstallation(try effects.Installation.init([_]u8{7} ** 16, .nftables, "host-default"), .{ .selector = "host-default", .disposition = .verified_absent });
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
        return .{ .tmp = tmp, .path = path, .store = store };
    }
    fn deinit(self: *Fixture) void {
        self.store.close();
        t.allocator.free(self.path);
        self.tmp.cleanup();
    }
};

fn staticRead(_: ?*anyopaque) i64 {
    return 5_000_000;
}
fn clock() effects.Clock {
    return .{ .prepared_us = 5_000_000, .context = null, .read = staticRead };
}
fn run(id: u8) durable.Store.MigrationRun {
    return .{ .run_id = [_]u8{id} ** 32, .host_id = [_]u8{1} ** 32, .source_db_fp = [_]u8{2} ** 32, .source_cfg_fp = [_]u8{3} ** 32, .plan_fp = [_]u8{4} ** 32, .recovery_point = "/var/lib/fail2zig/migration/r/recovery.sqlite3", .generation = [_]u8{5} ** 32, .state = .planned, .created_us = 100, .updated_us = 100 };
}
fn hostScope(last: u8) ![92]u8 {
    const scope = canonical.Scope{ .subject = canonical.Subject.host(.{ .ipv4 = (192 << 24) | (0 << 16) | (2 << 8) | @as(u32, last) }) };
    return scope.encode();
}

test "migration store: BUG-036 corrupt stored integers refuse and roll back activation" {
    var f = try Fixture.init();
    defer f.deinit();
    const run_id = [_]u8{9} ** 32;
    try f.store.createMigrationRun(run(9));
    try f.store.stageMigrationRows(run_id, &.{.{ .jail = "sshd", .scope = try hostScope(10), .lease_kind = 1, .deadline_us = 9_000_000, .source_event_us = 1_000_000, .source_row = 1 }}, &.{});
    const seq = try f.store.beginMigrationStep(run_id, .stage_destination, "", 300);
    try f.store.finishMigrationStep(run_id, seq, .success, "", .staged, 301);
    try f.store.inspectExec("PRAGMA ignore_check_constraints=ON;");
    try f.store.inspectExec("UPDATE migration_staged_owners SET lease_kind=256;");
    const generations: []const durable.Store.JailGeneration = &.{.{ .jail = "sshd", .generation = [_]u8{5} ** 32 }};
    try t.expectError(error.InvalidMigrationRow, f.store.activateStagedOwners(run_id, generations, clock()));
    try t.expectEqual(@as(i64, 0), try f.store.inspectInteger("SELECT count(*) FROM effect_owners;"));
    try t.expectEqual(@as(i64, @intFromEnum(durable.Store.MigrationState.staged)), try f.store.inspectInteger("SELECT state FROM migration_runs;"));
    try f.store.inspectExec("UPDATE migration_staged_owners SET lease_kind=1,seq=-1;");
    try t.expectError(error.InvalidMigrationRow, f.store.activateStagedOwners(run_id, generations, clock()));
    try t.expectEqual(@as(i64, 0), try f.store.inspectInteger("SELECT count(*) FROM effect_owners;"));
    try f.store.inspectExec("UPDATE migration_staged_owners SET seq=1;");
    try f.store.inspectExec("PRAGMA ignore_check_constraints=OFF;");
    try t.expectEqual(@as(u64, 1), try f.store.activateStagedOwners(run_id, generations, clock()));
}

test "migration store: runs are unique, steps record intent before outcome and refuse overlap" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.store.createMigrationRun(run(9));
    try t.expectError(error.MigrationRunExists, f.store.createMigrationRun(run(9)));
    const loaded = (try f.store.migrationRun(t.allocator, [_]u8{9} ** 32)).?;
    defer t.allocator.free(loaded.recovery_point);
    try t.expectEqual(durable.Store.MigrationState.planned, loaded.state);
    try t.expectEqualStrings("/var/lib/fail2zig/migration/r/recovery.sqlite3", loaded.recovery_point);
    try t.expectEqual(@as(?durable.Store.MigrationRun, null), try f.store.migrationRun(t.allocator, [_]u8{8} ** 32));

    const seq = try f.store.beginMigrationStep([_]u8{9} ** 32, .validate_plan, "plan=abc", 200);
    try t.expectEqual(@as(u64, 1), seq);
    try t.expectError(error.MigrationStepOpen, f.store.beginMigrationStep([_]u8{9} ** 32, .check_drift, "", 201));
    try t.expectError(error.MigrationStepMissing, f.store.finishMigrationStep([_]u8{9} ** 32, 2, .success, "", null, 202));
    try t.expectError(error.InvalidMigrationRow, f.store.finishMigrationStep([_]u8{9} ** 32, 1, .pending, "", null, 202));
    try f.store.finishMigrationStep([_]u8{9} ** 32, 1, .success, "ok", .validated, 202);
    try t.expectError(error.MigrationStepMissing, f.store.finishMigrationStep([_]u8{9} ** 32, 1, .success, "", null, 203));
    f.store.fail_at = .after_migration_step_intent;
    try t.expectError(error.InjectedFailure, f.store.beginMigrationStep([_]u8{9} ** 32, .check_drift, "", 300));
    f.store.fail_at = null;
    var steps: [8]durable.Store.MigrationStepRow = undefined;
    try t.expectEqual(@as(usize, 1), try f.store.migrationSteps([_]u8{9} ** 32, &steps));
    try t.expectEqual(durable.Store.MigrationStep.validate_plan, steps[0].step);
    try t.expectEqual(durable.Store.MigrationOutcome.success, steps[0].outcome);
    try t.expectEqual(@as(?i64, 202), steps[0].finished_us);
    const after = (try f.store.migrationRun(t.allocator, [_]u8{9} ** 32)).?;
    defer t.allocator.free(after.recovery_point);
    try t.expectEqual(durable.Store.MigrationState.validated, after.state);
    try t.expectEqual(@as(i64, 202), after.updated_us);
    try t.expectError(error.MigrationRunMissing, f.store.beginMigrationStep([_]u8{8} ** 32, .validate_plan, "", 400));
}

test "migration store: staged rows replace atomically and stay outside authority until activation" {
    var f = try Fixture.init();
    defer f.deinit();
    const run_id = [_]u8{9} ** 32;
    try f.store.createMigrationRun(run(9));
    const owners = [_]durable.Store.StagedOwnerRow{
        .{ .jail = "sshd", .scope = try hostScope(10), .lease_kind = 1, .deadline_us = 9_000_000, .source_event_us = 1_000_000, .source_row = 1 },
        .{ .jail = "sshd", .scope = try hostScope(11), .lease_kind = 2, .deadline_us = null, .source_event_us = 1_000_000, .source_row = 2 },
        .{ .jail = "sshd", .scope = try hostScope(12), .lease_kind = 1, .deadline_us = 4_000_000, .source_event_us = 900_000, .source_row = 3 },
    };
    const history = [_]durable.Store.StagedHistoryRow{.{ .jail = "sshd", .scope = try hostScope(10), .event_kind = 1, .event_us = 1_000_000, .bancount = 2, .source_row = 1 }};
    try f.store.stageMigrationRows(run_id, &owners, &history);
    try t.expectEqual(durable.Store.StagedCounts{ .owners = 3, .history = 1 }, try f.store.stagedMigrationCounts(run_id));
    try f.store.stageMigrationRows(run_id, owners[0..2], &.{});
    try t.expectEqual(durable.Store.StagedCounts{ .owners = 2, .history = 0 }, try f.store.stagedMigrationCounts(run_id));
    try t.expectError(error.InvalidMigrationRow, f.store.stageMigrationRows(run_id, &.{.{ .jail = "sshd", .scope = try hostScope(10), .lease_kind = 1, .deadline_us = null, .source_event_us = 1, .source_row = 1 }}, &.{}));
    try t.expectEqual(durable.Store.StagedCounts{ .owners = 2, .history = 0 }, try f.store.stagedMigrationCounts(run_id));
    try t.expectEqual(@as(i64, 0), try f.store.inspectInteger("SELECT count(*) FROM effect_owners;"));
    try f.store.stageMigrationRows(run_id, &owners, &history);

    try t.expectError(error.InvalidMigrationState, f.store.activateStagedOwners(run_id, &.{.{ .jail = "sshd", .generation = [_]u8{5} ** 32 }}, clock()));
    const seq = try f.store.beginMigrationStep(run_id, .stage_destination, "", 300);
    try f.store.finishMigrationStep(run_id, seq, .success, "", .staged, 301);
    try t.expectError(error.MigrationJailUnknown, f.store.activateStagedOwners(run_id, &.{.{ .jail = "other", .generation = [_]u8{5} ** 32 }}, clock()));
    try t.expectEqual(@as(i64, 0), try f.store.inspectInteger("SELECT count(*) FROM effect_owners;"));
    var keys: [4][32]u8 = undefined;
    const before = try f.store.migrationActivatedKeys(run_id, 5_000_000, &keys);
    try t.expectEqual(@as(u64, 2), before.expected);
    try t.expectEqual(@as(usize, 0), before.found);
    try t.expectEqual(@as(u64, 2), try f.store.activateStagedOwners(run_id, &.{.{ .jail = "sshd", .generation = [_]u8{5} ** 32 }}, clock()));
    try t.expectEqual(@as(i64, @intFromEnum(durable.Store.MigrationState.activating)), try f.store.inspectInteger("SELECT state FROM migration_runs WHERE run_id=x'0909090909090909090909090909090909090909090909090909090909090909';"));
    const after = try f.store.migrationActivatedKeys(run_id, 5_000_000, &keys);
    try t.expectEqual(@as(u64, 2), after.expected);
    try t.expectEqual(@as(usize, 2), after.found);
    try t.expectError(error.EffectCapacity, f.store.migrationActivatedKeys(run_id, 5_000_000, keys[0..1]));
    try t.expectEqual(@as(i64, 2), try f.store.inspectInteger("SELECT count(*) FROM effect_owners WHERE jail='sshd';"));
    try t.expectEqual(@as(i64, 1), try f.store.inspectInteger("SELECT count(*) FROM effect_owners WHERE lease_kind=1 AND deadline_us=9000000;"));
    try t.expectEqual(@as(i64, 1), try f.store.inspectInteger("SELECT count(*) FROM effect_owners WHERE lease_kind=2;"));
    const revisions = try f.store.inspectInteger("SELECT count(*) FROM effect_owner_revisions;");
    try t.expectEqual(@as(u64, 2), try f.store.activateStagedOwners(run_id, &.{.{ .jail = "sshd", .generation = [_]u8{5} ** 32 }}, clock()));
    try t.expectEqual(revisions, try f.store.inspectInteger("SELECT count(*) FROM effect_owner_revisions;"));
    f.store.fail_at = .before_migration_activation_commit;
    try t.expectError(error.InjectedFailure, f.store.activateStagedOwners([_]u8{9} ** 32, &.{.{ .jail = "sshd", .generation = [_]u8{5} ** 32 }}, clock()));
    f.store.fail_at = null;
    try t.expectEqual(@as(i64, 2), try f.store.inspectInteger("SELECT count(*) FROM effect_owners WHERE jail='sshd';"));
}

test "migration store: rollback deltas name released, expired and native owners and the release retains history" {
    var f = try Fixture.init();
    defer f.deinit();
    const run_id = [_]u8{0x0c} ** 32;
    try f.store.createMigrationRun(run(0x0c));
    const owners = [_]durable.Store.StagedOwnerRow{
        .{ .jail = "sshd", .scope = try hostScope(20), .lease_kind = 1, .deadline_us = 9_000_000, .source_event_us = 1_000_000, .source_row = 1 },
        .{ .jail = "sshd", .scope = try hostScope(21), .lease_kind = 2, .deadline_us = null, .source_event_us = 1_000_000, .source_row = 2 },
        .{ .jail = "sshd", .scope = try hostScope(22), .lease_kind = 1, .deadline_us = 6_000_000, .source_event_us = 900_000, .source_row = 3 },
    };
    try f.store.stageMigrationRows(run_id, &owners, &.{});
    const seq = try f.store.beginMigrationStep(run_id, .stage_destination, "", 300);
    try f.store.finishMigrationStep(run_id, seq, .success, "", .staged, 301);
    try t.expectEqual(@as(u64, 3), try f.store.activateStagedOwners(run_id, &.{.{ .jail = "sshd", .generation = [_]u8{5} ** 32 }}, clock()));
    const native = canonical.Scope{ .subject = canonical.Subject.host(.{ .ipv4 = (192 << 24) | (2 << 8) | 30 }) };
    _ = try f.store.setOwnerFromCanonical(.{ .scope = native, .jail = "sshd", .generation = [_]u8{5} ** 32, .decision_id = [_]u8{0x3a} ** 32, .expected_revision = 0, .lease = .{ .finite = 8_000_000 }, .decided_us = 4_900_000 }, clock());
    const released_scope = canonical.Scope{ .subject = canonical.Subject.host(.{ .ipv4 = (192 << 24) | (2 << 8) | 21 }) };
    const installation = (try f.store.readInstallation()).?;
    const released_key = try (try effects.Scope.exact(released_scope)).key(installation);
    const owner = (try f.store.currentOwner(released_key, "sshd")).?;
    _ = try f.store.transitionOwner(.{ .scope = released_scope, .jail = "sshd", .current_generation = owner.generation, .next_generation = owner.generation, .expected_owner_revision = owner.revision, .transition_id = [_]u8{0x3b} ** 32, .mode = .release, .occurred_us = 4_950_000 }, clock());
    _ = try f.store.setOwnerFromCanonical(.{ .scope = released_scope, .jail = "sshd", .generation = [_]u8{5} ** 32, .decision_id = [_]u8{0x3c} ** 32, .expected_revision = (try f.store.currentOwner(released_key, "sshd")).?.revision, .lease = .{ .finite = 9_500_000 }, .decided_us = 4_960_000 }, clock());
    var deltas: [8]durable.Store.MigrationDelta = undefined;
    const count = try f.store.planMigrationDeltas(run_id, &.{"sshd"}, 7_000_000, &deltas);
    try t.expectEqual(@as(usize, 3), count);
    try t.expectEqual(durable.Store.MigrationDeltaKind.ban, deltas[0].kind);
    try t.expectEqual(durable.Store.MigrationCarryBack.mapped, deltas[0].carry_back);
    try t.expectEqual(@as(?i64, 9_500_000), deltas[0].deadline_us);
    try t.expectEqual(durable.Store.MigrationDeltaKind.unban, deltas[1].kind);
    try t.expectEqual(durable.Store.MigrationCarryBack.expired, deltas[1].carry_back);
    try t.expectEqual(durable.Store.MigrationDeltaKind.ban, deltas[2].kind);
    try t.expectEqual(durable.Store.MigrationCarryBack.mapped, deltas[2].carry_back);
    try t.expectEqual(@as(i64, 4_900_000), deltas[2].decided_us);
    try f.store.recordMigrationDeltas(run_id, deltas[0..count], false, 7_000_000);
    try f.store.recordMigrationDeltas(run_id, deltas[0..count], false, 7_000_001);
    try t.expectEqual(@as(i64, 3), try f.store.inspectInteger("SELECT count(*) FROM migration_deltas WHERE run_id=x'0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c' AND applied=0;"));
    try f.store.markMigrationDeltasApplied(run_id);
    try t.expectEqual(@as(i64, 3), try f.store.inspectInteger("SELECT count(*) FROM migration_deltas WHERE run_id=x'0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c' AND applied=1;"));
    var keys: [8][32]u8 = undefined;
    try t.expectEqual(@as(usize, 3), try f.store.migrationStagedKeys(run_id, &keys));
    const history_before = try f.store.inspectInteger("SELECT count(*) FROM effect_owner_revisions;");
    try t.expectEqual(@as(u64, 3), try f.store.releaseMigrationOwners(run_id, clock()));
    try t.expectEqual(@as(i64, 1), try f.store.inspectInteger("SELECT count(*) FROM effect_owners WHERE jail='sshd' AND lease_kind!=0 AND deadline_us=8000000;"));
    try t.expect(try f.store.inspectInteger("SELECT count(*) FROM effect_owner_revisions;") > history_before);
    try t.expectEqual(@as(u64, 0), try f.store.releaseMigrationOwners(run_id, clock()));
}

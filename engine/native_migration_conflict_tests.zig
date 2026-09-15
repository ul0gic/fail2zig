// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Regression root for BUG-024: staged migration owners must never replace or shorten a
//! live native owner on the same scope. Contract asserted: a permanent native lease is kept,
//! a later native deadline is kept, an earlier native deadline is extended to the staged one,
//! exactly one owner row per scope remains, the native decision id survives whenever the
//! native lease was kept, each conflict is recorded as a migration delta (kind 3, carry_back
//! 1 mapped, applied 0), and the returned activation count excludes conflicts.
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
        const path = try std.fs.path.join(t.allocator, &.{ root, "conflict.sqlite" });
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

const now_us: i64 = 5_000_000;
const generation = [_]u8{5} ** 32;
const run_id = [_]u8{9} ** 32;

fn staticRead(_: ?*anyopaque) i64 {
    return now_us;
}
fn clock() effects.Clock {
    return .{ .prepared_us = now_us, .context = null, .read = staticRead };
}
fn hostScope(last: u8) canonical.Scope {
    return .{ .subject = canonical.Subject.host(.{ .ipv4 = (192 << 24) | (0 << 16) | (2 << 8) | @as(u32, last) }) };
}
fn nativeDecision(last: u8) [32]u8 {
    return [_]u8{last} ** 32;
}
fn placeNativeOwner(store: *durable.Store, last: u8, lease: effects.Lease) !void {
    _ = try store.setOwnerFromCanonical(.{ .scope = hostScope(last), .jail = "sshd", .generation = generation, .decision_id = nativeDecision(last), .expected_revision = 0, .lease = lease, .decided_us = now_us - 1_000_000 }, clock());
}

const OwnerRow = struct { count: i64, lease_kind: i64, deadline_us: ?i64, native_decision: bool };

fn ownerRow(store: *durable.Store, last: u8) !OwnerRow {
    var sql: [512]u8 = undefined;
    const encoded = try hostScope(last).encode();
    const hex = std.fmt.bytesToHex(encoded, .lower);
    const where = try std.fmt.bufPrintZ(&sql, "FROM effect_owners o JOIN native_effects n USING(scope_key) WHERE o.jail='sshd' AND n.canonical_scope=x'{s}'", .{hex});
    var buf: [1024]u8 = undefined;
    const count = try store.inspectInteger(try std.fmt.bufPrintZ(&buf, "SELECT count(*) {s};", .{where}));
    if (count == 0) return .{ .count = 0, .lease_kind = 0, .deadline_us = null, .native_decision = false };
    const lease_kind = try store.inspectInteger(try std.fmt.bufPrintZ(&buf, "SELECT o.lease_kind {s};", .{where}));
    const has_deadline = try store.inspectInteger(try std.fmt.bufPrintZ(&buf, "SELECT o.deadline_us IS NOT NULL {s};", .{where}));
    const deadline: ?i64 = if (has_deadline == 1) try store.inspectInteger(try std.fmt.bufPrintZ(&buf, "SELECT o.deadline_us {s};", .{where})) else null;
    const decision_hex = std.fmt.bytesToHex(nativeDecision(last), .lower);
    const native = try store.inspectInteger(try std.fmt.bufPrintZ(&buf, "SELECT o.decision_id=x'{s}' {s};", .{ decision_hex, where }));
    return .{ .count = count, .lease_kind = lease_kind, .deadline_us = deadline, .native_decision = native == 1 };
}

fn expectOwner(label: []const u8, actual: OwnerRow, expected: OwnerRow) !void {
    if (actual.count != expected.count or actual.lease_kind != expected.lease_kind or !std.meta.eql(actual.deadline_us, expected.deadline_us) or actual.native_decision != expected.native_decision) {
        std.debug.print("BUG-024 {s}: effect_owners row is {any}, contract requires {any}\n", .{ label, actual, expected });
        return error.TestUnexpectedResult;
    }
}

test "migration conflict: activation keeps live native owners, records conflicts and counts only fresh owners" {
    var f = try Fixture.init();
    defer f.deinit();
    const staged_deadline: i64 = now_us + 3_600_000_000;
    try placeNativeOwner(&f.store, 10, .permanent);
    try placeNativeOwner(&f.store, 11, .{ .finite = staged_deadline + 1_000_000_000 });
    try placeNativeOwner(&f.store, 12, .{ .finite = staged_deadline - 1_000_000_000 });
    try t.expectEqual(@as(i64, 3), try f.store.inspectInteger("SELECT count(*) FROM effect_owners WHERE jail='sshd';"));
    const revisions_before = try f.store.inspectInteger("SELECT count(*) FROM effect_owner_revisions;");

    try f.store.createMigrationRun(.{ .run_id = run_id, .host_id = [_]u8{1} ** 32, .source_db_fp = [_]u8{2} ** 32, .source_cfg_fp = [_]u8{3} ** 32, .plan_fp = [_]u8{4} ** 32, .recovery_point = "/var/lib/fail2zig/migration/r/recovery.sqlite3", .generation = generation, .state = .planned, .created_us = 100, .updated_us = 100 });
    const owners = [_]durable.Store.StagedOwnerRow{
        .{ .jail = "sshd", .scope = try hostScope(10).encode(), .lease_kind = 1, .deadline_us = staged_deadline, .source_event_us = 1_000_000, .source_row = 1 },
        .{ .jail = "sshd", .scope = try hostScope(11).encode(), .lease_kind = 1, .deadline_us = staged_deadline, .source_event_us = 1_000_000, .source_row = 2 },
        .{ .jail = "sshd", .scope = try hostScope(12).encode(), .lease_kind = 1, .deadline_us = staged_deadline, .source_event_us = 1_000_000, .source_row = 3 },
        .{ .jail = "sshd", .scope = try hostScope(13).encode(), .lease_kind = 1, .deadline_us = staged_deadline, .source_event_us = 1_000_000, .source_row = 4 },
    };
    try f.store.stageMigrationRows(run_id, &owners, &.{});
    const seq = try f.store.beginMigrationStep(run_id, .stage_destination, "", 300);
    try f.store.finishMigrationStep(run_id, seq, .success, "", .staged, 301);

    const activated = try f.store.activateStagedOwners(run_id, &.{.{ .jail = "sshd", .generation = generation }}, clock());

    try t.expectEqual(@as(i64, 4), try f.store.inspectInteger("SELECT count(*) FROM effect_owners WHERE jail='sshd';"));
    try expectOwner("(a) permanent native owner", try ownerRow(&f.store, 10), .{ .count = 1, .lease_kind = 2, .deadline_us = null, .native_decision = true });
    try expectOwner("(b) later native deadline", try ownerRow(&f.store, 11), .{ .count = 1, .lease_kind = 1, .deadline_us = staged_deadline + 1_000_000_000, .native_decision = true });
    const extended = try ownerRow(&f.store, 12);
    if (extended.count != 1 or extended.lease_kind != 1 or extended.deadline_us != staged_deadline) {
        std.debug.print("BUG-024 (c) earlier native deadline: effect_owners row is {any}, contract requires one finite owner extended to the staged deadline {d}\n", .{ extended, staged_deadline });
        return error.TestUnexpectedResult;
    }
    try expectOwner("(d) fresh staged owner", try ownerRow(&f.store, 13), .{ .count = 1, .lease_kind = 1, .deadline_us = staged_deadline, .native_decision = false });

    const conflicts = try f.store.inspectInteger("SELECT count(*) FROM migration_deltas WHERE run_id=x'0909090909090909090909090909090909090909090909090909090909090909' AND kind=3 AND carry_back=1 AND applied=0;");
    if (conflicts != 3) {
        std.debug.print("BUG-024: migration_deltas holds {d} conflict rows (kind=3, carry_back=1, applied=0); contract requires one per conflicting scope (3)\n", .{conflicts});
        return error.TestUnexpectedResult;
    }
    if (activated != 1) {
        std.debug.print("BUG-024: activateStagedOwners returned {d}; contract requires the count of fresh owners only (1)\n", .{activated});
        return error.TestUnexpectedResult;
    }
    // Kept native leases (a)/(b) must not spend an owner revision; only (c) and (d) may.
    const revisions_after = try f.store.inspectInteger("SELECT count(*) FROM effect_owner_revisions;");
    if (revisions_after - revisions_before > 2) {
        std.debug.print("BUG-024: {d} owner revisions were written by activation; kept native owners must not be rewritten (at most 2 expected)\n", .{revisions_after - revisions_before});
        return error.TestUnexpectedResult;
    }
}

test "migration conflict: repeated activation after a conflict replays without new revisions" {
    var f = try Fixture.init();
    defer f.deinit();
    try placeNativeOwner(&f.store, 10, .permanent);
    try f.store.createMigrationRun(.{ .run_id = run_id, .host_id = [_]u8{1} ** 32, .source_db_fp = [_]u8{2} ** 32, .source_cfg_fp = [_]u8{3} ** 32, .plan_fp = [_]u8{4} ** 32, .recovery_point = "/r", .generation = generation, .state = .planned, .created_us = 100, .updated_us = 100 });
    try f.store.stageMigrationRows(run_id, &.{.{ .jail = "sshd", .scope = try hostScope(10).encode(), .lease_kind = 1, .deadline_us = now_us + 60_000_000, .source_event_us = 1_000_000, .source_row = 1 }}, &.{});
    const seq = try f.store.beginMigrationStep(run_id, .stage_destination, "", 300);
    try f.store.finishMigrationStep(run_id, seq, .success, "", .staged, 301);
    _ = try f.store.activateStagedOwners(run_id, &.{.{ .jail = "sshd", .generation = generation }}, clock());
    const revisions = try f.store.inspectInteger("SELECT count(*) FROM effect_owner_revisions;");
    const deltas = try f.store.inspectInteger("SELECT count(*) FROM migration_deltas;");
    _ = try f.store.activateStagedOwners(run_id, &.{.{ .jail = "sshd", .generation = generation }}, clock());
    try t.expectEqual(revisions, try f.store.inspectInteger("SELECT count(*) FROM effect_owner_revisions;"));
    try t.expectEqual(deltas, try f.store.inspectInteger("SELECT count(*) FROM migration_deltas;"));
    try expectOwner("(a) permanent native owner after replay", try ownerRow(&f.store, 10), .{ .count = 1, .lease_kind = 2, .deadline_us = null, .native_decision = true });
}

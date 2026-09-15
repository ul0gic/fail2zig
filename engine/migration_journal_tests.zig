// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Resumable migration journal: identity checks, step lifecycle, interruption
//! at every step boundary, storage failure and clock refusal.
const std = @import("std");
const journal = @import("migration/journal.zig");
const durable = @import("core/record_store.zig");
const effects = @import("core/native_effect.zig");

comptime {
    _ = @import("shared");
}

const t = std.testing;
const a = t.allocator;
const Step = journal.Step;
const Outcome = journal.Outcome;
const t0: i64 = 1_700_000_000_000_000;

const Fixture = struct {
    tmp: t.TmpDir,
    path: []u8,
    store: durable.Store,

    fn init() !Fixture {
        var tmp = t.tmpDir(.{});
        errdefer tmp.cleanup();
        const root = try tmp.dir.realpathAlloc(a, ".");
        defer a.free(root);
        const path = try std.fs.path.join(a, &.{ root, "state.sqlite" });
        errdefer a.free(path);
        var store = try durable.Store.open(a, path);
        errdefer store.close();
        try enableThrough23(&store);
        return .{ .tmp = tmp, .path = path, .store = store };
    }

    fn deinit(self: *Fixture) void {
        self.store.close();
        a.free(self.path);
        self.tmp.cleanup();
    }

    /// Simulates a crash: the process state is gone, the file remains.
    fn reopen(self: *Fixture) !void {
        self.store.close();
        self.store = try durable.Store.open(a, self.path);
        try enableThrough23(&self.store);
    }
};

fn enableThrough23(store: *durable.Store) !void {
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
}

const run_id = [_]u8{0x42} ** 32;
const identity = journal.Identity{
    .host_id = [_]u8{0xaa} ** 32,
    .source_db_fp = [_]u8{1} ** 32,
    .source_cfg_fp = [_]u8{2} ** 32,
    .plan_fp = [_]u8{3} ** 32,
    .recovery_point = "/var/lib/fail2zig/migration/recovery-42",
    .generation = [_]u8{4} ** 32,
};

const Probe = struct {
    observation: journal.Observation = .{},
    calls: u32 = 0,
    last_step: ?Step = null,
    fail: bool = false,

    fn observe(ctx: ?*anyopaque, step: Step, run: *const durable.Store.MigrationRun, staged: journal.StagedCounts) anyerror!journal.Observation {
        const self: *Probe = @ptrCast(@alignCast(ctx.?));
        self.calls += 1;
        self.last_step = step;
        try t.expectEqualSlices(u8, &run_id, &run.run_id);
        _ = staged;
        if (self.fail) return error.ReadbackFailed;
        return self.observation;
    }

    fn observer(self: *Probe) journal.Observer {
        return .{ .ctx = self, .observe = observe };
    }
};

const forward = [_]Step{ .validate_plan, .check_drift, .capture_recovery_point, .quiesce_source, .stage_destination, .activate_owners, .verify_protection, .complete };
const state_after = [_]?journal.State{ .validated, null, .recovery_point, .quiesced, .staged, .activating, null, .complete };

/// Runs the forward steps before `upto` to completion, then leaves `upto` pending.
fn advanceTo(j: *journal.Journal, upto: Step, now: *i64) !journal.Pending {
    for (forward, 0..) |step, i| {
        now.* += 10;
        const pending = try j.begin(step, "intent", now.*);
        if (step == upto) return pending;
        now.* += 10;
        try j.finish(pending, .success, "ok", state_after[i], now.*);
    }
    return error.TestUnexpectedResult;
}

fn stagedRows() [1]durable.Store.StagedOwnerRow {
    return .{.{ .jail = "sshd", .scope = [_]u8{2} ++ [_]u8{0} ** 91, .lease_kind = 2, .deadline_us = null, .source_event_us = t0, .source_row = 1 }};
}

test "migration journal: create then open round-trips identity and an empty run continues from validate_plan" {
    var f = try Fixture.init();
    defer f.deinit();
    var created = try journal.Journal.create(a, &f.store, run_id, identity, t0);
    defer created.deinit();
    try t.expectEqual(journal.State.planned, created.state());
    try t.expectEqualSlices(u8, &run_id, &created.runId());

    var opened = try journal.Journal.open(a, &f.store, run_id, identity);
    defer opened.deinit();
    try t.expectEqualStrings(identity.recovery_point, opened.run.recovery_point);
    try t.expectEqual(t0, opened.run.created_us);
    try t.expectEqual(t0, opened.run.updated_us);
    try t.expectEqualSlices(u8, &identity.plan_fp, &opened.run.plan_fp);
    var probe = Probe{};
    try t.expectEqual(journal.Resume{ .continue_from = .validate_plan }, try opened.classify(probe.observer(), t0 + 1));
    try t.expectEqual(@as(u32, 0), probe.calls);
    try t.expectEqual(@as(?journal.Pending, null), try opened.pendingStep());
}

test "migration journal: duplicate create, missing run and every stale fingerprint are typed refusals" {
    var f = try Fixture.init();
    defer f.deinit();
    var created = try journal.Journal.create(a, &f.store, run_id, identity, t0);
    defer created.deinit();
    try t.expectError(error.AlreadyExists, journal.Journal.create(a, &f.store, run_id, identity, t0 + 5));
    try t.expectError(error.RunMissing, journal.Journal.open(a, &f.store, [_]u8{9} ** 32, identity));

    var other_host = identity;
    other_host.host_id = journal.hostId("0123456789abcdef0123456789abcdef", "other");
    try t.expect(!std.mem.eql(u8, &other_host.host_id, &identity.host_id));
    try t.expectError(error.IncompatibleHost, journal.Journal.open(a, &f.store, run_id, other_host));
    var db_changed = identity;
    db_changed.source_db_fp[0] ^= 1;
    try t.expectError(error.IncompatibleSourceDb, journal.Journal.open(a, &f.store, run_id, db_changed));
    var cfg_changed = identity;
    cfg_changed.source_cfg_fp[31] ^= 1;
    try t.expectError(error.IncompatibleSourceConfig, journal.Journal.open(a, &f.store, run_id, cfg_changed));
    var plan_changed = identity;
    plan_changed.plan_fp[7] ^= 1;
    try t.expectError(error.IncompatiblePlan, journal.Journal.open(a, &f.store, run_id, plan_changed));
    var generation_changed = identity;
    generation_changed.generation[0] ^= 1;
    try t.expectError(error.IncompatibleGeneration, journal.Journal.open(a, &f.store, run_id, generation_changed));
    // Host mismatch wins even when everything else also differs.
    var all_changed = other_host;
    all_changed.plan_fp[0] ^= 1;
    try t.expectError(error.IncompatibleHost, journal.Journal.open(a, &f.store, run_id, all_changed));
}

test "migration journal: host id derivation is deterministic, trimmed and hostname-sensitive" {
    const base = journal.hostId("abc\n", "gateway");
    try t.expectEqualSlices(u8, &base, &journal.hostId("abc", " gateway \n"));
    try t.expect(!std.mem.eql(u8, &base, &journal.hostId("abc", "gateway2")));
    try t.expect(!std.mem.eql(u8, &base, &journal.hostId("abd", "gateway")));
    try t.expect(!std.mem.eql(u8, &journal.hostId("", "gateway"), &journal.hostId("gateway", "")));
    const local = journal.localHostId();
    try t.expectEqualSlices(u8, &local, &journal.localHostId());
}

test "migration journal: step lifecycle records intent before outcome and a second opener cannot begin over a pending step" {
    var f = try Fixture.init();
    defer f.deinit();
    var j = try journal.Journal.create(a, &f.store, run_id, identity, t0);
    defer j.deinit();
    const pending = try j.begin(.validate_plan, "validate", t0 + 1);
    try t.expectEqual(@as(u64, 1), pending.seq);
    var rows: [journal.max_steps]journal.StepRow = undefined;
    const listed = try j.steps(&rows);
    try t.expectEqual(@as(usize, 1), listed.len);
    try t.expectEqual(Outcome.pending, listed[0].outcome);
    try t.expectEqual(@as(?i64, null), listed[0].finished_us);

    var second = try journal.Journal.open(a, &f.store, run_id, identity);
    defer second.deinit();
    try t.expectError(error.StepOpen, second.begin(.check_drift, "drift", t0 + 2));
    try t.expectError(error.StepOpen, j.begin(.check_drift, "drift", t0 + 2));

    try j.finish(pending, .success, "ok", .validated, t0 + 3);
    try t.expectEqual(journal.State.validated, j.state());
    try t.expectError(error.StepMissing, j.finish(pending, .success, "twice", null, t0 + 4));
    const next = try second.begin(.check_drift, "drift", t0 + 5);
    try t.expectEqual(@as(u64, 2), next.seq);
    try second.finish(next, .success, "", null, t0 + 6);
    var opened = try journal.Journal.open(a, &f.store, run_id, identity);
    defer opened.deinit();
    try t.expectEqual(journal.State.validated, opened.state());
    try t.expectEqual(t0 + 6, opened.run.updated_us);
}

test "migration journal: clock reversal and oversized detail are refused before any write" {
    var f = try Fixture.init();
    defer f.deinit();
    try t.expectError(error.ClockReversed, journal.Journal.create(a, &f.store, run_id, identity, -1));
    var j = try journal.Journal.create(a, &f.store, run_id, identity, t0);
    defer j.deinit();
    try t.expectError(error.ClockReversed, j.begin(.validate_plan, "x", t0 - 1));
    const big = try a.alloc(u8, journal.max_detail_bytes + 1);
    defer a.free(big);
    @memset(big, 'd');
    try t.expectError(error.DetailTooLarge, j.begin(.validate_plan, big, t0 + 1));
    const pending = try j.begin(.validate_plan, "x", t0 + 1);
    try t.expectError(error.ClockReversed, j.finish(pending, .success, "", null, t0));
    try t.expectError(error.DetailTooLarge, j.finish(pending, .success, big, null, t0 + 2));
    try t.expectError(error.InvalidMigrationRow, j.finish(pending, .pending, "", null, t0 + 2));
    // The store's own guard surfaces as a typed error, never a panic.
    try t.expectError(error.MigrationStepMissing, f.store.finishMigrationStep(run_id, pending.seq, .success, "", null, t0));
    try t.expectError(error.InvalidMigrationRow, f.store.createMigrationRun(.{ .run_id = [_]u8{5} ** 32, .host_id = identity.host_id, .source_db_fp = identity.source_db_fp, .source_cfg_fp = identity.source_cfg_fp, .plan_fp = identity.plan_fp, .recovery_point = "", .generation = identity.generation, .state = .planned, .created_us = t0, .updated_us = t0 - 1 }));
    var probe = Probe{};
    try t.expectError(error.ClockReversed, j.classify(probe.observer(), t0));
    try j.finish(pending, .success, "", .validated, t0 + 3);
    var long_recovery = identity;
    long_recovery.recovery_point = big;
    try t.expectError(error.DetailTooLarge, journal.Journal.create(a, &f.store, [_]u8{6} ** 32, long_recovery, t0));
}

const Case = struct {
    step: Step,
    observation: journal.Observation = .{},
    stage_rows: bool = false,
    expect: journal.Resume,
    recorded: Outcome,
    state: journal.State,
};

const cases = [_]Case{
    .{ .step = .validate_plan, .expect = .{ .repeat_step = .validate_plan }, .recorded = .operational_failure, .state = .planned },
    .{ .step = .check_drift, .expect = .{ .repeat_step = .check_drift }, .recorded = .operational_failure, .state = .validated },
    .{ .step = .capture_recovery_point, .expect = .{ .repeat_step = .capture_recovery_point }, .recorded = .operational_failure, .state = .validated },
    .{ .step = .quiesce_source, .observation = .{ .source = .present }, .expect = .{ .continue_from = .stage_destination }, .recorded = .success, .state = .quiesced },
    .{ .step = .quiesce_source, .observation = .{ .source = .unknown }, .expect = .{ .repeat_step = .quiesce_source }, .recorded = .operational_failure, .state = .recovery_point },
    .{ .step = .stage_destination, .stage_rows = true, .expect = .{ .continue_from = .activate_owners }, .recorded = .success, .state = .staged },
    .{ .step = .stage_destination, .expect = .{ .repeat_step = .stage_destination }, .recorded = .operational_failure, .state = .quiesced },
    .{ .step = .activate_owners, .observation = .{ .destination = .present }, .expect = .{ .continue_from = .verify_protection }, .recorded = .success, .state = .activating },
    .{ .step = .activate_owners, .observation = .{ .destination = .absent }, .expect = .{ .repeat_step = .activate_owners }, .recorded = .operational_failure, .state = .staged },
    .{ .step = .activate_owners, .observation = .{ .destination = .partial }, .expect = .{ .rollback_required = .{ .reason = "activation-partial", .step = .activate_owners } }, .recorded = .partial, .state = .staged },
    .{ .step = .activate_owners, .observation = .{ .destination = .uncertain }, .expect = .{ .refuse = .{ .reason = "activation-uncertain-inspect-before-retry", .step = .activate_owners } }, .recorded = .uncertain, .state = .staged },
    .{ .step = .verify_protection, .expect = .{ .repeat_step = .verify_protection }, .recorded = .operational_failure, .state = .activating },
    .{ .step = .complete, .observation = .{ .destination = .present }, .expect = .complete, .recorded = .success, .state = .complete },
    .{ .step = .complete, .observation = .{ .destination = .unknown }, .expect = .{ .refuse = .{ .reason = "completion-unverified", .step = .complete } }, .recorded = .uncertain, .state = .activating },
};

fn expectResume(expected: journal.Resume, actual: journal.Resume) !void {
    try t.expectEqual(std.meta.activeTag(expected), std.meta.activeTag(actual));
    switch (expected) {
        .continue_from, .repeat_step => try t.expectEqual(expected, actual),
        .refuse => |r| {
            try t.expectEqualStrings(r.reason, actual.refuse.reason);
            try t.expectEqual(r.step, actual.refuse.step);
        },
        .rollback_required => |r| {
            try t.expectEqualStrings(r.reason, actual.rollback_required.reason);
            try t.expectEqual(r.step, actual.rollback_required.step);
        },
        .complete, .rolled_back => {},
    }
}

test "migration journal: interruption at every forward step boundary is classified from durable and observed state" {
    for (cases) |case| {
        var f = try Fixture.init();
        defer f.deinit();
        var now = t0;
        {
            var j = try journal.Journal.create(a, &f.store, run_id, identity, now);
            defer j.deinit();
            _ = try advanceTo(&j, case.step, &now);
            if (case.stage_rows) try f.store.stageMigrationRows(run_id, &stagedRows(), &.{});
        }
        try f.reopen();

        var j = try journal.Journal.open(a, &f.store, run_id, identity);
        defer j.deinit();
        try t.expectEqual(case.step, (try j.pendingStep()).?.step);
        var probe = Probe{ .observation = case.observation };
        now += 10;
        const decision = try j.classify(probe.observer(), now);
        expectResume(case.expect, decision) catch |err| {
            std.debug.print("case step={s} destination={s} source={s}\n", .{ @tagName(case.step), @tagName(case.observation.destination), @tagName(case.observation.source) });
            return err;
        };
        try t.expectEqual(case.state, j.state());
        try t.expectEqual(@as(?journal.Pending, null), try j.pendingStep());
        var rows: [journal.max_steps]journal.StepRow = undefined;
        const listed = try j.steps(&rows);
        const last = listed[listed.len - 1];
        try t.expectEqual(case.step, last.step);
        try t.expectEqual(case.recorded, last.outcome);
        try t.expectEqual(now, last.finished_us.?);
        const observed = switch (case.step) {
            .quiesce_source, .activate_owners, .complete, .rollback => true,
            else => false,
        };
        try t.expectEqual(@as(u32, if (observed) 1 else 0), probe.calls);

        // A second classification finds no pending step and must agree without re-observing.
        var again = Probe{};
        const second = try j.classify(again.observer(), now + 1);
        try t.expectEqual(@as(u32, 0), again.calls);
        switch (case.expect) {
            .continue_from => |step| try t.expectEqual(journal.Resume{ .continue_from = step }, second),
            .repeat_step, .refuse => try t.expectEqual(std.meta.activeTag(journal.Resume{ .refuse = undefined }), std.meta.activeTag(second)),
            .rollback_required => try t.expectEqual(std.meta.activeTag(journal.Resume{ .rollback_required = undefined }), std.meta.activeTag(second)),
            .complete => try t.expectEqual(journal.Resume.complete, second),
            .rolled_back => try t.expectEqual(journal.Resume.rolled_back, second),
        }
        // Reopening after the settlement reads the same state back.
        try f.reopen();
        var reopened = try journal.Journal.open(a, &f.store, run_id, identity);
        defer reopened.deinit();
        try t.expectEqual(case.state, reopened.state());
    }
}

test "migration journal: interruption between steps continues from the next step without observation" {
    var f = try Fixture.init();
    defer f.deinit();
    var now = t0;
    {
        var j = try journal.Journal.create(a, &f.store, run_id, identity, now);
        defer j.deinit();
        const pending = try advanceTo(&j, .stage_destination, &now);
        try f.store.stageMigrationRows(run_id, &stagedRows(), &.{});
        now += 10;
        try j.finish(pending, .success, "", .staged, now);
    }
    try f.reopen();
    var j = try journal.Journal.open(a, &f.store, run_id, identity);
    defer j.deinit();
    var probe = Probe{ .fail = true };
    try t.expectEqual(journal.Resume{ .continue_from = .activate_owners }, try j.classify(probe.observer(), now + 1));
    try t.expectEqual(@as(u32, 0), probe.calls);
}

test "migration journal: rollback interruption and a failed observer" {
    var f = try Fixture.init();
    defer f.deinit();
    const now = t0;
    var j = try journal.Journal.create(a, &f.store, run_id, identity, now);
    defer j.deinit();
    _ = try j.begin(.rollback, "restore", now + 1);
    var failing = Probe{ .fail = true };
    try t.expectError(error.ObserverFailed, j.classify(failing.observer(), now + 2));
    try t.expect((try j.pendingStep()) != null);

    var restored = Probe{ .observation = .{ .source = .present, .destination = .absent } };
    try t.expectEqual(journal.Resume.rolled_back, try j.classify(restored.observer(), now + 3));
    try t.expectEqual(journal.State.rolled_back, j.state());
    try t.expectEqual(journal.Resume.rolled_back, try j.classify(restored.observer(), now + 4));

    var g = try Fixture.init();
    defer g.deinit();
    var k = try journal.Journal.create(a, &g.store, run_id, identity, now);
    defer k.deinit();
    _ = try k.begin(.rollback, "restore", now + 1);
    var broken = Probe{ .observation = .{ .source = .absent } };
    const decision = try k.classify(broken.observer(), now + 2);
    try t.expectEqualStrings("rollback-failed-manual-recovery", decision.refuse.reason);
    try t.expectEqual(journal.State.failed, k.state());
    try t.expectEqualStrings("run-failed", (try k.classify(broken.observer(), now + 3)).refuse.reason);
}

test "migration journal: settled failures without a pending step refuse or require rollback" {
    var f = try Fixture.init();
    defer f.deinit();
    var j = try journal.Journal.create(a, &f.store, run_id, identity, t0);
    defer j.deinit();
    var probe = Probe{};
    const p1 = try j.begin(.validate_plan, "", t0 + 1);
    try j.finish(p1, .validation_failed, "plan-expired", null, t0 + 2);
    const refused = try j.classify(probe.observer(), t0 + 3);
    try t.expectEqualStrings("prior-step-failed", refused.refuse.reason);
    try t.expectEqual(Step.validate_plan, refused.refuse.step.?);

    const p2 = try j.begin(.activate_owners, "", t0 + 4);
    try j.finish(p2, .partial, "half", null, t0 + 5);
    const rollback = try j.classify(probe.observer(), t0 + 6);
    try t.expectEqualStrings("partial-effect-recorded", rollback.rollback_required.reason);
    try t.expectEqual(@as(u32, 0), probe.calls);
}

test "migration journal: storage full surfaces as a typed error and leaves no dangling intent" {
    var f = try Fixture.init();
    defer f.deinit();
    var j = try journal.Journal.create(a, &f.store, run_id, identity, t0);
    defer j.deinit();
    const pages = try f.store.inspectInteger("PRAGMA page_count;");
    var sql: [64]u8 = undefined;
    try f.store.inspectExec(try std.fmt.bufPrintZ(&sql, "PRAGMA max_page_count={d};", .{pages}));
    const intent = try a.alloc(u8, journal.max_detail_bytes);
    defer a.free(intent);
    @memset(intent, 'i');
    var now = t0;
    var full: ?anyerror = null;
    var i: usize = 0;
    while (i < 256) : (i += 1) {
        now += 2;
        const pending = j.begin(.check_drift, intent, now) catch |err| {
            full = err;
            break;
        };
        now += 1;
        j.finish(pending, .success, intent, null, now) catch |err| {
            full = err;
            break;
        };
    }
    try t.expectEqual(@as(?anyerror, error.StorageFull), full);
    try f.store.inspectExec("PRAGMA max_page_count=1073741823;");
    // Whatever failed was rolled back: either no step is pending, or the pending step is the one whose finish failed.
    if (try j.pendingStep()) |pending| {
        try j.finish(pending, .operational_failure, "storage-full", null, now + 1);
    }
    var probe = Probe{};
    const decision = try j.classify(probe.observer(), now + 2);
    try t.expect(decision == .continue_from or decision == .refuse);
}

test "migration journal: allocation failure is reported, not swallowed" {
    var f = try Fixture.init();
    defer f.deinit();
    var created = try journal.Journal.create(a, &f.store, run_id, identity, t0);
    defer created.deinit();
    var failing = t.FailingAllocator.init(a, .{ .fail_index = 0 });
    try t.expectError(error.OutOfMemory, journal.Journal.open(failing.allocator(), &f.store, run_id, identity));
    try t.expectError(error.OutOfMemory, journal.Journal.create(failing.allocator(), &f.store, [_]u8{8} ** 32, identity, t0));
    try t.expectEqual(@as(i64, 1), try f.store.inspectInteger("SELECT count(*) FROM migration_runs;"));
    const pending = try created.begin(.validate_plan, "", t0 + 1);
    try created.finish(pending, .success, "", .validated, t0 + 2);
    var report_failing = t.FailingAllocator.init(a, .{ .fail_index = 0 });
    try t.expectError(error.OutOfMemory, created.report(report_failing.allocator(), &.{}));
}

test "migration journal: report is versioned JSON with bounded steps" {
    var f = try Fixture.init();
    defer f.deinit();
    var now = t0;
    var j = try journal.Journal.create(a, &f.store, run_id, identity, now);
    defer j.deinit();
    const pending = try advanceTo(&j, .activate_owners, &now);
    var probe = Probe{ .observation = .{ .destination = .present, .source = .absent, .detail = "readback ok" } };
    now += 10;
    try t.expectEqual(journal.Resume{ .continue_from = .verify_protection }, try j.classify(probe.observer(), now));
    _ = pending;

    var report = try j.report(a, &.{"drift:/etc/fail2ban/jail.local"});
    defer report.deinit(a);
    try t.expectEqual(@as(u32, 1), report.report_version);
    try t.expectEqual(@as(usize, 6), report.steps.len);
    try t.expectEqual(Outcome.success, report.outcome);
    try t.expectEqual(journal.Protection.present, report.observed_protection.destination);
    try t.expect(!report.truncated);

    var out = std.ArrayList(u8).init(a);
    defer out.deinit();
    try report.writeJson(out.writer());
    const doc = try std.json.parseFromSlice(std.json.Value, a, out.items, .{});
    defer doc.deinit();
    const root = doc.value.object;
    try t.expectEqual(@as(i64, 1), root.get("report_version").?.integer);
    try t.expectEqualStrings("42" ** 32, root.get("run_id").?.string);
    try t.expectEqualStrings("activating", root.get("state").?.string);
    try t.expectEqualStrings("success", root.get("outcome").?.string);
    const steps = root.get("steps").?.array.items;
    try t.expectEqual(@as(usize, 6), steps.len);
    try t.expectEqualStrings("activate_owners", steps[5].object.get("step").?.string);
    try t.expectEqual(@as(i64, 6), steps[5].object.get("seq").?.integer);
    try t.expectEqualStrings("present", root.get("observed_protection").?.object.get("destination").?.string);
    try t.expectEqualStrings("absent", root.get("observed_protection").?.object.get("source").?.string);
    try t.expectEqualStrings("drift:/etc/fail2ban/jail.local", root.get("blockers").?.array.items[0].string);
    try t.expect(!root.get("steps_truncated").?.bool);
    try t.expect(out.items.len < 4096);
}

test "migration journal: more than 64 steps is refused for classification and flagged in the report" {
    var f = try Fixture.init();
    defer f.deinit();
    var now = t0;
    var j = try journal.Journal.create(a, &f.store, run_id, identity, now);
    defer j.deinit();
    var i: usize = 0;
    while (i < journal.max_steps) : (i += 1) {
        now += 2;
        const pending = try j.begin(.check_drift, "", now);
        now += 1;
        try j.finish(pending, .success, "", null, now);
    }
    var probe = Probe{};
    try t.expectError(error.TooManySteps, j.classify(probe.observer(), now + 1));
    try t.expectError(error.TooManySteps, j.pendingStep());
    var report = try j.report(a, &.{});
    defer report.deinit(a);
    try t.expect(report.truncated);
    try t.expectEqual(journal.max_steps, report.steps.len);
}

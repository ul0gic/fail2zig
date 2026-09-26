// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const t = std.testing;
const history = @import("engine_test").core.native_effect_history;
const effects = @import("engine_test").core.native_effect;
const durable = @import("engine_test").core.record_store;
const application = @import("engine_test").core.native_application_history;
const detection = @import("engine_test").core.native_detection_record;
const retry = @import("engine_test").core.native_retry;
const recurrence = @import("engine_test").core.native_recurrence;
const time_policy = @import("engine_test").core.source_time_policy;
const Fixture = struct {
    tmp: t.TmpDir,
    path: []u8,
    store: durable.Store,
    installation: effects.Installation,
    fn init() !Fixture {
        var tmp = t.tmpDir(.{});
        errdefer tmp.cleanup();
        const root = try tmp.dir.realpathAlloc(t.allocator, ".");
        defer t.allocator.free(root);
        const path = try std.fs.path.join(t.allocator, &.{ root, "history.sqlite" });
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
        try store.enableConsumerManifests();
        const installation = try effects.Installation.init([_]u8{13} ** 16, .nftables, "history-store-fixture");
        try store.admitInstallation(installation, .{ .selector = installation.selector(), .disposition = .verified_absent });
        return .{ .tmp = tmp, .path = path, .store = store, .installation = installation };
    }
    fn deinit(self: *Fixture) void {
        self.store.close();
        t.allocator.free(self.path);
        self.tmp.cleanup();
    }
    fn reopen(self: *Fixture) !void {
        self.store.close();
        self.store = try durable.Store.open(t.allocator, self.path);
        try self.store.enableReceipts(8);
    }
    fn confirm(self: *Fixture, id: u8, clock: *Clock) !effects.Entry {
        return self.confirmAs("ssh", id, clock);
    }
    fn confirmAs(self: *Fixture, jail: []const u8, id: u8, clock: *Clock) !effects.Entry {
        const entry = try self.store.setOwner(.{ .scope = try effects.Scope.host(.{ .v4 = .{ 192, 0, 2, id } }), .jail = jail, .generation = [_]u8{3} ** 32, .decision_id = [_]u8{id} ** 32, .expected_revision = 0, .lease = .permanent, .decided_us = clock.now }, clock.value());
        _ = try self.store.settleOutcome(entry.token(), clock.now, observation(entry, clock.now), clock.value());
        return entry;
    }
    fn bootstrap(self: *Fixture, owner: *history.Consumer, clock: *Clock) !void {
        const initial = try owner.prepareInitial();
        defer initial.release();
        try self.store.bootstrapConfirmedHistory(owner.manifest(), try initial.batch(clock.value()), self.installation);
        initial.publish();
    }
};
const Clock = struct {
    now: i64 = 100,
    fn read(ctx: ?*anyopaque) i64 {
        const self: *Clock = @ptrCast(@alignCast(ctx.?));
        return self.now;
    }
    fn value(self: *Clock) effects.Clock {
        return .{ .prepared_us = self.now, .context = self, .read = read };
    }
};
fn observation(entry: effects.Entry, now: i64) effects.Observation {
    return .{ .installation = entry.installation.id, .scope_key = entry.scope_key, .fingerprint = [_]u8{9} ** 32, .observed_us = now, .qualification = .complete_owned, .state = entry.desired };
}
fn effectForSubject(store: *durable.Store, subject: detection.Subject) !effects.Entry {
    var rows: [effects.max_page]effects.Entry = undefined;
    const page = try store.effectPage(null, null, &rows);
    const wanted = try effects.Scope.host(subject);
    for (rows[0..page.count]) |entry| if (std.meta.eql(entry.scope, wanted)) return entry;
    return error.MissingNativeEffect;
}
fn sql(store: *durable.Store, statement: [:0]const u8) !void {
    const run = @extern(*const fn (*anyopaque, [*:0]const u8, ?*anyopaque, ?*anyopaque, ?*?[*:0]u8) callconv(.c) c_int, .{ .name = "sqlite3_exec" });
    if (run(@ptrCast(store.db), statement, null, null, null) != 0) return error.TestSqlFailed;
}

const FilteredScan = struct {
    matches: usize,
    pages: usize,
    resume_after: u64,
    more: bool,
};

fn scanFilteredHistory(store: *durable.Store, installation: effects.Installation, jail: []const u8, after_sequence: u64, limit: usize, max_pages: usize) !FilteredScan {
    var rows: [history.max_page]history.Event = undefined;
    var after = after_sequence;
    var pages: usize = 0;
    var matches: usize = 0;
    while (matches < limit and pages < max_pages) : (pages += 1) {
        const page = try store.confirmedEffectPage(installation, after, null, &rows);
        if (page.count == 0) return .{ .matches = matches, .pages = pages + 1, .resume_after = after, .more = false };
        for (rows[0..page.count]) |event| {
            if (matches == limit) return .{ .matches = matches, .pages = pages + 1, .resume_after = after, .more = true };
            after = event.sequence;
            if (std.mem.eql(u8, event.jail.slice(), jail)) matches += 1;
        }
        if (!page.more) return .{ .matches = matches, .pages = pages + 1, .resume_after = after, .more = false };
    }
    return .{ .matches = matches, .pages = pages, .resume_after = after, .more = true };
}

fn enableApplicationHistory(store: *durable.Store) !void {
    try store.enableConfirmedHistory();
    try store.enableMaintenance();
    try store.enableCleanup();
    try store.enableRetryLeases();
    try store.enableApplicationHistory();
}

fn nativeRecord(store: *durable.Store, clock: *Clock, jail: []const u8, occurrence: []const u8, revision: u64, address: detection.Subject, policy: retry.Policy, evidence: ?[]const u8) !durable.Record {
    const generation = [_]u8{3} ** 32;
    const identity = durable.ReceiptIdentity{ .jail = jail, .source = "file", .occurrence = occurrence, .cursor = occurrence, .raw_hash = [_]u8{4} ** 32, .generation = generation };
    const receipt = try store.beginReceipt(identity, .{ .us = clock.now }, revision);
    const outcome = try time_policy.evaluate(.timestamped, .{ .parsed = receipt }, receipt, receipt, 1_000);
    return .{ .jail = jail, .source = identity.source, .occurrence = occurrence, .cursor = occurrence, .raw_hash = identity.raw_hash, .receipt = .{ .time = receipt, .generation = generation }, .native_time_outcome = outcome, .native_detection = .{ .kind = .candidate, .generation = generation, .filter = try detection.Name.init("fixture"), .pattern = try detection.Name.init("failure"), .pattern_index = 0, .subject = address }, .native_retry = .{ .generation = generation, .policy = policy, .processing_us = clock.now }, .retry_evidence = .{ .text = evidence }, .effects_clock = clock.value(), .expected_revision = revision, .disposition = outcome.disposition(), .checkpoint = "application-history" };
}

fn applicationAllocationRead(allocator: std.mem.Allocator, fixture: *Fixture) !void {
    var rows: [2]application.Event = undefined;
    const page = try fixture.store.applicationHistoryPage(allocator, fixture.installation, .{}, &rows);
    defer for (rows[0..page.count]) |*row| row.deinit(allocator);
    try t.expectEqual(@as(usize, 2), page.count);
}

test "native effect history store: migration backfill rollback deterministic append and reopen" {
    var f = try Fixture.init();
    defer f.deinit();
    var clock = Clock{};
    _ = try f.confirm(11, &clock);
    _ = try f.confirm(12, &clock);
    f.store.fail_at = .before_consumer_input_commit;
    try t.expectError(error.InjectedFailure, f.store.enableConfirmedHistory());
    try t.expectEqual(@as(u32, 12), f.store.schema_version);
    f.store.fail_at = null;
    try f.store.enableConfirmedHistory();
    var events: [64]history.Event = undefined;
    const first = try f.store.confirmedEffectPage(f.installation, 0, null, &events);
    try t.expectEqual(@as(usize, 2), first.count);
    try t.expect(std.mem.order(u8, &events[0].event_id, &events[1].event_id) == .lt);
    const saved = events[0..2].*;
    try f.reopen();
    try f.store.enableConfirmedHistory();
    _ = try f.store.confirmedEffectPage(f.installation, 0, first.token.stream_revision, &events);
    try t.expectEqualDeep(saved, events[0..2].*);
    _ = try f.confirm(1, &clock);
    const next = try f.store.confirmedEffectPage(f.installation, 2, null, &events);
    try t.expectEqual(@as(usize, 1), next.count);
    try t.expectEqual(@as(u64, 3), events[0].sequence);
    try t.expectError(error.StaleHistoryPage, f.store.validateConfirmedEffectPage(first.token));
}

test "native effect history store: large filtered scans stop at the page budget and resume in SQLite" {
    var f = try Fixture.init();
    defer f.deinit();
    var clock = Clock{};
    try f.store.enableConfirmedHistory();
    const entry = try f.store.setOwner(.{
        .scope = try effects.Scope.host(.{ .v4 = .{ 192, 0, 2, 1 } }),
        .jail = "seed",
        .generation = [_]u8{3} ** 32,
        .decision_id = [_]u8{4} ** 32,
        .expected_revision = 0,
        .lease = .permanent,
        .decided_us = 100,
    }, clock.value());
    var statement = std.ArrayList(u8).init(t.allocator);
    defer statement.deinit();
    try statement.appendSlice("INSERT INTO confirmed_effect_events(event_id,scope_key,jail,decision_id,confirmed_us) VALUES");
    const scope_hex = std.fmt.bytesToHex(entry.scope_key, .lower);
    var n: u64 = 1;
    while (n <= 1025) : (n += 1) {
        const jail = if (n == 1025) "needle" else "decoy";
        const decision_id = effects.hashParts("fail2zig-prf003-decision-v1", &.{std.mem.asBytes(&n)});
        const event_id = effects.hashParts("fail2zig-native-confirmed-owner-v1", &.{ &f.installation.id, &entry.scope_key, jail, &decision_id });
        const event_hex = std.fmt.bytesToHex(event_id, .lower);
        const decision_hex = std.fmt.bytesToHex(decision_id, .lower);
        try statement.writer().print("{s}(X'{s}',X'{s}','{s}',X'{s}',{d})", .{ if (n == 1) "" else ",", event_hex, scope_hex, jail, decision_hex, n });
    }
    try statement.appendSlice(";\x00");
    try sql(&f.store, statement.items[0 .. statement.items.len - 1 :0]);

    const first = try scanFilteredHistory(&f.store, f.installation, "needle", 0, 1, 16);
    try t.expectEqual(@as(usize, 0), first.matches);
    try t.expectEqual(@as(usize, 16), first.pages);
    try t.expectEqual(@as(u64, 1024), first.resume_after);
    try t.expect(first.more);

    const second = try scanFilteredHistory(&f.store, f.installation, "needle", first.resume_after, 1, 16);
    try t.expectEqual(@as(usize, 1), second.matches);
    try t.expectEqual(@as(usize, 1), second.pages);
    try t.expectEqual(@as(u64, 1025), second.resume_after);
    try t.expect(!second.more);
}

test "native effect history store: application detail pages aggregates and policy summaries are bounded and fenced" {
    var f = try Fixture.init();
    defer f.deinit();
    var clock = Clock{};
    _ = try f.confirm(11, &clock);
    try f.store.enableConfirmedHistory();
    try f.store.enableMaintenance();
    try f.store.enableCleanup();
    try f.store.enableRetryLeases();
    f.store.fail_at = .before_application_history_schema_commit;
    try t.expectError(error.InjectedFailure, f.store.enableApplicationHistory());
    try t.expectEqual(@as(i64, 16), f.store.schema_version);
    f.store.fail_at = null;
    try f.store.enableApplicationHistory();
    try t.expectEqual(@as(i64, 17), f.store.schema_version);

    var rows: [1]application.Event = undefined;
    const migrated = try f.store.applicationHistoryPage(t.allocator, f.installation, .{}, &rows);
    try t.expectEqual(@as(usize, 1), migrated.count);
    try t.expect(rows[0].detail == null);
    rows[0].deinit(t.allocator);

    const permanent = retry.Policy{ .maxretry = 1, .window_us = 1_000, .duration = .permanent, .max_subjects = 8, .enforce = true };
    try f.store.admitRetry("native", [_]u8{3} ** 32, permanent);
    const native_subject = detection.Subject{ .v4 = .{ 192, 0, 2, 21 } };
    try t.expectEqual(durable.CommitResult.committed, try f.store.commitRecord(try nativeRecord(&f.store, &clock, "native", "native-one", 0, native_subject, permanent, "bounded failure example")));
    var effects_rows: [4]effects.Entry = undefined;
    const effects_page = try f.store.effectPage(null, null, &effects_rows);
    var native_effect: ?effects.Entry = null;
    const native_scope = try effects.Scope.host(native_subject);
    for (effects_rows[0..effects_page.count]) |entry| {
        if (std.meta.eql(entry.scope, native_scope)) native_effect = entry;
    }
    const pending = native_effect orelse return error.MissingNativeEffect;
    try t.expectEqual(effects.Settlement.verified, try f.store.settleOutcome(pending.token(), clock.now, observation(pending, clock.now), clock.value()));

    const first = try f.store.applicationHistoryPage(t.allocator, f.installation, .{}, &rows);
    try t.expect(first.more);
    try t.expect(rows[0].detail == null);
    rows[0].deinit(t.allocator);
    const second = try f.store.applicationHistoryPage(t.allocator, f.installation, .{ .after_sequence = first.last_sequence, .expected_stream_revision = first.stream_revision }, &rows);
    try t.expectEqual(@as(usize, 1), second.count);
    try t.expect(!second.more);
    try t.expectEqualStrings("native", rows[0].confirmed.jail.slice());
    try t.expectEqualStrings("file", rows[0].detail.?.source);
    try t.expectEqualStrings("native-one", rows[0].detail.?.occurrence);
    try t.expectEqualStrings("bounded failure example", rows[0].detail.?.evidence.?);
    try t.expectEqual(@as(u64, 1), rows[0].detail.?.ordinal);
    rows[0].deinit(t.allocator);
    try t.checkAllAllocationFailures(t.allocator, applicationAllocationRead, .{&f});

    try sql(&f.store, "DELETE FROM retry_decision_details;");
    const retained = try f.store.applicationHistoryPage(t.allocator, f.installation, .{ .after_sequence = first.last_sequence, .expected_stream_revision = first.stream_revision }, &rows);
    try t.expectEqual(@as(usize, 1), retained.count);
    try t.expect(rows[0].detail != null);
    rows[0].deinit(t.allocator);

    var aggregates: [65]application.Aggregate = undefined;
    const aggregate = try f.store.applicationHistoryAggregates(f.installation, .{ .range = .{ .from_us = 100, .to_us = 101 } }, &aggregates);
    try t.expectEqual(@as(usize, 3), aggregate.count);
    try t.expectEqual(@as(u64, 2), aggregates[0].confirmed);
    try t.expectEqual(@as(?i64, 100), aggregates[0].first_confirmed_us);
    try t.expectEqual(@as(?i64, 100), aggregates[0].latest_confirmed_us);
    const empty_aggregate = try f.store.applicationHistoryAggregates(f.installation, .{ .range = .{ .from_us = 99, .to_us = 100 } }, &aggregates);
    try t.expectEqual(@as(u64, 0), aggregates[0].confirmed);
    try t.expectEqual(@as(usize, 1), empty_aggregate.count);
    try t.expectError(error.InvalidApplicationHistoryQuery, f.store.applicationHistoryPage(t.allocator, f.installation, .{ .range = .{ .from_us = 100, .to_us = 100 } }, &rows));
    try t.expectError(error.InvalidApplicationHistoryQuery, f.store.applicationHistoryPage(t.allocator, f.installation, .{}, &.{}));

    const log_only = retry.Policy{ .maxretry = 1, .window_us = 1_000, .duration = .{ .finite_us = 500 }, .max_subjects = 8 };
    try f.store.admitRetry("zeta", [_]u8{3} ** 32, log_only);
    _ = try f.store.commitRecord(try nativeRecord(&f.store, &clock, "zeta", "zeta-one", 0, .{ .v4 = .{ 192, 0, 2, 22 } }, log_only, null));
    var summaries: [1]application.PolicySummary = undefined;
    const policy_first = try f.store.retryPolicySummaryPage(.{}, &summaries);
    try t.expectEqual(@as(usize, 1), policy_first.count);
    try t.expect(policy_first.more);
    const cursor = application.PolicyCursor{ .jail = summaries[0].jail, .subject = summaries[0].subject };
    const policy_second = try f.store.retryPolicySummaryPage(.{ .after = cursor, .expected_revision = policy_first.revision }, &summaries);
    try t.expectEqual(@as(usize, 1), policy_second.count);
    try t.expect(!policy_second.more);

    _ = try f.confirmAs("other", 12, &clock);
    try t.expectError(error.StaleHistoryPage, f.store.applicationHistoryPage(t.allocator, f.installation, .{ .after_sequence = first.last_sequence, .expected_stream_revision = first.stream_revision }, &rows));
    try t.expectError(error.StaleHistoryPage, f.store.applicationHistoryAggregates(f.installation, .{ .expected_stream_revision = aggregate.stream_revision }, &aggregates));
    try f.store.admitRetry("omega", [_]u8{3} ** 32, log_only);
    _ = try f.store.commitRecord(try nativeRecord(&f.store, &clock, "omega", "omega-one", 0, .{ .v4 = .{ 192, 0, 2, 23 } }, log_only, null));
    try t.expectError(error.StalePolicySummary, f.store.retryPolicySummaryPage(.{ .after = cursor, .expected_revision = policy_first.revision }, &summaries));

    try f.reopen();
    const restored = try f.store.applicationHistoryPage(t.allocator, f.installation, .{ .jail = "native" }, &rows);
    try t.expectEqual(@as(usize, 1), restored.count);
    try t.expectEqualStrings("bounded failure example", rows[0].detail.?.evidence.?);
    rows[0].deinit(t.allocator);
}

test "native effect history store: schema 18 escalation uses confirmed history and one durable jitter sample" {
    var f = try Fixture.init();
    defer f.deinit();
    var clock = Clock{};
    try enableApplicationHistory(&f.store);

    const base = retry.Policy{ .maxretry = 1, .window_us = 60_000_000, .duration = .{ .finite_us = 10_000_000 }, .max_subjects = 8, .enforce = true };
    var escalated = base;
    escalated.escalation = .{ .enabled = true, .formula = .linear, .scope = .per_jail, .multiplier = 1, .factor = 1, .max_duration_us = 60_000_000, .jitter_us = 5_000_000 };
    try t.expectError(error.RetryStorageRequired, f.store.admitRetry("escalated", [_]u8{3} ** 32, escalated));
    try f.store.admitRetry("legacy", [_]u8{3} ** 32, base);
    f.store.fail_at = .before_escalation_schema_commit;
    try t.expectError(error.InjectedFailure, f.store.enableEscalation());
    try t.expectEqual(@as(i64, 17), f.store.schema_version);
    f.store.fail_at = null;
    try f.store.enableEscalation();
    try t.expectEqual(@as(i64, 18), f.store.schema_version);
    try f.store.validateRetry("legacy", [_]u8{3} ** 32, base);
    try f.store.admitRetry("escalated", [_]u8{3} ** 32, escalated);

    const Jitter = struct {
        calls: u32 = 0,
        fn sample(context: ?*anyopaque, maximum_seconds: u64) u64 {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.calls += 1;
            return maximum_seconds;
        }
    };
    var jitter = Jitter{};
    f.store.escalation_jitter_context = &jitter;
    f.store.escalation_jitter = Jitter.sample;
    const subject = detection.Subject{ .v4 = .{ 192, 0, 2, 51 } };

    _ = try f.store.commitRecord(try nativeRecord(&f.store, &clock, "escalated", "one", 0, subject, escalated, null));
    const first_decision = (try f.store.retryDecision("escalated", "file", "one")).?;
    try t.expectEqualDeep(retry.Lease{ .finite = clock.now + 10_000_000 }, first_decision.lease);
    try t.expectEqual(@as(u32, 0), jitter.calls);
    const first_effect = try effectForSubject(&f.store, subject);
    _ = try f.store.settleOutcome(first_effect.token(), clock.now, observation(first_effect, clock.now), clock.value());
    _ = try f.store.settleOutcome(first_effect.token(), clock.now, observation(first_effect, clock.now), clock.value());

    clock.now += 10_000_000;
    _ = try f.store.commitRecord(try nativeRecord(&f.store, &clock, "escalated", "two", 1, subject, escalated, null));
    const second_decision = (try f.store.retryDecision("escalated", "file", "two")).?;
    try t.expectEqualDeep(retry.Lease{ .finite = clock.now + 25_000_000 }, second_decision.lease);
    const selection = (try f.store.retryEscalationDecision("escalated", "file", "two", subject)).?;
    try t.expectEqual(retry.EscalationScope.per_jail, selection.scope);
    try t.expectEqual(@as(u64, 1), selection.prior_confirmed);
    try t.expectEqual(@as(?i64, 100), selection.latest_confirmed_us);
    try t.expectEqual(@as(i64, 25_000_000), selection.chosen_duration_us);
    try t.expectEqual(@as(i64, 5_000_000), selection.jitter_us);
    try t.expectEqual(@as(u32, 1), jitter.calls);

    var overall = escalated;
    overall.escalation.scope = .overall;
    try f.store.admitRetry("overall", [_]u8{3} ** 32, overall);
    _ = try f.store.commitRecord(try nativeRecord(&f.store, &clock, "overall", "overall-one", 0, subject, overall, null));
    try t.expectEqualDeep(retry.Lease{ .finite = clock.now + 25_000_000 }, (try f.store.retryDecision("overall", "file", "overall-one")).?.lease);
    try t.expectEqual(@as(u32, 2), jitter.calls);
    var changed = escalated;
    changed.escalation.scope = .overall;
    try t.expectError(error.RetryGenerationMismatch, f.store.validateRetry("escalated", [_]u8{3} ** 32, changed));

    try f.reopen();
    try f.store.validateRetry("escalated", [_]u8{3} ** 32, escalated);
    try t.expectEqualDeep(second_decision, (try f.store.retryDecision("escalated", "file", "two")).?);
    try t.expectEqualDeep(selection, (try f.store.retryEscalationDecision("escalated", "file", "two", subject)).?);
}

test "native effect history store: recidive consumes only replay-safe foreign native confirmations" {
    var f = try Fixture.init();
    defer f.deinit();
    var clock = Clock{};
    try enableApplicationHistory(&f.store);
    try f.store.enableEscalation();
    var owner = try history.Consumer.init(f.installation, [_]u8{6} ** 32);
    const initial = try owner.prepareInitial();
    try f.store.bootstrapConfirmedHistory(owner.manifest(), try initial.batch(clock.value()), f.installation);
    initial.publish();
    initial.release();

    const source_policy = retry.Policy{ .maxretry = 1, .window_us = 60_000_000, .duration = .permanent, .max_subjects = 8, .enforce = true };
    const recidive_policy = retry.Policy{ .maxretry = 2, .window_us = 60_000_000, .duration = .{ .finite_us = 60_000_000 }, .max_subjects = 8 };
    const recidive_generation = [_]u8{5} ** 32;
    try f.store.admitRetry("source-a", [_]u8{3} ** 32, source_policy);
    try f.store.admitRetry("source-b", [_]u8{3} ** 32, source_policy);
    try f.store.admitRetry("recidive", recidive_generation, recidive_policy);
    const subject = detection.Subject{ .v4 = .{ 198, 51, 100, 77 } };
    const binding = recurrence.Binding{ .jail = "recidive", .generation = recidive_generation, .policy = recidive_policy };

    _ = try f.store.commitRecord(try nativeRecord(&f.store, &clock, "source-a", "a-one", 0, subject, source_policy, null));
    var pending = try effectForSubject(&f.store, subject);
    _ = try f.store.settleOutcome(pending.token(), clock.now, observation(pending, clock.now), clock.value());
    var events: [history.max_page]history.Event = undefined;
    const first_page = try f.store.confirmedEffectPage(f.installation, 0, null, &events);
    try t.expectEqual(@as(usize, 1), first_page.count);
    try t.expect(events[0].native_retry);
    var first_stage = try owner.prepare(first_page, events[0..first_page.count], clock.now);
    try t.expect(try recurrence.consume(&f.store, binding, events[0], clock.now, clock.value()));
    try t.expectEqual(@as(u16, 1), (try f.store.retryState("recidive", subject)).?.count);
    f.store.fail_at = .before_consumer_input_commit;
    try t.expectError(error.InjectedFailure, f.store.commitConfirmedHistory(owner.manifest(), try first_stage.batch(clock.value()), first_page.token));
    first_stage.release();

    try f.reopen();
    const replay_page = try f.store.confirmedEffectPage(f.installation, 0, null, &events);
    try t.expect(try recurrence.consume(&f.store, binding, events[0], clock.now, clock.value()));
    try t.expectEqual(@as(u16, 1), (try f.store.retryState("recidive", subject)).?.count);
    const replay_stage = try owner.prepare(replay_page, events[0..replay_page.count], clock.now);
    try f.store.commitConfirmedHistory(owner.manifest(), try replay_stage.batch(clock.value()), replay_page.token);
    replay_stage.publish();
    replay_stage.release();

    _ = try f.store.commitRecord(try nativeRecord(&f.store, &clock, "source-b", "b-one", 0, subject, source_policy, null));
    pending = try effectForSubject(&f.store, subject);
    _ = try f.store.settleOutcome(pending.token(), clock.now, observation(pending, clock.now), clock.value());
    const second_page = try f.store.confirmedEffectPage(f.installation, 1, null, &events);
    try t.expectEqual(@as(usize, 1), second_page.count);
    try t.expect(events[0].native_retry);
    try t.expect(try recurrence.consume(&f.store, binding, events[0], clock.now, clock.value()));
    const occurrence = std.fmt.bytesToHex(events[0].event_id, .lower);
    try t.expect((try f.store.retryDecision("recidive", recurrence.source_id, &occurrence)) != null);

    var self_event = events[0];
    self_event.jail = try detection.Name.init("recidive");
    self_event.decision_id = [_]u8{99} ** 32;
    self_event.event_id = effects.hashParts("fail2zig-native-confirmed-owner-v1", &.{ &self_event.installation.id, &self_event.scope_key, self_event.jail.slice(), &self_event.decision_id });
    try t.expect(!try recurrence.consume(&f.store, binding, self_event, clock.now, clock.value()));

    _ = try f.confirmAs("manual", 77, &clock);
    const manual_page = try f.store.confirmedEffectPage(f.installation, 2, null, &events);
    try t.expectEqual(@as(usize, 1), manual_page.count);
    try t.expect(!events[0].native_retry);
    try t.expect(!try recurrence.consume(&f.store, binding, events[0], clock.now, clock.value()));
    try t.expectEqual(@as(u64, 1), (try f.store.retryState("recidive", subject)).?.decisions);
}

test "native effect history store: typed reset fences recurrence and escalation without changing protection" {
    var f = try Fixture.init();
    defer f.deinit();
    var clock = Clock{};
    try enableApplicationHistory(&f.store);
    try f.store.enableEscalation();
    try f.store.enableCanonicalEffects();
    f.store.fail_at = .before_history_reset_schema_commit;
    try t.expectError(error.InjectedFailure, f.store.enableHistoryResets());
    try t.expectEqual(@as(i64, 19), f.store.schema_version);
    f.store.fail_at = null;
    try f.store.enableHistoryResets();
    try t.expectEqual(@as(i64, 20), f.store.schema_version);

    const source_policy = retry.Policy{ .maxretry = 1, .window_us = 60_000_000, .duration = .permanent, .max_subjects = 8, .enforce = true };
    const recidive_policy = retry.Policy{ .maxretry = 3, .window_us = 60_000_000, .duration = .permanent, .max_subjects = 8 };
    const recidive_generation = [_]u8{5} ** 32;
    const subject = detection.Subject{ .v4 = .{ 198, 51, 100, 88 } };
    try f.store.admitRetry("source-a", [_]u8{3} ** 32, source_policy);
    try f.store.admitRetry("source-b", [_]u8{3} ** 32, source_policy);
    try f.store.admitRetry("recidive", recidive_generation, recidive_policy);
    const binding = recurrence.Binding{ .jail = "recidive", .generation = recidive_generation, .policy = recidive_policy };

    for ([_][]const u8{ "source-a", "source-b" }, [_][]const u8{ "a", "b" }) |jail, occurrence| {
        _ = try f.store.commitRecord(try nativeRecord(&f.store, &clock, jail, occurrence, 0, subject, source_policy, null));
        const pending = try effectForSubject(&f.store, subject);
        _ = try f.store.settleOutcome(pending.token(), clock.now, observation(pending, clock.now), clock.value());
    }
    var events: [history.max_page]history.Event = undefined;
    const initial = try f.store.confirmedEffectPage(f.installation, 0, null, &events);
    try t.expectEqual(@as(usize, 2), initial.count);
    try t.expect(try f.store.historyEventEligible(events[0]));

    const jail_reset = durable.HistoryResetIntent{ .scope = .{ .jail = "source-a" }, .subject = subject, .expected_revision = 0, .intent_id = [_]u8{0xa1} ** 32 };
    f.store.fail_at = .after_history_reset;
    try t.expectError(error.InjectedFailure, f.store.resetHistory(jail_reset, clock.value()));
    f.store.fail_at = null;
    try t.expect(try f.store.historyEventEligible(events[0]));
    const reset = try f.store.resetHistory(jail_reset, clock.value());
    try t.expectEqual(@as(u64, 1), reset.revision);
    try t.expectEqual(@as(u64, 2), reset.through_sequence);
    try t.expectEqualDeep(reset, try f.store.resetHistory(jail_reset, clock.value()));
    try t.expect(!try f.store.historyEventEligible(events[0]));
    try t.expect(try f.store.historyEventEligible(events[1]));
    try t.expect(!try recurrence.consume(&f.store, binding, events[0], clock.now, clock.value()));
    try t.expect(try recurrence.consume(&f.store, binding, events[1], clock.now, clock.value()));

    try f.reopen();
    try t.expect(!try f.store.historyEventEligible(events[0]));
    try t.expectError(error.StaleHistoryReset, f.store.resetHistory(.{ .scope = .{ .jail = "source-a" }, .subject = subject, .expected_revision = 0, .intent_id = [_]u8{0xa2} ** 32 }, clock.value()));
    const overall = try f.store.resetHistory(.{ .scope = .overall, .subject = subject, .expected_revision = 0, .intent_id = [_]u8{0xb1} ** 32 }, clock.value());
    try t.expectEqual(@as(u64, 2), overall.through_sequence);
    try t.expect(!try f.store.historyEventEligible(events[1]));

    var escalated = source_policy;
    escalated.duration = .{ .finite_us = 10_000_000 };
    escalated.escalation = .{ .enabled = true, .formula = .linear, .scope = .overall, .multiplier = 1, .factor = 1, .max_duration_us = 60_000_000 };
    try f.store.admitRetry("after-reset", [_]u8{3} ** 32, escalated);
    _ = try f.store.commitRecord(try nativeRecord(&f.store, &clock, "after-reset", "first", 0, subject, escalated, null));
    try t.expectEqual(@as(u64, 0), (try f.store.retryEscalationDecision("after-reset", "file", "first", subject)).?.prior_confirmed);

    const pending = try effectForSubject(&f.store, subject);
    _ = try f.store.settleOutcome(pending.token(), clock.now, observation(pending, clock.now), clock.value());
    const fresh = try f.store.confirmedEffectPage(f.installation, 2, null, &events);
    try t.expectEqual(@as(usize, 1), fresh.count);
    try t.expect(try f.store.historyEventEligible(events[0]));
    try t.expect(try recurrence.consume(&f.store, binding, events[0], clock.now, clock.value()));
    var effect_rows: [1]effects.Entry = undefined;
    try t.expectEqual(@as(usize, 1), (try f.store.effectPage(null, null, &effect_rows)).count);
    try t.expect(effect_rows[0].desired == .permanent);
}

test "native effect history store: retention is consumed-prefix bounded rollback-safe and owner-pinned" {
    var f = try Fixture.init();
    defer f.deinit();
    var clock = Clock{};
    try upgradeToLoadRepair(&f, &clock, 0);
    var owner = try history.Consumer.init(f.installation, [_]u8{8} ** 32);
    const initial = try owner.prepareInitial();
    try f.store.bootstrapConfirmedHistory(owner.manifest(), try initial.batch(clock.value()), f.installation);
    initial.publish();
    initial.release();

    const finite = retry.Policy{ .maxretry = 1, .window_us = 60_000_000, .duration = .{ .finite_us = 10_000_000 }, .max_subjects = 8, .enforce = true };
    const subject = detection.Subject{ .v4 = .{ 203, 0, 113, 91 } };
    try f.store.admitRetry("finite-history", [_]u8{3} ** 32, finite);
    _ = try f.store.commitRecord(try nativeRecord(&f.store, &clock, "finite-history", "one", 0, subject, finite, "retained detail"));
    const pending = try effectForSubject(&f.store, subject);
    _ = try f.store.settleOutcome(pending.token(), clock.now, observation(pending, clock.now), clock.value());
    // The runtime settles the decision's outcomes after confirmation; only unsettled
    // outcomes pin the stream prefix from schema 24 on.
    const decision = (try f.store.currentOwner(pending.scope_key, "finite-history")).?.decision_id;
    for ([_]@import("engine_test").core.native_action_outcome.Kind{ .enforcement, .notification }) |kind| {
        try f.store.markActionTargetDispatched(decision, kind, clock.value());
        try f.store.settleActionTarget(decision, kind, .confirmed, clock.value());
    }
    var events: [history.max_page]history.Event = undefined;
    const page = try f.store.confirmedEffectPage(f.installation, 0, null, &events);
    const stage = try owner.prepare(page, events[0..page.count], clock.now);
    try f.store.commitConfirmedHistory(owner.manifest(), try stage.batch(clock.value()), page.token);
    stage.publish();
    stage.release();

    f.store.fail_at = .after_history_detail_delete;
    try t.expectError(error.InjectedFailure, f.store.cleanupConfirmedHistoryOne(.{ .age_us = std.math.maxInt(i64) - @mod(std.math.maxInt(i64), 1_000_000), .max_matches = 0 }, clock.now));
    var application_rows: [1]application.Event = undefined;
    const before = try f.store.applicationHistoryPage(t.allocator, f.installation, .{}, &application_rows);
    try t.expectEqual(@as(usize, 1), before.count);
    try t.expect(application_rows[0].detail != null);
    application_rows[0].deinit(t.allocator);
    f.store.fail_at = null;
    try t.expect(try f.store.cleanupConfirmedHistoryOne(.{ .age_us = std.math.maxInt(i64) - @mod(std.math.maxInt(i64), 1_000_000), .max_matches = 0 }, clock.now));
    const stripped = try f.store.applicationHistoryPage(t.allocator, f.installation, .{}, &application_rows);
    try t.expectEqual(@as(usize, 1), stripped.count);
    try t.expect(application_rows[0].detail == null);
    application_rows[0].deinit(t.allocator);

    // Schema 24 removes the live-owner pin: the still-live owner no longer holds the
    // consumed prefix, which now waits only for its retention age.
    try t.expect(!try f.store.cleanupConfirmedHistoryOne(.{ .age_us = 1_000_000, .max_matches = 0 }, clock.now));
    clock.now += 10_000_000;
    f.store.fail_at = .after_history_event_delete;
    try t.expectError(error.InjectedFailure, f.store.cleanupConfirmedHistoryOne(.{ .age_us = 0, .max_matches = 0 }, clock.now));
    try t.expectEqual(@as(usize, 1), (try f.store.confirmedEffectPage(f.installation, 0, null, &events)).count);
    f.store.fail_at = null;
    try t.expect(try f.store.cleanupConfirmedHistoryOne(.{ .age_us = 0, .max_matches = 0 }, clock.now));
    try t.expectError(error.HistoryGap, f.store.confirmedEffectPage(f.installation, 0, null, &events));
    try f.reopen();
    try t.expectError(error.HistoryGap, f.store.confirmedEffectPage(f.installation, 0, null, &events));
}

test "native effect history store: only first qualified receipt appends and repair replay is stable" {
    var f = try Fixture.init();
    defer f.deinit();
    var clock = Clock{};
    try f.store.enableConfirmedHistory();
    const entry = try f.confirm(1, &clock);
    var events: [64]history.Event = undefined;
    const first = try f.store.confirmedEffectPage(f.installation, 0, null, &events);
    _ = try f.store.settleOutcome(entry.token(), 100, observation(entry, 100), clock.value());
    const repeated = try f.store.confirmedEffectPage(f.installation, 0, first.token.stream_revision, &events);
    try t.expectEqualDeep(first, repeated);
    const pending = try f.store.setOwner(.{ .scope = try effects.Scope.host(.{ .v4 = .{ 192, 0, 2, 2 } }), .jail = "ssh", .generation = [_]u8{3} ** 32, .decision_id = [_]u8{2} ** 32, .expected_revision = 0, .lease = .permanent, .decided_us = 100 }, clock.value());
    var uncertain = observation(pending, 100);
    uncertain.qualification = .incomplete;
    try t.expectError(error.IncompleteEffectObservation, f.store.settleOutcome(pending.token(), 100, uncertain, clock.value()));
    try f.store.validateConfirmedEffectPage(first.token);
    f.store.fail_at = .before_effect_receipt_commit;
    try t.expectError(error.InjectedFailure, f.store.settleOutcome(pending.token(), 100, observation(pending, 100), clock.value()));
    f.store.fail_at = null;
    try f.store.validateConfirmedEffectPage(first.token);
    try f.reopen();
    _ = try f.store.settleOutcome(pending.token(), 100, observation(pending, 100), clock.value());
    try t.expectEqual(@as(u64, 2), (try f.store.confirmedEffectPage(f.installation, 0, null, &events)).token.head_sequence);
}

test "native effect history store: canonical bootstrap atomic consume rollback and restored replay" {
    var f = try Fixture.init();
    defer f.deinit();
    var clock = Clock{};
    try f.store.enableConfirmedHistory();
    _ = try f.confirm(1, &clock);
    var owner = try history.Consumer.init(f.installation, [_]u8{1} ** 32);
    for ([_]durable.CommitStage{ .after_consumer_delta, .after_manifest_ready, .before_consumer_input_commit }) |point| {
        f.store.fail_at = point;
        try t.expectError(error.InjectedFailure, f.bootstrap(&owner, &clock));
        try t.expect(!owner.ready);
        try t.expectError(error.ConsumerManifestMissing, f.store.consumerManifestSnapshot(t.allocator, owner.manifest()));
    }
    f.store.fail_at = null;
    try f.bootstrap(&owner, &clock);
    var events: [64]history.Event = undefined;
    const input = try f.store.confirmedEffectPage(f.installation, 0, null, &events);
    for ([_]durable.CommitStage{ .after_consumer_delta, .before_consumer_input_commit }) |point| {
        const stage = try owner.prepare(input, events[0..input.count], 100);
        defer stage.release();
        f.store.fail_at = point;
        try t.expectError(error.InjectedFailure, f.store.commitConfirmedHistory(owner.manifest(), try stage.batch(clock.value()), input.token));
        try t.expectEqual(@as(u64, 0), owner.live.last_sequence);
        var saved = try f.store.consumerManifestSnapshot(t.allocator, owner.manifest());
        defer saved.deinit(t.allocator);
        try t.expectEqual(@as(u64, 0), (try history.Checkpoint.decode(saved.states[0].payload.?)).last_sequence);
    }
    f.store.fail_at = null;
    const committed = try owner.prepare(input, events[0..input.count], 100);
    try f.store.commitConfirmedHistory(owner.manifest(), try committed.batch(clock.value()), input.token);
    committed.release();
    try f.reopen();
    var snapshot = try f.store.consumerManifestSnapshot(t.allocator, owner.manifest());
    defer snapshot.deinit(t.allocator);
    var restored = try history.Consumer.init(f.installation, [_]u8{1} ** 32);
    const restore = try restored.prepareRestore(snapshot.states[0].revision, snapshot.states[0].payload.?);
    try f.store.validateConsumerManifestSnapshot(restored.manifest(), &snapshot);
    restore.publish();
    restore.release();
    try t.expectEqual(@as(u64, 1), restored.live.total_confirmed);
    try t.expectError(error.StaleHistoryPage, restored.prepare(input, events[0..input.count], 100));
    try t.expectEqual(@as(u64, 0), try f.store.revision("ssh"));
}

test "native effect history store: generic writes and forged unread summaries refused" {
    var f = try Fixture.init();
    defer f.deinit();
    var clock = Clock{};
    try f.store.enableConfirmedHistory();
    var owner = try history.Consumer.init(f.installation, [_]u8{1} ** 32);
    const initial = try owner.prepareInitial();
    const batch = try initial.batch(clock.value());
    try t.expectError(error.InvalidHistoryTransition, f.store.bootstrapConsumerManifest(owner.manifest(), batch));
    initial.release();
    try f.bootstrap(&owner, &clock);
    _ = try f.confirm(1, &clock);
    var events: [64]history.Event = undefined;
    const input = try f.store.confirmedEffectPage(f.installation, 0, null, &events);
    const stage = try owner.prepare(input, events[0..input.count], 100);
    defer stage.release();
    try t.expectError(error.InvalidHistoryTransition, f.store.commitConsumerInput(owner.manifest(), try stage.batch(clock.value())));
    var altered = (try stage.batch(clock.value())).deltas[0];
    var checkpoint = try history.Checkpoint.decode(altered.payload);
    checkpoint.confirmed_watermark_us = 999;
    const bytes = try checkpoint.encode();
    altered.payload = &bytes;
    var forged = try stage.batch(clock.value());
    forged.deltas = &.{altered};
    try t.expectError(error.InvalidHistoryTransition, f.store.commitConfirmedHistory(owner.manifest(), forged, input.token));
    var record = durable.Record{ .jail = "@history", .source = "confirmed-effects", .occurrence = "forged", .cursor = "1", .raw_hash = [_]u8{1} ** 32, .disposition = "counted", .checkpoint = "cursor", .consumers = try stage.batch(clock.value()), .consumer_manifest = owner.manifest() };
    try t.expectError(error.InvalidHistoryTransition, f.store.commitRecord(record));
    record.consumer_manifest = null;
    try t.expectError(error.ConsumerManifestRequired, f.store.commitRecord(record));
}

test "native effect history store: missing sequence and retained floor never skip unread events" {
    var f = try Fixture.init();
    defer f.deinit();
    var clock = Clock{};
    try f.store.enableConfirmedHistory();
    _ = try f.confirm(1, &clock);
    _ = try f.confirm(2, &clock);
    var events: [64]history.Event = undefined;
    const input = try f.store.confirmedEffectPage(f.installation, 0, null, &events);
    try sql(&f.store, "DELETE FROM confirmed_history_sequence WHERE sequence=1;");
    try t.expectError(error.HistoryGap, f.store.confirmedEffectPage(f.installation, 0, null, &events));
    try t.expectError(error.HistoryGap, f.store.validateConfirmedEffectPage(input.token));
    try sql(&f.store, "UPDATE confirmed_history_stream SET retained_from=2,revision=revision+1;");
    try t.expectError(error.HistoryGap, f.store.confirmedEffectPage(f.installation, 0, null, &events));
    var owner = try history.Consumer.init(f.installation, [_]u8{1} ** 32);
    try t.expectError(error.HistoryGap, f.bootstrap(&owner, &clock));
    try t.expectEqual(@as(usize, 1), (try f.store.confirmedEffectPage(f.installation, 1, null, &events)).count);
}

test "native effect history store: final structural ownership needs canonical history and exact revision" {
    var f = try Fixture.init();
    defer f.deinit();
    var clock = Clock{};
    try f.store.enableConfirmedHistory();
    var owner = try history.Consumer.init(f.installation, [_]u8{1} ** 32);
    try f.bootstrap(&owner, &clock);
    try f.store.validateRuntimeOwnerNames(&.{"ssh"});
    var snapshot = try f.store.consumerManifestSnapshot(t.allocator, owner.manifest());
    defer snapshot.deinit(t.allocator);
    try f.store.validateConsumerOwnership(&.{"ssh"}, 1, snapshot.revision, true);
    try t.expectError(error.UnconfiguredStateOwner, f.store.validateConsumerOwnership(&.{"ssh"}, 1, snapshot.revision, false));
    try t.expectError(error.StaleConsumerCheckpoint, f.store.validateConsumerOwnership(&.{"ssh"}, 1, snapshot.revision + 1, true));
    try t.expectError(error.ConsumerManifestMismatch, f.store.validateConsumerOwnership(&.{"ssh"}, 0, snapshot.revision, true));
    try sql(&f.store, "DELETE FROM consumer_checkpoints WHERE kind=5;");
    try t.expectError(error.MissingRequiredConsumer, f.store.consumerManifestSnapshot(t.allocator, owner.manifest()));
    var fresh = try history.Consumer.init(f.installation, [_]u8{1} ** 32);
    try t.expectError(error.ConsumerManifestExists, f.bootstrap(&fresh, &clock));
}

test "native effect history store: actual killed migration and consumer commits reopen before or after" {
    for ([_]bool{ false, true }) |migration| for ([_]bool{ false, true }) |after| {
        var f = try Fixture.init();
        defer f.deinit();
        var clock = Clock{};
        _ = try f.confirm(1, &clock);
        var owner = try history.Consumer.init(f.installation, [_]u8{1} ** 32);
        var events: [64]history.Event = undefined;
        var input: history.Page = undefined;
        if (!migration) {
            try f.store.enableConfirmedHistory();
            try f.bootstrap(&owner, &clock);
            input = try f.store.confirmedEffectPage(f.installation, 0, null, &events);
        }
        f.store.close();
        const pid = try std.posix.fork();
        if (pid == 0) {
            var child = durable.Store.open(std.heap.page_allocator, f.path) catch std.process.exit(2);
            child.enableReceipts(8) catch std.process.exit(3);
            const Kill = struct {
                const Db = std.meta.Child(@FieldType(durable.Store, "db"));
                const Exec = @FieldType(@FieldType(durable.Store, "api"), "exec");
                var actual: Exec = undefined;
                var after_commit: bool = false;
                fn exec(db: *Db, statement: [*:0]const u8, callback: ?*anyopaque, ctx: ?*anyopaque, message: ?*?[*:0]u8) callconv(.c) c_int {
                    if (!std.mem.eql(u8, std.mem.span(statement), "COMMIT;")) return actual(db, statement, callback, ctx, message);
                    if (after_commit and actual(db, statement, callback, ctx, message) != 0) std.process.exit(4);
                    std.posix.kill(std.os.linux.getpid(), std.posix.SIG.KILL) catch std.process.exit(5);
                    std.process.exit(6);
                }
            };
            Kill.actual = child.api.exec;
            Kill.after_commit = after;
            child.api.exec = Kill.exec;
            if (migration) child.enableConfirmedHistory() catch std.process.exit(7) else {
                const stage = owner.prepare(input, events[0..input.count], 100) catch std.process.exit(8);
                child.commitConfirmedHistory(owner.manifest(), stage.batch(clock.value()) catch std.process.exit(9), input.token) catch std.process.exit(10);
            }
            std.process.exit(11);
        }
        const ended = std.posix.waitpid(pid, 0);
        f.store = try durable.Store.open(t.allocator, f.path);
        try f.store.enableReceipts(8);
        try t.expect(std.posix.W.IFSIGNALED(ended.status));
        try t.expectEqual(@as(u32, std.posix.SIG.KILL), std.posix.W.TERMSIG(ended.status));
        if (migration) {
            try t.expectEqual(@as(i64, if (after) 13 else 12), f.store.schema_version);
            try f.store.enableConfirmedHistory();
            try t.expectEqual(@as(u64, 1), (try f.store.confirmedEffectPage(f.installation, 0, null, &events)).token.head_sequence);
        } else {
            var saved = try f.store.consumerManifestSnapshot(t.allocator, owner.manifest());
            defer saved.deinit(t.allocator);
            const checkpoint = try history.Checkpoint.decode(saved.states[0].payload.?);
            try t.expectEqual(@as(u64, @intFromBool(after)), checkpoint.total_confirmed);
        }
    };
}

test "native effect history store: removed append trigger refuses receipt without losing confirmed stream" {
    var f = try Fixture.init();
    defer f.deinit();
    var clock = Clock{};
    try f.store.enableConfirmedHistory();
    _ = try f.confirm(1, &clock);
    try sql(&f.store, "DROP TRIGGER confirmed_history_append;");
    try t.expectError(error.HistoryGap, f.confirm(2, &clock));
    try t.expectEqual(@as(u64, 1), try f.store.confirmedEffectEvents());
    var events: [64]history.Event = undefined;
    try t.expectEqual(@as(u64, 1), (try f.store.confirmedEffectPage(f.installation, 0, null, &events)).token.head_sequence);
}

test "native effect history store: bounded page source revision CAS and fresh clock all fence consumption" {
    var f = try Fixture.init();
    defer f.deinit();
    var clock = Clock{};
    try f.store.enableConfirmedHistory();
    var owner = try history.Consumer.init(f.installation, [_]u8{1} ** 32);
    try f.bootstrap(&owner, &clock);
    _ = try f.confirm(1, &clock);
    var events: [1]history.Event = undefined;
    const first = try f.store.confirmedEffectPage(f.installation, 0, null, &events);
    var stage = try owner.prepare(first, &events, 100);
    _ = try f.confirm(2, &clock);
    try t.expectError(error.StaleHistoryPage, f.store.commitConfirmedHistory(owner.manifest(), try stage.batch(clock.value()), first.token));
    stage.release();
    const current = try f.store.confirmedEffectPage(f.installation, 0, null, &events);
    try t.expect(current.more);
    stage = try owner.prepare(current, &events, 100);
    const batch = try stage.batch(clock.value());
    clock.now = 99;
    try t.expectError(error.ConsumerClockReversed, f.store.commitConfirmedHistory(owner.manifest(), batch, current.token));
    clock.now = 100;
    try f.store.commitConfirmedHistory(owner.manifest(), batch, current.token);
    try t.expectError(error.StaleConsumerCheckpoint, f.store.commitConfirmedHistory(owner.manifest(), batch, current.token));
    stage.publish();
    stage.release();
    const last = try f.store.confirmedEffectPage(f.installation, 1, current.token.stream_revision, &events);
    try t.expect(!last.more);
    try t.expectEqual(@as(u64, 2), events[0].sequence);
    const next = try owner.prepare(last, &events, 100);
    defer next.release();
    try f.store.commitConfirmedHistory(owner.manifest(), try next.batch(clock.value()), last.token);
    next.publish();
    try t.expectEqual(@as(u64, 2), owner.live.total_confirmed);
    try t.expectError(error.InvalidHistoryPage, f.store.confirmedEffectPage(f.installation, 2, null, &.{}));
}

// ---- Schema 24: retention order, deduplication and history capacity ----

extern fn sqlite3_open_v2(path: [*:0]const u8, db: *?*anyopaque, flags: c_int, vfs: ?[*:0]const u8) c_int;
extern fn sqlite3_close_v2(db: *anyopaque) c_int;
extern fn sqlite3_backup_init(dest: *anyopaque, dest_name: [*:0]const u8, source: *anyopaque, source_name: [*:0]const u8) ?*anyopaque;
extern fn sqlite3_backup_step(backup: *anyopaque, pages: c_int) c_int;
extern fn sqlite3_backup_finish(backup: *anyopaque) c_int;
extern fn sqlite3_prepare_v2(db: *anyopaque, sql: [*:0]const u8, bytes: c_int, statement: *?*anyopaque, tail: ?*anyopaque) c_int;
extern fn sqlite3_step(statement: *anyopaque) c_int;
extern fn sqlite3_finalize(statement: *anyopaque) c_int;
extern fn sqlite3_bind_int64(statement: *anyopaque, index: c_int, value: i64) c_int;
extern fn sqlite3_bind_blob(statement: *anyopaque, index: c_int, value: ?*const anyopaque, bytes: c_int, destructor: ?*anyopaque) c_int;
extern fn sqlite3_column_int64(statement: *anyopaque, column: c_int) i64;
extern fn sqlite3_column_blob(statement: *anyopaque, column: c_int) ?*const anyopaque;
extern fn sqlite3_changes(db: *anyopaque) c_int;

fn upgradeToLoadRepair(f: *Fixture, clock: *Clock, max_matches: u16) !void {
    try enableApplicationHistory(&f.store);
    try f.store.enableEscalation();
    try f.store.enableCanonicalEffects();
    try f.store.enableHistoryResets();
    try f.store.enableActionTargets();
    try f.store.enableAdminState();
    try f.store.enableMigrationState();
    try f.store.enableLoadRepair(.{ .state_path = f.path, .now_us = clock.now, .history_max_matches = max_matches }, null);
    try t.expectEqual(durable.latest_schema, f.store.schema_version);
}

fn scalar(store: *durable.Store, statement: [:0]const u8) !i64 {
    return store.inspectInteger(statement);
}

// Copied verbatim from the schema-23 cleanupConfirmedHistoryOne detail branch
// (tests/harness/load_repro/oracle.c keeps the same text): the one-row shipped predicate.
const shipped_detail_sql = "SELECT d.event_id FROM confirmed_event_details d JOIN confirmed_effect_events e USING(event_id) JOIN confirmed_history_sequence s USING(event_id) LEFT JOIN retry_decision_details r ON r.jail=e.jail AND r.effect_decision_id=e.decision_id WHERE s.sequence<=?1 AND (e.confirmed_us<=?2 OR (r.effect_decision_id IS NOT NULL AND ((SELECT count(*) FROM confirmed_event_details d2 JOIN confirmed_effect_events e2 USING(event_id) JOIN retry_decision_details r2 ON r2.jail=e2.jail AND r2.effect_decision_id=e2.decision_id WHERE r2.family=r.family AND r2.subject=r.subject)>?3 OR (d.evidence IS NOT NULL AND (SELECT coalesce(sum(length(CAST(d3.evidence AS BLOB))),0) FROM confirmed_event_details d3 JOIN confirmed_effect_events e3 USING(event_id) JOIN retry_decision_details r3 ON r3.jail=e3.jail AND r3.effect_decision_id=e3.decision_id WHERE r3.family=r.family AND r3.subject=r.subject)>16384)))) ORDER BY s.sequence LIMIT 1;";

const OracleStatement = struct {
    handle: *anyopaque,
    fn init(db: *anyopaque, text: [:0]const u8) !OracleStatement {
        var handle: ?*anyopaque = null;
        if (sqlite3_prepare_v2(db, text, -1, &handle, null) != 0) return error.TestSqlFailed;
        return .{ .handle = handle orelse return error.TestSqlFailed };
    }
    fn deinit(self: OracleStatement) void {
        _ = sqlite3_finalize(self.handle);
    }
};

// Repeats the shipped one-row decision on an in-memory copy and returns the complete
// deletion vector for one retention transaction.
fn shippedVector(store: *durable.Store, fence: i64, cutoff: i64, max_matches: u16, output: []i64) !usize {
    var opened: ?*anyopaque = null;
    if (sqlite3_open_v2(":memory:", &opened, 0x06, null) != 0) return error.TestSqlFailed;
    const copy = opened orelse return error.TestSqlFailed;
    defer _ = sqlite3_close_v2(copy);
    const backup = sqlite3_backup_init(copy, "main", @ptrCast(store.db), "main") orelse return error.TestSqlFailed;
    const copied = sqlite3_backup_step(backup, -1);
    if (sqlite3_backup_finish(backup) != 0 or copied != 101) return error.TestSqlFailed;
    var count: usize = 0;
    while (count < output.len) : (count += 1) {
        var event_id: [32]u8 = undefined;
        {
            const choose = try OracleStatement.init(copy, shipped_detail_sql);
            defer choose.deinit();
            _ = sqlite3_bind_int64(choose.handle, 1, fence);
            _ = sqlite3_bind_int64(choose.handle, 2, cutoff);
            _ = sqlite3_bind_int64(choose.handle, 3, max_matches);
            const rc = sqlite3_step(choose.handle);
            if (rc == 101) break;
            if (rc != 100) return error.TestSqlFailed;
            const bytes: [*]const u8 = @ptrCast(sqlite3_column_blob(choose.handle, 0) orelse return error.TestSqlFailed);
            @memcpy(&event_id, bytes[0..32]);
        }
        {
            const sequence = try OracleStatement.init(copy, "SELECT sequence FROM confirmed_history_sequence WHERE event_id=?1;");
            defer sequence.deinit();
            _ = sqlite3_bind_blob(sequence.handle, 1, &event_id, 32, null);
            if (sqlite3_step(sequence.handle) != 100) return error.TestSqlFailed;
            output[count] = sqlite3_column_int64(sequence.handle, 0);
        }
        const remove = try OracleStatement.init(copy, "DELETE FROM confirmed_event_details WHERE event_id=?1;");
        defer remove.deinit();
        _ = sqlite3_bind_blob(remove.handle, 1, &event_id, 32, null);
        if (sqlite3_step(remove.handle) != 101 or sqlite3_changes(copy) != 1) return error.TestSqlFailed;
    }
    return count;
}

const DetailSet = struct {
    present: [256]bool = [_]bool{false} ** 256,
    fn read(store: *durable.Store) !DetailSet {
        var result = DetailSet{};
        var row = try store.statement("SELECT sequence FROM confirmed_event_details;");
        defer row.deinit();
        while (try row.row()) result.present[@intCast(try row.signed(0))] = true;
        return result;
    }
    fn removed(before: DetailSet, after: DetailSet, output: []i64) !usize {
        var count: usize = 0;
        for (before.present, after.present, 0..) |was, is, sequence| {
            if (is and !was) return error.DetailAppeared;
            if (was and !is) {
                output[count] = @intCast(sequence);
                count += 1;
            }
        }
        return count;
    }
};

// Independent recomputation of every maintained summary and candidate from the details.
fn expectSummariesExact(store: *durable.Store) !void {
    try t.expectEqual(@as(i64, 0), try scalar(store, "SELECT count(*) FROM (SELECT family,subject,count(*) c,coalesce(sum(evidence_bytes),0) b,min(sequence) m,min(CASE WHEN evidence_bytes IS NOT NULL THEN sequence END) me FROM confirmed_event_details WHERE family IS NOT NULL GROUP BY family,subject) x FULL OUTER JOIN retained_subject_summaries s ON s.family=x.family AND s.subject=x.subject WHERE s.detail_count IS NOT x.c OR s.evidence_bytes IS NOT x.b OR s.earliest_sequence IS NOT x.m OR s.earliest_evidence_sequence IS NOT x.me;"));
    try t.expectEqual(@as(i64, 0), try scalar(store, "SELECT count(*) FROM retained_subject_summaries s JOIN retention_policy p ON p.id=1 WHERE p.state=2 AND (s.evaluated_generation<>p.generation OR s.candidate_sequence IS NOT (CASE WHEN s.detail_count>p.max_matches THEN s.earliest_sequence WHEN s.evidence_bytes>16384 THEN s.earliest_evidence_sequence END));"));
}

const retention_policy = retry.Policy{ .maxretry = 1, .window_us = 60_000_000, .duration = .{ .finite_us = 3_600_000_000 }, .max_subjects = 64, .enforce = true };

// A schema-24 state whose details come from the production record, dispatch and
// confirmation path. Repeated details of one subject use distinct jails, so each has its
// own live owner and confirmation.
const RetainedHistory = struct {
    f: Fixture,
    clock: Clock = .{},
    owner: history.Consumer,
    names: [24][4]u8 = undefined,
    revisions: [24]u64 = [_]u64{0} ** 24,
    admitted: [24]bool = [_]bool{false} ** 24,
    details_per_subject: [8]u8 = [_]u8{0} ** 8,
    confirmed_at: [256]i64 = [_]i64{0} ** 256,
    head: usize = 0,
    consumed: u64 = 0,
    occurrence: u32 = 0,

    fn init(self: *RetainedHistory, max_matches: u16) !void {
        self.* = .{ .f = try Fixture.init(), .owner = undefined };
        errdefer self.f.deinit();
        try upgradeToLoadRepair(&self.f, &self.clock, max_matches);
        self.owner = try history.Consumer.init(self.f.installation, [_]u8{8} ** 32);
        try self.f.bootstrap(&self.owner, &self.clock);
    }
    fn deinit(self: *RetainedHistory) void {
        self.f.deinit();
    }
    fn subject(index: u8) detection.Subject {
        return .{ .v4 = .{ 198, 51, 100, index + 1 } };
    }
    fn jail(self: *RetainedHistory, index: usize) ![]const u8 {
        const name = try std.fmt.bufPrint(&self.names[index], "r{d}", .{index});
        if (!self.admitted[index]) {
            try self.f.store.admitRetry(name, [_]u8{3} ** 32, retention_policy);
            self.admitted[index] = true;
        }
        return name;
    }
    fn arrive(self: *RetainedHistory, arrival: Arrival) !void {
        const index = self.details_per_subject[arrival.subject];
        self.details_per_subject[arrival.subject] += 1;
        const name = try self.jail(index);
        var occurrence_buffer: [16]u8 = undefined;
        const occurrence = try std.fmt.bufPrint(&occurrence_buffer, "o{d}", .{self.occurrence});
        self.occurrence += 1;
        var evidence_buffer: [2048]u8 = undefined;
        const evidence: ?[]const u8 = if (arrival.evidence) |length| blk: {
            @memset(evidence_buffer[0..length], 'e');
            break :blk evidence_buffer[0..length];
        } else null;
        _ = try self.f.store.commitRecord(try nativeRecord(&self.f.store, &self.clock, name, occurrence, self.revisions[index], subject(arrival.subject), retention_policy, evidence));
        self.revisions[index] += 1;
        const entry = try effectForSubject(&self.f.store, subject(arrival.subject));
        _ = try self.f.store.settleOutcome(entry.token(), self.clock.now, observation(entry, self.clock.now), self.clock.value());
        self.head += 1;
        self.confirmed_at[self.head] = self.clock.now;
        self.clock.now += 1_000_000;
    }
    fn consumeTo(self: *RetainedHistory, target: u64) !void {
        var events: [history.max_page]history.Event = undefined;
        while (self.consumed < target) {
            const wanted: usize = @intCast(@min(history.max_page, target - self.consumed));
            const page = try self.f.store.confirmedEffectPage(self.f.installation, self.consumed, null, events[0..wanted]);
            const stage = try self.owner.prepare(page, events[0..page.count], self.clock.now);
            defer stage.release();
            try self.f.store.commitConfirmedHistory(self.owner.manifest(), try stage.batch(self.clock.value()), page.token);
            stage.publish();
            self.consumed = page.token.last_sequence;
        }
    }
};

const Arrival = struct { subject: u8, evidence: ?u16 = null };
const RetentionCheck = struct {
    arrivals: []const Arrival = &.{},
    // Applied in order; every value but the last is superseded after one sweep page.
    policies: []const u16,
    // Confirmations up to this sequence are age-eligible; null makes none eligible by age.
    cutoff: ?usize = null,
    // Consumer checkpoint; null consumes to the head.
    fence: ?usize = null,
};
const RetentionCase = struct { name: []const u8, initial_max: u16, arrivals: []const Arrival, checks: []const RetentionCheck };

fn repeatArrival(comptime count: usize, arrival: Arrival) [count]Arrival {
    return [_]Arrival{arrival} ** count;
}

const retention_cases = [_]RetentionCase{
    .{ .name = "OR-1 age, count and byte candidates compete", .initial_max = 10, .arrivals = &([_]Arrival{.{ .subject = 2 }} ++ repeatArrival(6, .{ .subject = 0 }) ++ repeatArrival(9, .{ .subject = 1, .evidence = 2048 }) ++ repeatArrival(6, .{ .subject = 0 })), .checks = &.{.{ .policies = &.{10}, .cutoff = 1 }} },
    .{ .name = "OR-2 consumer lag keeps the eligible detail after the fence", .initial_max = 1, .arrivals = &.{ .{ .subject = 1 }, .{ .subject = 0 }, .{ .subject = 0 } }, .checks = &.{.{ .policies = &.{1}, .fence = 1 }} },
    .{ .name = "OR-3 partial rebuild lowering 10 to 1 deletes sequence 1 first", .initial_max = 10, .arrivals = &.{ .{ .subject = 1 }, .{ .subject = 0 }, .{ .subject = 1 }, .{ .subject = 0 } }, .checks = &.{.{ .policies = &.{1} }} },
    .{ .name = "OR-4 raising 1 to 10 drops the stale candidate", .initial_max = 1, .arrivals = &.{ .{ .subject = 0 }, .{ .subject = 0 }, .{ .subject = 1 } }, .checks = &.{.{ .policies = &.{10} }} },
    .{ .name = "OR-5 lower, raise and lower again with superseded builds", .initial_max = 10, .arrivals = &.{ .{ .subject = 0 }, .{ .subject = 1 }, .{ .subject = 0 }, .{ .subject = 1 }, .{ .subject = 0 } }, .checks = &.{ .{ .policies = &.{ 1, 10, 1 } }, .{ .arrivals = &.{ .{ .subject = 1 }, .{ .subject = 1 } }, .policies = &.{ 10, 2 } } } },
    .{ .name = "OR-6 only non-NULL evidence is a byte candidate", .initial_max = 20, .arrivals = &(repeatArrival(2, .{ .subject = 0 }) ++ repeatArrival(8, .{ .subject = 0, .evidence = 2048 })), .checks = &.{ .{ .policies = &.{20} }, .{ .arrivals = &.{.{ .subject = 0, .evidence = 1 }}, .policies = &.{20} } } },
    .{ .name = "OR-7 limit 0 makes every subject detail a candidate", .initial_max = 10, .arrivals = &.{ .{ .subject = 0 }, .{ .subject = 1 }, .{ .subject = 0 } }, .checks = &.{.{ .policies = &.{0} }} },
    .{ .name = "OR-7 limit 10 deletes only the eleventh", .initial_max = 10, .arrivals = &(repeatArrival(11, .{ .subject = 0 }) ++ [_]Arrival{.{ .subject = 1 }}), .checks = &.{.{ .policies = &.{10} }} },
    .{ .name = "OR-7 limit 1024 deletes nothing", .initial_max = 10, .arrivals = &repeatArrival(11, .{ .subject = 0 }), .checks = &.{.{ .policies = &.{1024} }} },
    .{ .name = "OR-8 an advancing cutoff chooses the earlier newly eligible sequence", .initial_max = 1, .arrivals = &.{ .{ .subject = 0 }, .{ .subject = 1 }, .{ .subject = 1 }, .{ .subject = 2 } }, .checks = &.{ .{ .policies = &.{1} }, .{ .policies = &.{1}, .cutoff = 1 }, .{ .policies = &.{1}, .cutoff = 4 } } },
    .{ .name = "OR-9 a live insert competes from the next transaction", .initial_max = 1, .arrivals = &.{ .{ .subject = 0 }, .{ .subject = 0 } }, .checks = &.{ .{ .policies = &.{1} }, .{ .arrivals = &.{.{ .subject = 0 }}, .policies = &.{1} } } },
};

fn retentionPublished(store: *durable.Store) !bool {
    return try scalar(store, "SELECT state FROM retention_policy WHERE id=1;") == 2;
}

test "native effect history store: schema 24 retention deletes exactly the shipped predicate's ascending vector" {
    // Guards the replacement selector: any order, fence, policy-generation or summary drift
    // from the shipped one-row predicate is a deletion the old daemon would not have made.
    var deleted_total: usize = 0;
    for (retention_cases) |case| {
        errdefer std.debug.print("retention case: {s}\n", .{case.name});
        var world: RetainedHistory = undefined;
        try world.init(case.initial_max);
        defer world.deinit();
        world.f.store.test_hooks.retention_sweep_rows = 1;
        for (case.arrivals) |arrival| try world.arrive(arrival);
        for (case.checks) |check| {
            for (check.arrivals) |arrival| try world.arrive(arrival);
            try world.consumeTo(check.fence orelse world.head);
            const cutoff = if (check.cutoff) |sequence| world.confirmed_at[sequence] else 0;
            const final = check.policies[check.policies.len - 1];
            const before = try DetailSet.read(&world.f.store);
            var removed: [256]i64 = undefined;
            // A partial or superseded candidate generation never deletes.
            for (check.policies[0 .. check.policies.len - 1]) |superseded| {
                _ = try world.f.store.setRetentionPolicy(superseded);
                const outcome = try world.f.store.historyRetentionStep(.{ .age_us = 0, .max_matches = superseded }, cutoff);
                try t.expect(outcome == .rebuilt or outcome == .published);
                try t.expectEqual(@as(usize, 0), try DetailSet.removed(before, try DetailSet.read(&world.f.store), &removed));
            }
            _ = try world.f.store.setRetentionPolicy(final);
            while (!try retentionPublished(&world.f.store)) {
                const outcome = try world.f.store.historyRetentionStep(.{ .age_us = 0, .max_matches = final }, cutoff);
                try t.expect(outcome == .rebuilt or outcome == .published);
                try t.expectEqual(@as(usize, 0), try DetailSet.removed(before, try DetailSet.read(&world.f.store), &removed));
            }
            try expectSummariesExact(&world.f.store);
            var expected: [256]i64 = undefined;
            const expected_count = try shippedVector(&world.f.store, @intCast(world.consumed), cutoff, final, &expected);
            for (expected[0..expected_count], 0..) |sequence, i| if (i > 0) try t.expect(expected[i - 1] < sequence);
            const outcome = try world.f.store.historyRetentionStep(.{ .age_us = 0, .max_matches = final }, cutoff);
            try t.expectEqual(@as(@TypeOf(outcome), if (expected_count == 0) .idle else .details), outcome);
            const removed_count = try DetailSet.removed(before, try DetailSet.read(&world.f.store), &removed);
            try t.expectEqualSlices(i64, expected[0..expected_count], removed[0..removed_count]);
            try expectSummariesExact(&world.f.store);
            deleted_total += removed_count;
        }
    }
    try t.expect(deleted_total >= 12);
}

const outcome_kinds = [_]@import("engine_test").core.native_action_outcome.Kind{ .enforcement, .notification };

// The runtime settles a confirmed decision's outcomes; tests do it directly.
fn settleOutcomes(store: *durable.Store, decision: effects.Hash, clock: *Clock) !void {
    for (outcome_kinds) |kind| {
        try store.markActionTargetDispatched(decision, kind, clock.value());
        try store.settleActionTarget(decision, kind, .confirmed, clock.value());
    }
}

fn ownerOf(store: *durable.Store, subject: detection.Subject, jail: []const u8) !effects.Owner {
    const entry = try effectForSubject(store, subject);
    return (try store.currentOwner(entry.scope_key, jail)) orelse error.MissingOwner;
}

fn dispatchAndSettle(store: *durable.Store, subject: detection.Subject, clock: *Clock) !void {
    const entry = try effectForSubject(store, subject);
    _ = try store.settleOutcome(entry.token(), clock.now, observation(entry, clock.now), clock.value());
}

fn stateDigest(store: *durable.Store) ![32]u8 {
    var row = try store.statement("SELECT coalesce((SELECT group_concat(sequence||':'||hex(event_id),',') FROM (SELECT * FROM confirmed_event_details ORDER BY sequence)),'')||'|'||coalesce((SELECT group_concat(family||':'||hex(subject)||':'||detail_count||':'||evidence_bytes||':'||earliest_sequence||':'||coalesce(earliest_evidence_sequence,'-')||':'||coalesce(candidate_sequence,'-')||':'||evaluated_generation,',') FROM (SELECT * FROM retained_subject_summaries ORDER BY family,subject)),'')||'|'||(SELECT retained_from||':'||head||':'||revision FROM confirmed_history_stream)||'|'||(SELECT count(*) FROM confirmed_effect_events)||'|'||(SELECT generation||':'||max_matches||':'||state||':'||sweep_cursor FROM retention_policy);");
    defer row.deinit();
    if (!try row.row()) return error.TestSqlFailed;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(try row.bytes(0), &digest, .{});
    return digest;
}

fn countOf(store: *durable.Store, comptime table: []const u8) !i64 {
    return scalar(store, "SELECT count(*) FROM " ++ table ++ ";");
}

// A consumer checkpoint at `sequence`, written directly: retention reads only its fence.
fn setFence(world: *RetainedHistory, sequence: u64) !void {
    const checkpoint = history.Checkpoint{ .generation = world.owner.manifest().source_generation, .installation = world.f.installation.id, .last_sequence = sequence, .total_confirmed = sequence, .confirmed_watermark_us = world.clock.now, .rolling_digest = [_]u8{1} ** 32 };
    var row = try world.f.store.statement("UPDATE consumer_checkpoints SET payload=?1 WHERE kind=5 AND jail='@history' AND source='confirmed-effects' AND rule='checkpoint';");
    defer row.deinit();
    try row.blob(1, &try checkpoint.encode());
    try row.done();
}

// Consumed-history filler with its own provenance; the append trigger sequences it.
fn fillEvents(store: *durable.Store, count: i64, confirmed_us: i64) !void {
    var row = try store.statement("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<?1) INSERT INTO confirmed_effect_events(event_id,scope_key,jail,decision_id,confirmed_us,canonical_scope) SELECT randomblob(32),randomblob(32),'filler',randomblob(32),?2,(SELECT canonical_scope FROM native_effects LIMIT 1) FROM n;");
    defer row.deinit();
    try row.int(1, count);
    try row.int(2, confirmed_us);
    try row.done();
}

test "native effect history store: reconfirmation after the stream prune never counts or appends twice" {
    // Failure: with the event as the only deduplication key, pruning it lets the next
    // readback of a still-live decision append again and increment its policy count; a
    // reinstated decision whose event is retained must gain only its marker.
    var world: RetainedHistory = undefined;
    try world.init(10);
    defer world.deinit();
    const store = &world.f.store;
    const subject = RetainedHistory.subject(0);
    try world.arrive(.{ .subject = 0, .evidence = 16 });
    try settleOutcomes(store, (try ownerOf(store, subject, "r0")).decision_id, &world.clock);
    try world.consumeTo(world.head);
    try t.expectEqual(.details, try store.historyRetentionStep(.{ .age_us = 0, .max_matches = 10 }, world.clock.now));
    try t.expectEqual(.prefix, try store.historyRetentionStep(.{ .age_us = 0, .max_matches = 10 }, world.clock.now));
    try t.expectEqual(@as(i64, 0), try countOf(store, "confirmed_effect_events"));
    try t.expect((try ownerOf(store, subject, "r0")).lease.live(world.clock.now));

    world.clock.now += 1_000_000;
    const applied = try effectForSubject(store, subject);
    _ = try store.settleOutcome(applied.token(), world.clock.now, observation(applied, world.clock.now), world.clock.value());
    try t.expectEqual(@as(i64, 1), try scalar(store, "SELECT head FROM confirmed_history_stream;"));
    try t.expectEqual(@as(i64, 0), try countOf(store, "confirmed_effect_events"));
    try t.expectEqual(@as(i64, 1), try scalar(store, "SELECT confirmed_count FROM confirmed_policy_summaries WHERE jail='r0';"));

    // A -> B -> A on one owner while A's event is still retained.
    const scope = try effects.Scope.host(.{ .v4 = .{ 198, 51, 100, 200 } });
    const decisions = [_]effects.Hash{ [_]u8{0xa} ** 32, [_]u8{0xb} ** 32, [_]u8{0xa} ** 32 };
    const heads = [_]i64{ 2, 3, 3 };
    for (decisions, heads) |decision, head| {
        world.clock.now += 1_000_000;
        const current = try store.currentOwner(try scope.key(world.f.installation), "swap");
        const entry = try store.setOwner(.{ .scope = scope, .jail = "swap", .generation = [_]u8{3} ** 32, .decision_id = decision, .expected_revision = if (current) |owner| owner.revision else 0, .lease = .permanent, .decided_us = world.clock.now }, world.clock.value());
        _ = try store.settleOutcome(entry.token(), world.clock.now, observation(entry, world.clock.now), world.clock.value());
        try t.expectEqual(head, try scalar(store, "SELECT head FROM confirmed_history_stream;"));
    }
    try t.expectEqual(@as(i64, 1), try scalar(store, "SELECT count(*) FROM confirmed_effect_events WHERE jail='swap' AND decision_id=x'0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a';"));
    try t.expectEqual(@as(i64, 1), try scalar(store, "SELECT count(*) FROM confirmation_markers WHERE jail='swap' AND decision_id=x'0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a';"));
}

test "native effect history store: a full reserve refuses admission as backpressure until expiry and reclamation free it" {
    // Failure: at the boundary an admission used to take the rows its owners' expiry needs,
    // or fail with a capacity error that latched intervention. The refusal must keep the
    // receipt, expiry must still complete, and admission must resume unaided.
    var world: RetainedHistory = undefined;
    try world.init(10);
    defer world.deinit();
    const store = &world.f.store;
    const short = retry.Policy{ .maxretry = 1, .window_us = 60_000_000, .duration = .{ .finite_us = 10_000_000 }, .max_subjects = 8, .enforce = true };
    try store.admitRetry("short", [_]u8{3} ** 32, short);
    _ = try store.commitRecord(try nativeRecord(store, &world.clock, "short", "first", 0, RetainedHistory.subject(0), short, null));
    try dispatchAndSettle(store, RetainedHistory.subject(0), &world.clock);
    const held = try ownerOf(store, RetainedHistory.subject(0), "short");
    try settleOutcomes(store, held.decision_id, &world.clock);
    // Obsolete revisions of another decision leave room for the live owner's expiry only.
    const fill = effects.max_owner_revisions - 2 - try countOf(store, "effect_owner_revisions");
    {
        var row = try store.statement("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<?1) INSERT INTO effect_owner_revisions SELECT o.scope_key,o.jail,o.generation,randomblob(32),o.revision+1000000+x,o.lease_kind,o.deadline_us,o.decided_us FROM effect_owners o,n;");
        defer row.deinit();
        try row.int(1, fill);
        try row.done();
    }
    world.clock.now += 1_000_000;
    const name = try world.jail(0);
    const record = try nativeRecord(store, &world.clock, name, "refused", 0, RetainedHistory.subject(1), retention_policy, null);
    const receipt = durable.ReceiptIdentity{ .jail = name, .source = "file", .occurrence = "refused", .cursor = "refused", .raw_hash = [_]u8{4} ** 32, .generation = [_]u8{3} ** 32 };
    try t.expectError(error.ReserveBackpressure, store.commitRecord(record));
    try t.expect(try store.pendingReceipt(receipt) != null);
    try t.expect(!store.reopen_required);

    world.clock.now = held.lease.finite + 1;
    const expiring = try effectForSubject(store, RetainedHistory.subject(0));
    _ = try store.prepareExpiry(expiring.scope_key, expiring.revision, world.clock.value());
    try t.expectEqual(effects.Lease.absent, (try ownerOf(store, RetainedHistory.subject(0), "short")).lease);
    try t.expectError(error.ReserveBackpressure, store.commitRecord(record));
    while (try store.reclaimObsoleteOne() != .idle) {}
    try t.expectEqual(durable.CommitResult.committed, try store.commitRecord(record));
    try t.expect(try store.pendingReceipt(receipt) == null);
    try t.expectEqual(@as(i64, 2), try countOf(store, "effect_owner_revisions"));
}

test "native effect history store: history at the overload threshold prunes consumed events first and admitted work still settles" {
    // Failure: a full event table failed confirmation and blocked enforcement proof. Only
    // consumed history may give way; an admitted owner's confirmation must always fit.
    var world: RetainedHistory = undefined;
    try world.init(10);
    defer world.deinit();
    const store = &world.f.store;
    const young = world.clock.now;
    const retention = durable.Store.HistoryRetention{ .age_us = 86_400_000_000, .max_matches = 10 };
    const held_scope = try effects.Scope.host(RetainedHistory.subject(7));
    const held = try store.setOwner(.{ .scope = held_scope, .jail = "held", .generation = [_]u8{3} ** 32, .decision_id = [_]u8{7} ** 32, .expected_revision = 0, .lease = .permanent, .decided_us = young }, world.clock.value());
    try fillEvents(store, durable.Store.history_overload_events, young);
    try setFence(&world, 40_000);
    try t.expectEqual(.prefix, try store.historyRetentionStep(retention, young));
    try t.expectEqual(durable.Store.history_overload_events - 1, try countOf(store, "confirmed_effect_events"));
    try t.expectEqual(@as(i64, 2), try scalar(store, "SELECT retained_from FROM confirmed_history_stream;"));
    _ = try store.settleOutcome(held.token(), world.clock.now, observation(held, young), world.clock.value());
    try t.expectEqual(.prefix, try store.historyRetentionStep(retention, young));
    try t.expectEqual(.idle, try store.historyRetentionStep(retention, young));
    try t.expectEqual(@as(i64, 3), try scalar(store, "SELECT retained_from FROM confirmed_history_stream;"));

    // A lagging consumer: nothing unconsumed is pruned, admission keeps each admitted
    // owner's confirmation in reserve, and that owner still confirms at the cap.
    const lagging_scope = try effects.Scope.host(RetainedHistory.subject(6));
    const lagging = try store.setOwner(.{ .scope = lagging_scope, .jail = "held", .generation = [_]u8{3} ** 32, .decision_id = [_]u8{6} ** 32, .expected_revision = 0, .lease = .permanent, .decided_us = young }, world.clock.value());
    try setFence(&world, 2);
    try fillEvents(store, effects.max_confirmed_events - 1 - try countOf(store, "confirmed_effect_events"), young);
    const before = try stateDigest(store);
    try t.expectEqual(.idle, try store.historyRetentionStep(retention, young));
    try t.expectEqualSlices(u8, &before, &try stateDigest(store));
    try t.expectError(error.ReserveBackpressure, store.setOwner(.{ .scope = try effects.Scope.host(RetainedHistory.subject(5)), .jail = "held", .generation = [_]u8{3} ** 32, .decision_id = [_]u8{5} ** 32, .expected_revision = 0, .lease = .permanent, .decided_us = young }, world.clock.value()));
    _ = try store.settleOutcome(lagging.token(), world.clock.now, observation(lagging, young), world.clock.value());
    try t.expectEqual(@as(i64, effects.max_confirmed_events), try countOf(store, "confirmed_effect_events"));
}

// The store's work guard checked on every VM step, so a zero selection budget interrupts
// the first selection statement itself.
fn everyStepProgress(context: ?*anyopaque) callconv(.c) c_int {
    const store: *durable.Store = @ptrCast(@alignCast(context.?));
    if (store.work_remaining == 0) return 1;
    store.work_remaining -= 1;
    return 0;
}
extern fn sqlite3_progress_handler(db: *anyopaque, instructions: c_int, callback: ?*const fn (?*anyopaque) callconv(.c) c_int, context: ?*anyopaque) void;

test "native effect history store: interrupted selection, failed writes and failed commit leave retention state unchanged" {
    // Failure: a page that deleted a detail without its summary or stream update, or an
    // interruption after a write treated as a harmless yield.
    var world: RetainedHistory = undefined;
    try world.init(1);
    defer world.deinit();
    const store = &world.f.store;
    for ([_]u8{ 0, 0, 0, 1 }) |subject| try world.arrive(.{ .subject = subject });
    try world.consumeTo(world.head);
    const retention = durable.Store.HistoryRetention{ .age_us = 86_400_000_000, .max_matches = 1 };
    const unchanged = try stateDigest(store);

    // The named pre-write yield halves the page; at one row it is an actionable failure.
    try store.configureRuntimeLimits();
    sqlite3_progress_handler(@ptrCast(store.db), 1, everyStepProgress, store);
    store.test_hooks.retention_select_work = 0;
    try t.expectEqual(.yielded, try store.historyRetentionStep(retention, world.clock.now));
    try t.expectEqual(durable.max_retention_page / 2, store.retention_page);
    store.retention_page = 1;
    try t.expectError(error.MaintenanceWorkExhausted, store.historyRetentionStep(retention, world.clock.now));
    store.test_hooks.retention_select_work = null;
    store.retention_page = durable.max_retention_page;
    try store.configureRuntimeLimits();
    try t.expect(!store.reopen_required);
    try t.expectEqualSlices(u8, &unchanged, &try stateDigest(store));

    for ([_]durable.CommitStage{ .after_history_detail_delete, .before_history_retention_commit }) |stage| {
        store.fail_at = stage;
        try t.expectError(error.InjectedFailure, store.historyRetentionStep(retention, world.clock.now));
        store.fail_at = null;
        try t.expectEqualSlices(u8, &unchanged, &try stateDigest(store));
    }
    try t.expectEqual(.details, try store.historyRetentionStep(retention, world.clock.now));
    try expectSummariesExact(store);
    try t.expectEqual(@as(i64, 2), try countOf(store, "confirmed_event_details"));

    // The stream prefix page rolls back as a unit too.
    for ([_]u8{ 0, 1 }) |subject| try settleOutcomes(store, (try ownerOf(store, RetainedHistory.subject(subject), "r0")).decision_id, &world.clock);
    for (1..3) |index| try settleOutcomes(store, (try ownerOf(store, RetainedHistory.subject(0), try world.jail(index))).decision_id, &world.clock);
    const aged = durable.Store.HistoryRetention{ .age_us = 0, .max_matches = 1 };
    // The two remaining details are deleted by age first.
    try t.expectEqual(.details, try store.historyRetentionStep(aged, world.clock.now));
    const prefix_before = try stateDigest(store);
    store.fail_at = .after_history_event_delete;
    try t.expectError(error.InjectedFailure, store.historyRetentionStep(aged, world.clock.now));
    store.fail_at = null;
    try t.expectEqualSlices(u8, &prefix_before, &try stateDigest(store));
    try t.expectEqual(.prefix, try store.historyRetentionStep(aged, world.clock.now));
    try t.expectEqual(@as(i64, 0), try countOf(store, "confirmed_effect_events"));
}

test "native effect history store: reused, permanent and multi-jail scopes keep counters and expiry through reclamation" {
    // Failure: a scope that is never spent (a permanent owner in one jail, a reused finite
    // owner in another) accumulated obsolete lifecycle rows forever; reclaiming them must
    // not touch current revisions, intents, deadlines or confirmation counts.
    var world: RetainedHistory = undefined;
    try world.init(10);
    defer world.deinit();
    const store = &world.f.store;
    const subject = RetainedHistory.subject(0);
    const permanent = retry.Policy{ .maxretry = 1, .window_us = 60_000_000, .duration = .permanent, .max_subjects = 8, .enforce = true };
    const short = retry.Policy{ .maxretry = 1, .window_us = 1_000_000, .duration = .{ .finite_us = 10_000_000 }, .max_subjects = 8, .enforce = true };
    try store.admitRetry("perm", [_]u8{3} ** 32, permanent);
    try store.admitRetry("short", [_]u8{3} ** 32, short);
    _ = try store.commitRecord(try nativeRecord(store, &world.clock, "perm", "p", 0, subject, permanent, null));
    try dispatchAndSettle(store, subject, &world.clock);
    try settleOutcomes(store, (try ownerOf(store, subject, "perm")).decision_id, &world.clock);
    const cycles = 4;
    var deadline: i64 = 0;
    for (0..cycles) |cycle| {
        world.clock.now += 2_000_000;
        var occurrence: [8]u8 = undefined;
        _ = try store.commitRecord(try nativeRecord(store, &world.clock, "short", try std.fmt.bufPrint(&occurrence, "s{d}", .{cycle}), cycle, subject, short, null));
        try dispatchAndSettle(store, subject, &world.clock);
        const owner = try ownerOf(store, subject, "short");
        try settleOutcomes(store, owner.decision_id, &world.clock);
        deadline = owner.lease.finite;
        if (cycle + 1 == cycles) break;
        world.clock.now = deadline + 1;
        const expiring = try effectForSubject(store, subject);
        _ = try store.prepareExpiry(expiring.scope_key, expiring.revision, world.clock.value());
        try dispatchAndSettle(store, subject, &world.clock);
    }
    while (try store.reclaimObsoleteOne() != .idle) {}
    try t.expectEqual(@as(i64, cycles), try scalar(store, "SELECT confirmed_count FROM confirmed_policy_summaries WHERE jail='short';"));
    try t.expectEqual(@as(i64, 1), try scalar(store, "SELECT confirmed_count FROM confirmed_policy_summaries WHERE jail='perm';"));
    try t.expectEqual(@as(i64, 2), try countOf(store, "effect_owner_revisions"));
    try t.expectEqual(@as(i64, 1), try countOf(store, "effect_intents"));
    try t.expectEqual(@as(i64, 4), try countOf(store, "action_targets"));
    try t.expect(try countOf(store, "effect_observations") <= 4);
    try t.expectEqual(deadline, (try ownerOf(store, subject, "short")).lease.finite);
    try t.expectEqual(effects.Lease.permanent, (try ownerOf(store, subject, "perm")).lease);
    try t.expectEqual(effects.Lease.permanent, (try effectForSubject(store, subject)).desired);
    try t.expectEqual(@as(i64, 2), try scalar(store, "SELECT live FROM effect_owner_live;"));
    try t.expectEqual(@as(?durable.Store.LiveOwnerRecount, null), try store.reconcileLiveOwners());
}

test "native effect history store: startup recount repairs a drifted live-owner counter and refuses altered triggers" {
    // Failure: the reserve trusts a derived counter; drift must be repaired before admission
    // and a missing maintenance trigger refused rather than silently recounted forever.
    var world: RetainedHistory = undefined;
    try world.init(10);
    defer world.deinit();
    const store = &world.f.store;
    try world.arrive(.{ .subject = 0 });
    try sql(store, "UPDATE effect_owner_live SET live=5;");
    try t.expectEqual(durable.Store.LiveOwnerRecount{ .stored = 5, .counted = 1 }, (try store.reconcileLiveOwners()).?);
    try t.expectEqual(@as(?durable.Store.LiveOwnerRecount, null), try store.reconcileLiveOwners());
    try sql(store, "DROP TRIGGER effect_owner_live_delete;");
    try t.expectError(error.LiveOwnerCounterInvalid, store.reconcileLiveOwners());
}

test "native effect history store: a spent scope is pruned while its confirmed history stays readable" {
    // Failure: retained events referenced the scope row, so a spent scope waited for its
    // history to age out and page readers lost events whose scope had been pruned.
    var world: RetainedHistory = undefined;
    try world.init(10);
    defer world.deinit();
    const store = &world.f.store;
    const subject = RetainedHistory.subject(0);
    try world.arrive(.{ .subject = 0, .evidence = 8 });
    const owner = try ownerOf(store, subject, "r0");
    try settleOutcomes(store, owner.decision_id, &world.clock);
    world.clock.now = owner.lease.finite + 1;
    const expiring = try effectForSubject(store, subject);
    _ = try store.prepareExpiry(expiring.scope_key, expiring.revision, world.clock.value());
    try dispatchAndSettle(store, subject, &world.clock);
    try world.consumeTo(world.head);
    const request = durable.Store.MaintenanceRequest{ .retention = .{ .age_us = 86_400_000_000, .max_matches = 10 }, .now_us = world.clock.now, .history_caught_up = true, .spent_scopes = true };
    var spent = false;
    var steps: usize = 0;
    while (steps < 64) : (steps += 1) switch (try store.maintenanceStep(request)) {
        .idle => break,
        .progress => |operation| spent = spent or operation == .spent_scopes,
        .wait => return error.TestUnexpectedWait,
    };
    try t.expect(spent);
    try t.expectEqual(@as(i64, 0), try countOf(store, "native_effects"));
    try t.expectEqual(@as(i64, 1), try countOf(store, "confirmed_effect_events"));
    var events: [1]history.Event = undefined;
    const page = try store.confirmedEffectPage(world.f.installation, 0, null, &events);
    try t.expectEqual(@as(usize, 1), page.count);
    try t.expect(std.meta.eql(events[0].scope, try effects.Scope.host(subject)));
    var rows: [1]application.Event = undefined;
    const detailed = try store.applicationHistoryPage(t.allocator, world.f.installation, .{}, &rows);
    defer for (rows[0..detailed.count]) |*row| row.deinit(t.allocator);
    try t.expect(rows[0].detail != null);
}

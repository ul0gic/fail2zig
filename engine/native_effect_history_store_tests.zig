// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const t = std.testing;
const history = @import("core/native_effect_history.zig");
const effects = @import("core/native_effect.zig");
const durable = @import("core/record_store.zig");
const application = @import("core/native_application_history.zig");
const detection = @import("core/native_detection_record.zig");
const retry = @import("core/native_retry.zig");
const recurrence = @import("core/native_recurrence.zig");
const time_policy = @import("core/source_time_policy.zig");
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
        try self.store.markDispatched(entry.token(), clock.value());
        _ = try self.store.settleVerified(entry.token(), observation(entry, clock.now), clock.value());
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
    try f.store.markDispatched(pending.token(), clock.value());
    try t.expectEqual(effects.Settlement.verified, try f.store.settleVerified(pending.token(), observation(pending, clock.now), clock.value()));

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
    try f.store.markDispatched(first_effect.token(), clock.value());
    _ = try f.store.settleVerified(first_effect.token(), observation(first_effect, clock.now), clock.value());
    _ = try f.store.settleVerified(first_effect.token(), observation(first_effect, clock.now), clock.value());

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
    try f.store.markDispatched(pending.token(), clock.value());
    _ = try f.store.settleVerified(pending.token(), observation(pending, clock.now), clock.value());
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
    try f.store.markDispatched(pending.token(), clock.value());
    _ = try f.store.settleVerified(pending.token(), observation(pending, clock.now), clock.value());
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
        try f.store.markDispatched(pending.token(), clock.value());
        _ = try f.store.settleVerified(pending.token(), observation(pending, clock.now), clock.value());
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
    try f.store.markDispatched(pending.token(), clock.value());
    _ = try f.store.settleVerified(pending.token(), observation(pending, clock.now), clock.value());
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
    try enableApplicationHistory(&f.store);
    try f.store.enableEscalation();
    var owner = try history.Consumer.init(f.installation, [_]u8{8} ** 32);
    const initial = try owner.prepareInitial();
    try f.store.bootstrapConfirmedHistory(owner.manifest(), try initial.batch(clock.value()), f.installation);
    initial.publish();
    initial.release();

    const finite = retry.Policy{ .maxretry = 1, .window_us = 60_000_000, .duration = .{ .finite_us = 10_000_000 }, .max_subjects = 8, .enforce = true };
    const subject = detection.Subject{ .v4 = .{ 203, 0, 113, 91 } };
    try f.store.admitRetry("finite-history", [_]u8{3} ** 32, finite);
    _ = try f.store.commitRecord(try nativeRecord(&f.store, &clock, "finite-history", "one", 0, subject, finite, "retained detail"));
    var pending = try effectForSubject(&f.store, subject);
    try f.store.markDispatched(pending.token(), clock.value());
    _ = try f.store.settleVerified(pending.token(), observation(pending, clock.now), clock.value());
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

    try t.expect(!try f.store.cleanupConfirmedHistoryOne(.{ .age_us = 0 }, clock.now));
    clock.now += 10_000_000;
    f.store.fail_at = .after_history_event_delete;
    try t.expectError(error.InjectedFailure, f.store.cleanupConfirmedHistoryOne(.{ .age_us = 0 }, clock.now));
    try t.expectEqual(@as(usize, 1), (try f.store.confirmedEffectPage(f.installation, 0, null, &events)).count);
    f.store.fail_at = null;
    try t.expect(try f.store.cleanupConfirmedHistoryOne(.{ .age_us = 0 }, clock.now));
    try t.expectError(error.HistoryGap, f.store.confirmedEffectPage(f.installation, 0, null, &events));
    try f.reopen();
    try t.expectError(error.HistoryGap, f.store.confirmedEffectPage(f.installation, 0, null, &events));

    const permanent = retry.Policy{ .maxretry = 1, .window_us = 60_000_000, .duration = .permanent, .max_subjects = 8, .enforce = true };
    const pinned_subject = detection.Subject{ .v4 = .{ 203, 0, 113, 92 } };
    try f.store.admitRetry("permanent-history", [_]u8{3} ** 32, permanent);
    _ = try f.store.commitRecord(try nativeRecord(&f.store, &clock, "permanent-history", "one", 0, pinned_subject, permanent, null));
    pending = try effectForSubject(&f.store, pinned_subject);
    try f.store.markDispatched(pending.token(), clock.value());
    _ = try f.store.settleVerified(pending.token(), observation(pending, clock.now), clock.value());
    const pinned_page = try f.store.confirmedEffectPage(f.installation, 1, null, &events);
    const pinned_stage = try owner.prepare(pinned_page, events[0..pinned_page.count], clock.now);
    try f.store.commitConfirmedHistory(owner.manifest(), try pinned_stage.batch(clock.value()), pinned_page.token);
    pinned_stage.publish();
    pinned_stage.release();
    try t.expect(try f.store.cleanupConfirmedHistoryOne(.{ .age_us = 0, .max_matches = 0 }, clock.now));
    try t.expect(!try f.store.cleanupConfirmedHistoryOne(.{ .age_us = 0, .max_matches = 0 }, clock.now));
}

test "native effect history store: only first qualified receipt appends and repair replay is stable" {
    var f = try Fixture.init();
    defer f.deinit();
    var clock = Clock{};
    try f.store.enableConfirmedHistory();
    const entry = try f.confirm(1, &clock);
    var events: [64]history.Event = undefined;
    const first = try f.store.confirmedEffectPage(f.installation, 0, null, &events);
    _ = try f.store.settleVerified(entry.token(), observation(entry, 100), clock.value());
    const repeated = try f.store.confirmedEffectPage(f.installation, 0, first.token.stream_revision, &events);
    try t.expectEqualDeep(first, repeated);
    const pending = try f.store.setOwner(.{ .scope = try effects.Scope.host(.{ .v4 = .{ 192, 0, 2, 2 } }), .jail = "ssh", .generation = [_]u8{3} ** 32, .decision_id = [_]u8{2} ** 32, .expected_revision = 0, .lease = .permanent, .decided_us = 100 }, clock.value());
    try f.store.markDispatched(pending.token(), clock.value());
    var uncertain = observation(pending, 100);
    uncertain.qualification = .incomplete;
    try t.expectError(error.IncompleteEffectObservation, f.store.settleVerified(pending.token(), uncertain, clock.value()));
    try f.store.validateConfirmedEffectPage(first.token);
    f.store.fail_at = .before_effect_receipt_commit;
    try t.expectError(error.InjectedFailure, f.store.settleVerified(pending.token(), observation(pending, 100), clock.value()));
    f.store.fail_at = null;
    try f.store.validateConfirmedEffectPage(first.token);
    try f.reopen();
    _ = try f.store.settleVerified(pending.token(), observation(pending, 100), clock.value());
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

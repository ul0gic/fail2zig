// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const durable = @import("engine_test").core.record_store;
const effects = @import("engine_test").core.native_effect;
const retry = @import("engine_test").core.native_retry;
const canonical = @import("engine_test").firewall.scope;

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
        const path = try std.fs.path.join(t.allocator, &.{ root, "reload.sqlite" });
        errdefer t.allocator.free(path);
        var store = try durable.Store.open(t.allocator, path);
        errdefer store.close();
        try enableAll(&store);
        return .{ .tmp = tmp, .path = path, .store = store };
    }
    fn deinit(self: *Fixture) void {
        self.store.close();
        t.allocator.free(self.path);
        self.tmp.cleanup();
    }
    fn reopen(self: *Fixture) !void {
        self.store.close();
        self.store = try durable.Store.open(t.allocator, self.path);
        try enableAll(&self.store);
    }
};

fn enableAll(store: *durable.Store) !void {
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

const now_us: i64 = 1_000_000;
const old_generation = [_]u8{9} ** 32;
const new_generation = [_]u8{10} ** 32;
const config_generation = [_]u8{6} ** 32;
const previous_generation = [_]u8{8} ** 32;

fn staticRead(_: ?*anyopaque) i64 {
    return now_us;
}
fn clock() effects.Clock {
    return .{ .prepared_us = now_us, .context = null, .read = staticRead };
}
fn policy(maxretry: u16, bantime_s: i64) retry.Policy {
    return .{ .maxretry = maxretry, .window_us = 600 * 1_000_000, .duration = .{ .finite_us = bantime_s * 1_000_000 }, .max_subjects = 64 };
}

const Observation = struct {
    row_count: i64,
    published: i64,
    policies_old: i64,
    policies_new: i64,
    escalation_old: i64,
    escalation_new: i64,
    owners_old: i64,
    owners_new: i64,
    records_new: i64,
    guards_new: i64,
    previous_published: i64,
};

fn countWhere(store: *durable.Store, comptime table: []const u8, comptime column: []const u8, value: [32]u8) !i64 {
    var buf: [256]u8 = undefined;
    return store.inspectInteger(try std.fmt.bufPrintZ(&buf, "SELECT count(*) FROM " ++ table ++ " WHERE " ++ column ++ "=x'{s}';", .{std.fmt.bytesToHex(value, .lower)}));
}

fn observe(store: *durable.Store) !Observation {
    var buf: [256]u8 = undefined;
    const row_count = try countWhere(store, "config_generations", "generation", config_generation);
    const published = if (row_count == 0) 0 else try store.inspectInteger(try std.fmt.bufPrintZ(&buf, "SELECT published FROM config_generations WHERE generation=x'{s}';", .{std.fmt.bytesToHex(config_generation, .lower)}));
    return .{
        .row_count = row_count,
        .published = published,
        .policies_old = try countWhere(store, "retry_policies", "generation", old_generation),
        .policies_new = try countWhere(store, "retry_policies", "generation", new_generation),
        .escalation_old = try countWhere(store, "retry_escalation_policies", "generation", old_generation),
        .escalation_new = try countWhere(store, "retry_escalation_policies", "generation", new_generation),
        .owners_old = try countWhere(store, "effect_owners", "generation", old_generation),
        .owners_new = try countWhere(store, "effect_owners", "generation", new_generation),
        .records_new = try countWhere(store, "records", "source_generation", new_generation),
        .guards_new = try countWhere(store, "replay_guards", "generation", new_generation),
        .previous_published = try store.inspectInteger(try std.fmt.bufPrintZ(&buf, "SELECT count(*) FROM config_generations WHERE generation=x'{s}' AND published=1;", .{std.fmt.bytesToHex(previous_generation, .lower)})),
    };
}

fn rolledBack(o: Observation) bool {
    return o.row_count == 0 and o.policies_old == 1 and o.policies_new == 0 and o.escalation_old == 1 and o.escalation_new == 0 and o.owners_old == 1 and o.owners_new == 0 and o.records_new == 0 and o.guards_new == 0 and o.previous_published == 1;
}

fn publishedAndRekeyed(o: Observation) bool {
    return o.row_count == 1 and o.published == 1 and o.policies_old == 0 and o.policies_new == 1 and o.escalation_old == 0 and o.escalation_new == 1 and o.owners_old == 0 and o.owners_new == 1 and o.previous_published == 0;
}

fn report(label: []const u8, o: Observation) void {
    std.debug.print(
        \\BUG-023 {s}:
        \\  config_generations rows for the new generation: {d} (published={d}); previous head still published: {d}
        \\  retry_policies at old/new generation: {d}/{d}
        \\  retry_escalation_policies at old/new generation: {d}/{d}
        \\  effect_owners at old/new generation: {d}/{d}
        \\  records/replay_guards at new generation: {d}/{d}
        \\
    , .{ label, o.row_count, o.published, o.previous_published, o.policies_old, o.policies_new, o.escalation_old, o.escalation_new, o.owners_old, o.owners_new, o.records_new, o.guards_new });
}

fn prepare(f: *Fixture, last: u8) !durable.Store.ConfigGenerationRecord {
    try f.store.admitRetry("sshd", old_generation, policy(3, 60));
    const scope = canonical.Scope{ .subject = canonical.Subject.host(.{ .ipv4 = (192 << 24) | (2 << 8) | @as(u32, last) }) };
    _ = try f.store.setOwnerFromCanonical(.{ .scope = scope, .jail = "sshd", .generation = old_generation, .decision_id = [_]u8{3} ** 32, .expected_revision = 0, .lease = .{ .finite = now_us + 60_000_000 }, .decided_us = now_us - 1 }, clock());
    try f.store.recordConfigGeneration(.{ .generation = previous_generation, .config_digest = [_]u8{1} ** 32, .config_path = "/etc/fail2zig/config.toml", .committed_us = 10, .published = true, .mutation_revision = 0 }, &.{.{ .jail = "sshd", .digest = [_]u8{1} ** 32, .allowlist_snapshot = "" }});
    return .{ .generation = config_generation, .config_digest = [_]u8{4} ** 32, .config_path = "/etc/fail2zig/config.toml", .committed_us = 50, .published = false, .mutation_revision = 0 };
}

fn transition() durable.Store.PolicyTransition {
    return .{ .jail = "sshd", .generation = old_generation, .next_generation = new_generation, .expected = policy(3, 60), .next = policy(2, 60) };
}

test "reload crash: a failure before the re-key commit leaves every object at the old generation" {
    var f = try Fixture.init();
    defer f.deinit();
    const record = try prepare(&f, 10);
    const revision = try f.store.adminRevision();
    f.store.fail_at = .before_config_generation_commit;
    try t.expectError(error.InjectedFailure, f.store.commitReloadGeneration(&.{transition()}, record, &.{.{ .jail = "sshd", .digest = [_]u8{4} ** 32, .allowlist_snapshot = "" }}, clock()));
    f.store.fail_at = null;
    try f.reopen();
    const o = try observe(&f.store);
    if (!rolledBack(o)) {
        report("re-key survived a failed commit", o);
        return error.TestUnexpectedResult;
    }
    try t.expectEqual(revision, try f.store.adminRevision());
    const head = (try f.store.latestConfigGeneration()).?;
    try t.expectEqualSlices(u8, &previous_generation, &head.generation);
    try t.expect(head.published);
}

test "reload crash: a committed re-key is published in the same transaction and survives reopen" {
    var f = try Fixture.init();
    defer f.deinit();
    const record = try prepare(&f, 11);
    const revision = try f.store.adminRevision();
    try f.store.commitReloadGeneration(&.{transition()}, record, &.{.{ .jail = "sshd", .digest = [_]u8{4} ** 32, .allowlist_snapshot = "" }}, clock());
    try f.reopen();
    const o = try observe(&f.store);
    if (!publishedAndRekeyed(o)) {
        report("committed re-key is not the single published head", o);
        return error.TestUnexpectedResult;
    }
    try t.expectEqual(revision + 1, try f.store.adminRevision());
    try t.expectEqual(@as(i64, 1), try f.store.inspectInteger("SELECT count(*) FROM config_generations WHERE published=1;"));
    const head = (try f.store.latestConfigGeneration()).?;
    try t.expectEqualSlices(u8, &config_generation, &head.generation);
    try t.expect(head.published);
    f.store.fail_at = .before_config_generation_publish;
    try t.expectError(error.InjectedFailure, f.store.publishConfigGeneration(config_generation));
    f.store.fail_at = null;
    try t.expect((try f.store.latestConfigGeneration()).?.published);
}

test "reload crash: an unpublished head is reported as unpublished for startup refusal" {
    var f = try Fixture.init();
    defer f.deinit();
    _ = try prepare(&f, 12);
    try f.store.recordConfigGeneration(.{ .generation = config_generation, .config_digest = [_]u8{4} ** 32, .config_path = "/etc/fail2zig/config.toml", .committed_us = 60, .published = false, .mutation_revision = 0 }, &.{});
    try f.reopen();
    const head = (try f.store.latestConfigGeneration()).?;
    try t.expectEqualSlices(u8, &config_generation, &head.generation);
    try t.expect(!head.published);
}

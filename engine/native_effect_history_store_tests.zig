// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const t = std.testing;
const history = @import("core/native_effect_history.zig");
const effects = @import("core/native_effect.zig");
const durable = @import("core/record_store.zig");
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
        const entry = try self.store.setOwner(.{ .scope = try effects.Scope.host(.{ .v4 = .{ 192, 0, 2, id } }), .jail = "ssh", .generation = [_]u8{3} ** 32, .decision_id = [_]u8{id} ** 32, .expected_revision = 0, .lease = .permanent, .decided_us = clock.now }, clock.value());
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
fn sql(store: *durable.Store, statement: [:0]const u8) !void {
    const run = @extern(*const fn (*anyopaque, [*:0]const u8, ?*anyopaque, ?*anyopaque, ?*?[*:0]u8) callconv(.c) c_int, .{ .name = "sqlite3_exec" });
    if (run(@ptrCast(store.db), statement, null, null, null) != 0) return error.TestSqlFailed;
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
    committed.release(); // process death before in-memory publication
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

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const support = @import("support.zig");
const std = support.std;
const builtin = support.builtin;
const engine = support.engine;
const store_mod = support.store_mod;
const Store = support.Store;
const Error = support.Error;
const Limits = support.Limits;
const Record = support.Record;
const ReceiptIdentity = support.ReceiptIdentity;
const CommitStage = support.CommitStage;
const CommitResult = support.CommitResult;
const Db = support.Db;
const OpenDiagnostic = support.OpenDiagnostic;
const OpenStage = support.OpenStage;
const OpenPosixCause = support.OpenPosixCause;
const latest_schema = support.latest_schema;
const sqliteError = support.sqliteError;
const embedded_api = support.embedded_api;
const native_time = support.native_time;
const time_policy = support.time_policy;
const native_record = support.native_record;
const detection = support.detection;
const retry = support.retry;
const action_context = support.action_context;
const consumers = support.consumers;
const effects = support.effects;
const effect_history = support.effect_history;
const application_history = support.application_history;
const action_outcome = support.action_outcome;
const ReceiptFixture = support.ReceiptFixture;
const DetectionFixture = support.DetectionFixture;

test "record store: killed writer preserves committed WAL and rolls back unfinished updates" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const path = try std.fs.path.join(allocator, &.{ base, "crash.sqlite" });
    defer allocator.free(path);
    for ([_]bool{ false, true }) |uncommitted| {
        const pid = try std.posix.fork();
        if (pid == 0) {
            var store = Store.open(std.heap.page_allocator, path) catch std.process.exit(2);
            if (!uncommitted) {
                _ = store.commitRecord(.{ .jail = "crash", .source = "file", .occurrence = "1", .cursor = "durable-cursor", .raw_hash = [_]u8{1} ** 32, .disposition = "matched", .checkpoint = "durable-state", .action_intent = "durable-intent" }) catch std.process.exit(3);
            } else {
                store.exec("BEGIN IMMEDIATE; UPDATE checkpoints SET payload='uncommitted-state'; DELETE FROM source_cursors; DELETE FROM action_intents;") catch std.process.exit(4);
            }
            std.posix.kill(std.os.linux.getpid(), std.posix.SIG.KILL) catch std.process.exit(5);
            unreachable;
        }
        const result = std.posix.waitpid(pid, 0);
        try std.testing.expect(std.os.linux.W.IFSIGNALED(result.status));
        try std.testing.expectEqual(@as(u32, std.posix.SIG.KILL), std.os.linux.W.TERMSIG(result.status));
        var recovered = try Store.open(allocator, path);
        defer recovered.close();
        const snapshot = try recovered.snapshot(allocator, "crash");
        defer snapshot.deinit(allocator);
        try std.testing.expectEqualStrings("durable-state", snapshot.payload.?);
        const cursor = (try recovered.sourceCursor(allocator, "crash", "file")).?;
        defer allocator.free(cursor);
        try std.testing.expectEqualStrings("durable-cursor", cursor);
        try std.testing.expectEqual(@as(i64, 1), try recovered.pendingIntents());
        try std.testing.expectEqual(@as(u64, 1), snapshot.revision);
    }
}

test "record store: record checkpoint cursor and intent commit together and replay is idempotent" {
    if (!builtin.link_libc) return error.SkipZigTest;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const path = try std.fs.path.join(std.testing.allocator, &.{ base, "state.sqlite" });
    defer std.testing.allocator.free(path);
    var store = try Store.open(std.testing.allocator, path);
    const record = Record{ .jail = "sshd", .source = "file:1", .occurrence = "incarnation:1:0:20", .cursor = "20", .raw_hash = [_]u8{1} ** 32, .event_time = 1800000000.125, .disposition = "matched", .checkpoint = "ticket=1", .action_intent = "typed-test-intent" };
    for ([_]CommitStage{ .after_record, .after_checkpoint, .before_commit }) |stage| {
        store.fail_at = stage;
        try std.testing.expectError(error.InjectedFailure, store.commitRecord(record));
        try std.testing.expectEqual(@as(?[]u8, null), try store.sourceCursor(std.testing.allocator, "sshd", "file:1"));
        try std.testing.expectEqual(@as(?[]u8, null), try store.checkpoint(std.testing.allocator, "sshd"));
        try std.testing.expectEqual(@as(i64, 0), try store.pendingIntents());
    }
    store.fail_at = null;
    try std.testing.expectEqual(CommitResult.committed, try store.commitRecord(record));
    try std.testing.expectEqual(CommitResult.already_committed, try store.commitRecord(record));
    try std.testing.expectEqual(@as(i64, 1), try store.pendingIntents());
    var conflict = record;
    conflict.raw_hash[0] = 2;
    try std.testing.expectError(error.OccurrenceConflict, store.commitRecord(conflict));
    store.close();
    store = try Store.open(std.testing.allocator, path);
    defer store.close();
    const cursor = (try store.sourceCursor(std.testing.allocator, "sshd", "file:1")).?;
    defer std.testing.allocator.free(cursor);
    try std.testing.expectEqualStrings("20", cursor);
    const saved = (try store.checkpoint(std.testing.allocator, "sshd")).?;
    defer std.testing.allocator.free(saved);
    try std.testing.expectEqualStrings("ticket=1", saved);
}

test "record store: stale writers cannot overwrite a committed jail checkpoint" {
    if (!builtin.link_libc) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const path = try std.fs.path.join(allocator, &.{ base, "state.sqlite" });
    defer allocator.free(path);
    var first = try Store.open(allocator, path);
    defer first.close();
    var second = try Store.open(allocator, path);
    defer second.close();
    var record = Record{ .jail = "fixture", .source = "one", .occurrence = "one", .cursor = "1", .raw_hash = [_]u8{1} ** 32, .disposition = "counted", .checkpoint = "first", .expected_revision = 0, .timestamp_us = std.math.maxInt(u64), .event_time = @bitCast(@as(u64, 0x8000000000000000)) };
    const stale = try second.snapshot(allocator, "fixture");
    defer stale.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), stale.revision);
    _ = try first.commitRecord(record);
    {
        var value = try first.statement("SELECT event_time,timestamp_us FROM records;");
        defer value.deinit();
        try std.testing.expect(try value.row());
        try std.testing.expectEqualSlices(u8, &.{ 0x80, 0, 0, 0, 0, 0, 0, 0 }, try value.bytes(0));
        try std.testing.expectEqualStrings("18446744073709551615", try value.bytes(1));
    }
    record.occurrence = "two";
    record.checkpoint = "stale";
    try std.testing.expectError(error.StaleCheckpoint, second.commitRecord(record));
    const current = try second.snapshot(allocator, "fixture");
    defer current.deinit(allocator);
    try std.testing.expectEqualStrings("first", current.payload.?);
    try std.testing.expectEqual(@as(u64, 1), current.revision);
    try std.testing.expectEqual(@as(i64, 1), try first.integer("SELECT count(*) FROM records;"));
    record.expected_revision = current.revision;
    record.checkpoint = "second";
    _ = try second.commitRecord(record);
    try std.testing.expectEqual(@as(i64, 2), try first.integer("SELECT count(*) FROM records;"));
}

test "record store: shared read dependencies and writes are atomic across jails and connections" {
    if (!builtin.link_libc) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const path = try std.fs.path.join(allocator, &.{ base, "shared.sqlite" });
    defer allocator.free(path);
    var first = try Store.open(allocator, path);
    defer first.close();
    var second = try Store.open(allocator, path);
    defer second.close();
    var record = Record{ .jail = "one", .source = "file", .occurrence = "1", .cursor = "1", .raw_hash = [_]u8{1} ** 32, .disposition = "ordinary", .checkpoint = "jail-one", .action_intent = "inert-intent", .shared_state = .{ .name = "dns", .expected_revision = 0 } };
    _ = try first.commitRecord(record);
    {
        const absent = try second.sharedSnapshot(allocator, "dns");
        defer absent.deinit(allocator);
        try std.testing.expectEqual(@as(u64, 0), absent.revision);
        try std.testing.expect(absent.payload == null);
    }
    record.jail = "two";
    record.shared_state.?.payload = "cache-one";
    second.fail_at = .after_shared_checkpoint;
    try std.testing.expectError(error.InjectedFailure, second.commitRecord(record));
    try std.testing.expectEqual(@as(u64, 0), try first.revision("two"));
    try std.testing.expectEqual(@as(?[]u8, null), try first.sourceCursor(allocator, "two", "file"));
    try std.testing.expectEqual(@as(i64, 1), try first.pendingIntents());
    {
        const absent = try first.sharedSnapshot(allocator, "dns");
        defer absent.deinit(allocator);
        try std.testing.expectEqual(@as(u64, 0), absent.revision);
    }
    second.fail_at = null;
    _ = try second.commitRecord(record);
    var stale = record;
    stale.jail = "three";
    stale.shared_state.?.payload = null;
    try std.testing.expectError(error.StaleSharedCheckpoint, first.commitRecord(stale));
    stale.shared_state.?.payload = "stale-cache";
    try std.testing.expectError(error.StaleSharedCheckpoint, first.commitRecord(stale));
    try std.testing.expectEqual(@as(u64, 0), try first.revision("three"));
    stale.shared_state.?.expected_revision = 1;
    stale.shared_state.?.payload = null;
    _ = try first.commitRecord(stale);
    {
        const saved = try second.sharedSnapshot(allocator, "dns");
        defer saved.deinit(allocator);
        try std.testing.expectEqual(@as(u64, 1), saved.revision);
        try std.testing.expectEqualStrings("cache-one", saved.payload.?);
    }
    stale.jail = "four";
    stale.shared_state.?.payload = "cache-two";
    _ = try first.commitRecord(stale);
    try std.testing.expectEqual(CommitResult.already_committed, try second.commitRecord(record));
    const saved = try second.sharedSnapshot(allocator, "dns");
    defer saved.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 2), saved.revision);
    try std.testing.expectEqualStrings("cache-two", saved.payload.?);
}

test "record store: schema one upgrade preserves committed state" {
    if (!builtin.link_libc) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const path = try std.fs.path.join(allocator, &.{ base, "upgrade.sqlite" });
    defer allocator.free(path);
    {
        var old = try Store.open(allocator, path);
        defer old.close();
        _ = try old.commitRecord(.{ .jail = "retained", .source = "file", .occurrence = "1", .cursor = "saved-cursor", .raw_hash = [_]u8{1} ** 32, .disposition = "ordinary", .checkpoint = "saved-jail", .action_intent = "saved-intent" });
        try old.exec("DROP TABLE shared_checkpoints; PRAGMA user_version=1;");
    }
    var upgraded = try Store.open(allocator, path);
    defer upgraded.close();
    try std.testing.expectEqual(@as(i64, 2), try upgraded.integer("PRAGMA user_version;"));
    const saved = try upgraded.snapshot(allocator, "retained");
    defer saved.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), saved.revision);
    try std.testing.expectEqualStrings("saved-jail", saved.payload.?);
    const cursor = (try upgraded.sourceCursor(allocator, "retained", "file")).?;
    defer allocator.free(cursor);
    try std.testing.expectEqualStrings("saved-cursor", cursor);
    try std.testing.expectEqual(@as(i64, 1), try upgraded.pendingIntents());
    const shared = try upgraded.sharedSnapshot(allocator, "dns");
    defer shared.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), shared.revision);
}

const EffectPublicationProbe = struct {
    store: *Store,
    calls: usize = 0,
    epoch_at_invalidation: u64 = 0,
    inside_transaction: bool = false,
    fn invalidate(context: ?*anyopaque) void {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        self.calls += 1;
        self.epoch_at_invalidation = self.store.effect_publication_epoch;
        self.inside_transaction = self.store.api.get_autocommit(self.store.db) == 0;
    }
    fn clockRead(_: ?*anyopaque) i64 {
        return 100;
    }
    fn clock() effects.Clock {
        return .{ .prepared_us = 100, .context = null, .read = clockRead };
    }
    fn enable(store: *Store) !void {
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
    }
    fn change() !effects.OwnerChange {
        return .{ .scope = try effects.Scope.host(.{ .v4 = .{ 192, 0, 2, 7 } }), .jail = "sshd", .generation = [_]u8{5} ** 32, .decision_id = [_]u8{6} ** 32, .expected_revision = 0, .lease = .{ .finite = 500 }, .decided_us = 100 };
    }
};

test "record store: effect invalidation precedes durable commit and unchanged owners keep authority" {
    const t = std.testing;
    var temp = t.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(base);
    const path = try std.fs.path.join(t.allocator, &.{ base, "publication.sqlite" });
    defer t.allocator.free(path);
    var store = try Store.open(t.allocator, path);
    defer store.close();
    try EffectPublicationProbe.enable(&store);
    var probe = EffectPublicationProbe{ .store = &store };
    store.effect_invalidation = .{ .context = &probe, .invalidate = EffectPublicationProbe.invalidate };
    const entry = try store.setOwner(try EffectPublicationProbe.change(), EffectPublicationProbe.clock());
    try t.expectEqual(@as(usize, 1), probe.calls);
    try t.expect(probe.inside_transaction);
    try t.expectEqual(@as(u64, 0), probe.epoch_at_invalidation);
    try t.expectEqual(@as(u64, 1), store.effect_publication_epoch);
    try t.expect(store.api.get_autocommit(store.db) != 0);
    _ = try store.setOwner(try EffectPublicationProbe.change(), EffectPublicationProbe.clock());
    _ = try store.prepareExpiry(entry.scope_key, entry.revision, EffectPublicationProbe.clock());
    try t.expectEqual(@as(usize, 1), probe.calls);
    try t.expectEqual(@as(u64, 1), store.effect_publication_epoch);
}

test "record store: failed effect commit retains invalidation without publishing an epoch and reopens unchanged" {
    const t = std.testing;
    var temp = t.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(base);
    const path = try std.fs.path.join(t.allocator, &.{ base, "failed-publication.sqlite" });
    defer t.allocator.free(path);
    for ([_]bool{ false, true }) |fail_rollback| {
        {
            var store = try Store.open(t.allocator, path);
            defer store.close();
            if (store.schema_version == 2) try EffectPublicationProbe.enable(&store);
            var probe = EffectPublicationProbe{ .store = &store };
            store.effect_invalidation = .{ .context = &probe, .invalidate = EffectPublicationProbe.invalidate };
            const Fault = struct {
                var active: *EffectPublicationProbe = undefined;
                var rollback_failure: bool = false;
                var saw_invalidated_commit: bool = false;
                fn exec(db: *Db, sql: [*:0]const u8, callback: ?*anyopaque, context: ?*anyopaque, message: ?*?[*:0]u8) callconv(.c) c_int {
                    if (std.mem.eql(u8, std.mem.span(sql), "COMMIT;")) {
                        saw_invalidated_commit = active.calls == 1 and active.store.effect_publication_epoch == 0;
                        return 10 | (3 << 8);
                    }
                    if (rollback_failure and std.mem.eql(u8, std.mem.span(sql), "ROLLBACK;")) return 10 | (4 << 8);
                    return embedded_api.exec(db, sql, callback, context, message);
                }
            };
            Fault.active = &probe;
            Fault.rollback_failure = fail_rollback;
            Fault.saw_invalidated_commit = false;
            store.api.exec = Fault.exec;
            try t.expectError(error.StorageIo, store.setOwner(try EffectPublicationProbe.change(), EffectPublicationProbe.clock()));
            try t.expect(Fault.saw_invalidated_commit and probe.inside_transaction);
            try t.expectEqual(@as(usize, 1), probe.calls);
            try t.expectEqual(@as(u64, 0), store.effect_publication_epoch);
            // COMMIT I/O uncertainty always requires reopen, even when rollback succeeds.
            try t.expect(store.reopen_required);
            try t.expectEqual(@as(?c_int, if (fail_rollback) 10 | (4 << 8) else null), store.rollback_error_code);
            try t.expectEqual(fail_rollback, store.api.get_autocommit(store.db) == 0);
            try t.expectEqual(@as(?c_int, 10 | (3 << 8)), store.last_error_code);
        }
        var reopened = try Store.open(t.allocator, path);
        defer reopened.close();
        try t.expectEqual(@as(i64, 0), try reopened.integer("SELECT count(*) FROM effect_owners;"));
    }
}

test "record store: extension-only staged activation invalidates effects despite zero fresh owners" {
    const t = std.testing;
    var temp = t.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(base);
    const path = try std.fs.path.join(t.allocator, &.{ base, "extension-publication.sqlite" });
    defer t.allocator.free(path);
    var store = try Store.open(t.allocator, path);
    defer store.close();
    try EffectPublicationProbe.enable(&store);
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
    const change = try EffectPublicationProbe.change();
    _ = try store.setOwner(change, EffectPublicationProbe.clock());
    const run_id = [_]u8{9} ** 32;
    try store.createMigrationRun(.{ .run_id = run_id, .host_id = [_]u8{1} ** 32, .source_db_fp = [_]u8{2} ** 32, .source_cfg_fp = [_]u8{3} ** 32, .plan_fp = [_]u8{4} ** 32, .recovery_point = "/fixture/recovery.sqlite", .generation = change.generation, .state = .planned, .created_us = 100, .updated_us = 100 });
    try store.stageMigrationRows(run_id, &.{.{ .jail = change.jail, .scope = try (try change.scope.toCanonical()).encode(), .lease_kind = 1, .deadline_us = 1000, .source_event_us = 100, .source_row = 1 }}, &.{});
    const seq = try store.beginMigrationStep(run_id, .stage_destination, "", 100);
    try store.finishMigrationStep(run_id, seq, .success, "", .staged, 100);
    var probe = EffectPublicationProbe{ .store = &store };
    store.effect_invalidation = .{ .context = &probe, .invalidate = EffectPublicationProbe.invalidate };
    const epoch = store.effect_publication_epoch;
    try t.expectEqual(@as(u64, 0), try store.activateStagedOwners(run_id, &.{.{ .jail = change.jail, .generation = change.generation }}, EffectPublicationProbe.clock()));
    try t.expectEqual(@as(usize, 1), probe.calls);
    try t.expect(probe.inside_transaction);
    try t.expectEqual(epoch, probe.epoch_at_invalidation);
    try t.expectEqual(epoch + 1, store.effect_publication_epoch);
    try t.expectEqual(@as(i64, 1000), try store.integer("SELECT deadline_us FROM effect_owners;"));
    _ = try store.activateStagedOwners(run_id, &.{.{ .jail = change.jail, .generation = change.generation }}, EffectPublicationProbe.clock());
    try t.expectEqual(@as(usize, 1), probe.calls);
    try t.expectEqual(epoch + 1, store.effect_publication_epoch);
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const t = std.testing;
const durable = @import("core/record_store.zig");
const consumer = @import("core/native_consumer.zig");
const history = @import("core/native_effect_history.zig");
const effect = @import("core/native_effect.zig");
const generation = [_]u8{9} ** 32;
fn clock(_: ?*anyopaque) i64 {
    return 100;
}
fn sql(store: *durable.Store, query: [:0]const u8) !void {
    const run = @extern(*const fn (*anyopaque, [*:0]const u8, ?*anyopaque, ?*anyopaque, ?*?[*:0]u8) callconv(.c) c_int, .{ .name = "sqlite3_exec" });
    if (run(@ptrCast(store.db), query, null, null, null) != 0) return error.TestSqlFailed;
}
const Fixture = struct {
    tmp: t.TmpDir,
    path: []u8,
    store: durable.Store,
    fn init() !Fixture {
        var tmp = t.tmpDir(.{});
        errdefer tmp.cleanup();
        const root = try tmp.dir.realpathAlloc(t.allocator, ".");
        defer t.allocator.free(root);
        const path = try std.fs.path.join(t.allocator, &.{ root, "maintenance.sqlite" });
        errdefer t.allocator.free(path);
        var store = try durable.Store.open(t.allocator, path);
        errdefer store.close();
        try store.enableReceipts(8);
        try store.enableNativeTime();
        try store.enableDetection();
        try store.enableClockRecovery();
        try store.enableJournalDetection();
        try store.enableRetry();
        try store.enableConsumers();
        try store.enableEffects();
        try store.enableConsumerManifests();
        try store.enableConfirmedHistory();
        return .{ .tmp = tmp, .path = path, .store = store };
    }
    fn deinit(self: *Fixture) void {
        self.store.close();
        t.allocator.free(self.path);
        self.tmp.cleanup();
    }
};
const key = consumer.Key{ .kind = .dns, .jail = "@shared", .source = "wal.example", .rule = "v4", .generation = generation };
const required = [_]consumer.Requirement{.{ .key = key, .format_version = 1 }};
const manifest = consumer.Manifest{ .jail = "@shared", .source = "v4:wal.example", .source_generation = generation, .required = &required };
fn batch(revision: u64, payload: []const u8, delta: *[1]consumer.Delta) consumer.Batch {
    delta.* = .{.{ .key = key, .format_version = 1, .expected_revision = revision, .payload = payload }};
    return .{ .prepared_us = 100, .clock = clock, .deltas = delta };
}
const identity = durable.ReceiptIdentity{ .jail = "receipt", .source = "file", .occurrence = "original", .cursor = "next", .raw_hash = [_]u8{3} ** 32, .generation = generation };

test "native maintenance: admitted overshoot pins all writer classes until checkpoint succeeds" {
    var f = try Fixture.init();
    defer f.deinit();
    const owner = try effect.Installation.init([_]u8{4} ** 16, .nftables, "maintenance-fixture");
    try f.store.admitInstallation(owner, .{ .selector = owner.selector(), .disposition = .verified_absent });
    const change = effect.OwnerChange{ .scope = try effect.Scope.host(.{ .v4 = .{ 192, 0, 2, 44 } }), .jail = "effects", .generation = generation, .decision_id = [_]u8{7} ** 32, .expected_revision = 0, .lease = .permanent, .decided_us = 100 };
    const pending = try f.store.setOwner(change, .{ .prepared_us = 100, .read = clock });
    var delta: [1]consumer.Delta = undefined;
    try f.store.bootstrapConsumerManifest(manifest, batch(0, "original", &delta));
    var history_owner = try history.Consumer.init(owner, generation);
    const initial = try history_owner.prepareInitial();
    try f.store.bootstrapConfirmedHistory(history_owner.manifest(), try initial.batch(.{ .prepared_us = 100, .read = clock }), owner);
    initial.publish();
    initial.release();
    try sql(&f.store, "PRAGMA wal_checkpoint(TRUNCATE);");
    var reader = try durable.Store.open(t.allocator, f.path);
    defer reader.close();
    try sql(&reader, "BEGIN; SELECT count(*) FROM records;");
    var pinned = true;
    defer if (pinned) sql(&reader, "COMMIT;") catch {};
    const hard_limit = @extern(*const fn (i64) callconv(.c) i64, .{ .name = "sqlite3_hard_heap_limit64" });
    const prior = hard_limit(-1);
    defer _ = hard_limit(prior);
    try f.store.configureRuntimeLimits();
    f.store.runtime_path = f.path;
    const payload = try t.allocator.alloc(u8, durable.Limits.checkpoint_bytes);
    defer t.allocator.free(payload);
    @memset(payload, 0x41);
    const record = durable.Record{ .jail = "volume", .source = "file", .occurrence = "one", .cursor = "one", .raw_hash = [_]u8{1} ** 32, .disposition = "baseline", .checkpoint = payload };
    try t.expectEqual(durable.CommitResult.committed, try f.store.commitRecord(record));
    const wal = try std.fmt.allocPrint(t.allocator, "{s}-wal", .{f.path});
    defer t.allocator.free(wal);
    const size = (try std.fs.cwd().statFile(wal)).size;
    try t.expect(size >= 16 * 1024 * 1024);
    std.debug.print("one admitted maximum-checkpoint transaction WAL bytes: {d}\n", .{size});
    try t.expectError(error.Busy, f.store.beginReceipt(identity, .{ .us = 100 }, 0));
    try t.expectEqual(@as(?c_int, 5), f.store.last_error_code);
    try t.expectEqual(@as(usize, 0), try f.store.pendingReceiptCount());
    try t.expectError(error.Busy, f.store.commitConsumerInput(manifest, batch(1, "replacement", &delta)));
    var saved = try f.store.consumerManifestSnapshot(t.allocator, manifest);
    defer saved.deinit(t.allocator);
    try t.expectEqualStrings("original", saved.states[0].payload.?);
    try t.expectError(error.Busy, f.store.markDispatched(pending.token(), .{ .prepared_us = 100, .read = clock }));
    try t.expectEqual(@as(u64, 0), try f.store.confirmedEffectEvents());
    var events: [1]history.Event = undefined;
    const page = try f.store.confirmedEffectPage(owner, 0, null, &events);
    const history_bytes = try history_owner.live.encode();
    const empty_batch = consumer.Batch{ .prepared_us = 100, .clock = clock, .deltas = &.{.{ .key = history.key(history_owner.binding), .format_version = history.version, .expected_revision = 1, .payload = &history_bytes }} };
    try t.expectError(error.Busy, f.store.commitConfirmedHistory(history_owner.manifest(), empty_batch, page.token));
    try t.expect(!f.store.reopen_required);
    try t.expectEqual(@as(u64, 1), try f.store.revision("volume"));
    try t.expectError(error.Busy, durable.Store.openRuntime(t.allocator, f.path));
    try t.expectEqual(@as(u64, 1), try f.store.revision("volume"));
    try sql(&reader, "COMMIT;");
    pinned = false;
    f.store.work_remaining = 0;
    try t.expectEqual(@as(i64, 100), (try f.store.beginReceipt(identity, .{ .us = 100 }, 0)).us);
    try t.expect((try std.fs.cwd().statFile(wal)).size < 16 * 1024 * 1024);
    try f.store.commitConsumerInput(manifest, batch(1, "replacement", &delta));
    try f.store.markDispatched(pending.token(), .{ .prepared_us = 100, .read = clock });
    _ = try f.store.settleVerified(pending.token(), .{ .installation = owner.id, .scope_key = pending.scope_key, .fingerprint = [_]u8{8} ** 32, .observed_us = 100, .qualification = .complete_owned, .state = .permanent }, .{ .prepared_us = 100, .read = clock });
    const fresh = try f.store.confirmedEffectPage(owner, 0, null, &events);
    const staged = try history_owner.prepare(fresh, events[0..fresh.count], 100);
    defer staged.release();
    try f.store.commitConfirmedHistory(history_owner.manifest(), try staged.batch(.{ .prepared_us = 100, .read = clock }), fresh.token);
    staged.publish();
    try t.expectEqual(@as(u64, 1), history_owner.live.total_confirmed);
    var reopened = try durable.Store.openRuntime(t.allocator, f.path);
    defer reopened.close();
    try t.expect(!reopened.runtime_limits);
    try t.expectEqualStrings(f.path, reopened.runtime_path.?);
    try reopened.configureRuntimeLimits();
    try t.expectEqual(@as(u64, 1), try reopened.revision("volume"));
    try t.expectEqual(@as(usize, 1), try reopened.pendingReceiptCount());
}

test "native maintenance: bounded path poison and read-only refusal preserve reads" {
    var f = try Fixture.init();
    defer f.deinit();
    f.store.runtime_path = f.path;
    const long = [_]u8{'a'} ** std.fs.max_path_bytes;
    try t.expectError(error.StorageLimit, f.store.maintainWal(&long));
    try t.expectError(error.OpenFailed, f.store.maintainWal("bad\x00path"));
    f.store.reopen_required = true;
    try t.expectError(error.ReopenRequired, f.store.beginReceipt(identity, .{ .us = 100 }, 0));
    try t.expectError(error.ReopenRequired, f.store.maintainWal(f.path));
    f.store.reopen_required = false;
    try sql(&f.store, "PRAGMA query_only=ON;");
    try t.expectError(error.ReadOnly, f.store.beginReceipt(identity, .{ .us = 100 }, 0));
    try t.expectEqual(@as(usize, 0), try f.store.pendingReceiptCount());
    try t.expect(!f.store.reopen_required);
    try sql(&f.store, "PRAGMA query_only=OFF;");
    _ = try f.store.beginReceipt(identity, .{ .us = 100 }, 0);
}

fn fileDigest(path: []const u8) ![32]u8 {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [32768]u8 = undefined;
    while (true) {
        const count = try file.read(&buffer);
        if (count == 0) break;
        hash.update(buffer[0..count]);
    }
    return hash.finalResult();
}

test "native maintenance: foreign overdue WAL is preserved before refusal and on last close" {
    const Db = std.meta.Child(@FieldType(durable.Store, "db"));
    const Native = struct {
        extern "c" fn sqlite3_open_v2([*:0]const u8, *?*Db, c_int, ?[*:0]const u8) c_int;
        extern "c" fn sqlite3_close_v2(*Db) c_int;
        extern "c" fn sqlite3_exec(*Db, [*:0]const u8, ?*anyopaque, ?*anyopaque, ?*?[*:0]u8) c_int;
        extern "c" fn sqlite3_db_config(*Db, c_int, ...) c_int;
    };
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(root);
    const path = try std.fs.path.join(t.allocator, &.{ root, "foreign.sqlite" });
    defer t.allocator.free(path);
    const filename = try t.allocator.dupeZ(u8, path);
    defer t.allocator.free(filename);
    const wal = try std.fmt.allocPrint(t.allocator, "{s}-wal", .{path});
    defer t.allocator.free(wal);
    const created = try std.fs.cwd().createFile(path, .{ .mode = 0o600 });
    created.close();
    var db: ?*Db = null;
    try t.expectEqual(@as(c_int, 0), Native.sqlite3_open_v2(filename, &db, 2 | 0x10000 | 0x01000000, null));
    var opened = true;
    defer if (opened) {
        _ = Native.sqlite3_close_v2(db.?);
    };
    try t.expectEqual(@as(c_int, 0), Native.sqlite3_db_config(db.?, 1006, @as(c_int, 1), @as(?*c_int, null)));
    try t.expectEqual(@as(c_int, 0), Native.sqlite3_exec(db.?, "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; PRAGMA application_id=1234; CREATE TABLE foreign_data(value BLOB); INSERT INTO foreign_data WITH RECURSIVE n(v) AS (SELECT 1 UNION ALL SELECT v+1 FROM n WHERE v<18000) SELECT zeroblob(1024) FROM n;", null, null, null));
    const hard_limit = @extern(*const fn (i64) callconv(.c) i64, .{ .name = "sqlite3_hard_heap_limit64" });
    const prior = hard_limit(-1);
    defer _ = hard_limit(prior);
    const wal_size = (try std.fs.cwd().statFile(wal)).size;
    try t.expect(wal_size >= 16 * 1024 * 1024);
    const before = try fileDigest(wal);
    try t.expectError(error.ForeignDatabase, durable.Store.openRuntime(t.allocator, path));
    try t.expectEqual(wal_size, (try std.fs.cwd().statFile(wal)).size);
    try t.expectEqual(before, try fileDigest(wal));
    try t.expectEqual(@as(c_int, 0), Native.sqlite3_close_v2(db.?));
    opened = false;
    const database_before = try fileDigest(path);
    try t.expectError(error.ForeignDatabase, durable.Store.openRuntime(t.allocator, path));
    try t.expectEqual(wal_size, (try std.fs.cwd().statFile(wal)).size);
    try t.expectEqual(before, try fileDigest(wal));
    try t.expectEqual(database_before, try fileDigest(path));
}

fn recordFor(id: durable.ReceiptIdentity, revision: u64) durable.Record {
    return .{ .jail = id.jail, .source = id.source, .occurrence = id.occurrence, .cursor = id.cursor, .raw_hash = id.raw_hash, .receipt = .{ .time = .{ .us = 100 }, .generation = id.generation }, .expected_revision = revision, .disposition = "fixture", .checkpoint = "original-checkpoint" };
}
fn commitObserved(store: *durable.Store, id: durable.ReceiptIdentity, revision: u64) !void {
    _ = try store.beginReceipt(id, .{ .us = 100 }, revision);
    try t.expectEqual(durable.CommitResult.committed, try store.commitRecord(recordFor(id, revision)));
}
fn reopen(f: *Fixture) !void {
    f.store.close();
    f.store = try durable.Store.open(t.allocator, f.path);
    try f.store.enableReceipts(8);
}

test "native maintenance: schema14 migration pins legacy and orders only new bound records" {
    var f = try Fixture.init();
    defer f.deinit();
    const legacy = durable.Record{ .jail = "legacy", .source = "inode", .occurrence = "before", .cursor = "opaque-old", .raw_hash = [_]u8{1} ** 32, .disposition = "source-checkpoint", .checkpoint = "legacy" };
    _ = try f.store.commitRecord(legacy);
    try commitObserved(&f.store, identity, 0);
    try t.expectError(error.MaintenanceStorageRequired, f.store.recordSequence(identity.jail, identity.source, identity.occurrence));
    f.store.fail_at = .before_maintenance_schema_commit;
    try t.expectError(error.InjectedFailure, f.store.enableMaintenance());
    f.store.fail_at = null;
    try t.expectEqual(@as(i64, 13), f.store.schema_version);
    try reopen(&f);
    try f.store.enableMaintenance();
    try f.store.enableMaintenance();
    try t.expectEqual(@as(i64, 14), f.store.schema_version);
    try t.expectEqual(@as(?durable.Store.RecordSequence, null), try f.store.recordSequence("legacy", "inode", "before"));
    try t.expectEqual(@as(?durable.Store.RecordSequence, null), try f.store.recordSequence(identity.jail, identity.source, identity.occurrence));
    var next = identity;
    next.occurrence = "z-last-lexically";
    next.cursor = "opaque-z";
    try commitObserved(&f.store, next, 1);
    try t.expectEqual(@as(u64, 1), (try f.store.recordSequence(next.jail, next.source, next.occurrence)).?.sequence);
    next.occurrence = "a-first-lexically";
    next.cursor = "opaque-a";
    try commitObserved(&f.store, next, 2);
    try t.expectEqual(@as(u64, 2), (try f.store.recordSequence(next.jail, next.source, next.occurrence)).?.sequence);
    try t.expectEqual(durable.CommitResult.already_committed, try f.store.commitRecord(recordFor(next, 0)));
    const state = (try f.store.sourceMaintenance(next.jail, next.source, generation)).?;
    try t.expectEqual(@as(u64, 2), state.head_sequence);
    try t.expectEqual(@as(u64, 1), state.reject_below_sequence);
    try t.expectEqual(@as(u64, 0), state.cleanup_revision);
    try t.expectEqual(@as(u64, 0), state.sweep_sequence);
    try reopen(&f);
    try t.expectEqualDeep(state, (try f.store.sourceMaintenance(next.jail, next.source, generation)).?);
    try t.expectError(error.InvalidMaintenanceState, f.store.fixtureReplayGuard("legacy", "inode", "before"));
}

test "native maintenance: source sequence receipt and cursor commit or roll back together" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.store.enableMaintenance();
    _ = try f.store.beginReceipt(identity, .{ .us = 100 }, 0);
    for ([_]durable.CommitStage{ .after_source_sequence, .after_record, .after_checkpoint, .after_receipt_delete, .before_commit }) |stage| {
        f.store.fail_at = stage;
        try t.expectError(error.InjectedFailure, f.store.commitRecord(recordFor(identity, 0)));
        f.store.fail_at = null;
        try t.expectEqual(@as(?durable.Store.SourceMaintenance, null), try f.store.sourceMaintenance(identity.jail, identity.source, generation));
        try t.expectEqual(@as(?durable.Store.RecordSequence, null), try f.store.recordSequence(identity.jail, identity.source, identity.occurrence));
        try t.expectEqual(@as(u64, 0), try f.store.revision(identity.jail));
        try t.expectEqual(@as(i64, 100), (try f.store.pendingReceipt(identity)).?.us);
    }
    try reopen(&f);
    _ = try f.store.commitRecord(recordFor(identity, 0));
    try t.expectEqual(@as(usize, 0), try f.store.pendingReceiptCount());
    try t.expectEqual(@as(u64, 1), (try f.store.recordSequence(identity.jail, identity.source, identity.occurrence)).?.sequence);
    var other = identity;
    other.generation = [_]u8{8} ** 32;
    other.occurrence = "new-generation";
    other.cursor = "new-anchor";
    try commitObserved(&f.store, other, 1);
    try t.expectEqual(@as(u64, 1), (try f.store.sourceMaintenance(identity.jail, identity.source, generation)).?.head_sequence);
    try t.expectEqual(@as(u64, 1), (try f.store.sourceMaintenance(other.jail, other.source, other.generation)).?.head_sequence);
    const policy = @import("core/native_retry.zig").Policy{ .maxretry = 2, .window_us = 1000, .duration = .{ .finite_us = 1000 }, .max_subjects = 8 };
    try f.store.admitRetry("baseline", generation, policy);
    const baseline = durable.Record{ .jail = "baseline", .source = "initial-inode", .occurrence = "start", .cursor = "head", .raw_hash = [_]u8{0} ** 32, .disposition = "source-checkpoint", .checkpoint = "state", .native_retry = .{ .generation = generation, .policy = policy } };
    _ = try f.store.commitRecord(baseline);
    try t.expectEqual(@as(u64, 1), (try f.store.recordSequence(baseline.jail, baseline.source, baseline.occurrence)).?.sequence);
    try f.store.fixtureReplayGuard(baseline.jail, baseline.source, baseline.occurrence);
    try t.expectError(error.PrunedReplay, f.store.commitRecord(baseline));
}

test "native maintenance: compact guard refuses full identity replay before and after detail removal" {
    var f = try Fixture.init();
    defer f.deinit();
    var stale = try durable.Store.open(t.allocator, f.path);
    defer stale.close();
    try f.store.enableMaintenance();
    try commitObserved(&f.store, identity, 0);
    var next = identity;
    next.occurrence = "current-anchor";
    next.cursor = "current-position";
    try commitObserved(&f.store, next, 1);
    f.store.fail_at = .after_replay_guard;
    try t.expectError(error.InjectedFailure, f.store.fixtureReplayGuard(identity.jail, identity.source, identity.occurrence));
    f.store.fail_at = null;
    try t.expect(try f.store.hasRecord(identity.jail, identity.source, identity.occurrence, identity.raw_hash, identity.cursor));
    try f.store.fixtureReplayGuard(identity.jail, identity.source, identity.occurrence);
    try t.expectError(error.PrunedReplay, stale.hasRecord(identity.jail, identity.source, identity.occurrence, identity.raw_hash, identity.cursor));
    try t.expectError(error.PrunedReplay, f.store.hasRecord(identity.jail, identity.source, identity.occurrence, identity.raw_hash, identity.cursor));
    try t.expectError(error.PrunedReplay, f.store.beginReceipt(identity, .{ .us = 999 }, 2));
    try t.expectError(error.PrunedReplay, f.store.committedReceipt(identity));
    try t.expectError(error.PrunedReplay, f.store.commitRecord(recordFor(identity, 2)));
    try sql(&f.store, "DELETE FROM records WHERE jail='receipt' AND source='file' AND occurrence='original';");
    try reopen(&f);
    try t.expectError(error.PrunedReplay, f.store.hasRecord(identity.jail, identity.source, identity.occurrence, identity.raw_hash, identity.cursor));
    try t.expectError(error.PrunedReplay, f.store.beginReceipt(identity, .{ .us = 999 }, 2));
    try t.expectError(error.PrunedReplay, f.store.committedReceipt(identity));
    try t.expectError(error.PrunedReplay, f.store.commitRecord(recordFor(identity, 2)));
    var altered = identity;
    altered.raw_hash[0] ^= 1;
    try t.expectError(error.OccurrenceConflict, f.store.hasRecord(altered.jail, altered.source, altered.occurrence, altered.raw_hash, altered.cursor));
    altered = identity;
    altered.cursor = "changed";
    try t.expectError(error.OccurrenceConflict, f.store.committedReceipt(altered));
    altered = identity;
    altered.generation = [_]u8{8} ** 32;
    try t.expectError(error.OccurrenceConflict, f.store.beginReceipt(altered, .{ .us = 100 }, 2));
    var wrong_receipt = recordFor(identity, 2);
    wrong_receipt.receipt.?.time.us = 101;
    try t.expectError(error.OccurrenceConflict, f.store.commitRecord(wrong_receipt));
    try t.expectEqual(@as(usize, 0), try f.store.pendingReceiptCount());
    try t.expectEqual(@as(u64, 2), try f.store.revision(identity.jail));
    const current_cursor = (try f.store.sourceCursor(t.allocator, identity.jail, identity.source)).?;
    defer t.allocator.free(current_cursor);
    try t.expectEqualStrings(next.cursor, current_cursor);
    next.occurrence = "following-event";
    next.cursor = "following-position";
    try commitObserved(&f.store, next, 2);
    try t.expectEqual(@as(u64, 3), (try f.store.sourceMaintenance(next.jail, next.source, generation)).?.head_sequence);
}

test "native maintenance: checked sequence bounds and corrupt missing heads never reset" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.store.enableMaintenance();
    try commitObserved(&f.store, identity, 0);
    var next = identity;
    next.occurrence = "next";
    next.cursor = "next-position";
    _ = try f.store.beginReceipt(next, .{ .us = 100 }, 1);
    try sql(&f.store, "UPDATE source_maintenance SET head_sequence=9223372036854775806; UPDATE records SET source_sequence=9223372036854775806;");
    try t.expectError(error.StorageLimit, f.store.commitRecord(recordFor(next, 1)));
    try t.expectEqual(@as(u64, 1), try f.store.revision(identity.jail));
    try sql(&f.store, "DELETE FROM source_maintenance;");
    try t.expectError(error.InvalidMaintenanceState, f.store.recordSequence(identity.jail, identity.source, identity.occurrence));
    try t.expectError(error.InvalidMaintenanceState, f.store.commitRecord(recordFor(next, 1)));
    try sql(&f.store, "INSERT INTO source_maintenance VALUES('receipt','file',X'0909090909090909090909090909090909090909090909090909090909090909',1,1,0,0);");
    try sql(&f.store, "PRAGMA ignore_check_constraints=ON; UPDATE source_maintenance SET cleanup_revision=-1;");
    try t.expectError(error.InvalidMaintenanceState, f.store.sourceMaintenance(identity.jail, identity.source, generation));
    try sql(&f.store, "UPDATE source_maintenance SET cleanup_revision=0; UPDATE records SET source_sequence=1; PRAGMA ignore_check_constraints=OFF;");
    try sql(&f.store, "PRAGMA query_only=ON;");
    try t.expectError(error.ReadOnly, f.store.commitRecord(recordFor(next, 1)));
    try sql(&f.store, "PRAGMA query_only=OFF;");
    _ = try f.store.commitRecord(recordFor(next, 1));
    var failing = std.testing.FailingAllocator.init(t.allocator, .{ .fail_index = 0 });
    const original_allocator = f.store.allocator;
    f.store.allocator = failing.allocator();
    defer f.store.allocator = original_allocator;
    try t.expectEqual(@as(u64, 2), (try f.store.sourceMaintenance(next.jail, next.source, generation)).?.head_sequence);
    try t.expectEqual(@as(u64, 2), (try f.store.recordSequence(next.jail, next.source, next.occurrence)).?.sequence);
    try t.expect(try f.store.hasRecord(next.jail, next.source, next.occurrence, next.raw_hash, next.cursor));
    try t.expect(!failing.has_induced_failure);
}

test "native maintenance: SQLite allocation failure during guard lookup preserves receipt boundary" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.store.enableMaintenance();
    try commitObserved(&f.store, identity, 0);
    try f.store.fixtureReplayGuard(identity.jail, identity.source, identity.occurrence);
    const Prepare = @TypeOf(f.store.api.prepare);
    const Parameters = @typeInfo(@typeInfo(Prepare).pointer.child).@"fn".params;
    const Fault = struct {
        var original: Prepare = undefined;
        fn prepare(db: Parameters[0].type.?, query: [*:0]const u8, length: c_int, statement: Parameters[3].type.?, tail: ?*?[*:0]const u8) callconv(.c) c_int {
            if (std.mem.startsWith(u8, std.mem.span(query), "SELECT generation,identity_key,receipt_us,source_sequence FROM replay_guards")) {
                statement.* = null;
                return 7;
            }
            return original(db, query, length, statement, tail);
        }
    };
    Fault.original = f.store.api.prepare;
    f.store.api.prepare = Fault.prepare;
    try t.expectError(error.OutOfMemory, f.store.beginReceipt(identity, .{ .us = 200 }, 1));
    f.store.api.prepare = Fault.original;
    try t.expectEqual(@as(usize, 0), try f.store.pendingReceiptCount());
    try t.expectEqual(@as(u64, 1), try f.store.revision(identity.jail));
    try t.expectError(error.PrunedReplay, f.store.beginReceipt(identity, .{ .us = 200 }, 1));
}

test "native maintenance: killed schema record and guard commits expose complete boundaries" {
    const DbPointer = @TypeOf(@as(durable.Store, undefined).db);
    const Exec = @TypeOf(@as(durable.Store, undefined).api.exec);
    const Fault = struct {
        var actual: Exec = undefined;
        var after: bool = false;
        fn exec(db: DbPointer, query: [*:0]const u8, callback: ?*anyopaque, context: ?*anyopaque, message: ?*?[*:0]u8) callconv(.c) c_int {
            if (!std.mem.eql(u8, std.mem.span(query), "COMMIT;")) return actual(db, query, callback, context, message);
            if (after) {
                const rc = actual(db, query, callback, context, message);
                if (rc != 0) std.process.exit(5);
            }
            std.posix.kill(std.os.linux.getpid(), std.posix.SIG.KILL) catch std.process.exit(6);
            std.process.exit(7);
        }
    };
    for (0..3) |operation| for ([_]bool{ false, true }) |after| {
        var f = try Fixture.init();
        defer f.deinit();
        if (operation != 0) try f.store.enableMaintenance();
        if (operation == 1) _ = try f.store.beginReceipt(identity, .{ .us = 100 }, 0);
        if (operation == 2) try commitObserved(&f.store, identity, 0);
        const pid = try std.posix.fork();
        if (pid == 0) {
            var child = durable.Store.open(std.heap.page_allocator, f.path) catch std.process.exit(2);
            child.enableReceipts(8) catch std.process.exit(2);
            Fault.actual = child.api.exec;
            Fault.after = after;
            child.api.exec = Fault.exec;
            switch (operation) {
                0 => child.enableMaintenance() catch std.process.exit(3),
                1 => _ = child.commitRecord(recordFor(identity, 0)) catch std.process.exit(3),
                2 => child.fixtureReplayGuard(identity.jail, identity.source, identity.occurrence) catch std.process.exit(3),
                else => std.process.exit(4),
            }
            std.process.exit(8);
        }
        const result = std.posix.waitpid(pid, 0);
        try t.expectEqual(@as(u32, std.posix.SIG.KILL), result.status);
        try reopen(&f);
        switch (operation) {
            0 => {
                try t.expectEqual(@as(i64, if (after) 14 else 13), f.store.schema_version);
                try f.store.enableMaintenance();
            },
            1 => {
                try t.expectEqual(@as(u64, @intFromBool(after)), try f.store.revision(identity.jail));
                try t.expectEqual(@as(usize, @intFromBool(!after)), try f.store.pendingReceiptCount());
                const ordering = try f.store.recordSequence(identity.jail, identity.source, identity.occurrence);
                try t.expectEqual(after, ordering != null);
                if (ordering) |value| try t.expectEqual(@as(u64, 1), value.sequence);
            },
            2 => if (after) {
                try t.expectError(error.PrunedReplay, f.store.committedReceipt(identity));
            } else {
                try t.expectEqual(@as(i64, 100), (try f.store.committedReceipt(identity)).?.us);
            },
            else => unreachable,
        }
    };
}

test "native maintenance: guard sequence prevents lowered head reuse after detail pruning" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.store.enableMaintenance();
    try commitObserved(&f.store, identity, 0);
    var marked = identity;
    marked.occurrence = "guarded";
    marked.cursor = "guarded-position";
    try commitObserved(&f.store, marked, 1);
    try f.store.fixtureReplayGuard(marked.jail, marked.source, marked.occurrence);
    try sql(&f.store, "DELETE FROM records WHERE occurrence='guarded'; UPDATE source_maintenance SET head_sequence=1; UPDATE source_cursors SET occurrence='original',cursor=CAST('next' AS BLOB);");
    var next = identity;
    next.occurrence = "new-after-corruption";
    next.cursor = "new-position";
    _ = try f.store.beginReceipt(next, .{ .us = 100 }, 2);
    try t.expectError(error.InvalidMaintenanceState, f.store.commitRecord(recordFor(next, 2)));
    try t.expectEqual(@as(u64, 1), (try f.store.sourceMaintenance(identity.jail, identity.source, generation)).?.head_sequence);
    try t.expectEqual(@as(u64, 2), try f.store.revision(identity.jail));
    try t.expectEqual(@as(i64, 100), (try f.store.pendingReceipt(next)).?.us);
    try t.expectEqual(@as(?durable.Store.RecordSequence, null), try f.store.recordSequence(next.jail, next.source, next.occurrence));
    try sql(&f.store, "UPDATE source_maintenance SET head_sequence=2;");
    try t.expectError(error.PrunedReplay, f.store.committedReceipt(marked));
    try reopen(&f);
    _ = try f.store.commitRecord(recordFor(next, 2));
    try t.expectEqual(@as(u64, 3), (try f.store.recordSequence(next.jail, next.source, next.occurrence)).?.sequence);
}

const CleanupClock = struct {
    now: i64 = 10000,
    fn read(context: ?*anyopaque) i64 {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        return self.now;
    }
    fn value(self: *@This()) effect.Clock {
        return .{ .prepared_us = self.now, .context = self, .read = read };
    }
};
fn cleanupFence(store: *durable.Store, id: durable.ReceiptIdentity, now: *CleanupClock) !durable.Store.CleanupFence {
    return .{ .jail = id.jail, .source = id.source, .generation = id.generation, .jail_revision = try store.revision(id.jail), .consumer_revision = try store.maintenanceConsumerRevision(), .effect_revision = try store.maintenanceEffectRevision(), .clock = now.value(), .preparations = .released };
}
fn validateCleanup(store: *durable.Store) !durable.Store.MaintenanceValidation {
    var cursor = durable.Store.MaintenanceValidation{};
    for (0..1024) |_| if (try store.validateMaintenanceTurn(&cursor)) {
        try store.finishMaintenanceValidation(&cursor);
        return cursor;
    };
    return error.TestValidationLimit;
}
fn setupCleanup(f: *Fixture) !void {
    try f.store.enableMaintenance();
    try f.store.enableCleanup();
}

test "native maintenance: production mark delete retains guard and current anchor across restart" {
    var f = try Fixture.init();
    defer f.deinit();
    try setupCleanup(&f);
    var now = CleanupClock{};
    try commitObserved(&f.store, identity, 0);
    var next = identity;
    next.occurrence = "current";
    next.cursor = "current-position";
    try commitObserved(&f.store, next, 1);
    _ = try validateCleanup(&f.store);
    const fence = try cleanupFence(&f.store, identity, &now);
    const initial = (try f.store.sourceMaintenance(identity.jail, identity.source, generation)).?;
    f.store.fail_at = .after_cleanup_mark;
    try t.expectError(error.InjectedFailure, f.store.cleanupAdvance(fence, initial, 2));
    f.store.fail_at = null;
    try t.expect(try f.store.hasRecord(identity.jail, identity.source, identity.occurrence, identity.raw_hash, identity.cursor));
    try t.expectEqualDeep(initial, (try f.store.sourceMaintenance(identity.jail, identity.source, generation)).?);
    const token = (try f.store.cleanupAdvance(fence, initial, 2)).?;
    try t.expectEqual(@as(u64, 2), token.state.reject_below_sequence);
    try t.expectError(error.PrunedReplay, f.store.committedReceipt(identity));
    try t.expect(try f.store.hasRecord(next.jail, next.source, next.occurrence, next.raw_hash, next.cursor));
    _ = try validateCleanup(&f.store);
    try reopen(&f);
    const resumed = (try f.store.cleanupResume(identity.jail, identity.source, generation)).?;
    try t.expectEqualDeep(token, resumed);
    const resumed_fence = try cleanupFence(&f.store, identity, &now);
    f.store.fail_at = .after_cleanup_delete;
    try t.expectError(error.InjectedFailure, f.store.cleanupDelete(resumed_fence, resumed));
    f.store.fail_at = null;
    try t.expectEqual(@as(u64, 1), (try f.store.recordSequence(identity.jail, identity.source, identity.occurrence)).?.sequence);
    const progress = try f.store.cleanupDelete(resumed_fence, resumed);
    try t.expectEqual(@as(u8, 1), progress.deleted_rows);
    try t.expect(!progress.more);
    try t.expectEqual(@as(u64, 1), progress.state.sweep_sequence);
    try t.expectEqual(@as(?durable.Store.RecordSequence, null), try f.store.recordSequence(identity.jail, identity.source, identity.occurrence));
    try t.expectError(error.PrunedReplay, f.store.beginReceipt(identity, .{ .us = now.now }, 2));
    try t.expectError(error.StaleMaintenance, f.store.cleanupDelete(resumed_fence, resumed));
    try t.expectEqual(@as(u64, 2), try f.store.revision(identity.jail));
    _ = try validateCleanup(&f.store);
    try reopen(&f);
    _ = try validateCleanup(&f.store);
    try t.expectEqual(@as(?durable.Store.CleanupToken, null), try f.store.cleanupResume(identity.jail, identity.source, generation));
    next.occurrence = "after-cleanup";
    next.cursor = "after-cleanup-position";
    try commitObserved(&f.store, next, 2);
    try t.expectEqual(@as(u64, 3), (try f.store.recordSequence(next.jail, next.source, next.occurrence)).?.sequence);
}

test "native maintenance: unenforceable detection does not pin cleanup rejection boundary" {
    var f = try Fixture.init();
    defer f.deinit();
    try setupCleanup(&f);
    var now = CleanupClock{};
    const detection = @import("core/native_detection_record.zig");
    var older = recordFor(identity, 0);
    older.native_time_outcome = .{ .eligible = .{ .timestamp = .{ .us = 100 }, .receipt = .{ .us = 100 }, .origin = .event, .original = .{ .us = 100 } } };
    older.disposition = older.native_time_outcome.?.disposition();
    older.native_detection = .{ .kind = .unenforceable, .generation = generation, .filter = try detection.Name.init("fixture"), .pattern = try detection.Name.init("failure"), .pattern_index = 0, .subject = .{ .v4 = .{ 127, 0, 0, 1 } } };
    _ = try f.store.beginReceipt(identity, .{ .us = 100 }, 0);
    try t.expectEqual(durable.CommitResult.committed, try f.store.commitRecord(older));
    var anchor = identity;
    anchor.occurrence = "current-anchor";
    anchor.cursor = "current-anchor";
    try commitObserved(&f.store, anchor, 1);

    const stored = (try f.store.nativeDetection(identity.jail, identity.source, identity.occurrence)).?;
    try t.expectEqual(detection.Kind.unenforceable, stored.kind);
    try t.expectEqualDeep(detection.Subject{ .v4 = .{ 127, 0, 0, 1 } }, stored.subject.?);
    const initial = (try f.store.sourceMaintenance(identity.jail, identity.source, generation)).?;
    const token = (try f.store.cleanupAdvance(try cleanupFence(&f.store, identity, &now), initial, 2)).?;
    try t.expectEqual(@as(u64, 2), token.state.reject_below_sequence);
    try t.expectEqualDeep(stored, (try f.store.nativeDetection(identity.jail, identity.source, identity.occurrence)).?);
}

test "native maintenance: physical delete budget includes children and resumes whole groups" {
    var f = try Fixture.init();
    defer f.deinit();
    try setupCleanup(&f);
    var now = CleanupClock{};
    var ids: [5]durable.ReceiptIdentity = undefined;
    const names = [_][]const u8{ "first", "second", "third", "fourth", "anchor" };
    for (&ids, names, 0..) |*id, name, i| {
        id.* = identity;
        id.occurrence = name;
        id.cursor = name;
        try commitObserved(&f.store, id.*, i);
    }
    for (names[0..4]) |name| for (0..16) |ordinal| {
        var query: [1024]u8 = undefined;
        const value = try std.fmt.bufPrintZ(&query, "INSERT INTO record_detections(jail,source,occurrence,ordinal,version,kind,generation,filter) VALUES('receipt','file','{s}',{d},1,1,zeroblob(32),'fixture');", .{ name, ordinal });
        try sql(&f.store, value);
        const decision = try std.fmt.bufPrintZ(&query, "INSERT INTO retry_decisions VALUES('receipt','file','{s}',4,X'C00002{x:0>2}',100,200,1,0);", .{ name, ordinal });
        try sql(&f.store, decision);
    };
    const fence = try cleanupFence(&f.store, identity, &now);
    const token = (try f.store.cleanupAdvance(fence, (try f.store.sourceMaintenance(identity.jail, identity.source, generation)).?, 5)).?;
    f.store.fail_at = .after_cleanup_delete;
    try t.expectError(error.InjectedFailure, f.store.cleanupDelete(fence, token));
    f.store.fail_at = null;
    var progress = try f.store.cleanupDelete(fence, token);
    try t.expectEqual(@as(u8, 33), progress.deleted_rows);
    try t.expect(progress.more);
    var total: usize = progress.deleted_rows;
    try reopen(&f);
    for (0..3) |_| {
        const resumed = (try f.store.cleanupResume(identity.jail, identity.source, generation)).?;
        progress = try f.store.cleanupDelete(try cleanupFence(&f.store, identity, &now), resumed);
        try t.expectEqual(@as(u8, 33), progress.deleted_rows);
        total += progress.deleted_rows;
    }
    try t.expectEqual(@as(usize, 132), total);
    try t.expect(!progress.more);
    try t.expect(try f.store.hasRecord(ids[4].jail, ids[4].source, ids[4].occurrence, ids[4].raw_hash, ids[4].cursor));
    _ = try validateCleanup(&f.store);
}

test "native maintenance: held preparation pending action and stale fences block marking" {
    var f = try Fixture.init();
    defer f.deinit();
    try setupCleanup(&f);
    var now = CleanupClock{};
    try commitObserved(&f.store, identity, 0);
    var next = identity;
    next.occurrence = "anchor";
    next.cursor = "anchor";
    try commitObserved(&f.store, next, 1);
    const state = (try f.store.sourceMaintenance(identity.jail, identity.source, generation)).?;
    var fence = try cleanupFence(&f.store, identity, &now);
    fence.preparations = .held;
    try t.expectError(error.MaintenancePinned, f.store.cleanupAdvance(fence, state, 1));
    fence.preparations = .released;
    fence.consumer_revision += 1;
    try t.expectError(error.StaleMaintenance, f.store.cleanupAdvance(fence, state, 1));
    fence = try cleanupFence(&f.store, identity, &now);
    try sql(&f.store, "INSERT INTO action_intents(jail,source,occurrence,payload) VALUES('receipt','file','original',X'00');");
    try t.expectEqual(@as(?durable.Store.CleanupToken, null), try f.store.cleanupAdvance(fence, state, 1));
    try sql(&f.store, "DELETE FROM action_intents;");
    next.occurrence = "pending";
    _ = try f.store.beginReceipt(next, .{ .us = 100 }, 2);
    try t.expectError(error.MaintenancePinned, f.store.cleanupAdvance(fence, state, 1));
    _ = try f.store.commitRecord(recordFor(next, 2));
    try t.expectError(error.StaleMaintenance, f.store.cleanupAdvance(fence, state, 1));
}

test "native maintenance: retired retries preserve counters and original clocks on reactivation" {
    var f = try Fixture.init();
    defer f.deinit();
    try setupCleanup(&f);
    var now = CleanupClock{ .now = 500 };
    const retry = @import("core/native_retry.zig");
    const policy = retry.Policy{ .maxretry = 1, .window_us = 100, .duration = .{ .finite_us = 100 }, .max_subjects = 1 };
    try f.store.admitRetry(identity.jail, generation, policy);
    const subject = @import("core/native_detection_record.zig").Subject{ .v4 = .{ 192, 0, 2, 91 } };
    try sql(&f.store, "UPDATE retry_clock SET floor_us=100; INSERT INTO retry_states VALUES('receipt',4,X'C000025B',100,200,7,X'');");
    const candidate = (try f.store.retryRetirementCandidate(identity.jail, null)).?;
    try t.expectEqualDeep(subject, candidate.subject);
    var fence = try cleanupFence(&f.store, identity, &now);
    f.store.fail_at = .after_retry_retire;
    try t.expectError(error.InjectedFailure, f.store.retireRetrySubject(fence, candidate));
    f.store.fail_at = null;
    try t.expectEqual(@as(u64, 7), (try f.store.retryState(identity.jail, subject)).?.decisions);
    try t.expect(try f.store.retireRetrySubject(fence, candidate));
    try t.expectEqual(@as(?durable.Store.RetryRetirementCandidate, null), try f.store.retryRetirementCandidate(identity.jail, null));
    const restored = (try f.store.retryState(identity.jail, subject)).?;
    try t.expectEqual(@as(i64, 100), restored.last_processed_us);
    try t.expectEqual(@as(u64, 7), restored.decisions);
    try t.expectEqual(@as(u16, 0), restored.count);
    var active: [1]durable.Store.ActiveDecision = undefined;
    try t.expectEqual(@as(u64, 7), (try f.store.retrySummary(identity.jail, 500, &active)).decisions);
    _ = try validateCleanup(&f.store);
    try reopen(&f);
    try t.expectEqual(@as(i64, 500), (try f.store.admissionClock()).?.us);
    const detection = @import("core/native_detection_record.zig");
    const outcome = @import("core/source_time_policy.zig").Result{ .eligible = .{ .timestamp = .{ .us = 600 }, .receipt = .{ .us = 600 }, .origin = .event, .original = .{ .us = 600 } } };
    var record = recordFor(identity, 0);
    record.receipt.?.time.us = 600;
    record.native_time_outcome = outcome;
    record.disposition = outcome.disposition();
    record.native_detection = .{ .kind = .candidate, .generation = generation, .filter = try detection.Name.init("fixture"), .pattern = try detection.Name.init("fixture"), .pattern_index = 0, .subject = subject };
    record.native_retry = .{ .generation = generation, .policy = policy, .processing_us = 600 };
    _ = try f.store.beginReceipt(identity, .{ .us = 600 }, 0);
    _ = try f.store.commitRecord(record);
    const next_state = (try f.store.retryState(identity.jail, subject)).?;
    try t.expectEqual(@as(u64, 8), next_state.decisions);
    now.now = 800;
    fence = try cleanupFence(&f.store, identity, &now);
    const next_candidate = (try f.store.retryRetirementCandidate(identity.jail, null)).?;
    try t.expect(try f.store.retireRetrySubject(fence, next_candidate));
    _ = try validateCleanup(&f.store);
}

test "native maintenance: startup validation refuses broken guard floor and stale cursor" {
    var f = try Fixture.init();
    defer f.deinit();
    try setupCleanup(&f);
    var now = CleanupClock{};
    try commitObserved(&f.store, identity, 0);
    var cursor = try validateCleanup(&f.store);
    var next = identity;
    next.occurrence = "anchor";
    next.cursor = "anchor";
    try commitObserved(&f.store, next, 1);
    try t.expectError(error.StaleMaintenance, f.store.finishMaintenanceValidation(&cursor));
    const fence = try cleanupFence(&f.store, identity, &now);
    const token = (try f.store.cleanupAdvance(fence, (try f.store.sourceMaintenance(identity.jail, identity.source, generation)).?, 1)).?;
    _ = try validateCleanup(&f.store);
    try sql(&f.store, "DELETE FROM replay_guards;");
    cursor = .{};
    try t.expectError(error.InvalidMaintenanceState, f.store.validateMaintenanceTurn(&cursor));
    try t.expectEqual(@as(?u64, null), cursor.revision);
    try t.expectError(error.InvalidMaintenanceState, f.store.cleanupDelete(fence, token));
    try t.expectEqual(@as(u64, 1), (try f.store.recordSequence(identity.jail, identity.source, identity.occurrence)).?.sequence);
}

fn candidateRecord(id: durable.ReceiptIdentity, revision: u64, at: i64, policy: @import("core/native_retry.zig").Policy) !durable.Record {
    const detection = @import("core/native_detection_record.zig");
    var record = recordFor(id, revision);
    record.receipt.?.time.us = at;
    record.native_time_outcome = .{ .eligible = .{ .timestamp = .{ .us = at }, .receipt = .{ .us = at }, .origin = .event, .original = .{ .us = at } } };
    record.disposition = record.native_time_outcome.?.disposition();
    record.native_detection = .{ .kind = .candidate, .generation = generation, .filter = try detection.Name.init("fixture"), .pattern = try detection.Name.init("fixture"), .pattern_index = 0, .subject = .{ .v4 = .{ 192, 0, 2, 91 } } };
    record.native_retry = .{ .generation = generation, .policy = policy, .processing_us = at };
    return record;
}

test "native maintenance: inclusive retry window pins detail and retirement until after endpoint" {
    var f = try Fixture.init();
    defer f.deinit();
    try setupCleanup(&f);
    const policy = @import("core/native_retry.zig").Policy{ .maxretry = 2, .window_us = 100, .duration = .{ .finite_us = 100 }, .max_subjects = 8 };
    try f.store.admitRetry(identity.jail, generation, policy);
    _ = try f.store.beginReceipt(identity, .{ .us = 100 }, 0);
    _ = try f.store.commitRecord(try candidateRecord(identity, 0, 100, policy));
    var baseline = recordFor(identity, 1);
    baseline.receipt = null;
    baseline.occurrence = "anchor";
    baseline.cursor = "anchor";
    baseline.native_retry = .{ .generation = generation, .policy = policy };
    _ = try f.store.commitRecord(baseline);
    var now = CleanupClock{ .now = 200 };
    const candidate = (try f.store.retryRetirementCandidate(identity.jail, null)).?;
    var fence = try cleanupFence(&f.store, identity, &now);
    const head = (try f.store.sourceMaintenance(identity.jail, identity.source, generation)).?;
    try t.expectEqual(@as(?durable.Store.CleanupToken, null), try f.store.cleanupAdvance(fence, head, 1));
    try t.expect(!try f.store.retireRetrySubject(fence, candidate));
    now.now = 201;
    fence = try cleanupFence(&f.store, identity, &now);
    _ = (try f.store.cleanupAdvance(fence, head, 1)).?;
    try t.expect(try f.store.retireRetrySubject(fence, candidate));
    var reversed = identity;
    reversed.occurrence = "reversed-processing";
    reversed.cursor = "later-position";
    _ = try f.store.beginReceipt(reversed, .{ .us = 150 }, 2);
    try t.expectError(error.ReceiptClockReversed, f.store.commitRecord(try candidateRecord(reversed, 2, 150, policy)));
    try t.expectEqual(@as(u64, 2), try f.store.revision(identity.jail));
}

test "native maintenance: live physical effect and missing caught-up history pin cleanup" {
    var f = try Fixture.init();
    defer f.deinit();
    try setupCleanup(&f);
    const policy = @import("core/native_retry.zig").Policy{ .maxretry = 2, .window_us = 100, .duration = .{ .finite_us = 100 }, .max_subjects = 8 };
    try f.store.admitRetry(identity.jail, generation, policy);
    _ = try f.store.beginReceipt(identity, .{ .us = 100 }, 0);
    _ = try f.store.commitRecord(try candidateRecord(identity, 0, 100, policy));
    var baseline = recordFor(identity, 1);
    baseline.receipt = null;
    baseline.occurrence = "anchor";
    baseline.cursor = "anchor";
    baseline.native_retry = .{ .generation = generation, .policy = policy };
    _ = try f.store.commitRecord(baseline);
    const installation = try effect.Installation.init([_]u8{4} ** 16, .nftables, "maintenance-history");
    try f.store.admitInstallation(installation, .{ .selector = installation.selector(), .disposition = .verified_absent });
    var owner = try history.Consumer.init(installation, effect.hashParts("fail2zig-native-confirmed-history-v1", &.{}));
    const initial = try owner.prepareInitial();
    defer initial.release();
    try f.store.bootstrapConfirmedHistory(owner.manifest(), try initial.batch(.{ .prepared_us = 100, .read = clock }), installation);
    initial.publish();
    _ = try f.store.setOwner(.{ .scope = try effect.Scope.host(.{ .v4 = .{ 192, 0, 2, 91 } }), .jail = "other-owner", .generation = generation, .decision_id = [_]u8{5} ** 32, .expected_revision = 0, .lease = .permanent, .decided_us = 100 }, .{ .prepared_us = 100, .read = clock });
    var now = CleanupClock{};
    var fence = try cleanupFence(&f.store, identity, &now);
    const head = (try f.store.sourceMaintenance(identity.jail, identity.source, generation)).?;
    try t.expectError(error.HistoryGap, f.store.cleanupAdvance(fence, head, 1));
    var events: [1]history.Event = undefined;
    fence.history = (try f.store.confirmedEffectPage(installation, 0, null, &events)).token;
    try t.expectEqual(@as(?durable.Store.CleanupToken, null), try f.store.cleanupAdvance(fence, head, 1));
    try t.expect(!try f.store.retireRetrySubject(fence, (try f.store.retryRetirementCandidate(identity.jail, null)).?));
    try t.expectEqual(@as(u64, 0), try f.store.confirmedEffectEvents());
}

test "native maintenance: required source checkpoint is rechecked before mark and deletion" {
    var f = try Fixture.init();
    defer f.deinit();
    try setupCleanup(&f);
    const rule_key = consumer.Key{ .kind = .rule, .jail = "receipt", .source = "file", .rule = "fixture", .generation = generation };
    const requirement = [_]consumer.Requirement{.{ .key = rule_key, .format_version = 1 }};
    const source_manifest = consumer.Manifest{ .jail = "receipt", .source = "file", .source_generation = generation, .required = &requirement };
    var deltas = [_]consumer.Delta{.{ .key = rule_key, .format_version = 1, .expected_revision = 0, .payload = "original-rule-state" }};
    const state = consumer.Batch{ .prepared_us = 100, .clock = clock, .deltas = &deltas };
    try f.store.bootstrapConsumerManifest(source_manifest, state);
    var id = identity;
    for (0..2) |index| {
        if (index == 1) {
            id.occurrence = "anchor";
            id.cursor = "anchor";
        }
        _ = try f.store.beginReceipt(id, .{ .us = 100 }, index);
        var record = recordFor(id, index);
        deltas[0].expected_revision = index + 1;
        record.consumer_manifest = source_manifest;
        record.consumers = state;
        _ = try f.store.commitRecord(record);
    }
    var now = CleanupClock{};
    var fence = try cleanupFence(&f.store, identity, &now);
    const head = (try f.store.sourceMaintenance(identity.jail, identity.source, generation)).?;
    try t.expectError(error.ConsumerManifestRequired, f.store.cleanupAdvance(fence, head, 1));
    fence.manifest = source_manifest;
    const token = (try f.store.cleanupAdvance(fence, head, 1)).?;
    try sql(&f.store, "DELETE FROM consumer_checkpoints WHERE kind=1;");
    try t.expectError(error.MissingRequiredConsumer, f.store.cleanupDelete(fence, token));
    try t.expectEqual(@as(u64, 1), (try f.store.recordSequence(identity.jail, identity.source, identity.occurrence)).?.sequence);
}

test "native maintenance: killed production migration mark delete and retirement commit atomically" {
    const DbPointer = @TypeOf(@as(durable.Store, undefined).db);
    const Exec = @TypeOf(@as(durable.Store, undefined).api.exec);
    const Fault = struct {
        var actual: Exec = undefined;
        var after: bool = false;
        fn exec(db: DbPointer, query: [*:0]const u8, callback: ?*anyopaque, context: ?*anyopaque, message: ?*?[*:0]u8) callconv(.c) c_int {
            if (!std.mem.eql(u8, std.mem.span(query), "COMMIT;")) return actual(db, query, callback, context, message);
            if (after and actual(db, query, callback, context, message) != 0) std.process.exit(5);
            std.posix.kill(std.os.linux.getpid(), std.posix.SIG.KILL) catch std.process.exit(6);
            std.process.exit(7);
        }
    };
    for (0..4) |operation| for ([_]bool{ false, true }) |after| {
        var f = try Fixture.init();
        defer f.deinit();
        try f.store.enableMaintenance();
        if (operation != 0) try f.store.enableCleanup();
        var now = CleanupClock{};
        if (operation == 1 or operation == 2) {
            try commitObserved(&f.store, identity, 0);
            var anchor = identity;
            anchor.occurrence = "anchor";
            anchor.cursor = "anchor";
            try commitObserved(&f.store, anchor, 1);
            if (operation == 2) _ = try f.store.cleanupAdvance(try cleanupFence(&f.store, identity, &now), (try f.store.sourceMaintenance(identity.jail, identity.source, generation)).?, 1);
        } else if (operation == 3) {
            try f.store.admitRetry(identity.jail, generation, .{ .maxretry = 1, .window_us = 100, .duration = .{ .finite_us = 100 }, .max_subjects = 1 });
            try sql(&f.store, "UPDATE retry_clock SET floor_us=100; INSERT INTO retry_states VALUES('receipt',4,X'C000025B',100,200,7,X'');");
        }
        const pid = try std.posix.fork();
        if (pid == 0) {
            var child = durable.Store.open(std.heap.page_allocator, f.path) catch std.process.exit(2);
            child.enableReceipts(8) catch std.process.exit(2);
            var child_now = CleanupClock{};
            const fence = if (operation != 0) cleanupFence(&child, identity, &child_now) catch std.process.exit(2) else undefined;
            const head = if (operation == 1) (child.sourceMaintenance(identity.jail, identity.source, generation) catch std.process.exit(2)).? else undefined;
            const token = if (operation == 2) (child.cleanupResume(identity.jail, identity.source, generation) catch std.process.exit(2)).? else undefined;
            const candidate = if (operation == 3) (child.retryRetirementCandidate(identity.jail, null) catch std.process.exit(2)).? else undefined;
            Fault.actual = child.api.exec;
            Fault.after = after;
            child.api.exec = Fault.exec;
            switch (operation) {
                0 => child.enableCleanup() catch std.process.exit(3),
                1 => _ = child.cleanupAdvance(fence, head, 1) catch std.process.exit(3),
                2 => _ = child.cleanupDelete(fence, token) catch std.process.exit(3),
                3 => _ = child.retireRetrySubject(fence, candidate) catch std.process.exit(3),
                else => std.process.exit(4),
            }
            std.process.exit(8);
        }
        try t.expectEqual(@as(u32, std.posix.SIG.KILL), std.posix.waitpid(pid, 0).status);
        try reopen(&f);
        switch (operation) {
            0 => {
                try t.expectEqual(@as(i64, if (after) 15 else 14), f.store.schema_version);
                try f.store.enableCleanup();
            },
            1 => {
                const head = (try f.store.sourceMaintenance(identity.jail, identity.source, generation)).?;
                try t.expectEqual(@as(u64, if (after) 2 else 1), head.reject_below_sequence);
                if (after) try t.expectError(error.PrunedReplay, f.store.committedReceipt(identity)) else try t.expectEqual(@as(i64, 100), (try f.store.committedReceipt(identity)).?.us);
            },
            2 => {
                try t.expectEqual(!after, try f.store.recordSequence(identity.jail, identity.source, identity.occurrence) != null);
                try t.expectError(error.PrunedReplay, f.store.committedReceipt(identity));
                try t.expectEqual(@as(u64, @intFromBool(after)), (try f.store.sourceMaintenance(identity.jail, identity.source, generation)).?.sweep_sequence);
            },
            3 => {
                try t.expectEqual(!after, try f.store.retryRetirementCandidate(identity.jail, null) != null);
                const subject = @import("core/native_detection_record.zig").Subject{ .v4 = .{ 192, 0, 2, 91 } };
                try t.expectEqual(@as(u64, 7), (try f.store.retryState(identity.jail, subject)).?.decisions);
                var output: [1]durable.Store.ActiveDecision = undefined;
                try t.expectEqual(@as(u64, 7), (try f.store.retrySummary(identity.jail, now.now, &output)).decisions);
            },
            else => unreachable,
        }
        _ = try validateCleanup(&f.store);
    };
}

test "native maintenance: paged validation and health remain bounded with accumulated detail and retired identities" {
    var f = try Fixture.init();
    defer f.deinit();
    try setupCleanup(&f);
    try commitObserved(&f.store, identity, 0);
    try sql(&f.store,
        \\BEGIN IMMEDIATE;
        \\WITH RECURSIVE n(x) AS (VALUES(2) UNION ALL SELECT x+1 FROM n WHERE x<2048)
        \\INSERT INTO records(jail,source,occurrence,raw_hash,cursor,disposition,source_generation,source_sequence,receipt_us,receipt_generation)
        \\SELECT jail,source,printf('record-%d',x),raw_hash,cursor,disposition,source_generation,x,receipt_us,receipt_generation FROM records,n WHERE occurrence='original';
        \\UPDATE source_maintenance SET head_sequence=2048;
        \\COMMIT;
    );
    try f.store.admitRetry("retired", generation, .{ .maxretry = 1, .window_us = 100, .duration = .{ .finite_us = 100 }, .max_subjects = 1 });
    try sql(&f.store,
        \\BEGIN IMMEDIATE;
        \\UPDATE retry_clock SET floor_us=100;
        \\WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<2048)
        \\INSERT INTO retry_retired SELECT jail,4,CAST(printf('%04d',x) AS BLOB),generation,100,1 FROM retry_policies,n WHERE jail='retired';
        \\INSERT INTO retry_retired_totals VALUES('retired',2048);
        \\COMMIT;
    );
    const Progress = struct {
        const DbPointer = @TypeOf(@as(durable.Store, undefined).db);
        extern "c" fn sqlite3_progress_handler(DbPointer, c_int, ?*const fn (?*anyopaque) callconv(.c) c_int, ?*anyopaque) void;
        var callbacks: usize = 0;
        fn tick(_: ?*anyopaque) callconv(.c) c_int {
            callbacks += 1;
            return @intFromBool(callbacks > 40_000);
        }
    };
    Progress.sqlite3_progress_handler(f.store.db, 1, Progress.tick, null);
    defer Progress.sqlite3_progress_handler(f.store.db, 0, null, null);
    var cursor = durable.Store.MaintenanceValidation{};
    var turns: usize = 0;
    var maximum: usize = 0;
    while (true) {
        turns += 1;
        try t.expect(turns < 1024);
        Progress.callbacks = 0;
        const done = try f.store.validateMaintenanceTurn(&cursor);
        maximum = @max(maximum, Progress.callbacks);
        if (done) break;
    }
    try t.expect(turns > 256);
    try f.store.finishMaintenanceValidation(&cursor);
    Progress.callbacks = 0;
    var output: [1]durable.Store.ActiveDecision = undefined;
    const summary = try f.store.retrySummary("retired", 100, &output);
    try t.expectEqual(@as(u64, 2048), summary.decisions);
    try t.expectEqual(@as(usize, 0), summary.subjects);
    try t.expect(Progress.callbacks > 0 and Progress.callbacks < 1000);
    try t.expect(maximum > 0);
    std.debug.print("maintenance validation: {d} pages, maximum {d} VM instructions; retired health {d}\n", .{ turns, maximum, Progress.callbacks });
    Progress.sqlite3_progress_handler(f.store.db, 0, null, null);
    try sql(&f.store, "DELETE FROM records WHERE source_sequence=1000;");
    try t.expectError(error.InvalidMaintenanceState, validateCleanup(&f.store));
    try sql(&f.store, "UPDATE retry_retired_totals SET total=2047;");
    cursor = .{ .phase = .retired };
    while (true) {
        const done = f.store.validateMaintenanceTurn(&cursor) catch |err| {
            try t.expectEqual(error.InvalidRetryState, err);
            break;
        };
        try t.expect(!done);
    }
    var malformed = durable.Store.MaintenanceValidation{ .jail_len = 4097 };
    try t.expectError(error.InvalidMaintenanceState, f.store.validateMaintenanceTurn(&malformed));
}

test "native maintenance: key budget no Zig allocation and failed writes preserve guarded boundary" {
    var f = try Fixture.init();
    defer f.deinit();
    try setupCleanup(&f);
    const long_cursor = [_]u8{'c'} ** durable.Limits.cursor_bytes;
    var first = identity;
    first.cursor = &long_cursor;
    for (0..20) |index| {
        var name_buffer: [32]u8 = undefined;
        var id = first;
        id.occurrence = if (index == 0) identity.occurrence else try std.fmt.bufPrint(&name_buffer, "occurrence-{d}", .{index});
        try commitObserved(&f.store, id, index);
    }
    var now = CleanupClock{};
    const fence = try cleanupFence(&f.store, first, &now);
    const initial = (try f.store.sourceMaintenance(first.jail, first.source, generation)).?;
    const Prepare = @TypeOf(f.store.api.prepare);
    const Parameters = @typeInfo(@typeInfo(Prepare).pointer.child).@"fn".params;
    const Fault = struct {
        var original: Prepare = undefined;
        fn prepare(db: Parameters[0].type.?, query: [*:0]const u8, length: c_int, statement: Parameters[3].type.?, tail: ?*?[*:0]const u8) callconv(.c) c_int {
            if (std.mem.startsWith(u8, std.mem.span(query), "INSERT INTO replay_guards")) {
                statement.* = null;
                return 7;
            }
            return original(db, query, length, statement, tail);
        }
    };
    Fault.original = f.store.api.prepare;
    f.store.api.prepare = Fault.prepare;
    try t.expectError(error.OutOfMemory, f.store.cleanupAdvance(fence, initial, 20));
    f.store.api.prepare = Fault.original;
    try t.expectEqualDeep(initial, (try f.store.sourceMaintenance(first.jail, first.source, generation)).?);
    try t.expectEqual(@as(i64, 100), (try f.store.committedReceipt(first)).?.us);
    try sql(&f.store, "PRAGMA query_only=ON;");
    try t.expectError(error.ReadOnly, f.store.cleanupAdvance(fence, initial, 20));
    try sql(&f.store, "PRAGMA query_only=OFF;");
    const allocator = f.store.allocator;
    var failing = t.FailingAllocator.init(t.allocator, .{ .fail_index = 0 });
    f.store.allocator = failing.allocator();
    defer f.store.allocator = allocator;
    const token = (try f.store.cleanupAdvance(fence, initial, 20)).?;
    try t.expectEqual(@as(u64, 16), token.state.reject_below_sequence);
    try t.expectError(error.PrunedReplay, f.store.committedReceipt(first));
    try sql(&f.store, "PRAGMA query_only=ON;");
    try t.expectError(error.ReadOnly, f.store.cleanupDelete(fence, token));
    try sql(&f.store, "PRAGMA query_only=OFF;");
    try t.expectEqual(@as(u64, 1), (try f.store.recordSequence(first.jail, first.source, first.occurrence)).?.sequence);
    const removed = try f.store.cleanupDelete(fence, token);
    try t.expectEqual(@as(u8, 15), removed.deleted_rows);
    try t.expect(!removed.more);
    _ = try validateCleanup(&f.store);
    try t.expect(!failing.has_induced_failure);
    try sql(&f.store, "DELETE FROM maintenance_clock;");
    var id = first;
    id.occurrence = "missing-clock";
    _ = try f.store.beginReceipt(id, .{ .us = 10001 }, 20);
    var record = recordFor(id, 20);
    record.receipt.?.time.us = 10001;
    try t.expectError(error.InvalidMaintenanceState, f.store.commitRecord(record));
    try t.expectEqual(@as(i64, 10001), (try f.store.pendingReceipt(id)).?.us);
}

test "native maintenance: real SQLite page ceiling rolls back the entire guard prefix" {
    var f = try Fixture.init();
    defer f.deinit();
    try setupCleanup(&f);
    for (0..65) |index| {
        var buffer: [32]u8 = undefined;
        var id = identity;
        id.occurrence = if (index == 0) identity.occurrence else try std.fmt.bufPrint(&buffer, "page-{d}", .{index});
        try commitObserved(&f.store, id, index);
    }
    var now = CleanupClock{};
    const fence = try cleanupFence(&f.store, identity, &now);
    const before = (try f.store.sourceMaintenance(identity.jail, identity.source, generation)).?;
    try sql(&f.store, "PRAGMA max_page_count=1;");
    try t.expectError(error.StorageFull, f.store.cleanupAdvance(fence, before, 65));
    try t.expectEqualDeep(before, (try f.store.sourceMaintenance(identity.jail, identity.source, generation)).?);
    try t.expectEqual(@as(i64, 100), (try f.store.committedReceipt(identity)).?.us);
    try t.expectEqual(@as(?durable.Store.CleanupToken, null), try f.store.cleanupResume(identity.jail, identity.source, generation));
    try sql(&f.store, "PRAGMA max_page_count=65536;");
    const marked = (try f.store.cleanupAdvance(fence, before, 65)).?;
    try t.expectEqual(@as(u64, 65), marked.state.reject_below_sequence);
    const deleted = try f.store.cleanupDelete(fence, marked);
    try t.expectEqual(@as(u8, 64), deleted.deleted_rows);
    try t.expect(!deleted.more);
    _ = try validateCleanup(&f.store);
}

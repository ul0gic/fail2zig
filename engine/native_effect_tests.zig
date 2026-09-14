// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const effects = @import("core/native_effect.zig");
const durable = @import("core/record_store.zig");
const time_policy = @import("core/source_time_policy.zig");
const retry = @import("core/native_retry.zig");
const t = std.testing;
const Fixture = struct {
    tmp: t.TmpDir,
    path: []u8,
    store: durable.Store,
    fn init() !Fixture {
        return initSchema(true);
    }
    fn initSchema(with_effects: bool) !Fixture {
        var tmp = t.tmpDir(.{});
        errdefer tmp.cleanup();
        const root = try tmp.dir.realpathAlloc(t.allocator, ".");
        defer t.allocator.free(root);
        const path = try std.fs.path.join(t.allocator, &.{ root, "effects.sqlite" });
        errdefer t.allocator.free(path);
        var store = try durable.Store.open(t.allocator, path);
        errdefer store.close();
        try enable(&store, with_effects);
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
        try self.store.enableReceipts(8);
    }
};
fn enable(store: *durable.Store, with_effects: bool) !void {
    try store.enableReceipts(8);
    try store.enableNativeTime();
    try store.enableYearInference();
    try store.enableDetection();
    try store.enableClockRecovery();
    try store.enableJournalDetection();
    try store.enableRetry();
    try store.enableConsumers();
    if (with_effects) try store.enableEffects();
}
const TestClock = struct {
    now: i64 = 100,
    advance: i64 = 0,
    fn read(ctx: ?*anyopaque) i64 {
        const self: *TestClock = @ptrCast(@alignCast(ctx.?));
        const now = self.now;
        self.now += self.advance;
        return now;
    }
    fn value(self: *TestClock) effects.Clock {
        return .{ .prepared_us = 100, .context = self, .read = read };
    }
};
fn installation() !effects.Installation {
    return effects.Installation.init([_]u8{7} ** 16, .nftables, "host-default");
}
fn admit(store: *durable.Store) !void {
    try store.admitInstallation(try installation(), .{ .selector = "host-default", .disposition = .verified_absent });
}
fn change(jail: []const u8, identity: u8, lease: effects.Lease) !effects.OwnerChange {
    return .{ .scope = try effects.Scope.host(.{ .v4 = .{ 192, 0, 2, 51 } }), .jail = jail, .generation = [_]u8{3} ** 32, .decision_id = [_]u8{identity} ** 32, .expected_revision = 0, .lease = lease, .decided_us = 100 };
}
fn observation(entry: effects.Entry, now: i64, state: effects.Lease) effects.Observation {
    return .{ .installation = entry.installation.id, .scope_key = entry.scope_key, .fingerprint = [_]u8{9} ** 32, .observed_us = now, .qualification = .complete_owned, .state = state };
}
fn first(store: *durable.Store) !effects.Entry {
    var rows: [1]effects.Entry = undefined;
    const page = try store.effectPage(null, null, &rows);
    try t.expectEqual(@as(usize, 1), page.count);
    return rows[0];
}
fn sql(store: *durable.Store, statement: [:0]const u8) !void {
    const run = @extern(*const fn (*anyopaque, [*:0]const u8, ?*anyopaque, ?*anyopaque, ?*?[*:0]u8) callconv(.c) c_int, .{ .name = "sqlite3_exec" });
    if (run(@ptrCast(store.db), statement, null, null, null) != 0) return error.TestSqlFailed;
}

test "native effects: canonical host scope refuses aliases and unsupported wire fields" {
    const scope = try effects.Scope.host(.{ .v4 = .{ 192, 0, 2, 1 } });
    const wire = try scope.encode();
    try t.expectEqualDeep(scope, try effects.Scope.decode(&wire));
    for ([_]usize{ 0, 2, 3, 4, 5, 6, 7, 23 }) |index| {
        var changed = wire;
        changed[index] +%= 1;
        try t.expectError(error.InvalidEffect, effects.Scope.decode(&changed));
    }
    try t.expectError(error.InvalidEffect, effects.Scope.host(.{ .v6 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192, 0, 2, 1 } }));
    try t.expectError(error.InvalidEffect, effects.Scope.host(.{ .v6 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 1 } }));
    var other = try installation();
    other.backend = .iptables;
    try t.expect(!std.mem.eql(u8, &try scope.key(try installation()), &try scope.key(other)));
}

test "native effects: migration alone authorizes nothing and installation remains stable on reopen" {
    var f = try Fixture.init();
    defer f.deinit();
    try t.expectEqual(@as(i64, 11), f.store.schema_version);
    try t.expectEqual(@as(?effects.Installation, null), try f.store.readInstallation());
    var clock = TestClock{};
    try t.expectError(error.InstallationRequired, f.store.setOwner(try change("one", 1, .{ .finite = 500 }), clock.value()));
    try t.expectError(error.NamespaceAdmissionRequired, f.store.admitInstallation(try installation(), .{ .selector = "host-default", .disposition = .verified_owned }));
    try admit(&f.store);
    try f.reopen();
    try t.expectEqualDeep(try installation(), (try f.store.readInstallation()).?);
    var other = try installation();
    other.id[0] = 8;
    try t.expectError(error.InstallationMismatch, f.store.admitInstallation(other, .{ .selector = "host-default", .disposition = .verified_absent }));
}

test "native effects: shared finite and permanent owners preserve maximum original protection" {
    var f = try Fixture.init();
    defer f.deinit();
    try admit(&f.store);
    var clock = TestClock{};
    const one = try f.store.setOwner(try change("one", 1, .{ .finite = 300 }), clock.value());
    const two = try f.store.setOwner(try change("two", 2, .{ .finite = 700 }), clock.value());
    try t.expectEqual(@as(i64, 700), two.desired.finite);
    try t.expectEqual(one.revision + 1, two.revision);
    const permanent = try f.store.setOwner(try change("three", 3, .permanent), clock.value());
    try t.expect(permanent.desired == .permanent);
    clock.now = 400;
    const partial = try f.store.prepareExpiry(permanent.scope_key, permanent.revision, clock.value());
    try t.expect(partial.desired == .permanent);
    var release = try change("three", 4, .absent);
    release.expected_revision = 1;
    release.decided_us = 400;
    const finite = try f.store.setOwner(release, clock.value());
    try t.expectEqual(@as(i64, 700), finite.desired.finite);
    clock.now = 700;
    const absent = try f.store.prepareExpiry(finite.scope_key, finite.revision, clock.value());
    try t.expect(absent.desired == .absent);
    var owners: [effects.max_page]effects.Owner = undefined;
    try t.expectEqual(@as(usize, 3), try f.store.effectOwners(absent.scope_key, absent.revision, &owners));
    for (owners[0..3]) |owner| try t.expect(owner.lease == .absent);
    try t.expectEqual(@as(i64, 300), (try f.store.ownerRevision(absent.scope_key, "one", 1)).?.lease.finite);
    try t.expectEqual(@as(i64, 700), (try f.store.ownerRevision(absent.scope_key, "two", 1)).?.lease.finite);
}

test "native effects: dispatch fences replacement and complete reconciliation retains intent identity" {
    var f = try Fixture.init();
    defer f.deinit();
    try admit(&f.store);
    var clock = TestClock{};
    const entry = try f.store.setOwner(try change("one", 1, .{ .finite = 500 }), clock.value());
    try f.store.markDispatched(entry.token(), clock.value());
    try t.expectError(error.EffectReconciliationRequired, f.store.setOwner(try change("two", 2, .permanent), clock.value()));
    var incomplete = observation(entry, 100, .absent);
    incomplete.qualification = .incomplete;
    try t.expectError(error.IncompleteEffectObservation, f.store.settleVerified(entry.token(), incomplete, clock.value()));
    try t.expectEqual(effects.Settlement.retry_same_intent, try f.store.settleVerified(entry.token(), observation(entry, 100, .absent), clock.value()));
    try t.expectEqualDeep(entry.intent_id, (try first(&f.store)).intent_id);
    try f.store.markDispatched(entry.token(), clock.value());
    try t.expectEqual(effects.Settlement.verified, try f.store.settleVerified(entry.token(), observation(entry, 100, entry.desired), clock.value()));
    try t.expectEqual(@as(u64, 1), try f.store.confirmedEffectEvents());
    _ = try f.store.settleVerified(entry.token(), observation(entry, 100, entry.desired), clock.value());
    try t.expectEqual(@as(u64, 1), try f.store.confirmedEffectEvents());
    clock.now = 101;
    var drift = observation(entry, 101, .absent);
    drift.state = null;
    try t.expectEqual(effects.Settlement.retry_same_intent, try f.store.settleVerified(entry.token(), drift, clock.value()));
    try f.store.markDispatched(entry.token(), clock.value());
    _ = try f.store.settleVerified(entry.token(), observation(entry, 101, entry.desired), clock.value());
    try t.expectEqual(@as(u64, 1), try f.store.confirmedEffectEvents());
}

test "native effects: expired uncertain add reconciles before exact removal without a new ban" {
    var f = try Fixture.init();
    defer f.deinit();
    try admit(&f.store);
    var clock = TestClock{};
    const entry = try f.store.setOwner(try change("one", 1, .{ .finite = 200 }), clock.value());
    try f.store.markDispatched(entry.token(), clock.value());
    try f.reopen();
    clock.now = 250;
    try t.expectError(error.EffectReconciliationRequired, f.store.prepareExpiry(entry.scope_key, entry.revision, clock.value()));
    try t.expectEqual(effects.Settlement.expired, try f.store.settleVerified(entry.token(), observation(entry, 250, entry.desired), clock.value()));
    const remove = try f.store.prepareExpiry(entry.scope_key, entry.revision, clock.value());
    try t.expect(remove.desired == .absent);
    try f.store.markDispatched(remove.token(), clock.value());
    _ = try f.store.settleVerified(remove.token(), observation(remove, 250, .absent), clock.value());
    try t.expectEqual(@as(u64, 0), try f.store.confirmedEffectEvents());
}

test "native effects: rollback preserves owner intent publication epoch and final clock expiry" {
    var f = try Fixture.init();
    defer f.deinit();
    try admit(&f.store);
    var clock = TestClock{};
    const entry = try f.store.setOwner(try change("one", 1, .{ .finite = 500 }), clock.value());
    const epoch = f.store.effect_publication_epoch;
    for ([_]durable.CommitStage{ .after_effect_owner, .after_effect_intent }) |stage| {
        f.store.fail_at = stage;
        try t.expectError(error.InjectedFailure, f.store.setOwner(try change("two", 2, .permanent), clock.value()));
        try t.expectEqual(epoch, f.store.effect_publication_epoch);
        try t.expectEqualDeep(entry, try first(&f.store));
    }
    f.store.fail_at = .before_effect_dispatch_commit;
    try t.expectError(error.InjectedFailure, f.store.markDispatched(entry.token(), clock.value()));
    try t.expectEqualDeep(entry, try first(&f.store));
    f.store.fail_at = null;
    clock.now = 499;
    clock.advance = 1;
    try t.expectError(error.EffectExpired, f.store.markDispatched(entry.token(), clock.value()));
    try t.expectEqualDeep(entry, try first(&f.store));
    clock.now = 200;
    clock.advance = 0;
    try f.store.markDispatched(entry.token(), clock.value());
    f.store.fail_at = .before_effect_receipt_commit;
    try t.expectError(error.InjectedFailure, f.store.settleVerified(entry.token(), observation(entry, 200, entry.desired), clock.value()));
    try t.expectEqual(@as(u64, 0), try f.store.confirmedEffectEvents());
    try f.reopen();
    clock.now = 199;
    try t.expectError(error.EffectClockReversed, f.store.settleVerified(entry.token(), observation(entry, 199, entry.desired), clock.value()));
}

test "native effects: detached pages detect changed snapshot and malformed canonical persisted values" {
    var f = try Fixture.init();
    defer f.deinit();
    try admit(&f.store);
    var clock = TestClock{};
    _ = try f.store.setOwner(try change("one", 1, .permanent), clock.value());
    var rows: [1]effects.Entry = undefined;
    const page = try f.store.effectPage(null, null, &rows);
    _ = try f.store.setOwner(try change("two", 2, .permanent), clock.value());
    try t.expectError(error.StaleEffect, f.store.effectPage(rows[0].scope_key, page.revision, &rows));
    try sql(&f.store, "PRAGMA ignore_check_constraints=ON; UPDATE native_effects SET scope=zeroblob(24);");
    try t.expectError(error.InvalidEffect, f.store.effectPage(null, null, &rows));
}

const record_identity = durable.ReceiptIdentity{ .jail = "one", .source = "file", .occurrence = "1", .cursor = "cursor-1", .raw_hash = [_]u8{1} ** 32, .generation = [_]u8{3} ** 32 };
const enforcing_policy = retry.Policy{ .maxretry = 1, .window_us = 1000, .bantime_us = 400, .max_subjects = 8, .enforce = true };
fn record(clock: *TestClock) !durable.Record {
    const detected = @import("core/native_detection_record.zig");
    const outcome = try time_policy.evaluate(.timestamped, .{ .parsed = .{ .us = 100 } }, .{ .us = 100 }, .{ .us = 100 }, 1000);
    return .{ .jail = record_identity.jail, .source = record_identity.source, .occurrence = record_identity.occurrence, .cursor = record_identity.cursor, .raw_hash = record_identity.raw_hash, .receipt = .{ .time = .{ .us = 100 }, .generation = record_identity.generation }, .native_time_outcome = outcome, .native_detection = .{ .kind = .candidate, .generation = record_identity.generation, .filter = try detected.Name.init("fixture"), .pattern = try detected.Name.init("failure"), .pattern_index = 0, .subject = .{ .v4 = .{ 192, 0, 2, 51 } } }, .native_retry = .{ .generation = record_identity.generation, .policy = enforcing_policy, .processing_us = 100 }, .effects_clock = clock.value(), .disposition = outcome.disposition(), .checkpoint = "checkpoint", .zone_provenance = .{ .zone_digest = [_]u8{4} ** 32, .offset_seconds = -18000, .ambiguity = .later, .fold_selected = true } };
}
fn admitRecord(store: *durable.Store) !void {
    try store.admitRetry(record_identity.jail, record_identity.generation, enforcing_policy);
    _ = try store.beginReceipt(record_identity, .{ .us = 100 }, 0);
}

test "native effects: enforcing record cursor receipt retry owner intent and zone commit atomically" {
    var f = try Fixture.init();
    defer f.deinit();
    try admit(&f.store);
    try admitRecord(&f.store);
    var clock = TestClock{};
    const value = try record(&clock);
    for ([_]durable.CommitStage{ .after_effect_owner, .after_effect_intent, .after_receipt_delete, .before_commit }) |stage| {
        f.store.fail_at = stage;
        try t.expectError(error.InjectedFailure, f.store.commitRecord(value));
        try t.expectEqual(@as(u64, 0), try f.store.revision("one"));
        try t.expectEqual(@as(usize, 1), try f.store.pendingReceiptCount());
        try t.expectEqual(@as(u64, 0), f.store.effect_publication_epoch);
        var rows: [1]effects.Entry = undefined;
        try t.expectEqual(@as(usize, 0), (try f.store.effectPage(null, null, &rows)).count);
    }
    f.store.fail_at = null;
    try t.expectEqual(durable.CommitResult.committed, try f.store.commitRecord(value));
    try t.expectEqual(@as(u64, 1), f.store.effect_publication_epoch);
    try t.expectEqual(@as(usize, 0), try f.store.pendingReceiptCount());
    try t.expectEqual(@as(i64, 500), (try first(&f.store)).desired.finite);
    try t.expectEqualDeep(value.zone_provenance, try f.store.nativeTimeProvenance("one", "file", "1"));
    try t.expectEqual(durable.CommitResult.already_committed, try f.store.commitRecord(value));
    try t.expectEqual(@as(u64, 1), f.store.effect_publication_epoch);
    var changed = value;
    changed.zone_provenance.?.offset_seconds = 0;
    try t.expectError(error.OccurrenceConflict, f.store.commitRecord(changed));
    try f.reopen();
    try t.expectEqualDeep(value.zone_provenance, try f.store.nativeTimeProvenance("one", "file", null));
    try t.expectEqual(@as(i64, 500), (try first(&f.store)).desired.finite);
}

test "native effects: actual killed migration record dispatch and receipt commits reopen before or after" {
    const Stage = enum { migration, record, dispatch, receipt };
    for ([_]Stage{ .migration, .record, .dispatch, .receipt }) |stage| for ([_]bool{ false, true }) |after| {
        var f = try Fixture.initSchema(stage != .migration);
        defer f.deinit();
        var clock = TestClock{};
        var entry: effects.Entry = undefined;
        if (stage != .migration) try admit(&f.store);
        if (stage == .record) try admitRecord(&f.store);
        if (stage == .dispatch or stage == .receipt) entry = try f.store.setOwner(try change("one", 1, .{ .finite = 500 }), clock.value());
        if (stage == .receipt) try f.store.markDispatched(entry.token(), clock.value());
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
                    unreachable;
                }
            };
            Kill.actual = child.api.exec;
            Kill.after_commit = after;
            child.api.exec = Kill.exec;
            switch (stage) {
                .migration => child.enableEffects() catch std.process.exit(6),
                .record => {
                    const value = record(&clock) catch std.process.exit(7);
                    _ = child.commitRecord(value) catch std.process.exit(8);
                },
                .dispatch => child.markDispatched(entry.token(), clock.value()) catch std.process.exit(9),
                .receipt => {
                    _ = child.settleVerified(entry.token(), observation(entry, 100, entry.desired), clock.value()) catch std.process.exit(10);
                },
            }
            std.process.exit(11);
        }
        const ended = std.posix.waitpid(pid, 0);
        f.store = try durable.Store.open(t.allocator, f.path);
        try f.store.enableReceipts(8);
        try t.expect(std.posix.W.IFSIGNALED(ended.status));
        try t.expectEqual(@as(u32, std.posix.SIG.KILL), std.posix.W.TERMSIG(ended.status));
        switch (stage) {
            .migration => try t.expectEqual(@as(i64, if (after) 11 else 10), f.store.schema_version),
            .record => {
                try t.expectEqual(@as(u64, @intFromBool(after)), try f.store.revision("one"));
                try t.expectEqual(@as(usize, @intFromBool(!after)), try f.store.pendingReceiptCount());
                var rows: [1]effects.Entry = undefined;
                try t.expectEqual(@as(usize, @intFromBool(after)), (try f.store.effectPage(null, null, &rows)).count);
                if (after) try t.expectEqual(@as(i64, 500), rows[0].desired.finite);
            },
            .dispatch => try t.expectEqual(if (after) effects.Status.dispatched else effects.Status.pending, (try first(&f.store)).status),
            .receipt => {
                try t.expectEqual(if (after) effects.Status.applied else effects.Status.dispatched, (try first(&f.store)).status);
                try t.expectEqual(@as(u64, @intFromBool(after)), try f.store.confirmedEffectEvents());
            },
        }
    };
}

fn allocationRead(allocator: std.mem.Allocator, path: []const u8) !void {
    var store = try durable.Store.open(allocator, path);
    defer store.close();
    var rows: [1]effects.Entry = undefined;
    try t.expectEqual(@as(usize, 1), (try store.effectPage(null, null, &rows)).count);
    try t.expectEqual(@as(i64, 500), rows[0].desired.finite);
}
test "native effects: allocator failure and SQLite OOM rollback retain committed protection" {
    var f = try Fixture.init();
    defer f.deinit();
    try admit(&f.store);
    var clock = TestClock{};
    const entry = try f.store.setOwner(try change("one", 1, .{ .finite = 500 }), clock.value());
    try t.checkAllAllocationFailures(t.allocator, allocationRead, .{f.path});
    const Fail = struct {
        const Db = std.meta.Child(@FieldType(durable.Store, "db"));
        const Api = @FieldType(durable.Store, "api");
        const Prepare = @FieldType(Api, "prepare");
        var actual: Prepare = undefined;
        fn prepare(db: *Db, statement: [*:0]const u8, length: c_int, output: *?*anyopaque, tail: ?*?[*:0]const u8) callconv(.c) c_int {
            if (std.mem.startsWith(u8, std.mem.span(statement), "INSERT INTO effect_intents")) return 7;
            return actual(db, statement, length, @ptrCast(output), tail);
        }
    };
    const epoch = f.store.effect_publication_epoch;
    Fail.actual = f.store.api.prepare;
    f.store.api.prepare = @ptrCast(&Fail.prepare);
    try t.expectError(error.OutOfMemory, f.store.setOwner(try change("two", 2, .permanent), clock.value()));
    f.store.api.prepare = Fail.actual;
    try t.expectEqual(epoch, f.store.effect_publication_epoch);
    try t.expectEqualDeep(entry, try first(&f.store));
    try t.expectEqual(@as(?c_int, 7), f.store.last_error_code);
}

test "native effects: exact owner limit refuses without evicting prior authorization" {
    var f = try Fixture.init();
    defer f.deinit();
    try admit(&f.store);
    var clock = TestClock{};
    var last: effects.Entry = undefined;
    for (0..effects.max_page) |i| {
        var name: [16]u8 = undefined;
        const jail = try std.fmt.bufPrint(&name, "owner-{d}", .{i});
        last = try f.store.setOwner(try change(jail, @intCast(i + 1), .permanent), clock.value());
    }
    const epoch = f.store.effect_publication_epoch;
    try t.expectError(error.EffectCapacity, f.store.setOwner(try change("overflow", 100, .permanent), clock.value()));
    try t.expectEqual(epoch, f.store.effect_publication_epoch);
    try t.expectEqualDeep(last, try first(&f.store));
    var rows: [effects.max_page]effects.Owner = undefined;
    try t.expectEqual(@as(usize, effects.max_page), try f.store.effectOwners(last.scope_key, last.revision, &rows));
    var stale = try change("owner-0", 101, .absent);
    try t.expectError(error.StaleEffect, f.store.setOwner(stale, clock.value()));
    stale.expected_revision = 1;
    stale.generation[0] = 99;
    try t.expectError(error.EffectGenerationMismatch, f.store.setOwner(stale, clock.value()));
}

test "native effects: advancing same-intent retry reopens with original observation history" {
    var f = try Fixture.init();
    defer f.deinit();
    try admit(&f.store);
    var clock = TestClock{};
    const entry = try f.store.setOwner(try change("one", 1, .{ .finite = 500 }), clock.value());
    try f.store.markDispatched(entry.token(), clock.value());
    clock.now = 110;
    _ = try f.store.settleVerified(entry.token(), observation(entry, 110, .absent), clock.value());
    clock.now = 120;
    try f.store.markDispatched(entry.token(), clock.value());
    try f.reopen();
    try t.expectEqual(effects.Status.dispatched, (try first(&f.store)).status);
    clock.now = 130;
    _ = try f.store.settleVerified(entry.token(), observation(entry, 130, entry.desired), clock.value());
    try sql(&f.store, "CREATE TEMP TABLE receipt_count(n INTEGER CHECK(n=2)); INSERT INTO receipt_count SELECT count(*) FROM effect_observations;");
    clock.now = 140;
    try t.expectError(error.StaleEffect, f.store.settleVerified(entry.token(), observation(entry, 125, .absent), clock.value()));
    var conflict = observation(entry, 130, .absent);
    conflict.fingerprint[0] = 8;
    try t.expectError(error.StaleEffect, f.store.settleVerified(entry.token(), conflict, clock.value()));
    try t.expectEqual(effects.Status.applied, (try first(&f.store)).status);
    try t.expectEqual(@as(i64, 500), (try first(&f.store)).desired.finite);
}

test "native effects: full confirmation ledger permits existing dedup but refuses new event atomically" {
    var f = try Fixture.init();
    defer f.deinit();
    try admit(&f.store);
    var clock = TestClock{};
    const entry = try f.store.setOwner(try change("one", 1, .permanent), clock.value());
    try f.store.markDispatched(entry.token(), clock.value());
    _ = try f.store.settleVerified(entry.token(), observation(entry, 100, .permanent), clock.value());
    try sql(&f.store, "WITH RECURSIVE numbers(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM numbers WHERE n<65535) INSERT INTO confirmed_effect_events SELECT CAST(printf('%032d',n) AS BLOB),(SELECT scope_key FROM native_effects LIMIT 1),'filler-'||n,zeroblob(32),100 FROM numbers;");
    try t.expectEqual(@as(u64, effects.max_confirmed_events), try f.store.confirmedEffectEvents());
    _ = try f.store.settleVerified(entry.token(), observation(entry, 100, .permanent), clock.value());
    clock.now = 110;
    _ = try f.store.settleVerified(entry.token(), observation(entry, 110, .absent), clock.value());
    clock.now = 120;
    try f.store.markDispatched(entry.token(), clock.value());
    _ = try f.store.settleVerified(entry.token(), observation(entry, 120, .permanent), clock.value());
    const second = try f.store.setOwner(try change("two", 2, .permanent), clock.value());
    try f.store.markDispatched(second.token(), clock.value());
    const epoch = f.store.effect_publication_epoch;
    try t.expectError(error.EffectCapacity, f.store.settleVerified(second.token(), observation(second, 120, .permanent), clock.value()));
    try t.expectEqual(epoch, f.store.effect_publication_epoch);
    try t.expectEqual(effects.Status.dispatched, (try first(&f.store)).status);
    try t.expectEqual(@as(u64, effects.max_confirmed_events), try f.store.confirmedEffectEvents());
}

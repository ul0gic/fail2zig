// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const t = std.testing;
const durable = @import("core/record_store.zig");
const consumer = @import("core/native_consumer.zig");
const detection = @import("core/native_detection_record.zig");
const retry = @import("core/native_retry.zig");
const effects = @import("core/native_effect.zig");
const time = @import("core/source_time_policy.zig");
const Fixture = struct {
    tmp: t.TmpDir,
    path: []u8,
    store: durable.Store,
    fn init() !Fixture {
        var tmp = t.tmpDir(.{});
        errdefer tmp.cleanup();
        const root = try tmp.dir.realpathAlloc(t.allocator, ".");
        defer t.allocator.free(root);
        const path = try std.fs.path.join(t.allocator, &.{ root, "manifest.sqlite" });
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
const key = consumer.Key{ .kind = .correlation, .jail = "fixture", .source = "file", .rule = "login", .generation = [_]u8{1} ** 32 };
const requirements = [_]consumer.Requirement{.{ .key = key, .format_version = 1 }};
const manifest = consumer.Manifest{ .jail = "fixture", .source = "file", .source_generation = [_]u8{1} ** 32, .required = &requirements };
const Clock = struct {
    now: i64 = 100,
    advance: i64 = 0,
    fn read(ctx: ?*anyopaque) i64 {
        const self: *Clock = @ptrCast(@alignCast(ctx.?));
        const value = self.now;
        self.now += self.advance;
        return value;
    }
    fn batch(self: *Clock, deltas: []const consumer.Delta) consumer.Batch {
        return .{ .deltas = deltas, .prepared_us = 100, .clock_context = self, .clock = read };
    }
};
fn delta(revision: u64) consumer.Delta {
    return .{ .key = key, .format_version = 1, .expected_revision = revision, .payload = "retained-context" };
}
fn sql(store: *durable.Store, statement: [:0]const u8) !void {
    const run = @extern(*const fn (*anyopaque, [*:0]const u8, ?*anyopaque, ?*anyopaque, ?*?[*:0]u8) callconv(.c) c_int, .{ .name = "sqlite3_exec" });
    if (run(@ptrCast(store.db), statement, null, null, null) != 0) return error.TestSqlFailed;
}
fn basicRecord() durable.Record {
    return .{ .jail = "fixture", .source = "file", .occurrence = "1", .cursor = "1", .raw_hash = [_]u8{1} ** 32, .disposition = "counted", .checkpoint = "source" };
}

test "native consumer manifest: startup refuses missing manifest for retained source or receipt" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.store.enableConsumerManifests();
    try f.store.validateCustomSourceManifests("fixture");
    const pending_identity = durable.ReceiptIdentity{ .jail = "fixture", .source = "file", .generation = manifest.source_generation, .occurrence = "pending", .raw_hash = [_]u8{3} ** 32, .cursor = "pending" };
    _ = try f.store.beginReceipt(pending_identity, .{ .us = 100 }, 0);
    try t.expectError(error.MissingRequiredConsumer, f.store.validateCustomSourceManifests("fixture"));
    try t.expectEqual(@as(usize, 1), try f.store.pendingReceiptCount());
    try sql(&f.store, "DELETE FROM pending_receipts;");
    try f.store.admitConsumerManifest(manifest, .first_use);
    var clock = Clock{};
    var input = basicRecord();
    input.consumer_manifest = manifest;
    input.consumers = clock.batch(&.{delta(0)});
    _ = try f.store.commitRecord(input);
    try f.store.validateCustomSourceManifests("fixture");
    try sql(&f.store, "DELETE FROM consumer_requirements; DELETE FROM consumer_manifests;");
    try t.expectError(error.MissingRequiredConsumer, f.store.validateCustomSourceManifests("fixture"));
    try t.expectEqual(@as(u64, 1), try f.store.revision("fixture"));
}

test "native consumer manifest: first use resume missing state and immutable requirements" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.store.enableConsumerManifests();
    try t.expectError(error.ConsumerManifestMissing, f.store.admitConsumerManifest(manifest, .@"resume"));
    try f.store.admitConsumerManifest(manifest, .first_use);
    try t.expectError(error.ConsumerManifestExists, f.store.admitConsumerManifest(manifest, .first_use));
    var empty = try f.store.consumerManifestSnapshot(t.allocator, manifest);
    defer empty.deinit(t.allocator);
    try t.expectEqual(durable.Store.ManifestStatus.first_use, empty.status);
    try t.expectEqual(@as(u64, 0), empty.states[0].revision);
    var wrong = manifest;
    wrong.source_generation[0] = 2;
    try t.expectError(error.ConsumerManifestMismatch, f.store.admitConsumerManifest(wrong, .@"resume"));
    var clock = Clock{};
    var input = basicRecord();
    input.consumer_manifest = manifest;
    input.consumers = clock.batch(&.{delta(0)});
    _ = try f.store.commitRecord(input);
    try f.reopen();
    try f.store.admitConsumerManifest(manifest, .@"resume");
    var ready = try f.store.consumerManifestSnapshot(t.allocator, manifest);
    defer ready.deinit(t.allocator);
    try t.expectEqual(durable.Store.ManifestStatus.ready, ready.status);
    try t.expectEqualStrings("retained-context", ready.states[0].payload.?);
    try t.expectEqual(durable.CommitResult.already_committed, try f.store.commitRecord(input));
    try sql(&f.store, "PRAGMA ignore_check_constraints=ON; UPDATE consumer_checkpoints SET payload='corrupt';");
    try t.expectError(error.InvalidConsumer, f.store.commitRecord(input));
    try sql(&f.store, "DELETE FROM consumer_checkpoints;");
    try t.expectError(error.MissingRequiredConsumer, f.store.commitRecord(input));
    try t.expectError(error.MissingRequiredConsumer, f.store.admitConsumerManifest(manifest, .@"resume"));
    try t.expectError(error.MissingRequiredConsumer, f.store.consumerManifestSnapshot(t.allocator, manifest));
}

test "native consumer manifest: shared input bootstrap rollback CAS expiry and no source acknowledgment" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.store.enableConsumerManifests();
    var clock = Clock{};
    for ([_]durable.CommitStage{ .after_consumer_delta, .after_manifest_ready, .before_consumer_input_commit }) |stage| {
        f.store.fail_at = stage;
        try t.expectError(error.InjectedFailure, f.store.bootstrapConsumerManifest(manifest, clock.batch(&.{delta(0)})));
        try t.expectError(error.ConsumerManifestMissing, f.store.consumerManifestSnapshot(t.allocator, manifest));
    }
    f.store.fail_at = null;
    try f.store.bootstrapConsumerManifest(manifest, clock.batch(&.{delta(0)}));
    try t.expectError(error.ConsumerManifestExists, f.store.bootstrapConsumerManifest(manifest, clock.batch(&.{delta(0)})));
    try t.expectError(error.StaleConsumerCheckpoint, f.store.commitConsumerInput(manifest, clock.batch(&.{delta(0)})));
    var expiring = delta(1);
    expiring.valid_until_us = 101;
    clock.advance = 1;
    try t.expectError(error.ConsumerExpired, f.store.commitConsumerInput(manifest, clock.batch(&.{expiring})));
    clock.now = 101;
    clock.advance = 0;
    try f.store.commitConsumerInput(manifest, clock.batch(&.{delta(1)}));
    try t.expectEqual(@as(u64, 0), try f.store.revision("fixture"));
    try t.expectEqual(@as(usize, 0), try f.store.pendingReceiptCount());
    try t.expectEqual(@as(?[]u8, null), try f.store.sourceCursor(t.allocator, "fixture", "file"));
    try f.reopen();
    clock.now = 100;
    try t.expectError(error.ConsumerClockReversed, f.store.commitConsumerInput(manifest, clock.batch(&.{delta(2)})));
    var saved = try f.store.consumerManifestSnapshot(t.allocator, manifest);
    defer saved.deinit(t.allocator);
    try t.expectEqual(@as(u64, 2), saved.states[0].revision);
}

test "native consumer manifest: exact batch required keys formats and source generation cannot be omitted" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.store.enableConsumerManifests();
    try f.store.admitConsumerManifest(manifest, .first_use);
    var clock = Clock{};
    try t.expectError(error.ConsumerManifestRequired, f.store.commitRecord(basicRecord()));
    var input = basicRecord();
    input.consumer_manifest = manifest;
    input.consumers = clock.batch(&.{});
    try t.expectError(error.MissingRequiredConsumer, f.store.commitRecord(input));
    var wrong = delta(0);
    wrong.format_version = 2;
    input.consumers = clock.batch(&.{wrong});
    try t.expectError(error.InvalidConsumer, f.store.commitRecord(input));
    var extra = delta(0);
    extra.key.rule = "extra";
    input.consumers = clock.batch(&.{ delta(0), extra });
    try t.expectError(error.ConsumerManifestMismatch, f.store.commitRecord(input));
    input.consumers = clock.batch(&.{delta(0)});
    f.store.fail_at = .before_commit;
    try t.expectError(error.InjectedFailure, f.store.commitRecord(input));
    f.store.fail_at = null;
    _ = try f.store.commitRecord(input);
    try t.expectEqual(@as(u64, 1), try f.store.revision("fixture"));
}

const identity = durable.ReceiptIdentity{ .jail = "fixture", .source = "file", .occurrence = "1", .cursor = "1", .raw_hash = [_]u8{1} ** 32, .generation = [_]u8{1} ** 32 };
const policy = retry.Policy{ .maxretry = 1, .window_us = 1000, .duration = .{ .finite_us = 400 }, .max_subjects = 32, .enforce = true };
fn candidate(last: u8) !detection.Outcome {
    return .{ .kind = .candidate, .generation = identity.generation, .filter = try detection.Name.init("dns-login"), .pattern = try detection.Name.init("failure"), .pattern_index = 0, .subject = .{ .v4 = .{ 192, 0, 2, last } } };
}
fn fanoutRecord(clock: *Clock, values: []const detection.Outcome) !durable.Record {
    const outcome = try time.evaluate(.timestamped, .{ .parsed = .{ .us = 100 } }, .{ .us = 100 }, .{ .us = 100 }, 1000);
    return .{ .jail = identity.jail, .source = identity.source, .occurrence = identity.occurrence, .cursor = identity.cursor, .raw_hash = identity.raw_hash, .receipt = .{ .time = .{ .us = 100 }, .generation = identity.generation }, .native_time_outcome = outcome, .native_detections = values, .native_retry = .{ .generation = identity.generation, .policy = policy, .processing_us = 100 }, .effects_clock = .{ .prepared_us = 100, .context = clock, .read = Clock.read }, .disposition = outcome.disposition(), .checkpoint = "all-subjects" };
}
fn prepareFanout(store: *durable.Store) !void {
    try store.admitInstallation(try effects.Installation.init([_]u8{7} ** 16, .nftables, "fixture"), .{ .selector = "fixture", .disposition = .verified_absent });
    try store.admitRetry("fixture", identity.generation, policy);
    _ = try store.beginReceipt(identity, .{ .us = 100 }, 0);
}

test "native consumer manifest: sixteen subjects retry effects and receipt commit atomically" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.store.enableConsumerManifests();
    try f.store.admitConsumerManifest(manifest, .first_use);
    try prepareFanout(&f.store);
    var clock = Clock{};
    var values: [16]detection.Outcome = undefined;
    for (&values, 0..) |*value, i| value.* = try candidate(@intCast(i + 1));
    var input = try fanoutRecord(&clock, &values);
    input.consumer_manifest = manifest;
    input.consumers = clock.batch(&.{delta(0)});
    for ([_]durable.CommitStage{ .after_detection, .after_retry_state, .after_retry_decision, .after_effect_intent, .after_receipt_delete, .before_commit }) |stage| {
        f.store.fail_at = stage;
        try t.expectError(error.InjectedFailure, f.store.commitRecord(input));
        try t.expectEqual(@as(u64, 0), try f.store.revision("fixture"));
        try t.expectEqual(@as(usize, 1), try f.store.pendingReceiptCount());
        var entries: [16]effects.Entry = undefined;
        try t.expectEqual(@as(usize, 0), (try f.store.effectPage(null, null, &entries)).count);
    }
    f.store.fail_at = null;
    _ = try f.store.commitRecord(input);
    try t.expectEqual(durable.CommitResult.already_committed, try f.store.commitRecord(input));
    try f.reopen();
    var decoded: [16]detection.Outcome = undefined;
    var decisions: [16]retry.Decision = undefined;
    try t.expectEqual(@as(usize, 16), try f.store.nativeDetections("fixture", "file", null, &decoded));
    try t.expectEqual(@as(usize, 16), try f.store.retryDecisions("fixture", "file", null, &decisions));
    try t.expectError(error.AmbiguousNativeDetection, f.store.nativeDetection("fixture", "file", null));
    try t.expectError(error.AmbiguousRetryDecision, f.store.retryDecision("fixture", "file", null));
    try t.expectError(error.ConsumerCapacity, f.store.nativeDetections("fixture", "file", null, decoded[0..15]));
    for (decisions) |decision| try t.expectEqual(@as(i64, 500), decision.lease.finite);
    var entries: [16]effects.Entry = undefined;
    try t.expectEqual(@as(usize, 16), (try f.store.effectPage(null, null, &entries)).count);
    try t.expectEqual(@as(usize, 0), try f.store.pendingReceiptCount());
}

test "native consumer manifest: zero seventeen duplicate and mixed scalar fanout refuse whole input" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.store.enableConsumerManifests();
    try prepareFanout(&f.store);
    var clock = Clock{};
    var values: [17]detection.Outcome = undefined;
    for (&values, 0..) |*value, i| value.* = try candidate(@intCast(i + 1));
    try t.expectError(error.InvalidRecord, f.store.commitRecord(try fanoutRecord(&clock, values[0..0])));
    try t.expectError(error.InvalidRecord, f.store.commitRecord(try fanoutRecord(&clock, &values)));
    values[1] = values[0];
    try t.expectError(error.InvalidRecord, f.store.commitRecord(try fanoutRecord(&clock, values[0..2])));
    var input = try fanoutRecord(&clock, values[0..1]);
    input.native_detection = values[0];
    try t.expectError(error.InvalidRecord, f.store.commitRecord(input));
    try t.expectEqual(@as(usize, 1), try f.store.pendingReceiptCount());
}

test "native consumer manifest: schema migration preserves scalar detection retry and rollback" {
    var f = try Fixture.init();
    defer f.deinit();
    try prepareFanout(&f.store);
    var clock = Clock{};
    var input = try fanoutRecord(&clock, &.{});
    input.native_detections = null;
    input.native_detection = try candidate(1);
    _ = try f.store.commitRecord(input);
    f.store.fail_at = .before_manifest_schema_commit;
    try t.expectError(error.InjectedFailure, f.store.enableConsumerManifests());
    try t.expectEqual(@as(i64, 11), f.store.schema_version);
    f.store.fail_at = null;
    try f.store.enableConsumerManifests();
    try t.expectEqualDeep(input.native_detection.?, (try f.store.nativeDetection("fixture", "file", null)).?);
    try t.expectEqual(@as(i64, 500), (try f.store.retryDecision("fixture", "file", null)).?.lease.finite);
    try t.expectError(error.ConsumerMigrationRequired, f.store.admitConsumerManifest(manifest, .first_use));
}

test "native consumer manifest: detached restore allocation failures and corrupted requirements refuse" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.store.enableConsumerManifests();
    var clock = Clock{};
    try f.store.bootstrapConsumerManifest(manifest, clock.batch(&.{delta(0)}));
    var failing = std.testing.FailingAllocator.init(t.allocator, .{ .fail_index = 0 });
    try t.expectError(error.OutOfMemory, f.store.consumerManifestSnapshot(failing.allocator(), manifest));
    try sql(&f.store, "UPDATE consumer_requirements SET format=2;");
    try t.expectError(error.InvalidConsumer, f.store.consumerManifestSnapshot(t.allocator, manifest));
    try sql(&f.store, "UPDATE consumer_requirements SET format=1; PRAGMA ignore_check_constraints=ON; UPDATE consumer_checkpoints SET payload='not-a-blob';");
    try t.expectError(error.InvalidConsumer, f.store.consumerManifestSnapshot(t.allocator, manifest));
}

test "native consumer manifest: shared keys preserve one CAS across exact source manifests" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.store.enableConsumerManifests();
    var clock = Clock{};
    try f.store.bootstrapConsumerManifest(manifest, clock.batch(&.{delta(0)}));
    var second = manifest;
    second.jail = "second";
    second.source = "another-file";
    var reads = clock.batch(&.{});
    reads.dependencies = &.{.{ .key = key, .expected_revision = 1 }};
    try f.store.bootstrapConsumerManifest(second, reads);
    try f.store.commitConsumerInput(manifest, clock.batch(&.{delta(1)}));
    try t.expectError(error.StaleConsumerCheckpoint, f.store.commitConsumerInput(second, reads));
    var saved = try f.store.consumerManifestSnapshot(t.allocator, second);
    defer saved.deinit(t.allocator);
    try t.expectEqual(@as(u64, 2), saved.states[0].revision);
    var changed = key;
    changed.generation[0] = 9;
    var incompatible = second;
    incompatible.source = "new-source";
    incompatible.required = &.{.{ .key = changed, .format_version = 1 }};
    try t.expectError(error.ConsumerMigrationRequired, f.store.admitConsumerManifest(incompatible, .first_use));
}

test "native consumer manifest: coherent sixteen-row snapshot releases every partial allocation" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.store.enableConsumerManifests();
    var names: [16][8]u8 = undefined;
    var required: [16]consumer.Requirement = undefined;
    var deltas: [16]consumer.Delta = undefined;
    for (&required, &deltas, &names, 0..) |*requirement, *change, *name, i| {
        var item = key;
        item.rule = try std.fmt.bufPrint(name, "rule-{d}", .{i});
        requirement.* = .{ .key = item, .format_version = 1 };
        change.* = .{ .key = item, .format_version = 1, .expected_revision = 0, .payload = "original context" };
    }
    var all = manifest;
    all.required = &required;
    var clock = Clock{};
    try f.store.bootstrapConsumerManifest(all, clock.batch(&deltas));
    for (0..16) |fail_index| {
        var failing = t.FailingAllocator.init(t.allocator, .{ .fail_index = fail_index });
        try t.expectError(error.OutOfMemory, f.store.consumerManifestSnapshot(failing.allocator(), all));
    }
    var saved = try f.store.consumerManifestSnapshot(t.allocator, all);
    defer saved.deinit(t.allocator);
    try t.expectEqual(@as(usize, 16), saved.count);
    for (saved.states[0..saved.count]) |state| try t.expectEqualStrings("original context", state.payload.?);
}

test "native consumer manifest: SIGKILL before and after migration bootstrap shared input and fanout commit" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    for ([_]enum { migration, bootstrap, shared, fanout }{ .migration, .bootstrap, .shared, .fanout }) |stage| for ([_]bool{ false, true }) |after| {
        var f = try Fixture.init();
        defer f.deinit();
        var clock = Clock{};
        if (stage != .migration) try f.store.enableConsumerManifests();
        if (stage == .shared) try f.store.bootstrapConsumerManifest(manifest, clock.batch(&.{delta(0)}));
        if (stage == .fanout) {
            try f.store.admitConsumerManifest(manifest, .first_use);
            try prepareFanout(&f.store);
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
                    unreachable;
                }
            };
            Kill.actual = child.api.exec;
            Kill.after_commit = after;
            child.api.exec = Kill.exec;
            switch (stage) {
                .migration => child.enableConsumerManifests() catch std.process.exit(6),
                .bootstrap => child.bootstrapConsumerManifest(manifest, clock.batch(&.{delta(0)})) catch std.process.exit(7),
                .shared => child.commitConsumerInput(manifest, clock.batch(&.{delta(1)})) catch std.process.exit(8),
                .fanout => {
                    const values = [_]detection.Outcome{ candidate(1) catch std.process.exit(9), candidate(2) catch std.process.exit(10) };
                    var input = fanoutRecord(&clock, &values) catch std.process.exit(11);
                    input.consumer_manifest = manifest;
                    input.consumers = clock.batch(&.{delta(0)});
                    _ = child.commitRecord(input) catch std.process.exit(12);
                },
            }
            std.process.exit(13);
        }
        const ended = std.posix.waitpid(pid, 0);
        f.store = try durable.Store.open(t.allocator, f.path);
        try f.store.enableReceipts(8);
        try t.expect(std.posix.W.IFSIGNALED(ended.status));
        try t.expectEqual(@as(u32, std.posix.SIG.KILL), std.posix.W.TERMSIG(ended.status));
        switch (stage) {
            .migration => try t.expectEqual(@as(i64, if (after) 12 else 11), f.store.schema_version),
            .bootstrap => {
                if (after) {
                    var saved = try f.store.consumerManifestSnapshot(t.allocator, manifest);
                    defer saved.deinit(t.allocator);
                    try t.expectEqual(durable.Store.ManifestStatus.ready, saved.status);
                    try t.expectEqual(@as(u64, 1), saved.states[0].revision);
                } else try t.expectError(error.ConsumerManifestMissing, f.store.consumerManifestSnapshot(t.allocator, manifest));
            },
            .shared => {
                var saved = try f.store.consumerManifestSnapshot(t.allocator, manifest);
                defer saved.deinit(t.allocator);
                try t.expectEqual(@as(u64, if (after) 2 else 1), saved.states[0].revision);
                try t.expectEqual(@as(u64, 0), try f.store.revision("fixture"));
            },
            .fanout => {
                try t.expectEqual(@as(u64, @intFromBool(after)), try f.store.revision("fixture"));
                try t.expectEqual(@as(usize, @intFromBool(!after)), try f.store.pendingReceiptCount());
                var decisions: [16]retry.Decision = undefined;
                try t.expectEqual(@as(usize, if (after) 2 else 0), try f.store.retryDecisions("fixture", "file", "1", &decisions));
                var saved = try f.store.consumerManifestSnapshot(t.allocator, manifest);
                defer saved.deinit(t.allocator);
                try t.expectEqual(@as(u64, @intFromBool(after)), saved.states[0].revision);
                var entries: [16]effects.Entry = undefined;
                try t.expectEqual(@as(usize, if (after) 2 else 0), (try f.store.effectPage(null, null, &entries)).count);
            },
        }
    };
}

test "native consumer manifest: paged dynamic discovery and restore recheck fence same-time commits" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.store.enableConsumerManifests();
    var clock = Clock{};
    try f.store.bootstrapConsumerManifest(manifest, clock.batch(&.{delta(0)}));
    var second = manifest;
    second.source = "second";
    var read = clock.batch(&.{});
    read.dependencies = &.{.{ .key = key, .expected_revision = 1 }};
    try f.store.bootstrapConsumerManifest(second, read);
    var snapshot = try f.store.consumerManifestSnapshot(t.allocator, manifest);
    defer snapshot.deinit(t.allocator);
    try f.store.validateConsumerManifestSnapshot(manifest, &snapshot);
    var keys: [1]durable.Store.ManifestKey = undefined;
    const page = try f.store.consumerManifestKeysPage(t.allocator, "fixture", null, null, &keys);
    defer keys[0].deinit(t.allocator);
    try t.expect(page.more);
    try t.expectEqualStrings("file", keys[0].source);
    var rest: [1]durable.Store.ManifestKey = undefined;
    const last = try f.store.consumerManifestKeysPage(t.allocator, "fixture", keys[0].source, page.revision, &rest);
    defer rest[0].deinit(t.allocator);
    try t.expect(!last.more);
    try t.expectEqualStrings("second", rest[0].source);
    var failing = t.FailingAllocator.init(t.allocator, .{ .fail_index = 0 });
    try t.expectError(error.OutOfMemory, f.store.consumerManifestKeysPage(failing.allocator(), "fixture", null, null, &rest));
    try f.store.commitConsumerInput(manifest, clock.batch(&.{delta(1)}));
    try t.expectError(error.StaleConsumerCheckpoint, f.store.validateConsumerManifestSnapshot(manifest, &snapshot));
    try t.expectError(error.StaleConsumerCheckpoint, f.store.consumerManifestKeysPage(t.allocator, "fixture", keys[0].source, page.revision, &rest));
}

test "native consumer manifest: complete runtime set refuses omitted or unreferenced consumers" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.store.enableConsumerManifests();
    var clock = Clock{};
    try f.store.bootstrapConsumerManifest(manifest, clock.batch(&.{delta(0)}));
    try t.expectError(error.NativeConsumersNotIntegrated, f.store.validateRuntimeOwners(&.{"fixture"}));
    try t.expectError(error.ConsumerManifestMismatch, f.store.validateRuntimeOwnersWithManifests(&.{"fixture"}, &.{}));
    try f.store.validateRuntimeOwnersWithManifests(&.{"fixture"}, &.{manifest});
    try sql(&f.store, "INSERT INTO consumer_checkpoints SELECT kind,jail,source,'orphan',generation,format,revision,payload,valid_until_us FROM consumer_checkpoints;");
    try t.expectError(error.ConsumerManifestMismatch, f.store.validateRuntimeOwnersWithManifests(&.{"fixture"}, &.{manifest}));
}

test "native consumer manifest: SQLite NOMEM at shared commit rolls back manifest and rows" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.store.enableConsumerManifests();
    var clock = Clock{};
    const Fault = struct {
        const Db = std.meta.Child(@FieldType(durable.Store, "db"));
        const Exec = @FieldType(@FieldType(durable.Store, "api"), "exec");
        var actual: Exec = undefined;
        fn exec(db: *Db, statement: [*:0]const u8, callback: ?*anyopaque, ctx: ?*anyopaque, message: ?*?[*:0]u8) callconv(.c) c_int {
            if (std.mem.eql(u8, std.mem.span(statement), "COMMIT;")) return 7;
            return actual(db, statement, callback, ctx, message);
        }
    };
    Fault.actual = f.store.api.exec;
    f.store.api.exec = Fault.exec;
    try t.expectError(error.OutOfMemory, f.store.bootstrapConsumerManifest(manifest, clock.batch(&.{delta(0)})));
    f.store.api.exec = Fault.actual;
    try t.expectError(error.ConsumerManifestMissing, f.store.consumerManifestSnapshot(t.allocator, manifest));
    const state = try f.store.consumerSnapshot(t.allocator, key);
    defer state.deinit(t.allocator);
    try t.expectEqual(@as(u64, 0), state.revision);
    try f.reopen();
    try f.store.bootstrapConsumerManifest(manifest, clock.batch(&.{delta(0)}));
}

test "native consumer manifest: all-jail generation preflight refuses before fresh registration" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.store.enableConsumerManifests();
    const startup_policy = retry.Policy{ .maxretry = 2, .window_us = 1000, .duration = .{ .finite_us = 1000 }, .max_subjects = 8 };
    const retained = [_]u8{7} ** 32;
    const changed = [_]u8{8} ** 32;
    try f.store.admitRetry("retained", retained, startup_policy);
    const total_changes = @extern(*const fn (*anyopaque) callconv(.c) i64, .{ .name = "sqlite3_total_changes64" });
    const before = total_changes(@ptrCast(f.store.db));
    const bindings = [_]durable.Store.RuntimeAdmission{
        .{ .jail = "new-first", .generation = retained, .policy = startup_policy },
        .{ .jail = "retained", .generation = changed, .policy = startup_policy },
    };
    try t.expectError(error.RetryGenerationMismatch, f.store.validateRuntimeAdmissions(&bindings, null));
    try t.expectEqual(before, total_changes(@ptrCast(f.store.db)));
    try f.reopen();
    try f.store.validateRuntimeAdmissions(&.{.{ .jail = "retained", .generation = retained, .policy = startup_policy }}, null);
    var compatible = bindings;
    compatible[1].generation = retained;
    try f.store.validateRuntimeAdmissions(&compatible, null);
    try f.store.validateRuntimeAdmissions(&.{.{ .jail = "retained", .generation = retained, .policy = startup_policy }}, null);
    try t.expectError(error.UnconfiguredStateOwner, f.store.validateRuntimeAdmissions(bindings[0..1], null));
    var changed_policy = startup_policy;
    changed_policy.max_subjects = 4;
    try t.expectError(error.RetryGenerationMismatch, f.store.validateRuntimeAdmissions(&.{.{ .jail = "retained", .generation = retained, .policy = changed_policy }}, null));
}

test "native consumer manifest: generation preflight rejects unconfigured or changed consumer owners" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.store.enableConsumerManifests();
    const startup_policy = retry.Policy{ .maxretry = 2, .window_us = 1000, .duration = .{ .finite_us = 1000 }, .max_subjects = 8 };
    try f.store.admitConsumerManifest(manifest, .first_use);
    const binding = durable.Store.RuntimeAdmission{ .jail = "fixture", .generation = manifest.source_generation, .policy = startup_policy, .custom = true };
    try f.store.validateRuntimeAdmissions(&.{binding}, null);
    var altered = binding;
    altered.custom = false;
    try t.expectError(error.UnconfiguredStateOwner, f.store.validateRuntimeAdmissions(&.{altered}, null));
    altered = binding;
    altered.generation = [_]u8{3} ** 32;
    try t.expectError(error.ConsumerGenerationMismatch, f.store.validateRuntimeAdmissions(&.{altered}, null));
    try f.store.validateRuntimeAdmissions(&.{binding}, null);
}

test "native consumer manifest: startup admission is invisible until commit and abort restores all owners" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.store.enableConsumerManifests();
    try f.store.admitRetry("retained", key.generation, policy);
    var observer = try durable.Store.open(t.allocator, f.path);
    defer observer.close();
    try f.store.beginStartupAdmission();
    try f.store.admitRetry("fresh", key.generation, policy);
    try t.expectError(error.ConsumerManifestMissing, f.store.consumerManifestSnapshot(t.allocator, manifest));
    try t.expect(f.store.startupAdmissionActive());
    try observer.validateRuntimeOwnerNames(&.{"retained"});
    var clock = Clock{};
    var changes = [_]consumer.Delta{delta(0)};
    f.store.fail_at = .before_consumer_input_commit;
    try t.expectError(error.InjectedFailure, f.store.bootstrapConsumerManifest(manifest, clock.batch(&changes)));
    f.store.fail_at = null;
    try t.expect(f.store.startupAdmissionActive());
    f.store.abortStartupAdmission();
    try f.store.validateRuntimeOwnerNames(&.{"retained"});
    try t.expectError(error.ConsumerManifestMissing, f.store.consumerManifestSnapshot(t.allocator, manifest));
    try f.store.beginStartupAdmission();
    try f.store.admitRetry("fresh", key.generation, policy);
    try f.store.bootstrapConsumerManifest(manifest, clock.batch(&changes));
    try t.expectError(error.DatabaseFailure, f.store.commitRecord(basicRecord()));
    try t.expectError(error.DatabaseFailure, f.store.commitConsumerInput(manifest, clock.batch(&changes)));
    try f.store.finishStartupAdmission();
    try t.expect(!f.store.startupAdmissionActive());
    try t.expectError(error.UnconfiguredStateOwner, observer.validateRuntimeOwnerNames(&.{"retained"}));
    try f.store.validateRuntimeOwnerNames(&.{ "retained", "fresh" });
    var saved = try f.store.consumerManifestSnapshot(t.allocator, manifest);
    defer saved.deinit(t.allocator);
    try t.expectEqual(durable.Store.ManifestStatus.ready, saved.status);
}

test "native consumer manifest: killed startup admission leaves no partial registrations" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(root);
    const path = try std.fs.path.join(t.allocator, &.{ root, "startup.sqlite" });
    defer t.allocator.free(path);
    {
        var store = try durable.Store.open(t.allocator, path);
        defer store.close();
        try store.enableReceipts(8);
        try store.enableNativeTime();
        try store.enableDetection();
        try store.enableClockRecovery();
        try store.enableJournalDetection();
        try store.enableRetry();
        try store.enableConsumers();
        try store.enableEffects();
        try store.enableConsumerManifests();
        try store.admitRetry("retained", key.generation, policy);
    }
    const ready = try std.posix.pipe();
    defer std.posix.close(ready[0]);
    const pid = try std.posix.fork();
    if (pid == 0) {
        std.posix.close(ready[0]);
        var store = durable.Store.open(t.allocator, path) catch std.process.exit(2);
        store.enableReceipts(8) catch std.process.exit(3);
        store.beginStartupAdmission() catch std.process.exit(4);
        store.admitRetry("fresh", key.generation, policy) catch std.process.exit(5);
        var clock = Clock{};
        var changes = [_]consumer.Delta{delta(0)};
        store.bootstrapConsumerManifest(manifest, clock.batch(&changes)) catch std.process.exit(6);
        _ = std.posix.write(ready[1], "R") catch std.process.exit(7);
        while (true) std.Thread.sleep(std.time.ns_per_s);
    }
    std.posix.close(ready[1]);
    var reaped = false;
    defer if (!reaped) {
        std.posix.kill(pid, std.posix.SIG.KILL) catch {};
        _ = std.posix.waitpid(pid, 0);
    };
    var poll_fds = [_]std.posix.pollfd{.{ .fd = ready[0], .events = std.posix.POLL.IN, .revents = 0 }};
    try t.expectEqual(@as(usize, 1), try std.posix.poll(&poll_fds, 5000));
    var marker: [1]u8 = undefined;
    try t.expectEqual(@as(usize, 1), try std.posix.read(ready[0], &marker));
    try t.expectEqual(@as(u8, 'R'), marker[0]);
    try std.posix.kill(pid, std.posix.SIG.KILL);
    _ = std.posix.waitpid(pid, 0);
    reaped = true;
    var restored = try durable.Store.open(t.allocator, path);
    defer restored.close();
    try restored.enableReceipts(8);
    try restored.validateRuntimeOwnerNames(&.{"retained"});
    try t.expectError(error.ConsumerManifestMissing, restored.consumerManifestSnapshot(t.allocator, manifest));
}

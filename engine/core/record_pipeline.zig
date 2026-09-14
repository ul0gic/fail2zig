// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const records = @import("source_record.zig");
const durable = @import("record_store.zig");
const health = @import("storage_health.zig");
const time = @import("native_time.zig");

pub const ReceiptAdmission = struct {
    generation: [32]u8,
    clock_context: ?*anyopaque = null,
    clock: *const fn (?*anyopaque) anyerror!time.Timestamp = systemClock,

    fn systemClock(_: ?*anyopaque) !time.Timestamp {
        return .{ .us = std.time.microTimestamp() };
    }
};
const CandidateReceipt = struct { identity: [32]u8, time: time.Timestamp };

/// prepare must leave live state unchanged. Its payload owns all resources
/// needed by publish; publish cannot allocate or fail after the durable commit.
pub const Prepared = struct {
    checkpoint: []const u8,
    disposition: []const u8,
    event_time: ?f64 = null,
    native_time: ?@import("source_time_policy.zig").Result = null,
    zone_provenance: ?@import("native_time_record.zig").Provenance = null,
    effects_clock: ?@import("native_effect.zig").Clock = null,
    native_detection: ?@import("native_detection_record.zig").Outcome = null,
    native_detections: ?[]const @import("native_detection_record.zig").Outcome = null,
    native_retry: ?@import("native_retry.zig").Admission = null,
    retry_evidence: @import("native_retry.zig").Evidence = .{},
    intent: ?[]const u8 = null,
    shared_state: ?durable.SharedState = null,
    consumers: ?@import("native_consumer.zig").Batch = null,
    consumer_manifest: ?@import("native_consumer.zig").Manifest = null,
    context: ?*anyopaque,
    publish: *const fn (?*anyopaque) void,
    release: *const fn (?*anyopaque) void,
};
pub const Restored = struct {
    context: ?*anyopaque,
    publish: *const fn (?*anyopaque) void,
    release: *const fn (?*anyopaque) void,
};
pub const Processor = struct {
    context: ?*anyopaque,
    prepare: *const fn (records.Record, ?*anyopaque) anyerror!Prepared,
    /// Validate and stage without modifying live state. Publication follows the
    /// revision recheck; allocation/decoder/CAS failure must keep the old owner.
    prepare_restore: *const fn (?[]const u8, ?*anyopaque) anyerror!Restored,
};
pub const Pipeline = struct {
    store: *durable.Store,
    jail: []const u8,
    processor: Processor,
    ready: bool = false,
    revision: u64 = 0,
    /// Native coordinator supplies the same gate to every pipeline using a store.
    /// Null preserves the staged legacy component interface during conversion.
    gate: ?*health.Gate = null,
    recovery_generation: u64 = 0,
    /// Opt in only for native processors after explicit store/schema admission.
    /// Capture occurs on a complete record, before decoding/time preparation.
    receipts: ?ReceiptAdmission = null,
    /// An unsuccessful first receipt write retains its proposed clock boundary.
    /// The serialized owner must retry this occurrence before observing another.
    candidate_receipt: ?CandidateReceipt = null,

    /// Source sessions call this before reading/framing, and acknowledge checks
    /// again before preparing state. Recovery must restore every admitted owner.
    pub fn admit(self: *Pipeline) !void {
        if (self.gate) |gate| try gate.admit(self.recovery_generation);
        if (!self.ready) return error.RestoreRequired;
        // Schema-7 owners check the global durable floor before reading another
        // record and again before publication. Older component schemas retain
        // their previous admission contract until explicitly migrated.
        if (self.store.schema_version >= 7) if (self.receipts) |admission| {
            const floor = self.store.admissionClock() catch |failure| {
                self.failed(failure);
                return failure;
            };
            if (floor) |value| if ((try admission.clock(admission.clock_context)).us < value.us) {
                self.receiptClockFailed(value.us);
                return error.ReceiptClockReversed;
            };
        };
    }

    pub fn receiptClockFailed(self: *Pipeline, floor_us: i64) void {
        self.ready = false;
        if (self.gate) |gate| gate.receiptClockFailed(floor_us);
    }

    fn failed(self: *Pipeline, cause: anyerror) void {
        // A changed source occurrence/configuration is not evidence that the
        // shared store is unavailable. Isolate it without stopping other owners.
        if (cause == error.ConsumerExpired or cause == error.ConsumerPending or cause == error.EffectExpired) return; // Release stage and resolve/reprepare the same receipt.
        if (cause == error.EffectClockReversed) {
            const floor = self.store.admissionClock() catch {
                self.ready = false;
                if (self.gate) |gate| gate.failed(cause, .{});
                return;
            };
            self.receiptClockFailed(if (floor) |value| value.us else std.time.microTimestamp());
            return;
        }
        if (cause == error.ConsumerClockReversed) {
            const floor = self.store.consumer_clock_floor_us orelse {
                self.ready = false;
                if (self.gate) |gate| gate.failed(error.InvalidConsumer, .{});
                return;
            };
            self.receiptClockFailed(floor);
            return;
        }
        // Source sessions fence these inputs without changing committed state.
        if (sourceLocalIntervention(cause)) return;
        if (cause == error.ReceiptConflict) {
            self.ready = false;
            return;
        }
        if (self.gate) |gate| {
            self.ready = false;
            gate.failed(cause, .{
                .sqlite_code = self.store.last_error_code,
                .rollback_code = self.store.rollback_error_code,
                .reopen_required = self.store.reopen_required,
            });
        }
    }

    fn beginDiagnostics(self: *Pipeline) void {
        // Preserve the original cause on a poisoned connection. Otherwise these
        // fields describe this operation, including failures before SQLite runs.
        if (!self.store.reopen_required) {
            self.store.last_error_code = null;
            self.store.rollback_error_code = null;
        }
    }

    pub fn restore(self: *Pipeline, allocator: std.mem.Allocator) anyerror!void {
        self.ready = false;
        if (self.gate) |gate| {
            const status = gate.snapshot();
            if (status.phase != .recovering or status.recovery_step != .state) return error.RecoveryOutOfOrder;
        }
        self.beginDiagnostics();
        self.restoreCommitted(allocator) catch |failure| {
            self.failed(failure);
            return failure;
        };
    }

    fn restoreCommitted(self: *Pipeline, allocator: std.mem.Allocator) !void {
        if (self.receipts) |admission| try self.store.validateReceiptGeneration(self.jail, admission.generation);
        const checkpoint = try self.store.snapshot(allocator, self.jail);
        defer checkpoint.deinit(allocator);
        const staged = try self.processor.prepare_restore(checkpoint.payload, self.processor.context);
        defer staged.release(staged.context);
        if (try self.store.revision(self.jail) != checkpoint.revision) return error.StaleCheckpoint;
        staged.publish(staged.context);
        self.revision = checkpoint.revision;
        if (self.gate) |gate| self.recovery_generation = gate.snapshot().generation;
        self.ready = true;
    }

    /// These failures leave committed consumer state intact. The source session
    /// retains its exact pending input and intervention cause; sibling sources
    /// may continue through this restored pipeline.
    pub fn sourceLocalIntervention(cause: anyerror) bool {
        return cause == error.PrunedReplay or cause == error.OutsideTimezoneCoverage;
    }

    pub fn acknowledge(record: records.Record, context: ?*anyopaque) anyerror!void {
        const self: *Pipeline = @ptrCast(@alignCast(context orelse return error.MissingPipeline));
        try self.admit();
        self.beginDiagnostics();
        self.acknowledgeAdmitted(record) catch |failure| {
            // Decoder/matcher failure belongs to this source owner. It does not
            // establish a storage outage for otherwise independent jails.
            // Dependency waits and expired preparation keep the same restored
            // owner/receipt. Invalidating it here would discard a same-turn DNS
            // answer even though failed() deliberately keeps the gate healthy.
            if (self.gate != null and failure != error.ConsumerExpired and failure != error.ConsumerPending and failure != error.EffectExpired and !sourceLocalIntervention(failure)) self.ready = false;
            return failure;
        };
    }

    fn acknowledgeAdmitted(self: *Pipeline, record: records.Record) !void {
        const exists = self.store.hasRecord(self.jail, record.source, record.occurrence, record.raw_hash, record.cursor) catch |failure| {
            self.failed(failure);
            return failure;
        };
        if (exists) {
            if (self.receipts) |admission| if (record.kind == .data) {
                const saved = self.store.committedReceipt(self.receiptIdentity(record, admission)) catch |failure| {
                    self.failed(failure);
                    return failure;
                };
                if (saved == null) {
                    self.failed(error.RestoreRequired);
                    return error.RestoreRequired;
                }
            };
            const revision = self.store.revision(self.jail) catch |failure| {
                self.failed(failure);
                return failure;
            };
            if (revision != self.revision) {
                self.ready = false;
                self.failed(error.RestoreRequired);
                return error.RestoreRequired;
            }
            if (self.receipts) |admission| if (self.candidate_receipt) |candidate| {
                if (std.mem.eql(u8, &candidate.identity, &receiptKey(self.receiptIdentity(record, admission)))) self.candidate_receipt = null;
            };
            return;
        }
        var observed = record;
        var receipt: ?durable.Receipt = null;
        if (self.receipts) |admission| if (record.kind == .data) {
            const identity = self.receiptIdentity(record, admission);
            const key = receiptKey(identity);
            if (self.candidate_receipt) |candidate| {
                if (!std.mem.eql(u8, &candidate.identity, &key)) return error.ReceiptRetryRequired;
            } else self.candidate_receipt = .{ .identity = key, .time = try admission.clock(admission.clock_context) };
            const saved = self.store.beginReceipt(identity, self.candidate_receipt.?.time, self.revision) catch |failure| {
                const cause = if (failure == error.ReceiptAlreadyCommitted) error.ConcurrentWriter else failure;
                self.failed(cause);
                return cause;
            };
            self.candidate_receipt = null;
            observed.receipt_time = saved;
            receipt = .{ .time = saved, .generation = admission.generation };
            try self.admit();
        };
        const prepared = self.processor.prepare(observed, self.processor.context) catch |failure| {
            if (failure == error.ReceiptClockReversed) if (observed.receipt_time) |saved| self.receiptClockFailed(saved.us);
            return failure;
        };
        defer prepared.release(prepared.context);
        try self.admit();
        const result = self.store.commitRecord(.{
            .jail = self.jail,
            .source = record.source,
            .source_path = record.source_path,
            .occurrence = record.occurrence,
            .cursor = record.cursor,
            .raw_hash = record.raw_hash,
            .event_time = prepared.event_time,
            .timestamp_us = record.timestamp_us,
            .receipt = receipt,
            .native_time_outcome = prepared.native_time,
            .zone_provenance = prepared.zone_provenance,
            .effects_clock = prepared.effects_clock,
            .native_detection = prepared.native_detection,
            .native_detections = prepared.native_detections,
            .native_retry = prepared.native_retry,
            .retry_evidence = prepared.retry_evidence,
            .expected_revision = self.revision,
            .disposition = prepared.disposition,
            .checkpoint = prepared.checkpoint,
            .action_intent = prepared.intent,
            .shared_state = prepared.shared_state,
            .consumers = prepared.consumers,
            .consumer_manifest = prepared.consumer_manifest,
        }) catch |err| {
            if (err == error.StaleCheckpoint or err == error.StaleSharedCheckpoint or err == error.StaleConsumerCheckpoint) self.ready = false;
            self.failed(err);
            return err;
        };
        // A single owner processes each jail. Another writer appearing between
        // lookup and commit invalidates this owner's in-memory snapshot.
        if (result == .already_committed) {
            self.ready = false;
            self.failed(error.ConcurrentWriter);
            return error.ConcurrentWriter;
        }
        self.revision += 1;
        prepared.publish(prepared.context);
        if (self.gate) |gate| gate.committed();
    }

    fn receiptIdentity(self: *const Pipeline, record: records.Record, admission: ReceiptAdmission) durable.ReceiptIdentity {
        return .{ .jail = self.jail, .source = record.source, .occurrence = record.occurrence, .cursor = record.cursor, .raw_hash = record.raw_hash, .generation = admission.generation };
    }

    fn receiptKey(identity: durable.ReceiptIdentity) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("fail2zig-receipt-candidate-v1\x00");
        for ([_][]const u8{ identity.jail, identity.source, identity.occurrence, identity.cursor, &identity.raw_hash, &identity.generation }) |part| {
            var length: [8]u8 = undefined;
            std.mem.writeInt(u64, &length, part.len, .little);
            hash.update(&length);
            hash.update(part);
        }
        var result: [32]u8 = undefined;
        hash.final(&result);
        return result;
    }
};

const TestProcessor = struct {
    count: u64 = 0,
    staged: u64 = 0,
    shared_state: ?durable.SharedState = null,
    bytes: [8]u8 = undefined,
    prepare_failure: ?anyerror = null,
    fn prepare(record: records.Record, context: ?*anyopaque) !Prepared {
        const self: *TestProcessor = @ptrCast(@alignCast(context.?));
        if (self.prepare_failure) |failure| return failure;
        self.staged = self.count + @intFromBool(record.kind == .data);
        std.mem.writeInt(u64, &self.bytes, self.staged, .little);
        return .{ .checkpoint = &self.bytes, .shared_state = self.shared_state, .disposition = "test-counted", .intent = if (self.staged == 2) "test-threshold" else null, .context = self, .publish = publish, .release = release };
    }
    fn publish(context: ?*anyopaque) void {
        const self: *TestProcessor = @ptrCast(@alignCast(context.?));
        self.count = self.staged;
    }
    fn release(_: ?*anyopaque) void {}
    fn restore(checkpoint: ?[]const u8, context: ?*anyopaque) !Restored {
        const self: *TestProcessor = @ptrCast(@alignCast(context.?));
        if (checkpoint) |payload| {
            if (payload.len != 8) return error.InvalidCheckpoint;
            self.staged = std.mem.readInt(u64, payload[0..8], .little);
        } else self.staged = 0;
        return .{ .context = self, .publish = publish, .release = release };
    }
    fn adapter(self: *TestProcessor) Processor {
        return .{ .context = self, .prepare = prepare, .prepare_restore = restore };
    }
};

test "pipeline: guarded replay refuses preparation while preserving committed state for siblings" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(a, ".");
    defer a.free(base);
    const path = try std.fs.path.join(a, &.{ base, "guard.sqlite" });
    defer a.free(path);
    var store = try durable.Store.open(a, path);
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
    try store.enableConfirmedHistory();
    try store.enableMaintenance();
    const generation = [_]u8{7} ** 32;
    const policy = @import("native_retry.zig").Policy{ .maxretry = 3, .window_us = 1000, .duration = .{ .finite_us = 1000 }, .max_subjects = 8 };
    try store.admitRetry("fixture", generation, policy);
    var checkpoint: [8]u8 = undefined;
    std.mem.writeInt(u64, &checkpoint, 1, .little);
    const record = records.Record{ .source = "file", .occurrence = "old", .cursor = "saved", .message = "ordinary event", .raw_hash = [_]u8{1} ** 32 };
    _ = try store.commitRecord(.{ .jail = "fixture", .source = record.source, .occurrence = record.occurrence, .cursor = record.cursor, .raw_hash = record.raw_hash, .disposition = "source-checkpoint", .checkpoint = &checkpoint, .native_retry = .{ .generation = generation, .policy = policy } });
    try store.fixtureReplayGuard("fixture", record.source, record.occurrence);
    var clock = RecoveryClock{};
    var gate = health.Gate.init(clock.clock());
    var processor = TestProcessor{ .prepare_failure = error.UnexpectedPreparation };
    var owner = Pipeline{ .store = &store, .jail = "fixture", .processor = processor.adapter(), .gate = &gate };
    const initial = try gate.beginRecovery();
    try gate.completed(initial, .storage);
    try owner.restore(a);
    for ([_]health.RecoveryStep{ .state, .ownership, .sources }) |step| try gate.completed(initial, step);
    try std.testing.expectError(error.PrunedReplay, Pipeline.acknowledge(record, &owner));
    try std.testing.expect(owner.ready);
    try std.testing.expectEqual(health.Phase.healthy, gate.snapshot().phase);
    try std.testing.expectEqual(@as(u64, 1), processor.count);
    try std.testing.expectEqual(@as(u64, 1), try store.revision("fixture"));
    try std.testing.expectEqual(@as(usize, 0), try store.pendingReceiptCount());
    const cursor = (try store.sourceCursor(a, "fixture", "file")).?;
    defer a.free(cursor);
    try std.testing.expectEqualStrings("saved", cursor);
    try std.testing.expectError(error.PrunedReplay, Pipeline.acknowledge(record, &owner));
    var other_processor = TestProcessor{};
    var other = Pipeline{ .store = &store, .jail = "other", .processor = other_processor.adapter(), .gate = &gate, .ready = true, .recovery_generation = initial };
    try Pipeline.acknowledge(record, &other);
    try std.testing.expectEqual(@as(u64, 1), other_processor.count);
}

test "pipeline: file acknowledgement waits for durable state, retry and restart do not repeat intents" {
    if (!@import("builtin").link_libc) return error.SkipZigTest;
    const files = @import("durable_file_source.zig");
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    try temp.dir.writeFile(.{ .sub_path = "events.log", .data = "first ordinary event\nsecond ordinary event\n" });
    const root = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const database_path = try std.fs.path.join(allocator, &.{ root, "state.sqlite" });
    defer allocator.free(database_path);
    const log_path = try std.fs.path.join(allocator, &.{ root, "events.log" });
    defer allocator.free(log_path);
    var store = try durable.Store.open(allocator, database_path);
    defer store.close();
    var processor = TestProcessor{};
    var pipeline = Pipeline{ .store = &store, .jail = "fixture", .processor = processor.adapter() };
    try pipeline.restore(allocator);
    var source = try files.FileSource.init(allocator, log_path, "fixture-source", .head, null);
    defer source.deinit();
    store.fail_at = .before_commit;
    try std.testing.expectError(error.InjectedFailure, source.poll(Pipeline.acknowledge, &pipeline));
    try std.testing.expectEqual(@as(u64, 0), processor.count);
    try std.testing.expectEqual(@as(u64, 0), source.committed.?.offset);
    try std.testing.expect(!source.baseline_committed);
    store.fail_at = null;
    try std.testing.expect(try source.poll(Pipeline.acknowledge, &pipeline));
    try std.testing.expectEqual(@as(u64, 1), processor.count);
    try std.testing.expect(try source.poll(Pipeline.acknowledge, &pipeline));
    try std.testing.expectEqual(@as(u64, 2), processor.count);
    try std.testing.expectEqual(@as(i64, 1), try store.pendingIntents());
    const raw = (try store.sourceCursor(allocator, "fixture", "fixture-source")).?;
    defer allocator.free(raw);
    var saved = try std.json.parseFromSlice(files.Resume, allocator, raw, .{});
    defer saved.deinit();
    var restarted = try files.FileSource.init(allocator, log_path, "fixture-source", .head, saved.value);
    defer restarted.deinit();
    processor.count = 0;
    try pipeline.restore(allocator);
    try std.testing.expectEqual(@as(u64, 2), processor.count);
    try std.testing.expect(!try restarted.poll(Pipeline.acknowledge, &pipeline));
    try std.testing.expectEqual(@as(i64, 1), try store.pendingIntents());
    var left = TestProcessor{};
    var right = TestProcessor{};
    var owner = Pipeline{ .store = &store, .jail = "concurrent", .processor = left.adapter() };
    var stale = Pipeline{ .store = &store, .jail = "concurrent", .processor = right.adapter() };
    try owner.restore(allocator);
    try stale.restore(allocator);
    const same = records.Record{ .source = "duplicate", .occurrence = "one", .cursor = "1", .message = "ordinary event", .raw_hash = [_]u8{2} ** 32 };
    try Pipeline.acknowledge(same, &owner);
    try std.testing.expectError(error.RestoreRequired, Pipeline.acknowledge(same, &stale));
    try std.testing.expect(!stale.ready);
    try std.testing.expectEqual(@as(u64, 0), right.count);
    try stale.restore(allocator);
    try Pipeline.acknowledge(same, &stale);
    try std.testing.expectEqual(@as(u64, 1), right.count);
}

test "pipeline: stale shared read prevents publication until refreshed restore" {
    if (!@import("builtin").link_libc) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const path = try std.fs.path.join(allocator, &.{ base, "shared.sqlite" });
    defer allocator.free(path);
    var store = try durable.Store.open(allocator, path);
    defer store.close();
    var processor = TestProcessor{ .shared_state = .{ .name = "dns", .expected_revision = 0 } };
    var pipeline = Pipeline{ .store = &store, .jail = "reader", .processor = processor.adapter() };
    try pipeline.restore(allocator);
    _ = try store.commitRecord(.{ .jail = "writer", .source = "file", .occurrence = "1", .cursor = "1", .raw_hash = [_]u8{1} ** 32, .disposition = "ordinary", .checkpoint = "writer", .shared_state = .{ .name = "dns", .expected_revision = 0, .payload = "new-cache" } });
    const record = records.Record{ .source = "file", .occurrence = "1", .cursor = "1", .message = "ordinary event", .raw_hash = [_]u8{2} ** 32 };
    try std.testing.expectError(error.StaleSharedCheckpoint, Pipeline.acknowledge(record, &pipeline));
    try std.testing.expect(!pipeline.ready);
    try std.testing.expectEqual(@as(u64, 0), processor.count);
    try std.testing.expectEqual(@as(u64, 0), try store.revision("reader"));
    try std.testing.expectError(error.RestoreRequired, Pipeline.acknowledge(record, &pipeline));
    const shared = try store.sharedSnapshot(allocator, "dns");
    defer shared.deinit(allocator);
    processor.shared_state.?.expected_revision = shared.revision;
    try pipeline.restore(allocator);
    try Pipeline.acknowledge(record, &pipeline);
    try std.testing.expectEqual(@as(u64, 1), processor.count);
    try Pipeline.acknowledge(record, &pipeline);
    try std.testing.expectEqual(@as(u64, 1), processor.count);
}

test "pipeline: locked and read-only storage prevent publication and permit retry after repair" {
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const path = try std.fs.path.join(allocator, &.{ base, "failures.sqlite" });
    defer allocator.free(path);
    var store = try durable.Store.open(allocator, path);
    defer store.close();
    var blocker = try durable.Store.open(allocator, path);
    defer blocker.close();
    for ([_]bool{ false, true }) |read_only| {
        const jail = if (read_only) "readonly" else "locked";
        var processor = TestProcessor{};
        var pipeline = Pipeline{ .store = &store, .jail = jail, .processor = processor.adapter() };
        try pipeline.restore(allocator);
        var record = records.Record{ .source = "file", .occurrence = "1", .cursor = "1", .message = "ordinary event", .raw_hash = [_]u8{1} ** 32 };
        try Pipeline.acknowledge(record, &pipeline);
        if (read_only) {
            try std.testing.expectEqual(@as(c_int, 0), store.api.exec(store.db, "PRAGMA query_only=ON;", null, null, null));
        } else {
            try std.testing.expectEqual(@as(c_int, 0), blocker.api.exec(blocker.db, "BEGIN IMMEDIATE;", null, null, null));
        }
        record.occurrence = "2";
        record.cursor = "2";
        try std.testing.expectError(if (read_only) error.ReadOnly else error.Busy, Pipeline.acknowledge(record, &pipeline));
        try std.testing.expectEqual(@as(u64, 1), processor.count);
        try std.testing.expectEqual(@as(u64, 1), pipeline.revision);
        try std.testing.expectEqual(@as(u64, 1), try store.revision(jail));
        try std.testing.expect(!try store.hasRecord(jail, "file", "2", record.raw_hash, "2"));
        const cursor = (try store.sourceCursor(allocator, jail, "file")).?;
        defer allocator.free(cursor);
        try std.testing.expectEqualStrings("1", cursor);
        try std.testing.expectEqual(@as(?c_int, if (read_only) 8 else 5), store.last_error_code);
        try std.testing.expectEqual(@as(?c_int, null), store.rollback_error_code);
        if (read_only) {
            try std.testing.expectEqual(@as(c_int, 0), store.api.exec(store.db, "PRAGMA query_only=OFF;", null, null, null));
        } else {
            try std.testing.expectEqual(@as(c_int, 0), blocker.api.exec(blocker.db, "ROLLBACK;", null, null, null));
        }
        try Pipeline.acknowledge(record, &pipeline);
        try Pipeline.acknowledge(record, &pipeline);
        try std.testing.expectEqual(@as(u64, 2), processor.count);
        try std.testing.expectEqual(@as(u64, 2), try store.revision(jail));
        try std.testing.expectEqual(@as(i64, if (read_only) 2 else 1), try store.pendingIntents());
    }
}

const RecoveryClock = struct {
    ms: u64 = 0,
    fn read(context: ?*anyopaque) u64 {
        const self: *RecoveryClock = @ptrCast(@alignCast(context.?));
        return self.ms;
    }
    fn clock(self: *RecoveryClock) health.Clock {
        return .{ .context = self, .read = read };
    }
};

test "pipeline: one storage failure pauses every owner and reopen requires restored state and source continuity" {
    const files = @import("durable_file_source.zig");
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const path = try std.fs.path.join(allocator, &.{ base, "gate.sqlite" });
    defer allocator.free(path);
    const input = try std.fs.path.join(allocator, &.{ base, "events.log" });
    defer allocator.free(input);
    try temp.dir.writeFile(.{ .sub_path = "events.log", .data = "ordinary first event\nordinary second event\n" });
    var store = try durable.Store.open(allocator, path);
    defer store.close();
    var clock = RecoveryClock{};
    var gate = health.Gate.init(clock.clock());
    var first = TestProcessor{};
    var second = TestProcessor{};
    var owner = Pipeline{ .store = &store, .jail = "first", .processor = first.adapter(), .gate = &gate };
    var other = Pipeline{ .store = &store, .jail = "second", .processor = second.adapter(), .gate = &gate };
    const initial = try gate.beginRecovery();
    try gate.completed(initial, .storage);
    try owner.restore(allocator);
    try other.restore(allocator);
    try gate.completed(initial, .state);
    try std.testing.expectEqual(@as(i64, 0), try store.pendingIntents());
    try gate.completed(initial, .ownership); // no installed/queued effects in this fixture
    var source = try files.FileSource.init(allocator, input, "file", .head, null);
    defer source.deinit();
    try gate.completed(initial, .sources); // new source; no durable anchor yet
    try owner.admit();
    try std.testing.expect(try source.poll(Pipeline.acknowledge, &owner));
    const saved = source.acknowledgedCheckpoint().?;
    const saved_revision = owner.revision;
    const record = records.Record{ .source = "file", .occurrence = "one", .cursor = "1", .message = "ordinary event", .raw_hash = [_]u8{1} ** 32 };
    try std.testing.expectEqual(@as(c_int, 0), store.api.exec(store.db, "PRAGMA query_only=ON;", null, null, null));
    clock.ms = 25;
    try std.testing.expectError(error.ReadOnly, source.poll(Pipeline.acknowledge, &owner));
    try std.testing.expectEqual(saved.offset, source.acknowledgedCheckpoint().?.offset);
    try std.testing.expectEqual(saved_revision, owner.revision);
    try std.testing.expectEqual(@as(u64, 1), first.count);
    try std.testing.expectError(error.StoragePaused, Pipeline.acknowledge(record, &other));
    try std.testing.expectError(error.StoragePaused, other.admit());
    try std.testing.expectEqual(@as(u64, 0), second.count);
    try std.testing.expectEqual(@as(u64, 0), try store.revision("second"));
    try std.testing.expectError(error.PersistenceUnavailable, gate.admitMutation());
    const paused = gate.snapshot();
    try std.testing.expectEqual(@as(?c_int, 8), paused.first_failure.?.diagnostics.sqlite_code);
    try std.testing.expectEqual(@as(?u64, 0), paused.last_commit_ms);
    try std.testing.expectEqual(@as(u64, 2), paused.committed_records); // baseline + first record
    for (0..10) |_| try std.testing.expectError(error.StoragePaused, Pipeline.acknowledge(record, &other));
    try std.testing.expectEqual(paused.notice_sequence, gate.snapshot().notice_sequence);
    try std.testing.expectEqual(paused.next_retry_ms, gate.snapshot().next_retry_ms);
    try std.testing.expectError(error.RetryNotDue, gate.beginRecovery());

    clock.ms = paused.next_retry_ms.?;
    const recovered = try gate.beginRecovery();
    store.close();
    store = try durable.Store.open(allocator, path);
    try gate.completed(recovered, .storage);
    try std.testing.expectError(error.StoragePaused, owner.admit());
    try owner.restore(allocator);
    try other.restore(allocator);
    try std.testing.expectEqual(@as(u64, 1), first.count);
    try gate.completed(recovered, .state);
    try std.testing.expectEqual(@as(i64, 0), try store.pendingIntents());
    try gate.completed(recovered, .ownership);
    const raw = (try store.sourceCursor(allocator, "first", "file")).?;
    defer allocator.free(raw);
    const parsed = try std.json.parseFromSlice(files.Resume, allocator, raw, .{});
    defer parsed.deinit();
    var resumed = try files.FileSource.init(allocator, input, "file", .head, parsed.value);
    defer resumed.deinit();
    // Validate the saved incarnation/prefix by opening it, before declaring
    // source continuity. It may be gone even though the database is writable.
    try std.testing.expect(try resumed.verifyContinuity());
    try gate.completed(recovered, .sources);
    try owner.admit();
    try std.testing.expect(try resumed.poll(Pipeline.acknowledge, &owner));
    try std.testing.expect(!try resumed.poll(Pipeline.acknowledge, &owner));
    try std.testing.expectEqual(@as(u64, 2), first.count);
    try std.testing.expectEqual(saved_revision + 1, owner.revision);
    try std.testing.expectEqual(@as(i64, 1), try store.pendingIntents());
    try Pipeline.acknowledge(record, &other);
    try Pipeline.acknowledge(record, &other);
    try std.testing.expectEqual(@as(u64, 1), second.count);
    // A source-specific decoder failure is not a database outage. It must not
    // let malformed input in one jail suspend otherwise independent protection.
    first.prepare_failure = error.InvalidEncoding;
    var next = record;
    next.occurrence = "next";
    next.cursor = "next";
    try std.testing.expectError(error.InvalidEncoding, Pipeline.acknowledge(next, &owner));
    try std.testing.expect(!owner.ready);
    try std.testing.expectEqual(health.Phase.healthy, gate.snapshot().phase);
    try std.testing.expectEqual(@as(u64, 2), first.count);
    try Pipeline.acknowledge(next, &other);
    try std.testing.expectEqual(@as(u64, 2), second.count);
}

test "pipeline: stale or failed restore never publishes a partially restored owner" {
    const Racing = struct {
        base: TestProcessor = .{ .count = 99 },
        writer: *durable.Store,
        fail_decode: bool = false,
        fn prepareRestore(payload: ?[]const u8, context: ?*anyopaque) !Restored {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            if (self.fail_decode) return error.InvalidCheckpoint;
            const result = try TestProcessor.restore(payload, &self.base);
            errdefer result.release(result.context);
            var bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &bytes, 2, .little);
            _ = try self.writer.commitRecord(.{ .jail = "fixture", .source = "file", .occurrence = "raced", .cursor = "2", .raw_hash = [_]u8{2} ** 32, .disposition = "test", .checkpoint = &bytes, .expected_revision = 1 });
            return result;
        }
        fn prepare(_: records.Record, _: ?*anyopaque) !Prepared {
            return error.UnexpectedRecord;
        }
    };
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const path = try std.fs.path.join(allocator, &.{ base, "restore.sqlite" });
    defer allocator.free(path);
    var store = try durable.Store.open(allocator, path);
    defer store.close();
    var writer = try durable.Store.open(allocator, path);
    defer writer.close();
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, 1, .little);
    _ = try store.commitRecord(.{ .jail = "fixture", .source = "file", .occurrence = "first", .cursor = "1", .raw_hash = [_]u8{1} ** 32, .disposition = "test", .checkpoint = &bytes });
    var processor = Racing{ .writer = &writer };
    var owner = Pipeline{ .store = &store, .jail = "fixture", .processor = .{ .context = &processor, .prepare = Racing.prepare, .prepare_restore = Racing.prepareRestore } };
    try std.testing.expectError(error.StaleCheckpoint, owner.restore(allocator));
    try std.testing.expectEqual(@as(u64, 99), processor.base.count);
    try std.testing.expect(!owner.ready);
    processor.fail_decode = true;
    try std.testing.expectError(error.InvalidCheckpoint, owner.restore(allocator));
    try std.testing.expectEqual(@as(u64, 99), processor.base.count);
    var no_memory = std.heap.FixedBufferAllocator.init(&.{});
    try std.testing.expectError(error.OutOfMemory, owner.restore(no_memory.allocator()));
    try std.testing.expectEqual(@as(u64, 99), processor.base.count);
    owner.processor = processor.base.adapter();
    try owner.restore(allocator);
    try std.testing.expectEqual(@as(u64, 2), processor.base.count);
    try std.testing.expect(owner.ready);
}

test "pipeline: real SQLite capacity failure pauses admission without losing the prior checkpoint or intent" {
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const path = try std.fs.path.join(allocator, &.{ base, "capacity.sqlite" });
    defer allocator.free(path);
    var store = try durable.Store.open(allocator, path);
    defer store.close();
    var clock = RecoveryClock{};
    var gate = health.Gate.init(clock.clock());
    var processor = TestProcessor{};
    var owner = Pipeline{ .store = &store, .jail = "fixture", .processor = processor.adapter(), .gate = &gate };
    const initial = try gate.beginRecovery();
    try gate.completed(initial, .storage);
    try owner.restore(allocator);
    for ([_]health.RecoveryStep{ .state, .ownership, .sources }) |step| try gate.completed(initial, step);
    var record = records.Record{ .source = "file", .occurrence = "1", .cursor = "1", .message = "ordinary event", .raw_hash = [_]u8{1} ** 32 };
    try Pipeline.acknowledge(record, &owner);
    record.occurrence = "2";
    record.cursor = "2";
    try Pipeline.acknowledge(record, &owner);
    try std.testing.expectEqual(@as(i64, 1), try store.pendingIntents());
    // SQLite clamps this below-current-size request to the existing page count.
    // A large new cursor needs additional pages. This does not fill the host disk.
    try std.testing.expectEqual(@as(c_int, 0), store.api.exec(store.db, "PRAGMA max_page_count=1;", null, null, null));
    const large_cursor = [_]u8{'c'} ** 65536;
    record.occurrence = "3";
    record.cursor = &large_cursor;
    try std.testing.expectError(error.StorageFull, Pipeline.acknowledge(record, &owner));
    try std.testing.expectEqual(health.Phase.paused, gate.snapshot().phase);
    try std.testing.expectEqual(@as(?c_int, 13), gate.snapshot().last_failure.?.diagnostics.sqlite_code);
    try std.testing.expectEqual(@as(u64, 2), processor.count);
    try std.testing.expectEqual(@as(u64, 2), try store.revision("fixture"));
    try std.testing.expectEqual(@as(i64, 1), try store.pendingIntents());
    try std.testing.expect(!try store.hasRecord("fixture", "file", "3", record.raw_hash, record.cursor));
    const cursor = (try store.sourceCursor(allocator, "fixture", "file")).?;
    defer allocator.free(cursor);
    try std.testing.expectEqualStrings("2", cursor);
    try std.testing.expectError(error.StoragePaused, Pipeline.acknowledge(record, &owner));
    try std.testing.expectError(error.PersistenceUnavailable, gate.admitMutation());

    // Even after capacity is repaired, an unresolved ownership outcome or lost
    // source anchor must keep admission closed. No cursor reset is attempted.
    clock.ms = gate.snapshot().next_retry_ms.?;
    const recovered = try gate.beginRecovery();
    try std.testing.expectEqual(@as(c_int, 0), store.api.exec(store.db, "PRAGMA max_page_count=65536;", null, null, null));
    try gate.completed(recovered, .storage);
    try owner.restore(allocator);
    try gate.completed(recovered, .state);
    try std.testing.expectError(error.StoragePaused, owner.admit());
    gate.failed(error.ResumeLost, .{});
    try std.testing.expectEqual(health.Phase.intervention, gate.snapshot().phase);
    try std.testing.expectError(error.StaleRecovery, gate.completed(recovered, .ownership));
    try std.testing.expectEqual(@as(i64, 1), try store.pendingIntents());
    try std.testing.expectEqual(@as(u64, 2), processor.count);
}

test "native consumers: dependency expiry reprepares while conflicts and clock pause recovery" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(a, ".");
    defer a.free(base);
    const path = try std.fs.path.join(a, &.{ base, "gate.sqlite" });
    defer a.free(path);
    var store = try durable.Store.open(a, path);
    defer store.close();
    const Clock = struct {
        fn read(_: ?*anyopaque) u64 {
            return 100;
        }
    };
    var processor = TestProcessor{};
    for ([_]anyerror{ error.ConsumerExpired, error.StaleConsumerCheckpoint, error.ConsumerClockReversed }) |cause| {
        var gate = health.Gate.init(.{ .context = null, .read = Clock.read });
        const generation = try gate.beginRecovery();
        for ([_]health.RecoveryStep{ .storage, .state, .ownership, .sources }) |step| try gate.completed(generation, step);
        var pipe = Pipeline{ .store = &store, .jail = "fixture", .processor = processor.adapter(), .ready = true, .gate = &gate };
        store.consumer_clock_floor_us = 250;
        pipe.failed(cause);
        try std.testing.expectEqual(cause == error.ConsumerExpired, pipe.ready);
        try std.testing.expectEqual(if (cause == error.ConsumerExpired) health.Phase.healthy else health.Phase.paused, gate.snapshot().phase);
        if (cause == error.ConsumerClockReversed) try std.testing.expectEqual(@as(?i64, 250), gate.snapshot().receipt_clock_floor_us);
    }
}

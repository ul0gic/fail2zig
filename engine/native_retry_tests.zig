// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const t = std.testing;
const retry = @import("core/native_retry.zig");
const detection = @import("core/native_detection_record.zig");
const durable = @import("core/record_store.zig");
const sessions = @import("core/native_file_session.zig");
const builtin = @import("core/native_builtin_detector.zig");
const time = @import("core/native_time.zig");
const policy = retry.Policy{ .maxretry = 3, .window_us = 10_000_000, .bantime_us = 60_000_000, .max_subjects = 2 };
const ip = detection.Subject{ .v4 = .{ 203, 0, 113, 7 } };
const failure = "Failed password for root from 203.0.113.7 port 22 ssh2\n";
const Clock = struct {
    now: i64 = 100_000_000,
    fn read(ctx: ?*anyopaque) !time.Timestamp {
        const self: *Clock = @ptrCast(@alignCast(ctx.?));
        return .{ .us = self.now };
    }
};
fn admitted(store: *durable.Store) !void {
    try store.enableReceipts(2);
    try store.enableNativeTime();
    try store.enableDetection();
    try store.enableClockRecovery();
    try store.enableJournalDetection();
    try store.enableRetry();
}
fn attempt(stamp: i64, id: u8) retry.Attempt {
    return .{ .at_us = stamp, .occurrence = [_]u8{id} ** 32 };
}
fn detector() !builtin.Detector {
    return builtin.Detector.init(t.allocator, .{ .filter = "sshd", .body = .whole, .ignore_capacity = 0, .max_decoded_bytes = 2048 });
}
fn options(consumer: *const builtin.Detector, clock: *Clock) sessions.Options {
    return .{ .processing = .{ .jail = "ssh", .parent_generation = [_]u8{1} ** 32, .timestamp = .undated, .window_us = policy.window_us }, .detection = consumer.consumer(), .retry = policy, .max_sources = 2, .clock = Clock.read, .clock_context = clock };
}

const StoreFixture = struct {
    const generation = [_]u8{7} ** 32;
    fn record(store: *durable.Store, occurrence: []const u8, revision: u64, stamp: i64, address: detection.Subject) !durable.Record {
        const identity = durable.ReceiptIdentity{ .jail = "ssh", .source = "file", .occurrence = occurrence, .cursor = occurrence, .raw_hash = [_]u8{8} ** 32, .generation = generation };
        const receipt = try store.beginReceipt(identity, .{ .us = stamp }, revision);
        return .{ .jail = identity.jail, .source = identity.source, .occurrence = identity.occurrence, .cursor = identity.cursor, .raw_hash = identity.raw_hash, .receipt = .{ .time = receipt, .generation = generation }, .native_time_outcome = .{ .eligible = .{ .timestamp = receipt, .receipt = receipt, .original = null, .origin = .receipt } }, .native_detection = .{ .kind = .candidate, .generation = [_]u8{2} ** 32, .filter = try detection.Name.init("sshd"), .pattern = try detection.Name.init("password"), .pattern_index = 0, .subject = address }, .native_retry = .{ .generation = generation, .policy = policy, .processing_us = stamp }, .expected_revision = revision, .disposition = "time-eligible-receipt", .checkpoint = "native-retry-test" };
    }
};

test "native retry: schema admission is atomic and cannot reset acknowledged history or omit retry" {
    var temp = t.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(root);
    const path = try std.fs.path.join(t.allocator, &.{ root, "state.sqlite" });
    defer t.allocator.free(path);
    var store = try durable.Store.open(t.allocator, path);
    defer store.close();
    try store.enableReceipts(2);
    try store.enableNativeTime();
    try store.enableDetection();
    try store.enableClockRecovery();
    try store.enableJournalDetection();
    store.fail_at = .before_retry_schema_commit;
    try t.expectError(error.InjectedFailure, store.enableRetry());
    try t.expectEqual(@as(i64, 8), store.schema_version);
    {
        var observer = try durable.Store.open(t.allocator, path);
        defer observer.close();
        try t.expectEqual(@as(i64, 8), observer.schema_version);
    }
    store.fail_at = null;
    try store.enableRetry();
    try store.enableJournalDetection();
    try t.expectEqual(@as(i64, 9), store.schema_version);
    try store.admitRetry("ssh", StoreFixture.generation, policy);
    const first = try StoreFixture.record(&store, "one", 0, 100_000_000, ip);
    var omitted = first;
    omitted.native_retry = null;
    try t.expectError(error.RetryAdmissionRequired, store.commitRecord(omitted));
    var changed = first;
    changed.native_retry.?.policy.enforce = true;
    try t.expectError(error.RetryGenerationMismatch, store.commitRecord(changed));
    try t.expectEqual(durable.CommitResult.committed, try store.commitRecord(first));
    try t.expectEqual(durable.CommitResult.already_committed, try store.commitRecord(first));
    try t.expectEqual(@as(u16, 1), (try store.retryState("ssh", ip)).?.count);
    try t.expectEqual(@as(u64, 1), try store.revision("ssh"));
    try t.expectError(error.UnconfiguredStateOwner, store.validateRuntimeOwners(&.{"other"}));
    try store.validateRuntimeOwners(&.{"ssh"});
    try store.validateRetry("ssh", StoreFixture.generation, policy);
    var changed_policy = policy;
    changed_policy.maxretry = 2;
    try t.expectError(error.RetryGenerationMismatch, store.admitRetry("ssh", StoreFixture.generation, changed_policy));
    _ = try store.commitRecord(.{ .jail = "old", .source = "old", .occurrence = "old", .cursor = "old", .raw_hash = [_]u8{0} ** 32, .disposition = "old", .checkpoint = "old" });
    try t.expectError(error.RetryMigrationRequired, store.admitRetry("old", StoreFixture.generation, policy));
}

test "native retry: capacity and malformed persisted state cannot advance the record" {
    var temp = t.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(root);
    const path = try std.fs.path.join(t.allocator, &.{ root, "state.sqlite" });
    defer t.allocator.free(path);
    var store = try durable.Store.open(t.allocator, path);
    defer store.close();
    try admitted(&store);
    try store.admitRetry("ssh", StoreFixture.generation, policy);
    _ = try store.commitRecord(try StoreFixture.record(&store, "one", 0, 100_000_000, ip));
    _ = try store.commitRecord(try StoreFixture.record(&store, "two", 1, 100_000_000, .{ .v6 = .{ 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 } }));
    const third = try StoreFixture.record(&store, "three", 2, 100_000_000, .{ .v4 = .{ 198, 51, 100, 3 } });
    try t.expectError(error.RetryCapacity, store.commitRecord(third));
    try t.expectEqual(@as(u64, 2), try store.revision("ssh"));
    try t.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
    const rejected = store.api.exec(store.db, "UPDATE retry_states SET attempts=x'00' WHERE family=4;", null, null, null);
    try t.expectEqual(@as(c_int, 19), rejected & 0xff);
    try t.expectEqual(@as(u16, 1), (try store.retryState("ssh", ip)).?.count);
    try t.expectEqual(@as(c_int, 0), store.api.exec(store.db, "PRAGMA ignore_check_constraints=ON; UPDATE retry_states SET attempts=x'00' WHERE family=4; PRAGMA ignore_check_constraints=OFF;", null, null, null));
    try t.expectError(error.InvalidRetryState, store.retryState("ssh", ip));
    try t.expectError(error.InvalidRetryState, store.validateRetry("ssh", StoreFixture.generation, policy));
    try t.expectEqual(@as(u64, 2), try store.revision("ssh"));
}

test "native retry: committed processing floor preserves receipts and pauses admission until catch-up" {
    var temp = t.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(root);
    const path = try std.fs.path.join(t.allocator, &.{ root, "state.sqlite" });
    defer t.allocator.free(path);
    var store = try durable.Store.open(t.allocator, path);
    defer store.close();
    try admitted(&store);
    try store.admitRetry("ssh", StoreFixture.generation, policy);
    var record = try StoreFixture.record(&store, "one", 0, 100_000_000, ip);
    record.native_retry.?.processing_us = 101_000_000;
    store.fail_at = .after_retry_state;
    try t.expectError(error.InjectedFailure, store.commitRecord(record));
    try t.expectEqual(@as(i64, 100_000_000), (try store.admissionClock()).?.us);
    store.fail_at = null;
    _ = try store.commitRecord(record);
    try t.expectEqual(@as(i64, 100_000_000), (try store.receiptClock()).?.us);
    try t.expectEqual(@as(i64, 101_000_000), (try store.admissionClock()).?.us);
    var snapshot: [policy.max_subjects]durable.Store.ActiveDecision = undefined;
    try t.expectError(error.ReceiptClockReversed, store.retrySummary("ssh", 100_500_000, &snapshot));
    try store.admitRetry("empty", StoreFixture.generation, policy);
    try t.expectError(error.ReceiptClockReversed, store.retrySummary("empty", 100_500_000, &snapshot));
    try t.expectEqual(@as(usize, 1), (try store.retrySummary("ssh", 101_000_000, &snapshot)).subjects);
    try t.expectEqual(@as(usize, 0), (try store.retrySummary("empty", 101_000_000, &snapshot)).subjects);
    var clock = Clock{ .now = 100_500_000 };
    const processing = @import("core/record_pipeline.zig");
    const Stub = struct {
        fn prepare(_: @import("core/source_record.zig").Record, _: ?*anyopaque) !processing.Prepared {
            return error.UnexpectedPreparation;
        }
        fn restore(_: ?[]const u8, _: ?*anyopaque) !processing.Restored {
            return error.UnexpectedRestoration;
        }
    };
    var pipe = processing.Pipeline{ .store = &store, .jail = "ssh", .ready = true, .processor = .{ .context = null, .prepare = Stub.prepare, .prepare_restore = Stub.restore }, .receipts = .{ .generation = StoreFixture.generation, .clock_context = &clock, .clock = Clock.read } };
    try t.expectError(error.ReceiptClockReversed, pipe.admit());
    clock.now = 101_000_000;
    pipe.ready = true; // The real coordinator restores/validates before this point.
    try pipe.admit();
}

test "native retry: inclusive processing window sorts late attempts and never rejuvenates stale evidence" {
    var result = try retry.advance(policy, null, ip, attempt(100_000_000, 1), 100_000_000);
    result = try retry.advance(policy, result.state, ip, attempt(90_000_000, 2), 100_000_000);
    try t.expectEqual(@as(u16, 2), result.state.count);
    try t.expectEqual(@as(i64, 90_000_000), result.state.attempts[0].at_us);
    result = try retry.advance(policy, result.state, ip, attempt(100_000_001, 3), 100_000_001);
    try t.expectEqual(@as(u16, 2), result.state.count);
    try t.expect(result.decision == null);
    result = try retry.advance(policy, result.state, ip, attempt(99_000_000, 4), 100_000_001);
    try t.expectEqual(@as(i64, 160_000_001), result.decision.?.expiry_us);
    try t.expectEqual(@as(u16, 0), result.state.count);
    try t.expectError(error.InvalidRetryState, retry.advance(policy, null, ip, attempt(89_999_999, 1), 100_000_000));
}

test "native retry: active decisions retain deadline and no attempts leak into the next window" {
    var single = policy;
    single.maxretry = 1;
    var result = try retry.advance(single, null, ip, attempt(100_000_000, 1), 100_000_000);
    result = try retry.advance(single, result.state, ip, attempt(110_000_000, 2), 110_000_000);
    try t.expect(result.decision == null);
    try t.expectEqual(@as(i64, 160_000_000), result.state.expiry_us.?);
    try t.expectEqual(@as(u16, 0), result.state.count);
    result = try retry.advance(single, result.state, ip, attempt(160_000_000, 3), 160_000_000);
    try t.expectEqual(@as(u64, 2), result.decision.?.ordinal);
    try t.expectEqual(@as(i64, 220_000_000), result.decision.?.expiry_us);
    try t.expectError(error.RetryClockReversed, retry.advance(single, result.state, ip, attempt(159_999_999, 4), 159_999_999));
    try t.expectError(error.RetryTimeOverflow, retry.advance(single, null, ip, attempt(std.math.maxInt(i64), 4), std.math.maxInt(i64)));
}

test "native retry: persisted encodings reject malformed versions limits duplicate identities and ordering" {
    var encoded = try policy.encode();
    try t.expectEqualDeep(policy, try retry.Policy.decode(&encoded));
    encoded[4] = 2;
    try t.expectError(error.InvalidRetryPolicy, retry.Policy.decode(&encoded));
    var maximum = policy;
    maximum.maxretry = 128;
    var state: ?retry.State = null;
    for (0..127) |i| state = (try retry.advance(maximum, state, ip, attempt(@intCast(i), @intCast(i)), 127)).state;
    var bytes: [retry.max_attempts * retry.attempt_bytes]u8 = undefined;
    const saved = state.?.encodeAttempts(&bytes);
    var restored = retry.State{ .last_processed_us = 127 };
    try restored.decodeAttempts(saved, maximum);
    try t.expectEqual(@as(u16, 127), restored.count);
    try t.expect((try retry.advance(maximum, restored, ip, attempt(128, 128), 128)).decision != null);
    @memcpy(bytes[retry.attempt_bytes + 8 ..][0..32], bytes[8..40]);
    try t.expectError(error.InvalidRetryState, restored.decodeAttempts(saved, maximum));
    maximum.maxretry = 129;
    try t.expectError(error.InvalidRetryPolicy, maximum.validate());
}

test "native retry: real file sessions retain attempts across restart and commit decision cursor receipt together" {
    for ([_]durable.CommitStage{ .after_retry_state, .after_retry_decision, .after_checkpoint, .after_receipt_delete, .before_commit }) |fault| {
        var temp = t.tmpDir(.{});
        defer temp.cleanup();
        const root = try temp.dir.realpathAlloc(t.allocator, ".");
        defer t.allocator.free(root);
        const path = try std.fs.path.join(t.allocator, &.{ root, "state.sqlite" });
        defer t.allocator.free(path);
        const log = try std.fs.path.join(t.allocator, &.{ root, "auth.log" });
        defer t.allocator.free(log);
        var file = try temp.dir.createFile("auth.log", .{});
        defer file.close();
        var consumer = try detector();
        defer consumer.deinit(t.allocator);
        var clock = Clock{};
        const opts = options(&consumer, &clock);
        const specs = [_]sessions.Spec{.{ .pattern = log }};
        var committed_revision: u64 = 0;
        {
            var store = try durable.Store.open(t.allocator, path);
            defer store.close();
            try admitted(&store);
            const session = try sessions.Session.create(t.allocator, &store, opts, &specs);
            defer session.destroy();
            _ = try session.poll(1);
            for (0..2) |_| {
                try file.writeAll(failure);
                try t.expectEqual(@as(usize, 1), try session.poll(1));
            }
            try t.expectEqual(@as(u16, 2), (try store.retryState("ssh", ip)).?.count);
            committed_revision = session.pipe.revision;
        }
        clock.now += 1_000_000;
        {
            var store = try durable.Store.open(t.allocator, path);
            defer store.close();
            try store.enableReceipts(2);
            const session = try sessions.Session.create(t.allocator, &store, opts, &specs);
            defer session.destroy();
            try file.writeAll(failure);
            store.fail_at = fault;
            try t.expectError(error.InjectedFailure, session.poll(1));
            try t.expectEqual(committed_revision, session.pipe.revision);
            try t.expectEqual(@as(u16, 2), (try store.retryState("ssh", ip)).?.count);
            try t.expectEqual(@as(u64, 2), session.processor.timeHealth().eligible);
            try t.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
            try t.expect(try store.retryDecision("ssh", session.sources.sources.items[0].source_id, null) == null);
        }
        clock.now += 1_000_000;
        {
            var store = try durable.Store.open(t.allocator, path);
            defer store.close();
            try store.enableReceipts(2);
            const session = try sessions.Session.create(t.allocator, &store, opts, &specs);
            defer session.destroy();
            try t.expectEqual(@as(usize, 1), try session.poll(1));
            const source = &session.sources.sources.items[0];
            const decision = (try store.retryDecision("ssh", source.source_id, null)).?;
            try t.expectEqual(clock.now + policy.bantime_us, decision.expiry_us);
            try t.expectEqual(@as(u64, 1), decision.ordinal);
            try t.expectEqual(committed_revision + 1, session.pipe.revision);
            try t.expectEqual(@as(usize, 0), try store.pendingReceiptCount());
            try t.expectEqual(clock.now - 1_000_000, (try store.nativeTime("ssh", source.source_id, null)).?.eligible.receipt.us);
            try t.expectEqual(@as(usize, 0), try session.poll(1));
            clock.now += 1_000_000;
            try file.writeAll(failure);
            try t.expectEqual(@as(usize, 1), try session.poll(1));
            try t.expect(try store.retryDecision("ssh", source.source_id, null) == null);
            const state = (try store.retryState("ssh", ip)).?;
            try t.expectEqual(decision.expiry_us, state.expiry_us.?);
            try t.expectEqual(@as(u64, 1), state.decisions);
            try t.expectEqual(@as(u16, 0), state.count);
        }
    }
}

test "native retry: failed pending record aging out cannot create a decision" {
    var temp = t.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(root);
    const path = try std.fs.path.join(t.allocator, &.{ root, "state.sqlite" });
    defer t.allocator.free(path);
    const log = try std.fs.path.join(t.allocator, &.{ root, "auth.log" });
    defer t.allocator.free(log);
    var file = try temp.dir.createFile("auth.log", .{});
    defer file.close();
    var consumer = try detector();
    defer consumer.deinit(t.allocator);
    var clock = Clock{};
    var opts = options(&consumer, &clock);
    opts.retry.?.maxretry = 1;
    const specs = [_]sessions.Spec{.{ .pattern = log }};
    var store = try durable.Store.open(t.allocator, path);
    defer store.close();
    try admitted(&store);
    {
        const session = try sessions.Session.create(t.allocator, &store, opts, &specs);
        defer session.destroy();
        _ = try session.poll(1);
        try file.writeAll(failure);
        store.fail_at = .after_retry_decision;
        try t.expectError(error.InjectedFailure, session.poll(1));
    }
    store.fail_at = null;
    clock.now += policy.window_us + 1;
    const session = try sessions.Session.create(t.allocator, &store, opts, &specs);
    defer session.destroy();
    try t.expectEqual(@as(usize, 1), try session.poll(1));
    try t.expect(try store.retryState("ssh", ip) == null);
    try t.expect(try store.retryDecision("ssh", session.sources.sources.items[0].source_id, null) == null);
    try t.expectEqual(@as(usize, 0), try store.pendingReceiptCount());
    try t.expectEqual(@as(u64, 1), session.processor.timeHealth().obsolete);
}

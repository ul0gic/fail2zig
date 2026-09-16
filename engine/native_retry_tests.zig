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
const native_config = @import("config/native.zig");
const retry_config = @import("config/native_retry_policy.zig");
const policy = retry.Policy{ .maxretry = 3, .window_us = 10_000_000, .duration = .{ .finite_us = 60_000_000 }, .max_subjects = 2 };
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
fn enableLatestFromRetry(store: *durable.Store) !void {
    try store.enableConsumers();
    try store.enableEffects();
    try store.enableConsumerManifests();
    try store.enableConfirmedHistory();
    try store.enableMaintenance();
    try store.enableCleanup();
    try store.enableRetryLeases();
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
        return recordWith(store, "ssh", occurrence, revision, stamp, address, policy);
    }
    fn recordWith(store: *durable.Store, jail: []const u8, occurrence: []const u8, revision: u64, stamp: i64, address: detection.Subject, selected: retry.Policy) !durable.Record {
        const identity = durable.ReceiptIdentity{ .jail = jail, .source = "file", .occurrence = occurrence, .cursor = occurrence, .raw_hash = [_]u8{8} ** 32, .generation = generation };
        const receipt = try store.beginReceipt(identity, .{ .us = stamp }, revision);
        return .{ .jail = identity.jail, .source = identity.source, .occurrence = identity.occurrence, .cursor = identity.cursor, .raw_hash = identity.raw_hash, .receipt = .{ .time = receipt, .generation = generation }, .native_time_outcome = .{ .eligible = .{ .timestamp = receipt, .receipt = receipt, .original = null, .origin = .receipt } }, .native_detection = .{ .kind = .candidate, .generation = [_]u8{2} ** 32, .filter = try detection.Name.init("sshd"), .pattern = try detection.Name.init("password"), .pattern_index = 0, .subject = address }, .native_retry = .{ .generation = generation, .policy = selected, .processing_us = stamp }, .expected_revision = revision, .disposition = "time-eligible-receipt", .checkpoint = "native-retry-test" };
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

test "native retry: ephemeral enforcement suppression preserves configured generation and durable policy" {
    var temp = t.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(root);
    const path = try std.fs.path.join(t.allocator, &.{ root, "state.sqlite" });
    defer t.allocator.free(path);
    var enforcing = policy;
    enforcing.maxretry = 1;
    enforcing.enforce = true;
    {
        var store = try durable.Store.open(t.allocator, path);
        defer store.close();
        try admitted(&store);
        try store.admitRetry("ssh", StoreFixture.generation, enforcing);
        var record = try StoreFixture.recordWith(&store, "ssh", "suppressed", 0, 100_000_000, ip, enforcing);
        record.native_retry.?.suppress_enforcement = true;
        try t.expectEqual(durable.CommitResult.committed, try store.commitRecord(record));
        try t.expectEqual(@as(u64, 0), store.effect_publication_epoch);
        var active: [2]durable.Store.ActiveDecision = undefined;
        const summary = try store.retrySummary("ssh", 100_000_000, &active);
        try t.expectEqual(@as(u64, 1), summary.decisions);
        try t.expectEqual(@as(usize, 1), summary.active);
        try store.validateRetry("ssh", StoreFixture.generation, enforcing);
    }
    var reopened = try durable.Store.open(t.allocator, path);
    defer reopened.close();
    try reopened.validateRetry("ssh", StoreFixture.generation, enforcing);
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
    pipe.ready = true;
    try pipe.admit();
}

test "native retry: observation-time pruning is read-only across reopen" {
    var temp = t.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(root);
    const path = try std.fs.path.join(t.allocator, &.{ root, "state.sqlite" });
    defer t.allocator.free(path);
    {
        var store = try durable.Store.open(t.allocator, path);
        defer store.close();
        try admitted(&store);
        try store.admitRetry("ssh", StoreFixture.generation, policy);
        _ = try store.commitRecord(try StoreFixture.record(&store, "early", 0, 90_000_000, ip));
        _ = try store.commitRecord(try StoreFixture.record(&store, "latest", 1, 100_000_000, ip));
        try t.expectEqual(@as(u16, 2), (try store.retryStateAt("ssh", ip, 100_000_000)).?.count);
        try t.expectEqual(@as(u16, 1), (try store.retryStateAt("ssh", ip, 100_000_001)).?.count);
        try t.expectEqual(@as(u16, 2), (try store.retryState("ssh", ip)).?.count);
        try t.expectEqual(@as(i64, 100_000_000), (try store.admissionClock()).?.us);
        var snapshot: [policy.max_subjects]durable.Store.ActiveDecision = undefined;
        try t.expectEqual(@as(usize, 1), (try store.retrySummary("ssh", 100_000_001, &snapshot)).subjects);
        try t.expectEqual(@as(u16, 2), (try store.retryState("ssh", ip)).?.count);
        try t.expectEqual(@as(i64, 100_000_000), (try store.admissionClock()).?.us);
    }
    {
        var restored = try durable.Store.open(t.allocator, path);
        defer restored.close();
        try t.expectEqual(@as(u16, 1), (try restored.retryStateAt("ssh", ip, 100_000_001)).?.count);
        try t.expectEqual(@as(u16, 2), (try restored.retryState("ssh", ip)).?.count);
        try t.expectError(error.ReceiptClockReversed, restored.retryStateAt("ssh", ip, 99_999_999));
    }
}

test "native retry: record evidence is bounded before mutation and cannot change counting" {
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
    var valid = try StoreFixture.record(&store, "valid", 0, 100_000_000, ip);
    valid.retry_evidence = .{ .text = failure };
    try t.expectEqual(durable.CommitResult.committed, try store.commitRecord(valid));
    try t.expectEqual(@as(u16, 1), (try store.retryState("ssh", ip)).?.count);

    var invalid = try StoreFixture.record(&store, "invalid", 1, 100_000_001, ip);
    invalid.retry_evidence = .{ .text = "\xff" };
    try t.expectError(error.InvalidRetryEvidence, store.commitRecord(invalid));
    try t.expectEqual(@as(u64, 1), try store.revision("ssh"));
    try t.expectEqual(@as(u16, 1), (try store.retryState("ssh", ip)).?.count);
}

test "native retry: inclusive processing window sorts late attempts and never rejuvenates stale evidence" {
    var result = try retry.advance(policy, null, ip, attempt(100_000_000, 1), 100_000_000);
    result = try retry.advance(policy, result.state, ip, attempt(90_000_000, 2), 100_000_000);
    try t.expectEqual(@as(u16, 2), result.state.count);
    try t.expectEqual(@as(i64, 90_000_000), result.state.attempts[0].at_us);
    try t.expectEqual(@as(?i64, 100_000_000), result.state.latestEventUs());
    result = try retry.advance(policy, result.state, ip, attempt(100_000_001, 3), 100_000_001);
    try t.expectEqual(@as(u16, 2), result.state.count);
    try t.expect(result.decision == null);
    try t.expectEqual(@as(?i64, 100_000_001), result.state.latestEventUs());
    result = try retry.advance(policy, result.state, ip, attempt(99_000_000, 4), 100_000_001);
    try t.expectEqualDeep(retry.Lease{ .finite = 160_000_001 }, result.decision.?.lease);
    try t.expectEqual(@as(u16, 0), result.state.count);
    try t.expectEqual(@as(?i64, null), result.state.latestEventUs());
    try t.expectError(error.InvalidRetryState, retry.advance(policy, null, ip, attempt(89_999_999, 1), 100_000_000));
}

test "native retry: exact duplicate is idempotent while conflicting identity refuses" {
    const first = try retry.advance(policy, null, ip, attempt(100_000_000, 1), 100_000_000);
    const duplicate = try retry.advance(policy, first.state, ip, attempt(100_000_000, 1), 100_000_001);
    try t.expectEqual(retry.Disposition.duplicate, duplicate.disposition);
    try t.expect(duplicate.decision == null);
    try t.expectEqual(first.state.last_processed_us, duplicate.state.last_processed_us);
    try t.expectEqual(first.state.count, duplicate.state.count);
    try t.expectEqual(first.state.attempts[0].at_us, duplicate.state.attempts[0].at_us);
    try t.expectEqualSlices(u8, &first.state.attempts[0].occurrence, &duplicate.state.attempts[0].occurrence);
    try t.expectError(error.InvalidRetryState, retry.advance(policy, first.state, ip, attempt(99_999_999, 1), 100_000_001));

    const distinct = try retry.advance(policy, first.state, ip, attempt(100_000_000, 2), 100_000_001);
    try t.expectEqual(retry.Disposition.counted, distinct.disposition);
    try t.expectEqual(@as(u16, 2), distinct.state.count);
}

test "native retry: delayed cleanup preserves the inclusive endpoint" {
    var state = (try retry.advance(policy, null, ip, attempt(90_000_000, 1), 100_000_000)).state;
    state = (try retry.advance(policy, state, ip, attempt(100_000_000, 2), 100_000_000)).state;
    const endpoint = try retry.prune(policy, state, 100_000_000);
    try t.expect(!endpoint.changed);
    try t.expectEqual(@as(u16, 2), endpoint.state.count);

    const one_old = try retry.prune(policy, state, 100_000_001);
    try t.expect(one_old.changed);
    try t.expectEqual(@as(u16, 1), one_old.state.count);
    try t.expectEqual(@as(?i64, 100_000_000), one_old.state.latestEventUs());

    const empty = try retry.prune(policy, one_old.state, 110_000_001);
    try t.expect(empty.changed);
    try t.expectEqual(@as(u16, 0), empty.state.count);
    try t.expectEqual(@as(?i64, null), empty.state.latestEventUs());
    try t.expectError(error.RetryClockReversed, retry.prune(policy, empty.state, 110_000_000));
}

test "native retry: evidence validation is independent of numeric attempt state" {
    const without = try retry.advance(policy, null, ip, attempt(100_000_000, 1), 100_000_000);
    const with = try retry.advanceWithEvidence(policy, null, ip, attempt(100_000_000, 1), 100_000_000, .{ .text = "failed password: caf\xc3\xa9" });
    try t.expectEqual(without.state.count, with.state.count);
    try t.expectEqual(without.state.last_processed_us, with.state.last_processed_us);
    try t.expectEqualSlices(u8, &without.state.attempts[0].occurrence, &with.state.attempts[0].occurrence);
    try t.expectEqual(@as(usize, 2 * 1024), retry.max_evidence_text_bytes);
    try t.expectEqual(@as(usize, 16 * 1024), retry.max_subject_evidence_bytes);
    try t.expectError(error.InvalidRetryEvidence, retry.advanceWithEvidence(policy, null, ip, attempt(100_000_000, 1), 100_000_000, .{ .text = "" }));
    try t.expectError(error.InvalidRetryEvidence, retry.advanceWithEvidence(policy, null, ip, attempt(100_000_000, 1), 100_000_000, .{ .text = "\xff" }));
    var too_large: [retry.max_evidence_text_bytes + 1]u8 = undefined;
    @memset(&too_large, 'x');
    try t.expectError(error.InvalidRetryEvidence, retry.advanceWithEvidence(policy, null, ip, attempt(100_000_000, 1), 100_000_000, .{ .text = &too_large }));
}

test "native retry: SYS-029 literal native expectations and supported threshold boundary" {
    var four = policy;
    four.maxretry = 4;
    four.window_us = 600;
    var state: ?retry.State = null;
    for ([_]i64{ 0, 1, 2, 601 }, 0..) |stamp, index| {
        const result = try retry.advance(four, state, ip, attempt(stamp, @intCast(index)), stamp);
        try t.expect(result.decision == null);
        state = result.state;
    }
    try t.expectEqual(@as(u16, 3), state.?.count);
    try t.expectEqual(@as(i64, 1), state.?.attempts[0].at_us);

    var decay = four;
    decay.maxretry = 5;
    state = null;
    for ([_]i64{ 0, 1, 2, 900 }, 0..) |stamp, index| {
        state = (try retry.advance(decay, state, ip, attempt(stamp, @intCast(index)), stamp)).state;
    }
    try t.expectEqual(@as(u16, 1), state.?.count);
    try t.expectEqual(@as(?i64, 900), state.?.latestEventUs());

    var ordered = try retry.advance(decay, null, ip, attempt(100, 1), 100);
    ordered = try retry.advance(decay, ordered.state, ip, attempt(0, 2), 100);
    try t.expectEqual(@as(?i64, 100), ordered.state.latestEventUs());
    try t.expectEqual(@as(i64, 0), ordered.state.attempts[0].at_us);

    var one = policy;
    one.maxretry = 1;
    try t.expect((try retry.advance(one, null, ip, attempt(0, 1), 0)).decision != null);
    var maximum = policy;
    maximum.maxretry = retry.max_attempts;
    state = null;
    for (0..retry.max_attempts) |index| {
        const result = try retry.advance(maximum, state, ip, attempt(@intCast(index), @intCast(index)), @intCast(index));
        if (index + 1 == retry.max_attempts) try t.expect(result.decision != null) else try t.expect(result.decision == null);
        state = result.state;
    }
    try t.expectEqual(@as(u16, 0), state.?.count);

    const unsupported = native_config.JailConfig{ .name = "ssh", .filter = "sshd", .maxretry = 129 };
    try t.expectError(error.InvalidRetryPolicy, retry_config.fromJail(&unsupported, .{}, 1));
}

test "native retry: active decisions retain deadline and no attempts leak into the next window" {
    var single = policy;
    single.maxretry = 1;
    var result = try retry.advance(single, null, ip, attempt(100_000_000, 1), 100_000_000);
    result = try retry.advance(single, result.state, ip, attempt(110_000_000, 2), 110_000_000);
    try t.expect(result.decision == null);
    try t.expectEqual(retry.Disposition.active, result.disposition);
    try t.expectEqualDeep(retry.Lease{ .finite = 160_000_000 }, result.state.lease);
    try t.expectEqual(@as(u16, 0), result.state.count);
    result = try retry.advance(single, result.state, ip, attempt(160_000_000, 3), 160_000_000);
    try t.expectEqual(@as(u64, 2), result.decision.?.ordinal);
    try t.expectEqualDeep(retry.Lease{ .finite = 220_000_000 }, result.decision.?.lease);
    try t.expectError(error.RetryClockReversed, retry.advance(single, result.state, ip, attempt(159_999_999, 4), 159_999_999));
    try t.expectError(error.RetryTimeOverflow, retry.advance(single, null, ip, attempt(std.math.maxInt(i64), 4), std.math.maxInt(i64)));
}

test "native retry: persisted encodings reject malformed versions limits duplicate identities and ordering" {
    var encoded = try policy.encode();
    try t.expectEqualDeep(policy, try retry.Policy.decode(&encoded));
    encoded[4] = 3;
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

test "native retry: permanent policy uses the tagged wire format and explicit config" {
    const permanent = retry.Policy{ .maxretry = 1, .window_us = 10, .duration = .permanent, .max_subjects = 1 };
    const encoded = try permanent.encode();
    try t.expectEqual(@as(u8, 2), encoded[4]);
    try t.expectEqual(@as(u8, 2), encoded[28]);
    try t.expectEqualDeep(permanent, try retry.Policy.decode(&encoded));
    const decided = try retry.advance(permanent, null, ip, attempt(100, 1), 100);
    try t.expectEqualDeep(retry.Lease.permanent, decided.state.lease);
    try t.expectEqualDeep(retry.Lease.permanent, decided.decision.?.lease);
    try t.expect(decided.state.lease.live(std.math.maxInt(i64)));

    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const cfg = try native_config.Config.parse(arena.allocator(),
        \\[defaults]
        \\bantime = "permanent"
        \\[jails.ssh]
        \\filter = "sshd"
    );
    const configured = try retry_config.fromJail(&cfg.jails[0], cfg.defaults, 8);
    try t.expectEqualDeep(retry.Duration.permanent, configured.duration);
}

test "native retry: escalation formula bounds encoding and config are explicit" {
    const base = retry.Duration{ .finite_us = 60_000_000 };
    var linear = retry.Escalation{ .enabled = true, .multiplier = 2, .factor = 0.5, .max_duration_us = 600_000_000, .jitter_us = 5_000_000 };
    try t.expectEqualDeep(base, try linear.duration(base, 0, 0));
    try t.expectEqualDeep(retry.Duration{ .finite_us = 305_000_000 }, try linear.duration(base, 3, 5_000_000));
    const encoded = try linear.encode();
    try t.expectEqualDeep(linear, try retry.Escalation.decode(&encoded));
    try t.expectError(error.InvalidEscalationInput, linear.duration(base, 0, 1_000_000));
    linear.formula = .exponential;
    linear.factor = 2;
    try t.expectEqualDeep(retry.Duration{ .finite_us = 485_000_000 }, try linear.duration(base, 2, 5_000_000));
    try t.expectEqualDeep(retry.Duration{ .finite_us = 600_000_000 }, try linear.duration(base, std.math.maxInt(u64), 5_000_000));

    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const cfg = try native_config.Config.parse(arena.allocator(),
        \\[defaults]
        \\bantime = 60
        \\bantime_increment_enabled = true
        \\bantime_increment_formula = "exponential"
        \\bantime_increment_scope = "overall"
        \\bantime_increment_multiplier = 2
        \\bantime_increment_factor = 2
        \\bantime_increment_max_bantime = 600
        \\bantime_increment_jitter = 5
        \\[jails.ssh]
        \\filter = "sshd"
    );
    const configured = try retry_config.fromJail(&cfg.jails[0], cfg.defaults, 8);
    try t.expect(configured.escalation.enabled);
    try t.expectEqual(retry.EscalationScope.overall, configured.escalation.scope);
    try t.expectEqual(@as(i64, 5_000_000), configured.escalation.jitter_us);
    var permanent = configured;
    permanent.duration = .permanent;
    try t.expectError(error.InvalidRetryPolicy, permanent.validate());
}

test "native retry: schema 16 migrates exact finite leases and persists permanent decisions" {
    var temp = t.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(root);
    const path = try std.fs.path.join(t.allocator, &.{ root, "leases.sqlite" });
    defer t.allocator.free(path);
    const one = retry.Policy{ .maxretry = 1, .window_us = policy.window_us, .duration = policy.duration, .max_subjects = 2 };
    const permanent = retry.Policy{ .maxretry = 1, .window_us = policy.window_us, .duration = .permanent, .max_subjects = 2 };
    {
        var store = try durable.Store.open(t.allocator, path);
        defer store.close();
        try admitted(&store);
        try store.admitRetry("finite", StoreFixture.generation, one);
        _ = try store.commitRecord(try StoreFixture.recordWith(&store, "finite", "one", 0, 100_000_000, ip, one));
        try store.enableConsumers();
        try store.enableEffects();
        try store.enableConsumerManifests();
        try store.enableConfirmedHistory();
        try store.enableMaintenance();
        try store.enableCleanup();
        try t.expectEqual(@as(i64, 15), store.schema_version);
        try t.expectError(error.RetryStorageRequired, store.admitRetry("permanent", StoreFixture.generation, permanent));
        store.fail_at = .before_retry_lease_schema_commit;
        try t.expectError(error.InjectedFailure, store.enableRetryLeases());
        try t.expectEqual(@as(i64, 15), store.schema_version);
        store.fail_at = null;
        try store.enableRetryLeases();
        try t.expectEqual(@as(i64, 16), store.schema_version);
        try t.expectEqualDeep(retry.Lease{ .finite = 160_000_000 }, (try store.retryState("finite", ip)).?.lease);
        try t.expectEqualDeep(retry.Lease{ .finite = 160_000_000 }, (try store.retryDecision("finite", "file", "one")).?.lease);
        try store.admitRetry("permanent", StoreFixture.generation, permanent);
        _ = try store.commitRecord(try StoreFixture.recordWith(&store, "permanent", "two", 0, 100_000_001, ip, permanent));
        try t.expectEqualDeep(retry.Lease.permanent, (try store.retryState("permanent", ip)).?.lease);
        try t.expectEqualDeep(retry.Lease.permanent, (try store.retryDecision("permanent", "file", "two")).?.lease);
    }
    var reopened = try durable.Store.open(t.allocator, path);
    defer reopened.close();
    try reopened.enableReceipts(2);
    try t.expectEqual(@as(i64, 16), reopened.schema_version);
    try t.expectEqualDeep(retry.Lease{ .finite = 160_000_000 }, (try reopened.retryState("finite", ip)).?.lease);
    try t.expectEqualDeep(retry.Lease.permanent, (try reopened.retryState("permanent", ip)).?.lease);
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
            try t.expectEqualDeep(retry.Lease{ .finite = clock.now + policy.duration.finite_us }, decision.lease);
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
            try t.expectEqualDeep(decision.lease, state.lease);
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

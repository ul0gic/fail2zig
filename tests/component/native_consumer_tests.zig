// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const consumer = @import("engine_test").core.native_consumer;
const store_mod = @import("engine_test").core.record_store;

fn enable(store: *store_mod.Store) !void {
    try store.enableReceipts(8);
    try store.enableNativeTime();
    try store.enableYearInference();
    try store.enableDetection();
    try store.enableClockRecovery();
    try store.enableJournalDetection();
    try store.enableRetry();
}
const fixture_key = consumer.Key{ .kind = .correlation, .jail = "fixture", .source = "file", .rule = "login", .generation = [_]u8{1} ** 32 };
const cache_key = consumer.Key{ .kind = .dns, .jail = "shared", .source = "resolver", .rule = "lookup", .generation = [_]u8{2} ** 32 };
fn record() store_mod.Record {
    return .{ .jail = "fixture", .source = "file", .occurrence = "1", .cursor = "1", .raw_hash = [_]u8{1} ** 32, .disposition = "counted", .checkpoint = "source-state" };
}
const TestClock = struct {
    now: i64 = 100,
    advance: i64 = 0,
    fn read(ctx: ?*anyopaque) i64 {
        const self: *TestClock = @ptrCast(@alignCast(ctx.?));
        const result = self.now;
        self.now += self.advance;
        return result;
    }
};

test "native consumers: register atomic store and contract tests" {
    std.testing.refAllDecls(@import("engine_test").core.record_store);
    std.testing.refAllDecls(@import("engine_test").core.record_pipeline);
}

test "native consumers: duplicate keys and expired dependency reject before mutation" {
    const key = consumer.Key{ .kind = .dns, .jail = "shared", .source = "resolver", .rule = "addresses", .generation = [_]u8{1} ** 32 };
    var now: i64 = 12;
    const Clock = struct {
        fn read(ctx: ?*anyopaque) i64 {
            const value: *i64 = @ptrCast(@alignCast(ctx.?));
            return value.*;
        }
    };
    const dependency = consumer.Dependency{ .key = key, .expected_revision = 1, .valid_until_us = 12 };
    var batch = consumer.Batch{ .prepared_us = 10, .clock_context = &now, .clock = Clock.read, .dependencies = &.{dependency} };
    try batch.validate();
    try std.testing.expectError(error.ConsumerExpired, batch.checkedTime(10));
    now = 11;
    try std.testing.expectEqual(@as(i64, 11), try batch.checkedTime(10));
    now = 9;
    try std.testing.expectError(error.ConsumerClockReversed, batch.checkedTime(10));
    batch.dependencies = &.{ dependency, dependency };
    try std.testing.expectError(error.InvalidConsumer, batch.validate());
    batch.dependencies = &.{};
    batch.commit_before_us = 12;
    now = 11;
    try std.testing.expectEqual(@as(i64, 11), try batch.checkedTime(10));
    now = 12;
    try std.testing.expectError(error.ConsumerExpired, batch.checkedTime(10));
}

test "native consumers: multiple deltas and source rollback then reopen commit once" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(a, ".");
    defer a.free(base);
    const path = try std.fs.path.join(a, &.{ base, "state.sqlite" });
    defer a.free(path);
    var clock = TestClock{};
    var input = record();
    input.consumers = .{ .prepared_us = 100, .clock_context = &clock, .clock = TestClock.read, .deltas = &.{
        .{ .key = fixture_key, .format_version = 1, .expected_revision = 0, .payload = "context" },
        .{ .key = cache_key, .format_version = 1, .expected_revision = 0, .payload = "address", .valid_until_us = 200 },
    } };
    {
        var store = try store_mod.Store.open(a, path);
        defer store.close();
        try enable(&store);
        store.fail_at = .before_consumer_schema_commit;
        try std.testing.expectError(error.InjectedFailure, store.enableConsumers());
        try std.testing.expectEqual(@as(i64, 9), store.schema_version);
        store.fail_at = null;
        try store.enableConsumers();
        for ([_]store_mod.CommitStage{ .after_consumer_delta, .before_commit }) |stage| {
            store.fail_at = stage;
            try std.testing.expectError(error.InjectedFailure, store.commitRecord(input));
            const saved = try store.consumerSnapshot(a, fixture_key);
            defer saved.deinit(a);
            try std.testing.expectEqual(@as(u64, 0), saved.revision);
            try std.testing.expectEqual(@as(u64, 0), try store.revision("fixture"));
            try std.testing.expectEqual(@as(?[]u8, null), try store.sourceCursor(a, "fixture", "file"));
        }
    }
    var reopened = try store_mod.Store.open(a, path);
    defer reopened.close();
    try std.testing.expectEqual(@as(i64, 10), reopened.schema_version);
    try std.testing.expectEqual(store_mod.CommitResult.committed, try reopened.commitRecord(input));
    try std.testing.expectEqual(store_mod.CommitResult.already_committed, try reopened.commitRecord(input));
    const state = try reopened.consumerSnapshot(a, fixture_key);
    defer state.deinit(a);
    const cache = try reopened.consumerSnapshot(a, cache_key);
    defer cache.deinit(a);
    try std.testing.expectEqual(@as(u64, 1), state.revision);
    try std.testing.expectEqual(@as(u64, 1), cache.revision);
    try std.testing.expectEqualStrings("context", state.payload.?);
    try std.testing.expectEqual(@as(?i64, 200), cache.valid_until_us);
}

test "native consumers: shared dependency conflicts and expiry after writes roll back record" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(a, ".");
    defer a.free(base);
    const path = try std.fs.path.join(a, &.{ base, "state.sqlite" });
    defer a.free(path);
    var store = try store_mod.Store.open(a, path);
    defer store.close();
    try enable(&store);
    try store.enableConsumers();
    var clock = TestClock{};
    var input = record();
    input.consumers = .{ .prepared_us = 100, .clock_context = &clock, .clock = TestClock.read, .deltas = &.{.{ .key = cache_key, .format_version = 1, .expected_revision = 0, .payload = "allowed", .valid_until_us = 200 }} };
    _ = try store.commitRecord(input);
    input.occurrence = "2";
    input.cursor = "2";
    input.expected_revision = 1;
    var dependency = [_]consumer.Dependency{.{ .key = cache_key, .expected_revision = 0 }};
    input.consumers.?.deltas = &.{.{ .key = fixture_key, .format_version = 1, .expected_revision = 0, .payload = "context" }};
    input.consumers.?.dependencies = &dependency;
    try std.testing.expectError(error.StaleConsumerCheckpoint, store.commitRecord(input));
    dependency[0].expected_revision = 1;
    try std.testing.expectError(error.StaleConsumerCheckpoint, store.commitRecord(input));
    dependency[0].valid_until_us = 200;
    clock = .{ .now = 199, .advance = 1 };
    try std.testing.expectError(error.ConsumerExpired, store.commitRecord(input));
    try std.testing.expectEqual(@as(u64, 1), try store.revision("fixture"));
    const prior = try store.consumerSnapshot(a, fixture_key);
    defer prior.deinit(a);
    try std.testing.expectEqual(@as(u64, 0), prior.revision);
    clock = .{ .now = 199 };
    _ = try store.commitRecord(input);
    const result = try store.consumerSnapshot(a, fixture_key);
    defer result.deinit(a);
    try std.testing.expectEqual(@as(u64, 1), result.revision);
    const cache = try store.consumerSnapshot(a, cache_key);
    defer cache.deinit(a);
    try std.testing.expectEqual(@as(u64, 1), cache.revision);
}

test "native consumers: processing floor survives restart and old reader sees schema upgrade" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(a, ".");
    defer a.free(base);
    const path = try std.fs.path.join(a, &.{ base, "clock.sqlite" });
    defer a.free(path);
    {
        var writer = try store_mod.Store.open(a, path);
        defer writer.close();
        try enable(&writer);
        var reader = try store_mod.Store.open(a, path);
        defer reader.close();
        try writer.enableConsumers();
        var clock = TestClock{ .now = 250 };
        var input = record();
        input.consumers = .{ .prepared_us = 250, .clock_context = &clock, .clock = TestClock.read, .deltas = &.{.{ .key = fixture_key, .format_version = 1, .expected_revision = 0, .payload = "context" }} };
        _ = try writer.commitRecord(input);
        const state = try reader.consumerSnapshot(a, fixture_key);
        defer state.deinit(a);
        try std.testing.expectEqual(@as(u64, 1), state.revision);
        try std.testing.expectError(error.NativeConsumersNotIntegrated, writer.validateRuntimeOwners(&.{"fixture"}));
    }
    var restored = try store_mod.Store.open(a, path);
    defer restored.close();
    try std.testing.expectEqual(@as(i64, 250), (try restored.admissionClock()).?.us);
    var clock = TestClock{ .now = 150 };
    var input = record();
    input.occurrence = "2";
    input.cursor = "2";
    input.expected_revision = 1;
    input.consumers = .{ .prepared_us = 150, .clock_context = &clock, .clock = TestClock.read, .dependencies = &.{.{ .key = fixture_key, .expected_revision = 1 }} };
    try std.testing.expectError(error.ConsumerClockReversed, restored.commitRecord(input));
    try std.testing.expectEqual(@as(?i64, 250), restored.consumer_clock_floor_us);
    try std.testing.expectEqual(@as(u64, 1), try restored.revision("fixture"));
}

pub const store_tests = @import("store/tests.zig");

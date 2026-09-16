// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const time = @import("core/native_time.zig");
const policy = @import("core/source_time_policy.zig");
const files = @import("core/durable_file_source.zig");
const records = @import("core/source_record.zig");
const durable = @import("core/record_store.zig");
const pipeline = @import("core/record_pipeline.zig");
const health = @import("core/storage_health.zig");
const Fixture = @import("future_time_pipeline_tests.zig").Fixture;

const Clock = struct {
    now: i64,
    calls: usize = 0,
    fn read(context: ?*anyopaque) !time.Timestamp {
        const self: *Clock = @ptrCast(@alignCast(context.?));
        self.calls += 1;
        return .{ .us = self.now };
    }
    fn admission(self: *Clock, generation: [32]u8) pipeline.ReceiptAdmission {
        return .{ .generation = generation, .clock_context = self, .clock = read };
    }
};

test "receipt recovery: file pipeline owns receipt before preparation and restores it without fixture memory" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "ordinary.log" });
    defer a.free(path);
    const database = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    defer a.free(database);
    const log = try temp.dir.createFile("ordinary.log", .{});
    defer log.close();
    const generation = try policy.binding([_]u8{17} ** 32, .timestamped, 600_000_000);
    const first = "1060.000000|ordinary adjusted event\n";
    const second = "1760.000001|ordinary excessive future event\n";
    const third = "1800.000000|ordinary current event\n";
    {
        var store = try durable.Store.open(a, database);
        defer store.close();
        try store.enableReceipts(2);
        var clock = Clock{ .now = 1_000_000_000 };
        var processor = Fixture{ .allocator = a, .receipt = .{ .us = 999_000_000_000 }, .now = .{ .us = clock.now } };
        var owner = pipeline.Pipeline{ .store = &store, .jail = "fixture", .processor = processor.adapter(), .receipts = clock.admission(generation) };
        try owner.restore(a);
        var source = try files.FileSource.init(a, path, "ordinary", .head, null);
        defer source.deinit();
        try source.setNativeFraming(.utf8, generation, 4096);
        try std.testing.expect(!try source.poll(pipeline.Pipeline.acknowledge, &owner));
        try std.testing.expectEqual(@as(usize, 0), clock.calls);
        try log.writeAll(first);
        store.fail_at = .before_receipt_commit;
        try std.testing.expectError(error.InjectedFailure, source.poll(pipeline.Pipeline.acknowledge, &owner));
        try std.testing.expectEqual(@as(usize, 0), processor.data_preparations);
        try std.testing.expectEqual(@as(usize, 0), try store.pendingReceiptCount());
        try std.testing.expectEqual(@as(u64, 0), source.acknowledgedCheckpoint().?.offset);
        try std.testing.expectEqual(@as(i64, 1_000_000_000), owner.candidate_receipt.?.time.us);
        clock.now = 1_700_000_000;
        processor.now.us = clock.now;
        store.fail_at = .after_receipt_commit;
        try std.testing.expectError(error.InjectedFailure, source.poll(pipeline.Pipeline.acknowledge, &owner));
        try std.testing.expectEqual(@as(usize, 1), clock.calls);
        try std.testing.expectEqual(@as(usize, 0), processor.data_preparations);
        try std.testing.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
        try std.testing.expectEqual(@as(u64, 1), owner.revision);
        try std.testing.expectEqual(@as(i64, 0), try store.pendingIntents());
    }
    {
        var store = try durable.Store.open(a, database);
        defer store.close();
        try store.enableReceipts(2);
        var clock = Clock{ .now = 1_700_000_000 };
        var processor = Fixture{ .allocator = a, .receipt = .{ .us = 999_000_000_000 }, .now = .{ .us = clock.now } };
        var owner = pipeline.Pipeline{ .store = &store, .jail = "fixture", .processor = processor.adapter(), .receipts = clock.admission([_]u8{0} ** 32) };
        try std.testing.expectError(error.ReceiptConflict, owner.restore(a));
        try std.testing.expect(!owner.ready);
        owner.receipts = clock.admission(generation);
        try owner.restore(a);
        const cursor = (try store.sourceCursor(a, "fixture", "ordinary")).?;
        defer a.free(cursor);
        const parsed = try std.json.parseFromSlice(files.Resume, a, cursor, .{});
        defer parsed.deinit();
        var source = try files.FileSource.init(a, path, "ordinary", .head, parsed.value);
        defer source.deinit();
        try source.setNativeFraming(.utf8, generation, 4096);
        try std.testing.expect(try source.verifyContinuity());
        try std.testing.expect(try source.poll(pipeline.Pipeline.acknowledge, &owner));
        const evidence = processor.state.outcome.?.obsolete;
        try std.testing.expectEqual(@as(i64, 1_000_000_000), evidence.receipt.us);
        try std.testing.expectEqual(@as(i64, 1_000_000_000), evidence.timestamp.us);
        try std.testing.expectEqual(@as(i64, 1_060_000_000), evidence.original.?.us);
        try std.testing.expectEqual(@as(usize, 0), try store.pendingReceiptCount());
        try std.testing.expectEqual(@as(i64, 0), try store.pendingIntents());
        try log.writeAll(second);
        store.fail_at = .after_receipt_delete;
        try std.testing.expectError(error.InjectedFailure, source.poll(pipeline.Pipeline.acknowledge, &owner));
        try std.testing.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
        try std.testing.expectEqual(@as(u64, first.len), source.acknowledgedCheckpoint().?.offset);
        try std.testing.expectEqual(@as(u64, 0), processor.health.snapshot().future);
        try std.testing.expect(processor.health.nextNotice(0) == null);
    }
    var store = try durable.Store.open(a, database);
    defer store.close();
    try store.enableReceipts(2);
    var clock = Clock{ .now = 1_800_000_000 };
    var processor = Fixture{ .allocator = a, .receipt = .{ .us = 999_000_000_000 }, .now = .{ .us = clock.now } };
    var owner = pipeline.Pipeline{ .store = &store, .jail = "fixture", .processor = processor.adapter(), .receipts = clock.admission(generation) };
    try owner.restore(a);
    const cursor = (try store.sourceCursor(a, "fixture", "ordinary")).?;
    defer a.free(cursor);
    const parsed = try std.json.parseFromSlice(files.Resume, a, cursor, .{});
    defer parsed.deinit();
    var source = try files.FileSource.init(a, path, "ordinary", .head, parsed.value);
    defer source.deinit();
    try source.setNativeFraming(.utf8, generation, 4096);
    try log.pwriteAll("2", first.len);
    try std.testing.expectError(error.ReceiptConflict, source.poll(pipeline.Pipeline.acknowledge, &owner));
    try std.testing.expectEqual(@as(usize, 0), processor.data_preparations);
    try std.testing.expectEqual(@as(u64, first.len), source.acknowledgedCheckpoint().?.offset);
    try log.pwriteAll("1", first.len);
    owner = .{ .store = &store, .jail = "fixture", .processor = processor.adapter(), .receipts = clock.admission(generation) };
    try owner.restore(a);
    try std.testing.expect(try source.poll(pipeline.Pipeline.acknowledge, &owner));
    const rejected = processor.state.outcome.?.rejected;
    try std.testing.expectEqual(policy.Reason.future, rejected.reason);
    try std.testing.expectEqual(@as(i64, 1_700_000_000), rejected.receipt.?.us);
    try std.testing.expectEqual(@as(i64, 1_760_000_001), rejected.original.?.us);
    try std.testing.expectEqual(@as(u64, 1), processor.health.nextNotice(0).?.future_since_notice);
    try log.writeAll(third);
    try std.testing.expect(try source.poll(pipeline.Pipeline.acknowledge, &owner));
    try std.testing.expectEqualDeep(policy.Counters{ .eligible = 1, .obsolete = 1, .adjusted = 1, .future = 1 }, processor.health.snapshot());
    try std.testing.expectEqual(@as(i64, 1), try store.pendingIntents());
    try std.testing.expectEqual(@as(usize, 0), try store.pendingReceiptCount());
    try owner.restore(a);
    try std.testing.expect(!try source.poll(pipeline.Pipeline.acknowledge, &owner));
    try std.testing.expect(processor.health.nextNotice(60_000) == null);
}

test "receipt recovery: receipt failure closes the shared gate before any processor runs" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    defer a.free(path);
    var store = try durable.Store.open(a, path);
    defer store.close();
    try store.enableReceipts(2);
    const Monotonic = struct {
        fn read(_: ?*anyopaque) u64 {
            return 0;
        }
    };
    var gate = health.Gate.init(.{ .context = null, .read = Monotonic.read });
    const generation = try gate.beginRecovery();
    try gate.completed(generation, .storage);
    var clock = Clock{ .now = 1_000_000_000 };
    var first = Fixture{ .allocator = a, .receipt = .{ .us = 0 }, .now = .{ .us = clock.now } };
    var second = Fixture{ .allocator = a, .receipt = .{ .us = 0 }, .now = .{ .us = clock.now } };
    var one = pipeline.Pipeline{ .store = &store, .jail = "one", .processor = first.adapter(), .gate = &gate, .receipts = clock.admission([_]u8{1} ** 32) };
    var two = pipeline.Pipeline{ .store = &store, .jail = "two", .processor = second.adapter(), .gate = &gate, .receipts = clock.admission([_]u8{2} ** 32) };
    try one.restore(a);
    try two.restore(a);
    try gate.completed(generation, .state);
    try gate.completed(generation, .ownership);
    try gate.completed(generation, .sources);
    const record = records.Record{ .source = "ordinary", .occurrence = "one", .cursor = "one", .message = "1000|ordinary event", .raw_hash = [_]u8{1} ** 32 };
    store.fail_at = .before_receipt_commit;
    try std.testing.expectError(error.InjectedFailure, pipeline.Pipeline.acknowledge(record, &one));
    try std.testing.expectEqual(health.Phase.intervention, gate.snapshot().phase);
    try std.testing.expectEqual(@as(u64, 0), gate.snapshot().committed_records);
    try std.testing.expectError(error.StoragePaused, pipeline.Pipeline.acknowledge(record, &two));
    try std.testing.expectEqual(@as(usize, 0), first.data_preparations + second.data_preparations);
    try std.testing.expectEqual(@as(usize, 1), clock.calls);
    try std.testing.expectEqual(@as(usize, 0), try store.pendingReceiptCount());
    try std.testing.expectEqual(@as(i64, 0), try store.pendingIntents());
}

test "receipt recovery: conflicting occurrence isolates its owner while other sources retain protection" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    defer a.free(path);
    var store = try durable.Store.open(a, path);
    defer store.close();
    try store.enableReceipts(2);
    const pending = durable.ReceiptIdentity{ .jail = "one", .source = "ordinary", .occurrence = "one", .cursor = "one", .raw_hash = [_]u8{1} ** 32, .generation = [_]u8{1} ** 32 };
    _ = try store.beginReceipt(pending, .{ .us = 1_000_000_000 }, 0);
    var different_generation = pending;
    different_generation.source = "another";
    different_generation.generation[0] ^= 1;
    try std.testing.expectError(error.ReceiptConflict, store.beginReceipt(different_generation, .{ .us = 1_000_000_000 }, 0));
    const Monotonic = struct {
        fn read(_: ?*anyopaque) u64 {
            return 0;
        }
    };
    var gate = health.Gate.init(.{ .context = null, .read = Monotonic.read });
    const generation = try gate.beginRecovery();
    try gate.completed(generation, .storage);
    var clock = Clock{ .now = 1_000_000_000 };
    var first = Fixture{ .allocator = a, .receipt = .{ .us = 0 }, .now = .{ .us = clock.now } };
    var second = Fixture{ .allocator = a, .receipt = .{ .us = 0 }, .now = .{ .us = clock.now } };
    var one = pipeline.Pipeline{ .store = &store, .jail = "one", .processor = first.adapter(), .gate = &gate, .receipts = clock.admission(pending.generation) };
    var two = pipeline.Pipeline{ .store = &store, .jail = "two", .processor = second.adapter(), .gate = &gate, .receipts = clock.admission([_]u8{2} ** 32) };
    try one.restore(a);
    try two.restore(a);
    try gate.completed(generation, .state);
    try gate.completed(generation, .ownership);
    try gate.completed(generation, .sources);
    const changed = records.Record{ .source = "ordinary", .occurrence = "one", .cursor = "one", .message = "1000|ordinary event", .raw_hash = [_]u8{2} ** 32 };
    try std.testing.expectError(error.ReceiptConflict, pipeline.Pipeline.acknowledge(changed, &one));
    try std.testing.expect(!one.ready);
    try std.testing.expectEqual(health.Phase.healthy, gate.snapshot().phase);
    try std.testing.expectEqual(@as(usize, 0), first.data_preparations);
    try pipeline.Pipeline.acknowledge(changed, &two);
    try std.testing.expectEqual(@as(u64, 1), second.health.snapshot().eligible);
    try std.testing.expectEqual(@as(u64, 1), gate.snapshot().committed_records);
    try std.testing.expectEqual(@as(i64, 1), try store.pendingIntents());
    try std.testing.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
    try std.testing.expectEqual(@as(i64, 1_000_000_000), (try store.pendingReceipt(pending)).?.us);
}

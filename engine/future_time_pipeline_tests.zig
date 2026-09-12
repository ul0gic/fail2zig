// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Original ordinary-file/SQLite fixture for future-time decisions. Receipt
//! times are supplied by this fixture's owner, not captured/recovered by a daemon.
//! The small JSON checkpoint/threshold are fixtures, not native production schema.
const std = @import("std");
const time = @import("core/native_time.zig");
const policy = @import("core/source_time_policy.zig");
const files = @import("core/durable_file_source.zig");
const records = @import("core/source_record.zig");
const durable = @import("core/record_store.zig");
const pipeline = @import("core/record_pipeline.zig");

const State = struct { counters: policy.Counters = .{}, outcome: ?policy.Result = null };
/// Shared by receipt-recovery integration tests; never a production processor.
pub const Fixture = struct {
    allocator: std.mem.Allocator,
    receipt: time.Timestamp,
    now: time.Timestamp,
    state: State = .{},
    health: policy.Health = .{},
    data_preparations: usize = 0,

    pub fn adapter(self: *Fixture) pipeline.Processor {
        return .{ .context = self, .prepare = prepare, .prepare_restore = restore };
    }
    const Staged = struct {
        owner: *Fixture,
        state: State,
        bytes: []u8,
        restoring: bool = false,
        fn publish(context: ?*anyopaque) void {
            const self: *Staged = @ptrCast(@alignCast(context.?));
            self.owner.state = self.state;
            if (self.restoring) {
                self.owner.health = policy.Health.init(self.state.counters) catch unreachable;
            } else self.owner.health.publish(self.state.counters);
        }
        fn release(context: ?*anyopaque) void {
            const self: *Staged = @ptrCast(@alignCast(context.?));
            const allocator = self.owner.allocator;
            allocator.free(self.bytes);
            allocator.destroy(self);
        }
    };
    fn stage(self: *Fixture, state: State) !*Staged {
        const bytes = try std.json.stringifyAlloc(self.allocator, state, .{});
        errdefer self.allocator.free(bytes);
        const staged = try self.allocator.create(Staged);
        staged.* = .{ .owner = self, .state = state, .bytes = bytes };
        return staged;
    }
    fn prepare(record: records.Record, context: ?*anyopaque) !pipeline.Prepared {
        const self: *Fixture = @ptrCast(@alignCast(context.?));
        var next = self.state;
        var disposition: []const u8 = "source-checkpoint";
        var intent: ?[]const u8 = null;
        if (record.kind == .data) {
            self.data_preparations += 1;
            const end = std.mem.indexOfScalar(u8, record.message, '|') orelse return error.InvalidFixture;
            const input = try policy.parseField(.epoch_seconds, record.message[0..end], .{});
            const result = try policy.evaluate(.timestamped, input, record.receipt_time orelse self.receipt, self.now, 600_000_000);
            next.outcome = result;
            next.counters = try next.counters.advanced(result);
            disposition = result.disposition();
            if (result == .eligible) intent = "ordinary-fixture-eligible";
        }
        const staged = try self.stage(next);
        return .{ .checkpoint = staged.bytes, .disposition = disposition, .intent = intent, .context = staged, .publish = Staged.publish, .release = Staged.release };
    }
    fn restore(checkpoint: ?[]const u8, context: ?*anyopaque) !pipeline.Restored {
        const self: *Fixture = @ptrCast(@alignCast(context.?));
        var next = State{};
        if (checkpoint) |bytes| {
            if (bytes.len > 1024) return error.InvalidFixtureCheckpoint;
            const parsed = try std.json.parseFromSlice(State, self.allocator, bytes, .{});
            defer parsed.deinit();
            next = parsed.value;
            try next.counters.validate();
        }
        const staged = try self.stage(next);
        staged.restoring = true;
        return .{ .context = staged, .publish = Staged.publish, .release = Staged.release };
    }
};

test "future time: file rollback and reopen preserve receipt bounds original time and rejection" {
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
    const binding = try policy.binding([_]u8{7} ** 32, .timestamped, 600_000_000);
    const first = "1060.000000|ordinary small clock difference\n";
    const second = "1660.000002|ordinary large clock difference\n";
    const third = "1700.000000|ordinary current event\n";
    {
        var store = try durable.Store.open(a, database);
        defer store.close();
        var processor = Fixture{ .allocator = a, .receipt = .{ .us = 1_000_000_000 }, .now = .{ .us = 1_000_000_000 } };
        var owner = pipeline.Pipeline{ .store = &store, .jail = "fixture", .processor = processor.adapter() };
        try owner.restore(a);
        var source = try files.FileSource.init(a, path, "ordinary", .head, null);
        defer source.deinit();
        try source.setNativeFraming(.utf8, binding, 4096);
        try std.testing.expect(!try source.poll(pipeline.Pipeline.acknowledge, &owner)); // committed baseline
        try log.writeAll(first);
        store.fail_at = .before_commit;
        try std.testing.expectError(error.InjectedFailure, source.poll(pipeline.Pipeline.acknowledge, &owner));
        try std.testing.expectEqual(State{}, processor.state);
        try std.testing.expectEqual(@as(u64, 0), source.acknowledgedCheckpoint().?.offset);
        try std.testing.expectEqual(@as(i64, 0), try store.pendingIntents());
    }
    var store = try durable.Store.open(a, database);
    defer store.close();
    // The owner retains the original observation while processing time advances.
    // Native session capture/crash provenance is a separate integration obligation.
    var processor = Fixture{ .allocator = a, .receipt = .{ .us = 1_000_000_000 }, .now = .{ .us = 1_600_000_001 } };
    var owner = pipeline.Pipeline{ .store = &store, .jail = "fixture", .processor = processor.adapter() };
    try owner.restore(a);
    const cursor = (try store.sourceCursor(a, "fixture", "ordinary")).?;
    defer a.free(cursor);
    const parsed = try std.json.parseFromSlice(files.Resume, a, cursor, .{});
    defer parsed.deinit();
    var source = try files.FileSource.init(a, path, "ordinary", .head, parsed.value);
    defer source.deinit();
    // A policy/window/config change cannot reinterpret the saved source silently.
    try std.testing.expectError(error.FramingProfileMismatch, source.setNativeFraming(.utf8, try policy.binding([_]u8{7} ** 32, .undated, 600_000_000), 4096));
    try std.testing.expectError(error.FramingProfileMismatch, source.setNativeFraming(.utf8, try policy.binding([_]u8{7} ** 32, .timestamped, 599_000_000), 4096));
    try source.setNativeFraming(.utf8, binding, 4096);
    try std.testing.expect(try source.verifyContinuity());
    try std.testing.expect(try source.poll(pipeline.Pipeline.acknowledge, &owner));
    const evidence = processor.state.outcome.?.obsolete;
    try std.testing.expectEqual(@as(i64, 1_000_000_000), evidence.timestamp.us);
    try std.testing.expectEqual(@as(i64, 1_060_000_000), evidence.original.?.us);
    try std.testing.expectEqual(policy.Origin.clock_adjusted, evidence.origin);
    try std.testing.expectEqualDeep(policy.Counters{ .obsolete = 1, .adjusted = 1 }, processor.health.snapshot());
    try std.testing.expectEqual(@as(i64, 0), try store.pendingIntents());
    try owner.restore(a);
    try std.testing.expectEqualDeep(evidence, processor.state.outcome.?.obsolete);
    // Next observed record is beyond tolerance. A failed rejection commit does
    // not publish its warning/counter; retry still rejects even after time catches up.
    processor.receipt = processor.now;
    try log.writeAll(second);
    store.fail_at = .before_commit;
    try std.testing.expectError(error.InjectedFailure, source.poll(pipeline.Pipeline.acknowledge, &owner));
    try std.testing.expectEqual(@as(u64, first.len), source.acknowledgedCheckpoint().?.offset);
    try std.testing.expect(processor.health.nextNotice(0) == null);
    try std.testing.expectEqual(@as(u64, 0), processor.health.snapshot().future);
    store.fail_at = null;
    processor.now.us = 1_700_000_000;
    try std.testing.expect(try source.poll(pipeline.Pipeline.acknowledge, &owner));
    const rejected = processor.state.outcome.?.rejected;
    try std.testing.expectEqual(policy.Reason.future, rejected.reason);
    try std.testing.expectEqual(@as(i64, 1_660_000_002), rejected.original.?.us);
    try std.testing.expectEqual(@as(i64, 1_600_000_001), rejected.receipt.?.us);
    try std.testing.expectEqual(@as(u64, 1), processor.health.nextNotice(0).?.future_since_notice);
    try std.testing.expectEqual(@as(i64, 0), try store.pendingIntents());
    try owner.restore(a);
    try std.testing.expectEqualDeep(rejected, processor.state.outcome.?.rejected);
    try std.testing.expect(processor.health.nextNotice(60_000) == null);
    try log.writeAll(third);
    processor.receipt = processor.now;
    try std.testing.expect(try source.poll(pipeline.Pipeline.acknowledge, &owner));
    try std.testing.expectEqualDeep(policy.Counters{ .eligible = 1, .obsolete = 1, .adjusted = 1, .future = 1 }, processor.health.snapshot());
    try std.testing.expectEqual(@as(i64, 1), try store.pendingIntents());
    const revision = owner.revision;
    try owner.restore(a);
    try std.testing.expect(!try source.poll(pipeline.Pipeline.acknowledge, &owner));
    try std.testing.expectEqual(revision, owner.revision);
    try std.testing.expectEqual(@as(i64, 1), try store.pendingIntents());
}

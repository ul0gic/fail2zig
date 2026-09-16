// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const admission = @import("core/source_time_policy.zig");
const text = @import("core/source_text.zig");
const records = @import("core/source_record.zig");
const files = @import("core/durable_file_source.zig");
const durable = @import("core/record_store.zig");
const pipeline = @import("core/record_pipeline.zig");

const Fixture = struct {
    health: admission.Health,
    staged: admission.Counters = .{},
    bytes: [64]u8 = undefined,
    scratch: [256]u8 = undefined,
    restoring: bool = false,

    fn adapter(self: *Fixture) pipeline.Processor {
        return .{ .context = self, .prepare = prepare, .prepare_restore = restore };
    }
    fn prepare(record: records.Record, context: ?*anyopaque) !pipeline.Prepared {
        const self: *Fixture = @ptrCast(@alignCast(context.?));
        self.restoring = false;
        self.staged = self.health.snapshot();
        var disposition: []const u8 = "source-checkpoint";
        var intent: ?[]const u8 = null;
        if (record.kind == .data) {
            const message = try text.decode(.utf8, record.message, &self.scratch, record.byte_start.?, .strip_stream_start);
            const delimiter = std.mem.indexOfScalar(u8, message, '|') orelse return error.InvalidFixture;
            const input = try admission.parseField(.epoch_seconds, message[0..delimiter], .{});
            const result = try admission.evaluate(.timestamped, input, .{ .us = 1_000_000_000 }, .{ .us = 1_000_000_000 }, 600_000_000);
            self.staged = try self.staged.advanced(result);
            disposition = result.disposition();
            if (result == .eligible and self.staged.eligible == 2) intent = "ordinary-fixture-two-eligible-records";
        }
        @memset(&self.bytes, 0);
        @memcpy(self.bytes[0..4], "TAF2");
        inline for (.{ "eligible", "obsolete", "missing", "malformed", "receipt", "adjusted", "future" }, 0..) |name, i|
            std.mem.writeInt(u64, self.bytes[8 + i * 8 ..][0..8], @field(self.staged, name), .little);
        return .{ .checkpoint = &self.bytes, .disposition = disposition, .intent = intent, .context = self, .publish = publish, .release = release };
    }
    fn restore(checkpoint: ?[]const u8, context: ?*anyopaque) !pipeline.Restored {
        const self: *Fixture = @ptrCast(@alignCast(context.?));
        self.staged = .{};
        self.restoring = true;
        if (checkpoint) |bytes| {
            if (bytes.len != 64 or !std.mem.eql(u8, bytes[0..8], "TAF2\x00\x00\x00\x00")) return error.InvalidFixtureCheckpoint;
            inline for (.{ "eligible", "obsolete", "missing", "malformed", "receipt", "adjusted", "future" }, 0..) |name, i|
                @field(self.staged, name) = std.mem.readInt(u64, bytes[8 + i * 8 ..][0..8], .little);
            try self.staged.validate();
        }
        return .{ .context = self, .publish = publish, .release = release };
    }
    fn publish(context: ?*anyopaque) void {
        const self: *Fixture = @ptrCast(@alignCast(context.?));
        if (self.restoring) {
            self.health = admission.Health.init(self.staged) catch unreachable;
        } else self.health.publish(self.staged);
    }
    fn release(_: ?*anyopaque) void {}
};

test "time admission: rejected file records commit once without blocking subsequent valid evidence" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "ordinary.log" });
    defer a.free(path);
    const database = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    defer a.free(database);
    const first = "700|ordinary eligible\n";
    const missing = "|ordinary missing timestamp\n";
    const malformed = "invalid|ordinary malformed timestamp\n";
    try temp.dir.writeFile(.{ .sub_path = "ordinary.log", .data = first ++ missing ++ malformed ++ "300|ordinary obsolete\n800|ordinary eligible\n" });
    var revision: u64 = 0;
    {
        var store = try durable.Store.open(a, database);
        defer store.close();
        var processor = Fixture{ .health = try admission.Health.init(.{}) };
        var owner = pipeline.Pipeline{ .store = &store, .jail = "fixture", .processor = processor.adapter() };
        try owner.restore(a);
        var source = try files.FileSource.init(a, path, "ordinary", .head, null);
        defer source.deinit();
        try source.setNativeFraming(.utf8, [_]u8{3} ** 32, 4096);
        try std.testing.expect(try source.poll(pipeline.Pipeline.acknowledge, &owner));
        revision = owner.revision;
        try std.testing.expectEqualDeep(admission.Counters{ .eligible = 1 }, processor.health.snapshot());
        store.fail_at = .before_commit;
        try std.testing.expectError(error.InjectedFailure, source.poll(pipeline.Pipeline.acknowledge, &owner));
        try std.testing.expectEqual(@as(u64, first.len), source.acknowledgedCheckpoint().?.offset);
        try std.testing.expectEqualDeep(admission.Counters{ .eligible = 1 }, processor.health.snapshot());
        try std.testing.expect(processor.health.nextNotice(0) == null);
        try std.testing.expectEqual(@as(i64, 0), try store.pendingIntents());
    }
    var store = try durable.Store.open(a, database);
    defer store.close();
    var processor = Fixture{ .health = try admission.Health.init(.{}) };
    var owner = pipeline.Pipeline{ .store = &store, .jail = "fixture", .processor = processor.adapter() };
    try owner.restore(a);
    try std.testing.expectEqual(revision, owner.revision);
    const cursor = (try store.sourceCursor(a, "fixture", "ordinary")).?;
    defer a.free(cursor);
    const parsed = try std.json.parseFromSlice(files.Resume, a, cursor, .{});
    defer parsed.deinit();
    var source = try files.FileSource.init(a, path, "ordinary", .head, parsed.value);
    defer source.deinit();
    try source.setNativeFraming(.utf8, [_]u8{3} ** 32, 4096);
    try std.testing.expect(try source.verifyContinuity());
    try std.testing.expect(try source.poll(pipeline.Pipeline.acknowledge, &owner));
    try std.testing.expectEqual(@as(u64, first.len + missing.len), source.acknowledgedCheckpoint().?.offset);
    try std.testing.expectEqual(revision + 1, owner.revision);
    try std.testing.expectEqual(@as(u64, 1), processor.health.nextNotice(0).?.missing_since_notice);
    try std.testing.expectEqual(@as(i64, 0), try store.pendingIntents());
    try std.testing.expect(try source.poll(pipeline.Pipeline.acknowledge, &owner));
    try std.testing.expectEqual(@as(u64, first.len + missing.len + malformed.len), source.acknowledgedCheckpoint().?.offset);
    try std.testing.expect(processor.health.nextNotice(59_999) == null);
    try std.testing.expectEqual(@as(i64, 0), try store.pendingIntents());
    try std.testing.expect(try source.poll(pipeline.Pipeline.acknowledge, &owner));
    try std.testing.expectEqual(@as(i64, 0), try store.pendingIntents());
    try std.testing.expect(try source.poll(pipeline.Pipeline.acknowledge, &owner));
    const expected = admission.Counters{ .eligible = 2, .obsolete = 1, .missing = 1, .malformed = 1 };
    try std.testing.expectEqualDeep(expected, processor.health.snapshot());
    try std.testing.expectEqual(@as(u64, 1), processor.health.nextNotice(60_000).?.malformed_since_notice);
    try std.testing.expectEqual(@as(i64, 1), try store.pendingIntents());
    revision = owner.revision;
    try owner.restore(a);
    try std.testing.expectEqualDeep(expected, processor.health.snapshot());
    try std.testing.expect(processor.health.nextNotice(120_000) == null);
    try std.testing.expect(!try source.poll(pipeline.Pipeline.acknowledge, &owner));
    try std.testing.expectEqual(revision, owner.revision);
    try std.testing.expectEqual(@as(i64, 1), try store.pendingIntents());
}

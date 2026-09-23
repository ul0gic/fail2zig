// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const times = @import("engine_test").core.event_time;
const files = @import("engine_test").core.durable_file_source;
const durable = @import("engine_test").core.record_store;
const records = @import("engine_test").core.source_record;
const pipeline = @import("engine_test").core.record_pipeline;

const Counts = struct { eligible: u64 = 0, obsolete: u64 = 0 };
const Timed = struct {
    now: f64,
    mode: times.Mode,
    committed: Counts = .{},
    staged: Counts = .{},
    bytes: [16]u8 = undefined,

    fn adapter(self: *Timed) pipeline.Processor {
        return .{ .context = self, .prepare = prepare, .prepare_restore = restore };
    }
    fn prepare(record: records.Record, context: ?*anyopaque) !pipeline.Prepared {
        const self: *Timed = @ptrCast(@alignCast(context.?));
        self.staged = self.committed;
        var disposition: []const u8 = "source-checkpoint";
        var event_time: ?f64 = null;
        var intent: ?[]const u8 = null;
        if (record.kind == .data) {
            const end = std.mem.indexOfScalar(u8, record.message, ' ') orelse return error.InvalidFixture;
            const timestamp = try times.EventTime.init(try std.fmt.parseFloat(f64, record.message[0..end]));
            var normalizer = times.Context{};
            const result = try normalizer.normalize(.{ .parsed = timestamp }, try times.EventTime.init(self.now), 600, self.mode, false);
            disposition = @tagName(result.disposition);
            event_time = result.effective.?.seconds;
            switch (result.disposition) {
                .accepted => {
                    self.staged.eligible = try std.math.add(u64, self.staged.eligible, 1);
                    if (self.staged.eligible == 1) intent = "original-fixture-threshold";
                },
                .obsolete => self.staged.obsolete = try std.math.add(u64, self.staged.obsolete, 1),
                .undated, .rejected => return error.UnexpectedFixtureDisposition,
            }
        }
        std.mem.writeInt(u64, self.bytes[0..8], self.staged.eligible, .little);
        std.mem.writeInt(u64, self.bytes[8..16], self.staged.obsolete, .little);
        return .{ .checkpoint = &self.bytes, .disposition = disposition, .event_time = event_time, .intent = intent, .context = self, .publish = publish, .release = release };
    }
    fn restore(checkpoint: ?[]const u8, context: ?*anyopaque) !pipeline.Restored {
        const self: *Timed = @ptrCast(@alignCast(context.?));
        self.staged = .{};
        if (checkpoint) |bytes| {
            if (bytes.len != 16) return error.InvalidFixtureCheckpoint;
            self.staged = .{ .eligible = std.mem.readInt(u64, bytes[0..8], .little), .obsolete = std.mem.readInt(u64, bytes[8..16], .little) };
        }
        return .{ .context = self, .publish = publish, .release = release };
    }
    fn publish(context: ?*anyopaque) void {
        const self: *Timed = @ptrCast(@alignCast(context.?));
        self.committed = self.staged;
    }
    fn release(_: ?*anyopaque) void {}
};

test "event age: file records aging out during failed commit stay obsolete after reopen and replay" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    try temp.dir.writeFile(.{ .sub_path = "events.log", .data = "300 ordinary old\n500 ordinary retry\n700 ordinary recent\n" });
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "events.log" });
    defer a.free(path);
    const database = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    defer a.free(database);
    var source = try files.FileSource.init(a, path, "fixture-file", .head, null);
    defer source.deinit();
    var initial = Timed{ .now = 1000, .mode = .live };
    var offset: u64 = 0;
    var revision: u64 = 0;
    {
        var store = try durable.Store.open(a, database);
        defer store.close();
        var owner = pipeline.Pipeline{ .store = &store, .jail = "fixture", .processor = initial.adapter() };
        try owner.restore(a);
        try std.testing.expect(try source.poll(pipeline.Pipeline.acknowledge, &owner));
        try std.testing.expectEqualDeep(Counts{ .obsolete = 1 }, initial.committed);
        try std.testing.expectEqual(@as(i64, 0), try store.pendingIntents());
        offset = source.acknowledgedCheckpoint().?.offset;
        revision = owner.revision;
        store.fail_at = .before_commit;
        try std.testing.expectError(error.InjectedFailure, source.poll(pipeline.Pipeline.acknowledge, &owner));
        try std.testing.expectEqualDeep(Counts{ .obsolete = 1 }, initial.committed);
        try std.testing.expectEqual(offset, source.acknowledgedCheckpoint().?.offset);
        try std.testing.expectEqual(revision, owner.revision);
        try std.testing.expectEqual(@as(i64, 0), try store.pendingIntents());
    }

    var store = try durable.Store.open(a, database);
    defer store.close();
    var resumed = Timed{ .now = 1200, .mode = .replay };
    var owner = pipeline.Pipeline{ .store = &store, .jail = "fixture", .processor = resumed.adapter() };
    try owner.restore(a);
    const raw = (try store.sourceCursor(a, "fixture", "fixture-file")).?;
    defer a.free(raw);
    const parsed = try std.json.parseFromSlice(files.Resume, a, raw, .{});
    defer parsed.deinit();
    var reopened = try files.FileSource.init(a, path, "fixture-file", .head, parsed.value);
    defer reopened.deinit();
    try std.testing.expect(try reopened.verifyContinuity());
    try std.testing.expectEqual(offset, reopened.acknowledgedCheckpoint().?.offset);
    try std.testing.expect(try reopened.poll(pipeline.Pipeline.acknowledge, &owner));
    try std.testing.expectEqualDeep(Counts{ .obsolete = 2 }, resumed.committed);
    try std.testing.expect(reopened.acknowledgedCheckpoint().?.offset > offset);
    try std.testing.expectEqual(revision + 1, owner.revision);
    try std.testing.expectEqual(@as(i64, 0), try store.pendingIntents());
    try std.testing.expect(try reopened.poll(pipeline.Pipeline.acknowledge, &owner));
    try std.testing.expectEqualDeep(Counts{ .eligible = 1, .obsolete = 2 }, resumed.committed);
    try std.testing.expectEqual(@as(i64, 1), try store.pendingIntents());
    try std.testing.expect(!try reopened.poll(pipeline.Pipeline.acknowledge, &owner));
    revision = owner.revision;
    try owner.restore(a);
    try std.testing.expect(!try reopened.poll(pipeline.Pipeline.acknowledge, &owner));
    try std.testing.expectEqual(revision, owner.revision);
    try std.testing.expectEqualDeep(Counts{ .eligible = 1, .obsolete = 2 }, resumed.committed);
    try std.testing.expectEqual(@as(i64, 1), try store.pendingIntents());
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const records = @import("source_record.zig");
const durable = @import("record_store.zig");

/// prepare must leave live state unchanged. Its payload owns all resources
/// needed by publish; publish cannot allocate or fail after the durable commit.
pub const Prepared = struct {
    checkpoint: []const u8,
    disposition: []const u8,
    event_time: ?f64 = null,
    intent: ?[]const u8 = null,
    shared_state: ?durable.SharedState = null,
    context: ?*anyopaque,
    publish: *const fn (?*anyopaque) void,
    release: *const fn (?*anyopaque) void,
};
pub const Processor = struct {
    context: ?*anyopaque,
    prepare: *const fn (records.Record, ?*anyopaque) anyerror!Prepared,
    /// Install the authoritative committed snapshot before reading sources.
    restore: *const fn (?[]const u8, ?*anyopaque) anyerror!void,
};
pub const Pipeline = struct {
    store: *durable.Store,
    jail: []const u8,
    processor: Processor,
    ready: bool = false,
    revision: u64 = 0,

    pub fn restore(self: *Pipeline, allocator: std.mem.Allocator) !void {
        self.ready = false;
        const checkpoint = try self.store.snapshot(allocator, self.jail);
        defer checkpoint.deinit(allocator);
        try self.processor.restore(checkpoint.payload, self.processor.context);
        self.revision = checkpoint.revision;
        self.ready = true;
    }

    pub fn acknowledge(record: records.Record, context: ?*anyopaque) !void {
        const self: *Pipeline = @ptrCast(@alignCast(context orelse return error.MissingPipeline));
        if (!self.ready) return error.RestoreRequired;
        if (try self.store.hasRecord(self.jail, record.source, record.occurrence, record.raw_hash, record.cursor)) {
            if (try self.store.revision(self.jail) != self.revision) {
                self.ready = false;
                return error.RestoreRequired;
            }
            return;
        }
        const prepared = try self.processor.prepare(record, self.processor.context);
        defer prepared.release(prepared.context);
        const result = self.store.commitRecord(.{
            .jail = self.jail,
            .source = record.source,
            .source_path = record.source_path,
            .occurrence = record.occurrence,
            .cursor = record.cursor,
            .raw_hash = record.raw_hash,
            .event_time = prepared.event_time,
            .timestamp_us = record.timestamp_us,
            .expected_revision = self.revision,
            .disposition = prepared.disposition,
            .checkpoint = prepared.checkpoint,
            .action_intent = prepared.intent,
            .shared_state = prepared.shared_state,
        }) catch |err| {
            if (err == error.StaleCheckpoint or err == error.StaleSharedCheckpoint) self.ready = false;
            return err;
        };
        // A single owner processes each jail. Another writer appearing between
        // lookup and commit invalidates this owner's in-memory snapshot.
        if (result == .already_committed) {
            self.ready = false;
            return error.ConcurrentWriter;
        }
        self.revision += 1;
        prepared.publish(prepared.context);
    }
};

const TestProcessor = struct {
    count: u64 = 0,
    staged: u64 = 0,
    shared_state: ?durable.SharedState = null,
    bytes: [8]u8 = undefined,
    fn prepare(record: records.Record, context: ?*anyopaque) !Prepared {
        const self: *TestProcessor = @ptrCast(@alignCast(context.?));
        self.staged = self.count + @intFromBool(record.kind == .data);
        std.mem.writeInt(u64, &self.bytes, self.staged, .little);
        return .{ .checkpoint = &self.bytes, .shared_state = self.shared_state, .disposition = "test-counted", .intent = if (self.staged == 2) "test-threshold" else null, .context = self, .publish = publish, .release = release };
    }
    fn publish(context: ?*anyopaque) void {
        const self: *TestProcessor = @ptrCast(@alignCast(context.?));
        self.count = self.staged;
    }
    fn release(_: ?*anyopaque) void {}
    fn restore(checkpoint: ?[]const u8, context: ?*anyopaque) !void {
        const self: *TestProcessor = @ptrCast(@alignCast(context.?));
        if (checkpoint) |payload| {
            if (payload.len != 8) return error.InvalidCheckpoint;
            self.count = std.mem.readInt(u64, payload[0..8], .little);
        } else self.count = 0;
    }
    fn adapter(self: *TestProcessor) Processor {
        return .{ .context = self, .prepare = prepare, .restore = restore };
    }
};

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

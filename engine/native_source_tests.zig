// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Native decoding/time qualification through actual file and SQLite adapters.
//! The tiny counting checkpoint below is a fixture, not the native jail schema.
const std = @import("std");
const text = @import("core/source_text.zig");
const time = @import("core/native_time.zig");
const files = @import("core/durable_file_source.zig");
const records = @import("core/source_record.zig");
const durable = @import("core/record_store.zig");
const pipeline = @import("core/record_pipeline.zig");

const State = struct { count: u64 = 0, last: ?time.Timestamp = null };
const Fixture = struct {
    committed: State = .{},
    staged: State = .{},
    checkpoint: [24]u8 = undefined,
    scratch: [256]u8 = undefined,

    fn adapter(self: *Fixture) pipeline.Processor {
        return .{ .context = self, .prepare = prepare, .prepare_restore = restore };
    }

    fn prepare(record: records.Record, context: ?*anyopaque) !pipeline.Prepared {
        const self: *Fixture = @ptrCast(@alignCast(context.?));
        self.staged = self.committed;
        var disposition: []const u8 = "source-checkpoint";
        if (record.kind == .data) {
            const message = try text.decode(.utf16le, record.message, &self.scratch, record.byte_start.?, .strip_stream_start);
            const end = std.mem.indexOfScalar(u8, message, ' ') orelse return error.InvalidFixture;
            const timestamp = try time.parse(.epoch_seconds, message[0..end], .{});
            if (try time.age(timestamp, .{ .us = 9007199254741093 }, 1000) != .eligible) return error.UnexpectedFixtureTime;
            if (self.staged.count == 0) {
                try std.testing.expectEqualStrings(" ordinary Ω", message[end..]);
            } else {
                try std.testing.expectEqualStrings(" ordinary café", message[end..]);
            }
            self.staged.count += 1;
            self.staged.last = timestamp;
            disposition = "fixture-eligible";
        }
        @memset(&self.checkpoint, 0);
        @memcpy(self.checkpoint[0..4], "NTF1");
        std.mem.writeInt(u64, self.checkpoint[8..16], self.staged.count, .little);
        if (self.staged.last) |last| {
            self.checkpoint[4] = 1;
            @memcpy(self.checkpoint[16..24], &last.encode());
        }
        return .{ .checkpoint = &self.checkpoint, .disposition = disposition, .context = self, .publish = publish, .release = release };
    }

    fn restore(checkpoint: ?[]const u8, context: ?*anyopaque) !pipeline.Restored {
        const self: *Fixture = @ptrCast(@alignCast(context.?));
        self.staged = .{};
        if (checkpoint) |bytes| {
            if (bytes.len != 24 or !std.mem.eql(u8, bytes[0..4], "NTF1") or bytes[4] > 1) return error.InvalidFixtureCheckpoint;
            self.staged.count = std.mem.readInt(u64, bytes[8..16], .little);
            if (bytes[4] == 1) self.staged.last = time.Timestamp.decode(bytes[16..24]);
        }
        return .{ .context = self, .publish = publish, .release = release };
    }

    fn publish(context: ?*anyopaque) void {
        const self: *Fixture = @ptrCast(@alignCast(context.?));
        self.committed = self.staged;
    }
    fn release(_: ?*anyopaque) void {}
};

fn asciiUtf16(file: std.fs.File, input: []const u8) !void {
    for (input) |byte| try file.writeAll(&.{ byte, 0 });
}

test "native source: UTF16 exact timestamps rollback reopen and invalid input retain cursor" {
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
    try log.writeAll("\xff\xfe");
    try asciiUtf16(log, "9007199254.740993 ordinary ");
    try log.writeAll("\xa9\x03\r\x00\n\x00");
    const first_end = try log.getPos();
    try asciiUtf16(log, "9007199254.741000 ordinary caf");
    try log.writeAll("\xe9\x00\n\x00");
    const second_end = try log.getPos();
    // Invalid Unicode is followed by a valid record boundary. It must not be
    // converted to replacement characters and passed to the counting fixture.
    try asciiUtf16(log, "9007199254.741001 ordinary ");
    try log.writeAll("\x00\xdc\n\x00");
    var revision: u64 = 0;
    {
        var store = try durable.Store.open(a, database);
        defer store.close();
        var processor = Fixture{};
        var owner = pipeline.Pipeline{ .store = &store, .jail = "fixture", .processor = processor.adapter() };
        try owner.restore(a);
        var source = try files.FileSource.init(a, path, "ordinary", .head, null);
        defer source.deinit();
        try source.setNativeFraming(.utf16le, [_]u8{42} ** 32, 4096);
        try std.testing.expect(try source.poll(pipeline.Pipeline.acknowledge, &owner));
        try std.testing.expectEqual(first_end, source.acknowledgedCheckpoint().?.offset);
        try std.testing.expectEqual(@as(i64, 9007199254740993), processor.committed.last.?.us);
        revision = owner.revision;
        store.fail_at = .before_commit;
        try std.testing.expectError(error.InjectedFailure, source.poll(pipeline.Pipeline.acknowledge, &owner));
        try std.testing.expectEqual(first_end, source.acknowledgedCheckpoint().?.offset);
        try std.testing.expectEqual(revision, owner.revision);
        try std.testing.expectEqual(@as(u64, 1), processor.committed.count);
        try std.testing.expectEqual(@as(i64, 9007199254740993), processor.committed.last.?.us);
    }
    var store = try durable.Store.open(a, database);
    defer store.close();
    var processor = Fixture{};
    var owner = pipeline.Pipeline{ .store = &store, .jail = "fixture", .processor = processor.adapter() };
    try owner.restore(a);
    try std.testing.expectEqual(@as(i64, 9007199254740993), processor.committed.last.?.us);
    const raw_cursor = (try store.sourceCursor(a, "fixture", "ordinary")).?;
    defer a.free(raw_cursor);
    const parsed = try std.json.parseFromSlice(files.Resume, a, raw_cursor, .{});
    defer parsed.deinit();
    var source = try files.FileSource.init(a, path, "ordinary", .head, parsed.value);
    defer source.deinit();
    try std.testing.expectError(error.FramingProfileMismatch, source.verifyContinuity());
    try std.testing.expectError(error.FramingProfileMismatch, source.setNativeFraming(.utf16be, [_]u8{42} ** 32, 4096));
    try std.testing.expectError(error.FramingProfileMismatch, source.setNativeFraming(.utf16le, [_]u8{43} ** 32, 4096));
    try std.testing.expectError(error.FramingProfileMismatch, source.setNativeFraming(.utf16le, [_]u8{42} ** 32, 2048));
    try std.testing.expectEqualDeep(parsed.value, source.acknowledgedCheckpoint().?);
    try source.setNativeFraming(.utf16le, [_]u8{42} ** 32, 4096);
    try std.testing.expect(try source.verifyContinuity());
    try std.testing.expect(try source.poll(pipeline.Pipeline.acknowledge, &owner));
    try std.testing.expectEqual(second_end, source.acknowledgedCheckpoint().?.offset);
    try std.testing.expectEqual(revision + 1, owner.revision);
    try std.testing.expectEqual(@as(u64, 2), processor.committed.count);
    try std.testing.expectEqual(@as(i64, 9007199254741000), processor.committed.last.?.us);
    for (0..2) |_| {
        try std.testing.expectError(error.InvalidEncoding, source.poll(pipeline.Pipeline.acknowledge, &owner));
        try std.testing.expectEqual(second_end, source.acknowledgedCheckpoint().?.offset);
        try std.testing.expectEqual(revision + 1, owner.revision);
        try std.testing.expectEqual(@as(u64, 2), processor.committed.count);
    }
    try std.testing.expectEqual(@as(i64, 0), try store.pendingIntents());
}

test "native source: partial code units CRLF and callback failure preserve raw boundaries" {
    const Sink = struct {
        fail: bool = true,
        delivered: usize = 0,
        fn receive(record: records.Record, context: ?*anyopaque) !void {
            if (record.kind == .checkpoint) return;
            const self: *@This() = @ptrCast(@alignCast(context.?));
            var scratch: [32]u8 = undefined;
            const decoded = try text.decode(.utf16le, record.message, &scratch, record.byte_start.?, .preserve);
            try std.testing.expectEqualStrings("Ċ\r", decoded);
            try std.testing.expectEqual(@as(u64, 0), record.byte_start.?);
            try std.testing.expectEqual(@as(u64, 8), record.byte_end.?);
            var expected: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash("\x0a\x01\r\x00\r\x00\n\x00", &expected, .{});
            try std.testing.expectEqualSlices(u8, &expected, &record.raw_hash);
            if (self.fail) return error.FixtureCommitFailure;
            self.delivered += 1;
        }
    };
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "split.log" });
    defer a.free(path);
    const log = try temp.dir.createFile("split.log", .{});
    defer log.close();
    try log.writeAll("\x0a\x01\r\x00\r");
    var source = try files.FileSource.init(a, path, "split", .head, null);
    defer source.deinit();
    try source.setNativeFraming(.utf16le, [_]u8{1} ** 32, 64);
    var sink = Sink{};
    try std.testing.expect(!try source.poll(Sink.receive, &sink));
    try std.testing.expectEqual(@as(u64, 0), source.acknowledgedCheckpoint().?.offset);
    try log.writeAll("\x00\n");
    try std.testing.expect(!try source.poll(Sink.receive, &sink));
    try std.testing.expectEqual(@as(u64, 0), source.acknowledgedCheckpoint().?.offset);
    // A new tail reader must not commit an offset inside a UTF-16 code unit.
    var tail = try files.FileSource.init(a, path, "tail", .tail, null);
    defer tail.deinit();
    try tail.setNativeFraming(.utf16le, [_]u8{1} ** 32, 64);
    try std.testing.expectError(error.MisalignedOffset, tail.poll(Sink.receive, &sink));
    try std.testing.expect(tail.acknowledgedCheckpoint() == null);
    try std.testing.expectEqual(.malformed_record, tail.health);
    try log.writeAll("\x00");
    try std.testing.expectError(error.FixtureCommitFailure, source.poll(Sink.receive, &sink));
    try std.testing.expectEqual(@as(u64, 0), source.acknowledgedCheckpoint().?.offset);
    sink.fail = false;
    try std.testing.expect(try source.poll(Sink.receive, &sink));
    try std.testing.expectEqual(@as(u64, 8), source.acknowledgedCheckpoint().?.offset);
    try std.testing.expect(!try source.poll(Sink.receive, &sink));
    try std.testing.expectEqual(@as(usize, 1), sink.delivered);
}

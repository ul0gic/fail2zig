// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const files = @import("engine_test").core.durable_file_source;
const records = @import("engine_test").core.source_record;
const a = std.testing.allocator;
const Sink = struct {
    records_seen: usize = 0,
    checkpoints: usize = 0,
    last: ?[]u8 = null,
    fail: bool = false,
    fn deinit(self: *Sink) void {
        if (self.last) |line| a.free(line);
    }
    fn ack(record: records.Record, context: ?*anyopaque) !void {
        const self: *Sink = @ptrCast(@alignCast(context.?));
        if (self.fail) return error.OriginalCommitFailure;
        if (record.kind == .checkpoint) {
            self.checkpoints += 1;
            return;
        }
        const next = try a.dupe(u8, record.message);
        if (self.last) |line| a.free(line);
        self.last = next;
        self.records_seen += 1;
    }
};

test "source health: real file permission denial then exact recovery" {
    if (std.os.linux.geteuid() == 0) return error.SkipZigTest;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "delayed.log" });
    defer a.free(path);
    var source = try files.FileSource.init(a, path, "original-delayed", .head, null);
    defer source.deinit();
    var sink = Sink{};
    defer sink.deinit();
    try std.testing.expect(!try source.poll(Sink.ack, &sink));
    try std.testing.expectEqual(records.Health.missing, source.health);
    var file = try temp.dir.createFile("delayed.log", .{ .read = true });
    defer file.close();
    try file.writeAll("ordinary-one\n");
    try file.chmod(0);
    defer file.chmod(0o600) catch {};
    try std.testing.expectError(error.AccessDenied, source.poll(Sink.ack, &sink));
    try std.testing.expectEqual(records.Health.permission_denied, source.health);
    try std.testing.expectEqual(@as(usize, 0), sink.checkpoints);
    try std.testing.expect(source.acknowledgedCheckpoint() == null);
    try file.chmod(0o600);
    sink.fail = true;
    try std.testing.expectError(error.OriginalCommitFailure, source.poll(Sink.ack, &sink));
    try std.testing.expectEqual(records.Health.commit_failed, source.health);
    try std.testing.expect(source.acknowledgedCheckpoint() == null);
    sink.fail = false;
    try std.testing.expect(try source.poll(Sink.ack, &sink));
    try std.testing.expectEqualStrings("ordinary-one", sink.last.?);
    try std.testing.expectEqual(@as(usize, 1), sink.records_seen);
    try std.testing.expectEqual(records.Health.healthy, source.health);
    try std.testing.expectEqual(@as(u64, 13), source.acknowledgedCheckpoint().?.offset);
}

test "source health: denied directory and delayed glob partial writes recover" {
    if (std.os.linux.geteuid() == 0) return error.SkipZigTest;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    try temp.dir.makeDir("inputs");
    var inputs = try temp.dir.openDir("inputs", .{ .iterate = true });
    defer inputs.close();
    const root = try inputs.realpathAlloc(a, ".");
    defer a.free(root);
    const pattern = try std.fs.path.join(a, &.{ root, "*.log" });
    defer a.free(pattern);
    var set = try files.FileSet.init(a, "original-glob");
    defer set.deinit();
    try set.add(pattern, .head);
    var sink = Sink{};
    defer sink.deinit();
    try std.testing.expectEqual(@as(usize, 0), try set.poll(Sink.ack, &sink));
    try std.testing.expectEqual(records.Health.missing, set.health);
    try inputs.chmod(0);
    defer inputs.chmod(0o700) catch {};
    try std.testing.expectError(error.AccessDenied, set.poll(Sink.ack, &sink));
    try std.testing.expectEqual(records.Health.permission_denied, set.health);
    try inputs.chmod(0o700);
    var file = try inputs.createFile("late.log", .{ .read = true });
    defer file.close();
    try file.writeAll("ordinary-");
    try std.testing.expectEqual(@as(usize, 0), try set.poll(Sink.ack, &sink));
    try std.testing.expectEqual(@as(usize, 0), sink.records_seen);
    try std.testing.expectEqual(@as(u64, 0), set.sources.items[0].acknowledgedCheckpoint().?.offset);
    try file.writeAll("two\n");
    try std.testing.expectEqual(@as(usize, 1), try set.poll(Sink.ack, &sink));
    try std.testing.expectEqualStrings("ordinary-two", sink.last.?);
    try std.testing.expectEqual(records.Health.healthy, set.health);
    try std.testing.expectEqual(@as(usize, 0), try set.poll(Sink.ack, &sink));
}

test "source health: retained rotation at source capacity stops visibly" {
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const pattern = try std.fs.path.join(a, &.{ root, "*.log" });
    defer a.free(pattern);
    try temp.dir.writeFile(.{ .sub_path = "input.log", .data = "first\n" });
    var set = try files.FileSet.init(a, "original-limit");
    defer set.deinit();
    set.max_sources = 1;
    try set.add(pattern, .head);
    var sink = Sink{};
    defer sink.deinit();
    try std.testing.expectEqual(@as(usize, 1), try set.poll(Sink.ack, &sink));
    try temp.dir.rename("input.log", "retained.saved");
    try temp.dir.writeFile(.{ .sub_path = "input.log", .data = "second\n" });
    try std.testing.expectError(error.SourceLimit, set.poll(Sink.ack, &sink));
    try std.testing.expectEqual(records.Health.read_failed, set.health);
    try std.testing.expectEqual(@as(usize, 1), sink.records_seen);
    set.max_sources = 2;
    try std.testing.expectEqual(@as(usize, 1), try set.poll(Sink.ack, &sink));
    try std.testing.expectEqualStrings("second", sink.last.?);
    try std.testing.expectEqual(@as(usize, 2), sink.records_seen);
}

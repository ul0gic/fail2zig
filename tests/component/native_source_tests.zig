// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const text = @import("engine_test").core.source_text;
const time = @import("engine_test").core.native_time;
const files = @import("engine_test").core.durable_file_source;
const records = @import("engine_test").core.source_record;
const durable = @import("engine_test").core.record_store;
const pipeline = @import("engine_test").core.record_pipeline;

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

const sessions = @import("engine_test").core.native_file_session;
const repair = @import("engine_test").core.source_repair;

const SessionFixture = struct {
    tmp: std.testing.TmpDir,
    root: []u8,
    path: []u8,
    database: []u8,
    store: durable.Store,
    us: i64 = 1_000_000_000,
    ms: u64 = 0,

    fn init(self: *SessionFixture) !void {
        const a = std.testing.allocator;
        self.tmp = std.testing.tmpDir(.{});
        errdefer self.tmp.cleanup();
        self.root = try self.tmp.dir.realpathAlloc(a, ".");
        errdefer a.free(self.root);
        self.path = try std.fs.path.join(a, &.{ self.root, "active.log" });
        errdefer a.free(self.path);
        self.database = try std.fs.path.join(a, &.{ self.root, "state.sqlite" });
        errdefer a.free(self.database);
        self.store = try durable.Store.open(a, self.database);
        errdefer self.store.close();
        try self.store.enableReceipts(8);
        try self.store.enableNativeTime();
        try self.store.enableDetection();
        try self.store.enableClockRecovery();
        self.us = 1_000_000_000;
        self.ms = 0;
    }
    fn deinit(self: *SessionFixture) void {
        const a = std.testing.allocator;
        self.store.close();
        a.free(self.database);
        a.free(self.path);
        a.free(self.root);
        self.tmp.cleanup();
    }
    fn wall(context: ?*anyopaque) !time.Timestamp {
        const self: *SessionFixture = @ptrCast(@alignCast(context.?));
        return .{ .us = self.us };
    }
    fn mono(context: ?*anyopaque) u64 {
        const self: *SessionFixture = @ptrCast(@alignCast(context.?));
        return self.ms;
    }
    fn open(self: *SessionFixture) !*sessions.Session {
        const options = sessions.Options{ .processing = .{ .jail = "fixture", .parent_generation = [_]u8{1} ** 32, .timestamp = .undated }, .max_sources = 8, .clock = wall, .clock_context = self, .monotonic_clock = .{ .context = self, .read = mono } };
        return sessions.Session.createDeferred(std.testing.allocator, &self.store, options, &.{.{ .pattern = self.path }});
    }
};

fn admitSession(session: *sessions.Session) !void {
    for (0..4096) |_| if (try session.admissionTurn()) return;
    return error.AdmissionDidNotComplete;
}

fn deliverSession(session: *sessions.Session) !usize {
    for (0..64) |_| {
        const count = try session.pollTurn(1);
        if (count > 0) return count;
    }
    return 0;
}

const ContinuityChange = enum { truncate, shrink_prefix, prefix, remove, replace, rotate };

fn expectRestartContinuity(change: ContinuityChange, expected: ?files.Discontinuity) !void {
    var f: SessionFixture = undefined;
    try f.init();
    defer f.deinit();
    // The shrink case keeps an unread line so the recorded prefix extends past the offset.
    const shrink = change == .shrink_prefix;
    const initial = if (shrink) "first\nsecond line, unread here\n" else "first event\nsecond event\n";
    const committed_offset: u64 = if (shrink) 6 else 25;
    try f.tmp.dir.writeFile(.{ .sub_path = "active.log", .data = initial });
    var checkpoint: files.Resume = undefined;
    var source_id: [256]u8 = undefined;
    var source_id_len: usize = 0;
    {
        const first = try f.open();
        defer first.destroy();
        try admitSession(first);
        try std.testing.expectEqual(@as(usize, 1), try deliverSession(first));
        if (!shrink) try std.testing.expectEqual(@as(usize, 1), try deliverSession(first));
        const source = &first.sources.sources.items[0];
        checkpoint = source.acknowledgedCheckpoint().?;
        try std.testing.expectEqual(committed_offset, checkpoint.offset);
        if (shrink) try std.testing.expectEqual(@as(u8, 31), checkpoint.prefix_len);
        @memcpy(source_id[0..source.source_id.len], source.source_id);
        source_id_len = source.source_id.len;
    }
    var observed_inode: ?u64 = null;
    var observed_size: ?u64 = null;
    switch (change) {
        .truncate => {
            const file = try f.tmp.dir.openFile("active.log", .{ .mode = .write_only });
            defer file.close();
            try file.setEndPos(4);
            observed_inode = checkpoint.inode;
            observed_size = 4;
        },
        .shrink_prefix => {
            const file = try f.tmp.dir.openFile("active.log", .{ .mode = .write_only });
            defer file.close();
            try file.setEndPos(20);
            observed_inode = checkpoint.inode;
            observed_size = 20;
        },
        .prefix => {
            const file = try f.tmp.dir.openFile("active.log", .{ .mode = .write_only });
            defer file.close();
            try file.pwriteAll("FIRST", 0);
            try file.seekFromEnd(0);
            try file.writeAll("third event\n");
            observed_inode = checkpoint.inode;
            observed_size = 37;
        },
        .remove => try f.tmp.dir.deleteFile("active.log"),
        .replace => {
            try f.tmp.dir.writeFile(.{ .sub_path = "active.log.new", .data = "replacement\n" });
            observed_inode = (try f.tmp.dir.statFile("active.log.new")).inode;
            try f.tmp.dir.rename("active.log.new", "active.log");
            observed_size = 12;
        },
        .rotate => {
            try f.tmp.dir.rename("active.log", "active.log.1");
            try f.tmp.dir.writeFile(.{ .sub_path = "active.log", .data = "replacement\n" });
            const old = try f.tmp.dir.openFile("active.log.1", .{ .mode = .write_only });
            defer old.close();
            try old.seekFromEnd(0);
            try old.writeAll("late\n");
        },
    }
    const restarted = try f.open();
    defer restarted.destroy();
    const kind = expected orelse {
        try admitSession(restarted);
        try std.testing.expect(restarted.continuityFailure() == null);
        try std.testing.expectEqual(@as(usize, 1), try deliverSession(restarted));
        try std.testing.expectEqual(repair.Phase.healthy, restarted.repairSnapshot().phase);
        return;
    };
    try std.testing.expectError(error.SourceInterventionRequired, admitSession(restarted));
    try std.testing.expectError(error.SourceInterventionRequired, admitSession(restarted));
    try std.testing.expectEqual(repair.Phase.intervention, restarted.repairSnapshot().phase);
    try std.testing.expectEqual(@as(?anyerror, error.ResumeLost), restarted.repairSnapshot().last_cause);
    try std.testing.expectEqual(records.Health.resume_lost, restarted.sources.sources.items[0].health);
    try std.testing.expectEqualDeep(checkpoint, restarted.sources.sources.items[0].acknowledgedCheckpoint().?);
    const report = restarted.continuityFailure() orelse return error.MissingContinuityReport;
    try std.testing.expectEqualStrings("fixture", report.jail);
    try std.testing.expectEqualStrings(f.path, report.path);
    try std.testing.expectEqualStrings(source_id[0..source_id_len], report.source);
    const failure = report.failure;
    try std.testing.expectEqual(kind, failure.kind);
    try std.testing.expectEqualSlices(u8, &checkpoint.incarnation, &failure.incarnation);
    try std.testing.expectEqual(checkpoint.offset, failure.committed_offset);
    try std.testing.expectEqual(checkpoint.device, failure.committed_device);
    try std.testing.expectEqual(checkpoint.inode, failure.committed_inode);
    try std.testing.expectEqual(observed_size, failure.observed_size);
    try std.testing.expectEqual(observed_inode, failure.observed_inode);
    try std.testing.expectEqual(if (observed_inode == null) null else @as(?u64, checkpoint.device), failure.observed_device);
    var rendered: [512]u8 = undefined;
    const text_out = try std.fmt.bufPrint(&rendered, "{}", .{failure});
    try std.testing.expect(std.mem.indexOf(u8, text_out, @tagName(kind)) != null);
    var offset_text: [32]u8 = undefined;
    try std.testing.expect(std.mem.indexOf(u8, text_out, try std.fmt.bufPrint(&offset_text, "committed_offset={d} ", .{committed_offset})) != null);
    for ([_][]const u8{ "first", "FIRST", "second", "unread", "replacement", "event" }) |content|
        try std.testing.expect(std.mem.indexOf(u8, text_out, content) == null);
}

test "native source: restart classifies truncate, prefix change, missing and replaced files; rename rotation resumes" {
    try expectRestartContinuity(.truncate, .truncated);
    try expectRestartContinuity(.shrink_prefix, .truncated);
    try expectRestartContinuity(.prefix, .prefix_changed);
    try expectRestartContinuity(.remove, .missing);
    try expectRestartContinuity(.replace, .replaced);
    try expectRestartContinuity(.rotate, null);
}

test "native source: runtime truncation under a pending receipt pauses with facts and no reset" {
    var f: SessionFixture = undefined;
    try f.init();
    defer f.deinit();
    try f.tmp.dir.writeFile(.{ .sub_path = "active.log", .data = "first\n" });
    const session = try f.open();
    var session_live = true;
    defer if (session_live) session.destroy();
    try admitSession(session);
    _ = try deliverSession(session);
    {
        const file = try f.tmp.dir.openFile("active.log", .{ .mode = .write_only });
        defer file.close();
        try file.seekFromEnd(0);
        try file.writeAll("pending\n");
    }
    f.store.fail_at = .after_receipt_delete;
    try std.testing.expectError(error.InjectedFailure, deliverSession(session));
    f.store.fail_at = null;
    const saved = session.sources.sources.items[0].acknowledgedCheckpoint().?;
    try f.tmp.dir.writeFile(.{ .sub_path = "active.log", .data = "x\n" });
    try std.testing.expectError(error.SourceInterventionRequired, deliverSession(session));
    try std.testing.expectError(error.SourceInterventionRequired, deliverSession(session));
    try std.testing.expectEqualDeep(saved, session.sources.sources.items[0].acknowledgedCheckpoint().?);
    try std.testing.expectEqual(@as(usize, 1), try f.store.pendingReceiptCount());
    const report = session.continuityFailure() orelse return error.MissingContinuityReport;
    try std.testing.expectEqual(files.Discontinuity.truncated, report.failure.kind);
    try std.testing.expectEqual(saved.offset, report.failure.committed_offset);
    try std.testing.expectEqual(@as(?u64, 2), report.failure.observed_size);
    try std.testing.expectEqual(@as(?u64, saved.inode), report.failure.observed_inode);
    const once = session.nextUnreportedContinuityFailure() orelse return error.MissingContinuityReport;
    try std.testing.expectEqualDeep(report.failure, once.failure);
    try std.testing.expect(session.nextUnreportedContinuityFailure() == null);
    try f.tmp.dir.writeFile(.{ .sub_path = "active.log", .data = "different and longer content\n" });
    try std.testing.expectError(error.ResumeLost, session.verifyRecoverySources());
    try std.testing.expectEqualDeep(report.failure, session.continuityFailure().?.failure);
    try std.testing.expect(session.nextUnreportedContinuityFailure() == null);

    const replacement = try f.open();
    defer replacement.destroy();
    try replacement.copyRepairStateFrom(session);
    try replacement.retainSourcesFrom(session);
    session.destroy();
    session_live = false;
    try std.testing.expectEqual(repair.Phase.intervention, replacement.repairSnapshot().phase);
    const retained = replacement.continuityFailure() orelse return error.MissingContinuityReport;
    try std.testing.expectEqualDeep(report.failure, retained.failure);
    try std.testing.expectEqualStrings(f.path, retained.path);
    try std.testing.expect(replacement.nextUnreportedContinuityFailure() == null);
}

fn lostPrefix(_: std.fs.File, _: u8) ![32]u8 {
    return error.ResumeLost;
}

fn pollUntilIntervention(session: *sessions.Session, index: usize) !void {
    for (0..64) |_| {
        _ = session.pollTurn(1) catch |err| switch (err) {
            error.SourceInterventionRequired, error.SourceRepairPending => {},
            else => return err,
        };
        if ((try session.sourceRepairSnapshot(index)).phase == .intervention) return;
    }
    return error.InterventionNotReached;
}

test "native source: each source discontinuity in a jail is reported exactly once" {
    var f: SessionFixture = undefined;
    try f.init();
    defer f.deinit();
    try f.tmp.dir.writeFile(.{ .sub_path = "a.log", .data = "first owner\n" });
    try f.tmp.dir.writeFile(.{ .sub_path = "b.log", .data = "second owner\n" });
    const pattern = try std.fs.path.join(std.testing.allocator, &.{ f.root, "*.log" });
    defer std.testing.allocator.free(pattern);
    const options = sessions.Options{ .processing = .{ .jail = "fixture", .parent_generation = [_]u8{1} ** 32, .timestamp = .undated }, .max_sources = 8, .clock = SessionFixture.wall, .clock_context = &f, .monotonic_clock = .{ .context = &f, .read = SessionFixture.mono } };
    const session = try sessions.Session.createDeferred(std.testing.allocator, &f.store, options, &.{.{ .pattern = pattern }});
    var session_live = true;
    defer if (session_live) session.destroy();
    try admitSession(session);
    try std.testing.expectEqual(@as(usize, 2), session.sources.sources.items.len);
    try std.testing.expect(session.nextUnreportedContinuityFailure() == null);
    for (0..2) |index| {
        session.sources.sources.items[index].read_prefix = lostPrefix;
        try pollUntilIntervention(session, index);
        const report = session.nextUnreportedContinuityFailure() orelse return error.MissingContinuityReport;
        try std.testing.expectEqualStrings(session.sources.sources.items[index].source_id, report.source);
        try std.testing.expectEqual(files.Discontinuity.prefix_changed, report.failure.kind);
        try std.testing.expect(session.nextUnreportedContinuityFailure() == null);
    }
    const replacement = try sessions.Session.createDeferred(std.testing.allocator, &f.store, options, &.{.{ .pattern = pattern }});
    defer replacement.destroy();
    try replacement.copyRepairStateFrom(session);
    session.destroy();
    session_live = false;
    try std.testing.expect(replacement.continuityFailure() != null);
    try std.testing.expect(replacement.nextUnreportedContinuityFailure() == null);
}

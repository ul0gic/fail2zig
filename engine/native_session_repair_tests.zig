// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const t = std.testing;
const durable = @import("core/record_store.zig");
const files = @import("core/native_file_session.zig");
const journal = @import("core/native_journal_session.zig");
const transport = @import("core/native_journal_transport.zig");
const repair = @import("core/source_repair.zig");
const records = @import("core/source_record.zig");
const time = @import("core/native_time.zig");
const health = @import("core/storage_health.zig");
const Fixture = struct {
    tmp: t.TmpDir,
    root: []u8,
    path: []u8,
    database: []u8,
    store: durable.Store,
    fn init() !Fixture {
        var tmp = t.tmpDir(.{});
        errdefer tmp.cleanup();
        const root = try tmp.dir.realpathAlloc(t.allocator, ".");
        errdefer t.allocator.free(root);
        const path = try std.fs.path.join(t.allocator, &.{ root, "active.log" });
        errdefer t.allocator.free(path);
        const database = try std.fs.path.join(t.allocator, &.{ root, "state.sqlite" });
        errdefer t.allocator.free(database);
        var store = try durable.Store.open(t.allocator, database);
        errdefer store.close();
        try store.enableReceipts(8);
        try store.enableNativeTime();
        try store.enableDetection();
        try store.enableClockRecovery();
        return .{ .tmp = tmp, .root = root, .path = path, .database = database, .store = store };
    }
    fn deinit(self: *Fixture) void {
        self.store.close();
        t.allocator.free(self.database);
        t.allocator.free(self.path);
        t.allocator.free(self.root);
        self.tmp.cleanup();
    }
    fn append(self: *Fixture, bytes: []const u8) !void {
        const file = try self.tmp.dir.openFile("active.log", .{ .mode = .write_only });
        defer file.close();
        try file.seekFromEnd(0);
        try file.writeAll(bytes);
    }
};
const Clock = struct {
    us: i64 = 1_000_000_000,
    ms: u64 = 0,
    fn wall(ctx: ?*anyopaque) !time.Timestamp {
        const self: *Clock = @ptrCast(@alignCast(ctx.?));
        return .{ .us = self.us };
    }
    fn mono(ctx: ?*anyopaque) u64 {
        const self: *Clock = @ptrCast(@alignCast(ctx.?));
        return self.ms;
    }
    fn fileOptions(self: *Clock) files.Options {
        return .{ .processing = .{ .jail = "fixture", .parent_generation = [_]u8{1} ** 32, .timestamp = .undated }, .max_sources = 8, .clock = wall, .clock_context = self, .monotonic_clock = .{ .context = self, .read = mono } };
    }
    fn journalOptions(self: *Clock, mock: *Mock) journal.Options {
        return .{ .processing = .{ .jail = "fixture", .parent_generation = [_]u8{2} ** 32, .timestamp = .journal }, .clock = wall, .clock_context = self, .monotonic_clock = .{ .context = self, .read = mono }, .executor = mock.executor() };
    }
};
fn admitFile(session: *files.Session) !void {
    for (0..4096) |_| if (try session.admissionTurn()) return;
    return error.AdmissionDidNotComplete;
}
fn fileDelivery(session: *files.Session) !usize {
    for (0..64) |_| {
        const count = try session.pollTurn(1);
        if (count > 0) return count;
    }
    return 0;
}
fn failFrame(_: []const u8, _: []const u8, _: bool, _: std.mem.Allocator, _: ?*anyopaque) !?records.Framed {
    return error.InputOutput;
}
const one = "{\"__CURSOR\":\"one\",\"__REALTIME_TIMESTAMP\":\"1000000000\",\"MESSAGE\":\"first\",\"_UID\":\"0\"}\n";
const two = "{\"__CURSOR\":\"two\",\"__REALTIME_TIMESTAMP\":\"1000000001\",\"MESSAGE\":\"second\",\"_UID\":\"0\"}\n";
const Mock = struct {
    response: []const u8 = one,
    failure: ?anyerror = null,
    calls: usize = 0,
    tails: usize = 0,
    saw_original_since: bool = false,
    fn run(_: std.mem.Allocator, args: []const []const u8, output: []u8, diagnostic: *transport.Diagnostic, _: u32, ctx: ?*anyopaque) ![]const u8 {
        const self: *Mock = @ptrCast(@alignCast(ctx.?));
        self.calls += 1;
        for (args) |arg| {
            if (std.mem.eql(u8, arg, "--lines=1")) self.tails += 1;
            if (std.mem.eql(u8, arg, "--since=@1000.000000")) self.saw_original_since = true;
        }
        diagnostic.* = .{ .exit_code = 0 };
        if (self.failure) |failure| return failure;
        if (self.response.len > output.len) return error.JournalOutputLimit;
        @memcpy(output[0..self.response.len], self.response);
        return output[0..self.response.len];
    }
    fn executor(self: *Mock) transport.Executor {
        return .{ .run = run, .context = self };
    }
};

test "native session repair: pruned file replay stays fenced while sibling source commits" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.store.enableJournalDetection();
    try f.store.enableRetry();
    try f.store.enableConsumers();
    try f.store.enableEffects();
    try f.store.enableConsumerManifests();
    try f.store.enableConfirmedHistory();
    try f.store.enableMaintenance();
    try f.tmp.dir.writeFile(.{ .sub_path = "active.log", .data = "" });
    try f.tmp.dir.writeFile(.{ .sub_path = "sibling.log", .data = "" });
    const sibling = try std.fs.path.join(t.allocator, &.{ f.root, "sibling.log" });
    defer t.allocator.free(sibling);
    var clock = Clock{};
    const session = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &.{ .{ .pattern = f.path }, .{ .pattern = sibling } });
    defer session.destroy();
    try admitFile(session);
    for (0..32) |_| {
        _ = try session.pollTurn(1);
        if (session.sources.sources.items.len == 2 and session.sources.sources.items[0].baseline_committed and session.sources.sources.items[1].baseline_committed) break;
    }
    try t.expectEqual(@as(usize, 2), session.sources.sources.items.len);
    var index: usize = 0;
    if (!std.mem.eql(u8, session.sources.sources.items[0].path, f.path)) index = 1;
    const source = &session.sources.sources.items[index];
    try t.expect(source.baseline_committed);
    const initial = source.committed.?;
    var gate = health.Gate.init(.{ .context = &clock, .read = Clock.mono });
    const recovery = try gate.beginRecovery();
    for ([_]health.RecoveryStep{ .storage, .state, .ownership, .sources }) |step| try gate.completed(recovery, step);
    session.pipe.gate = &gate;
    session.pipe.recovery_generation = recovery;
    try f.append("first\n");
    session.next_source = index;
    session.discover_next = false;
    try t.expectEqual(@as(usize, 1), try session.pollTurn(1));
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("first\n", &hash, .{});
    var occurrence_bytes: [256]u8 = undefined;
    const occurrence = try std.fmt.bufPrint(&occurrence_bytes, "file:v1:{s}:0:6:{s}", .{ std.fmt.fmtSliceHexLower(&initial.incarnation), std.fmt.fmtSliceHexLower(&hash) });
    try f.store.fixtureReplayGuard("fixture", source.source_id, occurrence);
    const saved = (try f.store.sourceCursor(t.allocator, "fixture", source.source_id)).?;
    defer t.allocator.free(saved);
    const revision = try f.store.revision("fixture");
    source.committed = initial;
    session.next_source = index;
    session.discover_next = false;
    try t.expectError(error.SourceInterventionRequired, session.pollTurn(1));
    try t.expect(session.pipe.ready);
    try t.expectEqual(health.Phase.healthy, gate.snapshot().phase);
    try t.expectEqual(repair.Phase.intervention, (try session.sourceRepairSnapshot(index)).phase);
    try t.expectEqual(error.PrunedReplay, (try session.sourceRepairSnapshot(index)).last_cause.?);
    try t.expectEqual(revision, try f.store.revision("fixture"));
    try t.expectEqual(@as(usize, 0), try f.store.pendingReceiptCount());
    try f.tmp.dir.writeFile(.{ .sub_path = "sibling.log", .data = "second\n" });
    var delivered: usize = 0;
    for (0..16) |_| {
        delivered += session.pollTurn(1) catch |err| switch (err) {
            error.SourceInterventionRequired => 0,
            else => return err,
        };
    }
    try t.expectEqual(@as(usize, 1), delivered);
    try t.expectEqual(revision + 1, try f.store.revision("fixture"));
    try t.expectEqual(error.PrunedReplay, session.repairSnapshot().last_cause.?);
    const after = (try f.store.sourceCursor(t.allocator, "fixture", source.source_id)).?;
    defer t.allocator.free(after);
    try t.expectEqualStrings(saved, after);
    try t.expectEqual(@as(u64, 2), gate.snapshot().committed_records);
}

test "native session repair: pruned journal replay retains precise intervention without helper retries" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.store.enableJournalDetection();
    try f.store.enableRetry();
    try f.store.enableConsumers();
    try f.store.enableEffects();
    try f.store.enableConsumerManifests();
    try f.store.enableConfirmedHistory();
    try f.store.enableMaintenance();
    var clock = Clock{};
    var mock = Mock{};
    const session = try journal.Session.create(t.allocator, &f.store, clock.journalOptions(&mock));
    defer session.destroy();
    _ = try session.pollTurn(1);
    const initial = session.position;
    mock.response = one ++ two;
    try t.expectEqual(@as(usize, 1), try session.pollTurn(1));
    try f.store.fixtureReplayGuard("fixture", session.options.source_id, "entry:two");
    const revision = try f.store.revision("fixture");
    const saved = (try f.store.sourceCursor(t.allocator, "fixture", session.options.source_id)).?;
    defer t.allocator.free(saved);
    var gate = health.Gate.init(.{ .context = &clock, .read = Clock.mono });
    const recovery = try gate.beginRecovery();
    for ([_]health.RecoveryStep{ .storage, .state, .ownership, .sources }) |step| try gate.completed(recovery, step);
    session.pipe.gate = &gate;
    session.pipe.recovery_generation = recovery;
    session.position = initial;
    try t.expectError(error.SourceInterventionRequired, session.pollTurn(1));
    const calls = mock.calls;
    for (0..3) |_| try t.expectError(error.SourceInterventionRequired, session.pollTurn(1));
    try t.expectEqual(calls, mock.calls);
    try t.expect(session.pipe.ready);
    try t.expectEqual(health.Phase.healthy, gate.snapshot().phase);
    try t.expectEqual(error.PrunedReplay, session.repairSnapshot().last_cause.?);
    try t.expectEqual(repair.Phase.intervention, session.repairSnapshot().phase);
    try t.expectEqual(revision, try f.store.revision("fixture"));
    try t.expectEqual(@as(usize, 0), try f.store.pendingReceiptCount());
    const after = (try f.store.sourceCursor(t.allocator, "fixture", session.options.source_id)).?;
    defer t.allocator.free(after);
    try t.expectEqualStrings(saved, after);
}

test "native session repair: deferred file discovery accounts every entry and never acknowledges admission" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.tmp.dir.writeFile(.{ .sub_path = "active.log", .data = "first\n" });
    for (0..300) |i| {
        var name: [32]u8 = undefined;
        try f.tmp.dir.writeFile(.{ .sub_path = try std.fmt.bufPrint(&name, "unmatched-{d}", .{i}), .data = "" });
    }
    var clock = Clock{};
    const session = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &.{.{ .pattern = f.path }});
    defer session.destroy();
    try t.expectEqual(@as(usize, 0), session.sources.sources.items.len);
    var prior: usize = 0;
    var maximum: usize = 0;
    var turns: usize = 0;
    while (!try session.admissionTurn()) {
        turns += 1;
        if (turns > 4096) return error.AdmissionDidNotComplete;
        const visited = session.sources.discovery_visited + (if (session.sources.discovery) |scan| scan.visited else @as(usize, 0));
        if (visited >= prior) try t.expect(visited - prior <= 256);
        maximum = @max(maximum, visited);
        prior = visited;
        try t.expectEqual(@as(u64, 0), try f.store.revision("fixture"));
    }
    try t.expect(maximum >= 300);
    try t.expect(turns > 2);
    try t.expectEqual(@as(usize, 1), try fileDelivery(session));
}

test "native session repair: file cooldown retains pending receipt inode and original time" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.tmp.dir.writeFile(.{ .sub_path = "active.log", .data = "first\n" });
    var clock = Clock{};
    const session = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &.{.{ .pattern = f.path }});
    defer session.destroy();
    try admitFile(session);
    _ = try fileDelivery(session);
    try f.append("pending\n");
    f.store.fail_at = .after_receipt_delete;
    try t.expectError(error.InjectedFailure, fileDelivery(session));
    try t.expectEqual(repair.Phase.healthy, session.repairSnapshot().phase);
    f.store.fail_at = null;
    const source = &session.sources.sources.items[0];
    const fd = source.file.?.handle;
    const saved = source.acknowledgedCheckpoint().?;
    source.frame_callback = failFrame;
    try t.expectError(error.SourceRepairPending, fileDelivery(session));
    try t.expectEqual(@as(?u64, 1000), session.repairSnapshot().next_retry_ms);
    try t.expectEqual(@as(usize, 1), try f.store.pendingReceiptCount());
    try f.tmp.dir.rename("active.log", "retained.old");
    source.frame_callback = null;
    try t.expectError(error.SourceRepairPending, fileDelivery(session));
    try t.expectEqual(@as(u8, 0), session.repairSnapshot().attempts);
    clock.ms = 1000;
    clock.us += 10_000_000;
    try t.expectEqual(@as(usize, 1), try fileDelivery(session));
    try t.expectEqual(fd, source.file.?.handle);
    try t.expect(source.acknowledgedCheckpoint().?.offset > saved.offset);
    try t.expectEqual(repair.Phase.healthy, session.repairSnapshot().phase);
    try t.expectEqual(@as(i64, 1_000_000_000), (try f.store.nativeTime("fixture", source.source_id, null)).?.eligible.receipt.us);
}

test "native session repair: pending copytruncate causes intervention without cursor or receipt reset" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.tmp.dir.writeFile(.{ .sub_path = "active.log", .data = "first\n" });
    var clock = Clock{};
    const session = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &.{.{ .pattern = f.path }});
    defer session.destroy();
    try admitFile(session);
    _ = try fileDelivery(session);
    try f.append("pending\n");
    f.store.fail_at = .after_receipt_delete;
    try t.expectError(error.InjectedFailure, fileDelivery(session));
    f.store.fail_at = null;
    const saved = session.sources.sources.items[0].acknowledgedCheckpoint().?;
    try f.tmp.dir.writeFile(.{ .sub_path = "active.log", .data = "x\n" });
    try t.expectError(error.SourceInterventionRequired, fileDelivery(session));
    try t.expectEqualDeep(saved, session.sources.sources.items[0].acknowledgedCheckpoint().?);
    try t.expectEqual(@as(usize, 1), try f.store.pendingReceiptCount());
    try t.expectEqual(repair.Phase.intervention, session.repairSnapshot().phase);
}

test "native session repair: journal cooldown storage fencing and twelve-attempt exhaustion" {
    var f = try Fixture.init();
    defer f.deinit();
    var clock = Clock{};
    var mock = Mock{};
    const session = try journal.Session.create(t.allocator, &f.store, clock.journalOptions(&mock));
    defer session.destroy();
    _ = try session.pollTurn(1);
    mock.failure = error.JournalTimeout;
    try t.expectError(error.SourceRepairPending, session.pollTurn(1));
    const calls = mock.calls;
    try t.expectError(error.SourceRepairPending, session.pollTurn(1));
    try t.expectEqual(calls, mock.calls);
    var gate = health.Gate.init(.{ .context = &clock, .read = Clock.mono });
    gate.state.phase = .healthy;
    session.pipe.gate = &gate;
    gate.failed(error.StorageIo, .{});
    const ticket = session.repairSnapshot();
    try t.expectError(error.StoragePaused, session.pollTurn(1));
    try t.expectEqualDeep(ticket, session.repairSnapshot());
    try t.expectEqual(calls, mock.calls);
    session.pipe.gate = null;
    for (0..12) |i| {
        clock.ms = session.repairSnapshot().next_retry_ms.?;
        if (i == 11) try t.expectError(error.SourceInterventionRequired, session.pollTurn(1)) else try t.expectError(error.SourceRepairPending, session.pollTurn(1));
    }
    try t.expectEqual(@as(u8, 12), session.repairSnapshot().attempts);
    const exhausted = mock.calls;
    clock.ms += 30_000;
    try t.expectError(error.SourceInterventionRequired, session.pollTurn(1));
    try t.expectEqual(exhausted, mock.calls);
}

test "native session repair: journal validates original anchor then resets only after record poll" {
    var f = try Fixture.init();
    defer f.deinit();
    var clock = Clock{};
    var mock = Mock{};
    const session = try journal.Session.create(t.allocator, &f.store, clock.journalOptions(&mock));
    defer session.destroy();
    _ = try session.pollTurn(1);
    mock.failure = error.JournalChildFailed;
    try t.expectError(error.SourceRepairPending, session.pollTurn(1));
    mock.failure = null;
    mock.response = one ++ two;
    clock.ms = 1000;
    try t.expectEqual(@as(usize, 0), try session.pollTurn(1));
    try t.expectEqual(repair.Phase.polling, session.repairSnapshot().phase);
    try t.expectEqual(@as(u8, 1), session.repairSnapshot().attempts);
    try t.expectEqual(@as(usize, 1), try session.pollTurn(1));
    try t.expectEqual(repair.Phase.healthy, session.repairSnapshot().phase);
    mock.failure = error.JournalTimeout;
    try t.expectError(error.SourceRepairPending, session.pollTurn(1));
    mock.failure = null;
    mock.response = one;
    clock.ms = session.repairSnapshot().next_retry_ms.?;
    try t.expectError(error.SourceInterventionRequired, session.pollTurn(1));
    try t.expectEqual(@as(?anyerror, error.ResumeLost), session.repairSnapshot().last_cause);
}

test "native session repair: failed fresh journal query cannot move original initial boundary" {
    var f = try Fixture.init();
    defer f.deinit();
    var clock = Clock{};
    var mock = Mock{ .failure = error.JournalTimeout };
    const session = try journal.Session.createDeferred(t.allocator, &f.store, clock.journalOptions(&mock));
    defer session.destroy();
    try t.expectEqual(@as(usize, 0), mock.calls);
    try t.expect(!try session.admissionTurn());
    try t.expectError(error.SourceRepairPending, session.admissionTurn());
    const tails = mock.tails;
    clock.ms = 1000;
    clock.us += 9_000_000;
    mock.failure = null;
    mock.response = two;
    try t.expect(!try session.admissionTurn());
    try t.expect(try session.admissionTurn());
    try t.expect(mock.saw_original_since);
    try t.expectEqual(tails, mock.tails);
    try t.expectEqual(@as(usize, 0), try session.pollTurn(1));
    try t.expectEqual(repair.Phase.polling, session.repairSnapshot().phase);
    try t.expectEqual(@as(usize, 1), try session.pollTurn(1));
    try t.expectEqual(repair.Phase.healthy, session.repairSnapshot().phase);
}

test "native session repair: missing initial file is retried without premature baseline" {
    var f = try Fixture.init();
    defer f.deinit();
    var clock = Clock{};
    const session = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &.{.{ .pattern = f.path }});
    defer session.destroy();
    try t.expectError(error.SourceRepairPending, admitFile(session));
    try t.expectEqual(@as(u64, 0), try f.store.revision("fixture"));
    try t.expectEqual(@as(?u64, 1000), session.repairSnapshot().next_retry_ms);
    try f.tmp.dir.writeFile(.{ .sub_path = "active.log", .data = "arrived during cooldown\n" });
    try t.expectError(error.SourceRepairPending, session.admissionTurn());
    clock.ms = 1000;
    try admitFile(session);
    try t.expectEqual(repair.Phase.polling, session.repairSnapshot().phase);
    try t.expectEqual(@as(u64, 0), try f.store.revision("fixture"));
    try t.expectEqual(@as(usize, 1), try fileDelivery(session));
    try t.expectEqual(repair.Phase.healthy, session.repairSnapshot().phase);
}

test "native session repair: one failing file does not monopolize another file in the jail" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.tmp.dir.writeFile(.{ .sub_path = "a.log", .data = "first owner\n" });
    try f.tmp.dir.writeFile(.{ .sub_path = "b.log", .data = "second owner\n" });
    const pattern = try std.fs.path.join(t.allocator, &.{ f.root, "*.log" });
    defer t.allocator.free(pattern);
    var clock = Clock{};
    const session = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &.{.{ .pattern = pattern }});
    defer session.destroy();
    try admitFile(session);
    session.sources.sources.items[0].frame_callback = failFrame;
    try t.expectError(error.SourceRepairPending, session.pollTurn(1));
    var delivered: usize = 0;
    for (0..64) |_| {
        delivered += session.pollTurn(1) catch |err| {
            if (err == error.SourceRepairPending) continue;
            return err;
        };
        if (delivered == 1) break;
    }
    try t.expectEqual(@as(usize, 1), delivered);
    try t.expectEqual(repair.Phase.waiting, (try session.sourceRepairSnapshot(0)).phase);
    try t.expectEqual(@as(u8, 0), (try session.sourceRepairSnapshot(0)).attempts);
    try t.expectEqual(repair.Phase.healthy, (try session.sourceRepairSnapshot(1)).phase);
}

test "native session repair: deferred owner allocation failures release all reservations" {
    var f = try Fixture.init();
    defer f.deinit();
    var clock = Clock{};
    const Check = struct {
        fn run(a: std.mem.Allocator, store: *durable.Store, options: files.Options, path: []const u8) !void {
            const session = try files.Session.createDeferred(a, store, options, &.{.{ .pattern = path }});
            defer session.destroy();
        }
    };
    try t.checkAllAllocationFailures(t.allocator, Check.run, .{ &f.store, clock.fileOptions(), f.path });
}

test "native session repair: restarted rotated file restores exact pending proof in bounded turns" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.tmp.dir.writeFile(.{ .sub_path = "active.log", .data = "first\n" });
    var clock = Clock{};
    {
        const session = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &.{.{ .pattern = f.path }});
        defer session.destroy();
        try admitFile(session);
        _ = try fileDelivery(session);
        try f.append("pending\n");
        f.store.fail_at = .after_receipt_delete;
        try t.expectError(error.InjectedFailure, fileDelivery(session));
        f.store.fail_at = null;
        try f.tmp.dir.rename("active.log", "retained.old");
    }
    f.store.close();
    f.store = try durable.Store.open(t.allocator, f.database);
    try f.store.enableReceipts(8);
    const before = try f.store.revision("fixture");
    clock.us += 1_000_000;
    const restored = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &.{.{ .pattern = f.path }});
    defer restored.destroy();
    try admitFile(restored);
    try t.expectEqual(before, try f.store.revision("fixture"));
    try t.expectEqual(@as(usize, 1), try f.store.pendingReceiptCount());
    try t.expectEqual(@as(usize, 1), try fileDelivery(restored));
    try t.expectEqual(@as(usize, 0), try f.store.pendingReceiptCount());
    try t.expectEqual(@as(i64, 1_000_000_000), (try f.store.nativeTime("fixture", restored.sources.sources.items[0].source_id, null)).?.eligible.receipt.us);
}

test "native session repair: changed pending journal origin cannot pass anchor-only repair" {
    var f = try Fixture.init();
    defer f.deinit();
    var clock = Clock{};
    var mock = Mock{};
    const session = try journal.Session.create(t.allocator, &f.store, clock.journalOptions(&mock));
    defer session.destroy();
    _ = try session.pollTurn(1);
    mock.response = one ++ two;
    f.store.fail_at = .after_receipt_delete;
    try t.expectError(error.InjectedFailure, session.pollTurn(1));
    f.store.fail_at = null;
    const before = try f.store.revision("fixture");
    mock.failure = error.JournalTimeout;
    try t.expectError(error.SourceRepairPending, session.pollTurn(1));
    mock.failure = null;
    mock.response = one ++ "{\"__CURSOR\":\"two\",\"__REALTIME_TIMESTAMP\":\"1000000001\",\"MESSAGE\":\"second\",\"_UID\":\"33\"}\n";
    clock.ms = 1000;
    try t.expectError(error.SourceInterventionRequired, session.pollTurn(1));
    try t.expectEqual(@as(?anyerror, error.PendingRecordMismatch), session.repairSnapshot().last_cause);
    try t.expectEqual(before, try f.store.revision("fixture"));
    try t.expectEqual(@as(usize, 1), try f.store.pendingReceiptCount());
    const pending = (try f.store.readPendingSource(t.allocator, "fixture", session.options.source_id)).?;
    defer pending.deinit(t.allocator);
    try t.expectEqual(@as(i64, 1_000_000_000), pending.receipt_us);
}

fn failPrefix(_: std.fs.File, _: u8) ![32]u8 {
    return error.InputOutput;
}
test "native session repair: failed prefix read retains the committed incarnation and starts cooldown" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.tmp.dir.writeFile(.{ .sub_path = "active.log", .data = "first\n" });
    var clock = Clock{};
    const session = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &.{.{ .pattern = f.path }});
    defer session.destroy();
    try admitFile(session);
    _ = try fileDelivery(session);
    const source = &session.sources.sources.items[0];
    const saved = source.acknowledgedCheckpoint().?;
    const revision = try f.store.revision("fixture");
    const read_prefix = source.read_prefix;
    source.read_prefix = failPrefix;
    try t.expectError(error.SourceRepairPending, fileDelivery(session));
    try t.expectEqualDeep(saved, source.acknowledgedCheckpoint().?);
    try t.expect(source.baseline_committed);
    try t.expectEqual(revision, try f.store.revision("fixture"));
    try t.expectEqual(@as(usize, 0), try f.store.pendingReceiptCount());
    source.read_prefix = read_prefix;
    clock.ms = 1000;
    _ = try fileDelivery(session);
    try t.expectEqual(repair.Phase.healthy, session.repairSnapshot().phase);
    try t.expectEqualDeep(saved, source.acknowledgedCheckpoint().?);
}

test "native session repair: reconstruction retains deleted inode descriptor and source cooldown" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.tmp.dir.writeFile(.{ .sub_path = "active.log", .data = "first\n" });
    var clock = Clock{};
    const old = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &.{.{ .pattern = f.path }});
    var old_live = true;
    defer if (old_live) old.destroy();
    try admitFile(old);
    _ = try fileDelivery(old);
    try f.append("after baseline\n");
    old.sources.sources.items[0].frame_callback = failFrame;
    try t.expectError(error.SourceRepairPending, fileDelivery(old));
    const saved = old.sources.sources.items[0].acknowledgedCheckpoint().?;
    try f.tmp.dir.deleteFile("active.log");
    const replacement = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &.{.{ .pattern = f.path }});
    defer replacement.destroy();
    try replacement.copyRepairStateFrom(old);
    try replacement.retainSourcesFrom(old);
    try t.expectEqualDeep(old.repairSnapshot(), replacement.repairSnapshot());
    old.destroy();
    old_live = false;
    try t.expectError(error.SourceRepairPending, admitFile(replacement));
    try t.expectEqual(@as(u8, 0), replacement.repairSnapshot().attempts);
    clock.ms = 1000;
    try admitFile(replacement);
    try t.expectEqual(repair.Phase.polling, replacement.repairSnapshot().phase);
    try t.expectEqual(saved.inode, (try replacement.sources.sources.items[0].file.?.stat()).inode);
    try t.expectEqual(@as(usize, 1), try fileDelivery(replacement));
    try t.expectEqual(repair.Phase.healthy, replacement.repairSnapshot().phase);
}

test "native session repair: uncommitted tail proposal survives reconstruction without advancing boundary" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.tmp.dir.writeFile(.{ .sub_path = "active.log", .data = "before tail\n" });
    var clock = Clock{};
    const old = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &.{.{ .pattern = f.path, .start = .tail }});
    defer old.destroy();
    try admitFile(old);
    const initial = old.sources.sources.items[0].committed.?;
    try t.expect(!old.sources.sources.items[0].baseline_committed);
    try f.append("after original tail\n");
    const replacement = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &.{.{ .pattern = f.path, .start = .tail }});
    defer replacement.destroy();
    try replacement.copyRepairStateFrom(old);
    try replacement.retainSourcesFrom(old);
    try admitFile(replacement);
    try t.expectEqualDeep(initial, replacement.sources.sources.items[0].committed.?);
    try t.expect(!replacement.sources.sources.items[0].baseline_committed);
    try t.expectEqual(@as(usize, 1), try fileDelivery(replacement));
    try t.expectEqual(@as(usize, 0), try fileDelivery(replacement));
}

test "native session repair: failed first journal tail preserves its boundary and timer through reconstruction" {
    var f = try Fixture.init();
    defer f.deinit();
    var clock = Clock{};
    var mock = Mock{ .failure = error.JournalTimeout };
    const old = try journal.Session.createDeferred(t.allocator, &f.store, clock.journalOptions(&mock));
    defer old.destroy();
    _ = try old.admissionTurn();
    try t.expectError(error.SourceRepairPending, old.admissionTurn());
    clock.us += 10_000_000;
    const replacement = try journal.Session.createDeferred(t.allocator, &f.store, clock.journalOptions(&mock));
    defer replacement.destroy();
    try replacement.copyRepairStateFrom(old);
    _ = try replacement.admissionTurn();
    const calls = mock.calls;
    try t.expectError(error.SourceRepairPending, replacement.admissionTurn());
    try t.expectEqual(calls, mock.calls);
    clock.ms = 1000;
    mock.failure = null;
    for (0..8) |_| if (try replacement.admissionTurn()) break;
    try t.expect(mock.saw_original_since);
    try t.expectEqual(@as(usize, 1), mock.tails);
    try t.expectEqual(repair.Phase.polling, replacement.repairSnapshot().phase);
    _ = try replacement.pollTurn(1);
    try t.expectEqual(repair.Phase.polling, replacement.repairSnapshot().phase);
    _ = try replacement.pollTurn(1);
    try t.expectEqual(repair.Phase.healthy, replacement.repairSnapshot().phase);
}

test "native session repair: exact committed pending proof permits fresh cursor recovery without resetting episode" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.tmp.dir.writeFile(.{ .sub_path = "active.log", .data = "first\n" });
    var clock = Clock{};
    const old = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &.{.{ .pattern = f.path }});
    defer old.destroy();
    try admitFile(old);
    _ = try fileDelivery(old);
    try f.append("pending\n");
    f.store.fail_at = .after_receipt_delete;
    try t.expectError(error.InjectedFailure, fileDelivery(old));
    f.store.fail_at = null;
    const source = &old.sources.sources.items[0];
    const saved = source.committed.?;
    const frame = source.frame_callback;
    source.frame_callback = failFrame;
    try t.expectError(error.SourceRepairPending, fileDelivery(old));
    source.frame_callback = frame;
    _ = try source.poll(@import("core/record_pipeline.zig").Pipeline.acknowledge, &old.pipe);
    source.committed = saved;
    try t.expectEqual(@as(usize, 0), try f.store.pendingReceiptCount());
    const replacement = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &.{.{ .pattern = f.path }});
    defer replacement.destroy();
    try replacement.copyRepairStateFrom(old);
    try replacement.retainSourcesFrom(old);
    clock.ms = 1000;
    try admitFile(replacement);
    try t.expectEqual(@as(u8, 1), replacement.repairSnapshot().attempts);
    try t.expectEqual(repair.Phase.polling, replacement.repairSnapshot().phase);
    try t.expect(replacement.repair_states[0].binding.pending_digest == null);
    try t.expect(replacement.sources.sources.items[0].committed.?.offset > saved.offset);
    _ = try fileDelivery(replacement);
    try t.expectEqual(repair.Phase.healthy, replacement.repairSnapshot().phase);
}

test "native session repair: missing pending row without a committed proof cannot clear repair binding" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.tmp.dir.writeFile(.{ .sub_path = "active.log", .data = "first\n" });
    var clock = Clock{};
    const old = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &.{.{ .pattern = f.path }});
    defer old.destroy();
    try admitFile(old);
    _ = try fileDelivery(old);
    try f.append("pending\n");
    f.store.fail_at = .after_receipt_delete;
    try t.expectError(error.InjectedFailure, fileDelivery(old));
    f.store.fail_at = null;
    old.sources.sources.items[0].frame_callback = failFrame;
    try t.expectError(error.SourceRepairPending, fileDelivery(old));
    try t.expectEqual(@as(c_int, 0), f.store.api.exec(f.store.db, "DELETE FROM pending_receipts;", null, null, null));
    const replacement = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &.{.{ .pattern = f.path }});
    defer replacement.destroy();
    try replacement.copyRepairStateFrom(old);
    try replacement.retainSourcesFrom(old);
    clock.ms = 1000;
    try t.expectError(error.SourceInterventionRequired, admitFile(replacement));
    try t.expect(replacement.repair_states[0].binding.pending_digest != null);
}

test "native session repair: first receipt write failure retries its exact source and original clock after reconstruction" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.tmp.dir.writeFile(.{ .sub_path = "active.log", .data = "first\n" });
    try f.tmp.dir.writeFile(.{ .sub_path = "second.log", .data = "second\n" });
    const pattern = try std.fs.path.join(t.allocator, &.{ f.root, "*.log" });
    defer t.allocator.free(pattern);
    var clock = Clock{};
    const old = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &.{.{ .pattern = pattern }});
    defer old.destroy();
    try admitFile(old);
    for (old.sources.sources.items) |*source| {
        _ = try source.poll(@import("core/record_pipeline.zig").Pipeline.acknowledge, &old.pipe);
    }
    try f.append("new first\n");
    const second = try f.tmp.dir.openFile("second.log", .{ .mode = .write_only });
    defer second.close();
    try second.seekFromEnd(0);
    try second.writeAll("new second\n");
    try t.expectEqual(@as(c_int, 0), f.store.api.exec(f.store.db, "PRAGMA query_only=ON;", null, null, null));
    try t.expectError(error.ReadOnly, fileDelivery(old));
    try t.expect(old.pipe.candidate_receipt != null);
    const candidate = old.candidate_source.?;
    const original = old.pipe.candidate_receipt.?.time;
    try t.expectEqual(@as(c_int, 0), f.store.api.exec(f.store.db, "PRAGMA query_only=OFF;", null, null, null));
    clock.us += 10_000_000;
    const replacement = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &.{.{ .pattern = pattern }});
    defer replacement.destroy();
    try replacement.copyRepairStateFrom(old);
    try replacement.retainSourcesFrom(old);
    try admitFile(replacement);
    try t.expectEqualStrings(candidate, replacement.candidate_source.?);
    try t.expectEqual(@as(usize, 1), try replacement.pollTurn(1));
    try t.expect(replacement.pipe.candidate_receipt == null);
    try t.expect(replacement.candidate_source == null);
    try t.expectEqual(original.us, (try f.store.nativeTime("fixture", candidate, null)).?.eligible.receipt.us);
}

test "native session repair: reconstruction allocation failures release copied metadata and descriptors" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.tmp.dir.writeFile(.{ .sub_path = "active.log", .data = "first\n" });
    var clock = Clock{};
    const old = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &.{.{ .pattern = f.path }});
    defer old.destroy();
    try admitFile(old);
    _ = try fileDelivery(old);
    try f.append("pending\n");
    f.store.fail_at = .after_receipt_delete;
    try t.expectError(error.InjectedFailure, fileDelivery(old));
    f.store.fail_at = null;
    old.sources.sources.items[0].frame_callback = failFrame;
    try t.expectError(error.SourceRepairPending, fileDelivery(old));
    const Check = struct {
        fn run(a: std.mem.Allocator, source: *const files.Session, store: *durable.Store, options: files.Options, path: []const u8) !void {
            const replacement = try files.Session.createDeferred(a, store, options, &.{.{ .pattern = path }});
            defer replacement.destroy();
            try replacement.copyRepairStateFrom(source);
            try replacement.retainSourcesFrom(source);
        }
    };
    try t.checkAllAllocationFailures(t.allocator, Check.run, .{ old, &f.store, clock.fileOptions(), f.path });
}

test "native session repair: successfully observed ordinary shrink retains explicit copytruncate policy" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.tmp.dir.writeFile(.{ .sub_path = "active.log", .data = "original sufficiently long line\n" });
    var clock = Clock{};
    const session = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &.{.{ .pattern = f.path }});
    defer session.destroy();
    try admitFile(session);
    _ = try fileDelivery(session);
    const incarnation = session.sources.sources.items[0].committed.?.incarnation;
    try f.tmp.dir.writeFile(.{ .sub_path = "active.log", .data = "new\n" });
    try t.expectEqual(@as(usize, 1), try fileDelivery(session));
    try t.expect(!std.mem.eql(u8, &incarnation, &session.sources.sources.items[0].committed.?.incarnation));
    try t.expectEqual(repair.Phase.healthy, session.repairSnapshot().phase);
}

test "native session repair: synchronous fresh journal tail is not repeated after metadata transfer" {
    var f = try Fixture.init();
    defer f.deinit();
    var clock = Clock{};
    var mock = Mock{};
    const old = try journal.Session.create(t.allocator, &f.store, clock.journalOptions(&mock));
    defer old.destroy();
    try t.expect(!old.baseline_committed);
    try t.expectEqual(@as(usize, 1), mock.tails);
    mock.response = one ++ two;
    clock.us += 10_000_000;
    const replacement = try journal.Session.createDeferred(t.allocator, &f.store, clock.journalOptions(&mock));
    defer replacement.destroy();
    try replacement.copyRepairStateFrom(old);
    for (0..8) |_| if (try replacement.admissionTurn()) break;
    try t.expectEqual(@as(usize, 1), mock.tails);
    try t.expectEqual(@as(usize, 0), try replacement.pollTurn(1));
    try t.expectEqual(@as(usize, 1), try replacement.pollTurn(1));
    try t.expectEqual(@as(usize, 1), mock.tails);
}

fn recoveryFdCount() !usize {
    var directory = try std.fs.openDirAbsolute("/proc/self/fd", .{ .iterate = true });
    defer directory.close();
    var iterator = directory.iterate();
    var count: usize = 0;
    while (try iterator.next() != null) count += 1;
    return count;
}

test "native session repair: detached file snapshot survives old owner destruction and partial repeated restoration" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.tmp.dir.writeFile(.{ .sub_path = "active.log", .data = "first\n" });
    var clock = Clock{};
    const old = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &.{.{ .pattern = f.path }});
    var old_live = true;
    defer if (old_live) old.destroy();
    try admitFile(old);
    _ = try fileDelivery(old);
    try f.append("pending\n");
    f.store.fail_at = .after_receipt_delete;
    try t.expectError(error.InjectedFailure, fileDelivery(old));
    f.store.fail_at = null;
    old.sources.sources.items[0].frame_callback = failFrame;
    try t.expectError(error.SourceRepairPending, fileDelivery(old));
    const original = (try f.store.readPendingSource(t.allocator, "fixture", old.sources.sources.items[0].source_id)).?;
    defer original.deinit(t.allocator);
    try f.tmp.dir.rename("active.log", "rotated.log");
    try f.tmp.dir.deleteFile("rotated.log");
    const snapshot = try old.exportRecovery();
    defer snapshot.destroy();
    try t.expectEqual(@as(usize, 1), snapshot.descriptorCount());
    try t.expect(snapshot.reservedBytes() <= (try files.RecoverySnapshot.reservation(8)).bytes);
    old.destroy();
    old_live = false;
    const partial = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &.{.{ .pattern = f.path }});
    var partial_live = true;
    defer if (partial_live) partial.destroy();
    try partial.importRecovery(snapshot);
    _ = try partial.admissionTurn();
    const next_snapshot = try partial.exportRecovery();
    defer next_snapshot.destroy();
    try t.expectEqual(@as(usize, 1), next_snapshot.descriptorCount());
    partial.destroy();
    partial_live = false;
    const replacement = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &.{.{ .pattern = f.path }});
    defer replacement.destroy();
    try replacement.importRecovery(next_snapshot);
    clock.ms = 1000;
    try admitFile(replacement);
    try t.expectEqual(@as(u8, 1), replacement.repairSnapshot().attempts);
    try t.expectEqual(@as(usize, 1), try replacement.pollTurn(1));
    const committed = (try f.store.committedReceipt(original.identity)).?;
    try t.expectEqual(original.receipt_us, committed.us);
    try t.expectEqual(@as(usize, 0), try f.store.pendingReceiptCount());
}

test "native session repair: newly observed first file tail persists through detached recovery cycles" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.tmp.dir.writeFile(.{ .sub_path = "active.log", .data = "history\n" });
    var clock = Clock{};
    const old = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &.{.{ .pattern = f.path, .start = .tail }});
    var old_live = true;
    defer if (old_live) old.destroy();
    try admitFile(old);
    try t.expect(!old.sources.sources.items[0].baseline_committed);
    const snapshot = try old.exportRecovery();
    defer snapshot.destroy();
    old.destroy();
    old_live = false;
    try f.append("new\n");
    const partial = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &.{.{ .pattern = f.path, .start = .tail }});
    var partial_live = true;
    defer if (partial_live) partial.destroy();
    try partial.importRecovery(snapshot);
    const repeated = try partial.exportRecovery();
    defer repeated.destroy();
    partial.destroy();
    partial_live = false;
    const replacement = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &.{.{ .pattern = f.path, .start = .tail }});
    defer replacement.destroy();
    try replacement.importRecovery(repeated);
    try admitFile(replacement);
    try t.expectEqual(@as(u64, 8), replacement.sources.sources.items[0].committed.?.offset);
    try t.expectEqual(@as(usize, 1), try fileDelivery(replacement));
    try t.expectEqual(@as(u64, 12), replacement.sources.sources.items[0].committed.?.offset);
    try t.expectEqual(@as(u64, 2), try f.store.revision("fixture"));
}

test "native session repair: new journal tail supersedes imported empty proposal before teardown" {
    var f = try Fixture.init();
    defer f.deinit();
    var clock = Clock{};
    var mock = Mock{};
    const old = try journal.Session.createDeferred(t.allocator, &f.store, clock.journalOptions(&mock));
    var old_live = true;
    defer if (old_live) old.destroy();
    const empty = try old.exportRecovery();
    defer empty.destroy();
    old.destroy();
    old_live = false;
    const middle = try journal.Session.createDeferred(t.allocator, &f.store, clock.journalOptions(&mock));
    var middle_live = true;
    defer if (middle_live) middle.destroy();
    try middle.importRecovery(empty);
    _ = try middle.admissionTurn();
    _ = try middle.admissionTurn();
    try t.expectEqual(@as(usize, 1), mock.tails);
    const latest = try middle.exportRecovery();
    defer latest.destroy();
    try t.expectEqual(@as(u16, 0), empty.initial_proposal.?.length);
    try t.expectEqual(@as(u16, 3), latest.initial_proposal.?.length);
    try t.expect(latest.reservedBytes() <= (try journal.RecoverySnapshot.reservation(1)).bytes);
    middle.destroy();
    middle_live = false;
    mock.response = one ++ two;
    const replacement = try journal.Session.createDeferred(t.allocator, &f.store, clock.journalOptions(&mock));
    defer replacement.destroy();
    try replacement.importRecovery(latest);
    for (0..8) |_| if (try replacement.admissionTurn()) break;
    try t.expectEqual(@as(usize, 1), mock.tails);
    try t.expectEqual(@as(usize, 0), try replacement.pollTurn(1));
    try t.expectEqual(@as(usize, 1), try replacement.pollTurn(1));
    try t.expectEqual(@as(usize, 1), mock.tails);
}

test "native session repair: detached export handles uninitialized fresh slots and refuses retained incarnation conflict" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.tmp.dir.writeFile(.{ .sub_path = "active.log", .data = "first\n" });
    var clock = Clock{};
    const old = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &.{.{ .pattern = f.path }});
    defer old.destroy();
    try admitFile(old);
    old.repair_count = 0;
    const snapshot = try old.exportRecovery();
    defer snapshot.destroy();
    try t.expectEqual(@as(usize, 1), snapshot.entries.items.len);
    const replacement = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &.{.{ .pattern = f.path }});
    defer replacement.destroy();
    try replacement.importRecovery(snapshot);
    _ = try replacement.admissionTurn();
    _ = try replacement.admissionTurn();
    try t.expectEqual(@as(usize, 1), replacement.sources.sources.items.len);
    replacement.repair_count = 0;
    replacement.sources.sources.items[0].committed.?.incarnation[0] ^= 1;
    const count = try recoveryFdCount();
    try t.expectError(error.ResumeLost, replacement.exportRecovery());
    try t.expectEqual(count, try recoveryFdCount());
    try t.expectEqual(@as(usize, 1), replacement.retained.items.len);
    try t.expectEqual(@as(usize, 1), snapshot.descriptorCount());
}

test "native session repair: detached export and import allocation failures retain source and snapshot owners" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.tmp.dir.writeFile(.{ .sub_path = "active.log", .data = "first\n" });
    var clock = Clock{};
    const old = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &.{.{ .pattern = f.path }});
    defer old.destroy();
    try admitFile(old);
    _ = try fileDelivery(old);
    try f.append("pending\n");
    f.store.fail_at = .after_receipt_delete;
    try t.expectError(error.InjectedFailure, fileDelivery(old));
    f.store.fail_at = null;
    old.sources.sources.items[0].frame_callback = failFrame;
    try t.expectError(error.SourceRepairPending, fileDelivery(old));
    const Check = struct {
        fn exportAll(a: std.mem.Allocator, session: *files.Session) !void {
            const original = session.allocator;
            session.allocator = a;
            defer session.allocator = original;
            const snapshot = try session.exportRecovery();
            defer snapshot.destroy();
        }
        fn importAll(a: std.mem.Allocator, store: *durable.Store, options: files.Options, path: []const u8, snapshot: *const files.RecoverySnapshot) !void {
            const next = try files.Session.createDeferred(a, store, options, &.{.{ .pattern = path }});
            defer next.destroy();
            try next.importRecovery(snapshot);
        }
    };
    const before = try recoveryFdCount();
    try t.checkAllAllocationFailures(t.allocator, Check.exportAll, .{old});
    try t.expectEqual(before, try recoveryFdCount());
    const snapshot = try old.exportRecovery();
    defer snapshot.destroy();
    const held = try recoveryFdCount();
    try t.checkAllAllocationFailures(t.allocator, Check.importAll, .{ &f.store, clock.fileOptions(), f.path, snapshot });
    try t.expectEqual(held, try recoveryFdCount());
    try t.expectEqual(@as(usize, 1), snapshot.descriptorCount());
    try t.expectEqual(@as(usize, 1), try f.store.pendingReceiptCount());
}

test "native session repair: detached first receipt candidate retains source and time without callbacks" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.tmp.dir.writeFile(.{ .sub_path = "active.log", .data = "first\n" });
    var clock = Clock{};
    const old = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &.{.{ .pattern = f.path }});
    var old_live = true;
    defer if (old_live) old.destroy();
    try admitFile(old);
    _ = try fileDelivery(old);
    try f.append("pending\n");
    try t.expectEqual(@as(c_int, 0), f.store.api.exec(f.store.db, "PRAGMA query_only=ON;", null, null, null));
    try t.expectError(error.ReadOnly, fileDelivery(old));
    const original = old.pipe.candidate_receipt.?.time;
    const Forbidden = struct {
        fn call(_: []const u8, _: [32]u8, _: ?*anyopaque) !void {
            return error.UnexpectedConsumerCallback;
        }
    };
    old.consumer_sources = .{ .context = null, .admit = Forbidden.call };
    f.store.reopen_required = true;
    const snapshot = try old.exportRecovery();
    defer snapshot.destroy();
    f.store.reopen_required = false;
    old.destroy();
    old_live = false;
    try t.expectEqual(@as(c_int, 0), f.store.api.exec(f.store.db, "PRAGMA query_only=OFF;", null, null, null));
    clock.us += 10_000_000;
    const replacement = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &.{.{ .pattern = f.path }});
    defer replacement.destroy();
    const generation = snapshot.generation;
    snapshot.generation[0] ^= 1;
    try t.expectError(error.SourceGenerationMismatch, replacement.importRecovery(snapshot));
    snapshot.generation = generation;
    try replacement.importRecovery(snapshot);
    try admitFile(replacement);
    const source = try t.allocator.dupe(u8, replacement.candidate_source.?);
    defer t.allocator.free(source);
    try t.expectEqual(@as(usize, 1), try replacement.pollTurn(1));
    try t.expectEqual(original.us, (try f.store.nativeTime("fixture", source, null)).?.eligible.receipt.us);
}

test "native session repair: detached journal proof survives allocation faults and rejects changed origin" {
    var f = try Fixture.init();
    defer f.deinit();
    var clock = Clock{};
    var mock = Mock{};
    const old = try journal.Session.create(t.allocator, &f.store, clock.journalOptions(&mock));
    var old_live = true;
    defer if (old_live) old.destroy();
    _ = try old.pollTurn(1);
    mock.response = one ++ two;
    f.store.fail_at = .after_receipt_delete;
    try t.expectError(error.InjectedFailure, old.pollTurn(1));
    f.store.fail_at = null;
    mock.failure = error.JournalTimeout;
    try t.expectError(error.SourceRepairPending, old.pollTurn(1));
    try t.expect(old.pending_proof != null);
    const Check = struct {
        fn exportAll(a: std.mem.Allocator, session: *journal.Session) !void {
            const original = session.allocator;
            session.allocator = a;
            defer session.allocator = original;
            const snapshot = try session.exportRecovery();
            defer snapshot.destroy();
        }
        fn importAll(a: std.mem.Allocator, store: *durable.Store, options: journal.Options, snapshot: *const journal.RecoverySnapshot) !void {
            const next = try journal.Session.createDeferred(a, store, options);
            defer next.destroy();
            try next.importRecovery(snapshot);
        }
    };
    const descriptors = try recoveryFdCount();
    const calls = mock.calls;
    try t.checkAllAllocationFailures(t.allocator, Check.exportAll, .{old});
    const snapshot = try old.exportRecovery();
    defer snapshot.destroy();
    try t.checkAllAllocationFailures(t.allocator, Check.importAll, .{ &f.store, clock.journalOptions(&mock), snapshot });
    try t.expectEqual(descriptors, try recoveryFdCount());
    try t.expectEqual(calls, mock.calls);
    const original_hash = snapshot.pending_proof.?.identity.raw_hash;
    const receipt_us = snapshot.pending_proof.?.receipt_us;
    old.destroy();
    old_live = false;
    mock.failure = null;
    mock.response = one ++ "{\"__CURSOR\":\"two\",\"__REALTIME_TIMESTAMP\":\"1000000001\",\"MESSAGE\":\"second\",\"_UID\":\"33\"}\n";
    const replacement = try journal.Session.createDeferred(t.allocator, &f.store, clock.journalOptions(&mock));
    defer replacement.destroy();
    try replacement.importRecovery(snapshot);
    try t.expectEqualSlices(u8, &original_hash, &replacement.pending_proof.?.identity.raw_hash);
    try t.expectEqual(receipt_us, replacement.pending_proof.?.receipt_us);
    const revision = try f.store.revision("fixture");
    clock.ms = 1000;
    var refused = false;
    for (0..8) |_| {
        _ = replacement.admissionTurn() catch |err| {
            try t.expectEqual(error.SourceInterventionRequired, err);
            refused = true;
            break;
        };
    }
    try t.expect(refused);
    try t.expectEqual(@as(?anyerror, error.PendingRecordMismatch), replacement.repairSnapshot().last_cause);
    try t.expectEqual(revision, try f.store.revision("fixture"));
    try t.expectEqual(@as(usize, 1), try f.store.pendingReceiptCount());
}

test "native session repair: partial detached import preserves every unadopted source proposal" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.tmp.dir.writeFile(.{ .sub_path = "active.log", .data = "old first\n" });
    try f.tmp.dir.writeFile(.{ .sub_path = "other.log", .data = "old second\n" });
    const other = try std.fs.path.join(t.allocator, &.{ f.root, "other.log" });
    defer t.allocator.free(other);
    const specs = [_]files.Spec{ .{ .pattern = f.path, .start = .tail }, .{ .pattern = other, .start = .tail } };
    var clock = Clock{};
    const old = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &specs);
    var old_live = true;
    defer if (old_live) old.destroy();
    try admitFile(old);
    const snapshot = try old.exportRecovery();
    defer snapshot.destroy();
    old.destroy();
    old_live = false;
    const middle = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &specs);
    var middle_live = true;
    defer if (middle_live) middle.destroy();
    try middle.importRecovery(snapshot);
    _ = try middle.admissionTurn();
    _ = try middle.admissionTurn();
    try t.expectEqual(@as(usize, 1), middle.sources.sources.items.len);
    const latest = try middle.exportRecovery();
    defer latest.destroy();
    try t.expectEqual(@as(usize, 2), latest.entries.items.len);
    try t.expectEqual(@as(usize, 2), latest.descriptorCount());
    middle.destroy();
    middle_live = false;
    const replacement = try files.Session.createDeferred(t.allocator, &f.store, clock.fileOptions(), &specs);
    defer replacement.destroy();
    try replacement.importRecovery(latest);
    try admitFile(replacement);
    try t.expectEqual(@as(usize, 2), replacement.sources.sources.items.len);
    for (replacement.sources.sources.items) |source| {
        try t.expect(!source.baseline_committed);
        try t.expectEqual(if (std.mem.eql(u8, source.path, f.path)) @as(u64, 10) else @as(u64, 11), source.committed.?.offset);
    }
    try t.expectEqual(@as(u64, 0), try f.store.revision("fixture"));
}

const GenerationProbe = struct {
    calls: usize = 0,
    admits: usize = 0,
    const detected = @import("core/native_detection_record.zig");
    fn failClock(ctx: ?*anyopaque) !time.Timestamp {
        const self: *@This() = @ptrCast(@alignCast(ctx.?));
        self.calls += 1;
        return error.UnexpectedPreflightCallback;
    }
    fn prepare(_: detected.StagedInput, ctx: ?*anyopaque) !detected.StagedPrepared {
        const self: *@This() = @ptrCast(@alignCast(ctx.?));
        self.calls += 1;
        return error.UnexpectedPreflightCallback;
    }
    fn checkpoint(_: records.Record, _: i64, _: u64, ctx: ?*anyopaque) !detected.StagedState {
        const self: *@This() = @ptrCast(@alignCast(ctx.?));
        self.calls += 1;
        return error.UnexpectedPreflightCallback;
    }
    fn manifest(_: []const u8, _: [32]u8, ctx: ?*anyopaque) !@import("core/native_consumer.zig").Manifest {
        const self: *@This() = @ptrCast(@alignCast(ctx.?));
        self.calls += 1;
        return error.UnexpectedPreflightCallback;
    }
    fn admit(_: []const u8, _: [32]u8, ctx: ?*anyopaque) !void {
        const self: *@This() = @ptrCast(@alignCast(ctx.?));
        self.admits += 1;
    }
    fn consumer(self: *@This()) detected.StagedConsumer {
        return .{ .generation = [_]u8{34} ** 32, .context = self, .prepare = prepare, .prepare_checkpoint = checkpoint, .manifest = manifest };
    }
};
fn totalChanges(store: *durable.Store) i64 {
    const read = @extern(*const fn (*anyopaque) callconv(.c) i64, .{ .name = "sqlite3_total_changes64" });
    return read(@ptrCast(store.db));
}

test "native session repair: pure generation equals file and journal builtin custom retry constructors" {
    for ([_]bool{ false, true }) |is_journal| for ([_]bool{ false, true }) |custom| for ([_]bool{ false, true }) |with_retry| {
        var f = try Fixture.init();
        defer f.deinit();
        try f.store.enableJournalDetection();
        try f.store.enableRetry();
        try f.store.enableConsumers();
        try f.store.enableEffects();
        try f.store.enableConsumerManifests();
        var detector = try @import("core/native_builtin_detector.zig").Detector.init(t.allocator, .{ .filter = "sshd", .body = .whole, .ignore_capacity = 8, .max_decoded_bytes = 2048 });
        defer detector.deinit(t.allocator);
        const profile = try @import("core/native_journal_origin.zig").Profile.init("0123456789abcdef0123456789abcdef", &.{"/fixture/sshd"});
        const qualified = try @import("core/native_journal_detector.zig").Detector.init(&detector, profile);
        var clock = Clock{};
        var mock = Mock{ .failure = error.UnexpectedSourceIo };
        var probe = GenerationProbe{};
        var scratch: [2048]u8 = undefined;
        const retry: ?@import("core/native_retry.zig").Policy = if (with_retry) .{ .maxretry = 2, .window_us = 600_000_000, .duration = .{ .finite_us = 60_000_000 }, .max_subjects = 8 } else null;
        const before = totalChanges(&f.store);
        if (is_journal) {
            var options = clock.journalOptions(&mock);
            options.retry = retry;
            options.clock = GenerationProbe.failClock;
            options.clock_context = &probe;
            if (custom) {
                options.staged_detection = probe.consumer();
                options.consumer_sources = .{ .context = &probe, .admit = GenerationProbe.admit };
            } else options.detection = qualified.consumer();
            const prepared = try journal.Session.prepareProcessor(t.allocator, options, &scratch, .{ .us = 0 });
            try t.expectEqual(before, totalChanges(&f.store));
            try t.expectEqual(@as(usize, 0), probe.calls + probe.admits + mock.calls);
            options.clock = Clock.wall;
            options.clock_context = &clock;
            const session = try journal.Session.createDeferred(t.allocator, &f.store, options);
            defer session.destroy();
            try t.expectEqual(prepared.generation, session.processor.generation);
            try t.expectEqualDeep(prepared.retry_policy, session.processor.retry_policy);
            try t.expectEqual(@as(usize, @intFromBool(custom)), probe.admits);
        } else {
            var options = clock.fileOptions();
            options.retry = retry;
            options.clock = GenerationProbe.failClock;
            options.clock_context = &probe;
            if (custom) {
                options.staged_detection = probe.consumer();
                options.consumer_sources = .{ .context = &probe, .admit = GenerationProbe.admit };
            } else options.detection = detector.consumer();
            const specs = [_]files.Spec{.{ .pattern = f.path, .start = .tail }};
            const prepared = try files.Session.prepareProcessor(t.allocator, options, &specs, &scratch, .{ .us = 0 });
            try t.expectEqual(before, totalChanges(&f.store));
            try t.expectEqual(@as(usize, 0), probe.calls + probe.admits + mock.calls);
            options.clock = Clock.wall;
            options.clock_context = &clock;
            const session = try files.Session.createDeferred(t.allocator, &f.store, options, &specs);
            defer session.destroy();
            try t.expectEqual(prepared.generation, session.processor.generation);
            try t.expectEqualDeep(prepared.retry_policy, session.processor.retry_policy);
            try t.expectEqual(@as(usize, 0), session.sources.sources.items.len);
        }
        try t.expectEqual(@as(usize, 0), probe.calls + mock.calls);
        try t.expectEqual(@as(u64, 0), try f.store.revision("fixture"));
        try t.expectEqual(@as(usize, 0), try f.store.pendingReceiptCount());
    };
}

test "native session repair: pure generation source binding bounds and allocation failures" {
    var clock = Clock{};
    var mock = Mock{};
    const file_options = clock.fileOptions();
    const journal_options = clock.journalOptions(&mock);
    var scratch: [2048]u8 = undefined;
    const first = try files.Session.prepareProcessor(t.allocator, file_options, &.{.{ .pattern = "/missing/one", .start = .head }}, &scratch, .{ .us = 0 });
    const other = try files.Session.prepareProcessor(t.allocator, file_options, &.{.{ .pattern = "/missing/one", .start = .tail }}, &scratch, .{ .us = 99 });
    try t.expect(!std.mem.eql(u8, &first.generation, &other.generation));
    const initial = try journal.Session.prepareProcessor(t.allocator, journal_options, &scratch, .{ .us = 0 });
    var changed = journal_options;
    changed.source_id = "different-source";
    try t.expect(!std.mem.eql(u8, &initial.generation, &(try journal.Session.prepareProcessor(t.allocator, changed, &scratch, .{ .us = 99 })).generation));
    try t.expectError(error.InvalidSourceLimit, files.Session.prepareProcessor(t.allocator, file_options, &.{}, &scratch, .{ .us = 0 }));
    try t.expectError(error.InvalidSourceSpecification, files.Session.prepareProcessor(t.allocator, file_options, &.{.{ .pattern = "bad\x00path" }}, &scratch, .{ .us = 0 }));
    try t.expectError(error.InvalidSourceLimits, files.Session.prepareProcessor(t.allocator, file_options, &.{.{ .pattern = "/missing" }}, scratch[0..1], .{ .us = 0 }));
    changed.source_id = "bad\x00source";
    try t.expectError(error.InvalidJournalSource, journal.Session.prepareProcessor(t.allocator, changed, &scratch, .{ .us = 0 }));
    const Oom = struct {
        fn check(a: std.mem.Allocator, fo: files.Options, jo: journal.Options) !void {
            var local: [2048]u8 = undefined;
            _ = try files.Session.prepareProcessor(a, fo, &.{.{ .pattern = "/missing" }}, &local, .{ .us = 0 });
            _ = try journal.Session.prepareProcessor(a, jo, &local, .{ .us = 0 });
        }
    };
    try t.checkAllAllocationFailures(t.allocator, Oom.check, .{ file_options, journal_options });
    try t.expectEqual(@as(usize, 0), mock.calls);
}

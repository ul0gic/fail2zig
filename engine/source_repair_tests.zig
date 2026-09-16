// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const repair = @import("core/source_repair.zig");
const files = @import("core/durable_file_source.zig");
const journal = @import("core/native_journal_transport.zig");
const records = @import("core/source_record.zig");
const t = std.testing;

fn binding() !repair.Binding {
    return (try repair.Binding.init([_]u8{7} ** 32, "fixture:retained-source")).withPending("occurrence:1", "exact-cursor", [_]u8{9} ** 32, -17);
}

test "source repair: finite attempts require verified poll and retain storage-fenced identity" {
    const identity = try binding();
    var state = try repair.Repair.init(identity, 0);
    try t.expectEqual(repair.Domain.transient_source, try state.failed(error.AccessDenied, 0));
    const first = state.snapshot();
    _ = try state.failed(error.AccessDenied, 5);
    try t.expectEqual(first.next_retry_ms, state.snapshot().next_retry_ms);
    try t.expectEqual(@as(?repair.Token, null), try state.begin(999, true));
    try t.expectEqual(@as(?repair.Token, null), try state.begin(1000, false));
    const unchanged = state.snapshot();
    try t.expectEqual(repair.Domain.storage, try state.failed(error.StorageFull, 1000));
    try t.expectEqualDeep(unchanged, state.snapshot());
    const token = (try state.begin(1000, true)).?;
    try t.expectError(error.StaleRepair, state.pollSucceeded(token));
    try state.continuityVerified(token, identity);
    try t.expectEqual(@as(u8, 1), state.snapshot().attempts);
    _ = try state.failed(error.JournalTimeout, 1000);
    try t.expectEqual(@as(?u64, 3000), state.snapshot().next_retry_ms);
    const next = (try state.begin(3000, true)).?;
    try t.expectError(error.StaleRepair, state.continuityVerified(token, identity));
    try t.expectError(error.StaleRepair, state.attemptFailed(token, error.JournalTimeout, 3000));
    for ([_]anyerror{ error.ConsumerClockReversed, error.StaleConsumerCheckpoint }) |cause|
        try t.expectEqual(repair.Domain.storage, try state.attemptFailed(next, cause, 3000));
    try state.continuityVerified(next, identity);
    try state.pollSucceeded(next);
    try t.expectEqual(repair.Phase.healthy, state.snapshot().phase);
    try t.expectEqualDeep(identity, state.binding);
    try t.expectEqual(@as(u8, 0), state.snapshot().attempts);
}

test "source repair: episode exhaustion and clock identity faults latch intervention" {
    var state = try repair.Repair.init(try binding(), 0);
    _ = try state.failed(error.FileNotFound, 0);
    var now: u64 = 0;
    for (0..repair.Repair.max_attempts) |index| {
        const due = state.snapshot().next_retry_ms.?;
        const delays = [_]u64{ 1000, 2000, 4000, 8000, 16000, 30000 };
        try t.expectEqual(delays[@min(index, delays.len - 1)], due - now);
        now = due;
        const token = (try state.begin(now, true)).?;
        try t.expectEqual(token, (try state.begin(now, true)).?);
        try t.expectEqual(repair.Domain.pending, try state.failed(error.SourceRepairPending, now));
        _ = try state.failed(error.JournalTimeout, now);
    }
    try t.expectEqual(repair.Phase.intervention, state.snapshot().phase);
    try t.expectError(error.SourceInterventionRequired, state.begin(now + 30_000, true));
    _ = try state.failed(error.AccessDenied, now + 30_000);
    try t.expectEqual(repair.Phase.intervention, state.snapshot().phase);

    for ([_]anyerror{ error.ResumeLost, error.PendingRecordMismatch, error.DiscoveryEntryLimit, error.InvalidResume }) |cause| {
        var broken = try repair.Repair.init(try binding(), 0);
        try t.expectEqual(repair.Domain.source_intervention, try broken.failed(cause, 0));
        try t.expectError(error.SourceInterventionRequired, broken.begin(60_000, true));
    }
    var reversed = try repair.Repair.init(try binding(), 10);
    try t.expectError(error.MonotonicClockReversed, reversed.begin(9, true));
    var overflow = try repair.Repair.init(try binding(), std.math.maxInt(u64) - 1);
    try t.expectError(error.RepairClockExhausted, overflow.failed(error.FileNotFound, std.math.maxInt(u64) - 1));
}

test "source repair: changed generation source receipt or pending bytes cannot resume" {
    const saved = try binding();
    for (0..4) |change| {
        var state = try repair.Repair.init(saved, 0);
        _ = try state.failed(error.AccessDenied, 0);
        const token = (try state.begin(1000, true)).?;
        var other = saved;
        switch (change) {
            0 => other.generation[0] ^= 1,
            1 => other.source_digest[0] ^= 1,
            2 => other.pending_digest.?[0] ^= 1,
            else => other.receipt_us = 0,
        }
        try t.expectError(error.PendingRecordMismatch, state.continuityVerified(token, other));
        try t.expectEqual(repair.Phase.intervention, state.snapshot().phase);
        try t.expectEqualDeep(saved, state.binding);
    }
    try t.expectError(error.InvalidRepairBinding, repair.Binding.init([_]u8{0} ** 32, ""));
}

test "source repair: replaced source owner rejects old token even with same attempt serial" {
    var first = try repair.Repair.init(try binding(), 0);
    _ = try first.failed(error.AccessDenied, 0);
    const stale = (try first.begin(1000, true)).?;
    var newer_binding = try binding();
    newer_binding.generation[0] ^= 1;
    var second = try repair.Repair.init(newer_binding, 0);
    _ = try second.failed(error.AccessDenied, 0);
    const current = (try second.begin(1000, true)).?;
    try t.expectEqual(stale.serial, current.serial);
    try t.expectError(error.StaleRepair, second.continuityVerified(stale, newer_binding));
    try second.continuityVerified(current, newer_binding);
    try t.expectError(error.StaleRepair, second.pollSucceeded(stale));
    try t.expectError(error.StaleRepair, second.attemptFailed(stale, error.JournalTimeout, 1000));
    try second.pollSucceeded(current);
}

fn finishDiscovery(discovery: *files.Discovery) !void {
    var turns: usize = 0;
    while (true) {
        const before = discovery.visited;
        const status = try discovery.pollTurn(files.discovery_entries_per_turn);
        try t.expect(discovery.visited - before <= files.discovery_entries_per_turn);
        if (status == .complete) return;
        turns += 1;
        if (turns > 1000) return error.FixtureTurnLimit;
    }
}

test "source repair: discovery counts nonmatches yields and refuses incomplete results" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    for (0..270) |i| {
        var name: [32]u8 = undefined;
        try tmp.dir.writeFile(.{ .sub_path = try std.fmt.bufPrint(&name, "ignored-{d}.txt", .{i}), .data = "" });
    }
    try tmp.dir.writeFile(.{ .sub_path = "z.log", .data = "z\n" });
    try tmp.dir.writeFile(.{ .sub_path = "a.log", .data = "a\n" });
    const dir = try tmp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(dir);
    const pattern = try std.fs.path.join(t.allocator, &.{ dir, "*.log" });
    defer t.allocator.free(pattern);
    var discovery = try files.Discovery.init(t.allocator, pattern, 2);
    defer discovery.deinit();
    try t.expectEqual(files.DiscoveryStatus.pending, try discovery.pollTurn(1));
    try t.expectError(error.DiscoveryIncomplete, discovery.takePaths());
    try finishDiscovery(&discovery);
    try t.expect(discovery.visited >= 272);
    try t.expectEqual(@as(usize, 2), discovery.paths.items.len);
    try t.expect(std.mem.endsWith(u8, discovery.paths.items[0], "/a.log"));
    var limited = try files.Discovery.init(t.allocator, pattern, 2);
    defer limited.deinit();
    limited.max_entries = 1;
    try t.expectError(error.DiscoveryEntryLimit, finishDiscovery(&limited));
    try t.expectError(error.DiscoveryEntryLimit, limited.takePaths());
    try t.expectEqual(@as(usize, 0), limited.depth);
    try t.expectError(error.InvalidDiscoveryBudget, discovery.pollTurn(257));
    var overfull = try files.Discovery.init(t.allocator, pattern, 1);
    defer overfull.deinit();
    try t.expectError(error.SourceLimit, finishDiscovery(&overfull));
    try t.expectError(error.DiscoveryDepthLimit, files.Discovery.init(t.allocator, "a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q", 1));
}

fn allocationDiscovery(a: std.mem.Allocator, pattern: []const u8) !void {
    var discovery = try files.Discovery.init(a, pattern, 4);
    defer discovery.deinit();
    try finishDiscovery(&discovery);
    const paths = try discovery.takePaths();
    defer a.free(paths);
    defer for (paths) |path| a.free(path);
    try t.expectEqual(@as(usize, 2), paths.len);
}

test "source repair: discovery allocation failures release paths iterators and partial output" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makeDir("nested");
    try tmp.dir.writeFile(.{ .sub_path = "nested/a.log", .data = "a\n" });
    try tmp.dir.writeFile(.{ .sub_path = "nested/b.log", .data = "b\n" });
    const dir = try tmp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(dir);
    const pattern = try std.fs.path.join(t.allocator, &.{ dir, "*", "*.log" });
    defer t.allocator.free(pattern);
    try t.checkAllAllocationFailures(t.allocator, allocationDiscovery, .{pattern});
}

const Capture = struct {
    occurrence: [256]u8 = undefined,
    occurrence_len: usize = 0,
    cursor: [2048]u8 = undefined,
    cursor_len: usize = 0,
    raw_hash: [32]u8 = undefined,
    fail_data: bool = true,
    data_count: usize = 0,

    fn acknowledge(record: records.Record, context: ?*anyopaque) !void {
        if (record.kind == .checkpoint) return;
        const self: *Capture = @ptrCast(@alignCast(context.?));
        if (record.occurrence.len > self.occurrence.len or record.cursor.len > self.cursor.len) return error.FixtureLimit;
        @memcpy(self.occurrence[0..record.occurrence.len], record.occurrence);
        self.occurrence_len = record.occurrence.len;
        @memcpy(self.cursor[0..record.cursor.len], record.cursor);
        self.cursor_len = record.cursor.len;
        self.raw_hash = record.raw_hash;
        if (self.fail_data) return error.FixtureCommitFailure;
        self.data_count += 1;
    }

    fn identity(self: *const Capture) files.FileSource.PendingIdentity {
        return .{ .source = "fixture-source", .occurrence = self.occurrence[0..self.occurrence_len], .cursor = self.cursor[0..self.cursor_len], .raw_hash = self.raw_hash };
    }
};

test "source repair: pending file proof survives retained rename and restart without acknowledgment" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "active.log", .data = "first benign record\npartial" });
    const path = try tmp.dir.realpathAlloc(t.allocator, "active.log");
    defer t.allocator.free(path);
    var source = try files.FileSource.init(t.allocator, path, "fixture-source", .head, null);
    defer source.deinit();
    try t.expectError(error.MissingFileCheckpoint, source.verifyExistingContinuity());
    try t.expect(source.file == null);
    var captured = Capture{};
    try t.expectError(error.FixtureCommitFailure, source.poll(Capture.acknowledge, &captured));
    const saved = source.acknowledgedCheckpoint().?;
    const original_fd = source.file.?.handle;
    try tmp.dir.rename("active.log", "retained.old");
    try tmp.dir.writeFile(.{ .sub_path = "active.log", .data = "replacement\n" });
    try source.verifyPending(captured.identity());
    try t.expectEqual(original_fd, source.file.?.handle);
    try t.expectEqualDeep(saved, source.acknowledgedCheckpoint().?);
    var changed = captured.identity();
    changed.raw_hash[0] ^= 1;
    try t.expectError(error.PendingRecordMismatch, source.verifyPending(changed));
    try t.expectEqualDeep(saved, source.acknowledgedCheckpoint().?);

    const encoded = try std.json.stringifyAlloc(t.allocator, saved, .{});
    defer t.allocator.free(encoded);
    const decoded = try std.json.parseFromSlice(files.Resume, t.allocator, encoded, .{});
    defer decoded.deinit();
    var reopened = try files.FileSource.init(t.allocator, path, "fixture-source", .head, decoded.value);
    defer reopened.deinit();
    while (true) {
        reopened.verifyPending(captured.identity()) catch |err| {
            if (err == error.SourceRepairPending) continue;
            return err;
        };
        break;
    }
    try t.expectEqualDeep(saved, reopened.acknowledgedCheckpoint().?);
    captured.fail_data = false;
    try t.expect(try reopened.poll(Capture.acknowledge, &captured));
    try t.expect(!try reopened.poll(Capture.acknowledge, &captured));
    try t.expectEqual(@as(usize, 1), captured.data_count);
    var retained = try tmp.dir.openFile("retained.old", .{ .mode = .write_only });
    defer retained.close();
    try retained.seekFromEnd(0);
    try retained.writeAll(" completed\n");
    try t.expect(try reopened.poll(Capture.acknowledge, &captured));
    try t.expectEqual(@as(usize, 2), captured.data_count);
}

test "source repair: copytruncate and lost rotated anchor preserve saved pending boundary" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "active.log", .data = "saved pending record\n" });
    const path = try tmp.dir.realpathAlloc(t.allocator, "active.log");
    defer t.allocator.free(path);
    var source = try files.FileSource.init(t.allocator, path, "fixture-source", .head, null);
    defer source.deinit();
    var captured = Capture{};
    try t.expectError(error.FixtureCommitFailure, source.poll(Capture.acknowledge, &captured));
    const saved = source.acknowledgedCheckpoint().?;
    try tmp.dir.writeFile(.{ .sub_path = "active.log", .data = "changed\n" });
    try t.expectError(error.ResumeLost, source.verifyPending(captured.identity()));
    try t.expectEqualDeep(saved, source.acknowledgedCheckpoint().?);
    try tmp.dir.deleteFile("active.log");
    var restored = try files.FileSource.init(t.allocator, path, "fixture-source", .head, saved);
    defer restored.deinit();
    try t.expectError(error.ResumeLost, restored.verifyExistingContinuity());
    try t.expectEqualDeep(saved, restored.acknowledgedCheckpoint().?);
}

test "source repair: retained-inode lookup yields without diagnosing missing anchor early" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "active.log", .data = "retained evidence\n" });
    const path = try tmp.dir.realpathAlloc(t.allocator, "active.log");
    defer t.allocator.free(path);
    var source = try files.FileSource.init(t.allocator, path, "fixture-source", .head, null);
    defer source.deinit();
    var captured = Capture{};
    try t.expectError(error.FixtureCommitFailure, source.poll(Capture.acknowledge, &captured));
    const saved = source.acknowledgedCheckpoint().?;
    try tmp.dir.deleteFile("active.log");
    for (0..300) |i| {
        var name: [32]u8 = undefined;
        try tmp.dir.writeFile(.{ .sub_path = try std.fmt.bufPrint(&name, "unrelated-{d}.txt", .{i}), .data = "" });
    }
    var reopened = try files.FileSource.init(t.allocator, path, "fixture-source", .head, saved);
    defer reopened.deinit();
    try t.expectError(error.SourceRepairPending, reopened.verifyExistingContinuity());
    try t.expectEqual(records.Health.waiting, reopened.health);
    try t.expectEqual(@as(usize, 256), reopened.resume_search.?.visited);
    try t.expectEqualDeep(saved, reopened.acknowledgedCheckpoint().?);
    try t.expectError(error.ResumeLost, reopened.verifyExistingContinuity());
    try t.expect(reopened.resume_search == null);
    try t.expectError(error.ResumeLost, reopened.verifyContinuity());
    try t.expectEqualDeep(saved, reopened.acknowledgedCheckpoint().?);
}

fn allocationPending(a: std.mem.Allocator, path: []const u8, saved: files.Resume, identity: files.FileSource.PendingIdentity) !void {
    var source = try files.FileSource.init(a, path, "fixture-source", .head, saved);
    defer source.deinit();
    try source.verifyPending(identity);
    try t.expectEqualDeep(saved, source.acknowledgedCheckpoint().?);
}

test "source repair: pending proof allocation failures preserve the acknowledged cursor" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "active.log", .data = "pending proof\n" });
    const path = try tmp.dir.realpathAlloc(t.allocator, "active.log");
    defer t.allocator.free(path);
    var source = try files.FileSource.init(t.allocator, path, "fixture-source", .head, null);
    defer source.deinit();
    var captured = Capture{};
    try t.expectError(error.FixtureCommitFailure, source.poll(Capture.acknowledge, &captured));
    try t.checkAllAllocationFailures(t.allocator, allocationPending, .{ path, source.acknowledgedCheckpoint().?, captured.identity() });
}

test "source repair: file set discovery is resumable and capacity never drops retained owners" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "a.log", .data = "a\n" });
    const dir = try tmp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(dir);
    const pattern = try std.fs.path.join(t.allocator, &.{ dir, "*.log" });
    defer t.allocator.free(pattern);
    var set = try files.FileSet.init(t.allocator, "fixture");
    defer set.deinit();
    set.max_sources = 1;
    try set.add(pattern, .head);
    try t.expectEqual(files.DiscoveryStatus.pending, try set.discoverTurn());
    while (try set.discoverTurn() != .complete) {}
    try t.expectEqual(@as(usize, 1), set.sources.items.len);
    const descriptor = set.sources.items[0].file.?.handle;
    try tmp.dir.rename("a.log", "a.old");
    try tmp.dir.writeFile(.{ .sub_path = "a.log", .data = "replacement\n" });
    try t.expectError(error.SourceLimit, set.discover());
    try t.expectEqual(@as(usize, 1), set.sources.items.len);
    try t.expectEqual(descriptor, set.sources.items[0].file.?.handle);
}

test "source repair: discovery transfers inspected descriptor across initializer rename" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "active.log", .data = "original\n" });
    const dir = try tmp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(dir);
    const pattern = try std.fs.path.join(t.allocator, &.{ dir, "active.log" });
    defer t.allocator.free(pattern);
    const Rename = struct {
        dir: std.fs.Dir,
        fn initialize(_: *files.FileSource, context: ?*anyopaque) !void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            try self.dir.rename("active.log", "retained.old");
            try self.dir.writeFile(.{ .sub_path = "active.log", .data = "replacement\n" });
        }
    };
    var renamer = Rename{ .dir = tmp.dir };
    var set = try files.FileSet.init(t.allocator, "fixture");
    defer set.deinit();
    set.initialize_source = Rename.initialize;
    set.initialize_userdata = &renamer;
    try set.add(pattern, .head);
    while (try set.discoverTurn() != .complete) {}
    try t.expectEqual(@as(usize, 1), set.sources.items.len);
    const held = set.sources.items[0].file.?;
    var bytes: [32]u8 = undefined;
    const count = try held.pread(&bytes, 0);
    try t.expectEqualStrings("original\n", bytes[0..count]);
    try t.expect(set.sources.items[0].resume_search == null);
    const old = try tmp.dir.statFile("retained.old");
    try t.expectEqual(old.inode, (try held.stat()).inode);
}

test "source repair: journal anchor and complete pending field identity never establish a fresh baseline" {
    const original = "{\"__CURSOR\":\"fixture-anchor\",\"MESSAGE\":\"benign journal record\",\"__REALTIME_TIMESTAMP\":\"17\",\"_UID\":\"0\",\"_EXE\":\"/usr/sbin/sshd\"}";
    var scratch: [journal.parse_bytes]u8 = undefined;
    const anchor = try journal.verifyAnchor(&scratch, original, "fixture-anchor", 4096);
    const hash = anchor.raw_hash;
    try journal.verifyPending(anchor, "fixture-anchor", hash);
    try t.expectError(error.ResumeLost, journal.verifyAnchor(&scratch, original, "missing-anchor", 4096));
    try t.expectError(error.ResumeLost, journal.verifyAnchor(&scratch, "", "fixture-anchor", 4096));
    const changed = "{\"__CURSOR\":\"fixture-anchor\",\"MESSAGE\":\"benign journal record\",\"__REALTIME_TIMESTAMP\":\"17\",\"_UID\":\"1000\",\"_EXE\":\"/usr/sbin/sshd\"}";
    const untrusted = try journal.verifyAnchor(&scratch, changed, "fixture-anchor", 4096);
    try t.expectError(error.PendingRecordMismatch, journal.verifyPending(untrusted, "fixture-anchor", hash));
    try t.expectError(error.MalformedJournalRecord, journal.verifyAnchor(&scratch, original[0 .. original.len - 1], "fixture-anchor", 4096));
    try t.expectError(error.JournalParseLimit, journal.verifyAnchor(&.{}, original, "fixture-anchor", 4096));
}

test "source repair: healthy pending proof update preserves episode serial fencing" {
    const original = try repair.Binding.init([_]u8{7} ** 32, "source");
    var state = try repair.Repair.init(original, 0);
    const pending = try original.withPending("occurrence", "cursor", [_]u8{1} ** 32, 10);
    try state.bindHealthy(pending);
    _ = try state.failed(error.InputOutput, 0);
    const first = (try state.begin(1000, true)).?;
    try t.expectError(error.StaleRepair, state.bindHealthy(original));
    try state.continuityVerified(first, pending);
    try state.pollSucceeded(first);
    try state.bindHealthy(original);
    _ = try state.failed(error.InputOutput, 1000);
    const next = (try state.begin(2000, true)).?;
    try t.expect(next.serial > first.serial);
    try t.expectError(error.StaleRepair, state.attemptFailed(first, error.InputOutput, 2000));
}

test "source repair: consumer scheduling yields preserve active episode and exact committed pending resolution" {
    const original = try repair.Binding.init([_]u8{9} ** 32, "source");
    const pending = try original.withPending("occurrence", "cursor", [_]u8{1} ** 32, 10);
    var state = try repair.Repair.init(pending, 0);
    _ = try state.failed(error.InputOutput, 0);
    const before = state.snapshot();
    for ([_]anyerror{ error.ConsumerPending, error.ConsumerExpired, error.EffectExpired }) |cause| {
        try t.expectEqual(repair.Domain.pending, try state.failed(cause, 0));
        try t.expectEqualDeep(before, state.snapshot());
    }
    const old_token = (try state.begin(1000, true)).?;
    try state.resolveCommittedPending(pending);
    try t.expectEqual(@as(u8, 1), state.snapshot().attempts);
    try t.expectEqual(repair.Phase.verifying, state.snapshot().phase);
    try t.expectError(error.StaleRepair, state.continuityVerified(old_token, original));
    const next = (try state.begin(1000, true)).?;
    try state.continuityVerified(next, original);
    try state.pollSucceeded(next);
}

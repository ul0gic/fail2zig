// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const store_mod = @import("core/record_store.zig");
const sessions = @import("core/native_file_session.zig");
const health = @import("core/storage_health.zig");
const recovery = @import("core/native_recovery.zig");
const time = @import("core/native_time.zig");
const t = std.testing;

const Clocks = struct {
    wall: i64 = 1_000_000_000,
    monotonic: u64 = 0,
    pending_probe: ?*store_mod.Store = null,
    pending_reads: usize = 0,
    reverse_after: usize = 0,
    fn wallRead(context: ?*anyopaque) !time.Timestamp {
        const self: *Clocks = @ptrCast(@alignCast(context.?));
        if (self.pending_probe) |store| if (try store.pendingReceiptCount() != 0) {
            self.pending_reads += 1;
            if (self.pending_reads == self.reverse_after) {
                self.wall -= 100_000_000;
                self.pending_probe = null;
            }
        };
        return .{ .us = self.wall };
    }
    fn monoRead(context: ?*anyopaque) u64 {
        const self: *Clocks = @ptrCast(@alignCast(context.?));
        return self.monotonic;
    }
};
const Owner = struct {
    allocator: std.mem.Allocator,
    store: *store_mod.Store,
    clocks: *Clocks,
    gate: *health.Gate,
    path: []const u8,
    session: ?*sessions.Session = null,
    calls: [4]usize = [_]usize{0} ** 4,
    fail_stage: ?usize = null,
    failure: anyerror = error.CorruptDatabase,
    reverse_in_sources: bool = false,
    /// Inert ownership fixture: proves recovery never rewrites an existing
    /// absolute deadline, not actual kernel expiry or backend reconciliation.
    original_deadline: i64 = 1_060_000_000,
    fn cast(context: ?*anyopaque) *Owner {
        return @ptrCast(@alignCast(context.?));
    }
    fn called(self: *Owner, stage: usize) !void {
        self.calls[stage] += 1;
        if (self.fail_stage == stage) return self.failure;
    }
    fn storage(context: ?*anyopaque) !void {
        const self = cast(context);
        try self.called(0);
        _ = try self.store.receiptClock();
    }
    fn state(context: ?*anyopaque) !void {
        const self = cast(context);
        try self.called(1);
        if (self.session) |old| old.destroy();
        self.session = null;
        self.session = try sessions.Session.create(self.allocator, self.store, .{
            .processing = .{ .jail = "ordinary", .parent_generation = [_]u8{1} ** 32, .timestamp = .{ .field = .{ .format = .epoch_seconds, .boundary = .{ .delimiter = '|' } } } },
            .max_sources = 1,
            .gate = self.gate,
            .clock = Clocks.wallRead,
            .clock_context = self.clocks,
        }, &.{.{ .pattern = self.path }});
    }
    fn ownership(context: ?*anyopaque) !void {
        const self = cast(context);
        try self.called(2);
        try t.expectEqual(@as(i64, 1_060_000_000), self.original_deadline);
    }
    fn sources(context: ?*anyopaque) !void {
        const self = cast(context);
        try self.called(3);
        try self.session.?.verifyRecoverySources();
        if (self.reverse_in_sources) self.clocks.wall = 1;
    }
    fn driver(self: *Owner) recovery.Driver {
        return .{ .store = self.store, .gate = self.gate, .clock = .{ .generation = [_]u8{0} ** 32, .clock = Clocks.wallRead, .clock_context = self.clocks }, .hooks = .{ .context = self, .storage = storage, .state = state, .ownership = ownership, .sources = sources } };
    }
    fn deinit(self: *Owner) void {
        if (self.session) |session| session.destroy();
    }
};
fn admit(store: *store_mod.Store) !void {
    try store.enableReceipts(2);
    try store.enableNativeTime();
    try store.enableDetection();
    try store.enableClockRecovery();
}

test "clock recovery: actual file ingestion pauses globally and resumes automatically without rewriting receipts" {
    var temp = t.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(root);
    const path = try std.fs.path.join(t.allocator, &.{ root, "events.log" });
    defer t.allocator.free(path);
    const database = try std.fs.path.join(t.allocator, &.{ root, "state.sqlite" });
    defer t.allocator.free(database);
    const file = try temp.dir.createFile("events.log", .{});
    defer file.close();
    var store = try store_mod.Store.open(t.allocator, database);
    defer store.close();
    try admit(&store);
    var clocks = Clocks{};
    var gate = health.Gate.init(.{ .context = &clocks, .read = Clocks.monoRead });
    var owner = Owner{ .allocator = t.allocator, .store = &store, .clocks = &clocks, .gate = &gate, .path = path };
    defer owner.deinit();
    var driver = owner.driver();
    try t.expectEqual(recovery.Status.resumed, try driver.poll());
    try file.writeAll("999|ordinary first event\n");
    try t.expectEqual(@as(usize, 1), try owner.session.?.poll(1));
    try t.expectEqual(clocks.wall, (try store.receiptClock()).?.us);
    const committed_revision = owner.session.?.pipe.revision;
    const saved_offset = owner.session.?.sources.sources.items[0].acknowledgedCheckpoint().?.offset;
    clocks.wall -= 100_000_000;
    try file.writeAll("1000|ordinary second event\n");
    try t.expectError(error.ReceiptClockReversed, owner.session.?.poll(1));
    try t.expectEqual(health.Phase.paused, gate.snapshot().phase);
    try t.expectEqual(@as(?i64, 1_000_000_000), gate.snapshot().receipt_clock_floor_us);
    try t.expectEqual(@as(usize, 0), try store.pendingReceiptCount());
    try t.expectEqual(saved_offset, owner.session.?.sources.sources.items[0].acknowledgedCheckpoint().?.offset);
    try t.expectError(error.StoragePaused, gate.admit(owner.session.?.pipe.recovery_generation));
    try t.expectError(error.PersistenceUnavailable, gate.admitMutation());
    const calls = owner.calls;
    try t.expectEqual(recovery.Status.waiting, try driver.poll());
    clocks.monotonic = 1000;
    try t.expectEqual(recovery.Status.waiting, try driver.poll());
    try t.expectEqual(calls, owner.calls); // known reversed clock avoids restore/IO
    try t.expectEqual(@as(?u64, 3000), gate.snapshot().next_retry_ms);
    clocks.wall = 1_000_000_000;
    clocks.monotonic = 3000;
    try t.expectEqual(recovery.Status.resumed, try driver.poll());
    try t.expect(gate.snapshot().receipt_clock_floor_us == null);
    try t.expectEqual(committed_revision, owner.session.?.pipe.revision);
    try t.expectEqual(@as(usize, 1), try owner.session.?.poll(1));
    try t.expectEqual(@as(u64, 2), owner.session.?.processor.timeHealth().eligible);
    try t.expectEqual(@as(i64, 1_060_000_000), owner.original_deadline);
    try t.expectEqual(@as(i64, 0), try store.pendingIntents());
}

test "clock recovery: startup behind a pending receipt waits and validates before automatic age-out" {
    var temp = t.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(root);
    const path = try std.fs.path.join(t.allocator, &.{ root, "events.log" });
    defer t.allocator.free(path);
    const database = try std.fs.path.join(t.allocator, &.{ root, "state.sqlite" });
    defer t.allocator.free(database);
    try temp.dir.writeFile(.{ .sub_path = "events.log", .data = "999|pending ordinary event\n" });
    var clocks = Clocks{};
    {
        var store = try store_mod.Store.open(t.allocator, database);
        defer store.close();
        try admit(&store);
        var gate = health.Gate.init(.{ .context = &clocks, .read = Clocks.monoRead });
        var owner = Owner{ .allocator = t.allocator, .store = &store, .clocks = &clocks, .gate = &gate, .path = path };
        defer owner.deinit();
        var driver = owner.driver();
        _ = try driver.poll();
        // A COMMIT-reported failure after the receipt actually became durable.
        store.fail_at = .after_receipt_commit;
        try t.expectError(error.InjectedFailure, owner.session.?.poll(1));
        try t.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
    }
    clocks.wall = 900_000_000;
    var store = try store_mod.Store.open(t.allocator, database);
    defer store.close();
    try store.enableReceipts(2);
    var gate = health.Gate.init(.{ .context = &clocks, .read = Clocks.monoRead });
    var owner = Owner{ .allocator = t.allocator, .store = &store, .clocks = &clocks, .gate = &gate, .path = path };
    defer owner.deinit();
    var driver = owner.driver();
    try t.expectEqual(recovery.Status.waiting, try driver.poll());
    try t.expect(owner.session == null);
    try t.expectEqual(@as(usize, 0), owner.calls[1]);
    try t.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
    clocks.wall = 1_700_000_000;
    clocks.monotonic = 1000;
    try t.expectEqual(recovery.Status.resumed, try driver.poll());
    try t.expectEqual(@as(usize, 1), try owner.session.?.poll(1));
    const value = (try store.nativeTime("ordinary", owner.session.?.sources.sources.items[0].source_id, null)).?.obsolete;
    try t.expectEqual(@as(i64, 1_000_000_000), value.receipt.us);
    try t.expectEqual(@as(i64, 999_000_000), value.timestamp.us);
    try t.expectEqual(@as(u64, 1), owner.session.?.processor.timeHealth().obsolete);
    try t.expectEqual(@as(i64, 0), try store.pendingIntents());
}

test "clock recovery: catch-up cannot bypass corruption lost sources or a second clock reversal" {
    for (0..3) |case| {
        var temp = t.tmpDir(.{});
        defer temp.cleanup();
        const root = try temp.dir.realpathAlloc(t.allocator, ".");
        defer t.allocator.free(root);
        const path = try std.fs.path.join(t.allocator, &.{ root, "events.log" });
        defer t.allocator.free(path);
        const database = try std.fs.path.join(t.allocator, &.{ root, "state.sqlite" });
        defer t.allocator.free(database);
        try temp.dir.writeFile(.{ .sub_path = "events.log", .data = "999|ordinary event\n" });
        var store = try store_mod.Store.open(t.allocator, database);
        defer store.close();
        try admit(&store);
        var clocks = Clocks{};
        var gate = health.Gate.init(.{ .context = &clocks, .read = Clocks.monoRead });
        var owner = Owner{ .allocator = t.allocator, .store = &store, .clocks = &clocks, .gate = &gate, .path = path };
        defer owner.deinit();
        var driver = owner.driver();
        _ = try driver.poll();
        _ = try owner.session.?.poll(1);
        clocks.wall = 900_000_000;
        try t.expectError(error.ReceiptClockReversed, owner.session.?.poll(1));
        clocks.wall = 1_000_000_000;
        clocks.monotonic = 1000;
        switch (case) {
            0 => owner.fail_stage = 1,
            1 => try temp.dir.writeFile(.{ .sub_path = "events.log", .data = "truncated\n" }),
            2 => owner.reverse_in_sources = true,
            else => unreachable,
        }
        try t.expectEqual(if (case == 2) recovery.Status.waiting else recovery.Status.intervention, try driver.poll());
        try t.expectError(error.StoragePaused, gate.admit(gate.snapshot().generation));
        if (case == 2) {
            owner.reverse_in_sources = false;
            clocks.wall = 1_000_000_000;
            clocks.monotonic = 3000;
            try t.expectEqual(recovery.Status.resumed, try driver.poll());
        } else {
            clocks.monotonic = 100_000;
            try t.expectEqual(recovery.Status.intervention, try driver.poll());
        }
    }
}

test "clock recovery: unavailable startup persistence is still refused" {
    var clocks = Clocks{};
    var gate = health.Gate.init(.{ .context = &clocks, .read = Clocks.monoRead });
    // The storage hook fails before touching this inert store value.
    var store: store_mod.Store = undefined;
    store.last_error_code = null;
    store.rollback_error_code = null;
    store.reopen_required = false;
    var owner = Owner{ .allocator = t.allocator, .store = &store, .clocks = &clocks, .gate = &gate, .path = "unused", .fail_stage = 0, .failure = error.OpenFailed };
    var driver = owner.driver();
    try t.expectError(error.OpenFailed, driver.poll());
    try t.expectEqual([4]usize{ 1, 0, 0, 0 }, owner.calls);

    // Waiting for a clock during startup must not weaken persistence refusal.
    gate = health.Gate.init(.{ .context = &clocks, .read = Clocks.monoRead });
    owner.calls = [_]usize{0} ** 4;
    gate.receiptClockFailed(clocks.wall + 1);
    clocks.monotonic = 1000;
    try t.expectEqual(recovery.Status.waiting, try driver.poll());
    try t.expectEqual([4]usize{ 0, 0, 0, 0 }, owner.calls);
    try t.expect(!gate.snapshot().has_been_healthy);
    clocks.wall += 1;
    clocks.monotonic = 3000;
    try t.expectError(error.OpenFailed, driver.poll());
    try t.expectEqual([4]usize{ 1, 0, 0, 0 }, owner.calls);
    try t.expect(!gate.snapshot().has_been_healthy);
}

test "clock recovery: reversal during preparation never publishes or loses the pending receipt" {
    // Reverse after receipt commit: before decoding, during time preparation,
    // and after preparation but before outcome commit.
    for (1..4) |reverse_after| {
        var temp = t.tmpDir(.{});
        defer temp.cleanup();
        const root = try temp.dir.realpathAlloc(t.allocator, ".");
        defer t.allocator.free(root);
        const path = try std.fs.path.join(t.allocator, &.{ root, "events.log" });
        defer t.allocator.free(path);
        const database = try std.fs.path.join(t.allocator, &.{ root, "state.sqlite" });
        defer t.allocator.free(database);
        try temp.dir.writeFile(.{ .sub_path = "events.log", .data = "999|ordinary event\n" });
        var store = try store_mod.Store.open(t.allocator, database);
        defer store.close();
        try admit(&store);
        var clocks = Clocks{ .reverse_after = reverse_after };
        var gate = health.Gate.init(.{ .context = &clocks, .read = Clocks.monoRead });
        var owner = Owner{ .allocator = t.allocator, .store = &store, .clocks = &clocks, .gate = &gate, .path = path };
        defer owner.deinit();
        var driver = owner.driver();
        _ = try driver.poll();
        clocks.pending_probe = &store;
        try t.expectError(error.ReceiptClockReversed, owner.session.?.poll(1));
        try t.expectEqual(health.Phase.paused, gate.snapshot().phase);
        try t.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
        try t.expectEqual(@as(u64, 0), owner.session.?.processor.timeHealth().eligible);
        try t.expect(!owner.session.?.processor.in_flight);
        try t.expectEqual(@as(u64, 0), owner.session.?.sources.sources.items[0].acknowledgedCheckpoint().?.offset);
        clocks.wall = 1_000_000_000;
        clocks.monotonic = 1000;
        try t.expectEqual(recovery.Status.resumed, try driver.poll());
        try t.expectEqual(@as(usize, 1), try owner.session.?.poll(1));
        try t.expectEqual(@as(u64, 1), owner.session.?.processor.timeHealth().eligible);
        const value = (try store.nativeTime("ordinary", owner.session.?.sources.sources.items[0].source_id, null)).?.eligible;
        try t.expectEqual(@as(i64, 1_000_000_000), value.receipt.us);
        try t.expectEqual(@as(i64, 0), try store.pendingIntents());
    }
}

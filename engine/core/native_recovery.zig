// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Serialized recovery driver. A caught-up wall clock is necessary, not sufficient:
//! each recovery stage must succeed before the shared gate admits ingestion.
const durable = @import("record_store.zig");
const health = @import("storage_health.zig");
const pipeline = @import("record_pipeline.zig");

pub const Hooks = struct {
    context: ?*anyopaque,
    /// All hooks must finish their work before returning. Storage may reopen in
    /// place; restore must cover every owner, ownership must preserve deadlines,
    /// and sources must verify required anchors and pending record identities.
    storage: *const fn (?*anyopaque) anyerror!void,
    state: *const fn (?*anyopaque) anyerror!void,
    ownership: *const fn (?*anyopaque) anyerror!void,
    sources: *const fn (?*anyopaque) anyerror!void,
    /// Optional resumable coordinator path: one bounded slice per poll. False
    /// retains this exact stage/generation; no failure or new attempt is recorded.
    turn: ?*const fn (health.RecoveryStep, ?*anyopaque) anyerror!bool = null,
};
pub const Status = enum { healthy, waiting, resumed, intervention };
pub const Driver = struct {
    store: *durable.Store,
    gate: *health.Gate,
    clock: pipeline.ReceiptAdmission,
    hooks: Hooks,

    /// Call from the serialized storage worker/scheduler, not a signal handler
    /// or status-serving event loop. One attempt at most; no sleeps or spin loop.
    pub fn poll(self: *Driver) !Status {
        try self.gate.tick();
        const status = self.gate.snapshot();
        switch (status.phase) {
            .healthy => return .healthy,
            .intervention => return .intervention,
            .recovering => if (self.hooks.turn == null) return error.RecoveryInProgress,
            .paused => if (status.next_retry_ms.? > self.gate.last_clock_ms) return .waiting,
            .starting => {},
        }
        const generation = if (status.phase == .recovering) status.generation else try self.gate.beginRecovery();
        const complete = self.recover(generation) catch |failure| {
            // Clock checking already recorded its floor. Re-reporting preserves
            // the retry schedule and keeps any prior intervention latched.
            self.gate.failed(failure, if (failure == error.ReceiptClockReversed) .{} else .{
                .sqlite_code = self.store.last_error_code,
                .rollback_code = self.store.rollback_error_code,
                .reopen_required = self.store.reopen_required,
            });
            // A running daemon may retry a storage outage. Startup must refuse
            // unavailable/invalid persistence, per the separately approved policy.
            if (!status.has_been_healthy and failure != error.ReceiptClockReversed) return failure;
            return if (self.gate.snapshot().phase == .intervention) .intervention else .waiting;
        };
        return if (complete) .resumed else .waiting;
    }
    fn checkFloor(self: *Driver, floor: ?i64) !void {
        if (floor) |value| if ((try self.clock.clock(self.clock.clock_context)).us < value) {
            self.gate.receiptClockFailed(value);
            return error.ReceiptClockReversed;
        };
    }
    fn checkDurableClock(self: *Driver) !void {
        const floor = try self.store.admissionClock();
        try self.checkFloor(if (floor) |value| value.us else null);
    }
    fn recover(self: *Driver, generation: u64) !bool {
        // While the known boundary is still ahead, avoid repeated database and
        // source work. The monotonic gate supplies bounded retry and reminders.
        try self.checkFloor(self.gate.snapshot().receipt_clock_floor_us);
        if (self.hooks.turn) |turn| {
            const stage = self.gate.snapshot().recovery_step orelse return error.RecoveryOutOfOrder;
            if (stage != .storage) try self.checkDurableClock();
            if (!try turn(stage, self.hooks.context)) return false;
            try self.checkDurableClock();
            try self.gate.completed(generation, stage);
            return stage == .sources;
        }
        try self.hooks.storage(self.hooks.context);
        try self.gate.completed(generation, .storage);
        try self.checkDurableClock();
        try self.hooks.state(self.hooks.context);
        try self.gate.completed(generation, .state);
        try self.checkDurableClock();
        try self.hooks.ownership(self.hooks.context);
        try self.gate.completed(generation, .ownership);
        try self.hooks.sources(self.hooks.context);
        try self.checkDurableClock();
        try self.gate.completed(generation, .sources);
        return true;
    }
};

test "clock recovery: yielded stages keep one attempt and cannot admit sources early" {
    const std = @import("std");
    const t = std.testing;
    var temp = t.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(base);
    const path = try std.fs.path.join(t.allocator, &.{ base, "yield.sqlite" });
    defer t.allocator.free(path);
    var store = try durable.Store.open(t.allocator, path);
    defer store.close();
    try store.enableReceipts(4);
    try store.enableNativeTime();
    try store.enableDetection();
    try store.enableClockRecovery();
    const Fixture = struct {
        calls: [4]u8 = [_]u8{0} ** 4,
        fn monotonic(_: ?*anyopaque) u64 {
            return 100;
        }
        fn legacy(_: ?*anyopaque) !void {
            return error.UnexpectedLegacyRecovery;
        }
        fn turn(stage: health.RecoveryStep, ctx: ?*anyopaque) !bool {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            const index = @intFromEnum(stage);
            self.calls[index] += 1;
            for (self.calls[0..index]) |count| if (count != 2) return error.RecoveryOutOfOrder;
            return self.calls[index] == 2;
        }
    };
    var fixture = Fixture{};
    var gate = health.Gate.init(.{ .context = null, .read = Fixture.monotonic });
    var driver = Driver{ .store = &store, .gate = &gate, .clock = .{ .generation = [_]u8{0} ** 32 }, .hooks = .{ .context = &fixture, .storage = Fixture.legacy, .state = Fixture.legacy, .ownership = Fixture.legacy, .sources = Fixture.legacy, .turn = Fixture.turn } };
    for (0..7) |_| {
        try t.expectEqual(Status.waiting, try driver.poll());
        try t.expectError(error.StoragePaused, gate.admit(gate.snapshot().generation));
        try t.expectEqual(@as(u64, 1), gate.snapshot().recovery_attempts);
    }
    try t.expectEqual(Status.resumed, try driver.poll());
    try gate.admit(gate.snapshot().generation);
    try t.expectEqualSlices(u8, &.{ 2, 2, 2, 2 }, &fixture.calls);
}

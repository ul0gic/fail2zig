// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const durable = @import("record_store.zig");
const health = @import("storage_health.zig");
const pipeline = @import("record_pipeline.zig");

pub const Hooks = struct {
    context: ?*anyopaque,
    storage: *const fn (?*anyopaque) anyerror!void,
    state: *const fn (?*anyopaque) anyerror!void,
    ownership: *const fn (?*anyopaque) anyerror!void,
    sources: *const fn (?*anyopaque) anyerror!void,
    turn: ?*const fn (health.RecoveryStep, ?*anyopaque) anyerror!bool = null,
};
pub const Status = enum { healthy, waiting, resumed, intervention };
pub const Driver = struct {
    store: *durable.Store,
    gate: *health.Gate,
    clock: pipeline.ReceiptAdmission,
    hooks: Hooks,

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
            self.gate.failed(failure, if (failure == error.ReceiptClockReversed) .{} else .{
                .sqlite_code = self.store.last_error_code,
                .rollback_code = self.store.rollback_error_code,
                .reopen_required = self.store.reopen_required,
            });
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

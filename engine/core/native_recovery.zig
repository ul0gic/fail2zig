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
            .recovering => return error.RecoveryInProgress,
            .paused => if (status.next_retry_ms.? > self.gate.last_clock_ms) return .waiting,
            .starting => {},
        }
        const generation = try self.gate.beginRecovery();
        self.recover(generation) catch |failure| {
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
        return .resumed;
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
    fn recover(self: *Driver, generation: u64) !void {
        // While the known boundary is still ahead, avoid repeated database and
        // source work. The monotonic gate supplies bounded retry and reminders.
        try self.checkFloor(self.gate.snapshot().receipt_clock_floor_us);
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
    }
};

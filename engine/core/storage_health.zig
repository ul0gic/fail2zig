// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");

pub const diagnostic_stall_ms: u64 = 5000;
pub const WorkerStatus = struct {
    busy: bool,
    stalled: bool,
    clock_uncertain: bool,
    expiry_overdue: bool,
    expiry_uncertain: bool,
    busy_age_ms: u64,
    heartbeat_age_ms: u64,
    next_committed_expiry_us: ?i64,
};

pub const WorkerObservation = struct {
    busy: bool = false,
    busy_since_ms: u64 = 0,
    heartbeat_ms: u64 = 0,
    monotonic_floor_ms: u64 = 0,
    wall_floor_us: ?i64 = null,
    clock_uncertain: bool = false,
    expiry_authority_current: bool = false,
    next_committed_expiry_us: ?i64 = null,

    pub fn init(monotonic_ms: ?u64, wall_us: ?i64) WorkerObservation {
        var result: WorkerObservation = .{};
        _ = result.observe(monotonic_ms, wall_us);
        result.heartbeat_ms = result.monotonic_floor_ms;
        return result;
    }

    pub fn begin(self: *WorkerObservation, monotonic_ms: ?u64, wall_us: ?i64) void {
        _ = self.observe(monotonic_ms, wall_us);
        if (!self.busy) {
            self.busy_since_ms = self.monotonic_floor_ms;
            self.heartbeat_ms = self.monotonic_floor_ms;
            self.busy = true;
        }
    }

    pub fn complete(self: *WorkerObservation, monotonic_ms: ?u64, wall_us: ?i64) void {
        _ = self.observe(monotonic_ms, wall_us);
        self.heartbeat_ms = self.monotonic_floor_ms;
        self.busy = false;
    }

    pub fn publication(self: *WorkerObservation, monotonic_ms: ?u64, wall_us: ?i64, next_committed_expiry_us: ?i64, authority_current: bool) void {
        const clocks_valid = self.observe(monotonic_ms, wall_us);
        self.expiry_authority_current = authority_current and clocks_valid;
        if (self.expiry_authority_current) {
            self.next_committed_expiry_us = next_committed_expiry_us;
            self.clock_uncertain = false;
        }
    }

    pub fn read(self: *WorkerObservation, monotonic_ms: ?u64, wall_us: ?i64) WorkerStatus {
        _ = self.observe(monotonic_ms, wall_us);
        const busy_age = if (self.busy) self.monotonic_floor_ms -| self.busy_since_ms else 0;
        const heartbeat_age = self.monotonic_floor_ms -| self.heartbeat_ms;
        return .{
            .busy = self.busy,
            .stalled = heartbeat_age >= diagnostic_stall_ms or busy_age >= diagnostic_stall_ms,
            .clock_uncertain = self.clock_uncertain,
            .expiry_overdue = !self.clock_uncertain and if (self.next_committed_expiry_us) |deadline| self.wall_floor_us.? >= deadline else false,
            .expiry_uncertain = !self.expiry_authority_current or self.clock_uncertain,
            .busy_age_ms = busy_age,
            .heartbeat_age_ms = heartbeat_age,
            .next_committed_expiry_us = self.next_committed_expiry_us,
        };
    }

    fn observe(self: *WorkerObservation, monotonic_ms: ?u64, wall_us: ?i64) bool {
        var valid = true;
        if (monotonic_ms) |now| {
            if (now < self.monotonic_floor_ms) valid = false else self.monotonic_floor_ms = now;
        } else valid = false;
        if (wall_us) |now| {
            if (self.wall_floor_us) |floor| {
                if (now < floor) valid = false else self.wall_floor_us = now;
            } else self.wall_floor_us = now;
        } else valid = false;
        if (!valid) self.clock_uncertain = true;
        return valid;
    }
};

pub const Clock = struct {
    context: ?*anyopaque,
    read: *const fn (?*anyopaque) u64,
};

pub const MaintenanceOperation = enum { history_rebuild, history_details, history_prefix, retry_details, spent_scopes, obsolete_rows };
pub const MaintenanceOutcome = union(enum) {
    progress: MaintenanceOperation,
    wait: MaintenanceOperation,
    idle,
};

pub const Fairness = struct {
    pub const maintenance_interval_ms: u64 = 250;
    last_maintenance_ms: ?u64 = null,

    pub fn maintenanceDue(self: *const Fairness, now_ms: u64) bool {
        const last = self.last_maintenance_ms orelse return true;
        return now_ms -| last >= maintenance_interval_ms;
    }
    pub fn maintained(self: *Fairness, now_ms: u64) void {
        self.last_maintenance_ms = now_ms;
    }
};

pub const Phase = enum { starting, healthy, paused, recovering, intervention };
pub const RecoveryStep = enum { storage, state, ownership, sources };
pub const Diagnostics = struct {
    sqlite_code: ?c_int = null,
    rollback_code: ?c_int = null,
    reopen_required: bool = false,
    operation: ?MaintenanceOperation = null,
};
pub const Failure = struct {
    cause: anyerror,
    diagnostics: Diagnostics,
    at_ms: u64,
};
pub const Snapshot = struct {
    phase: Phase,
    recovery_step: ?RecoveryStep,
    generation: u64,
    first_failure: ?Failure,
    last_failure: ?Failure,
    next_retry_ms: ?u64,
    retry_delay_ms: u32,
    recovery_attempts: u64,
    last_commit_ms: ?u64,
    committed_records: u64,
    notice_sequence: u64,
    receipt_clock_floor_us: ?i64 = null,
    has_been_healthy: bool = false,
};

pub const Gate = struct {
    clock: Clock,
    state: Snapshot = .{
        .phase = .starting,
        .recovery_step = null,
        .generation = 0,
        .first_failure = null,
        .last_failure = null,
        .next_retry_ms = null,
        .retry_delay_ms = 1000,
        .recovery_attempts = 0,
        .last_commit_ms = null,
        .committed_records = 0,
        .notice_sequence = 0,
    },
    last_clock_ms: u64 = 0,
    last_notice_ms: u64 = 0,

    pub fn init(clock: Clock) Gate {
        return .{ .clock = clock, .last_clock_ms = clock.read(clock.context) };
    }

    pub fn snapshot(self: *const Gate) Snapshot {
        return self.state;
    }

    fn notice(self: *Gate, at: u64) void {
        self.state.notice_sequence +|= 1;
        self.last_notice_ms = at;
    }

    fn now(self: *Gate) !u64 {
        const value = self.clock.read(self.clock.context);
        if (value < self.last_clock_ms) {
            self.failAt(error.MonotonicClockReversed, .{}, self.last_clock_ms);
            return error.MonotonicClockReversed;
        }
        self.last_clock_ms = value;
        return value;
    }

    pub fn admit(self: *const Gate, generation: u64) !void {
        if (self.state.phase != .healthy) return error.StoragePaused;
        if (generation != self.state.generation) return error.RestoreRequired;
    }

    pub fn admitMutation(self: *const Gate) !void {
        if (self.state.phase != .healthy) return error.PersistenceUnavailable;
    }

    pub fn failed(self: *Gate, cause: anyerror, diagnostics: Diagnostics) void {
        const at = self.now() catch return;
        self.failAt(cause, diagnostics, at);
    }

    pub fn receiptClockFailed(self: *Gate, floor_us: i64) void {
        self.state.receipt_clock_floor_us = if (self.state.receipt_clock_floor_us) |old| @max(old, floor_us) else floor_us;
        self.failed(error.ReceiptClockReversed, .{});
    }

    fn failAt(self: *Gate, cause: anyerror, diagnostics: Diagnostics, at: u64) void {
        const failure = Failure{ .cause = cause, .diagnostics = diagnostics, .at_ms = at };
        if (self.state.first_failure == null) self.state.first_failure = failure;
        self.state.last_failure = failure;
        const next: Phase = if (self.state.phase == .intervention or !retryable(cause)) .intervention else .paused;
        const changed = self.state.phase != next;
        self.state.phase = next;
        self.state.recovery_step = null;
        self.state.next_retry_ms = if (next == .paused) at +| self.state.retry_delay_ms else null;
        if (changed or self.state.notice_sequence == 0) self.notice(at);
    }

    pub fn tick(self: *Gate) !void {
        const at = try self.now();
        if (self.state.phase != .healthy and self.state.phase != .starting and at - self.last_notice_ms >= 60_000)
            self.notice(at);
    }

    pub fn requestRebuild(self: *Gate) !void {
        const at = try self.now();
        if (self.state.phase != .healthy) return error.RebuildNotAllowed;
        self.state.phase = .paused;
        self.state.recovery_step = null;
        self.state.next_retry_ms = at;
        self.notice(at);
    }

    pub fn beginRecovery(self: *Gate) !u64 {
        const at = try self.now();
        switch (self.state.phase) {
            .starting => {},
            .paused => if (at < self.state.next_retry_ms.?) return error.RetryNotDue,
            .intervention => return error.InterventionRequired,
            .healthy, .recovering => return error.RecoveryNotAllowed,
        }
        self.state.generation = std.math.add(u64, self.state.generation, 1) catch {
            self.failAt(error.GenerationExhausted, .{}, at);
            return error.GenerationExhausted;
        };
        if (self.state.phase == .paused) self.state.retry_delay_ms = @min(self.state.retry_delay_ms * 2, 30_000);
        self.state.phase = .recovering;
        self.state.recovery_step = .storage;
        self.state.next_retry_ms = null;
        self.state.recovery_attempts +|= 1;
        self.notice(at);
        return self.state.generation;
    }

    pub fn completed(self: *Gate, generation: u64, step: RecoveryStep) !void {
        const at = try self.now();
        if (self.state.phase != .recovering or generation != self.state.generation) return error.StaleRecovery;
        if (self.state.recovery_step != step) return error.RecoveryOutOfOrder;
        self.state.recovery_step = switch (step) {
            .storage => .state,
            .state => .ownership,
            .ownership => .sources,
            .sources => null,
        };
        if (step == .sources) {
            self.state.phase = .healthy;
            self.state.has_been_healthy = true;
            self.state.first_failure = null;
            self.state.last_failure = null;
            self.state.retry_delay_ms = 1000;
            self.state.receipt_clock_floor_us = null;
        }
        self.notice(at);
    }

    pub fn committed(self: *Gate) void {
        const at = self.now() catch return;
        self.state.last_commit_ms = at;
        self.state.committed_records +|= 1;
    }
};

fn retryable(cause: anyerror) bool {
    return switch (cause) {
        error.Busy,
        error.StorageFull,
        error.ReadOnly,
        error.StorageIo,
        error.OpenFailed,
        error.AccessDenied,
        error.OutOfMemory,
        error.ReopenRequired,
        error.StaleCheckpoint,
        error.StaleSharedCheckpoint,
        error.StaleConsumerCheckpoint,
        error.StaleMaintenance,
        error.RestoreRequired,
        error.ConcurrentWriter,
        error.ReceiptClockReversed,
        error.EffectClockReversed,
        error.EffectBackendUncertain,
        error.StaleEffect,
        error.EffectReconciliationRequired,
        // Source-scoped backpressure that expiry and retirement clear; never latches intervention.
        error.ReserveBackpressure,
        error.RetryCapacity,
        => true,
        else => false,
    };
}

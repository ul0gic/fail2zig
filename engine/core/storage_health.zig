// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! One allocation-free admission gate per durable store. The coordinator owns
//! this value and serializes access; status readers receive a detached Snapshot.
//! A successful write probe alone never authorizes ingestion after a failure.
const std = @import("std");

pub const Clock = struct {
    context: ?*anyopaque,
    /// Milliseconds from a monotonic clock, shared with the coordinator scheduler.
    read: *const fn (?*anyopaque) u64,
};
pub const Phase = enum { starting, healthy, paused, recovering, intervention };
pub const RecoveryStep = enum { storage, state, ownership, sources };
pub const Diagnostics = struct {
    sqlite_code: ?c_int = null,
    rollback_code: ?c_int = null,
    reopen_required: bool = false,
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
    /// Changes only for a state transition or a bounded periodic reminder.
    notice_sequence: u64,
    /// Independent clock-fault detail; keep until validated recovery completes.
    /// Epoch microseconds, never compared with this gate's monotonic scheduler.
    receipt_clock_floor_us: ?i64 = null,
    /// A clock wait during startup does not convert startup storage failures
    /// into runtime retries. Set only after every recovery stage succeeds.
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

    /// No database access, allocations, source text or dynamically owned strings.
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

    /// Administrative mutations which require persistence use this same gate.
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
        // Intervention remains latched. Another source cannot turn corruption
        // into an automatically retryable condition by reporting a later error.
        const next: Phase = if (self.state.phase == .intervention or !retryable(cause)) .intervention else .paused;
        const changed = self.state.phase != next;
        self.state.phase = next;
        self.state.recovery_step = null;
        self.state.next_retry_ms = if (next == .paused) at +| self.state.retry_delay_ms else null;
        if (changed or self.state.notice_sequence == 0) self.notice(at);
    }

    /// Called by the scheduler, never once per input record. A notice sequence
    /// lets logging/status consumers report transitions without repeated alerts.
    pub fn tick(self: *Gate) !void {
        const at = try self.now();
        if (self.state.phase != .healthy and self.state.phase != .starting and at - self.last_notice_ms >= 60_000)
            self.notice(at);
    }

    /// Startup may wait for a reversed wall clock; the caller must propagate
    /// other startup failures and refuse activation. Runtime retries start at 1s.
    /// Intervention needs operator repair/restart, not a timer-driven reset.
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

    /// Each operation must actually finish successfully before its completion
    /// is supplied. The generation rejects completions from a previous attempt.
    /// State includes committed configuration/revisions; ownership includes
    /// uncertain effects/expiry; sources includes each required recovery anchor.
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
        // Called only after a durable commit and infallible publication. A clock
        // failure still pauses future work; it cannot undo this committed record.
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
        error.RestoreRequired,
        error.ConcurrentWriter,
        error.ReceiptClockReversed,
        => true,
        // Invalid state, unknown schema, unsupported resource requirements and
        // unknown errors need intervention. Retrying the same deterministic work
        // indefinitely is not recovery. Test faults likewise require a restart.
        else => false,
    };
}

const TestClock = struct {
    value: u64 = 0,
    fn read(context: ?*anyopaque) u64 {
        const self: *TestClock = @ptrCast(@alignCast(context.?));
        return self.value;
    }
    fn clock(self: *TestClock) Clock {
        return .{ .context = self, .read = read };
    }
};

test "storage health: recovery requires ordered current evidence and all admission remains closed" {
    var clock = TestClock{};
    var gate = Gate.init(clock.clock());
    try std.testing.expectError(error.StoragePaused, gate.admit(0));
    const initial = try gate.beginRecovery();
    try std.testing.expectError(error.RecoveryOutOfOrder, gate.completed(initial, .sources));
    for ([_]RecoveryStep{ .storage, .state, .ownership }) |step| {
        try gate.completed(initial, step);
        try std.testing.expectError(error.StoragePaused, gate.admit(initial));
        try std.testing.expectError(error.PersistenceUnavailable, gate.admitMutation());
    }
    try gate.completed(initial, .sources);
    try gate.admit(initial);
    try gate.admitMutation();
    clock.value = 42;
    gate.committed();
    gate.failed(error.StorageFull, .{ .sqlite_code = 13 });
    const failure = gate.snapshot();
    try std.testing.expectEqual(Phase.paused, failure.phase);
    try std.testing.expectEqual(@as(?u64, 42), failure.last_commit_ms);
    try std.testing.expectEqual(@as(u64, 1), failure.committed_records);
    try std.testing.expectEqual(@as(?c_int, 13), failure.first_failure.?.diagnostics.sqlite_code);
    try std.testing.expectEqual(@as(?u64, 1042), failure.next_retry_ms);
    try std.testing.expectError(error.RetryNotDue, gate.beginRecovery());
    clock.value = 1042;
    const next = try gate.beginRecovery();
    try std.testing.expectError(error.StaleRecovery, gate.completed(initial, .storage));
    for ([_]RecoveryStep{ .storage, .state, .ownership, .sources }) |step| try gate.completed(next, step);
    try std.testing.expectError(error.RestoreRequired, gate.admit(initial));
    try gate.admit(next);
    try std.testing.expectEqual(@as(u32, 1000), gate.snapshot().retry_delay_ms);
    try std.testing.expect(gate.snapshot().first_failure == null);
}

test "storage health: retries cap at thirty seconds and diagnostics remain bounded" {
    var clock = TestClock{};
    var gate = Gate.init(clock.clock());
    _ = try gate.beginRecovery();
    gate.failed(error.Busy, .{ .sqlite_code = 5 });
    for ([_]u32{ 1000, 2000, 4000, 8000, 16000, 30000, 30000 }) |delay| {
        const before = gate.snapshot();
        try std.testing.expectEqual(delay, before.retry_delay_ms);
        clock.value = before.next_retry_ms.? - 1;
        try std.testing.expectError(error.RetryNotDue, gate.beginRecovery());
        clock.value += 1;
        _ = try gate.beginRecovery();
        gate.failed(error.StorageIo, .{ .sqlite_code = 778, .rollback_code = 10, .reopen_required = true });
    }
    const saved = gate.snapshot();
    try std.testing.expectEqual(error.Busy, saved.first_failure.?.cause);
    try std.testing.expectEqual(error.StorageIo, saved.last_failure.?.cause);
    try std.testing.expect(saved.last_failure.?.diagnostics.reopen_required);
    clock.value += 59_999;
    try gate.tick();
    try std.testing.expectEqual(saved.notice_sequence, gate.snapshot().notice_sequence);
    clock.value += 1;
    try gate.tick();
    try std.testing.expectEqual(saved.notice_sequence + 1, gate.snapshot().notice_sequence);
    for (0..100) |_| try gate.tick();
    try std.testing.expectEqual(saved.notice_sequence + 1, gate.snapshot().notice_sequence);
}

test "storage health: corruption and continuity loss latch intervention without reset" {
    for ([_]anyerror{ error.CorruptDatabase, error.UnsupportedSchema, error.ForeignDatabase, error.InvalidCheckpoint, error.ResumeLost, error.StorageLimit, error.Interrupted }) |cause| {
        var clock = TestClock{};
        var gate = Gate.init(clock.clock());
        const token = try gate.beginRecovery();
        gate.failed(cause, .{});
        gate.failed(error.Busy, .{});
        clock.value = 1_000_000;
        try std.testing.expectEqual(Phase.intervention, gate.snapshot().phase);
        try std.testing.expectEqual(cause, gate.snapshot().first_failure.?.cause);
        try std.testing.expect(gate.snapshot().next_retry_ms == null);
        try std.testing.expectError(error.InterventionRequired, gate.beginRecovery());
        try std.testing.expectError(error.StaleRecovery, gate.completed(token, .storage));
    }
}

test "storage health: reversed monotonic clock blocks recovery" {
    var clock = TestClock{ .value = 50 };
    var gate = Gate.init(clock.clock());
    _ = try gate.beginRecovery();
    clock.value = 49;
    try std.testing.expectError(error.MonotonicClockReversed, gate.tick());
    try std.testing.expectEqual(Phase.intervention, gate.snapshot().phase);
    try std.testing.expectEqual(error.MonotonicClockReversed, gate.snapshot().first_failure.?.cause);
}

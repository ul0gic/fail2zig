// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Source-local repair scheduling. The coordinator owns one value per source;
//! shared storage failures fence it without consuming a source retry attempt.
const std = @import("std");

pub const Phase = enum { healthy, waiting, verifying, polling, intervention };
pub const Domain = enum { transient_source, source_intervention, storage, pending };

/// Classify only after the caller has identified the failing subsystem. An
/// AccessDenied from SQLite is a storage fault, not a source-file permission fault.
pub fn classify(cause: anyerror) Domain {
    return switch (cause) {
        error.Busy,
        error.StorageFull,
        error.ReadOnly,
        error.StorageIo,
        error.ReopenRequired,
        error.StaleCheckpoint,
        error.StaleSharedCheckpoint,
        error.StaleConsumerCheckpoint,
        error.ConsumerClockReversed,
        error.ConcurrentWriter,
        error.CorruptDatabase,
        error.UnsupportedSchema,
        error.ForeignDatabase,
        error.ReceiptClockReversed,
        error.StoragePaused,
        error.PersistenceUnavailable,
        => .storage,
        error.SourceRepairPending, error.ConsumerPending, error.ConsumerExpired, error.EffectExpired => .pending,
        error.FileNotFound,
        error.AccessDenied,
        error.InputOutput,
        error.JournalTimeout,
        error.JournalChildFailed,
        error.SourceChanged,
        => .transient_source,
        else => .source_intervention,
    };
}

/// An immutable source/configuration binding. Pending identity hashes are made
/// from length-delimited full identity fields, never from cursor text ordering.
pub const Binding = struct {
    generation: [32]u8,
    source_digest: [32]u8,
    pending_digest: ?[32]u8 = null,
    receipt_us: ?i64 = null,

    pub fn init(generation: [32]u8, source: []const u8) !Binding {
        if (source.len == 0 or source.len > 16 * 1024) return error.InvalidRepairBinding;
        return .{ .generation = generation, .source_digest = digest(&.{source}) };
    }

    pub fn withPending(self: Binding, occurrence: []const u8, cursor: []const u8, raw_hash: [32]u8, receipt_us: i64) !Binding {
        if (occurrence.len == 0 or occurrence.len > 16 * 1024 or cursor.len == 0 or cursor.len > 64 * 1024) return error.InvalidRepairBinding;
        var result = self;
        result.pending_digest = digest(&.{ &self.generation, &self.source_digest, occurrence, cursor, &raw_hash });
        result.receipt_us = receipt_us;
        return result;
    }

    fn digest(parts: []const []const u8) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("fail2zig-source-repair-v1\x00");
        for (parts) |part| {
            var length: [8]u8 = undefined;
            std.mem.writeInt(u64, &length, part.len, .little);
            hash.update(&length);
            hash.update(part);
        }
        var result: [32]u8 = undefined;
        hash.final(&result);
        return result;
    }

    fn tokenIdentity(self: Binding) [32]u8 {
        const present = [_]u8{@intFromBool(self.pending_digest != null)};
        const pending = self.pending_digest orelse [_]u8{0} ** 32;
        var receipt: [8]u8 = undefined;
        std.mem.writeInt(i64, &receipt, self.receipt_us orelse 0, .little);
        return digest(&.{ &self.generation, &self.source_digest, &present, &pending, &receipt });
    }
};

pub const Token = struct { serial: u64, binding_digest: [32]u8 };
pub const Snapshot = struct {
    phase: Phase = .healthy,
    attempts: u8 = 0,
    first_cause: ?anyerror = null,
    last_cause: ?anyerror = null,
    next_retry_ms: ?u64 = null,
};

pub const Repair = struct {
    pub const max_attempts: u8 = 12;
    binding: Binding,
    state: Snapshot = .{},
    serial: u64 = 0,
    last_now_ms: u64,

    pub fn init(binding: Binding, now_ms: u64) !Repair {
        if ((binding.pending_digest != null) != (binding.receipt_us != null)) return error.InvalidRepairBinding;
        return .{ .binding = binding, .last_now_ms = now_ms };
    }

    /// Healthy polling may create/resolve a pending receipt. Preserve episode
    /// serials and immutable source/generation identity when updating that proof.
    pub fn bindHealthy(self: *Repair, binding: Binding) !void {
        if (self.state.phase != .healthy) return error.StaleRepair;
        if (!std.mem.eql(u8, &binding.generation, &self.binding.generation) or
            !std.mem.eql(u8, &binding.source_digest, &self.binding.source_digest) or
            ((binding.pending_digest != null) != (binding.receipt_us != null))) return error.InvalidRepairBinding;
        self.binding = binding;
    }

    /// Caller has verified the exact immutable committed receipt, including
    /// original timestamp. Absence of a pending row alone is never sufficient.
    /// Preserve the episode/deadline; subsequent continuity and poll still gate reset.
    pub fn resolveCommittedPending(self: *Repair, expected: Binding) !void {
        if (self.binding.pending_digest == null or !std.meta.eql(self.binding, expected)) return error.PendingRecordMismatch;
        self.binding.pending_digest = null;
        self.binding.receipt_us = null;
    }

    pub fn snapshot(self: *const Repair) Snapshot {
        return self.state;
    }

    fn observeClock(self: *Repair, now_ms: u64) !void {
        if (now_ms < self.last_now_ms) {
            self.intervene(error.MonotonicClockReversed);
            return error.MonotonicClockReversed;
        }
        self.last_now_ms = now_ms;
    }

    fn intervene(self: *Repair, cause: anyerror) void {
        if (self.state.first_cause == null) self.state.first_cause = cause;
        self.state.last_cause = cause;
        self.state.phase = .intervention;
        self.state.next_retry_ms = null;
    }

    /// A fenced storage failure or a yielded scan does not alter this episode.
    /// OOM/capacity and unknown deterministic errors require intervention rather
    /// than an endless retry loop. The store gate owns global OOM policy.
    pub fn failed(self: *Repair, cause: anyerror, now_ms: u64) !Domain {
        const domain = classify(cause);
        if (domain == .storage or domain == .pending) return domain;
        try self.observeClock(now_ms);
        if (self.state.phase == .intervention) return .source_intervention;
        if (domain == .source_intervention or self.state.attempts >= max_attempts) {
            self.intervene(cause);
            return .source_intervention;
        }
        if (self.state.first_cause == null) self.state.first_cause = cause;
        self.state.last_cause = cause;
        // Repeated reports while waiting cannot postpone the existing deadline.
        if (self.state.phase != .waiting) {
            const delays = [_]u32{ 1000, 2000, 4000, 8000, 16000, 30000 };
            const delay = delays[@min(self.state.attempts, delays.len - 1)];
            self.state.next_retry_ms = std.math.add(u64, now_ms, delay) catch {
                self.intervene(error.RepairClockExhausted);
                return error.RepairClockExhausted;
            };
        }
        self.state.phase = .waiting;
        return domain;
    }

    /// Returns null while fenced/not due. No sleeps, I/O, allocations or cursor
    /// changes. A pending turn retains its token until verification completes.
    pub fn begin(self: *Repair, now_ms: u64, storage_available: bool) !?Token {
        if (!storage_available) return null;
        try self.observeClock(now_ms);
        switch (self.state.phase) {
            .healthy => return null,
            .intervention => return error.SourceInterventionRequired,
            .verifying, .polling => return self.currentToken(),
            .waiting => if (now_ms < self.state.next_retry_ms.?) return null,
        }
        if (self.state.attempts >= max_attempts) return error.SourceInterventionRequired;
        self.serial = std.math.add(u64, self.serial, 1) catch {
            self.intervene(error.RepairGenerationExhausted);
            return error.RepairGenerationExhausted;
        };
        self.state.attempts += 1;
        self.state.phase = .verifying;
        self.state.next_retry_ms = null;
        return self.currentToken();
    }

    fn currentToken(self: *const Repair) Token {
        return .{ .serial = self.serial, .binding_digest = self.binding.tokenIdentity() };
    }

    fn check(self: *const Repair, token: Token, phase: Phase) !void {
        if (!std.meta.eql(token, self.currentToken()) or self.state.phase != phase) return error.StaleRepair;
    }

    pub fn continuityVerified(self: *Repair, token: Token, observed: Binding) !void {
        try self.check(token, .verifying);
        if (!std.meta.eql(self.binding, observed)) {
            self.intervene(error.PendingRecordMismatch);
            return error.PendingRecordMismatch;
        }
        self.state.phase = .polling;
    }

    /// Ignore completion from an older helper/repair attempt. Initial source
    /// failures use failed(); asynchronous attempt results use this token gate.
    pub fn attemptFailed(self: *Repair, token: Token, cause: anyerror, now_ms: u64) !Domain {
        if (!std.meta.eql(token, self.currentToken()) or (self.state.phase != .verifying and self.state.phase != .polling)) return error.StaleRepair;
        return self.failed(cause, now_ms);
    }

    /// Call only after a successful bounded poll/disposition, including proven
    /// healthy EOF. Intermediate opens/anchor checks never reach this method.
    pub fn pollSucceeded(self: *Repair, token: Token) !void {
        try self.check(token, .polling);
        self.state = .{};
    }
};

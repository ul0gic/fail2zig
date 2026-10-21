// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const records = @import("source_record.zig");
const durable = @import("record_store.zig");
const health = @import("storage_health.zig");
const time = @import("native_time.zig");

pub const ReceiptAdmission = struct {
    generation: [32]u8,
    clock_context: ?*anyopaque = null,
    clock: *const fn (?*anyopaque) anyerror!time.Timestamp = systemClock,

    fn systemClock(_: ?*anyopaque) !time.Timestamp {
        return .{ .us = std.time.microTimestamp() };
    }
};
const CandidateReceipt = struct { identity: [32]u8, time: time.Timestamp };

pub const Prepared = struct {
    checkpoint: []const u8,
    disposition: []const u8,
    event_time: ?f64 = null,
    native_time: ?@import("source_time_policy.zig").Result = null,
    zone_provenance: ?@import("native_time_record.zig").Provenance = null,
    effects_clock: ?@import("native_effect.zig").Clock = null,
    native_detection: ?@import("native_detection_record.zig").Outcome = null,
    native_detections: ?[]const @import("native_detection_record.zig").Outcome = null,
    native_retry: ?@import("native_retry.zig").Admission = null,
    retry_suspended: bool = false,
    retry_evidence: @import("native_retry.zig").Evidence = .{},
    intent: ?[]const u8 = null,
    shared_state: ?durable.SharedState = null,
    consumers: ?@import("native_consumer.zig").Batch = null,
    consumer_manifest: ?@import("native_consumer.zig").Manifest = null,
    context: ?*anyopaque,
    publish: *const fn (?*anyopaque) void,
    release: *const fn (?*anyopaque) void,
};
pub const Restored = struct {
    context: ?*anyopaque,
    publish: *const fn (?*anyopaque) void,
    release: *const fn (?*anyopaque) void,
};
pub const Processor = struct {
    context: ?*anyopaque,
    prepare: *const fn (records.Record, ?*anyopaque) anyerror!Prepared,
    prepare_restore: *const fn (?[]const u8, ?*anyopaque) anyerror!Restored,
};
pub const Pipeline = struct {
    store: *durable.Store,
    jail: []const u8,
    processor: Processor,
    ready: bool = false,
    revision: u64 = 0,
    gate: ?*health.Gate = null,
    recovery_generation: u64 = 0,
    receipts: ?ReceiptAdmission = null,
    candidate_receipt: ?CandidateReceipt = null,

    pub fn admit(self: *Pipeline) !void {
        if (self.gate) |gate| try gate.admit(self.recovery_generation);
        if (!self.ready) return error.RestoreRequired;
        if (self.store.schema_version >= 7) if (self.receipts) |admission| {
            const floor = self.store.admissionClock() catch |failure| {
                self.failed(failure);
                return failure;
            };
            if (floor) |value| if ((try admission.clock(admission.clock_context)).us < value.us) {
                self.receiptClockFailed(value.us);
                return error.ReceiptClockReversed;
            };
        };
    }

    pub fn receiptClockFailed(self: *Pipeline, floor_us: i64) void {
        self.ready = false;
        if (self.gate) |gate| gate.receiptClockFailed(floor_us);
    }

    fn failed(self: *Pipeline, cause: anyerror) void {
        if (cause == error.ConsumerExpired or cause == error.ConsumerPending or cause == error.EffectExpired or cause == error.ReserveBackpressure or cause == error.RetryCapacity) return;
        if (cause == error.EffectClockReversed) {
            const floor = self.store.admissionClock() catch {
                self.ready = false;
                if (self.gate) |gate| gate.failed(cause, .{});
                return;
            };
            self.receiptClockFailed(if (floor) |value| value.us else std.time.microTimestamp());
            return;
        }
        if (cause == error.ConsumerClockReversed) {
            const floor = self.store.consumer_clock_floor_us orelse {
                self.ready = false;
                if (self.gate) |gate| gate.failed(error.InvalidConsumer, .{});
                return;
            };
            self.receiptClockFailed(floor);
            return;
        }
        if (sourceLocalIntervention(cause)) return;
        if (cause == error.ReceiptConflict) {
            self.ready = false;
            return;
        }
        if (self.gate) |gate| {
            self.ready = false;
            gate.failed(cause, .{
                .sqlite_code = self.store.last_error_code,
                .rollback_code = self.store.rollback_error_code,
                .reopen_required = self.store.reopen_required,
            });
        }
    }

    fn beginDiagnostics(self: *Pipeline) void {
        if (!self.store.reopen_required) {
            self.store.last_error_code = null;
            self.store.rollback_error_code = null;
        }
    }

    pub fn restore(self: *Pipeline, allocator: std.mem.Allocator) anyerror!void {
        self.ready = false;
        if (self.gate) |gate| {
            const status = gate.snapshot();
            if (status.phase != .recovering or status.recovery_step != .state) return error.RecoveryOutOfOrder;
        }
        self.beginDiagnostics();
        self.restoreCommitted(allocator) catch |failure| {
            self.failed(failure);
            return failure;
        };
    }

    fn restoreCommitted(self: *Pipeline, allocator: std.mem.Allocator) !void {
        if (self.receipts) |admission| try self.store.validateReceiptGeneration(self.jail, admission.generation);
        const checkpoint = try self.store.snapshot(allocator, self.jail);
        defer checkpoint.deinit(allocator);
        const staged = try self.processor.prepare_restore(checkpoint.payload, self.processor.context);
        defer staged.release(staged.context);
        if (try self.store.revision(self.jail) != checkpoint.revision) return error.StaleCheckpoint;
        staged.publish(staged.context);
        self.revision = checkpoint.revision;
        if (self.gate) |gate| self.recovery_generation = gate.snapshot().generation;
        self.ready = true;
    }

    pub fn commitBlocked(cause: anyerror) bool {
        return cause == error.ReserveBackpressure or cause == error.RetryCapacity;
    }

    pub fn sourceLocalIntervention(cause: anyerror) bool {
        return cause == error.PrunedReplay or cause == error.OutsideTimezoneCoverage;
    }

    pub fn acknowledge(record: records.Record, context: ?*anyopaque) anyerror!void {
        const self: *Pipeline = @ptrCast(@alignCast(context orelse return error.MissingPipeline));
        try self.admit();
        self.beginDiagnostics();
        self.acknowledgeAdmitted(record) catch |failure| {
            if (self.gate != null and failure != error.ConsumerExpired and failure != error.ConsumerPending and failure != error.EffectExpired and failure != error.ReserveBackpressure and failure != error.RetryCapacity and !sourceLocalIntervention(failure)) self.ready = false;
            return failure;
        };
    }

    fn acknowledgeAdmitted(self: *Pipeline, record: records.Record) !void {
        const exists = self.store.hasRecord(self.jail, record.source, record.occurrence, record.raw_hash, record.cursor) catch |failure| {
            self.failed(failure);
            return failure;
        };
        if (exists) {
            if (self.receipts) |admission| if (record.kind == .data) {
                const saved = self.store.committedReceipt(self.receiptIdentity(record, admission)) catch |failure| {
                    self.failed(failure);
                    return failure;
                };
                if (saved == null) {
                    self.failed(error.RestoreRequired);
                    return error.RestoreRequired;
                }
            };
            const revision = self.store.revision(self.jail) catch |failure| {
                self.failed(failure);
                return failure;
            };
            if (revision != self.revision) {
                self.ready = false;
                self.failed(error.RestoreRequired);
                return error.RestoreRequired;
            }
            if (self.receipts) |admission| if (self.candidate_receipt) |candidate| {
                if (std.mem.eql(u8, &candidate.identity, &receiptKey(self.receiptIdentity(record, admission)))) self.candidate_receipt = null;
            };
            return;
        }
        var observed = record;
        var receipt: ?durable.Receipt = null;
        if (self.receipts) |admission| if (record.kind == .data) {
            const identity = self.receiptIdentity(record, admission);
            const key = receiptKey(identity);
            if (self.candidate_receipt) |candidate| {
                if (!std.mem.eql(u8, &candidate.identity, &key)) return error.ReceiptRetryRequired;
            } else self.candidate_receipt = .{ .identity = key, .time = try admission.clock(admission.clock_context) };
            const saved = self.store.beginReceipt(identity, self.candidate_receipt.?.time, self.revision) catch |failure| {
                const cause = if (failure == error.ReceiptAlreadyCommitted) error.ConcurrentWriter else failure;
                self.failed(cause);
                return cause;
            };
            self.candidate_receipt = null;
            observed.receipt_time = saved;
            receipt = .{ .time = saved, .generation = admission.generation };
            try self.admit();
        };
        const prepared = self.processor.prepare(observed, self.processor.context) catch |failure| {
            if (failure == error.ReceiptClockReversed) if (observed.receipt_time) |saved| self.receiptClockFailed(saved.us);
            return failure;
        };
        defer prepared.release(prepared.context);
        try self.admit();
        const result = self.store.commitRecord(.{
            .jail = self.jail,
            .source = record.source,
            .source_path = record.source_path,
            .occurrence = record.occurrence,
            .cursor = record.cursor,
            .raw_hash = record.raw_hash,
            .event_time = prepared.event_time,
            .timestamp_us = record.timestamp_us,
            .receipt = receipt,
            .native_time_outcome = prepared.native_time,
            .zone_provenance = prepared.zone_provenance,
            .effects_clock = prepared.effects_clock,
            .native_detection = prepared.native_detection,
            .native_detections = prepared.native_detections,
            .native_retry = prepared.native_retry,
            .retry_suspended = prepared.retry_suspended,
            .retry_evidence = prepared.retry_evidence,
            .expected_revision = self.revision,
            .disposition = prepared.disposition,
            .checkpoint = prepared.checkpoint,
            .action_intent = prepared.intent,
            .shared_state = prepared.shared_state,
            .consumers = prepared.consumers,
            .consumer_manifest = prepared.consumer_manifest,
        }) catch |err| {
            if (err == error.StaleCheckpoint or err == error.StaleSharedCheckpoint or err == error.StaleConsumerCheckpoint) self.ready = false;
            self.failed(err);
            return err;
        };
        if (result == .already_committed) {
            self.ready = false;
            self.failed(error.ConcurrentWriter);
            return error.ConcurrentWriter;
        }
        self.revision += 1;
        prepared.publish(prepared.context);
        if (self.gate) |gate| gate.committed();
    }

    fn receiptIdentity(self: *const Pipeline, record: records.Record, admission: ReceiptAdmission) durable.ReceiptIdentity {
        return .{ .jail = self.jail, .source = record.source, .occurrence = record.occurrence, .cursor = record.cursor, .raw_hash = record.raw_hash, .generation = admission.generation };
    }

    fn receiptKey(identity: durable.ReceiptIdentity) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("fail2zig-receipt-candidate-v1\x00");
        for ([_][]const u8{ identity.jail, identity.source, identity.occurrence, identity.cursor, &identity.raw_hash, &identity.generation }) |part| {
            var length: [8]u8 = undefined;
            std.mem.writeInt(u64, &length, part.len, .little);
            hash.update(&length);
            hash.update(part);
        }
        var result: [32]u8 = undefined;
        hash.final(&result);
        return result;
    }
};

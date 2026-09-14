// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Native journal receipt/checkpoint owner. Fresh tail or empty-time baselines
//! commit explicitly; saved opaque cursors require an exact inclusive anchor.
const std = @import("std");
const transport = @import("native_journal_transport.zig");
const native = @import("native_source_processor.zig");
const pipeline = @import("record_pipeline.zig");
const durable = @import("record_store.zig");
const records = @import("source_record.zig");
const time = @import("native_time.zig");
const health = @import("storage_health.zig");
const repair = @import("source_repair.zig");
pub const checkpoint_bytes = 560;
const Position = struct {
    generation: [32]u8,
    start_us: i64,
    length: u16 = 0,
    cursor_bytes: [transport.max_cursor_bytes]u8 = [_]u8{0} ** transport.max_cursor_bytes,
    fn cursor(self: *const Position) []const u8 {
        return self.cursor_bytes[0..self.length];
    }
    fn withCursor(self: Position, value: []const u8) !Position {
        if (value.len == 0 or value.len > self.cursor_bytes.len or std.mem.indexOfScalar(u8, value, 0) != null) return error.InvalidJournalCursor;
        var next = self;
        @memset(&next.cursor_bytes, 0);
        @memcpy(next.cursor_bytes[0..value.len], value);
        next.length = @intCast(value.len);
        return next;
    }
    fn encode(self: *const Position) [checkpoint_bytes]u8 {
        var result: [checkpoint_bytes]u8 = undefined;
        @memcpy(result[0..4], "F2JC");
        std.mem.writeInt(u16, result[4..6], 1, .little);
        @memcpy(result[6..38], &self.generation);
        std.mem.writeInt(i64, result[38..46], self.start_us, .little);
        std.mem.writeInt(u16, result[46..48], self.length, .little);
        @memcpy(result[48..], &self.cursor_bytes);
        return result;
    }
    fn decode(value: []const u8, generation: [32]u8) !Position {
        if (value.len != checkpoint_bytes or !std.mem.eql(u8, value[0..4], "F2JC")) return error.ForeignJournalCheckpoint;
        if (std.mem.readInt(u16, value[4..6], .little) != 1) return error.UnsupportedJournalCheckpoint;
        if (!std.mem.eql(u8, value[6..38], &generation)) return error.SourceGenerationMismatch;
        const start = std.mem.readInt(i64, value[38..46], .little);
        const length = std.mem.readInt(u16, value[46..48], .little);
        if (start < 0 or length > transport.max_cursor_bytes) return error.InvalidJournalCursor;
        var result = Position{ .generation = generation, .start_us = start, .length = length };
        @memcpy(&result.cursor_bytes, value[48..]);
        if (std.mem.indexOfScalar(u8, result.cursor(), 0) != null or !std.mem.allEqual(u8, result.cursor_bytes[length..], 0)) return error.InvalidJournalCursor;
        return result;
    }
};
pub const Options = struct {
    processing: native.Options,
    detection: ?@import("native_detection_record.zig").JournalConsumer = null,
    staged_detection: ?@import("native_detection_record.zig").StagedConsumer = null,
    consumer_sources: ?@import("native_file_session.zig").ConsumerSources = null,
    retry: ?@import("native_retry.zig").Policy = null,
    journal: transport.Options = .{},
    source_id: []const u8 = "system-journal",
    gate: ?*health.Gate = null,
    monotonic_clock: ?health.Clock = null,
    clock_context: ?*anyopaque = null,
    clock: ?*const fn (?*anyopaque) anyerror!time.Timestamp = null,
    executor: transport.Executor = .{},
};
pub const RecoverySnapshot = struct {
    allocator: std.mem.Allocator,
    generation: [32]u8,
    jail: []u8,
    source: []u8,
    pending_proof: ?durable.Store.PendingSource,
    candidate_receipt: @FieldType(pipeline.Pipeline, "candidate_receipt"),
    source_repair: repair.Repair,
    source_health: records.Health,
    last_error: ?anyerror,
    notices: std.time.Timer,
    expected_durable: bool,
    initial_proposal: ?Position,
    initial_tail_attempted: bool,

    pub fn reservation(max_sources: usize) !@import("native_file_session.zig").RecoveryReservation {
        if (max_sources != 1) return error.InvalidSourceLimit;
        return .{ .bytes = @sizeOf(RecoverySnapshot) + 128 + 3 * durable.Limits.source_bytes + durable.Limits.cursor_bytes, .allocations = 7, .descriptors = 0 };
    }
    pub fn reservedBytes(self: *const RecoverySnapshot) usize {
        var bytes = @sizeOf(RecoverySnapshot) + self.jail.len + self.source.len;
        if (self.pending_proof) |pending| bytes += pending.identity.jail.len + pending.identity.source.len + pending.identity.occurrence.len + pending.identity.cursor.len;
        return bytes;
    }
    pub fn descriptorCount(_: *const RecoverySnapshot) usize {
        return 0;
    }
    pub fn destroy(self: *RecoverySnapshot) void {
        const a = self.allocator;
        if (self.pending_proof) |pending| pending.deinit(a);
        a.free(self.jail);
        a.free(self.source);
        a.destroy(self);
    }
};
pub const Session = struct {
    allocator: std.mem.Allocator,
    options: Options,
    processor: native.Processor,
    pipe: pipeline.Pipeline,
    position: Position,
    baseline_committed: bool = false,
    decode_scratch: []u8,
    parse_scratch: []u8,
    output: []u8,
    diagnostic: transport.Diagnostic = .{},
    source_health: records.Health = .waiting,
    last_error: ?anyerror = null,
    notices: std.time.Timer,
    source_repair: repair.Repair,
    admission_phase: enum { positions, anchor, pending, ready } = .positions,
    restore_after: ?[]const u8 = null,
    initial_tail_attempted: bool = false,
    pending_expected: ?durable.ReceiptIdentity = null,
    pending_proof: ?durable.Store.PendingSource = null,
    initial_proposal: ?Position = null,
    expected_durable: bool = false,
    last_failure_domain: ?repair.Domain = null,

    fn validateOptions(options: Options) !void {
        if (options.staged_detection != null and (options.detection != null or options.consumer_sources == null)) return error.ConsumerManifestRequired;
        if (options.staged_detection == null and options.consumer_sources != null) return error.InvalidConsumer;
        try transport.validate(options.journal);
        if (options.source_id.len == 0 or options.source_id.len > 512 or std.mem.indexOfScalar(u8, options.source_id, 0) != null) return error.InvalidJournalSource;
        if (options.processing.timestamp != .journal or options.processing.max_record_bytes > 64 * 1024 or options.processing.max_decoded_bytes > 64 * 1024 or options.processing.max_decoded_bytes == 0) return error.InvalidJournalProcessing;
    }

    /// Pure binding only: no clock, executor, consumer, Store or DNS callback.
    /// Scratch/config remain borrowed; preflight reads generation without escape.
    pub fn prepareProcessor(a: std.mem.Allocator, options: Options, scratch: []u8, now: time.Timestamp) !native.Processor {
        try validateOptions(options);
        if (now.us < 0) return error.InvalidJournalStart;
        const specification = try std.json.stringifyAlloc(a, .{ .version = 1, .parent = options.processing.parent_generation, .source = options.source_id, .journal = options.journal }, .{});
        defer a.free(specification);
        var bound = options.processing;
        std.crypto.hash.sha2.Sha256.hash(specification, &bound.parent_generation, .{});
        var processor = if (options.staged_detection) |consumer| try native.Processor.initWithStaged(a, bound, scratch, now, consumer) else try native.Processor.initWithJournalDetection(a, bound, scratch, now, options.detection);
        if (options.retry) |policy| try processor.bindRetry(policy);
        return processor;
    }

    /// Borrowed configuration/clock/executor context and store must outlive this
    /// stable owner. Store schema admission belongs to the global coordinator.
    pub fn create(a: std.mem.Allocator, store: *durable.Store, options: Options) !*Session {
        return createInternal(a, store, options, false);
    }
    pub fn createDeferred(a: std.mem.Allocator, store: *durable.Store, options: Options) !*Session {
        return createInternal(a, store, options, true);
    }
    fn createInternal(a: std.mem.Allocator, store: *durable.Store, options: Options, deferred: bool) !*Session {
        if (store.receipt_limit == null) return error.ReceiptStorageRequired;
        if (store.schema_version < 4 or store.schema_version > durable.latest_schema) return error.NativeTimeStorageRequired;
        if (options.detection != null and store.schema_version < 8) return error.JournalDetectionStorageRequired;
        if (options.staged_detection != null and (options.detection != null or options.consumer_sources == null or store.schema_version < 12)) return error.ConsumerManifestRequired;
        try validateOptions(options);
        var admission = pipeline.ReceiptAdmission{ .generation = undefined, .clock_context = options.clock_context };
        if (options.clock) |clock| admission.clock = clock;
        const now = try admission.clock(admission.clock_context);
        if (now.us < 0) return error.InvalidJournalStart;
        const self = try a.create(Session);
        errdefer a.destroy(self);
        self.allocator = a;
        self.options = options;
        self.decode_scratch = try a.alloc(u8, options.processing.max_decoded_bytes);
        errdefer a.free(self.decode_scratch);
        self.parse_scratch = try a.alloc(u8, transport.parse_bytes);
        errdefer a.free(self.parse_scratch);
        self.output = try a.alloc(u8, (@as(usize, options.journal.batch_records) + 1) * (transport.max_line_bytes + 1));
        errdefer a.free(self.output);
        self.processor = try prepareProcessor(a, options, self.decode_scratch, now);
        if (options.retry) |policy| {
            try store.admitRetry(options.processing.jail, self.processor.generation, policy);
            try store.validateRetry(options.processing.jail, self.processor.generation, policy);
        }
        self.processor.processing_clock = .{ .read = admission.clock, .context = admission.clock_context };
        admission.generation = self.processor.generation;
        self.pipe = .{ .store = store, .jail = options.processing.jail, .processor = self.processor.adapter(), .gate = options.gate, .receipts = admission };
        self.position = .{ .generation = self.processor.generation, .start_us = now.us };
        self.baseline_committed = false;
        self.diagnostic = .{};
        self.source_health = .waiting;
        self.last_error = null;
        self.notices = try std.time.Timer.start();
        self.processor.monotonic_clock = .{ .read = monotonic, .context = self };
        self.source_repair = try repair.Repair.init(try repair.Binding.init(self.processor.generation, options.source_id), self.nowMs());
        self.admission_phase = .positions;
        self.restore_after = null;
        self.initial_tail_attempted = false;
        self.pending_expected = null;
        self.pending_proof = null;
        self.initial_proposal = null;
        self.expected_durable = false;
        self.last_failure_domain = null;
        if (options.consumer_sources) |binding| try binding.admit(options.source_id, self.processor.generation, binding.context);
        try self.pipe.restore(a);
        if (deferred) return self;
        try store.visitSources(self.pipe.jail, restoreSource, self);
        try self.checkStartClock();
        if (self.pipe.revision != 0 and !self.baseline_committed) return error.MissingJournalCheckpoint;
        if (self.baseline_committed) {
            // Exact anchor verification also applies when no pending receipt exists.
            _ = try self.fetch(1);
        } else {
            self.initial_tail_attempted = true;
            var lines = try self.query(.tail, 1);
            if (try lines.next()) |line| {
                const entry = try transport.decode(self.parse_scratch, line, options.processing.max_record_bytes);
                self.position = try self.position.withCursor(entry.cursor);
            }
            if (try lines.next() != null) return error.JournalRecordLimit;
        }
        try store.visitPendingReceipts(restorePending, self);
        if (try store.revision(self.pipe.jail) != self.pipe.revision) return error.StaleCheckpoint;
        self.admission_phase = .ready;
        return self;
    }
    pub fn destroy(self: *Session) void {
        std.debug.assert(!self.processor.in_flight);
        if (self.pending_proof) |saved| saved.deinit(self.allocator);
        self.allocator.free(self.output);
        self.allocator.free(self.parse_scratch);
        self.allocator.free(self.decode_scratch);
        self.allocator.destroy(self);
    }
    /// Export only detached continuity/repair evidence, never executor, consumer
    /// or clock callbacks. No helper/query/Store access occurs in this operation.
    pub fn exportRecovery(self: *const Session) !*RecoverySnapshot {
        if (self.processor.in_flight or self.pending_expected != null) return error.ConsumerBusy;
        if (self.options.processing.jail.len > 64 or self.options.source_id.len > durable.Limits.source_bytes) return error.InvalidSourceLimit;
        if (self.pending_proof) |pending| if (pending.identity.jail.len > 64 or pending.identity.source.len > durable.Limits.source_bytes or pending.identity.occurrence.len > durable.Limits.source_bytes or pending.identity.cursor.len > durable.Limits.cursor_bytes) return error.PendingRecordMismatch;
        const a = self.allocator;
        const out = try a.create(RecoverySnapshot);
        errdefer a.destroy(out);
        const jail = try a.dupe(u8, self.options.processing.jail);
        errdefer a.free(jail);
        const source = try a.dupe(u8, self.options.source_id);
        errdefer a.free(source);
        const pending = if (self.pending_proof) |saved| try @import("native_file_session.zig").clonePending(a, saved) else null;
        const expected_durable = self.baseline_committed or self.expected_durable;
        out.* = .{ .allocator = a, .generation = self.processor.generation, .jail = jail, .source = source, .pending_proof = pending, .candidate_receipt = self.pipe.candidate_receipt, .source_repair = self.source_repair, .source_health = self.source_health, .last_error = self.last_error, .notices = self.notices, .expected_durable = expected_durable, .initial_proposal = self.recoveryProposal(), .initial_tail_attempted = self.initial_tail_attempted };
        return out;
    }
    fn recoveryProposal(self: *const Session) ?Position {
        if (self.baseline_committed or self.expected_durable) return null;
        // Before position restoration, the imported proposal is still newer
        // than the fresh constructor's clock. Afterwards retain any newly
        // observed first-tail cursor, not a stale imported empty proposal.
        return if (self.admission_phase == .positions) self.initial_proposal orelse self.position else self.position;
    }
    pub fn importRecovery(self: *Session, snapshot: *const RecoverySnapshot) !void {
        if (self.processor.in_flight or self.admission_phase != .positions or self.baseline_committed or self.restore_after != null or self.pending_proof != null) return error.RecoveryOutOfOrder;
        if (!std.mem.eql(u8, &self.processor.generation, &snapshot.generation) or !std.mem.eql(u8, self.options.processing.jail, snapshot.jail) or !std.mem.eql(u8, self.options.source_id, snapshot.source)) return error.SourceGenerationMismatch;
        const pending = if (snapshot.pending_proof) |saved| try @import("native_file_session.zig").clonePending(self.allocator, saved) else null;
        self.pending_proof = pending;
        self.pipe.candidate_receipt = snapshot.candidate_receipt;
        self.source_repair = snapshot.source_repair;
        self.source_health = snapshot.source_health;
        self.last_error = snapshot.last_error;
        self.notices = snapshot.notices;
        self.expected_durable = snapshot.expected_durable;
        self.initial_proposal = snapshot.initial_proposal;
        self.initial_tail_attempted = snapshot.initial_tail_attempted;
    }
    /// Import only generation-bound repair metadata and the uncommitted first
    /// boundary. A freshly loaded durable position always takes precedence.
    pub fn copyRepairStateFrom(self: *Session, old: *const Session) !void {
        if (self.admission_phase != .positions or self.baseline_committed or self.restore_after != null or self.pending_proof != null) return error.RecoveryOutOfOrder;
        if (!std.mem.eql(u8, &self.processor.generation, &old.processor.generation) or !std.mem.eql(u8, self.options.source_id, old.options.source_id)) return error.SourceGenerationMismatch;
        const proof = if (old.pending_proof) |saved| try @import("native_file_session.zig").clonePending(self.allocator, saved) else null;
        self.pending_proof = proof;
        self.pipe.candidate_receipt = old.pipe.candidate_receipt;
        self.source_repair = old.source_repair;
        self.source_health = old.source_health;
        self.last_error = old.last_error;
        self.notices = old.notices;
        self.expected_durable = old.baseline_committed or old.expected_durable;
        self.initial_proposal = old.recoveryProposal();
        self.initial_tail_attempted = old.initial_tail_attempted;
    }
    fn checkStartClock(self: *Session) !void {
        const clock = self.pipe.receipts.?;
        if ((try clock.clock(clock.clock_context)).us < self.position.start_us) {
            self.pipe.receiptClockFailed(self.position.start_us);
            return error.ReceiptClockReversed;
        }
    }
    pub fn verifyRecoverySources(self: *Session) !void {
        if (self.pipe.gate) |gate| {
            const status = gate.snapshot();
            if (status.phase != .recovering or status.recovery_step != .sources) return error.RecoveryOutOfOrder;
        }
        if (!self.pipe.ready) return error.RestoreRequired;
        try self.checkStartClock();
        if (self.baseline_committed) _ = try self.fetch(1);
        try self.pipe.store.visitPendingReceipts(restorePending, self);
        if (try self.pipe.store.revision(self.pipe.jail) != self.pipe.revision) return error.StaleCheckpoint;
    }
    fn nowMs(self: *Session) u64 {
        if (self.options.monotonic_clock) |clock| return clock.read(clock.context);
        return self.notices.read() / std.time.ns_per_ms;
    }
    pub fn repairSnapshot(self: *const Session) repair.Snapshot {
        return self.source_repair.snapshot();
    }
    fn storageFailure(self: *Session, cause: anyerror) anyerror {
        self.last_failure_domain = .storage;
        self.pipe.ready = false;
        if (self.pipe.gate) |gate| gate.failed(cause, .{ .sqlite_code = self.pipe.store.last_error_code, .rollback_code = self.pipe.store.rollback_error_code, .reopen_required = self.pipe.store.reopen_required });
        return cause;
    }
    fn sourceFailure(self: *Session, cause: anyerror) anyerror {
        self.last_error = cause;
        self.source_health = switch (cause) {
            error.ResumeLost, error.PendingRecordMismatch, error.PendingRecordUnavailable => .resume_lost,
            error.AccessDenied => .permission_denied,
            error.FileNotFound => .missing,
            error.JournalChildFailed, error.JournalTimeout => .child_failed,
            else => .read_failed,
        };
        const domain = self.source_repair.failed(cause, self.nowMs()) catch |failure| return failure;
        self.last_failure_domain = domain;
        return switch (domain) {
            .pending, .transient_source => error.SourceRepairPending,
            .source_intervention => error.SourceInterventionRequired,
            .storage => self.storageFailure(cause),
        };
    }
    fn sourceBinding(self: *Session, pending: anytype) !repair.Binding {
        var binding = try repair.Binding.init(self.processor.generation, self.options.source_id);
        if (pending) |saved| {
            if (!std.mem.eql(u8, saved.identity.source, self.options.source_id) or !std.mem.eql(u8, &saved.identity.generation, &self.processor.generation)) return error.ForeignJournalSource;
            binding = try binding.withPending(saved.identity.occurrence, saved.identity.cursor, saved.identity.raw_hash, saved.receipt_us);
        }
        return binding;
    }
    fn bindPending(self: *Session, pending: ?durable.Store.PendingSource) !repair.Binding {
        const state = &self.source_repair;
        const binding = try self.sourceBinding(pending);
        if (state.state.phase != .healthy and !std.meta.eql(state.binding, binding)) {
            if (pending != null or state.binding.pending_digest == null) return error.PendingRecordMismatch;
            const proof = self.pending_proof orelse return error.PendingRecordMismatch;
            const original = try self.sourceBinding(@as(?durable.Store.PendingSource, proof));
            if (!std.meta.eql(original, state.binding)) return error.PendingRecordMismatch;
            const committed = self.pipe.store.committedReceipt(proof.identity) catch |err| return self.storageFailure(err);
            if (committed == null or committed.?.us != proof.receipt_us) return error.PendingRecordMismatch;
            try state.resolveCommittedPending(original);
        }
        if (pending) |saved| {
            const replacement = try @import("native_file_session.zig").clonePending(self.allocator, saved);
            if (self.pending_proof) |value| value.deinit(self.allocator);
            self.pending_proof = replacement;
        } else {
            if (self.pending_proof) |value| value.deinit(self.allocator);
            self.pending_proof = null;
        }
        if (state.state.phase == .healthy) try state.bindHealthy(binding);
        return binding;
    }
    fn sourceIoAdmission(self: *Session) !void {
        if (!self.pipe.ready) return error.RestoreRequired;
        if (self.pipe.gate) |gate| {
            const status = gate.snapshot();
            if (status.phase != .healthy and !(status.phase == .recovering and status.recovery_step == .sources)) return error.RecoveryOutOfOrder;
            if (status.generation != self.pipe.recovery_generation) return error.RestoreRequired;
        }
        try self.checkStartClock();
    }
    fn checkCandidate(candidate: records.Record, identity: durable.ReceiptIdentity) !void {
        if (candidate.kind != .data or !std.mem.eql(u8, candidate.source, identity.source) or !std.mem.eql(u8, candidate.occurrence, identity.occurrence) or !std.mem.eql(u8, candidate.cursor, identity.cursor) or !std.mem.eql(u8, &candidate.raw_hash, &identity.raw_hash)) return error.PendingRecordMismatch;
    }
    /// Validate the exact inclusive anchor and, when present, the complete next
    /// pending entry including its origin fields. One fixed-argument query only.
    fn verifyTurn(self: *Session) !void {
        try self.sourceIoAdmission();
        if (self.source_repair.state.phase == .intervention) return error.SourceInterventionRequired;
        var token: ?repair.Token = null;
        if (self.source_repair.state.phase != .healthy) {
            token = try self.source_repair.begin(self.nowMs(), true);
            if (token == null) return error.SourceRepairPending;
        }
        const pending = self.pipe.store.readPendingSource(self.allocator, self.pipe.jail, self.options.source_id) catch |err| return self.storageFailure(err);
        defer if (pending) |saved| saved.deinit(self.allocator);
        const binding = self.bindPending(pending) catch |err| return if (self.last_failure_domain == .storage) err else self.sourceFailure(err);
        if (token != null) token = try self.source_repair.begin(self.nowMs(), true);
        var lines = self.fetch(1) catch |err| return self.sourceFailure(err);
        if (pending) |saved| {
            if (!self.baseline_committed) return self.sourceFailure(error.MissingJournalCheckpoint);
            const line = (try lines.next()) orelse return self.sourceFailure(error.PendingRecordUnavailable);
            const entry = transport.decode(self.parse_scratch, line, self.options.processing.max_record_bytes) catch |err| return self.sourceFailure(err);
            const next = try self.position.withCursor(entry.cursor);
            var cursor: [checkpoint_bytes]u8 = undefined;
            var occurrence: [518]u8 = undefined;
            checkCandidate(self.record(entry, &next, &cursor, &occurrence), saved.identity) catch |err| return self.sourceFailure(err);
        }
        if (token) |value| if (self.source_repair.state.phase == .verifying) try self.source_repair.continuityVerified(value, binding);
    }
    /// Deferred admission performs one detached state read or one journal query
    /// per turn. A failed first tail query freezes the original start boundary;
    /// retry must not seek a later tail and skip entries written during cooldown.
    pub fn admissionTurn(self: *Session) !bool {
        try self.sourceIoAdmission();
        self.last_failure_domain = null;
        switch (self.admission_phase) {
            .positions => {
                const position = self.pipe.store.readSourcePosition(self.allocator, self.pipe.jail, self.restore_after, self.pipe.revision) catch |err| return self.storageFailure(err);
                if (position) |saved| {
                    defer saved.deinit(self.allocator);
                    try restoreSource(saved.source, saved.path, saved.cursor, self);
                    self.restore_after = self.options.source_id;
                } else {
                    if ((self.pipe.revision != 0 or self.expected_durable) and !self.baseline_committed) return error.MissingJournalCheckpoint;
                    if (!self.baseline_committed) if (self.initial_proposal) |proposal| {
                        self.position = proposal;
                    };
                    self.admission_phase = .anchor;
                }
            },
            .anchor => {
                if (!self.baseline_committed and !self.initial_tail_attempted) {
                    self.initial_tail_attempted = true;
                    var lines = self.query(.tail, 1) catch |err| return self.sourceFailure(err);
                    if (try lines.next()) |line| {
                        const entry = transport.decode(self.parse_scratch, line, self.options.processing.max_record_bytes) catch |err| return self.sourceFailure(err);
                        self.position = try self.position.withCursor(entry.cursor);
                    }
                } else try self.verifyTurn();
                self.admission_phase = .pending;
            },
            .pending => {
                const pending = self.pipe.store.readPendingPosition(self.allocator, self.pipe.jail, null) catch |err| return self.storageFailure(err);
                if (pending) |saved| {
                    defer saved.deinit(self.allocator);
                    if (!std.mem.eql(u8, saved.identity.source, self.options.source_id)) return error.ForeignJournalSource;
                    try self.verifyTurn();
                    const other = self.pipe.store.readPendingPosition(self.allocator, self.pipe.jail, self.options.source_id) catch |err| return self.storageFailure(err);
                    if (other) |unexpected| {
                        unexpected.deinit(self.allocator);
                        return error.ForeignJournalSource;
                    }
                }
                if (try self.pipe.store.revision(self.pipe.jail) != self.pipe.revision) return self.storageFailure(error.StaleCheckpoint);
                self.admission_phase = .ready;
            },
            .ready => return true,
        }
        return self.admission_phase == .ready;
    }
    pub fn verifyRecoverySourcesTurn(self: *Session) !bool {
        if (self.admission_phase != .ready) return self.admissionTurn();
        try self.verifyTurn();
        if (try self.pipe.store.revision(self.pipe.jail) != self.pipe.revision) return self.storageFailure(error.StaleCheckpoint);
        return true;
    }
    pub fn resumeConsumerSource(self: *Session, source_id: []const u8) !usize {
        try self.pipe.admit();
        if (self.admission_phase != .ready) return error.RestoreRequired;
        if (!std.mem.eql(u8, source_id, self.options.source_id)) return error.ForeignJournalSource;
        const pending = (try self.pipe.store.readPendingSource(self.allocator, self.pipe.jail, source_id)) orelse return error.PendingRecordUnavailable;
        defer pending.deinit(self.allocator);
        if (!std.mem.eql(u8, &pending.identity.generation, &self.processor.generation)) return error.SourceGenerationMismatch;
        return self.pollTurn(1);
    }
    /// Native scheduler entry point. Cooldown/intervention makes no helper call;
    /// successful continuity alone never resets an episode before actual polling.
    pub fn pollTurn(self: *Session, budget: usize) !usize {
        defer self.reportNotices();
        if (budget == 0 or budget > self.options.journal.batch_records) return error.InvalidPollBudget;
        try self.pipe.admit();
        if (self.admission_phase != .ready) {
            _ = try self.admissionTurn();
            return 0;
        }
        self.last_failure_domain = null;
        switch (self.source_repair.state.phase) {
            .intervention => return error.SourceInterventionRequired,
            .waiting, .verifying => {
                try self.verifyTurn();
                return 0;
            },
            .healthy, .polling => {},
        }
        const pending = self.pipe.store.readPendingSource(self.allocator, self.pipe.jail, self.options.source_id) catch |err| return self.storageFailure(err);
        defer if (pending) |saved| saved.deinit(self.allocator);
        _ = self.bindPending(pending) catch |err| return if (self.last_failure_domain == .storage) err else self.sourceFailure(err);
        self.pending_expected = if (pending) |saved| saved.identity else null;
        defer self.pending_expected = null;
        var committing = false;
        const had_baseline = self.baseline_committed;
        const count = self.pollAdmitted(budget, &committing) catch |err| {
            if (committing) {
                if (pipeline.Pipeline.sourceLocalIntervention(err)) return self.sourceFailure(err);
                self.last_failure_domain = if (repair.classify(err) == .pending) .pending else .storage;
                self.last_error = err;
                self.source_health = if (self.last_failure_domain == .pending) .waiting else .commit_failed;
                return err;
            }
            return self.sourceFailure(err);
        };
        if (had_baseline and self.source_repair.state.phase == .polling) try self.source_repair.pollSucceeded((try self.source_repair.begin(self.nowMs(), true)).?);
        self.last_error = null;
        self.source_health = .healthy;
        return count;
    }

    fn restoreSource(source: []const u8, path: []const u8, cursor: []const u8, context: ?*anyopaque) !void {
        const self: *Session = @ptrCast(@alignCast(context.?));
        if (self.baseline_committed or path.len != 0 or !std.mem.eql(u8, source, self.options.source_id)) return error.ForeignJournalSource;
        self.position = try Position.decode(cursor, self.processor.generation);
        self.baseline_committed = true;
    }
    const Lines = struct {
        bytes: []const u8,
        remaining: usize,
        fn next(self: *Lines) !?[]const u8 {
            if (self.bytes.len == 0) return null;
            if (self.remaining == 0) return error.JournalRecordLimit;
            const end = std.mem.indexOfScalar(u8, self.bytes, '\n') orelse return error.IncompleteJournalRecord;
            if (end == 0 or end > transport.max_line_bytes) return error.JournalRecordLimit;
            const line = self.bytes[0..end];
            self.bytes = self.bytes[end + 1 ..];
            self.remaining -= 1;
            return line;
        }
    };
    fn query(self: *Session, q: transport.Query, count: usize) !Lines {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const args = try transport.argv(arena.allocator(), self.options.journal, q, count);
        self.diagnostic = .{};
        const result = try self.options.executor.run(self.allocator, args, self.output, &self.diagnostic, self.options.journal.timeout_ms, self.options.executor.context);
        if (result.len > self.output.len) return error.JournalOutputLimit;
        // Do not acknowledge any records from a truncated command response.
        if (result.len > 0 and result[result.len - 1] != '\n') return error.IncompleteJournalRecord;
        var framed = Lines{ .bytes = result, .remaining = count };
        while (try framed.next()) |_| {}
        return .{ .bytes = result, .remaining = count };
    }
    fn fetch(self: *Session, budget: usize) !Lines {
        const anchored = self.position.length > 0;
        var lines = try self.query(if (anchored) .{ .cursor = self.position.cursor() } else .{ .since_us = self.position.start_us }, budget + @as(usize, if (anchored) 1 else 0));
        if (anchored) {
            const line = (try lines.next()) orelse return error.ResumeLost;
            const anchor = try transport.decode(self.parse_scratch, line, self.options.processing.max_record_bytes);
            if (!std.mem.eql(u8, anchor.cursor, self.position.cursor())) return error.ResumeLost;
        }
        return lines;
    }
    fn record(self: *Session, entry: transport.Entry, proposed: *const Position, cursor: *[checkpoint_bytes]u8, occurrence: *[518]u8) records.Record {
        cursor.* = proposed.encode();
        @memcpy(occurrence[0..6], "entry:");
        @memcpy(occurrence[6..][0..entry.cursor.len], entry.cursor);
        return .{ .source = self.options.source_id, .occurrence = occurrence[0 .. 6 + entry.cursor.len], .cursor = cursor, .message = entry.message, .raw_hash = entry.raw_hash, .timestamp_us = entry.realtime_us, .journal_monotonic_us = entry.monotonic_us, .journal_fields = entry.fields };
    }
    fn restorePending(identity: durable.ReceiptIdentity, _: time.Timestamp, context: ?*anyopaque) !void {
        const self: *Session = @ptrCast(@alignCast(context.?));
        if (!std.mem.eql(u8, identity.jail, self.pipe.jail)) return;
        if (!self.baseline_committed) return error.MissingJournalCheckpoint;
        if (!std.mem.eql(u8, identity.source, self.options.source_id) or !std.mem.eql(u8, &identity.generation, &self.processor.generation)) return error.ForeignJournalSource;
        var lines = try self.fetch(1);
        const line = (try lines.next()) orelse return error.PendingRecordUnavailable;
        const entry = try transport.decode(self.parse_scratch, line, self.options.processing.max_record_bytes);
        const next = try self.position.withCursor(entry.cursor);
        var cursor: [checkpoint_bytes]u8 = undefined;
        var occurrence: [518]u8 = undefined;
        const candidate = self.record(entry, &next, &cursor, &occurrence);
        if (!std.mem.eql(u8, candidate.occurrence, identity.occurrence) or !std.mem.eql(u8, candidate.cursor, identity.cursor) or !std.mem.eql(u8, &candidate.raw_hash, &identity.raw_hash)) return error.PendingRecordMismatch;
    }
    pub fn poll(self: *Session, budget: usize) !usize {
        defer self.reportNotices();
        var committing = false;
        const count = self.pollAdmitted(budget, &committing) catch |err| {
            self.last_error = err;
            self.source_health = switch (err) {
                error.ResumeLost, error.PendingRecordMismatch, error.PendingRecordUnavailable => .resume_lost,
                error.AccessDenied => .permission_denied,
                error.FileNotFound => .missing,
                error.JournalRecordLimit, error.JournalMessageLimit, error.JournalOutputLimit, error.JournalParseLimit => .record_too_long,
                error.JournalChildFailed, error.JournalTimeout, error.JournalDiagnostic, error.JournalDiagnosticLimit => .child_failed,
                error.MalformedJournalRecord, error.IncompleteJournalRecord, error.MissingJournalCursor, error.MissingJournalMessage, error.UnsupportedJournalField, error.RepeatedJournalCursor, error.InvalidJournalArgument => .malformed_record,
                error.StoragePaused, error.RestoreRequired => .commit_failed,
                error.ReceiptClockReversed => .clock_failed,
                else => if (committing) .commit_failed else .read_failed,
            };
            return err;
        };
        self.last_error = null;
        self.source_health = .healthy;
        return count;
    }
    fn monotonic(context: ?*anyopaque) u64 {
        const self: *Session = @ptrCast(@alignCast(context.?));
        return self.nowMs();
    }
    fn reportNotices(self: *Session) void {
        if (self.processor.timeNotice(self.notices.read() / std.time.ns_per_ms)) |notice| std.log.scoped(.source_time).warn("jail {s}: rejected journal timestamps: missing={d}, malformed={d}, future={d}", .{ self.pipe.jail, notice.missing_since_notice, notice.malformed_since_notice, notice.future_since_notice });
    }
    fn pollAdmitted(self: *Session, budget: usize, committing: *bool) !usize {
        if (budget == 0 or budget > self.options.journal.batch_records) return error.InvalidPollBudget;
        try self.pipe.admit();
        try self.checkStartClock();
        if (!self.baseline_committed) {
            if (self.pending_expected != null) return error.MissingJournalCheckpoint;
            const cursor = self.position.encode();
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(&cursor, &digest, .{});
            committing.* = true;
            try pipeline.Pipeline.acknowledge(.{ .kind = .checkpoint, .source = self.options.source_id, .occurrence = "baseline", .cursor = &cursor, .message = "", .raw_hash = digest }, &self.pipe);
            self.baseline_committed = true;
            return 0;
        }
        var lines = try self.fetch(budget);
        var delivered: usize = 0;
        while (try lines.next()) |line| {
            const entry = try transport.decode(self.parse_scratch, line, self.options.processing.max_record_bytes);
            if (std.mem.eql(u8, entry.cursor, self.position.cursor())) return error.RepeatedJournalCursor;
            const next = try self.position.withCursor(entry.cursor);
            var cursor: [checkpoint_bytes]u8 = undefined;
            var occurrence: [518]u8 = undefined;
            const candidate = self.record(entry, &next, &cursor, &occurrence);
            const revision = self.pipe.revision;
            if (self.pending_expected) |identity| try checkCandidate(candidate, identity);
            committing.* = true;
            try pipeline.Pipeline.acknowledge(candidate, &self.pipe);
            committing.* = false;
            if (self.pipe.revision == revision) return error.RepeatedJournalCursor;
            self.position = next;
            self.pending_expected = null;
            delivered += 1;
        }
        return delivered;
    }
};

test "native journal: fixed cursor checkpoints reject foreign versions generations and padding" {
    const generation = [_]u8{7} ** 32;
    const position = try (Position{ .generation = generation, .start_us = 123 }).withCursor("opaque cursor");
    const valid = position.encode();
    try std.testing.expectEqualDeep(position, try Position.decode(&valid, generation));
    for (0..6) |variant| {
        var bytes = valid;
        switch (variant) {
            0 => bytes[0] = '{',
            1 => bytes[4] = 2,
            2 => bytes[6] ^= 1,
            3 => std.mem.writeInt(i64, bytes[38..46], -1, .little),
            4 => std.mem.writeInt(u16, bytes[46..48], 513, .little),
            5 => bytes[559] = 1,
            else => unreachable,
        }
        if (Position.decode(&bytes, generation)) |_| return error.InvalidCheckpointAccepted else |_| {}
    }
    try std.testing.expectError(error.ForeignJournalCheckpoint, Position.decode(valid[0..559], generation));
}

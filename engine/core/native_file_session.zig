// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const linux_dupfd_cloexec = 1030;
const processing = @import("native_source_processor.zig");
const files = @import("durable_file_source.zig");
const durable = @import("record_store.zig");
const pipeline = @import("record_pipeline.zig");
const records = @import("source_record.zig");
const time = @import("native_time.zig");
const storage_health = @import("storage_health.zig");
const repair = @import("source_repair.zig");

pub const Spec = struct { pattern: []const u8, start: files.Start = .head };
pub const ConsumerSources = struct {
    context: ?*anyopaque,
    admit: *const fn ([]const u8, [32]u8, ?*anyopaque) anyerror!void,
};
pub const Options = struct {
    processing: processing.Options,
    detection: ?@import("native_detection_record.zig").Consumer = null,
    staged_detection: ?@import("native_detection_record.zig").StagedConsumer = null,
    consumer_sources: ?ConsumerSources = null,
    retry: ?@import("native_retry.zig").Policy = null,
    suppress_retry_enforcement: bool = false,
    max_sources: usize,
    gate: ?*storage_health.Gate = null,
    monotonic_clock: ?storage_health.Clock = null,
    clock_context: ?*anyopaque = null,
    clock: ?*const fn (?*anyopaque) anyerror!time.Timestamp = null,
};
pub fn clonePending(a: std.mem.Allocator, saved: durable.Store.PendingSource) !durable.Store.PendingSource {
    var value = saved;
    value.identity.jail = try a.dupe(u8, saved.identity.jail);
    errdefer a.free(value.identity.jail);
    value.identity.source = try a.dupe(u8, saved.identity.source);
    errdefer a.free(value.identity.source);
    value.identity.occurrence = try a.dupe(u8, saved.identity.occurrence);
    errdefer a.free(value.identity.occurrence);
    value.identity.cursor = try a.dupe(u8, saved.identity.cursor);
    return value;
}
const Retained = struct {
    source: []const u8,
    path: []const u8,
    state: repair.Repair,
    health: records.Health,
    in_operation: bool,
    expected_durable: bool,
    incarnation: ?[16]u8,
    pending: ?durable.Store.PendingSource = null,
    descriptor: ?std.fs.File = null,
    proposal: ?files.Resume = null,
    fn deinit(self: Retained, a: std.mem.Allocator) void {
        if (self.pending) |value| value.deinit(a);
        if (self.descriptor) |value| value.close();
        a.free(self.path);
        a.free(self.source);
    }
};

pub const RecoveryReservation = struct { bytes: usize, allocations: usize, descriptors: usize };
const CandidateReceipt = @FieldType(pipeline.Pipeline, "candidate_receipt");
pub const RecoverySnapshot = struct {
    allocator: std.mem.Allocator,
    generation: [32]u8,
    jail: []u8,
    max_sources: usize,
    entries: std.ArrayList(Retained),
    discovery_repair: repair.Repair,
    notices: std.time.Timer,
    candidate_receipt: CandidateReceipt,
    candidate_index: ?usize = null,

    pub fn reservation(max_sources: usize) !RecoveryReservation {
        if (max_sources == 0 or max_sources > durable.Limits.pending_receipts) return error.InvalidSourceLimit;
        const entry_bytes = @sizeOf(Retained) + 5 * durable.Limits.source_bytes + durable.Limits.cursor_bytes;
        return .{ .bytes = @sizeOf(RecoverySnapshot) + 64 + max_sources * entry_bytes, .allocations = 3 + 6 * max_sources, .descriptors = max_sources };
    }
    pub fn reservedBytes(self: *const RecoverySnapshot) usize {
        var bytes = @sizeOf(RecoverySnapshot) + self.jail.len + self.entries.capacity * @sizeOf(Retained);
        for (self.entries.items) |entry| {
            bytes += entry.source.len + entry.path.len;
            if (entry.pending) |pending| bytes += pending.identity.jail.len + pending.identity.source.len + pending.identity.occurrence.len + pending.identity.cursor.len;
        }
        return bytes;
    }
    pub fn descriptorCount(self: *const RecoverySnapshot) usize {
        var count: usize = 0;
        for (self.entries.items) |entry| if (entry.descriptor != null) {
            count += 1;
        };
        return count;
    }
    pub fn destroy(self: *RecoverySnapshot) void {
        const a = self.allocator;
        for (self.entries.items) |entry| entry.deinit(a);
        self.entries.deinit();
        a.free(self.jail);
        a.destroy(self);
    }
};

fn cloneRetained(a: std.mem.Allocator, original: Retained) !Retained {
    if (original.source.len == 0 or original.source.len > durable.Limits.source_bytes or original.path.len == 0 or original.path.len > durable.Limits.source_bytes) return error.InvalidSourceSpecification;
    if (original.pending) |pending| {
        if (pending.identity.jail.len > 64 or pending.identity.source.len > durable.Limits.source_bytes or pending.identity.occurrence.len > durable.Limits.source_bytes or pending.identity.cursor.len > durable.Limits.cursor_bytes) return error.PendingRecordMismatch;
    }
    var result = original;
    result.source = try a.dupe(u8, original.source);
    errdefer a.free(result.source);
    result.path = try a.dupe(u8, original.path);
    errdefer a.free(result.path);
    result.pending = if (original.pending) |pending| try clonePending(a, pending) else null;
    errdefer if (result.pending) |pending| pending.deinit(a);
    result.descriptor = if (original.descriptor) |file| .{ .handle = @intCast(try std.posix.fcntl(file.handle, linux_dupfd_cloexec, 3)) } else null;
    return result;
}
pub const Session = struct {
    allocator: std.mem.Allocator,
    scratch: []u8,
    processor: processing.Processor,
    sources: files.FileSet,
    pipe: pipeline.Pipeline,
    next_source: usize = 0,
    notices: std.time.Timer,
    consumer_sources: ?ConsumerSources,
    repair_states: []repair.Repair,
    repair_count: usize = 0,
    pending_proofs: []?durable.Store.PendingSource,
    retained: std.ArrayList(Retained),
    retained_index: usize = 0,
    discovery_repair: repair.Repair,
    scheduler_clock: ?storage_health.Clock,
    admission_phase: enum { positions, proposals, continuity, pending, discovery, ready } = .positions,
    admission_index: usize = 0,
    restore_after: ?[]const u8 = null,
    pending_after: ?[]const u8 = null,
    recovery_index: usize = 0,
    recovery_pending: bool = false,
    recovery_after: ?[]const u8 = null,
    discover_next: bool = true,
    last_failure_domain: ?repair.Domain = null,
    candidate_source: ?[]const u8 = null,

    fn validateOptions(options: Options, specs: []const Spec) !void {
        if (options.staged_detection != null and (options.detection != null or options.consumer_sources == null)) return error.ConsumerManifestRequired;
        if (options.staged_detection == null and options.consumer_sources != null) return error.InvalidConsumer;
        if (options.max_sources == 0 or options.max_sources > durable.Limits.pending_receipts or specs.len == 0 or specs.len > options.max_sources) return error.InvalidSourceLimit;
        for (specs) |spec| if (spec.pattern.len == 0 or spec.pattern.len > durable.Limits.source_bytes or std.mem.indexOfScalar(u8, spec.pattern, 0) != null) return error.InvalidSourceSpecification;
        if (options.processing.max_decoded_bytes == 0 or options.processing.max_decoded_bytes > @import("source_text.zig").max_record_bytes) return error.InvalidSourceLimits;
        if (options.processing.timestamp == .journal) return error.InvalidFileTimestampSource;
    }

    pub fn prepareProcessor(allocator: std.mem.Allocator, options: Options, specs: []const Spec, scratch: []u8, now: time.Timestamp) !processing.Processor {
        try validateOptions(options, specs);
        const configuration = try std.json.stringifyAlloc(allocator, .{ .parent = options.processing.parent_generation, .sources = specs, .maximum_sources = options.max_sources }, .{});
        defer allocator.free(configuration);
        var bound = options.processing;
        std.crypto.hash.sha2.Sha256.hash(configuration, &bound.parent_generation, .{});
        var processor = if (options.staged_detection) |consumer| try processing.Processor.initWithStaged(allocator, bound, scratch, now, consumer) else try processing.Processor.initWithDetection(allocator, bound, scratch, now, options.detection);
        if (options.retry) |policy| try processor.bindRetry(policy, options.suppress_retry_enforcement);
        return processor;
    }

    pub fn create(allocator: std.mem.Allocator, store: *durable.Store, options: Options, specs: []const Spec) !*Session {
        return createInternal(allocator, store, options, specs, false);
    }
    pub fn createDeferred(allocator: std.mem.Allocator, store: *durable.Store, options: Options, specs: []const Spec) !*Session {
        return createInternal(allocator, store, options, specs, true);
    }
    fn createInternal(allocator: std.mem.Allocator, store: *durable.Store, options: Options, specs: []const Spec, deferred: bool) !*Session {
        const admitted = store.receipt_limit orelse return error.ReceiptStorageRequired;
        if (store.schema_version < 4 or store.schema_version > durable.latest_schema) return error.NativeTimeStorageRequired;
        if (options.detection != null and store.schema_version < 6) return error.DetectionStorageRequired;
        if (options.staged_detection != null and (options.detection != null or options.consumer_sources == null or store.schema_version < 12)) return error.ConsumerManifestRequired;
        try validateOptions(options, specs);
        if (options.max_sources > admitted) return error.InvalidSourceLimit;
        if (options.processing.timestamp == .field and options.processing.timestamp.field.infer_year and store.schema_version < 5) return error.InferenceStorageRequired;
        if (options.processing.timestamp == .field and options.processing.timestamp.field.zone != null and store.schema_version < 11) return error.NativeTimeProvenanceRequired;
        var receipt_clock = pipeline.ReceiptAdmission{ .generation = [_]u8{0} ** 32, .clock_context = options.clock_context };
        if (options.clock) |read| receipt_clock.clock = read;
        const now = try receipt_clock.clock(receipt_clock.clock_context);
        const self = try allocator.create(Session);
        errdefer allocator.destroy(self);
        self.allocator = allocator;
        self.scratch = try allocator.alloc(u8, options.processing.max_decoded_bytes);
        errdefer allocator.free(self.scratch);
        self.processor = try prepareProcessor(allocator, options, specs, self.scratch, now);
        self.consumer_sources = options.consumer_sources;
        self.repair_states = try allocator.alloc(repair.Repair, options.max_sources);
        errdefer allocator.free(self.repair_states);
        self.pending_proofs = try allocator.alloc(?durable.Store.PendingSource, options.max_sources);
        errdefer allocator.free(self.pending_proofs);
        @memset(self.pending_proofs, null);
        self.retained = std.ArrayList(Retained).init(allocator);
        self.retained_index = 0;
        self.repair_count = 0;
        self.scheduler_clock = options.monotonic_clock;
        self.admission_phase = .positions;
        self.admission_index = 0;
        self.restore_after = null;
        self.pending_after = null;
        self.recovery_index = 0;
        self.recovery_pending = false;
        self.recovery_after = null;
        self.discover_next = true;
        self.last_failure_domain = null;
        self.candidate_source = null;
        if (options.retry) |policy| {
            try store.admitRetry(options.processing.jail, self.processor.generation, policy);
            try store.validateRetry(options.processing.jail, self.processor.generation, policy);
        }
        self.processor.processing_clock = .{ .read = receipt_clock.clock, .context = receipt_clock.clock_context };
        self.sources = try files.FileSet.init(allocator, options.processing.jail);
        errdefer self.sources.deinit();
        self.sources.max_sources = options.max_sources;
        self.sources.initialize_source = bindFile;
        self.sources.initialize_userdata = self;
        for (specs) |spec| try self.sources.add(spec.pattern, spec.start);
        self.next_source = 0;
        self.notices = try std.time.Timer.start();
        self.processor.monotonic_clock = .{ .read = monotonic, .context = self };
        self.discovery_repair = try repair.Repair.init(try repair.Binding.init(self.processor.generation, self.sources.jail), self.nowMs());
        receipt_clock.generation = self.processor.generation;
        self.pipe = .{ .store = store, .jail = self.sources.jail, .processor = self.processor.adapter(), .gate = options.gate, .receipts = receipt_clock };
        try self.pipe.restore(allocator);
        if (deferred) return self;
        try store.visitSources(self.pipe.jail, restoreSource, self);
        try store.visitPendingReceipts(restorePending, self);
        if (try store.revision(self.pipe.jail) != self.pipe.revision) return error.StaleCheckpoint;
        try self.sources.discover();
        try self.initializeRepairs();
        self.admission_phase = .ready;
        return self;
    }
    pub fn destroy(self: *Session) void {
        std.debug.assert(!self.processor.in_flight);
        self.sources.deinit();
        for (self.pending_proofs) |saved| if (saved) |value| value.deinit(self.allocator);
        self.allocator.free(self.pending_proofs);
        for (self.retained.items) |value| value.deinit(self.allocator);
        self.retained.deinit();
        self.allocator.free(self.repair_states);
        self.allocator.free(self.scratch);
        self.allocator.destroy(self);
    }

    pub fn exportRecovery(self: *const Session) !*RecoverySnapshot {
        if (self.processor.in_flight) return error.ConsumerBusy;
        _ = try RecoverySnapshot.reservation(self.sources.max_sources);
        if (self.repair_count > self.sources.sources.items.len) return error.RestoreRequired;
        const a = self.allocator;
        const out = try a.create(RecoverySnapshot);
        errdefer a.destroy(out);
        out.* = .{ .allocator = a, .generation = self.processor.generation, .jail = try a.dupe(u8, self.pipe.jail), .max_sources = self.sources.max_sources, .entries = std.ArrayList(Retained).init(a), .discovery_repair = self.discovery_repair, .notices = self.notices, .candidate_receipt = self.pipe.candidate_receipt };
        errdefer {
            for (out.entries.items) |entry| entry.deinit(a);
            out.entries.deinit();
            a.free(out.jail);
        }
        try out.entries.ensureTotalCapacityPrecise(self.sources.max_sources);
        for (self.sources.sources.items, 0..) |source, index| {
            var previous: ?Retained = null;
            for (self.retained.items) |entry| if (std.mem.eql(u8, entry.source, source.source_id)) {
                previous = entry;
                break;
            };
            const initialized = index < self.repair_count;
            if (!initialized) if (previous) |entry| if (entry.incarnation) |expected| {
                const observed = source.committed orelse return error.MissingFileCheckpoint;
                if (!std.mem.eql(u8, &expected, &observed.incarnation)) return error.ResumeLost;
            };
            const state = if (initialized) self.repair_states[index] else if (previous) |entry| entry.state else try repair.Repair.init(try repair.Binding.init(self.processor.generation, source.source_id), self.discovery_repair.last_now_ms);
            const pending = if (initialized) self.pending_proofs[index] else if (previous) |entry| entry.pending else null;
            const original = Retained{
                .source = source.source_id,
                .path = source.path,
                .state = state,
                .health = if (initialized) source.health else if (previous) |entry| entry.health else source.health,
                .in_operation = source.in_operation,
                .expected_durable = source.baseline_committed or (if (previous) |entry| entry.expected_durable else false),
                .incarnation = if (source.committed) |saved| saved.incarnation else if (previous) |entry| entry.incarnation else null,
                .pending = pending,
                .descriptor = source.file orelse if (previous) |entry| entry.descriptor else null,
                .proposal = if (!source.baseline_committed) source.committed orelse (if (previous) |entry| entry.proposal else null) else null,
            };
            if (out.entries.items.len == self.sources.max_sources) return error.SourceLimit;
            out.entries.appendAssumeCapacity(try cloneRetained(a, original));
        }
        for (self.retained.items) |entry| {
            var adopted = false;
            for (out.entries.items) |copied| if (std.mem.eql(u8, copied.source, entry.source)) {
                adopted = true;
                break;
            };
            if (adopted) continue;
            if (out.entries.items.len == self.sources.max_sources) return error.SourceLimit;
            out.entries.appendAssumeCapacity(try cloneRetained(a, entry));
        }
        if (out.candidate_receipt != null) {
            const source = self.candidate_source orelse return error.PendingSourceMissing;
            for (out.entries.items, 0..) |entry, index| if (std.mem.eql(u8, entry.source, source)) {
                out.candidate_index = index;
                break;
            };
            if (out.candidate_index == null) return error.PendingSourceMissing;
        }
        return out;
    }

    pub fn importRecovery(self: *Session, snapshot: *const RecoverySnapshot) !void {
        if (self.processor.in_flight or self.admission_phase != .positions or self.sources.sources.items.len != 0 or self.retained.items.len != 0) return error.RecoveryOutOfOrder;
        if (self.sources.max_sources != snapshot.max_sources or !std.mem.eql(u8, &self.processor.generation, &snapshot.generation) or !std.mem.eql(u8, self.pipe.jail, snapshot.jail)) return error.SourceGenerationMismatch;
        if (snapshot.entries.items.len > self.sources.max_sources) return error.SourceLimit;
        if ((snapshot.candidate_receipt == null) != (snapshot.candidate_index == null)) return error.PendingRecordMismatch;
        if (snapshot.candidate_index) |index| if (index >= snapshot.entries.items.len) return error.PendingSourceMissing;
        var staged = std.ArrayList(Retained).init(self.allocator);
        errdefer {
            for (staged.items) |entry| entry.deinit(self.allocator);
            staged.deinit();
        }
        try staged.ensureTotalCapacityPrecise(self.sources.max_sources);
        for (snapshot.entries.items) |entry| staged.appendAssumeCapacity(try cloneRetained(self.allocator, entry));
        self.retained.deinit();
        self.retained = staged;
        self.candidate_source = if (snapshot.candidate_index) |index| self.retained.items[index].source else null;
        self.pipe.candidate_receipt = snapshot.candidate_receipt;
        self.discovery_repair = snapshot.discovery_repair;
        self.notices = snapshot.notices;
    }

    fn retainedSource(self: *Session, source: []const u8) ?*Retained {
        for (self.retained.items) |*value| if (std.mem.eql(u8, value.source, source)) return value;
        return null;
    }
    fn addRetained(self: *Session, source: []const u8, path: []const u8, state: repair.Repair, source_health: records.Health, in_operation: bool, expected_durable: bool, incarnation: ?[16]u8, pending: ?durable.Store.PendingSource) !void {
        if (self.retained.items.len >= self.sources.max_sources) return error.SourceLimit;
        const source_copy = try self.allocator.dupe(u8, source);
        errdefer self.allocator.free(source_copy);
        const path_copy = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(path_copy);
        const proof = if (pending) |value| try clonePending(self.allocator, value) else null;
        errdefer if (proof) |value| value.deinit(self.allocator);
        try self.retained.append(.{ .source = source_copy, .path = path_copy, .state = state, .health = source_health, .in_operation = in_operation, .expected_durable = expected_durable, .incarnation = incarnation, .pending = proof });
    }
    pub fn copyRepairStateFrom(self: *Session, old: *const Session) !void {
        if (old.repair_count != old.sources.sources.items.len) return error.RestoreRequired;
        if (self.admission_phase != .positions or self.sources.sources.items.len != 0 or self.retained.items.len != 0) return error.RecoveryOutOfOrder;
        if (!std.mem.eql(u8, &self.processor.generation, &old.processor.generation)) return error.SourceGenerationMismatch;
        errdefer {
            for (self.retained.items) |value| value.deinit(self.allocator);
            self.retained.clearRetainingCapacity();
        }
        for (old.sources.sources.items, 0..) |source, index| {
            try self.addRetained(source.source_id, source.path, old.repair_states[index], source.health, source.in_operation, source.baseline_committed, if (source.committed) |saved| saved.incarnation else null, old.pending_proofs[index]);
        }
        for (old.retained.items) |value| if (self.retainedSource(value.source) == null) {
            try self.addRetained(value.source, value.path, value.state, value.health, value.in_operation, value.expected_durable, value.incarnation, value.pending);
        };
        if (old.pipe.candidate_receipt != null) {
            const source = old.candidate_source orelse return error.PendingSourceMissing;
            self.candidate_source = (self.retainedSource(source) orelse return error.PendingSourceMissing).source;
        }
        self.pipe.candidate_receipt = old.pipe.candidate_receipt;
        self.discovery_repair = old.discovery_repair;
        self.notices = old.notices;
    }
    pub fn retainSourcesFrom(self: *Session, old: *const Session) !void {
        if (self.admission_phase != .positions or self.sources.sources.items.len != 0) return error.RecoveryOutOfOrder;
        if (!std.mem.eql(u8, &self.processor.generation, &old.processor.generation)) return error.SourceGenerationMismatch;
        for (self.retained.items) |*value| {
            if (value.descriptor != null) return error.RecoveryOutOfOrder;
            var descriptor: ?std.fs.File = null;
            var proposal: ?files.Resume = null;
            for (old.sources.sources.items) |source| if (std.mem.eql(u8, source.source_id, value.source)) {
                descriptor = source.file;
                if (!source.baseline_committed) proposal = source.committed;
                break;
            };
            if (descriptor == null or proposal == null) for (old.retained.items) |previous| if (std.mem.eql(u8, previous.source, value.source)) {
                if (descriptor == null) descriptor = previous.descriptor;
                if (!value.expected_durable and proposal == null) proposal = previous.proposal;
                break;
            };
            if (descriptor) |file| value.descriptor = .{ .handle = @intCast(try std.posix.fcntl(file.handle, linux_dupfd_cloexec, 3)) };
            value.proposal = proposal;
        }
    }
    pub fn verifyRecoverySources(self: *Session) !void {
        if (self.pipe.gate) |gate| {
            const status = gate.snapshot();
            if (status.phase != .recovering or status.recovery_step != .sources) return error.RecoveryOutOfOrder;
        }
        if (!self.pipe.ready) return error.RestoreRequired;
        for (self.sources.sources.items) |*source| if (!try source.verifyContinuity()) return error.ResumeLost;
        try self.pipe.store.visitPendingReceipts(restorePending, self);
        if (try self.pipe.store.revision(self.pipe.jail) != self.pipe.revision) return error.StaleCheckpoint;
    }
    fn bindFile(source: *files.FileSource, context: ?*anyopaque) !void {
        const self: *Session = @ptrCast(@alignCast(context.?));
        try self.processor.bindFile(source);
        if (self.consumer_sources) |binding| binding.admit(source.source_id, self.processor.generation, binding.context) catch |err| return self.storageFailure(err);
    }
    fn monotonic(context: ?*anyopaque) u64 {
        const self: *Session = @ptrCast(@alignCast(context.?));
        return self.nowMs();
    }
    fn nowMs(self: *Session) u64 {
        if (self.scheduler_clock) |clock| return clock.read(clock.context);
        return self.notices.read() / std.time.ns_per_ms;
    }
    fn initializeRepairs(self: *Session) !void {
        while (self.repair_count < self.sources.sources.items.len) : (self.repair_count += 1) {
            const source = &self.sources.sources.items[self.repair_count];
            if (self.retainedSource(source.source_id)) |previous| {
                if (previous.incarnation) |expected| {
                    const saved = source.committed orelse return error.MissingFileCheckpoint;
                    if (!std.mem.eql(u8, &expected, &saved.incarnation)) return error.ResumeLost;
                }
                self.repair_states[self.repair_count] = previous.state;
                self.pending_proofs[self.repair_count] = previous.pending;
                previous.pending = null;
                source.health = previous.health;
                source.in_operation = previous.in_operation;
            } else self.repair_states[self.repair_count] = try repair.Repair.init(try repair.Binding.init(self.processor.generation, source.source_id), self.nowMs());
        }
    }
    pub fn sourceRepairSnapshot(self: *const Session, index: usize) !repair.Snapshot {
        if (index >= self.repair_count) return error.InvalidSource;
        return self.repair_states[index].snapshot();
    }
    pub fn repairSnapshot(self: *const Session) repair.Snapshot {
        var result = self.discovery_repair.snapshot();
        for (self.repair_states[0..self.repair_count]) |state| {
            const candidate = state.snapshot();
            if (candidate.phase == .intervention) return candidate;
            if (result.phase == .healthy and candidate.phase != .healthy) result = candidate;
        }
        for (self.retained.items) |value| {
            var adopted = false;
            for (self.sources.sources.items) |source| if (std.mem.eql(u8, source.source_id, value.source)) {
                adopted = true;
                break;
            };
            if (adopted) continue;
            const candidate = value.state.snapshot();
            if (candidate.phase == .intervention) return candidate;
            if (result.phase == .healthy and candidate.phase != .healthy) result = candidate;
        }
        return result;
    }
    fn storageFailure(self: *Session, cause: anyerror) anyerror {
        self.last_failure_domain = .storage;
        self.pipe.ready = false;
        if (self.pipe.gate) |gate| gate.failed(cause, .{ .sqlite_code = self.pipe.store.last_error_code, .rollback_code = self.pipe.store.rollback_error_code, .reopen_required = self.pipe.store.reopen_required });
        return cause;
    }
    fn sourceFailure(self: *Session, state: *repair.Repair, cause: anyerror) anyerror {
        const domain = state.failed(cause, self.nowMs()) catch |failure| return failure;
        self.last_failure_domain = domain;
        self.sources.health = switch (cause) {
            error.SourceRepairPending => .waiting,
            error.FileNotFound => .missing,
            error.AccessDenied => .permission_denied,
            error.ResumeLost, error.PendingRecordMismatch, error.PendingRecordUnavailable => .resume_lost,
            else => if (domain == .storage) .commit_failed else .read_failed,
        };
        return switch (domain) {
            .pending, .transient_source => error.SourceRepairPending,
            .source_intervention => error.SourceInterventionRequired,
            .storage => self.storageFailure(cause),
        };
    }
    fn sourceBinding(self: *Session, source: *const files.FileSource, pending: anytype) !repair.Binding {
        var result = try repair.Binding.init(self.processor.generation, source.source_id);
        if (pending) |saved| {
            if (!std.mem.eql(u8, &saved.identity.generation, &self.processor.generation)) return error.SourceGenerationMismatch;
            result = try result.withPending(saved.identity.occurrence, saved.identity.cursor, saved.identity.raw_hash, saved.receipt_us);
        }
        return result;
    }
    fn bindPending(self: *Session, index: usize, pending: ?durable.Store.PendingSource) !repair.Binding {
        const state = &self.repair_states[index];
        const binding = try self.sourceBinding(&self.sources.sources.items[index], pending);
        if (state.state.phase != .healthy and !std.meta.eql(state.binding, binding)) {
            if (pending != null or state.binding.pending_digest == null) return error.PendingRecordMismatch;
            const proof = self.pending_proofs[index] orelse return error.PendingRecordMismatch;
            const original = try self.sourceBinding(&self.sources.sources.items[index], @as(?durable.Store.PendingSource, proof));
            if (!std.meta.eql(original, state.binding)) return error.PendingRecordMismatch;
            const committed = self.pipe.store.committedReceipt(proof.identity) catch |err| return self.storageFailure(err);
            if (committed == null or committed.?.us != proof.receipt_us) return error.PendingRecordMismatch;
            try state.resolveCommittedPending(original);
        }
        if (pending) |saved| {
            const replacement = try clonePending(self.allocator, saved);
            if (self.pending_proofs[index]) |value| value.deinit(self.allocator);
            self.pending_proofs[index] = replacement;
        } else {
            if (self.pending_proofs[index]) |value| value.deinit(self.allocator);
            self.pending_proofs[index] = null;
        }
        if (state.state.phase == .healthy) try state.bindHealthy(binding);
        return binding;
    }
    fn verifySourceTurn(self: *Session, index: usize) !void {
        const source = &self.sources.sources.items[index];
        const state = &self.repair_states[index];
        if (state.state.phase == .intervention) return error.SourceInterventionRequired;
        var token: ?repair.Token = null;
        if (state.state.phase != .healthy) {
            token = try state.begin(self.nowMs(), true);
            if (token == null) return error.SourceRepairPending;
        }
        const pending = self.pipe.store.readPendingSource(self.allocator, self.pipe.jail, source.source_id) catch |err| return self.storageFailure(err);
        defer if (pending) |saved| saved.deinit(self.allocator);
        const binding = self.bindPending(index, pending) catch |err| return if (self.last_failure_domain == .storage) err else self.sourceFailure(state, err);
        if (token != null) token = try state.begin(self.nowMs(), true);
        if (source.file == null) if (self.retainedSource(source.source_id)) |previous| if (previous.descriptor) |descriptor| {
            source.attachRetained(descriptor) catch |err| return self.sourceFailure(state, err);
            descriptor.close();
            previous.descriptor = null;
        };
        const continuous = source.verifyContinuityTurn() catch |err| return self.sourceFailure(state, err);
        if (!continuous) return self.sourceFailure(state, error.FileNotFound);
        if (pending) |saved| source.verifyPending(.{ .source = saved.identity.source, .occurrence = saved.identity.occurrence, .cursor = saved.identity.cursor, .raw_hash = saved.identity.raw_hash }) catch |err| return self.sourceFailure(state, err);
        if (token) |value| if (state.state.phase == .verifying) state.continuityVerified(value, binding) catch |err| return self.sourceFailure(state, err);
    }
    fn sourceIoAdmission(self: *Session) !void {
        if (!self.pipe.ready) return error.RestoreRequired;
        if (self.pipe.gate) |gate| {
            const status = gate.snapshot();
            if (status.phase != .healthy and !(status.phase == .recovering and status.recovery_step == .sources)) return error.RecoveryOutOfOrder;
            if (status.generation != self.pipe.recovery_generation) return error.RestoreRequired;
        }
    }
    pub fn admissionTurn(self: *Session) !bool {
        try self.sourceIoAdmission();
        self.last_failure_domain = null;
        switch (self.admission_phase) {
            .positions => {
                const position = self.pipe.store.readSourcePosition(self.allocator, self.pipe.jail, self.restore_after, self.pipe.revision) catch |err| return self.storageFailure(err);
                if (position) |saved| {
                    defer saved.deinit(self.allocator);
                    const parsed = try std.json.parseFromSlice(files.Resume, self.allocator, saved.cursor, .{});
                    defer parsed.deinit();
                    if (saved.path.len == 0) return error.InvalidFileCursor;
                    try self.sources.addResume(saved.path, saved.source, parsed.value);
                    try self.initializeRepairs();
                    self.restore_after = self.sources.sources.items[self.sources.sources.items.len - 1].source_id;
                } else self.admission_phase = .proposals;
            },
            .proposals => {
                if (self.retained_index < self.retained.items.len) {
                    const previous = &self.retained.items[self.retained_index];
                    var exists = false;
                    for (self.sources.sources.items) |source| if (std.mem.eql(u8, source.source_id, previous.source)) {
                        exists = true;
                        break;
                    };
                    if (!exists) {
                        if (previous.expected_durable) return error.MissingFileCheckpoint;
                        const proposal = previous.proposal orelse return error.MissingFileCheckpoint;
                        try self.sources.addProposal(previous.path, previous.source, proposal);
                        try self.initializeRepairs();
                    }
                    self.retained_index += 1;
                } else self.admission_phase = .continuity;
            },
            .continuity => {
                if (self.admission_index < self.sources.sources.items.len) {
                    try self.verifySourceTurn(self.admission_index);
                    self.admission_index += 1;
                } else self.admission_phase = .pending;
            },
            .pending => {
                if (try self.pendingTurn(&self.pending_after)) self.admission_phase = .discovery;
            },
            .discovery => {
                if (try self.discoveryTurn()) {
                    if (try self.pipe.store.revision(self.pipe.jail) != self.pipe.revision) return self.storageFailure(error.StaleCheckpoint);
                    self.admission_phase = .ready;
                    self.discover_next = false;
                }
            },
            .ready => return true,
        }
        return self.admission_phase == .ready;
    }
    fn pendingTurn(self: *Session, after: *?[]const u8) !bool {
        const pending = self.pipe.store.readPendingPosition(self.allocator, self.pipe.jail, after.*) catch |err| return self.storageFailure(err);
        const saved = pending orelse return true;
        defer saved.deinit(self.allocator);
        for (self.sources.sources.items, 0..) |source, index| {
            if (!std.mem.eql(u8, source.source_id, saved.identity.source)) continue;
            try self.verifySourceTurn(index);
            after.* = source.source_id;
            return false;
        }
        return error.PendingSourceMissing;
    }
    pub fn verifyRecoverySourcesTurn(self: *Session) !bool {
        try self.sourceIoAdmission();
        if (self.admission_phase != .ready) return self.admissionTurn();
        if (!self.recovery_pending) {
            if (self.recovery_index < self.sources.sources.items.len) {
                try self.verifySourceTurn(self.recovery_index);
                self.recovery_index += 1;
                return false;
            }
            self.recovery_pending = true;
        }
        if (!try self.pendingTurn(&self.recovery_after)) return false;
        if (try self.pipe.store.revision(self.pipe.jail) != self.pipe.revision) return self.storageFailure(error.StaleCheckpoint);
        self.recovery_index = 0;
        self.recovery_pending = false;
        self.recovery_after = null;
        return true;
    }
    fn discoveryTurn(self: *Session) !bool {
        const state = &self.discovery_repair;
        if (state.state.phase == .intervention) return error.SourceInterventionRequired;
        var token: ?repair.Token = null;
        if (state.state.phase != .healthy) {
            token = try state.begin(self.nowMs(), true);
            if (token == null) return error.SourceRepairPending;
            if (state.state.phase == .polling) return true;
        }
        const result = self.sources.discoverTurn() catch |err| {
            if (self.last_failure_domain == .storage) return err;
            return self.sourceFailure(state, err);
        };
        try self.initializeRepairs();
        if (result != .complete) return false;
        if (self.sources.sources.items.len == 0) return self.sourceFailure(state, error.FileNotFound);
        if (token) |value| try state.continuityVerified(value, state.binding);
        return true;
    }
    const Acknowledgment = struct {
        session: *Session,
        pending: ?durable.ReceiptIdentity,
        committing: bool = false,
        fn run(record: records.Record, context: ?*anyopaque) !void {
            const self: *Acknowledgment = @ptrCast(@alignCast(context.?));
            if (self.pending) |expected| {
                if (record.kind != .data or !std.mem.eql(u8, record.source, expected.source) or !std.mem.eql(u8, record.occurrence, expected.occurrence) or !std.mem.eql(u8, record.cursor, expected.cursor) or !std.mem.eql(u8, &record.raw_hash, &expected.raw_hash)) return error.PendingRecordMismatch;
            }
            self.committing = true;
            pipeline.Pipeline.acknowledge(record, &self.session.pipe) catch |err| {
                if (self.session.pipe.candidate_receipt != null) self.session.candidate_source = record.source;
                return err;
            };
            if (self.session.pipe.candidate_receipt == null) self.session.candidate_source = null;
            self.committing = false;
            self.pending = null;
        }
    };
    pub fn pollTurn(self: *Session, budget: usize) !usize {
        defer self.logNotices();
        if (budget == 0 or budget > self.sources.max_sources) return error.InvalidPollBudget;
        try self.pipe.admit();
        if (self.admission_phase != .ready) {
            _ = try self.admissionTurn();
            return 0;
        }
        self.last_failure_domain = null;
        if (self.discover_next and self.candidate_source == null) {
            self.discover_next = false;
            _ = try self.discoveryTurn();
            return 0;
        }
        self.discover_next = true;
        const count = self.sources.sources.items.len;
        if (count == 0) return error.SourceRepairPending;
        var index = self.next_source % count;
        if (self.candidate_source) |candidate| {
            var found = false;
            for (self.sources.sources.items, 0..) |source, i| if (std.mem.eql(u8, source.source_id, candidate)) {
                index = i;
                found = true;
                break;
            };
            if (!found) return error.PendingSourceMissing;
        }
        self.next_source = (index + 1) % count;
        return self.pollSourceTurn(index);
    }
    pub fn resumeConsumerSource(self: *Session, source_id: []const u8) !usize {
        try self.pipe.admit();
        if (self.admission_phase != .ready) return error.RestoreRequired;
        self.last_failure_domain = null;
        if (self.candidate_source) |candidate| if (!std.mem.eql(u8, candidate, source_id)) return error.PendingRecordMismatch;
        for (self.sources.sources.items, 0..) |source, index| if (std.mem.eql(u8, source.source_id, source_id)) {
            const pending = (try self.pipe.store.readPendingSource(self.allocator, self.pipe.jail, source_id)) orelse return error.PendingRecordUnavailable;
            defer pending.deinit(self.allocator);
            if (!std.mem.eql(u8, &pending.identity.generation, &self.processor.generation)) return error.SourceGenerationMismatch;
            return self.pollSourceTurn(index);
        };
        return error.PendingSourceMissing;
    }
    fn pollSourceTurn(self: *Session, index: usize) !usize {
        const source = &self.sources.sources.items[index];
        const state = &self.repair_states[index];
        if (state.state.phase == .intervention) return error.SourceInterventionRequired;
        if (state.state.phase == .waiting or state.state.phase == .verifying) {
            try self.verifySourceTurn(index);
            return 0;
        }
        const pending = self.pipe.store.readPendingSource(self.allocator, self.pipe.jail, source.source_id) catch |err| return self.storageFailure(err);
        defer if (pending) |saved| saved.deinit(self.allocator);
        _ = self.bindPending(index, pending) catch |err| return if (self.last_failure_domain == .storage) err else self.sourceFailure(state, err);
        var acknowledgment = Acknowledgment{ .session = self, .pending = if (pending) |saved| saved.identity else null };
        const delivered = source.pollTurn(Acknowledgment.run, &acknowledgment, pending != null or self.candidate_source != null or state.state.phase == .polling) catch |err| {
            if (acknowledgment.committing) {
                if (pipeline.Pipeline.sourceLocalIntervention(err)) return self.sourceFailure(state, err);
                self.last_failure_domain = if (repair.classify(err) == .pending) .pending else .storage;
                return err;
            }
            return self.sourceFailure(state, err);
        };
        if (source.health == .healthy) {
            if (state.state.phase == .polling) try state.pollSucceeded((try state.begin(self.nowMs(), true)).?);
            if (self.discovery_repair.state.phase == .polling) try self.discovery_repair.pollSucceeded((try self.discovery_repair.begin(self.nowMs(), true)).?);
        }
        self.sources.health = source.health;
        return @intFromBool(delivered);
    }

    fn restoreSource(source: []const u8, path: []const u8, cursor: []const u8, context: ?*anyopaque) !void {
        const self: *Session = @ptrCast(@alignCast(context.?));
        if (path.len == 0) return error.InvalidFileCursor;
        const parsed = try std.json.parseFromSlice(files.Resume, self.allocator, cursor, .{});
        defer parsed.deinit();
        try self.sources.addResume(path, source, parsed.value);
        if (!try self.sources.sources.items[self.sources.sources.items.len - 1].verifyContinuity()) return error.ResumeLost;
    }
    const PendingProbe = struct {
        identity: durable.ReceiptIdentity,
        fn verify(record: records.Record, context: ?*anyopaque) !void {
            const self: *PendingProbe = @ptrCast(@alignCast(context.?));
            const saved = self.identity;
            if (record.kind != .data or !std.mem.eql(u8, record.source, saved.source) or !std.mem.eql(u8, record.occurrence, saved.occurrence) or
                !std.mem.eql(u8, record.cursor, saved.cursor) or !std.mem.eql(u8, &record.raw_hash, &saved.raw_hash)) return error.PendingRecordMismatch;
            return error.PendingRecordVerified;
        }
    };
    fn restorePending(identity: durable.ReceiptIdentity, _: time.Timestamp, context: ?*anyopaque) !void {
        const self: *Session = @ptrCast(@alignCast(context.?));
        if (!std.mem.eql(u8, identity.jail, self.pipe.jail)) return;
        if (!std.mem.eql(u8, &identity.generation, &self.processor.generation)) return error.SourceGenerationMismatch;
        for (self.sources.sources.items, 0..) |*source, index| {
            if (!std.mem.eql(u8, source.source_id, identity.source)) continue;
            var probe = PendingProbe{ .identity = identity };
            _ = source.poll(PendingProbe.verify, &probe) catch |err| {
                if (err != error.PendingRecordVerified) return err;
                source.health = .healthy;
                self.next_source = index;
                return;
            };
            return error.PendingRecordUnavailable;
        }
        return error.PendingSourceMissing;
    }
    fn logNotices(self: *Session) void {
        if (self.processor.timeNotice(self.notices.read() / std.time.ns_per_ms)) |notice| std.log.scoped(.source_time).warn(
            "jail {s}: rejected timestamps: missing={d}, malformed={d}, future={d}; records excluded from detection evidence",
            .{ self.pipe.jail, notice.missing_since_notice, notice.malformed_since_notice, notice.future_since_notice },
        );
    }
    pub fn poll(self: *Session, budget: usize) !usize {
        defer self.logNotices();
        if (budget == 0 or budget > self.sources.max_sources) return error.InvalidPollBudget;
        self.pipe.admit() catch |err| {
            if (err == error.ReceiptClockReversed) self.sources.health = .clock_failed;
            return err;
        };
        try self.sources.discover();
        const count = self.sources.sources.items.len;
        if (count == 0) return 0;
        var delivered: usize = 0;
        for (0..@min(budget, count)) |_| {
            const index = self.next_source % count;
            self.next_source = (index + 1) % count;
            const source = &self.sources.sources.items[index];
            if (source.poll(pipeline.Pipeline.acknowledge, &self.pipe) catch |err| {
                self.next_source = index;
                self.sources.health = if (err == error.ReceiptClockReversed) .clock_failed else source.health;
                return err;
            }) delivered += 1;
        }
        return delivered;
    }
};

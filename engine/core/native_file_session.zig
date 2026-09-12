// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Native file ingestion owner: restore exact cursors and pending receipts before
//! discovery, then stage native decoding/time checkpoints through SQLite.
const std = @import("std");
const processing = @import("native_source_processor.zig");
const files = @import("durable_file_source.zig");
const durable = @import("record_store.zig");
const pipeline = @import("record_pipeline.zig");
const records = @import("source_record.zig");
const time = @import("native_time.zig");
const storage_health = @import("storage_health.zig");

pub const Spec = struct { pattern: []const u8, start: files.Start = .head };
pub const Options = struct {
    processing: processing.Options,
    detection: ?@import("native_detection_record.zig").Consumer = null,
    retry: ?@import("native_retry.zig").Policy = null,
    max_sources: usize,
    gate: ?*storage_health.Gate = null,
    clock_context: ?*anyopaque = null,
    clock: ?*const fn (?*anyopaque) anyerror!time.Timestamp = null,
};
pub const Session = struct {
    allocator: std.mem.Allocator,
    scratch: []u8,
    processor: processing.Processor,
    sources: files.FileSet,
    pipe: pipeline.Pipeline,
    next_source: usize = 0,
    notices: std.time.Timer,

    /// Store admission/migration belongs to the coordinator, before constructing
    /// any owner. Config strings and store must outlive this stable allocation.
    pub fn create(allocator: std.mem.Allocator, store: *durable.Store, options: Options, specs: []const Spec) !*Session {
        const admitted = store.receipt_limit orelse return error.ReceiptStorageRequired;
        if (store.schema_version < 4 or store.schema_version > durable.latest_schema) return error.NativeTimeStorageRequired;
        if (options.detection != null and store.schema_version < 6) return error.DetectionStorageRequired;
        if (options.max_sources == 0 or options.max_sources > admitted or specs.len == 0 or specs.len > options.max_sources) return error.InvalidSourceLimit;
        for (specs) |spec| if (spec.pattern.len == 0 or spec.pattern.len > durable.Limits.source_bytes or std.mem.indexOfScalar(u8, spec.pattern, 0) != null) return error.InvalidSourceSpecification;
        if (options.processing.max_decoded_bytes == 0 or options.processing.max_decoded_bytes > @import("source_text.zig").max_record_bytes) return error.InvalidSourceLimits;
        if (options.processing.timestamp == .journal) return error.InvalidFileTimestampSource;
        if (options.processing.timestamp == .field and options.processing.timestamp.field.infer_year and store.schema_version < 5) return error.InferenceStorageRequired;
        var receipt_clock = pipeline.ReceiptAdmission{ .generation = [_]u8{0} ** 32, .clock_context = options.clock_context };
        if (options.clock) |read| receipt_clock.clock = read;
        const now = try receipt_clock.clock(receipt_clock.clock_context);
        const self = try allocator.create(Session);
        errdefer allocator.destroy(self);
        self.allocator = allocator;
        self.scratch = try allocator.alloc(u8, options.processing.max_decoded_bytes);
        errdefer allocator.free(self.scratch);
        const configuration = try std.json.stringifyAlloc(allocator, .{ .parent = options.processing.parent_generation, .sources = specs, .maximum_sources = options.max_sources }, .{});
        defer allocator.free(configuration);
        var bound = options.processing;
        std.crypto.hash.sha2.Sha256.hash(configuration, &bound.parent_generation, .{});
        self.processor = try processing.Processor.initWithDetection(allocator, bound, self.scratch, now, options.detection);
        if (options.retry) |policy| {
            try self.processor.bindRetry(policy);
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
        receipt_clock.generation = self.processor.generation;
        self.pipe = .{ .store = store, .jail = self.sources.jail, .processor = self.processor.adapter(), .gate = options.gate, .receipts = receipt_clock };
        try self.pipe.restore(allocator);
        try store.visitSources(self.pipe.jail, restoreSource, self);
        try store.visitPendingReceipts(restorePending, self);
        if (try store.revision(self.pipe.jail) != self.pipe.revision) return error.StaleCheckpoint;
        try self.sources.discover();
        return self;
    }
    pub fn destroy(self: *Session) void {
        std.debug.assert(!self.processor.in_flight);
        self.sources.deinit();
        self.allocator.free(self.scratch);
        self.allocator.destroy(self);
    }

    /// Recheck after ownership recovery, immediately before reopening admission.
    /// Restore this owner's state first; a clock catch-up cannot replace source
    /// validation because rotation/retention may have removed pending evidence.
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
    }
    fn restoreSource(source: []const u8, path: []const u8, cursor: []const u8, context: ?*anyopaque) !void {
        const self: *Session = @ptrCast(@alignCast(context.?));
        if (path.len == 0) return error.InvalidFileCursor;
        const parsed = try std.json.parseFromSlice(files.Resume, self.allocator, cursor, .{});
        defer parsed.deinit();
        // Tail controls the first attachment only. A saved tail position is just
        // as authoritative as a saved head position; downtime must not skip data.
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
            // Deliberate abort: validation must never acknowledge the proposed
            // cursor or publish processor state during source restoration.
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

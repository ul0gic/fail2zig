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
    retry: ?@import("native_retry.zig").Policy = null,
    journal: transport.Options = .{},
    source_id: []const u8 = "system-journal",
    gate: ?*health.Gate = null,
    clock_context: ?*anyopaque = null,
    clock: ?*const fn (?*anyopaque) anyerror!time.Timestamp = null,
    executor: transport.Executor = .{},
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

    /// Borrowed configuration/clock/executor context and store must outlive this
    /// stable owner. Store schema admission belongs to the global coordinator.
    pub fn create(a: std.mem.Allocator, store: *durable.Store, options: Options) !*Session {
        if (store.receipt_limit == null) return error.ReceiptStorageRequired;
        if (store.schema_version < 4 or store.schema_version > durable.latest_schema) return error.NativeTimeStorageRequired;
        if (options.detection != null and store.schema_version < 8) return error.JournalDetectionStorageRequired;
        try transport.validate(options.journal);
        if (options.source_id.len == 0 or options.source_id.len > 512 or std.mem.indexOfScalar(u8, options.source_id, 0) != null) return error.InvalidJournalSource;
        if (options.processing.timestamp != .journal or options.processing.max_record_bytes > 64 * 1024 or options.processing.max_decoded_bytes > 64 * 1024 or options.processing.max_decoded_bytes == 0) return error.InvalidJournalProcessing;
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
        const specification = try std.json.stringifyAlloc(a, .{ .version = 1, .parent = options.processing.parent_generation, .source = options.source_id, .journal = options.journal }, .{});
        defer a.free(specification);
        var bound = options.processing;
        std.crypto.hash.sha2.Sha256.hash(specification, &bound.parent_generation, .{});
        self.processor = try native.Processor.initWithJournalDetection(a, bound, self.decode_scratch, now, options.detection);
        if (options.retry) |policy| {
            try self.processor.bindRetry(policy);
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
        try self.pipe.restore(a);
        try store.visitSources(self.pipe.jail, restoreSource, self);
        try self.checkStartClock();
        if (self.pipe.revision != 0 and !self.baseline_committed) return error.MissingJournalCheckpoint;
        if (self.baseline_committed) {
            // Exact anchor verification also applies when no pending receipt exists.
            _ = try self.fetch(1);
        } else {
            var lines = try self.query(.tail, 1);
            if (try lines.next()) |line| {
                const entry = try transport.decode(self.parse_scratch, line, options.processing.max_record_bytes);
                self.position = try self.position.withCursor(entry.cursor);
            }
            if (try lines.next() != null) return error.JournalRecordLimit;
        }
        try store.visitPendingReceipts(restorePending, self);
        if (try store.revision(self.pipe.jail) != self.pipe.revision) return error.StaleCheckpoint;
        return self;
    }
    pub fn destroy(self: *Session) void {
        std.debug.assert(!self.processor.in_flight);
        self.allocator.free(self.output);
        self.allocator.free(self.parse_scratch);
        self.allocator.free(self.decode_scratch);
        self.allocator.destroy(self);
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
    fn reportNotices(self: *Session) void {
        if (self.processor.timeNotice(self.notices.read() / std.time.ns_per_ms)) |notice| std.log.scoped(.source_time).warn("jail {s}: rejected journal timestamps: missing={d}, malformed={d}, future={d}", .{ self.pipe.jail, notice.missing_since_notice, notice.malformed_since_notice, notice.future_since_notice });
    }
    fn pollAdmitted(self: *Session, budget: usize, committing: *bool) !usize {
        if (budget == 0 or budget > self.options.journal.batch_records) return error.InvalidPollBudget;
        try self.pipe.admit();
        try self.checkStartClock();
        if (!self.baseline_committed) {
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
            committing.* = true;
            try pipeline.Pipeline.acknowledge(candidate, &self.pipe);
            committing.* = false;
            if (self.pipe.revision == revision) return error.RepeatedJournalCursor;
            self.position = next;
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

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Native source decoding/time admission. Immutable configuration, caller-owned
//! scratch and a fixed checkpoint replace worker state on this path. An optional
//! stateless detector consumes the decoded slice and stages a typed outcome in
//! the same transaction. Optional retry policy joins that transaction in SQLite;
//! correlation and enforcement integration remain separate work.
const std = @import("std");
const text = @import("source_text.zig");
const time = @import("native_time.zig");
const inference = @import("year_inference.zig");
const policy = @import("source_time_policy.zig");
const records = @import("source_record.zig");
const pipeline = @import("record_pipeline.zig");
const files = @import("durable_file_source.zig");
const detection = @import("native_detection_record.zig");
const retry = @import("native_retry.zig");

pub const Field = struct {
    format: time.Format,
    start: u32 = 0,
    /// Select one complete configured field: fixed width, or a single byte
    /// delimiter. This is not a date search, regular expression or log grammar.
    boundary: union(enum) { length: u8, delimiter: u8 },
    context: time.Context = .{},
    /// Opt-in only for syslog with an explicit fixed offset and no explicit year.
    infer_year: bool = false,
};
pub const TimestampSource = union(enum) { field: Field, journal, undated };
pub const Options = struct {
    jail: []const u8,
    parent_generation: [32]u8,
    encoding: text.Encoding = .utf8,
    bom: text.Bom = .preserve,
    timestamp: TimestampSource,
    window_us: i64 = 600_000_000,
    max_record_bytes: u32 = 2048,
    max_decoded_bytes: u32 = 2048,
};
pub const checkpoint_version: u16 = 1;
pub const checkpoint_bytes = 96;
const counter_fields = .{ "eligible", "obsolete", "missing", "malformed", "receipt", "adjusted", "future" };

pub const Processor = struct {
    options: Options,
    generation: [32]u8,
    scratch: []u8,
    now: time.Timestamp,
    /// Native sessions sample processing time after receipt durability/decoding.
    /// Standalone users can instead supply an explicit clock with setClock.
    processing_clock: ?struct { read: *const fn (?*anyopaque) anyerror!time.Timestamp, context: ?*anyopaque } = null,
    health: policy.Health = .{},
    in_flight: bool = false,
    staged_counters: policy.Counters = .{},
    staged_bytes: [checkpoint_bytes]u8 = undefined,
    restoring: bool = false,
    detector: ?detection.Consumer = null,
    journal_detector: ?detection.JournalConsumer = null,
    retry_policy: ?retry.Policy = null,

    /// Configure before source framing/receipt admission. The policy participates
    /// in the source generation; previous evidence-only checkpoints cannot be
    /// silently reused with an empty retry window.
    pub fn bindRetry(self: *Processor, value: retry.Policy) !void {
        if (self.in_flight or self.retry_policy != null) return error.ProcessorBusy;
        if (self.detector == null and self.journal_detector == null) return error.RetryDetectorRequired;
        if (value.window_us != self.options.window_us) return error.InvalidRetryPolicy;
        const encoded = try value.encode();
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("fail2zig-source-retry-v1\x00");
        hash.update(&self.generation);
        hash.update(&encoded);
        hash.final(&self.generation);
        self.retry_policy = value;
    }

    pub fn initWithJournalDetection(allocator: std.mem.Allocator, options: Options, scratch: []u8, now: time.Timestamp, consumer: ?detection.JournalConsumer) !Processor {
        if (options.timestamp != .journal) return error.InvalidJournalProcessing;
        var self = try init(allocator, options, scratch, now);
        if (consumer) |value| {
            if (options.encoding != .utf8 or options.bom != .preserve) return error.InvalidJournalProcessing;
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update("fail2zig-source-journal-detection-v1\x00");
            hash.update(&self.generation);
            hash.update(&value.generation);
            hash.final(&self.generation);
            self.journal_detector = value;
        }
        return self;
    }

    /// File detection receives the actual decoded slice before scratch is reused.
    /// Journals must use the separate origin-qualified consumer API above.
    pub fn initWithDetection(allocator: std.mem.Allocator, options: Options, scratch: []u8, now: time.Timestamp, consumer: ?detection.Consumer) !Processor {
        var self = try init(allocator, options, scratch, now);
        if (consumer) |value| {
            if (options.timestamp == .journal) return error.JournalOriginPolicyRequired;
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update("fail2zig-source-detection-v1\x00");
            hash.update(&self.generation);
            hash.update(&value.generation);
            hash.final(&self.generation);
            self.detector = value;
        }
        return self;
    }

    /// Config strings and exclusive scratch must outlive the stable processor.
    /// No record allocation or external helper is needed by this processor.
    pub fn init(allocator: std.mem.Allocator, options: Options, scratch: []u8, now: time.Timestamp) !Processor {
        if (options.jail.len == 0 or options.jail.len > 64 or std.mem.indexOfScalar(u8, options.jail, 0) != null) return error.InvalidJail;
        if (options.window_us < 0 or options.max_record_bytes < options.encoding.width() or options.max_record_bytes > text.max_record_bytes or
            options.max_decoded_bytes == 0 or options.max_decoded_bytes > text.max_record_bytes or scratch.len < options.max_decoded_bytes)
            return error.InvalidSourceLimits;
        switch (options.timestamp) {
            .field => |field| {
                if (field.start >= options.max_decoded_bytes) return error.InvalidTimestampField;
                switch (field.boundary) {
                    .length => |length| if (length == 0 or length > 64 or @as(u64, field.start) + length > options.max_decoded_bytes) return error.InvalidTimestampField,
                    .delimiter => |delimiter| if (delimiter == 0 or delimiter > 127) return error.InvalidTimestampField,
                }
                if (field.infer_year and (field.format != .syslog or field.context.year != null)) return error.InvalidYearInference;
                if (field.format == .syslog and ((!field.infer_year and field.context.year == null) or field.context.offset_seconds == null)) return error.SourceTimeContextRequired;
                if (field.context.year) |year| if (year == 0 or year > 9999) return error.InvalidTimeContext;
                if (field.context.offset_seconds) |offset| if (offset < -86340 or offset > 86340 or @mod(offset, 60) != 0) return error.InvalidTimeContext;
            },
            .journal => if (options.encoding != .utf8 or options.bom != .preserve) return error.InvalidJournalCodec,
            .undated => {},
        }
        const encoded = try std.json.stringifyAlloc(allocator, .{ .component = checkpoint_version, .inference_version = inference.version, .options = options }, .{});
        defer allocator.free(encoded);
        var parent: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(encoded, &parent, .{});
        return .{ .options = options, .generation = try policy.binding(parent, if (options.timestamp == .undated) .undated else .timestamped, options.window_us), .scratch = scratch[0..options.max_decoded_bytes], .now = now };
    }

    pub fn bindFile(self: *const Processor, source: *files.FileSource) !void {
        if (self.options.timestamp == .journal) return error.InvalidFileTimestampSource;
        try source.setNativeFraming(self.options.encoding, self.generation, self.options.max_record_bytes);
    }
    pub fn setClock(self: *Processor, now: time.Timestamp) !void {
        if (self.in_flight) return error.ProcessorBusy;
        self.now = now;
    }
    pub fn adapter(self: *Processor) pipeline.Processor {
        return .{ .context = self, .prepare = prepare, .prepare_restore = restore };
    }
    pub fn timeHealth(self: *const Processor) policy.Counters {
        return self.health.snapshot();
    }
    pub fn timeNotice(self: *Processor, monotonic_ms: u64) ?policy.Notice {
        return self.health.nextNotice(monotonic_ms);
    }

    fn encode(self: *Processor, counters: policy.Counters) void {
        @memcpy(self.staged_bytes[0..4], "F2NT");
        std.mem.writeInt(u16, self.staged_bytes[4..6], checkpoint_version, .little);
        @memset(self.staged_bytes[6..8], 0);
        @memcpy(self.staged_bytes[8..40], &self.generation);
        inline for (counter_fields, 0..) |field, i| std.mem.writeInt(u64, self.staged_bytes[40 + i * 8 ..][0..8], @field(counters, field), .little);
    }
    fn decode(self: *const Processor, bytes: []const u8) !policy.Counters {
        if (bytes.len != checkpoint_bytes or !std.mem.eql(u8, bytes[0..4], "F2NT")) return error.ForeignSourceCheckpoint;
        if (std.mem.readInt(u16, bytes[4..6], .little) != checkpoint_version or bytes[6] != 0 or bytes[7] != 0) return error.UnsupportedSourceCheckpoint;
        if (!std.mem.eql(u8, bytes[8..40], &self.generation)) return error.SourceGenerationMismatch;
        var counters = policy.Counters{};
        inline for (counter_fields, 0..) |field, i| @field(counters, field) = std.mem.readInt(u64, bytes[40 + i * 8 ..][0..8], .little);
        try counters.validate();
        return counters;
    }
    fn stage(self: *Processor, counters: policy.Counters, restoring: bool) void {
        self.staged_counters = counters;
        self.restoring = restoring;
        self.encode(counters);
        self.in_flight = true;
    }
    fn publish(context: ?*anyopaque) void {
        const self: *Processor = @ptrCast(@alignCast(context.?));
        if (self.restoring) self.health = policy.Health.init(self.staged_counters) catch unreachable else self.health.publish(self.staged_counters);
    }
    fn release(context: ?*anyopaque) void {
        const self: *Processor = @ptrCast(@alignCast(context.?));
        self.in_flight = false;
    }
    fn restore(saved: ?[]const u8, context: ?*anyopaque) !pipeline.Restored {
        const self: *Processor = @ptrCast(@alignCast(context.?));
        if (self.in_flight) return error.ProcessorBusy;
        const counters = if (saved) |bytes| try self.decode(bytes) else policy.Counters{};
        self.stage(counters, true);
        return .{ .context = self, .publish = publish, .release = release };
    }

    const ParsedField = struct { input: policy.Input, inferred_year: ?u16 = null };
    fn fieldInput(field: Field, decoded: []const u8, receipt: time.Timestamp) !ParsedField {
        if (field.start >= decoded.len) return .{ .input = .{ .rejected = .missing } };
        const remaining = decoded[field.start..];
        const value = switch (field.boundary) {
            .length => |length| if (remaining.len < length) return .{ .input = .{ .rejected = .malformed } } else remaining[0..length],
            .delimiter => |delimiter| remaining[0 .. std.mem.indexOfScalar(u8, remaining[0..@min(remaining.len, 65)], delimiter) orelse @min(remaining.len, 65)],
        };
        if (!field.infer_year) return .{ .input = try policy.parseField(field.format, value, field.context) };
        if (value.len == 0) return .{ .input = .{ .rejected = .missing } };
        const parsed = inference.infer(value, receipt, field.context.offset_seconds.?) catch |err| switch (err) {
            error.InvalidTimestamp, error.AmbiguousYear => return .{ .input = .{ .rejected = .malformed } },
            error.TimeOutOfRange => return .{ .input = .{ .rejected = .out_of_range } },
            else => return err,
        };
        return .{ .input = .{ .parsed = parsed.timestamp }, .inferred_year = parsed.year };
    }
    fn prepare(record: records.Record, context: ?*anyopaque) !pipeline.Prepared {
        const self: *Processor = @ptrCast(@alignCast(context.?));
        if (self.in_flight) return error.ProcessorBusy;
        if (record.predecoded != null) return error.ForeignDecodedRecord;
        var counters = self.health.snapshot();
        var outcome: ?policy.Result = null;
        var detected: ?detection.Outcome = null;
        var processing_us: ?i64 = null;
        if (record.kind == .data) {
            const receipt = record.receipt_time orelse return error.MissingReceiptTime;
            if (record.message.len > self.options.max_record_bytes) return error.RecordTooLarge;
            const offset = record.byte_start orelse 0;
            if (record.byte_start == null and self.options.timestamp != .journal) return error.MissingSourceOffset;
            const decoded = try text.decode(self.options.encoding, record.message, self.scratch, offset, self.options.bom);
            var inferred_year: ?u16 = null;
            const input: policy.Input = switch (self.options.timestamp) {
                .field => |field| blk: {
                    const parsed = try fieldInput(field, decoded, receipt);
                    inferred_year = parsed.inferred_year;
                    break :blk parsed.input;
                },
                .journal => if (record.timestamp_us) |stamp| blk: {
                    const timestamp = time.Timestamp.fromJournal(stamp) catch break :blk .{ .rejected = .out_of_range };
                    break :blk .{ .parsed = timestamp };
                } else .{ .rejected = .missing },
                .undated => .{ .rejected = .missing },
            };
            const now = if (self.processing_clock) |clock| try clock.read(clock.context) else self.now;
            processing_us = now.us;
            outcome = try policy.evaluate(if (self.options.timestamp == .undated) .undated else .timestamped, input, receipt, now, self.options.window_us);
            switch (outcome.?) {
                .eligible, .obsolete => |*e| e.inferred_year = inferred_year,
                .rejected => |*r| {
                    r.receipt = receipt;
                    r.inferred_year = inferred_year;
                },
            }
            counters = try counters.advanced(outcome.?);
            if (self.detector) |consumer| {
                detected = try consumer.evaluate(decoded, outcome.?, consumer.context);
                if (!std.mem.eql(u8, &detected.?.generation, &consumer.generation)) return error.DetectorGenerationMismatch;
                try detected.?.validate(outcome.?);
            }
            if (self.journal_detector) |consumer| {
                detected = try consumer.evaluate(decoded, record.journal_fields, outcome.?, consumer.context);
                if (!std.mem.eql(u8, &detected.?.generation, &consumer.generation)) return error.DetectorGenerationMismatch;
                try detected.?.validate(outcome.?);
            }
        }
        self.stage(counters, false);
        return .{ .checkpoint = &self.staged_bytes, .disposition = if (outcome) |value| value.disposition() else "source-checkpoint", .native_time = outcome, .native_detection = detected, .native_retry = if (self.retry_policy) |value| .{ .generation = self.generation, .policy = value, .processing_us = processing_us } else null, .context = self, .publish = publish, .release = release };
    }
};

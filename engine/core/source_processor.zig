// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Actual source decoding/date processing staged for the record transaction.
//! No matching, ticket mutation, action execution or daemon activation occurs here.
const std = @import("std");
const worker_mod = @import("compat_worker.zig");
const records = @import("source_record.zig");
const pipeline = @import("record_pipeline.zig");
const times = @import("event_time.zig");
const lines = @import("line_context.zig");
const Allocator = std.mem.Allocator;

pub const Options = struct {
    python: []const u8,
    script: []const u8,
    identity: worker_mod.Identity,
    encoding: []const u8 = "utf-8",
    date_patterns: []const []const u8,
    reference_year: u16,
    default_tz: ?[]const u8 = null,
    findtime: f64 = 600,
    mode: times.Mode = .startup,
    check_findtime: bool = true,
    deadline_ms: u64 = 2000,
    launch: worker_mod.LaunchOptions = .{},
    line_limits: lines.Limits = .{},
    /// Coordinator binding for ordered source selection and start policy.
    source_configuration_hash: ?[32]u8 = null,
    /// Bind prior compatibility conversions (for example findtime) to this helper.
    expected_profile_hash: ?[32]u8 = null,
};

pub const Observation = struct {
    source: []const u8,
    occurrence: []const u8,
    message: []const u8,
    codec_disposition: []const u8,
    codec_diagnostic: ?[]const u8,
    codec_warning_due: bool,
    date_kind: []const u8,
    date_raw_timestamp_bits: ?[]const u8,
    timestamp_us: ?u64,
    now_bits: []const u8,
    usage_time_bits: []const u8,
    disposition: times.Disposition,
    mode: times.Mode,
    raw_bits: ?[]const u8,
    effective_bits: ?[]const u8,
    stored_bits: ?[]const u8,
    origin: ?times.Origin,
    diagnostic: bool,
};
pub const Snapshot = struct {
    schema_version: u32 = 2,
    line_context: lines.Snapshot = .{},
    profile_hash: []const u8,
    config_generation: []const u8,
    configuration_hash: [32]u8,
    codec_context: std.json.Value,
    date_context: std.json.Value,
    last_date_bits: ?[]const u8 = null,
    last: ?Observation = null,
};

pub const ModeSelector = struct {
    /// Called with canonical decoded journal time during preparation. Any proposed
    /// coordinator state must publish only after the surrounding record commits.
    choose: *const fn (records.Record, times.EventTime, ?*anyopaque) anyerror!times.Mode,
    context: ?*anyopaque,
};
pub const SourceProcessor = struct {
    allocator: Allocator,
    /// Configuration strings must outlive this processor.
    options: Options,
    worker: worker_mod.Worker,
    sequence: u64 = 0,
    max_requests: u64 = std.math.maxInt(u64),
    max_record_bytes: usize = 0,
    in_flight: bool = false,
    owned_epoch: ?[]u8 = null,
    mode_selector: ?ModeSelector = null,
    committed: []u8,
    initial: []u8,
    profile_hash: []u8,
    now: f64,
    usage_time: f64,

    pub fn init(allocator: Allocator, options: Options, now: f64, usage_time: f64) !SourceProcessor {
        try lines.validate(.{}, options.line_limits);
        _ = try times.EventTime.init(now);
        _ = try times.EventTime.init(usage_time);
        if (!std.math.isFinite(options.findtime) or options.findtime < 0) return error.InvalidWindow;
        const worker = try worker_mod.Worker.startWithOptions(allocator, options.python, options.script, options.identity, options.launch);
        var self = SourceProcessor{ .allocator = allocator, .options = options, .worker = worker, .committed = &.{}, .initial = &.{}, .profile_hash = &.{}, .now = now, .usage_time = usage_time };
        errdefer self.worker.stop();
        const hello = try self.request("hello", struct {}{});
        defer allocator.free(hello);
        var hello_json = try std.json.parseFromSlice(std.json.Value, allocator, hello, .{});
        defer hello_json.deinit();
        const hello_data = try completeData(hello_json.value);
        const limits = try field(hello_data, "limits");
        self.max_requests = try positiveIntegerField(limits, "max_requests");
        self.max_record_bytes = std.math.cast(usize, try positiveIntegerField(limits, "record_bytes")) orelse return error.InvalidComponentResponse;
        const profile = try stringField(hello_data, "profile_hash");
        if (options.expected_profile_hash) |expected| {
            const expected_hex = std.fmt.bytesToHex(expected, .lower);
            if (!std.mem.eql(u8, &expected_hex, profile)) return error.AdmissionProfileMismatch;
        }
        const configured = try self.request("configure", .{ .profile_hash = profile, .encoding = options.encoding, .date_patterns = options.date_patterns, .reference_year = options.reference_year, .default_tz = options.default_tz });
        defer allocator.free(configured);
        var configured_json = try std.json.parseFromSlice(std.json.Value, allocator, configured, .{});
        defer configured_json.deinit();
        const data = try completeData(configured_json.value);
        self.profile_hash = try allocator.dupe(u8, profile);
        errdefer allocator.free(self.profile_hash);
        self.initial = try std.json.stringifyAlloc(allocator, Snapshot{ .profile_hash = self.profile_hash, .config_generation = options.identity.config_generation, .configuration_hash = try configurationHash(allocator, options), .codec_context = try field(data, "codec_context"), .date_context = try field(data, "date_context") }, .{});
        errdefer allocator.free(self.initial);
        self.committed = try allocator.dupe(u8, self.initial);
        return self;
    }

    pub fn deinit(self: *SourceProcessor) void {
        self.worker.stop();
        self.allocator.free(self.committed);
        self.allocator.free(self.initial);
        self.allocator.free(self.profile_hash);
        if (self.owned_epoch) |epoch| self.allocator.free(epoch);
        self.* = undefined;
    }

    /// Replace an exhausted or failed helper between transactions. Reconfiguration
    /// must produce the same profile before any committed contexts are reused.
    pub fn restart(self: *SourceProcessor, worker_epoch: []const u8) !void {
        if (self.in_flight) return error.ProcessorBusy;
        if (worker_epoch.len == 0 or std.mem.eql(u8, worker_epoch, self.options.identity.worker_epoch)) return error.InvalidWorkerEpoch;
        const epoch = try self.allocator.dupe(u8, worker_epoch);
        errdefer self.allocator.free(epoch);
        var options = self.options;
        options.identity.worker_epoch = epoch;
        var replacement = try SourceProcessor.init(self.allocator, options, self.now, self.usage_time);
        errdefer replacement.deinit();
        try restore(self.committed, &replacement);
        replacement.owned_epoch = epoch;
        replacement.mode_selector = self.mode_selector;
        self.deinit();
        self.* = replacement;
    }

    /// The reader persists this binding with its byte cursor. It covers both
    /// codec/date configuration and the captured helper runtime profile.
    pub fn framingIdentity(self: *SourceProcessor) ![32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(&(try configurationHash(self.allocator, self.options)));
        hash.update(self.profile_hash);
        var result: [32]u8 = undefined;
        hash.final(&result);
        return result;
    }

    pub fn bindFile(self: *SourceProcessor, file: *@import("durable_file_source.zig").FileSource) !void {
        try file.setFramer(frame, self, try self.framingIdentity(), self.max_record_bytes);
    }

    fn frame(source: []const u8, bytes: []const u8, eof: bool, allocator: Allocator, context: ?*anyopaque) !?records.Framed {
        const self: *SourceProcessor = @ptrCast(@alignCast(context orelse return error.MissingProcessor));
        if (self.in_flight) return error.ProcessorBusy;
        if (bytes.len > self.max_record_bytes) return error.RecordTooLarge;
        var saved = try self.snapshot(allocator);
        defer saved.deinit();
        try self.validateSnapshot(saved.value);
        const encoder = std.base64.standard.Encoder;
        const encoded = try allocator.alloc(u8, encoder.calcSize(bytes.len));
        defer allocator.free(encoded);
        _ = encoder.encode(encoded, bytes);
        const now_bits = try bitsText(allocator, self.now);
        defer allocator.free(now_bits);
        const response = try self.request("record", .{ .operation = "frame_decode", .bytes_b64 = encoded, .eof = eof, .source = source, .now_bits = now_bits, .codec_context = saved.value.codec_context });
        defer self.allocator.free(response);
        const parsed = try std.json.parseFromSliceLeaky(std.json.Value, allocator, response, .{ .allocate = .alloc_always });
        const payload = try field(parsed, "payload");
        const outcome = try stringField(payload, "outcome");
        if (std.mem.eql(u8, outcome, "resource_limit")) return error.RecordTooLarge;
        if (std.mem.eql(u8, outcome, "unsupported")) return error.UnsupportedFramingBoundary;
        const data = try completeData(parsed);
        const disposition = try stringField(data, "disposition");
        const consumed_value = try field(data, "consumed");
        if (consumed_value != .integer or consumed_value.integer < 0) return error.InvalidFramingResult;
        const consumed = std.math.cast(usize, consumed_value.integer) orelse return error.InvalidFramingResult;
        if (std.mem.eql(u8, disposition, "incomplete")) {
            if (consumed != 0) return error.InvalidFramingResult;
            return null;
        }
        if (!std.mem.eql(u8, disposition, "complete") or consumed == 0 or consumed > bytes.len) return error.InvalidFramingResult;
        const decoded = try field(data, "decoded");
        var checkpoint_hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(self.committed, &checkpoint_hash, .{});
        var raw_hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes[0..consumed], &raw_hash, .{});
        return .{ .consumed = consumed, .decoded = .{
            .text = try stringField(decoded, "text"),
            .codec = try stringField(decoded, "codec"),
            .disposition = try stringField(decoded, "disposition"),
            .diagnostic = try optionalStringField(decoded, "diagnostic"),
            .warning_due = try boolField(decoded, "warning_due"),
            .codec_context_json = try std.json.stringifyAlloc(allocator, try field(data, "codec_context"), .{}),
            .profile_hash = try allocator.dupe(u8, self.profile_hash),
            .config_generation = try allocator.dupe(u8, self.options.identity.config_generation),
            .configuration_hash = try configurationHash(allocator, self.options),
            .checkpoint_hash = checkpoint_hash,
            .raw_hash = raw_hash,
        } };
    }

    pub fn setClock(self: *SourceProcessor, now: f64, usage_time: f64) !void {
        _ = try times.EventTime.init(now);
        _ = try times.EventTime.init(usage_time);
        self.now = now;
        self.usage_time = usage_time;
    }

    pub fn adapter(self: *SourceProcessor) pipeline.Processor {
        return .{ .context = self, .prepare = prepare, .restore = restore };
    }

    pub fn snapshot(self: *const SourceProcessor, allocator: Allocator) !std.json.Parsed(Snapshot) {
        return std.json.parseFromSlice(Snapshot, allocator, self.committed, .{ .allocate = .alloc_always });
    }

    fn request(self: *SourceProcessor, kind: []const u8, payload: anytype) ![]u8 {
        if (self.sequence >= self.max_requests) return error.WorkerRestartRequired;
        var sequence_buf: [20]u8 = undefined;
        const sequence = try std.fmt.bufPrint(&sequence_buf, "{d}", .{self.sequence});
        const identity = self.options.identity;
        const envelope = try std.json.stringifyAlloc(self.allocator, .{ .wire_version = 1, .kind = kind, .request_id = sequence, .daemon_epoch = identity.daemon_epoch, .worker_epoch = identity.worker_epoch, .config_generation = identity.config_generation, .jail_id = identity.jail_id, .sequence = sequence, .capabilities = [_]bool{}, .payload = payload }, .{});
        defer self.allocator.free(envelope);
        self.sequence += 1;
        return self.worker.exchange(envelope, self.options.deadline_ms);
    }

    fn validateSnapshot(self: *SourceProcessor, value: Snapshot) !void {
        if (value.schema_version != 2 or !std.mem.eql(u8, value.profile_hash, self.profile_hash) or !std.mem.eql(u8, value.config_generation, self.options.identity.config_generation)) return error.CheckpointProfileMismatch;
        if (!std.mem.eql(u8, &value.configuration_hash, &(try configurationHash(self.allocator, self.options)))) return error.CheckpointProfileMismatch;
        try lines.validate(value.line_context, self.options.line_limits);
        if (value.codec_context != .object or value.date_context != .object) return error.InvalidCheckpoint;
        if (value.last_date_bits) |bits| _ = try parseBits(bits);
    }

    fn restore(checkpoint: ?[]const u8, context: ?*anyopaque) !void {
        const self: *SourceProcessor = @ptrCast(@alignCast(context orelse return error.MissingProcessor));
        if (self.in_flight) return error.ProcessorBusy;
        const payload = checkpoint orelse self.initial;
        if (payload.len > 16 * 1024 * 1024) return error.InvalidCheckpoint;
        var parsed = try std.json.parseFromSlice(Snapshot, self.allocator, payload, .{});
        defer parsed.deinit();
        try self.validateSnapshot(parsed.value);
        const owned = try self.allocator.dupe(u8, payload);
        self.allocator.free(self.committed);
        self.committed = owned;
    }

    const Staged = struct {
        owner: *SourceProcessor,
        bytes: []u8,
        published: bool = false,
        fn publish(context: ?*anyopaque) void {
            const self: *Staged = @ptrCast(@alignCast(context.?));
            self.owner.allocator.free(self.owner.committed);
            self.owner.committed = self.bytes;
            self.published = true;
        }
        fn release(context: ?*anyopaque) void {
            const self: *Staged = @ptrCast(@alignCast(context.?));
            const allocator = self.owner.allocator;
            self.owner.in_flight = false;
            if (!self.published) allocator.free(self.bytes);
            allocator.destroy(self);
        }
    };

    fn prepare(record: records.Record, context: ?*anyopaque) !pipeline.Prepared {
        const self: *SourceProcessor = @ptrCast(@alignCast(context orelse return error.MissingProcessor));
        if (self.in_flight) return error.ProcessorBusy;
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var saved = try std.json.parseFromSlice(Snapshot, arena, self.committed, .{});
        defer saved.deinit();
        try self.validateSnapshot(saved.value);
        var next = saved.value;
        var disposition: []const u8 = "source-checkpoint";
        var effective_time: ?f64 = null;
        if (record.kind == .data) {
            if (record.message.len > self.max_record_bytes) return error.RecordTooLarge;
            const decode_source = record.source_path orelse record.source;
            const encoder = std.base64.standard.Encoder;
            var encoded: []const u8 = "";
            if (record.predecoded == null and record.journal_fields == null) {
                const buffer = try arena.alloc(u8, encoder.calcSize(record.message.len));
                _ = encoder.encode(buffer, record.message);
                encoded = buffer;
            }
            const EncodedField = struct { name: []const u8, bytes_b64: []const u8 };
            var journal_fields: ?[]EncodedField = null;
            if (record.journal_fields) |fields| {
                if (record.timestamp_us == null or fields.len > 4096) return error.InvalidJournalRecord;
                const values = try arena.alloc(EncodedField, fields.len);
                var total: usize = 0;
                for (fields, 0..) |field_value, index| {
                    total = std.math.add(usize, total, field_value.value.len) catch return error.RecordTooLarge;
                    if (total > self.max_record_bytes) return error.RecordTooLarge;
                    const buffer = try arena.alloc(u8, encoder.calcSize(field_value.value.len));
                    _ = encoder.encode(buffer, field_value.value);
                    values[index] = .{ .name = field_value.name, .bytes_b64 = buffer };
                }
                journal_fields = values;
            }
            const now_bits = try bitsText(arena, self.now);
            const usage_bits = try bitsText(arena, self.usage_time);
            if (record.predecoded) |decoded| {
                if (record.timestamp_us != null or !std.mem.eql(u8, decoded.profile_hash, self.profile_hash) or !std.mem.eql(u8, decoded.config_generation, self.options.identity.config_generation) or !std.mem.eql(u8, &decoded.configuration_hash, &(try configurationHash(arena, self.options))) or !std.mem.eql(u8, &decoded.raw_hash, &record.raw_hash)) return error.InvalidPredecodedRecord;
                var current_checkpoint_hash: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(self.committed, &current_checkpoint_hash, .{});
                if (!std.mem.eql(u8, &current_checkpoint_hash, &decoded.checkpoint_hash)) return error.InvalidPredecodedRecord;
                var hash: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(record.message, &hash, .{});
                if (!std.mem.eql(u8, &hash, &record.raw_hash)) return error.InvalidPredecodedRecord;
            }
            const response = if (record.predecoded) |decoded|
                try self.request("record", .{ .operation = "date", .line = decoded.text, .now_bits = now_bits, .usage_time_bits = usage_bits, .date_context = next.date_context })
            else if (journal_fields) |fields|
                try self.request("record", .{ .operation = "format_journal", .source = decode_source, .fields = fields, .now_bits = now_bits, .codec_context = next.codec_context, .timestamp_us = try std.fmt.allocPrint(arena, "{d}", .{record.timestamp_us.?}), .monotonic_us = if (record.journal_monotonic_us) |value| try std.fmt.allocPrint(arena, "{d}", .{value}) else @as(?[]const u8, null) })
            else if (record.timestamp_us != null)
                try self.request("record", .{ .operation = "decode_journal", .source = decode_source, .bytes_b64 = encoded, .now_bits = now_bits, .codec_context = next.codec_context, .timestamp_us = try std.fmt.allocPrint(arena, "{d}", .{record.timestamp_us.?}) })
            else
                try self.request("record", .{ .operation = "decode_date", .source = decode_source, .bytes_b64 = encoded, .now_bits = now_bits, .usage_time_bits = usage_bits, .codec_context = next.codec_context, .date_context = next.date_context });
            defer self.allocator.free(response);
            const parsed = try std.json.parseFromSliceLeaky(std.json.Value, arena, response, .{ .allocate = .alloc_always });
            const payload = try field(parsed, "payload");
            const outcome = try stringField(payload, "outcome");
            const reason = try stringField(payload, "reason");
            if (std.mem.eql(u8, reason, "journal_timestamp_range")) return error.JournalTimestampRange;
            if (!std.mem.eql(u8, outcome, "complete") and !std.mem.eql(u8, outcome, "no_match") and !(std.mem.eql(u8, outcome, "invalid_input") and std.mem.eql(u8, reason, "invalid_calendar_time"))) return error.ComponentRejected;
            var data = try field(payload, "data");
            if (record.predecoded) |decoded_record| {
                if (data != .object) return error.InvalidComponentResponse;
                const decoded_json = try std.json.stringifyAlloc(arena, .{ .text = decoded_record.text, .codec = decoded_record.codec, .disposition = decoded_record.disposition, .diagnostic = decoded_record.diagnostic, .warning_due = decoded_record.warning_due }, .{});
                try data.object.put("decoded", try std.json.parseFromSliceLeaky(std.json.Value, arena, decoded_json, .{}));
                try data.object.put("codec_context", try std.json.parseFromSliceLeaky(std.json.Value, arena, decoded_record.codec_context_json, .{ .allocate = .alloc_always }));
            }
            const decoded = try field(data, "decoded");
            next.codec_context = try field(data, "codec_context");
            var input: times.Input = .missing;
            var date_kind: []const u8 = "missing";
            var date_raw: ?[]const u8 = null;
            var parts: ?lines.Tuple = null;
            const text = try stringField(decoded, "text");
            if (record.timestamp_us != null) {
                const converted = try field(data, "journal_time");
                date_raw = try stringField(converted, "timestamp_bits");
                input = .{ .parsed = try parseBits(date_raw.?) };
                date_kind = "journal-authoritative";
                parts = .{ .time = try stringField(converted, "time_text"), .suffix = text };
            } else {
                next.date_context = try field(data, "date_context");
                const date = try field(data, "date");
                if (date != .null) {
                    date_kind = try stringField(date, "kind");
                    date_raw = try optionalStringField(date, "raw_timestamp_bits");
                    parts = try lines.splitPythonSpan(text, try spanField(date, "start"), try spanField(date, "end"));
                    if (std.mem.eql(u8, date_kind, "invalid")) input = .invalid else if (std.mem.eql(u8, date_kind, "optional-empty")) input = .optional_empty else {
                        const effective = (try optionalStringField(date, "effective_bits")) orelse return error.InvalidComponentResponse;
                        input = .{ .parsed = try parseBits(effective) };
                    }
                }
            }
            var normalizer = times.Context{ .last_date = if (next.last_date_bits) |bits| try parseBits(bits) else null };
            const previous_date = normalizer.last_date;
            const mode = if (record.timestamp_us != null and self.mode_selector != null)
                try self.mode_selector.?.choose(record, input.parsed, self.mode_selector.?.context)
            else
                self.options.mode;
            const normalized = try normalizer.normalize(input, try times.EventTime.init(self.now), self.options.findtime, mode, self.options.check_findtime);
            const staged_lines = try lines.stage(arena, next.line_context, .{ .line = text, .parts = parts, .event_input = input, .previous_date = previous_date, .now = try times.EventTime.init(self.now), .normalized = normalized }, self.options.line_limits);
            next.line_context = staged_lines.snapshot;
            next.last_date_bits = if (normalizer.last_date) |value| try bitsText(arena, value.seconds) else null;
            next.last = .{ .source = record.source, .occurrence = record.occurrence, .message = try stringField(decoded, "text"), .codec_disposition = try stringField(decoded, "disposition"), .codec_diagnostic = try optionalStringField(decoded, "diagnostic"), .codec_warning_due = try boolField(decoded, "warning_due"), .date_kind = date_kind, .date_raw_timestamp_bits = date_raw, .timestamp_us = record.timestamp_us, .now_bits = now_bits, .usage_time_bits = usage_bits, .disposition = normalized.disposition, .mode = mode, .raw_bits = try optionalBits(arena, normalized.raw), .effective_bits = try optionalBits(arena, normalized.effective), .stored_bits = try optionalBits(arena, normalized.stored), .origin = normalized.origin, .diagnostic = normalized.diagnostic };
            disposition = @tagName(normalized.disposition);
            effective_time = if (normalized.effective) |value| value.seconds else null;
        }
        const bytes = try std.json.stringifyAlloc(self.allocator, next, .{});
        errdefer self.allocator.free(bytes);
        if (bytes.len > 16 * 1024 * 1024) return error.CheckpointLimit;
        const staged = try self.allocator.create(Staged);
        staged.* = .{ .owner = self, .bytes = bytes };
        self.in_flight = true;
        return .{ .checkpoint = bytes, .disposition = disposition, .event_time = effective_time, .context = staged, .publish = Staged.publish, .release = Staged.release };
    }
};

/// Operational startup/live/replay mode is per-record provenance, not immutable
/// configuration. Decoder/date rules, window and findtime policy are bound here.
fn configurationHash(allocator: Allocator, options: Options) ![32]u8 {
    const bytes = try std.json.stringifyAlloc(allocator, .{ .encoding = options.encoding, .date_patterns = options.date_patterns, .reference_year = options.reference_year, .default_tz = options.default_tz, .findtime_bits = @as(u64, @bitCast(options.findtime)), .check_findtime = options.check_findtime, .line_limits = options.line_limits, .source_configuration_hash = options.source_configuration_hash, .expected_profile_hash = options.expected_profile_hash }, .{});
    defer allocator.free(bytes);
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &hash, .{});
    return hash;
}

pub fn journalTime(timestamp_us: u64) !times.EventTime {
    // Avoid rounding the integer to binary64 before division. The intermediate
    // has enough precision for every u64 microsecond value and binary64 result.
    const seconds: f128 = @as(f128, @floatFromInt(timestamp_us)) / 1_000_000.0;
    return times.EventTime.init(@floatCast(seconds));
}

fn field(value: std.json.Value, name: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidComponentResponse;
    return value.object.get(name) orelse return error.InvalidComponentResponse;
}
fn spanField(value: std.json.Value, name: []const u8) !i64 {
    const item = try field(value, name);
    if (item != .integer) return error.InvalidComponentResponse;
    return item.integer;
}
fn positiveIntegerField(value: std.json.Value, name: []const u8) !u64 {
    const item = try field(value, name);
    if (item != .integer or item.integer <= 0) return error.InvalidComponentResponse;
    return @intCast(item.integer);
}
fn stringField(value: std.json.Value, name: []const u8) ![]const u8 {
    const item = try field(value, name);
    if (item != .string) return error.InvalidComponentResponse;
    return item.string;
}
fn optionalStringField(value: std.json.Value, name: []const u8) !?[]const u8 {
    const item = try field(value, name);
    return switch (item) {
        .null => null,
        .string => item.string,
        else => error.InvalidComponentResponse,
    };
}
fn boolField(value: std.json.Value, name: []const u8) !bool {
    const item = try field(value, name);
    if (item != .bool) return error.InvalidComponentResponse;
    return item.bool;
}
fn completeData(value: std.json.Value) !std.json.Value {
    const payload = try field(value, "payload");
    if (!std.mem.eql(u8, try stringField(payload, "outcome"), "complete")) return error.ComponentRejected;
    return field(payload, "data");
}
fn bitsText(allocator: Allocator, value: f64) ![]u8 {
    const time = try times.EventTime.init(value);
    return std.fmt.allocPrint(allocator, "{x:0>16}", .{time.bits()});
}
fn parseBits(text: []const u8) !times.EventTime {
    if (text.len != 16) return error.InvalidCheckpoint;
    return times.EventTime.fromBits(try std.fmt.parseInt(u64, text, 16));
}
fn optionalBits(allocator: Allocator, value: ?times.EventTime) !?[]const u8 {
    return if (value) |time| try bitsText(allocator, time.seconds) else null;
}

test "source processor: actual file worker SQLite transaction rollback and restored date context" {
    const files = @import("durable_file_source.zig");
    const store_mod = @import("record_store.zig");
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const path = try std.fs.path.join(allocator, &.{ base, "input.log" });
    defer allocator.free(path);
    const database = try std.fs.path.join(allocator, &.{ base, "state.sqlite" });
    defer allocator.free(database);
    const script = try std.fs.cwd().realpathAlloc(allocator, "engine/compat/worker.py");
    defer allocator.free(script);
    try temp.dir.writeFile(.{ .sub_path = "input.log", .data = "1730000000.125 ordinary first\nordinary continuation\n1729998000 ordinary old\n1730001000 ordinary future\n" });
    const options = Options{ .python = "/usr/bin/python3", .script = script, .identity = .{ .daemon_epoch = "source-test", .worker_epoch = "worker-one", .config_generation = "source-config", .jail_id = "fixture" }, .date_patterns = &.{"EPOCH"}, .reference_year = 2026, .line_limits = .{ .max_lines = 3 } };
    var processor = try SourceProcessor.init(allocator, options, 1730000001.25, 1730000001.25);
    defer processor.deinit();
    var store = try store_mod.Store.open(allocator, database);
    defer store.close();
    var pipe = pipeline.Pipeline{ .store = &store, .jail = "fixture", .processor = processor.adapter() };
    try pipe.restore(allocator);
    var source = try files.FileSource.init(allocator, path, "fixture-file", .head, null);
    defer source.deinit();
    // Baseline acknowledgement is context-only: no worker record operation.
    const sequence_before = processor.sequence;
    const baseline_prepare = try SourceProcessor.prepare(.{ .kind = .checkpoint, .source = "fixture-file", .occurrence = "baseline", .cursor = "0", .message = "", .raw_hash = [_]u8{0} ** 32 }, &processor);
    try std.testing.expectError(error.ProcessorBusy, processor.restart("busy-epoch"));
    baseline_prepare.release(baseline_prepare.context);
    try std.testing.expectEqual(sequence_before, processor.sequence);
    try std.testing.expect(try source.poll(pipeline.Pipeline.acknowledge, &pipe));
    var first = try processor.snapshot(allocator);
    defer first.deinit();
    // A caller cannot reuse contexts after changing policy under the same generation.
    processor.options.default_tz = "UTC";
    try std.testing.expectError(error.CheckpointProfileMismatch, SourceProcessor.restore(processor.committed, &processor));
    processor.options.default_tz = null;
    try std.testing.expectEqualStrings("1730000000.125", first.value.line_context.last_time_text);
    try std.testing.expectEqual(@as(usize, 1), first.value.line_context.lines.len);
    try std.testing.expectEqual(times.Disposition.accepted, first.value.last.?.disposition);
    try std.testing.expectEqual(@as(f64, 1730000000.125), (try parseBits(first.value.last.?.effective_bits.?)).seconds);
    const committed_position = source.acknowledgedCheckpoint().?.offset;
    const committed_bytes = try allocator.dupe(u8, processor.committed);
    defer allocator.free(committed_bytes);
    store.fail_at = .before_commit;
    try std.testing.expectError(error.InjectedFailure, source.poll(pipeline.Pipeline.acknowledge, &pipe));
    try std.testing.expectEqualStrings(committed_bytes, processor.committed);
    try std.testing.expectEqual(committed_position, source.acknowledgedCheckpoint().?.offset);
    store.fail_at = null;
    // Replace the real worker and processor, then restore from authoritative SQLite.
    var restarted_options = options;
    restarted_options.identity.worker_epoch = "worker-two";
    var restarted = try SourceProcessor.init(allocator, restarted_options, 1730000001.25, 1730000001.25);
    defer restarted.deinit();
    var restarted_pipeline = pipeline.Pipeline{ .store = &store, .jail = "fixture", .processor = restarted.adapter() };
    try restarted_pipeline.restore(allocator);
    const raw_cursor = (try store.sourceCursor(allocator, "fixture", "fixture-file")).?;
    defer allocator.free(raw_cursor);
    var saved_cursor = try std.json.parseFromSlice(files.Resume, allocator, raw_cursor, .{});
    defer saved_cursor.deinit();
    var reopened = try files.FileSource.init(allocator, path, "fixture-file", .head, saved_cursor.value);
    defer reopened.deinit();
    // Exhaustion is explicit and does not consume a record or change state.
    restarted.sequence = restarted.max_requests;
    const before_limit = reopened.acknowledgedCheckpoint().?.offset;
    try std.testing.expectError(error.WorkerRestartRequired, reopened.poll(pipeline.Pipeline.acknowledge, &restarted_pipeline));
    try std.testing.expectEqual(before_limit, reopened.acknowledgedCheckpoint().?.offset);
    try std.testing.expectError(error.InvalidWorkerEpoch, restarted.restart("worker-two"));
    try restarted.restart("worker-three");
    try std.testing.expectEqual(@as(u64, 2), restarted.sequence);
    try std.testing.expect(try reopened.poll(pipeline.Pipeline.acknowledge, &restarted_pipeline));
    var missing = try restarted.snapshot(allocator);
    defer missing.deinit();
    try std.testing.expectEqual(@as(usize, 2), missing.value.line_context.lines.len);
    try std.testing.expectEqualStrings("1730000000.125", missing.value.line_context.processed.?.time);
    try std.testing.expectEqualStrings("ordinary continuation", missing.value.line_context.processed.?.suffix);
    try std.testing.expectEqual(times.Origin.recent_context, missing.value.last.?.origin.?);
    try std.testing.expectEqual(@as(f64, 1730000000.125), (try parseBits(missing.value.last.?.effective_bits.?)).seconds);
    try std.testing.expect(try reopened.poll(pipeline.Pipeline.acknowledge, &restarted_pipeline));
    var obsolete = try restarted.snapshot(allocator);
    defer obsolete.deinit();
    try std.testing.expectEqual(@as(usize, 2), obsolete.value.line_context.lines.len);
    try std.testing.expectEqualStrings("1729998000", obsolete.value.line_context.last_time_text);
    try std.testing.expectEqual(times.Disposition.obsolete, obsolete.value.last.?.disposition);
    try std.testing.expect(obsolete.value.last.?.stored_bits == null);
    restarted.options.mode = .live;
    try std.testing.expect(try reopened.poll(pipeline.Pipeline.acknowledge, &restarted_pipeline));
    var corrected = try restarted.snapshot(allocator);
    defer corrected.deinit();
    try std.testing.expectEqual(@as(usize, 3), corrected.value.line_context.lines.len);
    try std.testing.expectEqualStrings("1730001000", corrected.value.line_context.processed.?.time);
    try std.testing.expectEqual(times.Origin.live_correction, corrected.value.last.?.origin.?);
    try std.testing.expectEqual(@as(f64, 1730000001.25), (try parseBits(corrected.value.last.?.effective_bits.?)).seconds);
    try std.testing.expectEqual(@as(i64, 0), try store.pendingIntents());
}

test "source processor: authoritative microseconds preserve correctly rounded bits beyond 2^53" {
    const cases = [_]struct { us: u64, bits: u64 }{
        .{ .us = 1730000000123456, .bits = 0x41d9c76d2007e6b4 },
        .{ .us = 9007199254740993, .bits = 0x4200c6f7a0b5ed8e },
        .{ .us = 9007199254740995, .bits = 0x4200c6f7a0b5ed8f },
        .{ .us = 10000000000000001, .bits = 0x4202a05f20000001 },
        // Rational conversion only: python-systemd rejects this rounded value
        // because its datetime conversion crosses the year-10000 boundary.
        .{ .us = 253402300799999999, .bits = 0x424d7ffa20c00000 },
    };
    for (cases) |case| try std.testing.expectEqual(case.bits, (try journalTime(case.us)).bits());
}

test "source processor: actual codec-aware EOF framing preserves raw cursor and stages contexts" {
    const files = @import("durable_file_source.zig");
    const store_mod = @import("record_store.zig");
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const path = try std.fs.path.join(allocator, &.{ base, "escaped.log" });
    defer allocator.free(path);
    const database = try std.fs.path.join(allocator, &.{ base, "escaped.sqlite" });
    defer allocator.free(database);
    const script = try std.fs.cwd().realpathAlloc(allocator, "engine/compat/worker.py");
    defer allocator.free(script);
    const first_raw = "1730000000 original escaped\\n";
    const second_raw = "ordinary continuation\\n";
    try temp.dir.writeFile(.{ .sub_path = "escaped.log", .data = first_raw });
    const options = Options{ .python = "/usr/bin/python3", .script = script, .identity = .{ .daemon_epoch = "framing-test", .worker_epoch = "framing-one", .config_generation = "framing-config", .jail_id = "fixture" }, .encoding = "unicode-escape", .date_patterns = &.{"EPOCH"}, .reference_year = 2026 };
    var processor = try SourceProcessor.init(allocator, options, 1730000001, 1730000001);
    defer processor.deinit();
    var store = try store_mod.Store.open(allocator, database);
    defer store.close();
    var pipe = pipeline.Pipeline{ .store = &store, .jail = "fixture", .processor = processor.adapter() };
    try pipe.restore(allocator);
    var source = try files.FileSource.init(allocator, path, "escaped-source", .head, null);
    defer source.deinit();
    try processor.bindFile(&source);
    try std.testing.expect(try source.poll(pipeline.Pipeline.acknowledge, &pipe));
    var first = try processor.snapshot(allocator);
    defer first.deinit();
    try std.testing.expectEqualStrings("1730000000 original escaped", first.value.last.?.message);
    try std.testing.expectEqual(@as(u64, first_raw.len), source.acknowledgedCheckpoint().?.offset);
    var writer = try temp.dir.openFile("escaped.log", .{ .mode = .write_only });
    defer writer.close();
    try writer.seekFromEnd(0);
    try writer.writeAll(second_raw);
    const committed = try allocator.dupe(u8, processor.committed);
    defer allocator.free(committed);
    store.fail_at = .before_commit;
    try std.testing.expectError(error.InjectedFailure, source.poll(pipeline.Pipeline.acknowledge, &pipe));
    try std.testing.expectEqualStrings(committed, processor.committed);
    try std.testing.expectEqual(@as(u64, first_raw.len), source.acknowledgedCheckpoint().?.offset);
    store.fail_at = null;
    const cursor = source.acknowledgedCheckpoint().?;
    try processor.restart("framing-two");
    var reopened = try files.FileSource.init(allocator, path, "escaped-source", .head, cursor);
    defer reopened.deinit();
    try std.testing.expectError(error.FramingProfileMismatch, reopened.poll(pipeline.Pipeline.acknowledge, &pipe));
    try processor.bindFile(&reopened);
    try std.testing.expect(try reopened.poll(pipeline.Pipeline.acknowledge, &pipe));
    var second = try processor.snapshot(allocator);
    defer second.deinit();
    try std.testing.expectEqualStrings("ordinary continuation", second.value.last.?.message);
    try std.testing.expectEqual(times.Origin.recent_context, second.value.last.?.origin.?);
    try std.testing.expectEqual(@as(u64, first_raw.len + second_raw.len), reopened.acknowledgedCheckpoint().?.offset);
    try writer.writeAll("partial");
    const before_partial = try allocator.dupe(u8, processor.committed);
    defer allocator.free(before_partial);
    try std.testing.expect(!try reopened.poll(pipeline.Pipeline.acknowledge, &pipe));
    try std.testing.expectEqualStrings(before_partial, processor.committed);
    try std.testing.expectEqual(@as(u64, first_raw.len + second_raw.len), reopened.acknowledgedCheckpoint().?.offset);
}

test "source processor: conversion admission binds the actual worker profile" {
    const allocator = std.testing.allocator;
    const script = try std.fs.cwd().realpathAlloc(allocator, "engine/compat/worker.py");
    defer allocator.free(script);
    var options = Options{ .python = "/usr/bin/python3", .script = script, .identity = .{ .daemon_epoch = "admission", .worker_epoch = "first", .config_generation = "fixture", .jail_id = "fixture" }, .date_patterns = &.{"EPOCH"}, .reference_year = 2026 };
    var first = try SourceProcessor.init(allocator, options, 1730000001, 1730000001);
    defer first.deinit();
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, first.profile_hash);
    options.expected_profile_hash = expected;
    options.identity.worker_epoch = "admitted";
    var admitted = try SourceProcessor.init(allocator, options, 1730000001, 1730000001);
    defer admitted.deinit();
    try std.testing.expectEqualStrings(first.profile_hash, admitted.profile_hash);
    options.expected_profile_hash = [_]u8{0} ** 32;
    options.identity.worker_epoch = "mismatched";
    try std.testing.expectError(error.AdmissionProfileMismatch, SourceProcessor.init(allocator, options, 1730000001, 1730000001));
}

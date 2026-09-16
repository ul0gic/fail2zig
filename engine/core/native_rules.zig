// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
pub const Ip = @import("shared").IpAddress;
pub const version: u16 = 1;
pub const field_cap = 8;
pub const segment_cap = 24;
pub const scratch_bytes = 32 * 1024;
pub const name_cap = 32;
pub const value_cap = 256;
pub const Limits = struct { config_bytes: usize = 4096, record_bytes: usize = 2048, work: usize = 16384 };
pub fn Text(comptime capacity: usize) type {
    return struct {
        bytes: [capacity]u8 = [_]u8{0} ** capacity,
        len: u16 = 0,
        pub fn init(value: []const u8) !@This() {
            if (value.len > capacity) return error.ValueTooLong;
            var result: @This() = .{ .len = @intCast(value.len) };
            @memcpy(result.bytes[0..value.len], value);
            return result;
        }
        pub fn slice(self: *const @This()) []const u8 {
            return self.bytes[0..self.len];
        }
        pub fn valid(self: *const @This()) bool {
            return self.len <= capacity and std.mem.allEqual(u8, self.bytes[self.len..], 0);
        }
    };
}
pub const Name = Text(name_cap);
pub const Key = Text(64);
pub const Hostname = struct {
    text: Text(253),
    pub fn init(value: []const u8) !Hostname {
        if (value.len == 0 or value.len > 254) return error.InvalidSubject;
        const input = if (value[value.len - 1] == '.') value[0 .. value.len - 1] else value;
        if (input.len == 0 or input.len > 253) return error.InvalidSubject;
        var labels = std.mem.splitScalar(u8, input, '.');
        while (labels.next()) |label| {
            if (label.len == 0 or label.len > 63 or !std.ascii.isAlphanumeric(label[0]) or !std.ascii.isAlphanumeric(label[label.len - 1])) return error.InvalidSubject;
            for (label) |c| if (!std.ascii.isAlphanumeric(c) and c != '-') return error.InvalidSubject;
        }
        if (Ip.parse(input)) |_| return error.InvalidSubject else |_| {}
        var result = Hostname{ .text = try Text(253).init(input) };
        for (result.text.bytes[0..result.text.len]) |*c| c.* = std.ascii.toLower(c.*);
        return result;
    }
    pub fn slice(self: *const Hostname) []const u8 {
        return self.text.slice();
    }
    pub fn validate(self: *const Hostname) !void {
        if (!self.text.valid()) return error.InvalidSubject;
        const expected = try init(self.slice());
        if (!std.mem.eql(u8, &expected.text.bytes, &self.text.bytes)) return error.InvalidSubject;
    }
};
pub const Subject = union(enum) {
    address: Ip,
    hostname: Hostname,
    pub fn eql(a: Subject, b: Subject) bool {
        if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
        return switch (a) {
            .address => |ip| ip.eql(b.address),
            .hostname => |name| std.mem.eql(u8, name.slice(), b.hostname.slice()),
        };
    }
};
pub const Predicate = struct { field: []const u8, op: enum { equal, starts_with } = .equal, text: ?[]const u8 = null, number: ?u64 = null };
pub const Correlation = struct { key: []const u8, phase: []const u8, start: []const u8, finish: []const u8, ttl_seconds: u64 };
pub const Spec = struct {
    id: []const u8,
    source: []const u8,
    format: enum { json, template },
    template: ?[]const u8 = null,
    subject: []const u8,
    subject_kind: enum { ip, hostname } = .ip,
    conditions: []const Predicate,
    exclude: []const Predicate = &.{},
    correlation: ?Correlation = null,
};
const Capture = enum { word, ip, uint, quoted, hostname };
const Segment = union(enum) { literal: []const u8, capture: struct { name: []const u8, kind: Capture, delimiter: ?u8 } };
const Value = union(enum) { text: []const u8, number: u64, address: Ip, hostname: Hostname };
const Field = struct { name: []const u8, value: Value };
const Fields = struct {
    entries: [field_cap]Field = undefined,
    count: usize = 0,
    fn add(self: *Fields, name: []const u8, value: Value) !void {
        if (self.count == field_cap) return error.ResourceLimit;
        if (!validName(name) or self.get(name) != null) return error.InvalidRecord;
        self.entries[self.count] = .{ .name = name, .value = value };
        self.count += 1;
    }
    fn get(self: *const Fields, name: []const u8) ?Value {
        for (self.entries[0..self.count]) |entry| if (std.mem.eql(u8, entry.name, name)) {
            return entry.value;
        };
        return null;
    }
};
const Budget = struct {
    remaining: usize,
    fn spend(self: *Budget, n: usize) !void {
        if (n > self.remaining) return error.ResourceLimit;
        self.remaining -= n;
    }
};
pub const Kind = enum { candidate, no_match, excluded, awaiting_context, rejected };
pub const Reason = enum { matched, source_mismatch, template_mismatch, condition_failed, exclusion_matched, missing_field, wrong_type, invalid_record, invalid_subject, incomplete_record, context_stored, context_missing, context_expired, context_conflict, event_order };
pub const Outcome = struct {
    kind: Kind,
    reason: Reason,
    rule: Name,
    source: Name,
    field: ?Name = null,
    predicate: ?u8 = null,
    subject: ?Subject = null,
    subject_origin: ?enum { record, context } = null,
    work_used: usize = 0,
};
pub const Input = struct { source: []const u8, record: []const u8, complete: bool = true };
pub const Scratch = struct { bytes: [scratch_bytes]u8 = undefined };
pub const CorrelationInput = struct { key: Key, phase: enum { start, finish, other } };
pub const Observation = struct { outcome: Outcome, correlation: ?CorrelationInput = null };
pub const Program = struct {
    owner: std.mem.Allocator,
    storage: [scratch_bytes]u8 = undefined,
    fixed: std.heap.FixedBufferAllocator,
    parsed: std.json.Parsed(Spec),
    limits: Limits,
    generation: [32]u8 = undefined,
    segments: [segment_cap]Segment = undefined,
    segment_count: usize = 0,
    pub fn create(owner: std.mem.Allocator, config: []const u8, limits: Limits) !*Program {
        if (limits.config_bytes == 0 or limits.config_bytes > 4096 or
            limits.record_bytes == 0 or limits.record_bytes > 2048 or
            limits.work == 0 or limits.work > 16384) return error.InvalidLimits;
        if (config.len > limits.config_bytes) return error.ConfigTooLarge;
        const self = try owner.create(Program);
        errdefer owner.destroy(self);
        self.* = .{ .owner = owner, .fixed = undefined, .parsed = undefined, .limits = limits };
        self.fixed = std.heap.FixedBufferAllocator.init(&self.storage);
        self.parsed = std.json.parseFromSlice(Spec, self.fixed.allocator(), config, .{
            .allocate = .alloc_always,
            .max_value_len = limits.config_bytes,
            .duplicate_field_behavior = .@"error",
        }) catch |err| return if (err == error.OutOfMemory) error.ResourceLimit else error.InvalidRule;
        errdefer self.parsed.deinit();
        try self.validate();
        var canonical: [8192]u8 = undefined;
        var stream = std.io.fixedBufferStream(&canonical);
        try std.json.stringify(.{ .version = version, .spec = self.parsed.value, .limits = limits }, .{}, stream.writer());
        std.crypto.hash.sha2.Sha256.hash(stream.getWritten(), &self.generation, .{});
        return self;
    }

    pub fn destroy(self: *Program) void {
        const owner = self.owner;
        self.parsed.deinit();
        owner.destroy(self);
    }

    fn validate(self: *Program) !void {
        const spec = self.parsed.value;
        if (!validName(spec.id) or !validName(spec.source) or !validName(spec.subject)) return error.InvalidRule;
        if (spec.conditions.len == 0 or spec.conditions.len + spec.exclude.len > 8) return error.InvalidRule;
        for ([_][]const Predicate{ spec.conditions, spec.exclude }) |list| for (list) |p| {
            if (!validName(p.field) or (p.text == null) == (p.number == null)) return error.InvalidRule;
            if (p.text) |v| if (v.len == 0 or v.len > value_cap) return error.InvalidRule;
            if (p.op == .starts_with and p.text == null) return error.InvalidRule;
        };
        if (spec.correlation) |c| {
            if (spec.format != .json or !validName(c.key) or !validName(c.phase) or
                c.key.len == 0 or std.mem.eql(u8, c.key, spec.subject) or
                std.mem.eql(u8, c.phase, spec.subject) or std.mem.eql(u8, c.key, c.phase) or
                c.start.len == 0 or c.finish.len == 0 or c.start.len > 64 or c.finish.len > 64 or
                std.mem.eql(u8, c.start, c.finish) or c.ttl_seconds == 0 or c.ttl_seconds > 300) return error.InvalidRule;
        }
        switch (spec.format) {
            .json => if (spec.template != null) return error.InvalidRule,
            .template => try self.compileTemplate(spec.template orelse return error.InvalidRule),
        }
    }

    fn append(self: *Program, segment: Segment) !void {
        if (self.segment_count == segment_cap) return error.InvalidRule;
        self.segments[self.segment_count] = segment;
        self.segment_count += 1;
    }

    fn compileTemplate(self: *Program, template: []const u8) !void {
        if (template.len == 0 or template.len > 512) return error.InvalidRule;
        var names: Fields = .{};
        var pos: usize = 0;
        var literal_start: usize = 0;
        while (pos < template.len) {
            if (template[pos] == '}') return error.InvalidRule;
            if (template[pos] != '{') {
                pos += 1;
                continue;
            }
            if (literal_start != pos) try self.append(.{ .literal = template[literal_start..pos] });
            const close = std.mem.indexOfScalarPos(u8, template, pos + 1, '}') orelse return error.InvalidRule;
            const token = template[pos + 1 .. close];
            const colon = std.mem.indexOfScalar(u8, token, ':') orelse return error.InvalidRule;
            const name = token[0..colon];
            const kind = std.meta.stringToEnum(Capture, token[colon + 1 ..]) orelse return error.InvalidRule;
            names.add(name, .{ .text = "" }) catch return error.InvalidRule;
            var delimiter: ?u8 = null;
            if (close + 1 < template.len and !space(template[close + 1])) {
                const next = template[close + 1];
                if (std.mem.indexOfScalar(u8, "[](),;:=|\"'", next) == null) return error.InvalidRule;
                if (kind == .ip and next == ':') return error.InvalidRule;
                delimiter = next;
            }
            if (kind == .quoted and ((pos > 0 and template[pos - 1] == '"') or delimiter == '"')) return error.InvalidRule;
            try self.append(.{ .capture = .{ .name = name, .kind = kind, .delimiter = delimiter } });
            pos = close + 1;
            literal_start = pos;
        }
        if (literal_start < template.len) try self.append(.{ .literal = template[literal_start..] });
        if (names.get(self.parsed.value.subject) == null) return error.InvalidRule;
        for ([_][]const Predicate{ self.parsed.value.conditions, self.parsed.value.exclude }) |list| for (list) |p| {
            if (names.get(p.field) == null) return error.InvalidRule;
            for (self.segments[0..self.segment_count]) |seg| switch (seg) {
                .capture => |c| if (std.mem.eql(u8, c.name, p.field)) {
                    if (((c.kind == .word or c.kind == .quoted) and p.text == null) or
                        (c.kind == .uint and p.number == null) or c.kind == .ip or c.kind == .hostname) return error.InvalidRule;
                },
                else => {},
            };
        };
        for (self.segments[0..self.segment_count]) |seg| switch (seg) {
            .capture => |c| if (std.mem.eql(u8, c.name, self.parsed.value.subject) and c.kind != (if (self.parsed.value.subject_kind == .ip) Capture.ip else Capture.hostname)) return error.InvalidRule,
            else => {},
        };
    }

    fn decode(self: *const Program, allocator: std.mem.Allocator, input: []const u8, budget: *Budget) !Fields {
        try budget.spend(input.len);
        var fields: Fields = .{};
        if (self.parsed.value.format == .json) {
            const parsed = std.json.parseFromSlice(std.json.Value, allocator, input, .{
                .max_value_len = value_cap,
                .duplicate_field_behavior = .@"error",
            }) catch |err| return if (err == error.OutOfMemory or err == error.ValueTooLong) error.ResourceLimit else error.InvalidRecord;
            if (parsed.value != .object) return error.InvalidRecord;
            var it = parsed.value.object.iterator();
            while (it.next()) |entry| {
                const value: Value = switch (entry.value_ptr.*) {
                    .string => |s| blk: {
                        if (s.len > value_cap) return error.ResourceLimit;
                        break :blk .{ .text = s };
                    },
                    .integer => |n| .{ .number = std.math.cast(u64, n) orelse return error.InvalidRecord },
                    else => return error.InvalidRecord,
                };
                try fields.add(entry.key_ptr.*, value);
            }
            return fields;
        }
        var cursor: usize = 0;
        for (self.segments[0..self.segment_count]) |seg| switch (seg) {
            .literal => |literal| {
                try budget.spend(literal.len);
                if (!std.mem.startsWith(u8, input[cursor..], literal)) return error.TemplateMismatch;
                cursor += literal.len;
            },
            .capture => |capture| {
                if (capture.kind == .quoted) {
                    const text = try decodeQuoted(allocator, input, &cursor, budget);
                    try fields.add(capture.name, .{ .text = text });
                    continue;
                }
                const start = cursor;
                while (cursor < input.len and !space(input[cursor]) and capture.delimiter != input[cursor]) : (cursor += 1) {
                    try budget.spend(1);
                    if (input[cursor] < 0x21 or input[cursor] > 0x7e) return error.InvalidRecord;
                    if (cursor - start >= value_cap) return error.ResourceLimit;
                }
                const text = input[start..cursor];
                if (text.len == 0) return error.InvalidRecord;
                const value: Value = switch (capture.kind) {
                    .word => .{ .text = text },
                    .ip => .{ .address = try parseAddress(text) },
                    .hostname => .{ .hostname = try Hostname.init(text) },
                    .uint => blk: {
                        for (text) |c| if (!std.ascii.isDigit(c)) return error.InvalidRecord;
                        break :blk .{ .number = std.fmt.parseInt(u64, text, 10) catch return error.InvalidRecord };
                    },
                    .quoted => return error.InvalidRecord,
                };
                try fields.add(capture.name, value);
            },
        };
        if (cursor != input.len) return error.TemplateMismatch;
        return fields;
    }

    pub fn metadata(self: *const Program) Spec {
        return self.parsed.value;
    }
    pub fn result(self: *const Program, kind: Kind, reason: Reason) Outcome {
        var rule: Name = .{ .len = @intCast(self.parsed.value.id.len) };
        var source: Name = .{ .len = @intCast(self.parsed.value.source.len) };
        @memcpy(rule.bytes[0..rule.len], self.parsed.value.id);
        @memcpy(source.bytes[0..source.len], self.parsed.value.source);
        return .{ .kind = kind, .reason = reason, .rule = rule, .source = source };
    }
    pub fn evaluate(self: *const Program, input: Input, scratch: *Scratch) !Outcome {
        if (self.parsed.value.correlation != null) return error.CorrelationRequired;
        return (try self.analyze(input, scratch)).outcome;
    }
    pub fn analyze(self: *const Program, input: Input, scratch: *Scratch) !Observation {
        if (!std.mem.eql(u8, input.source, self.parsed.value.source)) return .{ .outcome = self.result(.no_match, .source_mismatch) };
        if (!input.complete) return .{ .outcome = self.result(.rejected, .incomplete_record) };
        if (input.record.len > self.limits.record_bytes) return error.RecordTooLarge;
        var budget: Budget = .{ .remaining = self.limits.work };
        var out = self.analyzeInner(input.record, scratch, &budget) catch |err| switch (err) {
            error.ResourceLimit => return error.ResourceLimit,
            error.TemplateMismatch => Observation{ .outcome = self.result(.no_match, .template_mismatch) },
            error.InvalidSubject => Observation{ .outcome = withField(self.result(.rejected, .invalid_subject), self.parsed.value.subject) },
            else => Observation{ .outcome = self.result(.rejected, .invalid_record) },
        };
        out.outcome.work_used = self.limits.work - budget.remaining;
        return out;
    }
    fn analyzeInner(self: *const Program, input: []const u8, scratch: *Scratch, budget: *Budget) !Observation {
        var fixed = std.heap.FixedBufferAllocator.init(&scratch.bytes);
        const fields = try self.decode(fixed.allocator(), input, budget);
        const spec = self.parsed.value;
        var observation: Observation = .{ .outcome = self.result(.candidate, .matched) };
        if (spec.correlation) |c| {
            const key_value = fields.get(c.key) orelse return .{ .outcome = withField(self.result(.rejected, .missing_field), c.key) };
            const phase_value = fields.get(c.phase) orelse return .{ .outcome = withField(self.result(.rejected, .missing_field), c.phase) };
            const key = textValue(key_value) orelse return .{ .outcome = withField(self.result(.rejected, .wrong_type), c.key) };
            const phase = textValue(phase_value) orelse return .{ .outcome = withField(self.result(.rejected, .wrong_type), c.phase) };
            if (key.len == 0 or key.len > 64) return .{ .outcome = self.result(.rejected, .invalid_record) };
            try budget.spend(8 * 64 + phase.len + c.start.len + c.finish.len);
            const tag: @FieldType(CorrelationInput, "phase") = if (std.mem.eql(u8, phase, c.start)) .start else if (std.mem.eql(u8, phase, c.finish)) .finish else .other;
            observation.correlation = .{ .key = try Key.init(key), .phase = tag };
            if (tag == .other) {
                observation.outcome = self.result(.no_match, .condition_failed);
                return observation;
            }
            observation.outcome.subject = try self.readSubject(fields.get(spec.subject), budget);
            if (tag == .start) {
                if (observation.outcome.subject == null) return .{ .outcome = withField(self.result(.rejected, .missing_field), spec.subject) };
                observation.outcome.kind = .awaiting_context;
                observation.outcome.reason = .context_stored;
                return self.applyExclusions(fields, observation, budget);
            }
        }
        for (spec.conditions, 0..) |predicate, i| {
            const value = fields.get(predicate.field) orelse return .{ .outcome = withField(self.result(.rejected, .missing_field), predicate.field) };
            const matches = try compare(value, predicate, budget) orelse return .{ .outcome = withField(self.result(.rejected, .wrong_type), predicate.field) };
            if (!matches) {
                observation.outcome = withField(self.result(.no_match, .condition_failed), predicate.field);
                observation.outcome.predicate = @intCast(i);
                return observation;
            }
        }
        if (spec.correlation == null) {
            observation.outcome.subject = try self.readSubject(fields.get(spec.subject), budget) orelse return .{ .outcome = withField(self.result(.rejected, .missing_field), spec.subject) };
        }
        observation = try self.applyExclusions(fields, observation, budget);
        if (observation.outcome.kind != .candidate) return observation;
        observation.outcome.field = try Name.init(spec.subject);
        if (observation.outcome.subject != null) observation.outcome.subject_origin = .record;
        return observation;
    }
    fn applyExclusions(self: *const Program, fields: Fields, initial: Observation, budget: *Budget) !Observation {
        var observation = initial;
        for (self.parsed.value.exclude, 0..) |predicate, i| {
            const value = fields.get(predicate.field) orelse return .{ .outcome = withField(self.result(.rejected, .missing_field), predicate.field) };
            const matches = try compare(value, predicate, budget) orelse return .{ .outcome = withField(self.result(.rejected, .wrong_type), predicate.field) };
            if (matches) {
                observation.outcome.kind = .excluded;
                observation.outcome.reason = .exclusion_matched;
                observation.outcome.field = try Name.init(predicate.field);
                observation.outcome.predicate = @intCast(i);
                return observation;
            }
        }
        return observation;
    }
    fn readSubject(self: *const Program, value: ?Value, budget: *Budget) !?Subject {
        const v = value orelse return null;
        return switch (v) {
            .address => |ip| if (self.parsed.value.subject_kind == .ip) Subject{ .address = ip } else error.InvalidSubject,
            .hostname => |host| if (self.parsed.value.subject_kind == .hostname) Subject{ .hostname = host } else error.InvalidSubject,
            .text => |text| blk: {
                try budget.spend(text.len);
                break :blk if (self.parsed.value.subject_kind == .ip) Subject{ .address = try parseAddress(text) } else Subject{ .hostname = try Hostname.init(text) };
            },
            else => error.InvalidSubject,
        };
    }
};
fn decodeQuoted(allocator: std.mem.Allocator, input: []const u8, cursor: *usize, budget: *Budget) ![]const u8 {
    if (cursor.* == input.len or input[cursor.*] != '"') return error.InvalidRecord;
    try budget.spend(1);
    cursor.* += 1;
    const decoded = allocator.alloc(u8, value_cap) catch return error.ResourceLimit;
    var len: usize = 0;
    while (cursor.* < input.len) {
        try budget.spend(1);
        var byte = input[cursor.*];
        cursor.* += 1;
        if (byte == '"') return decoded[0..len];
        if (byte == '\\') {
            if (cursor.* == input.len) return error.InvalidRecord;
            try budget.spend(1);
            byte = input[cursor.*];
            cursor.* += 1;
            if (byte != '"' and byte != '\\') return error.InvalidRecord;
        }
        if (byte < 0x20 or byte > 0x7e) return error.InvalidRecord;
        if (len == value_cap) return error.ResourceLimit;
        decoded[len] = byte;
        len += 1;
    }
    return error.InvalidRecord;
}

pub fn validName(name: []const u8) bool {
    if (name.len == 0 or name.len > name_cap) return false;
    for (name) |c| if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '-') return false;
    return true;
}
fn space(c: u8) bool {
    return c == ' ' or c == '\t';
}
fn textValue(value: ?Value) ?[]const u8 {
    return if (value) |v| switch (v) {
        .text => |t| t,
        else => null,
    } else null;
}
fn compare(value: Value, p: Predicate, budget: *Budget) !?bool {
    try budget.spend(field_cap * name_cap);
    if (p.number) |n| return switch (value) {
        .number => |v| v == n,
        else => null,
    };
    const actual = switch (value) {
        .text => |t| t,
        else => return null,
    };
    const expected = p.text.?;
    try budget.spend(actual.len + expected.len);
    return switch (p.op) {
        .equal => std.mem.eql(u8, actual, expected),
        .starts_with => std.mem.startsWith(u8, actual, expected),
    };
}

fn parseAddress(text: []const u8) !Ip {
    if (text.len == 0 or text.len > 45) return error.InvalidSubject;
    const ip = Ip.parse(text) catch return error.InvalidSubject;
    if (ip.isUnenforceable()) return error.InvalidSubject;
    return ip;
}
fn withField(outcome: Outcome, field: []const u8) Outcome {
    var out = outcome;
    var name: Name = .{ .len = @intCast(field.len) };
    @memcpy(name.bytes[0..name.len], field);
    out.field = name;
    return out;
}

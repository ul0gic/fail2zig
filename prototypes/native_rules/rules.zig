// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Isolated N1 experiment. No daemon, firewall, subprocess, network or persistence access.
const std = @import("std");
const Ip = @import("shared").IpAddress;
const field_cap = 8;
const segment_cap = 24;
const scratch_bytes = 32 * 1024;
const session_cap = 8;
const name_cap = 32;
const value_cap = 256;

pub const Limits = struct {
    config_bytes: usize = 4096,
    record_bytes: usize = 2048,
    work: usize = 16384,
};
const Predicate = struct {
    field: []const u8,
    op: enum { equal, starts_with } = .equal,
    text: ?[]const u8 = null,
    number: ?u64 = null,
};
const Correlation = struct {
    key: []const u8,
    phase: []const u8,
    start: []const u8,
    finish: []const u8,
    ttl_seconds: u64,
};
const Spec = struct {
    id: []const u8,
    source: []const u8,
    format: enum { json, template },
    template: ?[]const u8 = null,
    subject: []const u8,
    conditions: []const Predicate,
    exclude: []const Predicate = &.{},
    correlation: ?Correlation = null,
};
const Capture = enum { word, ip, uint, quoted };
const Segment = union(enum) {
    literal: []const u8,
    capture: struct { name: []const u8, kind: Capture, delimiter: ?u8 },
};
const Value = union(enum) { text: []const u8, number: u64, ip: Ip };
const Field = struct { name: []const u8, value: Value };
const Fields = struct {
    entries: [field_cap]Field = undefined,
    count: usize = 0,

    fn add(self: *Fields, name: []const u8, value: Value) !void {
        if (self.count == field_cap) return error.ResourceLimit;
        if (!validName(name)) return error.InvalidRecord;
        if (self.get(name) != null) return error.InvalidRecord;
        self.entries[self.count] = .{ .name = name, .value = value };
        self.count += 1;
    }

    fn get(self: *const Fields, name: []const u8) ?Value {
        for (self.entries[0..self.count]) |entry| {
            if (std.mem.eql(u8, entry.name, name)) return entry.value;
        }
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

pub const Kind = enum { candidate, no_match, excluded, awaiting_context, rejected, exhausted };
pub const Reason = enum {
    matched,
    source_mismatch,
    template_mismatch,
    condition_failed,
    exclusion_matched,
    missing_field,
    wrong_type,
    invalid_record,
    invalid_subject,
    incomplete_record,
    input_limit,
    resource_limit,
    context_stored,
    context_missing,
    context_expired,
    context_conflict,
    clock_reversed,
};
pub const Outcome = struct {
    kind: Kind,
    reason: Reason,
    rule: []const u8,
    source: []const u8,
    field: ?[]const u8 = null,
    predicate: ?usize = null,
    subject: ?Ip = null,
    subject_origin: ?enum { record, context } = null,
    work_used: usize = 0,

    /// Emits selected evidence only; never echoes raw records or account/session values.
    pub fn writeJson(self: Outcome, writer: anytype) !void {
        var buf: [64]u8 = undefined;
        const address: ?[]const u8 = if (self.subject) |ip| try std.fmt.bufPrint(&buf, "{}", .{ip}) else null;
        try std.json.stringify(.{
            .kind = self.kind,
            .reason = self.reason,
            .rule = self.rule,
            .source = self.source,
            .field = self.field,
            .predicate = self.predicate,
            .subject = address,
            .subject_origin = self.subject_origin,
            .work_used = self.work_used,
        }, .{}, writer);
        try writer.writeByte('\n');
    }
};

/// Heap-pinned owner: all config strings and compiled segments live in fixed storage.
/// Sessions borrow this program. Destroy sessions before destroying/replacing it.
pub const Program = struct {
    owner: std.mem.Allocator,
    storage: [scratch_bytes]u8 = undefined,
    fixed: std.heap.FixedBufferAllocator,
    parsed: std.json.Parsed(Spec),
    limits: Limits,
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
                // A colon belongs to IPv6 addresses: require bracket/whitespace framing
                // instead of accepting a valid prefix of a longer address.
                if (kind == .ip and next == ':') return error.InvalidRule;
                delimiter = next;
            }
            // Quoted captures own their opening and closing quotes.
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
                        (c.kind == .uint and p.number == null) or c.kind == .ip) return error.InvalidRule;
                },
                else => {},
            };
        };
        // A subject token has explicit IP typing, not an arbitrary text search.
        for (self.segments[0..self.segment_count]) |seg| switch (seg) {
            .capture => |c| if (std.mem.eql(u8, c.name, self.parsed.value.subject) and c.kind != .ip) return error.InvalidRule,
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
            // Fixed per-record allocator owns the parse for the entire evaluation.
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
                    .ip => .{ .ip = try parseSubject(text) },
                    .uint => blk: {
                        for (text) |c| if (!std.ascii.isDigit(c)) return error.InvalidRecord;
                        break :blk .{ .number = std.fmt.parseInt(u64, text, 10) catch return error.InvalidRecord };
                    },
                    .quoted => unreachable,
                };
                try fields.add(capture.name, value);
            },
        };
        if (cursor != input.len) return error.TemplateMismatch;
        return fields;
    }

    fn result(self: *const Program, kind: Kind, reason: Reason) Outcome {
        return .{ .kind = kind, .reason = reason, .rule = self.parsed.value.id, .source = self.parsed.value.source };
    }
};

const Context = struct {
    key: [64]u8 = undefined,
    len: usize = 0,
    subject: Ip = .{ .ipv4 = 0 },
    started: u64 = 0,
};

/// One bounded session per program/source. Time is caller-supplied monotonic seconds.
/// Context is deliberately memory-only; restart/reload continuity is outside this experiment.
pub const Session = struct {
    program: *const Program,
    contexts: [session_cap]Context = [_]Context{.{}} ** session_cap,
    last_time: u64 = 0,

    pub fn evaluate(self: *Session, source: []const u8, input: []const u8, complete: bool, now: u64) Outcome {
        const p = self.program;
        if (!std.mem.eql(u8, source, p.parsed.value.source)) return p.result(.no_match, .source_mismatch);
        if (!complete) return p.result(.rejected, .incomplete_record);
        if (input.len > p.limits.record_bytes) return p.result(.exhausted, .input_limit);
        if (now < self.last_time) return p.result(.rejected, .clock_reversed);
        var staged = self.*;
        var budget: Budget = .{ .remaining = p.limits.work };
        var out = staged.evaluateInner(input, now, &budget) catch |err| p.result(
            if (err == error.ResourceLimit) .exhausted else if (err == error.TemplateMismatch) .no_match else .rejected,
            switch (err) {
                error.ResourceLimit => .resource_limit,
                error.TemplateMismatch => .template_mismatch,
                error.InvalidSubject => .invalid_subject,
                else => .invalid_record,
            },
        );
        out.work_used = p.limits.work - budget.remaining;
        if (out.reason == .invalid_subject) out.field = p.parsed.value.subject;
        // Errors/no-match do not publish a partial context update.
        if (out.kind == .candidate or out.kind == .awaiting_context or out.kind == .excluded) self.* = staged;
        self.last_time = now;
        return out;
    }

    fn evaluateInner(self: *Session, input: []const u8, now: u64, budget: *Budget) !Outcome {
        const p = self.program;
        const spec = p.parsed.value;
        var scratch: [scratch_bytes]u8 = undefined;
        var fixed = std.heap.FixedBufferAllocator.init(&scratch);
        const fields = try p.decode(fixed.allocator(), input, budget);
        var context_index: ?usize = null;
        var inherited: ?Ip = null;
        if (spec.correlation) |c| {
            const key_value = fields.get(c.key) orelse return withField(p.result(.rejected, .missing_field), c.key);
            const phase_value = fields.get(c.phase) orelse return withField(p.result(.rejected, .missing_field), c.phase);
            const key = textValue(key_value) orelse return withField(p.result(.rejected, .wrong_type), c.key);
            const phase = textValue(phase_value) orelse return withField(p.result(.rejected, .wrong_type), c.phase);
            if (key.len == 0 or key.len > 64) return p.result(.rejected, .invalid_record);
            try budget.spend(session_cap * 64 + phase.len + c.start.len + c.finish.len);
            var empty: ?usize = null;
            for (&self.contexts, 0..) |*entry, i| {
                if (entry.len == 0) {
                    if (empty == null) empty = i;
                    continue;
                }
                const same = std.mem.eql(u8, entry.key[0..entry.len], key);
                if (now - entry.started >= c.ttl_seconds) {
                    if (same and std.mem.eql(u8, phase, c.finish)) return p.result(.rejected, .context_expired);
                    entry.len = 0;
                    if (empty == null) empty = i;
                } else if (same) context_index = i;
            }
            if (std.mem.eql(u8, phase, c.start)) {
                const ip = try subject(fields.get(spec.subject), budget) orelse return withField(p.result(.rejected, .missing_field), spec.subject);
                if (context_index) |i| {
                    if (!self.contexts[i].subject.eql(ip)) return p.result(.rejected, .context_conflict);
                    return p.result(.awaiting_context, .context_stored); // no TTL extension
                }
                const index = empty orelse return error.ResourceLimit;
                self.contexts[index] = .{ .len = key.len, .subject = ip, .started = now };
                @memcpy(self.contexts[index].key[0..key.len], key);
                return p.result(.awaiting_context, .context_stored);
            }
            if (!std.mem.eql(u8, phase, c.finish)) return p.result(.no_match, .condition_failed);
            const index = context_index orelse return p.result(.rejected, .context_missing);
            inherited = self.contexts[index].subject;
            if (try subject(fields.get(spec.subject), budget)) |explicit| {
                if (!explicit.eql(inherited.?)) return p.result(.rejected, .context_conflict);
            }
        }
        for (spec.conditions, 0..) |predicate, i| {
            const value = fields.get(predicate.field) orelse return withField(p.result(.rejected, .missing_field), predicate.field);
            const matches = try compare(value, predicate, budget) orelse return withField(p.result(.rejected, .wrong_type), predicate.field);
            if (!matches) {
                var out = withField(p.result(.no_match, .condition_failed), predicate.field);
                out.predicate = i;
                return out;
            }
        }
        const ip = inherited orelse (try subject(fields.get(spec.subject), budget) orelse return withField(p.result(.rejected, .missing_field), spec.subject));
        for (spec.exclude, 0..) |predicate, i| {
            const value = fields.get(predicate.field) orelse return withField(p.result(.rejected, .missing_field), predicate.field);
            const matches = try compare(value, predicate, budget) orelse return withField(p.result(.rejected, .wrong_type), predicate.field);
            if (matches) {
                if (context_index) |index| self.contexts[index].len = 0;
                var out = withField(p.result(.excluded, .exclusion_matched), predicate.field);
                out.predicate = i;
                return out;
            }
        }
        if (context_index) |index| self.contexts[index].len = 0;
        var out = p.result(.candidate, .matched);
        out.subject = ip;
        out.field = spec.subject;
        out.subject_origin = if (inherited != null) .context else .record;
        return out;
    }
};

/// Own quotes and decode only escaped quote/backslash. Consume once, without searching
/// for a later closing quote if the following literal fails. Storage is caller's fixed arena.
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

fn validName(name: []const u8) bool {
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
fn parseSubject(text: []const u8) !Ip {
    if (text.len == 0 or text.len > 45) return error.InvalidSubject;
    const ip = Ip.parse(text) catch return error.InvalidSubject;
    if (ip.isUnenforceable()) return error.InvalidSubject;
    return ip;
}
fn subject(value: ?Value, budget: *Budget) !?Ip {
    const v = value orelse return null;
    return switch (v) {
        .ip => |ip| ip,
        .text => |text| blk: {
            try budget.spend(text.len);
            break :blk try parseSubject(text);
        },
        else => error.InvalidSubject,
    };
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
fn withField(outcome: Outcome, field: []const u8) Outcome {
    var out = outcome;
    out.field = field;
    return out;
}

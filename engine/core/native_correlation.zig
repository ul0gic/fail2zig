// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const rules = @import("native_rules.zig");
pub const capacity = 8;
pub const version: u16 = 1;
pub const entry_bytes = 384;
pub const checkpoint_bytes = 48 + capacity * entry_bytes;
pub const Timing = struct {
    occurrence: [32]u8,
    event_us: i64,
    receipt_us: i64,
    processing_us: i64,
    pub fn validate(self: Timing) !void {
        if (self.receipt_us > self.processing_us or self.event_us > self.processing_us) return error.InvalidCorrelationTime;
    }
};
pub const Entry = struct {
    key: rules.Key,
    subject: rules.Subject,
    occurrence: [32]u8,
    event_us: i64,
    receipt_us: i64,
    deadline_us: i64,
};
pub const State = struct {
    entries: [capacity]?Entry = [_]?Entry{null} ** capacity,
    watermark_us: ?i64 = null,
};
pub const Prepared = struct {
    checkpoint: []const u8,
    outcome: ?rules.Outcome,
    valid_until_us: ?i64 = null,
    owner: *Session,
    pub fn publish(self: Prepared) void {
        self.owner.live = self.owner.staged;
    }
    pub fn release(self: Prepared) void {
        self.owner.in_flight = false;
    }
};
pub const Session = struct {
    binding: [32]u8,
    ttl_us: i64,
    subject_kind: enum { ip, hostname },
    live: State = .{},
    staged: State = .{},
    bytes: [checkpoint_bytes]u8 = undefined,
    in_flight: bool = false,

    pub fn init(binding: [32]u8, ttl_seconds: u64, hostname: bool) !Session {
        if (ttl_seconds == 0 or ttl_seconds > 300) return error.InvalidCorrelationPolicy;
        return .{ .binding = binding, .ttl_us = @as(i64, @intCast(ttl_seconds)) * 1_000_000, .subject_kind = if (hostname) .hostname else .ip };
    }
    pub fn prepare(self: *Session, observation: rules.Observation, timing: Timing) !Prepared {
        if (self.in_flight) return error.ConsumerBusy;
        try timing.validate();
        if (self.live.watermark_us) |watermark| if (timing.processing_us < watermark) return error.CorrelationClockReversed;
        var next = self.live;
        next.watermark_us = timing.processing_us;
        var outcome = observation.outcome;
        var valid_until_us: ?i64 = null;
        if (observation.correlation) |input| {
            if (!input.key.valid() or input.key.len == 0) return error.InvalidCorrelationInput;
            if (outcome.kind == .awaiting_context and input.phase == .start) {
                const subject = outcome.subject orelse return error.InvalidCorrelationInput;
                try self.validateSubject(subject);
                const deadline = std.math.add(i64, timing.receipt_us, self.ttl_us) catch return error.CorrelationTimeOverflow;
                if (timing.processing_us >= deadline) {
                    outcome.kind = .rejected;
                    outcome.reason = .context_expired;
                    outcome.subject = null;
                } else {
                    var empty: ?usize = null;
                    var matched: ?usize = null;
                    var expired_same: ?usize = null;
                    for (next.entries, 0..) |maybe, i| {
                        if (maybe) |entry| {
                            if (entry.deadline_us <= timing.processing_us) {
                                if (empty == null) empty = i;
                                if (std.mem.eql(u8, entry.key.slice(), input.key.slice())) expired_same = i;
                            } else if (std.mem.eql(u8, entry.key.slice(), input.key.slice())) matched = i;
                        } else if (empty == null) {
                            empty = i;
                        }
                    }
                    if (matched) |index| {
                        if (!next.entries[index].?.subject.eql(subject)) {
                            outcome.kind = .rejected;
                            outcome.reason = .context_conflict;
                            outcome.subject = null;
                        }
                        if (outcome.kind == .awaiting_context) valid_until_us = next.entries[index].?.deadline_us;
                    } else {
                        const index = expired_same orelse empty orelse return error.ContextCapacity;
                        next.entries[index] = .{ .key = input.key, .subject = subject, .occurrence = timing.occurrence, .event_us = timing.event_us, .receipt_us = timing.receipt_us, .deadline_us = deadline };
                        valid_until_us = deadline;
                    }
                }
            } else if (input.phase == .finish and (outcome.kind == .candidate or outcome.kind == .excluded)) {
                var found: ?usize = null;
                for (next.entries, 0..) |maybe, i| if (maybe) |entry| {
                    if (std.mem.eql(u8, entry.key.slice(), input.key.slice())) {
                        found = i;
                        break;
                    }
                };
                if (found) |index| {
                    const entry = next.entries[index].?;
                    const event_end = @as(i128, entry.event_us) + self.ttl_us;
                    const reason: ?rules.Reason = if (timing.processing_us >= entry.deadline_us) .context_expired else if (timing.event_us < entry.event_us or @as(i128, timing.event_us) > event_end) .event_order else if (outcome.subject != null and !outcome.subject.?.eql(entry.subject)) .context_conflict else null;
                    if (reason) |why| {
                        outcome.kind = .rejected;
                        outcome.reason = why;
                        outcome.subject = null;
                        outcome.subject_origin = null;
                    } else {
                        outcome.subject = entry.subject;
                        outcome.subject_origin = .context;
                        valid_until_us = entry.deadline_us;
                        next.entries[index] = null;
                    }
                } else {
                    outcome.kind = .rejected;
                    outcome.reason = .context_missing;
                    outcome.subject = null;
                    outcome.subject_origin = null;
                }
            }
        }
        try self.encode(next);
        self.staged = next;
        self.in_flight = true;
        return .{ .owner = self, .checkpoint = &self.bytes, .outcome = outcome, .valid_until_us = valid_until_us };
    }
    pub fn prepareRestore(self: *Session, saved: []const u8) !Prepared {
        if (self.in_flight) return error.ConsumerBusy;
        const next = try self.decode(saved);
        try self.encode(next);
        self.staged = next;
        self.in_flight = true;
        return .{ .owner = self, .checkpoint = &self.bytes, .outcome = null };
    }
    pub fn prepareSnapshot(self: *Session) !Prepared {
        if (self.in_flight) return error.ConsumerBusy;
        try self.encode(self.live);
        self.staged = self.live;
        self.in_flight = true;
        return .{ .owner = self, .checkpoint = &self.bytes, .outcome = null };
    }
    fn validateSubject(self: *const Session, subject: rules.Subject) !void {
        if ((self.subject_kind == .hostname) != (subject == .hostname)) return error.InvalidCorrelationCheckpoint;
        switch (subject) {
            .hostname => |name| try name.validate(),
            .address => |ip| {
                if (ip.isUnenforceable()) return error.InvalidCorrelationCheckpoint;
                if (ip == .ipv6 and ((ip.ipv6 >> 32) == 0xffff or (ip.ipv6 > 1 and ip.ipv6 >> 32 == 0))) return error.InvalidCorrelationCheckpoint;
            },
        }
    }
    fn validateState(self: *const Session, state: State) !void {
        for (state.entries, 0..) |maybe, index| if (maybe) |entry| {
            const watermark = state.watermark_us orelse return error.InvalidCorrelationCheckpoint;
            if (!entry.key.valid() or entry.key.len == 0 or entry.event_us > watermark or entry.receipt_us > watermark or
                @as(i128, entry.deadline_us) != @as(i128, entry.receipt_us) + self.ttl_us) return error.InvalidCorrelationCheckpoint;
            try self.validateSubject(entry.subject);
            for (state.entries[0..index]) |previous| if (previous) |other| {
                if (std.mem.eql(u8, other.key.slice(), entry.key.slice())) return error.InvalidCorrelationCheckpoint;
            };
        };
    }
    fn encode(self: *Session, state: State) !void {
        try self.validateState(state);
        @memset(&self.bytes, 0);
        @memcpy(self.bytes[0..4], "F2NC");
        std.mem.writeInt(u16, self.bytes[4..6], version, .little);
        self.bytes[6] = @intFromBool(state.watermark_us != null);
        @memcpy(self.bytes[8..40], &self.binding);
        if (state.watermark_us) |watermark| std.mem.writeInt(i64, self.bytes[40..48], watermark, .little);
        for (state.entries, 0..) |maybe, i| if (maybe) |entry| {
            const out = self.bytes[48 + i * entry_bytes ..][0..entry_bytes];
            out[0] = @intCast(entry.key.len);
            @memcpy(out[1..65], &entry.key.bytes);
            switch (entry.subject) {
                .address => |ip| switch (ip) {
                    .ipv4 => |v| {
                        out[65] = 4;
                        std.mem.writeInt(u16, out[66..68], 4, .little);
                        std.mem.writeInt(u32, out[68..72], v, .big);
                    },
                    .ipv6 => |v| {
                        out[65] = 6;
                        std.mem.writeInt(u16, out[66..68], 16, .little);
                        std.mem.writeInt(u128, out[68..84], v, .big);
                    },
                },
                .hostname => |name| {
                    out[65] = 1;
                    std.mem.writeInt(u16, out[66..68], name.text.len, .little);
                    @memcpy(out[68..321], &name.text.bytes);
                },
            }
            @memcpy(out[321..353], &entry.occurrence);
            std.mem.writeInt(i64, out[353..361], entry.event_us, .little);
            std.mem.writeInt(i64, out[361..369], entry.receipt_us, .little);
            std.mem.writeInt(i64, out[369..377], entry.deadline_us, .little);
        };
    }
    fn decode(self: *const Session, saved: []const u8) !State {
        if (saved.len != checkpoint_bytes or !std.mem.eql(u8, saved[0..4], "F2NC")) return error.InvalidCorrelationCheckpoint;
        if (std.mem.readInt(u16, saved[4..6], .little) != version or saved[6] > 1 or saved[7] != 0) return error.UnsupportedCorrelationCheckpoint;
        if (!std.mem.eql(u8, saved[8..40], &self.binding)) return error.CorrelationGenerationMismatch;
        var state: State = .{};
        if (saved[6] == 1) state.watermark_us = std.mem.readInt(i64, saved[40..48], .little) else if (!std.mem.allEqual(u8, saved[40..48], 0)) return error.InvalidCorrelationCheckpoint;
        for (&state.entries, 0..) |*slot, i| {
            const input = saved[48 + i * entry_bytes ..][0..entry_bytes];
            if (input[0] == 0) {
                if (!std.mem.allEqual(u8, input, 0)) return error.InvalidCorrelationCheckpoint;
                continue;
            }
            if (input[0] > 64 or !std.mem.allEqual(u8, input[377..], 0)) return error.InvalidCorrelationCheckpoint;
            const length = std.mem.readInt(u16, input[66..68], .little);
            if (length == 0 or length > 253 or !std.mem.allEqual(u8, input[68 + @as(usize, length) .. 321], 0)) return error.InvalidCorrelationCheckpoint;
            const subject: rules.Subject = switch (input[65]) {
                4 => if (length == 4) .{ .address = .{ .ipv4 = std.mem.readInt(u32, input[68..72], .big) } } else return error.InvalidCorrelationCheckpoint,
                6 => if (length == 16) .{ .address = .{ .ipv6 = std.mem.readInt(u128, input[68..84], .big) } } else return error.InvalidCorrelationCheckpoint,
                1 => blk: {
                    const name = rules.Hostname.init(input[68 .. 68 + length]) catch return error.InvalidCorrelationCheckpoint;
                    if (!std.mem.eql(u8, name.slice(), input[68 .. 68 + length])) return error.InvalidCorrelationCheckpoint;
                    break :blk .{ .hostname = name };
                },
                else => return error.InvalidCorrelationCheckpoint,
            };
            var key = rules.Key{ .len = input[0] };
            @memcpy(&key.bytes, input[1..65]);
            slot.* = .{ .key = key, .subject = subject, .occurrence = input[321..353].*, .event_us = std.mem.readInt(i64, input[353..361], .little), .receipt_us = std.mem.readInt(i64, input[361..369], .little), .deadline_us = std.mem.readInt(i64, input[369..377], .little) };
        }
        try self.validateState(state);
        return state;
    }
};

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
pub const StagedInput = struct {
    record: @import("source_record.zig").Record,
    decoded: []const u8,
    time: policy.Result,
    processing_us: i64,
    monotonic_ms: u64,
};
pub const StagedPrepared = struct {
    outcomes: []const Outcome,
    consumers: @import("native_consumer.zig").Batch,
    context: ?*anyopaque,
    publish: *const fn (?*anyopaque) void,
    release: *const fn (?*anyopaque) void,
};
pub const StagedState = struct {
    consumers: @import("native_consumer.zig").Batch,
    context: ?*anyopaque,
    publish: *const fn (?*anyopaque) void,
    release: *const fn (?*anyopaque) void,
};
pub const StagedConsumer = struct {
    generation: [32]u8,
    context: ?*anyopaque,
    prepare: *const fn (StagedInput, ?*anyopaque) anyerror!StagedPrepared,
    prepare_checkpoint: *const fn (@import("source_record.zig").Record, i64, u64, ?*anyopaque) anyerror!StagedState,
    manifest: *const fn ([]const u8, [32]u8, ?*anyopaque) anyerror!@import("native_consumer.zig").Manifest,
    processing_time: ?*const fn (@import("source_record.zig").Record, i64, ?*anyopaque) anyerror!i64 = null,
};
const policy = @import("source_time_policy.zig");
pub const version: u16 = 1;
pub const Kind = enum(u8) {
    time_excluded = 1,
    malformed_body,
    no_match,
    unenforceable,
    ignored,
    candidate,
    origin_missing,
    origin_ambiguous,
    origin_machine,
    origin_uid,
    origin_executable,
    origin_transport,
};
pub const Name = struct {
    bytes: [64]u8 = [_]u8{0} ** 64,
    len: u8,
    pub fn init(value: []const u8) !Name {
        if (value.len == 0 or value.len > 64) return error.InvalidDetection;
        for (value) |c| if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_' and c != '.') return error.InvalidDetection;
        var result = Name{ .len = @intCast(value.len) };
        @memcpy(result.bytes[0..value.len], value);
        return result;
    }
    pub fn slice(self: *const Name) []const u8 {
        return self.bytes[0..self.len];
    }
    fn validate(self: *const Name) !void {
        if (self.len == 0 or self.len > self.bytes.len) return error.InvalidDetection;
        const canonical = try init(self.slice());
        if (!std.mem.eql(u8, &self.bytes, &canonical.bytes)) return error.InvalidDetection;
    }
};
pub const Subject = union(enum) {
    v4: [4]u8,
    v6: [16]u8,
    pub fn unenforceable(self: Subject) bool {
        return switch (self) {
            .v4 => |v| v[0] == 0 or v[0] == 127,
            .v6 => |v| std.mem.readInt(u128, &v, .big) <= 1,
        };
    }
    pub fn validate(self: Subject) error{InvalidDetection}!void {
        if (self == .v6) {
            const value = std.mem.readInt(u128, &self.v6, .big);
            if ((value >> 32) == 0xffff or (value > 1 and value >> 32 == 0)) return error.InvalidDetection;
        }
    }
};
pub const Outcome = struct {
    kind: Kind,
    generation: [32]u8,
    filter: Name,
    pattern: ?Name = null,
    pattern_index: ?u16 = null,
    subject: ?Subject = null,

    pub fn validate(self: *const Outcome, time: policy.Result) !void {
        try self.filter.validate();
        if ((self.kind == .time_excluded) != (time != .eligible)) return error.InvalidDetection;
        switch (self.kind) {
            .time_excluded, .malformed_body, .no_match, .origin_missing, .origin_ambiguous, .origin_machine, .origin_uid, .origin_executable, .origin_transport => if (self.pattern != null or self.pattern_index != null or self.subject != null) return error.InvalidDetection,
            .unenforceable, .ignored, .candidate => {
                const pattern = self.pattern orelse return error.InvalidDetection;
                try pattern.validate();
                if (self.pattern_index == null) return error.InvalidDetection;
                const subject = self.subject orelse return error.InvalidDetection;
                try subject.validate();
                if ((self.kind == .unenforceable) != subject.unenforceable()) return error.InvalidDetection;
            },
        }
    }
};

pub const Consumer = struct {
    generation: [32]u8,
    context: ?*const anyopaque,
    evaluate: *const fn ([]const u8, policy.Result, ?*const anyopaque) anyerror!Outcome,
};

pub const JournalConsumer = struct {
    generation: [32]u8,
    context: ?*const anyopaque,
    evaluate: *const fn ([]const u8, ?[]const @import("source_record.zig").JournalField, policy.Result, ?*const anyopaque) anyerror!Outcome,
};

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Detached native detection rows; no borrowed SQLite memory or native struct
//! layout on disk. This is failure evidence, not an enforcement intent.
const std = @import("std");
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
            // Mapped addresses must already be canonical IPv4. Compatible IPv6
            // aliases are rejected by the shared address parser as well.
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

/// Stable borrowed consumer. Only immutable/stateless consumers fit this API;
/// correlated rules require a staged checkpoint/publication contract of their own.
pub const Consumer = struct {
    generation: [32]u8,
    context: ?*const anyopaque,
    evaluate: *const fn ([]const u8, policy.Result, ?*const anyopaque) anyerror!Outcome,
};

/// A journal consumer must validate the record's origin before matching. Kept
/// separate from the file consumer so an unqualified detector cannot be selected
/// for journal input accidentally. Fields borrow the current complete record.
pub const JournalConsumer = struct {
    generation: [32]u8,
    context: ?*const anyopaque,
    evaluate: *const fn ([]const u8, ?[]const @import("source_record.zig").JournalField, policy.Result, ?*const anyopaque) anyerror!Outcome,
};

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Bounded retry-window transition. SQLite owns publication and occurrence
//! deduplication; this module never mutates live state or performs an effect.
const std = @import("std");
const detection = @import("native_detection_record.zig");
pub const max_attempts = 128;
pub const attempt_bytes = 40;
pub const policy_bytes = 32;
pub const Error = error{ InvalidRetryPolicy, InvalidRetryState, RetryClockReversed, RetryTimeOverflow };

pub const Policy = struct {
    maxretry: u16,
    window_us: i64,
    bantime_us: i64,
    max_subjects: u32,
    enforce: bool = false,

    pub fn validate(self: Policy) Error!void {
        if (self.maxretry == 0 or self.maxretry > max_attempts or self.window_us <= 0 or
            self.bantime_us <= 0 or self.max_subjects == 0 or self.max_subjects > 65536)
            return error.InvalidRetryPolicy;
    }
    pub fn encode(self: Policy) Error![policy_bytes]u8 {
        try self.validate();
        var bytes = [_]u8{0} ** policy_bytes;
        @memcpy(bytes[0..4], "F2RP");
        bytes[4] = 1;
        bytes[5] = @intFromBool(self.enforce);
        std.mem.writeInt(u16, bytes[6..8], self.maxretry, .little);
        std.mem.writeInt(i64, bytes[8..16], self.window_us, .little);
        std.mem.writeInt(i64, bytes[16..24], self.bantime_us, .little);
        std.mem.writeInt(u32, bytes[24..28], self.max_subjects, .little);
        return bytes;
    }
    pub fn decode(bytes: []const u8) Error!Policy {
        if (bytes.len != policy_bytes or !std.mem.eql(u8, bytes[0..4], "F2RP") or bytes[4] != 1 or
            bytes[5] > 1 or !std.mem.allEqual(u8, bytes[28..], 0)) return error.InvalidRetryPolicy;
        const result = Policy{
            .enforce = bytes[5] == 1,
            .maxretry = std.mem.readInt(u16, bytes[6..8], .little),
            .window_us = std.mem.readInt(i64, bytes[8..16], .little),
            .bantime_us = std.mem.readInt(i64, bytes[16..24], .little),
            .max_subjects = std.mem.readInt(u32, bytes[24..28], .little),
        };
        try result.validate();
        return result;
    }
};
pub const Admission = struct { generation: [32]u8, policy: Policy, processing_us: ?i64 = null };
pub const Attempt = struct { at_us: i64, occurrence: [32]u8 };
pub const State = struct {
    last_processed_us: i64,
    expiry_us: ?i64 = null,
    decisions: u64 = 0,
    attempts: [max_attempts]Attempt = undefined,
    count: u16 = 0,

    pub fn validate(self: *const State, policy: Policy) Error!void {
        try policy.validate();
        if (self.count >= policy.maxretry or self.decisions > std.math.maxInt(i64)) return error.InvalidRetryState;
        if (self.expiry_us) |expiry| {
            if (self.decisions == 0 or self.count != 0 or expiry <= self.last_processed_us or
                @as(i128, expiry) - self.last_processed_us > policy.bantime_us) return error.InvalidRetryState;
        }
        const cutoff = @as(i128, self.last_processed_us) - policy.window_us;
        for (self.attempts[0..self.count], 0..) |attempt, i| {
            if (attempt.at_us > self.last_processed_us or attempt.at_us < cutoff) return error.InvalidRetryState;
            if (i > 0 and attempt.at_us < self.attempts[i - 1].at_us) return error.InvalidRetryState;
            for (self.attempts[0..i]) |other| if (std.mem.eql(u8, &other.occurrence, &attempt.occurrence)) return error.InvalidRetryState;
        }
    }
    pub fn encodeAttempts(self: *const State, buffer: *[max_attempts * attempt_bytes]u8) []const u8 {
        for (self.attempts[0..self.count], 0..) |attempt, i| {
            const offset = i * attempt_bytes;
            std.mem.writeInt(i64, buffer[offset..][0..8], attempt.at_us, .little);
            @memcpy(buffer[offset + 8 ..][0..32], &attempt.occurrence);
        }
        return buffer[0 .. self.count * attempt_bytes];
    }
    pub fn decodeAttempts(self: *State, bytes: []const u8, policy: Policy) Error!void {
        if (bytes.len > max_attempts * attempt_bytes or bytes.len % attempt_bytes != 0) return error.InvalidRetryState;
        self.count = @intCast(bytes.len / attempt_bytes);
        for (self.attempts[0..self.count], 0..) |*attempt, i| {
            const offset = i * attempt_bytes;
            attempt.at_us = std.mem.readInt(i64, bytes[offset..][0..8], .little);
            @memcpy(&attempt.occurrence, bytes[offset + 8 ..][0..32]);
        }
        try self.validate(policy);
    }
};
pub const Decision = struct { subject: detection.Subject, decided_us: i64, expiry_us: i64, ordinal: u64, enforce: bool };
pub const Transition = struct { state: State, decision: ?Decision = null };

pub fn occurrenceKey(source: []const u8, occurrence: []const u8) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("fail2zig-retry-occurrence-v1\x00");
    for ([_][]const u8{ source, occurrence }) |value| {
        var length: [8]u8 = undefined;
        std.mem.writeInt(u64, &length, value.len, .little);
        hash.update(&length);
        hash.update(value);
    }
    return hash.finalResult();
}

/// Prune against processing time, keeping the existing inclusive findtime
/// endpoint. Late evidence cannot retain stale attempts by moving the window
/// backwards. A decision's finite deadline is fixed at its committed decision
/// time; subsequent matching records never extend it or accumulate behind it.
pub fn advance(policy: Policy, previous: ?State, subject: detection.Subject, attempt: Attempt, now_us: i64) Error!Transition {
    try policy.validate();
    subject.validate() catch return error.InvalidRetryState;
    if (subject.unenforceable()) return error.InvalidRetryState;
    if (attempt.at_us > now_us or @as(i128, attempt.at_us) < @as(i128, now_us) - policy.window_us) return error.InvalidRetryState;
    var next = previous orelse State{ .last_processed_us = now_us };
    if (previous != null) {
        try next.validate(policy);
        if (now_us < next.last_processed_us) return error.RetryClockReversed;
    }
    next.last_processed_us = now_us;
    if (next.expiry_us) |expiry| {
        if (expiry > now_us) return .{ .state = next };
        next.expiry_us = null;
    }
    var count: u16 = 0;
    for (next.attempts[0..next.count]) |retained| {
        if (@as(i128, retained.at_us) < @as(i128, now_us) - policy.window_us) continue;
        if (std.mem.eql(u8, &retained.occurrence, &attempt.occurrence)) return error.InvalidRetryState;
        next.attempts[count] = retained;
        count += 1;
    }
    next.count = count + 1;
    var index: usize = count;
    while (index > 0 and next.attempts[index - 1].at_us > attempt.at_us) : (index -= 1)
        next.attempts[index] = next.attempts[index - 1];
    next.attempts[index] = attempt;
    if (next.count < policy.maxretry) return .{ .state = next };
    const expiry = std.math.add(i64, now_us, policy.bantime_us) catch return error.RetryTimeOverflow;
    if (next.decisions == std.math.maxInt(i64)) return error.RetryTimeOverflow;
    next.decisions += 1;
    next.expiry_us = expiry;
    next.count = 0;
    return .{ .state = next, .decision = .{ .subject = subject, .decided_us = now_us, .expiry_us = expiry, .ordinal = next.decisions, .enforce = policy.enforce } };
}

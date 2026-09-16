// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const detection = @import("native_detection_record.zig");
const lease_policy = @import("native_lease.zig");
const escalation_policy = @import("native_escalation.zig");
pub const max_attempts = 128;
pub const attempt_bytes = 40;
pub const policy_bytes = 32;
pub const escalation_bytes = escalation_policy.encoded_bytes;
pub const max_evidence_text_bytes = 2 * 1024;
pub const max_subject_evidence_bytes = 16 * 1024;
pub const Error = lease_policy.Error || escalation_policy.Error || error{ InvalidRetryPolicy, InvalidRetryState, InvalidRetryEvidence, RetryClockReversed, RetryTimeOverflow };
pub const Duration = lease_policy.Duration;
pub const Lease = lease_policy.Lease;
pub const Escalation = escalation_policy.Policy;
pub const EscalationScope = escalation_policy.Scope;
pub const EscalationHistoryInput = escalation_policy.HistoryInput;

pub const Policy = struct {
    maxretry: u16,
    window_us: i64,
    duration: Duration,
    max_subjects: u32,
    enforce: bool = false,
    escalation: Escalation = .{},

    pub fn validate(self: Policy) Error!void {
        if (self.maxretry == 0 or self.maxretry > max_attempts or self.window_us <= 0 or
            self.max_subjects == 0 or self.max_subjects > 65536)
            return error.InvalidRetryPolicy;
        self.duration.validate() catch return error.InvalidRetryPolicy;
        self.escalation.validate() catch return error.InvalidRetryPolicy;
        if (self.escalation.enabled and self.duration == .permanent) return error.InvalidRetryPolicy;
    }
    pub fn encode(self: Policy) Error![policy_bytes]u8 {
        try self.validate();
        var bytes = [_]u8{0} ** policy_bytes;
        @memcpy(bytes[0..4], "F2RP");
        bytes[4] = 2;
        bytes[5] = @intFromBool(self.enforce);
        std.mem.writeInt(u16, bytes[6..8], self.maxretry, .little);
        std.mem.writeInt(i64, bytes[8..16], self.window_us, .little);
        switch (self.duration) {
            .finite_us => |value| std.mem.writeInt(i64, bytes[16..24], value, .little),
            .permanent => {},
        }
        std.mem.writeInt(u32, bytes[24..28], self.max_subjects, .little);
        bytes[28] = switch (self.duration) {
            .finite_us => 1,
            .permanent => 2,
        };
        return bytes;
    }
    pub fn decode(bytes: []const u8) Error!Policy {
        if (bytes.len != policy_bytes or !std.mem.eql(u8, bytes[0..4], "F2RP") or
            (bytes[4] != 1 and bytes[4] != 2) or bytes[5] > 1) return error.InvalidRetryPolicy;
        const raw_duration = std.mem.readInt(i64, bytes[16..24], .little);
        const duration: Duration = if (bytes[4] == 1) blk: {
            if (!std.mem.allEqual(u8, bytes[28..], 0)) return error.InvalidRetryPolicy;
            break :blk .{ .finite_us = raw_duration };
        } else switch (bytes[28]) {
            1 => if (std.mem.allEqual(u8, bytes[29..], 0)) .{ .finite_us = raw_duration } else return error.InvalidRetryPolicy,
            2 => if (raw_duration == 0 and std.mem.allEqual(u8, bytes[29..], 0)) .permanent else return error.InvalidRetryPolicy,
            else => return error.InvalidRetryPolicy,
        };
        const result = Policy{
            .enforce = bytes[5] == 1,
            .maxretry = std.mem.readInt(u16, bytes[6..8], .little),
            .window_us = std.mem.readInt(i64, bytes[8..16], .little),
            .duration = duration,
            .max_subjects = std.mem.readInt(u32, bytes[24..28], .little),
        };
        try result.validate();
        return result;
    }
    pub fn escalationBytes(self: Policy) Error![escalation_policy.encoded_bytes]u8 {
        try self.validate();
        return self.escalation.encode() catch return error.InvalidRetryPolicy;
    }
};
pub const Admission = struct {
    generation: [32]u8,
    policy: Policy,
    processing_us: ?i64 = null,
    suppress_enforcement: bool = false,

    pub fn enforces(self: Admission) bool {
        return self.policy.enforce and !self.suppress_enforcement;
    }
};
pub const Attempt = struct { at_us: i64, occurrence: [32]u8 };
pub const Evidence = struct {
    text: ?[]const u8 = null,

    pub fn validate(self: Evidence) Error!void {
        const value = self.text orelse return;
        if (value.len == 0 or value.len > max_evidence_text_bytes or !std.unicode.utf8ValidateSlice(value))
            return error.InvalidRetryEvidence;
    }
};
pub const State = struct {
    last_processed_us: i64,
    lease: Lease = .absent,
    decisions: u64 = 0,
    attempts: [max_attempts]Attempt = undefined,
    count: u16 = 0,

    pub fn latestEventUs(self: *const State) ?i64 {
        return if (self.count == 0) null else self.attempts[self.count - 1].at_us;
    }

    pub fn validate(self: *const State, policy: Policy) Error!void {
        try policy.validate();
        if (self.count >= policy.maxretry or self.decisions > std.math.maxInt(i64)) return error.InvalidRetryState;
        switch (self.lease) {
            .absent => {},
            .finite => |expiry| {
                if (self.decisions == 0 or self.count != 0 or expiry <= self.last_processed_us) return error.InvalidRetryState;
            },
            .permanent => if (self.decisions == 0 or self.count != 0) return error.InvalidRetryState,
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
pub const Decision = struct { subject: detection.Subject, decided_us: i64, lease: Lease, ordinal: u64, enforce: bool };
pub const Disposition = enum { counted, duplicate, active };
pub const Transition = struct { state: State, decision: ?Decision = null, disposition: Disposition = .counted };
pub const PruneResult = struct { state: State, changed: bool };

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

pub fn prune(policy: Policy, previous: State, now_us: i64) Error!PruneResult {
    try previous.validate(policy);
    if (now_us < previous.last_processed_us) return error.RetryClockReversed;
    var next = previous;
    next.last_processed_us = now_us;
    var changed = now_us != previous.last_processed_us;
    if (next.lease == .finite and !next.lease.live(now_us)) {
        next.lease = .absent;
        changed = true;
    }
    var count: u16 = 0;
    const cutoff = @as(i128, now_us) - policy.window_us;
    for (next.attempts[0..next.count]) |retained| {
        if (@as(i128, retained.at_us) < cutoff) {
            changed = true;
            continue;
        }
        next.attempts[count] = retained;
        count += 1;
    }
    next.count = count;
    try next.validate(policy);
    return .{ .state = next, .changed = changed };
}

pub fn advance(policy: Policy, previous: ?State, subject: detection.Subject, attempt: Attempt, now_us: i64) Error!Transition {
    try policy.validate();
    subject.validate() catch return error.InvalidRetryState;
    if (subject.unenforceable()) return error.InvalidRetryState;
    if (attempt.at_us > now_us or @as(i128, attempt.at_us) < @as(i128, now_us) - policy.window_us) return error.InvalidRetryState;
    if (previous) |prior| {
        try prior.validate(policy);
        if (now_us < prior.last_processed_us) return error.RetryClockReversed;
        for (prior.attempts[0..prior.count]) |retained| {
            if (!std.mem.eql(u8, &retained.occurrence, &attempt.occurrence)) continue;
            if (retained.at_us != attempt.at_us) return error.InvalidRetryState;
            return .{ .state = prior, .disposition = .duplicate };
        }
    }
    var next = if (previous) |prior| (try prune(policy, prior, now_us)).state else State{ .last_processed_us = now_us };
    if (next.lease != .absent) {
        if (!next.lease.live(now_us)) return error.InvalidRetryState;
        return .{ .state = next, .disposition = .active };
    }
    const count = next.count;
    next.count = count + 1;
    var index: usize = count;
    while (index > 0 and next.attempts[index - 1].at_us > attempt.at_us) : (index -= 1)
        next.attempts[index] = next.attempts[index - 1];
    next.attempts[index] = attempt;
    if (next.count < policy.maxretry) return .{ .state = next };
    if (next.decisions == std.math.maxInt(i64)) return error.RetryTimeOverflow;
    const lease = policy.duration.lease(now_us) catch |err| return switch (err) {
        error.TimeOverflow => error.RetryTimeOverflow,
        else => error.InvalidRetryPolicy,
    };
    next.decisions += 1;
    next.lease = lease;
    next.count = 0;
    return .{ .state = next, .decision = .{ .subject = subject, .decided_us = now_us, .lease = lease, .ordinal = next.decisions, .enforce = policy.enforce } };
}

pub fn advanceWithEvidence(policy: Policy, previous: ?State, subject: detection.Subject, attempt: Attempt, now_us: i64, evidence: Evidence) Error!Transition {
    try evidence.validate();
    return advance(policy, previous, subject, attempt, now_us);
}

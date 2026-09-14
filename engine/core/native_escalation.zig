// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Pure bounded duration escalation. Confirmed-history selection and durable
//! decision snapshots belong to Store; randomness is injected exactly once.
const std = @import("std");
const lease = @import("native_lease.zig");

pub const encoded_bytes: usize = 40;
pub const Formula = enum(u8) { linear = 1, exponential = 2 };
pub const Scope = enum(u8) { per_jail = 1, overall = 2 };
pub const Error = error{ InvalidEscalationPolicy, InvalidEscalationInput };

pub const Policy = struct {
    enabled: bool = false,
    formula: Formula = .linear,
    scope: Scope = .per_jail,
    multiplier: f64 = 1.0,
    factor: f64 = 1.0,
    max_duration_us: i64 = 7 * 86_400 * lease.micros_per_second,
    jitter_us: i64 = 0,

    pub fn validate(self: Policy) Error!void {
        if (!std.math.isFinite(self.multiplier) or self.multiplier <= 0 or !std.math.isFinite(self.factor) or self.factor < 0 or
            self.max_duration_us <= 0 or @mod(self.max_duration_us, lease.micros_per_second) != 0 or
            self.jitter_us < 0 or self.jitter_us > self.max_duration_us or @mod(self.jitter_us, lease.micros_per_second) != 0)
            return error.InvalidEscalationPolicy;
    }

    pub fn encode(self: Policy) Error![encoded_bytes]u8 {
        try self.validate();
        var bytes = [_]u8{0} ** encoded_bytes;
        @memcpy(bytes[0..4], "F2ES");
        bytes[4] = 1;
        bytes[5] = @intFromBool(self.enabled);
        bytes[6] = @intFromEnum(self.formula);
        bytes[7] = @intFromEnum(self.scope);
        std.mem.writeInt(u64, bytes[8..16], @bitCast(self.multiplier), .little);
        std.mem.writeInt(u64, bytes[16..24], @bitCast(self.factor), .little);
        std.mem.writeInt(i64, bytes[24..32], self.max_duration_us, .little);
        std.mem.writeInt(i64, bytes[32..40], self.jitter_us, .little);
        return bytes;
    }

    pub fn decode(bytes: []const u8) Error!Policy {
        if (bytes.len != encoded_bytes or !std.mem.eql(u8, bytes[0..4], "F2ES") or bytes[4] != 1 or bytes[5] > 1) return error.InvalidEscalationPolicy;
        const result = Policy{
            .enabled = bytes[5] == 1,
            .formula = std.meta.intToEnum(Formula, bytes[6]) catch return error.InvalidEscalationPolicy,
            .scope = std.meta.intToEnum(Scope, bytes[7]) catch return error.InvalidEscalationPolicy,
            .multiplier = @bitCast(std.mem.readInt(u64, bytes[8..16], .little)),
            .factor = @bitCast(std.mem.readInt(u64, bytes[16..24], .little)),
            .max_duration_us = std.mem.readInt(i64, bytes[24..32], .little),
            .jitter_us = std.mem.readInt(i64, bytes[32..40], .little),
        };
        try result.validate();
        return result;
    }

    /// `prior_confirmed=0` is the first ban and consumes no random sample.
    /// Later calls accept a caller-sampled whole-second jitter in `[0,jitter]`.
    pub fn duration(self: Policy, base: lease.Duration, prior_confirmed: u64, sampled_jitter_us: i64) Error!lease.Duration {
        try self.validate();
        if (!self.enabled) {
            if (sampled_jitter_us != 0) return error.InvalidEscalationInput;
            return base;
        }
        const base_us = switch (base) {
            .finite_us => |value| value,
            .permanent => return error.InvalidEscalationPolicy,
        };
        if (base_us <= 0 or @mod(base_us, lease.micros_per_second) != 0 or sampled_jitter_us < 0 or sampled_jitter_us > self.jitter_us or @mod(sampled_jitter_us, lease.micros_per_second) != 0) return error.InvalidEscalationInput;
        if (prior_confirmed == 0) {
            if (sampled_jitter_us != 0) return error.InvalidEscalationInput;
            return .{ .finite_us = base_us };
        }
        const base_seconds: f64 = @floatFromInt(@divExact(base_us, lease.micros_per_second));
        const n: f64 = @floatFromInt(prior_confirmed);
        const evaluated = switch (self.formula) {
            .linear => base_seconds * self.multiplier * (1.0 + self.factor * n),
            .exponential => base_seconds * self.multiplier * std.math.pow(f64, self.factor, n),
        };
        const cap_seconds: f64 = @floatFromInt(@divExact(self.max_duration_us, lease.micros_per_second));
        var formula_us: i64 = undefined;
        if (!std.math.isFinite(evaluated) or evaluated >= cap_seconds) {
            formula_us = self.max_duration_us;
        } else {
            const floored = @max(@as(f64, 1.0), @floor(evaluated));
            const seconds = std.math.lossyCast(i64, floored);
            formula_us = std.math.mul(i64, seconds, lease.micros_per_second) catch self.max_duration_us;
        }
        const with_jitter = std.math.add(i64, formula_us, sampled_jitter_us) catch self.max_duration_us;
        return .{ .finite_us = @min(with_jitter, self.max_duration_us) };
    }
};

pub const HistoryInput = struct { prior_confirmed: u64 = 0, latest_confirmed_us: ?i64 = null };

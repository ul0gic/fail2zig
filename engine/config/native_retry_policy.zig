// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const config = @import("native.zig");
const retry = @import("../core/native_retry.zig");

pub fn fromJail(jail: *const config.JailConfig, defaults: config.JailDefaults, max_subjects: u32) !retry.Policy {
    const effective = config.resolveJailFromConfig(jail, defaults);
    // Check the frozen native range before narrowing and before the caller opens
    // or mutates durable state. Values above 128 remain an explicit supported-
    // range refusal rather than a larger transient allocation.
    if (effective.maxretry == 0 or effective.maxretry > retry.max_attempts) return error.InvalidRetryPolicy;
    const value = retry.Policy{
        .maxretry = @intCast(effective.maxretry),
        .window_us = try micros(effective.findtime),
        .duration = switch (effective.bantime_kind) {
            .finite => .{ .finite_us = try micros(effective.bantime) },
            .permanent => .permanent,
        },
        .max_subjects = max_subjects,
        .enforce = effective.banaction != .@"log-only",
        .escalation = .{
            .enabled = effective.bantime_increment.enabled,
            .formula = switch (effective.bantime_increment.formula) {
                .linear => .linear,
                .exponential => .exponential,
            },
            .scope = switch (effective.bantime_increment.scope) {
                .per_jail => .per_jail,
                .overall => .overall,
            },
            .multiplier = effective.bantime_increment.multiplier,
            .factor = effective.bantime_increment.factor,
            .max_duration_us = try micros(effective.bantime_increment.max_bantime),
            .jitter_us = try micros(effective.bantime_increment.jitter),
        },
    };
    try value.validate();
    return value;
}
fn micros(seconds: u64) !i64 {
    return std.math.mul(i64, std.math.cast(i64, seconds) orelse return error.InvalidRetryPolicy, 1_000_000) catch error.InvalidRetryPolicy;
}

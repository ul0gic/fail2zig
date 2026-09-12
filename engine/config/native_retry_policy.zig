// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const config = @import("native.zig");
const retry = @import("../core/native_retry.zig");

pub fn fromJail(jail: *const config.JailConfig, defaults: config.JailDefaults, max_subjects: u32) !retry.Policy {
    const effective = config.resolveJailFromConfig(jail, defaults);
    // Constant finite duration is the first integrated policy. Never silently
    // downgrade an enabled escalation policy while its durable consumer is absent.
    if (effective.bantime_increment.enabled) return error.NativeEscalationRequired;
    const value = retry.Policy{
        .maxretry = std.math.cast(u16, effective.maxretry) orelse return error.InvalidRetryPolicy,
        .window_us = try micros(effective.findtime),
        .bantime_us = try micros(effective.bantime),
        .max_subjects = max_subjects,
        .enforce = effective.banaction != .@"log-only",
    };
    try value.validate();
    return value;
}
fn micros(seconds: u64) !i64 {
    return std.math.mul(i64, std.math.cast(i64, seconds) orelse return error.InvalidRetryPolicy, 1_000_000) catch error.InvalidRetryPolicy;
}

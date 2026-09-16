// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");

var runtime_level = std.atomic.Value(u8).init(@intFromEnum(std.log.Level.info));

pub fn set(level: std.log.Level) void {
    runtime_level.store(@intFromEnum(level), .monotonic);
}

pub fn enabled(level: std.log.Level) bool {
    return @intFromEnum(level) <= runtime_level.load(.monotonic);
}

pub fn current() std.log.Level {
    return @enumFromInt(runtime_level.load(.monotonic));
}

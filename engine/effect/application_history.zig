// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const effect_history = @import("effect_history.zig");

pub const version: u16 = 1;
pub const max_page: usize = 64;
pub const max_details: usize = 262_144;
pub const Error = error{ InvalidApplicationHistoryQuery, InvalidApplicationHistoryRow, InvalidPolicySummary, StalePolicySummary };

pub const Detail = struct {
    source: []u8,
    occurrence: []u8,
    decided_us: i64,
    ordinal: u64,
    evidence: ?[]u8 = null,

    pub fn deinit(self: *Detail, allocator: std.mem.Allocator) void {
        allocator.free(self.source);
        allocator.free(self.occurrence);
        if (self.evidence) |value| allocator.free(value);
        self.* = undefined;
    }
};

pub const Event = struct {
    confirmed: effect_history.Event,
    detail: ?Detail = null,

    pub fn deinit(self: *Event, allocator: std.mem.Allocator) void {
        if (self.detail) |*value| value.deinit(allocator);
        self.* = undefined;
    }
};

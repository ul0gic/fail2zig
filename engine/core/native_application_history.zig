// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const detection = @import("native_detection_record.zig");
const effect_history = @import("native_effect_history.zig");
const retry = @import("native_retry.zig");

pub const version: u16 = 1;
pub const max_page: usize = 64;
pub const max_details: usize = 65_536;
pub const Error = error{ InvalidApplicationHistoryQuery, InvalidApplicationHistoryRow, InvalidPolicySummary, StalePolicySummary };

pub const TimeRange = struct {
    from_us: ?i64 = null,
    to_us: ?i64 = null,

    pub fn validate(self: TimeRange) Error!void {
        if (self.from_us != null and self.to_us != null and self.from_us.? >= self.to_us.?) return error.InvalidApplicationHistoryQuery;
    }
};

pub const EventQuery = struct {
    after_sequence: u64 = 0,
    expected_stream_revision: ?u64 = null,
    jail: ?[]const u8 = null,
    range: TimeRange = .{},

    pub fn validate(self: EventQuery) Error!void {
        if (self.after_sequence > std.math.maxInt(i64) or (self.expected_stream_revision != null and (self.expected_stream_revision.? == 0 or self.expected_stream_revision.? > std.math.maxInt(i64)))) return error.InvalidApplicationHistoryQuery;
        try self.range.validate();
        if (self.jail) |jail| _ = detection.Name.init(jail) catch return error.InvalidApplicationHistoryQuery;
    }
};

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

pub const EventPage = struct {
    format_version: u16 = version,
    stream_revision: u64,
    head_sequence: u64,
    last_sequence: u64,
    count: usize,
    more: bool,
};

pub const Aggregate = struct {
    jail: ?detection.Name,
    confirmed: u64,
    first_confirmed_us: ?i64,
    latest_confirmed_us: ?i64,
};
pub const AggregateQuery = struct {
    expected_stream_revision: ?u64 = null,
    jail: ?[]const u8 = null,
    range: TimeRange = .{},

    pub fn validate(self: AggregateQuery) Error!void {
        if (self.expected_stream_revision != null and (self.expected_stream_revision.? == 0 or self.expected_stream_revision.? > std.math.maxInt(i64))) return error.InvalidApplicationHistoryQuery;
        try self.range.validate();
        if (self.jail) |jail| _ = detection.Name.init(jail) catch return error.InvalidApplicationHistoryQuery;
    }
};
pub const AggregatePage = struct { format_version: u16 = version, stream_revision: u64, head_sequence: u64, count: usize, more: bool };

pub const PolicyCursor = struct { jail: detection.Name, subject: detection.Subject };
pub const PolicyQuery = struct {
    jail: ?[]const u8 = null,
    after: ?PolicyCursor = null,
    expected_revision: ?u64 = null,

    pub fn validate(self: PolicyQuery) Error!void {
        if (self.jail) |jail| _ = detection.Name.init(jail) catch return error.InvalidPolicySummary;
        if (self.expected_revision != null and (self.expected_revision.? == 0 or self.expected_revision.? > std.math.maxInt(i64))) return error.InvalidPolicySummary;
        if (self.after) |cursor| {
            const canonical = detection.Name.init(cursor.jail.slice()) catch return error.InvalidPolicySummary;
            if (!std.mem.eql(u8, &canonical.bytes, &cursor.jail.bytes)) return error.InvalidPolicySummary;
            cursor.subject.validate() catch return error.InvalidPolicySummary;
            if (cursor.subject.unenforceable()) return error.InvalidPolicySummary;
            if (self.jail) |jail| if (!std.mem.eql(u8, jail, cursor.jail.slice())) return error.InvalidPolicySummary;
        }
    }
};
pub const PolicySummary = struct {
    jail: detection.Name,
    subject: detection.Subject,
    generation: [32]u8,
    last_processed_us: i64,
    lease: retry.Lease,
    decisions: u64,
    retired: bool,
};
pub const PolicyPage = struct { format_version: u16 = version, revision: u64, count: usize, more: bool };

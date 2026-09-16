// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

pub const Predecoded = struct {
    text: []const u8,
    codec: []const u8,
    disposition: []const u8,
    diagnostic: ?[]const u8,
    warning_due: bool,
    codec_context_json: []const u8,
    profile_hash: []const u8,
    config_generation: []const u8,
    configuration_hash: [32]u8,
    checkpoint_hash: [32]u8,
    raw_hash: [32]u8,
};
pub const Framed = struct { consumed: usize, decoded: Predecoded };
pub const FrameCallback = *const fn ([]const u8, []const u8, bool, @import("std").mem.Allocator, ?*anyopaque) anyerror!?Framed;

pub const JournalField = struct { name: []const u8, value: []const u8 };

pub const Record = struct {
    kind: enum { data, checkpoint } = .data,
    source: []const u8,
    source_path: ?[]const u8 = null,
    occurrence: []const u8,
    cursor: []const u8,
    message: []const u8,
    raw_hash: [32]u8,
    predecoded: ?Predecoded = null,
    timestamp_us: ?u64 = null,
    receipt_time: ?@import("native_time.zig").Timestamp = null,
    journal_fields: ?[]const JournalField = null,
    journal_monotonic_us: ?u64 = null,
    byte_start: ?u64 = null,
    byte_end: ?u64 = null,
};

pub const AckCallback = *const fn (Record, ?*anyopaque) anyerror!void;
pub const Health = enum {
    waiting,
    healthy,
    missing,
    permission_denied,
    read_failed,
    resume_lost,
    record_too_long,
    malformed_record,
    commit_failed,
    child_failed,
    clock_failed,
};

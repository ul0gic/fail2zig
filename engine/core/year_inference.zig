// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const time = @import("native_time.zig");
const timezone = @import("native_timezone.zig");
const provenance = @import("native_time_record.zig");
pub const version: u16 = 1;
pub const Inferred = struct { timestamp: time.Timestamp, year: u16 };
pub const Zoned = struct { timestamp: time.Timestamp, year: u16, zone: provenance.Provenance };

pub fn inferZoned(field: []const u8, receipt: time.Timestamp, zone: *const timezone.Zone) !Zoned {
    const receipt_offset = try zone.utcOffsetAt(@divFloor(receipt.us, 1_000_000));
    const local_receipt = std.math.cast(i64, @as(i128, receipt.us) + @as(i128, receipt_offset) * 1_000_000) orelse return error.TimeOutOfRange;
    const reference = try receiptYear(.{ .us = local_receipt }, 0);
    _ = try time.parse(.syslog, field, .{ .year = 2000, .offset_seconds = 0 });
    var minimum: i32 = std.math.maxInt(i32);
    var maximum: i32 = std.math.minInt(i32);
    for (zone.types) |kind| if (!kind.unspecified) {
        minimum = @min(minimum, kind.offset_seconds);
        maximum = @max(maximum, kind.offset_seconds);
    };
    if (minimum > maximum) return error.OutsideTimezoneCoverage;
    var best: ?Zoned = null;
    var distance: u128 = std.math.maxInt(u128);
    var uncertain_distance: u128 = std.math.maxInt(u128);
    var uncertain: ?anyerror = null;
    var tied = false;
    const first = if (reference > 1) reference - 1 else reference;
    const last = if (reference < 9999) reference + 1 else reference;
    for (first..@as(usize, last) + 1) |year| {
        const local = time.parse(.syslog, field, .{ .year = @intCast(year), .offset_seconds = 0 }) catch |err| switch (err) {
            error.InvalidTimestamp => continue,
            else => return err,
        };
        const selected = zone.resolveLocalMicros(local.us) catch |err| {
            const earliest = @as(i128, local.us) - @as(i128, maximum) * 1_000_000;
            const latest = @as(i128, local.us) - @as(i128, minimum) * 1_000_000;
            const possible_distance: u128 = if (receipt.us < earliest) @intCast(earliest - receipt.us) else if (receipt.us > latest) @intCast(@as(i128, receipt.us) - latest) else 0;
            if (possible_distance < uncertain_distance) {
                uncertain_distance = possible_distance;
                uncertain = err;
            }
            continue;
        };
        const delta = @abs(@as(i128, selected.utc_us) - receipt.us);
        if (delta < distance) {
            best = .{ .timestamp = .{ .us = selected.utc_us }, .year = @intCast(year), .zone = .{
                .zone_digest = selected.provenance.zone_digest,
                .offset_seconds = selected.provenance.offset_seconds,
                .ambiguity = selected.provenance.ambiguity,
                .fold_selected = selected.provenance.fold_selected,
            } };
            distance = delta;
            tied = false;
        } else if (delta == distance) tied = true;
    }
    if (uncertain_distance <= distance) if (uncertain) |failure| return failure;
    if (tied) return error.AmbiguousYear;
    return best orelse error.InvalidTimestamp;
}

pub fn receiptYear(receipt: time.Timestamp, offset_seconds: i32) !u16 {
    if (offset_seconds < -86340 or offset_seconds > 86340 or @mod(offset_seconds, 60) != 0) return error.InvalidTimeContext;
    const local = @as(i128, receipt.us) + @as(i128, offset_seconds) * 1_000_000;
    if (local < -62135596800000000 or local > 253402300799999999) return error.TimeOutOfRange;
    var low: u16 = 1;
    var high: u16 = 9999;
    while (low < high) {
        const middle = low + (high - low + 1) / 2;
        const start = try time.parse(.syslog, "Jan  1 00:00:00", .{ .year = middle, .offset_seconds = 0 });
        if (start.us <= local) low = middle else high = middle - 1;
    }
    return low;
}

pub fn infer(field: []const u8, receipt: time.Timestamp, offset_seconds: i32) !Inferred {
    const reference = try receiptYear(receipt, offset_seconds);
    _ = try time.parse(.syslog, field, .{ .year = 2000, .offset_seconds = offset_seconds });
    var best: ?Inferred = null;
    var distance: u128 = std.math.maxInt(u128);
    var tied = false;
    const first = if (reference > 1) reference - 1 else reference;
    const last = if (reference < 9999) reference + 1 else reference;
    var year = first;
    while (true) {
        const candidate: ?time.Timestamp = time.parse(.syslog, field, .{ .year = year, .offset_seconds = offset_seconds }) catch |err| switch (err) {
            error.InvalidTimestamp => null,
            else => return err,
        };
        if (candidate) |timestamp| {
            const delta = @abs(@as(i128, timestamp.us) - receipt.us);
            if (delta < distance) {
                best = .{ .timestamp = timestamp, .year = year };
                distance = delta;
                tied = false;
            } else if (delta == distance) tied = true;
        }
        if (year == last) break;
        year += 1;
    }
    if (tied) return error.AmbiguousYear;
    return best orelse error.InvalidTimestamp;
}

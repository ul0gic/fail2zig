// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Closed native time outcome stored as typed SQLite columns, never float bits.
const time = @import("native_time.zig");
const policy = @import("source_time_policy.zig");
const std = @import("std");
pub const Kind = enum(u8) { eligible_event = 1, eligible_receipt, eligible_adjusted, obsolete_event, obsolete_receipt, obsolete_adjusted, missing, malformed, range, precision, future };
pub const Stored = struct {
    kind: Kind,
    original_us: ?i64 = null,
    effective_us: ?i64 = null,
    inferred_year: ?u16 = null,

    pub fn fromOutcome(result: policy.Result, receipt: time.Timestamp) !Stored {
        const stored: Stored = switch (result) {
            .eligible, .obsolete => |e| blk: {
                if (e.receipt.us != receipt.us) return error.InvalidNativeTime;
                const kind: Kind = if (result == .eligible) switch (e.origin) {
                    .event => .eligible_event,
                    .receipt => .eligible_receipt,
                    .clock_adjusted => .eligible_adjusted,
                } else switch (e.origin) {
                    .event => .obsolete_event,
                    .receipt => .obsolete_receipt,
                    .clock_adjusted => .obsolete_adjusted,
                };
                break :blk .{ .kind = kind, .original_us = if (e.original) |original| original.us else null, .effective_us = e.timestamp.us, .inferred_year = e.inferred_year };
            },
            .rejected => |r| blk: {
                if (r.receipt) |observed| if (observed.us != receipt.us) return error.InvalidNativeTime;
                break :blk .{ .kind = switch (r.reason) {
                    .missing => .missing,
                    .malformed => .malformed,
                    .out_of_range => .range,
                    .unsupported_precision => .precision,
                    .future => .future,
                }, .original_us = if (r.original) |original| original.us else null, .inferred_year = r.inferred_year };
            },
        };
        _ = try stored.outcome(receipt);
        return stored;
    }
    pub fn outcome(self: Stored, receipt: time.Timestamp) !policy.Result {
        if (self.inferred_year) |year| {
            if (year == 0 or year > 9999 or self.original_us == null) return error.InvalidNativeTime;
        }
        switch (self.kind) {
            .eligible_event, .eligible_receipt, .eligible_adjusted, .obsolete_event, .obsolete_receipt, .obsolete_adjusted => {
                const effective = self.effective_us orelse return error.InvalidNativeTime;
                const origin: policy.Origin = switch (self.kind) {
                    .eligible_event, .obsolete_event => .event,
                    .eligible_receipt, .obsolete_receipt => .receipt,
                    else => .clock_adjusted,
                };
                switch (origin) {
                    .event => if (self.original_us == null or self.original_us.? != effective or effective > receipt.us) return error.InvalidNativeTime,
                    .receipt => if (self.original_us != null or effective != receipt.us) return error.InvalidNativeTime,
                    .clock_adjusted => {
                        const original = self.original_us orelse return error.InvalidNativeTime;
                        const ahead = @as(i128, original) - receipt.us;
                        if (effective != receipt.us or ahead <= 0 or ahead > policy.future_tolerance_us) return error.InvalidNativeTime;
                    },
                }
                const evidence = policy.Evidence{ .timestamp = .{ .us = effective }, .origin = origin, .original = if (self.original_us) |v| .{ .us = v } else null, .receipt = receipt, .inferred_year = self.inferred_year };
                return if (@intFromEnum(self.kind) <= @intFromEnum(Kind.eligible_adjusted)) .{ .eligible = evidence } else .{ .obsolete = evidence };
            },
            else => {
                if (self.effective_us != null) return error.InvalidNativeTime;
                if (self.kind == .future) {
                    const original = self.original_us orelse return error.InvalidNativeTime;
                    if (@as(i128, original) - receipt.us <= policy.future_tolerance_us) return error.InvalidNativeTime;
                } else if (self.original_us != null) return error.InvalidNativeTime;
                return .{ .rejected = .{ .reason = switch (self.kind) {
                    .missing => .missing,
                    .malformed => .malformed,
                    .range => .out_of_range,
                    .precision => .unsupported_precision,
                    .future => .future,
                    else => unreachable,
                }, .original = if (self.original_us) |v| .{ .us = v } else null, .receipt = receipt, .inferred_year = self.inferred_year } };
            },
        }
    }
};

test "native processor: typed time rows reject inconsistent provenance" {
    const receipt = time.Timestamp{ .us = 9_007_199_254_740_993 };
    const adjusted = try policy.evaluate(.timestamped, .{ .parsed = .{ .us = receipt.us + 60_000_000 } }, receipt, receipt, 600_000_000);
    const stored = try Stored.fromOutcome(adjusted, receipt);
    try std.testing.expectEqualDeep(adjusted, try stored.outcome(receipt));
    var invalid = stored;
    invalid.effective_us = receipt.us + 1;
    try std.testing.expectError(error.InvalidNativeTime, invalid.outcome(receipt));
    invalid = stored;
    invalid.kind = .future;
    invalid.effective_us = null;
    try std.testing.expectError(error.InvalidNativeTime, invalid.outcome(receipt));
    invalid.kind = .missing;
    try std.testing.expectError(error.InvalidNativeTime, invalid.outcome(receipt));
    const oldest = Stored{ .kind = .obsolete_event, .original_us = std.math.minInt(i64), .effective_us = std.math.minInt(i64) };
    try std.testing.expectEqual(@as(i64, std.math.minInt(i64)), (try oldest.outcome(receipt)).obsolete.timestamp.us);
}

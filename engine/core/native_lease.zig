// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Canonical N3 relative durations, absolute leases and monotonic scheduling.
//! Imported unknown values are inspection data and can never become authority.
const std = @import("std");

pub const micros_per_second: i64 = 1_000_000;
pub const max_finite_seconds: u64 = @intCast(@divTrunc(std.math.maxInt(i64), micros_per_second));
pub const Error = error{
    InvalidDuration,
    ImportedDurationUnknown,
    LeaseExpired,
    TimeOverflow,
    ClockReversed,
};

/// Relative policy duration in microseconds. Native configuration constructs
/// whole seconds through finiteSeconds; deterministic component policies may
/// use finer values without performing expiry-time rounding.
pub const Duration = union(enum) {
    finite_us: i64,
    permanent,

    pub fn finiteSeconds(seconds: u64) Error!Duration {
        if (seconds == 0 or seconds > max_finite_seconds) return error.InvalidDuration;
        const narrowed = std.math.cast(i64, seconds) orelse return error.InvalidDuration;
        return .{ .finite_us = std.math.mul(i64, narrowed, micros_per_second) catch return error.TimeOverflow };
    }

    pub fn validate(self: Duration) Error!void {
        switch (self) {
            .finite_us => |value| if (value <= 0) return error.InvalidDuration,
            .permanent => {},
        }
    }

    pub fn lease(self: Duration, decided_us: i64) Error!Lease {
        try self.validate();
        return switch (self) {
            .finite_us => |value| .{ .finite = std.math.add(i64, decided_us, value) catch return error.TimeOverflow },
            .permanent => .permanent,
        };
    }
};

/// Migration-only interpretation of the pinned foreign sentinels. Unknown is
/// deliberately absent from Duration and Lease, so activation must fail.
pub const ImportedDuration = union(enum) {
    finite: Duration,
    permanent,
    imported_unknown,

    pub fn fromSeconds(value: i64) Error!ImportedDuration {
        return switch (value) {
            -1 => .permanent,
            -2 => .imported_unknown,
            1...std.math.maxInt(i64) => .{ .finite = try Duration.finiteSeconds(@intCast(value)) },
            else => error.InvalidDuration,
        };
    }

    pub fn activate(self: ImportedDuration) Error!Duration {
        return switch (self) {
            .finite => |value| value,
            .permanent => .permanent,
            .imported_unknown => error.ImportedDurationUnknown,
        };
    }
};

/// Absolute durable authority. Finite leases are live strictly before their
/// deadline and expire at equality; permanent leases have no deadline.
pub const Lease = union(enum(u8)) {
    absent = 0,
    finite: i64 = 1,
    permanent = 2,

    pub fn live(self: Lease, now_us: i64) bool {
        return switch (self) {
            .absent => false,
            .finite => |until| now_us < until,
            .permanent => true,
        };
    }

    pub fn eql(a: Lease, b: Lease) bool {
        return std.meta.eql(a, b);
    }

    /// Explicit prolongation never shortens protection. Expired/absent leases
    /// require a distinct reban decision rather than revival through this API.
    pub fn prolonged(self: Lease, requested: Lease, now_us: i64) Error!struct { lease: Lease, changed: bool } {
        if (self == .absent or requested == .absent) return error.InvalidDuration;
        if (!self.live(now_us)) return error.LeaseExpired;
        return switch (self) {
            .absent => unreachable,
            .permanent => .{ .lease = .permanent, .changed = false },
            .finite => |current| switch (requested) {
                .absent => unreachable,
                .permanent => .{ .lease = .permanent, .changed = true },
                .finite => |candidate| if (candidate > current)
                    .{ .lease = .{ .finite = candidate }, .changed = true }
                else
                    .{ .lease = self, .changed = false },
            },
        };
    }
};

pub const ClockSample = struct {
    wall_us: i64,
    monotonic_us: u64,
};

/// Process-local wake authority derived from a durable absolute lease. Forward
/// wall steps do not shorten the admitted elapsed lifetime; backward wall or
/// monotonic samples fail the fence before destructive expiry.
pub const Schedule = union(enum) {
    none,
    due_at_us: u64,

    pub fn fromLease(lease: Lease, sample: ClockSample) Error!Schedule {
        return switch (lease) {
            .absent => error.InvalidDuration,
            .permanent => .none,
            .finite => |deadline| if (deadline <= sample.wall_us)
                .{ .due_at_us = sample.monotonic_us }
            else blk: {
                const remaining: u64 = @intCast(@as(i128, deadline) - sample.wall_us);
                break :blk .{ .due_at_us = std.math.add(u64, sample.monotonic_us, remaining) catch return error.TimeOverflow };
            },
        };
    }

    pub fn due(self: Schedule, monotonic_us: u64) bool {
        return switch (self) {
            .none => false,
            .due_at_us => |deadline| monotonic_us >= deadline,
        };
    }
};

pub const ClockFence = struct {
    wall_us: i64,
    monotonic_us: u64,

    pub fn advance(self: *ClockFence, sample: ClockSample) Error!void {
        if (sample.wall_us < self.wall_us or sample.monotonic_us < self.monotonic_us) return error.ClockReversed;
        self.* = .{ .wall_us = sample.wall_us, .monotonic_us = sample.monotonic_us };
    }
};

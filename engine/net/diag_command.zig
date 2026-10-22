// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const shared = @import("shared");
const clock_mod = @import("../core/clock.zig");

const Request = struct {
    op: enum { show, rate, advance },
    rate: ?u32 = null,
    us: ?u64 = null,
};

pub fn handle(clock: *clock_mod.VirtualClock, effects_live: bool, installed_live: u32, body: []const u8, a: std.mem.Allocator) !shared.Response {
    const parsed = std.json.parseFromSlice(Request, a, body, .{}) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return refuse(a, 400, "invalid diag request: {s}", .{@errorName(err)}),
    };
    defer parsed.deinit();
    const request = parsed.value;
    switch (request.op) {
        .show => {},
        .rate => {
            const next = request.rate orelse return refuse(a, 400, "rate requires an integer 0..{d}", .{clock_mod.VirtualClock.max_rate});
            if (next > clock_mod.VirtualClock.max_rate) return refuse(a, 400, "rate {d} out of range 0..{d}", .{ next, clock_mod.VirtualClock.max_rate });
            if (next != clock.rate()) {
                if (next == 0 and effects_live) return refuse(a, 409, "step mode refused: a kernel enforcement backend is active; step mode needs log-only jails", .{});
                if (installed_live != 0) return refuse(a, 409, "rate change refused: {d} kernel elements installed; retry after they expire", .{installed_live});
                clock.setRate(next) catch return refuse(a, 400, "rate {d} out of range 0..{d}", .{ next, clock_mod.VirtualClock.max_rate });
            }
        },
        .advance => {
            const us = request.us orelse return refuse(a, 400, "advance requires us in 1..{d}", .{clock_mod.VirtualClock.max_advance_us});
            clock.advance(us) catch |err| switch (err) {
                error.NotStepMode => return refuse(a, 409, "advance refused: the clock is not in step mode (rate 0)", .{}),
                error.OutOfRange => return refuse(a, 400, "advance {d} us out of range 1..{d}", .{ us, clock_mod.VirtualClock.max_advance_us }),
            };
        },
    }
    var out: std.ArrayListUnmanaged(u8) = .{};
    errdefer out.deinit(a);
    try std.json.stringify(clock.snapshot(), .{}, out.writer(a));
    return .{ .ok = .{ .payload = try out.toOwnedSlice(a) } };
}

fn refuse(a: std.mem.Allocator, code: u16, comptime fmt: []const u8, args: anytype) !shared.Response {
    return .{ .err = .{ .code = code, .message = try std.fmt.allocPrint(a, fmt, args) } };
}

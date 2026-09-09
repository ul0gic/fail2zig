// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const builtin = @import("builtin");

const shared = @import("shared");
const engine = @import("engine");

const harness_mod = @import("harness.zig");
const Harness = harness_mod.Harness;

const testing = std.testing;

fn bringUp(allocator: std.mem.Allocator) !Harness {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (std.os.linux.geteuid() != 0) return error.SkipZigTest;

    var h = try Harness.init(allocator, .{
        .jail = .{
            .name = "sshd",
            .filter = "sshd",
            .maxretry = 3,
            .findtime = 600,
            .bantime = 60,
        },
    });
    errdefer h.deinit();

    h.writeConfig() catch return error.SkipZigTest;
    h.startDaemon() catch |err| switch (err) {
        error.DaemonBinaryMissing, error.DaemonUnavailable, error.DaemonFailedToStart, error.SocketNeverAppeared => return error.SkipZigTest,
        else => return err,
    };

    return h;
}

test "integration: ssh brute force ban round-trip" {
    var h = bringUp(testing.allocator) catch |err| switch (err) {
        error.SkipZigTest => return error.SkipZigTest,
        else => return err,
    };
    defer h.deinit();

    const attacker = try shared.IpAddress.parse("203.0.113.42");

    const lines = [_][]const u8{
        "Failed password for root from 203.0.113.42 port 43210 ssh2",
        "Failed password for root from 203.0.113.42 port 43211 ssh2",
        "Failed password for root from 203.0.113.42 port 43212 ssh2",
    };
    for (lines) |ln| try h.writeLine(ln);

    try h.waitForBan(attacker, 2_000);

    const status = try h.queryStatus();
    defer testing.allocator.free(status);
    const bans_field = harness_mod.parseJsonUintField(status, "active_bans") orelse 0;
    try testing.expectEqual(@as(u32, 1), bans_field);

    try testing.expect(try h.queryListContains(attacker));

    const unban_reply = try h.unban(attacker);
    testing.allocator.free(unban_reply);

    var cleared = false;
    var attempts: u32 = 0;
    while (attempts < 40) : (attempts += 1) {
        const st = h.queryStatus() catch break;
        defer testing.allocator.free(st);
        if ((harness_mod.parseJsonUintField(st, "active_bans") orelse 1) == 0) {
            cleared = true;
            break;
        }
        std.time.sleep(25 * std.time.ns_per_ms);
    }
    try testing.expect(cleared);
    try testing.expect(!(try h.queryListContains(attacker)));
}

test "integration: ban ignores lines below maxretry" {
    var h = bringUp(testing.allocator) catch |err| switch (err) {
        error.SkipZigTest => return error.SkipZigTest,
        else => return err,
    };
    defer h.deinit();

    const attacker = try shared.IpAddress.parse("198.51.100.9");

    try h.writeLine("Failed password for root from 198.51.100.9 port 1 ssh2");
    try h.writeLine("Failed password for root from 198.51.100.9 port 2 ssh2");

    std.time.sleep(500 * std.time.ns_per_ms);

    const status = try h.queryStatus();
    defer testing.allocator.free(status);
    try testing.expectEqual(
        @as(u32, 0),
        harness_mod.parseJsonUintField(status, "active_bans") orelse 0,
    );
    try testing.expect(!(try h.queryListContains(attacker)));
}

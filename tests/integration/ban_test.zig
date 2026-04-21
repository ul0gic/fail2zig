//! End-to-end ban test for the fail2zig daemon.
//!
//! What this test proves (when it runs):
//!
//!   (a) Start the daemon with a single sshd jail, `maxretry=3`,
//!       `findtime=600`, `bantime=60`.
//!   (b) Append 3 failed SSH auth lines referencing the same IP to the
//!       watched log file.
//!   (c) Observe the ban appear within 2 seconds via `/status`.
//!   (d) Observe `active_bans=1` in the status response.
//!   (e) Observe the banned IP in the `/list` response.
//!   (f) Unban via `/unban` client command.
//!   (g) Confirm the IP no longer appears in `/list`, and active_bans
//!       returns to 0.
//!
//! Skip semantics:
//!
//!   * `error.SkipZigTest` if the daemon binary isn't built yet.
//!   * `error.SkipZigTest` if the daemon refuses to start (no firewall
//!     backend — common in unprivileged CI and developer laptops).
//!   * `error.SkipZigTest` if the test process isn't uid 0 (IPC auth
//!     via `SO_PEERCRED` rejects anything but uid 0 / fail2zig group).
//!
//! Running under `sudo zig build test -Dtest-filter=ban_test` with a
//! kernel that supports nftables exercises the whole stack. Everything
//! else cleanly skips.

const std = @import("std");
const builtin = @import("builtin");

const shared = @import("shared");
const engine = @import("engine");

const harness_mod = @import("harness.zig");
const Harness = harness_mod.Harness;

const testing = std.testing;

/// Shared setup for every scenario in this file. Returns a harness with
/// the daemon running and the socket reachable, or a clean skip.
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

    // (b) Write 3 failed SSH auth lines. OpenSSH 8+ format is the one
    // matched by the built-in `failed-password` pattern.
    // Lines are delivered raw to the parser; the built-in sshd pattern
    // anchors the first literal at position 0, so we omit the syslog
    // prefix that a journald pipeline would normally strip.
    const lines = [_][]const u8{
        "Failed password for root from 203.0.113.42 port 43210 ssh2",
        "Failed password for root from 203.0.113.42 port 43211 ssh2",
        "Failed password for root from 203.0.113.42 port 43212 ssh2",
    };
    for (lines) |ln| try h.writeLine(ln);

    // (c) Ban must appear within 2 seconds.
    try h.waitForBan(attacker, 2_000);

    // (d) Status confirms active_bans == 1.
    const status = try h.queryStatus();
    defer testing.allocator.free(status);
    const bans_field = harness_mod.parseJsonUintField(status, "active_bans") orelse 0;
    try testing.expectEqual(@as(u32, 1), bans_field);

    // (e) List confirms the IP is present.
    try testing.expect(try h.queryListContains(attacker));

    // (f) Unban via IPC.
    const unban_reply = try h.unban(attacker);
    testing.allocator.free(unban_reply);

    // (g) Post-unban: verify the IP is gone and active_bans is 0.
    // Small settling delay — the unban also calls the firewall backend
    // which can be slow the first time.
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

    // Write maxretry - 1 = 2 failed attempts. No ban should appear.
    try h.writeLine("Failed password for root from 198.51.100.9 port 1 ssh2");
    try h.writeLine("Failed password for root from 198.51.100.9 port 2 ssh2");

    // Give the daemon a conservative window to process what was written.
    // 500ms is generous — the log watcher is inotify-driven, not polling.
    std.time.sleep(500 * std.time.ns_per_ms);

    const status = try h.queryStatus();
    defer testing.allocator.free(status);
    try testing.expectEqual(
        @as(u32, 0),
        harness_mod.parseJsonUintField(status, "active_bans") orelse 0,
    );
    try testing.expect(!(try h.queryListContains(attacker)));
}

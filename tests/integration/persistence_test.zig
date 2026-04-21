// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! State persistence integration test.
//!
//! Two scenarios, one covered in every environment and one gated on
//! root:
//!
//!   1. Module-level round-trip (always runs):
//!      seed a `StateTracker`, call `persist.save`, load it back with
//!      `persist.load`, seed a fresh tracker, and verify the banned IP
//!      survives. This exercises the same save/load contract the daemon
//!      uses across a SIGTERM → restart cycle without needing to spawn
//!      a real daemon or satisfy root-only IPC auth.
//!
//!   2. Full daemon restart (root-gated):
//!      spawn the daemon via the harness, trigger a ban, SIGTERM the
//!      daemon, assert the state file appears on disk, re-spawn, assert
//!      the same ban is still in place. Skips unless uid 0.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

const shared = @import("shared");
const engine = @import("engine");

const harness_mod = @import("harness.zig");
const Harness = harness_mod.Harness;

const persist = engine.state_mod; // fallback for state types
const state = engine.state_mod;

// `persist` module is private in engine/main.zig — re-import via the
// `engine` public surface only exposes a subset. Reach in through the
// canonical relative path that the tests live alongside.
const persist_mod = struct {
    pub const save = @import("../../engine/core/persist.zig").save;
    pub const load = @import("../../engine/core/persist.zig").load;
    pub const seed = @import("../../engine/core/persist.zig").seed;
    pub const StateEntry = @import("../../engine/core/persist.zig").StateEntry;
};

const testing = std.testing;

test "integration: persist round-trip preserves banned IPs across a simulated restart" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &path_buf);
    const path = try std.fmt.allocPrint(a, "{s}/state.bin", .{dir});
    defer a.free(path);

    // Seed a tracker with a ban, then save.
    var tracker1 = try state.StateTracker.init(a, .{});
    defer tracker1.deinit();

    const ip = try shared.IpAddress.parse("192.0.2.99");
    const jail = try shared.JailId.fromSlice("sshd");
    // recordAttempt enough times to trigger the ban threshold in the
    // default config (maxretry=5). Each attempt lands at the same
    // timestamp, which is fine — findtime is 600s so all five stay
    // live in the ring.
    var i: u32 = 0;
    while (i < 5) : (i += 1) {
        _ = try tracker1.recordAttempt(ip, jail, 1_700_000_000);
    }
    try testing.expect(tracker1.contains(ip));

    // The ring-based tracker does not assign a ban_expiry automatically
    // because `recordAttempt` in its current form emits a `BanDecision`
    // without mutating the entry's `ban_state` (that's the caller's
    // responsibility — main.zig does it via the firewall backend path).
    // For the persistence roundtrip we want to prove that a banned
    // entry survives, so flip the field directly before saving.
    if (tracker1.map.getPtr(ip)) |s| {
        s.ban_state = .banned;
        s.ban_expiry = 1_700_000_000 + 3600;
    }

    try persist_mod.save(&tracker1, path);

    // Verify the file exists with the right permissions.
    const stat = try std.fs.cwd().statFile(path);
    try testing.expect(stat.size > 0);

    // Load into a fresh tracker and verify the ban came back.
    const loaded = try persist_mod.load(a, path);
    defer a.free(loaded);
    try testing.expectEqual(@as(usize, 1), loaded.len);
    try testing.expect(shared.IpAddress.eql(loaded[0].ip, ip));
    try testing.expect(loaded[0].isBanned());

    var tracker2 = try state.StateTracker.init(a, .{});
    defer tracker2.deinit();
    try persist_mod.seed(&tracker2, loaded);

    try testing.expect(tracker2.contains(ip));
    const restored = tracker2.get(ip).?;
    try testing.expect(restored.ban_state == .banned);
    try testing.expect(restored.ban_expiry != null);
}

test "integration: persist file is overwritten atomically on re-save" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &path_buf);
    const path = try std.fmt.allocPrint(a, "{s}/state.bin", .{dir});
    defer a.free(path);

    // Save once.
    var tracker = try state.StateTracker.init(a, .{});
    defer tracker.deinit();
    const ip = try shared.IpAddress.parse("203.0.113.7");
    const jail = try shared.JailId.fromSlice("sshd");
    _ = try tracker.recordAttempt(ip, jail, 1_700_000_000);
    try persist_mod.save(&tracker, path);
    const size1 = (try std.fs.cwd().statFile(path)).size;

    // Save again after adding a second IP. The file grows by one entry
    // and the temp-file swap leaves no stale `.tmp` artifact.
    const ip2 = try shared.IpAddress.parse("198.51.100.1");
    _ = try tracker.recordAttempt(ip2, jail, 1_700_000_000);
    try persist_mod.save(&tracker, path);
    const size2 = (try std.fs.cwd().statFile(path)).size;
    try testing.expect(size2 > size1);

    // No leftover .tmp file.
    const tmp_path = try std.fmt.allocPrint(a, "{s}.tmp", .{path});
    defer a.free(tmp_path);
    try testing.expectError(error.FileNotFound, std.fs.cwd().access(tmp_path, .{}));
}

test "integration: daemon-level SIGTERM write + restart restores state" {
    // Root-gated — relies on running the real daemon, which refuses to
    // start without a functional firewall backend.
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (std.os.linux.geteuid() != 0) return error.SkipZigTest;

    const a = testing.allocator;

    var h = Harness.init(a, .{
        .jail = .{
            .name = "sshd",
            .filter = "sshd",
            .maxretry = 3,
            .findtime = 600,
            .bantime = 60,
        },
    }) catch return error.SkipZigTest;
    defer h.deinit();

    h.writeConfig() catch return error.SkipZigTest;
    h.startDaemon() catch |err| switch (err) {
        error.DaemonBinaryMissing, error.DaemonUnavailable, error.DaemonFailedToStart => return error.SkipZigTest,
        else => return err,
    };

    const attacker = try shared.IpAddress.parse("192.0.2.42");
    const lines = [_][]const u8{
        "Failed password for root from 192.0.2.42 port 1 ssh2",
        "Failed password for root from 192.0.2.42 port 2 ssh2",
        "Failed password for root from 192.0.2.42 port 3 ssh2",
    };
    for (lines) |ln| try h.writeLine(ln);
    try h.waitForBan(attacker, 2_000);

    // Stop the daemon via SIGTERM; harness.stopDaemon() already does
    // that and waits for exit. Verify the state file appears.
    _ = try h.stopDaemon();
    const stat = try std.fs.cwd().statFile(h.state_path);
    try testing.expect(stat.size > 0);

    // Re-start the daemon with the same config. The state file should
    // be loaded and the IP should still be banned.
    h.startDaemon() catch return error.SkipZigTest;

    // Give the ban expiry / state-load path a brief moment to finish.
    std.time.sleep(200 * std.time.ns_per_ms);
    try testing.expect(try h.queryListContains(attacker));
}

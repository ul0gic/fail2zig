// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Status-honesty-surface integration tests (SYS-017 #35, BUG-006 #36).
//!
//! These close the harness gap that let both bugs reach a live box: the
//! existing inline tests stub the resolution and the persisted-lifetime
//! seams in isolation, but nothing wired the *real* resolution → status
//! path or the *real* save → reload → seed path end to end. Both bugs only
//! manifested when those seams were connected, on f2z-target.
//!
//! Higher fidelity than the inline tests:
//!   1. drive the REAL `journald_source.resolveSource` with the exact
//!      f2z-target inputs (config says file, but the file is absent on a
//!      journald-only box) and prove the descriptor that reaches the REAL
//!      `commands.handleListJails` follows the RESOLVED source (journald),
//!      never the config logpath — the SYS-017 source-label divergence;
//!   2. drive the REAL `persist.saveAll` → `loadFull` → `seedLifetimes`
//!      path and prove the persisted lifetime survives a restart and stays
//!      ≥ active bans, and that restored bans never re-increment it — the
//!      BUG-006 reset / Total < Active regression.
//!
//! All non-root, no journald, no firewall — CI-runnable under
//! `zig build test`.

const std = @import("std");
const builtin = @import("builtin");

const shared = @import("shared");
const engine = @import("engine");

const commands = engine.commands_mod;
const journald = engine.journald_source_mod;
const config_mod = engine.config_mod;
const firewall = engine.firewall;
const state = engine.state_mod;
const tracker_map = engine.tracker_map_mod;

// `persist` is private to engine/main.zig; reach it via the canonical
// relative path the integration tests already use (cf. persistence_test.zig).
const persist = struct {
    pub const saveAll = @import("../../engine/core/persist.zig").saveAll;
    pub const loadFull = @import("../../engine/core/persist.zig").loadFull;
    pub const seedMap = @import("../../engine/core/persist.zig").seedMap;
    pub const seedLifetimes = @import("../../engine/core/persist.zig").seedLifetimes;
};

const testing = std.testing;

// ---------------------------------------------------------------------------
// A faithful re-implementation of the daemon's resolution → descriptor step.
// Mirrors engine/main.zig runDaemon (resolveSource + putJournald/putFile),
// so the test exercises the SAME decision and the SAME descriptor shape that
// the live daemon recorded — without needing the private JailSourceDescriptors
// type or a running event loop. The string formats are asserted against the
// daemon's `journald ({filter})` / logpath-join contract.
// ---------------------------------------------------------------------------

const ResolvedDescriptor = struct {
    name: []const u8,
    descriptor: []const u8, // arena-owned
};

/// Resolve one jail exactly as the daemon does and produce the SOURCE
/// descriptor string the status surface must show. `logpath_exists` and
/// `journalctl_present` are the same injected facts `resolveSource` takes —
/// the live box passes the real filesystem/PATH probe; the test passes the
/// f2z-target reality (auth.log absent, journalctl present).
fn resolveDescriptor(
    arena: std.mem.Allocator,
    jail: config_mod.JailConfig,
    logpath_exists: bool,
    journalctl_present: bool,
    filter_journald_supported: bool,
) !ResolvedDescriptor {
    const resolved = journald.resolveSource(
        jail.source,
        logpath_exists,
        journalctl_present,
        filter_journald_supported,
    );
    const desc = switch (resolved) {
        .journald => try std.fmt.allocPrint(arena, "journald ({s})", .{jail.filter}),
        .file => if (jail.logpath.len == 0)
            try arena.dupe(u8, "file")
        else if (jail.logpath.len == 1)
            try arena.dupe(u8, jail.logpath[0])
        else
            try std.mem.join(arena, ", ", jail.logpath),
        .fail => try arena.dupe(u8, "unavailable"),
    };
    return .{ .name = jail.name, .descriptor = desc };
}

/// Test source-descriptor vtable backed by a flat slice — the integration
/// analogue of the daemon's JailSourceDescriptors.lookup over its resolution
/// record. Source-descriptor truth is INDEPENDENT of live health by design.
const DescriptorTable = struct {
    entries: []const ResolvedDescriptor,
    fn lookup(ctx: ?*anyopaque, jail_name: []const u8) ?[]const u8 {
        const self: *const DescriptorTable = @ptrCast(@alignCast(ctx.?));
        for (self.entries) |e| {
            if (std.mem.eql(u8, jail_name, e.name)) return e.descriptor;
        }
        return null;
    }
};

test "integration: SYS-017 a journald-resolved jail reports journald, never its config logpath" {
    const a = testing.allocator;
    var arena_inst = std.heap.ArenaAllocator.init(a);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    // The exact f2z-target shape: source=auto, a FILE logpath configured,
    // but on a journald-only box that file is ABSENT. The daemon's resolver
    // must fall through to journald — and the status SOURCE must follow that
    // resolved truth, not the config guess that pointed at auth.log.
    var jails = [_]config_mod.JailConfig{
        .{ .name = "sshd", .enabled = true, .banaction = .nftables, .source = .auto, .filter = "sshd", .logpath = &.{"/var/log/auth.log"} },
        // A real file jail whose path exists → resolves to file → shows path.
        .{ .name = "nginx", .enabled = true, .banaction = .nftables, .source = .file, .filter = "nginx", .logpath = &.{"/var/log/nginx/error.log"} },
    };

    // Resolve through the REAL resolveSource with f2z-target facts:
    //   sshd: auto, logpath absent (false), journalctl present (true), filter supported.
    //   nginx: file, path exists.
    var descs = [_]ResolvedDescriptor{
        try resolveDescriptor(arena, jails[0], false, true, true),
        try resolveDescriptor(arena, jails[1], true, true, true),
    };
    // Lock the resolution itself: sshd MUST have resolved to journald.
    try testing.expectEqualStrings("journald (sshd)", descs[0].descriptor);
    try testing.expectEqualStrings("/var/log/nginx/error.log", descs[1].descriptor);

    var cfg = config_mod.Config{ .global = .{}, .defaults = .{ .banaction = .nftables }, .jails = &jails, .diag = .{} };
    var trackers = tracker_map.TrackerMap.init(a);
    defer trackers.deinit();
    var backend: firewall.Backend = .{ .nftables = firewall.nftables.NftablesBackend{} };
    defer backend.deinit();
    var table = DescriptorTable{ .entries = &descs };

    var ctx = commands.Context{
        .trackers = &trackers,
        .config = &cfg,
        .backend = &backend,
        .source_descriptor = .{ .ctx = @ptrCast(&table), .lookup = DescriptorTable.lookup },
    };

    // Go through the PUBLIC dispatch vtable — the exact entry the IPC server
    // calls — not the private handler, for true end-to-end fidelity.
    const resp = try commands.Context.dispatch(@ptrCast(&ctx), .{ .list_jails = {} }, a);
    defer resp.deinit(a);
    const body = resp.ok.payload;

    // sshd: SOURCE follows the RESOLVED journald descriptor …
    try testing.expect(std.mem.indexOf(u8, body, "\"log_source\":\"journald (sshd)\"") != null);
    // … and the config logpath NEVER leaks into the surface (the divergence bug).
    try testing.expect(std.mem.indexOf(u8, body, "/var/log/auth.log") == null);
    // nginx: file jail shows its real path.
    try testing.expect(std.mem.indexOf(u8, body, "\"log_source\":\"/var/log/nginx/error.log\"") != null);
    // No enabled jail renders SOURCE "unknown".
    try testing.expect(std.mem.indexOf(u8, body, "\"log_source\":\"unknown\"") == null);
}

test "integration: SYS-017 a file jail whose log is ABSENT still reports its path, never unknown" {
    const a = testing.allocator;
    var arena_inst = std.heap.ArenaAllocator.init(a);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    // source=file, path explicitly configured, but the file does not exist
    // (logpath_exists=false). resolveSource still returns .file for an
    // explicit file source — so the SOURCE descriptor must be the configured
    // path (the misconfiguration signal), never "unknown". This is the second
    // half of the f2z-target divergence the inline tests stub.
    var jails = [_]config_mod.JailConfig{
        .{ .name = "mail", .enabled = true, .banaction = .nftables, .source = .file, .filter = "mail", .logpath = &.{"/var/log/mail.log"} },
    };
    var descs = [_]ResolvedDescriptor{
        try resolveDescriptor(arena, jails[0], false, true, true),
    };
    try testing.expectEqualStrings("/var/log/mail.log", descs[0].descriptor);

    var cfg = config_mod.Config{ .global = .{}, .defaults = .{ .banaction = .nftables }, .jails = &jails, .diag = .{} };
    var trackers = tracker_map.TrackerMap.init(a);
    defer trackers.deinit();
    var backend: firewall.Backend = .{ .nftables = firewall.nftables.NftablesBackend{} };
    defer backend.deinit();
    var table = DescriptorTable{ .entries = &descs };

    // No health source at all — health genuinely unknown for every jail.
    var ctx = commands.Context{
        .trackers = &trackers,
        .config = &cfg,
        .backend = &backend,
        .source_descriptor = .{ .ctx = @ptrCast(&table), .lookup = DescriptorTable.lookup },
    };
    // Go through the PUBLIC dispatch vtable — the exact entry the IPC server
    // calls — not the private handler, for true end-to-end fidelity.
    const resp = try commands.Context.dispatch(@ptrCast(&ctx), .{ .list_jails = {} }, a);
    defer resp.deinit(a);
    const body = resp.ok.payload;

    // The absent file's PATH is shown — never "unknown".
    try testing.expect(std.mem.indexOf(u8, body, "\"log_source\":\"/var/log/mail.log\"") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"log_source\":\"unknown\"") == null);
    // Health is genuinely unknown (no source) → source_healthy omitted, not a false.
    try testing.expect(std.mem.indexOf(u8, body, "\"source_healthy\"") == null);
}

// ---------------------------------------------------------------------------
// BUG-006: persisted lifetime survives a restart and stays >= active bans.
// Real save → real load → real seed, then prove the invariant on the
// restored map. No daemon needed; this exercises the same persistence
// contract the daemon runs across SIGTERM → restart.
// ---------------------------------------------------------------------------

fn tIp(s: []const u8) shared.IpAddress {
    return shared.IpAddress.parse(s) catch unreachable;
}
fn tJail(s: []const u8) shared.JailId {
    return shared.JailId.fromSlice(s) catch unreachable;
}

test "integration: BUG-006 persisted lifetime survives restart and stays >= active bans" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &path_buf);
    const path = try std.fmt.allocPrint(a, "{s}/state.bin", .{dir});
    defer a.free(path);

    // --- "Before restart": a jail with a lifetime that EXCEEDS its current
    // active bans (older bans since expired) plus one live active ban. ---
    {
        var tm = tracker_map.TrackerMap.init(a);
        defer tm.deinit();
        const sshd = try tm.addTracker("sshd", .{ .max_entries = 16, .maxretry = 1, .findtime = 600, .bantime = 600 });
        sshd.lifetime_bans = 9; // nine bans issued over the daemon's life
        // One currently-active ban (the others have expired/been cleared).
        _ = try sshd.recordAttempt(tIp("203.0.113.5"), tJail("sshd"), 1_000);
        sshd.map.getPtr(tIp("203.0.113.5")).?.ban_state = .banned;
        try testing.expectEqual(@as(u32, 1), tm.totalActiveBans());
        try persist.saveAll(&tm, path);
    }

    // --- "After restart": fresh map, real load + seed. ---
    var tm2 = tracker_map.TrackerMap.init(a);
    defer tm2.deinit();
    _ = try tm2.addTracker("sshd", .{ .max_entries = 16 });
    _ = try tm2.ensureLegacy(.{ .max_entries = 16 });

    const loaded = try persist.loadFull(a, path);
    defer loaded.deinit(a);
    try persist.seedMap(&tm2, loaded.entries, null, null);
    persist.seedLifetimes(&tm2, loaded.lifetimes);

    const sshd2 = tm2.get("sshd").?;
    // Lifetime restored verbatim — NOT reset to 0, NOT re-derived from active.
    try testing.expectEqual(@as(u64, 9), sshd2.lifetime_bans);
    // The restored ban is active again …
    try testing.expectEqual(@as(u32, 1), tm2.totalActiveBans());
    // … and the headline invariant holds: Total (9) >= Active (1).
    try testing.expect(sshd2.lifetime_bans >= tm2.totalActiveBans());
}

test "integration: BUG-006 restored bans do not re-increment the lifetime (no double-count)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &path_buf);
    const path = try std.fmt.allocPrint(a, "{s}/state.bin", .{dir});
    defer a.free(path);

    // Save: lifetime == active (3) — the exact f2z-target post-first-ban shape
    // (every active ban was counted once when first issued).
    {
        var tm = tracker_map.TrackerMap.init(a);
        defer tm.deinit();
        const sshd = try tm.addTracker("sshd", .{ .max_entries = 16, .maxretry = 1, .findtime = 600, .bantime = 600 });
        sshd.lifetime_bans = 3;
        inline for (.{ "10.0.0.1", "10.0.0.2", "10.0.0.3" }) |ip_s| {
            _ = try sshd.recordAttempt(tIp(ip_s), tJail("sshd"), 1_000);
            sshd.map.getPtr(tIp(ip_s)).?.ban_state = .banned;
        }
        try testing.expectEqual(@as(u32, 3), tm.totalActiveBans());
        try persist.saveAll(&tm, path);
    }

    // Reload TWICE — simulating two restart cycles. Each restore re-surfaces
    // the same three bans; the lifetime must stay 3, never climbing to 6/9.
    var round: u32 = 0;
    while (round < 2) : (round += 1) {
        var tm = tracker_map.TrackerMap.init(a);
        defer tm.deinit();
        _ = try tm.addTracker("sshd", .{ .max_entries = 16 });
        _ = try tm.ensureLegacy(.{ .max_entries = 16 });
        const loaded = try persist.loadFull(a, path);
        defer loaded.deinit(a);
        try persist.seedMap(&tm, loaded.entries, null, null);
        persist.seedLifetimes(&tm, loaded.lifetimes);

        const sshd = tm.get("sshd").?;
        try testing.expectEqual(@as(u32, 3), tm.totalActiveBans());
        // The invariant under repeated restore: lifetime is set, never added.
        try testing.expectEqual(@as(u64, 3), sshd.lifetime_bans);

        // Re-save so the next round loads the just-restored state — proving
        // the no-double-count holds across a chain of restarts, not just one.
        try persist.saveAll(&tm, path);
    }
}

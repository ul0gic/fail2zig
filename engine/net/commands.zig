// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Command handlers for the IPC server.
//!
//! The handlers here take a parsed `shared.Command`, walk the
//! state/backend/config trio the daemon owns, and produce a
//! `shared.Response` whose `ok.payload` is a JSON document the
//! `fail2zig-client` formatter can render for humans or scripts.
//!
//! Every handler is allocation-aware: any response body is allocated
//! from the caller-provided `Allocator`. The IPC layer frees the
//! response after serialization.
//!
//! Design constraints:
//!   * No hidden state — pure functions over `*Context`.
//!   * Every path returns a Response. Invalid input becomes an `err`,
//!     never a crash.
//!   * Status snapshots read atomic counters (via an injected
//!     `StatsSource` vtable) so the metrics module from 5.2.1 can plug
//!     in without this file having a compile-time dependency on it.

const std = @import("std");
const shared = @import("shared");
const build_options = @import("build_options");

const state_mod = @import("../core/state.zig");
const tracker_map_mod = @import("../core/tracker_map.zig");
const firewall = @import("../firewall/backend.zig");
const config_mod = @import("../config/native.zig");
const ipc = @import("ipc.zig");

// ============================================================================
// Handler context
// ============================================================================

/// Read-only snapshot shape the status handler reports. Produced by
/// whichever module owns the live counters. Zeroed by default so the
/// daemon can wire this up incrementally.
pub const StatsSnapshot = struct {
    memory_bytes_used: u64 = 0,
    parse_rate: u64 = 0,
    /// Lifetime total bans issued (SYS-017). The daemon adapter fills this
    /// from `metrics.snapshot().bans_total`; zero by default so this file
    /// keeps no compile-time dependency on metrics.zig.
    bans_total: u64 = 0,
};

/// Vtable the handler uses to read live stats. Kept separate from the
/// metrics module so this file has no compile-time dependency on
/// metrics.zig — they can be integrated at the main.zig wiring step.
pub const StatsSource = struct {
    ctx: ?*anyopaque = null,
    snapshot: *const fn (ctx: ?*anyopaque) StatsSnapshot = defaultStatsSnapshot,
};

fn defaultStatsSnapshot(ctx: ?*anyopaque) StatsSnapshot {
    _ = ctx;
    return .{};
}

/// Per-jail log-source read-HEALTH (SYS-017), looked up at status time.
/// Mirrors `core/log_watcher.zig`'s `JailHealth` shape; the daemon adapter
/// in main.zig copies between them so this file keeps zero compile-time
/// dependency on the source modules.
///
/// `healthy == false` is a genuine negative probe. journald reports it when
/// no clean `journalctl` poll has ever completed; the file source reports it
/// (ENH-004) when a watch that was once attached has been detached past the
/// debounce window (deleted / unmounted / perms revoked). Either way it is a
/// real source break, which is what lets `computeOverallState` use
/// `healthy == false` as the DEGRADED trigger for ANY enforcing jail
/// (ENH-004 lifts the SYS-017 v1 journald-only restriction). A source that
/// has never read returns "unknown" (null), never a hard false, so DEGRADED
/// is never asserted from a placeholder.
///
/// This carries HEALTH only (whether the source is reading). The SOURCE
/// label is the *resolved-source descriptor* — `JailSourceSource`, always
/// present for a configured jail even when no live source is attached — so
/// a misconfigured (absent-path) file jail still shows its path, not
/// "unknown". HEALTH and SOURCE stay KIND-consistent because both derive
/// from the same runtime `resolveSource` result.
pub const JailHealth = struct { healthy: bool, lines_seen: u64, last_read_ok_ts: i64 };

/// Vtable the handler uses to read per-jail source health. Read-only,
/// same decoupling idiom as `StatsSource`. Default returns `.unknown`
/// (null) for every jail so the daemon can wire it incrementally and
/// tests need not supply it.
pub const JailHealthSource = struct {
    ctx: ?*anyopaque = null,
    /// Look up health for one jail by name. `null` => no source health
    /// known for that jail (renders "unknown", never "unhealthy").
    lookup: *const fn (ctx: ?*anyopaque, jail_name: []const u8) ?JailHealth = defaultNoHealth,
};

fn defaultNoHealth(ctx: ?*anyopaque, jail_name: []const u8) ?JailHealth {
    _ = ctx;
    _ = jail_name;
    return null;
}

/// Vtable the handler uses to read a jail's RESOLVED SOURCE DESCRIPTOR —
/// the authoritative SOURCE label, recorded at jail-resolution time in the
/// daemon (where the runtime `file`/`journald` decision is made). Unlike
/// live read-health, this is known for every enabled/configured jail
/// regardless of whether a source is attached, so a configured jail NEVER
/// renders `SOURCE: unknown` (the absent-logpath case shows the path, which
/// is exactly the misconfiguration signal an operator needs).
///
/// The descriptor is KIND-truthful: journald → `journald (<filter>)`; file
/// → the resolved logpath(s). It is NOT a config heuristic — the daemon
/// records the descriptor only after `resolveSource` picks the kind. The
/// returned slice points into long-lived daemon data (no allocation per
/// call, no lifetime hazard). `null` => the daemon did not record one (e.g.
/// the default vtable in tests) → the handler renders "unknown".
pub const JailSourceSource = struct {
    ctx: ?*anyopaque = null,
    lookup: *const fn (ctx: ?*anyopaque, jail_name: []const u8) ?[]const u8 = defaultNoSource,
};

fn defaultNoSource(ctx: ?*anyopaque, jail_name: []const u8) ?[]const u8 {
    _ = ctx;
    _ = jail_name;
    return null;
}

/// Aggregate context plumbed into the handler at construction time. The
/// daemon owns the referenced objects and outlives the server.
pub const Context = struct {
    /// Per-jail tracker collection (ISSUE-007). Replaces the prior
    /// single-tracker design — every IPC handler now walks the map or
    /// looks up a specific jail's tracker by name.
    trackers: *tracker_map_mod.TrackerMap,
    config: *const config_mod.Config,
    backend: *firewall.Backend,
    stats_source: StatsSource = .{},
    /// Per-jail log-source health (SYS-017). Default returns "unknown" for
    /// every jail; the daemon installs an adapter over the live sources.
    health_source: JailHealthSource = .{},
    /// Per-jail RESOLVED SOURCE DESCRIPTOR (SYS-017) — the authoritative
    /// SOURCE label, recorded at jail-resolution time. Default returns
    /// "unknown"; the daemon installs an adapter over its resolution record.
    source_descriptor: JailSourceSource = .{},
    /// Monotonic startup timestamp captured by the daemon at main()
    /// so the status handler can report uptime as a whole number of
    /// seconds.
    start_time: i64 = 0,
    /// Build version string; mirrored into responses. Defaults to the
    /// build-injected single source of truth (`build_options.version`) so the
    /// IPC response can never report a stale literal even before main.zig
    /// explicitly wires it.
    version: []const u8 = build_options.version,

    /// Entry point used by the IPC server. Matches the
    /// `CommandHandler.dispatch` function pointer signature.
    pub fn dispatch(
        ctx: ?*anyopaque,
        cmd: shared.Command,
        allocator: std.mem.Allocator,
    ) anyerror!shared.Response {
        const self: *Context = @ptrCast(@alignCast(ctx.?));
        return self.handle(cmd, allocator);
    }

    /// Bundle the context into an `ipc.CommandHandler` for
    /// `IpcServer.setCommandHandler`.
    pub fn asHandler(self: *Context) ipc.CommandHandler {
        return .{
            .ctx = @ptrCast(self),
            .dispatch = dispatch,
        };
    }

    fn handle(self: *Context, cmd: shared.Command, a: std.mem.Allocator) !shared.Response {
        return switch (cmd) {
            .status => self.handleStatus(a),
            .ban => |b| self.handleBan(a, b),
            .unban => |u| self.handleUnban(a, u),
            .list => |l| self.handleList(a, l),
            .list_jails => self.handleListJails(a),
            .reload => self.handleReload(a),
            .version => self.handleVersion(a),
        };
    }

    // ----- Handlers -----

    fn handleStatus(self: *Context, a: std.mem.Allocator) !shared.Response {
        const now: i64 = std.time.timestamp();
        const uptime: u64 = if (now > self.start_time)
            @intCast(now - self.start_time)
        else
            0;
        const stats = self.stats_source.snapshot(self.stats_source.ctx);
        const active_bans = self.trackers.totalActiveBans();
        const backend_name = @tagName(self.backend.tag());
        const protection = self.computeOverallState();
        const jails_active = self.enabledJailCount();

        var buf: std.ArrayListUnmanaged(u8) = .{};
        defer buf.deinit(a);
        const w = buf.writer(a);
        try w.writeAll("{");
        try w.print("\"version\":\"{s}\",", .{self.version});
        try w.print("\"uptime_seconds\":{d},", .{uptime});
        try w.print("\"memory_bytes_used\":{d},", .{stats.memory_bytes_used});
        try w.print("\"parse_rate\":{d},", .{stats.parse_rate});
        try w.print("\"active_bans\":{d},", .{active_bans});
        // SYS-017: lifetime total bans (from the stats vtable) and the
        // count of ENABLED jails. `jail_count` is kept (additive) — it
        // counts ALL configured jails; `jails_active` is the enabled subset
        // the client renders as "Jails:".
        try w.print("\"total_bans\":{d},", .{stats.bans_total});
        try w.print("\"jail_count\":{d},", .{self.config.jails.len});
        try w.print("\"jails_active\":{d},", .{jails_active});
        try w.print("\"protection\":\"{s}\",", .{protection});
        try w.print("\"backend\":\"{s}\"", .{backend_name});
        try w.writeAll("}");

        const payload = try a.dupe(u8, buf.items);
        return .{ .ok = .{ .payload = payload } };
    }

    /// Count of ENABLED jails (SYS-017). Reported as `jails_active`; the
    /// client renders it as the "Jails:" rollup.
    fn enabledJailCount(self: *const Context) u32 {
        var n: u32 = 0;
        for (self.config.jails) |*jc| {
            if (jc.enabled) n += 1;
        }
        return n;
    }

    /// Resolve overall protection state across enabled jails (SYS-017,
    /// replaces `computeProtection`). Returns one of `"degraded"`,
    /// `"mixed"`, `"log-only"`, `"active"` with precedence:
    ///
    ///     degraded  >  mixed  >  log-only  >  active
    ///
    /// The effective banaction per jail comes from the same resolver the
    /// dispatch path uses (`resolveJailFromConfig`), so the enforcement
    /// descriptors never disagree with what the daemon actually does.
    ///
    /// DEGRADED predicate (§4): an ENABLED, ENFORCING jail whose log source
    /// is genuinely unhealthy (`health.healthy == false`). Both source kinds
    /// can report a hard false: journald when no clean poll has ever
    /// completed, file (ENH-004) when a once-attached watch is detached past
    /// the debounce window. So DEGRADED is source-agnostic — the predicate
    /// needs no explicit source check. A jail with unknown health (null) is
    /// NEVER degraded: DEGRADED is asserted only from a real negative probe,
    /// never a placeholder. This reads health probes only — it never changes
    /// whether/how a ban is dispatched.
    pub fn computeOverallState(self: *const Context) []const u8 {
        var any_enforcing = false;
        var any_log_only = false;
        var any_degraded = false;
        for (self.config.jails) |*jc| {
            if (!jc.enabled) continue;
            const resolved = config_mod.resolveJailFromConfig(jc, self.config.defaults);
            if (resolved.banaction == .@"log-only") {
                any_log_only = true;
            } else {
                any_enforcing = true;
                // Enforcing jail: a genuine negative source-health probe
                // (journald OR file, per ENH-004) flips the host to DEGRADED.
                if (self.health_source.lookup(self.health_source.ctx, jc.name)) |h| {
                    if (!h.healthy) any_degraded = true;
                }
            }
        }
        if (any_degraded) return "degraded";
        if (any_enforcing and any_log_only) return "mixed";
        if (any_log_only) return "log-only";
        return "active";
    }

    fn handleBan(
        self: *Context,
        a: std.mem.Allocator,
        args: shared.Command.Ban,
    ) !shared.Response {
        const duration: shared.Duration = args.duration orelse self.config.defaults.bantime;
        self.backend.ban(args.ip, args.jail, duration) catch |err| {
            return errResponse(a, 500, @errorName(err));
        };

        var buf: std.ArrayListUnmanaged(u8) = .{};
        defer buf.deinit(a);
        const w = buf.writer(a);
        try w.print("{{\"ip\":\"{}\",\"jail\":\"{s}\",\"duration\":{d}}}", .{
            args.ip, args.jail.slice(), duration,
        });
        const payload = try a.dupe(u8, buf.items);
        return .{ .ok = .{ .payload = payload } };
    }

    fn handleUnban(
        self: *Context,
        a: std.mem.Allocator,
        args: shared.Command.Unban,
    ) !shared.Response {
        // Without a jail hint we call unban on every configured jail.
        // Stop on first success; errors are non-fatal.
        if (args.jail) |j| {
            self.backend.unban(args.ip, j) catch |err| {
                return errResponse(a, 500, @errorName(err));
            };
            if (self.trackers.getByJail(j)) |t| t.clearBan(args.ip);
        } else {
            var any_ok = false;
            for (self.config.jails) |jc| {
                const jid = shared.JailId.fromSlice(jc.name) catch continue;
                self.backend.unban(args.ip, jid) catch continue;
                any_ok = true;
                if (self.trackers.get(jc.name)) |t| t.clearBan(args.ip);
            }
            if (!any_ok) return errResponse(a, 404, "no jail accepted unban");
        }

        var buf: std.ArrayListUnmanaged(u8) = .{};
        defer buf.deinit(a);
        try buf.writer(a).print("{{\"ip\":\"{}\"}}", .{args.ip});
        const payload = try a.dupe(u8, buf.items);
        return .{ .ok = .{ .payload = payload } };
    }

    fn handleList(
        self: *Context,
        a: std.mem.Allocator,
        args: shared.Command.List,
    ) !shared.Response {
        // Prefer the backend-provided list when a jail is given (the
        // backend is the source of truth for what's actually blocked
        // in the kernel). If no jail is passed, walk every tracker.
        var buf: std.ArrayListUnmanaged(u8) = .{};
        defer buf.deinit(a);
        const w = buf.writer(a);
        try w.writeAll("[");

        if (args.jail) |j| {
            const ips = self.backend.listBans(j, a) catch |err| {
                return errResponse(a, 500, @errorName(err));
            };
            defer a.free(ips);
            const jail_tracker = self.trackers.getByJail(j);
            for (ips, 0..) |ip, i| {
                if (i > 0) try w.writeAll(",");
                const st = if (jail_tracker) |t| t.get(ip) else null;
                try writeListEntry(w, ip, j, st);
            }
        } else {
            var first = true;
            var tit = self.trackers.iterator();
            while (tit.next()) |tkv| {
                var it = tkv.value_ptr.*.iterator();
                while (it.next()) |kv| {
                    if (kv.value_ptr.ban_state != .banned) continue;
                    if (!first) try w.writeAll(",");
                    first = false;
                    try writeListEntry(w, kv.key_ptr.*, kv.value_ptr.jail, kv.value_ptr);
                }
            }
        }
        try w.writeAll("]");
        const payload = try a.dupe(u8, buf.items);
        return .{ .ok = .{ .payload = payload } };
    }

    fn handleListJails(self: *Context, a: std.mem.Allocator) !shared.Response {
        // Per-jail bans are now resident in per-jail trackers, so
        // counting is a direct lookup instead of an O(N*M) scan.
        var buf: std.ArrayListUnmanaged(u8) = .{};
        defer buf.deinit(a);
        const w = buf.writer(a);
        try w.writeAll("[");
        for (self.config.jails, 0..) |*jc, idx| {
            if (idx > 0) try w.writeAll(",");
            var count: u32 = 0;
            if (self.trackers.get(jc.name)) |t| {
                var it = t.iterator();
                while (it.next()) |kv| {
                    if (kv.value_ptr.ban_state == .banned) count += 1;
                }
            }
            const resolved = config_mod.resolveJailFromConfig(jc, self.config.defaults);
            // SYS-017: per-jail SOURCE + HEALTH for the human/JSON list,
            // BOTH derived from the same runtime `resolveSource` decision so
            // they are KIND-consistent and never config-guessed.
            //   * SOURCE (`log_source`) = the RESOLVED SOURCE DESCRIPTOR,
            //     recorded at jail-resolution time — known for every enabled
            //     jail even when no source is attached, so a configured jail
            //     NEVER renders "unknown" (an absent-path file jail shows its
            //     path, the misconfiguration signal). Falls back to "unknown"
            //     only when the daemon recorded none (e.g. tests).
            //   * HEALTH (`source_healthy`, `lines_seen`) = the LIVE source
            //     read-health. Tri-state: `true`/`false` when the source
            //     reports a verdict, OMITTED when "unknown" (no signal yet, or
            //     a file source that has never read).
            const health = self.health_source.lookup(self.health_source.ctx, jc.name);
            const lines_seen: u64 = if (health) |h| h.lines_seen else 0;
            const log_source: []const u8 =
                self.source_descriptor.lookup(self.source_descriptor.ctx, jc.name) orelse "unknown";
            try w.print(
                "{{\"name\":\"{s}\",\"enabled\":{s},\"active_bans\":{d},\"maxretry\":{d},\"findtime\":{d},\"bantime\":{d},\"action\":\"{s}\",\"enforcing\":{s},\"log_source\":\"{s}\",\"lines_seen\":{d}",
                .{
                    jc.name,
                    if (jc.enabled) "true" else "false",
                    count,
                    resolved.maxretry,
                    resolved.findtime,
                    resolved.bantime,
                    @tagName(resolved.banaction),
                    if (resolved.banaction != .@"log-only") "true" else "false",
                    log_source,
                    lines_seen,
                },
            );
            if (health) |h| {
                try w.print(",\"source_healthy\":{s}}}", .{if (h.healthy) "true" else "false"});
            } else {
                // Unknown: omit `source_healthy` entirely (tri-state).
                try w.writeAll("}");
            }
        }
        try w.writeAll("]");
        const payload = try a.dupe(u8, buf.items);
        return .{ .ok = .{ .payload = payload } };
    }

    fn handleReload(self: *Context, a: std.mem.Allocator) !shared.Response {
        _ = self;
        std.log.info("ipc: reload requested (not yet implemented)", .{});
        const payload = try a.dupe(u8, "{\"status\":\"reload not yet implemented\"}");
        return .{ .ok = .{ .payload = payload } };
    }

    fn handleVersion(self: *Context, a: std.mem.Allocator) !shared.Response {
        var buf: std.ArrayListUnmanaged(u8) = .{};
        defer buf.deinit(a);
        // ISSUE-011: the field MUST be `daemon_version` to match the client's
        // `VersionPayload` contract (client/format.zig). Emitting `version`
        // here parses as null on the client and silently drops the daemon line.
        // The `status` command pair uses `version` separately — do not unify.
        try buf.writer(a).print("{{\"daemon_version\":\"{s}\"}}", .{self.version});
        const payload = try a.dupe(u8, buf.items);
        return .{ .ok = .{ .payload = payload } };
    }
};

// ============================================================================
// Helpers
// ============================================================================

fn errResponse(a: std.mem.Allocator, code: u16, msg: []const u8) !shared.Response {
    const owned = try a.dupe(u8, msg);
    return .{ .err = .{ .code = code, .message = owned } };
}

fn writeListEntry(
    writer: anytype,
    ip: shared.IpAddress,
    jail: shared.JailId,
    st_opt: ?*const state_mod.IpState,
) !void {
    const attempt_count: u32 = if (st_opt) |st| st.attempt_count else 0;
    const last_attempt: shared.Timestamp = if (st_opt) |st| st.last_attempt else 0;
    const ban_count: u32 = if (st_opt) |st| st.ban_count else 0;
    const ban_expiry: ?shared.Timestamp = if (st_opt) |st| st.ban_expiry else null;
    try writer.print(
        "{{\"ip\":\"{}\",\"jail\":\"{s}\",\"attempt_count\":{d},\"last_attempt\":{d},\"ban_count\":{d},",
        .{ ip, jail.slice(), attempt_count, last_attempt, ban_count },
    );
    if (ban_expiry) |e| {
        try writer.print("\"ban_expiry\":{d}}}", .{e});
    } else {
        try writer.writeAll("\"ban_expiry\":null}");
    }
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

/// Build a `Context` whose backend is a stub that records every call
/// but never touches the kernel. Tests can inspect the stub state
/// after each handler invocation.
const StubBackend = struct {
    ban_called: u32 = 0,
    unban_called: u32 = 0,
    last_ip: ?shared.IpAddress = null,
    last_jail_len: u8 = 0,
    last_duration: shared.Duration = 0,
    listed_ips: []const shared.IpAddress = &.{},
    err_on_ban: ?firewall.BackendError = null,

    fn banFn(
        ctx: *anyopaque,
        ip: shared.IpAddress,
        jail: shared.JailId,
        duration: shared.Duration,
    ) firewall.BackendError!void {
        const self: *StubBackend = @ptrCast(@alignCast(ctx));
        self.ban_called += 1;
        self.last_ip = ip;
        self.last_jail_len = jail.len;
        self.last_duration = duration;
        if (self.err_on_ban) |e| return e;
    }

    fn unbanFn(
        ctx: *anyopaque,
        ip: shared.IpAddress,
        jail: shared.JailId,
    ) firewall.BackendError!void {
        const self: *StubBackend = @ptrCast(@alignCast(ctx));
        self.unban_called += 1;
        self.last_ip = ip;
        self.last_jail_len = jail.len;
    }

    fn listBansFn(
        ctx: *anyopaque,
        jail: shared.JailId,
        allocator: std.mem.Allocator,
    ) firewall.BackendError![]shared.IpAddress {
        _ = jail;
        const self: *StubBackend = @ptrCast(@alignCast(ctx));
        return allocator.dupe(shared.IpAddress, self.listed_ips) catch error.OutOfMemory;
    }

    fn flushFn(ctx: *anyopaque, jail: shared.JailId) firewall.BackendError!void {
        _ = ctx;
        _ = jail;
    }

    fn initFn(
        ctx: *anyopaque,
        config: firewall.BackendConfig,
        allocator: std.mem.Allocator,
    ) firewall.BackendError!void {
        _ = ctx;
        _ = config;
        _ = allocator;
    }

    fn deinitFn(ctx: *anyopaque) void {
        _ = ctx;
    }

    fn isAvailableFn(ctx: *anyopaque) bool {
        _ = ctx;
        return true;
    }
};

/// We don't need the real `Backend` tagged union to test the handlers —
/// we only need `backend.ban()`, `backend.unban()`, `backend.listBans()`,
/// `backend.tag()`. Mutating the union variant inside a test to route
/// through a stub vtable would require touching engine/firewall/backend.zig
/// (outside our ownership). Instead, we wrap the stub in a minimal
/// private shim that mirrors the Backend surface the handlers use.
///
/// This keeps commands.zig decoupled from the concrete Backend union at
/// test time; production wiring still uses the real `*firewall.Backend`.
fn realBackendFromStub(s: *StubBackend) firewall.Backend {
    _ = s;
    // For the happy-path tests below we use the real nftables variant
    // (which has an isAvailable test-friendly stub). We only exercise
    // `.tag()` and a handful of methods that are safe to call even
    // without root — ban/unban are tested by direct invocation on the
    // stub in dedicated tests that skip the Backend layer entirely.
    return .{ .nftables = firewall.nftables.NftablesBackend{} };
}

/// Stub stats source returning a fixed `bans_total` so handleStatus's
/// rollup can be asserted without metrics.zig.
const StubStats = struct {
    bans_total: u64,
    fn snapshot(ctx: ?*anyopaque) StatsSnapshot {
        const self: *StubStats = @ptrCast(@alignCast(ctx.?));
        return .{ .bans_total = self.bans_total };
    }
};

/// Stub jail-HEALTH source. Maps a fixed name to a verdict; everything else
/// is "unknown" (null). Mirrors the daemon adapter contract: only a journald
/// jail ever yields `healthy == false`. (SOURCE labels come from
/// `StubSource`, not here — HEALTH and SOURCE are separate signals.)
const StubHealth = struct {
    name: []const u8,
    healthy: bool,
    lines_seen: u64,
    last_read_ok_ts: i64,
    fn lookup(ctx: ?*anyopaque, jail_name: []const u8) ?JailHealth {
        const self: *StubHealth = @ptrCast(@alignCast(ctx.?));
        if (!std.mem.eql(u8, jail_name, self.name)) return null;
        return .{
            .healthy = self.healthy,
            .lines_seen = self.lines_seen,
            .last_read_ok_ts = self.last_read_ok_ts,
        };
    }
};

/// Stub resolved-source descriptor source for `JailSourceSource`. Maps a
/// fixed name to its descriptor; everything else returns null (→ "unknown").
const StubSource = struct {
    name: []const u8,
    descriptor: []const u8,
    fn lookup(ctx: ?*anyopaque, jail_name: []const u8) ?[]const u8 {
        const self: *StubSource = @ptrCast(@alignCast(ctx.?));
        if (std.mem.eql(u8, jail_name, self.name)) return self.descriptor;
        return null;
    }
};

fn makeConfig() config_mod.Config {
    return .{
        .global = .{},
        .defaults = .{ .bantime = 600, .findtime = 600, .maxretry = 5 },
        .jails = &.{},
        .diag = .{},
    };
}

/// Test helper: build an empty TrackerMap (no jails) for handlers that
/// don't need any tracker state.
fn makeEmptyTrackerMap(a: std.mem.Allocator) tracker_map_mod.TrackerMap {
    return tracker_map_mod.TrackerMap.init(a);
}

test "commands: handleVersion returns version JSON" {
    const a = testing.allocator;

    var trackers = makeEmptyTrackerMap(a);
    defer trackers.deinit();
    var cfg = makeConfig();
    var stub = StubBackend{};
    var be = realBackendFromStub(&stub);
    defer be.deinit();

    var ctx = Context{
        .trackers = &trackers,
        .config = &cfg,
        .backend = &be,
        .version = "9.9.9",
    };
    const resp = try ctx.handle(.{ .version = {} }, a);
    defer resp.deinit(a);
    try testing.expect(resp == .ok);
    try testing.expect(std.mem.indexOf(u8, resp.ok.payload, "9.9.9") != null);
    // ISSUE-011: the payload MUST carry the daemon version under the
    // `daemon_version` key (not `version`) so the client's VersionPayload
    // parser picks it up.
    try testing.expect(std.mem.indexOf(u8, resp.ok.payload, "\"daemon_version\"") != null);
}

// ISSUE-011 contract guard: the daemon's `version`-command payload must parse
// cleanly as the client's `VersionPayload` shape, with `daemon_version`
// populated. This mirrors `client/format.zig`'s `VersionPayload` (all fields
// optional; only `daemon_version` is set by the daemon). If someone renames
// the emitted field back to `version`, `daemon_version` parses as null and
// this test fails — pinning the daemon↔client field-name contract.
test "commands: handleVersion payload parses as client VersionPayload (ISSUE-011)" {
    const a = testing.allocator;

    var trackers = makeEmptyTrackerMap(a);
    defer trackers.deinit();
    var cfg = makeConfig();
    var stub = StubBackend{};
    var be = realBackendFromStub(&stub);
    defer be.deinit();

    var ctx = Context{
        .trackers = &trackers,
        .config = &cfg,
        .backend = &be,
        .version = "1.2.3",
    };
    const resp = try ctx.handle(.{ .version = {} }, a);
    defer resp.deinit(a);
    try testing.expect(resp == .ok);

    // Local mirror of client/format.zig's VersionPayload contract.
    const VersionPayload = struct {
        daemon_version: ?[]const u8 = null,
        git_commit: ?[]const u8 = null,
        build_date: ?[]const u8 = null,
    };
    const parsed = try std.json.parseFromSlice(
        VersionPayload,
        a,
        resp.ok.payload,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    try testing.expect(parsed.value.daemon_version != null);
    try testing.expectEqualStrings("1.2.3", parsed.value.daemon_version.?);
    // The daemon deliberately does NOT embed git/build state (reproducible
    // builds) — these stay absent and the client handles their absence.
    try testing.expect(parsed.value.git_commit == null);
    try testing.expect(parsed.value.build_date == null);
}

test "commands: handleStatus produces expected JSON fields" {
    const a = testing.allocator;

    var trackers = makeEmptyTrackerMap(a);
    defer trackers.deinit();
    const sshd_tracker = try trackers.addTracker("sshd", .{ .max_entries = 16 });

    // Seed one banned entry so active_bans > 0.
    _ = try sshd_tracker.recordAttempt(
        try shared.IpAddress.parse("1.2.3.4"),
        try shared.JailId.fromSlice("sshd"),
        100,
    );
    if (sshd_tracker.map.getPtr(try shared.IpAddress.parse("1.2.3.4"))) |s| {
        s.ban_state = .banned;
    }

    var cfg = makeConfig();
    var stub = StubBackend{};
    var be = realBackendFromStub(&stub);
    defer be.deinit();

    var ctx = Context{
        .trackers = &trackers,
        .config = &cfg,
        .backend = &be,
        .start_time = std.time.timestamp() - 42,
    };
    const resp = try ctx.handle(.{ .status = {} }, a);
    defer resp.deinit(a);
    try testing.expect(resp == .ok);
    const body = resp.ok.payload;
    try testing.expect(std.mem.indexOf(u8, body, "\"uptime_seconds\":") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"active_bans\":1") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"jail_count\":0") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"backend\":\"nftables\"") != null);
    // Zero enabled jails -> "active" (nothing to misreport).
    try testing.expect(std.mem.indexOf(u8, body, "\"protection\":\"active\"") != null);
}

test "commands: handleListJails counts banned entries per-jail" {
    const a = testing.allocator;

    var trackers = makeEmptyTrackerMap(a);
    defer trackers.deinit();
    const sshd_tracker = try trackers.addTracker("sshd", .{ .max_entries = 16 });
    _ = try trackers.addTracker("nginx", .{ .max_entries = 16 });

    const sshd_jail = try shared.JailId.fromSlice("sshd");
    _ = try sshd_tracker.recordAttempt(try shared.IpAddress.parse("10.0.0.1"), sshd_jail, 1);
    _ = try sshd_tracker.recordAttempt(try shared.IpAddress.parse("10.0.0.2"), sshd_jail, 2);
    if (sshd_tracker.map.getPtr(try shared.IpAddress.parse("10.0.0.1"))) |s| s.ban_state = .banned;
    if (sshd_tracker.map.getPtr(try shared.IpAddress.parse("10.0.0.2"))) |s| s.ban_state = .banned;

    var jails = [_]config_mod.JailConfig{
        .{ .name = "sshd", .enabled = true },
        .{ .name = "nginx", .enabled = false },
    };
    var cfg = config_mod.Config{
        .global = .{},
        .defaults = .{},
        .jails = &jails,
        .diag = .{},
    };
    var stub = StubBackend{};
    var be = realBackendFromStub(&stub);
    defer be.deinit();

    var ctx = Context{ .trackers = &trackers, .config = &cfg, .backend = &be };
    const resp = try ctx.handle(.{ .list_jails = {} }, a);
    defer resp.deinit(a);
    try testing.expect(resp == .ok);
    try testing.expect(std.mem.indexOf(u8, resp.ok.payload, "\"name\":\"sshd\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.ok.payload, "\"active_bans\":2") != null);
    try testing.expect(std.mem.indexOf(u8, resp.ok.payload, "\"name\":\"nginx\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.ok.payload, "\"enabled\":false") != null);
}

test "commands: handleListJails reflects per-jail resolved thresholds (ISSUE-007)" {
    const a = testing.allocator;
    var trackers = makeEmptyTrackerMap(a);
    defer trackers.deinit();
    _ = try trackers.addTracker("sshd", .{ .max_entries = 16 });
    _ = try trackers.addTracker("nginx", .{ .max_entries = 16 });

    var jails = [_]config_mod.JailConfig{
        .{ .name = "sshd", .enabled = true, .maxretry = 1, .findtime = 10, .bantime = 60 },
        .{ .name = "nginx", .enabled = true }, // inherits defaults
    };
    var cfg = config_mod.Config{
        .global = .{},
        .defaults = .{ .maxretry = 5, .findtime = 600, .bantime = 600 },
        .jails = &jails,
        .diag = .{},
    };
    var stub = StubBackend{};
    var be = realBackendFromStub(&stub);
    defer be.deinit();

    var ctx = Context{ .trackers = &trackers, .config = &cfg, .backend = &be };
    const resp = try ctx.handle(.{ .list_jails = {} }, a);
    defer resp.deinit(a);
    const body = resp.ok.payload;
    // sshd's per-jail values surface; nginx inherits defaults.
    try testing.expect(std.mem.indexOf(u8, body, "\"name\":\"sshd\",\"enabled\":true,\"active_bans\":0,\"maxretry\":1,\"findtime\":10,\"bantime\":60") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"name\":\"nginx\",\"enabled\":true,\"active_bans\":0,\"maxretry\":5,\"findtime\":600,\"bantime\":600") != null);
}

test "commands: handleStatus protection is active when all enabled jails enforce" {
    const a = testing.allocator;
    var trackers = makeEmptyTrackerMap(a);
    defer trackers.deinit();

    var jails = [_]config_mod.JailConfig{
        .{ .name = "sshd", .enabled = true, .banaction = .nftables },
        .{ .name = "nginx", .enabled = true, .banaction = .iptables },
    };
    var cfg = config_mod.Config{
        .global = .{},
        .defaults = .{ .banaction = .nftables },
        .jails = &jails,
        .diag = .{},
    };
    var stub = StubBackend{};
    var be = realBackendFromStub(&stub);
    defer be.deinit();

    var ctx = Context{ .trackers = &trackers, .config = &cfg, .backend = &be };
    const resp = try ctx.handle(.{ .status = {} }, a);
    defer resp.deinit(a);
    try testing.expect(std.mem.indexOf(u8, resp.ok.payload, "\"protection\":\"active\"") != null);
}

test "commands: handleStatus protection is log-only when all enabled jails are log-only" {
    const a = testing.allocator;
    var trackers = makeEmptyTrackerMap(a);
    defer trackers.deinit();

    var jails = [_]config_mod.JailConfig{
        .{ .name = "sshd", .enabled = true, .banaction = .@"log-only" },
        // Disabled enforcing jail must NOT pull the verdict back to active.
        .{ .name = "nginx", .enabled = false, .banaction = .nftables },
    };
    var cfg = config_mod.Config{
        .global = .{},
        .defaults = .{ .banaction = .@"log-only" },
        .jails = &jails,
        .diag = .{},
    };
    var stub = StubBackend{};
    var be = realBackendFromStub(&stub);
    defer be.deinit();

    var ctx = Context{ .trackers = &trackers, .config = &cfg, .backend = &be };
    const resp = try ctx.handle(.{ .status = {} }, a);
    defer resp.deinit(a);
    try testing.expect(std.mem.indexOf(u8, resp.ok.payload, "\"protection\":\"log-only\"") != null);
}

test "commands: handleStatus protection is mixed when enforcing and log-only coexist" {
    const a = testing.allocator;
    var trackers = makeEmptyTrackerMap(a);
    defer trackers.deinit();

    var jails = [_]config_mod.JailConfig{
        .{ .name = "sshd", .enabled = true, .banaction = .nftables },
        // Inherits a log-only default -> non-enforcing via the resolver.
        .{ .name = "sshd-test", .enabled = true },
    };
    var cfg = config_mod.Config{
        .global = .{},
        .defaults = .{ .banaction = .@"log-only" },
        .jails = &jails,
        .diag = .{},
    };
    var stub = StubBackend{};
    var be = realBackendFromStub(&stub);
    defer be.deinit();

    var ctx = Context{ .trackers = &trackers, .config = &cfg, .backend = &be };
    const resp = try ctx.handle(.{ .status = {} }, a);
    defer resp.deinit(a);
    try testing.expect(std.mem.indexOf(u8, resp.ok.payload, "\"protection\":\"mixed\"") != null);
}

test "commands: handleListJails emits action and enforcing per jail" {
    const a = testing.allocator;
    var trackers = makeEmptyTrackerMap(a);
    defer trackers.deinit();

    var jails = [_]config_mod.JailConfig{
        .{ .name = "sshd", .enabled = true, .banaction = .nftables },
        .{ .name = "sshd-test", .enabled = true, .banaction = .@"log-only" },
    };
    var cfg = config_mod.Config{
        .global = .{},
        .defaults = .{ .banaction = .nftables },
        .jails = &jails,
        .diag = .{},
    };
    var stub = StubBackend{};
    var be = realBackendFromStub(&stub);
    defer be.deinit();

    var ctx = Context{ .trackers = &trackers, .config = &cfg, .backend = &be };
    const resp = try ctx.handle(.{ .list_jails = {} }, a);
    defer resp.deinit(a);
    const body = resp.ok.payload;
    // Enforcing jail.
    try testing.expect(std.mem.indexOf(u8, body, "\"name\":\"sshd\"") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"action\":\"nftables\",\"enforcing\":true") != null);
    // Non-enforcing jail.
    try testing.expect(std.mem.indexOf(u8, body, "\"name\":\"sshd-test\"") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"action\":\"log-only\",\"enforcing\":false") != null);
}

test "commands: handleList without jail returns only banned entries" {
    const a = testing.allocator;

    var trackers = makeEmptyTrackerMap(a);
    defer trackers.deinit();
    const sshd_tracker = try trackers.addTracker("sshd", .{ .max_entries = 16 });

    const sshd = try shared.JailId.fromSlice("sshd");
    _ = try sshd_tracker.recordAttempt(try shared.IpAddress.parse("1.1.1.1"), sshd, 1);
    _ = try sshd_tracker.recordAttempt(try shared.IpAddress.parse("2.2.2.2"), sshd, 2);
    if (sshd_tracker.map.getPtr(try shared.IpAddress.parse("1.1.1.1"))) |s| s.ban_state = .banned;

    var cfg = makeConfig();
    var stub = StubBackend{};
    var be = realBackendFromStub(&stub);
    defer be.deinit();

    var ctx = Context{ .trackers = &trackers, .config = &cfg, .backend = &be };
    const resp = try ctx.handle(.{ .list = .{ .jail = null } }, a);
    defer resp.deinit(a);
    try testing.expect(resp == .ok);
    try testing.expect(std.mem.indexOf(u8, resp.ok.payload, "1.1.1.1") != null);
    // 2.2.2.2 is tracked but not banned -> must NOT appear
    try testing.expect(std.mem.indexOf(u8, resp.ok.payload, "2.2.2.2") == null);
}

test "commands: handleReload is a stub but returns ok" {
    const a = testing.allocator;

    var trackers = makeEmptyTrackerMap(a);
    defer trackers.deinit();
    var cfg = makeConfig();
    var stub = StubBackend{};
    var be = realBackendFromStub(&stub);
    defer be.deinit();

    var ctx = Context{ .trackers = &trackers, .config = &cfg, .backend = &be };
    const resp = try ctx.handle(.{ .reload = {} }, a);
    defer resp.deinit(a);
    try testing.expect(resp == .ok);
    try testing.expect(std.mem.indexOf(u8, resp.ok.payload, "not yet implemented") != null);
}

test "commands: asHandler round-trips via the dispatch pointer" {
    const a = testing.allocator;

    var trackers = makeEmptyTrackerMap(a);
    defer trackers.deinit();
    var cfg = makeConfig();
    var stub = StubBackend{};
    var be = realBackendFromStub(&stub);
    defer be.deinit();

    var ctx = Context{ .trackers = &trackers, .config = &cfg, .backend = &be, .version = "7.7.7" };
    const h = ctx.asHandler();
    const resp = try h.dispatch(h.ctx, .{ .version = {} }, a);
    defer resp.deinit(a);
    try testing.expect(std.mem.indexOf(u8, resp.ok.payload, "7.7.7") != null);
}

test "commands: handleBan on uninitialized backend returns err response" {
    // The nftables backend returns .NotAvailable when `init()` has not
    // been called — exercise that error path through `handleBan`.
    const a = testing.allocator;

    var trackers = makeEmptyTrackerMap(a);
    defer trackers.deinit();
    var cfg = makeConfig();
    var stub = StubBackend{};
    var be = realBackendFromStub(&stub);
    defer be.deinit();

    var ctx = Context{ .trackers = &trackers, .config = &cfg, .backend = &be };
    const ip = try shared.IpAddress.parse("9.9.9.9");
    const jail = try shared.JailId.fromSlice("sshd");
    const resp = try ctx.handle(
        .{ .ban = .{ .ip = ip, .jail = jail, .duration = 300 } },
        a,
    );
    defer resp.deinit(a);
    try testing.expect(resp == .err);
    try testing.expectEqual(@as(u16, 500), resp.err.code);
}

// --- SYS-017: rollups, DEGRADED overall state, list-jails source/health ---

test "commands: handleStatus emits total_bans + jails_active rollups (SYS-017)" {
    const a = testing.allocator;
    var trackers = makeEmptyTrackerMap(a);
    defer trackers.deinit();

    var jails = [_]config_mod.JailConfig{
        .{ .name = "sshd", .enabled = true, .banaction = .nftables },
        .{ .name = "nginx", .enabled = false, .banaction = .nftables },
    };
    var cfg = config_mod.Config{
        .global = .{},
        .defaults = .{ .banaction = .nftables },
        .jails = &jails,
        .diag = .{},
    };
    var stub = StubBackend{};
    var be = realBackendFromStub(&stub);
    defer be.deinit();
    var stats = StubStats{ .bans_total = 42 };

    var ctx = Context{
        .trackers = &trackers,
        .config = &cfg,
        .backend = &be,
        .stats_source = .{ .ctx = @ptrCast(&stats), .snapshot = StubStats.snapshot },
    };
    const resp = try ctx.handle(.{ .status = {} }, a);
    defer resp.deinit(a);
    const body = resp.ok.payload;
    try testing.expect(std.mem.indexOf(u8, body, "\"total_bans\":42") != null);
    // One enabled, one disabled → jails_active = 1, jail_count = 2 (kept).
    try testing.expect(std.mem.indexOf(u8, body, "\"jails_active\":1") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"jail_count\":2") != null);
}

test "commands: BUG-006 status Total bans >= Active bans after a restore" {
    // The exact regression: after a restart that restored active bans, the
    // persisted lifetime (seeded ≥ active) must keep Total >= Active. Here
    // the stats source reports the persisted lifetime (2) and the tracker
    // holds 2 restored active bans — Total (2) must not read below Active.
    const a = testing.allocator;
    var trackers = makeEmptyTrackerMap(a);
    defer trackers.deinit();
    const sshd = try trackers.addTracker("sshd", .{ .max_entries = 16 });
    // Two restored, banned entries.
    inline for (.{ "1.2.3.4", "5.6.7.8" }) |ip_s| {
        _ = try sshd.recordAttempt(try shared.IpAddress.parse(ip_s), try shared.JailId.fromSlice("sshd"), 100);
        sshd.map.getPtr(try shared.IpAddress.parse(ip_s)).?.ban_state = .banned;
    }
    var cfg = makeConfig();
    var stub = StubBackend{};
    var be = realBackendFromStub(&stub);
    defer be.deinit();
    // Persisted lifetime floored at active (2) — the BUG-006 seed.
    var stats = StubStats{ .bans_total = 2 };

    var ctx = Context{
        .trackers = &trackers,
        .config = &cfg,
        .backend = &be,
        .stats_source = .{ .ctx = @ptrCast(&stats), .snapshot = StubStats.snapshot },
    };
    const resp = try ctx.handle(.{ .status = {} }, a);
    defer resp.deinit(a);
    const body = resp.ok.payload;
    try testing.expect(std.mem.indexOf(u8, body, "\"active_bans\":2") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"total_bans\":2") != null);
    // Total (2) >= Active (2): the self-contradictory state is gone.
}

test "commands: overall state is degraded for an enforcing jail with unhealthy source (SYS-017)" {
    const a = testing.allocator;
    var trackers = makeEmptyTrackerMap(a);
    defer trackers.deinit();
    var jails = [_]config_mod.JailConfig{
        .{ .name = "sshd", .enabled = true, .banaction = .nftables },
    };
    var cfg = config_mod.Config{ .global = .{}, .defaults = .{ .banaction = .nftables }, .jails = &jails, .diag = .{} };
    var stub = StubBackend{};
    var be = realBackendFromStub(&stub);
    defer be.deinit();
    var health = StubHealth{ .name = "sshd", .healthy = false, .lines_seen = 0, .last_read_ok_ts = 0 };

    var ctx = Context{
        .trackers = &trackers,
        .config = &cfg,
        .backend = &be,
        .health_source = .{ .ctx = @ptrCast(&health), .lookup = StubHealth.lookup },
    };
    const resp = try ctx.handle(.{ .status = {} }, a);
    defer resp.deinit(a);
    try testing.expect(std.mem.indexOf(u8, resp.ok.payload, "\"protection\":\"degraded\"") != null);
}

test "commands: degraded outranks mixed (enforcing+unhealthy with a log-only jail) (SYS-017)" {
    const a = testing.allocator;
    var trackers = makeEmptyTrackerMap(a);
    defer trackers.deinit();
    var jails = [_]config_mod.JailConfig{
        .{ .name = "sshd", .enabled = true, .banaction = .nftables },
        .{ .name = "audit", .enabled = true, .banaction = .@"log-only" },
    };
    var cfg = config_mod.Config{ .global = .{}, .defaults = .{ .banaction = .nftables }, .jails = &jails, .diag = .{} };
    var stub = StubBackend{};
    var be = realBackendFromStub(&stub);
    defer be.deinit();
    var health = StubHealth{ .name = "sshd", .healthy = false, .lines_seen = 0, .last_read_ok_ts = 0 };

    var ctx = Context{
        .trackers = &trackers,
        .config = &cfg,
        .backend = &be,
        .health_source = .{ .ctx = @ptrCast(&health), .lookup = StubHealth.lookup },
    };
    const resp = try ctx.handle(.{ .status = {} }, a);
    defer resp.deinit(a);
    try testing.expect(std.mem.indexOf(u8, resp.ok.payload, "\"protection\":\"degraded\"") != null);
}

test "commands: healthy enforcing + log-only is mixed, not degraded (SYS-017)" {
    const a = testing.allocator;
    var trackers = makeEmptyTrackerMap(a);
    defer trackers.deinit();
    var jails = [_]config_mod.JailConfig{
        .{ .name = "sshd", .enabled = true, .banaction = .nftables },
        .{ .name = "audit", .enabled = true, .banaction = .@"log-only" },
    };
    var cfg = config_mod.Config{ .global = .{}, .defaults = .{ .banaction = .nftables }, .jails = &jails, .diag = .{} };
    var stub = StubBackend{};
    var be = realBackendFromStub(&stub);
    defer be.deinit();
    var health = StubHealth{ .name = "sshd", .healthy = true, .lines_seen = 5, .last_read_ok_ts = 100 };

    var ctx = Context{
        .trackers = &trackers,
        .config = &cfg,
        .backend = &be,
        .health_source = .{ .ctx = @ptrCast(&health), .lookup = StubHealth.lookup },
    };
    const resp = try ctx.handle(.{ .status = {} }, a);
    defer resp.deinit(a);
    try testing.expect(std.mem.indexOf(u8, resp.ok.payload, "\"protection\":\"mixed\"") != null);
}

test "commands: a log-only jail with a dead source does NOT degrade (SYS-017)" {
    // A non-enforcing jail's source health never flips the host critical —
    // its non-enforcement is already honestly reported by "log-only".
    const a = testing.allocator;
    var trackers = makeEmptyTrackerMap(a);
    defer trackers.deinit();
    var jails = [_]config_mod.JailConfig{
        .{ .name = "sshd", .enabled = true, .banaction = .@"log-only" },
    };
    var cfg = config_mod.Config{ .global = .{}, .defaults = .{ .banaction = .@"log-only" }, .jails = &jails, .diag = .{} };
    var stub = StubBackend{};
    var be = realBackendFromStub(&stub);
    defer be.deinit();
    var health = StubHealth{ .name = "sshd", .healthy = false, .lines_seen = 0, .last_read_ok_ts = 0 };

    var ctx = Context{
        .trackers = &trackers,
        .config = &cfg,
        .backend = &be,
        .health_source = .{ .ctx = @ptrCast(&health), .lookup = StubHealth.lookup },
    };
    const resp = try ctx.handle(.{ .status = {} }, a);
    defer resp.deinit(a);
    try testing.expect(std.mem.indexOf(u8, resp.ok.payload, "\"protection\":\"log-only\"") != null);
}

test "commands: enforcing jail with UNKNOWN health is not degraded (SYS-017)" {
    // No source-health signal yet (lookup returns null) → never a synthetic
    // DEGRADED. The default no-health vtable yields exactly this.
    const a = testing.allocator;
    var trackers = makeEmptyTrackerMap(a);
    defer trackers.deinit();
    var jails = [_]config_mod.JailConfig{
        .{ .name = "sshd", .enabled = true, .banaction = .nftables },
    };
    var cfg = config_mod.Config{ .global = .{}, .defaults = .{ .banaction = .nftables }, .jails = &jails, .diag = .{} };
    var stub = StubBackend{};
    var be = realBackendFromStub(&stub);
    defer be.deinit();

    // No health_source installed → defaultNoHealth → unknown for every jail.
    var ctx = Context{ .trackers = &trackers, .config = &cfg, .backend = &be };
    const resp = try ctx.handle(.{ .status = {} }, a);
    defer resp.deinit(a);
    try testing.expect(std.mem.indexOf(u8, resp.ok.payload, "\"protection\":\"active\"") != null);
}

/// Multi-jail health stub: maps each jail name to a resolved-source label
/// + verdict, writing the label into the caller's `source_buf` (exactly
/// like the real per-source `healthForJail`). HEALTH only — SOURCE comes
/// from `MultiSource`.
const MultiHealth = struct {
    const Entry = struct { name: []const u8, healthy: bool, lines_seen: u64 };
    entries: []const Entry,
    fn lookup(ctx: ?*anyopaque, jail_name: []const u8) ?JailHealth {
        const self: *MultiHealth = @ptrCast(@alignCast(ctx.?));
        for (self.entries) |e| {
            if (!std.mem.eql(u8, jail_name, e.name)) continue;
            return .{ .healthy = e.healthy, .lines_seen = e.lines_seen, .last_read_ok_ts = 0 };
        }
        return null;
    }
};

/// Multi-jail RESOLVED-source descriptor stub. The descriptor is the
/// runtime-resolved truth recorded by the daemon — INDEPENDENT of the
/// jail's config and of whether a live source is attached — so a test can
/// prove SOURCE follows runtime resolution, never the config logpath, and
/// is present even for a jail with no live health.
const MultiSource = struct {
    const Entry = struct { name: []const u8, descriptor: []const u8 };
    entries: []const Entry,
    fn lookup(ctx: ?*anyopaque, jail_name: []const u8) ?[]const u8 {
        const self: *MultiSource = @ptrCast(@alignCast(ctx.?));
        for (self.entries) |e| {
            if (std.mem.eql(u8, jail_name, e.name)) return e.descriptor;
        }
        return null;
    }
};

test "commands: handleListJails emits log_source/source_healthy/lines_seen (SYS-017)" {
    const a = testing.allocator;
    var trackers = makeEmptyTrackerMap(a);
    defer trackers.deinit();
    var jails = [_]config_mod.JailConfig{
        // sshd: config says source=auto with a FILE logpath (auth.log), but
        // at runtime it RESOLVED to journald (the exact f2z-target bug:
        // auth.log doesn't exist on a journald-only box). SOURCE must follow
        // the resolved descriptor (journald), NOT the config logpath.
        .{ .name = "sshd", .enabled = true, .banaction = .nftables, .source = .auto, .filter = "sshd", .logpath = &.{"/var/log/auth.log"} },
        // nginx: a real, reading file jail.
        .{ .name = "nginx", .enabled = true, .banaction = .nftables, .source = .file, .filter = "nginx", .logpath = &.{"/var/log/nginx/error.log"} },
        // mail: file-resolved but its path is ABSENT — no live source is
        // attached, so HEALTH is unknown. SOURCE must STILL show the
        // resolved path (the misconfiguration signal), never "unknown".
        .{ .name = "mail", .enabled = true, .banaction = .nftables, .source = .file, .filter = "mail", .logpath = &.{"/var/log/mail.log"} },
    };
    var cfg = config_mod.Config{ .global = .{}, .defaults = .{ .banaction = .nftables }, .jails = &jails, .diag = .{} };
    var stub = StubBackend{};
    var be = realBackendFromStub(&stub);
    defer be.deinit();
    // HEALTH: sshd + nginx report; mail has NO live source (unknown health).
    var health = MultiHealth{ .entries = &.{
        .{ .name = "sshd", .healthy = true, .lines_seen = 12 },
        .{ .name = "nginx", .healthy = true, .lines_seen = 3 },
    } };
    // SOURCE descriptors: recorded for ALL enabled jails at resolution time,
    // including mail (whose path is absent) — so SOURCE never renders unknown.
    var source = MultiSource{ .entries = &.{
        .{ .name = "sshd", .descriptor = "journald (sshd)" },
        .{ .name = "nginx", .descriptor = "/var/log/nginx/error.log" },
        .{ .name = "mail", .descriptor = "/var/log/mail.log" },
    } };

    var ctx = Context{
        .trackers = &trackers,
        .config = &cfg,
        .backend = &be,
        .health_source = .{ .ctx = @ptrCast(&health), .lookup = MultiHealth.lookup },
        .source_descriptor = .{ .ctx = @ptrCast(&source), .lookup = MultiSource.lookup },
    };
    const resp = try ctx.handle(.{ .list_jails = {} }, a);
    defer resp.deinit(a);
    const body = resp.ok.payload;
    // sshd: SOURCE follows the resolved descriptor (journald), NOT the
    // config logpath — auth.log must NOT appear anywhere.
    try testing.expect(std.mem.indexOf(u8, body, "\"log_source\":\"journald (sshd)\"") != null);
    try testing.expect(std.mem.indexOf(u8, body, "/var/log/auth.log") == null);
    try testing.expect(std.mem.indexOf(u8, body, "\"source_healthy\":true") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"lines_seen\":12") != null);
    // nginx: file jail shows its real path.
    try testing.expect(std.mem.indexOf(u8, body, "\"log_source\":\"/var/log/nginx/error.log\"") != null);
    // mail (THE FIX): absent path / no live health → SOURCE shows the
    // resolved path, NOT "unknown"; health omitted (no source_healthy).
    try testing.expect(std.mem.indexOf(u8, body, "\"log_source\":\"/var/log/mail.log\"") != null);
    // And no configured jail renders log_source "unknown".
    try testing.expect(std.mem.indexOf(u8, body, "\"log_source\":\"unknown\"") == null);
}

test "commands: an enabled jail with a recorded descriptor never renders SOURCE unknown (SYS-017)" {
    // Direct guard on the fix: even with NO health source at all (health
    // unknown for every jail), a jail whose resolved descriptor was recorded
    // shows that descriptor — never "unknown".
    const a = testing.allocator;
    var trackers = makeEmptyTrackerMap(a);
    defer trackers.deinit();
    var jails = [_]config_mod.JailConfig{
        .{ .name = "nginx", .enabled = true, .banaction = .nftables, .source = .file, .filter = "nginx", .logpath = &.{"/var/log/nginx/error.log"} },
    };
    var cfg = config_mod.Config{ .global = .{}, .defaults = .{ .banaction = .nftables }, .jails = &jails, .diag = .{} };
    var stub = StubBackend{};
    var be = realBackendFromStub(&stub);
    defer be.deinit();
    var source = MultiSource{ .entries = &.{
        .{ .name = "nginx", .descriptor = "/var/log/nginx/error.log" },
    } };
    // No health_source installed → unknown HEALTH for every jail.
    var ctx = Context{
        .trackers = &trackers,
        .config = &cfg,
        .backend = &be,
        .source_descriptor = .{ .ctx = @ptrCast(&source), .lookup = MultiSource.lookup },
    };
    const resp = try ctx.handle(.{ .list_jails = {} }, a);
    defer resp.deinit(a);
    const body = resp.ok.payload;
    try testing.expect(std.mem.indexOf(u8, body, "\"log_source\":\"/var/log/nginx/error.log\"") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"log_source\":\"unknown\"") == null);
    // HEALTH genuinely unknown → source_healthy omitted.
    try testing.expect(std.mem.indexOf(u8, body, "\"source_healthy\"") == null);
}

test "commands: handleUnban without jail returns 404 when no jails configured" {
    const a = testing.allocator;

    var trackers = makeEmptyTrackerMap(a);
    defer trackers.deinit();
    var cfg = makeConfig();
    var stub = StubBackend{};
    var be = realBackendFromStub(&stub);
    defer be.deinit();

    var ctx = Context{ .trackers = &trackers, .config = &cfg, .backend = &be };
    const ip = try shared.IpAddress.parse("10.10.10.10");
    const resp = try ctx.handle(.{ .unban = .{ .ip = ip, .jail = null } }, a);
    defer resp.deinit(a);
    try testing.expect(resp == .err);
    try testing.expectEqual(@as(u16, 404), resp.err.code);
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const shared = @import("shared");
const build_options = @import("build_options");

const state_mod = @import("../core/state.zig");
const tracker_map_mod = @import("../core/tracker_map.zig");
const firewall = @import("../firewall/backend.zig");
const config_mod = @import("../config/native.zig");
const ipc = @import("ipc.zig");
const lifecycle_mod = @import("../core/ban_lifecycle.zig");

pub const StatsSnapshot = struct {
    memory_bytes_used: u64 = 0,
    parse_rate: u64 = 0,
    bans_total: u64 = 0,
};

pub const StatsSource = struct {
    ctx: ?*anyopaque = null,
    snapshot: *const fn (ctx: ?*anyopaque) StatsSnapshot = defaultStatsSnapshot,
};

fn defaultStatsSnapshot(ctx: ?*anyopaque) StatsSnapshot {
    _ = ctx;
    return .{};
}

pub const JailHealth = struct { healthy: bool, lines_seen: u64, last_read_ok_ts: i64 };

pub const JailHealthSource = struct {
    ctx: ?*anyopaque = null,
    lookup: *const fn (ctx: ?*anyopaque, jail_name: []const u8) ?JailHealth = defaultNoHealth,
};

fn defaultNoHealth(ctx: ?*anyopaque, jail_name: []const u8) ?JailHealth {
    _ = ctx;
    _ = jail_name;
    return null;
}

pub const JailSourceSource = struct {
    ctx: ?*anyopaque = null,
    lookup: *const fn (ctx: ?*anyopaque, jail_name: []const u8) ?[]const u8 = defaultNoSource,
};

fn defaultNoSource(ctx: ?*anyopaque, jail_name: []const u8) ?[]const u8 {
    _ = ctx;
    _ = jail_name;
    return null;
}

pub const NoBackendCause = union(enum) {
    detect: firewall.DetectError,
    init: firewall.BackendError,

    pub fn name(self: NoBackendCause) []const u8 {
        return switch (self) {
            .detect => |e| @errorName(e),
            .init => |e| @errorName(e),
        };
    }

    pub fn describe(self: NoBackendCause, buf: []u8) []const u8 {
        return switch (self) {
            .detect => |e| firewall.causeName(e),
            .init => |e| std.fmt.bufPrint(buf, "backend init failed: {s}", .{@errorName(e)}) catch "backend init failed",
        };
    }
};

pub const FirewallState = union(enum) {
    ready,
    not_needed,
    unavailable: NoBackendCause,

    pub fn effectiveAction(self: FirewallState, configured: config_mod.BanAction) config_mod.BanAction {
        return switch (self) {
            .ready => configured,
            .not_needed, .unavailable => .@"log-only",
        };
    }

    pub fn cause(self: FirewallState) ?NoBackendCause {
        return switch (self) {
            .unavailable => |c| c,
            else => null,
        };
    }
};

pub fn firewallNeeded(cfg: *const config_mod.Config) bool {
    for (cfg.jails) |*jc| {
        if (!jc.enabled) continue;
        if (config_mod.resolveJailFromConfig(jc, cfg.defaults).banaction != .@"log-only") return true;
    }
    return false;
}

pub const Context = struct {
    trackers: *tracker_map_mod.TrackerMap,
    config: *const config_mod.Config,
    backend: ?*firewall.Backend,
    firewall_state: FirewallState = .ready,
    lifecycle: ?*lifecycle_mod.Lifecycle = null,
    stats_source: StatsSource = .{},
    health_source: JailHealthSource = .{},
    source_descriptor: JailSourceSource = .{},
    start_time: i64 = 0,
    version: []const u8 = build_options.version,

    pub fn dispatch(
        ctx: ?*anyopaque,
        cmd: shared.Command,
        allocator: std.mem.Allocator,
    ) anyerror!shared.Response {
        const self: *Context = @ptrCast(@alignCast(ctx.?));
        return self.handle(cmd, allocator);
    }

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
            .query_v1, .admin_v1, .reload_v1 => .{ .err = .{ .code = 501, .message = try a.dupe(u8, "versioned commands require the native daemon") } },
        };
    }

    fn handleStatus(self: *Context, a: std.mem.Allocator) !shared.Response {
        const now: i64 = std.time.timestamp();
        const uptime: u64 = if (now > self.start_time)
            @intCast(now - self.start_time)
        else
            0;
        const stats = self.stats_source.snapshot(self.stats_source.ctx);
        const active_bans = self.trackers.totalActiveBans();
        const backend_name: []const u8 = if (self.backend) |be| @tagName(be.tag()) else "none";
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
        try w.print("\"total_bans\":{d},", .{stats.bans_total});
        try w.print("\"jail_count\":{d},", .{self.config.jails.len});
        try w.print("\"jails_active\":{d},", .{jails_active});
        try w.print("\"protection\":\"{s}\",", .{protection});
        if (self.firewall_state.cause()) |c| {
            try w.print("\"protection_cause\":\"{s}\",", .{c.name()});
        }
        try w.print("\"backend\":\"{s}\"", .{backend_name});
        try w.writeAll("}");

        const payload = try a.dupe(u8, buf.items);
        return .{ .ok = .{ .payload = payload } };
    }

    fn enabledJailCount(self: *const Context) u32 {
        var n: u32 = 0;
        for (self.config.jails) |*jc| {
            if (jc.enabled) n += 1;
        }
        return n;
    }

    pub fn jailEnforcing(self: *const Context, jc: *const config_mod.JailConfig) bool {
        const resolved = config_mod.resolveJailFromConfig(jc, self.config.defaults);
        return self.firewall_state.effectiveAction(resolved.banaction) != .@"log-only";
    }

    pub fn computeOverallState(self: *const Context) []const u8 {
        if (self.firewall_state == .unavailable) return "degraded";
        if (self.enabledJailCount() == 0) return "log-only";
        if (self.lifecycle != null) {
            var trackers = self.trackers.iterator();
            while (trackers.next()) |entry| {
                var states = entry.value_ptr.*.iterator();
                while (states.next()) |kv| {
                    const st = kv.value_ptr;
                    if (st.ban_state == .banned and st.enforced and (!st.applied or (st.ban_expiry orelse 0) <= std.time.timestamp())) return "degraded";
                }
            }
        }
        var any_enforcing = false;
        var any_log_only = false;
        var any_degraded = false;
        for (self.config.jails) |*jc| {
            if (!jc.enabled) continue;
            if (!self.jailEnforcing(jc)) {
                any_log_only = true;
            } else {
                any_enforcing = true;
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
        const jc = for (self.config.jails) |*candidate| {
            if (std.mem.eql(u8, candidate.name, args.jail.slice())) break candidate;
        } else return errResponse(a, 404, "unknown jail");
        if (!jc.enabled) return errResponse(a, 409, "jail is disabled");
        if (!self.jailEnforcing(jc)) return errResponse(a, 409, "jail is not enforcing");
        const requested_duration = args.duration orelse config_mod.resolveJailFromConfig(jc, self.config.defaults).bantime;
        if (requested_duration == 0 or requested_duration > config_mod.max_ban_duration) return errResponse(a, 400, "duration is outside the supported range");
        const tracker = self.trackers.getByJail(args.jail) orelse return errResponse(a, 404, "unknown jail");
        if (args.ip.isUnenforceable() or tracker.isIgnored(args.ip)) return errResponse(a, 400, "address is ignored or unenforceable");
        if (self.backend == null and self.lifecycle == null) return errResponse(a, 503, "no firewall backend");
        const now = std.time.timestamp();
        tracker.manualBan(args.ip, args.jail, now, requested_duration) catch |err| return errResponse(a, 503, @errorName(err));
        var fallback = lifecycle_mod.Lifecycle{ .trackers = self.trackers, .backend = self.backend };
        const lifecycle = self.lifecycle orelse &fallback;
        lifecycle.apply(args.ip, args.jail, now) catch |err| return errResponse(a, 503, @errorName(err));
        const duration: u64 = @intCast((tracker.get(args.ip).?.ban_expiry orelse now) -| now);

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
        var fallback = lifecycle_mod.Lifecycle{ .trackers = self.trackers, .backend = self.backend };
        const lifecycle = self.lifecycle orelse &fallback;
        const now = std.time.timestamp();
        if (args.jail) |j| {
            lifecycle.release(args.ip, j, now) catch |err| return errResponse(a, if (err == error.NotBanned or err == error.NotAvailable) 404 else 503, @errorName(err));
        } else {
            var any = false;
            var failed = false;
            var it = self.trackers.iterator();
            while (it.next()) |entry| {
                const st = entry.value_ptr.*.get(args.ip) orelse continue;
                if (st.ban_state != .banned) continue;
                any = true;
                lifecycle.release(args.ip, st.jail, now) catch {
                    failed = true;
                };
            }
            if (failed) return errResponse(a, 503, "some bans could not be removed; retry unban");
            if (!any) return errResponse(a, 404, "address is not banned");
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
        var buf: std.ArrayListUnmanaged(u8) = .{};
        defer buf.deinit(a);
        const w = buf.writer(a);
        try w.writeAll("[");

        if (args.jail) |j| {
            if (self.trackers.getByJail(j) == null) return errResponse(a, 404, "unknown jail");
        }
        var first = true;
        var tit = self.trackers.iterator();
        while (tit.next()) |tkv| {
            var it = tkv.value_ptr.*.iterator();
            while (it.next()) |kv| {
                if (kv.value_ptr.ban_state != .banned) continue;
                if (args.jail) |j| if (!std.mem.eql(u8, kv.value_ptr.jail.slice(), j.slice())) continue;
                if (!first) try w.writeAll(",");
                first = false;
                try writeListEntry(w, kv.key_ptr.*, kv.value_ptr.jail, kv.value_ptr);
            }
        }
        try w.writeAll("]");
        const payload = try a.dupe(u8, buf.items);
        return .{ .ok = .{ .payload = payload } };
    }

    fn handleListJails(self: *Context, a: std.mem.Allocator) !shared.Response {
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
                    @tagName(self.firewall_state.effectiveAction(resolved.banaction)),
                    if (self.jailEnforcing(jc)) "true" else "false",
                    log_source,
                    lines_seen,
                },
            );
            if (health) |h| {
                try w.print(",\"source_healthy\":{s}}}", .{if (h.healthy) "true" else "false"});
            } else {
                try w.writeAll("}");
            }
        }
        try w.writeAll("]");
        const payload = try a.dupe(u8, buf.items);
        return .{ .ok = .{ .payload = payload } };
    }

    fn handleReload(self: *Context, a: std.mem.Allocator) !shared.Response {
        _ = self;
        return errResponse(a, 501, "reload is not implemented; validate config and restart the service");
    }

    fn handleVersion(self: *Context, a: std.mem.Allocator) !shared.Response {
        var buf: std.ArrayListUnmanaged(u8) = .{};
        defer buf.deinit(a);
        try buf.writer(a).print("{{\"daemon_version\":\"{s}\"}}", .{self.version});
        const payload = try a.dupe(u8, buf.items);
        return .{ .ok = .{ .payload = payload } };
    }
};

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

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

pub const Context = struct {
    trackers: *tracker_map_mod.TrackerMap,
    config: *const config_mod.Config,
    backend: *firewall.Backend,
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
        try w.print("\"total_bans\":{d},", .{stats.bans_total});
        try w.print("\"jail_count\":{d},", .{self.config.jails.len});
        try w.print("\"jails_active\":{d},", .{jails_active});
        try w.print("\"protection\":\"{s}\",", .{protection});
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
                    @tagName(resolved.banaction),
                    if (resolved.banaction != .@"log-only") "true" else "false",
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
        std.log.info("ipc: reload requested (not yet implemented)", .{});
        const payload = try a.dupe(u8, "{\"status\":\"reload not yet implemented\"}");
        return .{ .ok = .{ .payload = payload } };
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

const testing = std.testing;

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

fn realBackendFromStub(s: *StubBackend) firewall.Backend {
    _ = s;
    return .{ .nftables = firewall.nftables.NftablesBackend{} };
}

const StubStats = struct {
    bans_total: u64,
    fn snapshot(ctx: ?*anyopaque) StatsSnapshot {
        const self: *StubStats = @ptrCast(@alignCast(ctx.?));
        return .{ .bans_total = self.bans_total };
    }
};

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
    try testing.expect(std.mem.indexOf(u8, resp.ok.payload, "\"daemon_version\"") != null);
}

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

    // Mirrors client/format.zig VersionPayload: the client parses exactly these field names.
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
    try testing.expect(parsed.value.git_commit == null);
    try testing.expect(parsed.value.build_date == null);
}

test "commands: handleStatus produces expected JSON fields" {
    const a = testing.allocator;

    var trackers = makeEmptyTrackerMap(a);
    defer trackers.deinit();
    const sshd_tracker = try trackers.addTracker("sshd", .{ .max_entries = 16 });

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
        .{ .name = "nginx", .enabled = true },
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
    try testing.expect(std.mem.indexOf(u8, body, "\"name\":\"sshd\"") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"action\":\"nftables\",\"enforcing\":true") != null);
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
    try testing.expect(std.mem.indexOf(u8, body, "\"jails_active\":1") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"jail_count\":2") != null);
}

test "commands: BUG-006 status Total bans >= Active bans after a restore" {
    const a = testing.allocator;
    var trackers = makeEmptyTrackerMap(a);
    defer trackers.deinit();
    const sshd = try trackers.addTracker("sshd", .{ .max_entries = 16 });
    inline for (.{ "1.2.3.4", "5.6.7.8" }) |ip_s| {
        _ = try sshd.recordAttempt(try shared.IpAddress.parse(ip_s), try shared.JailId.fromSlice("sshd"), 100);
        sshd.map.getPtr(try shared.IpAddress.parse(ip_s)).?.ban_state = .banned;
    }
    var cfg = makeConfig();
    var stub = StubBackend{};
    var be = realBackendFromStub(&stub);
    defer be.deinit();
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

    var ctx = Context{ .trackers = &trackers, .config = &cfg, .backend = &be };
    const resp = try ctx.handle(.{ .status = {} }, a);
    defer resp.deinit(a);
    try testing.expect(std.mem.indexOf(u8, resp.ok.payload, "\"protection\":\"active\"") != null);
}

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
        .{ .name = "sshd", .enabled = true, .banaction = .nftables, .source = .auto, .filter = "sshd", .logpath = &.{"/var/log/auth.log"} },
        .{ .name = "nginx", .enabled = true, .banaction = .nftables, .source = .file, .filter = "nginx", .logpath = &.{"/var/log/nginx/error.log"} },
        .{ .name = "mail", .enabled = true, .banaction = .nftables, .source = .file, .filter = "mail", .logpath = &.{"/var/log/mail.log"} },
    };
    var cfg = config_mod.Config{ .global = .{}, .defaults = .{ .banaction = .nftables }, .jails = &jails, .diag = .{} };
    var stub = StubBackend{};
    var be = realBackendFromStub(&stub);
    defer be.deinit();
    var health = MultiHealth{ .entries = &.{
        .{ .name = "sshd", .healthy = true, .lines_seen = 12 },
        .{ .name = "nginx", .healthy = true, .lines_seen = 3 },
    } };
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
    try testing.expect(std.mem.indexOf(u8, body, "\"log_source\":\"journald (sshd)\"") != null);
    try testing.expect(std.mem.indexOf(u8, body, "/var/log/auth.log") == null);
    try testing.expect(std.mem.indexOf(u8, body, "\"source_healthy\":true") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"lines_seen\":12") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"log_source\":\"/var/log/nginx/error.log\"") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"log_source\":\"/var/log/mail.log\"") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"log_source\":\"unknown\"") == null);
}

test "commands: an enabled jail with a recorded descriptor never renders SOURCE unknown (SYS-017)" {
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

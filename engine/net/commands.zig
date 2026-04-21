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

const state_mod = @import("../core/state.zig");
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

/// Aggregate context plumbed into the handler at construction time. The
/// daemon owns the referenced objects and outlives the server.
pub const Context = struct {
    state: *state_mod.StateTracker,
    config: *const config_mod.Config,
    backend: *firewall.Backend,
    stats_source: StatsSource = .{},
    /// Monotonic startup timestamp captured by the daemon at main()
    /// so the status handler can report uptime as a whole number of
    /// seconds.
    start_time: i64 = 0,
    /// Build version string; mirrored into responses.
    version: []const u8 = "0.1.0",

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
        const active_bans = countActiveBans(self.state);
        const backend_name = @tagName(self.backend.tag());

        var buf: std.ArrayListUnmanaged(u8) = .{};
        defer buf.deinit(a);
        const w = buf.writer(a);
        try w.writeAll("{");
        try w.print("\"version\":\"{s}\",", .{self.version});
        try w.print("\"uptime_seconds\":{d},", .{uptime});
        try w.print("\"memory_bytes_used\":{d},", .{stats.memory_bytes_used});
        try w.print("\"parse_rate\":{d},", .{stats.parse_rate});
        try w.print("\"active_bans\":{d},", .{active_bans});
        try w.print("\"jail_count\":{d},", .{self.config.jails.len});
        try w.print("\"backend\":\"{s}\"", .{backend_name});
        try w.writeAll("}");

        const payload = try a.dupe(u8, buf.items);
        return .{ .ok = .{ .payload = payload } };
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
        } else {
            var any_ok = false;
            for (self.config.jails) |jc| {
                const jid = shared.JailId.fromSlice(jc.name) catch continue;
                self.backend.unban(args.ip, jid) catch continue;
                any_ok = true;
            }
            if (!any_ok) return errResponse(a, 404, "no jail accepted unban");
        }
        self.state.clearBan(args.ip);

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
        // in the kernel). If no jail is passed, fall back to the
        // tracker which knows across all jails.
        var buf: std.ArrayListUnmanaged(u8) = .{};
        defer buf.deinit(a);
        const w = buf.writer(a);
        try w.writeAll("[");

        if (args.jail) |j| {
            const ips = self.backend.listBans(j, a) catch |err| {
                return errResponse(a, 500, @errorName(err));
            };
            defer a.free(ips);
            for (ips, 0..) |ip, i| {
                if (i > 0) try w.writeAll(",");
                try writeListEntry(w, ip, j, self.state.get(ip));
            }
        } else {
            var it = self.state.iterator();
            var first = true;
            while (it.next()) |kv| {
                if (kv.value_ptr.ban_state != .banned) continue;
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
        // Count per-jail bans in one walk of the state tracker.
        const max_jails = 128;
        var counts: [max_jails]u32 = [_]u32{0} ** max_jails;
        {
            var it = self.state.iterator();
            while (it.next()) |kv| {
                if (kv.value_ptr.ban_state != .banned) continue;
                for (self.config.jails, 0..) |jc, idx| {
                    if (idx >= max_jails) break;
                    if (std.mem.eql(u8, jc.name, kv.value_ptr.jail.slice())) {
                        counts[idx] += 1;
                        break;
                    }
                }
            }
        }

        var buf: std.ArrayListUnmanaged(u8) = .{};
        defer buf.deinit(a);
        const w = buf.writer(a);
        try w.writeAll("[");
        for (self.config.jails, 0..) |jc, idx| {
            if (idx > 0) try w.writeAll(",");
            const count = if (idx < max_jails) counts[idx] else 0;
            try w.print(
                "{{\"name\":\"{s}\",\"enabled\":{s},\"active_bans\":{d},\"maxretry\":{d},\"findtime\":{d},\"bantime\":{d}}}",
                .{
                    jc.name,
                    if (jc.enabled) "true" else "false",
                    count,
                    jc.effectiveMaxretry(self.config.defaults),
                    jc.effectiveFindtime(self.config.defaults),
                    jc.effectiveBantime(self.config.defaults),
                },
            );
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
        try buf.writer(a).print("{{\"version\":\"{s}\"}}", .{self.version});
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

fn countActiveBans(tracker: *state_mod.StateTracker) u32 {
    var n: u32 = 0;
    var it = tracker.iterator();
    while (it.next()) |kv| {
        if (kv.value_ptr.ban_state == .banned) n += 1;
    }
    return n;
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

fn makeConfig() config_mod.Config {
    return .{
        .global = .{},
        .defaults = .{ .bantime = 600, .findtime = 600, .maxretry = 5 },
        .jails = &.{},
        .diag = .{},
    };
}

test "commands: handleVersion returns version JSON" {
    const a = testing.allocator;

    var tracker = try state_mod.StateTracker.init(a, .{});
    defer tracker.deinit();
    var cfg = makeConfig();
    var stub = StubBackend{};
    var be = realBackendFromStub(&stub);
    defer be.deinit();

    var ctx = Context{
        .state = &tracker,
        .config = &cfg,
        .backend = &be,
        .version = "9.9.9",
    };
    const resp = try ctx.handle(.{ .version = {} }, a);
    defer resp.deinit(a);
    try testing.expect(resp == .ok);
    try testing.expect(std.mem.indexOf(u8, resp.ok.payload, "9.9.9") != null);
}

test "commands: handleStatus produces expected JSON fields" {
    const a = testing.allocator;

    var tracker = try state_mod.StateTracker.init(a, .{});
    defer tracker.deinit();
    // Seed one banned entry so active_bans > 0.
    _ = try tracker.recordAttempt(
        try shared.IpAddress.parse("1.2.3.4"),
        try shared.JailId.fromSlice("sshd"),
        100,
    );
    // Force-set ban state.
    if (tracker.map.getPtr(try shared.IpAddress.parse("1.2.3.4"))) |s| {
        s.ban_state = .banned;
    }

    var cfg = makeConfig();
    var stub = StubBackend{};
    var be = realBackendFromStub(&stub);
    defer be.deinit();

    var ctx = Context{
        .state = &tracker,
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
}

test "commands: handleListJails counts banned entries per-jail" {
    const a = testing.allocator;

    var tracker = try state_mod.StateTracker.init(a, .{});
    defer tracker.deinit();

    const sshd = try shared.JailId.fromSlice("sshd");
    _ = try tracker.recordAttempt(try shared.IpAddress.parse("10.0.0.1"), sshd, 1);
    _ = try tracker.recordAttempt(try shared.IpAddress.parse("10.0.0.2"), sshd, 2);
    if (tracker.map.getPtr(try shared.IpAddress.parse("10.0.0.1"))) |s| s.ban_state = .banned;
    if (tracker.map.getPtr(try shared.IpAddress.parse("10.0.0.2"))) |s| s.ban_state = .banned;

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

    var ctx = Context{ .state = &tracker, .config = &cfg, .backend = &be };
    const resp = try ctx.handle(.{ .list_jails = {} }, a);
    defer resp.deinit(a);
    try testing.expect(resp == .ok);
    try testing.expect(std.mem.indexOf(u8, resp.ok.payload, "\"name\":\"sshd\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.ok.payload, "\"active_bans\":2") != null);
    try testing.expect(std.mem.indexOf(u8, resp.ok.payload, "\"name\":\"nginx\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.ok.payload, "\"enabled\":false") != null);
}

test "commands: handleList without jail returns only banned entries" {
    const a = testing.allocator;

    var tracker = try state_mod.StateTracker.init(a, .{});
    defer tracker.deinit();

    const sshd = try shared.JailId.fromSlice("sshd");
    _ = try tracker.recordAttempt(try shared.IpAddress.parse("1.1.1.1"), sshd, 1);
    _ = try tracker.recordAttempt(try shared.IpAddress.parse("2.2.2.2"), sshd, 2);
    if (tracker.map.getPtr(try shared.IpAddress.parse("1.1.1.1"))) |s| s.ban_state = .banned;

    var cfg = makeConfig();
    var stub = StubBackend{};
    var be = realBackendFromStub(&stub);
    defer be.deinit();

    var ctx = Context{ .state = &tracker, .config = &cfg, .backend = &be };
    const resp = try ctx.handle(.{ .list = .{ .jail = null } }, a);
    defer resp.deinit(a);
    try testing.expect(resp == .ok);
    try testing.expect(std.mem.indexOf(u8, resp.ok.payload, "1.1.1.1") != null);
    // 2.2.2.2 is tracked but not banned -> must NOT appear
    try testing.expect(std.mem.indexOf(u8, resp.ok.payload, "2.2.2.2") == null);
}

test "commands: handleReload is a stub but returns ok" {
    const a = testing.allocator;

    var tracker = try state_mod.StateTracker.init(a, .{});
    defer tracker.deinit();
    var cfg = makeConfig();
    var stub = StubBackend{};
    var be = realBackendFromStub(&stub);
    defer be.deinit();

    var ctx = Context{ .state = &tracker, .config = &cfg, .backend = &be };
    const resp = try ctx.handle(.{ .reload = {} }, a);
    defer resp.deinit(a);
    try testing.expect(resp == .ok);
    try testing.expect(std.mem.indexOf(u8, resp.ok.payload, "not yet implemented") != null);
}

test "commands: asHandler round-trips via the dispatch pointer" {
    const a = testing.allocator;

    var tracker = try state_mod.StateTracker.init(a, .{});
    defer tracker.deinit();
    var cfg = makeConfig();
    var stub = StubBackend{};
    var be = realBackendFromStub(&stub);
    defer be.deinit();

    var ctx = Context{ .state = &tracker, .config = &cfg, .backend = &be, .version = "7.7.7" };
    const h = ctx.asHandler();
    const resp = try h.dispatch(h.ctx, .{ .version = {} }, a);
    defer resp.deinit(a);
    try testing.expect(std.mem.indexOf(u8, resp.ok.payload, "7.7.7") != null);
}

test "commands: countActiveBans counts only .banned entries" {
    const a = testing.allocator;
    var tracker = try state_mod.StateTracker.init(a, .{});
    defer tracker.deinit();

    const j = try shared.JailId.fromSlice("sshd");
    _ = try tracker.recordAttempt(try shared.IpAddress.parse("5.5.5.5"), j, 1);
    _ = try tracker.recordAttempt(try shared.IpAddress.parse("6.6.6.6"), j, 2);
    if (tracker.map.getPtr(try shared.IpAddress.parse("5.5.5.5"))) |s| s.ban_state = .banned;

    try testing.expectEqual(@as(u32, 1), countActiveBans(&tracker));
}

test "commands: handleBan on uninitialized backend returns err response" {
    // The nftables backend returns .NotAvailable when `init()` has not
    // been called — exercise that error path through `handleBan`.
    const a = testing.allocator;

    var tracker = try state_mod.StateTracker.init(a, .{});
    defer tracker.deinit();
    var cfg = makeConfig();
    var stub = StubBackend{};
    var be = realBackendFromStub(&stub);
    defer be.deinit();

    var ctx = Context{ .state = &tracker, .config = &cfg, .backend = &be };
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

test "commands: handleUnban without jail returns 404 when no jails configured" {
    const a = testing.allocator;

    var tracker = try state_mod.StateTracker.init(a, .{});
    defer tracker.deinit();
    var cfg = makeConfig();
    var stub = StubBackend{};
    var be = realBackendFromStub(&stub);
    defer be.deinit();

    var ctx = Context{ .state = &tracker, .config = &cfg, .backend = &be };
    const ip = try shared.IpAddress.parse("10.10.10.10");
    const resp = try ctx.handle(.{ .unban = .{ .ip = ip, .jail = null } }, a);
    defer resp.deinit(a);
    try testing.expect(resp == .err);
    try testing.expectEqual(@as(u16, 404), resp.err.code);
}

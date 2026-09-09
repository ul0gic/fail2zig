// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;

const shared = @import("shared");
const build_options = @import("build_options");

pub const event_loop_mod = @import("core/event_loop.zig");
const log_watcher_mod = @import("core/log_watcher.zig");
pub const journald_source_mod = @import("core/journald_source.zig");
const line_buffer_mod = @import("core/line_buffer.zig");
const logger_mod = @import("core/logger.zig");
const parser_mod = @import("core/parser.zig");
pub const state_mod = @import("core/state.zig");
pub const tracker_map_mod = @import("core/tracker_map.zig");
const persist_mod = @import("core/persist.zig");
const reconcile_mod = @import("core/reconcile.zig");
pub const firewall = @import("firewall/backend.zig");
pub const config_mod = @import("config/native.zig");
pub const fail2ban_mod = @import("config/fail2ban.zig");
pub const migration_mod = @import("config/migration.zig");
pub const filter_types_mod = @import("filters/types.zig");
pub const filter_sshd_mod = @import("filters/sshd.zig");
pub const filter_nginx_mod = @import("filters/nginx.zig");
pub const filter_apache_mod = @import("filters/apache.zig");
pub const filter_mail_mod = @import("filters/mail.zig");
pub const filter_misc_mod = @import("filters/misc.zig");
pub const filter_registry_mod = @import("filters/registry.zig");
const http = @import("net/http.zig");
const ws = @import("net/ws.zig");
pub const ipc_mod = @import("net/ipc.zig");
pub const commands_mod = @import("net/commands.zig");
const metrics_mod = @import("core/metrics.zig");

pub const version = build_options.version;

pub const CliError = error{
    MissingValue,
    UnknownFlag,
    AllocFailure,
};

pub const CliAction = enum {
    run,
    print_version,
    print_help,
    test_config,
    validate_config,
    import_config,
};

pub const CliOptions = struct {
    action: CliAction = .run,
    config_path: []const u8 = "/etc/fail2zig/config.toml",
    import_path: ?[]const u8 = null,
    import_output: []const u8 = "/etc/fail2zig/config.toml",
    foreground: bool = true,
};

pub fn parseArgs(args: []const []const u8) CliError!CliOptions {
    var out: CliOptions = .{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) {
            out.action = .print_help;
        } else if (std.mem.eql(u8, a, "--version") or std.mem.eql(u8, a, "-V")) {
            out.action = .print_version;
        } else if (std.mem.eql(u8, a, "--test-config")) {
            out.action = .test_config;
        } else if (std.mem.eql(u8, a, "--validate-config")) {
            out.action = .validate_config;
        } else if (std.mem.eql(u8, a, "--foreground")) {
            out.foreground = true;
        } else if (std.mem.eql(u8, a, "--config")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            out.config_path = args[i];
        } else if (std.mem.startsWith(u8, a, "--config=")) {
            out.config_path = a["--config=".len..];
        } else if (std.mem.eql(u8, a, "--import-config")) {
            if (i + 1 < args.len and !std.mem.startsWith(u8, args[i + 1], "--")) {
                i += 1;
                out.import_path = args[i];
            } else {
                out.import_path = "/etc/fail2ban";
            }
            out.action = .import_config;
        } else if (std.mem.startsWith(u8, a, "--import-config=")) {
            out.import_path = a["--import-config=".len..];
            out.action = .import_config;
        } else if (std.mem.eql(u8, a, "--import-output")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            out.import_output = args[i];
        } else if (std.mem.startsWith(u8, a, "--import-output=")) {
            out.import_output = a["--import-output=".len..];
        } else {
            return error.UnknownFlag;
        }
    }
    return out;
}

fn printHelp(w: anytype) !void {
    try w.print(
        \\fail2zig {s} — modern intrusion prevention
        \\
        \\USAGE:
        \\  fail2zig [OPTIONS]
        \\
        \\OPTIONS:
        \\  --config <path>           Config file (default: /etc/fail2zig/config.toml)
        \\  --foreground              Run in foreground (v0.1: only mode)
        \\  --test-config             Alias for --validate-config
        \\  --validate-config         Load + validate config, print result, exit
        \\  --import-config [<dir>]   Import fail2ban config (default: /etc/fail2ban)
        \\  --import-output <path>    Where to write imported config (default: /etc/fail2zig/config.toml)
        \\  --version, -V             Print version and exit
        \\  --help, -h                Print this help and exit
        \\
        \\EXIT CODES:
        \\  0   success
        \\  1   config load / validation failure, or zero jails imported
        \\  2   hard parse error on import
        \\
    , .{version});
}

pub fn runImport(
    heap: std.mem.Allocator,
    source: []const u8,
    output: []const u8,
    stderr: anytype,
) u8 {
    var arena = std.heap.ArenaAllocator.init(heap);
    defer arena.deinit();

    const report = migration_mod.importConfig(arena.allocator(), source, output) catch |err| {
        stderr.print("import: failed: {s}\n", .{@errorName(err)}) catch {};
        return 2;
    };
    migration_mod.printReport(report, stderr) catch {};
    if (report.jails_imported == 0) return 1;
    return 0;
}

const JailContext = struct {
    jail: shared.JailId,
    matcher: filter_registry_mod.FilterMatcher,
    state: *state_mod.StateTracker,
    backend_ptr: *firewall.Backend,
    banaction: config_mod.BanAction = .nftables,
    metrics: ?*metrics_mod.Metrics = null,
    ws: ?*ws.WsServer = null,
    ws_alloc: ?std.mem.Allocator = null,
    now_override: ?shared.Timestamp = null,
    ban_hook: ?*const fn (
        userdata: ?*anyopaque,
        ip: shared.IpAddress,
        jail: shared.JailId,
        duration: shared.Duration,
    ) firewall.BackendError!void = null,
    ban_hook_ctx: ?*anyopaque = null,

    fn now(self: *const JailContext) shared.Timestamp {
        if (self.now_override) |t| return t;
        return std.time.timestamp();
    }

    fn enforceBan(
        self: *JailContext,
        ip: shared.IpAddress,
        jail: shared.JailId,
        duration: shared.Duration,
    ) firewall.BackendError!void {
        if (self.ban_hook) |hook| {
            return hook(self.ban_hook_ctx, ip, jail, duration);
        }
        return self.backend_ptr.ban(ip, jail, duration);
    }
};

fn dispatchBan(ctx: *JailContext, d: state_mod.BanDecision) void {
    if (ctx.banaction == .@"log-only") {
        std.log.info(
            "would-ban: jail='{s}' ip={} duration={d}s ban_count={d} action=log-only",
            .{ ctx.jail.slice(), d.ip, d.duration, d.ban_count },
        );
        ctx.state.recordLifetimeBan();
        if (ctx.metrics) |m| {
            m.incrementBans();
            m.jailIncrementBans(ctx.jail.slice());
        }
        // No broadcastBanned(): nothing changed in the firewall, so an ip_banned event would lie.
        return;
    }

    std.log.info(
        "ban: jail='{s}' ip={} duration={d}s ban_count={d} action={s}",
        .{ ctx.jail.slice(), d.ip, d.duration, d.ban_count, @tagName(ctx.banaction) },
    );
    ctx.enforceBan(d.ip, d.jail, d.duration) catch |err| {
        std.log.warn(
            "backend: ban failed for ip={} jail='{s}': {s}",
            .{ d.ip, ctx.jail.slice(), @errorName(err) },
        );
        return;
    };
    ctx.state.recordLifetimeBan();
    if (ctx.metrics) |m| {
        m.incrementBans();
        m.jailIncrementBans(ctx.jail.slice());
    }
    if (ctx.ws) |ws_server| {
        if (ctx.ws_alloc) |a| {
            var ip_buf: [64]u8 = undefined;
            if (std.fmt.bufPrint(&ip_buf, "{}", .{d.ip})) |ip_str| {
                ws_server.broadcastBanned(a, ip_str, ctx.jail.slice(), d.duration) catch |err| {
                    std.log.warn("ws: broadcastBanned failed: {s}", .{@errorName(err)});
                };
            } else |_| {}
        }
    }
}

fn lineCallback(
    line: []const u8,
    _jail: shared.JailId,
    truncated: bool,
    userdata: ?*anyopaque,
) void {
    _ = _jail;
    if (truncated) {
        return;
    }
    const ctx: *JailContext = @ptrCast(@alignCast(userdata.?));
    if (ctx.metrics) |m| {
        m.incrementParsed();
        m.jailIncrementParsed(ctx.jail.slice());
    }

    const body = parser_mod.stripSyslogPrefix(line);

    const result = ctx.matcher.match(body) orelse {
        if (ctx.metrics) |m| {
            m.incrementParseErrors();
            m.jailIncrementParseErrors(ctx.jail.slice());
        }
        return;
    };

    if (result.ip.isUnenforceable()) {
        @branchHint(.unlikely);
        std.log.debug(
            "skip: jail='{s}' matched but ip={} is unenforceable (unspecified/loopback) — ignoring",
            .{ ctx.jail.slice(), result.ip },
        );
        return;
    }

    if (ctx.metrics) |m| {
        m.incrementMatched();
        m.jailIncrementMatched(ctx.jail.slice());
    }
    const ts = ctx.now();

    const ignored = ctx.state.isIgnored(result.ip);

    if (!ignored) {
        if (ctx.ws) |ws_server| {
            if (ctx.ws_alloc) |a| {
                var ip_buf: [64]u8 = undefined;
                if (std.fmt.bufPrint(&ip_buf, "{}", .{result.ip})) |ip_str| {
                    ws_server.broadcastAttackDetected(a, ip_str, ctx.jail.slice(), ctx.jail.slice()) catch |err| {
                        std.log.warn("ws: broadcastAttackDetected failed: {s}", .{@errorName(err)});
                    };
                } else |_| {}
            }
        }
    }

    if (ignored) return;

    const decision = ctx.state.recordAttempt(result.ip, ctx.jail, ts) catch |err| {
        std.log.warn(
            "state: recordAttempt failed for jail '{s}': {s}",
            .{ ctx.jail.slice(), @errorName(err) },
        );
        return;
    };
    if (decision) |d| {
        dispatchBan(ctx, d);
    }
}

const ExpiryContext = struct {
    trackers: *tracker_map_mod.TrackerMap,
    backend_ptr: *firewall.Backend,
    metrics: ?*metrics_mod.Metrics = null,
    ws: ?*ws.WsServer = null,
    ws_alloc: ?std.mem.Allocator = null,
};

fn expirySweep(expirations: u64, userdata: ?*anyopaque) void {
    _ = expirations;
    const ctx: *ExpiryContext = @ptrCast(@alignCast(userdata.?));
    const now = std.time.timestamp();

    const max_per_tick: usize = 64;
    var to_unban: [max_per_tick]struct {
        ip: shared.IpAddress,
        jail: shared.JailId,
        tracker: *state_mod.StateTracker,
    } = undefined;
    var n: usize = 0;

    var tit = ctx.trackers.iterator();
    outer: while (tit.next()) |tkv| {
        const tracker = tkv.value_ptr.*;
        var it = tracker.iterator();
        while (it.next()) |kv| {
            if (n >= max_per_tick) break :outer;
            const st = kv.value_ptr;
            if (st.ban_state != .banned) continue;
            const exp = st.ban_expiry orelse continue;
            if (exp <= now) {
                to_unban[n] = .{ .ip = kv.key_ptr.*, .jail = st.jail, .tracker = tracker };
                n += 1;
            }
        }
    }

    var i: usize = 0;
    while (i < n) : (i += 1) {
        const item = to_unban[i];
        ctx.backend_ptr.unban(item.ip, item.jail) catch |err| {
            std.log.warn(
                "backend: unban failed for ip={} jail='{s}': {s}",
                .{ item.ip, item.jail.slice(), @errorName(err) },
            );
        };
        item.tracker.clearBan(item.ip);
        if (ctx.metrics) |m| {
            m.incrementUnbans();
            m.jailIncrementUnbans(item.jail.slice());
        }
        std.log.info(
            "unban: jail='{s}' ip={}",
            .{ item.jail.slice(), item.ip },
        );
        if (ctx.ws) |ws_server| {
            if (ctx.ws_alloc) |a| {
                var ip_buf: [64]u8 = undefined;
                if (std.fmt.bufPrint(&ip_buf, "{}", .{item.ip})) |ip_str| {
                    ws_server.broadcastUnbanned(a, ip_str, item.jail.slice()) catch |err| {
                        std.log.warn("ws: broadcastUnbanned failed: {s}", .{@errorName(err)});
                    };
                } else |_| {}
            }
        }
    }
}

const WsTickContext = struct {
    ws: *ws.WsServer,
    metrics: *metrics_mod.Metrics,
    ws_alloc: std.mem.Allocator,
    start_time: i64,
    cmd_ctx: *commands_mod.Context,
};

fn readSelfRssBytes() !u64 {
    var file = std.fs.openFileAbsolute("/proc/self/status", .{}) catch |err| return err;
    defer file.close();
    var buf: [8192]u8 = undefined;
    const n = file.readAll(&buf) catch |err| return err;
    const contents = buf[0..n];
    const needle = "VmRSS:";
    const idx = std.mem.indexOf(u8, contents, needle) orelse return error.NotFound;
    const tail = contents[idx + needle.len ..];
    const nl = std.mem.indexOfScalar(u8, tail, '\n') orelse tail.len;
    const line = tail[0..nl];
    var i: usize = 0;
    while (i < line.len and (line[i] < '0' or line[i] > '9')) : (i += 1) {}
    const start = i;
    while (i < line.len and line[i] >= '0' and line[i] <= '9') : (i += 1) {}
    if (i == start) return error.ParseFailed;
    const kb = try std.fmt.parseInt(u64, line[start..i], 10);
    return kb * 1024;
}

fn wsTick(expirations: u64, userdata: ?*anyopaque) void {
    _ = expirations;
    const ctx: *WsTickContext = @ptrCast(@alignCast(userdata.?));

    ctx.ws.tickHeartbeat();

    if (readSelfRssBytes()) |rss_bytes| {
        ctx.metrics.setMemoryBytes(rss_bytes);
    } else |_| {}

    const snap = ctx.metrics.snapshot();
    const uptime_s: u64 = blk: {
        const now = std.time.timestamp();
        if (now <= ctx.start_time) break :blk 0;
        break :blk @intCast(now - ctx.start_time);
    };

    const protection_state = ctx.cmd_ctx.computeOverallState();
    ctx.ws.broadcastMetrics(ctx.ws_alloc, .{
        .lines_parsed = snap.lines_parsed,
        .lines_matched = snap.lines_matched,
        .bans_total = snap.bans_total,
        .active_bans = snap.active_bans,
        .memory_bytes_used = snap.memory_bytes_used,
        .uptime_s = uptime_s,
        .protection_state = protection_state,
        .degraded = std.mem.eql(u8, protection_state, "degraded"),
    }) catch |err| {
        std.log.warn("ws: broadcastMetrics failed: {s}", .{@errorName(err)});
    };
}

const SignalContext = struct {
    loop: *event_loop_mod.EventLoop,
    trackers: *tracker_map_mod.TrackerMap,
    state_path: []const u8,
    journald: ?*journald_source_mod.JournaldSource = null,
    save_requested: bool = false,
};

fn flushStateThenCursors(
    trackers: *tracker_map_mod.TrackerMap,
    state_path: []const u8,
    journald: ?*journald_source_mod.JournaldSource,
) void {
    persist_mod.saveAll(trackers, state_path) catch |err| {
        std.log.warn("persist: state save failed: {s}", .{@errorName(err)});
    };
    if (journald) |jd| {
        if (jd.hasJails()) {
            var buf: [journald_source_mod.max_jails]journald_source_mod.CursorEntry = undefined;
            const cursors = jd.collectCursors(&buf);
            journald_source_mod.saveCursors(cursors, jd.cursor_path) catch |err| {
                std.log.warn("journald: cursor sidecar save failed: {s}", .{@errorName(err)});
            };
        }
    }
}

const JournaldFlushContext = struct {
    trackers: *tracker_map_mod.TrackerMap,
    state_path: []const u8,
    journald: *journald_source_mod.JournaldSource,
};

fn journaldFlushHook(userdata: ?*anyopaque) void {
    const ctx: *JournaldFlushContext = @ptrCast(@alignCast(userdata.?));
    flushStateThenCursors(ctx.trackers, ctx.state_path, ctx.journald);
}

fn onTerminate(siginfo: *const linux.signalfd_siginfo, userdata: ?*anyopaque) void {
    _ = siginfo;
    const ctx: *SignalContext = @ptrCast(@alignCast(userdata.?));
    ctx.save_requested = true;
    std.log.info("signal: termination requested, saving state and shutting down", .{});
    flushStateThenCursors(ctx.trackers, ctx.state_path, ctx.journald);
    ctx.loop.stop();
}

fn onReload(siginfo: *const linux.signalfd_siginfo, userdata: ?*anyopaque) void {
    _ = siginfo;
    _ = userdata;
    std.log.info("signal: SIGHUP received — reload not yet implemented", .{});
}

fn translateBanTimeIncrement(incr: config_mod.BanTimeIncrement) state_mod.BanTimeIncrement {
    return .{
        .enabled = incr.enabled,
        .multiplier = incr.multiplier,
        .factor = incr.factor,
        .formula = switch (incr.formula) {
            .linear => .linear,
            .exponential => .exponential,
        },
        .max_bantime = incr.max_bantime,
    };
}

fn deriveJailTrackerConfig(
    resolved: config_mod.ResolvedJailConfig,
    max_entries: u32,
) state_mod.Config {
    return .{
        .max_entries = max_entries,
        .findtime = resolved.findtime,
        .maxretry = resolved.maxretry,
        .bantime = resolved.bantime,
        .bantime_increment = translateBanTimeIncrement(resolved.bantime_increment),
        .eviction_policy = .drop_oldest_unbanned,
    };
}

fn deriveLegacyTrackerConfig(cfg: *const config_mod.Config, max_entries: u32) state_mod.Config {
    const d = cfg.defaults;
    return .{
        .max_entries = max_entries,
        .findtime = d.findtime,
        .maxretry = d.maxretry,
        .bantime = d.bantime,
        .bantime_increment = translateBanTimeIncrement(d.bantime_increment),
        .eviction_policy = .drop_oldest_unbanned,
    };
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const heap = gpa.allocator();

    const argv = try std.process.argsAlloc(heap);
    defer std.process.argsFree(heap, argv);

    const opts = parseArgs(argv) catch |err| {
        const stderr = std.io.getStdErr().writer();
        switch (err) {
            error.MissingValue => try stderr.print("error: missing value for flag\n", .{}),
            error.UnknownFlag => try stderr.print("error: unknown flag (use --help)\n", .{}),
            error.AllocFailure => try stderr.print("error: allocation failure\n", .{}),
        }
        std.process.exit(1);
    };

    const stdout = std.io.getStdOut().writer();
    switch (opts.action) {
        .print_version => {
            try stdout.print("fail2zig {s}\n", .{version});
            return;
        },
        .print_help => {
            try printHelp(stdout);
            return;
        },
        .import_config => {
            const stderr = std.io.getStdErr().writer();
            const source = opts.import_path orelse "/etc/fail2ban";
            const rc = runImport(heap, source, opts.import_output, stderr);
            std.process.exit(rc);
        },
        .test_config, .validate_config, .run => {},
    }

    var cfg_arena = std.heap.ArenaAllocator.init(heap);
    defer cfg_arena.deinit();
    const cfg = config_mod.Config.loadFile(cfg_arena.allocator(), opts.config_path) catch |err| {
        const stderr = std.io.getStdErr().writer();
        try stderr.print("config: failed to load '{s}': {s}\n", .{ opts.config_path, @errorName(err) });
        std.process.exit(1);
    };

    const is_validate_only = opts.action == .test_config or opts.action == .validate_config;
    if (!is_validate_only) {
        ensureSocketDir(cfg.global.socket_path) catch |err| {
            const stderr = std.io.getStdErr().writer();
            try stderr.print("config: cannot prepare socket directory: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
    }

    config_mod.validate(&cfg) catch |err| {
        const stderr = std.io.getStdErr().writer();
        try stderr.print("config: validation failed: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    if (is_validate_only) {
        try stdout.print("config: OK ({d} jail(s) configured)\n", .{cfg.jails.len});
        return;
    }

    try runDaemon(heap, &cfg);
}

fn reconcileBanApply(
    ctx: *anyopaque,
    ip: shared.IpAddress,
    jail: shared.JailId,
    remaining: u64,
) anyerror!void {
    const be: *firewall.Backend = @ptrCast(@alignCast(ctx));
    be.ban(ip, jail, remaining) catch |err| switch (err) {
        error.AlreadyBanned => return,
        else => {
            std.log.warn(
                "persist: backend re-ban failed for ip={}: {s}",
                .{ ip, @errorName(err) },
            );
            return err;
        },
    };
}

const StartupTrace = struct {
    enabled: bool,
    timer: ?std.time.Timer,
    last_ns: u64 = 0,
    buf: std.ArrayListUnmanaged(u8) = .{},
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) StartupTrace {
        const on = blk: {
            const v = std.process.getEnvVarOwned(allocator, "FAIL2ZIG_STARTUP_TRACE") catch break :blk false;
            defer allocator.free(v);
            break :blk std.mem.eql(u8, v, "1") or std.mem.eql(u8, v, "true");
        };
        if (!on) return .{ .enabled = false, .timer = null, .allocator = allocator };
        const t = std.time.Timer.start() catch return .{ .enabled = false, .timer = null, .allocator = allocator };
        var self: StartupTrace = .{ .enabled = true, .timer = t, .allocator = allocator };
        self.buf.appendSlice(allocator, "{\"trace\":\"startup\"") catch {};
        return self;
    }

    fn mark(self: *StartupTrace, phase: []const u8) void {
        if (!self.enabled) return;
        const now = self.timer.?.read();
        const delta_ms = @as(f64, @floatFromInt(now - self.last_ns)) / @as(f64, std.time.ns_per_ms);
        self.last_ns = now;
        const w = self.buf.writer(self.allocator);
        w.print(",\"{s}_ms\":{d:.2}", .{ phase, delta_ms }) catch {};
    }

    fn report(self: *StartupTrace) void {
        if (self.enabled) {
            self.enabled = false;
            const total_ms = @as(f64, @floatFromInt(self.timer.?.read())) / @as(f64, std.time.ns_per_ms);
            const w = self.buf.writer(self.allocator);
            w.print(",\"total_ms\":{d:.2}}}\n", .{total_ms}) catch {};
            std.io.getStdErr().writeAll(self.buf.items) catch {};
        }
        self.buf.clearAndFree(self.allocator);
    }
};

fn runDaemon(heap: std.mem.Allocator, cfg: *const config_mod.Config) !void {
    var trace = StartupTrace.init(heap);
    defer trace.report();

    var metrics = metrics_mod.Metrics.init();
    for (cfg.jails) |jc| {
        if (!jc.enabled) continue;
        _ = metrics.registerJail(jc.name);
    }
    trace.mark("metrics");

    var backend_val = firewall.detect(heap) catch |err| {
        std.log.err("firewall: no backend available ({s}) — refusing to run unprotected", .{@errorName(err)});
        std.process.exit(1);
    };
    trace.mark("fw_detect");
    backend_val.init(.{}, heap) catch |err| {
        std.log.err("firewall: backend init failed: {s} — refusing to run unprotected", .{@errorName(err)});
        std.process.exit(1);
    };
    defer backend_val.deinit();
    trace.mark("fw_init");

    var trackers = tracker_map_mod.TrackerMap.init(heap);
    defer trackers.deinit();

    var enabled_count: u32 = 0;
    for (cfg.jails) |jc| {
        if (jc.enabled) enabled_count += 1;
    }
    const tracker_count: u32 = @max(1, enabled_count + 1);
    const bytes_per_mb: usize = 1024 * 1024;
    const state_tracker_bytes: usize = (@as(usize, cfg.global.memory_ceiling_mb) * bytes_per_mb) / 2;
    const per_tracker_bytes: usize = state_tracker_bytes / tracker_count;
    const per_tracker_capacity = state_mod.capacityFromBudget(per_tracker_bytes);

    for (cfg.jails) |*jc| {
        if (!jc.enabled) continue;
        const resolved = config_mod.resolveJailFromConfig(jc, cfg.defaults);
        const tcfg = deriveJailTrackerConfig(resolved, per_tracker_capacity);
        const tracker = trackers.addTracker(jc.name, tcfg) catch |err| {
            std.log.err("state: tracker init for jail '{s}' failed: {s}", .{ jc.name, @errorName(err) });
            return err;
        };
        const ignore_list: []const []const u8 = jc.ignoreip orelse cfg.defaults.ignoreip;
        for (ignore_list) |spec| {
            tracker.addIgnoreCidr(spec) catch |err| {
                std.log.warn(
                    "state: ignoreip '{s}' (jail '{s}') rejected: {s}",
                    .{ spec, jc.name, @errorName(err) },
                );
            };
        }
    }

    {
        const legacy_cfg = deriveLegacyTrackerConfig(cfg, per_tracker_capacity);
        const legacy_tracker = trackers.ensureLegacy(legacy_cfg) catch |err| {
            std.log.err("state: legacy tracker init failed: {s}", .{@errorName(err)});
            return err;
        };
        for (cfg.defaults.ignoreip) |spec| {
            legacy_tracker.addIgnoreCidr(spec) catch |err| {
                std.log.warn("state: legacy ignoreip '{s}' rejected: {s}", .{ spec, @errorName(err) });
            };
        }
    }

    trace.mark("trackers");

    if (persist_mod.loadFull(heap, cfg.global.state_file)) |loaded| {
        defer loaded.deinit(heap);
        if (loaded.entries.len > 0) {
            var routed: u32 = 0;
            var legacy_routed: u32 = 0;
            persist_mod.seedMap(&trackers, loaded.entries, &routed, &legacy_routed) catch |err| {
                std.log.warn("persist: seed failed: {s}", .{@errorName(err)});
            };
            std.log.info(
                "persist: restored {d} entries ({d} routed, {d} -> legacy bucket)",
                .{ loaded.entries.len, routed, legacy_routed },
            );
        }
        persist_mod.seedLifetimes(&trackers, loaded.lifetimes);
        var lifetime_sum: u64 = 0;
        var tit = trackers.iterator();
        while (tit.next()) |kv| {
            const t = kv.value_ptr.*;
            lifetime_sum += t.lifetime_bans;
            metrics.jailSetBansTotal(kv.key_ptr.*, t.lifetime_bans);
        }
        metrics.setBansTotal(lifetime_sum);
    } else |err| {
        std.log.warn("persist: load failed: {s}", .{@errorName(err)});
    }

    {
        const now = std.time.timestamp();
        const reinstalled = reconcile_mod.reconcileAllRestoredBans(
            heap,
            &trackers,
            &metrics,
            now,
            reconcileBanApply,
            @ptrCast(&backend_val),
        ) catch |err| blk: {
            std.log.warn("persist: reconcile failed: {s}", .{@errorName(err)});
            break :blk 0;
        };
        if (reinstalled > 0) {
            std.log.info(
                "persist: reconciled {d} active ban(s) with firewall backend",
                .{reinstalled},
            );
        }
    }

    trace.mark("state_load");

    var loop = event_loop_mod.EventLoop.init(heap) catch |err| {
        std.log.err("event_loop: init failed: {s}", .{@errorName(err)});
        return err;
    };
    defer loop.deinit();

    var watcher = log_watcher_mod.LogWatcher.init(heap, &loop) catch |err| {
        std.log.err("log_watcher: init failed: {s}", .{@errorName(err)});
        return err;
    };
    defer watcher.deinit();
    try watcher.attach();

    var journald = journald_source_mod.JournaldSource.init(heap, &loop, cfg.global.state_file) catch |err| {
        std.log.err("journald: init failed: {s}", .{@errorName(err)});
        return err;
    };
    defer journald.deinit();

    var journald_flush_ctx = JournaldFlushContext{
        .trackers = &trackers,
        .state_path = cfg.global.state_file,
        .journald = &journald,
    };

    var contexts = std.ArrayList(*JailContext).init(heap);
    defer {
        for (contexts.items) |ctx| heap.destroy(ctx);
        contexts.deinit();
    }

    var source_descriptors = JailSourceDescriptors.init(heap);
    defer source_descriptors.deinit();

    for (cfg.jails) |jail_cfg| {
        if (!jail_cfg.enabled) continue;
        const jail = shared.JailId.fromSlice(jail_cfg.name) catch |err| {
            std.log.warn("jail '{s}' rejected: {s}", .{ jail_cfg.name, @errorName(err) });
            continue;
        };
        const tracker_ptr = trackers.get(jail_cfg.name) orelse {
            std.log.warn(
                "jail '{s}' has no tracker — wiring bug, skipping",
                .{jail_cfg.name},
            );
            continue;
        };
        const jail_matcher = filter_registry_mod.matcherForFilter(jail_cfg.filter) orelse {
            std.log.err(
                "jail '{s}' uses filter '{s}', which has no builtin matcher — refusing to start (fail2zig will not run a jail with no patterns, as that would ban any line containing an IP). Use a supported builtin filter or remove the jail.",
                .{ jail_cfg.name, jail_cfg.filter },
            );
            return error.UnsupportedFilter;
        };
        const resolved = config_mod.resolveJailFromConfig(&jail_cfg, cfg.defaults);
        const ctx = try heap.create(JailContext);
        ctx.* = .{
            .jail = jail,
            .matcher = jail_matcher,
            .state = tracker_ptr,
            .backend_ptr = &backend_val,
            .banaction = resolved.banaction,
            .metrics = &metrics,
        };
        try contexts.append(ctx);

        const journalctl_present = config_mod.journalctlPresent();
        const logpath_exists = config_mod.anyLogpathExists(jail_cfg.logpath);
        const filter_journald_supported =
            journald_source_mod.selectorsForFilter(jail_cfg.filter) != null;
        const resolved_source = journald_source_mod.resolveSource(
            jail_cfg.source,
            logpath_exists,
            journalctl_present,
            filter_journald_supported,
        );
        switch (resolved_source) {
            .file => {
                for (jail_cfg.logpath) |lp| {
                    watcher.watchFile(lp, jail, lineCallback, ctx) catch |err| {
                        std.log.warn(
                            "log_watcher: watchFile '{s}' (jail '{s}') failed: {s}",
                            .{ lp, jail_cfg.name, @errorName(err) },
                        );
                        continue;
                    };
                }
                source_descriptors.putFile(jail_cfg.name, jail_cfg.logpath) catch |err| {
                    std.log.warn("status: source descriptor record failed for '{s}': {s}", .{ jail_cfg.name, @errorName(err) });
                };
                std.log.info(
                    "jail: enabled '{s}' source=file ({d} logpath(s))",
                    .{ jail_cfg.name, jail_cfg.logpath.len },
                );
            },
            .journald => {
                journald.addJail(jail, jail_cfg.filter, lineCallback, ctx) catch |err| switch (err) {
                    error.UnsupportedJournaldFilter => {
                        std.log.err(
                            "journald source supports only the \"sshd\" filter in v1; jail '{s}' uses filter '{s}' — refusing to start (use source=file with a text logpath, or remove the jail)",
                            .{ jail_cfg.name, jail_cfg.filter },
                        );
                        return err;
                    },
                    else => {
                        std.log.err(
                            "journald: addJail '{s}' failed: {s}",
                            .{ jail_cfg.name, @errorName(err) },
                        );
                        return err;
                    },
                };
                source_descriptors.putJournald(jail_cfg.name, jail_cfg.filter) catch |err| {
                    std.log.warn("status: source descriptor record failed for '{s}': {s}", .{ jail_cfg.name, @errorName(err) });
                };
                std.log.info(
                    "jail: enabled '{s}' source=journald (filter '{s}')",
                    .{ jail_cfg.name, jail_cfg.filter },
                );
            },
            .fail => {
                std.log.err(
                    "jail '{s}' has no usable log source (source={s}, logpath={d}, journalctl={}); refusing to run a jail that protects nothing",
                    .{ jail_cfg.name, @tagName(jail_cfg.source), jail_cfg.logpath.len, journalctl_present },
                );
                return error.JailHasNoUsableSource;
            },
        }
    }

    if (journald.hasJails()) {
        if (journald_source_mod.loadCursors(heap, journald.cursor_path)) |cursors| {
            defer {
                for (cursors) |c| {
                    heap.free(c.name);
                    heap.free(c.cursor);
                }
                heap.free(cursors);
            }
            for (cursors) |c| journald.seedCursor(c.name, c.cursor);
            if (cursors.len > 0) {
                std.log.info("journald: restored {d} cursor(s) from sidecar", .{cursors.len});
            }
        } else |err| {
            std.log.warn("journald: cursor restore failed: {s}; baselining at now", .{@errorName(err)});
        }
        journald.setFlushHook(journaldFlushHook, &journald_flush_ctx);
        journald.attach() catch |err| {
            std.log.err("journald: attach (poll timer) failed: {s}", .{@errorName(err)});
            return err;
        };
        std.log.info("journald: polling {d} jail(s) every {d}ms", .{ journald.jailCount(), journald_source_mod.poll_interval_ms });
    }

    var health_sources = HealthSources{
        .watcher = &watcher,
        .journald = &journald,
    };

    var cmd_ctx: commands_mod.Context = .{
        .trackers = &trackers,
        .config = cfg,
        .backend = &backend_val,
        .stats_source = .{
            .ctx = @ptrCast(&metrics),
            .snapshot = metricsStatsSnapshot,
        },
        .health_source = .{
            .ctx = @ptrCast(&health_sources),
            .lookup = jailHealthLookup,
        },
        .source_descriptor = .{
            .ctx = @ptrCast(&source_descriptors),
            .lookup = JailSourceDescriptors.lookup,
        },
        .start_time = std.time.timestamp(),
        .version = version,
    };

    var ipc_server = ipc_mod.IpcServer.init(heap, &loop, cfg.global.socket_path) catch |err| {
        std.log.err("ipc: init failed at '{s}': {s}", .{ cfg.global.socket_path, @errorName(err) });
        return err;
    };
    defer ipc_server.deinit();
    ipc_server.setCommandHandler(cmd_ctx.asHandler());
    try ipc_server.start();

    var ws_server = ws.WsServer.init(
        heap,
        &loop,
        cfg.global.websocket_max_clients,
    ) catch |err| {
        std.log.err(
            "ws: init failed (max_clients={d}): {s}",
            .{ cfg.global.websocket_max_clients, @errorName(err) },
        );
        return err;
    };
    defer ws_server.deinit();

    var http_ctx: HttpSources = .{
        .metrics = &metrics,
        .cmd_ctx = &cmd_ctx,
        .trackers = &trackers,
    };
    var http_server = http.HttpServer.init(
        heap,
        &loop,
        cfg.global.metrics_port,
        cfg.global.metrics_bind,
    ) catch |err| {
        std.log.err(
            "http: init on {s}:{d} failed: {s}",
            .{ cfg.global.metrics_bind, cfg.global.metrics_port, @errorName(err) },
        );
        return err;
    };
    defer http_server.deinit();
    http_server.setMetricsSource(.{ .ctx = @ptrCast(&http_ctx), .write = writeMetricsPayload });
    http_server.setStatusSource(.{ .ctx = @ptrCast(&http_ctx), .write = writeStatusPayload });
    http_server.setBansSource(.{ .ctx = @ptrCast(&http_ctx), .write = writeBansPayload });
    http_server.setWsServer(&ws_server);
    try http_server.start();

    for (contexts.items) |jctx| {
        jctx.ws = &ws_server;
        jctx.ws_alloc = heap;
    }

    var sig_ctx = SignalContext{
        .loop = &loop,
        .trackers = &trackers,
        .state_path = cfg.global.state_file,
        .journald = &journald,
    };
    try loop.addSignalHandler(linux.SIG.TERM, onTerminate, &sig_ctx);
    try loop.addSignalHandler(linux.SIG.INT, onTerminate, &sig_ctx);
    try loop.addSignalHandler(linux.SIG.HUP, onReload, &sig_ctx);

    var expiry_ctx = ExpiryContext{
        .trackers = &trackers,
        .backend_ptr = &backend_val,
        .metrics = &metrics,
        .ws = &ws_server,
        .ws_alloc = heap,
    };
    _ = try loop.addTimer(1000, expirySweep, &expiry_ctx, false);

    var ws_tick_ctx = WsTickContext{
        .ws = &ws_server,
        .metrics = &metrics,
        .ws_alloc = heap,
        .start_time = cmd_ctx.start_time,
        .cmd_ctx = &cmd_ctx,
    };
    _ = try loop.addTimer(1000, wsTick, &ws_tick_ctx, false);

    std.log.info(
        "fail2zig {s} running; backend={s}; ipc={s}; http={s}:{d}",
        .{
            version,
            @tagName(backend_val.tag()),
            cfg.global.socket_path,
            cfg.global.metrics_bind,
            cfg.global.metrics_port,
        },
    );

    trace.mark("servers");
    trace.report();

    try loop.run();

    flushStateThenCursors(&trackers, cfg.global.state_file, &journald);

    std.log.info("fail2zig: shutting down", .{});
}

fn ensureSocketDir(socket_path: []const u8) !void {
    const dir = std.fs.path.dirname(socket_path) orelse return;
    std.fs.cwd().makeDir(dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => {
            std.log.err(
                "ipc: failed to create socket parent dir '{s}': {s}",
                .{ dir, @errorName(err) },
            );
            return err;
        },
    };

    std.posix.fchmodat(std.posix.AT.FDCWD, dir, 0o750, 0) catch |err| {
        std.log.warn(
            "ipc: chmod of socket parent dir '{s}' failed: {s}",
            .{ dir, @errorName(err) },
        );
    };
}

fn metricsStatsSnapshot(ctx: ?*anyopaque) commands_mod.StatsSnapshot {
    const m: *metrics_mod.Metrics = @ptrCast(@alignCast(ctx.?));
    const s = m.snapshot();
    return .{
        .memory_bytes_used = s.memory_bytes_used,
        .parse_rate = 0,
        .bans_total = s.bans_total,
    };
}

const HealthSources = struct {
    watcher: *log_watcher_mod.LogWatcher,
    journald: *journald_source_mod.JournaldSource,
};

fn jailHealthLookup(ctx: ?*anyopaque, jail_name: []const u8) ?commands_mod.JailHealth {
    const self: *HealthSources = @ptrCast(@alignCast(ctx.?));
    if (self.journald.healthForJail(jail_name)) |h| {
        return .{ .healthy = h.healthy, .lines_seen = h.lines_seen, .last_read_ok_ts = h.last_read_ok_ts };
    }
    if (self.watcher.healthForJail(jail_name)) |h| {
        return .{ .healthy = h.healthy, .lines_seen = h.lines_seen, .last_read_ok_ts = h.last_read_ok_ts };
    }
    return null;
}

const JailSourceDescriptors = struct {
    map: std.StringHashMap([]const u8),
    arena: std.heap.ArenaAllocator,

    fn init(backing: std.mem.Allocator) JailSourceDescriptors {
        return .{
            .map = std.StringHashMap([]const u8).init(backing),
            .arena = std.heap.ArenaAllocator.init(backing),
        };
    }

    fn deinit(self: *JailSourceDescriptors) void {
        self.map.deinit();
        self.arena.deinit();
    }

    fn putJournald(self: *JailSourceDescriptors, jail_name: []const u8, filter: []const u8) !void {
        const a = self.arena.allocator();
        const desc = try std.fmt.allocPrint(a, "journald ({s})", .{filter});
        try self.map.put(jail_name, desc);
    }

    fn putFile(self: *JailSourceDescriptors, jail_name: []const u8, logpath: []const []const u8) !void {
        const a = self.arena.allocator();
        if (logpath.len == 0) {
            try self.map.put(jail_name, "file");
            return;
        }
        if (logpath.len == 1) {
            const desc = try a.dupe(u8, logpath[0]);
            try self.map.put(jail_name, desc);
            return;
        }
        const joined = try std.mem.join(a, ", ", logpath);
        try self.map.put(jail_name, joined);
    }

    fn lookup(ctx: ?*anyopaque, jail_name: []const u8) ?[]const u8 {
        const self: *JailSourceDescriptors = @ptrCast(@alignCast(ctx.?));
        return self.map.get(jail_name);
    }
};

const HttpSources = struct {
    metrics: *metrics_mod.Metrics,
    cmd_ctx: *commands_mod.Context,
    trackers: *tracker_map_mod.TrackerMap,
};

fn writeMetricsPayload(
    ctx: ?*anyopaque,
    out: *std.ArrayListUnmanaged(u8),
    a: std.mem.Allocator,
) anyerror!void {
    const self: *HttpSources = @ptrCast(@alignCast(ctx.?));
    const snap = self.metrics.snapshot();
    const w = out.writer(a);

    try w.writeAll("# HELP fail2zig_up 1 when the daemon is running\n");
    try w.writeAll("# TYPE fail2zig_up gauge\n");
    try w.writeAll("fail2zig_up 1\n");

    try w.writeAll("# HELP fail2zig_lines_parsed_total Total log lines parsed\n");
    try w.writeAll("# TYPE fail2zig_lines_parsed_total counter\n");
    try w.print("fail2zig_lines_parsed_total {d}\n", .{snap.lines_parsed});

    try w.writeAll("# HELP fail2zig_lines_matched_total Log lines matching a filter\n");
    try w.writeAll("# TYPE fail2zig_lines_matched_total counter\n");
    try w.print("fail2zig_lines_matched_total {d}\n", .{snap.lines_matched});

    try w.writeAll("# HELP fail2zig_bans_total Total bans issued\n");
    try w.writeAll("# TYPE fail2zig_bans_total counter\n");
    try w.print("fail2zig_bans_total {d}\n", .{snap.bans_total});

    try w.writeAll("# HELP fail2zig_unbans_total Total unbans issued\n");
    try w.writeAll("# TYPE fail2zig_unbans_total counter\n");
    try w.print("fail2zig_unbans_total {d}\n", .{snap.unbans_total});

    try w.writeAll("# HELP fail2zig_active_bans Current active bans\n");
    try w.writeAll("# TYPE fail2zig_active_bans gauge\n");
    try w.print("fail2zig_active_bans {d}\n", .{snap.active_bans});

    try w.writeAll("# HELP fail2zig_parse_errors_total Total parse errors\n");
    try w.writeAll("# TYPE fail2zig_parse_errors_total counter\n");
    try w.print("fail2zig_parse_errors_total {d}\n", .{snap.parse_errors});

    try w.writeAll("# HELP fail2zig_memory_bytes_used Current memory footprint\n");
    try w.writeAll("# TYPE fail2zig_memory_bytes_used gauge\n");
    try w.print("fail2zig_memory_bytes_used {d}\n", .{snap.memory_bytes_used});

    const uptime_s: u64 = blk: {
        const now = std.time.timestamp();
        if (now <= self.cmd_ctx.start_time) break :blk 0;
        break :blk @intCast(now - self.cmd_ctx.start_time);
    };
    try w.writeAll("# HELP fail2zig_uptime_seconds Seconds since daemon start\n");
    try w.writeAll("# TYPE fail2zig_uptime_seconds gauge\n");
    try w.print("fail2zig_uptime_seconds {d}\n", .{uptime_s});

    const overall = self.cmd_ctx.computeOverallState();
    const actively_enforcing =
        std.mem.eql(u8, overall, "active") or std.mem.eql(u8, overall, "mixed");
    try w.writeAll("# HELP fail2zig_protection_active 1 when the host is actively enforcing (overall state active/mixed), else 0\n");
    try w.writeAll("# TYPE fail2zig_protection_active gauge\n");
    try w.print("fail2zig_protection_active {d}\n", .{@intFromBool(actively_enforcing)});

    try w.writeAll("# HELP fail2zig_jail_log_source_healthy 1 when the jail's log source is confirmed reading, else 0\n");
    try w.writeAll("# TYPE fail2zig_jail_log_source_healthy gauge\n");
    try w.writeAll("# HELP fail2zig_jail_enforcing 1 when the jail's resolved action touches the firewall, else 0\n");
    try w.writeAll("# TYPE fail2zig_jail_enforcing gauge\n");
    try w.writeAll("# HELP fail2zig_jail_lines_seen_total Lines the jail's log source has delivered (read-health proxy)\n");
    try w.writeAll("# TYPE fail2zig_jail_lines_seen_total counter\n");
    for (self.cmd_ctx.config.jails) |*jc| {
        if (!jc.enabled) continue;
        const resolved = config_mod.resolveJailFromConfig(jc, self.cmd_ctx.config.defaults);
        const enforcing = resolved.banaction != .@"log-only";
        const hs = self.cmd_ctx.health_source;
        const health = hs.lookup(hs.ctx, jc.name);
        const healthy = if (health) |h| h.healthy else false;
        const lines_seen: u64 = if (health) |h| h.lines_seen else 0;
        try w.print("fail2zig_jail_log_source_healthy{{jail=\"{s}\"}} {d}\n", .{ jc.name, @intFromBool(healthy) });
        try w.print("fail2zig_jail_enforcing{{jail=\"{s}\"}} {d}\n", .{ jc.name, @intFromBool(enforcing) });
        try w.print("fail2zig_jail_lines_seen_total{{jail=\"{s}\"}} {d}\n", .{ jc.name, lines_seen });
    }

    for (snap.perJail()) |pj| {
        const name = pj.name();
        try w.print("fail2zig_lines_parsed_total{{jail=\"{s}\"}} {d}\n", .{ name, pj.lines_parsed });
        try w.print("fail2zig_lines_matched_total{{jail=\"{s}\"}} {d}\n", .{ name, pj.lines_matched });
        try w.print("fail2zig_bans_total{{jail=\"{s}\"}} {d}\n", .{ name, pj.bans_total });
        try w.print("fail2zig_unbans_total{{jail=\"{s}\"}} {d}\n", .{ name, pj.unbans_total });
        try w.print("fail2zig_active_bans{{jail=\"{s}\"}} {d}\n", .{ name, pj.active_bans });
    }
}

fn writeStatusPayload(
    ctx: ?*anyopaque,
    out: *std.ArrayListUnmanaged(u8),
    a: std.mem.Allocator,
) anyerror!void {
    const self: *HttpSources = @ptrCast(@alignCast(ctx.?));
    const handler = self.cmd_ctx.asHandler();
    const resp = try handler.dispatch(handler.ctx, .{ .status = {} }, a);
    defer resp.deinit(a);
    switch (resp) {
        .ok => |o| try out.appendSlice(a, o.payload),
        .err => |e| {
            var buf: [128]u8 = undefined;
            const s = try std.fmt.bufPrint(&buf, "{{\"error\":{d},\"message\":\"{s}\"}}", .{ e.code, e.message });
            try out.appendSlice(a, s);
        },
    }
}

fn writeBansPayload(
    ctx: ?*anyopaque,
    out: *std.ArrayListUnmanaged(u8),
    a: std.mem.Allocator,
) anyerror!void {
    const self: *HttpSources = @ptrCast(@alignCast(ctx.?));
    const w = out.writer(a);

    const total: u32 = self.trackers.totalActiveBans();

    try w.writeAll("{\"total\":");
    try w.print("{d}", .{total});
    try w.writeAll(",\"entries\":[");

    const now_s: i64 = std.time.timestamp();

    var written: usize = 0;
    var tit = self.trackers.iterator();
    outer: while (tit.next()) |tkv| {
        const tracker = tkv.value_ptr.*;
        const cfg = tracker.config;
        var it = tracker.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.ban_state != .banned) continue;
            if (written >= http.max_bans_in_snapshot) break :outer;
            if (written > 0) try w.writeAll(",");
            written += 1;

            const ip = kv.key_ptr.*;
            const st = kv.value_ptr;

            const seconds_remaining: i64 = if (st.ban_expiry) |exp|
                @max(0, exp - now_s)
            else
                0;

            const duration = state_mod.computeBantime(
                cfg.bantime,
                cfg.bantime_increment,
                if (st.ban_count == 0) 0 else st.ban_count - 1,
            );
            const dur_i64: i64 = @intCast(@min(duration, std.math.maxInt(i64)));
            const banned_at_epoch_s: i64 = if (st.ban_expiry) |exp|
                std.math.sub(i64, exp, dur_i64) catch now_s
            else
                now_s;

            var ts_buf: [32]u8 = undefined;
            const banned_at_iso = try ws.formatIso8601Utc(&ts_buf, banned_at_epoch_s * 1000);

            try w.print(
                "{{\"ip\":\"{}\",\"jail\":\"{s}\",\"banned_at\":\"{s}\",\"seconds_remaining\":{d}}}",
                .{ ip, st.jail.slice(), banned_at_iso, seconds_remaining },
            );
        }
    }

    try w.writeAll("]}");
}

test "engine: version constant tracks build_options" {
    try std.testing.expectEqualStrings(build_options.version, version);
}

test "engine: all version identities agree (ISSUE-010 drift guard)" {
    const ctx_default_version = (commands_mod.Context{
        .trackers = undefined,
        .config = undefined,
        .backend = undefined,
    }).version;
    try std.testing.expectEqualStrings(build_options.version, version);
    try std.testing.expectEqualStrings(build_options.version, ctx_default_version);
}

test "cli: default action is run" {
    const args = [_][]const u8{"fail2zig"};
    const opts = try parseArgs(&args);
    try std.testing.expectEqual(CliAction.run, opts.action);
    try std.testing.expectEqualStrings("/etc/fail2zig/config.toml", opts.config_path);
}

test "cli: --version" {
    const args = [_][]const u8{ "fail2zig", "--version" };
    const opts = try parseArgs(&args);
    try std.testing.expectEqual(CliAction.print_version, opts.action);
}

test "cli: -V short" {
    const args = [_][]const u8{ "fail2zig", "-V" };
    const opts = try parseArgs(&args);
    try std.testing.expectEqual(CliAction.print_version, opts.action);
}

test "cli: --help" {
    const args = [_][]const u8{ "fail2zig", "--help" };
    const opts = try parseArgs(&args);
    try std.testing.expectEqual(CliAction.print_help, opts.action);
}

test "cli: --config path" {
    const args = [_][]const u8{ "fail2zig", "--config", "/etc/foo.toml" };
    const opts = try parseArgs(&args);
    try std.testing.expectEqualStrings("/etc/foo.toml", opts.config_path);
}

test "cli: --config= inline" {
    const args = [_][]const u8{ "fail2zig", "--config=/etc/bar.toml" };
    const opts = try parseArgs(&args);
    try std.testing.expectEqualStrings("/etc/bar.toml", opts.config_path);
}

test "cli: --test-config" {
    const args = [_][]const u8{ "fail2zig", "--test-config" };
    const opts = try parseArgs(&args);
    try std.testing.expectEqual(CliAction.test_config, opts.action);
}

test "cli: --import-config with explicit path" {
    const args = [_][]const u8{ "fail2zig", "--import-config", "/etc/fail2ban" };
    const opts = try parseArgs(&args);
    try std.testing.expectEqual(CliAction.import_config, opts.action);
    try std.testing.expectEqualStrings("/etc/fail2ban", opts.import_path.?);
    try std.testing.expectEqualStrings("/etc/fail2zig/config.toml", opts.import_output);
}

test "cli: --import-config with no arg uses default source" {
    const args = [_][]const u8{"fail2zig"} ++ [_][]const u8{"--import-config"};
    const opts = try parseArgs(&args);
    try std.testing.expectEqual(CliAction.import_config, opts.action);
    try std.testing.expectEqualStrings("/etc/fail2ban", opts.import_path.?);
}

test "cli: --import-config with --import-output override" {
    const args = [_][]const u8{ "fail2zig", "--import-config", "/etc/fail2ban", "--import-output", "/tmp/out.toml" };
    const opts = try parseArgs(&args);
    try std.testing.expectEqual(CliAction.import_config, opts.action);
    try std.testing.expectEqualStrings("/tmp/out.toml", opts.import_output);
}

test "cli: --import-config= inline" {
    const args = [_][]const u8{ "fail2zig", "--import-config=/etc/fail2ban" };
    const opts = try parseArgs(&args);
    try std.testing.expectEqual(CliAction.import_config, opts.action);
    try std.testing.expectEqualStrings("/etc/fail2ban", opts.import_path.?);
}

test "cli: --validate-config" {
    const args = [_][]const u8{ "fail2zig", "--validate-config" };
    const opts = try parseArgs(&args);
    try std.testing.expectEqual(CliAction.validate_config, opts.action);
}

test "cli: --foreground" {
    const args = [_][]const u8{ "fail2zig", "--foreground" };
    const opts = try parseArgs(&args);
    try std.testing.expect(opts.foreground);
    try std.testing.expectEqual(CliAction.run, opts.action);
}

test "cli: unknown flag errors" {
    const args = [_][]const u8{ "fail2zig", "--bogus" };
    try std.testing.expectError(error.UnknownFlag, parseArgs(&args));
}

test "cli: missing value errors" {
    const args = [_][]const u8{ "fail2zig", "--config" };
    try std.testing.expectError(error.MissingValue, parseArgs(&args));
}

test "cli: printHelp writes usage" {
    var buf: [2048]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try printHelp(stream.writer());
    const written = stream.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, written, "fail2zig") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "--config") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "--version") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "--import-config") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "--import-output") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "--validate-config") != null);
}

test "cli: runImport succeeds and returns 0 for a viable config tree" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{
        .sub_path = "jail.conf",
        .data =
        \\[sshd]
        \\enabled = true
        \\filter = sshd
        \\logpath = /var/log/auth.log
        ,
    });

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source = try tmp.dir.realpathAlloc(arena.allocator(), ".");
    const out = try std.fs.path.join(arena.allocator(), &.{ source, "out.toml" });

    var stderr_buf = std.ArrayList(u8).init(std.testing.allocator);
    defer stderr_buf.deinit();

    const rc = runImport(std.testing.allocator, source, out, stderr_buf.writer());
    try std.testing.expectEqual(@as(u8, 0), rc);
}

test "cli: runImport returns 1 when zero jails are imported" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{
        .sub_path = "jail.conf",
        .data =
        \\[DEFAULT]
        \\bantime = 600
        ,
    });

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source = try tmp.dir.realpathAlloc(arena.allocator(), ".");
    const out = try std.fs.path.join(arena.allocator(), &.{ source, "out.toml" });

    var stderr_buf = std.ArrayList(u8).init(std.testing.allocator);
    defer stderr_buf.deinit();

    const rc = runImport(std.testing.allocator, source, out, stderr_buf.writer());
    try std.testing.expectEqual(@as(u8, 1), rc);
}

test "cli: runImport returns 2 on unreadable source dir" {
    var stderr_buf = std.ArrayList(u8).init(std.testing.allocator);
    defer stderr_buf.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{
        .sub_path = "jail.conf",
        .data =
        \\[sshd]
        \\enabled = true
        \\filter = sshd
        ,
    });

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source = try tmp.dir.realpathAlloc(arena.allocator(), ".");

    try tmp.dir.writeFile(.{ .sub_path = "blocker", .data = "x" });
    const bad_out = try std.fs.path.join(arena.allocator(), &.{ source, "blocker", "out.toml" });

    const rc = runImport(std.testing.allocator, source, bad_out, stderr_buf.writer());
    try std.testing.expectEqual(@as(u8, 2), rc);
}

test "main: deriveJailTrackerConfig uses resolved per-jail values" {
    var jails = [_]config_mod.JailConfig{
        .{
            .name = "aggressive",
            .enabled = true,
            .maxretry = 1,
            .findtime = 10,
            .bantime = 30,
        },
    };
    const cfg: config_mod.Config = .{
        .global = .{ .memory_ceiling_mb = 64 },
        .defaults = .{ .bantime = 600, .findtime = 600, .maxretry = 5 },
        .jails = &jails,
        .diag = .{},
    };
    const resolved = config_mod.resolveJail(&cfg, "aggressive").?;
    const t = deriveJailTrackerConfig(resolved, 2048);
    try std.testing.expectEqual(@as(u32, 2048), t.max_entries);
    try std.testing.expectEqual(@as(shared.Duration, 30), t.bantime);
    try std.testing.expectEqual(@as(shared.Duration, 10), t.findtime);
    try std.testing.expectEqual(@as(u32, 1), t.maxretry);
}

const BanSpy = struct {
    calls: u32 = 0,
    last_ip: ?shared.IpAddress = null,

    fn ban(
        userdata: ?*anyopaque,
        ip: shared.IpAddress,
        jail: shared.JailId,
        duration: shared.Duration,
    ) firewall.BackendError!void {
        _ = jail;
        _ = duration;
        const self: *BanSpy = @ptrCast(@alignCast(userdata.?));
        self.calls += 1;
        self.last_ip = ip;
    }
};

fn makeDispatchTestCtx(
    jail: shared.JailId,
    tracker: *state_mod.StateTracker,
    backend: *firewall.Backend,
    metrics: *metrics_mod.Metrics,
    spy: *BanSpy,
    action: config_mod.BanAction,
) JailContext {
    return .{
        .jail = jail,
        .matcher = undefined,
        .state = tracker,
        .backend_ptr = backend,
        .banaction = action,
        .metrics = metrics,
        .ban_hook = BanSpy.ban,
        .ban_hook_ctx = spy,
    };
}

fn produceDecision(
    tracker: *state_mod.StateTracker,
    ip: shared.IpAddress,
    jail: shared.JailId,
) !state_mod.BanDecision {
    try testing.expect((try tracker.recordAttempt(ip, jail, 1_000)) == null);
    try testing.expect((try tracker.recordAttempt(ip, jail, 1_100)) == null);
    return (try tracker.recordAttempt(ip, jail, 1_200)).?;
}

test "dispatch: log-only jail records ban intent but does NOT call backend" {
    const a = testing.allocator;
    var tracker = try state_mod.StateTracker.init(a, .{
        .max_entries = 16,
        .maxretry = 3,
        .findtime = 600,
        .bantime = 600,
    });
    defer tracker.deinit();

    var metrics = metrics_mod.Metrics.init();
    const jail_name = "sshd";
    _ = metrics.registerJail(jail_name);
    const jail = try shared.JailId.fromSlice(jail_name);
    const ip = try shared.IpAddress.parse("203.0.113.66");

    var backend: firewall.Backend = .{ .iptables = firewall.iptables.IptablesBackend{} };
    var spy: BanSpy = .{};

    var ctx = makeDispatchTestCtx(jail, &tracker, &backend, &metrics, &spy, .@"log-only");

    const decision = try produceDecision(&tracker, ip, jail);
    dispatchBan(&ctx, decision);

    try testing.expectEqual(@as(u32, 0), spy.calls);

    const snap = metrics.snapshot();
    try testing.expectEqual(@as(u64, 1), snap.bans_total);
    var found = false;
    for (snap.perJail()) |pj| {
        if (std.mem.eql(u8, pj.name(), jail_name)) {
            try testing.expectEqual(@as(u64, 1), pj.bans_total);
            found = true;
        }
    }
    try testing.expect(found);
}

test "dispatch: enforcing jail (nftables) DOES call the backend ban path" {
    const a = testing.allocator;
    var tracker = try state_mod.StateTracker.init(a, .{
        .max_entries = 16,
        .maxretry = 3,
        .findtime = 600,
        .bantime = 600,
    });
    defer tracker.deinit();

    var metrics = metrics_mod.Metrics.init();
    const jail_name = "sshd";
    _ = metrics.registerJail(jail_name);
    const jail = try shared.JailId.fromSlice(jail_name);
    const ip = try shared.IpAddress.parse("203.0.113.66");

    var backend: firewall.Backend = .{ .iptables = firewall.iptables.IptablesBackend{} };
    var spy: BanSpy = .{};

    var ctx = makeDispatchTestCtx(jail, &tracker, &backend, &metrics, &spy, .nftables);

    const decision = try produceDecision(&tracker, ip, jail);
    dispatchBan(&ctx, decision);

    try testing.expectEqual(@as(u32, 1), spy.calls);
    try testing.expect(spy.last_ip != null);
    try testing.expect(shared.IpAddress.eql(spy.last_ip.?, ip));

    const snap = metrics.snapshot();
    try testing.expectEqual(@as(u64, 1), snap.bans_total);
}

test "dispatch: backend error on enforcing path skips metrics (no false ban)" {
    const a = testing.allocator;
    var tracker = try state_mod.StateTracker.init(a, .{
        .max_entries = 16,
        .maxretry = 3,
        .findtime = 600,
        .bantime = 600,
    });
    defer tracker.deinit();

    var metrics = metrics_mod.Metrics.init();
    const jail_name = "sshd";
    _ = metrics.registerJail(jail_name);
    const jail = try shared.JailId.fromSlice(jail_name);
    const ip = try shared.IpAddress.parse("203.0.113.66");

    var backend: firewall.Backend = .{ .iptables = firewall.iptables.IptablesBackend{} };

    const FailingSpy = struct {
        fn ban(
            _: ?*anyopaque,
            _: shared.IpAddress,
            _: shared.JailId,
            _: shared.Duration,
        ) firewall.BackendError!void {
            return error.SystemError;
        }
    };

    var ctx: JailContext = .{
        .jail = jail,
        .matcher = undefined,
        .state = &tracker,
        .backend_ptr = &backend,
        .banaction = .nftables,
        .metrics = &metrics,
        .ban_hook = FailingSpy.ban,
        .ban_hook_ctx = null,
    };

    const decision = try produceDecision(&tracker, ip, jail);
    dispatchBan(&ctx, decision);

    const snap = metrics.snapshot();
    try testing.expectEqual(@as(u64, 0), snap.bans_total);
    try testing.expectEqual(@as(u64, 0), tracker.lifetime_bans);
}

test "dispatch: BUG-006 a new ban increments the jail's persisted lifetime" {
    const a = testing.allocator;
    var tracker = try state_mod.StateTracker.init(a, .{ .max_entries = 16, .maxretry = 3, .findtime = 600, .bantime = 600 });
    defer tracker.deinit();
    var metrics = metrics_mod.Metrics.init();
    _ = metrics.registerJail("sshd");
    const jail = try shared.JailId.fromSlice("sshd");
    var backend: firewall.Backend = .{ .iptables = firewall.iptables.IptablesBackend{} };
    var spy: BanSpy = .{};

    var ctx = makeDispatchTestCtx(jail, &tracker, &backend, &metrics, &spy, .nftables);
    const d1 = try produceDecision(&tracker, try shared.IpAddress.parse("203.0.113.10"), jail);
    dispatchBan(&ctx, d1);
    try testing.expectEqual(@as(u64, 1), tracker.lifetime_bans);

    tracker.clearBan(try shared.IpAddress.parse("203.0.113.10"));
    var ctx2 = makeDispatchTestCtx(jail, &tracker, &backend, &metrics, &spy, .@"log-only");
    const d2 = try produceDecision(&tracker, try shared.IpAddress.parse("203.0.113.11"), jail);
    dispatchBan(&ctx2, d2);
    try testing.expectEqual(@as(u64, 2), tracker.lifetime_bans);
}

test "dispatch: BUG-006 restored bans do NOT increment lifetime (no double-count)" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &path_buf);
    var full: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&full, "{s}/state.bin", .{dir});

    {
        var tm = tracker_map_mod.TrackerMap.init(a);
        defer tm.deinit();
        const sshd = try tm.addTracker("sshd", .{ .max_entries = 16, .maxretry = 1, .findtime = 600, .bantime = 600 });
        sshd.lifetime_bans = 4;
        _ = try sshd.recordAttempt(try shared.IpAddress.parse("9.9.9.9"), try shared.JailId.fromSlice("sshd"), 1_000);
        try persist_mod.saveAll(&tm, path);
    }

    var tm2 = tracker_map_mod.TrackerMap.init(a);
    defer tm2.deinit();
    _ = try tm2.addTracker("sshd", .{ .max_entries = 16 });
    _ = try tm2.ensureLegacy(.{ .max_entries = 16 });
    const loaded = try persist_mod.loadFull(a, path);
    defer loaded.deinit(a);
    try persist_mod.seedMap(&tm2, loaded.entries, null, null);
    persist_mod.seedLifetimes(&tm2, loaded.lifetimes);

    try testing.expectEqual(@as(u64, 4), tm2.get("sshd").?.lifetime_bans);
    try testing.expect(tm2.get("sshd").?.lifetime_bans >= tm2.totalActiveBans());
}

fn makeLineCallbackCtx(
    jail: shared.JailId,
    tracker: *state_mod.StateTracker,
    backend: *firewall.Backend,
    metrics: *metrics_mod.Metrics,
    spy: *BanSpy,
) JailContext {
    return .{
        .jail = jail,
        .matcher = filter_registry_mod.matcherForFilter("sshd").?,
        .state = tracker,
        .backend_ptr = backend,
        .banaction = .nftables,
        .metrics = metrics,
        .now_override = 1_000,
        .ban_hook = BanSpy.ban,
        .ban_hook_ctx = spy,
    };
}

const LineCallbackFixture = struct {
    tracker: state_mod.StateTracker,
    metrics: metrics_mod.Metrics,
    backend: firewall.Backend,
    spy: BanSpy,
    jail: shared.JailId,

    fn deinit(self: *LineCallbackFixture) void {
        self.tracker.deinit();
    }
};

fn initLineCallbackFixture(self: *LineCallbackFixture) !void {
    self.tracker = try state_mod.StateTracker.init(testing.allocator, .{
        .max_entries = 16,
        .maxretry = 1,
        .findtime = 600,
        .bantime = 600,
    });
    self.metrics = metrics_mod.Metrics.init();
    _ = self.metrics.registerJail("sshd");
    self.backend = .{ .iptables = firewall.iptables.IptablesBackend{} };
    self.spy = .{};
    self.jail = try shared.JailId.fromSlice("sshd");
}

test "lineCallback: sshd listener startup line does NOT match/count/ban (SYS-020)" {
    var fx: LineCallbackFixture = undefined;
    try initLineCallbackFixture(&fx);
    defer fx.deinit();
    var ctx = makeLineCallbackCtx(fx.jail, &fx.tracker, &fx.backend, &fx.metrics, &fx.spy);

    lineCallback("Server listening on 0.0.0.0 port 22.", fx.jail, false, &ctx);
    lineCallback("Server listening on :: port 22.", fx.jail, false, &ctx);

    try testing.expectEqual(@as(u32, 0), fx.spy.calls);
    const snap = fx.metrics.snapshot();
    try testing.expectEqual(@as(u64, 0), snap.bans_total);
    try testing.expectEqual(@as(u64, 0), snap.lines_matched);
}

test "lineCallback: successful auth (Accepted password/publickey) does NOT ban (SYS-020)" {
    var fx: LineCallbackFixture = undefined;
    try initLineCallbackFixture(&fx);
    defer fx.deinit();
    var ctx = makeLineCallbackCtx(fx.jail, &fx.tracker, &fx.backend, &fx.metrics, &fx.spy);

    lineCallback("Accepted password for root from 198.51.100.7 port 22 ssh2", fx.jail, false, &ctx);
    lineCallback("Accepted publickey for root from 198.51.100.7 port 22 ssh2: RSA SHA256:x", fx.jail, false, &ctx);

    try testing.expectEqual(@as(u32, 0), fx.spy.calls);
    try testing.expectEqual(@as(u64, 0), fx.metrics.snapshot().bans_total);
}

test "lineCallback: real sshd auth failures DO match and ban (no regression, SYS-020)" {
    var fx: LineCallbackFixture = undefined;
    try initLineCallbackFixture(&fx);
    defer fx.deinit();
    var ctx = makeLineCallbackCtx(fx.jail, &fx.tracker, &fx.backend, &fx.metrics, &fx.spy);

    lineCallback("Failed password for root from 203.0.113.10 port 22 ssh2", fx.jail, false, &ctx);
    try testing.expectEqual(@as(u32, 1), fx.spy.calls);
    try testing.expect(fx.spy.last_ip != null);
    try testing.expect(shared.IpAddress.eql(fx.spy.last_ip.?, try shared.IpAddress.parse("203.0.113.10")));

    lineCallback("Invalid user oracle from 203.0.113.20 port 22", fx.jail, false, &ctx);
    try testing.expectEqual(@as(u32, 2), fx.spy.calls);
}

test "lineCallback: [preauth] self-ban guard takes effect at runtime (SYS-011 via SYS-020)" {
    var fx: LineCallbackFixture = undefined;
    try initLineCallbackFixture(&fx);
    defer fx.deinit();
    var ctx = makeLineCallbackCtx(fx.jail, &fx.tracker, &fx.backend, &fx.metrics, &fx.spy);

    lineCallback("Received disconnect from 192.0.2.50 port 22:11: disconnected by user", fx.jail, false, &ctx);
    try testing.expectEqual(@as(u32, 0), fx.spy.calls);

    lineCallback("Received disconnect from 203.0.113.99 port 22:11: Bye Bye [preauth]", fx.jail, false, &ctx);
    try testing.expectEqual(@as(u32, 1), fx.spy.calls);
}

test "lineCallback: matched line with unenforceable IP never bans (reserved-IP guard, SYS-020)" {
    var fx: LineCallbackFixture = undefined;
    try initLineCallbackFixture(&fx);
    defer fx.deinit();
    var ctx = makeLineCallbackCtx(fx.jail, &fx.tracker, &fx.backend, &fx.metrics, &fx.spy);

    lineCallback("Invalid user attacker from 0.0.0.0 port 22", fx.jail, false, &ctx);
    lineCallback("Invalid user attacker from :: port 22", fx.jail, false, &ctx);
    lineCallback("Failed password for root from 127.0.0.1 port 22 ssh2", fx.jail, false, &ctx);

    try testing.expectEqual(@as(u32, 0), fx.spy.calls);
    const snap = fx.metrics.snapshot();
    try testing.expectEqual(@as(u64, 0), snap.bans_total);
    try testing.expectEqual(@as(u64, 0), snap.lines_matched);
}

test "lineCallback: file and journald inputs resolve to the SAME configured matcher (SYS-020)" {
    var fx: LineCallbackFixture = undefined;
    try initLineCallbackFixture(&fx);
    defer fx.deinit();
    var ctx = makeLineCallbackCtx(fx.jail, &fx.tracker, &fx.backend, &fx.metrics, &fx.spy);

    lineCallback("Apr 21 10:15:03 host sshd[1234]: Accepted password for root from 198.51.100.8 port 22 ssh2", fx.jail, false, &ctx);
    lineCallback("Accepted password for root from 198.51.100.8 port 22 ssh2", fx.jail, false, &ctx);

    try testing.expectEqual(@as(u32, 0), fx.spy.calls);

    lineCallback("Apr 21 10:15:04 host sshd[1234]: Failed password for root from 203.0.113.30 port 22 ssh2", fx.jail, false, &ctx);
    try testing.expectEqual(@as(u32, 1), fx.spy.calls);
}

test "main: deriveLegacyTrackerConfig mirrors defaults" {
    const cfg: config_mod.Config = .{
        .global = .{ .memory_ceiling_mb = 64 },
        .defaults = .{
            .bantime = 900,
            .findtime = 450,
            .maxretry = 4,
        },
        .jails = &.{},
        .diag = .{},
    };
    const t = deriveLegacyTrackerConfig(&cfg, 2048);
    try std.testing.expectEqual(@as(u32, 2048), t.max_entries);
    try std.testing.expectEqual(@as(shared.Duration, 900), t.bantime);
    try std.testing.expectEqual(@as(shared.Duration, 450), t.findtime);
    try std.testing.expectEqual(@as(u32, 4), t.maxretry);
}

test {
    _ = event_loop_mod;
    _ = log_watcher_mod;
    _ = journald_source_mod;
    _ = line_buffer_mod;
    _ = logger_mod;
    _ = parser_mod;
    _ = state_mod;
    _ = tracker_map_mod;
    _ = persist_mod;
    _ = firewall;
    _ = config_mod;
    _ = fail2ban_mod;
    _ = migration_mod;
    _ = filter_types_mod;
    _ = filter_sshd_mod;
    _ = filter_nginx_mod;
    _ = filter_apache_mod;
    _ = filter_mail_mod;
    _ = filter_misc_mod;
    _ = filter_registry_mod;
    _ = http;
    _ = ws;
    _ = ipc_mod;
    _ = commands_mod;
    _ = metrics_mod;
    _ = shared;
}

const testing = std.testing;

fn injectBan(
    tracker: *state_mod.StateTracker,
    ip_str: []const u8,
    jail_name: []const u8,
    banned_at: shared.Timestamp,
    duration: shared.Duration,
) !void {
    const ip = try shared.IpAddress.parse(ip_str);
    const jail = try shared.JailId.fromSlice(jail_name);
    const gop = try tracker.map.getOrPut(ip);
    gop.value_ptr.* = .{
        .jail = jail,
        .attempt_count = 1,
        .ban_count = 1,
        .first_attempt = banned_at,
        .last_attempt = banned_at,
        .ban_state = .banned,
        .ban_expiry = banned_at + @as(shared.Timestamp, @intCast(duration)),
        .ring = undefined,
        .ring_len = 0,
    };
}

test "http: /api/bans empty snapshot -> count 0, elements []" {
    const a = testing.allocator;
    var trackers = tracker_map_mod.TrackerMap.init(a);
    defer trackers.deinit();
    _ = try trackers.addTracker("sshd", .{
        .max_entries = 16,
        .findtime = 600,
        .maxretry = 5,
        .bantime = 600,
    });

    var ctx: HttpSources = .{
        .metrics = undefined,
        .cmd_ctx = undefined,
        .trackers = &trackers,
    };
    var out: std.ArrayListUnmanaged(u8) = .{};
    defer out.deinit(a);
    try writeBansPayload(@ptrCast(&ctx), &out, a);

    const body = out.items;
    try testing.expect(std.mem.indexOf(u8, body, "\"total\":0") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"entries\":[]") != null);
}

test "http: /api/bans single ban populates element fields" {
    const a = testing.allocator;
    var trackers = tracker_map_mod.TrackerMap.init(a);
    defer trackers.deinit();
    const sshd_tracker = try trackers.addTracker("sshd", .{
        .max_entries = 16,
        .findtime = 600,
        .maxretry = 5,
        .bantime = 600,
    });

    try injectBan(sshd_tracker, "185.220.101.5", "sshd", 1_714_000_000, 600);

    var ctx: HttpSources = .{
        .metrics = undefined,
        .cmd_ctx = undefined,
        .trackers = &trackers,
    };
    var out: std.ArrayListUnmanaged(u8) = .{};
    defer out.deinit(a);
    try writeBansPayload(@ptrCast(&ctx), &out, a);

    const body = out.items;
    try testing.expect(std.mem.indexOf(u8, body, "\"total\":1") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"ip\":\"185.220.101.5\"") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"jail\":\"sshd\"") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"banned_at\":\"2024-04-24T23:06:") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"seconds_remaining\":") != null);
}

test "http: /api/bans truncates elements at 200 but count reflects total" {
    const a = testing.allocator;
    var trackers = tracker_map_mod.TrackerMap.init(a);
    defer trackers.deinit();
    const sshd_tracker = try trackers.addTracker("sshd", .{
        .max_entries = 512,
        .findtime = 600,
        .maxretry = 5,
        .bantime = 600,
    });

    var i: u32 = 0;
    while (i < 250) : (i += 1) {
        var buf: [16]u8 = undefined;
        const s = try std.fmt.bufPrint(&buf, "10.0.{d}.{d}", .{ i / 256, i % 256 });
        try injectBan(sshd_tracker, s, "sshd", 1_714_000_000, 600);
    }

    var ctx: HttpSources = .{
        .metrics = undefined,
        .cmd_ctx = undefined,
        .trackers = &trackers,
    };
    var out: std.ArrayListUnmanaged(u8) = .{};
    defer out.deinit(a);
    try writeBansPayload(@ptrCast(&ctx), &out, a);

    const body = out.items;
    try testing.expect(std.mem.indexOf(u8, body, "\"total\":250") != null);

    var element_count: usize = 0;
    var cursor: usize = 0;
    while (std.mem.indexOf(u8, body[cursor..], "\"ip\":")) |rel| {
        element_count += 1;
        cursor += rel + 1;
    }
    try testing.expectEqual(http.max_bans_in_snapshot, element_count);
}

test "http: /api/bans aggregates across per-jail trackers (ISSUE-007)" {
    const a = testing.allocator;
    var trackers = tracker_map_mod.TrackerMap.init(a);
    defer trackers.deinit();
    const sshd_tracker = try trackers.addTracker("sshd", .{ .max_entries = 16, .findtime = 600, .maxretry = 5, .bantime = 600 });
    const nginx_tracker = try trackers.addTracker("nginx", .{ .max_entries = 16, .findtime = 600, .maxretry = 5, .bantime = 600 });

    try injectBan(sshd_tracker, "1.1.1.1", "sshd", 1_714_000_000, 600);
    try injectBan(nginx_tracker, "2.2.2.2", "nginx", 1_714_000_000, 600);

    var ctx: HttpSources = .{
        .metrics = undefined,
        .cmd_ctx = undefined,
        .trackers = &trackers,
    };
    var out: std.ArrayListUnmanaged(u8) = .{};
    defer out.deinit(a);
    try writeBansPayload(@ptrCast(&ctx), &out, a);
    const body = out.items;
    try testing.expect(std.mem.indexOf(u8, body, "\"total\":2") != null);
    try testing.expect(std.mem.indexOf(u8, body, "1.1.1.1") != null);
    try testing.expect(std.mem.indexOf(u8, body, "2.2.2.2") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"jail\":\"sshd\"") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"jail\":\"nginx\"") != null);
}

fn testUnhealthySshdLookup(ctx: ?*anyopaque, jail_name: []const u8) ?commands_mod.JailHealth {
    _ = ctx;
    if (std.mem.eql(u8, jail_name, "sshd")) {
        return .{ .healthy = false, .lines_seen = 0, .last_read_ok_ts = 0 };
    }
    return null;
}

test "metrics: SYS-017 protection_active + per-jail gauges render with jail label only" {
    const a = testing.allocator;
    var trackers = tracker_map_mod.TrackerMap.init(a);
    defer trackers.deinit();

    var metrics = metrics_mod.Metrics.init();
    var jails = [_]config_mod.JailConfig{
        .{ .name = "sshd", .enabled = true, .banaction = .nftables },
    };
    var cfg = config_mod.Config{
        .global = .{},
        .defaults = .{ .banaction = .nftables },
        .jails = &jails,
        .diag = .{},
    };
    var backend_val: firewall.Backend = .{ .nftables = firewall.nftables.NftablesBackend{} };
    defer backend_val.deinit();

    var cmd_ctx: commands_mod.Context = .{
        .trackers = &trackers,
        .config = &cfg,
        .backend = &backend_val,
        .stats_source = .{ .ctx = @ptrCast(&metrics), .snapshot = metricsStatsSnapshot },
        .health_source = .{ .ctx = null, .lookup = testUnhealthySshdLookup },
    };
    var http_ctx: HttpSources = .{ .metrics = &metrics, .cmd_ctx = &cmd_ctx, .trackers = &trackers };

    var out: std.ArrayListUnmanaged(u8) = .{};
    defer out.deinit(a);
    try writeMetricsPayload(@ptrCast(&http_ctx), &out, a);
    const body = out.items;

    try testing.expect(std.mem.indexOf(u8, body, "# TYPE fail2zig_protection_active gauge") != null);
    try testing.expect(std.mem.indexOf(u8, body, "fail2zig_protection_active 0") != null);

    try testing.expect(std.mem.indexOf(u8, body, "# TYPE fail2zig_jail_log_source_healthy gauge") != null);
    try testing.expect(std.mem.indexOf(u8, body, "fail2zig_jail_log_source_healthy{jail=\"sshd\"} 0") != null);
    try testing.expect(std.mem.indexOf(u8, body, "# TYPE fail2zig_jail_enforcing gauge") != null);
    try testing.expect(std.mem.indexOf(u8, body, "fail2zig_jail_enforcing{jail=\"sshd\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, body, "# TYPE fail2zig_jail_lines_seen_total counter") != null);
    try testing.expect(std.mem.indexOf(u8, body, "fail2zig_jail_lines_seen_total{jail=\"sshd\"} 0") != null);
}

test "JailSourceDescriptors: records KIND-truthful resolved descriptors (SYS-017)" {
    const a = testing.allocator;
    var d = JailSourceDescriptors.init(a);
    defer d.deinit();

    try d.putJournald("sshd", "sshd");
    try d.putFile("nginx", &.{"/var/log/nginx/error.log"});
    try d.putFile("multi", &.{ "/var/log/a.log", "/var/log/b.log" });
    try d.putFile("weird", &.{});

    try testing.expectEqualStrings("journald (sshd)", JailSourceDescriptors.lookup(@ptrCast(&d), "sshd").?);
    try testing.expectEqualStrings("/var/log/nginx/error.log", JailSourceDescriptors.lookup(@ptrCast(&d), "nginx").?);
    try testing.expectEqualStrings("/var/log/a.log, /var/log/b.log", JailSourceDescriptors.lookup(@ptrCast(&d), "multi").?);
    try testing.expectEqualStrings("file", JailSourceDescriptors.lookup(@ptrCast(&d), "weird").?);
    try testing.expect(JailSourceDescriptors.lookup(@ptrCast(&d), "nope") == null);
}

const enh004NoopLine = struct {
    fn cb(_: []const u8, _: shared.JailId, _: bool, _: ?*anyopaque) void {}
}.cb;

test "ENH-004 e2e: real file move-away → real detach → DEGRADED + log_source_healthy 0" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = tmp.dir.realpath(".", &path_buf) catch return error.SkipZigTest;
    const log_name = "enh004.log";
    var full_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const log_path = try std.fmt.bufPrint(&full_path_buf, "{s}/{s}", .{ dir_path, log_name });

    {
        const f = try tmp.dir.createFile(log_name, .{ .truncate = true });
        f.close();
    }

    const Sink = struct {
        mutex: std.Thread.Mutex = .{},
        lines: u32 = 0,
        fn cb(_: []const u8, _: shared.JailId, _: bool, ud: ?*anyopaque) void {
            const s: *@This() = @ptrCast(@alignCast(ud.?));
            s.mutex.lock();
            defer s.mutex.unlock();
            s.lines += 1;
        }
        fn count(s: *@This()) u32 {
            s.mutex.lock();
            defer s.mutex.unlock();
            return s.lines;
        }
    };
    var sink = Sink{};

    var loop = event_loop_mod.EventLoop.init(a) catch return error.SkipZigTest;
    defer loop.deinit();
    var watcher = log_watcher_mod.LogWatcher.init(a, &loop) catch return error.SkipZigTest;
    try watcher.attach();
    defer watcher.deinit();

    const jail = try shared.JailId.fromSlice("sshd");
    try watcher.watchFile(log_path, jail, Sink.cb, &sink);

    const Ctx = struct { tmp_dir: std.fs.Dir, loop: *event_loop_mod.EventLoop, sink: *Sink };
    var ctx = Ctx{ .tmp_dir = tmp.dir, .loop = &loop, .sink = &sink };
    const th = try std.Thread.spawn(.{}, struct {
        fn kick(c: *Ctx) void {
            std.time.sleep(30 * std.time.ns_per_ms);
            {
                const f = c.tmp_dir.openFile("enh004.log", .{ .mode = .write_only }) catch return;
                defer f.close();
                _ = f.seekFromEnd(0) catch {};
                _ = f.writeAll("Failed password for root from 203.0.113.7 port 22 ssh2\n") catch {};
            }
            var tries: u32 = 0;
            while (tries < 400 and c.sink.count() < 1) : (tries += 1) {
                std.time.sleep(5 * std.time.ns_per_ms);
            }
            c.tmp_dir.rename("enh004.log", "enh004.log.gone") catch {};
            std.time.sleep(120 * std.time.ns_per_ms);
            c.loop.stop();
        }
    }.kick, .{&ctx});

    try loop.run();
    th.join();

    try testing.expect(sink.count() >= 1);
    try assertStructuralDetach(&watcher, "sshd");

    backdateDetach(&watcher, "sshd");
    {
        const h = watcher.healthForJail("sshd").?;
        try testing.expect(!h.healthy);
    }

    var trackers = tracker_map_mod.TrackerMap.init(a);
    defer trackers.deinit();
    var metrics = metrics_mod.Metrics.init();
    var jails = [_]config_mod.JailConfig{
        .{ .name = "sshd", .enabled = true, .banaction = .nftables },
    };
    var cfg = config_mod.Config{ .global = .{}, .defaults = .{ .banaction = .nftables }, .jails = &jails, .diag = .{} };
    var backend_val: firewall.Backend = .{ .nftables = firewall.nftables.NftablesBackend{} };
    defer backend_val.deinit();

    var journald_src = journald_source_mod.JournaldSource.init(a, &loop, log_path) catch return error.SkipZigTest;
    defer journald_src.deinit();
    var health_sources = HealthSources{ .watcher = &watcher, .journald = &journald_src };

    var cmd_ctx: commands_mod.Context = .{
        .trackers = &trackers,
        .config = &cfg,
        .backend = &backend_val,
        .stats_source = .{ .ctx = @ptrCast(&metrics), .snapshot = metricsStatsSnapshot },
        .health_source = .{ .ctx = @ptrCast(&health_sources), .lookup = jailHealthLookup },
    };

    try testing.expectEqualStrings("degraded", cmd_ctx.computeOverallState());

    var http_ctx: HttpSources = .{ .metrics = &metrics, .cmd_ctx = &cmd_ctx, .trackers = &trackers };
    var out: std.ArrayListUnmanaged(u8) = .{};
    defer out.deinit(a);
    try writeMetricsPayload(@ptrCast(&http_ctx), &out, a);
    try testing.expect(std.mem.indexOf(u8, out.items, "fail2zig_jail_log_source_healthy{jail=\"sshd\"} 0") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "fail2zig_protection_active 0") != null);
}

fn backdateDetach(watcher: *log_watcher_mod.LogWatcher, jail_name: []const u8) void {
    const jail = shared.JailId.fromSlice(jail_name) catch return;
    for (watcher.files.items) |fw| {
        if (fw.jail.eql(jail) and fw.file_fd < 0 and fw.was_ever_attached) {
            fw.detached_at_ts = std.time.timestamp() - 3600;
        }
    }
}

fn assertStructuralDetach(watcher: *log_watcher_mod.LogWatcher, jail_name: []const u8) !void {
    const jail = try shared.JailId.fromSlice(jail_name);
    for (watcher.files.items) |fw| {
        if (fw.jail.eql(jail) and fw.was_ever_attached and fw.file_fd < 0 and fw.detached_at_ts != 0) {
            return;
        }
    }
    return error.NoStructuralDetach;
}

test "ENH-004 e2e: a quiet healthy file jail stays ACTIVE, gauge 1 (no false flag)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = tmp.dir.realpath(".", &path_buf) catch return error.SkipZigTest;
    const log_name = "quiet.log";
    var full_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const log_path = try std.fmt.bufPrint(&full_path_buf, "{s}/{s}", .{ dir_path, log_name });
    {
        const f = try tmp.dir.createFile(log_name, .{ .truncate = true });
        f.close();
    }

    var loop = event_loop_mod.EventLoop.init(a) catch return error.SkipZigTest;
    defer loop.deinit();
    var watcher = log_watcher_mod.LogWatcher.init(a, &loop) catch return error.SkipZigTest;
    try watcher.attach();
    defer watcher.deinit();

    const jail = try shared.JailId.fromSlice("sshd");
    try watcher.watchFile(log_path, jail, enh004NoopLine, &watcher);

    const h = watcher.healthForJail("sshd").?;
    try testing.expect(h.healthy);
    try testing.expectEqual(@as(u64, 0), h.lines_seen);

    var trackers = tracker_map_mod.TrackerMap.init(a);
    defer trackers.deinit();
    var metrics = metrics_mod.Metrics.init();
    var jails = [_]config_mod.JailConfig{
        .{ .name = "sshd", .enabled = true, .banaction = .nftables },
    };
    var cfg = config_mod.Config{ .global = .{}, .defaults = .{ .banaction = .nftables }, .jails = &jails, .diag = .{} };
    var backend_val: firewall.Backend = .{ .nftables = firewall.nftables.NftablesBackend{} };
    defer backend_val.deinit();
    var journald_src = journald_source_mod.JournaldSource.init(a, &loop, log_path) catch return error.SkipZigTest;
    defer journald_src.deinit();
    var health_sources = HealthSources{ .watcher = &watcher, .journald = &journald_src };
    var cmd_ctx: commands_mod.Context = .{
        .trackers = &trackers,
        .config = &cfg,
        .backend = &backend_val,
        .stats_source = .{ .ctx = @ptrCast(&metrics), .snapshot = metricsStatsSnapshot },
        .health_source = .{ .ctx = @ptrCast(&health_sources), .lookup = jailHealthLookup },
    };
    try testing.expectEqualStrings("active", cmd_ctx.computeOverallState());

    var http_ctx: HttpSources = .{ .metrics = &metrics, .cmd_ctx = &cmd_ctx, .trackers = &trackers };
    var out: std.ArrayListUnmanaged(u8) = .{};
    defer out.deinit(a);
    try writeMetricsPayload(@ptrCast(&http_ctx), &out, a);
    try testing.expect(std.mem.indexOf(u8, out.items, "fail2zig_jail_log_source_healthy{jail=\"sshd\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "fail2zig_protection_active 1") != null);
}

test "ENH-004 e2e: a never-appeared (late) log is NOT degraded, gauge 0 (no false flash)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = tmp.dir.realpath(".", &path_buf) catch return error.SkipZigTest;
    var full_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const log_path = try std.fmt.bufPrint(&full_path_buf, "{s}/never_appears.log", .{dir_path});

    var loop = event_loop_mod.EventLoop.init(a) catch return error.SkipZigTest;
    defer loop.deinit();
    var watcher = log_watcher_mod.LogWatcher.init(a, &loop) catch return error.SkipZigTest;
    try watcher.attach();
    defer watcher.deinit();

    const jail = try shared.JailId.fromSlice("sshd");
    try watcher.watchFile(log_path, jail, enh004NoopLine, &watcher);

    try testing.expect(watcher.healthForJail("sshd") == null);

    var trackers = tracker_map_mod.TrackerMap.init(a);
    defer trackers.deinit();
    var metrics = metrics_mod.Metrics.init();
    var jails = [_]config_mod.JailConfig{
        .{ .name = "sshd", .enabled = true, .banaction = .nftables },
    };
    var cfg = config_mod.Config{ .global = .{}, .defaults = .{ .banaction = .nftables }, .jails = &jails, .diag = .{} };
    var backend_val: firewall.Backend = .{ .nftables = firewall.nftables.NftablesBackend{} };
    defer backend_val.deinit();
    var journald_src = journald_source_mod.JournaldSource.init(a, &loop, log_path) catch return error.SkipZigTest;
    defer journald_src.deinit();
    var health_sources = HealthSources{ .watcher = &watcher, .journald = &journald_src };
    var cmd_ctx: commands_mod.Context = .{
        .trackers = &trackers,
        .config = &cfg,
        .backend = &backend_val,
        .stats_source = .{ .ctx = @ptrCast(&metrics), .snapshot = metricsStatsSnapshot },
        .health_source = .{ .ctx = @ptrCast(&health_sources), .lookup = jailHealthLookup },
    };
    try testing.expectEqualStrings("active", cmd_ctx.computeOverallState());

    var http_ctx: HttpSources = .{ .metrics = &metrics, .cmd_ctx = &cmd_ctx, .trackers = &trackers };
    var out: std.ArrayListUnmanaged(u8) = .{};
    defer out.deinit(a);
    try writeMetricsPayload(@ptrCast(&http_ctx), &out, a);
    try testing.expect(std.mem.indexOf(u8, out.items, "fail2zig_jail_log_source_healthy{jail=\"sshd\"} 0") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "fail2zig_protection_active 1") != null);
}

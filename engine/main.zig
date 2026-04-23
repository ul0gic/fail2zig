// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! fail2zig daemon entry point.
//!
//! Responsibilities:
//!   1. Parse CLI args (--config, --version, --help, --test-config,
//!      --foreground, --import-config).
//!   2. Load + validate config.
//!   3. Build the memory pool from the config ceiling.
//!   4. Detect the firewall backend (or fail closed if none available).
//!   5. Initialize the state tracker; seed it from the persisted state
//!      file if present.
//!   6. For each enabled jail, wire a `Parser` + `LogWatcher` per
//!      `logpath`, with a static line callback that routes matches
//!      through the state tracker and on ban decisions into the
//!      firewall backend.
//!   7. Install signal handlers (SIGTERM/SIGINT save state + exit,
//!      SIGHUP logs "reload not yet implemented").
//!   8. Arm a 1s periodic timer that scans for expired bans and calls
//!      `backend.unban` for each.
//!   9. Enter the event loop until stopped.
//!
//! Every allocating step is backed by either the memory pool (per
//! component) or a process-lifetime arena (for config strings and
//! per-jail contexts). The steady-state hot path — log line → parse →
//! state update → (maybe) ban — is allocation-free on the happy path.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;

const shared = @import("shared");

// Wire all engine modules into the build graph so their tests are discovered.
// Modules reached by integration tests (via the named `engine` module) are
// `pub const`; the rest stay private.
const allocator_mod = @import("core/allocator.zig");
const memory_mod = @import("core/memory.zig");
pub const event_loop_mod = @import("core/event_loop.zig");
const log_watcher_mod = @import("core/log_watcher.zig");
const line_buffer_mod = @import("core/line_buffer.zig");
const logger_mod = @import("core/logger.zig");
const parser_mod = @import("core/parser.zig");
pub const state_mod = @import("core/state.zig");
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

pub const version = "0.1.0";

// ============================================================================
// CLI argument parsing
// ============================================================================

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

/// Parsed command-line options. String fields are slices into the owning
/// arena (for tests) or into the argv storage returned by `std.process.argsAlloc`.
pub const CliOptions = struct {
    action: CliAction = .run,
    config_path: []const u8 = "/etc/fail2zig/config.toml",
    /// Source directory passed to `--import-config`. Defaults to
    /// fail2ban's standard location.
    import_path: ?[]const u8 = null,
    /// Destination path for `--import-config` output. Defaults to
    /// fail2zig's standard config location so the workflow
    /// `fail2zig --import-config` → `fail2zig` just works.
    import_output: []const u8 = "/etc/fail2zig/config.toml",
    foreground: bool = true, // v0.1: foreground-only
};

/// Parse command-line arguments from a slice (test-friendly; the real
/// entry point feeds in `std.process.argsAlloc`-produced slices).
pub fn parseArgs(args: []const []const u8) CliError!CliOptions {
    var out: CliOptions = .{};
    var i: usize = 1; // skip argv[0]
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) {
            out.action = .print_help;
        } else if (std.mem.eql(u8, a, "--version") or std.mem.eql(u8, a, "-V")) {
            out.action = .print_version;
        } else if (std.mem.eql(u8, a, "--test-config")) {
            out.action = .test_config;
        } else if (std.mem.eql(u8, a, "--validate-config")) {
            // Alias of --test-config with clearer naming — we still keep
            // --test-config for backward compatibility with early release docs.
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
            // Optional argument: if the next token looks like a path (not
            // a flag), consume it; otherwise default to /etc/fail2ban.
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

// ============================================================================
// Migration driver — small wrapper so tests can drive it without spawning
// the whole daemon. Returns the same exit code the CLI surfaces.
// ============================================================================

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

// ============================================================================
// Jail context — glue between log watcher, parser, state, backend
// ============================================================================

const JailContext = struct {
    jail: shared.JailId,
    parser: parser_mod.Parser,
    state: *state_mod.StateTracker,
    backend_ptr: *firewall.Backend,
    /// Metrics is nullable for tests that don't care about counters —
    /// the daemon always supplies a real pointer.
    metrics: ?*metrics_mod.Metrics = null,
    /// Dashboard WS server. Nullable for tests; the daemon always
    /// supplies a real pointer. When present, every parsed match
    /// broadcasts `attack_detected` and every ban broadcasts
    /// `ip_banned` so live dashboards can render in real time.
    ws: ?*ws.WsServer = null,
    /// Allocator used to render event payload strings before handing
    /// them to WS broadcast. A small FBA would be nicer, but the
    /// broadcasts are rare (per-match, per-ban), payloads are tiny
    /// (<200 B), and the daemon's heap allocator tolerates this fine.
    ws_alloc: ?std.mem.Allocator = null,
    /// Current wall-clock is read at callback time; stored here so tests
    /// can override it. In production this stays at null.
    now_override: ?shared.Timestamp = null,

    fn now(self: *const JailContext) shared.Timestamp {
        if (self.now_override) |t| return t;
        return std.time.timestamp();
    }
};

fn lineCallback(
    line: []const u8,
    _jail: shared.JailId,
    truncated: bool,
    userdata: ?*anyopaque,
) void {
    _ = _jail; // we use the jail from the context (authoritative)
    if (truncated) {
        // Truncated lines are suspicious (too long). Drop and move on —
        // a partial line can't reliably yield a ban decision.
        return;
    }
    const ctx: *JailContext = @ptrCast(@alignCast(userdata.?));
    if (ctx.metrics) |m| {
        m.incrementParsed();
        m.jailIncrementParsed(ctx.jail.slice());
    }

    // QA-001: strip the syslog envelope before pattern anchoring. Built-in
    // filter patterns match against the program-emitted message body
    // (e.g. `Failed password for ...`), not against the rsyslog-framed
    // line (`Apr 21 10:15:03 host sshd[1234]: Failed password ...`).
    // `stripSyslogPrefix` returns the same slice unchanged when no
    // syslog envelope is detected — zero-alloc, zero-cost on non-syslog
    // inputs (e.g. journalctl-piped lines where the prefix is absent).
    const body = parser_mod.stripSyslogPrefix(line);

    const result = ctx.parser.parseLine(body) catch {
        if (ctx.metrics) |m| {
            m.incrementParseErrors();
            m.jailIncrementParseErrors(ctx.jail.slice());
        }
        return;
    };
    if (ctx.metrics) |m| {
        m.incrementMatched();
        m.jailIncrementMatched(ctx.jail.slice());
    }
    const ts = ctx.now();

    // CRITICAL PRIVACY CHECK: if the IP is in `ignoreip`, do NOT
    // broadcast anything to the public WS feed. `ignoreip` exists
    // specifically to exempt operator + trusted infrastructure IPs
    // from ban decisions; before this guard, we were matching the
    // filter and emitting `attack_detected` for every operator SSH
    // session, leaking the operator's real IP to anyone watching
    // see-it-live. `recordAttempt` short-circuits for ignored IPs
    // internally (no ban decision), so we also skip it here — both
    // to save a hash lookup and to keep the control flow obvious.
    const ignored = ctx.state.isIgnored(result.ip);

    // Broadcast `attack_detected` on every non-ignored match. Live
    // dashboards render these as they stream in; `ip_banned` alone
    // would leave the terminal pane empty in findtime windows where
    // hits don't cross the retry threshold. Failure to broadcast is
    // non-fatal.
    //
    // `pattern_name` would ideally be the specific filter pattern
    // (e.g. "failed-password"), but the parser exposes only
    // `matched_pattern_id: u16` today — resolving id→name needs a
    // per-jail lookup table. For now we pass the jail name so the
    // frontend has something non-empty; plumbing actual pattern names
    // through is Phase 10 polish (see SYS-012 TODO).
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

    // Ignored IPs never yield a ban decision, so we skip the state
    // tracker call entirely. Anything downstream (ban broadcasts,
    // nftables install) is therefore unreachable for ignored IPs.
    if (ignored) return;

    const decision = ctx.state.recordAttempt(result.ip, ctx.jail, ts) catch |err| {
        std.log.warn(
            "state: recordAttempt failed for jail '{s}': {s}",
            .{ ctx.jail.slice(), @errorName(err) },
        );
        return;
    };
    if (decision) |d| {
        std.log.info(
            "ban: jail='{s}' ip={} duration={d}s ban_count={d}",
            .{ ctx.jail.slice(), d.ip, d.duration, d.ban_count },
        );
        ctx.backend_ptr.ban(d.ip, d.jail, d.duration) catch |err| {
            std.log.warn(
                "backend: ban failed for ip={} jail='{s}': {s}",
                .{ d.ip, ctx.jail.slice(), @errorName(err) },
            );
            return;
        };
        if (ctx.metrics) |m| {
            m.incrementBans();
            m.jailIncrementBans(ctx.jail.slice());
        }
        // Broadcast `ip_banned` after the kernel ban is confirmed.
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
}

// ============================================================================
// Ban expiry sweep (periodic timer)
// ============================================================================

const ExpiryContext = struct {
    state: *state_mod.StateTracker,
    backend_ptr: *firewall.Backend,
    metrics: ?*metrics_mod.Metrics = null,
    ws: ?*ws.WsServer = null,
    ws_alloc: ?std.mem.Allocator = null,
};

fn expirySweep(expirations: u64, userdata: ?*anyopaque) void {
    _ = expirations;
    const ctx: *ExpiryContext = @ptrCast(@alignCast(userdata.?));
    const now = std.time.timestamp();

    // Collect expired IPs into a small stack buffer; HashMap iteration
    // while mutating the map is unsafe. 64 per tick keeps the cadence
    // reasonable even under high expiry load.
    const max_per_tick: usize = 64;
    var to_unban: [max_per_tick]struct {
        ip: shared.IpAddress,
        jail: shared.JailId,
    } = undefined;
    var n: usize = 0;

    var it = ctx.state.iterator();
    while (it.next()) |kv| {
        if (n >= max_per_tick) break;
        const st = kv.value_ptr;
        if (st.ban_state != .banned) continue;
        const exp = st.ban_expiry orelse continue;
        if (exp <= now) {
            to_unban[n] = .{ .ip = kv.key_ptr.*, .jail = st.jail };
            n += 1;
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
        ctx.state.clearBan(item.ip);
        if (ctx.metrics) |m| {
            m.incrementUnbans();
            m.jailIncrementUnbans(item.jail.slice());
        }
        std.log.info(
            "unban: jail='{s}' ip={}",
            .{ item.jail.slice(), item.ip },
        );
        // Broadcast `ip_unbanned` so dashboards can visually retire the
        // entry as soon as nftables has dropped it. Non-fatal on error.
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

// ============================================================================
// WS tick — heartbeat + periodic metrics push (1 Hz)
// ============================================================================
//
// Without this, the /events stream is silent between filter matches.
// Live dashboards need to show forward motion even during attack lulls;
// they also need ping/pong so CF and clients keep the WS alive.
const WsTickContext = struct {
    ws: *ws.WsServer,
    metrics: *metrics_mod.Metrics,
    ws_alloc: std.mem.Allocator,
    start_time: i64,
};

/// Read `VmRSS` from `/proc/self/status` and return bytes. Linux-only.
/// On any I/O or parse failure returns an error — callers should
/// treat that as "gauge unavailable this tick" and skip the update.
fn readSelfRssBytes() !u64 {
    var file = std.fs.openFileAbsolute("/proc/self/status", .{}) catch |err| return err;
    defer file.close();
    var buf: [8192]u8 = undefined;
    const n = file.readAll(&buf) catch |err| return err;
    const contents = buf[0..n];
    // Line shape: "VmRSS:\t   12345 kB"
    const needle = "VmRSS:";
    const idx = std.mem.indexOf(u8, contents, needle) orelse return error.NotFound;
    const tail = contents[idx + needle.len ..];
    const nl = std.mem.indexOfScalar(u8, tail, '\n') orelse tail.len;
    const line = tail[0..nl];
    // Extract the first run of decimal digits.
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

    // Heartbeat: send pings to silent clients, drop any that haven't
    // pong'd in time. Cheap; no-op if there are no clients.
    ctx.ws.tickHeartbeat();

    // Refresh the RSS gauge before snapshotting. /proc/self/status is
    // kernel-maintained; the VmRSS line is ~40 bytes in a ~8 KiB text
    // file — a single read + strtoul per second is vanishing overhead.
    // Falls back silently on non-Linux or an open-failure.
    if (readSelfRssBytes()) |rss_bytes| {
        ctx.metrics.setMemoryBytes(rss_bytes);
    } else |_| {}

    const snap = ctx.metrics.snapshot();
    const uptime_s: u64 = blk: {
        const now = std.time.timestamp();
        if (now <= ctx.start_time) break :blk 0;
        break :blk @intCast(now - ctx.start_time);
    };

    ctx.ws.broadcastMetrics(ctx.ws_alloc, .{
        .lines_parsed = snap.lines_parsed,
        .lines_matched = snap.lines_matched,
        .bans_total = snap.bans_total,
        .active_bans = snap.active_bans,
        .memory_bytes_used = snap.memory_bytes_used,
        .uptime_s = uptime_s,
    }) catch |err| {
        std.log.warn("ws: broadcastMetrics failed: {s}", .{@errorName(err)});
    };
}

// ============================================================================
// Signal handlers
// ============================================================================

const SignalContext = struct {
    loop: *event_loop_mod.EventLoop,
    state: *state_mod.StateTracker,
    state_path: []const u8,
    save_requested: bool = false,
};

fn onTerminate(siginfo: *const linux.signalfd_siginfo, userdata: ?*anyopaque) void {
    _ = siginfo;
    const ctx: *SignalContext = @ptrCast(@alignCast(userdata.?));
    ctx.save_requested = true;
    std.log.info("signal: termination requested, saving state and shutting down", .{});
    persist_mod.save(ctx.state, ctx.state_path) catch |err| {
        std.log.warn("persist: save failed on shutdown: {s}", .{@errorName(err)});
    };
    ctx.loop.stop();
}

fn onReload(siginfo: *const linux.signalfd_siginfo, userdata: ?*anyopaque) void {
    _ = siginfo;
    _ = userdata;
    std.log.info("signal: SIGHUP received — reload not yet implemented", .{});
}

// ============================================================================
// Tracker config derivation from parsed config
// ============================================================================

fn deriveTrackerConfig(cfg: *const config_mod.Config, max_entries: u32) state_mod.Config {
    const d = cfg.defaults;
    // SYS-008: translate `config.native.BanTimeIncrement` into the
    // state tracker's shape. The two structs carry the same fields but
    // are defined independently (state has zero config-layer imports).
    // Per-jail `bantime_increment` on JailConfig is parsed but
    // currently inactive (single global tracker). When per-jail
    // tracking lands in Phase 2, this will read from the active jail's
    // resolved settings instead of defaults.
    const incr: state_mod.BanTimeIncrement = .{
        .enabled = d.bantime_increment.enabled,
        .multiplier = d.bantime_increment.multiplier,
        .factor = d.bantime_increment.factor,
        .formula = switch (d.bantime_increment.formula) {
            .linear => .linear,
            .exponential => .exponential,
        },
        .max_bantime = d.bantime_increment.max_bantime,
    };
    return .{
        .max_entries = max_entries,
        .findtime = d.findtime,
        .maxretry = d.maxretry,
        .bantime = d.bantime,
        .bantime_increment = incr,
        .eviction_policy = .drop_oldest_unbanned,
    };
}

fn deriveMemoryConfig(cfg: *const config_mod.Config) memory_mod.MemoryConfig {
    // Scale each component proportionally to the ceiling. The default
    // schema (64MB) matches memory_mod's defaults exactly.
    const ceiling_bytes: usize = @as(usize, cfg.global.memory_ceiling_mb) * memory_mod.one_mb;
    // Shares: state 50%, parser 6%, event 2%, log 12%. Sum = 70%.
    // Leftover 30% is headroom (future components, fragmentation safety).
    const state_bytes = ceiling_bytes / 2;
    const parser_bytes = @max(@as(usize, 1) * memory_mod.one_mb, ceiling_bytes / 16);
    const event_bytes = @max(@as(usize, 512 * 1024), ceiling_bytes / 64);
    const log_bytes = @max(@as(usize, 2) * memory_mod.one_mb, ceiling_bytes / 8);
    return .{
        .state_tracker_bytes = state_bytes,
        .parser_buffer_bytes = parser_bytes,
        .event_queue_bytes = event_bytes,
        .log_buffer_bytes = log_bytes,
        .total_ceiling_bytes = ceiling_bytes,
    };
}

// ============================================================================
// Entry point
// ============================================================================

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

    // Load config.
    var cfg_arena = std.heap.ArenaAllocator.init(heap);
    defer cfg_arena.deinit();
    const cfg = config_mod.Config.loadFile(cfg_arena.allocator(), opts.config_path) catch |err| {
        const stderr = std.io.getStdErr().writer();
        try stderr.print("config: failed to load '{s}': {s}\n", .{ opts.config_path, @errorName(err) });
        std.process.exit(1);
    };

    // Ensure the socket directory exists before `validate()` checks it.
    // On `--test-config` / `--validate-config` we skip the mkdir — the
    // validator treats a missing dir as a hard error, which is what
    // operators want when they're troubleshooting from a laptop without
    // root.
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

    // Run the daemon.
    try runDaemon(heap, &cfg);
}

/// Bridges `reconcile_mod.reconcileRestoredBans` to the live firewall
/// backend. `ctx` is a `*firewall.Backend`. Treats `AlreadyBanned` as
/// idempotent success; surfaces any other failure as a warn log +
/// error return so reconcile counts it as a failed apply and moves on
/// to the next entry.
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

fn runDaemon(heap: std.mem.Allocator, cfg: *const config_mod.Config) !void {
    // Memory pool.
    const mem_cfg = deriveMemoryConfig(cfg);
    var pool = memory_mod.MemoryPool.init(mem_cfg) catch |err| {
        std.log.err("memory: pool init failed: {s}", .{@errorName(err)});
        return err;
    };
    defer pool.deinit();

    // Metrics (atomic counters). Cheap; construct before anything that
    // increments them.
    var metrics = metrics_mod.Metrics.init();
    for (cfg.jails) |jc| {
        if (!jc.enabled) continue;
        _ = metrics.registerJail(jc.name);
    }

    // Firewall backend.
    var backend_val = firewall.detect(heap) catch |err| {
        std.log.err("firewall: no backend available ({s}) — refusing to run unprotected", .{@errorName(err)});
        return err;
    };
    backend_val.init(.{}, heap) catch |err| {
        std.log.err("firewall: backend init failed: {s}", .{@errorName(err)});
        return err;
    };
    defer backend_val.deinit();

    // State tracker.
    const tracker_capacity = state_mod.capacityFromBudget(mem_cfg.state_tracker_bytes);
    const tracker_cfg = deriveTrackerConfig(cfg, tracker_capacity);
    var tracker = state_mod.StateTracker.init(heap, tracker_cfg) catch |err| {
        std.log.err("state: tracker init failed: {s}", .{@errorName(err)});
        return err;
    };
    defer tracker.deinit();

    // Global ignore CIDRs.
    for (cfg.defaults.ignoreip) |spec| {
        tracker.addIgnoreCidr(spec) catch |err| {
            std.log.warn("state: ignoreip '{s}' rejected: {s}", .{ spec, @errorName(err) });
        };
    }

    // Seed state from disk.
    if (persist_mod.load(heap, cfg.global.state_file)) |entries| {
        defer heap.free(entries);
        if (entries.len > 0) {
            persist_mod.seed(&tracker, entries) catch |err| {
                std.log.warn("persist: seed failed: {s}", .{@errorName(err)});
            };
            std.log.info("persist: restored {d} state entries", .{entries.len});
        }
    } else |err| {
        std.log.warn("persist: load failed: {s}", .{@errorName(err)});
    }

    // Reconcile the firewall backend with restored state (SYS-007).
    //
    // The backend's scaffold was freshly installed by `backend.init` —
    // its ban sets are empty regardless of what was active before the
    // restart. The state tracker holds the restored bans. Without this
    // step the kernel silently stops enforcing those bans until a fresh
    // ban decision fires. Logic extracted into core/reconcile.zig so
    // it's testable without spinning up the whole daemon.
    {
        const now = std.time.timestamp();
        const reinstalled = reconcile_mod.reconcileRestoredBans(
            heap,
            &tracker,
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

    // Event loop.
    var loop = event_loop_mod.EventLoop.init(heap) catch |err| {
        std.log.err("event_loop: init failed: {s}", .{@errorName(err)});
        return err;
    };
    defer loop.deinit();

    // Log watcher.
    var watcher = log_watcher_mod.LogWatcher.init(heap, &loop) catch |err| {
        std.log.err("log_watcher: init failed: {s}", .{@errorName(err)});
        return err;
    };
    defer watcher.deinit();
    try watcher.attach();

    // Per-jail contexts. Heap-allocated so their pointers remain stable
    // across the event loop lifetime (the watcher's userdata field holds
    // these pointers).
    var contexts = std.ArrayList(*JailContext).init(heap);
    defer {
        for (contexts.items) |ctx| heap.destroy(ctx);
        contexts.deinit();
    }

    for (cfg.jails) |jail_cfg| {
        if (!jail_cfg.enabled) continue;
        const jail = shared.JailId.fromSlice(jail_cfg.name) catch |err| {
            std.log.warn("jail '{s}' rejected: {s}", .{ jail_cfg.name, @errorName(err) });
            continue;
        };
        const ctx = try heap.create(JailContext);
        ctx.* = .{
            .jail = jail,
            .parser = parser_mod.Parser.init(pool.allocator(.parser_buffer)),
            .state = &tracker,
            .backend_ptr = &backend_val,
            .metrics = &metrics,
        };
        try contexts.append(ctx);

        for (jail_cfg.logpath) |lp| {
            watcher.watchFile(lp, jail, lineCallback, ctx) catch |err| {
                std.log.warn(
                    "log_watcher: watchFile '{s}' (jail '{s}') failed: {s}",
                    .{ lp, jail_cfg.name, @errorName(err) },
                );
                continue;
            };
        }
        std.log.info("jail: enabled '{s}' ({d} logpath(s))", .{ jail_cfg.name, jail_cfg.logpath.len });
    }

    // IPC command handler context. Must outlive the IpcServer and HTTP
    // status source. start_time captured here so uptime reflects the
    // operational start.
    var cmd_ctx: commands_mod.Context = .{
        .state = &tracker,
        .config = cfg,
        .backend = &backend_val,
        .stats_source = .{
            .ctx = @ptrCast(&metrics),
            .snapshot = metricsStatsSnapshot,
        },
        .start_time = std.time.timestamp(),
        .version = version,
    };

    // IPC server. The caller (`main()`) has already ensured
    // `socket_path`'s parent directory exists, so bind(2) can't fail on
    // ENOENT here.

    var ipc_server = ipc_mod.IpcServer.init(heap, &loop, cfg.global.socket_path) catch |err| {
        std.log.err("ipc: init failed at '{s}': {s}", .{ cfg.global.socket_path, @errorName(err) });
        return err;
    };
    defer ipc_server.deinit();
    ipc_server.setCommandHandler(cmd_ctx.asHandler());
    try ipc_server.start();

    // WebSocket server — state-only, the HTTP server owns the listener.
    // Client cap comes from `[global] websocket_max_clients` (default 16,
    // capped at `ws.hard_max_clients` by the config validator).
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

    // HTTP server (metrics + status + /events WebSocket upgrade).
    var http_ctx: HttpSources = .{
        .metrics = &metrics,
        .cmd_ctx = &cmd_ctx,
        .state = &tracker,
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

    // Now that the WS server exists, wire it into every per-jail
    // context so lineCallback can broadcast `attack_detected` +
    // `ip_banned` events. Without this, dashboards subscribe to a
    // silent channel — every parse + every ban happens, but nothing
    // streams to the see-it-live page.
    for (contexts.items) |jctx| {
        jctx.ws = &ws_server;
        jctx.ws_alloc = heap;
    }

    // Signal handlers. Order matters: install TERM/INT before HUP so
    // tests can observe TERM behaviour without HUP interference.
    var sig_ctx = SignalContext{
        .loop = &loop,
        .state = &tracker,
        .state_path = cfg.global.state_file,
    };
    try loop.addSignalHandler(linux.SIG.TERM, onTerminate, &sig_ctx);
    try loop.addSignalHandler(linux.SIG.INT, onTerminate, &sig_ctx);
    try loop.addSignalHandler(linux.SIG.HUP, onReload, &sig_ctx);

    // Ban expiry timer.
    var expiry_ctx = ExpiryContext{
        .state = &tracker,
        .backend_ptr = &backend_val,
        .metrics = &metrics,
        .ws = &ws_server,
        .ws_alloc = heap,
    };
    _ = try loop.addTimer(1000, expirySweep, &expiry_ctx, false);

    // WS heartbeat + 1 Hz metrics push. Keeps the dashboard's terminal
    // pane alive between attack matches and keeps the WS pings flowing
    // so CF doesn't idle-close the stream.
    var ws_tick_ctx = WsTickContext{
        .ws = &ws_server,
        .metrics = &metrics,
        .ws_alloc = heap,
        .start_time = cmd_ctx.start_time,
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

    try loop.run();

    // Final state save on clean shutdown (best-effort; ignore errors).
    persist_mod.save(&tracker, cfg.global.state_file) catch {};

    // Explicit teardown order: close IPC/HTTP/WS first so their FDs are
    // no longer registered with the loop when `loop.deinit` runs below
    // via `defer`. Deferred calls run in reverse, so the defers above
    // will fire in the correct order already — but if the loop exits
    // abnormally, logging here surfaces it.
    std.log.info("fail2zig: shutting down", .{});
}

// ============================================================================
// Service helpers
// ============================================================================

/// Ensure the parent directory of `socket_path` exists. Created with
/// mode 0710 so the root user can write and members of the fail2zig
/// group can traverse it (to reach the socket file itself). On
/// AlreadyExists this is a no-op — any other error is surfaced because
/// it would prevent `bind(2)` from succeeding later.
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
    // Best-effort chmod to 0710 — root/rw, group/x, other/none. If
    // chmod fails (e.g. the directory is not owned by us), log and
    // continue; the bind() still works if the parent is at least
    // traversable by the daemon.
    std.posix.fchmodat(std.posix.AT.FDCWD, dir, 0o710, 0) catch |err| {
        std.log.warn(
            "ipc: chmod of socket parent dir '{s}' failed: {s}",
            .{ dir, @errorName(err) },
        );
    };
}

// ============================================================================
// Metrics / HTTP glue — decoupling shims between metrics.zig and the
// source-vtables defined by http.zig and commands.zig.
// ============================================================================

/// Adapter invoked from `commands.StatsSource.snapshot` to read the live
/// metrics counters. Lives in main.zig so `net/commands.zig` doesn't
/// take a compile-time dependency on `core/metrics.zig`.
fn metricsStatsSnapshot(ctx: ?*anyopaque) commands_mod.StatsSnapshot {
    const m: *metrics_mod.Metrics = @ptrCast(@alignCast(ctx.?));
    const s = m.snapshot();
    return .{
        .memory_bytes_used = s.memory_bytes_used,
        .parse_rate = 0, // computed across an interval; Phase 6 improvement.
    };
}

/// Bundle of pointers the HTTP `/metrics`, `/api/status`, and
/// `/api/bans` handlers need. Kept together so we only plumb one `ctx`
/// pointer through each source vtable.
const HttpSources = struct {
    metrics: *metrics_mod.Metrics,
    cmd_ctx: *commands_mod.Context,
    state: *state_mod.StateTracker,
};

/// MetricsSource.write implementation — renders the Prometheus text
/// exposition for all live counters.
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

    // Uptime exposed directly (vs relying on Prometheus' derive-
    // from-process_start_time convention). Operators scraping this
    // get a simple counter they can render without client-side
    // arithmetic; the dashboard's MetricsPane reads this verbatim.
    const uptime_s: u64 = blk: {
        const now = std.time.timestamp();
        if (now <= self.cmd_ctx.start_time) break :blk 0;
        break :blk @intCast(now - self.cmd_ctx.start_time);
    };
    try w.writeAll("# HELP fail2zig_uptime_seconds Seconds since daemon start\n");
    try w.writeAll("# TYPE fail2zig_uptime_seconds gauge\n");
    try w.print("fail2zig_uptime_seconds {d}\n", .{uptime_s});

    // Per-jail labels.
    for (snap.perJail()) |pj| {
        const name = pj.name();
        try w.print("fail2zig_lines_parsed_total{{jail=\"{s}\"}} {d}\n", .{ name, pj.lines_parsed });
        try w.print("fail2zig_lines_matched_total{{jail=\"{s}\"}} {d}\n", .{ name, pj.lines_matched });
        try w.print("fail2zig_bans_total{{jail=\"{s}\"}} {d}\n", .{ name, pj.bans_total });
        try w.print("fail2zig_unbans_total{{jail=\"{s}\"}} {d}\n", .{ name, pj.unbans_total });
        try w.print("fail2zig_active_bans{{jail=\"{s}\"}} {d}\n", .{ name, pj.active_bans });
    }
}

/// StatusSource.write implementation — delegates to the same JSON
/// renderer the IPC `status` command uses. Guarantees the dashboard and
/// the CLI see identical data shapes.
fn writeStatusPayload(
    ctx: ?*anyopaque,
    out: *std.ArrayListUnmanaged(u8),
    a: std.mem.Allocator,
) anyerror!void {
    const self: *HttpSources = @ptrCast(@alignCast(ctx.?));
    // Go through the installed handler vtable so `/api/status` emits
    // byte-identical JSON to what the IPC `status` command produces.
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

/// BansSource.write implementation — walks the state tracker and emits
/// the active-ban snapshot consumed by `NftSetPane` on the see-it-live
/// dashboard. Wire contract documented in
/// `.project/design/demo-concept.md`:
///
/// ```
/// {
///   "total": N,
///   "entries": [
///     {"ip":"...","jail":"...","banned_at":"<ISO-8601 UTC>","seconds_remaining":N}
///   ]
/// }
/// ```
///
/// `total` reflects the full number of active bans; `entries` is
/// truncated at `http.max_bans_in_snapshot` (200) so the response
/// stays bounded. `seconds_remaining` is `max(0, ban_expiry - now)`.
/// `banned_at` is an ISO-8601 UTC string reconstructed from
/// `ban_expiry - duration`; see Phase 10 for persisting a real ban
/// start time.
fn writeBansPayload(
    ctx: ?*anyopaque,
    out: *std.ArrayListUnmanaged(u8),
    a: std.mem.Allocator,
) anyerror!void {
    const self: *HttpSources = @ptrCast(@alignCast(ctx.?));
    const w = out.writer(a);

    // First pass: count active bans (so `total` is accurate even when
    // we truncate `entries`).
    var total: u32 = 0;
    {
        var it = self.state.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.ban_state == .banned) total += 1;
        }
    }

    try w.writeAll("{\"total\":");
    try w.print("{d}", .{total});
    try w.writeAll(",\"entries\":[");

    const now_s: i64 = std.time.timestamp();
    const cfg = self.state.config;

    var written: usize = 0;
    var it = self.state.iterator();
    while (it.next()) |kv| {
        if (kv.value_ptr.ban_state != .banned) continue;
        if (written >= http.max_bans_in_snapshot) break;
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

    try w.writeAll("]}");
}

// ============================================================================
// Tests
// ============================================================================

test "engine: version constant" {
    try std.testing.expectEqualStrings("0.1.0", version);
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

    // Only a DEFAULT section — no user jails = zero imported.
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

    // A source with an oversized jail.conf would exceed our bound and fail
    // parsing. Here we just point at a non-existent path: loadJailConfig
    // handles that gracefully (returns empty ini) so the next non-success
    // code path to exercise is filesystem-level. We simulate by asking
    // for an output path inside a nonexistent directory — writeTomlAtomic
    // will attempt to create it, but we'll also feed an unwritable output
    // to force WriteFailed.
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

    // Writing under a file-as-directory path fails.
    try tmp.dir.writeFile(.{ .sub_path = "blocker", .data = "x" });
    const bad_out = try std.fs.path.join(arena.allocator(), &.{ source, "blocker", "out.toml" });

    const rc = runImport(std.testing.allocator, source, bad_out, stderr_buf.writer());
    try std.testing.expectEqual(@as(u8, 2), rc);
}

test "main: deriveMemoryConfig splits ceiling sensibly" {
    const cfg: config_mod.Config = .{
        .global = .{ .memory_ceiling_mb = 64 },
        .defaults = .{},
        .jails = &.{},
        .diag = .{},
    };
    const m = deriveMemoryConfig(&cfg);
    try std.testing.expect(m.total_ceiling_bytes == 64 * memory_mod.one_mb);
    try std.testing.expect(m.state_tracker_bytes >= m.parser_buffer_bytes);
    try m.validate();
}

test "main: deriveTrackerConfig mirrors defaults" {
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
    const t = deriveTrackerConfig(&cfg, 2048);
    try std.testing.expectEqual(@as(u32, 2048), t.max_entries);
    try std.testing.expectEqual(@as(shared.Duration, 900), t.bantime);
    try std.testing.expectEqual(@as(shared.Duration, 450), t.findtime);
    try std.testing.expectEqual(@as(u32, 4), t.maxretry);
}

test {
    // Force test discovery for every engine module. Zig only includes a
    // file's tests in the test binary if it is referenced from inside a
    // `test` block — top-level `@import` alone is not enough. Keep this
    // list complete even for modules that `runDaemon` constructs
    // directly, otherwise their unit tests disappear from `zig build
    // test` output.
    _ = allocator_mod;
    _ = memory_mod;
    _ = event_loop_mod;
    _ = log_watcher_mod;
    _ = line_buffer_mod;
    _ = logger_mod;
    _ = parser_mod;
    _ = state_mod;
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

// ---------- 9B.1.1: /api/bans payload tests ----------
//
// These exercise `writeBansPayload` directly with a state tracker we
// control. We bypass `recordAttempt` and inject banned entries via the
// map — mirrors the pattern used by `net/commands.zig` tests.

const testing = std.testing;

/// Helper: build a minimal HttpSources wired up only for the bans path.
/// `metrics` and `cmd_ctx` fields get unused stub pointers — the bans
/// writer reads only `state`.
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
    var tracker = try state_mod.StateTracker.init(a, .{
        .max_entries = 16,
        .findtime = 600,
        .maxretry = 5,
        .bantime = 600,
    });
    defer tracker.deinit();

    var ctx: HttpSources = .{
        .metrics = undefined,
        .cmd_ctx = undefined,
        .state = &tracker,
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
    var tracker = try state_mod.StateTracker.init(a, .{
        .max_entries = 16,
        .findtime = 600,
        .maxretry = 5,
        .bantime = 600,
    });
    defer tracker.deinit();

    // Use a banned_at comfortably in the past so `banned_at` field in
    // the response is deterministic relative to the fixed bantime.
    try injectBan(&tracker, "185.220.101.5", "sshd", 1_714_000_000, 600);

    var ctx: HttpSources = .{
        .metrics = undefined,
        .cmd_ctx = undefined,
        .state = &tracker,
    };
    var out: std.ArrayListUnmanaged(u8) = .{};
    defer out.deinit(a);
    try writeBansPayload(@ptrCast(&ctx), &out, a);

    const body = out.items;
    try testing.expect(std.mem.indexOf(u8, body, "\"total\":1") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"ip\":\"185.220.101.5\"") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"jail\":\"sshd\"") != null);
    // ISO-8601 UTC renders 1_714_000_000 (2024-04-24T23:06:40Z).
    // Check the stable parts — full date + minute-precision time —
    // rather than exact seconds to decouple from format helper.
    try testing.expect(std.mem.indexOf(u8, body, "\"banned_at\":\"2024-04-24T23:06:") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"seconds_remaining\":") != null);
}

test "http: /api/bans truncates elements at 200 but count reflects total" {
    const a = testing.allocator;
    // Capacity large enough to hold all 250 entries; the cap we enforce
    // at the response layer is `http.max_bans_in_snapshot`, not the
    // tracker's.
    var tracker = try state_mod.StateTracker.init(a, .{
        .max_entries = 512,
        .findtime = 600,
        .maxretry = 5,
        .bantime = 600,
    });
    defer tracker.deinit();

    // 250 unique IPs in 10.x.y.z range — all banned.
    var i: u32 = 0;
    while (i < 250) : (i += 1) {
        var buf: [16]u8 = undefined;
        const s = try std.fmt.bufPrint(&buf, "10.0.{d}.{d}", .{ i / 256, i % 256 });
        try injectBan(&tracker, s, "sshd", 1_714_000_000, 600);
    }

    var ctx: HttpSources = .{
        .metrics = undefined,
        .cmd_ctx = undefined,
        .state = &tracker,
    };
    var out: std.ArrayListUnmanaged(u8) = .{};
    defer out.deinit(a);
    try writeBansPayload(@ptrCast(&ctx), &out, a);

    const body = out.items;
    try testing.expect(std.mem.indexOf(u8, body, "\"total\":250") != null);

    // Count the elements by counting `"ip":` occurrences — robust to
    // element ordering since HashMap iteration isn't sorted.
    var element_count: usize = 0;
    var cursor: usize = 0;
    while (std.mem.indexOf(u8, body[cursor..], "\"ip\":")) |rel| {
        element_count += 1;
        cursor += rel + 1;
    }
    try testing.expectEqual(http.max_bans_in_snapshot, element_count);
}

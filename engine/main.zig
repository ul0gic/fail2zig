// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! fail2zig daemon entry point.
//!
//! Responsibilities:
//!   1. Parse CLI args (--config, --version, --help, --test-config,
//!      --foreground, --import-config).
//!   2. Load + validate config.
//!   3. Detect the firewall backend (or fail closed if none available).
//!   4. Initialize the state tracker; seed it from the persisted state
//!      file if present.
//!   5. For each enabled jail, resolve its configured filter to a
//!      `FilterMatcher` and wire a `LogWatcher` (or journald source) per
//!      `logpath`, with a static line callback that routes matches
//!      through the state tracker and on ban decisions into the
//!      firewall backend.
//!   6. Install signal handlers (SIGTERM/SIGINT save state + exit,
//!      SIGHUP logs "reload not yet implemented").
//!   7. Arm a 1s periodic timer that scans for expired bans and calls
//!      `backend.unban` for each.
//!   8. Enter the event loop until stopped.
//!
//! The steady-state hot path — log line → match → state update →
//! (maybe) ban — is allocation-free on the happy path: the matcher
//! operates on slices of the caller's buffer and the per-jail state
//! tracker is a fixed-capacity map sized at startup. Per-component
//! memory-ceiling enforcement (the `MemoryPool` scaffolding in
//! `core/memory.zig`) is not yet wired to a live consumer — tracked
//! separately.

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

pub const version = "0.1.1";

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
    /// Runtime matcher for THIS jail's configured filter (SYS-020). Built
    /// once at construction from `jail.filter` via
    /// `filter_registry_mod.matcherForFilter`, which resolves the filter
    /// name to its comptime-compiled pattern set. This REPLACES the old
    /// permissive `Parser.init` default (`<*><IP>` — "any line containing
    /// an IP"), which matched benign IP-bearing lines (sshd's
    /// `Server listening on 0.0.0.0 port 22`, successful logins) and caused
    /// false bans. Both the file tailer and the journald source route
    /// through `lineCallback`, so both resolve to the SAME configured
    /// matcher for a given jail. A jail whose filter has no builtin matcher
    /// fails closed at construction (never reaches here with a default).
    matcher: filter_registry_mod.FilterMatcher,
    /// Per-jail state tracker (ISSUE-007). Each jail's tracker carries
    /// its own resolved `maxretry`/`findtime`/`bantime` so per-jail
    /// overrides actually take effect.
    state: *state_mod.StateTracker,
    backend_ptr: *firewall.Backend,
    /// Resolved ban action for THIS jail (SYS-016). Drives ban dispatch:
    /// `.@"log-only"` records the ban intent (would-ban log line + bans
    /// metric) but skips the firewall mutation AND the `ip_banned` event;
    /// every other value enforces through `backend_ptr` and emits the
    /// event. Resolved once at context construction via
    /// `config_mod.resolveJailFromConfig` so the per-jail-vs-defaults rule
    /// isn't reimplemented here. Defaults to `.nftables` (the schema
    /// default) so a context built without this field still enforces.
    banaction: config_mod.BanAction = .nftables,
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
    /// Test seam (SYS-016). When non-null, the enforcing dispatch path
    /// calls this instead of `backend_ptr.ban`, letting tests observe
    /// whether enforcement was invoked without a real kernel/firewall.
    /// In production this stays null and the real backend is called.
    /// Mirrors the `now_override` test-seam idiom already used here.
    ban_hook: ?*const fn (
        userdata: ?*anyopaque,
        ip: shared.IpAddress,
        jail: shared.JailId,
        duration: shared.Duration,
    ) firewall.BackendError!void = null,
    /// Opaque userdata handed to `ban_hook` (e.g. a call-count spy).
    ban_hook_ctx: ?*anyopaque = null,

    fn now(self: *const JailContext) shared.Timestamp {
        if (self.now_override) |t| return t;
        return std.time.timestamp();
    }

    /// Enforce a ban through the configured backend, honoring the test
    /// seam when present. Returns the backend error unchanged so callers
    /// keep their existing error handling.
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

/// Dispatch a ban decision (SYS-016). Honors the jail's resolved
/// `banaction`:
///
///   * `.@"log-only"` — record the ban INTENT only: log a "would-ban"
///     line and increment the bans counter so the operator can see the
///     jail is doing its job, but DO NOT mutate the firewall and DO NOT
///     emit the `ip_banned` WS event. That event asserts the IP was
///     actually banned; emitting it for a log-only jail would be a lie —
///     the same dishonesty (claiming an enforcement that didn't happen)
///     this fix exists to remove. Honest audit/monitoring mode.
///   * everything else — a real ban. Enforce through the backend first;
///     on backend error, warn and return BEFORE incrementing metrics /
///     broadcasting (preserving the original ordering) so a failed
///     enforcement is not counted as a successful ban. Then broadcast the
///     honest `ip_banned` event.
///
/// Extracted from `lineCallback` so the branch is unit-testable.
fn dispatchBan(ctx: *JailContext, d: state_mod.BanDecision) void {
    if (ctx.banaction == .@"log-only") {
        // Audit mode: record intent, touch nothing.
        std.log.info(
            "would-ban: jail='{s}' ip={} duration={d}s ban_count={d} action=log-only",
            .{ ctx.jail.slice(), d.ip, d.duration, d.ban_count },
        );
        if (ctx.metrics) |m| {
            m.incrementBans();
            m.jailIncrementBans(ctx.jail.slice());
        }
        // Deliberately NO broadcastBanned() here: no firewall mutation
        // occurred, so an `ip_banned` event would misrepresent reality.
        return;
    }

    // Enforcing path — a real ban.
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

    // SYS-020: match against THIS jail's CONFIGURED filter patterns, not a
    // permissive default. A non-matching line is the common case (most log
    // lines are not auth failures) — no count, no ban. `incrementParseErrors`
    // is misnamed for "no match" but is the existing counter for "a line we
    // saw but did not act on"; keep using it so metrics stay continuous.
    const result = ctx.matcher.match(body) orelse {
        if (ctx.metrics) |m| {
            m.incrementParseErrors();
            m.jailIncrementParseErrors(ctx.jail.slice());
        }
        return;
    };

    // SYS-020 defense-in-depth: even a matched line may carry an
    // unenforceable IP (the unspecified `0.0.0.0` / `::` a listener logs on
    // start, or loopback). Banning these is noise at best, self-DoS at
    // worst. Drop the match here — at the record boundary, so this rail
    // protects EVERY matcher, not just sshd. We never coerce a missing IP
    // to zero; extraction returns no match instead, so this only fires when
    // a real-but-unenforceable token was parsed.
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
        dispatchBan(ctx, d);
    }
}

// ============================================================================
// Ban expiry sweep (periodic timer)
// ============================================================================

const ExpiryContext = struct {
    /// Walks every tracker each tick. With per-jail trackers
    /// (ISSUE-007), expiry must visit every jail's ring buffer.
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

    // Collect expired IPs into a small stack buffer; HashMap iteration
    // while mutating the map is unsafe. 64 per tick keeps the cadence
    // reasonable even under high expiry load.
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
    /// Snapshots every per-jail tracker on shutdown (ISSUE-007). The
    /// flat on-disk format already carries per-entry jail names, so
    /// load+route on next start rehydrates the right tracker.
    trackers: *tracker_map_mod.TrackerMap,
    state_path: []const u8,
    /// journald source (SYS-015). Null when no jail reads the journal.
    /// Its cursor sidecar is flushed AFTER engine state — see
    /// `flushStateThenCursors`.
    journald: ?*journald_source_mod.JournaldSource = null,
    save_requested: bool = false,
};

/// Persist engine state, THEN the journald cursor sidecar — ordering is
/// load-bearing (SYS-015 Lead decision 2). State must hit disk before the
/// cursor so a crash between the two writes leaves the cursor OLDER than
/// the state: the next start replays ≤1 poll interval of already-counted
/// entries (safe at-least-once) and NEVER skips entries. Reversing the
/// order would risk advancing the cursor past entries whose ban-state
/// updates were lost. Both writes are best-effort: a failure is logged,
/// never fatal.
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

/// Context for the journald periodic-flush hook (SYS-015 Change 2).
/// Lives on `runDaemon`'s stack across `loop.run()`. The hook is invoked
/// by `JournaldSource.maybeFlush` after any poll tick that advanced a
/// cursor, so state + cursors are durable within ≤1 poll interval of the
/// entries they reflect (without a separate flush timer).
const JournaldFlushContext = struct {
    trackers: *tracker_map_mod.TrackerMap,
    state_path: []const u8,
    journald: *journald_source_mod.JournaldSource,
};

/// JournaldSource flush hook. Casts userdata → `*JournaldFlushContext` and
/// delegates to `flushStateThenCursors`, which enforces the load-bearing
/// state-first / cursor-second ordering. Single-threaded loop: this runs
/// on the loop thread inside `pollTick` and never re-enters the poller.
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

// ============================================================================
// Tracker config derivation from parsed config
// ============================================================================

/// Translate a config-layer `BanTimeIncrement` into the state tracker's
/// shape. The two structs carry the same fields but are defined
/// independently so the state module has zero config-layer imports.
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

/// Build the state-tracker config for a single jail from the resolved
/// per-jail values (ISSUE-007). Each jail gets its own tracker with its
/// own thresholds.
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

/// Synthesize a state-tracker config for the synthetic `__legacy__`
/// tracker. Uses the defaults block since legacy entries have no
/// surviving jail config to consult. Tuned for a small ceiling — the
/// legacy bucket exists only to keep restored bans active until the
/// operator either deletes the state file or re-adds the jail.
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

    // Per-jail state trackers (ISSUE-007). The state-tracker memory
    // budget is split evenly across the configured jails plus one
    // legacy bucket for restored entries whose jail no longer matches
    // the live config. Each tracker gets its own resolved thresholds,
    // so per-jail `maxretry` / `findtime` / `bantime` / `bantime_increment`
    // actually take effect.
    var trackers = tracker_map_mod.TrackerMap.init(heap);
    defer trackers.deinit();

    // Determine per-tracker capacity. Count enabled jails + 1 (legacy);
    // never fall below 1 to keep the division safe even with zero
    // enabled jails (legacy still gets the whole budget).
    var enabled_count: u32 = 0;
    for (cfg.jails) |jc| {
        if (jc.enabled) enabled_count += 1;
    }
    const tracker_count: u32 = @max(1, enabled_count + 1);
    // State-tracker share of the configured ceiling: half the ceiling, split
    // evenly across trackers. This is the SAME value the (now-removed)
    // MemoryPool config used for `state_tracker_bytes` — kept inline so
    // tracker capacity sizing is byte-for-byte unchanged. It sizes the
    // tracker HashMaps' entry counts only; it is not an allocator budget.
    const state_tracker_bytes: usize = (@as(usize, cfg.global.memory_ceiling_mb) * memory_mod.one_mb) / 2;
    const per_tracker_bytes: usize = state_tracker_bytes / tracker_count;
    const per_tracker_capacity = state_mod.capacityFromBudget(per_tracker_bytes);

    // Install one tracker per enabled jail. Per-jail ignoreip resolves
    // to defaults.ignoreip when the jail leaves the field unset.
    for (cfg.jails) |*jc| {
        if (!jc.enabled) continue;
        const resolved = config_mod.resolveJailFromConfig(jc, cfg.defaults);
        const tcfg = deriveJailTrackerConfig(resolved, per_tracker_capacity);
        const tracker = trackers.addTracker(jc.name, tcfg) catch |err| {
            std.log.err("state: tracker init for jail '{s}' failed: {s}", .{ jc.name, @errorName(err) });
            return err;
        };
        // ignoreip: per-jail override wins; otherwise inherit defaults.
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

    // Ensure the legacy tracker exists. Receives restored entries whose
    // jail name no longer matches a live jail; uses the defaults block
    // for thresholds since the original jail is gone.
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

    // Seed state from disk. Entries are routed by `jail` field on each
    // record; orphans land in the legacy tracker.
    if (persist_mod.load(heap, cfg.global.state_file)) |entries| {
        defer heap.free(entries);
        if (entries.len > 0) {
            var routed: u32 = 0;
            var legacy_routed: u32 = 0;
            persist_mod.seedMap(&trackers, entries, &routed, &legacy_routed) catch |err| {
                std.log.warn("persist: seed failed: {s}", .{@errorName(err)});
            };
            std.log.info(
                "persist: restored {d} entries ({d} routed, {d} -> legacy bucket)",
                .{ entries.len, routed, legacy_routed },
            );
        }
    } else |err| {
        std.log.warn("persist: load failed: {s}", .{@errorName(err)});
    }

    // Reconcile the firewall backend with restored state (SYS-007).
    // Walks every per-jail tracker so all restored bans are reinstalled.
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

    // journald log source (SYS-015). Sibling of the file watcher: a jail
    // whose source resolves to `journald` reads the systemd journal via a
    // polled `journalctl -o json` subprocess instead of an inotify file
    // tail. The timer is armed only if at least one jail uses it.
    var journald = journald_source_mod.JournaldSource.init(heap, &loop, cfg.global.state_file) catch |err| {
        std.log.err("journald: init failed: {s}", .{@errorName(err)});
        return err;
    };
    defer journald.deinit();

    // Flush context for the journald periodic-flush hook. Declared at
    // function scope so it outlives `loop.run()` — the hook captures its
    // address and fires from inside `pollTick`. Wired into `journald` only
    // when the source is actually in use (after the per-jail loop below).
    var journald_flush_ctx = JournaldFlushContext{
        .trackers = &trackers,
        .state_path = cfg.global.state_file,
        .journald = &journald,
    };

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
        // Each JailContext points at its own tracker. The tracker map
        // is keyed by jail name and was populated above; lookup here is
        // infallible because we just inserted it.
        const tracker_ptr = trackers.get(jail_cfg.name) orelse {
            std.log.warn(
                "jail '{s}' has no tracker — wiring bug, skipping",
                .{jail_cfg.name},
            );
            continue;
        };
        // SYS-020: resolve this jail's CONFIGURED filter to its runtime
        // matcher BEFORE allocating anything. A filter with no builtin
        // matcher must fail closed — refuse to start, NEVER fall back to a
        // permissive default that bans benign IP-bearing lines. This is the
        // file-path equivalent of the journald source's
        // `error.UnsupportedJournaldFilter`; resolving here covers BOTH
        // sources (file + journald share `lineCallback`/`JailContext`).
        const jail_matcher = filter_registry_mod.matcherForFilter(jail_cfg.filter) orelse {
            std.log.err(
                "jail '{s}' uses filter '{s}', which has no builtin matcher — refusing to start (fail2zig will not run a jail with no patterns, as that would ban any line containing an IP). Use a supported builtin filter or remove the jail.",
                .{ jail_cfg.name, jail_cfg.filter },
            );
            return error.UnsupportedFilter;
        };
        // Resolve this jail's effective ban action (SYS-016). Same
        // per-jail-vs-defaults rule used for the tracker config above;
        // `resolveJailFromConfig` is the single source of that rule.
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

        // SYS-015: resolve this jail's effective log source. `.file` keeps
        // the inotify tailer (and its late-appearance/rotation tolerance);
        // `.journald` reads the journal via the polled subprocess; `.fail`
        // means an EXPLICIT `source = journald` jail on a box without
        // journalctl — fail closed (don't run a jail that protects nothing).
        // `auto` never yields `.fail`: it degrades to a file tail instead.
        // SYS-015 (reopened): `auto` is EXISTENCE-based, so the resolver
        // needs to know whether a configured logpath is actually present on
        // disk (stat here, keeping the resolver pure/fs-free) and whether
        // this jail's filter has a journald selector set (sshd only in v1).
        // The filter gate stops a non-sshd jail with an absent log from
        // resolving to journald and then failing closed at wiring time.
        // The journalctl probe is read-only (access X_OK), no spawn.
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
                std.log.info(
                    "jail: enabled '{s}' source=file ({d} logpath(s))",
                    .{ jail_cfg.name, jail_cfg.logpath.len },
                );
            },
            .journald => {
                journald.addJail(jail, jail_cfg.filter, lineCallback, ctx) catch |err| switch (err) {
                    // v1 journald supports the `sshd` filter only. A jail
                    // asking for journald with any other filter would get
                    // sshd selectors silently mis-applied — fail closed
                    // with a message that tells the operator exactly how to
                    // fix it, and refuse to start.
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

    // Seed journald cursors from the sidecar and arm the poll timer, but
    // only if at least one jail actually reads the journal. Cursor restore
    // failure is non-fatal — a jail with no restored cursor baselines at
    // "now" on its first tick (no history replay).
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
        // Install the periodic-flush hook BEFORE arming the timer, so the
        // first dirty tick can persist state + cursors (SYS-015 Change 2).
        journald.setFlushHook(journaldFlushHook, &journald_flush_ctx);
        journald.attach() catch |err| {
            std.log.err("journald: attach (poll timer) failed: {s}", .{@errorName(err)});
            return err;
        };
        std.log.info("journald: polling {d} jail(s) every {d}ms", .{ journald.jailCount(), journald_source_mod.poll_interval_ms });
    }

    // IPC command handler context. Must outlive the IpcServer and HTTP
    // status source. start_time captured here so uptime reflects the
    // operational start.
    var cmd_ctx: commands_mod.Context = .{
        .trackers = &trackers,
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
        .trackers = &trackers,
        .state_path = cfg.global.state_file,
        .journald = &journald,
    };
    try loop.addSignalHandler(linux.SIG.TERM, onTerminate, &sig_ctx);
    try loop.addSignalHandler(linux.SIG.INT, onTerminate, &sig_ctx);
    try loop.addSignalHandler(linux.SIG.HUP, onReload, &sig_ctx);

    // Ban expiry timer.
    var expiry_ctx = ExpiryContext{
        .trackers = &trackers,
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

    // Final flush on clean shutdown (best-effort): engine state first,
    // then the journald cursor sidecar (ordering is load-bearing — see
    // `flushStateThenCursors`).
    flushStateThenCursors(&trackers, cfg.global.state_file, &journald);

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

/// Ensure the parent directory of `socket_path` exists, mode 0750 (owner
/// rwx, group r-x, other none). Group OWNERSHIP is deliberately NOT set
/// here (SYS-019): under the shipped systemd unit, `RuntimeDirectory=
/// fail2zig` + `Group=fail2zig` create `/run/fail2zig` as `root:fail2zig`
/// and the socket inherits the `fail2zig` group from the daemon's egid —
/// no chown needed. A daemon-side chown would be a `@privileged` syscall
/// the hardened unit's seccomp filter (`~@privileged`) kills with SIGSYS,
/// and CAP_CHOWN is not in the unit's bounding set, so it could not
/// succeed even if permitted. For bare `--config` runs (no systemd) the
/// dir/socket are `root:root` and only root may use the IPC socket — the
/// correct least-privilege default. makeDir errors other than
/// AlreadyExists are surfaced (they would block `bind(2)`); a chmod
/// failure is non-fatal — bind() still works as long as the daemon (root)
/// can traverse the dir.
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

    // Mode 0750 — owner rwx, group r-x, other none. Group members need
    // `x` to traverse into the dir and `r` to resolve the socket path.
    // Best-effort: if chmod fails (e.g. not owned by us), log and
    // continue; bind() still works if the daemon can traverse.
    std.posix.fchmodat(std.posix.AT.FDCWD, dir, 0o750, 0) catch |err| {
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
    /// Tracker map for `/api/bans` aggregation. Walks every per-jail
    /// tracker to assemble the active-ban snapshot.
    trackers: *tracker_map_mod.TrackerMap,
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

    // First pass: count active bans across every tracker so `total`
    // remains accurate even when we truncate `entries`.
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

// ============================================================================
// Tests
// ============================================================================

test "engine: version constant" {
    try std.testing.expectEqualStrings("0.1.1", version);
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

test "main: deriveJailTrackerConfig uses resolved per-jail values" {
    // ISSUE-007: the tracker config for a jail now reflects its
    // resolved thresholds (jail value if set, else defaults).
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

// ---------- SYS-016: banaction honored at ban dispatch ----------
//
// These exercise `dispatchBan` directly with a real `BanDecision`
// (produced by a real `StateTracker` crossing its threshold) and a spy
// in place of the firewall backend. The spy lets us assert whether the
// enforcing `ban` path was invoked WITHOUT a real kernel/firewall — the
// core of the bug was that a `log-only` jail still mutated the firewall.

/// Counts calls to the ban hook. The hook signature matches
/// `JailContext.ban_hook`; the spy never touches the kernel.
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

/// Build a JailContext wired to a spy + metrics for dispatch tests.
/// `backend_ptr` is required by the struct but is never dereferenced
/// because the spy hook short-circuits the enforcing call.
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
        .matcher = undefined, // dispatchBan never reads the matcher
        .state = tracker,
        .backend_ptr = backend,
        .banaction = action,
        .metrics = metrics,
        .ban_hook = BanSpy.ban,
        .ban_hook_ctx = spy,
    };
}

/// Drive a tracker across its `maxretry` threshold and return the
/// resulting decision. Asserts a decision actually fired.
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

    // A backend that must NOT be touched. If `dispatchBan` ever called
    // through it instead of the spy, the iptables CLI path would run —
    // but the spy hook intercepts first, so this stays inert.
    var backend: firewall.Backend = .{ .iptables = firewall.iptables.IptablesBackend{} };
    var spy: BanSpy = .{};

    var ctx = makeDispatchTestCtx(jail, &tracker, &backend, &metrics, &spy, .@"log-only");

    const decision = try produceDecision(&tracker, ip, jail);
    dispatchBan(&ctx, decision);

    // The firewall was NOT mutated: the enforcing path was never invoked.
    try testing.expectEqual(@as(u32, 0), spy.calls);

    // ...yet the ban intent WAS recorded: global + per-jail counters move.
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

    // Enforcing path WAS invoked exactly once, with the offending IP.
    try testing.expectEqual(@as(u32, 1), spy.calls);
    try testing.expect(spy.last_ip != null);
    try testing.expect(shared.IpAddress.eql(spy.last_ip.?, ip));

    // And accounting still happened (the enforcing path increments after
    // a successful backend call).
    const snap = metrics.snapshot();
    try testing.expectEqual(@as(u64, 1), snap.bans_total);
}

test "dispatch: backend error on enforcing path skips metrics (no false ban)" {
    // The enforcing path must NOT count a ban when the backend fails —
    // it warns and returns before incrementing. This guards the ordering
    // the original inline block relied on.
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

    // Backend failed -> no ban counted.
    const snap = metrics.snapshot();
    try testing.expectEqual(@as(u64, 0), snap.bans_total);
}

// ----------------------------------------------------------------------------
// SYS-020: runtime applies the jail's CONFIGURED filter, not a permissive
// default; reserved/unenforceable IPs never ban. These drive the SHARED
// `lineCallback` directly — both the file tailer and the journald source
// route through it with the same `*JailContext`, so exercising it here
// proves BOTH paths resolve to the same configured matcher.
// ----------------------------------------------------------------------------

/// Build a `lineCallback`-ready context wired to the sshd filter matcher,
/// a real tracker, a ban spy, and metrics. `maxretry` is the caller's so a
/// test can force a single hit to cross the threshold.
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
        .now_override = 1_000, // deterministic clock
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

/// maxretry=1 so a single matching line that crosses the threshold bans
/// immediately — makes "did this line ban?" a one-shot assertion.
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

    // The exact lines sshd logs on (re)start. The old `<*><IP>` default
    // matched these and banned 0.0.0.0 / ::; the configured sshd patterns
    // do not match them at all.
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

    // maxretry=1 -> the first failure crosses the threshold and bans.
    lineCallback("Failed password for root from 203.0.113.10 port 22 ssh2", fx.jail, false, &ctx);
    try testing.expectEqual(@as(u32, 1), fx.spy.calls);
    try testing.expect(fx.spy.last_ip != null);
    try testing.expect(shared.IpAddress.eql(fx.spy.last_ip.?, try shared.IpAddress.parse("203.0.113.10")));

    // A second distinct offender via the "Invalid user" pattern also bans.
    lineCallback("Invalid user oracle from 203.0.113.20 port 22", fx.jail, false, &ctx);
    try testing.expectEqual(@as(u32, 2), fx.spy.calls);
}

test "lineCallback: [preauth] self-ban guard takes effect at runtime (SYS-011 via SYS-020)" {
    var fx: LineCallbackFixture = undefined;
    try initLineCallbackFixture(&fx);
    defer fx.deinit();
    var ctx = makeLineCallbackCtx(fx.jail, &fx.tracker, &fx.backend, &fx.metrics, &fx.spy);

    // Clean operator logout — OpenSSH writes this on every normal session
    // close. The configured pattern requires the `[preauth]` suffix, so a
    // clean disconnect MUST NOT ban. Before SYS-020 the `<*><IP>` default
    // matched it and could self-ban the operator.
    lineCallback("Received disconnect from 192.0.2.50 port 22:11: disconnected by user", fx.jail, false, &ctx);
    try testing.expectEqual(@as(u32, 0), fx.spy.calls);

    // Attacker pre-auth disconnect — the `[preauth]` suffix means the IP
    // never authenticated; this MUST ban.
    lineCallback("Received disconnect from 203.0.113.99 port 22:11: Bye Bye [preauth]", fx.jail, false, &ctx);
    try testing.expectEqual(@as(u32, 1), fx.spy.calls);
}

test "lineCallback: matched line with unenforceable IP never bans (reserved-IP guard, SYS-020)" {
    var fx: LineCallbackFixture = undefined;
    try initLineCallbackFixture(&fx);
    defer fx.deinit();
    var ctx = makeLineCallbackCtx(fx.jail, &fx.tracker, &fx.backend, &fx.metrics, &fx.spy);

    // These lines DO match the sshd "Invalid user" pattern, but the
    // extracted token is unspecified/loopback — the record-boundary guard
    // must drop them before any count or ban, even though a pattern matched.
    lineCallback("Invalid user attacker from 0.0.0.0 port 22", fx.jail, false, &ctx);
    lineCallback("Invalid user attacker from :: port 22", fx.jail, false, &ctx);
    lineCallback("Failed password for root from 127.0.0.1 port 22 ssh2", fx.jail, false, &ctx);

    try testing.expectEqual(@as(u32, 0), fx.spy.calls);
    const snap = fx.metrics.snapshot();
    try testing.expectEqual(@as(u64, 0), snap.bans_total);
    // The guard fires AFTER the match but BEFORE the matched counter, so a
    // dropped unenforceable hit is not counted as a match either.
    try testing.expectEqual(@as(u64, 0), snap.lines_matched);
}

test "lineCallback: file and journald inputs resolve to the SAME configured matcher (SYS-020)" {
    // The file tailer passes a syslog-framed line; the journald source
    // passes the bare message body. Both reach this identical callback with
    // the identical context. A benign-but-IP-bearing line must be rejected
    // on BOTH shapes, proving neither path uses a permissive default.
    var fx: LineCallbackFixture = undefined;
    try initLineCallbackFixture(&fx);
    defer fx.deinit();
    var ctx = makeLineCallbackCtx(fx.jail, &fx.tracker, &fx.backend, &fx.metrics, &fx.spy);

    // File-source shape: full rsyslog envelope (stripSyslogPrefix peels it).
    lineCallback("Apr 21 10:15:03 host sshd[1234]: Accepted password for root from 198.51.100.8 port 22 ssh2", fx.jail, false, &ctx);
    // journald shape: bare message body, no envelope.
    lineCallback("Accepted password for root from 198.51.100.8 port 22 ssh2", fx.jail, false, &ctx);

    // Neither shape banned — both ran the configured sshd matcher, which
    // rejects successful auth.
    try testing.expectEqual(@as(u32, 0), fx.spy.calls);

    // And a real failure in BOTH shapes DOES ban (same matcher, same result).
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
    // Force test discovery for every engine module. Zig only includes a
    // file's tests in the test binary if it is referenced from inside a
    // `test` block — top-level `@import` alone is not enough. Keep this
    // list complete even for modules that `runDaemon` constructs
    // directly, otherwise their unit tests disappear from `zig build
    // test` output.
    _ = allocator_mod;
    // Test-only: surface memory.zig's tests. The MemoryPool is not yet
    // wired to a live consumer (tracked separately); see the
    // memory-ceiling-not-enforced issue.
    _ = memory_mod;
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

// ---------- 9B.1.1: /api/bans payload tests ----------
//
// These exercise `writeBansPayload` directly with a state tracker we
// control. We bypass `recordAttempt` and inject banned entries via the
// map — mirrors the pattern used by `net/commands.zig` tests.

const testing = std.testing;

/// Helper: build a minimal HttpSources wired up only for the bans path.
/// `metrics` and `cmd_ctx` fields get unused stub pointers — the bans
/// writer reads only `trackers`.
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

    // Use a banned_at comfortably in the past so `banned_at` field in
    // the response is deterministic relative to the fixed bantime.
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
    // ISO-8601 UTC renders 1_714_000_000 (2024-04-24T23:06:40Z).
    // Check the stable parts — full date + minute-precision time —
    // rather than exact seconds to decouple from format helper.
    try testing.expect(std.mem.indexOf(u8, body, "\"banned_at\":\"2024-04-24T23:06:") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"seconds_remaining\":") != null);
}

test "http: /api/bans truncates elements at 200 but count reflects total" {
    const a = testing.allocator;
    var trackers = tracker_map_mod.TrackerMap.init(a);
    defer trackers.deinit();
    // Capacity large enough to hold all 250 entries; the cap we enforce
    // at the response layer is `http.max_bans_in_snapshot`, not the
    // tracker's.
    const sshd_tracker = try trackers.addTracker("sshd", .{
        .max_entries = 512,
        .findtime = 600,
        .maxretry = 5,
        .bantime = 600,
    });

    // 250 unique IPs in 10.x.y.z range — all banned.
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

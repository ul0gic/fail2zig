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
        \\fail2zig v{s} — modern intrusion prevention
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

    const result = ctx.parser.parseLine(line) catch {
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
    }
}

// ============================================================================
// Ban expiry sweep (periodic timer)
// ============================================================================

const ExpiryContext = struct {
    state: *state_mod.StateTracker,
    backend_ptr: *firewall.Backend,
    metrics: ?*metrics_mod.Metrics = null,
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
    }
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
    return .{
        .max_entries = max_entries,
        .findtime = d.findtime,
        .maxretry = d.maxretry,
        .bantime = d.bantime,
        // Global ignore list / bantime_increment live per-jail in the
        // current schema; the global tracker uses conservative defaults.
        .bantime_increment = .{},
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
    var ws_server = ws.WsServer.init(heap, &loop) catch |err| {
        std.log.err("ws: init failed: {s}", .{@errorName(err)});
        return err;
    };
    defer ws_server.deinit();

    // HTTP server (metrics + status + /events WebSocket upgrade).
    var http_ctx: HttpSources = .{ .metrics = &metrics, .cmd_ctx = &cmd_ctx };
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
    http_server.setWsServer(&ws_server);
    try http_server.start();

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
    };
    _ = try loop.addTimer(1000, expirySweep, &expiry_ctx, false);

    std.log.info(
        "fail2zig v{s} running; backend={s}; ipc={s}; http={s}:{d}",
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

/// Bundle of pointers the HTTP `/metrics` and `/api/status` handlers
/// need. Kept together so we only plumb one `ctx` pointer through the
/// vtable.
const HttpSources = struct {
    metrics: *metrics_mod.Metrics,
    cmd_ctx: *commands_mod.Context,
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

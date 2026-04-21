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
const allocator_mod = @import("core/allocator.zig");
const memory_mod = @import("core/memory.zig");
const event_loop_mod = @import("core/event_loop.zig");
const log_watcher_mod = @import("core/log_watcher.zig");
const line_buffer_mod = @import("core/line_buffer.zig");
const logger_mod = @import("core/logger.zig");
const parser_mod = @import("core/parser.zig");
const state_mod = @import("core/state.zig");
const persist_mod = @import("core/persist.zig");
const firewall = @import("firewall/backend.zig");
const config_mod = @import("config/native.zig");
const http = @import("net/http.zig");
const ws = @import("net/ws.zig");

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
    import_config,
};

/// Parsed command-line options. String fields are slices into the owning
/// arena (for tests) or into the argv storage returned by `std.process.argsAlloc`.
pub const CliOptions = struct {
    action: CliAction = .run,
    config_path: []const u8 = "/etc/fail2zig/config.toml",
    import_path: ?[]const u8 = null,
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
        } else if (std.mem.eql(u8, a, "--foreground")) {
            out.foreground = true;
        } else if (std.mem.eql(u8, a, "--config")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            out.config_path = args[i];
        } else if (std.mem.startsWith(u8, a, "--config=")) {
            out.config_path = a["--config=".len..];
        } else if (std.mem.eql(u8, a, "--import-config")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            out.import_path = args[i];
            out.action = .import_config;
        } else if (std.mem.startsWith(u8, a, "--import-config=")) {
            out.import_path = a["--import-config=".len..];
            out.action = .import_config;
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
        \\  --config <path>        Config file (default: /etc/fail2zig/config.toml)
        \\  --foreground           Run in foreground (v0.1: only mode)
        \\  --test-config          Validate config and exit
        \\  --import-config <path> Import fail2ban config (not yet implemented)
        \\  --version, -V          Print version and exit
        \\  --help, -h             Print this help and exit
        \\
    , .{version});
}

// ============================================================================
// Jail context — glue between log watcher, parser, state, backend
// ============================================================================

const JailContext = struct {
    jail: shared.JailId,
    parser: parser_mod.Parser,
    state: *state_mod.StateTracker,
    backend_ptr: *firewall.Backend,
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

    const result = ctx.parser.parseLine(line) catch return;
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
        };
    }
}

// ============================================================================
// Ban expiry sweep (periodic timer)
// ============================================================================

const ExpiryContext = struct {
    state: *state_mod.StateTracker,
    backend_ptr: *firewall.Backend,
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
            try stdout.print("fail2zig: --import-config not yet implemented\n", .{});
            return;
        },
        .test_config, .run => {},
    }

    // Load + validate config.
    var cfg_arena = std.heap.ArenaAllocator.init(heap);
    defer cfg_arena.deinit();
    const cfg = config_mod.Config.loadFile(cfg_arena.allocator(), opts.config_path) catch |err| {
        const stderr = std.io.getStdErr().writer();
        try stderr.print("config: failed to load '{s}': {s}\n", .{ opts.config_path, @errorName(err) });
        std.process.exit(1);
    };
    config_mod.validate(&cfg) catch |err| {
        const stderr = std.io.getStdErr().writer();
        try stderr.print("config: validation failed: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    if (opts.action == .test_config) {
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
    var expiry_ctx = ExpiryContext{ .state = &tracker, .backend_ptr = &backend_val };
    _ = try loop.addTimer(1000, expirySweep, &expiry_ctx, false);

    std.log.info("fail2zig v{s} running; backend={s}", .{ version, @tagName(backend_val.tag()) });

    try loop.run();

    // Final state save on clean shutdown (best-effort; ignore errors).
    persist_mod.save(&tracker, cfg.global.state_file) catch {};
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

test "cli: --import-config" {
    const args = [_][]const u8{ "fail2zig", "--import-config", "/etc/fail2ban/jail.conf" };
    const opts = try parseArgs(&args);
    try std.testing.expectEqual(CliAction.import_config, opts.action);
    try std.testing.expectEqualStrings("/etc/fail2ban/jail.conf", opts.import_path.?);
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
    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try printHelp(stream.writer());
    const written = stream.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, written, "fail2zig") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "--config") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "--version") != null);
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
    _ = http;
    _ = ws;
    _ = shared;
}

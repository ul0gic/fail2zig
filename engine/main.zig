// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const linux = std.os.linux;

const shared = @import("shared");
const build_options = @import("build_options");
const cli = @import("cli");

const log_level = @import("core/log_level.zig");
pub const std_options: std.Options = .{ .log_level = .debug, .logFn = configuredLog };

fn configuredLog(comptime level: std.log.Level, comptime scope: @Type(.enum_literal), comptime format: []const u8, args: anytype) void {
    if (!log_level.enabled(level)) return;
    @import("core/log_target.zig").logFn(level, scope, format, args);
}

pub const event_loop_mod = @import("core/event_loop.zig");
pub const journald_source_mod = @import("core/journald_source.zig");
pub const parser_mod = @import("core/parser.zig");
pub const state_mod = @import("core/state.zig");
pub const tracker_map_mod = @import("core/tracker_map.zig");
pub const persist_mod = @import("core/persist.zig");
pub const native_store_mod = @import("core/record_store.zig");
pub const firewall_scope_mod = @import("firewall/scope.zig");
pub const native_action_outcome_mod = @import("core/native_action_outcome.zig");
pub const native_effect_mod = @import("core/native_effect.zig");
pub const firewall = @import("firewall/backend.zig");
pub const config_mod = @import("config/native.zig");
pub const fail2ban_mod = @import("config/fail2ban.zig");
pub const migration_mod = @import("config/migration.zig");
pub const migration_inspect_mod = @import("migration/inspect.zig");
pub const migration_snapshot_mod = @import("migration/sqlite_snapshot.zig");
pub const migration_fixture_mod = @import("migration/fail2ban_fixture.zig");
pub const migrate_cli_mod = @import("cli/migrate.zig");
pub const rule_test_cli_mod = @import("cli/rule_test.zig");
pub const cli_mod = cli;
pub const filter_types_mod = @import("filters/types.zig");
pub const filter_sshd_mod = @import("filters/sshd.zig");
pub const filter_nginx_mod = @import("filters/nginx.zig");
pub const filter_apache_mod = @import("filters/apache.zig");
pub const filter_mail_mod = @import("filters/mail.zig");
pub const filter_misc_mod = @import("filters/misc.zig");
pub const filter_registry_mod = @import("filters/registry.zig");
pub const ban_lifecycle_mod = @import("core/ban_lifecycle.zig");
pub const ipc_mod = @import("net/ipc.zig");
pub const commands_mod = @import("net/commands.zig");

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

pub const EntryMode = enum { daemon, operator, migrate, rule_test };

const operator_words = [_][]const u8{ "status", "jails", "list", "ban", "unban", "reload", "version", "help", "completions", "config", "history", "jail", "firewall" };
const operator_globals = [_][]const u8{ "--socket", "--output", "--no-color", "--timeout" };

pub fn classifyEntry(args: []const []const u8) EntryMode {
    if (args.len == 0) return .daemon;
    const first = args[0];
    if (std.mem.eql(u8, first, "migrate")) return .migrate;
    if (std.mem.eql(u8, first, "rule-test")) return .rule_test;
    for (operator_words) |w| if (std.mem.eql(u8, first, w)) return .operator;
    for (operator_globals) |g| {
        if (std.mem.eql(u8, first, g)) return .operator;
        if (first.len > g.len and std.mem.startsWith(u8, first, g) and first[g.len] == '=') return .operator;
    }
    return .daemon;
}

pub fn exitClassForClient(code: cli.ExitCode) shared.ExitClass {
    return switch (code) {
        .success => .success,
        .daemon_error => .rejected,
        .client_error => .usage,
        .connection_failed => .unavailable,
        .partial_effect => .partial,
        .uncertain_effect => .uncertain,
    };
}

pub fn parseArgs(args: []const []const u8) CliError!CliOptions {
    var out: CliOptions = .{};
    var i: usize = 1;
    if (args.len > 1 and std.mem.eql(u8, args[1], "daemon")) i = 2;
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
        \\  fail2zig [daemon] [OPTIONS]                 start the daemon (installed service entry)
        \\  fail2zig [GLOBALS] <command> [args]         administer a running daemon
        \\
        \\COMMANDS:
        \\  status | jails | list | ban | unban | reload | version | help | completions
        \\  config | history | jail | firewall show
        \\  migrate inspect|snapshot|plan|validate ... read-only migration preparation
        \\  rule-test --file|--record|--journal ...   offline rule evaluation (no daemon needed)
        \\  Globals: --socket <path> --output table|json|plain --no-color --timeout <ms>
        \\  `fail2zig help <command>` documents each command; `fail2zig version` is the daemon's.
        \\
        \\OPTIONS:
        \\  --config <path>           Config file (default: /etc/fail2zig/config.toml)
        \\  --foreground              Run in foreground (only mode)
        \\  --test-config             Alias for --validate-config
        \\  --validate-config         Load + validate config, print result, exit
        \\  --import-config [<dir>]   Import fail2ban config (default: /etc/fail2ban)
        \\  --import-output <path>    Where to write imported config (default: /etc/fail2zig/config.toml)
        \\  --version, -V             Print version and exit
        \\  --help, -h                Print this help and exit
        \\
        \\EXIT CLASSES:
        \\  0   success
        \\  1   valid request rejected by the daemon or local operation (fail-closed startup,
        \\      zero enabled jails imported)
        \\  2   usage, argument, config parse/validation or import parse failure
        \\  3   daemon/transport unavailable
        \\  4   partial durable effect (reserved)   5   uncertain durable effect (reserved)
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
    if (report.jails_enabled == 0) return 1;
    return 0;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const heap = gpa.allocator();

    const argv = try std.process.argsAlloc(heap);
    defer std.process.argsFree(heap, argv);

    const rest: []const []const u8 = if (argv.len > 0) argv[1..] else argv;
    switch (classifyEntry(rest)) {
        .operator => {
            const code = cli.run(heap, rest, std.io.getStdOut().writer(), std.io.getStdErr().writer());
            std.process.exit(exitClassForClient(code).code());
        },
        .migrate => std.process.exit(@import("cli/migrate.zig").run(heap, rest[1..], version, std.io.getStdOut().writer(), std.io.getStdErr().writer()).code()),
        .rule_test => std.process.exit(@import("cli/rule_test.zig").run(heap, rest[1..], std.io.getStdOut().writer(), std.io.getStdErr().writer()).code()),
        .daemon => {},
    }

    const opts = parseArgs(argv) catch |err| {
        const stderr = std.io.getStdErr().writer();
        switch (err) {
            error.MissingValue => try stderr.print("error: missing value for flag\n", .{}),
            error.UnknownFlag => try stderr.print("error: unknown flag or command (use --help)\n", .{}),
            error.AllocFailure => try stderr.print("error: allocation failure\n", .{}),
        }
        std.process.exit(shared.ExitClass.usage.code());
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
    var cfg_diag: config_mod.Diagnostic = .{};
    var cfg = config_mod.Config.loadFileDiag(cfg_arena.allocator(), opts.config_path, &cfg_diag) catch |err| {
        try printConfigLoadError(std.io.getStdErr().writer(), opts.config_path, err, &cfg_diag);
        std.process.exit(shared.ExitClass.usage.code());
    };
    cfg.retained_capacity = cfg_arena.queryCapacity();

    if (cfg.legacy_banaction_used) std.log.warn("config: banaction is deprecated; use defaults/jail enforce; global.firewall selects the backend", .{});

    const is_validate_only = opts.action == .test_config or opts.action == .validate_config;
    var validation_diag: config_mod.ValidationDiagnostic = .{};
    config_mod.validateDiag(&cfg, &validation_diag) catch |err| {
        const stderr = std.io.getStdErr().writer();
        var detail: [160]u8 = undefined;
        try stderr.print("config: validation failed: {s}; {s}\n", .{ @errorName(err), validation_diag.render(&detail) });
        std.process.exit(shared.ExitClass.usage.code());
    };
    if (!is_validate_only) {
        ensureSocketDir(cfg.global.socket_path) catch |err| {
            const stderr = std.io.getStdErr().writer();
            try stderr.print("config: cannot prepare socket directory: {s}\n", .{@errorName(err)});
            std.process.exit(shared.ExitClass.rejected.code());
        };
    }

    warnIfVolatileStateDir(cfg.global.state_file);
    if (is_validate_only) {
        try printValidateSummary(stdout, &cfg);
        return;
    }

    try runDaemon(heap, &cfg, opts.config_path);
}

fn printConfigLoadError(
    w: anytype,
    path: []const u8,
    err: config_mod.Error,
    diag: *const config_mod.Diagnostic,
) !void {
    switch (err) {
        error.ConfigWorldWritable => {
            try w.print(
                "config: {s}: world-writable (mode {o:0>4}); refusing to start — fix: chmod 0640 {s}\n",
                .{ path, diag.mode, path },
            );
            return;
        },
        error.ConfigGroupWritable => {
            try w.print(
                "config: {s}: writable by a non-root group (mode {o:0>4}); refusing to start — fix: chmod 0640 {s}\n",
                .{ path, diag.mode, path },
            );
            return;
        },
        else => {},
    }
    if (diag.line == 0) {
        try w.print("config: {s}: {s}\n", .{ path, @errorName(err) });
        return;
    }
    try w.print("config: {s}:{d}:{d}: {s}", .{ path, diag.line, diag.col, @errorName(err) });
    const key = diag.key();
    const section = diag.section();
    if (key.len > 0 and section.len > 0) {
        try w.print(" (key '{s}' in [{s}])", .{ key, section });
    } else if (key.len > 0) {
        try w.print(" (key '{s}')", .{key});
    } else if (section.len > 0) {
        try w.print(" (in [{s}])", .{section});
    }
    if (diag.hint.len > 0) try w.print(" — {s}", .{diag.hint});
    try w.writeAll("\n");
}

fn printValidateSummary(w: anytype, cfg: *const config_mod.Config) !void {
    if (cfg.global.firewall != .auto) try w.print("config: firewall={s}\n", .{@tagName(cfg.global.firewall)});
    try w.print("config: on_no_backend={s}\n", .{@tagName(cfg.global.on_no_backend)});
    for (cfg.jails) |*j| {
        const r = config_mod.resolveJailFromConfig(j, cfg.defaults);
        try w.print(
            "config: jail '{s}' enabled={} filter={s} source={s} banaction={s}\n",
            .{ j.name, j.enabled, j.filter, @tagName(j.source), @tagName(r.banaction) },
        );
    }
    try w.print("config: OK ({d} jail(s) configured)\n", .{cfg.jails.len});
}

test "cli: config load error prints path:line:col with key and section" {
    var buf: [256]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    var diag: config_mod.Diagnostic = .{};
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src = "[jails.sshd]\nenabled = true\nfilter = \"sshd\"\nbackend_typo = \"systemd\"\n";
    _ = config_mod.Config.parseDiag(arena.allocator(), src, &diag) catch |err| {
        try printConfigLoadError(stream.writer(), "/etc/fail2zig/config.toml", err, &diag);
    };
    try std.testing.expectEqualStrings(
        "config: /etc/fail2zig/config.toml:4:1: UnknownKey (key 'backend_typo' in [jails.sshd])\n",
        stream.getWritten(),
    );
}

test "cli: config load error without a position prints only the cause" {
    var buf: [256]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const diag: config_mod.Diagnostic = .{};
    try printConfigLoadError(stream.writer(), "/x.toml", error.FileNotFound, &diag);
    try std.testing.expectEqualStrings("config: /x.toml: FileNotFound\n", stream.getWritten());
}

test "cli: config permission errors name the octal mode and the chmod fix" {
    var buf: [256]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const world: config_mod.Diagnostic = .{ .mode = 0o666 };
    try printConfigLoadError(stream.writer(), "/etc/fail2zig/config.toml", error.ConfigWorldWritable, &world);
    try std.testing.expectEqualStrings(
        "config: /etc/fail2zig/config.toml: world-writable (mode 0666); refusing to start — fix: chmod 0640 /etc/fail2zig/config.toml\n",
        stream.getWritten(),
    );

    stream.reset();
    const group: config_mod.Diagnostic = .{ .mode = 0o660 };
    try printConfigLoadError(stream.writer(), "/etc/fail2zig/config.toml", error.ConfigGroupWritable, &group);
    try std.testing.expectEqualStrings(
        "config: /etc/fail2zig/config.toml: writable by a non-root group (mode 0660); refusing to start — fix: chmod 0640 /etc/fail2zig/config.toml\n",
        stream.getWritten(),
    );
}

test "cli: validate summary names each jail's resolved source" {
    var buf: [512]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const cfg = try config_mod.Config.parse(arena.allocator(), "[jails.sshd]\nfilter = \"sshd\"\nbackend = \"systemd\"\n");
    try printValidateSummary(stream.writer(), &cfg);
    try std.testing.expectEqualStrings(
        "config: on_no_backend=fail-closed\nconfig: jail 'sshd' enabled=true filter=sshd source=journald banaction=nftables\nconfig: OK (1 jail(s) configured)\n",
        stream.getWritten(),
    );
}

test "cli: validate summary shows an opted-in on_no_backend (SYS-014)" {
    var buf: [512]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const cfg = try config_mod.Config.parse(arena.allocator(), "[global]\non_no_backend = \"log-only\"\n");
    try printValidateSummary(stream.writer(), &cfg);
    try std.testing.expectEqualStrings(
        "config: on_no_backend=log-only\nconfig: OK (0 jail(s) configured)\n",
        stream.getWritten(),
    );
}

test "cli: validate summary echoes firewall only when forced (ENH-007)" {
    var buf: [512]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const cfg = try config_mod.Config.parse(arena.allocator(), "[global]\nfirewall = \"ipset\"\n");
    try printValidateSummary(stream.writer(), &cfg);
    try std.testing.expectEqualStrings(
        "config: firewall=ipset\nconfig: on_no_backend=fail-closed\nconfig: OK (0 jail(s) configured)\n",
        stream.getWritten(),
    );
}

test "cli: config load error appends the diag hint for metrics_port = 0 (ENH-008)" {
    var buf: [256]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    var diag: config_mod.Diagnostic = .{};
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    _ = config_mod.Config.parseDiag(arena.allocator(), "[global]\nmetrics_port = 0\n", &diag) catch |err| {
        try printConfigLoadError(stream.writer(), "/etc/fail2zig/config.toml", err, &diag);
    };
    try std.testing.expectEqualStrings(
        "config: /etc/fail2zig/config.toml:2:16: InvalidValue (key 'metrics_port' in [global]) — metrics_port = 0 does not disable the endpoint; set metrics_enabled = false\n",
        stream.getWritten(),
    );
}

fn failClosed(err: anytype, comptime fmt: []const u8, args: anytype) @TypeOf(err) {
    std.log.err(fmt, args);
    const any: anyerror = err;
    switch (any) {
        error.OutOfMemory => return err,
        else => {
            if (@import("native_daemon.zig").log_sink) |sink| sink.drain();
            std.process.exit(shared.ExitClass.rejected.code());
        },
    }
}

fn runDaemon(heap: std.mem.Allocator, cfg: *const config_mod.Config, config_path: []const u8) !void {
    const level = std.meta.stringToEnum(std.log.Level, @tagName(cfg.global.log_level)) orelse .info;
    log_level.set(level);
    const log_target = @import("core/log_target.zig");
    var sink: ?log_target.Sink = null;
    defer if (sink) |*value| {
        log_target.install(null);
        value.drain();
        value.deinit();
    };
    if (!std.mem.eql(u8, cfg.global.log_target, "stderr")) {
        sink = log_target.Sink.init(heap, .{ .file = cfg.global.log_target }) catch |err| {
            std.log.err("log target '{s}' unusable: {s}; refusing to start", .{ cfg.global.log_target, @errorName(err) });
            std.process.exit(shared.ExitClass.rejected.code());
        };
        @import("native_daemon.zig").log_sink = &sink.?;
        log_target.install(&sink.?);
    }
    return @import("native_daemon.zig").run(heap, cfg, config_path) catch |err|
        failClosed(err, "native: startup failed: {s}; refusing to start", .{@errorName(err)});
}

const tmpfs_magic: i64 = 0x01021994;

fn stateDirIsVolatile(state_file: []const u8, fs_magic: ?i64) bool {
    if (std.mem.startsWith(u8, state_file, "/run/")) return true;
    return if (fs_magic) |m| m == tmpfs_magic else false;
}

fn fsMagicOfDir(dir: []const u8) ?i64 {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    if (dir.len >= path_buf.len) return null;
    @memcpy(path_buf[0..dir.len], dir);
    path_buf[dir.len] = 0;
    var statfs_buf: [256]u8 align(8) = undefined;
    const rc = linux.syscall2(.statfs, @intFromPtr(&path_buf), @intFromPtr(&statfs_buf));
    if (linux.E.init(rc) != .SUCCESS) return null;
    return @as(i64, std.mem.bytesToValue(c_long, statfs_buf[0..@sizeOf(c_long)]));
}

fn warnIfVolatileStateDir(state_file: []const u8) void {
    const dir = std.fs.path.dirname(state_file) orelse "/";
    if (!stateDirIsVolatile(state_file, fsMagicOfDir(dir))) return;
    std.log.warn(
        "persist: state_file '{s}' is on volatile storage (tmpfs or /run): state will not survive restart; use /var/lib/fail2zig",
        .{state_file},
    );
}

test "persist: state path under /run or on tmpfs is classified volatile" {
    try std.testing.expect(stateDirIsVolatile("/run/fail2zig/state.bin", null));
    try std.testing.expect(stateDirIsVolatile("/var/lib/fail2zig/state.bin", tmpfs_magic));
    try std.testing.expect(!stateDirIsVolatile("/var/lib/fail2zig/state.bin", null));
    try std.testing.expect(!stateDirIsVolatile("/var/lib/fail2zig/state.bin", 0xEF53));
    try std.testing.expect(!stateDirIsVolatile("/runway/state.bin", null));
}

test "persist: fsMagicOfDir reads a real mount and rejects a missing one" {
    try std.testing.expect(fsMagicOfDir("/") != null);
    try std.testing.expect(fsMagicOfDir("/nonexistent-fail2zig-dir") == null);
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

test {
    _ = @import("cli/migrate.zig");
    _ = @import("cli/rule_test.zig");
}

test "cli: entry classification routes operator spellings and globals only" {
    try std.testing.expectEqual(EntryMode.daemon, classifyEntry(&.{}));
    try std.testing.expectEqual(EntryMode.daemon, classifyEntry(&.{"daemon"}));
    try std.testing.expectEqual(EntryMode.daemon, classifyEntry(&.{ "--config", "/x" }));
    try std.testing.expectEqual(EntryMode.daemon, classifyEntry(&.{"--version"}));
    try std.testing.expectEqual(EntryMode.daemon, classifyEntry(&.{"--validate-config"}));
    try std.testing.expectEqual(EntryMode.operator, classifyEntry(&.{"status"}));
    try std.testing.expectEqual(EntryMode.operator, classifyEntry(&.{ "--socket", "/s", "status" }));
    try std.testing.expectEqual(EntryMode.operator, classifyEntry(&.{ "--output=json", "version" }));
    try std.testing.expectEqual(EntryMode.operator, classifyEntry(&.{"completions"}));
    inline for (.{ "config", "history", "jail", "firewall" }) |word|
        try std.testing.expectEqual(EntryMode.operator, classifyEntry(&.{word}));
    try std.testing.expectEqual(EntryMode.migrate, classifyEntry(&.{ "migrate", "inspect" }));
    try std.testing.expectEqual(EntryMode.rule_test, classifyEntry(&.{ "rule-test", "--record", "x" }));
    try std.testing.expectEqual(EntryMode.daemon, classifyEntry(&.{"--socketpath"}));
    try std.testing.expectEqual(EntryMode.daemon, classifyEntry(&.{"statusx"}));
}

test "cli: explicit daemon word is the no-subcommand startup" {
    const args = [_][]const u8{ "fail2zig", "daemon", "--config", "/tmp/c.toml" };
    const opts = try parseArgs(&args);
    try std.testing.expectEqual(CliAction.run, opts.action);
    try std.testing.expectEqualStrings("/tmp/c.toml", opts.config_path);
    const bad = [_][]const u8{ "fail2zig", "--config", "/tmp/c.toml", "status" };
    try std.testing.expectError(error.UnknownFlag, parseArgs(&bad));
}

test "cli: client outcomes map onto frozen exit classes" {
    try std.testing.expectEqual(shared.ExitClass.success, exitClassForClient(.success));
    try std.testing.expectEqual(shared.ExitClass.rejected, exitClassForClient(.daemon_error));
    try std.testing.expectEqual(shared.ExitClass.usage, exitClassForClient(.client_error));
    try std.testing.expectEqual(shared.ExitClass.unavailable, exitClassForClient(.connection_failed));
    try std.testing.expectEqual(shared.ExitClass.partial, exitClassForClient(.partial_effect));
    try std.testing.expectEqual(shared.ExitClass.uncertain, exitClassForClient(.uncertain_effect));
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

test {
    _ = event_loop_mod;
    _ = journald_source_mod;
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
    _ = ipc_mod;
    _ = @import("net/http.zig");
    _ = commands_mod;
    _ = shared;
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const shared = @import("shared");
const config = @import("engine_test").config.native;
const BanAction = config.BanAction;
const BantimeFormula = config.BantimeFormula;
const BantimeKind = config.BantimeKind;
const BantimeScope = config.BantimeScope;
const Config = config.Config;
const Diagnostic = config.Diagnostic;
const FirewallSelection = config.FirewallSelection;
const JailConfig = config.JailConfig;
const LogLevel = config.LogLevel;
const LogSource = config.LogSource;
const OnNoBackend = config.OnNoBackend;
const anyLogpathExists = config.anyLogpathExists;
const decodeCompatibilityManifest = config.decodeCompatibilityManifest;
const filterSupportsInternal = config.filterSupportsInternal;
const filterSupportsJournald = config.filterSupportsJournald;
const max_ban_duration = config.max_ban_duration;
const max_config_bytes = config.max_config_bytes;
const metrics_port_zero_hint = config.metrics_port_zero_hint;
const resolveJail = config.resolveJail;
const resolveJailFromConfig = config.resolveJailFromConfig;
const validate = config.validate;
const websocket_hard_max_clients = config.websocket_hard_max_clients;

test "native: parse minimal config" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src =
        \\[global]
        \\log_level = "warn"
        \\memory_ceiling_mb = 128
        \\
        \\[defaults]
        \\bantime = 3600
        \\findtime = 600
        \\maxretry = 5
        \\banaction = "nftables"
    ;
    const cfg = try Config.parse(arena.allocator(), src);

    try std.testing.expectEqual(LogLevel.warn, cfg.global.log_level);
    try std.testing.expectEqual(@as(u32, 128), cfg.global.memory_ceiling_mb);
    try std.testing.expectEqualStrings("/proc/self/ns/net", cfg.global.firewall_namespace);
    try std.testing.expectEqual(@as(shared.Duration, 3600), cfg.defaults.bantime);
    try std.testing.expectEqual(BanAction.nftables, cfg.defaults.banaction);
}

test "native: parse defaults retains zero-copy string slices" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src =
        \\[global]
        \\pid_file = "/tmp/pf.pid"
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    const s = cfg.global.pid_file;
    const src_start = @intFromPtr(src.ptr);
    const s_start = @intFromPtr(s.ptr);
    try std.testing.expect(s_start >= src_start);
    try std.testing.expect(s_start + s.len <= src_start + src.len);
    try std.testing.expectEqualStrings("/tmp/pf.pid", s);
}

test "native: parse jails section with overrides" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src =
        \\[defaults]
        \\bantime = 600
        \\findtime = 600
        \\maxretry = 5
        \\
        \\[jails.sshd]
        \\enabled = true
        \\filter = "sshd"
        \\logpath = ["/var/log/auth.log", "/var/log/secure"]
        \\maxretry = 3
        \\
        \\[jails.nginx]
        \\enabled = false
        \\filter = "nginx-http-auth"
        \\logpath = ["/var/log/nginx/error.log"]
    ;
    const cfg = try Config.parse(arena.allocator(), src);

    try std.testing.expectEqual(@as(usize, 2), cfg.jails.len);
    try std.testing.expectEqualStrings("sshd", cfg.jails[0].name);
    try std.testing.expect(cfg.jails[0].enabled);
    try std.testing.expectEqualStrings("sshd", cfg.jails[0].filter);
    try std.testing.expectEqual(@as(usize, 2), cfg.jails[0].logpath.len);
    try std.testing.expectEqualStrings("/var/log/auth.log", cfg.jails[0].logpath[0]);
    try std.testing.expectEqual(@as(?u32, 3), cfg.jails[0].maxretry);

    try std.testing.expectEqualStrings("nginx", cfg.jails[1].name);
    try std.testing.expect(!cfg.jails[1].enabled);

    const eff_find = cfg.jails[0].effectiveFindtime(cfg.defaults);
    try std.testing.expectEqual(@as(shared.Duration, 600), eff_find);
    const eff_mr = cfg.jails[0].effectiveMaxretry(cfg.defaults);
    try std.testing.expectEqual(@as(u32, 3), eff_mr);
}

test "native: jail source defaults to auto when unset" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[jails.sshd]
        \\filter = "sshd"
        \\logpath = ["/var/log/auth.log"]
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    try std.testing.expectEqual(@as(usize, 1), cfg.jails.len);
    try std.testing.expectEqual(LogSource.auto, cfg.jails[0].source);
}

test "native: jail source parses file / journald / auto" {
    const cases = [_]struct { tok: []const u8, want: LogSource }{
        .{ .tok = "file", .want = .file },
        .{ .tok = "journald", .want = .journald },
        .{ .tok = "auto", .want = .auto },
    };
    for (cases) |c| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        var buf: [128]u8 = undefined;
        const src = try std.fmt.bufPrint(
            &buf,
            "[jails.sshd]\nfilter = \"sshd\"\nsource = \"{s}\"\n",
            .{c.tok},
        );
        const cfg = try Config.parse(arena.allocator(), src);
        try std.testing.expectEqual(c.want, cfg.jails[0].source);
    }
}

test "native: jail source rejects an unknown token" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[jails.sshd]
        \\filter = "sshd"
        \\source = "syslog"
    ;
    try std.testing.expectError(error.InvalidValue, Config.parse(arena.allocator(), src));
}

test "native: unknown journalmatch key still trips UnknownKey (v1 has no override)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[jails.sshd]
        \\filter = "sshd"
        \\source = "journald"
        \\journalmatch = "_SYSTEMD_UNIT=ssh.service"
    ;
    try std.testing.expectError(error.UnknownKey, Config.parse(arena.allocator(), src));
}

test "native: anyLogpathExists is existence-based, not configured-based (SYS-015)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "present.log", .data = "x" });

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const present = try tmp.dir.realpathAlloc(arena.allocator(), "present.log");
    const absent = try std.fmt.allocPrint(arena.allocator(), "{s}/nope.log", .{std.fs.path.dirname(present).?});

    try std.testing.expect(!anyLogpathExists(&.{}));
    try std.testing.expect(!anyLogpathExists(&.{""}));
    try std.testing.expect(!anyLogpathExists(&.{absent}));
    try std.testing.expect(!anyLogpathExists(&.{ "", absent }));

    try std.testing.expect(anyLogpathExists(&.{present}));
    try std.testing.expect(anyLogpathExists(&.{ "", absent, present }));
}

test "native: filterSupportsJournald is sshd-only in v1" {
    try std.testing.expect(filterSupportsJournald("sshd"));
    try std.testing.expect(!filterSupportsJournald("nginx-http-auth"));
    try std.testing.expect(!filterSupportsJournald("apache-auth"));
    try std.testing.expect(!filterSupportsJournald(""));
    try std.testing.expect(!filterSupportsJournald("sshd-ddos"));
}

test "native: validate does not fail when a jail resolves to journald" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[global]
        \\memory_ceiling_mb = 32
        \\socket_path = "/tmp/fail2zig-sys015.sock"
        \\[defaults]
        \\bantime = 600
        \\findtime = 600
        \\maxretry = 5
        \\[jails.sshd]
        \\filter = "sshd"
        \\source = "journald"
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    try validate(&cfg);
}

test "native: parse bantime_increment config" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src =
        \\[jails.sshd]
        \\filter = "sshd"
        \\bantime_increment_enabled = true
        \\bantime_increment_multiplier = 2
        \\bantime_increment_formula = "exponential"
        \\bantime_increment_scope = "overall"
        \\bantime_increment_max_bantime = 604800
        \\bantime_increment_jitter = 9
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    try std.testing.expectEqual(@as(usize, 1), cfg.jails.len);
    const bi = cfg.jails[0].bantime_increment;
    try std.testing.expect(bi.enabled);
    try std.testing.expectEqual(@as(f64, 2.0), bi.multiplier);
    try std.testing.expectEqual(BantimeFormula.exponential, bi.formula);
    try std.testing.expectEqual(BantimeScope.overall, bi.scope);
    try std.testing.expectEqual(@as(shared.Duration, 604800), bi.max_bantime);
    try std.testing.expectEqual(@as(shared.Duration, 9), bi.jitter);
}

test "native: bantime_increment rejects invalid scope and jitter above cap" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.InvalidValue, Config.parse(
        arena.allocator(),
        "[defaults]\nbantime_increment_scope = \"global\"\n",
    ));
    const cfg = try Config.parse(
        arena.allocator(),
        "[defaults]\nbantime_increment_max_bantime = 10\nbantime_increment_jitter = 11\n",
    );
    try std.testing.expectError(error.InvalidIncrement, validate(&cfg));
}

test "native: bantime_increment accepts fractional factor in defaults" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[defaults]
        \\bantime = 600
        \\findtime = 600
        \\maxretry = 5
        \\bantime_increment_enabled = true
        \\bantime_increment_factor = 1.5
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    try std.testing.expect(cfg.defaults.bantime_increment.enabled);
    try std.testing.expectEqual(@as(f64, 1.5), cfg.defaults.bantime_increment.factor);
}

test "native: bantime_increment accepts fractional multiplier in defaults" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[defaults]
        \\bantime = 600
        \\findtime = 600
        \\maxretry = 5
        \\bantime_increment_enabled = true
        \\bantime_increment_multiplier = 2.5
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    try std.testing.expectEqual(@as(f64, 2.5), cfg.defaults.bantime_increment.multiplier);
}

test "native: bantime_increment accepts fractional factor in per-jail block" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[jails.sshd]
        \\filter = "sshd"
        \\bantime_increment_enabled = true
        \\bantime_increment_factor = 1.75
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    try std.testing.expectEqual(@as(usize, 1), cfg.jails.len);
    try std.testing.expectEqual(@as(f64, 1.75), cfg.jails[0].bantime_increment.factor);
}

test "native: bantime_increment still accepts integer factor/multiplier (regression)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[defaults]
        \\bantime = 600
        \\findtime = 600
        \\maxretry = 5
        \\bantime_increment_enabled = true
        \\bantime_increment_factor = 2
        \\bantime_increment_multiplier = 3
        \\[jails.sshd]
        \\filter = "sshd"
        \\bantime_increment_enabled = true
        \\bantime_increment_factor = 4
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    try std.testing.expectEqual(@as(f64, 2.0), cfg.defaults.bantime_increment.factor);
    try std.testing.expectEqual(@as(f64, 3.0), cfg.defaults.bantime_increment.multiplier);
    try std.testing.expectEqual(@as(usize, 1), cfg.jails.len);
    try std.testing.expectEqual(@as(f64, 4.0), cfg.jails[0].bantime_increment.factor);
}

test "native: parse rejects unclosed string" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src = "[global]\nlog_level = \"info\n";
    try std.testing.expectError(error.UnterminatedString, Config.parse(arena.allocator(), src));
}

test "native: parse rejects invalid integer" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src = "[defaults]\nbantime = not-a-number\n";
    try std.testing.expectError(error.UnexpectedToken, Config.parse(arena.allocator(), src));
}

test "native: parse rejects unknown section" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src = "[unknown]\nfoo = 1\n";
    try std.testing.expectError(error.UnknownSection, Config.parse(arena.allocator(), src));
}

test "native: parse rejects unknown key" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src = "[global]\nbogus_key = 1\n";
    try std.testing.expectError(error.UnknownKey, Config.parse(arena.allocator(), src));
}

test "native: parse tolerates comments and blank lines" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src =
        \\# header
        \\
        \\[global] # section comment
        \\log_level = "debug" # trailing
        \\memory_ceiling_mb = 64
        \\
        \\# between sections
        \\[defaults]
        \\bantime = 600 # seconds
        \\findtime = 600
        \\maxretry = 5
        \\banaction = "iptables"
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    try std.testing.expectEqual(LogLevel.debug, cfg.global.log_level);
    try std.testing.expectEqual(BanAction.iptables, cfg.defaults.banaction);
}

test "native: parse string escapes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src =
        \\[global]
        \\state_file = "/var/\"lib\"/fail2zig.bin"
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    try std.testing.expectEqualStrings("/var/\"lib\"/fail2zig.bin", cfg.global.state_file);
}

test "native: validate rejects memory ceiling below floor" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src =
        \\[global]
        \\memory_ceiling_mb = 8
        \\[defaults]
        \\bantime = 600
        \\findtime = 600
        \\maxretry = 5
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    try std.testing.expectError(error.MemoryCeilingTooLow, validate(&cfg));
}

test "native: validate rejects bantime=0" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src =
        \\[defaults]
        \\bantime = 0
        \\findtime = 600
        \\maxretry = 5
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    try std.testing.expectError(error.InvalidBantime, validate(&cfg));
}

test "native: validate rejects duplicate jail names" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src =
        \\[global]
        \\memory_ceiling_mb = 32
        \\socket_path = "/tmp/fail2zig-test-validate.sock"
        \\[defaults]
        \\bantime = 600
        \\findtime = 600
        \\maxretry = 5
        \\[jails.sshd]
        \\filter = "sshd"
    ;
    var cfg = try Config.parse(arena.allocator(), src);

    var jails_buf = try arena.allocator().alloc(JailConfig, 2);
    jails_buf[0] = cfg.jails[0];
    jails_buf[1] = .{ .name = "sshd", .filter = "sshd" };
    cfg.jails = jails_buf;
    try std.testing.expectError(error.DuplicateJailName, validate(&cfg));
}

test "native: validate warns on missing socket dir, does not fail" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src =
        \\[global]
        \\memory_ceiling_mb = 32
        \\socket_path = "/definitely-does-not-exist-xyz/sock"
        \\[defaults]
        \\bantime = 600
        \\findtime = 600
        \\maxretry = 5
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    try validate(&cfg);
}

test "native: validate accepts healthy config" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src =
        \\[global]
        \\memory_ceiling_mb = 32
        \\socket_path = "/tmp/fail2zig.sock"
        \\[defaults]
        \\bantime = 600
        \\findtime = 600
        \\maxretry = 5
        \\[jails.sshd]
        \\filter = "sshd"
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    try validate(&cfg);
}

test "native: load file not found" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(
        error.FileNotFound,
        Config.loadFile(arena.allocator(), "/nonexistent/fail2zig.toml"),
    );
}

test "native: loadFile parses a tmp file" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const contents =
        \\[global]
        \\memory_ceiling_mb = 32
    ;
    {
        const f = try tmp.dir.createFile("cfg.toml", .{});
        defer f.close();
        try f.writeAll(contents);
        try f.chmod(0o640);
    }

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const real = try tmp.dir.realpathAlloc(arena.allocator(), "cfg.toml");
    const cfg = try Config.loadFile(arena.allocator(), real);
    try std.testing.expectEqual(@as(u32, 32), cfg.global.memory_ceiling_mb);
}

test "native: parse a full example with all options" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src =
        \\[global]
        \\log_level = "info"
        \\pid_file = "/run/fail2zig.pid"
        \\socket_path = "/tmp/fail2zig.sock"
        \\state_file = "/var/lib/fail2zig/state.bin"
        \\memory_ceiling_mb = 64
        \\
        \\[defaults]
        \\bantime = 600
        \\findtime = 600
        \\maxretry = 5
        \\banaction = "nftables"
        \\ignoreip = ["127.0.0.1", "10.0.0.0/8"]
        \\
        \\[jails.sshd]
        \\enabled = true
        \\filter = "sshd"
        \\logpath = ["/var/log/auth.log"]
        \\maxretry = 3
        \\bantime = 3600
        \\bantime_increment_enabled = true
        \\bantime_increment_formula = "exponential"
        \\bantime_increment_max_bantime = 604800
        \\
        \\[jails.nginx-http-auth]
        \\enabled = true
        \\filter = "nginx-http-auth"
        \\logpath = ["/var/log/nginx/error.log"]
        \\ignoreip = ["192.168.0.0/16"]
    ;

    const cfg = try Config.parse(arena.allocator(), src);
    try std.testing.expectEqual(@as(usize, 2), cfg.jails.len);
    try std.testing.expectEqual(@as(usize, 2), cfg.defaults.ignoreip.len);
    try std.testing.expectEqualStrings("127.0.0.1", cfg.defaults.ignoreip[0]);
    try std.testing.expectEqual(@as(shared.Duration, 3600), cfg.jails[0].bantime.?);
    try std.testing.expect(cfg.jails[0].bantime_increment.enabled);
    try std.testing.expectEqualStrings("nginx-http-auth", cfg.jails[1].name);
    try std.testing.expectEqual(@as(usize, 1), cfg.jails[1].ignoreip.?.len);
}

test "native: websocket_max_clients default is 16" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[global]
        \\memory_ceiling_mb = 32
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    try std.testing.expectEqual(@as(u32, 16), cfg.global.websocket_max_clients);
}

test "native: history retention defaults and bounded overrides are explicit" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const defaults = try Config.parse(arena.allocator(), "[global]\nmetrics_enabled = false\n");
    try std.testing.expectEqual(@as(shared.Duration, 86_400), defaults.global.history_retention);
    try std.testing.expectEqual(@as(u16, 10), defaults.global.history_max_matches);
    const configured = try Config.parse(arena.allocator(), "[global]\nhistory_retention = 0\nhistory_max_matches = 1024\n");
    try std.testing.expectEqual(@as(shared.Duration, 0), configured.global.history_retention);
    try std.testing.expectEqual(@as(u16, 1024), configured.global.history_max_matches);
    try std.testing.expectError(error.InvalidValue, Config.parse(arena.allocator(), "[global]\nhistory_max_matches = 1025\n"));
}

test "native: websocket_max_clients accepts 16, 128, and hard cap" {
    const cases = [_]u32{ 16, 128, websocket_hard_max_clients };
    for (cases) |v| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var buf: [128]u8 = undefined;
        const src = try std.fmt.bufPrint(
            &buf,
            "[global]\nwebsocket_max_clients = {d}\n",
            .{v},
        );
        const cfg = try Config.parse(arena.allocator(), src);
        try std.testing.expectEqual(v, cfg.global.websocket_max_clients);
    }
}

test "native: websocket_max_clients rejects 0" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[global]
        \\websocket_max_clients = 0
    ;
    try std.testing.expectError(error.InvalidValue, Config.parse(arena.allocator(), src));
}

test "native: resolveJail returns null for unknown jail" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[defaults]
        \\bantime = 600
        \\findtime = 600
        \\maxretry = 5
        \\[jails.sshd]
        \\filter = "sshd"
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    try std.testing.expect(resolveJail(&cfg, "nope") == null);
}

test "native: resolveJail uses per-jail values when set" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[defaults]
        \\bantime = 600
        \\findtime = 600
        \\maxretry = 5
        \\[jails.aggressive]
        \\filter = "sshd"
        \\maxretry = 1
        \\findtime = 10
        \\bantime = 30
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    const r = resolveJail(&cfg, "aggressive").?;
    try std.testing.expectEqual(@as(u32, 1), r.maxretry);
    try std.testing.expectEqual(@as(shared.Duration, 10), r.findtime);
    try std.testing.expectEqual(@as(shared.Duration, 30), r.bantime);
}

test "native: resolveJail falls back to defaults for unset fields" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[defaults]
        \\bantime = 1800
        \\findtime = 900
        \\maxretry = 7
        \\[jails.sshd]
        \\filter = "sshd"
        \\maxretry = 2
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    const r = resolveJail(&cfg, "sshd").?;
    try std.testing.expectEqual(@as(u32, 2), r.maxretry);
    try std.testing.expectEqual(@as(shared.Duration, 900), r.findtime);
    try std.testing.expectEqual(@as(shared.Duration, 1800), r.bantime);
}

test "native: resolveJail inherits defaults bantime_increment when jail is silent" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[defaults]
        \\bantime = 600
        \\findtime = 600
        \\maxretry = 5
        \\bantime_increment_enabled = true
        \\bantime_increment_factor = 3
        \\bantime_increment_formula = "exponential"
        \\bantime_increment_max_bantime = 86400
        \\[jails.sshd]
        \\filter = "sshd"
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    const r = resolveJail(&cfg, "sshd").?;
    try std.testing.expect(r.bantime_increment.enabled);
    try std.testing.expectEqual(@as(f64, 3.0), r.bantime_increment.factor);
    try std.testing.expectEqual(BantimeFormula.exponential, r.bantime_increment.formula);
}

test "native: resolveJail takes per-jail bantime_increment when present" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[defaults]
        \\bantime = 600
        \\findtime = 600
        \\maxretry = 5
        \\bantime_increment_enabled = true
        \\bantime_increment_factor = 2
        \\[jails.sshd]
        \\filter = "sshd"
        \\bantime_increment_enabled = true
        \\bantime_increment_factor = 5
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    const r = resolveJail(&cfg, "sshd").?;
    try std.testing.expect(r.bantime_increment.enabled);
    try std.testing.expectEqual(@as(f64, 5.0), r.bantime_increment.factor);
}

test "native: websocket_max_clients rejects values above hard cap" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    const src = try std.fmt.bufPrint(
        &buf,
        "[global]\nwebsocket_max_clients = {d}\n",
        .{websocket_hard_max_clients + 1},
    );
    try std.testing.expectError(error.InvalidValue, Config.parse(arena.allocator(), src));
}

test "native: diag reports UnknownKey at the key position with key and section" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[jails.sshd]
        \\enabled = true
        \\filter = "sshd"
        \\bogus = "x"
    ;
    var diag: Diagnostic = .{};
    try std.testing.expectError(error.UnknownKey, Config.parseDiag(arena.allocator(), src, &diag));
    try std.testing.expectEqual(@as(u32, 4), diag.line);
    try std.testing.expectEqual(@as(u32, 1), diag.col);
    try std.testing.expectEqualStrings("bogus", diag.key());
    try std.testing.expectEqualStrings("jails.sshd", diag.section());
}

test "native: diag reports InvalidValue at the value position" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[global]
        \\
        \\metrics_port = 70000
    ;
    var diag: Diagnostic = .{};
    try std.testing.expectError(error.InvalidValue, Config.parseDiag(arena.allocator(), src, &diag));
    try std.testing.expectEqual(@as(u32, 3), diag.line);
    try std.testing.expectEqual(@as(u32, 16), diag.col);
    try std.testing.expectEqualStrings("metrics_port", diag.key());
    try std.testing.expectEqualStrings("global", diag.section());
}

test "native: on_no_backend defaults to fail-closed (SYS-014)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const cfg = try Config.parse(arena.allocator(), "[global]\nmemory_ceiling_mb = 32\n");
    try std.testing.expectEqual(OnNoBackend.@"fail-closed", cfg.global.on_no_backend);
}

test "native: on_no_backend parses both accepted values (SYS-014)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const lo = try Config.parse(arena.allocator(), "[global]\non_no_backend = \"log-only\"\n");
    try std.testing.expectEqual(OnNoBackend.@"log-only", lo.global.on_no_backend);
    const fc = try Config.parse(arena.allocator(), "[global]\non_no_backend = \"fail-closed\"\n");
    try std.testing.expectEqual(OnNoBackend.@"fail-closed", fc.global.on_no_backend);
}

test "native: on_no_backend rejects any other value with a positioned diag (SYS-014)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[global]
        \\on_no_backend = "degrade"
    ;
    var diag: Diagnostic = .{};
    try std.testing.expectError(error.InvalidValue, Config.parseDiag(arena.allocator(), src, &diag));
    try std.testing.expectEqual(@as(u32, 2), diag.line);
    try std.testing.expectEqualStrings("on_no_backend", diag.key());
    try std.testing.expectEqualStrings("global", diag.section());

    var diag_int: Diagnostic = .{};
    try std.testing.expectError(error.InvalidValue, Config.parseDiag(arena.allocator(), "[global]\non_no_backend = 1\n", &diag_int));
    try std.testing.expectEqualStrings("on_no_backend", diag_int.key());
}

test "native: diag reports UnknownSection at the header and UnterminatedString at the value" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var diag: Diagnostic = .{};

    try std.testing.expectError(error.UnknownSection, Config.parseDiag(arena.allocator(), "\n[nope]\nfoo = 1\n", &diag));
    try std.testing.expectEqual(@as(u32, 2), diag.line);
    try std.testing.expectEqual(@as(u32, 1), diag.col);
    try std.testing.expectEqualStrings("nope", diag.section());

    try std.testing.expectError(error.UnterminatedString, Config.parseDiag(arena.allocator(), "[global]\nlog_level = \"info\n", &diag));
    try std.testing.expectEqual(@as(u32, 2), diag.line);
    try std.testing.expectEqual(@as(u32, 13), diag.col);
    try std.testing.expectEqualStrings("log_level", diag.key());
}

test "native: diag bounds the copied key and sanitizes section bytes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var diag: Diagnostic = .{};

    const long_key = "k" ** 200;
    try std.testing.expectError(error.UnknownKey, Config.parseDiag(arena.allocator(), "[global]\n" ++ long_key ++ " = 1\n", &diag));
    try std.testing.expectEqual(Diagnostic.max_name, diag.key().len);

    try std.testing.expectError(error.UnknownSection, Config.parseDiag(arena.allocator(), "[a\x01b]\nx = 1\n", &diag));
    try std.testing.expectEqualStrings("a?b", diag.section());
}

test "native: duplicate key in one section reports DuplicateKey at the second key" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[jails.sshd]
        \\filter = "sshd"
        \\maxretry = 3
        \\maxretry = 30
        \\
    ;
    var diag: Diagnostic = .{};
    try std.testing.expectError(error.DuplicateKey, Config.parseDiag(arena.allocator(), src, &diag));
    try std.testing.expectEqual(@as(u32, 4), diag.line);
    try std.testing.expectEqual(@as(u32, 1), diag.col);
    try std.testing.expectEqualStrings("maxretry", diag.key());
    try std.testing.expectEqualStrings("jails.sshd", diag.section());
}

test "native: duplicate key across a repeated section header is still a duplicate" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src = "[jails.sshd]\nmaxretry = 3\n[jails.nginx]\nmaxretry = 5\n[jails.sshd]\nmaxretry = 30\n";
    var diag: Diagnostic = .{};
    try std.testing.expectError(error.DuplicateKey, Config.parseDiag(arena.allocator(), src, &diag));
    try std.testing.expectEqual(@as(u32, 6), diag.line);
    try std.testing.expectEqualStrings("jails.sshd", diag.section());
}

test "native: same key in different sections is not a duplicate" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const cfg = try Config.parse(arena.allocator(), "[defaults]\nmaxretry = 3\n[jails.sshd]\nmaxretry = 5\n[jails.nginx]\nmaxretry = 7\n");
    try std.testing.expectEqual(@as(u32, 3), cfg.defaults.maxretry);
    try std.testing.expectEqual(@as(u32, 5), cfg.jails[0].maxretry.?);
    try std.testing.expectEqual(@as(u32, 7), cfg.jails[1].maxretry.?);
}

test "native: loadFileDiag resets the diagnostic on file errors" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var diag: Diagnostic = .{ .line = 9, .col = 9 };
    try std.testing.expectError(error.FileNotFound, Config.loadFileDiag(arena.allocator(), "/nonexistent/fail2zig.toml", &diag));
    try std.testing.expectEqual(@as(u32, 0), diag.line);
    try std.testing.expectEqual(@as(usize, 0), diag.key().len);
}

test "native: config permission classifier" {
    try Config.checkConfigPerms(0o640, 1000);
    try Config.checkConfigPerms(0o644, 1000);
    try Config.checkConfigPerms(0o660, 0);
    try std.testing.expectError(error.ConfigGroupWritable, Config.checkConfigPerms(0o660, 1000));
    try std.testing.expectError(error.ConfigWorldWritable, Config.checkConfigPerms(0o666, 0));
    try std.testing.expectError(error.ConfigWorldWritable, Config.checkConfigPerms(0o602, 1000));
}

fn writeTmpConfigWithMode(tmp: *std.testing.TmpDir, mode: std.posix.mode_t) !std.posix.gid_t {
    const f = try tmp.dir.createFile("cfg.toml", .{});
    defer f.close();
    try f.writeAll("[global]\nmemory_ceiling_mb = 32\n");
    try f.chmod(mode);
    const st = try std.posix.fstat(f.handle);
    return st.gid;
}

test "native: loadFileDiag accepts a 0640 config" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    _ = try writeTmpConfigWithMode(&tmp, 0o640);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const real = try tmp.dir.realpathAlloc(arena.allocator(), "cfg.toml");
    var diag: Diagnostic = .{};
    const cfg = try Config.loadFileDiag(arena.allocator(), real, &diag);
    try std.testing.expectEqual(@as(u32, 32), cfg.global.memory_ceiling_mb);
    try std.testing.expectEqual(@as(u32, 0o640), diag.mode);
}

test "native: loadFileDiag rejects a 0666 config and reports the mode" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    _ = try writeTmpConfigWithMode(&tmp, 0o666);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const real = try tmp.dir.realpathAlloc(arena.allocator(), "cfg.toml");
    var diag: Diagnostic = .{};
    try std.testing.expectError(error.ConfigWorldWritable, Config.loadFileDiag(arena.allocator(), real, &diag));
    try std.testing.expectEqual(@as(u32, 0o666), diag.mode);
    try std.testing.expectEqual(@as(u32, 0), diag.line);
}

test "native: loadFileDiag rejects a 0660 config unless the group is root" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const gid = try writeTmpConfigWithMode(&tmp, 0o660);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const real = try tmp.dir.realpathAlloc(arena.allocator(), "cfg.toml");
    var diag: Diagnostic = .{};
    const result = Config.loadFileDiag(arena.allocator(), real, &diag);
    if (gid == 0) {
        _ = try result;
    } else {
        try std.testing.expectError(error.ConfigGroupWritable, result);
    }
    try std.testing.expectEqual(@as(u32, 0o660), diag.mode);
}

test "native: backend alias maps every fail2ban name in a jail" {
    const cases = [_]struct { tok: []const u8, want: LogSource }{
        .{ .tok = "systemd", .want = .journald },
        .{ .tok = "auto", .want = .auto },
        .{ .tok = "polling", .want = .auto },
        .{ .tok = "pyinotify", .want = .auto },
        .{ .tok = "gamin", .want = .auto },
    };
    for (cases) |c| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        var buf: [128]u8 = undefined;
        const src = try std.fmt.bufPrint(
            &buf,
            "[jails.sshd]\nfilter = \"sshd\"\nbackend = \"{s}\"\n",
            .{c.tok},
        );
        const cfg = try Config.parse(arena.allocator(), src);
        try std.testing.expectEqual(c.want, cfg.jails[0].source);
    }
}

test "native: backend alias rejects an unknown name with diag at the value" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[jails.sshd]
        \\filter = "sshd"
        \\backend = "bogus"
    ;
    var diag: Diagnostic = .{};
    try std.testing.expectError(error.InvalidValue, Config.parseDiag(arena.allocator(), src, &diag));
    try std.testing.expectEqual(@as(u32, 3), diag.line);
    try std.testing.expectEqual(@as(u32, 11), diag.col);
    try std.testing.expectEqualStrings("backend", diag.key());
}

test "native: backend and source in the same jail conflict in either order" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a =
        \\[jails.sshd]
        \\backend = "systemd"
        \\source = "journald"
    ;
    const b =
        \\[jails.sshd]
        \\source = "file"
        \\backend = "systemd"
    ;
    var diag: Diagnostic = .{};
    try std.testing.expectError(error.InvalidValue, Config.parseDiag(arena.allocator(), a, &diag));
    try std.testing.expectEqualStrings("source", diag.key());
    try std.testing.expectError(error.InvalidValue, Config.parseDiag(arena.allocator(), b, &diag));
    try std.testing.expectEqualStrings("backend", diag.key());
}

test "native: backend in [defaults] is inherited by jails without an explicit source" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[jails.sshd]
        \\filter = "sshd"
        \\[jails.nginx]
        \\filter = "nginx-http-auth"
        \\source = "file"
        \\[defaults]
        \\backend = "systemd"
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    try std.testing.expectEqual(LogSource.journald, cfg.defaults.source);
    try std.testing.expectEqual(LogSource.journald, cfg.jails[0].source);
    try std.testing.expectEqual(LogSource.file, cfg.jails[1].source);
}

test "native: backend and source conflict in [defaults] and unknown backend is rejected there" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.InvalidValue, Config.parse(arena.allocator(), "[defaults]\nsource = \"auto\"\nbackend = \"systemd\"\n"));
    try std.testing.expectError(error.InvalidValue, Config.parse(arena.allocator(), "[defaults]\nbackend = \"systemd[journalflags=1]\"\n"));
    const cfg = try Config.parse(arena.allocator(), "[defaults]\nsource = \"journald\"\n");
    try std.testing.expectEqual(LogSource.journald, cfg.defaults.source);
}

test "native: source = \"internal\" parses per jail and in defaults (ENH-005)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const cfg = try Config.parse(arena.allocator(), "[defaults]\nsource = \"internal\"\n[jails.recidive]\nfilter = \"recidive\"\nsource = \"internal\"\n");
    try std.testing.expectEqual(LogSource.internal, cfg.defaults.source);
    try std.testing.expectEqual(LogSource.internal, cfg.jails[0].source);
    try std.testing.expect(filterSupportsInternal("recidive"));
    try std.testing.expect(!filterSupportsInternal("sshd"));
}

test "native: firewall defaults to auto and parses every backend name (ENH-007)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const def = try Config.parse(arena.allocator(), "[global]\n");
    try std.testing.expectEqual(FirewallSelection.auto, def.global.firewall);
    inline for (.{ "auto", "nftables", "ipset", "iptables" }) |name| {
        const cfg = try Config.parse(arena.allocator(), "[global]\nfirewall = \"" ++ name ++ "\"\n");
        try std.testing.expectEqual(@field(FirewallSelection, name), cfg.global.firewall);
    }
}

test "native: firewall rejects unknown and non-string values with a positioned diag (ENH-007)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[global]
        \\log_level = "info"
        \\firewall = "ebpf"
    ;
    var diag: Diagnostic = .{};
    try std.testing.expectError(error.InvalidValue, Config.parseDiag(arena.allocator(), src, &diag));
    try std.testing.expectEqual(@as(u32, 3), diag.line);
    try std.testing.expectEqual(@as(u32, 12), diag.col);
    try std.testing.expectEqualStrings("firewall", diag.key());
    try std.testing.expectEqualStrings("global", diag.section());
    try std.testing.expectEqualStrings("", diag.hint);

    var diag_int: Diagnostic = .{};
    try std.testing.expectError(error.InvalidValue, Config.parseDiag(arena.allocator(), "[global]\nfirewall = 1\n", &diag_int));
    try std.testing.expectEqualStrings("firewall", diag_int.key());
}

test "native: firewall is global-only; UnknownKey in [jails.*] and [defaults] (ENH-007)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var diag: Diagnostic = .{};
    try std.testing.expectError(error.UnknownKey, Config.parseDiag(arena.allocator(), "[jails.sshd]\nfilter = \"sshd\"\nfirewall = \"nftables\"\n", &diag));
    try std.testing.expectEqualStrings("firewall", diag.key());
    try std.testing.expectEqualStrings("jails.sshd", diag.section());
    try std.testing.expectEqual(@as(u32, 3), diag.line);
    try std.testing.expectError(error.UnknownKey, Config.parse(arena.allocator(), "[defaults]\nfirewall = \"nftables\"\n"));
}

test "native: metrics_enabled defaults true and parses false; non-bool is InvalidValue (ENH-008)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const def = try Config.parse(arena.allocator(), "[global]\n");
    try std.testing.expect(def.global.metrics_enabled);
    try std.testing.expectEqual(@as(u16, 9100), def.global.metrics_port);
    const off = try Config.parse(arena.allocator(), "[global]\nmetrics_enabled = false\n");
    try std.testing.expect(!off.global.metrics_enabled);
    try std.testing.expectEqual(@as(u16, 9100), off.global.metrics_port);
    var diag: Diagnostic = .{};
    try std.testing.expectError(error.InvalidValue, Config.parseDiag(arena.allocator(), "[global]\nmetrics_enabled = \"no\"\n", &diag));
    try std.testing.expectEqualStrings("metrics_enabled", diag.key());
    try std.testing.expectError(error.UnknownKey, Config.parse(arena.allocator(), "[jails.sshd]\nfilter = \"sshd\"\nmetrics_enabled = false\n"));
}

test "native: metrics_port = 0 is InvalidValue with a hint naming metrics_enabled (ENH-008, DBT-010)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[global]
        \\metrics_port = 0
    ;
    var diag: Diagnostic = .{};
    try std.testing.expectError(error.InvalidValue, Config.parseDiag(arena.allocator(), src, &diag));
    try std.testing.expectEqual(@as(u32, 2), diag.line);
    try std.testing.expectEqual(@as(u32, 16), diag.col);
    try std.testing.expectEqualStrings("metrics_port", diag.key());
    try std.testing.expectEqualStrings(metrics_port_zero_hint, diag.hint);

    var out_of_range: Diagnostic = .{};
    try std.testing.expectError(error.InvalidValue, Config.parseDiag(arena.allocator(), "[global]\nmetrics_port = 65536\n", &out_of_range));
    try std.testing.expectEqualStrings("", out_of_range.hint);
    const one = try Config.parse(arena.allocator(), "[global]\nmetrics_port = 1\n");
    try std.testing.expectEqual(@as(u16, 1), one.global.metrics_port);
}

test "native: retry and numeric bounds are rejected before narrowing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    for ([_][]const u8{
        "[defaults]\nmaxretry = 129\n",
        "[jails.sshd]\nmaxretry = 4294967296\n",
        "[global]\nmemory_ceiling_mb = 4294967296\n",
        "[defaults]\nbantime = 9223372036854775807\n",
    }) |source| try std.testing.expectError(error.InvalidValue, Config.parse(arena.allocator(), source));
    const cfg = try Config.parse(arena.allocator(), "[defaults]\nmaxretry = 128\n");
    try validate(&cfg);
}

test "native: unsupported enabled filter fails validation but disabled import can be retained" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var cfg = try Config.parse(arena.allocator(), "[jails.custom]\nenabled = true\nfilter = \"custom\"\n");
    try std.testing.expectError(error.UnknownFilter, validate(&cfg));
    cfg.jails[0].enabled = false;
    try validate(&cfg);
}

test "native: a single jail increment override inherits the other default fields" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const cfg = try Config.parse(arena.allocator(), "[jails.sshd]\nfilter = \"sshd\"\nbantime_increment_factor = 1.5\n[defaults]\nbantime_increment_enabled = true\nbantime_increment_multiplier = 2\n");
    const resolved = resolveJailFromConfig(&cfg.jails[0], cfg.defaults);
    try std.testing.expect(resolved.bantime_increment.enabled);
    try std.testing.expectEqual(@as(f64, 2), resolved.bantime_increment.multiplier);
    try std.testing.expectEqual(@as(f64, 1.5), resolved.bantime_increment.factor);
}

test "native preparation ceiling covers file parse and manifest entrypoints" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const oversized = try a.alloc(u8, max_config_bytes + 1);
    @memset(oversized, ' ');
    try std.testing.expectError(error.FileTooLarge, Config.parse(a, oversized));
    var diag: Diagnostic = .{};
    try std.testing.expectError(error.FileTooLarge, Config.parseDiag(a, oversized, &diag));
    try std.testing.expectError(error.FileTooLarge, decodeCompatibilityManifest(a, oversized));
    _ = try Config.parse(a, oversized[0..max_config_bytes]);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try tmp.dir.createFile("oversized.toml", .{ .mode = 0o600 });
    try file.writeAll(oversized);
    file.close();
    const path = try tmp.dir.realpathAlloc(a, "oversized.toml");
    try std.testing.expectError(error.FileTooLarge, Config.loadFile(a, path));
}

test "native: enforce normalizes policy before inheritance without choosing backend" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const cfg = try Config.parse(arena.allocator(),
        \\[global]
        \\firewall = "ipset"
        \\[defaults]
        \\enforce = false
        \\[jails.one]
        \\filter = "sshd"
        \\banaction = "iptables"
        \\[jails.two]
        \\filter = "sshd"
    );
    try std.testing.expectEqual(FirewallSelection.ipset, cfg.global.firewall);
    try std.testing.expectEqual(BanAction.iptables, cfg.jails[0].effectiveBanaction(cfg.defaults));
    try std.testing.expectEqual(BanAction.@"log-only", cfg.jails[1].effectiveBanaction(cfg.defaults));
    try std.testing.expect(cfg.legacy_banaction_used);
    const inverse = try Config.parse(arena.allocator(),
        \\[defaults]
        \\banaction = "log-only"
        \\[jails.one]
        \\filter = "sshd"
        \\enforce = true
    );
    try std.testing.expect(inverse.jails[0].effectiveBanaction(inverse.defaults) != .@"log-only");
    const native_only = try Config.parse(arena.allocator(), "[defaults]\nenforce = true\n");
    try std.testing.expect(!native_only.legacy_banaction_used);
}

test "native: mixed policy spellings conflict in either order and section" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    for ([_][]const u8{ "defaults", "jails.one" }) |section| {
        for ([_][]const u8{ "enforce = true\nbanaction = \"nftables\"\n", "banaction = \"log-only\"\nenforce = false\n" }) |body| {
            const text = try std.fmt.allocPrint(arena.allocator(), "[{s}]\n{s}", .{ section, body });
            var diagnostic: Diagnostic = .{};
            try std.testing.expectError(error.InvalidValue, Config.parseDiag(arena.allocator(), text, &diagnostic));
            try std.testing.expectEqualStrings(section, diagnostic.section());
            try std.testing.expect(std.mem.indexOf(u8, diagnostic.hint, "conflict") != null);
        }
    }
    try std.testing.expectError(error.InvalidValue, Config.parse(arena.allocator(), "[defaults]\nenforce = \"false\"\n"));
}

test "native: named timezone configuration rejects conflicting and unused context" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var cfg = try Config.parse(a, "[global]\nnative_ingestion = true\n[defaults]\nenforce = false\n[jails.sshd]\nfilter = \"sshd\"\ntimestamp = \"syslog\"\ntimezone = \"America/New_York\"\ntimezone_ambiguity = \"earlier\"\n");
    try validate(&cfg);
    try std.testing.expectEqualStrings("America/New_York", cfg.jails[0].timezone.?);
    try std.testing.expectEqual(.earlier, cfg.jails[0].timezone_ambiguity.?);
    cfg.jails[0].timezone_offset_minutes = 0;
    try std.testing.expectError(error.InvalidNativeTimezone, validate(&cfg));
    cfg.jails[0].timezone_offset_minutes = null;
    cfg.jails[0].timezone = null;
    try std.testing.expectError(error.InvalidNativeTimezone, validate(&cfg));
    try std.testing.expectError(error.InvalidValue, Config.parse(a, "[jails.sshd]\ntimezone = \"../escape\"\n"));
    try std.testing.expectError(error.InvalidValue, Config.parse(a, "[global]\ntimezone_root = \"relative\"\n"));
}

test "native: permanent bantime is explicit and inherits without numeric sentinels" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const cfg = try Config.parse(arena.allocator(),
        \\[defaults]
        \\bantime = "permanent"
        \\[jails.inherited]
        \\filter = "sshd"
        \\[jails.finite]
        \\filter = "sshd"
        \\bantime = 45
        \\[jails.permanent]
        \\filter = "sshd"
        \\bantime = "permanent"
    );
    try std.testing.expectEqual(BantimeKind.permanent, cfg.defaults.bantime_kind);
    try std.testing.expectEqual(BantimeKind.permanent, resolveJailFromConfig(&cfg.jails[0], cfg.defaults).bantime_kind);
    const finite = resolveJailFromConfig(&cfg.jails[1], cfg.defaults);
    try std.testing.expectEqual(BantimeKind.finite, finite.bantime_kind);
    try std.testing.expectEqual(@as(shared.Duration, 45), finite.bantime);
    try std.testing.expectEqual(BantimeKind.permanent, resolveJailFromConfig(&cfg.jails[2], cfg.defaults).bantime_kind);
    try std.testing.expectError(error.InvalidValue, Config.parse(arena.allocator(), "[defaults]\nbantime = -1\n"));
    try std.testing.expectError(error.InvalidValue, Config.parse(arena.allocator(), "[defaults]\nbantime = \"forever\"\n"));
}

test "native: duration defaults overrides integers and permanent retain inheritance" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const cfg = try Config.parse(arena.allocator(),
        \\[defaults]
        \\bantime = "1h30m"
        \\findtime = "2min"
        \\bantime_increment_enabled = true
        \\bantime_increment_max_bantime = "1w"
        \\bantime_increment_jitter = "30s"
        \\[jails.inherited]
        \\filter = "sshd"
        \\[jails.override]
        \\filter = "sshd"
        \\bantime = "2h"
        \\findtime = 90
        \\bantime_increment_max_bantime = "1d"
        \\bantime_increment_jitter = "0s"
        \\[jails.mixed]
        \\filter = "sshd"
        \\bantime = 45
        \\findtime = "3mm"
        \\bantime_increment_jitter = 5
        \\[jails.permanent]
        \\filter = "sshd"
        \\bantime = "permanent"
    );
    const cases = .{
        .{ 0, 5400, 120, 604_800, 30, BantimeKind.finite },
        .{ 1, 7200, 90, 86_400, 0, BantimeKind.finite },
        .{ 2, 45, 180, 604_800, 5, BantimeKind.finite },
        .{ 3, 5400, 120, 604_800, 30, BantimeKind.permanent },
    };
    inline for (cases) |case| {
        const resolved = resolveJailFromConfig(&cfg.jails[case[0]], cfg.defaults);
        try std.testing.expectEqual(@as(u64, case[1]), resolved.bantime);
        try std.testing.expectEqual(@as(u64, case[2]), resolved.findtime);
        try std.testing.expectEqual(@as(u64, case[3]), resolved.bantime_increment.max_bantime);
        try std.testing.expectEqual(@as(u64, case[4]), resolved.bantime_increment.jitter);
        try std.testing.expectEqual(case[5], resolved.bantime_kind);
        try std.testing.expect(resolved.bantime_increment.enabled);
    }
    const permanent = try Config.parse(arena.allocator(), "[defaults]\nbantime = \"permanent\"\n[jails.sshd]\nbantime = \"1m\"\n");
    try std.testing.expectEqual(BantimeKind.finite, resolveJailFromConfig(&permanent.jails[0], permanent.defaults).bantime_kind);
}

test "native: duration rejection preserves field ceilings and positioned diagnostics" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const cases = .{
        .{ "bantime", "\"1ms\"" },
        .{ "bantime", "\"-1h\"" },
        .{ "bantime", "-1" },
        .{ "bantime", "1.5" },
        .{ "bantime", "\"1.5h\"" },
        .{ "bantime", "\"1h+1m\"" },
        .{ "bantime", "\"18446744073709551616s\"" },
        .{ "bantime", "\"18446744073709551615h\"" },
        .{ "bantime", "\"18446744073709551615s1s\"" },
        .{ "bantime", "\"18446744073709552s\"" },
        .{ "bantime_increment_max_bantime", "\"18446744073709552s\"" },
        .{ "bantime_increment_jitter", "\"18446744073709552s\"" },
        .{ "findtime", "\"9223372036854775808s\"" },
        .{ "findtime", "\"permanent\"" },
        .{ "bantime_increment_max_bantime", "\"permanent\"" },
        .{ "bantime_increment_jitter", "\"permanent\"" },
    };
    inline for (cases) |case| {
        for ([_][]const u8{ "defaults", "jails.sshd" }) |section| {
            const text = try std.fmt.allocPrint(arena.allocator(), "[{s}]\n{s} = {s}\n", .{ section, case[0], case[1] });
            var diag: Diagnostic = .{};
            try std.testing.expectError(error.InvalidValue, Config.parseDiag(arena.allocator(), text, &diag));
            try std.testing.expectEqual(@as(u32, 2), diag.line);
            try std.testing.expectEqual(@as(u32, case[0].len + 4), diag.col);
            try std.testing.expectEqualStrings(case[0], diag.key());
            try std.testing.expectEqualStrings(section, diag.section());
        }
    }
    const at_limit = try Config.parse(arena.allocator(), "[defaults]\nbantime = \"18446744073709551s\"\nfindtime = \"9223372036854775807s\"\nbantime_increment_max_bantime = \"18446744073709551s\"\nbantime_increment_jitter = \"18446744073709551s\"\n");
    try std.testing.expectEqual(max_ban_duration, at_limit.defaults.bantime);
    try std.testing.expectEqual(@as(u64, std.math.maxInt(i64)), at_limit.defaults.findtime);
    try std.testing.expectEqual(max_ban_duration, at_limit.defaults.bantime_increment.max_bantime);
    try std.testing.expectEqual(max_ban_duration, at_limit.defaults.bantime_increment.jitter);
}

test "native: duration strings preserve validation zero rules" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    for ([_][]const u8{ "defaults", "jails.sshd" }) |section| {
        inline for (.{ .{ "bantime", error.InvalidBantime }, .{ "findtime", error.InvalidFindtime }, .{ "bantime_increment_max_bantime", error.InvalidIncrement } }) |case| {
            const text = try std.fmt.allocPrint(arena.allocator(), "[{s}]\n{s} = \"0s\"\n{s}", .{ section, case[0], if (std.mem.startsWith(u8, section, "jails.")) "filter = \"sshd\"\n" else "" });
            const cfg = try Config.parse(arena.allocator(), text);
            try std.testing.expectError(case[1], validate(&cfg));
        }
        const text = try std.fmt.allocPrint(arena.allocator(), "[{s}]\nbantime_increment_jitter = \"0s\"\n{s}", .{ section, if (std.mem.startsWith(u8, section, "jails.")) "filter = \"sshd\"\n" else "" });
        const cfg = try Config.parse(arena.allocator(), text);
        try validate(&cfg);
    }
}

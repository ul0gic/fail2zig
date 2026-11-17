// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Defines the typed global, default and jail settings and loads the native configuration file into them.
// Holds: A configuration file larger than max_config_bytes, or writable by others or by a non-root group, is refused before parsing.

const std = @import("std");
const shared = @import("shared");
const Parser = @import("parser.zig").Parser;
pub const max_config_bytes: usize = 16 * 1024 * 1024;
pub const max_supported_retry: usize = 128;
pub const max_ban_duration: u64 = std.math.maxInt(u64) / 1000;

pub const Error = error{
    FileNotFound,
    FileTooLarge,
    AccessDenied,
    UnexpectedToken,
    UnterminatedString,
    InvalidEscape,
    InvalidInteger,
    InvalidFloat,
    InvalidBool,
    InvalidArray,
    DuplicateKey,
    UnknownSection,
    UnknownKey,
    MissingRequired,
    InvalidValue,
    TooManyJails,
    OutOfMemory,
    ReadFailed,
    ConfigWorldWritable,
    ConfigGroupWritable,
    InvalidTruncationPolicy,
    TruncationPolicyNotFileSource,
    TruncationPolicyNotAllowedInDefaults,
};

pub const Diagnostic = struct {
    line: u32 = 0,
    col: u32 = 0,
    mode: u32 = 0,
    hint: []const u8 = "",
    key_len: u8 = 0,
    section_len: u8 = 0,
    key_buf: [max_name]u8 = [_]u8{0} ** max_name,
    section_buf: [max_name]u8 = [_]u8{0} ** max_name,

    pub const max_name: usize = 64;

    pub fn key(self: *const Diagnostic) []const u8 {
        return self.key_buf[0..self.key_len];
    }

    pub fn section(self: *const Diagnostic) []const u8 {
        return self.section_buf[0..self.section_len];
    }

    pub fn copyName(dst: *[max_name]u8, src: []const u8) u8 {
        const n = @min(src.len, max_name);
        for (src[0..n], 0..) |c, i| {
            dst[i] = if (std.ascii.isPrint(c)) c else '?';
        }
        return @intCast(n);
    }
};

pub const LogLevel = enum { debug, info, warn, err };

pub const LogFormat = enum { text, json };

pub const BanAction = enum { nftables, iptables, ipset, @"log-only" };

pub const LogSource = enum { auto, file, journald, internal };

pub const TruncationPolicy = enum { refuse, restart };

pub const internal_filter: []const u8 = "recidive";

pub fn filterSupportsInternal(filter: []const u8) bool {
    return std.mem.eql(u8, filter, internal_filter);
}

pub const BantimeFormula = enum { linear, exponential };
pub const BantimeScope = enum { per_jail, overall };
pub const BantimeKind = enum { finite, permanent };

pub const OnNoBackend = enum { @"fail-closed", @"log-only" };

pub const FirewallSelection = enum { auto, nftables, ipset, iptables };

pub const BanTimeIncrement = struct {
    enabled: bool = false,
    multiplier: f64 = 1.0,
    factor: f64 = 1.0,
    formula: BantimeFormula = .linear,
    scope: BantimeScope = .per_jail,
    max_bantime: shared.Duration = 86_400 * 7,
    jitter: shared.Duration = 0,
};

pub const GlobalConfig = struct {
    native_ingestion: bool = true,
    compatibility_manifest: []const u8 = "",
    compatibility_pending: bool = false,
    log_level: LogLevel = .info,
    log_format: LogFormat = .text,
    log_target: []const u8 = "stderr",
    pid_file: []const u8 = "/run/fail2zig/fail2zig.pid",
    socket_path: []const u8 = "/run/fail2zig/fail2zig.sock",
    state_file: []const u8 = "/var/lib/fail2zig/state.bin",
    memory_ceiling_mb: u32 = 64,
    native_memory_ceiling_mb: u32 = 512,
    native_fd_ceiling: u32 = 8192,
    metrics_enabled: bool = true,
    metrics_bind: []const u8 = "127.0.0.1",
    metrics_port: u16 = 9100,
    history_retention: shared.Duration = 86_400,
    history_max_matches: u16 = 10,
    on_no_backend: OnNoBackend = .@"fail-closed",
    firewall: FirewallSelection = .auto,
    timezone_root: []const u8 = "/usr/share/zoneinfo",
    firewall_namespace: []const u8 = "/proc/self/ns/net",
    dns_server: ?[]const u8 = null,
    dns_port: u16 = 53,
};

pub const max_configured_jails: usize = 256;

pub const JailDefaults = struct {
    bantime: shared.Duration = 600,
    bantime_kind: BantimeKind = .finite,
    findtime: shared.Duration = 600,
    maxretry: u32 = 5,
    banaction: BanAction = .nftables,
    ignoreip: []const []const u8 = &.{},
    banip: []const []const u8 = &.{},
    ignoreself: bool = true,
    bantime_increment_decay: shared.Duration = 30 * 86_400,
    ignoretime: ?shared.Duration = null,
    bantime_increment: BanTimeIncrement = .{},
    source: LogSource = .auto,
};

pub const JailConfig = struct {
    timestamp: ?enum { iso8601, syslog, epoch_seconds, common_log, undated } = null,
    timezone_offset_minutes: ?i16 = null,
    timezone: ?[]const u8 = null,
    timezone_ambiguity: ?@import("../time/timezone.zig").Ambiguity = null,
    journal_executables: []const []const u8 = &.{},
    journal_executables_explicit: bool = false,
    rule_files: []const []const u8 = &.{},
    ignore_file: ?[]const u8 = null,
    compatibility_pending: bool = false,
    name: []const u8,
    enabled: bool = true,
    logpath: []const []const u8 = &.{},
    source: LogSource = .auto,
    filter: []const u8 = "",
    maxretry: ?u32 = null,
    history_max_matches: ?u16 = null,
    findtime: ?shared.Duration = null,
    bantime: ?shared.Duration = null,
    bantime_kind: ?BantimeKind = null,
    banaction: ?BanAction = null,
    ignoreip: ?[]const []const u8 = null,
    banip: ?[]const []const u8 = null,
    ignoreself: ?bool = null,
    bantime_increment_decay: ?shared.Duration = null,
    ignoretime: ?shared.Duration = null,
    bantime_increment: BanTimeIncrement = .{},
    bantime_increment_explicit: bool = false,
    // Does:  Marks the increment keys this jail set: 1 enabled, 2 multiplier, 4 factor, 8 formula, 16 max_bantime, 32 scope, 64 jitter.
    bantime_increment_fields: u8 = 0,
    on_truncation: ?TruncationPolicy = null,

    pub fn effectiveBantime(self: *const JailConfig, def: JailDefaults) shared.Duration {
        return self.bantime orelse def.bantime;
    }
    pub fn effectiveBantimeKind(self: *const JailConfig, def: JailDefaults) BantimeKind {
        if (self.bantime != null) return self.bantime_kind orelse .finite;
        return self.bantime_kind orelse def.bantime_kind;
    }
    pub fn effectiveFindtime(self: *const JailConfig, def: JailDefaults) shared.Duration {
        return self.findtime orelse def.findtime;
    }
    pub fn effectiveMaxretry(self: *const JailConfig, def: JailDefaults) u32 {
        return self.maxretry orelse def.maxretry;
    }
    pub fn effectiveBanaction(self: *const JailConfig, def: JailDefaults) BanAction {
        return self.banaction orelse def.banaction;
    }
};

pub const ResolvedJailConfig = struct {
    name: []const u8,
    enabled: bool,
    maxretry: u32,
    history_max_matches: ?u16,
    findtime: shared.Duration,
    bantime: shared.Duration,
    bantime_kind: BantimeKind,
    banaction: BanAction,
    bantime_increment: BanTimeIncrement,
    on_truncation: TruncationPolicy,
    banip: []const []const u8,
    ignoreself: bool,
    bantime_increment_decay: shared.Duration,
    ignoretime_s: ?u64,
};

pub fn resolveJailFromConfig(j: *const JailConfig, defaults: JailDefaults) ResolvedJailConfig {
    var increment = defaults.bantime_increment;
    if (j.bantime_increment_explicit and j.bantime_increment_fields == 0) {
        increment = j.bantime_increment;
    } else {
        if (j.bantime_increment_fields & 1 != 0) increment.enabled = j.bantime_increment.enabled;
        if (j.bantime_increment_fields & 2 != 0) increment.multiplier = j.bantime_increment.multiplier;
        if (j.bantime_increment_fields & 4 != 0) increment.factor = j.bantime_increment.factor;
        if (j.bantime_increment_fields & 8 != 0) increment.formula = j.bantime_increment.formula;
        if (j.bantime_increment_fields & 16 != 0) increment.max_bantime = j.bantime_increment.max_bantime;
        if (j.bantime_increment_fields & 32 != 0) increment.scope = j.bantime_increment.scope;
        if (j.bantime_increment_fields & 64 != 0) increment.jitter = j.bantime_increment.jitter;
    }
    return .{
        .name = j.name,
        .enabled = j.enabled,
        .maxretry = j.effectiveMaxretry(defaults),
        .history_max_matches = j.history_max_matches,
        .findtime = j.effectiveFindtime(defaults),
        .bantime = j.effectiveBantime(defaults),
        .bantime_kind = j.effectiveBantimeKind(defaults),
        .banaction = j.effectiveBanaction(defaults),
        .bantime_increment = increment,
        .on_truncation = j.on_truncation orelse .refuse,
        .banip = j.banip orelse defaults.banip,
        .ignoreself = j.ignoreself orelse defaults.ignoreself,
        .bantime_increment_decay = j.bantime_increment_decay orelse defaults.bantime_increment_decay,
        .ignoretime_s = resolvedIgnoretime(j, defaults),
    };
}

pub fn resolvedIgnoretime(j: *const JailConfig, defaults: JailDefaults) ?u64 {
    const seconds = j.ignoretime orelse defaults.ignoretime orelse return null;
    return if (seconds == 0) null else seconds;
}

pub const Config = struct {
    retained_capacity: usize = 0,
    global: GlobalConfig = .{},
    defaults: JailDefaults = .{},
    jails: []JailConfig = &.{},
    diag: Diagnostic = .{},
    legacy_banaction_used: bool = false,

    pub fn loadFile(arena: std.mem.Allocator, path: []const u8) Error!Config {
        var scratch: Diagnostic = .{};
        return loadFileDiag(arena, path, &scratch);
    }

    pub fn parse(arena: std.mem.Allocator, source: []const u8) Error!Config {
        var scratch: Diagnostic = .{};
        return parseDiag(arena, source, &scratch);
    }

    pub fn loadFileDiag(arena: std.mem.Allocator, path: []const u8, out: *Diagnostic) Error!Config {
        out.* = .{};
        const file = std.fs.cwd().openFile(path, .{}) catch |err| return switch (err) {
            error.FileNotFound => error.FileNotFound,
            error.AccessDenied => error.AccessDenied,
            else => error.ReadFailed,
        };
        defer file.close();

        const st = std.posix.fstat(file.handle) catch return error.ReadFailed;
        out.mode = st.mode & 0o7777;
        try checkConfigPerms(st.mode, st.gid);
        if (st.uid != 0) {
            std.log.warn("config: {s} is owned by uid {d}, not root", .{ path, st.uid });
        }

        const bytes = file.readToEndAlloc(arena, max_config_bytes) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.FileTooBig => error.FileTooLarge,
            else => error.ReadFailed,
        };
        return parseDiag(arena, bytes, out);
    }

    pub fn checkConfigPerms(mode: u32, gid: u32) error{ ConfigWorldWritable, ConfigGroupWritable }!void {
        if (mode & std.posix.S.IWOTH != 0) return error.ConfigWorldWritable;
        if (mode & std.posix.S.IWGRP != 0 and gid != 0) return error.ConfigGroupWritable;
    }

    pub fn parseDiag(arena: std.mem.Allocator, source: []const u8, out: *Diagnostic) Error!Config {
        if (source.len > max_config_bytes) return error.FileTooLarge;
        var p = Parser.init(arena, source);
        return p.parseConfig(out);
    }

    pub fn load(allocator: std.mem.Allocator, path: []const u8) Error!Config {
        return loadFile(allocator, path);
    }
};

pub const validate = @import("validation.zig").validate;
pub const validateDiag = @import("validation.zig").validateDiag;
pub const ValidationDiagnostic = @import("validation.zig").ValidationDiagnostic;

pub fn mapBackendAlias(s: []const u8) ?LogSource {
    if (std.mem.eql(u8, s, "systemd")) return .journald;
    const auto_names = [_][]const u8{ "auto", "polling", "pyinotify", "gamin" };
    for (auto_names) |n| if (std.mem.eql(u8, s, n)) return .auto;
    return null;
}

pub const journalctl_path: []const u8 = "/usr/bin/journalctl";

pub fn anyLogpathExists(logpath: []const []const u8) bool {
    for (logpath) |lp| {
        if (lp.len == 0) continue;
        std.fs.cwd().access(lp, .{ .mode = .read_only }) catch continue;
        return true;
    }
    return false;
}

pub fn filterSupportsJournald(filter: []const u8) bool {
    return std.mem.eql(u8, filter, "sshd");
}

pub fn journalctlPresent() bool {
    std.fs.cwd().access(journalctl_path, .{ .mode = .read_only }) catch return false;
    return true;
}

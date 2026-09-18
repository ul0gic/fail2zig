// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const shared = @import("shared");
const native_duration = @import("native_duration.zig");
const filter_registry = @import("../filters/registry.zig");
pub const max_config_bytes: usize = 16 * 1024 * 1024;
pub const max_supported_retry = @import("../core/state.zig").max_attempts_per_ip;
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

    fn copyName(dst: *[max_name]u8, src: []const u8) u8 {
        const n = @min(src.len, max_name);
        for (src[0..n], 0..) |c, i| {
            dst[i] = if (std.ascii.isPrint(c)) c else '?';
        }
        return @intCast(n);
    }
};

pub const LogLevel = enum { debug, info, warn, err };

pub const BanAction = enum { nftables, iptables, ipset, @"log-only" };

pub const LogSource = enum { auto, file, journald, internal };

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
    log_target: []const u8 = "stderr",
    pid_file: []const u8 = "/run/fail2zig/fail2zig.pid",
    socket_path: []const u8 = "/run/fail2zig/fail2zig.sock",
    state_file: []const u8 = "/var/lib/fail2zig/state.bin",
    memory_ceiling_mb: u32 = 64,
    native_memory_ceiling_mb: u32 = 256,
    native_fd_ceiling: u32 = 2048,
    metrics_enabled: bool = true,
    metrics_bind: []const u8 = "127.0.0.1",
    metrics_port: u16 = 9100,
    websocket_max_clients: u32 = 16,
    history_retention: shared.Duration = 86_400,
    history_max_matches: u16 = 10,
    on_no_backend: OnNoBackend = .@"fail-closed",
    firewall: FirewallSelection = .auto,
    timezone_root: []const u8 = "/usr/share/zoneinfo",
    firewall_namespace: []const u8 = "/proc/self/ns/net",
    dns_server: ?[]const u8 = null,
    dns_port: u16 = 53,
};

pub const websocket_hard_max_clients: u32 = 1024;

pub const JailDefaults = struct {
    bantime: shared.Duration = 600,
    bantime_kind: BantimeKind = .finite,
    findtime: shared.Duration = 600,
    maxretry: u32 = 5,
    banaction: BanAction = .nftables,
    ignoreip: []const []const u8 = &.{},
    bantime_increment: BanTimeIncrement = .{},
    source: LogSource = .auto,
};

pub const JailConfig = struct {
    timestamp: ?enum { iso8601, syslog, epoch_seconds, common_log, undated } = null,
    timezone_offset_minutes: ?i16 = null,
    timezone: ?[]const u8 = null,
    timezone_ambiguity: ?@import("../core/native_timezone.zig").Ambiguity = null,
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
    findtime: ?shared.Duration = null,
    bantime: ?shared.Duration = null,
    bantime_kind: ?BantimeKind = null,
    banaction: ?BanAction = null,
    ignoreip: ?[]const []const u8 = null,
    bantime_increment: BanTimeIncrement = .{},
    bantime_increment_explicit: bool = false,
    bantime_increment_fields: u8 = 0,

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
    findtime: shared.Duration,
    bantime: shared.Duration,
    bantime_kind: BantimeKind,
    banaction: BanAction,
    bantime_increment: BanTimeIncrement,
};

pub fn resolveJail(cfg: *const Config, jail_name: []const u8) ?ResolvedJailConfig {
    for (cfg.jails) |*j| {
        if (std.mem.eql(u8, j.name, jail_name)) {
            return resolveJailFromConfig(j, cfg.defaults);
        }
    }
    return null;
}

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
        .findtime = j.effectiveFindtime(defaults),
        .bantime = j.effectiveBantime(defaults),
        .bantime_kind = j.effectiveBantimeKind(defaults),
        .banaction = j.effectiveBanaction(defaults),
        .bantime_increment = increment,
    };
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

pub const ValidationError = error{
    InvalidNativePath,
    InvalidNativeDns,
    InvalidNativeRules,
    InvalidNativeResources,
    InvalidNativeTimezone,
    NativeIngestionRequired,
    CompatibilityNotAdmitted,
    InvalidBantime,
    InvalidFindtime,
    InvalidMaxretry,
    MemoryCeilingTooLow,
    MemoryCeilingTooHigh,
    InvalidIncrement,
    UnknownFilter,
    EmptyJailName,
    InvalidJailName,
    DuplicateJailName,
};

pub const ValidationSection = enum {
    none,
    global,
    defaults,
    jail,
};

pub const ValidationKey = enum {
    none,
    native_ingestion,
    socket_path,
    state_file,
    pid_file,
    timezone_root,
    firewall_namespace,
    dns_server,
    dns_port,
    logpath,
    journal_executables,
    rule_files,
    ignore_file,
    memory_ceiling_mb,
    native_memory_ceiling_mb,
    native_fd_ceiling,
    bantime_increment_multiplier,
    bantime_increment_factor,
    bantime_increment_max_bantime,
    bantime_increment_jitter,
    bantime,
    findtime,
    maxretry,
    timezone,
    timezone_ambiguity,
    name,
    compatibility_manifest,
    filter,
};

pub const ValidationConstraint = enum {
    none,
    must_be_enabled,
    valid_path,
    unix_socket_path_limit,
    valid_ip_address,
    port_greater_than_zero,
    default_port_without_server,
    absolute_path,
    namespace_path,
    at_most_eight_entries,
    native_ingestion_required,
    absolute_path_entries,
    unique_entries,
    at_least_sixteen_mib,
    fits_address_space,
    greater_than_zero,
    finite_greater_than_zero,
    finite_nonnegative,
    valid_ban_duration,
    jitter_within_max_bantime,
    between_one_and_max_retry,
    mutually_exclusive_timezone,
    timezone_required,
    nonempty_jail_name,
    valid_jail_name,
    unique_jail_name,
    admitted_compatibility,
    valid_rule_filter,
    builtin_filter,
};

/// Allocation-free semantic validation context. Configuration values are never
/// retained here; the only copied input is a bounded jail identifier.
pub const ValidationDiagnostic = struct {
    section: ValidationSection = .none,
    key: ValidationKey = .none,
    constraint: ValidationConstraint = .none,
    jail_len: u8 = 0,
    jail_truncated: bool = false,
    jail_buf: [max_jail_bytes]u8 = [_]u8{0} ** max_jail_bytes,

    pub const max_jail_bytes: usize = shared.JailId.max_len;

    pub fn jail(self: *const ValidationDiagnostic) []const u8 {
        return self.jail_buf[0..self.jail_len];
    }

    /// Render bounded context without inventing source coordinates. Field and
    /// constraint come first so a short caller buffer remains actionable.
    /// Truncation is always visible and an escaped jail byte is never split.
    pub fn render(self: *const ValidationDiagnostic, out: []u8) []const u8 {
        var rendered = ValidationRenderBuffer{ .out = out };
        switch (self.section) {
            .global => rendered.appendLiteral("[global]."),
            .defaults => rendered.appendLiteral("[defaults]."),
            .jail, .none => {},
        }
        rendered.appendLiteral(validationKeyName(self.key));
        rendered.appendLiteral(": ");
        rendered.appendLiteral(validationConstraintText(self.constraint));
        if (self.section == .jail) {
            rendered.appendLiteral("; jail '");
            for (self.jail()) |byte| rendered.appendEscapedByte(byte);
            if (self.jail_truncated) rendered.appendLiteral("...");
            rendered.appendLiteral("'");
        }
        return rendered.slice();
    }

    fn setJail(self: *ValidationDiagnostic, name: []const u8) void {
        const len = @min(name.len, max_jail_bytes);
        @memcpy(self.jail_buf[0..len], name[0..len]);
        self.jail_len = @intCast(len);
        self.jail_truncated = name.len > len;
    }
};

const ValidationRenderBuffer = struct {
    out: []u8,
    len: usize = 0,
    truncated: bool = false,

    fn slice(self: *const ValidationRenderBuffer) []const u8 {
        return self.out[0..self.len];
    }

    fn appendLiteral(self: *ValidationRenderBuffer, text: []const u8) void {
        if (self.truncated or text.len == 0) return;
        const available = self.availableBeforeEllipsis();
        if (text.len <= available) {
            @memcpy(self.out[self.len..][0..text.len], text);
            self.len += text.len;
            return;
        }
        const copied = @min(text.len, available);
        @memcpy(self.out[self.len..][0..copied], text[0..copied]);
        self.len += copied;
        self.markTruncated();
    }

    fn appendEscapedByte(self: *ValidationRenderBuffer, byte: u8) void {
        if (self.truncated) return;
        if (byte >= 0x20 and byte <= 0x7e and byte != '\\' and byte != '\'') {
            const unit = [1]u8{byte};
            return self.appendUnit(&unit);
        }
        if (byte == '\\' or byte == '\'') {
            const unit = [2]u8{ '\\', byte };
            return self.appendUnit(&unit);
        }
        const hex = "0123456789abcdef";
        const unit = [4]u8{ '\\', 'x', hex[byte >> 4], hex[byte & 0x0f] };
        self.appendUnit(&unit);
    }

    fn appendUnit(self: *ValidationRenderBuffer, unit: []const u8) void {
        if (self.truncated) return;
        if (unit.len > self.availableBeforeEllipsis()) return self.markTruncated();
        @memcpy(self.out[self.len..][0..unit.len], unit);
        self.len += unit.len;
    }

    fn availableBeforeEllipsis(self: *const ValidationRenderBuffer) usize {
        if (self.out.len <= self.len + 3) return 0;
        return self.out.len - self.len - 3;
    }

    fn markTruncated(self: *ValidationRenderBuffer) void {
        if (self.truncated) return;
        self.truncated = true;
        if (self.out.len == 0) return;
        const count = @min(@as(usize, 3), self.out.len - self.len);
        @memset(self.out[self.len..][0..count], '.');
        self.len += count;
        if (count == 0) {
            const replace = @min(@as(usize, 3), self.len);
            @memset(self.out[self.len - replace .. self.len], '.');
        }
    }
};

fn validationKeyName(key: ValidationKey) []const u8 {
    return switch (key) {
        .none => "validation",
        else => @tagName(key),
    };
}

fn validationConstraintText(constraint: ValidationConstraint) []const u8 {
    return switch (constraint) {
        .none => "failed",
        .must_be_enabled => "must be enabled",
        .valid_path => "must be nonempty, bounded, and contain no NUL",
        .unix_socket_path_limit => "must fit a Unix socket address",
        .valid_ip_address => "must be a bounded IP address",
        .port_greater_than_zero => "must be greater than 0",
        .default_port_without_server => "must be 53 when dns_server is unset",
        .absolute_path => "must be an absolute path",
        .namespace_path => "must be an absolute path of at most 256 bytes",
        .at_most_eight_entries => "must contain at most 8 entries",
        .native_ingestion_required => "requires native ingestion",
        .absolute_path_entries => "entries must be absolute, bounded, and contain no NUL",
        .unique_entries => "entries must be unique",
        .at_least_sixteen_mib => "must be at least 16 MiB",
        .fits_address_space => "is too large for this platform",
        .greater_than_zero => "must be greater than 0",
        .finite_greater_than_zero => "must be finite and greater than 0",
        .finite_nonnegative => "must be finite and nonnegative",
        .valid_ban_duration => "must be greater than 0 and within the duration limit",
        .jitter_within_max_bantime => "must not exceed bantime_increment_max_bantime",
        .between_one_and_max_retry => "must be between 1 and 128",
        .mutually_exclusive_timezone => "cannot be combined with timezone_offset_minutes",
        .timezone_required => "requires timezone",
        .nonempty_jail_name => "must not be empty",
        .valid_jail_name => "must be a valid jail identifier",
        .unique_jail_name => "must be unique",
        .admitted_compatibility => "requires admitted compatibility settings",
        .valid_rule_filter => "must identify a valid rule filter",
        .builtin_filter => "must identify a built-in filter",
    };
}

fn setValidationDiagnostic(
    out: *ValidationDiagnostic,
    section: ValidationSection,
    key: ValidationKey,
    constraint: ValidationConstraint,
    jail: ?[]const u8,
) void {
    out.section = section;
    out.key = key;
    out.constraint = constraint;
    if (jail) |name| out.setJail(name);
}

pub fn validate(cfg: *const Config) ValidationError!void {
    var scratch: ValidationDiagnostic = .{};
    return validateDiag(cfg, &scratch);
}

pub fn validateDiag(cfg: *const Config, out: *ValidationDiagnostic) ValidationError!void {
    out.* = .{};
    if (!cfg.global.native_ingestion) return validationFailure(out, .global, .native_ingestion, .must_be_enabled, null, error.NativeIngestionRequired);
    inline for (.{
        .{ cfg.global.socket_path, ValidationKey.socket_path },
        .{ cfg.global.state_file, ValidationKey.state_file },
        .{ cfg.global.pid_file, ValidationKey.pid_file },
        .{ cfg.global.timezone_root, ValidationKey.timezone_root },
        .{ cfg.global.firewall_namespace, ValidationKey.firewall_namespace },
    }) |entry| {
        const path, const key = entry;
        if (path.len == 0 or path.len >= std.fs.max_path_bytes or std.mem.indexOfScalar(u8, path, 0) != null)
            return validationFailure(out, .global, key, .valid_path, null, error.InvalidNativePath);
    }
    if (cfg.global.socket_path.len >= 108) return validationFailure(out, .global, .socket_path, .unix_socket_path_limit, null, error.InvalidNativePath);
    if (cfg.global.dns_server) |server| {
        if (!cfg.global.native_ingestion) return validationFailure(out, .global, .native_ingestion, .must_be_enabled, null, error.NativeIngestionRequired);
        if (server.len == 0 or server.len > 64)
            return validationFailure(out, .global, .dns_server, .valid_ip_address, null, error.InvalidNativeDns);
        if (cfg.global.dns_port == 0) return validationFailure(out, .global, .dns_port, .port_greater_than_zero, null, error.InvalidNativeDns);
        if (std.mem.indexOfScalar(u8, server, 0) != null)
            return validationFailure(out, .global, .dns_server, .valid_ip_address, null, error.InvalidNativeDns);
        _ = std.net.Address.parseIp(server, cfg.global.dns_port) catch
            return validationFailure(out, .global, .dns_server, .valid_ip_address, null, error.InvalidNativeDns);
    } else if (cfg.global.dns_port != 53) {
        return validationFailure(out, .global, .dns_port, .default_port_without_server, null, error.InvalidNativeDns);
    }
    if (cfg.global.native_ingestion) {
        if (!std.fs.path.isAbsolute(cfg.global.state_file)) return validationFailure(out, .global, .state_file, .absolute_path, null, error.InvalidNativePath);
        if (!std.fs.path.isAbsolute(cfg.global.socket_path)) return validationFailure(out, .global, .socket_path, .absolute_path, null, error.InvalidNativePath);
        if (!std.fs.path.isAbsolute(cfg.global.firewall_namespace) or cfg.global.firewall_namespace.len > 256)
            return validationFailure(out, .global, .firewall_namespace, .namespace_path, null, error.InvalidNativePath);
    }
    for (cfg.jails) |jail| {
        for (jail.logpath) |path| if (path.len == 0 or path.len >= std.fs.max_path_bytes or std.mem.indexOfScalar(u8, path, 0) != null)
            return validationFailure(out, .jail, .logpath, .valid_path, jail.name, error.InvalidNativePath);
        for (jail.journal_executables) |path| if (!std.fs.path.isAbsolute(path) or path.len >= std.fs.max_path_bytes or std.mem.indexOfScalar(u8, path, 0) != null)
            return validationFailure(out, .jail, .journal_executables, .absolute_path_entries, jail.name, error.InvalidNativePath);
        if (jail.rule_files.len > 8) return validationFailure(out, .jail, .rule_files, .at_most_eight_entries, jail.name, error.InvalidNativeRules);
        if (!cfg.global.native_ingestion and (jail.rule_files.len != 0 or jail.ignore_file != null))
            return validationFailure(out, .jail, if (jail.rule_files.len != 0) .rule_files else .ignore_file, .native_ingestion_required, jail.name, error.NativeIngestionRequired);
        for (jail.rule_files, 0..) |path, i| {
            if (!std.fs.path.isAbsolute(path) or path.len >= std.fs.max_path_bytes or std.mem.indexOfScalar(u8, path, 0) != null)
                return validationFailure(out, .jail, .rule_files, .absolute_path_entries, jail.name, error.InvalidNativePath);
            for (jail.rule_files[0..i]) |prior| if (std.mem.eql(u8, prior, path))
                return validationFailure(out, .jail, .rule_files, .unique_entries, jail.name, error.InvalidNativeRules);
        }
        if (jail.ignore_file) |path| if (!std.fs.path.isAbsolute(path) or path.len >= std.fs.max_path_bytes or std.mem.indexOfScalar(u8, path, 0) != null)
            return validationFailure(out, .jail, .ignore_file, .absolute_path, jail.name, error.InvalidNativePath);
    }
    if (cfg.global.memory_ceiling_mb < 16) {
        std.log.warn("config: memory_ceiling_mb={d} is below 16MB floor", .{cfg.global.memory_ceiling_mb});
        return validationFailure(out, .global, .memory_ceiling_mb, .at_least_sixteen_mib, null, error.MemoryCeilingTooLow);
    }
    if (cfg.global.memory_ceiling_mb > std.math.maxInt(usize) / (1024 * 1024))
        return validationFailure(out, .global, .memory_ceiling_mb, .fits_address_space, null, error.MemoryCeilingTooHigh);
    if (cfg.global.native_memory_ceiling_mb == 0)
        return validationFailure(out, .global, .native_memory_ceiling_mb, .greater_than_zero, null, error.InvalidNativeResources);
    if (cfg.global.native_memory_ceiling_mb > std.math.maxInt(usize) / (1024 * 1024))
        return validationFailure(out, .global, .native_memory_ceiling_mb, .fits_address_space, null, error.InvalidNativeResources);
    if (cfg.global.native_fd_ceiling == 0)
        return validationFailure(out, .global, .native_fd_ceiling, .greater_than_zero, null, error.InvalidNativeResources);
    try validateIncrementDiag(cfg.defaults.bantime_increment, out, .defaults, null);
    if (cfg.defaults.bantime_kind == .finite and (cfg.defaults.bantime == 0 or cfg.defaults.bantime > max_ban_duration)) {
        std.log.warn("config: defaults.bantime must be > 0", .{});
        return validationFailure(out, .defaults, .bantime, .valid_ban_duration, null, error.InvalidBantime);
    }
    if (cfg.defaults.findtime == 0) {
        std.log.warn("config: defaults.findtime must be > 0", .{});
        return validationFailure(out, .defaults, .findtime, .greater_than_zero, null, error.InvalidFindtime);
    }
    if (cfg.defaults.maxretry == 0 or cfg.defaults.maxretry > max_supported_retry) {
        std.log.warn("config: defaults.maxretry must be between 1 and 128", .{});
        return validationFailure(out, .defaults, .maxretry, .between_one_and_max_retry, null, error.InvalidMaxretry);
    }

    const sock_dir = std.fs.path.dirname(cfg.global.socket_path) orelse "/";
    if (sock_dir.len > 0) {
        std.fs.cwd().access(sock_dir, .{}) catch {
            std.log.warn("config: socket_path parent directory not found (created at startup): {s}", .{sock_dir});
        };
    }

    for (cfg.jails, 0..) |j, i| {
        if (!cfg.global.native_ingestion and (j.timestamp != null or j.timezone_offset_minutes != null or j.timezone != null or j.timezone_ambiguity != null or j.journal_executables.len != 0))
            return validationFailure(out, .global, .native_ingestion, .native_ingestion_required, null, error.NativeIngestionRequired);
        if (j.timezone != null and j.timezone_offset_minutes != null)
            return validationFailure(out, .jail, .timezone, .mutually_exclusive_timezone, j.name, error.InvalidNativeTimezone);
        if (j.timezone_ambiguity != null and j.timezone == null)
            return validationFailure(out, .jail, .timezone_ambiguity, .timezone_required, j.name, error.InvalidNativeTimezone);
        if (j.name.len == 0) return validationFailure(out, .jail, .name, .nonempty_jail_name, j.name, error.EmptyJailName);
        _ = shared.JailId.fromSlice(j.name) catch
            return validationFailure(out, .jail, .name, .valid_jail_name, j.name, error.InvalidJailName);

        var k: usize = i + 1;
        while (k < cfg.jails.len) : (k += 1) {
            if (std.mem.eql(u8, j.name, cfg.jails[k].name)) {
                // The caller renders bounded, escaped context for this failure.
                // Do not write the untrusted jail identifier separately.
                return validationFailure(out, .jail, .name, .unique_jail_name, j.name, error.DuplicateJailName);
            }
        }

        try validateIncrementDiag(resolveJailFromConfig(&j, cfg.defaults).bantime_increment, out, .jail, j.name);
        if (j.enabled and j.compatibility_pending)
            return validationFailure(out, .jail, .compatibility_manifest, .admitted_compatibility, j.name, error.CompatibilityNotAdmitted);
        if (j.enabled and cfg.global.compatibility_pending)
            return validationFailure(out, .global, .compatibility_manifest, .admitted_compatibility, null, error.CompatibilityNotAdmitted);
        if (j.enabled and j.rule_files.len != 0) _ = @import("../core/native_detection_record.zig").Name.init(j.filter) catch
            return validationFailure(out, .jail, .filter, .valid_rule_filter, j.name, error.InvalidNativeRules);
        if (j.enabled and j.rule_files.len == 0 and filter_registry.matcherForFilter(j.filter) == null) {
            // The filter value is not needed to identify the setting or repair.
            return validationFailure(out, .jail, .filter, .builtin_filter, j.name, error.UnknownFilter);
        }
        if ((j.bantime_kind orelse .finite) == .finite) if (j.bantime) |b| if (b == 0 or b > max_ban_duration)
            return validationFailure(out, .jail, .bantime, .valid_ban_duration, j.name, error.InvalidBantime);
        if (j.findtime) |f| if (f == 0)
            return validationFailure(out, .jail, .findtime, .greater_than_zero, j.name, error.InvalidFindtime);
        if (j.maxretry) |m| if (m == 0 or m > max_supported_retry)
            return validationFailure(out, .jail, .maxretry, .between_one_and_max_retry, j.name, error.InvalidMaxretry);

        for (j.logpath) |lp| {
            std.fs.cwd().access(lp, .{}) catch {
                std.log.warn("config: jail '{s}' logpath not found (may appear later): {s}", .{ j.name, lp });
            };
        }

        if (j.enabled) {
            const would_use_journald = switch (j.source) {
                .journald => true,
                .auto => !anyLogpathExists(j.logpath) and filterSupportsJournald(j.filter),
                .file, .internal => false,
            };
            if (would_use_journald and !journalctlPresent()) {
                std.log.warn(
                    "config: jail '{s}' source resolves to journald but journalctl not found at {s}",
                    .{ j.name, journalctl_path },
                );
            }
        }

        if (j.filter.len == 0 and j.enabled) {
            std.log.warn("config: jail '{s}' has no filter declared", .{j.name});
        }
    }
}

fn validationFailure(
    out: *ValidationDiagnostic,
    section: ValidationSection,
    key: ValidationKey,
    constraint: ValidationConstraint,
    jail: ?[]const u8,
    err: ValidationError,
) ValidationError {
    setValidationDiagnostic(out, section, key, constraint, jail);
    return err;
}

fn validateIncrementDiag(
    incr: BanTimeIncrement,
    out: *ValidationDiagnostic,
    section: ValidationSection,
    jail: ?[]const u8,
) ValidationError!void {
    if (!std.math.isFinite(incr.multiplier) or incr.multiplier <= 0)
        return validationFailure(out, section, .bantime_increment_multiplier, .finite_greater_than_zero, jail, error.InvalidIncrement);
    if (!std.math.isFinite(incr.factor) or incr.factor < 0)
        return validationFailure(out, section, .bantime_increment_factor, .finite_nonnegative, jail, error.InvalidIncrement);
    if (incr.max_bantime == 0 or incr.max_bantime > max_ban_duration)
        return validationFailure(out, section, .bantime_increment_max_bantime, .valid_ban_duration, jail, error.InvalidIncrement);
    if (incr.jitter > incr.max_bantime)
        return validationFailure(out, section, .bantime_increment_jitter, .jitter_within_max_bantime, jail, error.InvalidIncrement);
}

const Parser = struct {
    arena: std.mem.Allocator,
    src: []const u8,
    pos: usize,
    line: u32,
    col: u32,

    global: GlobalConfig,
    defaults: JailDefaults,
    jails: std.ArrayList(JailConfig),
    seen_keys: std.StringHashMap(void),
    jail_source_origin: std.ArrayList(SourceOrigin),
    defaults_source_origin: SourceOrigin = .unset,
    legacy_banaction_used: bool = false,

    cur_section: []const u8 = "",
    cur_key: []const u8 = "",
    hint: []const u8 = "",
    section_pos: Pos = .{},
    key_pos: Pos = .{},
    value_pos: Pos = .{},

    const Pos = struct { line: u32 = 1, col: u32 = 1 };
    const SourceOrigin = enum { unset, source, backend };

    const TOP_GLOBAL: []const u8 = "global";
    const TOP_DEFAULTS: []const u8 = "defaults";
    const TOP_JAILS: []const u8 = "jails";
    const MAX_JAILS: usize = 256;

    fn init(arena: std.mem.Allocator, src: []const u8) Parser {
        return .{
            .arena = arena,
            .src = src,
            .pos = 0,
            .line = 1,
            .col = 1,
            .global = .{},
            .defaults = .{},
            .jails = std.ArrayList(JailConfig).init(arena),
            .seen_keys = std.StringHashMap(void).init(arena),
            .jail_source_origin = std.ArrayList(SourceOrigin).init(arena),
        };
    }

    fn here(self: *const Parser) Pos {
        return .{ .line = self.line, .col = self.col };
    }

    fn fillDiag(self: *const Parser, err: Error, out: *Diagnostic) void {
        const pos: Pos = switch (err) {
            error.UnknownSection => self.section_pos,
            error.UnknownKey, error.DuplicateKey, error.TooManyJails => self.key_pos,
            error.InvalidValue,
            error.InvalidInteger,
            error.InvalidFloat,
            error.InvalidBool,
            error.InvalidArray,
            error.UnterminatedString,
            error.InvalidEscape,
            => self.value_pos,
            else => self.here(),
        };
        out.line = pos.line;
        out.col = pos.col;
        out.hint = self.hint;
        out.key_len = Diagnostic.copyName(&out.key_buf, self.cur_key);
        out.section_len = Diagnostic.copyName(&out.section_buf, self.cur_section);
    }

    fn eof(self: *const Parser) bool {
        return self.pos >= self.src.len;
    }

    fn peek(self: *const Parser) u8 {
        return self.src[self.pos];
    }

    fn advance(self: *Parser) void {
        if (self.eof()) return;
        const c = self.src[self.pos];
        self.pos += 1;
        if (c == '\n') {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
    }

    fn skipSpaceTabs(self: *Parser) void {
        while (!self.eof()) {
            const c = self.peek();
            if (c == ' ' or c == '\t') self.advance() else break;
        }
    }

    fn skipTrailing(self: *Parser) void {
        self.skipSpaceTabs();
        if (!self.eof() and self.peek() == '#') {
            while (!self.eof() and self.peek() != '\n') self.advance();
        }
    }

    fn expectEndOfLine(self: *Parser) Error!void {
        self.skipTrailing();
        if (self.eof()) return;
        if (self.peek() != '\n') return error.UnexpectedToken;
        self.advance();
    }

    fn skipBlankAndComments(self: *Parser) void {
        while (!self.eof()) {
            const c = self.peek();
            switch (c) {
                ' ', '\t', '\n', '\r' => self.advance(),
                '#' => while (!self.eof() and self.peek() != '\n') self.advance(),
                else => break,
            }
        }
    }

    fn parseConfig(self: *Parser, out: *Diagnostic) Error!Config {
        return self.parseBody() catch |err| {
            self.fillDiag(err, out);
            return err;
        };
    }

    fn parseBody(self: *Parser) Error!Config {
        while (true) {
            self.skipBlankAndComments();
            if (self.eof()) break;

            if (self.peek() == '[') {
                self.cur_section = "";
                self.cur_key = "";
                self.section_pos = self.here();
                self.cur_section = try self.parseSectionHeader();
                try self.expectEndOfLine();
                continue;
            }

            self.key_pos = self.here();
            self.cur_key = try self.parseBareKey();
            try self.noteKeySeen(self.cur_section, self.cur_key);
            self.skipSpaceTabs();
            if (self.eof() or self.peek() != '=') return error.UnexpectedToken;
            self.advance();
            self.skipSpaceTabs();
            self.value_pos = self.here();

            try self.dispatchKeyValue(self.cur_section, self.cur_key);
            try self.expectEndOfLine();
        }

        for (self.jails.items, self.jail_source_origin.items) |*j, origin| {
            if (origin == .unset) j.source = self.defaults.source;
        }

        return .{
            .global = self.global,
            .defaults = self.defaults,
            .jails = try self.jails.toOwnedSlice(),
            .diag = .{ .line = self.line, .col = self.col },
            .legacy_banaction_used = self.legacy_banaction_used,
        };
    }

    fn noteKeySeen(self: *Parser, section: []const u8, key: []const u8) Error!void {
        const composite = try std.fmt.allocPrint(self.arena, "{s}\x00{s}", .{ section, key });
        const gop = self.seen_keys.getOrPut(composite) catch return error.OutOfMemory;
        if (gop.found_existing) return error.DuplicateKey;
    }

    fn policySpelling(self: *Parser, key: []const u8) Error!void {
        const alias = if (std.mem.eql(u8, key, "enforce")) "banaction" else "enforce";
        const composite = try std.fmt.allocPrint(self.arena, "{s}\x00{s}", .{ self.cur_section, alias });
        if (self.seen_keys.contains(composite)) {
            self.hint = "enforce and banaction conflict in the same section; global.firewall selects the backend";
            return error.InvalidValue;
        }
        if (std.mem.eql(u8, key, "banaction")) self.legacy_banaction_used = true;
    }

    fn parseSectionHeader(self: *Parser) Error![]const u8 {
        if (self.peek() != '[') return error.UnexpectedToken;
        self.advance();
        const start = self.pos;
        while (!self.eof() and self.peek() != ']' and self.peek() != '\n') self.advance();
        if (self.eof() or self.peek() != ']') return error.UnexpectedToken;
        const name = self.src[start..self.pos];
        self.advance();
        const trimmed = std.mem.trim(u8, name, " \t");
        if (trimmed.len == 0) return error.UnexpectedToken;
        return trimmed;
    }

    fn parseBareKey(self: *Parser) Error![]const u8 {
        const start = self.pos;
        while (!self.eof()) {
            const c = self.peek();
            switch (c) {
                'a'...'z', 'A'...'Z', '0'...'9', '_', '-' => self.advance(),
                else => break,
            }
        }
        if (self.pos == start) return error.UnexpectedToken;
        return self.src[start..self.pos];
    }

    const Value = union(enum) {
        string: []const u8,
        int: i64,
        float: f64,
        boolean: bool,
        str_array: []const []const u8,
    };

    fn parseValue(self: *Parser) Error!Value {
        if (self.eof()) return error.UnexpectedToken;
        const c = self.peek();
        switch (c) {
            '"' => return .{ .string = try self.parseString() },
            '[' => return .{ .str_array = try self.parseStringArray() },
            't', 'f' => return .{ .boolean = try self.parseBool() },
            '-', '0'...'9' => return self.parseNumber(),
            else => return error.UnexpectedToken,
        }
    }

    fn parseString(self: *Parser) Error![]const u8 {
        if (self.peek() != '"') return error.UnexpectedToken;
        self.advance();
        const start = self.pos;
        var has_escape = false;
        while (true) {
            if (self.eof()) return error.UnterminatedString;
            const c = self.peek();
            if (c == '\n') return error.UnterminatedString;
            if (c == '\\') {
                has_escape = true;
                self.advance();
                if (self.eof()) return error.InvalidEscape;
                const esc = self.peek();
                if (esc != '"' and esc != '\\' and esc != 'n' and esc != 't') {
                    return error.InvalidEscape;
                }
                self.advance();
                continue;
            }
            if (c == '"') break;
            self.advance();
        }
        const end = self.pos;
        self.advance();

        if (!has_escape) return self.src[start..end];

        var buf = std.ArrayList(u8).init(self.arena);
        errdefer buf.deinit();
        var i: usize = start;
        while (i < end) : (i += 1) {
            const c = self.src[i];
            if (c == '\\' and i + 1 < end) {
                const esc = self.src[i + 1];
                const out: u8 = switch (esc) {
                    '"' => '"',
                    '\\' => '\\',
                    'n' => '\n',
                    't' => '\t',
                    else => return error.InvalidEscape,
                };
                try buf.append(out);
                i += 1;
                continue;
            }
            try buf.append(c);
        }
        return try buf.toOwnedSlice();
    }

    fn parseBool(self: *Parser) Error!bool {
        const rest = self.src[self.pos..];
        if (std.mem.startsWith(u8, rest, "true")) {
            for (0..4) |_| self.advance();
            return true;
        }
        if (std.mem.startsWith(u8, rest, "false")) {
            for (0..5) |_| self.advance();
            return false;
        }
        return error.InvalidBool;
    }

    fn parseInt(self: *Parser) Error!i64 {
        const start = self.pos;
        if (self.peek() == '-') self.advance();
        const digit_start = self.pos;
        while (!self.eof()) {
            const c = self.peek();
            if (c < '0' or c > '9') break;
            self.advance();
        }
        if (self.pos == digit_start) return error.InvalidInteger;
        const slice = self.src[start..self.pos];
        return std.fmt.parseInt(i64, slice, 10) catch return error.InvalidInteger;
    }

    fn parseNumber(self: *Parser) Error!Value {
        const start = self.pos;
        if (self.peek() == '-') self.advance();
        const digit_start = self.pos;
        while (!self.eof()) {
            const c = self.peek();
            if (c < '0' or c > '9') break;
            self.advance();
        }
        if (self.pos == digit_start) return error.InvalidInteger;
        if (self.eof() or self.peek() != '.') {
            const slice = self.src[start..self.pos];
            const n = std.fmt.parseInt(i64, slice, 10) catch return error.InvalidInteger;
            return .{ .int = n };
        }
        self.advance();
        const frac_start = self.pos;
        while (!self.eof()) {
            const c = self.peek();
            if (c < '0' or c > '9') break;
            self.advance();
        }
        if (self.pos == frac_start) return error.InvalidFloat;
        const slice = self.src[start..self.pos];
        const f = std.fmt.parseFloat(f64, slice) catch return error.InvalidFloat;
        return .{ .float = f };
    }

    fn parseStringArray(self: *Parser) Error![]const []const u8 {
        if (self.peek() != '[') return error.UnexpectedToken;
        self.advance();

        var items = std.ArrayList([]const u8).init(self.arena);
        errdefer items.deinit();

        while (true) {
            self.skipWhitespaceAcrossLines();
            if (self.eof()) return error.InvalidArray;
            if (self.peek() == ']') {
                self.advance();
                return try items.toOwnedSlice();
            }
            if (self.peek() != '"') return error.InvalidArray;
            const s = try self.parseString();
            try items.append(s);
            self.skipWhitespaceAcrossLines();
            if (self.eof()) return error.InvalidArray;
            const c = self.peek();
            if (c == ',') {
                self.advance();
                continue;
            }
            if (c == ']') {
                self.advance();
                return try items.toOwnedSlice();
            }
            return error.InvalidArray;
        }
    }

    fn skipWhitespaceAcrossLines(self: *Parser) void {
        while (!self.eof()) {
            const c = self.peek();
            switch (c) {
                ' ', '\t', '\n', '\r' => self.advance(),
                '#' => while (!self.eof() and self.peek() != '\n') self.advance(),
                else => break,
            }
        }
    }

    fn dispatchKeyValue(self: *Parser, section: []const u8, key: []const u8) Error!void {
        if (section.len == 0) return error.UnexpectedToken;
        if (std.mem.eql(u8, section, TOP_GLOBAL)) {
            return self.applyGlobalKey(key);
        }
        if (std.mem.eql(u8, section, TOP_DEFAULTS)) {
            return self.applyDefaultsKey(key);
        }
        if (std.mem.startsWith(u8, section, "jails.")) {
            const jail_name = section[6..];
            return self.applyJailKey(jail_name, key);
        }
        if (std.mem.startsWith(u8, section, "jails.") or std.mem.eql(u8, section, TOP_JAILS)) {
            return error.UnknownSection;
        }
        return error.UnknownSection;
    }

    fn applyGlobalKey(self: *Parser, key: []const u8) Error!void {
        const v = try self.parseValue();
        if (std.mem.eql(u8, key, "firewall_namespace")) {
            const path = try asString(v);
            if (!std.fs.path.isAbsolute(path) or path.len > 256 or std.mem.indexOfScalar(u8, path, 0) != null or
                std.mem.indexOf(u8, path, "/self/") != null or std.mem.indexOf(u8, path, "/thread-self/") != null) return error.InvalidValue;
            self.global.firewall_namespace = path;
        } else if (std.mem.eql(u8, key, "timezone_root")) {
            const path = try asString(v);
            if (!std.fs.path.isAbsolute(path) or path.len > 4096 or std.mem.indexOfScalar(u8, path, 0) != null) return error.InvalidValue;
            self.global.timezone_root = path;
        } else if (std.mem.eql(u8, key, "native_ingestion")) {
            self.global.native_ingestion = try asBool(v);
        } else if (std.mem.eql(u8, key, "compatibility_manifest")) {
            const manifest = try asString(v);
            _ = try decodeCompatibilityManifest(self.arena, manifest);
            self.global.compatibility_manifest = manifest;
        } else if (std.mem.eql(u8, key, "compatibility_pending")) {
            self.global.compatibility_pending = try asBool(v);
        } else if (std.mem.eql(u8, key, "log_level")) {
            const s = try asString(v);
            self.global.log_level = try parseLogLevel(s);
        } else if (std.mem.eql(u8, key, "log_target")) {
            const s = try asString(v);
            if (!std.mem.eql(u8, s, "stderr") and (!std.fs.path.isAbsolute(s) or s.len >= std.fs.max_path_bytes or std.mem.indexOfScalar(u8, s, 0) != null)) return error.InvalidValue;
            self.global.log_target = s;
        } else if (std.mem.eql(u8, key, "pid_file")) {
            self.global.pid_file = try asString(v);
            std.log.warn("config: pid_file is a deprecated compatibility key and is not written; use systemd MainPID", .{});
        } else if (std.mem.eql(u8, key, "socket_path")) {
            self.global.socket_path = try asString(v);
        } else if (std.mem.eql(u8, key, "state_file")) {
            self.global.state_file = try asString(v);
        } else if (std.mem.eql(u8, key, "memory_ceiling_mb")) {
            const n = try asInt(v);
            if (n < 0 or n > std.math.maxInt(u32)) return error.InvalidValue;
            self.global.memory_ceiling_mb = @intCast(n);
        } else if (std.mem.eql(u8, key, "native_memory_ceiling_mb")) {
            const n = try asInt(v);
            if (n <= 0 or n > std.math.maxInt(u32)) return error.InvalidValue;
            self.global.native_memory_ceiling_mb = @intCast(n);
        } else if (std.mem.eql(u8, key, "native_fd_ceiling")) {
            const n = try asInt(v);
            if (n <= 0 or n > std.math.maxInt(u32)) return error.InvalidValue;
            self.global.native_fd_ceiling = @intCast(n);
        } else if (std.mem.eql(u8, key, "metrics_enabled")) {
            self.global.metrics_enabled = try asBool(v);
        } else if (std.mem.eql(u8, key, "metrics_bind")) {
            self.global.metrics_bind = try asString(v);
        } else if (std.mem.eql(u8, key, "metrics_port")) {
            const n = try asInt(v);
            if (n == 0) {
                self.hint = metrics_port_zero_hint;
                return error.InvalidValue;
            }
            if (n < 0 or n > 65535) return error.InvalidValue;
            self.global.metrics_port = @intCast(n);
        } else if (std.mem.eql(u8, key, "websocket_max_clients")) {
            const n = try asInt(v);
            if (n <= 0 or n > websocket_hard_max_clients) return error.InvalidValue;
            self.global.websocket_max_clients = @intCast(n);
        } else if (std.mem.eql(u8, key, "history_retention")) {
            const n = try asInt(v);
            if (n < 0 or n > @divTrunc(std.math.maxInt(i64), 1_000_000)) return error.InvalidValue;
            self.global.history_retention = @intCast(n);
        } else if (std.mem.eql(u8, key, "history_max_matches")) {
            const n = try asInt(v);
            if (n < 0 or n > 1024) return error.InvalidValue;
            self.global.history_max_matches = @intCast(n);
        } else if (std.mem.eql(u8, key, "on_no_backend")) {
            const s = try asString(v);
            self.global.on_no_backend = try parseOnNoBackend(s);
        } else if (std.mem.eql(u8, key, "firewall")) {
            const s = try asString(v);
            self.global.firewall = try parseFirewallSelection(s);
        } else if (std.mem.eql(u8, key, "dns_server")) {
            self.global.dns_server = try asString(v);
        } else if (std.mem.eql(u8, key, "dns_port")) {
            const n = try asInt(v);
            if (n <= 0 or n > 65535) return error.InvalidValue;
            self.global.dns_port = @intCast(n);
        } else return error.UnknownKey;
    }

    fn applyDefaultsKey(self: *Parser, key: []const u8) Error!void {
        const v = try self.parseValue();
        if (std.mem.eql(u8, key, "bantime")) {
            if (v == .string and std.mem.eql(u8, v.string, "permanent")) {
                self.defaults.bantime_kind = .permanent;
            } else {
                self.defaults.bantime = try asDuration(v, max_ban_duration);
                self.defaults.bantime_kind = .finite;
            }
        } else if (std.mem.eql(u8, key, "findtime")) {
            self.defaults.findtime = try asDuration(v, std.math.maxInt(i64));
        } else if (std.mem.eql(u8, key, "maxretry")) {
            const n = try asInt(v);
            if (n < 0 or n > max_supported_retry) {
                self.hint = "maxretry must be between 1 and 128 (bounded attempt history)";
                return error.InvalidValue;
            }
            self.defaults.maxretry = @intCast(n);
        } else if (std.mem.eql(u8, key, "enforce")) {
            try self.policySpelling(key);
            self.defaults.banaction = if (try asBool(v)) .nftables else .@"log-only";
        } else if (std.mem.eql(u8, key, "banaction")) {
            try self.policySpelling(key);
            const s = try asString(v);
            self.defaults.banaction = try parseBanAction(s);
        } else if (std.mem.eql(u8, key, "ignoreip")) {
            self.defaults.ignoreip = try asStringArray(v);
        } else if (std.mem.eql(u8, key, "source")) {
            if (self.defaults_source_origin == .backend) return error.InvalidValue;
            self.defaults.source = try parseLogSource(try asString(v));
            self.defaults_source_origin = .source;
        } else if (std.mem.eql(u8, key, "backend")) {
            if (self.defaults_source_origin == .source) return error.InvalidValue;
            self.defaults.source = try backendAlias(self.cur_section, try asString(v));
            self.defaults_source_origin = .backend;
        } else if (std.mem.eql(u8, key, "bantime_increment_enabled")) {
            self.defaults.bantime_increment.enabled = try asBool(v);
        } else if (std.mem.eql(u8, key, "bantime_increment_multiplier")) {
            self.defaults.bantime_increment.multiplier = try asFloat(v);
        } else if (std.mem.eql(u8, key, "bantime_increment_factor")) {
            self.defaults.bantime_increment.factor = try asFloat(v);
        } else if (std.mem.eql(u8, key, "bantime_increment_formula")) {
            const s = try asString(v);
            if (std.mem.eql(u8, s, "linear")) {
                self.defaults.bantime_increment.formula = .linear;
            } else if (std.mem.eql(u8, s, "exponential")) {
                self.defaults.bantime_increment.formula = .exponential;
            } else return error.InvalidValue;
        } else if (std.mem.eql(u8, key, "bantime_increment_scope")) {
            const s = try asString(v);
            if (std.mem.eql(u8, s, "per-jail")) {
                self.defaults.bantime_increment.scope = .per_jail;
            } else if (std.mem.eql(u8, s, "overall")) {
                self.defaults.bantime_increment.scope = .overall;
            } else return error.InvalidValue;
        } else if (std.mem.eql(u8, key, "bantime_increment_max_bantime")) {
            self.defaults.bantime_increment.max_bantime = try asDuration(v, max_ban_duration);
        } else if (std.mem.eql(u8, key, "bantime_increment_jitter")) {
            self.defaults.bantime_increment.jitter = try asDuration(v, max_ban_duration);
        } else return error.UnknownKey;
    }

    fn applyJailKey(self: *Parser, jail_name: []const u8, key: []const u8) Error!void {
        const v = try self.parseValue();
        const idx = try self.findOrCreateJail(jail_name);
        const j = &self.jails.items[idx];
        const origin = &self.jail_source_origin.items[idx];

        if (std.mem.eql(u8, key, "timestamp")) {
            j.timestamp = std.meta.stringToEnum(@typeInfo(@TypeOf(j.timestamp)).optional.child, try asString(v)) orelse return error.InvalidValue;
        } else if (std.mem.eql(u8, key, "timezone_offset_minutes")) {
            const n = try asInt(v);
            if (n < -1439 or n > 1439) return error.InvalidValue;
            j.timezone_offset_minutes = @intCast(n);
        } else if (std.mem.eql(u8, key, "timezone")) {
            const identifier = try asString(v);
            @import("../core/native_timezone.zig").validateIdentifier(identifier) catch return error.InvalidValue;
            j.timezone = identifier;
        } else if (std.mem.eql(u8, key, "timezone_ambiguity")) {
            j.timezone_ambiguity = std.meta.stringToEnum(@import("../core/native_timezone.zig").Ambiguity, try asString(v)) orelse return error.InvalidValue;
        } else if (std.mem.eql(u8, key, "journal_executables")) {
            j.journal_executables = try asStringArray(v);
            j.journal_executables_explicit = true;
        } else if (std.mem.eql(u8, key, "rule_files")) {
            j.rule_files = try asStringArray(v);
        } else if (std.mem.eql(u8, key, "ignore_file")) {
            j.ignore_file = try asString(v);
        } else if (std.mem.eql(u8, key, "compatibility_pending")) {
            j.compatibility_pending = try asBool(v);
        } else if (std.mem.eql(u8, key, "enabled")) {
            j.enabled = try asBool(v);
        } else if (std.mem.eql(u8, key, "filter")) {
            j.filter = try asString(v);
        } else if (std.mem.eql(u8, key, "logpath")) {
            j.logpath = try asStringArray(v);
        } else if (std.mem.eql(u8, key, "source")) {
            if (origin.* == .backend) return error.InvalidValue;
            j.source = try parseLogSource(try asString(v));
            origin.* = .source;
        } else if (std.mem.eql(u8, key, "backend")) {
            if (origin.* == .source) return error.InvalidValue;
            j.source = try backendAlias(self.cur_section, try asString(v));
            origin.* = .backend;
        } else if (std.mem.eql(u8, key, "maxretry")) {
            const n = try asInt(v);
            if (n < 0 or n > max_supported_retry) {
                self.hint = "maxretry must be between 1 and 128 (bounded attempt history)";
                return error.InvalidValue;
            }
            j.maxretry = @intCast(n);
        } else if (std.mem.eql(u8, key, "findtime")) {
            j.findtime = try asDuration(v, std.math.maxInt(i64));
        } else if (std.mem.eql(u8, key, "bantime")) {
            if (v == .string and std.mem.eql(u8, v.string, "permanent")) {
                j.bantime = null;
                j.bantime_kind = .permanent;
            } else {
                j.bantime = try asDuration(v, max_ban_duration);
                j.bantime_kind = .finite;
            }
        } else if (std.mem.eql(u8, key, "enforce")) {
            try self.policySpelling(key);
            j.banaction = if (try asBool(v)) .nftables else .@"log-only";
        } else if (std.mem.eql(u8, key, "banaction")) {
            try self.policySpelling(key);
            const s = try asString(v);
            j.banaction = try parseBanAction(s);
        } else if (std.mem.eql(u8, key, "ignoreip")) {
            j.ignoreip = try asStringArray(v);
        } else if (std.mem.eql(u8, key, "bantime_increment_enabled")) {
            j.bantime_increment.enabled = try asBool(v);
            j.bantime_increment_explicit = true;
            j.bantime_increment_fields |= 1;
        } else if (std.mem.eql(u8, key, "bantime_increment_multiplier")) {
            j.bantime_increment.multiplier = try asFloat(v);
            j.bantime_increment_explicit = true;
            j.bantime_increment_fields |= 2;
        } else if (std.mem.eql(u8, key, "bantime_increment_factor")) {
            j.bantime_increment.factor = try asFloat(v);
            j.bantime_increment_explicit = true;
            j.bantime_increment_fields |= 4;
        } else if (std.mem.eql(u8, key, "bantime_increment_formula")) {
            const s = try asString(v);
            if (std.mem.eql(u8, s, "linear")) {
                j.bantime_increment.formula = .linear;
            } else if (std.mem.eql(u8, s, "exponential")) {
                j.bantime_increment.formula = .exponential;
            } else return error.InvalidValue;
            j.bantime_increment_explicit = true;
            j.bantime_increment_fields |= 8;
        } else if (std.mem.eql(u8, key, "bantime_increment_scope")) {
            const s = try asString(v);
            if (std.mem.eql(u8, s, "per-jail")) {
                j.bantime_increment.scope = .per_jail;
            } else if (std.mem.eql(u8, s, "overall")) {
                j.bantime_increment.scope = .overall;
            } else return error.InvalidValue;
            j.bantime_increment_explicit = true;
            j.bantime_increment_fields |= 32;
        } else if (std.mem.eql(u8, key, "bantime_increment_max_bantime")) {
            j.bantime_increment.max_bantime = try asDuration(v, max_ban_duration);
            j.bantime_increment_explicit = true;
            j.bantime_increment_fields |= 16;
        } else if (std.mem.eql(u8, key, "bantime_increment_jitter")) {
            j.bantime_increment.jitter = try asDuration(v, max_ban_duration);
            j.bantime_increment_explicit = true;
            j.bantime_increment_fields |= 64;
        } else return error.UnknownKey;
    }

    fn findOrCreateJail(self: *Parser, name: []const u8) Error!usize {
        for (self.jails.items, 0..) |existing, i| {
            if (std.mem.eql(u8, existing.name, name)) return i;
        }
        if (self.jails.items.len >= MAX_JAILS) return error.TooManyJails;
        try self.jails.append(.{ .name = name });
        errdefer _ = self.jails.pop();
        try self.jail_source_origin.append(.unset);
        return self.jails.items.len - 1;
    }
};

fn backendAlias(section: []const u8, s: []const u8) Error!LogSource {
    const mapped = mapBackendAlias(s) orelse return error.InvalidValue;
    std.log.warn(
        "config: [{s}] 'backend' is a deprecated fail2ban compatibility alias; use source = \"{s}\"",
        .{ section, @tagName(mapped) },
    );
    return mapped;
}

pub fn mapBackendAlias(s: []const u8) ?LogSource {
    if (std.mem.eql(u8, s, "systemd")) return .journald;
    const auto_names = [_][]const u8{ "auto", "polling", "pyinotify", "gamin" };
    for (auto_names) |n| if (std.mem.eql(u8, s, n)) return .auto;
    return null;
}

fn asString(v: Parser.Value) Error![]const u8 {
    return switch (v) {
        .string => |s| s,
        else => error.InvalidValue,
    };
}

fn asInt(v: Parser.Value) Error!i64 {
    return switch (v) {
        .int => |n| n,
        else => error.InvalidValue,
    };
}

fn asDuration(v: Parser.Value, maximum: u64) Error!shared.Duration {
    const seconds: u64 = switch (v) {
        .int => |n| if (n >= 0) @intCast(n) else return error.InvalidValue,
        .string => |s| try native_duration.parse(s),
        else => return error.InvalidValue,
    };
    if (seconds > maximum) return error.InvalidValue;
    return seconds;
}

fn asFloat(v: Parser.Value) Error!f64 {
    return switch (v) {
        .int => |n| @floatFromInt(n),
        .float => |f| f,
        else => error.InvalidValue,
    };
}

fn asBool(v: Parser.Value) Error!bool {
    return switch (v) {
        .boolean => |b| b,
        else => error.InvalidValue,
    };
}

fn asStringArray(v: Parser.Value) Error![]const []const u8 {
    return switch (v) {
        .str_array => |a| a,
        else => error.InvalidValue,
    };
}

fn parseLogLevel(s: []const u8) Error!LogLevel {
    if (std.mem.eql(u8, s, "debug")) return .debug;
    if (std.mem.eql(u8, s, "info")) return .info;
    if (std.mem.eql(u8, s, "warn")) return .warn;
    if (std.mem.eql(u8, s, "err")) return .err;
    return error.InvalidValue;
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

fn parseBanAction(s: []const u8) Error!BanAction {
    if (std.mem.eql(u8, s, "nftables")) return .nftables;
    if (std.mem.eql(u8, s, "iptables")) return .iptables;
    if (std.mem.eql(u8, s, "ipset")) return .ipset;
    if (std.mem.eql(u8, s, "log-only")) return .@"log-only";
    return error.InvalidValue;
}

pub const metrics_port_zero_hint: []const u8 = "metrics_port = 0 does not disable the endpoint; set metrics_enabled = false";

fn parseFirewallSelection(s: []const u8) Error!FirewallSelection {
    if (std.mem.eql(u8, s, "auto")) return .auto;
    if (std.mem.eql(u8, s, "nftables")) return .nftables;
    if (std.mem.eql(u8, s, "ipset")) return .ipset;
    if (std.mem.eql(u8, s, "iptables")) return .iptables;
    return error.InvalidValue;
}

fn parseOnNoBackend(s: []const u8) Error!OnNoBackend {
    if (std.mem.eql(u8, s, "fail-closed")) return .@"fail-closed";
    if (std.mem.eql(u8, s, "log-only")) return .@"log-only";
    return error.InvalidValue;
}

fn parseLogSource(s: []const u8) Error!LogSource {
    if (std.mem.eql(u8, s, "auto")) return .auto;
    if (std.mem.eql(u8, s, "file")) return .file;
    if (std.mem.eql(u8, s, "journald")) return .journald;
    if (std.mem.eql(u8, s, "internal")) return .internal;
    return error.InvalidValue;
}

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

pub fn decodeCompatibilityManifest(arena: std.mem.Allocator, manifest: []const u8) Error!std.json.Value {
    if (manifest.len > max_config_bytes) return error.FileTooLarge;
    const value = std.json.parseFromSliceLeaky(std.json.Value, arena, manifest, .{ .allocate = .alloc_always }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidValue,
    };
    if (value != .object) return error.InvalidValue;
    const version = value.object.get("schema_version") orelse return error.InvalidValue;
    if (version != .integer or version.integer != 1) return error.InvalidValue;
    const admission = value.object.get("admission") orelse return error.InvalidValue;
    if (admission != .string or !std.mem.eql(u8, admission.string, "prepared")) return error.InvalidValue;
    return value;
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

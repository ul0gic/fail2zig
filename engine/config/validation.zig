// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Validates a parsed configuration and renders the first failed check as a bounded diagnostic.
// Holds: Every validation failure records its section, key and constraint in the diagnostic before its error is returned.

const std = @import("std");
const shared = @import("shared");
const filter_registry = @import("../filters/registry.zig");
const native_banip = @import("banip.zig");
const Config = @import("config.zig").Config;
const BanTimeIncrement = @import("config.zig").BanTimeIncrement;
const max_ban_duration = @import("config.zig").max_ban_duration;
const max_supported_retry = @import("config.zig").max_supported_retry;
const resolveJailFromConfig = @import("config.zig").resolveJailFromConfig;
const resolvedIgnoretime = @import("config.zig").resolvedIgnoretime;
const anyLogpathExists = @import("config.zig").anyLogpathExists;
const filterSupportsJournald = @import("config.zig").filterSupportsJournald;
const journalctlPresent = @import("config.zig").journalctlPresent;
const journalctl_path = @import("config.zig").journalctl_path;

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
    InvalidIgnoretime,
    InvalidBanip,
    InvalidEntryDuration,
    BanListConflict,
    BanListLimit,
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
    banip,
    ignoreip,
    ignoretime,
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
    ignoretime_invalid,
    ignoretime_rule_files,
    banip_invalid,
    entry_duration_invalid,
    entry_duration_rule_files,
    banip_conflict,
    banip_limit,
};

pub const ValidationDiagnostic = struct {
    section: ValidationSection = .none,
    key: ValidationKey = .none,
    constraint: ValidationConstraint = .none,
    jail_len: u8 = 0,
    jail_truncated: bool = false,
    jail_buf: [max_jail_bytes]u8 = [_]u8{0} ** max_jail_bytes,
    entry_len: u16 = 0,
    entry_truncated: bool = false,
    entry_buf: [max_entry_bytes]u8 = [_]u8{0} ** max_entry_bytes,

    pub const max_jail_bytes: usize = shared.JailId.max_len;
    pub const max_entry_bytes: usize = 256;

    pub fn entry(self: *const ValidationDiagnostic) []const u8 {
        return self.entry_buf[0..self.entry_len];
    }

    pub fn jail(self: *const ValidationDiagnostic) []const u8 {
        return self.jail_buf[0..self.jail_len];
    }

    pub fn render(self: *const ValidationDiagnostic, out: []u8) []const u8 {
        var rendered = ValidationRenderBuffer{ .out = out };
        switch (self.constraint) {
            .ignoretime_invalid, .ignoretime_rule_files, .banip_invalid, .entry_duration_invalid, .entry_duration_rule_files, .banip_conflict, .banip_limit => {
                self.renderEntry(&rendered);
                return rendered.slice();
            },
            else => {},
        }
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

    fn renderEntry(self: *const ValidationDiagnostic, rendered: *ValidationRenderBuffer) void {
        if (self.section == .jail) {
            rendered.appendLiteral("jails.");
            for (self.jail()) |byte| rendered.appendEscapedByte(byte);
            if (self.jail_truncated) rendered.appendLiteral("...");
            rendered.appendLiteral(".");
        }
        rendered.appendLiteral(validationKeyName(self.key));
        rendered.appendLiteral(": ");
        if (self.constraint == .banip_conflict) {
            for (self.entry()) |byte| rendered.appendEscapedByte(byte);
            rendered.appendLiteral(" ");
            rendered.appendLiteral(validationConstraintText(self.constraint));
            return;
        }
        if (self.constraint == .entry_duration_rule_files) {
            self.renderQuotedEntry(rendered);
            rendered.appendLiteral(": ");
            rendered.appendLiteral(validationConstraintText(self.constraint));
            return;
        }
        rendered.appendLiteral(validationConstraintText(self.constraint));
        if (self.constraint == .banip_invalid or self.constraint == .entry_duration_invalid) {
            rendered.appendLiteral(" ");
            self.renderQuotedEntry(rendered);
        }
    }

    fn renderQuotedEntry(self: *const ValidationDiagnostic, rendered: *ValidationRenderBuffer) void {
        rendered.appendLiteral("'");
        for (self.entry()) |byte| rendered.appendEscapedByte(byte);
        if (self.entry_truncated) rendered.appendLiteral("...");
        rendered.appendLiteral("'");
    }

    fn setEntry(self: *ValidationDiagnostic, text: []const u8) void {
        const len = @min(text.len, max_entry_bytes);
        @memcpy(self.entry_buf[0..len], text[0..len]);
        self.entry_len = @intCast(len);
        self.entry_truncated = text.len > len;
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
        .ignoretime_invalid => "invalid duration",
        .ignoretime_rule_files => "a default ignore duration is not supported with rule_files",
        .banip_invalid => "invalid entry",
        .entry_duration_invalid => "invalid duration in",
        .entry_duration_rule_files => "a duration is not supported with rule_files",
        .banip_conflict => "is also in ignoreip",
        .banip_limit => std.fmt.comptimePrint("more than {d} entries", .{native_banip.max_banip_entries}),
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
    // Why: sockaddr_un.sun_path holds 108 bytes including the terminating NUL (unix(7)).
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
    if (cfg.defaults.ignoretime) |seconds| if (seconds > shared.types.TimedEntry.max_duration_s)
        return validationFailure(out, .defaults, .ignoretime, .ignoretime_invalid, null, error.InvalidIgnoretime);
    try validateEntryLists(out, .defaults, null, cfg.defaults.banip, cfg.defaults.ignoreip);

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
                // Why: A quoted jail name may hold control bytes, so this failure carries it only in the diagnostic, which escapes it.
                return validationFailure(out, .jail, .name, .unique_jail_name, j.name, error.DuplicateJailName);
            }
        }

        try validateIncrementDiag(resolveJailFromConfig(&j, cfg.defaults).bantime_increment, out, .jail, j.name);
        if (j.enabled and j.compatibility_pending)
            return validationFailure(out, .jail, .compatibility_manifest, .admitted_compatibility, j.name, error.CompatibilityNotAdmitted);
        if (j.enabled and cfg.global.compatibility_pending)
            return validationFailure(out, .global, .compatibility_manifest, .admitted_compatibility, null, error.CompatibilityNotAdmitted);
        if (j.enabled and j.rule_files.len != 0) _ = @import("../detect/detection_record.zig").Name.init(j.filter) catch
            return validationFailure(out, .jail, .filter, .valid_rule_filter, j.name, error.InvalidNativeRules);
        if (j.enabled and j.rule_files.len == 0 and filter_registry.matcherForFilter(j.filter) == null) {
            return validationFailure(out, .jail, .filter, .builtin_filter, j.name, error.UnknownFilter);
        }
        if ((j.bantime_kind orelse .finite) == .finite) if (j.bantime) |b| if (b == 0 or b > max_ban_duration)
            return validationFailure(out, .jail, .bantime, .valid_ban_duration, j.name, error.InvalidBantime);
        if (j.findtime) |f| if (f == 0)
            return validationFailure(out, .jail, .findtime, .greater_than_zero, j.name, error.InvalidFindtime);
        if (j.maxretry) |m| if (m == 0 or m > max_supported_retry)
            return validationFailure(out, .jail, .maxretry, .between_one_and_max_retry, j.name, error.InvalidMaxretry);
        if (j.ignoretime) |seconds| if (seconds > shared.types.TimedEntry.max_duration_s)
            return validationFailure(out, .jail, .ignoretime, .ignoretime_invalid, j.name, error.InvalidIgnoretime);
        try validateEntryLists(out, .jail, j.name, j.banip orelse &.{}, j.ignoreip orelse &.{});
        if (j.rule_files.len != 0) {
            if (resolvedIgnoretime(&j, cfg.defaults) != null)
                return validationFailure(out, .jail, .ignoretime, .ignoretime_rule_files, j.name, error.InvalidIgnoretime);
            for (j.ignoreip orelse cfg.defaults.ignoreip) |literal| if (std.mem.indexOfAny(u8, literal, &std.ascii.whitespace) != null)
                return entryFailure(out, .jail, .ignoreip, .entry_duration_rule_files, j.name, literal, error.InvalidEntryDuration);
        }
        if ((j.banip orelse cfg.defaults.banip).len > native_banip.max_banip_entries)
            return validationFailure(out, .jail, .banip, .banip_limit, j.name, error.BanListLimit);

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
    var conflict: native_banip.BanListConflict = undefined;
    if (native_banip.findConflict(cfg, &conflict))
        return entryFailure(out, .jail, .banip, .banip_conflict, conflict.jail, conflict.address[0..conflict.address_len], error.BanListConflict);
}

fn validateEntryLists(
    out: *ValidationDiagnostic,
    section: ValidationSection,
    jail: ?[]const u8,
    banip: []const []const u8,
    ignoreip: []const []const u8,
) ValidationError!void {
    for (banip) |literal| {
        if (std.mem.indexOfAny(u8, literal, &std.ascii.whitespace) != null) {
            _ = shared.types.TimedEntry.parse(literal, null) catch
                return entryFailure(out, section, .banip, .entry_duration_invalid, jail, literal, error.InvalidEntryDuration);
        } else {
            _ = shared.types.IgnoreEntry.parse(literal) catch
                return entryFailure(out, section, .banip, .banip_invalid, jail, literal, error.InvalidBanip);
        }
    }
    for (ignoreip) |literal| if (std.mem.indexOfAny(u8, literal, &std.ascii.whitespace) != null) {
        _ = shared.types.TimedEntry.parse(literal, null) catch
            return entryFailure(out, section, .ignoreip, .entry_duration_invalid, jail, literal, error.InvalidEntryDuration);
    };
}

fn entryFailure(
    out: *ValidationDiagnostic,
    section: ValidationSection,
    key: ValidationKey,
    constraint: ValidationConstraint,
    jail: ?[]const u8,
    literal: []const u8,
    err: ValidationError,
) ValidationError {
    out.setEntry(literal);
    return validationFailure(out, section, key, constraint, jail, err);
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

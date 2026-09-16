// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const fail2ban = @import("fail2ban.zig");
const native = @import("native.zig");
pub const source_plan = @import("source_plan.zig");
const filter_context = @import("filter_context.zig");
const registry = @import("../filters/registry.zig");

pub const Error = error{
    FileNotFound,
    AccessDenied,
    ReadFailed,
    WriteFailed,
    InvalidPath,
    OutOfMemory,
    FileTooLarge,
    UnterminatedSection,
    EmptySectionName,
    KeyWithoutValue,
    TooManySections,
    TooManyKeysInSection,
    TooManyFiles,
    InterpolationCycle,
    InterpolationOverflow,
    InterpolationUnterminated,
    UnsupportedRegex,
    IncludeDepthExceeded,
    InterpolationMissingOption,
    InvalidParameter,
    DuplicateSection,
    DuplicateOption,
    InvalidEncoding,
    NoJailsImported,
    InvalidGeneratedConfig,
};

pub const MigrationReport = struct {
    jails_imported: u32 = 0,
    jails_enabled: u32 = 0,
    jails_skipped: u32 = 0,
    filters_translated: u32 = 0,
    filters_builtin: u32 = 0,
    filters_skipped: u32 = 0,
    warnings: []const []const u8 = &.{},
    output_path: []const u8 = "",
    compatibility_prepared: bool = false,
    compatibility_pending_jails: u32 = 0,
    compatibility_pending_globals: bool = false,
};

pub fn printReport(report: MigrationReport, writer: anytype) !void {
    try writer.print(
        "migration: imported={d} skipped={d} filters(translated={d} builtin={d} skipped={d}) output='{s}'\n",
        .{
            report.jails_imported,
            report.jails_skipped,
            report.filters_translated,
            report.filters_builtin,
            report.filters_skipped,
            report.output_path,
        },
    );
    if (report.warnings.len > 0) {
        try writer.print("migration: {d} warning(s):\n", .{report.warnings.len});
        try writer.print("migration: enabled_jails={d}\n", .{report.jails_enabled});
        for (report.warnings) |w| {
            try writer.print("  - {s}\n", .{w});
        }
    }
}

const Context = struct {
    arena: std.mem.Allocator,
    source_dir: []const u8,
    warnings: std.ArrayListUnmanaged([]const u8) = .{},
    report: MigrationReport = .{},

    fn warn(self: *Context, comptime fmt: []const u8, args: anytype) !void {
        const msg = try std.fmt.allocPrint(self.arena, fmt, args);
        try self.warnings.append(self.arena, msg);
    }
};

pub fn importConfig(
    arena: std.mem.Allocator,
    source_dir: []const u8,
    output_path: []const u8,
) Error!MigrationReport {
    var ctx = Context{ .arena = arena, .source_dir = source_dir };

    const document = fail2ban.prepareConfigDocument(arena, source_dir, "jail") catch |err| switch (err) {
        error.FileNotFound, error.AccessDenied, error.ReadFailed => return err,
        else => |e| return e,
    };

    const global_document = try fail2ban.prepareConfigDocument(arena, source_dir, "fail2ban");
    var ini = document.source;
    for (ini.warnings.items) |w| {
        try ctx.warn("{s}:{d}: {s}", .{ w.source, w.line, w.message });
    }

    var cfg = native.Config{};
    cfg.global = .{};
    cfg.global.compatibility_pending = global_document.source.sources.items.len > 0;
    ctx.report.compatibility_pending_globals = cfg.global.compatibility_pending;
    if (cfg.global.compatibility_pending) try ctx.warn("global fail2ban settings and phase-specific defaults retained for admission; imported jails disabled", .{});
    cfg.defaults = try extractDefaults(&ctx, &ini);

    var jails = std.ArrayListUnmanaged(native.JailConfig){};
    errdefer jails.deinit(arena);

    var user_it = ini.userSections();
    while (user_it.next()) |sec| {
        var effective = try effectiveSection(arena, &ini, sec.name);
        var jail = translateJail(&ctx, &effective, &ini) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => |e| return e,
        } orelse {
            ctx.report.jails_skipped += 1;
            continue;
        };
        if (cfg.global.compatibility_pending) {
            if (!jail.compatibility_pending) ctx.report.compatibility_pending_jails += 1;
            jail.compatibility_pending = true;
            jail.enabled = false;
        }
        try jails.append(arena, jail);
        ctx.report.jails_imported += 1;
        if (jail.enabled) ctx.report.jails_enabled += 1;
    }

    cfg.jails = try jails.toOwnedSlice(arena);
    cfg.global.compatibility_manifest = try prepareManifest(&ctx, &document, &global_document);
    ctx.report.compatibility_prepared = true;

    native.validate(&cfg) catch |err| {
        std.log.warn("import: generated configuration is invalid ({s}); output was not replaced", .{@errorName(err)});
        return error.InvalidGeneratedConfig;
    };

    try writeTomlAtomic(arena, &cfg, output_path);

    ctx.report.warnings = try ctx.warnings.toOwnedSlice(arena);
    ctx.report.output_path = try arena.dupe(u8, output_path);
    return ctx.report;
}

fn extractDefaults(
    ctx: *Context,
    ini: *fail2ban.ParsedIni,
) Error!native.JailDefaults {
    var out = native.JailDefaults{};
    const def_sec = ini.section("DEFAULT") orelse return out;

    if (def_sec.get("bantime")) |v| {
        if (parseImportedDuration(v)) |d| out.bantime = d else {
            try ctx.warn("[DEFAULT].bantime = '{s}' could not be parsed; keeping fail2zig default", .{v});
        }
    }
    if (def_sec.get("findtime")) |v| {
        if (parseImportedDuration(v)) |d| out.findtime = d else {
            try ctx.warn("[DEFAULT].findtime = '{s}' could not be parsed; keeping fail2zig default", .{v});
        }
    }
    if (def_sec.get("maxretry")) |v| {
        if (std.fmt.parseInt(u32, std.mem.trim(u8, v, " \t"), 10)) |n| {
            out.maxretry = n;
        } else |_| {
            try ctx.warn("[DEFAULT].maxretry = '{s}' is not a valid integer; keeping default", .{v});
        }
    }
    if (def_sec.get("ignoreip")) |v| {
        out.ignoreip = try splitWhitespaceList(ctx.arena, v);
    }
    if (def_sec.get("banaction")) |v| {
        out.banaction = mapBanaction(ctx, v);
    }
    if (def_sec.get("backend")) |v| {
        out.source = try mapBackend(ctx, "[DEFAULT]", v);
    }

    out.bantime_increment = try extractIncrement(ctx, def_sec, .{ .formula = .exponential, .factor = 2 });
    return out;
}

fn translateJail(
    ctx: *Context,
    sec: *fail2ban.Section,
    ini: *fail2ban.ParsedIni,
) Error!?native.JailConfig {
    if (sec.get("enabled")) |v| {
        if (!parseBool(v)) return null;
    } else {}

    var jail = native.JailConfig{
        .name = try ctx.arena.dupe(u8, sec.name),
    };

    if (sec.get("enabled")) |v| {
        jail.enabled = parseBool(v);
    } else {
        jail.enabled = false;
    }

    if (sec.get("logpath")) |v| {
        jail.logpath = try splitLogpath(ctx.arena, v);
    }

    {
        const v = sec.get("filter") orelse sec.name;
        const trimmed = std.mem.trim(u8, v, " \t");
        if (trimmed.len == 0) {
            try ctx.warn("jail '{s}': empty filter name", .{sec.name});
            ctx.report.filters_skipped += 1;
            jail.enabled = false;
        } else if (resolveFilter(ctx, trimmed)) |kind| {
            switch (kind) {
                .builtin => ctx.report.filters_builtin += 1,
            }
            jail.filter = try ctx.arena.dupe(u8, trimmed);
        } else {
            try ctx.warn("jail '{s}': filter '{s}' not found (neither built-in nor filter.d); jail disabled", .{ sec.name, trimmed });
            ctx.report.filters_skipped += 1;
            jail.enabled = false;
            jail.filter = try ctx.arena.dupe(u8, trimmed);
        }
    }

    if (sec.get("maxretry")) |v| {
        if (std.fmt.parseInt(u32, std.mem.trim(u8, v, " \t"), 10)) |n| {
            jail.maxretry = n;
        } else |_| {
            try ctx.warn("jail '{s}': maxretry = '{s}' invalid", .{ sec.name, v });
        }
    }
    if (sec.get("findtime")) |v| {
        if (parseImportedDuration(v)) |d| {
            jail.findtime = d;
        } else {
            try ctx.warn("jail '{s}': findtime = '{s}' invalid", .{ sec.name, v });
        }
    }
    if (sec.get("bantime")) |v| {
        if (parseImportedDuration(v)) |d| {
            jail.bantime = d;
        } else {
            try ctx.warn("jail '{s}': bantime = '{s}' invalid", .{ sec.name, v });
        }
    }

    if (sec.get("action")) |v| {
        jail.banaction = mapBanaction(ctx, v);
    } else if (sec.get("banaction")) |v| {
        jail.banaction = mapBanaction(ctx, v);
    }

    if (sec.get("ignoreip")) |v| {
        jail.ignoreip = try splitWhitespaceList(ctx.arena, v);
    }

    if (sec.get("backend")) |v| {
        jail.source = try mapBackend(ctx, sec.name, v);
    }

    var base = native.BanTimeIncrement{ .formula = .exponential, .factor = 2 };
    if (ini.section("DEFAULT")) |def| base = try extractIncrement(ctx, def, base);
    jail.bantime_increment = try extractIncrement(ctx, sec, base);
    jail.bantime_increment_explicit = sec.get("bantime.increment") != null or sec.get("bantime.factor") != null or sec.get("bantime.maxtime") != null;

    var pending = requiresCompatibility(sec);
    if (!pending) {
        const filter = sec.get("filter") orelse sec.name;
        const asset = fail2ban.loadParameterizedAsset(ctx.arena, ctx.source_dir, "filter.d", filter) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => null,
        };
        if (asset) |prepared| {
            if (prepared.config.sources.items.len > 0) pending = true;
        } else pending = true;
    }
    if (pending) {
        jail.enabled = false;
        jail.compatibility_pending = true;
        ctx.report.compatibility_pending_jails += 1;
        try ctx.warn("jail '{s}': imported scope, options or assets require compatibility admission; retained in prepared manifest and disabled", .{sec.name});
    }
    return jail;
}

fn extractIncrement(ctx: *Context, sec: *const fail2ban.Section, base: native.BanTimeIncrement) Error!native.BanTimeIncrement {
    var incr = base;
    if (sec.get("bantime.increment")) |v| incr.enabled = parseBool(v);
    if (sec.get("bantime.factor")) |v| incr.multiplier = std.fmt.parseFloat(f64, std.mem.trim(u8, v, " \t")) catch return error.InvalidGeneratedConfig;
    if (sec.get("bantime.maxtime")) |v| incr.max_bantime = parseImportedDuration(v) orelse return error.InvalidGeneratedConfig;
    if (sec.get("bantime.multipliers") != null or sec.get("bantime.formula") != null) {
        try ctx.warn("jail '{s}': custom ban formulas/multiplier lists are unsupported; section cannot be imported", .{sec.name});
        return error.InvalidGeneratedConfig;
    }
    return incr;
}

const FilterResolution = enum { builtin };

fn resolveFilter(ctx: *Context, name: []const u8) ?FilterResolution {
    if (registry.get(name) != null) return .builtin;
    ctx.warn("filter '{s}': custom runtime filters are not supported; jail disabled (no patterns were installed)", .{name}) catch {};
    return null;
}

pub fn parseDuration(raw: []const u8) ?u64 {
    const trimmed = std.mem.trim(u8, raw, " \t");
    if (trimmed.len == 0) return null;

    var split: usize = 0;
    while (split < trimmed.len) : (split += 1) {
        const c = trimmed[split];
        if (c < '0' or c > '9') break;
    }
    if (split == 0) return null;
    const n = std.fmt.parseInt(u64, trimmed[0..split], 10) catch return null;

    const rest = std.mem.trim(u8, trimmed[split..], " \t");
    if (rest.len == 0) return n;

    const Unit = struct { suf: []const u8, mul: u64 };
    const units = [_]Unit{
        .{ .suf = "seconds", .mul = 1 },
        .{ .suf = "second", .mul = 1 },
        .{ .suf = "sec", .mul = 1 },
        .{ .suf = "s", .mul = 1 },
        .{ .suf = "minutes", .mul = 60 },
        .{ .suf = "minute", .mul = 60 },
        .{ .suf = "min", .mul = 60 },
        .{ .suf = "m", .mul = 60 },
        .{ .suf = "hours", .mul = 3600 },
        .{ .suf = "hour", .mul = 3600 },
        .{ .suf = "hr", .mul = 3600 },
        .{ .suf = "h", .mul = 3600 },
        .{ .suf = "days", .mul = 86_400 },
        .{ .suf = "day", .mul = 86_400 },
        .{ .suf = "d", .mul = 86_400 },
        .{ .suf = "weeks", .mul = 604_800 },
        .{ .suf = "week", .mul = 604_800 },
        .{ .suf = "w", .mul = 604_800 },
        .{ .suf = "months", .mul = 30 * 86_400 },
        .{ .suf = "month", .mul = 30 * 86_400 },
        .{ .suf = "mo", .mul = 30 * 86_400 },
        .{ .suf = "years", .mul = 365 * 86_400 },
        .{ .suf = "year", .mul = 365 * 86_400 },
        .{ .suf = "y", .mul = 365 * 86_400 },
    };
    for (units) |u| {
        if (std.ascii.eqlIgnoreCase(rest, u.suf)) {
            return std.math.mul(u64, n, u.mul) catch null;
        }
    }
    return null;
}

fn parseBool(raw: []const u8) bool {
    const s = std.mem.trim(u8, raw, " \t");
    return std.ascii.eqlIgnoreCase(s, "true") or
        std.ascii.eqlIgnoreCase(s, "yes") or
        std.ascii.eqlIgnoreCase(s, "on") or
        std.ascii.eqlIgnoreCase(s, "1");
}

fn splitWhitespaceList(arena: std.mem.Allocator, raw: []const u8) Error![]const []const u8 {
    var list = std.ArrayListUnmanaged([]const u8){};
    errdefer list.deinit(arena);
    var it = std.mem.tokenizeAny(u8, raw, " \t\n,");
    while (it.next()) |tok| {
        const copy = try arena.dupe(u8, tok);
        try list.append(arena, copy);
    }
    return try list.toOwnedSlice(arena);
}

fn splitLogpath(arena: std.mem.Allocator, raw: []const u8) Error![]const []const u8 {
    var list = std.ArrayListUnmanaged([]const u8){};
    errdefer list.deinit(arena);
    var it = std.mem.tokenizeAny(u8, raw, "\n");
    while (it.next()) |tok| {
        const trimmed = std.mem.trim(u8, tok, " \t");
        if (trimmed.len == 0) continue;
        const copy = try arena.dupe(u8, trimmed);
        try list.append(arena, copy);
    }
    return try list.toOwnedSlice(arena);
}

fn mapBackend(ctx: *Context, scope: []const u8, raw: []const u8) Error!native.LogSource {
    const trimmed = std.mem.trim(u8, raw, " \t");
    return native.mapBackendAlias(trimmed) orelse {
        try ctx.warn("{s}: backend = '{s}' not recognized; source left as auto", .{ scope, trimmed });
        return .auto;
    };
}

fn mapBanaction(ctx: *Context, raw: []const u8) native.BanAction {
    const trimmed = std.mem.trim(u8, raw, " \t");
    const bracket_idx = std.mem.indexOfScalar(u8, trimmed, '[') orelse trimmed.len;
    const name = std.mem.trim(u8, trimmed[0..bracket_idx], " \t");

    if (std.mem.startsWith(u8, name, "nftables")) return .nftables;
    if (std.mem.startsWith(u8, name, "iptables")) return .iptables;
    if (std.mem.startsWith(u8, name, "ipset")) return .ipset;

    ctx.warn("action '{s}' not recognized; mapped to log-only (edit the TOML to override)", .{name}) catch {};
    return .@"log-only";
}

fn writeTomlAtomic(
    arena: std.mem.Allocator,
    cfg: *const native.Config,
    output_path: []const u8,
) Error!void {
    const nonce = std.crypto.random.int(u64);
    const tmp_path = try std.fmt.allocPrint(arena, "{s}.tmp-{x}", .{ output_path, nonce });
    errdefer std.fs.cwd().deleteFile(tmp_path) catch {};

    if (std.fs.path.dirname(output_path)) |parent| {
        std.fs.cwd().makePath(parent) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return error.WriteFailed,
        };
    }

    var buf = std.ArrayListUnmanaged(u8){};
    defer buf.deinit(arena);
    const w = buf.writer(arena);
    try renderToml(cfg, w);
    if (buf.items.len > native.max_config_bytes) return error.FileTooLarge;

    const tmp_file = std.fs.cwd().createFile(tmp_path, .{ .mode = 0o600, .exclusive = true }) catch return error.WriteFailed;
    {
        defer tmp_file.close();
        tmp_file.writeAll(buf.items) catch return error.WriteFailed;
        tmp_file.sync() catch return error.WriteFailed;
    }
    std.fs.cwd().rename(tmp_path, output_path) catch return error.WriteFailed;
}

pub fn renderToml(cfg: *const native.Config, w: anytype) !void {
    try w.writeAll(
        \\# fail2zig configuration — generated by `fail2zig --import-config`.
        \\# Edit freely; re-import will overwrite.
        \\
        \\
    );

    try w.writeAll("[global]\n");
    if (cfg.global.compatibility_manifest.len > 0) try writeQuoted(w, "compatibility_manifest", cfg.global.compatibility_manifest);
    if (cfg.global.compatibility_pending) try w.writeAll("compatibility_pending = true\n");
    try w.print("log_level = \"{s}\"\n", .{@tagName(cfg.global.log_level)});
    try writeQuoted(w, "pid_file", cfg.global.pid_file);
    try writeQuoted(w, "socket_path", cfg.global.socket_path);
    try writeQuoted(w, "state_file", cfg.global.state_file);
    try w.print("memory_ceiling_mb = {d}\n", .{cfg.global.memory_ceiling_mb});
    try writeQuoted(w, "metrics_bind", cfg.global.metrics_bind);
    try w.print("metrics_port = {d}\n", .{cfg.global.metrics_port});
    try w.print("metrics_enabled = {s}\nwebsocket_max_clients = {d}\non_no_backend = \"{s}\"\nfirewall = \"{s}\"\n", .{ if (cfg.global.metrics_enabled) "true" else "false", cfg.global.websocket_max_clients, @tagName(cfg.global.on_no_backend), @tagName(cfg.global.firewall) });
    try w.writeAll("\n");

    try w.writeAll("[defaults]\n");
    try w.print("bantime = {d}\n", .{cfg.defaults.bantime});
    try w.print("findtime = {d}\n", .{cfg.defaults.findtime});
    try w.print("maxretry = {d}\n", .{cfg.defaults.maxretry});
    try w.print("banaction = \"{s}\"\n", .{@tagName(cfg.defaults.banaction)});
    if (cfg.defaults.source != .auto) try w.print("source = \"{s}\"\n", .{@tagName(cfg.defaults.source)});
    if (cfg.defaults.ignoreip.len > 0) {
        try writeStringArray(w, "ignoreip", cfg.defaults.ignoreip);
    }
    try writeIncrement(w, cfg.defaults.bantime_increment);
    try w.writeAll("\n");

    for (cfg.jails) |j| {
        try w.print("[jails.{s}]\n", .{j.name});
        try w.print("enabled = {s}\n", .{if (j.enabled) "true" else "false"});
        if (j.compatibility_pending) try w.writeAll("compatibility_pending = true\n");
        if (j.filter.len > 0) try writeQuoted(w, "filter", j.filter);
        if (j.logpath.len > 0) try writeStringArray(w, "logpath", j.logpath);
        if (j.source != .auto) try w.print("source = \"{s}\"\n", .{@tagName(j.source)});
        if (j.maxretry) |v| try w.print("maxretry = {d}\n", .{v});
        if (j.findtime) |v| try w.print("findtime = {d}\n", .{v});
        if (j.bantime) |v| try w.print("bantime = {d}\n", .{v});
        if (j.banaction) |v| try w.print("banaction = \"{s}\"\n", .{@tagName(v)});
        if (j.ignoreip) |list| try writeStringArray(w, "ignoreip", list);
        if (j.bantime_increment_explicit) try writeIncrementMask(w, j.bantime_increment, if (j.bantime_increment_fields == 0) 31 else j.bantime_increment_fields);
        try w.writeAll("\n");
    }
}

fn writeIncrement(w: anytype, incr: native.BanTimeIncrement) !void {
    try writeIncrementMask(w, incr, 31);
}
fn writeIncrementMask(w: anytype, incr: native.BanTimeIncrement, mask: u8) !void {
    if (mask & 1 != 0) try w.print("bantime_increment_enabled = {s}\n", .{if (incr.enabled) "true" else "false"});
    if (mask & 2 != 0) try w.print("bantime_increment_multiplier = {d}\n", .{incr.multiplier});
    if (mask & 4 != 0) try w.print("bantime_increment_factor = {d}\n", .{incr.factor});
    if (mask & 8 != 0) try w.print("bantime_increment_formula = \"{s}\"\n", .{@tagName(incr.formula)});
    if (mask & 16 != 0) try w.print("bantime_increment_max_bantime = {d}\n", .{incr.max_bantime});
}

fn writeQuoted(w: anytype, key: []const u8, value: []const u8) !void {
    try w.print("{s} = \"", .{key});
    for (value) |c| {
        switch (c) {
            '\\', '"' => try w.print("\\{c}", .{c}),
            '\n' => try w.writeAll("\\n"),
            '\t' => try w.writeAll("\\t"),
            else => try w.writeByte(c),
        }
    }
    try w.writeAll("\"\n");
}

fn writeStringArray(w: anytype, key: []const u8, items: []const []const u8) !void {
    try w.print("{s} = [", .{key});
    for (items, 0..) |item, i| {
        if (i > 0) try w.writeAll(", ");
        try w.writeAll("\"");
        for (item) |c| {
            switch (c) {
                '\\', '"' => try w.print("\\{c}", .{c}),
                '\n' => try w.writeAll("\\n"),
                '\t' => try w.writeAll("\\t"),
                else => try w.writeByte(c),
            }
        }
        try w.writeAll("\"");
    }
    try w.writeAll("]\n");
}

const testing = std.testing;

test "migration: parseDuration plain integer" {
    try testing.expectEqual(@as(?u64, 600), parseDuration("600"));
    try testing.expectEqual(@as(?u64, 0), parseDuration("0"));
    try testing.expectEqual(@as(?u64, 3600), parseDuration(" 3600 "));
}

test "migration: parseDuration suffixes" {
    try testing.expectEqual(@as(?u64, 600), parseDuration("10m"));
    try testing.expectEqual(@as(?u64, 3600), parseDuration("1h"));
    try testing.expectEqual(@as(?u64, 86400), parseDuration("1d"));
    try testing.expectEqual(@as(?u64, 604800), parseDuration("1w"));
    try testing.expectEqual(@as(?u64, 600), parseDuration("10 minutes"));
    try testing.expectEqual(@as(?u64, 7200), parseDuration("2h"));
}

test "migration: parseDuration rejects garbage" {
    try testing.expect(parseDuration("") == null);
    try testing.expect(parseDuration("abc") == null);
    try testing.expect(parseDuration("10xyz") == null);
}

test "migration: writes valid TOML that native parser can reload" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{
        .sub_path = "jail.conf",
        .data =
        \\[DEFAULT]
        \\bantime = 600
        \\findtime = 600
        \\maxretry = 5
        \\ignoreip = 127.0.0.1/8 10.0.0.0/8
        \\
        \\backend = polling
        \\
        \\[sshd]
        \\enabled = true
        \\filter = sshd
        \\logpath = /var/log/auth.log
        \\maxretry = 3
        \\bantime = 1h
        \\backend = systemd
        \\
        \\[nginx-http-auth]
        \\enabled = true
        \\filter = nginx-http-auth
        \\logpath = /var/log/nginx/error.log
        \\backend = pyinotify
        ,
    });

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const source = try tmp.dir.realpathAlloc(arena.allocator(), ".");
    const out = try std.fs.path.join(arena.allocator(), &.{ source, "out.toml" });

    const report = try importConfig(arena.allocator(), source, out);
    try testing.expectEqual(@as(u32, 2), report.jails_imported);
    try testing.expect(report.filters_builtin >= 2);

    const toml = try std.fs.cwd().readFileAlloc(arena.allocator(), out, 1 << 20);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, toml, "source = \"journald\""));
    try testing.expect(std.mem.indexOf(u8, toml, "\nbackend =") == null);

    var arena2 = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena2.deinit();
    const cfg = try native.Config.loadFile(arena2.allocator(), out);
    try testing.expectEqual(@as(usize, 2), cfg.jails.len);
    try testing.expectEqual(native.LogSource.auto, cfg.defaults.source);

    var sshd_jail: ?native.JailConfig = null;
    var nginx_jail: ?native.JailConfig = null;
    for (cfg.jails) |j| {
        if (std.mem.eql(u8, j.name, "sshd")) sshd_jail = j;
        if (std.mem.eql(u8, j.name, "nginx-http-auth")) nginx_jail = j;
    }
    try testing.expect(sshd_jail != null);
    try testing.expectEqualStrings("sshd", sshd_jail.?.filter);
    try testing.expectEqual(@as(?u32, 3), sshd_jail.?.maxretry);
    try testing.expectEqual(@as(?u64, 3600), sshd_jail.?.bantime);
    try testing.expectEqual(native.LogSource.journald, sshd_jail.?.source);
    try testing.expectEqual(native.LogSource.auto, nginx_jail.?.source);
}

test "migration: DEFAULT backend = systemd becomes [defaults] source and an unknown backend warns" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{
        .sub_path = "jail.conf",
        .data =
        \\[DEFAULT]
        \\backend = systemd
        \\
        \\[sshd]
        \\enabled = true
        \\filter = sshd
        \\backend = bogus
        ,
    });

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const source = try tmp.dir.realpathAlloc(arena.allocator(), ".");
    const out = try std.fs.path.join(arena.allocator(), &.{ source, "out.toml" });

    const report = try importConfig(arena.allocator(), source, out);
    var warned = false;
    for (report.warnings) |w| {
        if (std.mem.indexOf(u8, w, "backend = 'bogus'") != null) warned = true;
    }
    try testing.expect(warned);

    var arena2 = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena2.deinit();
    const cfg = try native.Config.loadFile(arena2.allocator(), out);
    try testing.expectEqual(native.LogSource.journald, cfg.defaults.source);
    try testing.expectEqual(native.LogSource.journald, cfg.jails[0].source);
}

test "migration: skips jails with enabled=false" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{
        .sub_path = "jail.conf",
        .data =
        \\[sshd]
        \\enabled = true
        \\filter = sshd
        \\
        \\[disabled-jail]
        \\enabled = false
        \\filter = sshd
        ,
    });

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const source = try tmp.dir.realpathAlloc(arena.allocator(), ".");
    const out = try std.fs.path.join(arena.allocator(), &.{ source, "out.toml" });

    const report = try importConfig(arena.allocator(), source, out);
    try testing.expectEqual(@as(u32, 1), report.jails_imported);
    try testing.expectEqual(@as(u32, 1), report.jails_skipped);
}

test "migration: warns on unknown filter but still writes output" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{
        .sub_path = "jail.conf",
        .data =
        \\[weird-app]
        \\enabled = true
        \\filter = nonexistent-filter
        \\logpath = /var/log/weird.log
        ,
    });

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const source = try tmp.dir.realpathAlloc(arena.allocator(), ".");
    const out = try std.fs.path.join(arena.allocator(), &.{ source, "out.toml" });

    const report = try importConfig(arena.allocator(), source, out);
    try testing.expectEqual(@as(u32, 1), report.filters_skipped);
    var found_filter_warning = false;
    for (report.warnings) |w| {
        if (std.mem.indexOf(u8, w, "nonexistent-filter") != null) found_filter_warning = true;
    }
    try testing.expect(found_filter_warning);

    var arena2 = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena2.deinit();
    const cfg = try native.Config.loadFile(arena2.allocator(), out);
    try testing.expectEqual(@as(usize, 1), cfg.jails.len);
    try testing.expect(!cfg.jails[0].enabled);
}

test "migration: unsupported custom filter is disabled rather than reported translated" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir("filter.d");
    try tmp.dir.writeFile(.{
        .sub_path = "filter.d/myapp.conf",
        .data =
        \\[Definition]
        \\failregex = ^Auth failed for user .* from <HOST>$
        ,
    });
    try tmp.dir.writeFile(.{
        .sub_path = "jail.conf",
        .data =
        \\[myapp]
        \\enabled = true
        \\filter = myapp
        \\logpath = /var/log/myapp.log
        ,
    });

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const source = try tmp.dir.realpathAlloc(arena.allocator(), ".");
    const out = try std.fs.path.join(arena.allocator(), &.{ source, "out.toml" });

    const report = try importConfig(arena.allocator(), source, out);
    try testing.expectEqual(@as(u32, 1), report.jails_imported);
    try testing.expectEqual(@as(u32, 0), report.filters_translated);
    try testing.expectEqual(@as(u32, 1), report.filters_skipped);
    const generated = try std.fs.cwd().readFileAlloc(arena.allocator(), out, 64 * 1024);
    const cfg = try native.Config.parse(arena.allocator(), generated);
    try testing.expect(!cfg.jails[0].enabled);
    try native.validate(&cfg);
}

test "migration: maps jail action to backend" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{
        .sub_path = "jail.conf",
        .data =
        \\[sshd]
        \\enabled = true
        \\filter = sshd
        \\action = iptables-multiport[name=SSH, port=22]
        ,
    });

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const source = try tmp.dir.realpathAlloc(arena.allocator(), ".");
    const out = try std.fs.path.join(arena.allocator(), &.{ source, "out.toml" });

    const report = try importConfig(arena.allocator(), source, out);
    try testing.expectEqual(@as(u32, 1), report.jails_imported);

    var arena2 = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena2.deinit();
    const cfg = try native.Config.loadFile(arena2.allocator(), out);
    try testing.expectEqual(@as(usize, 1), cfg.jails.len);
    try testing.expectEqual(native.BanAction.iptables, cfg.jails[0].banaction.?);
}

test "migration: printReport formats a summary line and warnings" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();

    const warnings = [_][]const u8{
        "jail 'foo': filter 'bar' not found",
        "action 'sendmail' not recognized",
    };
    const report = MigrationReport{
        .jails_imported = 3,
        .jails_skipped = 1,
        .filters_translated = 2,
        .filters_builtin = 1,
        .filters_skipped = 1,
        .warnings = &warnings,
        .output_path = "/tmp/x.toml",
    };
    try printReport(report, buf.writer());
    try testing.expect(std.mem.indexOf(u8, buf.items, "imported=3") != null);
    try testing.expect(std.mem.indexOf(u8, buf.items, "warning(s)") != null);
    try testing.expect(std.mem.indexOf(u8, buf.items, "sendmail") != null);
}

test "migration: generated config preserves increment overrides and empty ignore lists" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var jails = [_]native.JailConfig{.{ .name = "sshd", .filter = "sshd", .ignoreip = &.{}, .bantime_increment_explicit = true, .bantime_increment = .{ .enabled = false, .factor = 1.5, .multiplier = 2.5 } }};
    const cfg = native.Config{ .defaults = .{ .ignoreip = &.{"192.0.2.1"}, .bantime_increment = .{ .enabled = true, .factor = 3.5 } }, .jails = &jails };
    var output = std.ArrayList(u8).init(arena.allocator());
    try renderToml(&cfg, output.writer());
    const parsed = try native.Config.parse(arena.allocator(), output.items);
    try testing.expect(parsed.defaults.bantime_increment.enabled);
    try testing.expectEqual(@as(f64, 3.5), parsed.defaults.bantime_increment.factor);
    try testing.expect(!parsed.jails[0].bantime_increment.enabled);
    try testing.expect(parsed.jails[0].bantime_increment_explicit);
    try testing.expectEqual(@as(f64, 1.5), parsed.jails[0].bantime_increment.factor);
    try testing.expectEqual(@as(f64, 2.5), parsed.jails[0].bantime_increment.multiplier);
    try testing.expectEqual(@as(usize, 0), parsed.jails[0].ignoreip.?.len);
}

test "migration: duration conversion preserves representable limits and rejects overflow" {
    const units = [_]struct { name: []const u8, seconds: u64 }{
        .{ .name = "s", .seconds = 1 },
        .{ .name = "m", .seconds = 60 },
        .{ .name = "h", .seconds = 3600 },
        .{ .name = "d", .seconds = 86400 },
        .{ .name = "w", .seconds = 604800 },
        .{ .name = "mo", .seconds = 30 * 86400 },
        .{ .name = "y", .seconds = 365 * 86400 },
    };
    var text: [64]u8 = undefined;
    for (units) |unit| {
        const limit = std.math.maxInt(u64) / unit.seconds;
        const valid = try std.fmt.bufPrint(&text, "{d}{s}", .{ limit, unit.name });
        try testing.expectEqual(@as(?u64, limit * unit.seconds), parseDuration(valid));
        if (unit.seconds > 1) {
            const invalid = try std.fmt.bufPrint(&text, "{d}{s}", .{ limit + 1, unit.name });
            try testing.expectEqual(@as(?u64, null), parseDuration(invalid));
        }
    }
}

test "migration: invalid converted increment duration preserves existing output" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const invalid_minutes = std.math.maxInt(u64) / 60 + 1;
    for ([_][]const u8{ "DEFAULT", "sshd" }) |section| {
        const input = try std.fmt.allocPrint(
            allocator,
            "[{s}]\nbantime.maxtime = {d}m\n{s}enabled = true\nfilter = sshd\n",
            .{ section, invalid_minutes, if (std.mem.eql(u8, section, "DEFAULT")) "[sshd]\n" else "" },
        );
        try tmp.dir.writeFile(.{ .sub_path = "jail.conf", .data = input });
        const sentinel = "existing operator configuration\n";
        try tmp.dir.writeFile(.{ .sub_path = "out.toml", .data = sentinel });
        const source = try tmp.dir.realpathAlloc(allocator, ".");
        const output = try std.fs.path.join(allocator, &.{ source, "out.toml" });
        try testing.expectError(error.InvalidGeneratedConfig, importConfig(allocator, source, output));
        const unchanged = try tmp.dir.readFileAlloc(allocator, "out.toml", 4096);
        try testing.expectEqualStrings(sentinel, unchanged);
    }
}

fn effectiveSection(arena: std.mem.Allocator, ini: *const fail2ban.ParsedIni, name: []const u8) Error!fail2ban.Section {
    var result = fail2ban.Section{ .name = name };
    for ([_]?*const fail2ban.Section{ ini.section("DEFAULT"), ini.section(name) }) |maybe| {
        if (maybe) |sec| {
            var it = sec.keys.iterator();
            while (it.next()) |kv| {
                var value = (fail2ban.resolve(arena, ini, name, kv.key_ptr.*) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => kv.value_ptr.*,
                }) orelse kv.value_ptr.*;
                if (std.mem.eql(u8, kv.key_ptr.*, "maxretry")) {
                    const typed = fail2ban.readTypedOption(arena, ini, name, kv.key_ptr.*, .integer, .null_value, "fail2ban-1.1.1/jailreader/maxretry") catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        else => null,
                    };
                    if (typed) |option| if (option.value == .integer) {
                        value = option.value.integer;
                    };
                }
                try result.keys.put(arena, kv.key_ptr.*, value);
                if (sec.origins.get(kv.key_ptr.*)) |origin| try result.origins.put(arena, kv.key_ptr.*, origin);
            }
        }
    }
    return result;
}

fn requiresCompatibility(sec: *const fail2ban.Section) bool {
    if (sec.get("logpath")) |raw| {
        var lines = std.mem.splitScalar(u8, raw, '\n');
        while (lines.next()) |line| if (std.mem.lastIndexOfScalar(u8, line, ' ') != null) return true;
    }
    const supported = [_][]const u8{ "enabled", "filter", "logpath", "backend", "maxretry", "findtime", "bantime", "ignoreip", "bantime.increment", "bantime.factor", "bantime.maxtime" };
    var it = sec.keys.iterator();
    while (it.next()) |kv| {
        var found = false;
        for (supported) |key| if (std.mem.eql(u8, key, kv.key_ptr.*)) {
            found = true;
            break;
        };
        if (!found) return true;
        if (std.mem.indexOf(u8, kv.value_ptr.*, "%(") != null) return true;
    }
    if (sec.get("filter")) |filter| if (registry.matcherForFilter(filter) == null) return true;
    if (sec.get("backend")) |backend| if (native.mapBackendAlias(backend) == null) return true;
    if (sec.get("maxretry")) |raw| {
        const retry = std.fmt.parseInt(u32, raw, 10) catch return true;
        if (retry == 0 or retry > native.max_supported_retry) return true;
    }
    for ([_][]const u8{ "bantime", "findtime" }) |key| {
        if (sec.get(key)) |raw| {
            const duration = parseImportedDuration(raw) orelse return true;
            if (duration == 0 or duration > native.max_ban_duration) return true;
        }
    }
    return false;
}

const ManifestOption = struct {
    section: []const u8,
    name: []const u8,
    raw: []const u8,
    effective: ?[]const u8,
    resolution_error: ?[]const u8,
    origin: ?fail2ban.Origin,
};
const ManifestAsset = struct {
    jail: []const u8,
    kind: []const u8,
    selector: []const u8,
    admission: []const u8,
    sources: []const fail2ban.SourceOccurrence,
    parameters: []const NameValue,
    combined: []const NameValue,
    diagnostics: []const fail2ban.Warning = &.{},
    known_combined: []const NameValue = &.{},
    auto_logtype: ?[]const u8 = null,
    consumer_phase: []const u8 = "asset-only",
};
const NameValue = struct { name: []const u8, value: []const u8 };

fn entries(arena: std.mem.Allocator, map: *const std.StringArrayHashMapUnmanaged([]const u8)) Error![]const NameValue {
    var list = std.ArrayListUnmanaged(NameValue){};
    var it = map.iterator();
    while (it.next()) |kv| try list.append(arena, .{ .name = kv.key_ptr.*, .value = kv.value_ptr.* });
    return try list.toOwnedSlice(arena);
}

fn prepareManifest(ctx: *Context, document: *const fail2ban.ConfigDocument, global_document: *const fail2ban.ConfigDocument) Error![]const u8 {
    const a = ctx.arena;
    var options = std.ArrayListUnmanaged(ManifestOption){};
    var assets = std.ArrayListUnmanaged(ManifestAsset){};
    var source_plans = std.ArrayListUnmanaged(source_plan.Plan){};
    var sections = document.source.sections.iterator();
    while (sections.next()) |section| {
        var effective = try effectiveSection(a, &document.source, section.key_ptr.*);
        var keys = effective.keys.iterator();
        while (keys.next()) |kv| {
            var resolution_error: ?[]const u8 = null;
            const value = fail2ban.resolve(a, &document.source, section.key_ptr.*, kv.key_ptr.*) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => value: {
                    resolution_error = @errorName(err);
                    break :value null;
                },
            };
            const origin = effective.origins.get(kv.key_ptr.*);
            try options.append(a, .{ .section = section.key_ptr.*, .name = kv.key_ptr.*, .raw = if (origin) |o| o.raw else kv.value_ptr.*, .effective = value, .resolution_error = resolution_error, .origin = origin });
        }
        if (std.mem.eql(u8, section.key_ptr.*, "DEFAULT") or std.mem.eql(u8, section.key_ptr.*, "INCLUDES")) continue;
        var source_defaults = source_plan.FilterDefaults{ .config_root = ctx.source_dir };
        var consumer_graph = try filter_context.readerDefaults(a, &document.source, ctx.source_dir);
        for ([_][]const u8{ "filter", "action", "banaction" }) |kind| {
            const selection = (fail2ban.resolve(a, &consumer_graph, section.key_ptr.*, kind) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => null,
            }) orelse if (std.mem.eql(u8, kind, "filter")) section.key_ptr.* else continue;
            const selections = try fail2ban.splitSelectors(a, selection);
            for (selections) |line| {
                const selector = std.mem.trim(u8, line, " \t");
                if (selector.len == 0) continue;
                const directory = if (std.mem.eql(u8, kind, "filter")) "filter.d" else "action.d";
                var prepared = try fail2ban.loadParameterizedAsset(a, ctx.source_dir, directory, selector);
                var known_values: []const NameValue = &.{};
                var auto_logtype: ?[]const u8 = null;
                var consumer_phase: []const u8 = "asset-only";
                const combined = combined: {
                    if (std.mem.eql(u8, kind, "filter")) {
                        const backend = (try fail2ban.resolve(a, &consumer_graph, section.key_ptr.*, "backend")) orelse "auto";
                        const context = filter_context.prepare(a, &consumer_graph, ctx.source_dir, section.key_ptr.*, selector, backend) catch |err| switch (err) {
                            error.OutOfMemory => return error.OutOfMemory,
                            else => {
                                source_defaults.error_name = @errorName(err);
                                try assets.append(a, .{ .jail = section.key_ptr.*, .kind = kind, .selector = selector, .admission = @errorName(err), .sources = prepared.config.sources.items, .parameters = try entries(a, &prepared.selector.parameters), .combined = &.{}, .consumer_phase = "filter-context-error" });
                                continue;
                            },
                        };
                        prepared = context.asset;
                        consumer_graph = context.jail_source;
                        known_values = try entries(a, &context.known_combined);
                        auto_logtype = context.auto_logtype;
                        consumer_phase = "filter-final-with-jail-variables";
                        break :combined context.combined;
                    }
                    break :combined fail2ban.combineAsset(a, &prepared, "") catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        else => {
                            try assets.append(a, .{ .jail = section.key_ptr.*, .kind = kind, .selector = selector, .admission = @errorName(err), .sources = prepared.config.sources.items, .parameters = try entries(a, &prepared.selector.parameters), .combined = &.{} });
                            continue;
                        },
                    };
                };
                if (std.mem.eql(u8, kind, "filter")) {
                    const retained = try a.create(@TypeOf(combined));
                    retained.* = combined;
                    source_defaults = .{ .values = retained, .asset_index = assets.items.len, .config_root = ctx.source_dir };
                }
                const admission = if (prepared.config.sources.items.len > 0) "prepared" else if (std.mem.eql(u8, kind, "filter") and registry.matcherForFilter(prepared.selector.name) != null) "native-projection" else "missing";
                try assets.append(a, .{ .jail = section.key_ptr.*, .kind = kind, .selector = selector, .admission = admission, .sources = prepared.config.sources.items, .parameters = try entries(a, &prepared.selector.parameters), .combined = try entries(a, &combined), .diagnostics = prepared.config.warnings.items, .known_combined = known_values, .auto_logtype = auto_logtype, .consumer_phase = consumer_phase });
            }
        }
        for (options.items) |*option| {
            if (!std.mem.eql(u8, option.section, section.key_ptr.*)) continue;
            option.resolution_error = null;
            option.effective = fail2ban.resolve(a, &consumer_graph, option.section, option.name) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => value: {
                    option.resolution_error = @errorName(err);
                    break :value null;
                },
            };
        }
        try source_plans.append(a, try source_plan.prepare(a, &consumer_graph, section.key_ptr.*, &global_document.source, source_defaults));
    }
    var bytes = std.ArrayListUnmanaged(u8){};
    var identity = std.crypto.hash.sha2.Sha256.init(.{});
    identity.update(&document.config_generation);
    identity.update(&global_document.config_generation);
    for (assets.items) |asset| {
        var length: [8]u8 = undefined;
        std.mem.writeInt(u64, &length, @intCast(asset.selector.len), .little);
        identity.update(&length);
        identity.update(asset.selector);
        for (asset.sources) |source| {
            std.mem.writeInt(u64, &length, @intCast(source.path.len), .little);
            identity.update(&length);
            identity.update(source.path);
            std.mem.writeInt(u64, &length, @intCast(source.resolved_target.len), .little);
            identity.update(&length);
            identity.update(source.resolved_target);
            identity.update(&source.sha256);
        }
    }
    var digest: [32]u8 = undefined;
    identity.final(&digest);
    const generation = std.fmt.bytesToHex(digest, .lower);
    std.json.stringify(.{ .schema_version = @as(u32, 1), .reference_profile = document.reference_profile, .config_generation = @as([]const u8, &generation), .admission = "prepared", .native_projection_profile = "legacy-builtin", .sources = document.source.sources.items, .assignments = document.source.assignments.items, .options = options.items, .assets = assets.items, .global = try prepareGlobalManifest(ctx, global_document), .source_plans = source_plans.items }, .{}, bytes.writer(a)) catch return error.OutOfMemory;
    return try bytes.toOwnedSlice(a);
}

test "p2 migration manifest retains source assets options and pending scoped admission" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const original = "[DEFAULT]\nhelper=retained\n[sshd]\nenabled=true\nfilter=custom[mode=custom]\nport=22\nprotocol=tcp\naction=iptables-multiport[name=custom]\nopaque=\n[disabled]\nenabled=false\nfilter=custom\n";
    try tmp.dir.writeFile(.{ .sub_path = "jail.conf", .data = original });
    try tmp.dir.makeDir("filter.d");
    try tmp.dir.writeFile(.{ .sub_path = "filter.d/custom.conf", .data = "[Definition]\nfailregex=<mode> <HOST>\n[Init]\nmode=normal\n" });
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const root = try tmp.dir.realpathAlloc(a, ".");
    const output = try std.fs.path.join(a, &.{ root, "out.toml" });
    const report = try importConfig(a, root, output);
    try testing.expect(report.compatibility_prepared);
    try testing.expectEqual(@as(u32, 1), report.compatibility_pending_jails);
    var cfg = try native.Config.loadFile(a, output);
    try testing.expect(!cfg.jails[0].enabled);
    try testing.expect(cfg.jails[0].compatibility_pending);
    const manifest = try native.decodeCompatibilityManifest(a, cfg.global.compatibility_manifest);
    const sources = manifest.object.get("sources").?.array;
    try testing.expectEqualStrings(original, sources.items[0].object.get("bytes").?.string);
    try testing.expect(manifest.object.get("assets").?.array.items.len >= 3);
    try testing.expect(std.mem.indexOf(u8, cfg.global.compatibility_manifest, "disabled") != null);
    try testing.expect(std.mem.indexOf(u8, cfg.global.compatibility_manifest, "custom <HOST>") != null);
    var rendered = std.ArrayList(u8).init(a);
    try renderToml(&cfg, rendered.writer());
    const reloaded = try native.Config.parse(a, rendered.items);
    try testing.expectEqualStrings(cfg.global.compatibility_manifest, reloaded.global.compatibility_manifest);
    cfg.jails[0].enabled = true;
    try testing.expectError(error.CompatibilityNotAdmitted, native.validate(&cfg));
}

test "p2 migration inherited values resolve in consuming jail context" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "jail.conf", .data = "[DEFAULT]\nmaxretry=%(retries)s\nretries=4\nenabled=true\n[sshd]\nfilter=sshd\nretries=7\n" });
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const root = try tmp.dir.realpathAlloc(a, ".");
    const output = try std.fs.path.join(a, &.{ root, "out.toml" });
    _ = try importConfig(a, root, output);
    const cfg = try native.Config.loadFile(a, output);
    try testing.expectEqual(@as(?u32, 7), cfg.jails[0].maxretry);
    try testing.expect(cfg.jails[0].compatibility_pending);
}

test "p2 migration same-name custom filter cannot silently activate builtin" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "jail.conf", .data = "[sshd]\nenabled=true\nfilter=sshd\n" });
    try tmp.dir.makeDir("filter.d");
    try tmp.dir.writeFile(.{ .sub_path = "filter.d/sshd.conf", .data = "[Definition]\nfailregex=custom <HOST>\n" });
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const root = try tmp.dir.realpathAlloc(a, ".");
    const output = try std.fs.path.join(a, &.{ root, "out.toml" });
    _ = try importConfig(a, root, output);
    const cfg = try native.Config.loadFile(a, output);
    try testing.expect(!cfg.jails[0].enabled);
    try testing.expect(cfg.jails[0].compatibility_pending);
}

fn parseImportedDuration(raw: []const u8) ?u64 {
    const value = @import("duration.zig").parse(raw, false) catch return null;
    return value.nativeSeconds() catch null;
}

test "p2 migration imported durations use reference calendar units" {
    try testing.expectEqual(@as(?u64, 31557600), parseImportedDuration("1year"));
    try testing.expectEqual(@as(?u64, 2629800), parseImportedDuration("1mo"));
    try testing.expectEqual(@as(?u64, 5400), parseImportedDuration("1h 30m"));
    try testing.expect(parseImportedDuration("0.5") == null);
    try testing.expect(parseImportedDuration("-1") == null);
}

const GlobalReaderObservation = struct {
    reader_entry: enum { emitted, omitted, invalid },
    phase: []const u8,
    section: []const u8,
    option: []const u8,
    value: ?fail2ban.ResolvedOption,
    resolution_error: ?[]const u8,
};
const GlobalManifest = struct {
    admission: []const u8,
    source_present: bool,
    thread_section_present: bool,
    sources: []const fail2ban.SourceOccurrence,
    assignments: []const fail2ban.Assignment,
    options: []const ManifestOption,
    reader_observations: []const GlobalReaderObservation,
    diagnostics: []const fail2ban.Warning,
};

fn prepareGlobalManifest(ctx: *Context, document: *const fail2ban.ConfigDocument) Error!GlobalManifest {
    const a = ctx.arena;
    var options = std.ArrayListUnmanaged(ManifestOption){};
    var sections = document.source.sections.iterator();
    while (sections.next()) |section| {
        var effective = try effectiveSection(a, &document.source, section.key_ptr.*);
        var keys = effective.keys.iterator();
        while (keys.next()) |kv| {
            var resolution_error: ?[]const u8 = null;
            const value = fail2ban.resolve(a, &document.source, section.key_ptr.*, kv.key_ptr.*) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => value: {
                    resolution_error = @errorName(err);
                    break :value null;
                },
            };
            const origin = effective.origins.get(kv.key_ptr.*);
            try options.append(a, .{ .section = section.key_ptr.*, .name = kv.key_ptr.*, .raw = if (origin) |o| o.raw else kv.value_ptr.*, .effective = value, .resolution_error = resolution_error, .origin = origin });
        }
    }
    const Rule = struct { phase: []const u8, section: []const u8 = "Definition", name: []const u8, kind: fail2ban.CanonicalType = .string, fallback: fail2ban.CanonicalValue };
    const rules = [_]Rule{
        .{ .phase = "early", .name = "socket", .fallback = .{ .string = "/var/run/fail2ban/fail2ban.sock" } },
        .{ .phase = "early", .name = "pidfile", .fallback = .{ .string = "/var/run/fail2ban/fail2ban.pid" } },
        .{ .phase = "early", .name = "loglevel", .fallback = .{ .string = "INFO" } },
        .{ .phase = "early", .name = "logtarget", .fallback = .{ .string = "/var/log/fail2ban.log" } },
        .{ .phase = "early", .name = "syslogsocket", .fallback = .{ .string = "auto" } },
        .{ .phase = "global", .name = "loglevel", .fallback = .{ .string = "INFO" } },
        .{ .phase = "global", .name = "logtarget", .fallback = .{ .string = "STDERR" } },
        .{ .phase = "global", .name = "syslogsocket", .fallback = .{ .string = "auto" } },
        .{ .phase = "global", .name = "allowipv6", .fallback = .{ .string = "auto" } },
        .{ .phase = "global", .name = "dbfile", .fallback = .{ .string = "/var/lib/fail2ban/fail2ban.sqlite3" } },
        .{ .phase = "global", .name = "dbmaxmatches", .kind = .integer, .fallback = .null_value },
        .{ .phase = "global", .name = "dbpurgeage", .fallback = .{ .string = "1d" } },
        .{ .phase = "thread", .section = "Thread", .name = "stacksize", .kind = .integer, .fallback = .null_value },
    };
    var observations = std.ArrayListUnmanaged(GlobalReaderObservation){};
    for (rules) |rule| {
        if (std.mem.eql(u8, rule.phase, "thread") and document.source.section("Thread") == null) continue;
        const default_identity = try std.fmt.allocPrint(a, "fail2ban-1.1.1/fail2banreader/{s}/{s}/{s}", .{ rule.phase, rule.section, rule.name });
        var resolution_error: ?[]const u8 = null;
        const value = fail2ban.readTypedOption(a, &document.source, rule.section, rule.name, rule.kind, rule.fallback, default_identity) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => value: {
                resolution_error = @errorName(err);
                break :value null;
            },
        };
        const reader_entry: @FieldType(GlobalReaderObservation, "reader_entry") = if (value) |option|
            if (document.source.section(rule.section) != null and option.presence == .absent and option.value == .null_value and option.resolution == .resolved) .omitted else .emitted
        else
            .invalid;
        try observations.append(a, .{ .reader_entry = reader_entry, .phase = rule.phase, .section = rule.section, .option = rule.name, .value = value, .resolution_error = resolution_error });
    }
    return .{ .admission = if (document.source.sources.items.len > 0) "pending" else "absent-native-projection", .source_present = document.source.sources.items.len > 0, .thread_section_present = document.source.section("Thread") != null, .sources = document.source.sources.items, .assignments = document.source.assignments.items, .options = options.items, .reader_observations = observations.items, .diagnostics = document.source.warnings.items };
}

test "p2 migration retains global layers and blocks unsupported activation" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("fail2ban.d");
    try tmp.dir.writeFile(.{ .sub_path = "jail.conf", .data = "[sshd]\nenabled=true\n" });
    try tmp.dir.writeFile(.{ .sub_path = "fail2ban.conf", .data = "[INCLUDES]\nbefore=global-common.conf\n[Definition]\nlogtarget=base\nallowipv6=auto\ndbfile=None\n[Thread]\nstacksize=8192\n[Extension]\ncustom=keep-me\n" });
    try tmp.dir.writeFile(.{ .sub_path = "global-common.conf", .data = "[Definition]\nsyslogsocket=auto\n" });
    try tmp.dir.writeFile(.{ .sub_path = "fail2ban.d/10-package.conf", .data = "[Definition]\nlogtarget=package\n" });
    try tmp.dir.writeFile(.{ .sub_path = "fail2ban.local", .data = "[Definition]\nlogtarget=operator\n" });
    try tmp.dir.writeFile(.{ .sub_path = "fail2ban.d/90-final.local", .data = "[Definition]\nlogtarget=\n" });
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const root = try tmp.dir.realpathAlloc(a, ".");
    const output = try std.fs.path.join(a, &.{ root, "out.toml" });
    const report = try importConfig(a, root, output);
    try testing.expect(report.compatibility_pending_globals);
    try testing.expectEqual(@as(u32, 0), report.jails_enabled);
    var cfg = try native.Config.loadFile(a, output);
    try testing.expect(cfg.global.compatibility_pending);
    const manifest = try native.decodeCompatibilityManifest(a, cfg.global.compatibility_manifest);
    const global = manifest.object.get("global").?.object;
    try testing.expectEqual(@as(usize, 5), global.get("sources").?.array.items.len);
    try testing.expect(global.get("thread_section_present").?.bool);
    try testing.expect(std.mem.indexOf(u8, cfg.global.compatibility_manifest, "keep-me") != null);
    var empty_targets: usize = 0;
    for (global.get("reader_observations").?.array.items) |observation| {
        const row = observation.object;
        if (std.mem.eql(u8, row.get("option").?.string, "logtarget")) {
            const value = row.get("value").?.object;
            try testing.expectEqualStrings("explicit", value.get("presence").?.string);
            try testing.expectEqualStrings("", value.get("raw").?.string);
            empty_targets += 1;
        }
    }
    try testing.expectEqual(@as(usize, 2), empty_targets);
    var jails = try a.dupe(native.JailConfig, cfg.jails);
    jails[0].enabled = true;
    jails[0].compatibility_pending = false;
    cfg.jails = jails;
    try testing.expectError(error.CompatibilityNotAdmitted, native.validate(&cfg));
    const old_generation = manifest.object.get("config_generation").?.string;
    try tmp.dir.writeFile(.{ .sub_path = "global-common.conf", .data = "[Definition]\nsyslogsocket=changed\n" });
    _ = try importConfig(a, root, output);
    const changed = try native.Config.loadFile(a, output);
    const updated = try native.decodeCompatibilityManifest(a, changed.global.compatibility_manifest);
    try testing.expect(!std.mem.eql(u8, old_generation, updated.object.get("config_generation").?.string));
}

test "p2 global reader defaults retain phase and missing source identity" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(a, ".");
    const document = try fail2ban.prepareConfigDocument(a, root, "fail2ban");
    var ctx = Context{ .arena = a, .source_dir = root };
    const global = try prepareGlobalManifest(&ctx, &document);
    try testing.expect(!global.source_present);
    try testing.expectEqualStrings("absent-native-projection", global.admission);
    var targets: usize = 0;
    for (global.reader_observations) |row| {
        if (!std.mem.eql(u8, row.option, "logtarget")) continue;
        try testing.expectEqual(.absent, row.value.?.presence);
        const expected = if (std.mem.eql(u8, row.phase, "early")) "/var/log/fail2ban.log" else "STDERR";
        try testing.expectEqualStrings(expected, row.value.?.value.string);
        targets += 1;
    }
    try testing.expectEqual(@as(usize, 2), targets);
    var present_document = document;
    present_document.source = try fail2ban.parseIniSource(a, "global-held-out", "[Definition]\n[Thread]\n");
    const present = try prepareGlobalManifest(&ctx, &present_document);
    var omitted: usize = 0;
    for (present.reader_observations) |row| {
        if (std.mem.eql(u8, row.option, "dbmaxmatches") or std.mem.eql(u8, row.option, "stacksize")) {
            try testing.expectEqual(.omitted, row.reader_entry);
            omitted += 1;
        }
    }
    try testing.expectEqual(@as(usize, 2), omitted);
    present_document.source = try fail2ban.parseIniSource(a, "global-held-out", "[Definition]\ndbmaxmatches=invalid\n");
    const invalid = try prepareGlobalManifest(&ctx, &present_document);
    for (invalid.reader_observations) |row| {
        if (std.mem.eql(u8, row.option, "dbmaxmatches")) {
            try testing.expectEqual(.emitted, row.reader_entry);
            try testing.expectEqual(.reference_fallback, row.value.?.resolution);
        }
    }
}

test "migration structural roundtrip retains globals override masks and protected provenance" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const input = "[global]\nmetrics_enabled=false\nwebsocket_max_clients=29\non_no_backend=\"log-only\"\nfirewall=\"iptables\"\n[defaults]\nbantime_increment_factor=7\n[jails.original]\nfilter=\"sshd\"\nlogpath=[\"/original/with\\nnewline\", \"/original/tab\\tname\"]\nbantime_increment_enabled=true\n";
    var before = try native.Config.parse(a, input);
    before.global.compatibility_manifest = "{\"schema_version\":1,\"admission\":\"prepared\",\"unknown_scope\":{\"raw\":\"original\\nbytes\",\"origin\":{\"path\":\"source.local\",\"line\":7},\"effective\":\"\"}}";
    var buffer = std.ArrayList(u8).init(a);
    try renderToml(&before, buffer.writer());
    const after = try native.Config.parse(a, buffer.items);
    try testing.expectEqualStrings(try std.json.stringifyAlloc(a, before.global, .{}), try std.json.stringifyAlloc(a, after.global, .{}));
    try testing.expectEqualStrings(try std.json.stringifyAlloc(a, before.defaults, .{}), try std.json.stringifyAlloc(a, after.defaults, .{}));
    try testing.expectEqualStrings(try std.json.stringifyAlloc(a, before.jails, .{}), try std.json.stringifyAlloc(a, after.jails, .{}));
    try testing.expectEqual(@as(u8, 1), after.jails[0].bantime_increment_fields);
}

test {
    _ = source_plan;
    _ = filter_context;
}

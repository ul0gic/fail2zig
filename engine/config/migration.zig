// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const fail2ban = @import("fail2ban.zig");
const native = @import("native.zig");
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

    var ini = fail2ban.loadJailConfig(arena, source_dir) catch |err| switch (err) {
        error.FileNotFound, error.AccessDenied, error.ReadFailed => return err,
        else => |e| return e,
    };

    for (ini.warnings.items) |w| {
        try ctx.warn("{s}:{d}: {s}", .{ w.source, w.line, w.message });
    }

    var cfg = native.Config{};
    cfg.global = .{};
    cfg.defaults = try extractDefaults(&ctx, &ini);

    var jails = std.ArrayListUnmanaged(native.JailConfig){};
    errdefer jails.deinit(arena);

    var user_it = ini.userSections();
    while (user_it.next()) |sec| {
        const jail = translateJail(&ctx, sec, &ini) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => |e| return e,
        } orelse {
            ctx.report.jails_skipped += 1;
            continue;
        };
        try jails.append(arena, jail);
        ctx.report.jails_imported += 1;
        if (jail.enabled) ctx.report.jails_enabled += 1;
    }

    cfg.jails = try jails.toOwnedSlice(arena);

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
        if (parseDuration(v)) |d| out.bantime = d else {
            try ctx.warn("[DEFAULT].bantime = '{s}' could not be parsed; keeping fail2zig default", .{v});
        }
    }
    if (def_sec.get("findtime")) |v| {
        if (parseDuration(v)) |d| out.findtime = d else {
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
        if (parseDuration(v)) |d| {
            jail.findtime = d;
        } else {
            try ctx.warn("jail '{s}': findtime = '{s}' invalid", .{ sec.name, v });
        }
    }
    if (sec.get("bantime")) |v| {
        if (parseDuration(v)) |d| {
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

    return jail;
}

fn extractIncrement(ctx: *Context, sec: *const fail2ban.Section, base: native.BanTimeIncrement) Error!native.BanTimeIncrement {
    var incr = base;
    if (sec.get("bantime.increment")) |v| incr.enabled = parseBool(v);
    if (sec.get("bantime.factor")) |v| incr.multiplier = std.fmt.parseFloat(f64, std.mem.trim(u8, v, " \t")) catch return error.InvalidGeneratedConfig;
    if (sec.get("bantime.maxtime")) |v| incr.max_bantime = parseDuration(v) orelse return error.InvalidGeneratedConfig;
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
    const tmp_path = try std.fmt.allocPrint(arena, "{s}.tmp", .{output_path});

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

    const tmp_file = std.fs.cwd().createFile(tmp_path, .{ .mode = 0o600 }) catch return error.WriteFailed;
    {
        defer tmp_file.close();
        tmp_file.writeAll(buf.items) catch return error.WriteFailed;
    }
    std.fs.cwd().rename(tmp_path, output_path) catch return error.WriteFailed;
}

fn renderToml(cfg: *const native.Config, w: anytype) !void {
    try w.writeAll(
        \\# fail2zig configuration — generated by `fail2zig --import-config`.
        \\# Edit freely; re-import will overwrite.
        \\
        \\
    );

    try w.writeAll("[global]\n");
    try w.print("log_level = \"{s}\"\n", .{@tagName(cfg.global.log_level)});
    try writeQuoted(w, "pid_file", cfg.global.pid_file);
    try writeQuoted(w, "socket_path", cfg.global.socket_path);
    try writeQuoted(w, "state_file", cfg.global.state_file);
    try w.print("memory_ceiling_mb = {d}\n", .{cfg.global.memory_ceiling_mb});
    try writeQuoted(w, "metrics_bind", cfg.global.metrics_bind);
    try w.print("metrics_port = {d}\n", .{cfg.global.metrics_port});
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
        if (j.filter.len > 0) try writeQuoted(w, "filter", j.filter);
        if (j.logpath.len > 0) try writeStringArray(w, "logpath", j.logpath);
        if (j.source != .auto) try w.print("source = \"{s}\"\n", .{@tagName(j.source)});
        if (j.maxretry) |v| try w.print("maxretry = {d}\n", .{v});
        if (j.findtime) |v| try w.print("findtime = {d}\n", .{v});
        if (j.bantime) |v| try w.print("bantime = {d}\n", .{v});
        if (j.banaction) |v| try w.print("banaction = \"{s}\"\n", .{@tagName(v)});
        if (j.ignoreip) |list| try writeStringArray(w, "ignoreip", list);
        if (j.bantime_increment_explicit) try writeIncrement(w, j.bantime_increment);
        try w.writeAll("\n");
    }
}

fn writeIncrement(w: anytype, incr: native.BanTimeIncrement) !void {
    try w.print("bantime_increment_enabled = {s}\n", .{if (incr.enabled) "true" else "false"});
    try w.print("bantime_increment_multiplier = {d}\n", .{incr.multiplier});
    try w.print("bantime_increment_factor = {d}\n", .{incr.factor});
    try w.print("bantime_increment_formula = \"{s}\"\n", .{@tagName(incr.formula)});
    try w.print("bantime_increment_max_bantime = {d}\n", .{incr.max_bantime});
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
    try testing.expect(std.mem.indexOf(u8, toml, "backend") == null);

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
            "[{s}]\nbantime.maxtime = {d}m\n[sshd]\nenabled = true\nfilter = sshd\n",
            .{ section, invalid_minutes },
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

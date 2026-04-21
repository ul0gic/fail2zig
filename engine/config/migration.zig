//! fail2ban → fail2zig migration tool.
//!
//! Reads a fail2ban config directory (jail.conf + jail.local + jail.d/
//! + filter.d/*.conf) and produces an equivalent fail2zig native TOML
//! config, emitting a MigrationReport that summarizes what was
//! translated, what was skipped, and every warning encountered along
//! the way.
//!
//! Design notes:
//!   * Filters listed by name (`filter = sshd`) are resolved first
//!     against the built-in filter registry; any name not found there
//!     is attempted as a user filter via `filter.d/<name>.conf`.
//!     Either path succeeding marks the jail as viable.
//!   * Unknown backends / action names map to `.log-only` with a
//!     warning — the operator still sees the ban decision in the log
//!     and can iterate.
//!   * Output is always written, even when no jails are viable, so
//!     operators can see the skeleton and diff against their expected
//!     layout. Zero-jail imports exit with code 1 at the CLI layer.
//!   * All allocations flow through a caller-provided arena. The arena
//!     outlives the `MigrationReport` — every slice in the report
//!     (warnings, output_path) points into it.

const std = @import("std");
const fail2ban = @import("fail2ban.zig");
const native = @import("native.zig");
const registry = @import("../filters/registry.zig");

// ============================================================================
// Public error set
// ============================================================================

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
};

// ============================================================================
// MigrationReport
// ============================================================================

/// Summary of the migration outcome. String slices inside `warnings`
/// and `output_path` live in the arena supplied to `importConfig`.
pub const MigrationReport = struct {
    jails_imported: u32 = 0,
    jails_skipped: u32 = 0,
    filters_translated: u32 = 0,
    filters_builtin: u32 = 0,
    filters_skipped: u32 = 0,
    warnings: []const []const u8 = &.{},
    output_path: []const u8 = "",
};

/// Pretty-print the migration report to `writer`. One line of summary,
/// then any warnings indented beneath.
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
        for (report.warnings) |w| {
            try writer.print("  - {s}\n", .{w});
        }
    }
}

// ============================================================================
// Internal context
// ============================================================================

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

// ============================================================================
// Public entry point
// ============================================================================

/// Run the migration. `source_dir` is the fail2ban config root (e.g.
/// `/etc/fail2ban`). `output_path` is the file to write the native TOML
/// config into (atomic write: tmp file + rename). `arena` must outlive
/// the returned report.
pub fn importConfig(
    arena: std.mem.Allocator,
    source_dir: []const u8,
    output_path: []const u8,
) Error!MigrationReport {
    var ctx = Context{ .arena = arena, .source_dir = source_dir };

    // Load the merged jail tree (jail.conf + jail.local + jail.d/*).
    var ini = fail2ban.loadJailConfig(arena, source_dir) catch |err| switch (err) {
        error.FileNotFound, error.AccessDenied, error.ReadFailed => return err,
        else => |e| return e,
    };

    // Carry forward any warnings generated during INI parse/interpolation.
    for (ini.warnings.items) |w| {
        try ctx.warn("{s}:{d}: {s}", .{ w.source, w.line, w.message });
    }

    // Build a native Config shell.
    var cfg = native.Config{};
    cfg.global = .{};
    cfg.defaults = try extractDefaults(&ctx, &ini);

    // Translate each non-DEFAULT section into a JailConfig.
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
    }

    cfg.jails = try jails.toOwnedSlice(arena);

    // Validate the native config. Warnings on validation failure, but
    // we still write the output so the operator can fix up manually.
    native.validate(&cfg) catch |err| {
        try ctx.warn(
            "generated config failed validation: {s} — review the TOML before starting the daemon",
            .{@errorName(err)},
        );
    };

    // Write the TOML.
    try writeTomlAtomic(arena, &cfg, output_path);

    ctx.report.warnings = try ctx.warnings.toOwnedSlice(arena);
    ctx.report.output_path = try arena.dupe(u8, output_path);
    return ctx.report;
}

// ============================================================================
// Defaults extraction
// ============================================================================

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

    return out;
}

// ============================================================================
// Jail translation
// ============================================================================

fn translateJail(
    ctx: *Context,
    sec: *fail2ban.Section,
    _: *fail2ban.ParsedIni,
) Error!?native.JailConfig {
    // Honor `enabled = false` — skip entirely.
    if (sec.get("enabled")) |v| {
        if (!parseBool(v)) return null;
    } else {
        // fail2ban defaults enabled to false unless explicitly set in
        // jail.local or DEFAULT. We mirror that — a jail that doesn't
        // say enabled=true gets imported BUT marked disabled, so the
        // operator can diff against fail2zig's native enabled-by-default
        // posture and decide.
    }

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

    if (sec.get("filter")) |v| {
        const trimmed = std.mem.trim(u8, v, " \t");
        if (trimmed.len == 0) {
            try ctx.warn("jail '{s}': empty filter name", .{sec.name});
            ctx.report.filters_skipped += 1;
        } else if (resolveFilter(ctx, trimmed)) |kind| {
            switch (kind) {
                .builtin => ctx.report.filters_builtin += 1,
                .translated => ctx.report.filters_translated += 1,
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

    // bantime.increment (fail2ban) → bantime_increment (fail2zig)
    if (sec.get("bantime.increment")) |v| {
        jail.bantime_increment.enabled = parseBool(v);
    }
    if (sec.get("bantime.factor")) |v| {
        if (std.fmt.parseFloat(f64, std.mem.trim(u8, v, " \t"))) |f| {
            jail.bantime_increment.factor = f;
        } else |_| {
            try ctx.warn("jail '{s}': bantime.factor = '{s}' invalid", .{ sec.name, v });
        }
    }
    if (sec.get("bantime.multipliers")) |_| {
        try ctx.warn("jail '{s}': bantime.multipliers is not supported; falling back to linear multiplier", .{sec.name});
    }
    if (sec.get("bantime.maxtime")) |v| {
        if (parseDuration(v)) |d| {
            jail.bantime_increment.max_bantime = d;
        } else {
            try ctx.warn("jail '{s}': bantime.maxtime = '{s}' invalid", .{ sec.name, v });
        }
    }

    return jail;
}

const FilterResolution = enum { builtin, translated };

/// Resolve a filter name: built-in first, then `filter.d/<name>.conf`.
fn resolveFilter(ctx: *Context, name: []const u8) ?FilterResolution {
    if (registry.get(name) != null) return .builtin;

    // Try filter.d/<name>.conf.
    const sub_path = std.fmt.allocPrint(ctx.arena, "filter.d/{s}.conf", .{name}) catch return null;
    const full = std.fs.path.join(ctx.arena, &[_][]const u8{ ctx.source_dir, sub_path }) catch return null;

    const f = fail2ban.parseFilterFile(ctx.arena, full) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => {
            ctx.warn("filter '{s}': parse error {s}; skipping", .{ name, @errorName(err) }) catch return null;
            return null;
        },
    };

    if (f.failregex.len == 0) {
        ctx.warn("filter '{s}': no translatable failregex patterns; skipping", .{name}) catch {};
        for (f.warnings) |w| {
            ctx.warn("  filter '{s}' warning: {s}", .{ name, w.message }) catch {};
        }
        return null;
    }

    // Log a one-line summary of what was translated.
    ctx.warn("filter '{s}': translated {d} pattern(s) from filter.d/{s}.conf", .{ name, f.failregex.len, name }) catch {};
    return .translated;
}

// ============================================================================
// Value helpers
// ============================================================================

/// Parse a fail2ban duration (integer seconds, or suffixed form like
/// `10m`, `1h`, `1d`, `1w`). Returns null on parse failure.
pub fn parseDuration(raw: []const u8) ?u64 {
    const trimmed = std.mem.trim(u8, raw, " \t");
    if (trimmed.len == 0) return null;

    // Split numeric prefix from optional suffix.
    var split: usize = 0;
    while (split < trimmed.len) : (split += 1) {
        const c = trimmed[split];
        if (c < '0' or c > '9') break;
    }
    if (split == 0) return null;
    const n = std.fmt.parseInt(u64, trimmed[0..split], 10) catch return null;

    const rest = std.mem.trim(u8, trimmed[split..], " \t");
    if (rest.len == 0) return n;

    // Support both single-letter and word suffixes (s, m, h, d, w, mo,
    // y). fail2ban's docs call out these forms explicitly.
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
            return n * u.mul;
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
    // fail2ban's logpath is typically newline-separated (multi-line
    // value) but some filters use whitespace. Honor both.
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

fn mapBanaction(ctx: *Context, raw: []const u8) native.BanAction {
    const trimmed = std.mem.trim(u8, raw, " \t");
    // fail2ban often uses `action[param=...]` syntax. Strip the bracket
    // portion for mapping purposes.
    const bracket_idx = std.mem.indexOfScalar(u8, trimmed, '[') orelse trimmed.len;
    const name = std.mem.trim(u8, trimmed[0..bracket_idx], " \t");

    if (std.mem.startsWith(u8, name, "nftables")) return .nftables;
    if (std.mem.startsWith(u8, name, "iptables")) return .iptables;
    if (std.mem.startsWith(u8, name, "ipset")) return .ipset;

    ctx.warn("action '{s}' not recognized; mapped to log-only (edit the TOML to override)", .{name}) catch {};
    return .@"log-only";
}

// ============================================================================
// TOML writer (native-config subset)
// ============================================================================

fn writeTomlAtomic(
    arena: std.mem.Allocator,
    cfg: *const native.Config,
    output_path: []const u8,
) Error!void {
    const tmp_path = try std.fmt.allocPrint(arena, "{s}.tmp", .{output_path});

    // Ensure parent directory exists.
    if (std.fs.path.dirname(output_path)) |parent| {
        std.fs.cwd().makePath(parent) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return error.WriteFailed,
        };
    }

    // Render into a buffer so any error aborts before we touch disk.
    var buf = std.ArrayListUnmanaged(u8){};
    defer buf.deinit(arena);
    const w = buf.writer(arena);
    try renderToml(cfg, w);

    // Atomic write: tmp file + rename.
    const tmp_file = std.fs.cwd().createFile(tmp_path, .{ .mode = 0o644 }) catch return error.WriteFailed;
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

    // [global]
    try w.writeAll("[global]\n");
    try w.print("log_level = \"{s}\"\n", .{@tagName(cfg.global.log_level)});
    try writeQuoted(w, "pid_file", cfg.global.pid_file);
    try writeQuoted(w, "socket_path", cfg.global.socket_path);
    try writeQuoted(w, "state_file", cfg.global.state_file);
    try w.print("memory_ceiling_mb = {d}\n", .{cfg.global.memory_ceiling_mb});
    try writeQuoted(w, "metrics_bind", cfg.global.metrics_bind);
    try w.print("metrics_port = {d}\n", .{cfg.global.metrics_port});
    try w.writeAll("\n");

    // [defaults]
    try w.writeAll("[defaults]\n");
    try w.print("bantime = {d}\n", .{cfg.defaults.bantime});
    try w.print("findtime = {d}\n", .{cfg.defaults.findtime});
    try w.print("maxretry = {d}\n", .{cfg.defaults.maxretry});
    try w.print("banaction = \"{s}\"\n", .{@tagName(cfg.defaults.banaction)});
    if (cfg.defaults.ignoreip.len > 0) {
        try writeStringArray(w, "ignoreip", cfg.defaults.ignoreip);
    }
    try w.writeAll("\n");

    // [jails.*]
    for (cfg.jails) |j| {
        try w.print("[jails.{s}]\n", .{j.name});
        try w.print("enabled = {s}\n", .{if (j.enabled) "true" else "false"});
        if (j.filter.len > 0) try writeQuoted(w, "filter", j.filter);
        if (j.logpath.len > 0) try writeStringArray(w, "logpath", j.logpath);
        if (j.maxretry) |v| try w.print("maxretry = {d}\n", .{v});
        if (j.findtime) |v| try w.print("findtime = {d}\n", .{v});
        if (j.bantime) |v| try w.print("bantime = {d}\n", .{v});
        if (j.banaction) |v| try w.print("banaction = \"{s}\"\n", .{@tagName(v)});
        if (j.ignoreip) |list| if (list.len > 0) try writeStringArray(w, "ignoreip", list);
        if (j.bantime_increment.enabled) {
            try w.writeAll("bantime_increment_enabled = true\n");
            try w.print("bantime_increment_formula = \"{s}\"\n", .{@tagName(j.bantime_increment.formula)});
            try w.print("bantime_increment_max_bantime = {d}\n", .{j.bantime_increment.max_bantime});
        }
        try w.writeAll("\n");
    }
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

// ============================================================================
// Tests
// ============================================================================

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

    // Build a mock fail2ban config tree.
    try tmp.dir.writeFile(.{
        .sub_path = "jail.conf",
        .data =
        \\[DEFAULT]
        \\bantime = 600
        \\findtime = 600
        \\maxretry = 5
        \\ignoreip = 127.0.0.1/8 10.0.0.0/8
        \\
        \\[sshd]
        \\enabled = true
        \\filter = sshd
        \\logpath = /var/log/auth.log
        \\maxretry = 3
        \\bantime = 1h
        \\
        \\[nginx-http-auth]
        \\enabled = true
        \\filter = nginx-http-auth
        \\logpath = /var/log/nginx/error.log
        ,
    });

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const source = try tmp.dir.realpathAlloc(arena.allocator(), ".");
    const out = try std.fs.path.join(arena.allocator(), &.{ source, "out.toml" });

    const report = try importConfig(arena.allocator(), source, out);
    try testing.expectEqual(@as(u32, 2), report.jails_imported);
    try testing.expect(report.filters_builtin >= 2);

    // Reload the emitted TOML through the native parser and assert it's valid.
    var arena2 = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena2.deinit();
    const cfg = try native.Config.loadFile(arena2.allocator(), out);
    try testing.expectEqual(@as(usize, 2), cfg.jails.len);

    // Find sshd jail and verify translated values.
    var sshd_jail: ?native.JailConfig = null;
    for (cfg.jails) |j| {
        if (std.mem.eql(u8, j.name, "sshd")) sshd_jail = j;
    }
    try testing.expect(sshd_jail != null);
    try testing.expectEqualStrings("sshd", sshd_jail.?.filter);
    try testing.expectEqual(@as(?u32, 3), sshd_jail.?.maxretry);
    try testing.expectEqual(@as(?u64, 3600), sshd_jail.?.bantime);
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
    // The jail still appears — but disabled, and with a warning.
    try testing.expectEqual(@as(u32, 1), report.filters_skipped);
    var found_filter_warning = false;
    for (report.warnings) |w| {
        if (std.mem.indexOf(u8, w, "nonexistent-filter") != null) found_filter_warning = true;
    }
    try testing.expect(found_filter_warning);

    // Output exists and parses cleanly.
    var arena2 = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena2.deinit();
    const cfg = try native.Config.loadFile(arena2.allocator(), out);
    try testing.expectEqual(@as(usize, 1), cfg.jails.len);
    // Because the filter was unresolvable, the jail was forced off.
    try testing.expect(!cfg.jails[0].enabled);
}

test "migration: translates user filter from filter.d/*.conf" {
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
    try testing.expectEqual(@as(u32, 1), report.filters_translated);
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

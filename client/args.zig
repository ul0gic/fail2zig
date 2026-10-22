// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const shared = @import("shared");
const format = @import("format.zig");

pub const default_socket_path: []const u8 = "/run/fail2zig/fail2zig.sock";
pub const default_timeout_ms: u64 = 5000;

pub const OutputFormat = enum {
    table,
    json,
    plain,

    pub fn fromString(s: []const u8) ?OutputFormat {
        if (std.mem.eql(u8, s, "table")) return .table;
        if (std.mem.eql(u8, s, "json")) return .json;
        if (std.mem.eql(u8, s, "plain")) return .plain;
        return null;
    }
};

pub const Shell = enum {
    bash,
    zsh,
    fish,

    pub fn fromString(s: []const u8) ?Shell {
        if (std.mem.eql(u8, s, "bash")) return .bash;
        if (std.mem.eql(u8, s, "zsh")) return .zsh;
        if (std.mem.eql(u8, s, "fish")) return .fish;
        return null;
    }
};

pub const Command = union(enum) {
    help: ?[]const u8,
    version: void,
    status: DetailArgs,
    stats: DetailArgs,
    ban: BanArgs,
    unban: UnbanArgs,
    list: ListArgs,
    jails: DetailArgs,
    reload: void,
    remote_version: void,
    completions: Shell,
    config: void,
    history: HistoryArgs,
    firewall: FirewallArgs,
    firewall_withdraw: void,
    jail_admin: JailAdminArgs,
    history_reset: HistoryResetArgs,
    ignore: IgnoreArgs,
    diag_clock: DiagClockArgs,

    pub const ScopeKind = enum { host, net };
    pub const ScopeArgs = struct {
        kind: ScopeKind,
        cidr: ?[]const u8 = null,
    };

    pub const BanArgs = struct {
        ip: []const u8,
        jail: ?[]const u8 = null,
        duration_s: ?u64 = null,
        scope: ?ScopeArgs = null,
        force: bool = false,
    };

    pub const UnbanArgs = struct {
        ip: []const u8,
        jail: ?[]const u8 = null,
        scope: ?ScopeArgs = null,
    };

    pub const JailAction = enum { enable, disable, pause, @"resume" };
    pub const JailAdminArgs = struct {
        action: JailAction,
        name: []const u8,
    };

    pub const HistoryResetArgs = struct {
        address: []const u8,
        jail: ?[]const u8 = null,
        all: bool = false,
    };

    pub const IgnoreAction = enum { add, remove, list };
    pub const IgnoreArgs = struct {
        action: IgnoreAction,
        address: ?[]const u8 = null,
        jail: ?[]const u8 = null,
        unban: bool = false,
        for_s: ?u64 = null,
    };

    pub const ListArgs = struct {
        jail: ?[]const u8 = null,
        details: bool = false,
        sort: bool = false,
        origin: ?shared.types.Origin = null,
    };

    pub const DetailArgs = struct { details: bool = false };

    pub const DiagClockAction = enum { show, rate, advance };
    pub const DiagClockArgs = union(DiagClockAction) {
        show: void,
        rate: u32,
        advance: u64,
    };

    pub const HistoryArgs = struct {
        jail: ?[]const u8 = null,
        limit: ?u32 = null,
        cursor: ?[]const u8 = null,
    };

    pub const FirewallArgs = struct {
        limit: ?u32 = null,
        cursor: ?[]const u8 = null,
        details: bool = false,
    };
};

pub const Globals = struct {
    socket_path: []const u8 = default_socket_path,
    output: OutputFormat = .table,
    color: bool = true,
    timeout_ms: u64 = default_timeout_ms,
};

pub const Parsed = struct {
    globals: Globals,
    command: Command,
};

pub const Error = error{
    UnknownCommand,
    UnknownFlag,
    MissingValue,
    MissingCommand,
    MissingArgument,
    InvalidValue,
    TooManyArguments,
};

pub const ParseDiag = struct {
    buf: [256]u8 = [_]u8{0} ** 256,
    len: usize = 0,

    pub fn message(self: *const ParseDiag) []const u8 {
        return self.buf[0..self.len];
    }

    fn set(self: *ParseDiag, comptime fmt: []const u8, args: anytype) void {
        const slice = std.fmt.bufPrint(&self.buf, fmt, args) catch {
            const trunc = "error message truncated";
            @memcpy(self.buf[0..trunc.len], trunc);
            self.len = trunc.len;
            return;
        };
        self.len = slice.len;
    }
};

pub fn parse(argv: []const []const u8, diag: *ParseDiag) Error!Parsed {
    var globals = Globals{};
    var i: usize = 0;

    while (i < argv.len) : (i += 1) {
        const a = argv[i];
        if (a.len == 0) continue;
        if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) {
            return Parsed{ .globals = globals, .command = .{ .help = null } };
        }
        if (std.mem.eql(u8, a, "--version") or std.mem.eql(u8, a, "-V")) {
            return Parsed{ .globals = globals, .command = .version };
        }
        if (std.mem.eql(u8, a, "--socket")) {
            i += 1;
            if (i >= argv.len) {
                diag.set("flag --socket requires a value (path to Unix socket)", .{});
                return error.MissingValue;
            }
            globals.socket_path = argv[i];
            continue;
        }
        if (std.mem.eql(u8, a, "--output")) {
            i += 1;
            if (i >= argv.len) {
                diag.set("flag --output requires a value: table, json, or plain", .{});
                return error.MissingValue;
            }
            globals.output = OutputFormat.fromString(argv[i]) orelse {
                diag.set("invalid --output value '{s}' (expected: table, json, plain)", .{argv[i]});
                return error.InvalidValue;
            };
            continue;
        }
        if (std.mem.eql(u8, a, "--no-color")) {
            globals.color = false;
            continue;
        }
        if (std.mem.eql(u8, a, "--timeout")) {
            i += 1;
            if (i >= argv.len) {
                diag.set("flag --timeout requires a value (milliseconds)", .{});
                return error.MissingValue;
            }
            globals.timeout_ms = std.fmt.parseInt(u64, argv[i], 10) catch {
                diag.set("invalid --timeout value '{s}' (expected positive integer ms)", .{argv[i]});
                return error.InvalidValue;
            };
            continue;
        }
        break;
    }

    if (i >= argv.len) {
        diag.set("no command given (try 'fail2zig --help')", .{});
        return error.MissingCommand;
    }

    const cmd_str = argv[i];
    i += 1;
    const rest = argv[i..];

    for (rest) |a| if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) {
        return Parsed{ .globals = globals, .command = .{ .help = cmd_str } };
    };

    if (std.mem.eql(u8, cmd_str, "status")) {
        return parseDetailsOnly(rest, "status", &globals, diag, .status);
    }
    if (std.mem.eql(u8, cmd_str, "stats")) {
        return parseDetailsOnly(rest, "stats", &globals, diag, .stats);
    }
    if (std.mem.eql(u8, cmd_str, "jails")) {
        return parseDetailsOnly(rest, "jails", &globals, diag, .jails);
    }
    if (std.mem.eql(u8, cmd_str, "reload")) {
        try expectNoPositional(rest, "reload", diag, &globals);
        return Parsed{ .globals = globals, .command = .reload };
    }
    if (std.mem.eql(u8, cmd_str, "version")) {
        try expectNoPositional(rest, "version", diag, &globals);
        return Parsed{ .globals = globals, .command = .remote_version };
    }
    if (std.mem.eql(u8, cmd_str, "config")) {
        try expectNoPositional(rest, "config", diag, &globals);
        return Parsed{ .globals = globals, .command = .config };
    }
    if (std.mem.eql(u8, cmd_str, "history")) {
        if (rest.len > 0 and std.mem.eql(u8, rest[0], "reset")) return parseHistoryReset(rest[1..], &globals, diag);
        return parseHistory(rest, &globals, diag);
    }
    if (std.mem.eql(u8, cmd_str, "firewall")) {
        return parseFirewall(rest, &globals, diag);
    }
    if (std.mem.eql(u8, cmd_str, "jail")) {
        return parseJailAdmin(rest, &globals, diag);
    }
    if (std.mem.eql(u8, cmd_str, "help")) {
        const topic: ?[]const u8 = if (rest.len > 0) rest[0] else null;
        return Parsed{ .globals = globals, .command = .{ .help = topic } };
    }
    if (std.mem.eql(u8, cmd_str, "ban")) {
        return parseBan(rest, &globals, diag);
    }
    if (std.mem.eql(u8, cmd_str, "unban")) {
        return parseUnban(rest, &globals, diag);
    }
    if (std.mem.eql(u8, cmd_str, "ignore")) {
        return parseIgnore(rest, &globals, diag);
    }
    if (std.mem.eql(u8, cmd_str, "diag")) {
        return parseDiagClock(rest, &globals, diag);
    }
    if (std.mem.eql(u8, cmd_str, "list")) {
        return parseList(rest, &globals, diag);
    }
    if (std.mem.eql(u8, cmd_str, "completions")) {
        return parseCompletions(rest, &globals, diag);
    }

    const suggestion = closestCommand(cmd_str);
    if (suggestion) |s| {
        diag.set("unknown command '{s}' (did you mean '{s}'?)", .{ cmd_str, s });
    } else {
        diag.set("unknown command '{s}' (try 'fail2zig --help')", .{cmd_str});
    }
    return error.UnknownCommand;
}

fn parseDetailsOnly(rest: []const []const u8, cmd: []const u8, globals: *Globals, diag: *ParseDiag, comptime tag: enum { status, stats, jails }) Error!Parsed {
    var detail = Command.DetailArgs{};
    var k: usize = 0;
    while (k < rest.len) : (k += 1) {
        const a = rest[k];
        if (try takeTrailingGlobal(a, rest, &k, globals, diag)) continue;
        if (std.mem.eql(u8, a, "--details")) {
            detail.details = true;
            continue;
        }
        if (std.mem.startsWith(u8, a, "--")) {
            diag.set("unknown flag for '{s}': {s}", .{ cmd, a });
            return error.UnknownFlag;
        }
        diag.set("command '{s}' takes no arguments, got '{s}'", .{ cmd, a });
        return error.TooManyArguments;
    }
    return Parsed{ .globals = globals.*, .command = @unionInit(Command, @tagName(tag), detail) };
}

fn expectNoPositional(rest: []const []const u8, cmd: []const u8, diag: *ParseDiag, globals: *Globals) Error!void {
    var k: usize = 0;
    while (k < rest.len) : (k += 1) {
        const a = rest[k];
        if (try takeTrailingGlobal(a, rest, &k, globals, diag)) continue;
        if (std.mem.startsWith(u8, a, "--")) {
            diag.set("unknown flag for '{s}': {s}", .{ cmd, a });
            return error.UnknownFlag;
        }
        diag.set("command '{s}' takes no arguments, got '{s}'", .{ cmd, a });
        return error.TooManyArguments;
    }
}

fn parseBan(rest: []const []const u8, globals: *Globals, diag: *ParseDiag) Error!Parsed {
    var args = Command.BanArgs{ .ip = "" };
    var have_ip = false;
    var k: usize = 0;
    while (k < rest.len) : (k += 1) {
        const a = rest[k];
        if (try takeTrailingGlobal(a, rest, &k, globals, diag)) continue;
        if (std.mem.eql(u8, a, "--jail")) {
            k += 1;
            if (k >= rest.len) {
                diag.set("flag --jail requires a value (jail name)", .{});
                return error.MissingValue;
            }
            args.jail = rest[k];
            continue;
        }
        if (std.mem.eql(u8, a, "--duration")) {
            k += 1;
            if (k >= rest.len) {
                diag.set("flag --duration requires a value (seconds, or a duration such as 2m or 1h30m)", .{});
                return error.MissingValue;
            }
            args.duration_s = parseForSeconds(rest[k]) orelse {
                diag.set("invalid --duration value '{s}' (expected seconds, or a duration such as 2m or 1h30m)", .{rest[k]});
                return error.InvalidValue;
            };
            continue;
        }
        if (std.mem.eql(u8, a, "--scope")) {
            args.scope = try parseScope(rest, &k, diag);
            continue;
        }
        if (std.mem.eql(u8, a, "--force")) {
            args.force = true;
            continue;
        }
        if (std.mem.startsWith(u8, a, "--")) {
            diag.set("unknown flag for 'ban': {s}", .{a});
            return error.UnknownFlag;
        }
        if (!have_ip) {
            args.ip = a;
            have_ip = true;
            continue;
        }
        diag.set("command 'ban' takes one IP argument, got extra '{s}'", .{a});
        return error.TooManyArguments;
    }
    if (!have_ip) {
        diag.set("command 'ban' requires an IP address (usage: ban <ip> --jail <name> [--duration <s>] [--scope host|net <cidr>] [--force])", .{});
        return error.MissingArgument;
    }
    if (args.jail == null) {
        diag.set("command 'ban' requires --jail <name>", .{});
        return error.MissingArgument;
    }
    return Parsed{ .globals = globals.*, .command = .{ .ban = args } };
}

fn parseUnban(rest: []const []const u8, globals: *Globals, diag: *ParseDiag) Error!Parsed {
    var args = Command.UnbanArgs{ .ip = "" };
    var have_ip = false;
    var k: usize = 0;
    while (k < rest.len) : (k += 1) {
        const a = rest[k];
        if (try takeTrailingGlobal(a, rest, &k, globals, diag)) continue;
        if (std.mem.eql(u8, a, "--jail")) {
            k += 1;
            if (k >= rest.len) {
                diag.set("flag --jail requires a value (jail name)", .{});
                return error.MissingValue;
            }
            args.jail = rest[k];
            continue;
        }
        if (std.mem.eql(u8, a, "--scope")) {
            args.scope = try parseScope(rest, &k, diag);
            continue;
        }
        if (std.mem.startsWith(u8, a, "--")) {
            diag.set("unknown flag for 'unban': {s}", .{a});
            return error.UnknownFlag;
        }
        if (!have_ip) {
            args.ip = a;
            have_ip = true;
            continue;
        }
        diag.set("command 'unban' takes one IP argument, got extra '{s}'", .{a});
        return error.TooManyArguments;
    }
    if (!have_ip) {
        diag.set("command 'unban' requires an IP address (usage: unban <ip> --jail <name> [--scope host|net <cidr>])", .{});
        return error.MissingArgument;
    }
    if (args.jail == null) {
        diag.set("command 'unban' requires --jail <name>", .{});
        return error.MissingArgument;
    }
    return Parsed{ .globals = globals.*, .command = .{ .unban = args } };
}

const diag_clock_usage = "diag clock show | diag clock rate <0..1000> | diag clock advance <seconds>";
const max_diag_rate: u32 = 1000;
const max_diag_advance_s: u64 = 366 * std.time.s_per_day;

fn parseDiagClock(rest: []const []const u8, globals: *Globals, diag: *ParseDiag) Error!Parsed {
    var echo: [format.diagnostic_max_bytes]u8 = undefined;
    var words: [3][]const u8 = undefined;
    var count: usize = 0;
    var k: usize = 0;
    while (k < rest.len) : (k += 1) {
        const a = rest[k];
        if (try takeTrailingGlobal(a, rest, &k, globals, diag)) continue;
        if (std.mem.startsWith(u8, a, "--")) {
            diag.set("unknown flag for 'diag': {s}", .{format.escapeArgument(&echo, a)});
            return error.UnknownFlag;
        }
        if (count == words.len) {
            diag.set("too many arguments for 'diag' (usage: {s})", .{diag_clock_usage});
            return error.TooManyArguments;
        }
        words[count] = a;
        count += 1;
    }
    if (count < 2 or !std.mem.eql(u8, words[0], "clock")) {
        diag.set("command 'diag' requires a clock subcommand (usage: {s})", .{diag_clock_usage});
        return error.MissingArgument;
    }
    const action = std.meta.stringToEnum(Command.DiagClockAction, words[1]) orelse {
        diag.set("unknown diag clock subcommand '{s}' (expected: show, rate, advance)", .{format.escapeArgument(&echo, words[1])});
        return error.InvalidValue;
    };
    const args: Command.DiagClockArgs = switch (action) {
        .show => blk: {
            if (count != 2) {
                diag.set("command 'diag clock show' takes no arguments", .{});
                return error.TooManyArguments;
            }
            break :blk .show;
        },
        .rate, .advance => blk: {
            if (count != 3) {
                diag.set("command 'diag clock {s}' requires one value (usage: {s})", .{ @tagName(action), diag_clock_usage });
                return error.MissingArgument;
            }
            if (action == .rate) {
                const value: ?u32 = std.fmt.parseInt(u32, words[2], 10) catch null;
                if (value == null or value.? > max_diag_rate) {
                    diag.set("invalid rate '{s}' (expected integer 0..1000)", .{format.escapeArgument(&echo, words[2])});
                    return error.InvalidValue;
                }
                break :blk .{ .rate = value.? };
            }
            const seconds: ?u64 = std.fmt.parseInt(u64, words[2], 10) catch null;
            if (seconds == null or seconds.? == 0 or seconds.? > max_diag_advance_s) {
                diag.set("invalid advance '{s}' (expected positive integer seconds up to 366 days)", .{format.escapeArgument(&echo, words[2])});
                return error.InvalidValue;
            }
            break :blk .{ .advance = seconds.? };
        },
    };
    return Parsed{ .globals = globals.*, .command = .{ .diag_clock = args } };
}

fn parseIgnore(rest: []const []const u8, globals: *Globals, diag: *ParseDiag) Error!Parsed {
    var echo: [format.diagnostic_max_bytes]u8 = undefined;
    var action: ?Command.IgnoreAction = null;
    var k: usize = 0;
    while (k < rest.len) : (k += 1) {
        const a = rest[k];
        if (try takeTrailingGlobal(a, rest, &k, globals, diag)) continue;
        if (std.mem.startsWith(u8, a, "--")) break;
        action = std.meta.stringToEnum(Command.IgnoreAction, a) orelse {
            diag.set("unknown ignore subcommand '{s}' (expected: add, remove, list)", .{format.escapeArgument(&echo, a)});
            return error.InvalidValue;
        };
        k += 1;
        break;
    }
    const chosen = action orelse {
        diag.set("command 'ignore' requires a subcommand: add, remove or list", .{});
        return error.MissingArgument;
    };
    const name = @tagName(chosen);

    var out = Command.IgnoreArgs{ .action = chosen };
    while (k < rest.len) : (k += 1) {
        const a = rest[k];
        if (try takeTrailingGlobal(a, rest, &k, globals, diag)) continue;
        if (std.mem.eql(u8, a, "--jail")) {
            k += 1;
            if (k >= rest.len) {
                diag.set("flag --jail requires a value (jail name)", .{});
                return error.MissingValue;
            }
            out.jail = rest[k];
            continue;
        }
        if (chosen == .add and std.mem.eql(u8, a, "--unban")) {
            out.unban = true;
            continue;
        }
        if (chosen == .add and std.mem.eql(u8, a, "--for")) {
            k += 1;
            if (k >= rest.len) {
                diag.set("flag --for requires a value (a duration such as 2m or 1h30m)", .{});
                return error.MissingValue;
            }
            out.for_s = parseForSeconds(rest[k]) orelse {
                diag.set("invalid --for value '{s}' (expected a duration such as 2m or 1h30m)", .{format.escapeArgument(&echo, rest[k])});
                return error.InvalidValue;
            };
            continue;
        }
        if (std.mem.startsWith(u8, a, "--")) {
            diag.set("unknown flag for 'ignore {s}': {s}", .{ name, format.escapeArgument(&echo, a) });
            return error.UnknownFlag;
        }
        if (chosen == .list) {
            diag.set("command 'ignore list' takes no arguments, got '{s}'", .{format.escapeArgument(&echo, a)});
            return error.TooManyArguments;
        }
        if (out.address == null) {
            out.address = a;
            continue;
        }
        diag.set("command 'ignore {s}' takes one address argument, got extra '{s}'", .{ name, format.escapeArgument(&echo, a) });
        return error.TooManyArguments;
    }
    if (chosen == .list) return Parsed{ .globals = globals.*, .command = .{ .ignore = out } };

    const address = out.address orelse {
        const usage = if (chosen == .add) "ignore add <address|cidr> --jail <name> [--unban] [--for <duration>]" else "ignore remove <address|cidr> --jail <name>";
        diag.set("command 'ignore {s}' requires an address (usage: {s})", .{ name, usage });
        return error.MissingArgument;
    };
    if (out.jail == null) {
        diag.set("command 'ignore {s}' requires --jail <name>", .{name});
        return error.MissingArgument;
    }
    _ = shared.types.IgnoreEntry.parse(address) catch |err| {
        switch (err) {
            error.InvalidAddress => diag.set("invalid address '{s}' for 'ignore {s}': expected an IPv4 or IPv6 address or CIDR such as 192.0.2.10 or 2001:db8::/32", .{ format.escapeArgument(&echo, address), name }),
            error.InvalidPrefix => diag.set("invalid prefix in '{s}': IPv4 prefixes are 0-32, IPv6 prefixes are 0-128", .{format.escapeArgument(&echo, address)}),
        }
        return error.InvalidValue;
    };
    return Parsed{ .globals = globals.*, .command = .{ .ignore = out } };
}

fn parseForSeconds(text: []const u8) ?u64 {
    const parsed = shared.duration.parse(text, false) catch return null;
    if (parsed != .finite) return null;
    const seconds = parsed.nativeSeconds() catch return null;
    if (seconds == 0 or seconds > shared.types.TimedEntry.max_duration_s) return null;
    return seconds;
}

fn parseScope(rest: []const []const u8, idx: *usize, diag: *ParseDiag) Error!Command.ScopeArgs {
    idx.* += 1;
    if (idx.* >= rest.len) {
        diag.set("flag --scope requires a value: host, or net <cidr>", .{});
        return error.MissingValue;
    }
    const kind = rest[idx.*];
    if (std.mem.eql(u8, kind, "host")) return .{ .kind = .host };
    if (std.mem.eql(u8, kind, "net")) {
        idx.* += 1;
        if (idx.* >= rest.len or rest[idx.*].len == 0 or std.mem.startsWith(u8, rest[idx.*], "--")) {
            diag.set("--scope net requires a CIDR (e.g. 192.0.2.0/24)", .{});
            return error.MissingValue;
        }
        return .{ .kind = .net, .cidr = rest[idx.*] };
    }
    diag.set("invalid --scope value '{s}' (expected: host, or net <cidr>)", .{kind});
    return error.InvalidValue;
}

fn parseJailAdmin(rest: []const []const u8, globals: *Globals, diag: *ParseDiag) Error!Parsed {
    var action: ?Command.JailAction = null;
    var name: ?[]const u8 = null;
    var k: usize = 0;
    while (k < rest.len) : (k += 1) {
        const a = rest[k];
        if (try takeTrailingGlobal(a, rest, &k, globals, diag)) continue;
        if (std.mem.startsWith(u8, a, "--")) {
            diag.set("unknown flag for 'jail': {s}", .{a});
            return error.UnknownFlag;
        }
        if (action == null) {
            action = std.meta.stringToEnum(Command.JailAction, a) orelse {
                diag.set("invalid jail action '{s}' (expected: enable, disable, pause, resume); use 'list --jail <name>', 'ban <ip> --jail <name>', or 'unban <ip> --jail <name>' to manage bans", .{a});
                return error.InvalidValue;
            };
            continue;
        }
        if (name == null) {
            name = a;
            continue;
        }
        diag.set("command 'jail' takes an action and one jail name, got extra '{s}'", .{a});
        return error.TooManyArguments;
    }
    const chosen = action orelse {
        diag.set("command 'jail' requires an action (usage: jail enable|disable|pause|resume <name>)", .{});
        return error.MissingArgument;
    };
    const jail = name orelse {
        diag.set("command 'jail {s}' requires a jail name", .{@tagName(chosen)});
        return error.MissingArgument;
    };
    return Parsed{ .globals = globals.*, .command = .{ .jail_admin = .{ .action = chosen, .name = jail } } };
}

fn parseHistoryReset(rest: []const []const u8, globals: *Globals, diag: *ParseDiag) Error!Parsed {
    var args = Command.HistoryResetArgs{ .address = "" };
    var have_address = false;
    var k: usize = 0;
    while (k < rest.len) : (k += 1) {
        const a = rest[k];
        if (try takeTrailingGlobal(a, rest, &k, globals, diag)) continue;
        if (std.mem.eql(u8, a, "--jail")) {
            k += 1;
            if (k >= rest.len) {
                diag.set("flag --jail requires a value (jail name)", .{});
                return error.MissingValue;
            }
            args.jail = rest[k];
            continue;
        }
        if (std.mem.eql(u8, a, "--all")) {
            args.all = true;
            continue;
        }
        if (std.mem.startsWith(u8, a, "--")) {
            diag.set("unknown flag for 'history reset': {s}", .{a});
            return error.UnknownFlag;
        }
        if (!have_address) {
            args.address = a;
            have_address = true;
            continue;
        }
        diag.set("command 'history reset' takes one IP argument, got extra '{s}'", .{a});
        return error.TooManyArguments;
    }
    if (!have_address) {
        diag.set("command 'history reset' requires an IP address (usage: history reset <ip> --jail <name> | --all)", .{});
        return error.MissingArgument;
    }
    if ((args.jail == null) == !args.all) {
        diag.set("command 'history reset' requires exactly one of --jail <name> or --all", .{});
        return error.MissingArgument;
    }
    return Parsed{ .globals = globals.*, .command = .{ .history_reset = args } };
}

fn parseList(rest: []const []const u8, globals: *Globals, diag: *ParseDiag) Error!Parsed {
    var args = Command.ListArgs{};
    var k: usize = 0;
    while (k < rest.len) : (k += 1) {
        const a = rest[k];
        if (try takeTrailingGlobal(a, rest, &k, globals, diag)) continue;
        if (std.mem.eql(u8, a, "--jail")) {
            k += 1;
            if (k >= rest.len) {
                diag.set("flag --jail requires a value (jail name)", .{});
                return error.MissingValue;
            }
            args.jail = rest[k];
            continue;
        }
        if (std.mem.eql(u8, a, "--details")) {
            args.details = true;
            continue;
        }
        if (std.mem.eql(u8, a, "--sort")) {
            args.sort = true;
            continue;
        }
        if (std.mem.eql(u8, a, "--origin")) {
            k += 1;
            if (k >= rest.len) {
                diag.set("flag --origin requires a value: detection, manual or config", .{});
                return error.MissingValue;
            }
            args.origin = std.meta.stringToEnum(shared.types.Origin, rest[k]) orelse {
                var echo: [format.diagnostic_max_bytes]u8 = undefined;
                diag.set("invalid --origin value '{s}' (expected: detection, manual, config)", .{format.escapeArgument(&echo, rest[k])});
                return error.InvalidValue;
            };
            continue;
        }
        if (std.mem.startsWith(u8, a, "--")) {
            diag.set("unknown flag for 'list': {s}", .{a});
            return error.UnknownFlag;
        }
        diag.set("command 'list' takes no positional arguments, got '{s}'", .{a});
        return error.TooManyArguments;
    }
    return Parsed{ .globals = globals.*, .command = .{ .list = args } };
}

pub const max_history_limit: u32 = 256;
pub const max_firewall_limit: u32 = 256;

fn parseHistory(rest: []const []const u8, globals: *Globals, diag: *ParseDiag) Error!Parsed {
    var args = Command.HistoryArgs{};
    var k: usize = 0;
    while (k < rest.len) : (k += 1) {
        const a = rest[k];
        if (try takeTrailingGlobal(a, rest, &k, globals, diag)) continue;
        if (std.mem.eql(u8, a, "--jail")) {
            k += 1;
            if (k >= rest.len) {
                diag.set("flag --jail requires a value (jail name)", .{});
                return error.MissingValue;
            }
            args.jail = rest[k];
            continue;
        }
        if (std.mem.eql(u8, a, "--limit")) {
            k += 1;
            if (k >= rest.len) {
                diag.set("flag --limit requires a value (1..{d})", .{max_history_limit});
                return error.MissingValue;
            }
            const value = std.fmt.parseInt(u32, rest[k], 10) catch 0;
            if (value < 1 or value > max_history_limit) {
                diag.set("invalid --limit value '{s}' (expected 1..{d})", .{ rest[k], max_history_limit });
                return error.InvalidValue;
            }
            args.limit = value;
            continue;
        }
        if (std.mem.eql(u8, a, "--cursor")) {
            k += 1;
            if (k >= rest.len) {
                diag.set("flag --cursor requires a value (from a previous page)", .{});
                return error.MissingValue;
            }
            if (rest[k].len == 0 or rest[k].len > 128) {
                diag.set("invalid --cursor value (expected 1..128 characters)", .{});
                return error.InvalidValue;
            }
            args.cursor = rest[k];
            continue;
        }
        if (std.mem.startsWith(u8, a, "--")) {
            diag.set("unknown flag for 'history': {s}", .{a});
            return error.UnknownFlag;
        }
        diag.set("command 'history' takes no positional arguments, got '{s}'", .{a});
        return error.TooManyArguments;
    }
    return Parsed{ .globals = globals.*, .command = .{ .history = args } };
}

fn parseFirewall(rest: []const []const u8, globals: *Globals, diag: *ParseDiag) Error!Parsed {
    if (rest.len > 0 and std.mem.eql(u8, rest[0], "withdraw")) {
        try expectNoPositional(rest[1..], "firewall withdraw", diag, globals);
        return Parsed{ .globals = globals.*, .command = .firewall_withdraw };
    }
    if (rest.len == 0 or !std.mem.eql(u8, rest[0], "show")) {
        diag.set("command 'firewall' requires 'show' or 'withdraw' (usage: firewall show [--details] [--limit <n>] [--cursor <token>] | firewall withdraw)", .{});
        return error.MissingArgument;
    }

    var out = Command.FirewallArgs{};
    var k: usize = 1;
    while (k < rest.len) : (k += 1) {
        const a = rest[k];
        if (try takeTrailingGlobal(a, rest, &k, globals, diag)) continue;
        if (std.mem.eql(u8, a, "--limit")) {
            k += 1;
            if (k >= rest.len) {
                diag.set("flag --limit requires a value (1..{d})", .{max_firewall_limit});
                return error.MissingValue;
            }
            const value = std.fmt.parseInt(u32, rest[k], 10) catch 0;
            if (value < 1 or value > max_firewall_limit) {
                diag.set("invalid --limit value '{s}' (expected 1..{d})", .{ rest[k], max_firewall_limit });
                return error.InvalidValue;
            }
            out.limit = value;
            continue;
        }
        if (std.mem.eql(u8, a, "--cursor")) {
            k += 1;
            if (k >= rest.len) {
                diag.set("flag --cursor requires a value (from a previous firewall page)", .{});
                return error.MissingValue;
            }
            if (rest[k].len == 0 or rest[k].len > 128) {
                diag.set("invalid --cursor value (expected 1..128 characters)", .{});
                return error.InvalidValue;
            }
            out.cursor = rest[k];
            continue;
        }
        if (std.mem.eql(u8, a, "--details")) {
            out.details = true;
            continue;
        }
        if (std.mem.startsWith(u8, a, "--")) {
            diag.set("unknown flag for 'firewall show': {s}", .{a});
            return error.UnknownFlag;
        }
        diag.set("command 'firewall show' takes no positional arguments, got '{s}'", .{a});
        return error.TooManyArguments;
    }
    return Parsed{ .globals = globals.*, .command = .{ .firewall = out } };
}

fn parseCompletions(rest: []const []const u8, globals: *Globals, diag: *ParseDiag) Error!Parsed {
    var shell: ?Shell = null;
    var k: usize = 0;
    while (k < rest.len) : (k += 1) {
        const a = rest[k];
        if (try takeTrailingGlobal(a, rest, &k, globals, diag)) continue;
        if (std.mem.startsWith(u8, a, "--")) {
            diag.set("unknown flag for 'completions': {s}", .{a});
            return error.UnknownFlag;
        }
        if (shell == null) {
            shell = Shell.fromString(a) orelse {
                diag.set("invalid shell '{s}' (expected: bash, zsh, fish)", .{a});
                return error.InvalidValue;
            };
            continue;
        }
        diag.set("command 'completions' takes one shell argument, got extra '{s}'", .{a});
        return error.TooManyArguments;
    }
    if (shell == null) {
        diag.set("command 'completions' requires a shell (bash | zsh | fish)", .{});
        return error.MissingArgument;
    }
    return Parsed{ .globals = globals.*, .command = .{ .completions = shell.? } };
}

fn takeTrailingGlobal(
    a: []const u8,
    rest: []const []const u8,
    idx: *usize,
    globals: *Globals,
    diag: *ParseDiag,
) Error!bool {
    if (std.mem.eql(u8, a, "--socket")) {
        idx.* += 1;
        if (idx.* >= rest.len) {
            diag.set("flag --socket requires a value (path to Unix socket)", .{});
            return error.MissingValue;
        }
        globals.socket_path = rest[idx.*];
        return true;
    }
    if (std.mem.eql(u8, a, "--output")) {
        idx.* += 1;
        if (idx.* >= rest.len) {
            diag.set("flag --output requires a value: table, json, or plain", .{});
            return error.MissingValue;
        }
        globals.output = OutputFormat.fromString(rest[idx.*]) orelse {
            diag.set("invalid --output value '{s}' (expected: table, json, plain)", .{rest[idx.*]});
            return error.InvalidValue;
        };
        return true;
    }
    if (std.mem.eql(u8, a, "--no-color")) {
        globals.color = false;
        return true;
    }
    if (std.mem.eql(u8, a, "--timeout")) {
        idx.* += 1;
        if (idx.* >= rest.len) {
            diag.set("flag --timeout requires a value (milliseconds)", .{});
            return error.MissingValue;
        }
        globals.timeout_ms = std.fmt.parseInt(u64, rest[idx.*], 10) catch {
            diag.set("invalid --timeout value '{s}' (expected positive integer ms)", .{rest[idx.*]});
            return error.InvalidValue;
        };
        return true;
    }
    return false;
}

pub const known_commands = [_][]const u8{
    "status",
    "ban",
    "unban",
    "list",
    "stats",
    "jails",
    "reload",
    "version",
    "config",
    "history",
    "firewall",
    "jail",
    "ignore",
    "completions",
    "help",
    "migrate",
    "rule-test",
    "repair-source",
    "support-bundle",
};

pub fn closestCommand(input: []const u8) ?[]const u8 {
    var best_dist: usize = std.math.maxInt(usize);
    var best: ?[]const u8 = null;
    for (known_commands) |cmd| {
        const d = editDistance(input, cmd);
        if (d < best_dist) {
            best_dist = d;
            best = cmd;
        }
    }
    if (best_dist <= 3) return best;
    return null;
}

pub fn editDistance(a: []const u8, b: []const u8) usize {
    const max_len = 128;
    if (a.len > max_len or b.len > max_len) return std.math.maxInt(usize);
    if (a.len == 0) return b.len;
    if (b.len == 0) return a.len;

    var prev: [max_len + 1]usize = undefined;
    var curr: [max_len + 1]usize = undefined;

    for (0..b.len + 1) |j| prev[j] = j;

    for (a, 0..) |ca, i| {
        curr[0] = i + 1;
        for (b, 0..) |cb, j| {
            const cost: usize = if (asciiLower(ca) == asciiLower(cb)) 0 else 1;
            const del = prev[j + 1] + 1;
            const ins = curr[j] + 1;
            const sub = prev[j] + cost;
            var m = if (del < ins) del else ins;
            if (sub < m) m = sub;
            curr[j + 1] = m;
        }
        @memcpy(prev[0 .. b.len + 1], curr[0 .. b.len + 1]);
    }
    return prev[b.len];
}

fn asciiLower(c: u8) u8 {
    return if (c >= 'A' and c <= 'Z') c + 32 else c;
}

pub const help_top =
    \\fail2zig — query and control the fail2zig daemon
    \\
    \\USAGE:
    \\    fail2zig [global-flags] <command> [args]
    \\
    \\COMMANDS:
    \\    status              Show protection-first daemon status (--details for identifiers/metrics)
    \\    stats               Show the retained enforcement statistics snapshot
    \\    jails               List configured jails with source health (--details for thresholds)
    \\    list                List active bans (--jail, --origin filters; --details for counts)
    \\    ban <ip>            Manually ban an address or, with --scope net, a network
    \\    unban <ip>          Manually unban an address or network
    \\    ignore <sub>        Manage per-jail exclusions: add, remove, list
    \\    history             Page through confirmed ban history
    \\    history reset <ip>  Reset an address's ban history in one jail or all jails
    \\    firewall show       Inspect sampled fail2zig-owned kernel protection
    \\    firewall withdraw   Remove fail2zig's kernel rules and hold enforcement off until restart
    \\    jail <action> <n>   enable, disable, pause or resume a jail
    \\    reload              Apply supported configuration changes live
    \\    config              Show the daemon's effective configuration
    \\    version             Show client and daemon versions
    \\    completions <sh>    Emit shell-completion script (bash|zsh|fish)
    \\    help [command]      Show help for a command; <command> --help does the same
    \\
    \\OFFLINE TOOLS (no daemon needed):
    \\    rule-test           Evaluate a log, one line or the journal against a rule
    \\    migrate <sub>       Inspect, plan and carry out a fail2ban migration
    \\    repair-source       Acknowledge a truncated or replaced file source
    \\    support-bundle      Write a redacted diagnostic bundle for a bug report
    \\
    \\GLOBAL FLAGS:
    \\    --socket <path>     Unix socket path (default: /run/fail2zig/fail2zig.sock)
    \\    --output <fmt>      Output format: table (default), json, plain
    \\    --no-color          Disable ANSI color output
    \\    --timeout <ms>      Command timeout (default: 5000)
    \\    --help, -h          Show this message
    \\    --version, -V       Print client version and exit
    \\
    \\EXAMPLES:
    \\    fail2zig status
    \\    fail2zig jails --details
    \\    fail2zig list --jail sshd --output json
    \\    fail2zig list --origin config
    \\    fail2zig ban 192.0.2.10 --jail sshd --duration 1h
    \\    fail2zig ban 192.0.2.10 --jail sshd --scope net 192.0.2.0/24
    \\    fail2zig unban 192.0.2.10 --jail sshd
    \\    fail2zig ignore add 198.51.100.20 --jail sshd --for 2h
    \\    fail2zig ignore list --jail sshd
    \\    fail2zig history --jail sshd --limit 50
    \\    fail2zig jail pause sshd
    \\    fail2zig firewall show --limit 50
    \\    fail2zig rule-test --file /var/log/auth.log --service sshd --output table
    \\    fail2zig completions bash > /etc/bash_completion.d/fail2zig
    \\
;

pub const help_status =
    \\fail2zig status — show protection, storage and source health
    \\
    \\USAGE:
    \\    fail2zig status [--details]
    \\
    \\FLAGS:
    \\    --details           Add uptime, memory and memory plan, parse rate, generation
    \\                        and the tracking pool to the summary rows
    \\
    \\ROWS:
    \\    Protection          active, log-only, mixed, unknown or DEGRADED (cause)
    \\    Active bans         What the kernel inventory holds right now
    \\    History             Retained confirmed events (maintenance trims them)
    \\    Knowledge           fresh, stale or absent, with the age of the last readback
    \\    Pending             Bans and removals the daemon has not yet confirmed
    \\    Storage / Cause     Storage phase and the diagnosed cause when not healthy
    \\    Sources             Count of unhealthy sources; run jails for the per-jail view
    \\    Paused / Repair     Each paused file source and the exact repair command
    \\    State file          Size and page use against the configured ceiling
    \\
    \\Protection is DEGRADED while any source is paused, storage is recovering or the
    \\kernel readback is stale; the Cause row says which. A missing log file does not
    \\degrade protection: jails shows it as missing (FileNotFound).
    \\
    \\--output json carries every field; --output plain prints one key per line.
    \\Exit 0 is reported state, not healthy protection: read the Protection row.
    \\
;

pub const help_reload =
    \\fail2zig reload — apply the configuration file to the running daemon
    \\
    \\USAGE:
    \\    fail2zig reload
    \\
    \\The daemon reads its configuration file again and reports one outcome:
    \\    noop                Nothing changed
    \\    applied             Every change is live
    \\    rejected            A jail failed validation (the message names it);
    \\                        every running jail is unchanged
    \\    restart_required    Only restart-only keys changed; reasons lists them
    \\
    \\Live keys: maxretry, bantime, bantime_kind, bantime_increment and its decay,
    \\ignoreip, banip and their durations, ignoreself, ignoretime, log_level and a
    \\custom jail's ignore_file. Adding an enabled jail starts it in the same reload;
    \\removing a jail lifts its bans and keeps its history. log_format is restart-only;
    \\the reasons list names every restart-only key that changed.
    \\
    \\An ignoreip edit applies from the next event and never alters an existing ban;
    \\a banip edit bans or lifts at once.
    \\
;

pub const help_version =
    \\fail2zig version — show the client and daemon versions
    \\
    \\USAGE:
    \\    fail2zig version
    \\
    \\Prints the client version, then asks the running daemon for its own; the two
    \\differ until a restart after an upgrade. Exit 3 when the daemon is unreachable.
    \\fail2zig --version prints the client version without contacting the daemon.
    \\
;

pub const help_migrate =
    \\fail2zig migrate — move from fail2ban in journaled, resumable steps
    \\
    \\USAGE:
    \\    fail2zig migrate inspect --source-dir <dir> [--output json|table]
    \\    fail2zig migrate snapshot --source-db <file> --staging-dir <dir> [--output json|table]
    \\    fail2zig migrate plan --source-dir <dir> [--source-db <file> --staging-dir <dir>] --out <plan.json>
    \\                          [--continuity lossless|reset-replay] [--replay-window <seconds>]
    \\                          [--runtime-socket <path>] [--output json|table]
    \\    fail2zig migrate validate --plan <plan.json> [--source-dir <dir>] [--snapshot <file>] [--output json|table]
    \\    fail2zig migrate cutover --plan <plan.json> --state-file <db> --staging-dir <dir>
    \\                             --backend nftables|ipset|iptables [--socket <path>] [--run-id <hex>] [--output json|table]
    \\    fail2zig migrate status --plan <plan.json> --state-file <db> --staging-dir <dir> --run-id <hex> [--output json|table]
    \\    fail2zig migrate rollback --plan <plan.json> --state-file <db> --staging-dir <dir> --backend <b> --run-id <hex>
    \\                              [--source-verified] [--socket <path>] [--output json|table]
    \\
    \\inspect, snapshot, plan and validate are read-only preparation. cutover stages
    \\the destination with the daemon stopped and activates it through the daemon; it
    \\is journaled, prints the --run-id command to resume when the socket is
    \\unreachable, and a rerun classifies the journal instead of replaying it. status
    \\reports a run. rollback reverses an activated run in two journaled phases.
    \\The staging directory must be private (0700) and non-volatile.
    \\See docs/operations/command-migration.md for the full procedure.
    \\
;

pub const help_rule_test =
    \\fail2zig rule-test — evaluate log input against one rule, offline
    \\
    \\USAGE:
    \\    fail2zig rule-test (--file <path> | --record "<line>" | --journal [<match>...])
    \\                       (--service <name> | --rule-file <path>)
    \\                       [--config <path>] [--jail <name>]
    \\                       [--timestamp iso8601|syslog|epoch_seconds|common_log|undated]
    \\                       [--time-zone <id>] [--tz-offset <minutes>] [--year <yyyy>]
    \\                       [--encoding utf8|ascii|latin1|utf16le|utf16be|utf32le|utf32be]
    \\                       [--identity raw|dns --dns-server <ip:port>] [--ignore <cidr>]...
    \\                       [--max-lines <n>] [--limit <n>] [--output json|table] [--print-lines]
    \\                       [--now <epoch-seconds>] [--window <seconds>]
    \\
    \\Uses the daemon's own decoder, time admission and detectors against exactly one
    \\input and one rule: a compiled service (--service) or a native rule file
    \\(--rule-file). It opens no state, no firewall and no socket. --config with
    \\--jail takes the timestamp, time zone and ignore settings from a configuration.
    \\Samples report match, miss, ignore or reject with the reason, identity and
    \\event time; --print-lines includes the raw lines. Exit 0 when the input was
    \\processed (even with zero matches), 1 when the rule, configuration or input was
    \\refused, 2 on usage errors.
    \\
    \\EXAMPLES:
    \\    fail2zig rule-test --file /var/log/auth.log --service sshd --output table
    \\    fail2zig rule-test --record "Failed password for root from 192.0.2.10 port 22 ssh2" --service sshd
    \\
;

pub const help_ban =
    \\fail2zig ban — manually ban an IP address
    \\
    \\USAGE:
    \\    fail2zig ban <ip> --jail <name> [--duration <duration>] [--scope host|net <cidr>] [--force]
    \\
    \\ARGS:
    \\    <ip>                IPv4 or IPv6 address (e.g. 192.0.2.10, 2001:db8::1)
    \\
    \\FLAGS:
    \\    --jail <name>       Target jail (required)
    \\    --duration <d>      Ban length: seconds, or a duration such as 2m or 1h30m
    \\                        (the jail's bantime if omitted)
    \\    --scope host        Ban the single address (default)
    \\    --scope net <cidr>  Ban the given network instead of the host
    \\    --force             Ban even a loopback address, an address of this host,
    \\                        or your SSH peer address
    \\
    \\Without --force, ban refuses a target that is or contains a loopback address,
    \\an address of this host, or the client address of the SSH session it runs in.
    \\Banning an address on the jail's ignore list is applied with a warning.
    \\A ban set by the jail's banip list cannot be changed here: edit banip.
    \\
;

pub const help_unban =
    \\fail2zig unban — manually unban an IP address
    \\
    \\USAGE:
    \\    fail2zig unban <ip> --jail <name> [--scope host|net <cidr>]
    \\
    \\ARGS:
    \\    <ip>                IPv4 or IPv6 address
    \\
    \\FLAGS:
    \\    --jail <name>       Jail that owns the ban (required)
    \\    --scope host        Release the single address (default)
    \\    --scope net <cidr>  Release the given network scope instead
    \\
;

pub const help_list =
    \\fail2zig list — list active bans
    \\
    \\USAGE:
    \\    fail2zig list [--jail <name>] [--origin detection|manual|config] [--details] [--sort]
    \\
    \\FLAGS:
    \\    --jail <name>       Filter by jail
    \\    --origin <origin>   Show only bans of one origin: detection, manual or config;
    \\                        config also shows timed banip entries that have expired
    \\    --details           Include ban counts in table output
    \\    --sort              Sort by numeric IP address, then jail name
    \\    IPv4 sorts before IPv6; networks sort by address and prefix length.
    \\    Without --sort, the daemon's existing order is preserved.
    \\    Plain output keeps four columns; expiry 0 means permanent or unknown.
    \\    Use JSON for explicit expiry fields.
    \\
;

pub const help_config =
    \\fail2zig config — show the daemon's effective configuration
    \\
    \\USAGE:
    \\    fail2zig config
    \\
    \\Paths and address lists are redacted unless the caller is an administrator.
    \\
;

pub const help_jails =
    \\fail2zig jails — show configured jails and observed protection
    \\
    \\USAGE:
    \\    fail2zig jails [--details]
    \\
    \\MODE reports configured enforcement intent (enforce or log-only).
    \\PROTECTION active means the daemon's current protection criteria are met;
    \\pending bans may remain. It is not an independent per-jail kernel verification.
    \\Unconfirmed does not mean installed rules are absent. Unknown means no value
    \\was supplied. Plain output preserves the enforcing boolean and uses - for
    \\an unknown active-ban count; a known zero remains 0.
    \\
    \\SOURCE HEALTH (HEALTH with --details) is the state of the jail's log source:
    \\    ok                      Reading normally
    \\    missing (FileNotFound)  The log file is absent; reading resumes when it
    \\                            appears, and protection is not affected
    \\    waiting (<cause>)       The jail waits for room (RetryCapacity or
    \\                            ReserveBackpressure); nothing is lost and it
    \\                            continues as room frees up
    \\    paused (<cause>)        The source stopped until repaired; status prints
    \\                            the repair command
    \\    broken (<cause>)        The source cannot be read; the cause names why
    \\
;

pub const help_stats =
    \\fail2zig stats — show one retained enforcement statistics snapshot
    \\
    \\USAGE:
    \\    fail2zig stats [--details]
    \\
    \\The snapshot may be stale; its age and readback knowledge are shown separately.
    \\Use status to inspect current protection and daemon health. A stats snapshot is
    \\not per-jail kernel verification and does not trigger a firewall readback.
    \\
    \\An older daemon may not support this query; upgrade the daemon to use stats.
    \\
;

pub const help_history =
    \\fail2zig history — page through confirmed ban history
    \\
    \\USAGE:
    \\    fail2zig history [--jail <name>] [--limit <n>] [--cursor <token>]
    \\
    \\FLAGS:
    \\    --jail <name>       Only events from this jail
    \\    --limit <n>         Events per page, 1..256 (default: daemon default)
    \\    --cursor <token>    Continue from the next_cursor of a previous page
    \\
    \\RESET:
    \\    fail2zig history reset <ip> --jail <name>
    \\    fail2zig history reset <ip> --all
    \\    Resets the durable history for one address; exactly one of --jail or --all is required.
    \\
;

pub const help_firewall =
    \\fail2zig firewall show — inspect fail2zig-owned kernel protection
    \\fail2zig firewall withdraw — remove fail2zig's kernel rules until the next start
    \\
    \\USAGE:
    \\    fail2zig firewall show [--limit <n>] [--cursor <token>] [--details]
    \\    fail2zig firewall withdraw
    \\
    \\FLAGS:
    \\    --limit <n>         Sample entries per page, 1..256 (default: daemon default)
    \\    --cursor <token>    Continue the same retained observation page
    \\    --details           Include verified owned structures, entry placement and identifiers
    \\
    \\This reads the daemon's latest retained observation. It does not refresh, repair,
    \\or enumerate firewall state owned by other applications. Structural detail appears
    \\only when the retained owned readback has exact verification.
    \\
    \\withdraw removes every rule the daemon realized and holds enforcement off until the
    \\next start; owners and deadlines are kept, and a restart reinstalls live bans. Stopping
    \\the daemon leaves rules in place, so run withdraw first to stop with an empty table.
    \\
;

pub const help_jail =
    \\fail2zig jail — administer one jail
    \\
    \\USAGE:
    \\    fail2zig jail enable <name>
    \\    fail2zig jail disable <name>
    \\    fail2zig jail pause <name>
    \\    fail2zig jail resume <name>
    \\
    \\Manage bans with 'fail2zig list --jail <name>', 'fail2zig ban <ip> --jail <name>',
    \\or 'fail2zig unban <ip> --jail <name>'.
    \\
;

pub const help_repair_source =
    \\fail2zig repair-source — acknowledge a truncated or replaced file source
    \\
    \\USAGE:
    \\    fail2zig repair-source --jail <name> --source <absolute path> --token <token>
    \\                           --acknowledge-truncation [--config <path>]
    \\
    \\When the daemon is running, the repair is sent to it over its socket and applied
    \\while every jail stays protected. When the daemon is stopped, it runs locally
    \\against the state file named by the config; it refuses when the state is locked
    \\or absent and never creates state.
    \\It accepts a same-inode truncation, or a log replaced by a different file whose
    \\previous file is gone, of a recorded source with no pending receipt, and restarts
    \\that source at offset 0 of the current file.
    \\
    \\Data removed by the truncation or left in the previous file before it was read is
    \\lost; its extent is unknown.
    \\When run locally, protection for every jail may be absent while the daemon is
    \\stopped; the next start reinstalls it before reporting READY.
    \\
    \\Repeating the command with the same token and arguments reports the committed
    \\outcome. The newest 256 outcomes are retained; an older token stays reserved and
    \\is refused, so it can never apply a second repair. The source must be a configured
    \\logpath of the jail. The repair binds the source generation recorded in the state,
    \\not one recomputed from the configuration; a changed configuration is applied by
    \\the next start.
    \\
;

pub const help_ignore =
    \\fail2zig ignore — manage per-jail exclusions at runtime
    \\
    \\USAGE:
    \\    fail2zig ignore add <address|cidr> --jail <name> [--unban] [--for <duration>]
    \\    fail2zig ignore remove <address|cidr> --jail <name>
    \\    fail2zig ignore list [--jail <name>]
    \\
    \\ARGS:
    \\    <address|cidr>      IPv4 or IPv6 address or network, as accepted by ignoreip
    \\                        (e.g. 198.51.100.20, 203.0.113.0/24, 2001:db8::/32)
    \\
    \\FLAGS:
    \\    --jail <name>       Jail whose list is changed (required for add and remove);
    \\                        for list, show one jail instead of every enabled jail
    \\    --unban             add only: also lift that jail's bans inside the entry
    \\    --for <duration>    add only: remove the entry after this long, in the
    \\                        configuration's duration syntax (e.g. 2m, 1h30m, 90)
    \\
    \\Entries added here are stored in the state database and survive restart and
    \\reload. They are merged with the jail's configured ignoreip and, when
    \\ignoreself is on, this host's own addresses; SOURCE shows config, runtime,
    \\config+runtime or self. EXPIRES shows when a timed entry runs out: an expired
    \\runtime entry is removed, an expired configured entry stays listed as expired.
    \\Entries set in the configuration file are changed there, not here.
    \\
    \\An ignore entry stops future bans from detection. It does not lift a ban that
    \\already exists: add tells you when the address is banned, until when, and how
    \\to lift it. Use --unban to lift it in the same command.
    \\
    \\Each jail holds at most 128 entries, configuration and runtime combined.
    \\Addresses are redacted for callers who are not administrators.
    \\
;

pub const help_completions =
    \\fail2zig completions — generate shell completion script
    \\
    \\USAGE:
    \\    fail2zig completions <shell>
    \\
    \\ARGS:
    \\    <shell>             One of: bash, zsh, fish
    \\
    \\INSTALL:
    \\    bash:  fail2zig completions bash > /etc/bash_completion.d/fail2zig
    \\    zsh:   fail2zig completions zsh  > /usr/share/zsh/site-functions/_fail2zig
    \\    fish:  fail2zig completions fish > ~/.config/fish/completions/fail2zig.fish
    \\
;

pub const help_support_bundle =
    \\fail2zig support-bundle — write a redacted diagnostic bundle for a bug report
    \\
    \\USAGE:
    \\    fail2zig support-bundle [--out <path>|-] [--config <path>] [--socket <path>]
    \\                            [--log-lines <n>] [--timeout <ms>] [--include-addresses]
    \\
    \\Collects versions, daemon status, jails, stats, continuity loss events, the
    \\effective configuration with its file and loaded SHA-256, state file page and
    \\per-table sizes, kernel readback counts, memory, host basics, and the last <n>
    \\(default 200, at most 2000) warnings and errors from the daemon log into one JSON
    \\file. Run it as the daemon's user; sections it cannot read record their error.
    \\
    \\Addresses become v4-<hash> or v6-<hash>, stable within one bundle only; loopback
    \\and unspecified addresses are kept. --include-addresses keeps every address.
    \\Paths other than configured log paths become <path>.
    \\
    \\The default output is ./fail2zig-support-<UTC time>.json, created mode 0600 and
    \\never overwritten; '-' writes to stdout. Exit 0 when every section was collected,
    \\4 when the bundle was written with sections that record an error, 1 when nothing
    \\was written.
    \\
;

pub fn helpFor(t: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, t, "help")) return help_top;
    if (std.mem.eql(u8, t, "status")) return help_status;
    if (std.mem.eql(u8, t, "reload")) return help_reload;
    if (std.mem.eql(u8, t, "version")) return help_version;
    if (std.mem.eql(u8, t, "migrate")) return help_migrate;
    if (std.mem.eql(u8, t, "rule-test")) return help_rule_test;
    if (std.mem.eql(u8, t, "ban")) return help_ban;
    if (std.mem.eql(u8, t, "unban")) return help_unban;
    if (std.mem.eql(u8, t, "list")) return help_list;
    if (std.mem.eql(u8, t, "stats")) return help_stats;
    if (std.mem.eql(u8, t, "jails")) return help_jails;
    if (std.mem.eql(u8, t, "completions")) return help_completions;
    if (std.mem.eql(u8, t, "config")) return help_config;
    if (std.mem.eql(u8, t, "history")) return help_history;
    if (std.mem.eql(u8, t, "firewall")) return help_firewall;
    if (std.mem.eql(u8, t, "jail")) return help_jail;
    if (std.mem.eql(u8, t, "ignore")) return help_ignore;
    if (std.mem.eql(u8, t, "repair-source")) return help_repair_source;
    if (std.mem.eql(u8, t, "support-bundle")) return help_support_bundle;
    return null;
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const shared = @import("shared");

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
    status: void,
    ban: BanArgs,
    unban: UnbanArgs,
    list: ListArgs,
    jails: void,
    reload: void,
    remote_version: void,
    completions: Shell,
    config: void,
    history: HistoryArgs,
    jail_admin: JailAdminArgs,
    history_reset: HistoryResetArgs,

    pub const ScopeKind = enum { host, net };
    pub const ScopeArgs = struct {
        kind: ScopeKind,
        cidr: ?[]const u8 = null,
    };

    /// `jail` is always set after a successful parse; it stays optional only so
    /// existing callers keep compiling.
    pub const BanArgs = struct {
        ip: []const u8,
        jail: ?[]const u8 = null,
        duration_s: ?u64 = null,
        scope: ?ScopeArgs = null,
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

    pub const ListArgs = struct {
        jail: ?[]const u8 = null,
    };

    pub const HistoryArgs = struct {
        jail: ?[]const u8 = null,
        limit: ?u32 = null,
        cursor: ?[]const u8 = null,
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

    if (std.mem.eql(u8, cmd_str, "status")) {
        try expectNoPositional(rest, "status", diag, &globals);
        return Parsed{ .globals = globals, .command = .status };
    }
    if (std.mem.eql(u8, cmd_str, "jails")) {
        try expectNoPositional(rest, "jails", diag, &globals);
        return Parsed{ .globals = globals, .command = .jails };
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
                diag.set("flag --duration requires a value (seconds)", .{});
                return error.MissingValue;
            }
            args.duration_s = std.fmt.parseInt(u64, rest[k], 10) catch {
                diag.set("invalid --duration value '{s}' (expected positive integer seconds)", .{rest[k]});
                return error.InvalidValue;
            };
            continue;
        }
        if (std.mem.eql(u8, a, "--scope")) {
            args.scope = try parseScope(rest, &k, diag);
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
        diag.set("command 'ban' requires an IP address (usage: ban <ip> --jail <name> [--duration <s>] [--scope host|net <cidr>])", .{});
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

/// `--scope host` or `--scope net <cidr>`; `idx` points at `--scope` on entry
/// and at the last consumed token on return.
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
                diag.set("invalid jail action '{s}' (expected: enable, disable, pause, resume)", .{a});
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
    "jails",
    "reload",
    "version",
    "config",
    "history",
    "jail",
    "completions",
    "help",
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
    \\    status              Show daemon status (uptime, memory, active bans)
    \\    ban <ip>            Manually ban an IP
    \\    unban <ip>          Manually unban an IP
    \\    list                List active bans (all or per-jail with --jail)
    \\    jails               List configured jails
    \\    reload              Apply a validated configuration live (restart-only keys reported)
    \\    version             Show client and daemon version
    \\    config              Show the daemon's effective configuration
    \\    history             Page through confirmed ban history
    \\    history reset <ip>  Reset an address's ban history in one jail or all jails
    \\    jail <action> <n>   enable, disable, pause or resume a jail
    \\    completions <sh>    Emit shell-completion script (bash|zsh|fish)
    \\    help [command]      Show help for a command
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
    \\    fail2zig ban 192.0.2.10 --jail sshd --duration 3600
    \\    fail2zig ban 192.0.2.10 --jail sshd --scope net 192.0.2.0/24
    \\    fail2zig jail pause sshd
    \\    fail2zig list --jail sshd --output json
    \\    fail2zig history --jail sshd --limit 50
    \\    fail2zig completions bash > /etc/bash_completion.d/fail2zig
    \\
;

pub const help_ban =
    \\fail2zig ban — manually ban an IP address
    \\
    \\USAGE:
    \\    fail2zig ban <ip> --jail <name> [--duration <seconds>] [--scope host|net <cidr>]
    \\
    \\ARGS:
    \\    <ip>                IPv4 or IPv6 address (e.g. 192.0.2.10, 2001:db8::1)
    \\
    \\FLAGS:
    \\    --jail <name>       Target jail (required)
    \\    --duration <s>      Ban duration in seconds (uses jail default if omitted)
    \\    --scope host        Ban the single address (default)
    \\    --scope net <cidr>  Ban the given network instead of the host
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
    \\    fail2zig list [--jail <name>]
    \\
    \\FLAGS:
    \\    --jail <name>       Filter by jail
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

pub const help_jail =
    \\fail2zig jail — administer one jail
    \\
    \\USAGE:
    \\    fail2zig jail enable <name>
    \\    fail2zig jail disable <name>
    \\    fail2zig jail pause <name>
    \\    fail2zig jail resume <name>
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

pub fn helpFor(topic: ?[]const u8) []const u8 {
    const t = topic orelse return help_top;
    if (std.mem.eql(u8, t, "ban")) return help_ban;
    if (std.mem.eql(u8, t, "unban")) return help_unban;
    if (std.mem.eql(u8, t, "list")) return help_list;
    if (std.mem.eql(u8, t, "completions")) return help_completions;
    if (std.mem.eql(u8, t, "config")) return help_config;
    if (std.mem.eql(u8, t, "history")) return help_history;
    if (std.mem.eql(u8, t, "jail")) return help_jail;
    return help_top;
}

fn parseOk(argv: []const []const u8) !Parsed {
    var diag: ParseDiag = .{};
    return parse(argv, &diag);
}

test "args: empty argv requires a command" {
    var diag: ParseDiag = .{};
    try std.testing.expectError(error.MissingCommand, parse(&.{}, &diag));
    try std.testing.expect(std.mem.indexOf(u8, diag.message(), "no command") != null);
}

test "args: status with defaults" {
    const p = try parseOk(&.{"status"});
    try std.testing.expect(p.command == .status);
    try std.testing.expectEqualStrings(default_socket_path, p.globals.socket_path);
    try std.testing.expectEqual(OutputFormat.table, p.globals.output);
    try std.testing.expect(p.globals.color);
    try std.testing.expectEqual(default_timeout_ms, p.globals.timeout_ms);
}

test "args: --help returns help command" {
    const p = try parseOk(&.{"--help"});
    try std.testing.expect(p.command == .help);
    try std.testing.expect(p.command.help == null);
}

test "args: -h short flag" {
    const p = try parseOk(&.{"-h"});
    try std.testing.expect(p.command == .help);
}

test "args: --version flag returns client version command" {
    const p = try parseOk(&.{"--version"});
    try std.testing.expect(p.command == .version);
}

test "args: help subtopic" {
    const p = try parseOk(&.{ "help", "ban" });
    try std.testing.expect(p.command == .help);
    try std.testing.expectEqualStrings("ban", p.command.help.?);
}

test "args: global flags before command" {
    const p = try parseOk(&.{ "--socket", "/tmp/a.sock", "--output", "json", "--no-color", "--timeout", "1000", "status" });
    try std.testing.expectEqualStrings("/tmp/a.sock", p.globals.socket_path);
    try std.testing.expectEqual(OutputFormat.json, p.globals.output);
    try std.testing.expect(!p.globals.color);
    try std.testing.expectEqual(@as(u64, 1000), p.globals.timeout_ms);
    try std.testing.expect(p.command == .status);
}

test "args: global flags after command" {
    const p = try parseOk(&.{ "list", "--output", "plain", "--no-color" });
    try std.testing.expectEqual(OutputFormat.plain, p.globals.output);
    try std.testing.expect(!p.globals.color);
    try std.testing.expect(p.command == .list);
}

test "args: --output rejects invalid value" {
    var diag: ParseDiag = .{};
    try std.testing.expectError(error.InvalidValue, parse(&.{ "--output", "xml", "status" }, &diag));
    try std.testing.expect(std.mem.indexOf(u8, diag.message(), "xml") != null);
}

test "args: --socket missing value" {
    var diag: ParseDiag = .{};
    try std.testing.expectError(error.MissingValue, parse(&.{"--socket"}, &diag));
    try std.testing.expect(std.mem.indexOf(u8, diag.message(), "--socket") != null);
}

test "args: ban with ip and jail only" {
    const p = try parseOk(&.{ "ban", "1.2.3.4", "--jail", "sshd" });
    try std.testing.expect(p.command == .ban);
    try std.testing.expectEqualStrings("1.2.3.4", p.command.ban.ip);
    try std.testing.expectEqualStrings("sshd", p.command.ban.jail.?);
    try std.testing.expect(p.command.ban.duration_s == null);
    try std.testing.expect(p.command.ban.scope == null);
}

test "args: ban and unban require --jail" {
    var diag: ParseDiag = .{};
    try std.testing.expectError(error.MissingArgument, parse(&.{ "ban", "1.2.3.4" }, &diag));
    try std.testing.expect(std.mem.indexOf(u8, diag.message(), "requires --jail") != null);
    try std.testing.expectError(error.MissingArgument, parse(&.{ "unban", "1.2.3.4" }, &diag));
    try std.testing.expect(std.mem.indexOf(u8, diag.message(), "requires --jail") != null);
}

test "args: --scope host and net on ban and unban" {
    const host = try parseOk(&.{ "ban", "1.2.3.4", "--jail", "sshd", "--scope", "host" });
    try std.testing.expectEqual(Command.ScopeKind.host, host.command.ban.scope.?.kind);
    try std.testing.expect(host.command.ban.scope.?.cidr == null);
    const net = try parseOk(&.{ "unban", "1.2.3.4", "--scope", "net", "192.0.2.0/24", "--jail", "sshd", "--output", "json" });
    try std.testing.expectEqual(Command.ScopeKind.net, net.command.unban.scope.?.kind);
    try std.testing.expectEqualStrings("192.0.2.0/24", net.command.unban.scope.?.cidr.?);
    try std.testing.expectEqualStrings("sshd", net.command.unban.jail.?);
    try std.testing.expectEqual(OutputFormat.json, net.globals.output);
    var diag: ParseDiag = .{};
    try std.testing.expectError(error.MissingValue, parse(&.{ "ban", "1.2.3.4", "--jail", "sshd", "--scope" }, &diag));
    try std.testing.expectError(error.MissingValue, parse(&.{ "ban", "1.2.3.4", "--jail", "sshd", "--scope", "net" }, &diag));
    try std.testing.expectError(error.MissingValue, parse(&.{ "ban", "1.2.3.4", "--scope", "net", "--jail", "sshd" }, &diag));
    try std.testing.expect(std.mem.indexOf(u8, diag.message(), "CIDR") != null);
    try std.testing.expectError(error.InvalidValue, parse(&.{ "unban", "1.2.3.4", "--jail", "sshd", "--scope", "port" }, &diag));
}

test "args: jail admin actions" {
    inline for (.{ "enable", "disable", "pause", "resume" }) |action| {
        const p = try parseOk(&.{ "jail", action, "sshd" });
        try std.testing.expect(p.command == .jail_admin);
        try std.testing.expectEqual(std.meta.stringToEnum(Command.JailAction, action).?, p.command.jail_admin.action);
        try std.testing.expectEqualStrings("sshd", p.command.jail_admin.name);
    }
    var diag: ParseDiag = .{};
    try std.testing.expectError(error.MissingArgument, parse(&.{"jail"}, &diag));
    try std.testing.expectError(error.MissingArgument, parse(&.{ "jail", "pause" }, &diag));
    try std.testing.expect(std.mem.indexOf(u8, diag.message(), "jail pause") != null);
    try std.testing.expectError(error.InvalidValue, parse(&.{ "jail", "delete", "sshd" }, &diag));
    try std.testing.expectError(error.TooManyArguments, parse(&.{ "jail", "enable", "sshd", "nginx" }, &diag));
    try std.testing.expectError(error.UnknownFlag, parse(&.{ "jail", "enable", "sshd", "--force" }, &diag));
}

test "args: history reset takes an address and exactly one of --jail or --all" {
    const one = try parseOk(&.{ "history", "reset", "192.0.2.10", "--jail", "sshd" });
    try std.testing.expect(one.command == .history_reset);
    try std.testing.expectEqualStrings("192.0.2.10", one.command.history_reset.address);
    try std.testing.expectEqualStrings("sshd", one.command.history_reset.jail.?);
    try std.testing.expect(!one.command.history_reset.all);
    const all = try parseOk(&.{ "history", "reset", "--all", "2001:db8::1", "--no-color" });
    try std.testing.expectEqualStrings("2001:db8::1", all.command.history_reset.address);
    try std.testing.expect(all.command.history_reset.all);
    try std.testing.expect(all.command.history_reset.jail == null);
    try std.testing.expect(!all.globals.color);
    var diag: ParseDiag = .{};
    try std.testing.expectError(error.MissingArgument, parse(&.{ "history", "reset" }, &diag));
    try std.testing.expectError(error.MissingArgument, parse(&.{ "history", "reset", "--all" }, &diag));
    try std.testing.expect(std.mem.indexOf(u8, diag.message(), "IP address") != null);
    try std.testing.expectError(error.MissingArgument, parse(&.{ "history", "reset", "192.0.2.10" }, &diag));
    try std.testing.expectError(error.MissingArgument, parse(&.{ "history", "reset", "192.0.2.10", "--jail", "sshd", "--all" }, &diag));
    try std.testing.expect(std.mem.indexOf(u8, diag.message(), "exactly one") != null);
    try std.testing.expectError(error.TooManyArguments, parse(&.{ "history", "reset", "192.0.2.10", "192.0.2.11", "--all" }, &diag));
    try std.testing.expectError(error.UnknownFlag, parse(&.{ "history", "reset", "--limit", "5" }, &diag));
    const paging = try parseOk(&.{ "history", "--jail", "sshd" });
    try std.testing.expect(paging.command == .history);
}

test "args: ban with jail and duration" {
    const p = try parseOk(&.{ "ban", "1.2.3.4", "--duration", "3600", "--jail", "sshd" });
    try std.testing.expectEqualStrings("sshd", p.command.ban.jail.?);
    try std.testing.expectEqual(@as(u64, 3600), p.command.ban.duration_s.?);
}

test "args: ban requires ip" {
    var diag: ParseDiag = .{};
    try std.testing.expectError(error.MissingArgument, parse(&.{"ban"}, &diag));
    try std.testing.expect(std.mem.indexOf(u8, diag.message(), "IP address") != null);
}

test "args: ban rejects extra positional" {
    var diag: ParseDiag = .{};
    try std.testing.expectError(error.TooManyArguments, parse(&.{ "ban", "1.2.3.4", "5.6.7.8", "--jail", "sshd" }, &diag));
}

test "args: unban with jail" {
    const p = try parseOk(&.{ "unban", "::1", "--jail", "sshd" });
    try std.testing.expectEqualStrings("::1", p.command.unban.ip);
    try std.testing.expectEqualStrings("sshd", p.command.unban.jail.?);
}

test "args: list with no jail" {
    const p = try parseOk(&.{"list"});
    try std.testing.expect(p.command == .list);
    try std.testing.expect(p.command.list.jail == null);
}

test "args: list with jail filter" {
    const p = try parseOk(&.{ "list", "--jail", "sshd" });
    try std.testing.expectEqualStrings("sshd", p.command.list.jail.?);
}

test "args: jails command" {
    const p = try parseOk(&.{"jails"});
    try std.testing.expect(p.command == .jails);
}

test "args: reload command" {
    const p = try parseOk(&.{"reload"});
    try std.testing.expect(p.command == .reload);
}

test "args: version command (remote)" {
    const p = try parseOk(&.{"version"});
    try std.testing.expect(p.command == .remote_version);
}

test "args: completions bash" {
    const p = try parseOk(&.{ "completions", "bash" });
    try std.testing.expect(p.command == .completions);
    try std.testing.expectEqual(Shell.bash, p.command.completions);
}

test "args: completions rejects unknown shell" {
    var diag: ParseDiag = .{};
    try std.testing.expectError(error.InvalidValue, parse(&.{ "completions", "ksh" }, &diag));
}

test "args: completions requires shell" {
    var diag: ParseDiag = .{};
    try std.testing.expectError(error.MissingArgument, parse(&.{"completions"}, &diag));
}

test "args: unknown command gets suggestion" {
    var diag: ParseDiag = .{};
    try std.testing.expectError(error.UnknownCommand, parse(&.{"statu"}, &diag));
    try std.testing.expect(std.mem.indexOf(u8, diag.message(), "status") != null);
}

test "args: unknown command with no close match" {
    var diag: ParseDiag = .{};
    try std.testing.expectError(error.UnknownCommand, parse(&.{"xyzzy"}, &diag));
    try std.testing.expect(std.mem.indexOf(u8, diag.message(), "xyzzy") != null);
}

test "args: unknown flag on subcommand" {
    var diag: ParseDiag = .{};
    try std.testing.expectError(error.UnknownFlag, parse(&.{ "ban", "1.2.3.4", "--jail", "sshd", "--frobnicate" }, &diag));
}

test "args: status rejects extra positional" {
    var diag: ParseDiag = .{};
    try std.testing.expectError(error.TooManyArguments, parse(&.{ "status", "oops" }, &diag));
}

test "args: --timeout rejects non-integer" {
    var diag: ParseDiag = .{};
    try std.testing.expectError(error.InvalidValue, parse(&.{ "--timeout", "soon", "status" }, &diag));
}

test "args: editDistance identity" {
    try std.testing.expectEqual(@as(usize, 0), editDistance("status", "status"));
}

test "args: editDistance one substitution" {
    try std.testing.expectEqual(@as(usize, 1), editDistance("statue", "status"));
}

test "args: editDistance one insertion" {
    try std.testing.expectEqual(@as(usize, 1), editDistance("statu", "status"));
}

test "args: editDistance case insensitive" {
    try std.testing.expectEqual(@as(usize, 0), editDistance("STATUS", "status"));
}

test "args: closestCommand typo" {
    try std.testing.expectEqualStrings("status", closestCommand("stats").?);
    try std.testing.expectEqualStrings("ban", closestCommand("bam").?);
    try std.testing.expectEqualStrings("unban", closestCommand("unbn").?);
    try std.testing.expectEqualStrings("jails", closestCommand("jals").?);
    try std.testing.expectEqualStrings("jail", closestCommand("jail").?);
}

test "args: closestCommand far input returns null" {
    try std.testing.expect(closestCommand("completely-unrelated-input-xyz") == null);
}

test "args: helpFor returns topical help" {
    try std.testing.expect(std.mem.indexOf(u8, helpFor("ban"), "ban <ip>") != null);
    try std.testing.expect(std.mem.indexOf(u8, helpFor("unban"), "unban <ip>") != null);
    try std.testing.expect(std.mem.indexOf(u8, helpFor("list"), "--jail") != null);
    try std.testing.expect(std.mem.indexOf(u8, helpFor("jail"), "jail pause <name>") != null);
    try std.testing.expect(std.mem.indexOf(u8, helpFor("ban"), "--scope net <cidr>") != null);
    try std.testing.expect(std.mem.indexOf(u8, helpFor("history"), "history reset <ip> --all") != null);
    try std.testing.expect(std.mem.indexOf(u8, helpFor("completions"), "bash") != null);
    try std.testing.expect(std.mem.indexOf(u8, helpFor(null), "fail2zig") != null);
}

test "args: config command takes no arguments" {
    const p = try parseOk(&.{"config"});
    try std.testing.expect(p.command == .config);
    var diag: ParseDiag = .{};
    try std.testing.expectError(error.TooManyArguments, parse(&.{ "config", "sshd" }, &diag));
}

test "args: history defaults and flags" {
    const p = try parseOk(&.{"history"});
    try std.testing.expect(p.command == .history);
    try std.testing.expect(p.command.history.jail == null);
    try std.testing.expect(p.command.history.limit == null);
    try std.testing.expect(p.command.history.cursor == null);
    const q = try parseOk(&.{ "history", "--jail", "sshd", "--limit", "256", "--cursor", "aDoy", "--output", "json" });
    try std.testing.expectEqualStrings("sshd", q.command.history.jail.?);
    try std.testing.expectEqual(@as(u32, 256), q.command.history.limit.?);
    try std.testing.expectEqualStrings("aDoy", q.command.history.cursor.?);
    try std.testing.expectEqual(OutputFormat.json, q.globals.output);
}

test "args: history rejects bad limits, empty cursor and positionals" {
    var diag: ParseDiag = .{};
    try std.testing.expectError(error.InvalidValue, parse(&.{ "history", "--limit", "0" }, &diag));
    try std.testing.expectError(error.InvalidValue, parse(&.{ "history", "--limit", "257" }, &diag));
    try std.testing.expectError(error.InvalidValue, parse(&.{ "history", "--limit", "ten" }, &diag));
    try std.testing.expectError(error.MissingValue, parse(&.{ "history", "--cursor" }, &diag));
    try std.testing.expectError(error.InvalidValue, parse(&.{ "history", "--cursor", "" }, &diag));
    try std.testing.expectError(error.TooManyArguments, parse(&.{ "history", "sshd" }, &diag));
    try std.testing.expectError(error.UnknownFlag, parse(&.{ "history", "--since", "1h" }, &diag));
}

test "args: help covers config and history" {
    try std.testing.expect(std.mem.indexOf(u8, helpFor("config"), "effective configuration") != null);
    try std.testing.expect(std.mem.indexOf(u8, helpFor("history"), "--cursor") != null);
    try std.testing.expect(std.mem.indexOf(u8, help_top, "history") != null);
    try std.testing.expect(std.mem.indexOf(u8, help_top, "config") != null);
    try std.testing.expect(std.mem.indexOf(u8, help_top, "fail2zig-client") == null);
    try std.testing.expectEqualStrings("history", closestCommand("histroy").?);
}

test "args: use shared types" {
    _ = shared.IpAddress;
    _ = shared.JailId;
}

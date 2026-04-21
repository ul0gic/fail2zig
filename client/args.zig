//! Command-line argument parser for fail2zig-client.
//!
//! Grammar:
//!   fail2zig-client [global-flags] <command> [command-args]
//!
//! Global flags (order-independent, may appear before or after the command):
//!   --socket <path>      Unix socket path
//!   --output <fmt>       table | json | plain
//!   --no-color           Disable ANSI color escapes
//!   --timeout <ms>       Command timeout in milliseconds
//!   --help, -h           Show help and exit
//!   --version, -V        Print client version and exit (no daemon call)
//!
//! Commands:
//!   status
//!   ban <ip> [--jail <name>] [--duration <seconds>]
//!   unban <ip> [--jail <name>]
//!   list [--jail <name>]
//!   jails
//!   reload
//!   version
//!   completions <bash|zsh|fish>

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

/// All commands the client can dispatch. Strings hold borrowed views into argv
/// — parsed args share lifetime with the caller's argv allocation.
pub const Command = union(enum) {
    help: ?[]const u8, // optional sub-topic
    version: void, // client-side version (no daemon call)
    status: void,
    ban: BanArgs,
    unban: UnbanArgs,
    list: ListArgs,
    jails: void,
    reload: void,
    remote_version: void, // daemon's version response
    completions: Shell,

    pub const BanArgs = struct {
        ip: []const u8,
        jail: ?[]const u8 = null,
        duration_s: ?u64 = null,
    };

    pub const UnbanArgs = struct {
        ip: []const u8,
        jail: ?[]const u8 = null,
    };

    pub const ListArgs = struct {
        jail: ?[]const u8 = null,
    };
};

pub const Globals = struct {
    socket_path: []const u8 = default_socket_path,
    output: OutputFormat = .table,
    color: bool = true, // true if color allowed; still gated by isatty at render time
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

/// Parsed error context. The `message` lives in `buf` and is valid for the
/// parser's lifetime OR until the caller copies it.
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

/// Parse argv (excluding program name). Returns Parsed on success; on error,
/// `diag` is populated with a user-facing message.
pub fn parse(argv: []const []const u8, diag: *ParseDiag) Error!Parsed {
    var globals = Globals{};
    var i: usize = 0;

    // Phase 1: eat global flags up to the first non-flag (the command).
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
        // Non-flag -> it's the command. Stop phase 1.
        break;
    }

    if (i >= argv.len) {
        diag.set("no command given (try 'fail2zig-client --help')", .{});
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
        diag.set("unknown command '{s}' (try 'fail2zig-client --help')", .{cmd_str});
    }
    return error.UnknownCommand;
}

fn expectNoPositional(rest: []const []const u8, cmd: []const u8, diag: *ParseDiag, globals: *Globals) Error!void {
    // Allow trailing global flags (e.g. `status --output json`), but no positionals.
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
        diag.set("command 'ban' requires an IP address (usage: ban <ip> [--jail <name>] [--duration <s>])", .{});
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
        diag.set("command 'unban' requires an IP address (usage: unban <ip> [--jail <name>])", .{});
        return error.MissingArgument;
    }
    return Parsed{ .globals = globals.*, .command = .{ .unban = args } };
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

/// Recognize a global flag appearing after the command. Returns true if
/// consumed (and advances `idx` past the value). Unknown flags return false
/// so the caller can emit a command-specific error.
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

// ============================================================================
// Command suggestion (Levenshtein distance)
// ============================================================================

pub const known_commands = [_][]const u8{
    "status",
    "ban",
    "unban",
    "list",
    "jails",
    "reload",
    "version",
    "completions",
    "help",
};

/// Suggest the closest known command within edit distance 3; returns null if
/// no command is close enough.
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
    // Only suggest if we're within an edit distance of 3 (avoids nonsensical
    // suggestions for totally unrelated input).
    if (best_dist <= 3) return best;
    return null;
}

/// Classic Levenshtein distance with a 2-row rolling buffer, case-insensitive
/// for ASCII letters. Max supported input length: 128 bytes (CLI commands are
/// tiny; longer inputs return max distance).
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

// ============================================================================
// Help text
// ============================================================================

pub const help_top =
    \\fail2zig-client — query and control the fail2zig daemon
    \\
    \\USAGE:
    \\    fail2zig-client [global-flags] <command> [args]
    \\
    \\COMMANDS:
    \\    status              Show daemon status (uptime, memory, active bans)
    \\    ban <ip>            Manually ban an IP
    \\    unban <ip>          Manually unban an IP
    \\    list                List active bans (all or per-jail with --jail)
    \\    jails               List configured jails
    \\    reload              Trigger config reload
    \\    version             Show client and daemon version
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
    \\    fail2zig-client status
    \\    fail2zig-client ban 45.227.253.98 --jail sshd --duration 3600
    \\    fail2zig-client list --jail sshd --output json
    \\    fail2zig-client completions bash > /etc/bash_completion.d/fail2zig-client
    \\
;

pub const help_ban =
    \\fail2zig-client ban — manually ban an IP address
    \\
    \\USAGE:
    \\    fail2zig-client ban <ip> [--jail <name>] [--duration <seconds>]
    \\
    \\ARGS:
    \\    <ip>                IPv4 or IPv6 address (e.g. 1.2.3.4, ::1)
    \\
    \\FLAGS:
    \\    --jail <name>       Target jail (uses first jail if omitted)
    \\    --duration <s>      Ban duration in seconds (uses jail default if omitted)
    \\
;

pub const help_unban =
    \\fail2zig-client unban — manually unban an IP address
    \\
    \\USAGE:
    \\    fail2zig-client unban <ip> [--jail <name>]
    \\
    \\ARGS:
    \\    <ip>                IPv4 or IPv6 address
    \\
    \\FLAGS:
    \\    --jail <name>       Unban only from this jail (default: all jails)
    \\
;

pub const help_list =
    \\fail2zig-client list — list active bans
    \\
    \\USAGE:
    \\    fail2zig-client list [--jail <name>]
    \\
    \\FLAGS:
    \\    --jail <name>       Filter by jail
    \\
;

pub const help_completions =
    \\fail2zig-client completions — generate shell completion script
    \\
    \\USAGE:
    \\    fail2zig-client completions <shell>
    \\
    \\ARGS:
    \\    <shell>             One of: bash, zsh, fish
    \\
    \\INSTALL:
    \\    bash:  fail2zig-client completions bash > /etc/bash_completion.d/fail2zig-client
    \\    zsh:   fail2zig-client completions zsh  > /usr/share/zsh/site-functions/_fail2zig-client
    \\    fish:  fail2zig-client completions fish > ~/.config/fish/completions/fail2zig-client.fish
    \\
;

pub fn helpFor(topic: ?[]const u8) []const u8 {
    const t = topic orelse return help_top;
    if (std.mem.eql(u8, t, "ban")) return help_ban;
    if (std.mem.eql(u8, t, "unban")) return help_unban;
    if (std.mem.eql(u8, t, "list")) return help_list;
    if (std.mem.eql(u8, t, "completions")) return help_completions;
    return help_top;
}

// ============================================================================
// Tests
// ============================================================================

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

test "args: ban with ip only" {
    const p = try parseOk(&.{ "ban", "1.2.3.4" });
    try std.testing.expect(p.command == .ban);
    try std.testing.expectEqualStrings("1.2.3.4", p.command.ban.ip);
    try std.testing.expect(p.command.ban.jail == null);
    try std.testing.expect(p.command.ban.duration_s == null);
}

test "args: ban with jail and duration" {
    const p = try parseOk(&.{ "ban", "1.2.3.4", "--jail", "sshd", "--duration", "3600" });
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
    try std.testing.expectError(error.TooManyArguments, parse(&.{ "ban", "1.2.3.4", "5.6.7.8" }, &diag));
}

test "args: unban with ip only" {
    const p = try parseOk(&.{ "unban", "1.2.3.4" });
    try std.testing.expectEqualStrings("1.2.3.4", p.command.unban.ip);
    try std.testing.expect(p.command.unban.jail == null);
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
    try std.testing.expectError(error.UnknownFlag, parse(&.{ "ban", "1.2.3.4", "--frobnicate" }, &diag));
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
    try std.testing.expectEqualStrings("jails", closestCommand("jail").?);
}

test "args: closestCommand far input returns null" {
    try std.testing.expect(closestCommand("completely-unrelated-input-xyz") == null);
}

test "args: helpFor returns topical help" {
    try std.testing.expect(std.mem.indexOf(u8, helpFor("ban"), "ban <ip>") != null);
    try std.testing.expect(std.mem.indexOf(u8, helpFor("unban"), "unban <ip>") != null);
    try std.testing.expect(std.mem.indexOf(u8, helpFor("list"), "--jail") != null);
    try std.testing.expect(std.mem.indexOf(u8, helpFor("completions"), "bash") != null);
    try std.testing.expect(std.mem.indexOf(u8, helpFor(null), "fail2zig-client") != null);
}

test "args: use shared types" {
    // Ensure shared types are reachable from this module (keeps linkage honest).
    _ = shared.IpAddress;
    _ = shared.JailId;
}

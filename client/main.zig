// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! fail2zig-client — CLI entry point.
//!
//! Parses argv, dispatches to a handler, prints formatted output. Exit codes:
//!   0 = success
//!   1 = daemon returned an error response
//!   2 = client-side error (bad args, invalid IP, invalid config)
//!   3 = connection failed (daemon unreachable, timeout, permission)
//!
//! All I/O is synchronous and minimal — the client is a thin, fast shim over
//! the binary IPC protocol defined in `shared/protocol.zig`.

const std = @import("std");
const shared = @import("shared");

pub const args = @import("args.zig");
pub const socket = @import("socket.zig");
pub const format = @import("format.zig");
pub const completions = @import("completions.zig");

pub const client_version = "0.1.0";

pub const ExitCode = enum(u8) {
    success = 0,
    daemon_error = 1,
    client_error = 2,
    connection_failed = 3,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Gather argv (skipping program name).
    const raw_argv = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, raw_argv);
    const argv: []const []const u8 = if (raw_argv.len > 0) raw_argv[1..] else raw_argv;

    const code = run(allocator, argv, std.io.getStdOut().writer(), std.io.getStdErr().writer());
    std.process.exit(@intFromEnum(code));
}

/// Execute the CLI with the given argv (excluding program name). Returns an
/// exit code. Separated from `main` so it can be tested by passing in
/// pre-built argv arrays and capturing output buffers.
pub fn run(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) ExitCode {
    var diag: args.ParseDiag = .{};
    const parsed = args.parse(argv, &diag) catch {
        stderr.print("error: {s}\n", .{diag.message()}) catch {};
        stderr.writeAll("try 'fail2zig-client --help' for usage\n") catch {};
        return .client_error;
    };

    const color = format.Color{ .enabled = format.shouldColor(parsed.globals.color) };

    switch (parsed.command) {
        .help => |topic| {
            stdout.writeAll(args.helpFor(topic)) catch {};
            return .success;
        },
        .version => {
            stdout.print("fail2zig-client v{s}\n", .{client_version}) catch {};
            return .success;
        },
        .completions => |shell| {
            const script = switch (shell) {
                .bash => completions.generateBash(),
                .zsh => completions.generateZsh(),
                .fish => completions.generateFish(),
            };
            stdout.writeAll(script) catch {};
            return .success;
        },

        .status => return doRequest(allocator, parsed.globals, .{ .status = {} }, stdout, stderr, color, formatStatusCmd),
        .list => |l| {
            const jail: ?shared.JailId = parseJailId(l.jail, stderr) catch return .client_error;
            const cmd = shared.Command{ .list = .{ .jail = jail } };
            return doRequest(allocator, parsed.globals, cmd, stdout, stderr, color, formatListCmd);
        },
        .jails => return doRequest(allocator, parsed.globals, .{ .list_jails = {} }, stdout, stderr, color, formatJailsCmd),
        .reload => return doRequest(allocator, parsed.globals, .{ .reload = {} }, stdout, stderr, color, formatReloadCmd),
        .remote_version => return doRequest(allocator, parsed.globals, .{ .version = {} }, stdout, stderr, color, formatVersionCmd),
        .ban => |b| {
            const ip = parseIp(b.ip, stderr) catch return .client_error;
            const jail_str = b.jail orelse {
                stderr.writeAll("error: ban requires --jail <name>\n") catch {};
                return .client_error;
            };
            const jail = parseJailIdRequired(jail_str, stderr) catch return .client_error;
            const cmd = shared.Command{ .ban = .{ .ip = ip, .jail = jail, .duration = b.duration_s } };
            return doRequest(allocator, parsed.globals, cmd, stdout, stderr, color, formatBanCmd);
        },
        .unban => |u| {
            const ip = parseIp(u.ip, stderr) catch return .client_error;
            const jail: ?shared.JailId = parseJailId(u.jail, stderr) catch return .client_error;
            const cmd = shared.Command{ .unban = .{ .ip = ip, .jail = jail } };
            return doRequest(allocator, parsed.globals, cmd, stdout, stderr, color, formatUnbanCmd);
        },
    }
}

// ============================================================================
// Request plumbing
// ============================================================================

const FormatFn = *const fn (
    std.mem.Allocator,
    anytype,
    []const u8,
    format.OutputFormat,
    format.Color,
) anyerror!void;

fn doRequest(
    allocator: std.mem.Allocator,
    globals: args.Globals,
    cmd: shared.Command,
    stdout: anytype,
    stderr: anytype,
    color: format.Color,
    comptime formatter: anytype,
) ExitCode {
    var diag: socket.DiagBuf = .{};
    var client = socket.connect(allocator, globals.socket_path, globals.timeout_ms, &diag) catch {
        stderr.print("error: {s}\n", .{diag.message()}) catch {};
        return .connection_failed;
    };
    defer client.close();

    const resp = client.sendCommand(cmd) catch {
        stderr.print("error: {s}\n", .{client.errorMessage()}) catch {};
        return .connection_failed;
    };
    defer resp.deinit(allocator);

    switch (resp) {
        .ok => |o| {
            formatter(allocator, stdout, o.payload, globals.output, color) catch |e| {
                stderr.print("error: failed to format response: {s}\n", .{@errorName(e)}) catch {};
                return .client_error;
            };
            return .success;
        },
        .err => |e| {
            format.formatError(stderr, e.code, e.message, globals.output, color) catch {};
            return .daemon_error;
        },
    }
}

// Per-command formatter shims — these exist to give doRequest a stable signature
// that works for every command, even ones with extra arguments (like version).
fn formatStatusCmd(
    allocator: std.mem.Allocator,
    writer: anytype,
    payload: []const u8,
    fmt: format.OutputFormat,
    color: format.Color,
) !void {
    return format.formatStatus(allocator, writer, payload, fmt, color);
}

fn formatListCmd(
    allocator: std.mem.Allocator,
    writer: anytype,
    payload: []const u8,
    fmt: format.OutputFormat,
    color: format.Color,
) !void {
    return format.formatList(allocator, writer, payload, fmt, color);
}

fn formatJailsCmd(
    allocator: std.mem.Allocator,
    writer: anytype,
    payload: []const u8,
    fmt: format.OutputFormat,
    color: format.Color,
) !void {
    return format.formatJails(allocator, writer, payload, fmt, color);
}

fn formatReloadCmd(
    allocator: std.mem.Allocator,
    writer: anytype,
    payload: []const u8,
    fmt: format.OutputFormat,
    color: format.Color,
) !void {
    return format.formatReload(allocator, writer, payload, fmt, color);
}

fn formatBanCmd(
    allocator: std.mem.Allocator,
    writer: anytype,
    payload: []const u8,
    fmt: format.OutputFormat,
    color: format.Color,
) !void {
    return format.formatBan(allocator, writer, payload, fmt, color);
}

fn formatUnbanCmd(
    allocator: std.mem.Allocator,
    writer: anytype,
    payload: []const u8,
    fmt: format.OutputFormat,
    color: format.Color,
) !void {
    return format.formatUnban(allocator, writer, payload, fmt, color);
}

fn formatVersionCmd(
    allocator: std.mem.Allocator,
    writer: anytype,
    payload: []const u8,
    fmt: format.OutputFormat,
    color: format.Color,
) !void {
    return format.formatVersion(allocator, writer, client_version, payload, fmt, color);
}

// ============================================================================
// Input validation helpers
// ============================================================================

fn parseIp(s: []const u8, stderr: anytype) !shared.IpAddress {
    return shared.IpAddress.parse(s) catch {
        stderr.print(
            "error: Invalid IP address: '{s}'. Expected IPv4 (1.2.3.4) or IPv6 (::1).\n",
            .{s},
        ) catch {};
        return error.InvalidIp;
    };
}

fn parseJailId(opt: ?[]const u8, stderr: anytype) !?shared.JailId {
    const s = opt orelse return null;
    return try parseJailIdRequired(s, stderr);
}

fn parseJailIdRequired(s: []const u8, stderr: anytype) !shared.JailId {
    return shared.JailId.fromSlice(s) catch |e| {
        switch (e) {
            error.JailIdEmpty => stderr.writeAll("error: jail name cannot be empty\n") catch {},
            error.JailIdTooLong => stderr.print(
                "error: jail name too long (max 64 bytes): '{s}'\n",
                .{s},
            ) catch {},
        }
        return error.InvalidJail;
    };
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

fn runCapture(argv: []const []const u8) !struct {
    code: ExitCode,
    out: []u8,
    err: []u8,
} {
    var out_list = std.ArrayList(u8).init(testing.allocator);
    defer out_list.deinit();
    var err_list = std.ArrayList(u8).init(testing.allocator);
    defer err_list.deinit();
    const code = run(testing.allocator, argv, out_list.writer(), err_list.writer());
    return .{
        .code = code,
        .out = try out_list.toOwnedSlice(),
        .err = try err_list.toOwnedSlice(),
    };
}

test "client: --help exits 0 and prints usage" {
    const r = try runCapture(&.{"--help"});
    defer testing.allocator.free(r.out);
    defer testing.allocator.free(r.err);
    try testing.expectEqual(ExitCode.success, r.code);
    try testing.expect(std.mem.indexOf(u8, r.out, "fail2zig-client") != null);
    try testing.expect(std.mem.indexOf(u8, r.out, "COMMANDS:") != null);
}

test "client: --version exits 0 and prints client version" {
    const r = try runCapture(&.{"--version"});
    defer testing.allocator.free(r.out);
    defer testing.allocator.free(r.err);
    try testing.expectEqual(ExitCode.success, r.code);
    try testing.expect(std.mem.indexOf(u8, r.out, "fail2zig-client v0.1.0") != null);
}

test "client: no args exits 2 with error about missing command" {
    const r = try runCapture(&.{});
    defer testing.allocator.free(r.out);
    defer testing.allocator.free(r.err);
    try testing.expectEqual(ExitCode.client_error, r.code);
    try testing.expect(std.mem.indexOf(u8, r.err, "no command") != null);
}

test "client: unknown command exits 2 with suggestion" {
    const r = try runCapture(&.{"statu"});
    defer testing.allocator.free(r.out);
    defer testing.allocator.free(r.err);
    try testing.expectEqual(ExitCode.client_error, r.code);
    try testing.expect(std.mem.indexOf(u8, r.err, "unknown command") != null);
    try testing.expect(std.mem.indexOf(u8, r.err, "status") != null);
}

test "client: ban with invalid IP exits 2" {
    const r = try runCapture(&.{ "ban", "not-an-ip", "--jail", "sshd" });
    defer testing.allocator.free(r.out);
    defer testing.allocator.free(r.err);
    try testing.expectEqual(ExitCode.client_error, r.code);
    try testing.expect(std.mem.indexOf(u8, r.err, "Invalid IP address") != null);
    try testing.expect(std.mem.indexOf(u8, r.err, "not-an-ip") != null);
}

test "client: ban without --jail exits 2" {
    const r = try runCapture(&.{ "ban", "1.2.3.4" });
    defer testing.allocator.free(r.out);
    defer testing.allocator.free(r.err);
    try testing.expectEqual(ExitCode.client_error, r.code);
    try testing.expect(std.mem.indexOf(u8, r.err, "requires --jail") != null);
}

test "client: status against unreachable socket exits 3" {
    const r = try runCapture(&.{
        "--socket",  "/tmp/fail2zig-does-not-exist-xyzzy.sock",
        "--timeout", "500",
        "status",
    });
    defer testing.allocator.free(r.out);
    defer testing.allocator.free(r.err);
    try testing.expectEqual(ExitCode.connection_failed, r.code);
    try testing.expect(std.mem.indexOf(u8, r.err, "Cannot connect") != null);
}

test "client: unban against unreachable socket exits 3" {
    const r = try runCapture(&.{
        "--socket",  "/tmp/fail2zig-does-not-exist-xyzzy.sock",
        "--timeout", "500",
        "unban",     "1.2.3.4",
    });
    defer testing.allocator.free(r.out);
    defer testing.allocator.free(r.err);
    try testing.expectEqual(ExitCode.connection_failed, r.code);
}

test "client: completions bash emits script with shebang" {
    const r = try runCapture(&.{ "completions", "bash" });
    defer testing.allocator.free(r.out);
    defer testing.allocator.free(r.err);
    try testing.expectEqual(ExitCode.success, r.code);
    try testing.expect(std.mem.startsWith(u8, r.out, "#!/usr/bin/env bash"));
}

test "client: completions zsh emits #compdef" {
    const r = try runCapture(&.{ "completions", "zsh" });
    defer testing.allocator.free(r.out);
    defer testing.allocator.free(r.err);
    try testing.expectEqual(ExitCode.success, r.code);
    try testing.expect(std.mem.startsWith(u8, r.out, "#compdef fail2zig-client"));
}

test "client: completions fish emits complete -c" {
    const r = try runCapture(&.{ "completions", "fish" });
    defer testing.allocator.free(r.out);
    defer testing.allocator.free(r.err);
    try testing.expectEqual(ExitCode.success, r.code);
    try testing.expect(std.mem.indexOf(u8, r.out, "complete -c fail2zig-client") != null);
}

test "client: completions unknown shell exits 2" {
    const r = try runCapture(&.{ "completions", "ksh" });
    defer testing.allocator.free(r.out);
    defer testing.allocator.free(r.err);
    try testing.expectEqual(ExitCode.client_error, r.code);
}

test "client: help ban subtopic" {
    const r = try runCapture(&.{ "help", "ban" });
    defer testing.allocator.free(r.out);
    defer testing.allocator.free(r.err);
    try testing.expectEqual(ExitCode.success, r.code);
    try testing.expect(std.mem.indexOf(u8, r.out, "ban <ip>") != null);
}

test "client: imports compile" {
    _ = shared;
    _ = args;
    _ = socket;
    _ = format;
    _ = completions;
}

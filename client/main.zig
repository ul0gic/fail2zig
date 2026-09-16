// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const shared = @import("shared");
const build_options = @import("build_options");

pub const args = @import("args.zig");
pub const socket = @import("socket.zig");
pub const format = @import("format.zig");
pub const completions = @import("completions.zig");

pub const client_version = build_options.version;

pub const ExitCode = enum(u8) {
    success = 0,
    daemon_error = 1,
    client_error = 2,
    connection_failed = 3,
    partial_effect = 4,
    uncertain_effect = 5,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const raw_argv = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, raw_argv);
    const argv: []const []const u8 = if (raw_argv.len > 0) raw_argv[1..] else raw_argv;

    const code = run(allocator, argv, std.io.getStdOut().writer(), std.io.getStdErr().writer());
    std.process.exit(@intFromEnum(code));
}

pub fn run(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) ExitCode {
    var diag: args.ParseDiag = .{};
    const parsed = args.parse(argv, &diag) catch {
        stderr.print("error: {s}\n", .{diag.message()}) catch {};
        stderr.writeAll("try 'fail2zig --help' for usage\n") catch {};
        return .client_error;
    };

    const color = format.Color{ .enabled = format.shouldColor(parsed.globals.color) };

    switch (parsed.command) {
        .help => |topic| {
            stdout.writeAll(args.helpFor(topic)) catch {};
            return .success;
        },
        .version => {
            stdout.print("fail2zig {s}\n", .{client_version}) catch {};
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
        .reload => return doReload(allocator, parsed.globals, stdout, stderr),
        .config => return doQuery(allocator, parsed.globals, stdout, stderr, color, "config", null, null, null, format.formatConfig),
        .history => |q| {
            if (q.jail) |jail_str| _ = parseJailIdRequired(jail_str, stderr) catch return .client_error;
            return doQuery(allocator, parsed.globals, stdout, stderr, color, "history", q.jail, q.limit, q.cursor, format.formatHistory);
        },
        .jail_admin => |j| {
            _ = parseJailIdRequired(j.name, stderr) catch return .client_error;
            const kind: []const u8 = switch (j.action) {
                .enable => "group_enable",
                .disable => "group_disable",
                .pause => "group_pause",
                .@"resume" => "group_resume",
            };
            return doAdmin(allocator, parsed.globals, stdout, stderr, .{ .kind = kind, .jail = j.name });
        },
        .history_reset => |h| {
            if (h.jail) |jail_str| _ = parseJailIdRequired(jail_str, stderr) catch return .client_error;
            _ = parseIp(h.address, stderr) catch return .client_error;
            return doAdmin(allocator, parsed.globals, stdout, stderr, .{ .kind = "history_reset", .jail = h.jail, .address = h.address, .all = h.all });
        },
        .remote_version => return doRequest(allocator, parsed.globals, .{ .version = {} }, stdout, stderr, color, formatVersionCmd),
        .ban => |b| {
            _ = parseIp(b.ip, stderr) catch return .client_error;
            const jail_str = b.jail orelse {
                stderr.writeAll("error: ban requires --jail <name>\n") catch {};
                return .client_error;
            };
            _ = parseJailIdRequired(jail_str, stderr) catch return .client_error;
            const scope = scopeSpec(b.ip, b.scope, stderr) catch return .client_error;
            return doAdmin(allocator, parsed.globals, stdout, stderr, .{ .kind = "ban", .jail = jail_str, .address = scope.address, .prefix = scope.prefix, .duration_s = b.duration_s });
        },
        .unban => |u| {
            _ = parseIp(u.ip, stderr) catch return .client_error;
            const jail_str = u.jail orelse {
                stderr.writeAll("error: unban requires --jail <name>\n") catch {};
                return .client_error;
            };
            _ = parseJailIdRequired(jail_str, stderr) catch return .client_error;
            const scope = scopeSpec(u.ip, u.scope, stderr) catch return .client_error;
            return doAdmin(allocator, parsed.globals, stdout, stderr, .{ .kind = "unban", .jail = jail_str, .address = scope.address, .prefix = scope.prefix });
        },
    }
}

const ScopeSpec = struct { address: []const u8, prefix: ?u8 };

fn scopeSpec(ip: []const u8, scope: ?args.Command.ScopeArgs, stderr: anytype) !ScopeSpec {
    const value = scope orelse return .{ .address = ip, .prefix = null };
    switch (value.kind) {
        .host => return .{ .address = ip, .prefix = null },
        .net => {
            const cidr = value.cidr orelse {
                stderr.writeAll("error: --scope net requires a <cidr>\n") catch {};
                return error.InvalidScope;
            };
            const slash = std.mem.indexOfScalar(u8, cidr, '/') orelse {
                stderr.writeAll("error: --scope net requires <address>/<prefix>\n") catch {};
                return error.InvalidScope;
            };
            const base = cidr[0..slash];
            const prefix = std.fmt.parseInt(u8, cidr[slash + 1 ..], 10) catch {
                stderr.writeAll("error: invalid network prefix\n") catch {};
                return error.InvalidScope;
            };
            const parsed = shared.IpAddress.parse(base) catch {
                stderr.writeAll("error: invalid network address\n") catch {};
                return error.InvalidScope;
            };
            const max: u8 = if (parsed == .ipv4) 32 else 128;
            if (prefix == 0 or prefix > max) {
                stderr.writeAll("error: network prefix out of range\n") catch {};
                return error.InvalidScope;
            }
            return .{ .address = base, .prefix = prefix };
        },
    }
}

fn doQuery(allocator: std.mem.Allocator, globals: args.Globals, stdout: anytype, stderr: anytype, color: format.Color, kind: []const u8, jail: ?[]const u8, limit: ?u32, cursor: ?[]const u8, comptime formatter: anytype) ExitCode {
    var body_bytes: [shared.protocol.max_request_body]u8 = undefined;
    var stream = std.io.fixedBufferStream(&body_bytes);
    std.json.stringify(.{ .schema_version = @as(u32, 1), .kind = kind, .jail = jail, .limit = limit, .cursor = cursor }, .{ .emit_null_optional_fields = false }, stream.writer()) catch return .client_error;
    const body = shared.Command.Body.init(stream.getWritten()) catch return .client_error;
    return doRequest(allocator, globals, .{ .query_v1 = body }, stdout, stderr, color, formatter);
}

pub const AdminSpec = struct {
    kind: []const u8,
    jail: ?[]const u8 = null,
    address: ?[]const u8 = null,
    prefix: ?u8 = null,
    duration_s: ?u64 = null,
    all: bool = false,
    run_id: ?[]const u8 = null,
};

const StatusHead = struct { generation: []const u8 = "", mutation_revision: u64 = 0 };

pub fn doAdmin(allocator: std.mem.Allocator, globals: args.Globals, stdout: anytype, stderr: anytype, spec: AdminSpec) ExitCode {
    var diag: socket.DiagBuf = .{};
    var client = socket.connect(allocator, globals.socket_path, globals.timeout_ms, &diag) catch {
        stderr.print("error: {s}\n", .{diag.message()}) catch {};
        return .connection_failed;
    };
    defer client.close();
    const status_resp = client.sendCommand(.{ .status = {} }) catch {
        stderr.print("error: {s}\n", .{client.errorMessage()}) catch {};
        return .connection_failed;
    };
    defer status_resp.deinit(allocator);
    const head_json = switch (status_resp) {
        .ok => |o| o.payload,
        .err => |e| {
            format.formatError(stderr, e.code, e.message, globals.output, .{ .enabled = false }) catch {};
            return .daemon_error;
        },
    };
    const head = std.json.parseFromSlice(StatusHead, allocator, head_json, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch {
        stderr.writeAll("error: daemon status did not carry a generation\n") catch {};
        return .client_error;
    };
    defer head.deinit();
    client.close();
    client = socket.connect(allocator, globals.socket_path, globals.timeout_ms, &diag) catch {
        stderr.print("error: {s}\n", .{diag.message()}) catch {};
        return .connection_failed;
    };
    var body_bytes: [shared.protocol.max_request_body]u8 = undefined;
    var stream = std.io.fixedBufferStream(&body_bytes);
    std.json.stringify(.{ .schema_version = @as(u32, 1), .kind = spec.kind, .jail = spec.jail, .address = spec.address, .prefix = spec.prefix, .duration_s = spec.duration_s, .all = spec.all, .run_id = spec.run_id, .expected_generation = head.value.generation, .expected_mutation_revision = head.value.mutation_revision }, .{ .emit_null_optional_fields = false }, stream.writer()) catch return .client_error;
    const body = shared.Command.Body.init(stream.getWritten()) catch return .client_error;
    var request_id: [shared.protocol.request_id_bytes]u8 = undefined;
    std.crypto.random.bytes(&request_id);
    const resp = client.sendCommand(.{ .admin_v1 = .{ .request_id = request_id, .body = body } }) catch {
        stderr.print("error: {s}\n", .{client.errorMessage()}) catch {};
        return .connection_failed;
    };
    defer resp.deinit(allocator);
    const payload: []const u8 = switch (resp) {
        .ok => |o| o.payload,
        .err => |e| e.message,
    };
    writeAdminOutcome(allocator, stdout, payload, globals.output) catch |e| {
        if (e != error.BrokenPipe) stderr.print("error: failed to format response: {s}\n", .{@errorName(e)}) catch {};
    };
    return switch (resp) {
        .ok => .success,
        .err => |e| switch (shared.Response.exitClassForCode(e.code)) {
            .partial => .partial_effect,
            .uncertain => .uncertain_effect,
            else => .daemon_error,
        },
    };
}

const AdminOutcome = struct { schema_version: u32 = 0, kind: []const u8 = "", outcome: []const u8 = "", generation: []const u8 = "", mutation_revision: u64 = 0, enforced: bool = false, reasons: []const []const u8 = &.{} };

fn writeAdminOutcome(allocator: std.mem.Allocator, writer: anytype, payload: []const u8, fmt: format.OutputFormat) !void {
    if (fmt == .json) {
        try writer.writeAll(payload);
        if (payload.len == 0 or payload[payload.len - 1] != '\n') try writer.writeAll("\n");
        return;
    }
    const parsed = std.json.parseFromSlice(AdminOutcome, allocator, payload, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch {
        try writer.print("outcome\tunparseable\n{s}\n", .{payload});
        return;
    };
    defer parsed.deinit();
    try writer.print("kind\t{s}\noutcome\t{s}\nenforced\t{}\ngeneration\t{s}\nmutation_revision\t{d}\n", .{ parsed.value.kind, parsed.value.outcome, parsed.value.enforced, parsed.value.generation, parsed.value.mutation_revision });
    for (parsed.value.reasons) |reason| try writer.print("reason\t{s}\n", .{reason});
}

fn doReload(allocator: std.mem.Allocator, globals: args.Globals, stdout: anytype, stderr: anytype) ExitCode {
    var request_id: [shared.protocol.request_id_bytes]u8 = undefined;
    std.crypto.random.bytes(&request_id);
    const body = shared.Command.Body.init("{\"schema_version\":1}") catch return .client_error;
    var diag: socket.DiagBuf = .{};
    var client = socket.connect(allocator, globals.socket_path, globals.timeout_ms, &diag) catch {
        stderr.print("error: {s}\n", .{diag.message()}) catch {};
        return .connection_failed;
    };
    defer client.close();
    const resp = client.sendCommand(.{ .reload_v1 = .{ .request_id = request_id, .body = body } }) catch {
        stderr.print("error: {s}\n", .{client.errorMessage()}) catch {};
        return .connection_failed;
    };
    defer resp.deinit(allocator);
    const payload: []const u8 = switch (resp) {
        .ok => |o| o.payload,
        .err => |e| e.message,
    };
    writeReloadOutcome(allocator, stdout, payload, globals.output) catch |e| {
        if (e != error.BrokenPipe) stderr.print("error: failed to format response: {s}\n", .{@errorName(e)}) catch {};
    };
    return switch (resp) {
        .ok => .success,
        .err => |e| switch (shared.Response.exitClassForCode(e.code)) {
            .partial => .partial_effect,
            .uncertain => .uncertain_effect,
            else => .daemon_error,
        },
    };
}

const ReloadOutcome = struct { schema_version: u32 = 0, outcome: []const u8 = "", generation: []const u8 = "", reasons: []const []const u8 = &.{} };

fn writeReloadOutcome(allocator: std.mem.Allocator, writer: anytype, payload: []const u8, fmt: format.OutputFormat) !void {
    if (fmt == .json) {
        try writer.writeAll(payload);
        if (payload.len == 0 or payload[payload.len - 1] != '\n') try writer.writeAll("\n");
        return;
    }
    const parsed = std.json.parseFromSlice(ReloadOutcome, allocator, payload, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch {
        try writer.print("outcome\tunparseable\n", .{});
        return;
    };
    defer parsed.deinit();
    try writer.print("outcome\t{s}\ngeneration\t{s}\n", .{ parsed.value.outcome, parsed.value.generation });
    for (parsed.value.reasons) |reason| try writer.print("reason\t{s}\n", .{reason});
}

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

    return renderResponse(allocator, resp, globals.output, stdout, stderr, color, formatter);
}

fn renderResponse(
    allocator: std.mem.Allocator,
    resp: shared.Response,
    output: format.OutputFormat,
    stdout: anytype,
    stderr: anytype,
    color: format.Color,
    comptime formatter: anytype,
) ExitCode {
    switch (resp) {
        .ok => |o| {
            formatter(allocator, stdout, o.payload, output, color) catch |e| {
                if (e == error.BrokenPipe) return .success;
                stderr.print("error: failed to format response: {s}\n", .{@errorName(e)}) catch {};
                return .client_error;
            };
            return .success;
        },
        .err => |e| {
            format.formatError(stderr, e.code, e.message, output, color) catch {};
            return .daemon_error;
        },
    }
}

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
    try testing.expect(std.mem.indexOf(u8, r.out, "fail2zig") != null);
    try testing.expect(std.mem.indexOf(u8, r.out, "COMMANDS:") != null);
}

test "client: --version exits 0 and prints client version" {
    const r = try runCapture(&.{"--version"});
    defer testing.allocator.free(r.out);
    defer testing.allocator.free(r.err);
    try testing.expectEqual(ExitCode.success, r.code);

    const expected = "fail2zig " ++ build_options.version;
    try testing.expect(std.mem.indexOf(u8, r.out, expected) != null);
}

test "client: client_version is the build-injected single source of truth" {
    try testing.expectEqualStrings(build_options.version, client_version);
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
        "--jail",    "sshd",
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
    try testing.expect(std.mem.startsWith(u8, r.out, "#compdef fail2zig"));
}

test "client: completions fish emits complete -c" {
    const r = try runCapture(&.{ "completions", "fish" });
    defer testing.allocator.free(r.out);
    defer testing.allocator.free(r.err);
    try testing.expectEqual(ExitCode.success, r.code);
    try testing.expect(std.mem.indexOf(u8, r.out, "complete -c fail2zig") != null);
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

const status_payload = "{\"version\":\"0.3.0\",\"uptime_seconds\":5,\"active_bans\":1}";

test "client: BrokenPipe on stdout is a quiet success (BUG-009)" {
    const BrokenPipe = error{BrokenPipe};
    const writeFn = struct {
        fn write(_: void, _: []const u8) BrokenPipe!usize {
            return error.BrokenPipe;
        }
    }.write;
    const stdout = std.io.GenericWriter(void, BrokenPipe, writeFn){ .context = {} };
    var err_list = std.ArrayList(u8).init(testing.allocator);
    defer err_list.deinit();

    const resp = shared.Response{ .ok = .{ .payload = status_payload } };
    const code = renderResponse(testing.allocator, resp, .table, stdout, err_list.writer(), .{ .enabled = false }, formatStatusCmd);
    try testing.expectEqual(ExitCode.success, code);
    try testing.expectEqualStrings("", err_list.items);
}

test "client: reader-closed pipe on stdout is a quiet success (BUG-009)" {
    const fds = try std.posix.pipe();
    std.posix.close(fds[0]);
    const write_end = std.fs.File{ .handle = fds[1] };
    defer write_end.close();
    var err_list = std.ArrayList(u8).init(testing.allocator);
    defer err_list.deinit();

    const resp = shared.Response{ .ok = .{ .payload = status_payload } };
    const code = renderResponse(testing.allocator, resp, .table, write_end.writer(), err_list.writer(), .{ .enabled = false }, formatStatusCmd);
    try testing.expectEqual(ExitCode.success, code);
    try testing.expectEqualStrings("", err_list.items);
}

test "client: other stdout write errors still exit 2 with a message (BUG-009)" {
    const NoSpace = error{NoSpaceLeft};
    const writeFn = struct {
        fn write(_: void, _: []const u8) NoSpace!usize {
            return error.NoSpaceLeft;
        }
    }.write;
    const stdout = std.io.GenericWriter(void, NoSpace, writeFn){ .context = {} };
    var err_list = std.ArrayList(u8).init(testing.allocator);
    defer err_list.deinit();

    const resp = shared.Response{ .ok = .{ .payload = status_payload } };
    const code = renderResponse(testing.allocator, resp, .table, stdout, err_list.writer(), .{ .enabled = false }, formatStatusCmd);
    try testing.expectEqual(ExitCode.client_error, code);
    try testing.expect(std.mem.indexOf(u8, err_list.items, "failed to format response: NoSpaceLeft") != null);
}

test "client: daemon error response still exits 1 (BUG-009 unchanged path)" {
    var out_list = std.ArrayList(u8).init(testing.allocator);
    defer out_list.deinit();
    var err_list = std.ArrayList(u8).init(testing.allocator);
    defer err_list.deinit();

    const resp = shared.Response{ .err = .{ .code = 4, .message = "no such jail" } };
    const code = renderResponse(testing.allocator, resp, .table, out_list.writer(), err_list.writer(), .{ .enabled = false }, formatStatusCmd);
    try testing.expectEqual(ExitCode.daemon_error, code);
    try testing.expect(std.mem.indexOf(u8, err_list.items, "no such jail") != null);
}

test "client: imports compile" {
    _ = shared;
    _ = args;
    _ = socket;
    _ = format;
    _ = completions;
}

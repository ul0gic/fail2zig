// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const shared = @import("shared");
const cli = @import("cli");
const inspect = @import("../migration/inspect.zig");
const snapshot = @import("../migration/sqlite_snapshot.zig");
const plan_mod = @import("../migration/plan.zig");
const journal = @import("../migration/journal.zig");
const cutover = @import("migrate_cutover.zig");
const import_mod = @import("../migration/import.zig");

pub const ExitClass = shared.ExitClass;
pub const Output = enum { json, table };

fn usage(stderr: anytype) ExitClass {
    stderr.writeAll(cli.args.help_migrate) catch {};
    return .usage;
}

const Parsed = struct {
    source_dir: ?[]const u8 = null,
    source_db: ?[]const u8 = null,
    staging_dir: ?[]const u8 = null,
    out: ?[]const u8 = null,
    plan: ?[]const u8 = null,
    snapshot_path: ?[]const u8 = null,
    continuity: plan_mod.Continuity = .reset_replay,
    replay_window_s: ?u32 = null,
    output: Output = .json,
    state_file: ?[]const u8 = null,
    backend: ?import_mod.Backend = null,
    socket_path: ?[]const u8 = null,
    run_id: ?[32]u8 = null,
    source_verified: bool = false,
    runtime_socket: ?[]const u8 = null,
};

fn parseFlags(args: []const []const u8, stderr: anytype) ?Parsed {
    var out: Parsed = .{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        const value: ?[]const u8 = if (i + 1 < args.len) args[i + 1] else null;
        if (std.mem.eql(u8, a, "--source-dir")) {
            out.source_dir = value orelse return null;
            i += 1;
        } else if (std.mem.eql(u8, a, "--source-db")) {
            out.source_db = value orelse return null;
            i += 1;
        } else if (std.mem.eql(u8, a, "--staging-dir")) {
            out.staging_dir = value orelse return null;
            i += 1;
        } else if (std.mem.eql(u8, a, "--out")) {
            out.out = value orelse return null;
            i += 1;
        } else if (std.mem.eql(u8, a, "--plan")) {
            out.plan = value orelse return null;
            i += 1;
        } else if (std.mem.eql(u8, a, "--snapshot")) {
            out.snapshot_path = value orelse return null;
            i += 1;
        } else if (std.mem.eql(u8, a, "--continuity")) {
            const text = value orelse return null;
            out.continuity = if (std.mem.eql(u8, text, "lossless")) .lossless else if (std.mem.eql(u8, text, "reset-replay")) .reset_replay else {
                stderr.print("error: unknown continuity '{s}'\n", .{text}) catch {};
                return null;
            };
            i += 1;
        } else if (std.mem.eql(u8, a, "--replay-window")) {
            const text = value orelse return null;
            out.replay_window_s = std.fmt.parseInt(u32, text, 10) catch {
                stderr.print("error: invalid replay window '{s}'\n", .{text}) catch {};
                return null;
            };
            i += 1;
        } else if (std.mem.eql(u8, a, "--state-file")) {
            out.state_file = value orelse return null;
            i += 1;
        } else if (std.mem.eql(u8, a, "--socket")) {
            out.socket_path = value orelse return null;
            i += 1;
        } else if (std.mem.eql(u8, a, "--backend")) {
            const text = value orelse return null;
            out.backend = std.meta.stringToEnum(import_mod.Backend, text) orelse {
                stderr.print("error: unknown backend '{s}'\n", .{text}) catch {};
                return null;
            };
            i += 1;
        } else if (std.mem.eql(u8, a, "--run-id")) {
            const text = value orelse return null;
            if (text.len != 64) {
                stderr.writeAll("error: --run-id must be 64 hex characters\n") catch {};
                return null;
            }
            var id: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&id, text) catch {
                stderr.writeAll("error: --run-id is not hex\n") catch {};
                return null;
            };
            out.run_id = id;
            i += 1;
        } else if (std.mem.eql(u8, a, "--runtime-socket")) {
            out.runtime_socket = value orelse return null;
            i += 1;
        } else if (std.mem.eql(u8, a, "--source-verified")) {
            out.source_verified = true;
        } else if (std.mem.eql(u8, a, "--output")) {
            const text = value orelse return null;
            out.output = std.meta.stringToEnum(Output, text) orelse {
                stderr.print("error: unknown output format '{s}'\n", .{text}) catch {};
                return null;
            };
            i += 1;
        } else {
            stderr.print("error: unknown migrate flag '{s}'\n", .{a}) catch {};
            return null;
        }
    }
    return out;
}

pub fn run(allocator: std.mem.Allocator, args: []const []const u8, tool_version: []const u8, configured_socket: ?[]const u8, stdout: anytype, stderr: anytype) ExitClass {
    for (args) |arg| if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
        stdout.writeAll(cli.args.help_migrate) catch return .rejected;
        return .success;
    };
    if (args.len == 0) return usage(stderr);
    const sub = args[0];
    const parsed = parseFlags(args[1..], stderr) orelse return usage(stderr);
    if (std.mem.eql(u8, sub, "inspect")) return runInspect(allocator, parsed, tool_version, stdout, stderr);
    if (std.mem.eql(u8, sub, "snapshot")) return runSnapshot(allocator, parsed, stdout, stderr);
    if (std.mem.eql(u8, sub, "plan")) return runPlan(allocator, parsed, tool_version, stdout, stderr);
    if (std.mem.eql(u8, sub, "validate")) return runValidate(allocator, parsed, stdout, stderr);
    if (std.mem.eql(u8, sub, "cutover") or std.mem.eql(u8, sub, "status") or std.mem.eql(u8, sub, "rollback")) {
        const options = cutoverOptions(parsed, configured_socket, stderr) orelse return .usage;
        if (std.mem.eql(u8, sub, "cutover")) return cutover.runCutover(allocator, options, stdout, stderr);
        if (std.mem.eql(u8, sub, "status")) return cutover.runStatus(allocator, options, stdout, stderr);
        return cutover.runRollback(allocator, options, stdout, stderr);
    }
    stderr.print("error: unknown migrate subcommand '{s}'\n", .{sub}) catch {};
    return usage(stderr);
}

fn runInspect(allocator: std.mem.Allocator, parsed: Parsed, tool_version: []const u8, stdout: anytype, stderr: anytype) ExitClass {
    const source_dir = parsed.source_dir orelse {
        stderr.writeAll("error: migrate inspect requires --source-dir <dir>\n") catch {};
        return .usage;
    };
    var manifest = inspect.inspect(allocator, .{ .source_dir = source_dir, .tool_version = tool_version }) catch |err| {
        stderr.print("migrate inspect: {s}: {s}\n", .{ source_dir, @errorName(err) }) catch {};
        return .usage;
    };
    defer manifest.deinit();
    switch (parsed.output) {
        .json => inspect.renderJson(&manifest, stdout) catch return .usage,
        .table => inspect.renderTable(&manifest, stdout) catch return .usage,
    }
    return switch (inspect.exitClass(&manifest)) {
        .success => .success,
        .rejected => .rejected,
        .usage => .usage,
    };
}

fn runSnapshot(allocator: std.mem.Allocator, parsed: Parsed, stdout: anytype, stderr: anytype) ExitClass {
    const source_db = parsed.source_db orelse {
        stderr.writeAll("error: migrate snapshot requires --source-db <file>\n") catch {};
        return .usage;
    };
    const staging_dir = parsed.staging_dir orelse {
        stderr.writeAll("error: migrate snapshot requires --staging-dir <dir>\n") catch {};
        return .usage;
    };
    var captured = snapshot.capture(allocator, source_db, staging_dir, .{}) catch |err| {
        stderr.print("migrate snapshot: {s}: {s}\n", .{ source_db, @errorName(err) }) catch {};
        return switch (err) {
            error.OpenFailed, error.AccessDenied, error.NotRegularFile, error.StagingUnavailable, error.PathTooLong, error.OutOfMemory => .usage,
            else => .rejected,
        };
    };
    defer captured.deinit(allocator);
    const digest = std.fmt.bytesToHex(captured.destination_sha256, .lower);
    switch (parsed.output) {
        .json => std.json.stringify(.{
            .schema_version = @as(u32, 1),
            .source_path = captured.source_path,
            .source_size = captured.source_size,
            .source_mtime_us = captured.source_mtime_us,
            .journal_mode_observed = captured.journal_mode_observed,
            .version = captured.version,
            .row_counts = captured.row_counts,
            .destination_path = captured.destination_path,
            .destination_sha256 = &digest,
            .captured_us = captured.captured_us,
            .backup_steps = captured.backup_steps,
            .pages_copied = captured.pages_copied,
            .restarts = captured.restarts,
        }, .{}, stdout) catch return .usage,
        .table => stdout.print("source\t{s}\nversion\t{d}\njails\t{d}\nlogs\t{d}\nbans\t{d}\nbips\t{d}\ndestination\t{s}\nsha256\t{s}\n", .{ captured.source_path, captured.version, captured.row_counts.jails, captured.row_counts.logs, captured.row_counts.bans, captured.row_counts.bips, captured.destination_path, &digest }) catch return .usage,
    }
    stdout.writeAll("\n") catch {};
    return .success;
}

fn cutoverOptions(parsed: Parsed, configured_socket: ?[]const u8, stderr: anytype) ?cutover.Options {
    const plan_path = parsed.plan orelse {
        stderr.writeAll("error: --plan <plan.json> is required\n") catch {};
        return null;
    };
    const state_file = parsed.state_file orelse {
        stderr.writeAll("error: --state-file <db> is required\n") catch {};
        return null;
    };
    const staging_dir = parsed.staging_dir orelse {
        stderr.writeAll("error: --staging-dir <dir> is required\n") catch {};
        return null;
    };
    const backend = parsed.backend orelse {
        stderr.writeAll("error: --backend nftables|ipset|iptables is required\n") catch {};
        return null;
    };
    return .{ .plan_path = plan_path, .state_file = state_file, .staging_dir = staging_dir, .backend = backend, .socket_path = parsed.socket_path orelse configured_socket orelse cli.socket.default_socket_path, .run_id = parsed.run_id, .output = if (parsed.output == .json) .json else .table, .source_verified = parsed.source_verified };
}

fn runPlan(allocator: std.mem.Allocator, parsed: Parsed, tool_version: []const u8, stdout: anytype, stderr: anytype) ExitClass {
    const source_dir = parsed.source_dir orelse {
        stderr.writeAll("error: migrate plan requires --source-dir <dir>\n") catch {};
        return .usage;
    };
    const out_path = parsed.out orelse {
        stderr.writeAll("error: migrate plan requires --out <plan.json>\n") catch {};
        return .usage;
    };
    var captured: ?snapshot.Snapshot = null;
    defer if (captured) |*value| value.deinit(allocator);
    if (parsed.source_db) |source_db| {
        const staging_dir = parsed.staging_dir orelse {
            stderr.writeAll("error: --source-db requires --staging-dir <dir>\n") catch {};
            return .usage;
        };
        captured = snapshot.capture(allocator, source_db, staging_dir, .{}) catch |err| {
            stderr.print("migrate plan: snapshot {s}: {s}\n", .{ source_db, @errorName(err) }) catch {};
            return switch (err) {
                error.OpenFailed, error.AccessDenied, error.NotRegularFile, error.StagingUnavailable, error.PathTooLong, error.OutOfMemory => .usage,
                else => .rejected,
            };
        };
    }
    var built = plan_mod.plan(allocator, .{ .source_dir = source_dir, .source_db = parsed.source_db, .snapshot = if (captured) |*value| value else null, .continuity = parsed.continuity, .replay_window_s = parsed.replay_window_s, .now_us = std.time.microTimestamp(), .host_id = journal.localHostId(), .tool_version = tool_version, .runtime_socket = parsed.runtime_socket }) catch |err| {
        stderr.print("migrate plan: {s}: {s}\n", .{ source_dir, @errorName(err) }) catch {};
        return .usage;
    };
    defer built.deinit();
    plan_mod.writePlanFile(&built, out_path) catch |err| {
        stderr.print("migrate plan: write {s}: {s}\n", .{ out_path, @errorName(err) }) catch {};
        return .usage;
    };
    switch (parsed.output) {
        .json => plan_mod.renderJson(&built, stdout) catch return .usage,
        .table => plan_mod.renderTable(&built, stdout) catch return .usage,
    }
    return if (built.doc.blockers.len == 0) .success else .rejected;
}

fn runValidate(allocator: std.mem.Allocator, parsed: Parsed, stdout: anytype, stderr: anytype) ExitClass {
    const plan_path = parsed.plan orelse {
        stderr.writeAll("error: migrate validate requires --plan <plan.json>\n") catch {};
        return .usage;
    };
    var loaded = plan_mod.readPlanFile(allocator, plan_path) catch |err| {
        stderr.print("migrate validate: {s}: {s}\n", .{ plan_path, @errorName(err) }) catch {};
        return .usage;
    };
    defer loaded.deinit();
    var validation = plan_mod.validate(allocator, &loaded, .{ .now_us = std.time.microTimestamp(), .source_dir = parsed.source_dir, .snapshot_path = parsed.snapshot_path }) catch |err| {
        stderr.print("migrate validate: {s}\n", .{@errorName(err)}) catch {};
        return .usage;
    };
    defer validation.deinit();
    switch (parsed.output) {
        .json => {
            std.json.stringify(.{ .schema_version = @as(u32, 1), .outcome = @tagName(validation.outcome), .reasons = validation.reasons }, .{}, stdout) catch return .usage;
            stdout.writeAll("\n") catch {};
        },
        .table => {
            stdout.print("outcome\t{s}\n", .{@tagName(validation.outcome)}) catch return .usage;
            for (validation.reasons) |reason| stdout.print("reason\t{s}\n", .{reason}) catch return .usage;
        },
    }
    return if (validation.outcome == .valid) .success else .rejected;
}

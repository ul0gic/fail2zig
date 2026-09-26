// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const shared = @import("shared");
const config_mod = @import("../config/native.zig");
const native_paths = @import("../config/native_paths.zig");
const durable = @import("../core/record_store.zig");
const repair = @import("../store/source_repair.zig");
const files = @import("../core/durable_file_source.zig");

pub const ExitClass = shared.ExitClass;
pub const default_config = "/etc/fail2zig/config.toml";

pub const Options = struct {
    config: []const u8 = default_config,
    jail: []const u8,
    source: []const u8,
    token: []const u8,
};

pub fn run(allocator: std.mem.Allocator, args: []const []const u8, stdout: anytype, stderr: anytype) ExitClass {
    for (args) |arg| if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
        stdout.writeAll(usage_text) catch return .rejected;
        return .success;
    };
    const options = parseArgs(args, stderr) orelse return usage(stderr);
    return execute(allocator, options, std.time.microTimestamp(), stdout, stderr);
}

fn parseArgs(args: []const []const u8, stderr: anytype) ?Options {
    var config: []const u8 = default_config;
    var jail: ?[]const u8 = null;
    var source: ?[]const u8 = null;
    var token: ?[]const u8 = null;
    var acknowledged = false;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--acknowledge-truncation")) {
            acknowledged = true;
            continue;
        }
        const Flag = enum { config, jail, source, token };
        const flag: Flag = if (std.mem.eql(u8, arg, "--config")) .config else if (std.mem.eql(u8, arg, "--jail")) .jail else if (std.mem.eql(u8, arg, "--source")) .source else if (std.mem.eql(u8, arg, "--token")) .token else {
            stderr.print("repair-source: unknown argument '{s}'\n", .{arg[0..@min(arg.len, 64)]}) catch {};
            return null;
        };
        i += 1;
        if (i >= args.len) return null;
        switch (flag) {
            .config => config = args[i],
            .jail => jail = args[i],
            .source => source = args[i],
            .token => token = args[i],
        }
    }
    if (jail == null or source == null or token == null) return null;
    if (!acknowledged) {
        stderr.writeAll("repair-source: --acknowledge-truncation is required; unread data lost in the truncation cannot be recovered\n") catch {};
        return null;
    }
    return .{ .config = config, .jail = jail.?, .source = source.?, .token = token.? };
}

const usage_text =
    \\usage:
    \\  fail2zig repair-source --jail <name> --source <absolute path> --token <token>
    \\                         --acknowledge-truncation [--config <path>]
    \\
    \\Run only while the daemon is stopped. Acknowledges that a configured file source
    \\was truncated in place, restarting it at offset 0 of the current file. <token>
    \\(1-128 of A-Z a-z 0-9 . _ : -) identifies this repair; repeating the same command
    \\replays the committed outcome. The newest 256 outcomes are kept; older tokens stay
    \\reserved and are refused. The repair binds the source generation recorded in the
    \\state, not one recomputed from the configuration; a configuration changed since the
    \\stop is applied by the next start.
    \\
;

fn usage(stderr: anytype) ExitClass {
    stderr.writeAll(usage_text) catch {};
    return .usage;
}

// The daemon reads exactly the paths its logpath patterns expand to.
fn configuredLogpath(allocator: std.mem.Allocator, jail: config_mod.JailConfig, path: []const u8) !bool {
    for (jail.logpath) |pattern| {
        if (std.mem.eql(u8, pattern, path)) return true;
        const expanded = try files.expandGlob(allocator, pattern, 4096);
        defer {
            for (expanded) |value| allocator.free(value);
            allocator.free(expanded);
        }
        for (expanded) |value| if (std.mem.eql(u8, value, path)) return true;
    }
    return false;
}

pub fn execute(allocator: std.mem.Allocator, options: Options, now_us: i64, stdout: anytype, stderr: anytype) ExitClass {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const cfg = config_mod.Config.loadFile(arena.allocator(), options.config) catch |err| {
        stderr.print("repair-source: config {s}: {s}\n", .{ options.config, @errorName(err) }) catch {};
        return .usage;
    };
    const jail = for (cfg.jails) |candidate| {
        if (std.mem.eql(u8, candidate.name, options.jail)) break candidate;
    } else {
        stderr.print("repair-source: jail '{s}' is not configured in {s}\n", .{ options.jail, options.config }) catch {};
        return .rejected;
    };
    const configured = configuredLogpath(allocator, jail, options.source) catch |err| {
        stderr.print("repair-source: cannot expand the logpath of jail '{s}': {s}\n", .{ options.jail, @errorName(err) }) catch {};
        return .rejected;
    };
    if (!configured) {
        stderr.print("repair-source: {s} is not a configured logpath of jail '{s}'\n", .{ options.source, options.jail }) catch {};
        return .rejected;
    }
    const state_path = cfg.global.state_file;
    // Never create state: an absent file has nothing to repair.
    const authority = native_paths.lockStateIfPresent(state_path) catch |err| {
        switch (err) {
            error.NativeAuthorityAlreadyRunning => stderr.print("repair-source: {s} is held by a running daemon or another administrator; stop fail2zig first\n", .{state_path}) catch {},
            else => stderr.print("repair-source: state {s}: {s}\n", .{ state_path, @errorName(err) }) catch {},
        }
        return .rejected;
    } orelse {
        stderr.print("repair-source: state {s} does not exist; nothing to repair and no state was created\n", .{state_path}) catch {};
        return .rejected;
    };
    // Released only after the store closes below.
    defer authority.close();
    if (!sameFile(authority, state_path)) {
        stderr.print("repair-source: state {s} was replaced while locked; nothing was changed\n", .{state_path}) catch {};
        return .rejected;
    }
    var store = durable.Store.openExisting(allocator, state_path) catch |err| {
        stderr.print("repair-source: open state {s}: {s}\n", .{ state_path, @errorName(err) }) catch {};
        return .rejected;
    };
    defer store.close();
    if (!sameFile(authority, state_path)) {
        stderr.print("repair-source: state {s} was replaced while locked; nothing was changed\n", .{state_path}) catch {};
        return .rejected;
    }

    var diagnostic: repair.Diagnostic = .{};
    const outcome = repair.repair(&store, allocator, .{ .jail = options.jail, .path = options.source, .token = options.token }, now_us, .{}, &diagnostic) catch |err| {
        refusal(stderr, options, err, diagnostic);
        return .rejected;
    };
    defer outcome.deinit(allocator);
    report(stdout, options, outcome) catch return .rejected;
    return .success;
}

fn sameFile(authority: std.fs.File, path: []const u8) bool {
    const held = std.posix.fstat(authority.handle) catch return false;
    const named = std.posix.fstatat(std.posix.AT.FDCWD, path, std.posix.AT.SYMLINK_NOFOLLOW) catch return false;
    return held.dev == named.dev and held.ino == named.ino;
}

fn refusal(stderr: anytype, options: Options, err: repair.Error, diagnostic: repair.Diagnostic) void {
    const reason: []const u8 = switch (err) {
        error.TokenUnknownStateMismatch => "token unknown; state no longer matches (repair may already be applied)",
        error.RepairTokenMismatch => "token was already used with a different jail or source; choose a new token",
        error.UnsupportedDiscontinuity => "the source is not truncated in place; only a same-inode truncation can be acknowledged",
        error.PendingReceipt => "an admitted record of this source is still pending; start the daemon after the source is restored so it commits, then retry",
        error.ConsumerWorkPending => "consumer state for this source is not ready; nothing was changed",
        error.StaleGeneration => "the source's recorded generation disagrees with its checkpoint or consumer manifest; offline repair cannot resolve this and nothing was changed",
        error.RepairTokenEvicted => "token belongs to an older repair whose outcome is no longer retained; it cannot be reused, choose a new token",
        error.RepairHistoryFull => "the repair token history is full; offline repair is unavailable for this state",
        error.StaleCheckpoint => "the checkpoint changed since observation; nothing was changed, retry",
        error.SourceChanged => "the file changed during the repair; nothing was changed, retry",
        error.SourceNotRecorded => "no recorded checkpoint names this source path for the jail",
        error.SourceAmbiguous => "several recorded checkpoints match this source; nothing was changed",
        error.SourceUnreadable => "the source file cannot be read",
        error.UnsupportedCheckpoint => "the jail checkpoint is not a file source checkpoint",
        error.InvalidRepairRequest => "invalid jail, source path (must be absolute) or token",
        error.LoadRepairMigrationRequired => "state is not at schema 24; start this release once so it migrates the state, then retry",
        error.LoadRepairMigrationIncomplete => "the schema 24 migration is incomplete; start this release so it finishes, then retry",
        else => "storage failure; nothing was changed",
    };
    stderr.print("repair-source: refused: {s} [{s}] jail={s} source={s}", .{ reason, @errorName(err), options.jail, options.source }) catch {};
    if (diagnostic.shape) |shape| stderr.print(" observed={s}", .{@tagName(shape)}) catch {};
    stderr.writeAll("\n") catch {};
}

fn report(stdout: anytype, options: Options, outcome: repair.Outcome) !void {
    const hex = std.fmt.fmtSliceHexLower;
    try stdout.print("repair-source: {s}\n", .{if (outcome.replayed) "already applied by this token (replayed; nothing changed now)" else "truncation acknowledged"});
    try stdout.print("  jail={s} source={s}\n  path={s}\n", .{ options.jail, outcome.source, options.source });
    try stdout.print("  generation={s}\n  checkpoint_revision={d} -> {d}\n  prior_cursor_sha256={s}\n", .{ hex(&outcome.generation), outcome.prior_checkpoint_revision, outcome.prior_checkpoint_revision + 1, hex(&outcome.prior_cursor_sha256) });
    if (outcome.prior_incarnation) |incarnation| try stdout.print("  prior_incarnation={s} prior_offset={d}\n", .{ hex(&incarnation), outcome.prior_offset.? });
    try stdout.print("  new_incarnation={s} new_offset=0\n  file device={d} inode={d} size={d} prefix_sha256={s}\n", .{ hex(&outcome.new_incarnation), outcome.file.device, outcome.file.inode, outcome.file.size, hex(&outcome.file.prefix_sha256) });
    try stdout.writeAll(
        \\Data written after the committed offset and removed by the truncation was never read.
        \\Its extent is unknown and it cannot be recovered. Reading restarts at offset 0 of the
        \\current file, so any older lines still in it are read again under the new incarnation.
        \\While the daemon is stopped, protection for every jail may be absent: the stop can
        \\remove installed firewall rules. The next start reinstalls them from durable state
        \\before it reports READY; start fail2zig now.
        \\
    );
}

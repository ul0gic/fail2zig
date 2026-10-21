// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const shared = @import("shared");
const cli = @import("cli");
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
    \\Runs through the daemon's admin socket while the daemon is running, and on the
    \\state file directly while it is stopped. Acknowledges that a configured file source
    \\was truncated in place, restarting it at offset 0 of the current file, or that a
    \\rotated-out incarnation was removed with unread bytes, resuming the current file at
    \\its committed offset. <token>
    \\(1-128 of A-Z a-z 0-9 . _ : -) identifies this repair; repeating the same command
    \\replays the committed outcome. The newest 256 outcomes are kept; older tokens stay
    \\reserved and are refused. The repair binds the source generation recorded in the
    \\state, not one recomputed from the configuration; offline, a configuration changed
    \\since the stop is applied by the next start.
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
    if (online(allocator, cfg.global.socket_path, options, stdout, stderr)) |class| return class;
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
    const outcome = repair.repair(&store, allocator, .{ .jail = options.jail, .path = options.source, .token = options.token }, now_us, &diagnostic) catch |err| {
        if (err == error.LossAlreadyRecorded) {
            reportRecorded(stdout, options, diagnostic.recorded.?) catch return .rejected;
            return .success;
        }
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
        error.UnsupportedDiscontinuity => "the source is not truncated in place, not replaced with its previous file gone, and not missing a removed rotated incarnation; an absent path, a rewrite in place and a previous file still in its directory have nothing to acknowledge",
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
        error.LoadRepairMigrationRequired => "state is not at schema 26; start this release once so it migrates the state, then retry",
        error.LoadRepairMigrationIncomplete => "the schema 24 migration is incomplete; start this release so it finishes, then retry",
        else => "storage failure; nothing was changed",
    };
    stderr.print("repair-source: refused: {s} [{s}] jail={s} source={s}", .{ reason, @errorName(err), options.jail, options.source }) catch {};
    if (diagnostic.shape) |shape| stderr.print(" observed={s}", .{@tagName(shape)}) catch {};
    stderr.writeAll("\n") catch {};
}

fn formatUtc(buffer: *[32]u8, wall_us: i64) []const u8 {
    const seconds = std.math.cast(u64, @divFloor(wall_us, std.time.us_per_s)) orelse return "out-of-range";
    const epoch = std.time.epoch.EpochSeconds{ .secs = seconds };
    const year_day = epoch.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day = epoch.getDaySeconds();
    return std.fmt.bufPrint(buffer, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        day.getHoursIntoDay(),
        day.getMinutesIntoHour(),
        day.getSecondsIntoMinute(),
    }) catch "out-of-range";
}

const SizeText = struct {
    size: ?u64,
    pub fn format(self: SizeText, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        if (self.size) |value| try writer.print("{d}", .{value}) else try writer.writeAll("unknown");
    }
};

fn reportRecorded(stdout: anytype, options: Options, recorded: repair.RecordedLoss) !void {
    var time_buffer: [32]u8 = undefined;
    try stdout.print("repair-source: {s}\n  jail={} source=file\n  path={}\n", .{ repair.Headline.loss_recorded, std.zig.fmtEscapes(options.jail), std.zig.fmtEscapes(options.source) });
    try stdout.print("  loss event: {s} UTC truncated inode={d} committed_offset={d} size={}\n", .{ formatUtc(&time_buffer, recorded.wall_us), recorded.inode, recorded.committed_offset, SizeText{ .size = recorded.observed_size } });
    try stdout.print("  reading resumed at offset 0 of inode {d}; no repair was performed and the token was not used\n", .{recorded.inode});
}

fn reportRemoved(stdout: anytype, options: Options, outcome: repair.Outcome, removed: repair.RemovedIncarnation) !void {
    try stdout.print("repair-source: {s}\n", .{repair.headline(outcome)});
    try stdout.print("  jail={} source=file\n  path={}\n", .{ std.zig.fmtEscapes(options.jail), std.zig.fmtEscapes(options.source) });
    try stdout.print("  removed inode={d}", .{removed.inode});
    if (removed.committed_offset) |offset| try stdout.print(" committed_offset={d}", .{offset});
    if (removed.last_size) |size| try stdout.print(" last_size={d}\n", .{size}) else if (outcome.replayed) try stdout.writeAll("\n") else try stdout.writeAll(" last_size=unknown\n");
    if (removed.current_inode) |inode| {
        try stdout.print("  current inode={d}", .{inode});
        if (removed.current_offset) |offset| try stdout.print(" resumes at offset {d}\n", .{offset}) else try stdout.writeAll(" has no checkpoint; the next start reads it from its configured start\n");
    }
    if (removed.committed_offset) |offset| try stdout.print("Records in the removed incarnation after offset {d} were never read and cannot be recovered.\n", .{offset}) else try stdout.writeAll(removed_loss_text);
    try stdout.writeAll(
        \\While the daemon is stopped, protection for every jail may be absent: the stop can
        \\remove installed firewall rules. The next start reinstalls them from durable state
        \\before it reports READY; start fail2zig now.
        \\
    );
}

fn report(stdout: anytype, options: Options, outcome: repair.Outcome) !void {
    if (outcome.removed) |removed| return reportRemoved(stdout, options, outcome, removed);
    const hex = std.fmt.fmtSliceHexLower;
    try stdout.print("repair-source: {s}\n", .{repair.headline(outcome)});
    try stdout.print("  jail={s} source={s}\n  path={s}\n", .{ options.jail, outcome.source, options.source });
    try stdout.print("  generation={s}\n  checkpoint_revision={d} -> {d}\n  prior_cursor_sha256={s}\n", .{ hex(&outcome.generation), outcome.prior_checkpoint_revision, outcome.prior_checkpoint_revision + 1, hex(&outcome.prior_cursor_sha256) });
    if (outcome.prior_incarnation) |incarnation| try stdout.print("  prior_incarnation={s} prior_offset={d}\n", .{ hex(&incarnation), outcome.prior_offset.? });
    try stdout.print("  new_incarnation={s} new_offset=0\n  file device={d} inode={d} size={d} prefix_sha256={s}\n", .{ hex(&outcome.new_incarnation), outcome.file.device, outcome.file.inode, outcome.file.size, hex(&outcome.file.prefix_sha256) });
    try stdout.writeAll(if (outcome.replaced_file) replaced_loss_text else truncated_loss_text);
    try stdout.writeAll(
        \\While the daemon is stopped, protection for every jail may be absent: the stop can
        \\remove installed firewall rules. The next start reinstalls them from durable state
        \\before it reports READY; start fail2zig now.
        \\
    );
}

const replaced_loss_text =
    \\Data written to the previous file after the committed offset was never read. That file
    \\is gone, so its extent is unknown and it cannot be recovered. Reading restarts at
    \\offset 0 of the file now at the path, so any lines already in it are read under the
    \\new incarnation.
    \\
;

const truncated_loss_text =
    \\Data written after the committed offset and removed by the truncation was never read.
    \\Its extent is unknown and it cannot be recovered. Reading restarts at offset 0 of the
    \\current file, so any older lines still in it are read again under the new incarnation.
    \\
;

const removed_loss_text = "Records in the removed incarnation after its committed offset were never read and cannot be recovered.\n";

const StatusHead = struct { generation: []const u8 = "", mutation_revision: u64 = 0 };

const OnlineOutcome = struct {
    outcome: []const u8,
    shape: ?[]const u8 = null,
    resumed_offset: ?u64 = null,
    reasons: []const []const u8 = &.{},
};

fn online(allocator: std.mem.Allocator, socket_path: []const u8, options: Options, stdout: anytype, stderr: anytype) ?ExitClass {
    var diag: cli.socket.DiagBuf = .{};
    var client = cli.socket.connect(allocator, socket_path, cli.args.default_timeout_ms, &diag) catch |err| {
        if (err == error.DaemonUnreachable) return null;
        stderr.print("repair-source: {s}\n", .{diag.message()}) catch {};
        return .unavailable;
    };
    defer client.close();
    const status = client.sendCommand(.{ .status = {} }) catch {
        stderr.print("repair-source: daemon status: {s}; nothing was changed\n", .{client.errorMessage()}) catch {};
        return .unavailable;
    };
    defer status.deinit(allocator);
    const head_json = switch (status) {
        .ok => |ok| ok.payload,
        .err => |failure| {
            stderr.print("repair-source: daemon status: {s}; nothing was changed\n", .{failure.message}) catch {};
            return .unavailable;
        },
    };
    const head = std.json.parseFromSlice(StatusHead, allocator, head_json, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch {
        stderr.writeAll("repair-source: daemon status did not carry a generation; nothing was changed\n") catch {};
        return .unavailable;
    };
    defer head.deinit();
    client.close();
    client = cli.socket.connect(allocator, socket_path, cli.args.default_timeout_ms, &diag) catch {
        stderr.print("repair-source: {s}; nothing was changed\n", .{diag.message()}) catch {};
        return .unavailable;
    };

    var body_bytes: [shared.protocol.max_request_body]u8 = undefined;
    var stream = std.io.fixedBufferStream(&body_bytes);
    std.json.stringify(.{ .schema_version = @as(u32, 1), .kind = "repair_source", .jail = options.jail, .source = options.source, .token = options.token, .expected_generation = head.value.generation, .expected_mutation_revision = head.value.mutation_revision }, .{}, stream.writer()) catch {
        refusal(stderr, options, error.InvalidRepairRequest, .{});
        return .rejected;
    };
    const body = shared.Command.Body.init(stream.getWritten()) catch {
        refusal(stderr, options, error.InvalidRepairRequest, .{});
        return .rejected;
    };
    var request_id: [shared.protocol.request_id_bytes]u8 = undefined;
    std.crypto.random.bytes(&request_id);
    const response = client.sendCommand(.{ .admin_v1 = .{ .request_id = request_id, .body = body } }) catch {
        stderr.print("repair-source: {s}; the outcome is unknown, repeat the same command to replay it\n", .{client.errorMessage()}) catch {};
        return .uncertain;
    };
    defer response.deinit(allocator);
    const payload: []const u8, const class: ExitClass = switch (response) {
        .ok => |ok| .{ ok.payload, .success },
        .err => |failure| .{ failure.message, shared.Response.exitClassForCode(failure.code) },
    };
    const parsed = std.json.parseFromSlice(OnlineOutcome, allocator, payload, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch {
        stderr.print("repair-source: daemon: {s}\n", .{payload[0..@min(payload.len, 512)]}) catch {};
        return if (class == .success) .uncertain else class;
    };
    defer parsed.deinit();
    const first: ?[]const u8 = if (parsed.value.reasons.len != 0) parsed.value.reasons[0] else null;
    if (class == .success) {
        reportOnline(stdout, options, parsed.value, first orelse "") catch return .rejected;
        return .success;
    }
    const shape: ?repair.Shape = if (parsed.value.shape) |text| std.meta.stringToEnum(repair.Shape, text) else null;
    if (first) |reason| if (repairError(reason)) |err| {
        refusal(stderr, options, err, .{ .shape = shape });
        return class;
    };
    stderr.print("repair-source: {s}: {s} jail={s} source={s}\n", .{ parsed.value.outcome, first orelse "no reason given", options.jail, options.source }) catch {};
    return class;
}

fn repairError(name: []const u8) ?repair.Error {
    inline for (@typeInfo(repair.Error).error_set.?) |member| {
        if (std.mem.eql(u8, name, member.name)) return @field(repair.Error, member.name);
    }
    return null;
}

fn reportOnline(stdout: anytype, options: Options, outcome: OnlineOutcome, title: []const u8) !void {
    try stdout.print("repair-source: {s}\n  jail={} source=file\n  path={}\n", .{ title, std.zig.fmtEscapes(options.jail), std.zig.fmtEscapes(options.source) });
    if (std.mem.eql(u8, title, repair.Headline.loss_recorded)) {
        try stdout.writeAll("  no repair was performed and the token was not used\n");
        return;
    }
    if (outcome.resumed_offset) |offset| try stdout.print("  reading resumed at offset {d}\n", .{offset});
    if (std.mem.eql(u8, title, repair.Headline.truncation)) try stdout.writeAll(truncated_loss_text);
    if (std.mem.eql(u8, title, repair.Headline.replaced_file)) try stdout.writeAll(replaced_loss_text);
    if (std.mem.eql(u8, title, repair.Headline.removed)) try stdout.writeAll(removed_loss_text);
}

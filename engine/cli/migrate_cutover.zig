// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

//! `fail2zig migrate cutover|status`: the resumable, journaled protection cutover. Every step
//! records its intent before acting and its observed outcome after; a rerun with `--run-id`
//! classifies the durable journal and the actual store state instead of replaying. Activation
//! and kernel verification run inside the daemon (`admin_v1 migration_activate`); this command
//! only stages the destination offline and then drives that request over the socket.

const std = @import("std");
const shared = @import("shared");
const cli = @import("cli");
const durable = @import("../core/record_store.zig");
const plan_mod = @import("../migration/plan.zig");
const journal = @import("../migration/journal.zig");
const import_mod = @import("../migration/import.zig");
const continuity = @import("../migration/continuity.zig");
const snapshot = @import("../migration/sqlite_snapshot.zig");
const fail2ban_db = @import("../migration/fail2ban_db.zig");

pub const ExitClass = shared.ExitClass;
pub const Output = enum { json, table };

/// Whole-run and per-step wall budgets.
pub const run_deadline_ns: u64 = 30 * std.time.ns_per_min;
pub const step_deadline_ns: u64 = 5 * std.time.ns_per_min;
/// The source database must be byte-stable for this long before it counts as quiesced.
pub const quiesce_window_ns: u64 = 2 * std.time.ns_per_s;

pub const Options = struct {
    plan_path: []const u8,
    state_file: []const u8,
    staging_dir: []const u8,
    backend: import_mod.Backend,
    socket_path: []const u8,
    run_id: ?[32]u8,
    output: Output,
    /// Rollback only: the operator attests that the restored source service is running and
    /// protecting again, which is what permits releasing destination ownership.
    source_verified: bool = false,
};

/// Fixed recovery-point name inside the staging directory, so rollback can find it by identity.
pub fn recoveryPointName(buffer: []u8, run_id: [32]u8) []const u8 {
    const hex = std.fmt.bytesToHex(run_id, .lower);
    return std.fmt.bufPrint(buffer, "recovery-point-{s}.sqlite3", .{hex[0..16]}) catch buffer[0..0];
}

const Context = struct {
    allocator: std.mem.Allocator,
    store: *durable.Store,
    loaded: *plan_mod.Plan,
    options: *const Options,
    run_id: [32]u8,
    started: std.time.Timer,
    stderr_buffer: std.ArrayList(u8),
};

/// Outcome → exit class: before mutation every failure is a rejection; after a mutation
/// step the observed protection decides between partial and uncertain.
pub fn exitFor(outcome: journal.Outcome, state: journal.State) ExitClass {
    return switch (outcome) {
        .success => if (state == .complete or state == .rolled_back) .success else .unavailable,
        .partial => .partial,
        .uncertain => .uncertain,
        .rollback_failed => .partial,
        .pending => .unavailable,
        .incompatible, .validation_failed, .operational_failure => .rejected,
    };
}

pub fn runCutover(allocator: std.mem.Allocator, options: Options, stdout: anytype, stderr: anytype) ExitClass {
    var loaded = plan_mod.readPlanFile(allocator, options.plan_path) catch |err| {
        stderr.print("migrate cutover: {s}: {s}\n", .{ options.plan_path, @errorName(err) }) catch {};
        return .usage;
    };
    defer loaded.deinit();
    if (loaded.doc.snapshot == null or loaded.doc.source_db == null) {
        stderr.writeAll("migrate cutover: the plan carries no source database snapshot; rebuild it with --source-db\n") catch {};
        return .rejected;
    }
    if (loaded.doc.blockers.len != 0) {
        stderr.writeAll("migrate cutover: the plan has blockers; resolve them and plan again\n") catch {};
        return .rejected;
    }
    snapshot.verifyStagingDir(options.staging_dir) catch |err| {
        stderr.print("migrate cutover: staging dir {s}: {s}\n", .{ options.staging_dir, @errorName(err) }) catch {};
        return .usage;
    };
    var store = durable.Store.open(allocator, options.state_file) catch |err| {
        stderr.print("migrate cutover: state {s}: {s}\n", .{ options.state_file, @errorName(err) }) catch {};
        return .usage;
    };
    defer store.close();
    if (store.schema_version < durable.latest_schema) {
        stderr.writeAll("migrate cutover: the destination state has not been initialised by the daemon; start fail2zig once, stop it, then rerun\n") catch {};
        return .rejected;
    }
    const identity = identityFor(&loaded, options.staging_dir) catch {
        stderr.writeAll("migrate cutover: the plan's snapshot fingerprint is malformed\n") catch {};
        return .usage;
    };
    var run_id: [32]u8 = undefined;
    if (options.run_id) |given| run_id = given else std.crypto.random.bytes(&run_id);
    const now = std.time.microTimestamp();
    var log = if (options.run_id != null)
        journal.Journal.open(allocator, &store, run_id, identity) catch |err| {
            stderr.print("migrate cutover: run {s}: {s}\n", .{ &std.fmt.bytesToHex(run_id, .lower), @errorName(err) }) catch {};
            return .rejected;
        }
    else
        journal.Journal.create(allocator, &store, run_id, identity, now) catch |err| {
            stderr.print("migrate cutover: cannot record the run: {s}\n", .{@errorName(err)}) catch {};
            return .rejected;
        };
    defer log.deinit();
    var ctx = Context{ .allocator = allocator, .store = &store, .loaded = &loaded, .options = &options, .run_id = run_id, .started = std.time.Timer.start() catch return .usage, .stderr_buffer = std.ArrayList(u8).init(allocator) };
    defer ctx.stderr_buffer.deinit();
    stderr.print("migrate cutover: run {s}\n", .{&std.fmt.bytesToHex(run_id, .lower)}) catch {};

    var exit: ExitClass = .rejected;
    if (try_pending_rollback(&log)) {
        stderr.writeAll("migrate cutover: a rollback is in progress for this run; continue with `migrate rollback --run-id`\n") catch {};
        return .rejected;
    }
    var iterations: u32 = 0;
    while (iterations < 32) : (iterations += 1) {
        const decision = log.classify(.{ .ctx = &ctx, .observe = observe }, std.time.microTimestamp()) catch |err| {
            stderr.print("migrate cutover: journal: {s}\n", .{@errorName(err)}) catch {};
            exit = .uncertain;
            break;
        };
        const step: journal.Step = switch (decision) {
            .complete => {
                exit = .success;
                break;
            },
            .rolled_back => {
                exit = .success;
                break;
            },
            .refuse => |refusal| {
                stderr.print("migrate cutover: refused: {s}\n", .{refusal.reason}) catch {};
                exit = exitFor(lastOutcome(&log), log.state());
                break;
            },
            .rollback_required => |refusal| {
                stderr.print("migrate cutover: rollback required: {s}; restore the recovery point under {s}\n", .{ refusal.reason, options.staging_dir }) catch {};
                exit = .partial;
                break;
            },
            .continue_from => |next| next,
            .repeat_step => |again| again,
        };
        if (ctx.started.read() > run_deadline_ns) {
            stderr.writeAll("migrate cutover: the 30 minute run budget is exhausted; rerun with --run-id\n") catch {};
            exit = if (journal.mutates(step)) .uncertain else .rejected;
            break;
        }
        const control = executeStep(&ctx, &log, step, stderr) catch |err| {
            stderr.print("migrate cutover: {s}: {s}\n", .{ @tagName(step), @errorName(err) }) catch {};
            exit = if (journal.mutates(step)) .uncertain else .rejected;
            break;
        };
        switch (control) {
            .next => {},
            .stop => |class| {
                exit = class;
                break;
            },
        }
    }
    // A fresh journal view reports the steps and state the daemon recorded meanwhile.
    var fresh = journal.Journal.open(allocator, &store, run_id, identity) catch |err| {
        stderr.print("migrate cutover: report: {s}\n", .{@errorName(err)}) catch {};
        return exit;
    };
    defer fresh.deinit();
    var report = fresh.report(allocator, &.{}) catch |err| {
        stderr.print("migrate cutover: report: {s}\n", .{@errorName(err)}) catch {};
        return exit;
    };
    defer report.deinit(allocator);
    writeReport(&report, options.output, stdout) catch {};
    return exit;
}

pub fn runStatus(allocator: std.mem.Allocator, options: Options, stdout: anytype, stderr: anytype) ExitClass {
    const run_id = options.run_id orelse {
        stderr.writeAll("error: migrate status requires --run-id <hex>\n") catch {};
        return .usage;
    };
    var loaded = plan_mod.readPlanFile(allocator, options.plan_path) catch |err| {
        stderr.print("migrate status: {s}: {s}\n", .{ options.plan_path, @errorName(err) }) catch {};
        return .usage;
    };
    defer loaded.deinit();
    var store = durable.Store.openReadOnly(allocator, options.state_file) catch |err| {
        stderr.print("migrate status: state {s}: {s}\n", .{ options.state_file, @errorName(err) }) catch {};
        return .usage;
    };
    defer store.close();
    const identity = identityFor(&loaded, options.staging_dir) catch return .usage;
    var log = journal.Journal.open(allocator, &store, run_id, identity) catch |err| {
        stderr.print("migrate status: run {s}: {s}\n", .{ &std.fmt.bytesToHex(run_id, .lower), @errorName(err) }) catch {};
        return .rejected;
    };
    defer log.deinit();
    var report = log.report(allocator, &.{}) catch |err| {
        stderr.print("migrate status: report: {s}\n", .{@errorName(err)}) catch {};
        return .uncertain;
    };
    defer report.deinit(allocator);
    writeReport(&report, options.output, stdout) catch return .usage;
    return exitFor(report.outcome, report.state);
}

fn writeReport(report: *const journal.Report, output: Output, stdout: anytype) !void {
    switch (output) {
        .json => {
            try report.writeJson(stdout);
            try stdout.writeAll("\n");
        },
        .table => {
            try stdout.print("run\t{s}\nstate\t{s}\noutcome\t{s}\ndestination\t{s}\nsource\t{s}\n", .{ &report.run_id_hex, @tagName(report.state), @tagName(report.outcome), @tagName(report.observed_protection.destination), @tagName(report.observed_protection.source) });
            for (report.steps) |step| try stdout.print("step\t{d}\t{s}\t{s}\n", .{ step.seq, @tagName(step.step), @tagName(step.outcome) });
        },
    }
}

fn lastOutcome(log: *journal.Journal) journal.Outcome {
    var rows: [journal.max_steps]journal.StepRow = undefined;
    const listed = log.steps(&rows) catch return .uncertain;
    if (listed.len == 0) return .pending;
    return listed[listed.len - 1].outcome;
}

/// Identity binds the run to the plan file bytes, the snapshot's recorded source hash, the jail
/// tree fingerprints the plan captured and the staging directory holding the recovery point.
fn identityFor(loaded: *const plan_mod.Plan, staging_dir: []const u8) !journal.Identity {
    var source_db_fp: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&source_db_fp, loaded.doc.snapshot.?.recorded_sha256);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("fail2zig-migration-source-config-v1");
    for (loaded.doc.drift.files) |file| {
        hash.update(file.path);
        hash.update(&[_]u8{0});
        hash.update(file.sha256);
        hash.update("\n");
    }
    var source_cfg_fp: [32]u8 = undefined;
    hash.final(&source_cfg_fp);
    return .{ .host_id = journal.localHostId(), .source_db_fp = source_db_fp, .source_cfg_fp = source_cfg_fp, .plan_fp = loaded.plan_fp orelse return error.PlanFingerprintMissing, .recovery_point = staging_dir, .generation = [_]u8{0} ** 32 };
}

const Control = union(enum) { next, stop: ExitClass };

fn try_pending_rollback(log: *journal.Journal) bool {
    const open = log.pendingStep() catch return false;
    return open != null and open.?.step == .rollback;
}

/// Qualification hook: `F2Z_MIGRATE_FAULT=<step>` terminates the process right after that step's
/// intent is journaled, leaving exactly the state a crash would; the resume classification is what
/// the lab rehearsal then exercises. It can only stop the command early, never alter a step.
fn faultAfterIntent(step: journal.Step) void {
    faultNamed(@tagName(step));
}
fn faultNamed(name: []const u8) void {
    const wanted = std.posix.getenv("F2Z_MIGRATE_FAULT") orelse return;
    if (std.mem.eql(u8, wanted, name)) std.process.exit(137);
}

fn executeStep(ctx: *Context, log: *journal.Journal, step: journal.Step, stderr: anytype) !Control {
    const now = std.time.microTimestamp();
    switch (step) {
        .validate_plan => {
            const pending = try log.begin(step, "", now);
            faultAfterIntent(step);
            var validation = try plan_mod.validate(ctx.allocator, ctx.loaded, .{ .now_us = now, .snapshot_path = ctx.loaded.doc.snapshot.?.path });
            defer validation.deinit();
            if (validation.outcome != .valid) {
                try log.finish(pending, .validation_failed, @tagName(validation.outcome), .failed, std.time.microTimestamp());
                for (validation.reasons) |reason| stderr.print("migrate cutover: plan {s}: {s}\n", .{ @tagName(validation.outcome), reason }) catch {};
                return .{ .stop = .rejected };
            }
            try log.finish(pending, .success, "valid", .validated, std.time.microTimestamp());
            return .next;
        },
        .check_drift => {
            const pending = try log.begin(step, "", now);
            faultAfterIntent(step);
            const rows = try continuity.readLogs(ctx.allocator, ctx.loaded.doc.snapshot.?.path);
            defer continuity.freeLogs(ctx.allocator, rows);
            var boundary = try continuity.evaluate(ctx.allocator, .{ .doc = &ctx.loaded.doc, .logs = rows, .cutover_us = now });
            defer boundary.deinit();
            if (boundary.outcome == .blocked) {
                try log.finish(pending, .validation_failed, "continuity blocked", .failed, std.time.microTimestamp());
                stderr.writeAll("migrate cutover: source continuity is blocked for the requested mode:\n") catch {};
                continuity.writeBoundaryJson(&boundary, stderr) catch {};
                stderr.writeAll("\n") catch {};
                return .{ .stop = .rejected };
            }
            if (boundary.outcome == .non_lossless) stderr.writeAll("migrate cutover: continuity is not lossless; the accepted replay window applies (see docs/operations/migration-continuity.md)\n") catch {};
            try log.finish(pending, .success, @tagName(boundary.outcome), null, std.time.microTimestamp());
            return .next;
        },
        .capture_recovery_point => {
            const pending = try log.begin(step, ctx.options.staging_dir, now);
            faultAfterIntent(step);
            var captured = snapshot.capture(ctx.allocator, ctx.loaded.doc.source_db.?, ctx.options.staging_dir, .{}) catch |err| {
                try log.finish(pending, .operational_failure, @errorName(err), null, std.time.microTimestamp());
                return err;
            };
            defer captured.deinit(ctx.allocator);
            var recorded: [32]u8 = undefined;
            _ = try std.fmt.hexToBytes(&recorded, ctx.loaded.doc.snapshot.?.recorded_sha256);
            if (!std.mem.eql(u8, &recorded, &captured.destination_sha256)) {
                try log.finish(pending, .validation_failed, "source database changed since the plan snapshot", .failed, std.time.microTimestamp());
                stderr.writeAll("migrate cutover: the source database changed since the plan was made; plan again\n") catch {};
                return .{ .stop = .rejected };
            }
            var name_buffer: [64]u8 = undefined;
            const name = recoveryPointName(&name_buffer, ctx.run_id);
            var dir = try std.fs.openDirAbsolute(ctx.options.staging_dir, .{});
            defer dir.close();
            try dir.rename(std.fs.path.basename(captured.destination_path), name);
            try log.finish(pending, .success, name, .recovery_point, std.time.microTimestamp());
            return .next;
        },
        .quiesce_source => {
            const pending = try log.begin(step, "", now);
            faultAfterIntent(step);
            const quiet = try sourceQuiesced(ctx);
            if (!quiet.stopped) {
                try log.finish(pending, .operational_failure, quiet.reason, null, std.time.microTimestamp());
                stderr.print("migrate cutover: the source writer is still active ({s}); stop fail2ban and rerun with --run-id\n", .{quiet.reason}) catch {};
                return .{ .stop = .rejected };
            }
            try log.finish(pending, .success, "writer stopped; database stable", .quiesced, std.time.microTimestamp());
            return .next;
        },
        .stage_destination => {
            const pending = try log.begin(step, "", now);
            faultAfterIntent(step);
            var staging = try import_mod.import(ctx.allocator, .{ .snapshot_path = ctx.loaded.doc.snapshot.?.path, .document = &ctx.loaded.doc, .backend = ctx.options.backend, .now_us = now });
            defer staging.deinit();
            if (staging.report.blocked()) {
                try log.finish(pending, .validation_failed, "import blockers", .failed, std.time.microTimestamp());
                for (staging.report.blockers) |blocker| stderr.print("migrate cutover: import blocker {s}: {s}\n", .{ blocker.group, blocker.reason }) catch {};
                return .{ .stop = .rejected };
            }
            import_mod.stage(ctx.store, ctx.run_id, &staging) catch |err| {
                try log.finish(pending, .operational_failure, @errorName(err), null, std.time.microTimestamp());
                return err;
            };
            var detail: [128]u8 = undefined;
            const text = std.fmt.bufPrint(&detail, "owners={d} history={d} expired={d} deduplicated={d}", .{ staging.report.imported_owners, staging.report.imported_history, staging.report.skipped_expired, staging.report.double_count_avoided }) catch "staged";
            try log.finish(pending, .success, text, .staged, std.time.microTimestamp());
            return .next;
        },
        .activate_owners, .verify_protection, .complete => return activateThroughDaemon(ctx, stderr),
        .rollback => {
            stderr.writeAll("migrate cutover: this run is being rolled back; use `fail2zig migrate rollback --run-id`\n") catch {};
            return .{ .stop = .rejected };
        },
    }
}

/// The daemon journals `activate_owners` and `verify_protection` itself; this side only relays
/// the typed outcome. An unreachable socket leaves the run `staged` for a later `--run-id` rerun.
fn activateThroughDaemon(ctx: *Context, stderr: anytype) !Control {
    var out = std.ArrayList(u8).init(ctx.allocator);
    defer out.deinit();
    ctx.stderr_buffer.clearRetainingCapacity();
    const hex = std.fmt.bytesToHex(ctx.run_id, .lower);
    const code = cli.doAdmin(ctx.allocator, .{ .socket_path = ctx.options.socket_path, .timeout_ms = 30_000, .output = .json, .color = false }, out.writer(), ctx.stderr_buffer.writer(), .{ .kind = "migration_activate", .run_id = &hex });
    switch (code) {
        .connection_failed => {
            stderr.print("migrate cutover: staged; the daemon at {s} is not reachable. Start fail2zig, then rerun: fail2zig migrate cutover --run-id {s} ...\n", .{ ctx.options.socket_path, &hex }) catch {};
            return .{ .stop = .unavailable };
        },
        .client_error => {
            stderr.print("migrate cutover: activation request failed: {s}\n", .{ctx.stderr_buffer.items}) catch {};
            return .{ .stop = .uncertain };
        },
        else => {},
    }
    const Outcome = struct { outcome: []const u8, reasons: []const []const u8 = &.{} };
    const parsed = std.json.parseFromSlice(Outcome, ctx.allocator, out.items, .{ .ignore_unknown_fields = true }) catch {
        stderr.print("migrate cutover: unreadable activation response: {s}\n", .{out.items}) catch {};
        return .{ .stop = .uncertain };
    };
    defer parsed.deinit();
    for (parsed.value.reasons) |reason| stderr.print("migrate cutover: daemon: {s}\n", .{reason}) catch {};
    if (std.mem.eql(u8, parsed.value.outcome, "applied")) {
        // The daemon journaled activation and verification and moved the run to `complete`;
        // the store row, not this process's cached view, is the authority for that.
        const run = (try ctx.store.migrationRun(ctx.allocator, ctx.run_id)) orelse return .{ .stop = .uncertain };
        defer ctx.allocator.free(run.recovery_point);
        return .{ .stop = if (run.state == .complete) .success else .uncertain };
    }
    if (std.mem.eql(u8, parsed.value.outcome, "partial")) return .{ .stop = .partial };
    if (std.mem.eql(u8, parsed.value.outcome, "uncertain")) return .{ .stop = .uncertain };
    return .{ .stop = .rejected };
}

const Quiesce = struct { stopped: bool, reason: []const u8 };

/// A quiesced source has no control socket, no `fail2ban-server` process and a database whose
/// size and mtime do not change across the observation window.
fn sourceQuiesced(ctx: *Context) !Quiesce {
    const socket_path = ctx.loaded.doc.drift.runtime_socket;
    if (socket_path.len != 0) {
        if (std.fs.cwd().statFile(socket_path)) |_| {
            return .{ .stopped = false, .reason = "control socket present" };
        } else |err| if (err != error.FileNotFound) return .{ .stopped = false, .reason = "control socket unreadable" };
    }
    if (try processRunning("fail2ban-server")) return .{ .stopped = false, .reason = "fail2ban-server process present" };
    const first = try std.fs.cwd().statFile(ctx.loaded.doc.source_db.?);
    std.time.sleep(quiesce_window_ns);
    const second = try std.fs.cwd().statFile(ctx.loaded.doc.source_db.?);
    if (first.size != second.size or first.mtime != second.mtime) return .{ .stopped = false, .reason = "source database still changing" };
    return .{ .stopped = true, .reason = "" };
}

/// Bounded `/proc` scan by `comm`; at most 65536 entries are inspected.
fn processRunning(comm: []const u8) !bool {
    var proc = std.fs.openDirAbsolute("/proc", .{ .iterate = true }) catch return false;
    defer proc.close();
    var it = proc.iterate();
    var seen: u32 = 0;
    while (try it.next()) |entry| {
        seen += 1;
        if (seen > 65536) break;
        if (entry.kind != .directory or entry.name.len == 0 or !std.ascii.isDigit(entry.name[0])) continue;
        var path_buffer: [64]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buffer, "/proc/{s}/comm", .{entry.name}) catch continue;
        var name_buffer: [64]u8 = undefined;
        const name = std.fs.cwd().readFile(path, &name_buffer) catch continue;
        if (std.mem.eql(u8, std.mem.trimRight(u8, name, "\n"), comm)) return true;
    }
    return false;
}

/// Observer for resume classification: destination protection is judged from the run's activated
/// owners in the store, source state from the quiescence check. Neither reaches the kernel; the
/// daemon's own verification did, and its journaled outcome is what `classify` settles on.
fn observe(raw: ?*anyopaque, step: journal.Step, _: *const durable.Store.MigrationRun, staged: journal.StagedCounts) anyerror!journal.Observation {
    const ctx: *Context = @ptrCast(@alignCast(raw.?));
    switch (step) {
        .quiesce_source => {
            const quiet = try sourceQuiesced(ctx);
            return .{ .source = if (quiet.stopped) .present else .unknown, .detail = quiet.reason };
        },
        .activate_owners, .verify_protection, .complete => {
            const keys = try ctx.allocator.alloc([32]u8, 4096);
            defer ctx.allocator.free(keys);
            const report = try ctx.store.migrationActivatedKeys(ctx.run_id, std.time.microTimestamp(), keys);
            const destination: journal.Protection = if (report.expected == 0)
                (if (staged.owners == 0) .present else .absent)
            else if (report.found == report.expected) .present else if (report.found == 0) .absent else .partial;
            return .{ .destination = destination };
        },
        .rollback => return .{ .source = .unknown },
        else => return .{},
    }
}

test "migrate cutover: outcome to exit mapping follows the frozen outcome table" {
    try std.testing.expectEqual(ExitClass.success, exitFor(.success, .complete));
    try std.testing.expectEqual(ExitClass.unavailable, exitFor(.success, .staged));
    try std.testing.expectEqual(ExitClass.partial, exitFor(.partial, .activating));
    try std.testing.expectEqual(ExitClass.uncertain, exitFor(.uncertain, .activating));
    try std.testing.expectEqual(ExitClass.rejected, exitFor(.validation_failed, .failed));
    try std.testing.expectEqual(ExitClass.rejected, exitFor(.incompatible, .planned));
    try std.testing.expectEqual(ExitClass.partial, exitFor(.rollback_failed, .failed));
}

test "migrate cutover: process scan finds this process and not a nonsense name" {
    var buffer: [64]u8 = undefined;
    const me = try std.fs.cwd().readFile("/proc/self/comm", &buffer);
    try std.testing.expect(try processRunning(std.mem.trimRight(u8, me, "\n")));
    try std.testing.expect(!try processRunning("fail2zig-no-such-process-name"));
}

/// `migrate rollback`: restore the source's protection from the recovery point plus the mapped
/// post-cutover deltas, then, once the operator attests the restored service is running, release
/// destination ownership. The `rollback` journal step stays open between the two invocations and
/// a durable restore marker in the staging directory records that the swap completed, so a
/// resumed command classifies the exact state (before, between, after the renames) instead of
/// replaying or guessing.
pub fn runRollback(allocator: std.mem.Allocator, options: Options, stdout: anytype, stderr: anytype) ExitClass {
    const run_id = options.run_id orelse {
        stderr.writeAll("error: migrate rollback requires --run-id <hex>\n") catch {};
        return .usage;
    };
    var loaded = plan_mod.readPlanFile(allocator, options.plan_path) catch |err| {
        stderr.print("migrate rollback: {s}: {s}\n", .{ options.plan_path, @errorName(err) }) catch {};
        return .usage;
    };
    defer loaded.deinit();
    if (loaded.doc.snapshot == null or loaded.doc.source_db == null) {
        stderr.writeAll("migrate rollback: the plan carries no source database snapshot\n") catch {};
        return .rejected;
    }
    snapshot.verifyStagingDir(options.staging_dir) catch |err| {
        stderr.print("migrate rollback: staging dir {s}: {s}\n", .{ options.staging_dir, @errorName(err) }) catch {};
        return .usage;
    };
    var store = durable.Store.open(allocator, options.state_file) catch |err| {
        stderr.print("migrate rollback: state {s}: {s}\n", .{ options.state_file, @errorName(err) }) catch {};
        return .usage;
    };
    defer store.close();
    const identity = identityFor(&loaded, options.staging_dir) catch return .usage;
    var log = journal.Journal.open(allocator, &store, run_id, identity) catch |err| {
        stderr.print("migrate rollback: run {s}: {s}\n", .{ &std.fmt.bytesToHex(run_id, .lower), @errorName(err) }) catch {};
        return .rejected;
    };
    defer log.deinit();
    var ctx = Context{ .allocator = allocator, .store = &store, .loaded = &loaded, .options = &options, .run_id = run_id, .started = std.time.Timer.start() catch return .usage, .stderr_buffer = std.ArrayList(u8).init(allocator) };
    defer ctx.stderr_buffer.deinit();
    const exit = rollbackPhases(&ctx, &log, stderr) catch |err| {
        stderr.print("migrate rollback: {s}; the journal step stays open, inspect and rerun\n", .{@errorName(err)}) catch {};
        return .uncertain;
    };
    var fresh = journal.Journal.open(allocator, &store, run_id, identity) catch return exit;
    defer fresh.deinit();
    var report = fresh.report(allocator, &.{}) catch return exit;
    defer report.deinit(allocator);
    writeReport(&report, options.output, stdout) catch {};
    return exit;
}

const RestorePaths = struct {
    source: []const u8,
    derived: []u8,
    kept: []u8,
    marker: []u8,
    fn init(ctx: *Context) !RestorePaths {
        const source = ctx.loaded.doc.source_db.?;
        const source_dir = std.fs.path.dirname(source) orelse ".";
        const base = std.fs.path.basename(source);
        var name_buffer: [64]u8 = undefined;
        const recovery = recoveryPointName(&name_buffer, ctx.run_id);
        const tag = recovery[15..31];
        return .{
            .source = source,
            .derived = try std.fmt.allocPrint(ctx.allocator, "{s}/.{s}.f2z-restore", .{ source_dir, base }),
            .kept = try std.fmt.allocPrint(ctx.allocator, "{s}.pre-rollback-{s}", .{ source, tag }),
            .marker = try std.fmt.allocPrint(ctx.allocator, "{s}/restored-{s}", .{ ctx.options.staging_dir, tag }),
        };
    }
    fn deinit(self: *RestorePaths, allocator: std.mem.Allocator) void {
        allocator.free(self.derived);
        allocator.free(self.kept);
        allocator.free(self.marker);
    }
    fn exists(path: []const u8) bool {
        std.fs.accessAbsolute(path, .{}) catch return false;
        return true;
    }
};

fn rollbackPhases(ctx: *Context, log: *journal.Journal, stderr: anytype) !ExitClass {
    const now = std.time.microTimestamp();
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, ctx.loaded.doc.snapshot.?.recorded_sha256);
    var paths = try RestorePaths.init(ctx);
    defer paths.deinit(ctx.allocator);
    if (try log.pendingStep()) |open| {
        if (open.step != .rollback) {
            stderr.print("migrate rollback: step {s} is still open; resume `migrate cutover --run-id` first\n", .{@tagName(open.step)}) catch {};
            return .rejected;
        }
        if (RestorePaths.exists(paths.marker)) return releaseDestination(ctx, log, open, stderr);
        return resumeRestore(ctx, log, open, expected, &paths, stderr);
    }
    switch (log.state()) {
        .complete, .activating => {},
        .rolled_back => {
            stderr.writeAll("migrate rollback: this run is already rolled back\n") catch {};
            return .success;
        },
        else => {
            stderr.print("migrate rollback: run is {s}; only an activated run needs rollback (a staged run is discarded by not activating it)\n", .{@tagName(log.state())}) catch {};
            return .rejected;
        },
    }
    const step = try log.begin(.rollback, "restore-source", now);
    faultNamed("rollback");
    return restoreSource(ctx, log, step, expected, &paths, stderr);
}

/// Resume with the step open and no restore marker: the exact on-disk state decides what remains.
fn resumeRestore(ctx: *Context, log: *journal.Journal, step: journal.Pending, expected: [32]u8, paths: *RestorePaths, stderr: anytype) !ExitClass {
    if (!RestorePaths.exists(paths.source)) {
        if (RestorePaths.exists(paths.derived)) {
            // Killed between the two renames: the derived file is complete, finish the swap.
            const derived_sha = try snapshot.sha256File(paths.derived);
            try finishSwap(ctx, paths);
            try writeMarker(paths.marker, derived_sha);
            try ctx.store.markMigrationDeltasApplied(ctx.run_id);
            stderr.print("migrate rollback: completed the interrupted swap; source restored at {s}. Start the source service, verify it protects, then rerun with --source-verified\n", .{paths.source}) catch {};
            return .unavailable;
        }
        if (RestorePaths.exists(paths.kept)) {
            // The original was moved aside but nothing replaced it: put it back and restore again.
            try moveDatabase(ctx.allocator, paths.kept, paths.source);
            return restoreSource(ctx, log, step, expected, paths, stderr);
        }
        try log.finish(step, .rollback_failed, "source missing with no derived or kept file", .failed, std.time.microTimestamp());
        stderr.print("migrate rollback: {s} is missing and neither the derived nor the kept copy exists; restore the recovery point by hand and release the destination manually\n", .{paths.source}) catch {};
        return .partial;
    }
    const current = sourceFingerprint(ctx) catch |err| {
        stderr.print("migrate rollback: cannot fingerprint {s}: {s}; the step stays open, nothing is released\n", .{ paths.source, @errorName(err) }) catch {};
        return .uncertain;
    };
    if (std.mem.eql(u8, &current, &expected)) return restoreSource(ctx, log, step, expected, paths, stderr);
    try log.finish(step, .rollback_failed, "source changed without a completed restore", .failed, std.time.microTimestamp());
    stderr.print("migrate rollback: {s} differs from the snapshot but no restore completed; inspect it and the kept/derived copies before restoring by hand\n", .{paths.source}) catch {};
    return .partial;
}

/// First phase under the open `rollback` step: validate, derive, replace. Only a fingerprint
/// mismatch is terminal; environment failures leave the run resumable.
fn restoreSource(ctx: *Context, log: *journal.Journal, step: journal.Pending, expected: [32]u8, paths: *RestorePaths, stderr: anytype) !ExitClass {
    const now = std.time.microTimestamp();
    var name_buffer: [64]u8 = undefined;
    const recovery_name = recoveryPointName(&name_buffer, ctx.run_id);
    const recovery_path = try std.fs.path.join(ctx.allocator, &.{ ctx.options.staging_dir, recovery_name });
    defer ctx.allocator.free(recovery_path);
    const recovery_sha = snapshot.sha256File(recovery_path) catch |err| {
        try log.finish(step, .operational_failure, "recovery point unreadable", null, std.time.microTimestamp());
        stderr.print("migrate rollback: recovery point {s}: {s}; fix access and rerun\n", .{ recovery_path, @errorName(err) }) catch {};
        return .rejected;
    };
    if (!std.mem.eql(u8, &recovery_sha, &expected)) {
        try log.finish(step, .rollback_failed, "recovery point fingerprint mismatch", .failed, std.time.microTimestamp());
        stderr.writeAll("migrate rollback: the recovery point does not match the plan's snapshot; do not restore from it\n") catch {};
        return .partial;
    }
    const source_sha = sourceFingerprint(ctx) catch |err| {
        try log.finish(step, .operational_failure, "source unreadable", null, std.time.microTimestamp());
        stderr.print("migrate rollback: source {s}: {s}; fix access and rerun\n", .{ paths.source, @errorName(err) }) catch {};
        return .rejected;
    };
    if (!std.mem.eql(u8, &source_sha, &expected)) {
        try log.finish(step, .rollback_failed, "source changed since quiescence", .failed, std.time.microTimestamp());
        stderr.print("migrate rollback: {s} changed since the cutover quiesced it; nothing was written. Inspect it, then restore {s} by hand if that is what you want\n", .{ paths.source, recovery_path }) catch {};
        return .partial;
    }
    if (ctx.loaded.doc.selection.len > 64) {
        try log.finish(step, .operational_failure, "more than 64 selected groups", null, std.time.microTimestamp());
        stderr.writeAll("migrate rollback: more than 64 selected groups is outside the supported rollback bound\n") catch {};
        return .rejected;
    }
    var jail_names: [64][]const u8 = undefined;
    for (ctx.loaded.doc.selection, 0..) |group, i| jail_names[i] = group;
    const deltas = try ctx.allocator.alloc(durable.Store.MigrationDelta, 4096);
    defer ctx.allocator.free(deltas);
    const delta_count = ctx.store.planMigrationDeltas(ctx.run_id, jail_names[0..ctx.loaded.doc.selection.len], now, deltas) catch |err| {
        try log.finish(step, .operational_failure, @errorName(err), null, std.time.microTimestamp());
        stderr.print("migrate rollback: delta computation: {s} (the 4096-delta bound or storage); nothing was written\n", .{@errorName(err)}) catch {};
        return .rejected;
    };
    // Deltas are recorded as not yet applied before anything is written, so an interrupted
    // restore can be reasoned about from the journal alone.
    try ctx.store.recordMigrationDeltas(ctx.run_id, deltas[0..delta_count], false, now);
    const original = std.fs.openFileAbsolute(paths.source, .{}) catch |err| {
        try log.finish(step, .operational_failure, "source unreadable", null, std.time.microTimestamp());
        stderr.print("migrate rollback: source {s}: {s}\n", .{ paths.source, @errorName(err) }) catch {};
        return .rejected;
    };
    const original_stat = try std.posix.fstat(original.handle);
    original.close();
    std.fs.copyFileAbsolute(recovery_path, paths.derived, .{ .override_mode = 0o600 }) catch |err| {
        try log.finish(step, .operational_failure, "derived database not written", null, std.time.microTimestamp());
        stderr.print("migrate rollback: cannot write {s}: {s}; free space or fix access and rerun\n", .{ paths.derived, @errorName(err) }) catch {};
        return .rejected;
    };
    var applied: usize = 0;
    var unsupported: usize = 0;
    {
        var derived_z: [std.fs.max_path_bytes]u8 = undefined;
        const path_z = std.fmt.bufPrintZ(&derived_z, "{s}", .{paths.derived}) catch return error.PathTooLong;
        var conn = try fail2ban_db.Connection.open(path_z, fail2ban_db.open_flags.readwrite);
        defer conn.close();
        for (deltas[0..delta_count]) |delta| {
            switch (delta.carry_back) {
                .unsupported => {
                    unsupported += 1;
                    var text: [64]u8 = undefined;
                    const scope = try @import("../firewall/scope.zig").Scope.decode(&delta.scope);
                    stderr.print("migrate rollback: unsupported delta not carried back: jail {s} scope {s} (protocol/port restricted); re-create it on the source by hand\n", .{ delta.jailName(), try subjectText(&text, scope.subject) }) catch {};
                },
                .expired, .mapped => {
                    try carryBack(conn, delta, now);
                    applied += 1;
                },
            }
        }
    }
    // Durable before the swap: the derived file's pages, then its directory entry after renaming.
    {
        const derived_file = try std.fs.openFileAbsolute(paths.derived, .{});
        defer derived_file.close();
        try derived_file.sync();
        // The restored database must be usable by the service that owns the original.
        try derived_file.chown(original_stat.uid, original_stat.gid);
        try derived_file.chmod(@intCast(original_stat.mode & 0o7777));
    }
    const derived_sha = try snapshot.sha256File(paths.derived);
    faultNamed("rollback_derived");
    const recheck = try sourceFingerprint(ctx);
    if (!std.mem.eql(u8, &recheck, &expected)) {
        std.fs.deleteFileAbsolute(paths.derived) catch {};
        try log.finish(step, .rollback_failed, "source changed during restore", .failed, std.time.microTimestamp());
        stderr.writeAll("migrate rollback: the source changed while the restore was prepared; nothing replaced\n") catch {};
        return .partial;
    }
    try moveDatabase(ctx.allocator, paths.source, paths.kept);
    faultNamed("rollback_swap");
    finishSwap(ctx, paths) catch |err| {
        moveDatabase(ctx.allocator, paths.kept, paths.source) catch {};
        try log.finish(step, .operational_failure, "restore rename failed", null, std.time.microTimestamp());
        stderr.print("migrate rollback: rename into place failed: {s}; the original is back at {s}, rerun after fixing the directory\n", .{ @errorName(err), paths.source }) catch {};
        return .rejected;
    };
    try writeMarker(paths.marker, derived_sha);
    try ctx.store.markMigrationDeltasApplied(ctx.run_id);
    stderr.print("migrate rollback: source database restored at {s} (previous kept at {s}); {d} deltas carried back, {d} unsupported. Start the source service, verify it protects, then run: fail2zig migrate rollback --run-id {s} --source-verified ...\n", .{ paths.source, paths.kept, applied, unsupported, &std.fmt.bytesToHex(ctx.run_id, .lower) }) catch {};
    if (ctx.options.source_verified) stderr.writeAll("migrate rollback: --source-verified applies to the release invocation only; the source service was just restored and cannot be attested yet\n") catch {};
    return .unavailable;
}

/// Renames the derived file into place and makes the directory entry durable.
fn finishSwap(ctx: *Context, paths: *RestorePaths) !void {
    _ = ctx;
    try std.fs.renameAbsolute(paths.derived, paths.source);
    const dir_path = std.fs.path.dirname(paths.source) orelse ".";
    // A plain directory descriptor (not O_PATH) is required for fsync; the raw syscall is used
    // because the std wrapper treats EINVAL/EBADF as unreachable.
    const fd = try std.posix.open(dir_path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    defer std.posix.close(fd);
    const rc = std.os.linux.fsync(fd);
    if (std.os.linux.E.init(rc) != .SUCCESS) return error.DirectorySyncFailed;
}

/// Moves a SQLite database together with its `-wal`/`-shm` siblings so a journal never sits
/// beside a file it does not belong to.
fn moveDatabase(allocator: std.mem.Allocator, from: []const u8, to: []const u8) !void {
    try std.fs.renameAbsolute(from, to);
    inline for (.{ "-wal", "-shm" }) |suffix| {
        const from_side = try std.fmt.allocPrint(allocator, "{s}{s}", .{ from, suffix });
        defer allocator.free(from_side);
        const to_side = try std.fmt.allocPrint(allocator, "{s}{s}", .{ to, suffix });
        defer allocator.free(to_side);
        std.fs.renameAbsolute(from_side, to_side) catch |err| if (err != error.FileNotFound) return err;
    }
}

fn writeMarker(path: []const u8, derived_sha: [32]u8) !void {
    var file = try std.fs.createFileAbsolute(path, .{ .mode = 0o600 });
    defer file.close();
    try file.writeAll(&std.fmt.bytesToHex(derived_sha, .lower));
    try file.sync();
}

/// Second phase: only an operator attestation plus a running source service (control socket and
/// process) permit releasing destination ownership; the daemon settles the release by kernel
/// readback and only its `applied` closes the step, every other outcome leaves it open.
fn releaseDestination(ctx: *Context, log: *journal.Journal, step: journal.Pending, stderr: anytype) !ExitClass {
    if (!ctx.options.source_verified) {
        stderr.writeAll("migrate rollback: the source is restored but destination ownership is still held; rerun with --source-verified once the source service protects again\n") catch {};
        return .unavailable;
    }
    const socket_path = ctx.loaded.doc.drift.runtime_socket;
    if (socket_path.len != 0) {
        _ = std.fs.cwd().statFile(socket_path) catch {
            stderr.print("migrate rollback: the source control socket {s} is absent; start the source service before releasing the destination\n", .{socket_path}) catch {};
            return .unavailable;
        };
    }
    if (!try processRunning("fail2ban-server")) {
        stderr.writeAll("migrate rollback: no fail2ban-server process is running; a stale socket is not a running service\n") catch {};
        return .unavailable;
    }
    var out = std.ArrayList(u8).init(ctx.allocator);
    defer out.deinit();
    const hex = std.fmt.bytesToHex(ctx.run_id, .lower);
    const code = cli.doAdmin(ctx.allocator, .{ .socket_path = ctx.options.socket_path, .timeout_ms = 30_000, .output = .json, .color = false }, out.writer(), ctx.stderr_buffer.writer(), .{ .kind = "migration_rollback", .run_id = &hex });
    switch (code) {
        .connection_failed => {
            stderr.print("migrate rollback: the daemon at {s} is not reachable; start it and rerun with --run-id {s} --source-verified\n", .{ ctx.options.socket_path, &hex }) catch {};
            return .unavailable;
        },
        .client_error => {
            stderr.print("migrate rollback: release request not accepted: {s}; nothing changed, rerun once resolved\n", .{ctx.stderr_buffer.items}) catch {};
            return .unavailable;
        },
        else => {},
    }
    const Outcome = struct { outcome: []const u8, reasons: []const []const u8 = &.{} };
    const parsed = std.json.parseFromSlice(Outcome, ctx.allocator, out.items, .{ .ignore_unknown_fields = true }) catch {
        stderr.print("migrate rollback: unreadable release response: {s}; the step stays open\n", .{out.items}) catch {};
        return .uncertain;
    };
    defer parsed.deinit();
    for (parsed.value.reasons) |reason| stderr.print("migrate rollback: daemon: {s}\n", .{reason}) catch {};
    if (std.mem.eql(u8, parsed.value.outcome, "applied")) {
        try log.finish(step, .success, "destination released", .rolled_back, std.time.microTimestamp());
        return .success;
    }
    if (std.mem.eql(u8, parsed.value.outcome, "partial")) {
        stderr.writeAll("migrate rollback: the release is partial; the step stays open, rerun with --source-verified\n") catch {};
        return .partial;
    }
    if (std.mem.eql(u8, parsed.value.outcome, "uncertain")) {
        stderr.writeAll("migrate rollback: the release is uncertain; inspect the daemon, then rerun with --source-verified\n") catch {};
        return .uncertain;
    }
    // A refusal because storage is not healthy at that instant is transient: the daemon is
    // recovering or rebuilding, nothing was changed, and the same command succeeds once healthy.
    for (parsed.value.reasons) |reason| if (std.mem.indexOf(u8, reason, "PersistenceUnavailable") != null) {
        stderr.writeAll("migrate rollback: the daemon's storage is not healthy right now; nothing changed, rerun with --source-verified once `status` reports healthy\n") catch {};
        return .unavailable;
    };
    stderr.writeAll("migrate rollback: the daemon refused the release; the step stays open\n") catch {};
    return .rejected;
}

/// Content fingerprint of the live source as the plan recorded it: a backup-API capture into the
/// staging directory (WAL included), hashed and removed. A main-file hash would differ from the
/// snapshot whenever the source has an uncheckpointed WAL.
fn sourceFingerprint(ctx: *Context) ![32]u8 {
    var captured = try snapshot.capture(ctx.allocator, ctx.loaded.doc.source_db.?, ctx.options.staging_dir, .{});
    defer captured.deinit(ctx.allocator);
    std.fs.deleteFileAbsolute(captured.destination_path) catch {};
    return captured.destination_sha256;
}

/// Writes one delta into the derived fail2ban database: a native ban becomes `bans` history plus
/// the current `bips` row with the original decision time and remaining lease; a released or
/// expired staged owner removes its `bips` row while `bans` history is kept.
fn carryBack(conn: fail2ban_db.Connection, delta: durable.Store.MigrationDelta, now_us: i64) !void {
    const canonical = @import("../firewall/scope.zig");
    const scope = try canonical.Scope.decode(&delta.scope);
    var ip_buffer: [64]u8 = undefined;
    const ip = try subjectText(&ip_buffer, scope.subject);
    switch (delta.kind) {
        .unban, .conflict => {
            var stmt = try conn.prepare("DELETE FROM bips WHERE jail=?1 AND ip=?2");
            defer stmt.finalize();
            try stmt.bindText(1, delta.jailName());
            try stmt.bindText(2, ip);
            _ = try stmt.step();
        },
        .ban => {
            const timeofban = @divFloor(delta.decided_us, std.time.us_per_s);
            const bantime: i64 = if (delta.lease_kind == 2) -1 else @max(1, @divFloor((delta.deadline_us orelse now_us) - delta.decided_us, std.time.us_per_s));
            inline for (.{ "INSERT INTO bans(jail, ip, timeofban, bantime, bancount, data) VALUES(?1, ?2, ?3, ?4, 1, NULL)", "INSERT OR REPLACE INTO bips(jail, ip, timeofban, bantime, bancount, data) VALUES(?1, ?2, ?3, ?4, 1, NULL)" }) |sql| {
                var stmt = try conn.prepare(sql);
                defer stmt.finalize();
                try stmt.bindText(1, delta.jailName());
                try stmt.bindText(2, ip);
                try stmt.bindInt64(3, timeofban);
                try stmt.bindInt64(4, bantime);
                _ = try stmt.step();
            }
        },
    }
}

fn subjectText(buffer: []u8, subject: anytype) ![]const u8 {
    const full: u8 = if (subject.family == .v4) 32 else 128;
    var address_buffer: [48]u8 = undefined;
    const address = switch (subject.family) {
        .v4 => try std.fmt.bufPrint(&address_buffer, "{d}.{d}.{d}.{d}", .{ subject.address[0], subject.address[1], subject.address[2], subject.address[3] }),
        .v6 => blk: {
            const v6 = std.net.Ip6Address.init(subject.address, 0, 0, 0);
            var stream = std.io.fixedBufferStream(&address_buffer);
            try stream.writer().print("{}", .{v6});
            const written = stream.getWritten();
            // `[addr]:port` → addr
            const close = std.mem.lastIndexOfScalar(u8, written, ']') orelse return error.InvalidSubject;
            break :blk written[1..close];
        },
    };
    if (subject.prefix == full) return std.fmt.bufPrint(buffer, "{s}", .{address});
    return std.fmt.bufPrint(buffer, "{s}/{d}", .{ address, subject.prefix });
}

test "migrate rollback: subject text renders hosts and networks for the source database" {
    const canonical = @import("../firewall/scope.zig");
    var buffer: [64]u8 = undefined;
    const host = canonical.Subject.host(.{ .ipv4 = (203 << 24) | (113 << 8) | 77 });
    try std.testing.expectEqualStrings("203.0.113.77", try subjectText(&buffer, host));
    const net = try canonical.Subject.network(.{ .ipv4 = (198 << 24) | (51 << 16) | (100 << 8) }, 24);
    try std.testing.expectEqualStrings("198.51.100.0/24", try subjectText(&buffer, net));
    const six = canonical.Subject.host(.{ .ipv6 = (0x2001_0db8 << 96) | 1 });
    try std.testing.expectEqualStrings("2001:db8::1", try subjectText(&buffer, six));
}

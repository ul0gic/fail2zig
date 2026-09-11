// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! One jail's file ingestion lifecycle. Owns stable callback addresses, restores
//! durable processing state and every saved incarnation before discovery, and
//! bounds each poll fairly. Filter/ticket/action activation is a separate stage.
const std = @import("std");
const files = @import("durable_file_source.zig");
const processing = @import("source_processor.zig");
const pipeline = @import("record_pipeline.zig");
const durable = @import("record_store.zig");

pub const Spec = struct { pattern: []const u8, start: files.Start = .head };
pub const Session = struct {
    allocator: std.mem.Allocator,
    processor: processing.SourceProcessor,
    sources: files.FileSet,
    pipe: pipeline.Pipeline,
    next_source: usize = 0,
    mode: @import("event_time.zig").Mode,
    /// Saved tail streams intentionally restart at current EOF. This includes
    /// retired incarnations: their saved positions are not resurrected as head
    /// input. Keep at most 64 IDs for diagnostics, plus the complete reset count.
    tail_resets: std.ArrayList([]u8),
    tail_reset_count: usize,
    restored_sources: usize,

    /// Store and processing option strings must outlive the session. Allocation
    /// keeps processor/pipe callback addresses stable across discovery and restart.
    pub fn create(allocator: std.mem.Allocator, store: *durable.Store, options: processing.Options, specs: []const Spec, now: f64, usage_time: f64) !*Session {
        if (specs.len == 0 or specs.len > 4096) return error.InvalidSourceSpecifications;
        const self = try allocator.create(Session);
        errdefer allocator.destroy(self);
        self.allocator = allocator;
        self.tail_resets = std.ArrayList([]u8).init(allocator);
        self.tail_reset_count = 0;
        self.restored_sources = 0;
        errdefer self.clearTailResets();
        var bound_options = options;
        const specification = try std.json.stringifyAlloc(allocator, .{ .parent = options.source_configuration_hash, .specs = specs }, .{});
        defer allocator.free(specification);
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(specification, &hash, .{});
        bound_options.source_configuration_hash = hash;
        self.processor = try processing.SourceProcessor.init(allocator, bound_options, now, usage_time);
        errdefer self.processor.deinit();
        self.sources = try files.FileSet.init(allocator, options.identity.jail_id);
        errdefer self.sources.deinit();
        self.sources.initialize_source = initializeSource;
        self.sources.initialize_userdata = self;
        self.next_source = 0;
        self.mode = options.mode;
        for (specs) |spec| try self.sources.add(spec.pattern, spec.start);
        self.pipe = .{ .store = store, .jail = self.sources.jail, .processor = self.processor.adapter() };
        try self.pipe.restore(allocator);
        try store.visitSources(self.pipe.jail, restoreSource, self);
        // Enumeration must agree with the processor snapshot. A later writer is
        // caught again by Pipeline's revision compare-and-swap before any publish.
        if (try store.revision(self.pipe.jail) != self.pipe.revision) return error.StaleCheckpoint;
        try self.sources.discover();
        return self;
    }

    pub fn destroy(self: *Session) void {
        self.clearTailResets();
        self.sources.deinit();
        self.processor.deinit();
        const allocator = self.allocator;
        allocator.destroy(self);
    }

    fn clearTailResets(self: *Session) void {
        for (self.tail_resets.items) |source| self.allocator.free(source);
        self.tail_resets.deinit();
    }

    fn initializeSource(source: *files.FileSource, context: ?*anyopaque) !void {
        const self: *Session = @ptrCast(@alignCast(context.?));
        try self.processor.bindFile(source);
    }

    fn restoreSource(source: []const u8, path: []const u8, cursor: []const u8, context: ?*anyopaque) !void {
        const self: *Session = @ptrCast(@alignCast(context.?));
        // Historical tail cursors do not occupy an active descriptor, but their
        // validation work and diagnostics still need an explicit restore budget.
        if (self.restored_sources >= 65536) return error.RestoreSourceLimit;
        self.restored_sources += 1;
        if (path.len == 0) return error.InvalidFileCursor;
        var parsed = try std.json.parseFromSlice(files.Resume, self.allocator, cursor, .{});
        defer parsed.deinit();
        if (parsed.value.version != 2 or parsed.value.prefix_len > 64) return error.InvalidResume;
        if (parsed.value.start == .tail) {
            const saved_hash = parsed.value.codec_configuration_hash orelse return error.FramingProfileMismatch;
            const configured_hash = try self.processor.framingIdentity();
            if (!std.mem.eql(u8, &saved_hash, &configured_hash)) return error.FramingProfileMismatch;
            self.tail_reset_count += 1;
            if (self.tail_resets.items.len < 64) {
                const id = try self.allocator.dupe(u8, source);
                errdefer self.allocator.free(id);
                try self.tail_resets.append(id);
            }
            return;
        }
        try self.sources.addResume(path, source, parsed.value);
    }

    /// Attempt at most budget sources, one record each, resuming after the last
    /// attempt next call. Idle sources consume budget too; this bounds work even
    /// when thousands of files contain no complete record. Errors retain cursors.
    pub fn poll(self: *Session, budget: usize, now: f64, usage_time: f64) !usize {
        if (budget == 0 or budget > self.sources.max_sources) return error.InvalidPollBudget;
        if (!self.pipe.ready) return error.RestoreRequired;
        try self.processor.setClock(now, usage_time);
        try self.sources.discover();
        const count = self.sources.sources.items.len;
        if (count == 0) return 0;
        var delivered: usize = 0;
        for (0..@min(budget, count)) |_| {
            const index = self.next_source % count;
            self.next_source = (index + 1) % count;
            const source = &self.sources.sources.items[index];
            self.processor.options.mode = if (self.mode == .startup) (if (source.in_operation) .live else .startup) else self.mode;
            if (source.poll(pipeline.Pipeline.acknowledge, &self.pipe) catch |err| {
                self.sources.health = source.health;
                return err;
            }) delivered += 1;
        }
        return delivered;
    }

    pub fn restartWorker(self: *Session, epoch: []const u8) !void {
        if (!self.pipe.ready) return error.RestoreRequired;
        try self.processor.restart(epoch);
        // Replacement keeps this field's address, so every FileSource callback
        // and Pipeline processor points to the replacement automatically.
    }
};

test "file session: multiple sources, fair bounded polls, rotation and durable restart" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const pattern = try std.fs.path.join(allocator, &.{ root, "*.log" });
    defer allocator.free(pattern);
    const database = try std.fs.path.join(allocator, &.{ root, "state.sqlite" });
    defer allocator.free(database);
    const script = try std.fs.cwd().realpathAlloc(allocator, "engine/compat/worker.py");
    defer allocator.free(script);
    try tmp.dir.writeFile(.{ .sub_path = "a.log", .data = "1730000000 ordinary A\n" });
    try tmp.dir.writeFile(.{ .sub_path = "b.log", .data = "1730000000 ordinary B\n" });
    const options = processing.Options{ .python = "/usr/bin/python3", .script = script, .identity = .{ .daemon_epoch = "session-test", .worker_epoch = "first", .config_generation = "fixture-config", .jail_id = "fixture" }, .date_patterns = &.{"EPOCH"}, .reference_year = 2026 };
    var store = try durable.Store.open(allocator, database);
    defer store.close();
    const session = try Session.create(allocator, &store, options, &.{.{ .pattern = pattern }}, 1730000001, 1730000001);
    var alive = true;
    defer if (alive) session.destroy();
    try std.testing.expectEqual(@as(usize, 2), session.sources.sources.items.len);
    try std.testing.expectEqual(@as(usize, 1), try session.poll(1, 1730000001, 1730000001));
    var first = try session.processor.snapshot(allocator);
    defer first.deinit();
    try std.testing.expectEqualStrings("1730000000 ordinary A", first.value.last.?.message);
    try std.testing.expectEqual(@as(usize, 1), try session.poll(1, 1730000001, 1730000001));
    var second = try session.processor.snapshot(allocator);
    defer second.deinit();
    try std.testing.expectEqualStrings("1730000000 ordinary B", second.value.last.?.message);
    const committed_revision = session.pipe.revision;
    try std.testing.expectEqual(@as(usize, 0), try session.poll(2, 1730000001, 1730000001));
    try std.testing.expectEqual(committed_revision, session.pipe.revision);
    try tmp.dir.rename("a.log", "a.rotated");
    try tmp.dir.writeFile(.{ .sub_path = "a.log", .data = "1730000001 ordinary replacement\n" });
    var rotated = try tmp.dir.openFile("a.rotated", .{ .mode = .write_only });
    defer rotated.close();
    try rotated.seekFromEnd(0);
    try rotated.writeAll("1730000001 ordinary late\n");
    session.destroy();
    alive = false;
    var resumed_options = options;
    resumed_options.identity.worker_epoch = "second";
    const resumed = try Session.create(allocator, &store, resumed_options, &.{.{ .pattern = pattern }}, 1730000002, 1730000002);
    defer resumed.destroy();
    try std.testing.expectEqual(@as(usize, 3), resumed.sources.sources.items.len);
    // Both late writes and replacement survive discovery/restart; neither old
    // record replays. Failure leaves the proposed raw position uncommitted.
    store.fail_at = .before_commit;
    try std.testing.expectError(error.InjectedFailure, resumed.poll(3, 1730000002, 1730000002));
    try std.testing.expectEqual(committed_revision, resumed.pipe.revision);
    store.fail_at = null;
    try resumed.restartWorker("third");
    var delivered: usize = 0;
    for (0..3) |_| delivered += try resumed.poll(3, 1730000002, 1730000002);
    try std.testing.expectEqual(@as(usize, 2), delivered);
    try std.testing.expectEqual(committed_revision + 3, resumed.pipe.revision); // new baseline + two records
    try std.testing.expectEqual(@as(i64, 0), try store.pendingIntents());
    // A configuration change cannot reuse old decoded/date contexts or cursors.
    var changed_options = resumed_options;
    changed_options.identity.worker_epoch = "changed";
    changed_options.encoding = "latin1";
    try std.testing.expectError(error.CheckpointProfileMismatch, Session.create(allocator, &store, changed_options, &.{.{ .pattern = pattern }}, 1730000002, 1730000002));
    try std.testing.expectError(error.CheckpointProfileMismatch, Session.create(allocator, &store, resumed_options, &.{.{ .pattern = pattern, .start = .tail }}, 1730000002, 1730000002));
}

test "file session: startup and live are per file and EOF follows successful publication" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const pattern = try std.fs.path.join(allocator, &.{ root, "*.log" });
    defer allocator.free(pattern);
    const database = try std.fs.path.join(allocator, &.{ root, "state.sqlite" });
    defer allocator.free(database);
    const script = try std.fs.cwd().realpathAlloc(allocator, "engine/compat/worker.py");
    defer allocator.free(script);
    try tmp.dir.writeFile(.{ .sub_path = "a.log", .data = "1729998000 ordinary old A\n" });
    try tmp.dir.writeFile(.{ .sub_path = "b.log", .data = "" });
    const options = processing.Options{ .python = "/usr/bin/python3", .script = script, .identity = .{ .daemon_epoch = "mode-test", .worker_epoch = "first", .config_generation = "mode-config", .jail_id = "fixture" }, .date_patterns = &.{"EPOCH"}, .reference_year = 2026 };
    var store = try durable.Store.open(allocator, database);
    defer store.close();
    const session = try Session.create(allocator, &store, options, &.{.{ .pattern = pattern }}, 1730000000, 1730000000);
    defer session.destroy();
    store.fail_at = .before_commit;
    try std.testing.expectError(error.InjectedFailure, session.poll(1, 1730000000, 1730000000));
    try std.testing.expect(!session.sources.sources.items[0].in_operation);
    store.fail_at = null;
    try std.testing.expectEqual(@as(usize, 0), try session.poll(1, 1730000000, 1730000000)); // empty B
    try std.testing.expect(!session.sources.sources.items[1].in_operation);
    try std.testing.expectEqual(@as(usize, 1), try session.poll(1, 1730000000, 1730000000)); // old A
    var old = try session.processor.snapshot(allocator);
    defer old.deinit();
    try std.testing.expectEqual(@import("event_time.zig").Mode.startup, old.value.last.?.mode);
    try std.testing.expectEqual(@import("event_time.zig").Disposition.obsolete, old.value.last.?.disposition);
    try std.testing.expect(session.sources.sources.items[0].in_operation);
    for ([_][]const u8{ "a.log", "b.log" }) |path| {
        var file = try tmp.dir.openFile(path, .{ .mode = .write_only });
        defer file.close();
        try file.seekFromEnd(0);
        try file.writeAll("1729998000 ordinary appended\n");
    }
    try std.testing.expectEqual(@as(usize, 1), try session.poll(1, 1730000000, 1730000000)); // B's first record
    var b = try session.processor.snapshot(allocator);
    defer b.deinit();
    try std.testing.expectEqual(@import("event_time.zig").Mode.startup, b.value.last.?.mode);
    try std.testing.expectEqual(@import("event_time.zig").Disposition.obsolete, b.value.last.?.disposition);
    try std.testing.expectEqual(@as(usize, 1), try session.poll(1, 1730000000, 1730000000)); // A is already live
    var a = try session.processor.snapshot(allocator);
    defer a.deinit();
    try std.testing.expectEqual(@import("event_time.zig").Mode.live, a.value.last.?.mode);
    try std.testing.expectEqual(@import("event_time.zig").Disposition.accepted, a.value.last.?.disposition);
    try std.testing.expectEqual(@import("event_time.zig").Origin.live_correction, a.value.last.?.origin.?);
    try tmp.dir.rename("a.log", "a.rotated");
    try tmp.dir.writeFile(.{ .sub_path = "a.log", .data = "1729998000 ordinary replacement\n" });
    try std.testing.expectEqual(@as(usize, 1), try session.poll(3, 1730000000, 1730000000));
    var replacement = try session.processor.snapshot(allocator);
    defer replacement.deinit();
    try std.testing.expectEqual(@import("event_time.zig").Mode.live, replacement.value.last.?.mode);
    try std.testing.expectEqual(@import("event_time.zig").Disposition.accepted, replacement.value.last.?.disposition);
}

test "file session: tail restart declares saved cursor reset and commits current EOF baseline" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const pattern = try std.fs.path.join(allocator, &.{ root, "*.log" });
    defer allocator.free(pattern);
    const database = try std.fs.path.join(allocator, &.{ root, "state.sqlite" });
    defer allocator.free(database);
    const script = try std.fs.cwd().realpathAlloc(allocator, "engine/compat/worker.py");
    defer allocator.free(script);
    try tmp.dir.writeFile(.{ .sub_path = "a.log", .data = "1730000000 ordinary history\n" });
    const options = processing.Options{ .python = "/usr/bin/python3", .script = script, .identity = .{ .daemon_epoch = "tail-test", .worker_epoch = "first", .config_generation = "tail-config", .jail_id = "fixture" }, .date_patterns = &.{"EPOCH"}, .reference_year = 2026 };
    var store = try durable.Store.open(allocator, database);
    defer store.close();
    const session = try Session.create(allocator, &store, options, &.{ .{ .pattern = pattern, .start = .tail }, .{ .pattern = pattern, .start = .head } }, 1730000001, 1730000001);
    var alive = true;
    defer if (alive) session.destroy();
    try std.testing.expectEqual(@as(usize, 0), try session.poll(1, 1730000001, 1730000001));
    try std.testing.expectEqual(files.Start.tail, session.sources.sources.items[0].acknowledgedCheckpoint().?.start);
    const revision = session.pipe.revision;
    const prior_cursor = try allocator.dupe(u8, session.sources.sources.items[0].source_id);
    defer allocator.free(prior_cursor);
    session.destroy();
    alive = false;
    // The old incarnation remains outside the active glob. Tail explicitly
    // chooses current EOF on restart rather than resurrecting historical input.
    try tmp.dir.rename("a.log", "a.rotated");
    try tmp.dir.writeFile(.{ .sub_path = "a.log", .data = "1730000001 ordinary offline\n" });
    var resumed_options = options;
    resumed_options.identity.worker_epoch = "second";
    const resumed = try Session.create(allocator, &store, resumed_options, &.{ .{ .pattern = pattern, .start = .tail }, .{ .pattern = pattern, .start = .head } }, 1730000002, 1730000002);
    defer resumed.destroy();
    try std.testing.expectEqual(@as(usize, 1), resumed.tail_resets.items.len);
    try std.testing.expectEqual(@as(usize, 1), resumed.tail_reset_count);
    try std.testing.expectEqualStrings(prior_cursor, resumed.tail_resets.items[0]);
    try std.testing.expectEqual(@as(usize, 1), resumed.sources.sources.items.len);
    try std.testing.expect(resumed.sources.sources.items[0].acknowledgedCheckpoint() == null);
    try std.testing.expectEqual(@as(usize, 0), try resumed.poll(1, 1730000002, 1730000002));
    try std.testing.expectEqual(revision + 1, resumed.pipe.revision);
    try std.testing.expect(resumed.sources.sources.items[0].acknowledgedCheckpoint() != null);
    var before = try resumed.processor.snapshot(allocator);
    defer before.deinit();
    try std.testing.expect(before.value.last == null);
    var file = try tmp.dir.openFile("a.log", .{ .mode = .write_only });
    defer file.close();
    try file.seekFromEnd(0);
    try file.writeAll("1730000002 ordinary online\n");
    try std.testing.expectEqual(@as(usize, 1), try resumed.poll(1, 1730000002, 1730000002));
    var after = try resumed.processor.snapshot(allocator);
    defer after.deinit();
    try std.testing.expectEqualStrings("1730000002 ordinary online", after.value.last.?.message);
    try std.testing.expectEqual(@import("event_time.zig").Mode.live, after.value.last.?.mode);
}

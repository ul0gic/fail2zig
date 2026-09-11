// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! A jail's acknowledged journal lifecycle. Exact cursor recovery never silently
//! falls back to a time seek; initial reference startup still uses a time window.
const std = @import("std");
const policy = @import("journal_policy.zig");
const journal = @import("systemd_reader.zig");
const processing = @import("source_processor.zig");
const pipeline = @import("record_pipeline.zig");
const durable = @import("record_store.zig");
const records = @import("source_record.zig");
const times = @import("event_time.zig");

pub const Options = struct {
    journal: policy.Options = .{},
    environment: policy.Environment,
    matches: []const []const u8 = &.{},
    source_id: []const u8 = "systemd-journal",
    /// An explicitly migrated reference time is considered only without a durable
    /// exact cursor. This never authorizes skipping a missing committed cursor.
    legacy_position: ?f64 = null,
};
pub const Session = struct {
    allocator: std.mem.Allocator,
    options: Options,
    processor: processing.SourceProcessor,
    pipe: pipeline.Pipeline,
    reader: journal.Reader,
    initial_tail: ?[:0]u8,
    tail_marker: bool,
    boundary_time: f64,
    in_operation: bool,
    base_mode: times.Mode,
    selection_diagnostic: ?[]const u8,
    pending_mode: ?*ProposedMode = null,
    const ProposedMode = struct { in_operation: bool, tail_marker: bool, boundary_time: f64 };

    /// Store, configuration strings and environment callback context must outlive
    /// this stable allocation. No firewall/action execution occurs in this session.
    pub fn create(allocator: std.mem.Allocator, store: *durable.Store, processor_options: processing.Options, options: Options, now: f64, usage_time: f64) !*Session {
        _ = try times.EventTime.init(now);
        if (options.legacy_position) |position| _ = try times.EventTime.init(position);
        if (options.source_id.len == 0) return error.InvalidSource;
        var arena_state = std.heap.ArenaAllocator.init(allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const prepared = try policy.prepare(arena, options.journal, options.environment);
        const selection = try prepared.selection(options.matches);
        const self = try allocator.create(Session);
        errdefer allocator.destroy(self);
        self.allocator = allocator;
        self.options = options;
        self.base_mode = processor_options.mode;
        self.selection_diagnostic = prepared.selectionDiagnostic();
        var bound_options = processor_options;
        // Bind requested policy and captured environment, not an incidental
        // discovery result which may change when journal files rotate/reappear.
        const specification = try std.json.stringifyAlloc(arena, .{ .parent_binding = processor_options.source_configuration_hash, .journal = options.journal, .matches = options.matches, .source_id = options.source_id, .legacy_position = options.legacy_position, .state_logs = options.environment.state_logs, .runtime_logs = options.environment.runtime_logs, .effective_uid = options.environment.effective_uid, .default_flags = options.environment.default_flags, .max_files = options.environment.max_files }, .{});
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(specification, &hash, .{});
        bound_options.source_configuration_hash = hash;
        self.processor = try processing.SourceProcessor.init(allocator, bound_options, now, usage_time);
        errdefer self.processor.deinit();
        self.processor.mode_selector = .{ .choose = selectMode, .context = self };
        self.pending_mode = null;
        self.pipe = .{ .store = store, .jail = processor_options.identity.jail_id, .processor = self.processor.adapter() };
        try self.pipe.restore(allocator);
        const cursor = try store.sourceCursor(allocator, self.pipe.jail, options.source_id);
        defer if (cursor) |value| allocator.free(value);
        if (try store.revision(self.pipe.jail) != self.pipe.revision) return error.StaleCheckpoint;
        self.reader = try journal.Reader.init(allocator, options.source_id, selection, cursor);
        errdefer self.reader.deinit();
        self.initial_tail = try self.reader.startupTail();
        errdefer if (self.initial_tail) |value| allocator.free(value);
        self.tail_marker = self.initial_tail != null;
        self.in_operation = self.initial_tail == null;
        self.boundary_time = now;
        if (cursor == null) {
            const start = if (self.initial_tail != null)
                @max(options.legacy_position orelse 0, now - @trunc(processor_options.findtime))
            else
                now;
            try self.reader.setStartRealtime(try realtimeMicros(start));
        }
        return self;
    }

    pub fn destroy(self: *Session) void {
        self.reader.deinit();
        self.processor.deinit();
        if (self.initial_tail) |value| self.allocator.free(value);
        const allocator = self.allocator;
        allocator.destroy(self);
    }

    /// A fresh helper must present the same runtime profile before restoring the
    /// committed codec/date/tuple context. Cursor and startup state remain intact.
    pub fn restartWorker(self: *Session, epoch: []const u8) !void {
        if (!self.pipe.ready) return error.RestoreRequired;
        try self.processor.restart(epoch);
    }

    /// Explicit source recovery re-evaluates current files but reuses only the
    /// authoritative durable cursor. A lost cursor remains a visible error at poll.
    pub fn reopen(self: *Session) !void {
        if (!self.pipe.ready) return error.RestoreRequired;
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();
        const prepared = try policy.prepare(arena_state.allocator(), self.options.journal, self.options.environment);
        const cursor = try self.pipe.store.sourceCursor(self.allocator, self.pipe.jail, self.options.source_id);
        defer if (cursor) |value| self.allocator.free(value);
        if (try self.pipe.store.revision(self.pipe.jail) != self.pipe.revision) return error.StaleCheckpoint;
        var replacement = try journal.Reader.init(self.allocator, self.options.source_id, try prepared.selection(self.options.matches), cursor);
        errdefer replacement.deinit();
        if (cursor == null) {
            // No successful record yet: retain the original startup boundary.
            const start = if (self.initial_tail != null)
                @max(self.options.legacy_position orelse 0, self.boundary_time - @trunc(self.processor.options.findtime))
            else
                self.boundary_time;
            try replacement.setStartRealtime(try realtimeMicros(start));
        }
        self.reader.deinit();
        self.reader = replacement;
        self.selection_diagnostic = prepared.selectionDiagnostic();
    }

    /// One bounded record attempt. EOF enters live mode without manufacturing a
    /// record or advancing durable state. Startup mode is reconstructed on restart
    /// against the new startup boundary, like the reference's run loop.
    pub fn poll(self: *Session, now: f64, usage_time: f64) !bool {
        if (!self.pipe.ready) return error.RestoreRequired;
        try self.processor.setClock(now, usage_time);
        const delivered = try self.reader.poll(acknowledge, self);
        if (!delivered) self.in_operation = true;
        return delivered;
    }

    fn acknowledge(record: records.Record, context: ?*anyopaque) !void {
        const self: *Session = @ptrCast(@alignCast(context.?));
        if (self.pending_mode != null) return error.ProcessorBusy;
        var proposed = ProposedMode{ .in_operation = self.in_operation, .tail_marker = self.tail_marker, .boundary_time = self.boundary_time };
        self.pending_mode = &proposed;
        defer self.pending_mode = null;
        try pipeline.Pipeline.acknowledge(record, &self.pipe);
        self.in_operation = proposed.in_operation;
        self.tail_marker = proposed.tail_marker;
        self.boundary_time = proposed.boundary_time;
    }

    fn selectMode(record: records.Record, timestamp: times.EventTime, context: ?*anyopaque) !times.Mode {
        const self: *Session = @ptrCast(@alignCast(context.?));
        const proposed = self.pending_mode orelse return error.MissingStagedMode;
        if (!proposed.in_operation) {
            const now = self.processor.now;
            if (timestamp.seconds >= now - 1) {
                proposed.in_operation = true;
            } else if (proposed.tail_marker) {
                if (std.mem.eql(u8, record.cursor, self.initial_tail.?) or timestamp.seconds > proposed.boundary_time) {
                    proposed.tail_marker = false;
                    proposed.boundary_time = now * 2 - proposed.boundary_time;
                    if (!std.math.isFinite(proposed.boundary_time)) return error.InvalidStartupBoundary;
                }
            } else if (timestamp.seconds > proposed.boundary_time) {
                proposed.in_operation = true;
            }
        }
        return if (self.base_mode == .startup) (if (proposed.in_operation) .live else .startup) else self.base_mode;
    }
};

fn realtimeMicros(seconds: f64) !u64 {
    // Python Reader.seek_realtime converts int(float_seconds * 1e6).
    const value = seconds * 1_000_000;
    if (!std.math.isFinite(value) or value < 0 or value >= 18446744073709551616.0) return error.InvalidStartTime;
    return @intFromFloat(value);
}

test "journal session: private source worker SQLite commit restart reopen and exact lost cursor" {
    const allocator = std.testing.allocator;
    const fixture = std.process.getEnvVarOwned(allocator, "F2Z_TEST_JOURNAL_PATH") catch return error.SkipZigTest;
    defer allocator.free(fixture);
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const path = try std.fs.path.join(allocator, &.{ base, "original.journal" });
    defer allocator.free(path);
    try std.fs.cwd().copyFile(fixture, temp.dir, "original.journal", .{});
    const database = try std.fs.path.join(allocator, &.{ base, "state.sqlite" });
    defer allocator.free(database);
    const script = try std.fs.cwd().realpathAlloc(allocator, "engine/compat/worker.py");
    defer allocator.free(script);
    var store = try durable.Store.open(allocator, database);
    defer store.close();
    const processor_options = processing.Options{ .python = "/usr/bin/python3", .script = script, .identity = .{ .daemon_epoch = "journal-session", .worker_epoch = "first", .config_generation = "private-journal-config", .jail_id = "fixture" }, .date_patterns = &.{}, .reference_year = 2026, .line_limits = .{ .max_lines = 10 } };
    const options = Options{ .journal = .{ .files = &.{path}, .flags = "0", .rotated = "yes" }, .environment = .{ .state_logs = base, .runtime_logs = base, .effective_uid = 0 } };
    const session = try Session.create(allocator, &store, processor_options, options, 1730000005, 1730000005);
    var alive = true;
    defer if (alive) session.destroy();
    store.fail_at = .before_commit;
    try std.testing.expectError(error.InjectedFailure, session.poll(1730000005, 1730000005));
    try std.testing.expect(session.reader.committed_cursor == null);
    try std.testing.expect(!session.in_operation);
    store.fail_at = null;
    try std.testing.expect(try session.poll(1730000005, 1730000005));
    var first = try session.processor.snapshot(allocator);
    defer first.deinit();
    try std.testing.expectEqual(@as(?u64, 1730000000123456), first.value.last.?.timestamp_us);
    try std.testing.expectEqualStrings("2024-10-27T03:33:20.123456+00:00 ", first.value.line_context.processed.?.time);
    try std.testing.expectEqual(times.Mode.startup, first.value.last.?.mode);
    const first_cursor = try allocator.dupe(u8, session.reader.committed_cursor.?);
    defer allocator.free(first_cursor);
    session.destroy();
    alive = false;
    var next_processor = processor_options;
    next_processor.identity.worker_epoch = "second";
    const resumed = try Session.create(allocator, &store, next_processor, options, 1730000006, 1730000006);
    defer resumed.destroy();
    try std.testing.expectEqualStrings(first_cursor, resumed.reader.committed_cursor.?);
    try resumed.restartWorker("third");
    try resumed.reopen();
    var count: usize = 0;
    while (try resumed.poll(1730000006, 1730000006)) : (count += 1) {
        if (count >= 6) return error.UnboundedPrivateFixture;
    }
    try std.testing.expectEqual(@as(usize, 5), count);
    try std.testing.expect(resumed.in_operation);
    var last = try resumed.processor.snapshot(allocator);
    defer last.deinit();
    try std.testing.expectEqual(@as(usize, 6), last.value.line_context.lines.len);
    try std.testing.expectEqual(@as(i64, 0), try store.pendingIntents());
    const revision = resumed.pipe.revision;
    try std.testing.expect(!try resumed.poll(1730000006, 1730000006));
    try std.testing.expectEqual(revision, resumed.pipe.revision);
    // A deliberately invalid durable cursor must never be replaced by "now".
    _ = try store.commitRecord(.{ .jail = "fixture", .source = options.source_id, .occurrence = "original-missing-cursor-control", .cursor = "s=00000000000000000000000000000000;i=ffffffff;b=11111111111111111111111111111111;m=1;t=1;x=1", .raw_hash = [_]u8{3} ** 32, .disposition = "original-control", .checkpoint = resumed.processor.committed, .expected_revision = revision });
    var lost_options = processor_options;
    lost_options.identity.worker_epoch = "lost-cursor";
    const lost = try Session.create(allocator, &store, lost_options, options, 1730000007, 1730000007);
    defer lost.destroy();
    try std.testing.expectError(error.ResumeLost, lost.poll(1730000007, 1730000007));
    try std.testing.expectEqual(records.Health.resume_lost, lost.reader.health);
}

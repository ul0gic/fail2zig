// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Original private-journal startup observations, with a fresh temporary database.
const std = @import("std");
const session_mod = @import("core/journal_session.zig");
const processing = @import("core/source_processor.zig");
const durable = @import("core/record_store.zig");
const Observation = struct { cursor: []const u8, mode: []const u8, time_text: []const u8, message: []const u8, timestamp_bits: []const u8 };
pub fn main() !void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const args = try std.process.argsAlloc(a);
    if (args.len < 5) return error.InvalidArguments;
    const now = try std.fmt.parseFloat(f64, args[2]);
    const findtime = try std.fmt.parseFloat(f64, args[3]);
    const legacy: ?f64 = if (std.mem.eql(u8, args[4], "none")) null else try std.fmt.parseFloat(f64, args[4]);
    var random: [16]u8 = undefined;
    std.crypto.random.bytes(&random);
    const root = try std.fmt.allocPrint(a, "/tmp/f2z-journal-session-{s}", .{std.fmt.fmtSliceHexLower(&random)});
    try std.fs.cwd().makeDir(root);
    defer std.fs.cwd().deleteTree(root) catch {};
    const database = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    const script = try std.fs.cwd().realpathAlloc(a, "engine/compat/worker.py");
    var store = try durable.Store.open(a, database);
    defer store.close();
    const encoding = std.process.getEnvVarOwned(a, "F2Z_JOURNAL_PROBE_ENCODING") catch "utf-8";
    const options = processing.Options{ .encoding = encoding, .python = "/usr/bin/python3", .script = script, .identity = .{ .daemon_epoch = "journal-probe", .worker_epoch = "first", .config_generation = "original-journal", .jail_id = "fixture" }, .findtime = findtime, .date_patterns = &.{}, .reference_year = 2026 };
    const session = try session_mod.Session.create(a, &store, options, .{ .journal = .{ .files = &.{args[1]}, .flags = "0", .rotated = "1" }, .matches = args[5..], .legacy_position = legacy, .environment = .{ .state_logs = root, .runtime_logs = root, .effective_uid = 0 } }, now, now);
    defer session.destroy();
    var observations = std.ArrayList(Observation).init(a);
    while (try session.poll(now, now)) {
        if (observations.items.len >= 64) return error.RecordLimit;
        var snapshot = try session.processor.snapshot(a);
        defer snapshot.deinit();
        const value = snapshot.value.last.?;
        try observations.append(.{ .cursor = try a.dupe(u8, session.reader.committed_cursor.?), .mode = try a.dupe(u8, @tagName(value.mode)), .time_text = try a.dupe(u8, snapshot.value.line_context.last_time_text), .message = try a.dupe(u8, value.message), .timestamp_bits = try a.dupe(u8, value.date_raw_timestamp_bits.?) });
    }
    try std.json.stringify(.{ .records = observations.items, .in_operation = session.in_operation }, .{}, std.io.getStdOut().writer());
}
test {
    std.testing.refAllDecls(session_mod);
}

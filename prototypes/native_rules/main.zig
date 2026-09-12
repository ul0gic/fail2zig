// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Offline observation only. Never imports the daemon or enforcement code.
const std = @import("std");
const rules = @import("rules.zig");

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const a = gpa.allocator();
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 4) {
        std.debug.print("usage: native-rules-probe RULE.json SOURCE RECORDS.jsonl-or-text\nOffline candidates only; each record advances the synthetic clock by one second.\n", .{});
        return error.InvalidArguments;
    }
    const config = try std.fs.cwd().readFileAlloc(a, args[1], 4096);
    defer a.free(config);
    const p = rules.Program.create(a, config, .{}) catch |err| {
        std.debug.print("rule rejected: {s}\n", .{@errorName(err)});
        return err;
    };
    defer p.destroy();
    const records = try std.fs.cwd().readFileAlloc(a, args[3], 1024 * 1024);
    defer a.free(records);
    var session: rules.Session = .{ .program = p };
    var lines = std.mem.splitScalar(u8, records, '\n');
    var now: u64 = 0;
    var rejected = false;
    while (lines.next()) |line| {
        // A final unterminated record is reported as incomplete rather than accepted.
        const complete = lines.index != null;
        if (line.len == 0 and !complete) break;
        const out = session.evaluate(args[2], line, complete, now);
        try out.writeJson(std.io.getStdOut().writer());
        rejected = rejected or out.kind == .rejected or out.kind == .exhausted;
        now += 1;
    }
    if (rejected) return error.RecordsRejected;
}

// SPDX-License-Identifier: AGPL-3.0-or-later
//! Prepared source conversion only; no sessions or runtime setters.
const std = @import("std");
const engine = @import("engine");
const source = engine.migration_mod.source_plan;
pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const args = try std.process.argsAlloc(a);
    const cfg = try engine.config_mod.Config.loadFile(a, args[1]);
    const manifest = try std.json.parseFromSlice(std.json.Value, a, cfg.global.compatibility_manifest, .{});
    const plans = manifest.value.object.get("source_plans").?.array.items;
    var results = std.ArrayList(std.json.Value).init(a);
    for (plans) |value| {
        const data = try std.json.stringifyAlloc(a, value, .{});
        const parsed = try std.json.parseFromSlice(source.Plan, a, data, .{});
        const plan = parsed.value;
        var path_error: ?[]const u8 = null;
        _ = plan.fileSpecs(a) catch |err| blk: {
            path_error = @errorName(err);
            break :blk &.{};
        };
        var match_error: ?[]const u8 = null;
        const matches = plan.journalMatches(a) catch |err| blk: {
            match_error = @errorName(err);
            break :blk &.{};
        };
        const out = try std.json.stringifyAlloc(a, .{ .jail = plan.jail, .path_error = path_error, .matches = matches, .match_error = match_error }, .{});
        try results.append((try std.json.parseFromSlice(std.json.Value, a, out, .{})).value);
    }
    try std.json.stringify(results.items, .{}, std.io.getStdOut().writer());
}

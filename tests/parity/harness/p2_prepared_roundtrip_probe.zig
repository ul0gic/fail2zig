// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Original read/render/read probe: no sessions, filters, actions or runtime setters.
const std = @import("std");
const engine = @import("engine");
const native = engine.config_mod;
const migration = engine.migration_mod;

fn equal(allocator: std.mem.Allocator, before: anytype, after: @TypeOf(before)) !bool {
    return std.mem.eql(u8, try std.json.stringifyAlloc(allocator, before, .{}), try std.json.stringifyAlloc(allocator, after, .{}));
}
pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const args = try std.process.argsAlloc(a);
    if (args.len != 3) return error.ExpectedInputOutput;
    const before = try native.Config.loadFile(a, args[1]);
    var rendered = std.ArrayList(u8).init(a);
    try migration.renderToml(&before, rendered.writer());
    if (rendered.items.len > native.max_config_bytes) return error.FileTooLarge;
    const after = try native.Config.parse(a, rendered.items);
    const result = .{
        .manifest_equal = std.mem.eql(u8, before.global.compatibility_manifest, after.global.compatibility_manifest),
        .global_equal = try equal(a, before.global, after.global),
        .defaults_equal = try equal(a, before.defaults, after.defaults),
        .jails_equal = try equal(a, before.jails, after.jails),
        .rendered_bytes = rendered.items.len,
    };
    const output = try std.fs.cwd().createFile(args[2], .{ .mode = 0o600, .exclusive = true });
    defer output.close();
    try output.writeAll(rendered.items);
    try std.json.stringify(result, .{}, std.io.getStdOut().writer());
    if (!(result.manifest_equal and result.global_equal and result.defaults_equal and result.jails_equal)) std.process.exit(1);
}

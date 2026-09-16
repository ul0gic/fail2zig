// SPDX-License-Identifier: AGPL-3.0-or-later
const std = @import("std");
const config = @import("fail2ban.zig");
const A = std.mem.Allocator;
pub const Prepared = struct {
    asset: config.ParameterizedAsset,
    known_combined: std.StringArrayHashMapUnmanaged([]const u8),
    combined: std.StringArrayHashMapUnmanaged([]const u8),
    jail_source: config.ParsedIni,
    auto_logtype: ?[]const u8,
};
const options = [_][]const u8{ "usedns", "prefregex", "ignoreregex", "failregex", "maxlines", "datepattern", "journalmatch" };

fn definition(a: A, asset: *config.ParameterizedAsset, parameters: *const std.StringArrayHashMapUnmanaged([]const u8)) config.Error!void {
    var entries = asset.definition.iterator();
    while (entries.next()) |entry| {
        entry.value_ptr.* = parameters.get(entry.key_ptr.*) orelse (try config.resolveWithParameters(a, &asset.config, "Definition", entry.key_ptr.*, parameters)) orelse entry.value_ptr.*;
    }
}

pub fn readerDefaults(a: A, source: *const config.ParsedIni, root: []const u8) config.Error!config.ParsedIni {
    var graph = source.*;
    graph.sections = try source.sections.clone(a);
    var defaults = if (source.section("DEFAULT")) |section| section.* else config.Section{ .name = "DEFAULT" };
    defaults.keys = try defaults.keys.clone(a);
    try defaults.keys.put(a, "fail2ban_confpath", root);
    try defaults.keys.put(a, "fail2ban_version", "1.1.1");
    try graph.sections.put(a, "DEFAULT", defaults);
    return graph;
}

pub fn prepare(a: A, source: *const config.ParsedIni, root: []const u8, jail: []const u8, selector: []const u8, backend: []const u8) config.Error!Prepared {
    var asset = try config.loadParameterizedAsset(a, root, "filter.d", selector);
    var parameters = try asset.selector.parameters.clone(a);
    if (!parameters.contains("backend")) try parameters.put(a, "backend", backend);
    if (!parameters.contains("filter")) try parameters.put(a, "filter", selector);
    var automatic: ?[]const u8 = null;
    const selected_logtype = asset.selector.parameters.get("logtype");
    const has_definition_logtype = if (asset.config.section("Definition")) |section| section.keys.contains("logtype") else false;
    if ((selected_logtype == null or selected_logtype.?.len == 0) and !has_definition_logtype) {
        automatic = if (std.mem.startsWith(u8, backend, "systemd")) "journal" else "file";
        try parameters.put(a, "logtype", automatic.?);
        try asset.init.put(a, "logtype", automatic.?);
    }
    try definition(a, &asset, &parameters);
    const known = try config.combineAsset(a, &asset, "");
    var graph = try readerDefaults(a, source, root);
    const jail_section = graph.sections.getPtr(jail) orelse return error.EmptySectionName;
    jail_section.keys = try jail_section.keys.clone(a);
    var values = known.iterator();
    while (values.next()) |entry| {
        if (std.mem.startsWith(u8, entry.key_ptr.*, "known/") or std.mem.eql(u8, entry.key_ptr.*, "__name__")) continue;
        const key = try std.fmt.allocPrint(a, "known/{s}", .{entry.key_ptr.*});
        try jail_section.keys.put(a, key, entry.value_ptr.*);
    }
    for (options) |key| {
        if (try config.resolve(a, &graph, jail, key)) |value| {
            if (!asset.selector.parameters.contains(key)) try parameters.put(a, key, value);
        }
    }
    try definition(a, &asset, &parameters);
    return .{ .asset = asset, .known_combined = known, .combined = try config.combineAsset(a, &asset, ""), .jail_source = graph, .auto_logtype = automatic };
}

test "filter context separates automatic initial known and final jail substitutions" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("filter.d");
    try tmp.dir.writeFile(.{ .sub_path = "filter.d/original.conf", .data = "[Definition]\ndatepattern=TAI64N\njournalmatch=TYPE=<logtype> FORMAT=%(datepattern)s\n[Init]\nlogtype=ignored-default\n" });
    const root = try tmp.dir.realpathAlloc(a, ".");
    var source = try config.parseIniSource(a, "original-jail", "[probe]\ndatepattern=%(known/datepattern)s EPOCH\n");
    const result = try prepare(a, &source, root, "probe", "original", "systemd");
    try std.testing.expectEqualStrings("journal", result.auto_logtype.?);
    try std.testing.expectEqualStrings("TAI64N", result.known_combined.get("datepattern").?);
    try std.testing.expectEqualStrings("TAI64N EPOCH", (try config.resolve(a, &result.jail_source, "probe", "datepattern")).?);
    try std.testing.expectEqualStrings("TYPE=journal FORMAT=TAI64N EPOCH", result.combined.get("journalmatch").?);
    try std.testing.expect(source.section("probe").?.get("known/datepattern") == null);
}

test "filter context known percent values retain reference interpolation rejection" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("filter.d");
    try tmp.dir.writeFile(.{ .sub_path = "filter.d/original.conf", .data = "[Definition]\ndatepattern=%%Y\n" });
    const root = try tmp.dir.realpathAlloc(a, ".");
    var source = try config.parseIniSource(a, "original-jail", "[probe]\noriginal=%(known/datepattern)s\n");
    const result = try prepare(a, &source, root, "probe", "original", "auto");
    try std.testing.expectError(error.InterpolationUnterminated, config.resolve(a, &result.jail_source, "probe", "original"));
}

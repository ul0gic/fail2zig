// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const engine = @import("engine");
const shared = @import("shared");

test "corpus: all built-in patterns have positive coverage and each filter rejects benign fixtures" {
    const registry = engine.filter_registry_mod;
    const Fixture = struct { filter: []const u8, ip: ?[]const u8, line: []const u8 };
    const corpus = try std.json.parseFromSlice([]Fixture, std.testing.allocator, @embedFile("filter_corpus.json"), .{});
    defer corpus.deinit();
    var covered = [_][16]bool{[_]bool{false} ** 16} ** registry.registered_count;
    var negatives = [_]usize{0} ** registry.registered_count;
    for (corpus.value) |fixture| {
        const index = for (registry.entries, 0..) |entry, i| {
            if (std.mem.eql(u8, fixture.filter, entry.name)) break i;
        } else return error.UnknownFixtureFilter;
        const body = engine.parser_mod.stripSyslogPrefix(fixture.line);
        const result = registry.matcherForFilter(fixture.filter).?.match(body);
        if (fixture.ip) |expected| {
            if (result == null) {
                std.debug.print("corpus missed {s}: {s}\n", .{ fixture.filter, fixture.line });
                return error.CorpusMiss;
            }
            try std.testing.expectEqual(try shared.IpAddress.parse(expected), result.?.ip);
            for (registry.entries[index].patterns, 0..) |pattern, j| {
                if (pattern.match(body) != null) covered[index][j] = true;
            }
        } else {
            negatives[index] += 1;
            if (result != null) {
                std.debug.print("corpus false match {s}: {s}\n", .{ fixture.filter, fixture.line });
                return error.CorpusFalseMatch;
            }
        }
    }
    var missing: usize = 0;
    for (registry.entries, 0..) |entry, i| {
        try std.testing.expect(negatives[i] > 0);
        for (entry.patterns, 0..) |pattern, j| {
            if (!covered[i][j]) {
                std.debug.print("corpus lacks positive fixture: {s}/{s}\n", .{ entry.name, pattern.name });
                missing += 1;
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 0), missing);
}

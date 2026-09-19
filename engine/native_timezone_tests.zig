// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const zone = @import("core/native_timezone.zig");
const time = @import("core/native_time.zig");
const t = std.testing;
const Kind = struct { offset: i32, dst: u8 = 0, abbreviation: u8 = 0 };

fn header(out: *std.ArrayList(u8), count: usize, types: usize, chars: usize, version: u8) !void {
    var bytes = [_]u8{0} ** 44;
    @memcpy(bytes[0..4], "TZif");
    bytes[4] = version;
    std.mem.writeInt(u32, bytes[32..36], @intCast(count), .big);
    std.mem.writeInt(u32, bytes[36..40], @intCast(types), .big);
    std.mem.writeInt(u32, bytes[40..44], @intCast(chars), .big);
    try out.appendSlice(&bytes);
}

fn fixture(a: std.mem.Allocator, transitions: []const zone.Transition, kinds: []const Kind, tail: []const u8, version: u8) ![]u8 {
    var bytes = std.ArrayList(u8).init(a);
    errdefer bytes.deinit();
    try header(&bytes, 0, 1, 4, version);
    try bytes.appendSlice(&.{ 0, 0, 0, 0, 0, 0 });
    try bytes.appendSlice("UTC\x00");
    try header(&bytes, transitions.len, kinds.len, 8, version);
    for (transitions) |transition| try bytes.writer().writeInt(i64, transition.utc_seconds, .big);
    for (transitions) |transition| try bytes.append(transition.type_index);
    for (kinds) |kind| {
        try bytes.writer().writeInt(i32, kind.offset, .big);
        try bytes.append(kind.dst);
        try bytes.append(kind.abbreviation);
    }
    try bytes.appendSlice("STD\x00DST\x00");
    try bytes.append('\n');
    try bytes.appendSlice(tail);
    try bytes.append('\n');
    return bytes.toOwnedSlice();
}

fn seasonal(a: std.mem.Allocator) ![]u8 {
    return fixture(a, &.{
        .{ .utc_seconds = 1000, .type_index = 0 },
        .{ .utc_seconds = 10_000, .type_index = 1 },
        .{ .utc_seconds = 30_000, .type_index = 0 },
        .{ .utc_seconds = 50_000, .type_index = 0 },
    }, &.{ .{ .offset = 0 }, .{ .offset = 3600, .dst = 1, .abbreviation = 4 } }, "STD0DST,M3.2.0,M11.1.0", '2');
}

test "native timezone: exact transition coverage gap fold and selected provenance" {
    const bytes = try seasonal(t.allocator);
    defer t.allocator.free(bytes);
    var rejected = try zone.Zone.parse(t.allocator, "Fixture/Seasonal", bytes, .reject);
    defer rejected.deinit();
    try t.expect(rejected.tail_present);
    try t.expectEqual(@as(i32, 0), try rejected.utcOffsetAt(1000));
    try t.expectEqual(@as(i32, 3600), try rejected.utcOffsetAt(10_000));
    try t.expectError(error.OutsideTimezoneCoverage, rejected.utcOffsetAt(999));
    try t.expectError(error.OutsideTimezoneCoverage, rejected.utcOffsetAt(50_000));
    try t.expectError(error.OutsideTimezoneCoverage, rejected.resolveLocalSeconds(999));
    try t.expectEqual(@as(i64, 1000), (try rejected.resolveLocalSeconds(1000)).utc_seconds);
    try t.expectEqual(@as(i64, 9999), (try rejected.resolveLocalSeconds(9999)).utc_seconds);
    for ([_]i64{ 10_000, 11_000, 13_599 }) |local|
        try t.expectError(error.LocalTimeGap, rejected.resolveLocalSeconds(local));
    const after_gap = try rejected.resolveLocalSeconds(13_600);
    try t.expectEqual(@as(i64, 10_000), after_gap.utc_seconds);
    try t.expectEqual(@as(i32, 3600), after_gap.offset_seconds);
    for ([_]i64{ 30_000, 31_000, 33_599 }) |local|
        try t.expectError(error.AmbiguousLocalTime, rejected.resolveLocalSeconds(local));
    try t.expectEqual(@as(i64, 33_600), (try rejected.resolveLocalSeconds(33_600)).utc_seconds);
    try t.expectError(error.OutsideTimezoneCoverage, rejected.resolveLocalSeconds(50_000));
    var earlier = try zone.Zone.parse(t.allocator, "Fixture/Seasonal", bytes, .earlier);
    defer earlier.deinit();
    var later = try zone.Zone.parse(t.allocator, "Fixture/Seasonal", bytes, .later);
    defer later.deinit();
    const first = try earlier.resolveLocalSeconds(31_000);
    const second = try later.resolveLocalSeconds(31_000);
    try t.expectEqual(@as(i64, 27_400), first.utc_seconds);
    try t.expectEqual(@as(i64, 31_000), second.utc_seconds);
    try t.expect(first.fold_selected and second.fold_selected);
    try t.expectEqualDeep(first.zone_digest, second.zone_digest);
    try t.expect(!std.mem.eql(u8, &first.generation, &second.generation));
    try t.expectError(error.LocalTimeGap, earlier.resolveLocalSeconds(11_000));
}

test "native timezone: fixed zones preserve negative microseconds and reject overflow" {
    const bytes = try fixture(t.allocator, &.{}, &.{.{ .offset = 3600 }}, "STD-1", '3');
    defer t.allocator.free(bytes);
    var fixed = try zone.Zone.parse(t.allocator, "Fixture/Fixed", bytes, .reject);
    defer fixed.deinit();
    try t.expect(fixed.fixed);
    try t.expectEqual(@as(i64, -3600), (try fixed.resolveLocalSeconds(0)).utc_seconds);
    try t.expectEqual(@as(i64, -3_600_000_001), (try fixed.resolveLocalMicros(-1)).utc_us);
    try t.expectError(error.TimeOutOfRange, fixed.resolveLocalSeconds(std.math.minInt(i64)));
    try t.expectError(error.TimeOutOfRange, fixed.resolveLocalMicros(std.math.minInt(i64)));
    const seasonal_tail = try fixture(t.allocator, &.{}, &.{.{ .offset = 0 }}, "STD0DST,M3.2.0,M11.1.0", '2');
    defer t.allocator.free(seasonal_tail);
    var unknown = try zone.Zone.parse(t.allocator, "Fixture/UnknownFuture", seasonal_tail, .reject);
    defer unknown.deinit();
    try t.expect(!unknown.fixed);
    try t.expectError(error.OutsideTimezoneCoverage, unknown.resolveLocalSeconds(0));
}

test "native timezone: empty and unknown-offset zones never invent seasonal coverage" {
    const bytes = try fixture(t.allocator, &.{}, &.{.{ .offset = 0 }}, "", '2');
    defer t.allocator.free(bytes);
    var fixed = try zone.Zone.parse(t.allocator, "Fixture/UTC", bytes, .reject);
    defer fixed.deinit();
    try t.expectEqual(@as(i64, std.math.minInt(i64)), (try fixed.resolveLocalMicros(std.math.minInt(i64))).utc_us);
    var changed = try t.allocator.dupe(u8, bytes);
    defer t.allocator.free(changed);
    @memcpy(changed[104..107], "-00");
    var unspecified = try zone.Zone.parse(t.allocator, "Fixture/UTC", changed, .reject);
    defer unspecified.deinit();
    try t.expectError(error.OutsideTimezoneCoverage, unspecified.resolveLocalSeconds(0));
}

test "native timezone: every truncated prefix and invalid header is refused" {
    const bytes = try seasonal(t.allocator);
    defer t.allocator.free(bytes);
    for (0..bytes.len) |length| {
        const result = zone.Zone.parse(t.allocator, "Fixture/Zone", bytes[0..length], .reject);
        if (result) |value| {
            var unexpected = value;
            unexpected.deinit();
            return error.TruncatedTimezoneAccepted;
        } else |_| {}
    }
    for ([_]struct { offset: usize, value: u8, err: anyerror }{
        .{ .offset = 0, .value = 'X', .err = error.InvalidTimezoneHeader },
        .{ .offset = 4, .value = '4', .err = error.UnsupportedTimezoneVersion },
        .{ .offset = 5, .value = 1, .err = error.InvalidTimezoneHeader },
        .{ .offset = 31, .value = 1, .err = error.UnsupportedLeapSeconds },
        .{ .offset = 54 + 4, .value = '3', .err = error.InvalidTimezoneHeader },
        .{ .offset = 54 + 23, .value = 1, .err = error.InvalidTimezoneHeader },
    }) |case| {
        const changed = try t.allocator.dupe(u8, bytes);
        defer t.allocator.free(changed);
        changed[case.offset] = case.value;
        try t.expectError(case.err, zone.Zone.parse(t.allocator, "Fixture/Zone", changed, .reject));
    }
}

test "native timezone: limits transition order type flags and tail framing are strict" {
    const original = try seasonal(t.allocator);
    defer t.allocator.free(original);
    const changed = try t.allocator.dupe(u8, original);
    defer t.allocator.free(changed);
    std.mem.writeInt(u32, changed[54 + 32 ..][0..4], zone.max_transitions + 1, .big);
    try t.expectError(error.TimezoneLimit, zone.Zone.parse(t.allocator, "Fixture/Zone", changed, .reject));
    @memcpy(changed, original);
    std.mem.writeInt(u32, changed[54 + 36 ..][0..4], 257, .big);
    try t.expectError(error.TimezoneLimit, zone.Zone.parse(t.allocator, "Fixture/Zone", changed, .reject));
    @memcpy(changed, original);
    std.mem.writeInt(i64, changed[98 + 8 ..][0..8], 1000, .big);
    try t.expectError(error.UnorderedTimezoneTransitions, zone.Zone.parse(t.allocator, "Fixture/Zone", changed, .reject));
    for ([_]usize{ 130, 138, 139 }) |index| {
        @memcpy(changed, original);
        changed[index] = 255;
        try t.expectError(error.InvalidTimezoneType, zone.Zone.parse(t.allocator, "Fixture/Zone", changed, .reject));
    }
    @memcpy(changed, original);
    std.mem.writeInt(i32, changed[134..138], std.math.minInt(i32), .big);
    try t.expectError(error.InvalidTimezoneType, zone.Zone.parse(t.allocator, "Fixture/Zone", changed, .reject));
    @memcpy(changed, original);
    changed[changed.len - 1] = 'x';
    try t.expectError(error.InvalidTimezoneTail, zone.Zone.parse(t.allocator, "Fixture/Zone", changed, .reject));
    const single = try fixture(t.allocator, &.{.{ .utc_seconds = 100, .type_index = 0 }}, &.{.{ .offset = 0 }}, "", '2');
    defer t.allocator.free(single);
    try t.expectError(error.InsufficientTimezoneCoverage, zone.Zone.parse(t.allocator, "Fixture/Zone", single, .reject));
}

test "native timezone: maximum transition and type counts remain bounded" {
    const transitions = try t.allocator.alloc(zone.Transition, zone.max_transitions);
    defer t.allocator.free(transitions);
    for (transitions, 0..) |*transition, i| transition.* = .{ .utc_seconds = @intCast(i), .type_index = 255 };
    const kinds = [_]Kind{.{ .offset = 0 }} ** zone.max_types;
    const bytes = try fixture(t.allocator, transitions, &kinds, "", '3');
    defer t.allocator.free(bytes);
    var parsed = try zone.Zone.parse(t.allocator, "Fixture/Maximum", bytes, .reject);
    defer parsed.deinit();
    try t.expectEqual(@as(i64, zone.max_transitions - 2), (try parsed.resolveLocalSeconds(zone.max_transitions - 2)).utc_seconds);
    try t.expectError(error.OutsideTimezoneCoverage, parsed.resolveLocalSeconds(zone.max_transitions - 1));
    const oversized = try t.allocator.alloc(u8, zone.max_file_bytes + 1);
    defer t.allocator.free(oversized);
    try t.expectError(error.TimezoneLimit, zone.Zone.parse(t.allocator, "Fixture/Maximum", oversized, .reject));
    var excessive = [_]u8{0} ** 44;
    @memcpy(&excessive, bytes[0..44]);
    std.mem.writeInt(u32, excessive[40..44], zone.max_abbreviations + 1, .big);
    try t.expectError(error.TimezoneLimit, zone.Zone.parse(t.allocator, "Fixture/Maximum", &excessive, .reject));
}

fn allocationParse(allocator: std.mem.Allocator, bytes: []const u8) !void {
    var parsed = try zone.Zone.parse(allocator, "Fixture/Zone", bytes, .later);
    defer parsed.deinit();
    try t.expectEqual(@as(i64, 31_000), (try parsed.resolveLocalSeconds(31_000)).utc_seconds);
}

fn allocationLoad(allocator: std.mem.Allocator, root: []const u8) !void {
    var parsed = try zone.Zone.load(allocator, root, "Region/Zone", .later);
    defer parsed.deinit();
    try t.expectEqual(@as(i64, 31_000), (try parsed.resolveLocalSeconds(31_000)).utc_seconds);
}

test "native timezone: allocation failure releases tables and owner survives input mutation" {
    const bytes = try seasonal(t.allocator);
    defer t.allocator.free(bytes);
    try t.checkAllAllocationFailures(t.allocator, allocationParse, .{bytes});
    var parsed = try zone.Zone.parse(t.allocator, "Fixture/Zone", bytes, .later);
    defer parsed.deinit();
    const generation = parsed.generation;
    @memset(bytes, 0);
    try t.expectEqual(@as(i64, 31_000), (try parsed.resolveLocalSeconds(31_000)).utc_seconds);
    try t.expectEqualDeep(generation, parsed.generation);
}

test "native timezone: trusted root rejects traversal symlink files directories and writable data" {
    const bytes = try seasonal(t.allocator);
    defer t.allocator.free(bytes);
    var tmp = t.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.chmod(0o700);
    try tmp.dir.makeDir("Region");
    var region = try tmp.dir.openDir("Region", .{ .iterate = true });
    defer region.close();
    try region.chmod(0o700);
    var file = try tmp.dir.createFile("Region/Zone", .{ .read = true });
    defer file.close();
    try file.chmod(0o600);
    try file.writeAll(bytes);
    const root = try tmp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(root);
    var loaded = try zone.Zone.load(t.allocator, root, "Region/Zone", .later);
    defer loaded.deinit();
    try t.expectEqual(@as(i64, 31_000), (try loaded.resolveLocalSeconds(31_000)).utc_seconds);
    try t.checkAllAllocationFailures(t.allocator, allocationLoad, .{root});
    for ([_][]const u8{ "", "../Zone", "/Region/Zone", "Region//Zone", "Region/./Zone", "Region/Zone/", "Region/Zo\x00ne" }) |bad|
        try t.expectError(error.InvalidZoneIdentifier, zone.Zone.load(t.allocator, root, bad, .reject));
    try tmp.dir.symLink("Region/Zone", "Alias", .{});
    try t.expectError(error.UnsafeTimezonePath, zone.Zone.load(t.allocator, root, "Alias", .reject));
    try tmp.dir.symLink("Region", "Link", .{});
    try t.expectError(error.UnsafeTimezonePath, zone.Zone.load(t.allocator, root, "Link/Zone", .reject));
    try region.chmod(0o770);
    try t.expectError(error.UntrustedTimezoneFile, zone.Zone.load(t.allocator, root, "Region/Zone", .reject));
    try region.chmod(0o700);
    try file.chmod(0o666);
    try t.expectError(error.UntrustedTimezoneFile, zone.Zone.load(t.allocator, root, "Region/Zone", .reject));
}

fn seconds(iso: []const u8) !i64 {
    return @divFloor((try time.parse(.iso8601, iso, .{})).us, 1_000_000);
}

test "native timezone: trusted copies of installed UTC and New York resolve read only" {
    var tmp = t.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = try @import("timezone_test_fixture.zig").copyInstalled(&tmp, &.{ "Etc/UTC", "America/New_York" });
    defer t.allocator.free(root);
    var utc = zone.Zone.load(t.allocator, root, "Etc/UTC", .reject) catch |err| {
        std.debug.print("installed Etc/UTC load: {s}\n", .{@errorName(err)});
        return err;
    };
    defer utc.deinit();
    try t.expect(utc.fixed);
    try t.expectEqual(@as(i64, -1), (try utc.resolveLocalMicros(-1)).utc_us);
    var ny = zone.Zone.load(t.allocator, root, "America/New_York", .reject) catch |err| {
        std.debug.print("installed America/New_York load: {s}\n", .{@errorName(err)});
        return err;
    };
    defer ny.deinit();
    const winter = ny.resolveLocalSeconds(try seconds("2026-01-15T12:00:00Z")) catch |err| {
        std.debug.print("installed New York 2026 resolution: {s}; transitions={d}, first={d}, last={d}, tail={}\n", .{
            @errorName(err),                                                  ny.transitions.len,
            if (ny.transitions.len > 0) ny.transitions[0].utc_seconds else 0, if (ny.transitions.len > 0) ny.transitions[ny.transitions.len - 1].utc_seconds else 0,
            ny.tail_present,
        });
        return err;
    };
    try t.expectEqual(@as(i32, -18000), winter.offset_seconds);
    try t.expectEqual(try seconds("2026-01-15T17:00:00Z"), winter.utc_seconds);
    const summer = try ny.resolveLocalSeconds(try seconds("2026-07-15T12:00:00Z"));
    try t.expectEqual(@as(i32, -14400), summer.offset_seconds);
    try t.expectError(error.LocalTimeGap, ny.resolveLocalSeconds(try seconds("2026-03-08T02:30:00Z")));
    try t.expectError(error.AmbiguousLocalTime, ny.resolveLocalSeconds(try seconds("2026-11-01T01:30:00Z")));
    try t.expectError(error.OutsideTimezoneCoverage, ny.resolveLocalSeconds(try seconds("2200-01-01T00:00:00Z")));
}

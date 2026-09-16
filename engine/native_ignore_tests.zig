// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const t = std.testing;
const ignore = @import("core/native_ignore.zig");
const dns = @import("core/native_dns.zig");
const Ip = @import("shared").IpAddress;
const generation = [_]u8{7} ** 32;
const options = ignore.Options{ .parent_generation = [_]u8{8} ** 32, .resolver_generation = generation, .family = .v4 };
fn address(value: []const u8) !Ip {
    return Ip.parse(value);
}
fn cacheResult(name: []const u8, positive: bool) !dns.Result {
    var answer = dns.Answer{ .kind = if (positive) .positive else .negative, .canonical = try dns.Name.init(name), .ttl_seconds = 10 };
    if (positive) try answer.add(try address("192.0.2.80"));
    return .{ .request = .{ .name = try dns.Name.init(name), .family = .v4, .generation = generation }, .answer = answer, .completed_us = 100, .valid_until_us = 10_000_100, .deadline_ms = 4000 };
}
fn insert(cache: *dns.Cache, name: []const u8, positive: bool) !void {
    const stage = try cache.prepare(try cacheResult(name, positive), 100);
    stage.publish();
    stage.release();
}
test "native ignore: literal IPv4 IPv6 and CIDR never need resolver state" {
    const snapshot = try ignore.Snapshot.create(t.allocator, options, &.{ "192.0.2.80", "198.51.100.0/24", "2001:db8::/32", "unavailable.example" });
    defer snapshot.destroy();
    for ([_][]const u8{ "192.0.2.80", "198.51.100.19", "2001:db8:1::8" }) |value| {
        const decision = try snapshot.check(try address(value), null, 100);
        try t.expectEqual(.ignored, decision.kind);
        try t.expectEqual(.literal, decision.origin);
        try t.expectEqual(@as(u8, 0), decision.count);
        try t.expect(decision.request == null);
    }
    try t.expectEqual(.pending, (try snapshot.check(try address("203.0.113.8"), null, 100)).kind);
}
test "native ignore: self state requires complete initial snapshot and retains owned addresses" {
    var selected = options;
    selected.self_required = true;
    try t.expectError(error.SelfStateUnavailable, ignore.Snapshot.create(t.allocator, selected, &.{}));
    selected.self_ready = true;
    var ips = [_]Ip{try address("192.0.2.11")};
    selected.self_addresses = &ips;
    const snapshot = try ignore.Snapshot.create(t.allocator, selected, &.{});
    defer snapshot.destroy();
    ips[0] = try address("198.51.100.11");
    try t.expectEqual(.self, (try snapshot.check(try address("192.0.2.11"), null, 100)).origin);
    try t.expectEqual(.not_ignored, (try snapshot.check(ips[0], null, 100)).kind);
    try t.expectError(error.IgnoreSelfGenerationMismatch, ignore.Snapshot.restore(t.allocator, selected, snapshot.payload));
    selected.self_ready = false;
    try t.expectError(error.SelfStateUnavailable, ignore.Snapshot.restore(t.allocator, selected, snapshot.payload));
    selected.self_ready = true;
    ips[0] = try address("192.0.2.11");
    const restored = try ignore.Snapshot.restore(t.allocator, selected, snapshot.payload);
    defer restored.destroy();
    try t.expectEqual(.self, (try restored.check(try address("192.0.2.11"), null, 100)).origin);
}
test "native ignore: DNS matches misses negatives expiry and duplicate dependencies are explicit" {
    var cache = try dns.Cache.init(t.allocator, generation, 4);
    defer cache.deinit();
    const snapshot = try ignore.Snapshot.create(t.allocator, options, &.{ "CLIENT.example", "client.example", "negative.example" });
    defer snapshot.destroy();
    var decision = try snapshot.check(try address("192.0.2.80"), &cache, 100);
    try t.expectEqual(.pending, decision.kind);
    try t.expectEqualStrings("client.example", decision.request.?.name.slice());
    try insert(&cache, "client.example", true);
    decision = try snapshot.check(try address("192.0.2.80"), &cache, 100);
    try t.expectEqual(.ignored, decision.kind);
    try t.expectEqual(@as(u8, 1), decision.count);
    try t.expectEqual(@as(u64, 1), decision.dependencies[0].revision);
    try t.expectEqual(.pending, (try snapshot.check(try address("203.0.113.7"), &cache, 100)).kind);
    try insert(&cache, "negative.example", false);
    decision = try snapshot.check(try address("203.0.113.7"), &cache, 100);
    try t.expectEqual(.not_ignored, decision.kind);
    try t.expectEqual(@as(u8, 2), decision.count);
    try t.expectEqual(@as(i64, 10_000_100), decision.dependencies[0].valid_until_us);
    try t.expectEqual(.pending, (try snapshot.check(try address("192.0.2.80"), &cache, 10_000_100)).kind);
    try t.expectError(error.DnsClockReversed, snapshot.check(try address("192.0.2.80"), &cache, 99));
}
test "native ignore: unknown DNS and foreign generation never become proven misses" {
    var cache = try dns.Cache.init(t.allocator, generation, 1);
    defer cache.deinit();
    var result = try cacheResult("client.example", true);
    result.answer = .{ .kind = .unknown, .reason = .timeout, .canonical = result.request.name };
    try t.expectError(error.InvalidDnsCheckpoint, cache.prepare(result, 100));
    const snapshot = try ignore.Snapshot.create(t.allocator, options, &.{"client.example"});
    defer snapshot.destroy();
    try t.expectEqual(.pending, (try snapshot.check(try address("192.0.2.80"), &cache, 100)).kind);
    var wrong = try dns.Cache.init(t.allocator, [_]u8{9} ** 32, 1);
    defer wrong.deinit();
    try t.expectError(error.DnsGenerationMismatch, snapshot.check(try address("192.0.2.80"), &wrong, 100));
}
test "native ignore: reversible refresh publishes only after commit and invalid refresh retains last valid" {
    var owner = ignore.Owner{ .live = try ignore.Snapshot.fromText(t.allocator, options, "# initial\n192.0.2.80 # literal\n"), .revision = 1 };
    defer owner.deinit();
    const original = owner.live.generation;
    try t.expectError(error.InvalidIgnoreEntry, ignore.Snapshot.fromText(t.allocator, options, "192.0.2.80\nbad entry\n"));
    try t.expectEqualSlices(u8, &original, &owner.live.generation);
    var aborted = try owner.prepare(try ignore.Snapshot.create(t.allocator, options, &.{"198.51.100.80"}));
    try t.expectEqual(.ignored, (try owner.live.check(try address("192.0.2.80"), null, 100)).kind);
    aborted.release();
    try t.expectEqual(@as(u64, 1), owner.revision);
    var committed = try owner.prepare(try ignore.Snapshot.create(t.allocator, options, &.{"198.51.100.80"}));
    const checkpoint = try t.allocator.dupe(u8, committed.next.payload);
    defer t.allocator.free(checkpoint);
    committed.publish();
    committed.release();
    try t.expectEqual(@as(u64, 2), owner.revision);
    const restored = try ignore.Snapshot.restore(t.allocator, options, checkpoint);
    defer restored.destroy();
    try t.expectEqual(.ignored, (try restored.check(try address("198.51.100.80"), null, 100)).kind);
    try t.expectEqual(.not_ignored, (try restored.check(try address("192.0.2.80"), null, 100)).kind);
    try t.expectEqualSlices(u8, owner.live.payload, restored.payload);
}
test "native ignore: malformed checkpoints and foreign parent generation refuse restoration" {
    const snapshot = try ignore.Snapshot.create(t.allocator, options, &.{"198.51.100.0/24"});
    defer snapshot.destroy();
    var foreign = options;
    foreign.parent_generation[0] ^= 1;
    try t.expectError(error.IgnoreGenerationMismatch, ignore.Snapshot.restore(t.allocator, foreign, snapshot.payload));
    const corrupt = try t.allocator.dupe(u8, snapshot.payload);
    defer t.allocator.free(corrupt);
    corrupt[corrupt.len - 1] = 1;
    try t.expectError(error.InvalidIgnoreCheckpoint, ignore.Snapshot.restore(t.allocator, options, corrupt));
    for (0..snapshot.payload.len) |length| try t.expectError(error.InvalidIgnoreCheckpoint, ignore.Snapshot.restore(t.allocator, options, snapshot.payload[0..length]));
}
test "native ignore: dependency entries lines and text have explicit limits" {
    const names = [_][]const u8{"client.example"} ** 17;
    try t.expectError(error.IgnoreDependencyLimit, ignore.Snapshot.create(t.allocator, options, &names));
    const entries = [_][]const u8{"192.0.2.80"} ** 1025;
    try t.expectError(error.IgnoreLimit, ignore.Snapshot.create(t.allocator, options, &entries));
    try t.expectError(error.IgnoreLimit, ignore.Snapshot.fromText(t.allocator, options, &([_]u8{'x'} ** 1025)));
    try t.expectError(error.InvalidIgnoreEntry, ignore.Snapshot.create(t.allocator, options, &.{"192.0.2.1/33"}));
}
fn allocation(a: std.mem.Allocator) !void {
    const snapshot = try ignore.Snapshot.fromText(a, options, "192.0.2.0/24\nclient.example\n2001:db8::/32\n");
    defer snapshot.destroy();
    const restored = try ignore.Snapshot.restore(a, options, snapshot.payload);
    defer restored.destroy();
}
test "native ignore: all snapshot allocation and restoration failures preserve ownership" {
    try t.checkAllAllocationFailures(t.allocator, allocation, .{});
}
test "native ignore: file refresh rejects unsafe regular file and symlink while keeping owner" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var file = try tmp.dir.createFile("allow", .{ .mode = 0o600 });
    try file.writeAll("192.0.2.80\n");
    file.close();
    const path = try tmp.dir.realpathAlloc(t.allocator, "allow");
    defer t.allocator.free(path);
    var owner = ignore.Owner{ .live = try ignore.Snapshot.fromFile(t.allocator, options, path), .revision = 1 };
    defer owner.deinit();
    file = try tmp.dir.openFile("allow", .{ .mode = .read_write });
    try file.chmod(0o666);
    file.close();
    try t.expectError(error.UntrustedIgnoreFile, ignore.Snapshot.fromFile(t.allocator, options, path));
    try t.expectEqual(.ignored, (try owner.live.check(try address("192.0.2.80"), null, 100)).kind);
    try tmp.dir.symLink("allow", "alias", .{});
    const directory = try tmp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(directory);
    const alias = try std.fs.path.join(t.allocator, &.{ directory, "alias" });
    defer t.allocator.free(alias);
    try t.expectError(error.SymLinkLoop, ignore.Snapshot.fromFile(t.allocator, options, alias));
}

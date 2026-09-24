// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const mem = std.mem;
const shared = @import("shared");
const source = @import("engine_test").firewall.inspection;
const access = source.TestAccess;
const canonical_scope = source.canonical_scope;
const CanonicalScope = source.CanonicalScope;
const Scope = source.Scope;
const Transport = source.Transport;
const Installation = source.Installation;
const ScopedRuleMetadata = source.ScopedRuleMetadata;
const scoped_comment_bytes = source.scoped_comment_bytes;
const Entry = source.Entry;
const EffectOperation = source.EffectOperation;
const validateCanonicalScope = source.validateCanonicalScope;
const canonicalizeLegacyScope = source.canonicalizeLegacyScope;
const buildFixedScopedArgv = access.buildFixedScopedArgv;
const parseIptables = access.parseIptables;
const parseIpset = access.parseIpset;
const deadlineUnits = access.deadlineUnits;
const effectMatches = access.effectMatches;
const scanSavedTables = access.scanSavedTables;
const entryLess = access.entryLess;
const sameEntries = access.sameEntries;
const entryScope = access.entryScope;

test "native firewall: typed projection refuses scope widening" {
    const address = try shared.IpAddress.parse("192.0.2.3");
    try (Scope{ .address = address, .prefix = 32 }).validate();
    try std.testing.expectError(error.UnsupportedScope, (Scope{ .address = address, .prefix = 24 }).validate());
    try std.testing.expectError(error.UnsupportedScope, (Scope{ .address = address, .prefix = 32, .protocol = .tcp }).validate());
}

test "native firewall: every transport shares the frozen N3 validation gate" {
    const selected = CanonicalScope{
        .subject = try canonical_scope.Subject.parseNetwork("2001:db8::/64"),
        .protocols = try canonical_scope.Protocols.list(&.{ .tcp, .udp }),
        .ports = try canonical_scope.Ports.list(&.{canonical_scope.PortRange.one(443)}),
    };
    for ([_]Transport{ .nftables, .ipset, .iptables }) |transport| try validateCanonicalScope(transport, selected);

    var unsupported = selected;
    unsupported.topology.hook = .forward;
    for ([_]Transport{ .nftables, .ipset, .iptables }) |transport|
        try std.testing.expectError(error.UnsupportedScope, validateCanonicalScope(transport, unsupported));

    const address = try shared.IpAddress.parse("192.0.2.7");
    const legacy = try canonicalizeLegacyScope(.{ .address = address, .prefix = 32 });
    try std.testing.expect(legacy.subject.kind == .host);
    try std.testing.expect(legacy.protocols.isAll());
    try std.testing.expect(legacy.ports.isAll());
}

test "native firewall: fixed scoped argv comment and readback are canonical" {
    const scope = CanonicalScope{
        .subject = try canonical_scope.Subject.parseNetwork("198.51.100.0/24"),
        .protocols = try canonical_scope.Protocols.one(.udp),
        .ports = try canonical_scope.Ports.list(&.{ canonical_scope.PortRange.one(35271), .{ .first = 35280, .last = 35282 } }),
    };
    var output = std.ArrayList(u8).init(std.testing.allocator);
    defer output.deinit();
    try output.appendSlice(policies ++ test_chain);
    for (0..2) |part| {
        const metadata = ScopedRuleMetadata{
            .effect_id = [_]u8{0x6e} ** 32,
            .part = @intCast(part),
            .count = 2,
            .deadline_us = 9_000_000,
            .scope = scope,
        };
        const comment = try metadata.encodeComment();
        try std.testing.expectEqualDeep(metadata, try ScopedRuleMetadata.decodeComment(&comment));
        var argv: [24][]const u8 = undefined;
        var subject_buf: [64]u8 = undefined;
        var port_buf: [16]u8 = undefined;
        var comment_buf: [scoped_comment_bytes]u8 = undefined;
        const command_argv = try buildFixedScopedArgv(&argv, &subject_buf, &port_buf, &comment_buf, "/usr/sbin/iptables", test_name, metadata, .insert);
        try std.testing.expectEqualStrings("/usr/sbin/iptables", command_argv[0]);
        try std.testing.expectEqualStrings("-I", command_argv[3]);
        try std.testing.expectEqualStrings("198.51.100.0/24", command_argv[7]);
        try std.testing.expectEqualStrings(if (part == 0) "35271" else "35280:35282", command_argv[13]);
        try output.writer().print("-A {s} -s 198.51.100.0/24 -p udp -m udp --dport {s} -m comment --comment \"{s}\" -j DROP\n", .{ test_name, if (part == 0) "35271" else "35280:35282", &comment });
    }
    try output.appendSlice(test_end);
    var builder = access.builderInit(std.testing.allocator, test_id, .{});
    defer access.builderDeinit(&builder);
    try std.testing.expect(try parseIptables(&builder, output.items, false));
    try std.testing.expectEqual(@as(usize, 1), builder.entries.items.len);
    try std.testing.expectEqualDeep(scope, builder.entries.items[0].scope.?);
    try std.testing.expectEqual(@as(?i64, 9_000_000), builder.entries.items[0].deadline_us);
    try std.testing.expectEqualSlices(u8, &([_]u8{0x6e} ** 32), &builder.entries.items[0].effect_id.?);

    var malformed = try (ScopedRuleMetadata{ .effect_id = [_]u8{0x6e} ** 32, .part = 0, .count = 2, .deadline_us = 9_000_000, .scope = scope }).encodeComment();
    malformed[malformed.len - 1] = if (malformed[malformed.len - 1] == 'A') 'B' else 'A';
    try std.testing.expectError(error.UnknownState, ScopedRuleMetadata.decodeComment(&malformed));
}

const test_id = Installation{ .id = [_]u8{0x31} ** 16, .transport = .iptables };
const test_name = "f2z_313131313131313131313131";
const test_marker = "fail2zig:v1:31313131313131313131313131313131";
const policies = "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n";
const test_chain = "-N " ++ test_name ++ "\n-A INPUT -m comment --comment \"" ++ test_marker ++ "\" -j " ++ test_name ++ "\n";
const test_end = "-A " ++ test_name ++ " -m comment --comment \"" ++ test_marker ++ "\" -j RETURN\n";

test "native firewall: complete iptables read distinguishes owned empty and absent" {
    var b = access.builderInit(std.testing.allocator, test_id, .{});
    defer access.builderDeinit(&b);
    try std.testing.expect(!try parseIptables(&b, policies, false));
    try std.testing.expect(try parseIptables(&b, policies ++ test_chain ++ test_end, false));
    try std.testing.expectEqual(@as(usize, 0), b.entries.items.len);
    try std.testing.expectError(error.Incomplete, parseIptables(&b, "", false));
    try std.testing.expectError(error.Incomplete, parseIptables(&b, "-P INPUT ACCEPT\n", false));
}
test "native firewall: foreign, widened and bypassed iptables topology refuses" {
    var b = access.builderInit(std.testing.allocator, test_id, .{});
    defer access.builderDeinit(&b);
    try std.testing.expectError(error.ForeignState, parseIptables(&b, policies ++ test_chain, false));
    try std.testing.expectError(error.ForeignState, parseIptables(&b, policies ++ test_chain ++ test_end ++ "-A " ++ test_name ++ " -s 192.0.2.1/32 -j DROP\n", false));
    try std.testing.expectError(error.UnsupportedScope, parseIptables(&b, policies ++ test_chain ++ "-A " ++ test_name ++ " -s 192.0.2.0/24 -j DROP\n" ++ test_end, false));
    try std.testing.expectError(error.ForeignState, parseIptables(&b, policies ++ "-A INPUT -j ACCEPT\n" ++ test_chain ++ test_end, false));
}
fn allocationFixture(allocator: mem.Allocator) !void {
    var b = access.builderInit(allocator, test_id, .{});
    defer access.builderDeinit(&b);
    _ = try parseIptables(&b, policies ++ test_chain ++ "-A " ++ test_name ++ " -s 192.0.2.1/32 -j DROP\n" ++ test_end, false);
    _ = try parseIptables(&b, policies ++ test_chain ++ "-A " ++ test_name ++ " -s 2001:db8::1/128 -j DROP\n" ++ test_end, true);
    b.present = true;
    var snapshot = try access.builderFinish(&b, 0, 1);
    defer snapshot.deinit();
    try std.testing.expectEqual(@as(usize, 2), snapshot.entries.len);
    try std.testing.expectEqual(@as(usize, 0), (try snapshot.page(2)).len);
    try std.testing.expectError(error.Incomplete, snapshot.page(3));
}
test "native firewall: dual-family snapshots release all failing allocations" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationFixture, .{});
}
test "native firewall: duplicate and entry budget failures cannot return complete" {
    var b = access.builderInit(std.testing.allocator, test_id, .{ .max_entries = 1 });
    defer access.builderDeinit(&b);
    const entry = Entry{ .address = try shared.IpAddress.parse("192.0.2.1") };
    try access.builderAdd(&b, entry);
    try std.testing.expectError(error.LimitExceeded, access.builderAdd(&b, entry));
    b.limits.max_entries = 2;
    try access.builderAdd(&b, entry);
    try std.testing.expectError(error.UnknownState, access.builderFinish(&b, 0, 1));
}
test "native firewall: ipset strict member and finite timeout parsing" {
    var id = test_id;
    id.transport = .ipset;
    var b = access.builderInit(std.testing.allocator, id, .{});
    defer access.builderDeinit(&b);
    const create = "create " ++ test_name ++ "_4 hash:ip family inet hashsize 1024 maxelem 65536 timeout 0\n";
    try std.testing.expect(try parseIpset(&b, create ++ "add " ++ test_name ++ "_4 192.0.2.1 timeout 19\n", false));
    try std.testing.expectEqual(@as(?u64, 19_000), b.entries.items[0].remaining_ms);
    try std.testing.expectError(error.UnknownState, parseIpset(&b, create ++ "add " ++ test_name ++ "_4 malformed\n", false));
    try std.testing.expectError(error.ForeignState, parseIpset(&b, "create " ++ test_name ++ "_4 hash:net family inet timeout 0\n", false));
    try std.testing.expectError(error.UnknownState, parseIpset(&b, create ++ "add " ++ test_name ++ "_4 192.0.2.1 timeout 18446744073709551615\n", false));
}
test "native firewall: tokenizer never evaluates or silently truncates syntax" {
    try std.testing.expectError(error.Incomplete, access.tokensParse("-A chain --comment \"unterminated"));
    try std.testing.expectError(error.UnknownState, access.tokensParse("-A chain --comment a\\b"));
    try std.testing.expectError(error.UnknownState, access.tokensParse("-A chain --comment \"one\"two"));
    const t = try access.tokensParse("-A chain --comment \"$(literal)\"");
    try std.testing.expectEqualStrings("$(literal)", t.values[3]);
}
test "native firewall: attribute duplicate unknown and length bounds" {
    var bytes: [16]u8 = @splat(0);
    mem.writeInt(u16, bytes[0..2], 8, @import("builtin").cpu.arch.endian());
    mem.writeInt(u16, bytes[2..4], 1, @import("builtin").cpu.arch.endian());
    @memcpy(bytes[8..16], bytes[0..8]);
    try std.testing.expectError(error.UnknownState, access.attrMapParse(&bytes, &.{1}));
    try std.testing.expectError(error.UnknownState, access.attrMapParse(bytes[0..8], &.{2}));
    try std.testing.expectError(error.Incomplete, access.attrMapParse(bytes[0..7], &.{1}));
}

test "native firewall: original deadline quantization and finite verification reject widening" {
    const finite = EffectOperation{ .ensure_present = .{ .finite_deadline_us = 2_100_001 } };
    try std.testing.expectEqual(@as(u64, 1101), try deadlineUnits(finite, .nftables, 1_000_000));
    try std.testing.expectEqual(@as(u64, 2), try deadlineUnits(finite, .ipset, 1_000_000));
    try std.testing.expectEqual(@as(u64, 1), try deadlineUnits(finite, .ipset, 2_100_000));
    try std.testing.expectError(error.ExpiredIntent, deadlineUnits(finite, .iptables, 2_100_001));
    const max = EffectOperation{ .ensure_present = .{ .finite_deadline_us = 2_147_483_000_001 } };
    try std.testing.expectEqual(@as(u64, 2_147_483), try deadlineUnits(max, .ipset, 1));
    try std.testing.expectError(error.UnsupportedDeadline, deadlineUnits(max, .ipset, 0));
    const address = try shared.IpAddress.parse("192.0.2.7");
    try std.testing.expect(!effectMatches(finite, .nftables, .{ .address = address, .remaining_ms = null }, 1_000_000, 1_000_100));
    try std.testing.expect(!effectMatches(finite, .nftables, .{ .address = address, .remaining_ms = 30_000 }, 1_000_000, 1_000_100));
    try std.testing.expect(!effectMatches(finite, .ipset, .{ .address = address, .remaining_ms = 30_000 }, 1_000_000, 1_000_100));
    try std.testing.expect(!effectMatches(finite, .ipset, .{ .address = address, .remaining_ms = std.math.maxInt(u64) / 1000 }, 1_000_000, 1_000_100));
}
test "native firewall: reserved inventory refuses incomplete framing and all legacy prefixes" {
    try scanSavedTables("# comment\n*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n");
    try std.testing.expectError(error.Incomplete, scanSavedTables("*filter\n:INPUT ACCEPT [0:0]\n"));
    try std.testing.expectError(error.Incomplete, scanSavedTables("COMMIT\n"));
    try std.testing.expectError(error.ForeignState, scanSavedTables("*mangle\n:FAIL2ZIG-old - [0:0]\nCOMMIT\n"));
    try std.testing.expectError(error.ForeignState, scanSavedTables("*filter\n:f2z_lost - [0:0]\nCOMMIT\n"));
}

test "native firewall: readback comparison accepts only scheduled kernel expiry" {
    const t = std.testing;
    const window = 2 * std.time.ns_per_ms;
    const expiring = Entry{ .address = try shared.IpAddress.parse("192.0.2.1"), .remaining_ms = 5 };
    const lasting = Entry{ .address = try shared.IpAddress.parse("192.0.2.2"), .remaining_ms = 60_000 };
    const permanent = Entry{ .address = try shared.IpAddress.parse("192.0.2.3") };
    const newcomer = Entry{ .address = try shared.IpAddress.parse("192.0.2.4"), .remaining_ms = 60_000 };
    var before = [_]Entry{ expiring, lasting, permanent };
    mem.sort(Entry, &before, {}, entryLess);
    try t.expect(sameEntries(&before, &before, null, window, .nftables));
    var expired = [_]Entry{ lasting, permanent };
    mem.sort(Entry, &expired, {}, entryLess);
    try t.expect(sameEntries(&before, &expired, null, window, .nftables));
    var removed = [_]Entry{ expiring, permanent };
    mem.sort(Entry, &removed, {}, entryLess);
    try t.expect(!sameEntries(&before, &removed, null, window, .nftables));
    var no_timeout_gone = [_]Entry{ expiring, lasting };
    mem.sort(Entry, &no_timeout_gone, {}, entryLess);
    try t.expect(!sameEntries(&before, &no_timeout_gone, null, window, .nftables));
    var added = [_]Entry{ expiring, lasting, permanent, newcomer };
    mem.sort(Entry, &added, {}, entryLess);
    try t.expect(!sameEntries(&before, &added, null, window, .nftables));
    var extended = before;
    for (&extended) |*entry| {
        if (entry.remaining_ms != null and entry.remaining_ms.? == 60_000) entry.remaining_ms = 60_001;
    }
    try t.expect(!sameEntries(&before, &extended, null, window, .nftables));
    var rebound = before;
    for (&rebound) |*entry| {
        if (entry.remaining_ms == null) entry.effect_id = [_]u8{0x42} ** 32;
    }
    try t.expect(!sameEntries(&before, &rebound, null, window, .nftables));
    try t.expect(sameEntries(&before, &added, entryScope(newcomer), window, .nftables));
    try t.expect(sameEntries(&before, &removed, entryScope(lasting), window, .nftables));

    const whole_second = [_]Entry{.{ .address = try shared.IpAddress.parse("192.0.2.5"), .remaining_ms = 1000 }};
    const two_seconds = [_]Entry{.{ .address = try shared.IpAddress.parse("192.0.2.6"), .remaining_ms = 2000 }};
    try t.expect(sameEntries(&whole_second, &.{}, null, window, .ipset));
    try t.expect(!sameEntries(&whole_second, &.{}, null, window, .nftables));
    try t.expect(!sameEntries(&two_seconds, &.{}, null, window, .ipset));
}

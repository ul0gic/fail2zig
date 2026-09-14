// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
test "native firewall: module registration" {
    _ = @import("firewall/inspection.zig");
}

const std = @import("std");
const inspection = @import("firewall/inspection.zig");
const nft = @import("firewall/nftables.zig");
const nl = @import("firewall/netlink.zig");
const command = @import("firewall/command.zig");
const linux = std.os.linux;

test "native firewall: isolated kernel complete empty and owned dual-family readback" {
    const transport = try isolatedTransport();
    var reader = try inspection.Inspector.open(std.testing.allocator, .{ .id = [_]u8{0x31} ** 16, .transport = transport }, .{});
    defer reader.close();
    if (std.posix.getenv("F2Z_NATIVE_IPSET_PATH")) |path| reader.ipset_path = path;
    var snapshot = try reader.inspect();
    defer snapshot.deinit();
    try std.testing.expectEqual(.absent, snapshot.state);
    try std.testing.expectEqual(@as(usize, 0), snapshot.entries.len);
    var name_buf: [28]u8 = undefined;
    var marker_buf: [44]u8 = undefined;
    const name = reader.installation.name(&name_buf);
    const marker = reader.installation.marker(&marker_buf);
    try fixtureForeign(&reader);
    const foreign_before = try captureForeign(&reader);
    defer foreign_before.deinit(std.testing.allocator);
    switch (transport) {
        .nftables => try fixtureNft(name, marker),
        .iptables, .ipset => try fixtureTools(&reader, name, marker),
    }
    var owned = try reader.inspect();
    defer owned.deinit();
    try std.testing.expectEqual(.owned, owned.state);
    try std.testing.expectEqual(@as(usize, 2), owned.entries.len);
    try std.testing.expectEqual(@as(u32, 0xc0000207), owned.entries[0].address.ipv4);
    try std.testing.expectEqual(.ipv6, std.meta.activeTag(owned.entries[1].address));
    if (transport != .iptables) {
        try std.testing.expect(owned.entries[1].remaining_ms.? > 0);
        try std.testing.expect(owned.entries[1].remaining_ms.? <= 30_000);
        try std.testing.expect(owned.entries[0].remaining_ms == null);
    }
    var reopened = try inspection.Inspector.open(std.testing.allocator, reader.installation, .{});
    reopened.ipset_path = reader.ipset_path;
    defer reopened.close();
    var restart = try reopened.inspect();
    defer restart.deinit();
    try std.testing.expectEqualSlices(u8, &owned.fingerprint, &restart.fingerprint);
    var collision_id = reader.installation;
    collision_id.id[15] = 0x42;
    var collision = try inspection.Inspector.open(std.testing.allocator, collision_id, .{});
    collision.ipset_path = reader.ipset_path;
    defer collision.close();
    try std.testing.expectError(error.ForeignState, collision.inspect());
    if (transport == .nftables) try fixtureCommand(&.{ "/usr/sbin/nft", "list", "table", "inet", name });
    if (transport == .ipset) try fixtureCommand(&.{ reader.ipset_path, "save" });
    if (transport == .iptables) try fixtureCommand(&.{ reader.iptables_path, "-S" });
    if (transport == .nftables) try fixtureCommand(&.{ "/usr/sbin/nft", "add", "chain", "inet", name, "unexpected" }) else try fixtureCommand(&.{ reader.iptables_path, "-I", name, "-p", "tcp", "--dport", "22", "-j", "DROP" });
    try std.testing.expectError(error.ForeignState, reader.inspect());
    const foreign_after = try captureForeign(&reader);
    defer foreign_after.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, foreign_before.stdout, foreign_after.stdout);
}

fn isolatedTransport() !inspection.Transport {
    const selected = std.posix.getenv("F2Z_NATIVE_FIREWALL_TRANSPORT") orelse return error.SkipZigTest;
    // This opt-in fixture must be launched in a separate network namespace.
    var current_buf: [std.fs.max_path_bytes]u8 = undefined;
    var init_buf: [std.fs.max_path_bytes]u8 = undefined;
    const current = try std.fs.readLinkAbsolute("/proc/self/ns/net", &current_buf);
    const initial = std.posix.getenv("F2Z_NATIVE_PARENT_NETNS") orelse try std.fs.readLinkAbsolute("/proc/1/ns/net", &init_buf);
    try std.testing.expect(!std.mem.eql(u8, current, initial));
    // Every kernel case receives a fresh namespace, independent of test order.
    if (linux.E.init(linux.unshare(linux.CLONE.NEWNET)) != .SUCCESS) return error.IsolationFailed;
    return std.meta.stringToEnum(inspection.Transport, selected) orelse error.InvalidFixture;
}

fn fixtureForeign(reader: *inspection.Inspector) !void {
    switch (reader.installation.transport) {
        .nftables => {
            try fixtureCommand(&.{ "/usr/sbin/nft", "add", "table", "inet", "f2z_fixture_foreign" });
            try fixtureCommand(&.{ "/usr/sbin/nft", "add", "chain", "inet", "f2z_fixture_foreign", "sentinel" });
        },
        .iptables => try fixtureCommand(&.{ reader.iptables_path, "-N", "f2z_fixture_foreign" }),
        .ipset => try fixtureCommand(&.{ reader.ipset_path, "create", "f2z_fixture_foreign", "hash:net" }),
    }
}
fn captureForeign(reader: *inspection.Inspector) !command.Result {
    const result = try command.run(std.testing.allocator, switch (reader.installation.transport) {
        .nftables => &.{ "/usr/sbin/nft", "list", "table", "inet", "f2z_fixture_foreign" },
        .iptables => &.{ reader.iptables_path, "-S", "f2z_fixture_foreign" },
        .ipset => &.{ reader.ipset_path, "save", "f2z_fixture_foreign" },
    }, 2000);
    errdefer result.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u8, 0), result.code);
    return result;
}

fn fixtureCommand(argv: []const []const u8) !void {
    const result = try command.run(std.testing.allocator, argv, 2000);
    defer result.deinit(std.testing.allocator);
    if (result.code != 0) {
        std.debug.print("fixture command failed: {s}\n", .{result.stderr});
        return error.FixtureCommandFailed;
    }
}
fn fixtureTools(reader: *inspection.Inspector, name: []const u8, marker: []const u8) !void {
    for ([_][]const u8{ reader.iptables_path, reader.ip6tables_path }, 0..) |binary, index| {
        try fixtureCommand(&.{ binary, "-N", name });
        if (reader.installation.transport == .ipset) {
            var set_buf: [31]u8 = undefined;
            const set = try std.fmt.bufPrint(&set_buf, "{s}_{s}", .{ name, if (index == 0) "4" else "6" });
            try fixtureCommand(&.{ reader.ipset_path, "create", set, "hash:ip", "family", if (index == 0) "inet" else "inet6", "timeout", "0" });
            try fixtureCommand(&.{ reader.ipset_path, "add", set, if (index == 0) "192.0.2.7" else "2001:db8::7", "timeout", if (index == 0) "0" else "30" });
            try fixtureCommand(&.{ binary, "-A", name, "-m", "set", "--match-set", set, "src", "-j", "DROP" });
        } else try fixtureCommand(&.{ binary, "-A", name, "-s", if (index == 0) "192.0.2.7" else "2001:db8::7", "-j", "DROP" });
        try fixtureCommand(&.{ binary, "-A", name, "-m", "comment", "--comment", marker, "-j", "RETURN" });
        try fixtureCommand(&.{ binary, "-I", "INPUT", "-m", "comment", "--comment", marker, "-j", name });
    }
}
fn fixtureNft(name: []const u8, marker: []const u8) !void {
    var sock = try nl.NetlinkSocket.init(linux.NETLINK.NETFILTER);
    defer sock.close();
    try sock.setRecvTimeout(2000);
    var payloads: [8][1024]u8 align(4) = undefined;
    const data = [_][]const u8{
        try nft.buildOwnedTablePayload(&payloads[0], name, marker),
        try nft.buildSetPayload(&payloads[1], nl.NFPROTO.INET, name, "banned_ipv4", 1, nft.NFT_TYPE.IPV4_ADDR, 4, 0),
        try nft.buildSetPayload(&payloads[2], nl.NFPROTO.INET, name, "banned_ipv6", 2, nft.NFT_TYPE.IPV6_ADDR, 16, 0),
        try nft.buildChainPayload(&payloads[3], nl.NFPROTO.INET, name, "input", 1, -1, "filter", 1),
        try nft.buildDropRulePayload(&payloads[4], nl.NFPROTO.INET, name, "input", "banned_ipv4", nl.NFPROTO.IPV4, 12, 4),
        try nft.buildDropRulePayload(&payloads[5], nl.NFPROTO.INET, name, "input", "banned_ipv6", nl.NFPROTO.IPV6, 8, 16),
        try nft.buildSetElemAddPayload(&payloads[6], nl.NFPROTO.INET, name, "banned_ipv4", &.{ 192, 0, 2, 7 }, 0),
        try nft.buildSetElemAddPayload(&payloads[7], nl.NFPROTO.INET, name, "banned_ipv6", &.{ 0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7 }, 30_000),
    };
    var batch_buf: [8192]u8 align(4) = undefined;
    var batch = nl.Batch.init(&batch_buf);
    try batch.begin(sock.nextSeq(), sock.port_id, nl.NFNL.SUBSYS_NFTABLES);
    var sequences: [8]u32 = undefined;
    const kinds = [_]u16{ nft.NFT_MSG.NEWTABLE, nft.NFT_MSG.NEWSET, nft.NFT_MSG.NEWSET, nft.NFT_MSG.NEWCHAIN, nft.NFT_MSG.NEWRULE, nft.NFT_MSG.NEWRULE, nft.NFT_MSG.NEWSETELEM, nft.NFT_MSG.NEWSETELEM };
    for (data, kinds, 0..) |payload, kind, index| {
        sequences[index] = sock.nextSeq();
        try batch.add(nl.nfnlMsgType(nl.NFNL.SUBSYS_NFTABLES, kind), linux.NLM_F_REQUEST | linux.NLM_F_ACK | linux.NLM_F_CREATE | linux.NLM_F_EXCL, sequences[index], sock.port_id, payload);
    }
    try sock.send(try batch.commit(sock.nextSeq(), sock.port_id, nl.NFNL.SUBSYS_NFTABLES));
    var ack: [8192]u8 align(4) = undefined;
    try sock.drainAck(&sequences, &ack);
}

fn admissionReader(transport: inspection.Transport) !inspection.Inspector {
    var reader = try inspection.Inspector.open(std.testing.allocator, .{ .id = [_]u8{0x51} ** 16, .transport = transport }, .{});
    if (std.posix.getenv("F2Z_NATIVE_IPSET_PATH")) |path| reader.ipset_path = path;
    return reader;
}
fn intentFor(reader: *const inspection.Inspector) inspection.DurableInstallationIntent {
    return .{ .installation = reader.installation, .intent_id = [_]u8{0x61} ** 32, .revision = 1 };
}
fn fixtureMembers(reader: *inspection.Inspector, finite: bool) !void {
    var name_buf: [28]u8 = undefined;
    const name = reader.installation.name(&name_buf);
    if (reader.installation.transport == .nftables) {
        try fixtureCommand(&.{ "/usr/sbin/nft", "add", "element", "inet", name, "banned_ipv4", "{", "192.0.2.7", "}" });
        if (finite) try fixtureCommand(&.{ "/usr/sbin/nft", "add", "element", "inet", name, "banned_ipv6", "{", "2001:db8::7", "timeout", "30s", "}" }) else try fixtureCommand(&.{ "/usr/sbin/nft", "add", "element", "inet", name, "banned_ipv6", "{", "2001:db8::7", "}" });
        return;
    }
    for ([_][]const u8{ reader.iptables_path, reader.ip6tables_path }, 0..) |binary, index| {
        const address = if (index == 0) "192.0.2.7" else "2001:db8::7";
        if (reader.installation.transport == .iptables) try fixtureCommand(&.{ binary, "-I", name, "1", "-s", address, "-j", "DROP" }) else {
            var buf: [31]u8 = undefined;
            const set = try std.fmt.bufPrint(&buf, "{s}_{s}", .{ name, if (index == 0) "4" else "6" });
            try fixtureCommand(&.{ reader.ipset_path, "add", set, address, "timeout", if (finite and index == 1) "30" else "0" });
        }
    }
}
fn captureScaffold(reader: *inspection.Inspector) ![]u8 {
    var text = std.ArrayList(u8).init(std.testing.allocator);
    errdefer text.deinit();
    if (reader.installation.transport == .nftables) {
        const result = try command.run(std.testing.allocator, &.{ "/usr/sbin/nft", "-nn", "list", "ruleset" }, 2000);
        defer result.deinit(std.testing.allocator);
        try std.testing.expectEqual(@as(u8, 0), result.code);
        try text.appendSlice(result.stdout);
    } else {
        for ([_][]const u8{ reader.iptables_path, reader.ip6tables_path }) |binary| {
            const result = try command.run(std.testing.allocator, &.{ binary, "-S" }, 2000);
            defer result.deinit(std.testing.allocator);
            try std.testing.expectEqual(@as(u8, 0), result.code);
            try text.appendSlice(result.stdout);
        }
        if (reader.installation.transport == .ipset) {
            const result = try command.run(std.testing.allocator, &.{ reader.ipset_path, "save" }, 2000);
            defer result.deinit(std.testing.allocator);
            try std.testing.expectEqual(@as(u8, 0), result.code);
            try text.appendSlice(result.stdout);
        }
    }
    return text.toOwnedSlice();
}
fn expectAdmissionRefused(reader: *inspection.Inspector) !void {
    if (reader.admitInstallation(intentFor(reader))) |value| {
        var result = value;
        defer result.deinit();
        return error.UnexpectedAdmission;
    } else |err| switch (err) {
        error.ForeignState, error.Incomplete, error.UnknownState => {},
        else => return err,
    }
}

test "native firewall: isolated admission creates both families and preserves owned restart" {
    const transport = try isolatedTransport();
    var reader = try admissionReader(transport);
    defer reader.close();
    try fixtureForeign(&reader);
    const foreign_before = try captureForeign(&reader);
    defer foreign_before.deinit(std.testing.allocator);
    var created = try reader.admitInstallation(intentFor(&reader));
    defer created.deinit();
    try std.testing.expect(created == .installed);
    try std.testing.expect(created.installed.created);
    try std.testing.expectEqual(.owned, created.installed.snapshot.state);
    try std.testing.expectEqual(@as(usize, 0), created.installed.snapshot.entries.len);
    try fixtureMembers(&reader, true);
    var before = try reader.inspect();
    defer before.deinit();
    var reopened = try admissionReader(transport);
    defer reopened.close();
    var admitted = try reopened.admitInstallation(intentFor(&reopened));
    defer admitted.deinit();
    try std.testing.expect(admitted == .installed);
    try std.testing.expect(!admitted.installed.created);
    const after = &admitted.installed.snapshot;
    try std.testing.expectEqualSlices(u8, &before.fingerprint, &after.fingerprint);
    try std.testing.expectEqual(@as(usize, 2), after.entries.len);
    if (transport != .iptables) try std.testing.expect(after.entries[1].remaining_ms.? <= before.entries[1].remaining_ms.?);
    var collision = try admissionReader(transport);
    defer collision.close();
    collision.installation.id[15] = 0x72;
    try expectAdmissionRefused(&collision);
    const foreign_after = try captureForeign(&reader);
    defer foreign_after.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, foreign_before.stdout, foreign_after.stdout);
}

test "native firewall: isolated admission never adopts unmarked partial objects" {
    const transport = try isolatedTransport();
    var reader = try admissionReader(transport);
    defer reader.close();
    var name_buf: [28]u8 = undefined;
    const name = reader.installation.name(&name_buf);
    switch (transport) {
        .nftables => try fixtureCommand(&.{ "/usr/sbin/nft", "add", "table", "inet", name }),
        .iptables => try fixtureCommand(&.{ reader.iptables_path, "-N", name }),
        .ipset => {
            var buf: [31]u8 = undefined;
            const set = try std.fmt.bufPrint(&buf, "{s}_4", .{name});
            try fixtureCommand(&.{ reader.ipset_path, "create", set, "hash:ip", "family", "inet", "timeout", "0" });
        },
    }
    const before = try captureScaffold(&reader);
    defer std.testing.allocator.free(before);
    try expectAdmissionRefused(&reader);
    const after = try captureScaffold(&reader);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
}

test "native firewall: isolated admission refuses known-owned incomplete scaffolds without cleanup" {
    const transport = try isolatedTransport();
    var reader = try admissionReader(transport);
    defer reader.close();
    var result = try reader.admitInstallation(intentFor(&reader));
    defer result.deinit();
    try std.testing.expect(result == .installed);
    try fixtureMembers(&reader, false);
    var name_buf: [28]u8 = undefined;
    var marker_buf: [44]u8 = undefined;
    const name = reader.installation.name(&name_buf);
    const marker = reader.installation.marker(&marker_buf);
    if (transport == .nftables) try fixtureCommand(&.{ "/usr/sbin/nft", "flush", "chain", "inet", name, "input" }) else try fixtureCommand(&.{ reader.iptables_path, "-D", "INPUT", "-m", "comment", "--comment", marker, "-j", name });
    const before = try captureScaffold(&reader);
    defer std.testing.allocator.free(before);
    try expectAdmissionRefused(&reader);
    const after = try captureScaffold(&reader);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
}

test "native firewall: isolated admission interruption stays uncertain until complete inspection" {
    const selected = try isolatedTransport();
    const steps: usize = switch (selected) {
        .nftables => 1,
        .iptables => 6,
        .ipset => 10,
    };
    for (1..steps + 1) |step| {
        _ = try isolatedTransport();
        var reader = try admissionReader(selected);
        defer reader.close();
        reader.test_fault_after_mutations = step;
        var failed = try reader.admitInstallation(intentFor(&reader));
        defer failed.deinit();
        try std.testing.expect(failed == .uncertain);
        try std.testing.expectEqual(error.Timeout, failed.uncertain);
        reader.test_fault_after_mutations = null;
        const before = try captureScaffold(&reader);
        defer std.testing.allocator.free(before);
        if (step == steps) {
            var recovered = try reader.admitInstallation(intentFor(&reader));
            defer recovered.deinit();
            try std.testing.expect(recovered == .installed);
            try std.testing.expect(!recovered.installed.created);
        } else try expectAdmissionRefused(&reader);
        const after = try captureScaffold(&reader);
        defer std.testing.allocator.free(after);
        try std.testing.expectEqualSlices(u8, before, after);
    }
}

test "native firewall: invalid admission token and unavailable tool fail before mutation" {
    var reader = try inspection.Inspector.open(std.testing.allocator, .{ .id = [_]u8{1} ** 16, .transport = .iptables }, .{});
    reader.iptables_path = "/nonexistent/fail2zig-fixture-iptables";
    defer reader.close();
    var intent = intentFor(&reader);
    intent.revision = 0;
    try std.testing.expectError(error.InvalidInstallation, reader.admitInstallation(intent));
    intent = intentFor(&reader);
    try std.testing.expectError(error.ToolUnavailable, reader.admitInstallation(intent));
}

test "native firewall: isolated denied admission leaves kernel unchanged" {
    const transport = try isolatedTransport();
    var reader = try admissionReader(transport);
    defer reader.close();
    const before = try captureScaffold(&reader);
    defer std.testing.allocator.free(before);
    const child = try std.posix.fork();
    if (child == 0) {
        var header = std.mem.zeroes(linux.cap_user_header_t);
        header.version = 0x20080522;
        var data: [2]linux.cap_user_data_t = undefined;
        if (linux.E.init(linux.capget(&header, &data[0])) != .SUCCESS) std.process.exit(10);
        if (linux.E.init(linux.prctl(24, linux.CAP.NET_ADMIN, 0, 0, 0)) != .SUCCESS) std.process.exit(11);
        const mask = ~(@as(u32, 1) << linux.CAP.NET_ADMIN);
        data[0].effective &= mask;
        data[0].permitted &= mask;
        data[0].inheritable &= mask;
        if (linux.E.init(linux.capset(&header, &data[0])) != .SUCCESS) std.process.exit(12);
        if (reader.admitInstallation(intentFor(&reader))) |value| {
            var result = value;
            result.deinit();
            std.process.exit(13);
        } else |err| {
            std.process.exit(if (err == error.PermissionDenied or err == error.UnknownState) @as(u8, 0) else 14);
        }
    }
    const waited = std.posix.waitpid(child, 0);
    try std.testing.expect(std.posix.W.IFEXITED(waited.status));
    try std.testing.expectEqual(@as(u8, 0), std.posix.W.EXITSTATUS(waited.status));
    const after = try captureScaffold(&reader);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
}

fn effectToken(reader: *const inspection.Inspector, v6: bool, operation: inspection.EffectOperation) !inspection.DispatchToken {
    return .{ .installation = reader.installation, .effect_id = [_]u8{0x71} ** 32, .aggregate_revision = 1, .scope = .{ .address = try @import("shared").IpAddress.parse(if (v6) "2001:db8::7" else "192.0.2.7"), .prefix = if (v6) 128 else 32 }, .operation = operation };
}
fn applyVerified(reader: *inspection.Inspector, token: inspection.DispatchToken) !inspection.EffectResult {
    var result = try reader.applyExact(token, .{ .wall_us = std.time.microTimestamp() });
    errdefer result.deinit();
    if (result == .uncertain) {
        std.debug.print("exact effect uncertain: {s}\n", .{@errorName(result.uncertain)});
        return error.UnexpectedUncertainty;
    }
    return result;
}
test "native firewall: exact intent rejects invalid scope expired deadline and overflow before I/O" {
    var reader = try admissionReader(.ipset);
    reader.ipset_path = "/not/a/tool";
    reader.iptables_path = "/not/a/tool";
    var token = try effectToken(&reader, false, .{ .ensure_present = .{ .finite_deadline_us = 100 } });
    try std.testing.expectError(error.ExpiredIntent, reader.applyExact(token, .{ .wall_us = 100 }));
    token.operation = .{ .ensure_present = .{ .finite_deadline_us = std.math.maxInt(i64) } };
    try std.testing.expectError(error.UnsupportedDeadline, reader.applyExact(token, .{ .wall_us = 100 }));
    token.scope.prefix = 24;
    try std.testing.expectError(error.UnsupportedScope, reader.applyExact(token, .{ .wall_us = 100 }));
    token.scope.prefix = 32;
    token.aggregate_revision = 0;
    try std.testing.expectError(error.InvalidInstallation, reader.applyExact(token, .{ .wall_us = 100 }));
}
test "native firewall: isolated exact permanent dual-family duplicate release foreign preservation" {
    const transport = try isolatedTransport();
    var reader = try admissionReader(transport);
    var admitted = try reader.admitInstallation(intentFor(&reader));
    defer admitted.deinit();
    try fixtureForeign(&reader);
    const foreign_before = try captureForeign(&reader);
    defer foreign_before.deinit(std.testing.allocator);
    for ([_]bool{ false, true }) |v6| {
        const token = try effectToken(&reader, v6, .{ .ensure_present = .permanent });
        var applied = try applyVerified(&reader, token);
        defer applied.deinit();
        try std.testing.expect(applied.verified.changed);
        const before = try captureScaffold(&reader);
        defer std.testing.allocator.free(before);
        var duplicate = try applyVerified(&reader, token);
        defer duplicate.deinit();
        try std.testing.expect(!duplicate.verified.changed);
        const after = try captureScaffold(&reader);
        defer std.testing.allocator.free(after);
        try std.testing.expectEqualSlices(u8, before, after);
    }
    for ([_]bool{ false, true }, 0..) |v6, index| {
        const token = try effectToken(&reader, v6, .ensure_absent);
        var removed = try applyVerified(&reader, token);
        defer removed.deinit();
        try std.testing.expectEqual(@as(usize, 1) - index, removed.verified.snapshot.entries.len);
        var duplicate = try applyVerified(&reader, token);
        defer duplicate.deinit();
        try std.testing.expect(!duplicate.verified.changed);
    }
    const foreign_after = try captureForeign(&reader);
    defer foreign_after.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, foreign_before.stdout, foreign_after.stdout);
}
test "native firewall: isolated exact uncertain acknowledged mutation reconciles same scope" {
    const transport = try isolatedTransport();
    var reader = try admissionReader(transport);
    var admitted = try reader.admitInstallation(intentFor(&reader));
    defer admitted.deinit();
    const token = try effectToken(&reader, true, .{ .ensure_present = .permanent });
    reader.test_fault_after_mutations = 1;
    var failed = try reader.applyExact(token, .{ .wall_us = std.time.microTimestamp() });
    defer failed.deinit();
    try std.testing.expectEqual(.uncertain, std.meta.activeTag(failed));
    try std.testing.expectEqual(error.Timeout, failed.uncertain);
    reader.test_fault_after_mutations = null;
    var recovered = try applyVerified(&reader, token);
    defer recovered.deinit();
    try std.testing.expect(!recovered.verified.changed);
    try std.testing.expectEqual(@as(usize, 1), recovered.verified.snapshot.entries.len);
}
test "native firewall: isolated finite retry retains original deadline and expires" {
    const transport = try isolatedTransport();
    var reader = try admissionReader(transport);
    var admitted = try reader.admitInstallation(intentFor(&reader));
    defer admitted.deinit();
    const deadline = std.time.microTimestamp() + 3_000_000;
    for ([_]bool{ false, true }) |v6| {
        const token = try effectToken(&reader, v6, .{ .ensure_present = .{ .finite_deadline_us = deadline } });
        var result = try applyVerified(&reader, token);
        result.deinit();
    }
    std.Thread.sleep(1_100_000_000);
    for ([_]bool{ false, true }) |v6| {
        const token = try effectToken(&reader, v6, .{ .ensure_present = .{ .finite_deadline_us = deadline } });
        var retry = try applyVerified(&reader, token);
        defer retry.deinit();
        if (transport != .iptables) for (retry.verified.snapshot.entries) |entry| {
            try std.testing.expect(entry.remaining_ms.? <= 2000);
        };
    }
    const remaining = deadline + 1_100_000 - std.time.microTimestamp();
    if (remaining > 0) std.Thread.sleep(@as(u64, @intCast(remaining)) * 1000);
    var expired = try reader.inspect();
    defer expired.deinit();
    // iptables owns no kernel timer: durable coordinator dispatches removal.
    try std.testing.expectEqual(@as(usize, if (transport == .iptables) 2 else 0), expired.entries.len);
    for ([_]bool{ false, true }) |v6| {
        var release = try applyVerified(&reader, try effectToken(&reader, v6, .ensure_absent));
        release.deinit();
    }
}
test "native firewall: isolated fresh authority refuses reserved objects across transports" {
    _ = try isolatedTransport();
    var reader = try admissionReader(.nftables);
    try reader.inspectReservedNamespace();
    try fixtureCommand(&.{ "/usr/sbin/nft", "add", "table", "ip6", "ordinary" });
    try fixtureCommand(&.{ "/usr/sbin/nft", "add", "chain", "ip6", "ordinary", "ordinary" });
    try reader.inspectReservedNamespace();
    try fixtureCommand(&.{ "/usr/sbin/nft", "add", "set", "ip6", "ordinary", "f2z_lost", "{", "type", "ipv6_addr", ";", "}" });
    try std.testing.expectError(error.ForeignState, reader.inspectReservedNamespace());
    try fixtureCommand(&.{ "/usr/sbin/nft", "delete", "set", "ip6", "ordinary", "f2z_lost" });
    try fixtureCommand(&.{ reader.ip6tables_path, "-t", "mangle", "-N", "fail2zig-old" });
    try std.testing.expectError(error.ForeignState, reader.inspectReservedNamespace());
    try fixtureCommand(&.{ reader.ip6tables_path, "-t", "mangle", "-X", "fail2zig-old" });
    try fixtureCommand(&.{ reader.ipset_path, "create", "fail2zig-lost", "hash:ip" });
    try std.testing.expectError(error.ForeignState, reader.inspectReservedNamespace());
    try fixtureCommand(&.{ reader.ipset_path, "destroy", "fail2zig-lost" });
    try reader.inspectReservedNamespace();
    try fixtureCommand(&.{ "/usr/sbin/iptables-legacy", "-t", "mangle", "-N", "fail2zig-old" });
    try std.testing.expectError(error.ForeignState, reader.inspectReservedNamespace());
    try fixtureCommand(&.{ "/usr/sbin/iptables-legacy", "-t", "mangle", "-X", "fail2zig-old" });
    try reader.inspectReservedNamespace();
    reader.ipset_path = "/not/a/tool";
    try std.testing.expectError(error.ToolUnavailable, reader.inspectReservedNamespace());
}

const PacketPeer = struct {
    pid: std.posix.pid_t,
    control: std.posix.fd_t,
    ready: std.posix.fd_t,
    receivers: [2]std.posix.fd_t,
    fn init() !PacketPeer {
        const control = try std.posix.pipe2(.{ .CLOEXEC = true });
        var parent_only = false;
        errdefer {
            std.posix.close(control[1]);
            if (!parent_only) std.posix.close(control[0]);
        }
        const ready = try std.posix.pipe2(.{ .CLOEXEC = true });
        errdefer {
            std.posix.close(ready[0]);
            if (!parent_only) std.posix.close(ready[1]);
        }
        const pid = try std.posix.fork();
        if (pid == 0) {
            std.posix.close(control[1]);
            std.posix.close(ready[0]);
            packetPeerChild(control[0], ready[1]) catch |err| {
                std.debug.print("packet peer: {s}\n", .{@errorName(err)});
                linux.exit_group(41);
            };
            linux.exit_group(0);
        }
        std.posix.close(control[0]);
        std.posix.close(ready[1]);
        parent_only = true;
        errdefer {
            std.posix.kill(pid, std.posix.SIG.KILL) catch {};
            _ = std.posix.waitpid(pid, 0);
        }
        try expectPipeByte(ready[0], 1);
        try fixtureCommand(&.{ "/usr/sbin/ip", "link", "add", "target0", "type", "veth", "peer", "name", "peer0" });
        var pid_buf: [20]u8 = undefined;
        const pid_text = try std.fmt.bufPrint(&pid_buf, "{d}", .{pid});
        try fixtureCommand(&.{ "/usr/sbin/ip", "link", "set", "peer0", "netns", pid_text });
        try configurePeerInterface("target0", "192.0.2.1/24", "2001:db8::1/64");
        try std.testing.expectEqual(@as(usize, 1), try std.posix.write(control[1], &.{1}));
        try expectPipeByte(ready[0], 2);
        var receivers: [2]std.posix.fd_t = undefined;
        receivers[0] = try packetSocket(false, "192.0.2.1", 35271);
        errdefer std.posix.close(receivers[0]);
        receivers[1] = try packetSocket(true, "2001:db8::1", 35271);
        return .{ .pid = pid, .control = control[1], .ready = ready[0], .receivers = receivers };
    }
    fn deinit(self: *PacketPeer) void {
        std.posix.close(self.control);
        std.posix.close(self.ready);
        for (self.receivers) |fd| std.posix.close(fd);
        _ = std.posix.waitpid(self.pid, 0);
    }
    fn exchange(self: *PacketPeer, v6: bool, sequence: u8, delivered: bool) !void {
        try std.testing.expectEqual(@as(usize, 2), try std.posix.write(self.control, &.{ if (v6) @as(u8, 6) else 4, sequence }));
        try expectPipeByte(self.ready, sequence);
        var fds = [_]std.posix.pollfd{.{ .fd = self.receivers[@intFromBool(v6)], .events = std.posix.POLL.IN, .revents = 0 }};
        const count = try std.posix.poll(&fds, if (delivered) 1500 else 150);
        try std.testing.expectEqual(@as(usize, @intFromBool(delivered)), count);
        if (delivered) {
            var byte: [16]u8 = undefined;
            const length = try std.posix.recv(fds[0].fd, &byte, 0);
            try std.testing.expectEqual(@as(usize, 1), length);
            try std.testing.expectEqual(sequence, byte[0]);
        }
    }
};
fn expectPipeByte(fd: std.posix.fd_t, expected: u8) !void {
    var fds = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
    if (try std.posix.poll(&fds, 3000) != 1) return error.PeerTimeout;
    var byte: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try std.posix.read(fd, &byte));
    try std.testing.expectEqual(expected, byte[0]);
}
fn configurePeerInterface(name: []const u8, v4: []const u8, v6: []const u8) !void {
    try fixtureCommand(&.{ "/usr/sbin/ip", "link", "set", name, "up" });
    try fixtureCommand(&.{ "/usr/sbin/ip", "address", "add", v4, "dev", name });
    try fixtureCommand(&.{ "/usr/sbin/ip", "-6", "address", "add", v6, "dev", name, "nodad" });
}
fn packetSocket(v6: bool, host: []const u8, port: u16) !std.posix.fd_t {
    const fd = try std.posix.socket(if (v6) std.posix.AF.INET6 else std.posix.AF.INET, std.posix.SOCK.DGRAM | std.posix.SOCK.CLOEXEC, 0);
    errdefer std.posix.close(fd);
    const address = try std.net.Address.parseIp(host, port);
    try std.posix.bind(fd, &address.any, address.getOsSockLen());
    return fd;
}
fn packetPeerChild(control: std.posix.fd_t, ready: std.posix.fd_t) !void {
    if (linux.E.init(linux.unshare(linux.CLONE.NEWNET)) != .SUCCESS) return error.IsolationFailed;
    _ = try std.posix.write(ready, &.{1});
    try expectPipeByte(control, 1);
    try configurePeerInterface("peer0", "192.0.2.7/24", "2001:db8::7/64");
    const senders = [_]std.posix.fd_t{ try packetSocket(false, "192.0.2.7", 0), try packetSocket(true, "2001:db8::7", 0) };
    _ = try std.posix.write(ready, &.{2});
    while (true) {
        var bytes: [2]u8 = undefined;
        const count = try std.posix.read(control, &bytes);
        if (count == 0) return;
        if (count != 2) return error.PeerProtocol;
        const v6 = bytes[0] == 6;
        const target = try std.net.Address.parseIp(if (v6) "2001:db8::1" else "192.0.2.1", 35271);
        _ = try std.posix.sendto(senders[@intFromBool(v6)], bytes[1..2], 0, &target.any, target.getOsSockLen());
        _ = try std.posix.write(ready, bytes[1..2]);
    }
}
test "native firewall: isolated benign namespace peer packets verify IPv4 IPv6 exact drop and release" {
    const transport = try isolatedTransport();
    var reader = try admissionReader(transport);
    var admitted = try reader.admitInstallation(intentFor(&reader));
    defer admitted.deinit();
    var peer = try PacketPeer.init();
    defer peer.deinit();
    try peer.exchange(false, 10, true);
    try peer.exchange(true, 11, true);
    var v4 = try applyVerified(&reader, try effectToken(&reader, false, .{ .ensure_present = .permanent }));
    v4.deinit();
    try peer.exchange(false, 12, false);
    try peer.exchange(true, 13, true);
    var v6 = try applyVerified(&reader, try effectToken(&reader, true, .{ .ensure_present = .permanent }));
    v6.deinit();
    try peer.exchange(false, 14, false);
    try peer.exchange(true, 15, false);
    var release4 = try applyVerified(&reader, try effectToken(&reader, false, .ensure_absent));
    release4.deinit();
    try peer.exchange(false, 16, true);
    try peer.exchange(true, 17, false);
    var release6 = try applyVerified(&reader, try effectToken(&reader, true, .ensure_absent));
    release6.deinit();
    try peer.exchange(true, 18, true);
}

fn failedEffectAllocation(allocator: std.mem.Allocator, stable: *inspection.Inspector) !void {
    var remove = try applyVerified(stable, try effectToken(stable, false, .ensure_absent));
    remove.deinit();
    var reader = try inspection.Inspector.open(allocator, stable.installation, .{});
    reader.ipset_path = stable.ipset_path;
    var result = try reader.applyExact(try effectToken(&reader, false, .{ .ensure_present = .permanent }), .{ .wall_us = std.time.microTimestamp() });
    defer result.deinit();
    if (result == .uncertain) return result.uncertain;
    try std.testing.expectEqual(@as(usize, 1), result.verified.snapshot.entries.len);
}
test "native firewall: isolated exact allocation failure preserves recoverable owned scaffold" {
    const transport = try isolatedTransport();
    var reader = try admissionReader(transport);
    var admitted = try reader.admitInstallation(intentFor(&reader));
    defer admitted.deinit();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, failedEffectAllocation, .{&reader});
    var recovered = try applyVerified(&reader, try effectToken(&reader, false, .{ .ensure_present = .permanent }));
    defer recovered.deinit();
    try std.testing.expectEqual(@as(usize, 1), recovered.verified.snapshot.entries.len);
}

test "native firewall: isolated read-only exact observation reconciles missing and expired desired state" {
    const transport = try isolatedTransport();
    var reader = try admissionReader(transport);
    var admitted = try reader.admitInstallation(intentFor(&reader));
    defer admitted.deinit();
    const token = try effectToken(&reader, false, .{ .ensure_present = .permanent });
    var missing = try reader.observeExact(token, .{ .wall_us = std.time.microTimestamp() });
    defer missing.deinit();
    try std.testing.expect(!missing.matches_desired);
    var present = try applyVerified(&reader, token);
    present.deinit();
    const before = try captureScaffold(&reader);
    defer std.testing.allocator.free(before);
    var observed = try reader.observeExact(token, .{ .wall_us = std.time.microTimestamp() });
    defer observed.deinit();
    try std.testing.expect(observed.matches_desired);
    const expired = try effectToken(&reader, false, .{ .ensure_present = .{ .finite_deadline_us = 1 } });
    var past = try reader.observeExact(expired, .{ .wall_us = std.time.microTimestamp() });
    defer past.deinit();
    try std.testing.expect(!past.matches_desired);
    const after = try captureScaffold(&reader);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
}

test "native firewall: snapshot classifier validates ownership interval scope and exact desired lease without I/O" {
    var reader = try admissionReader(.nftables);
    reader.iptables_path = "/not/a/tool";
    reader.ipset_path = "/not/a/tool";
    const token = try effectToken(&reader, false, .{ .ensure_present = .permanent });
    var entries = [_]inspection.Entry{.{ .address = token.scope.address }};
    var snapshot = inspection.Snapshot{ .allocator = std.testing.allocator, .installation = reader.installation, .state = .owned, .entries = &entries, .fingerprint = [_]u8{1} ** 32, .observed_start_ns = 1000, .observed_end_ns = 2000 };
    try std.testing.expect(try reader.matchesSnapshot(&snapshot, token, 100, 102));
    var wrong = token;
    wrong.scope = (try effectToken(&reader, true, .{ .ensure_present = .permanent })).scope;
    try std.testing.expect(!try reader.matchesSnapshot(&snapshot, wrong, 100, 102));
    wrong.scope.prefix = 64;
    try std.testing.expectError(error.UnsupportedScope, reader.matchesSnapshot(&snapshot, wrong, 100, 102));
    try std.testing.expectError(error.UnsupportedDeadline, reader.matchesSnapshot(&snapshot, token, 102, 100));
    try std.testing.expectError(error.Incomplete, reader.matchesSnapshot(&snapshot, token, 100, 100));
    try std.testing.expectError(error.Incomplete, reader.matchesSnapshot(&snapshot, token, 100, 5_000_101));
    snapshot.installation.id[0] ^= 1;
    try std.testing.expectError(error.InvalidInstallation, reader.matchesSnapshot(&snapshot, token, 100, 102));
    snapshot.installation = reader.installation;
    snapshot.state = .absent;
    try std.testing.expectError(error.InvalidInstallation, reader.matchesSnapshot(&snapshot, token, 100, 102));
    snapshot.state = .owned;
    snapshot.entries = entries[0..0];
    try std.testing.expect(!try reader.matchesSnapshot(&snapshot, token, 100, 102));
    wrong = token;
    wrong.operation = .ensure_absent;
    try std.testing.expect(try reader.matchesSnapshot(&snapshot, wrong, 100, 102));
    snapshot.entries = &entries;
    wrong.operation = .{ .ensure_present = .{ .finite_deadline_us = 2_000_100 } };
    try std.testing.expect(!try reader.matchesSnapshot(&snapshot, wrong, 100, 102));
    entries[0].remaining_ms = 2000;
    try std.testing.expect(try reader.matchesSnapshot(&snapshot, wrong, 100, 102));
    try std.testing.expect(!try reader.matchesSnapshot(&snapshot, token, 100, 102));
    entries[0].remaining_ms = 30_000;
    try std.testing.expect(!try reader.matchesSnapshot(&snapshot, wrong, 100, 102));
    wrong.operation = .{ .ensure_present = .{ .finite_deadline_us = 101 } };
    try std.testing.expect(!try reader.matchesSnapshot(&snapshot, wrong, 100, 102));
}

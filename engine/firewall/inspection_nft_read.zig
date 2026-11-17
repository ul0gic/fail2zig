// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Reads this installation's nftables table, chain, sets, rules and elements over netlink and checks them against what was built.
// Holds: The table reads as owned only with the installation marker, one input chain, both timeout sets and both set drop rules as built.

const std = @import("std");
const shared = @import("shared");
const build_options = @import("build_options");
const diag_mod = @import("../diag/diag.zig");
const nl = @import("netlink.zig");
const nft = @import("nftables.zig");
const linux = @import("std").os.linux;
const mem = @import("std").mem;
const Entry = @import("inspection.zig").Entry;
const Error = @import("inspection.zig").Error;
const Inspector = @import("inspection.zig").Inspector;
const MutationProgress = @import("inspection.zig").MutationProgress;
const ScopedRuleMetadata = @import("inspection.zig").ScopedRuleMetadata;
const Builder = @import("inspection_builder.zig").Builder;
const ScopedGroup = @import("inspection_builder.zig").ScopedGroup;
const collectScopedGroup = @import("inspection_builder.zig").collectScopedGroup;
const finishScopedGroups = @import("inspection_builder.zig").finishScopedGroups;

// Why: Bare attribute kinds in this file are enum values from include/uapi/linux/netfilter/nf_tables.h.
pub const AttrMap = struct {
    values: [32]?[]const u8 = @splat(null),
    flags: [32]u16 = @splat(0),
    pub fn parse(bytes: []const u8, allowed: []const u16) Error!AttrMap {
        var map: AttrMap = .{};
        var it = nl.Attributes{ .bytes = bytes };
        while (it.next() catch return error.Incomplete) |a| {
            if (a.kind >= map.values.len or mem.indexOfScalar(u16, allowed, a.kind) == null) return error.UnknownState;
            if (map.values[a.kind] != null) return error.UnknownState;
            // Why: Flag 0x8000 is NLA_F_NESTED and 0x4000 is NLA_F_NET_BYTEORDER (include/uapi/linux/netlink.h).
            if ((a.flags & 0x8000) != 0) try validateNested(a.value, 0);
            map.values[a.kind] = a.value;
            map.flags[a.kind] = a.flags;
        }
        return map;
    }
    pub fn get(self: AttrMap, kind: usize) Error![]const u8 {
        return self.values[kind] orelse error.Incomplete;
    }
    pub fn text(self: AttrMap, kind: usize) Error![]const u8 {
        if (self.flags[kind] != 0) return error.UnknownState;
        const value = try self.get(kind);
        if (value.len == 0 or value[value.len - 1] != 0 or mem.indexOfScalar(u8, value[0 .. value.len - 1], 0) != null) return error.UnknownState;
        return value[0 .. value.len - 1];
    }
    pub fn number(self: AttrMap, comptime T: type, kind: usize) Error!T {
        if ((self.flags[kind] & 0x8000) != 0) return error.UnknownState;
        const value = try self.get(kind);
        if (value.len != @sizeOf(T)) return error.UnknownState;
        return mem.readInt(T, value[0..@sizeOf(T)], .big);
    }
};
fn validateNested(bytes: []const u8, depth: usize) Error!void {
    if (depth >= 16) return error.LimitExceeded;
    var it = nl.Attributes{ .bytes = bytes };
    while (it.next() catch return error.Incomplete) |a| {
        if ((a.flags & 0x8000) != 0) try validateNested(a.value, depth + 1);
    }
}
const Records = struct {
    allocator: mem.Allocator,
    values: std.ArrayList([]u8),
    bytes: usize = 0,
    pub fn deinit(self: *Records) void {
        for (self.values.items) |value| self.allocator.free(value);
        self.values.deinit();
    }
};
pub fn netlinkError(err: nl.Error) Error {
    return switch (err) {
        error.PermissionDenied => error.PermissionDenied,
        error.Timeout => error.Timeout,
        error.TruncatedMessage => error.Incomplete,
        error.BufferTooSmall => error.LimitExceeded,
        error.EventsOverflowed => error.Changed,
        error.DumpInterrupted => error.DumpInterrupted,
        else => error.UnknownState,
    };
}
// Why: The kernel commits a batch whole or not at all, so EEXIST or ENOENT from a stale baseline means nothing changed.
pub fn rejectedBatch(err: nl.Error, progress: *MutationProgress) Error {
    switch (err) {
        error.AlreadyExists, error.NotFound => {
            progress.requested = false;
            return error.Changed;
        },
        else => return netlinkError(err),
    }
}
pub fn scopeBuildError(err: anyerror) Error {
    return switch (err) {
        error.PermissionDenied => error.PermissionDenied,
        error.Timeout => error.Timeout,
        error.OutOfMemory => error.OutOfMemory,
        error.BufferTooSmall => error.LimitExceeded,
        error.SendFailed, error.RecvFailed, error.SocketFailed => error.SystemError,
        else => error.UnsupportedScope,
    };
}
pub fn dump(self: *Inspector, sock: *nl.NetlinkSocket, request_type: u16, response_type: u16, request: []const u8, timer: *std.time.Timer, reserved: usize) Error!Records {
    var records = Records{ .allocator = self.allocator, .values = std.ArrayList([]u8).init(self.allocator) };
    errdefer records.deinit();
    try self.checkTime(timer);
    var outgoing: [1024]u8 align(4) = undefined;
    var message = nl.MessageBuilder.init(&outgoing);
    const sequence = sock.nextSeq();
    // Why: 0x300 is NLM_F_DUMP, NLM_F_ROOT | NLM_F_MATCH (include/uapi/linux/netlink.h).
    message.append(nl.nfnlMsgType(nl.NFNL.SUBSYS_NFTABLES, request_type), linux.NLM_F_REQUEST | 0x300, sequence, sock.port_id, request) catch |err| return netlinkError(err);
    nl.sendKernel(sock, message.bytes(), @min(try self.remainingMs(timer), 2000)) catch |err| return netlinkError(err);
    var state = nl.Dump{ .sequence = sequence, .message_type = nl.nfnlMsgType(nl.NFNL.SUBSYS_NFTABLES, response_type), .port_id = sock.port_id, .max_messages = self.limits.max_messages };
    var scratch: [65536]u8 = undefined;
    var datagrams: usize = 0;
    while (!state.complete) {
        try self.checkTime(timer);
        datagrams += 1;
        if (datagrams > self.limits.max_messages) return error.LimitExceeded;
        const remaining = try self.remainingMs(timer);
        sock.setRecvTimeout(@max(@as(u64, 1), @min(remaining, 2000))) catch |err| return netlinkError(err);
        const bytes = nl.recvKernel(sock, &scratch) catch |err| return netlinkError(err);
        var messages = nl.StrictMessages{ .bytes = bytes };
        while (messages.next() catch |err| return netlinkError(err)) |item| {
            try self.chargeMessages(1);
            if (comptime build_options.diag) diag_mod.count(.dump_messages, 1);
            if (state.accept(item) catch |err| return netlinkError(err)) |payload| {
                const cost = std.math.add(usize, payload.len, 2 * @sizeOf([]u8)) catch return error.LimitExceeded;
                const used = std.math.add(usize, records.bytes, reserved + self.retained_bytes) catch return error.LimitExceeded;
                if (used > self.limits.max_bytes or cost > self.limits.max_bytes - used) return error.LimitExceeded;
                const owned = try self.allocator.dupe(u8, payload);
                errdefer self.allocator.free(owned);
                try records.values.append(owned);
                records.bytes += cost;
            }
        }
    }
    return records;
}
pub fn payloadAttrs(payload: []const u8, allowed: []const u16) Error!AttrMap {
    if (payload.len < 4 or payload[0] != nl.NFPROTO.INET or payload[1] != 0) return error.UnknownState;
    return AttrMap.parse(payload[4..], allowed);
}
pub fn nftSetAttrs(payload: []const u8) Error!AttrMap {
    const attrs = try payloadAttrs(payload, &.{ 1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 14, 16, 19, 20 });
    if (attrs.values[19] != null) {
        _ = try attrs.text(19);
    }
    if (attrs.values[20] != null) {
        _ = try attrs.number(u32, 20);
    }
    return attrs;
}
fn equalAttributes(a: []const u8, b: []const u8, depth: usize, optional_zero_attr: ?u16) Error!bool {
    if (depth > 16) return error.LimitExceeded;
    var ai = nl.Attributes{ .bytes = a };
    var actual: [32]?nl.Attributes.View = @splat(null);
    var count: usize = 0;
    while (ai.next() catch return error.Incomplete) |av| {
        if (av.kind >= actual.len or actual[av.kind] != null) return error.UnknownState;
        actual[av.kind] = av;
        count += 1;
    }
    var bi = nl.Attributes{ .bytes = b };
    while (bi.next() catch return error.Incomplete) |bv| {
        if (bv.kind >= actual.len) return error.UnknownState;
        const av = actual[bv.kind] orelse return false;
        actual[bv.kind] = null;
        count -= 1;
        if ((bv.flags & 0x8000) != 0) {
            if ((av.flags & 0x4000) != 0 or !try equalAttributes(av.value, bv.value, depth + 1, null)) return false;
        } else if (av.flags != bv.flags or !mem.eql(u8, av.value, bv.value)) return false;
    }
    if (count == 0) return true;
    if (optional_zero_attr) |kind| {
        if (count == 1) {
            const value = actual[kind] orelse return false;
            return value.flags == 0 and mem.eql(u8, value.value, &.{ 0, 0, 0, 0 });
        }
    }
    return false;
}
pub fn validateScopedDropRule(table: []const u8, attributes: AttrMap, metadata: ScopedRuleMetadata) Error!void {
    const part_count = nft.scopeRulePartCount(metadata.scope) catch |err| return scopeBuildError(err);
    if (part_count != metadata.count) return error.ForeignState;
    var expected_buf: [2048]u8 align(4) = undefined;
    const expected = nft.buildScopedDropRulePayload(&expected_buf, table, "input", metadata.scope, metadata.part, try attributes.get(7)) catch |err| return scopeBuildError(err);
    const expected_attrs = try payloadAttrs(expected, &.{ 1, 2, 4, 7 });
    if (!try equalExpressions(try attributes.get(4), try expected_attrs.get(4))) return error.ForeignState;
}
fn equalExpressions(a: []const u8, b: []const u8) Error!bool {
    var actual = nl.Attributes{ .bytes = a };
    var expected = nl.Attributes{ .bytes = b };
    while (expected.next() catch return error.Incomplete) |e| {
        const observed = (actual.next() catch return error.Incomplete) orelse return false;
        if (e.kind != 1 or observed.kind != 1 or (observed.flags & 0x4000) != 0) return false;
        const ea = try AttrMap.parse(e.value, &.{ 1, 2 });
        const oa = try AttrMap.parse(observed.value, &.{ 1, 2 });
        const name = try ea.text(1);
        if (!mem.eql(u8, name, try oa.text(1))) return false;
        // Why: The kernel dumps NFTA_LOOKUP_FLAGS (5) and NFTA_BITWISE_OP (6) as zero although the built rule omits them.
        const optional_zero_attr: ?u16 = if (mem.eql(u8, name, "lookup")) 5 else if (mem.eql(u8, name, "bitwise")) 6 else null;
        if (!try equalAttributes(try oa.get(2), try ea.get(2), 0, optional_zero_attr)) return false;
    }
    return (actual.next() catch return error.Incomplete) == null;
}

pub fn decodeSetElement(value: []const u8, family_index: usize) Error!Entry {
    const e = try AttrMap.parse(value, &.{ 1, 3, 4, 5, 8 });
    if (e.values[3] != null and try e.number(u32, 3) != 0) return error.ForeignState;
    const key = try AttrMap.parse(try e.get(1), &.{1});
    const bytes = try key.get(1);
    if (bytes.len != (if (family_index == 0) @as(usize, 4) else 16)) return error.UnknownState;
    var remaining: ?u64 = null;
    if (e.values[4] != null) {
        if (try e.number(u64, 4) != 0) remaining = try e.number(u64, 5);
    } else if (e.values[5] != null) return error.UnknownState;
    const address: shared.IpAddress = if (family_index == 0) .{ .ipv4 = mem.readInt(u32, bytes[0..4], .big) } else .{ .ipv6 = mem.readInt(u128, bytes[0..16], .big) };
    return .{ .address = address, .remaining_ms = remaining };
}

pub fn readNft(self: *Inspector, builder: *Builder, timer: *std.time.Timer) Error!void {
    var sock = nl.NetlinkSocket.init(linux.NETLINK.NETFILTER) catch |err| return netlinkError(err);
    defer sock.close();
    var name_buf: [28]u8 = undefined;
    const name = self.installation.name(&name_buf);
    var marker_buf: [44]u8 = undefined;
    const marker = self.installation.marker(&marker_buf);
    var found = false;
    {
        var tables = try dump(self, &sock, nft.NFT_MSG.GETTABLE, nft.NFT_MSG.NEWTABLE, &.{ nl.NFPROTO.INET, 0, 0, 0 }, timer, 0);
        defer tables.deinit();
        for (tables.values.items) |payload| {
            const attrs = try payloadAttrs(payload, &.{ 1, 2, 3, 4, 5, 6, 7 });
            if (!mem.eql(u8, try attrs.text(1), name)) continue;
            if (found) return error.UnknownState;
            found = true;
            if (!mem.eql(u8, try attrs.get(6), marker) or try attrs.number(u32, 2) != 0) return error.ForeignState;
            builder.topology.update(try attrs.get(4));
        }
    }
    if (!found) return;
    var request_buf: [256]u8 align(4) = undefined;
    const request = nft.buildTablePayload(&request_buf, nl.NFPROTO.INET, name) catch |err| return netlinkError(err);
    {
        var chains = try dump(self, &sock, nft.NFT_MSG.GETCHAIN, nft.NFT_MSG.NEWCHAIN, request, timer, 0);
        defer chains.deinit();
        var chain_count: usize = 0;
        for (chains.values.items) |payload| {
            const a = try payloadAttrs(payload, &.{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 });
            if (!mem.eql(u8, try a.text(1), name)) continue;
            chain_count += 1;
            if (chain_count != 1 or !mem.eql(u8, try a.text(3), "input") or
                !mem.eql(u8, try a.text(7), "filter") or try a.number(u32, 5) != 1) return error.ForeignState;
            const hook = try AttrMap.parse(try a.get(4), &.{ 1, 2 });
            if (try hook.number(u32, 1) != 1 or try hook.number(i32, 2) != -1) return error.ForeignState;
            if (a.values[10] != null and try a.number(u32, 10) != 1) return error.ForeignState;
            builder.topology.update(try a.get(2));
        }
        if (chain_count != 1) return error.ForeignState;
    }
    {
        var sets = try dump(self, &sock, nft.NFT_MSG.GETSET, nft.NFT_MSG.NEWSET, request, timer, 0);
        defer sets.deinit();
        var seen = [_]bool{ false, false };
        for (sets.values.items) |payload| {
            const a = try nftSetAttrs(payload);
            if (!mem.eql(u8, try a.text(1), name)) continue;
            const set = try a.text(2);
            const index: usize = if (mem.eql(u8, set, "banned_ipv4")) 0 else if (mem.eql(u8, set, "banned_ipv6")) 1 else return error.ForeignState;
            if (seen[index]) return error.UnknownState;
            seen[index] = true;
            if (try a.number(u32, 3) != nft.NFT_SET_TIMEOUT or try a.number(u32, 4) != (if (index == 0) @as(u32, 7) else 8) or
                try a.number(u32, 5) != (if (index == 0) @as(u32, 4) else 16)) return error.ForeignState;
            if (a.values[11] != null and try a.number(u64, 11) != 0) return error.ForeignState;
            if (a.values[16]) |handle| {
                if (handle.len != 8) return error.UnknownState;
                builder.topology.update(handle);
            }
        }
        if (!seen[0] or !seen[1]) return error.ForeignState;
    }
    {
        var rules = try dump(self, &sock, nft.NFT_MSG.GETRULE, nft.NFT_MSG.NEWRULE, request, timer, 0);
        defer rules.deinit();
        var seen = [_]bool{ false, false };
        var scoped = std.ArrayList(ScopedGroup).init(self.allocator);
        defer scoped.deinit();
        for (rules.values.items) |payload| {
            const a = try payloadAttrs(payload, &.{ 1, 2, 3, 4, 6, 7, 8 });
            if (!mem.eql(u8, try a.text(1), name)) continue;
            if (!mem.eql(u8, try a.text(2), "input")) return error.ForeignState;
            var matched = false;
            for (0..2) |index| {
                var expected_buf: [512]u8 align(4) = undefined;
                const expected = nft.buildDropRulePayload(
                    &expected_buf,
                    nl.NFPROTO.INET,
                    name,
                    "input",
                    if (index == 0) "banned_ipv4" else "banned_ipv6",
                    if (index == 0) nl.NFPROTO.IPV4 else nl.NFPROTO.IPV6,
                    if (index == 0) 12 else 8,
                    if (index == 0) 4 else 16,
                ) catch |err| return netlinkError(err);
                const expected_attrs = try payloadAttrs(expected, &.{ 1, 2, 4 });
                if (try equalExpressions(try a.get(4), try expected_attrs.get(4))) {
                    if (seen[index]) return error.UnknownState;
                    seen[index] = true;
                    matched = true;
                    builder.topology.update(try a.get(3));
                    break;
                }
            }
            if (matched) {
                if (a.values[7] != null) return error.ForeignState;
                continue;
            }
            const metadata = try ScopedRuleMetadata.decode(try a.get(7));
            try validateScopedDropRule(name, a, metadata);
            _ = try a.number(u64, 3);
            try collectScopedGroup(&scoped, metadata, builder.limits);
            builder.topology.update(try a.get(3));
        }
        if (!seen[0] or !seen[1]) return error.ForeignState;
        try finishScopedGroups(builder, scoped.items);
    }
    for (0..2) |index| {
        var element_request_buf: [256]u8 = undefined;
        const query = nft.buildSetQueryPayload(&element_request_buf, name, if (index == 0) "banned_ipv4" else "banned_ipv6") catch |err| return netlinkError(err);
        var elements = try dump(self, &sock, nft.NFT_MSG.GETSETELEM, nft.NFT_MSG.NEWSETELEM, query, timer, builder.entries.capacity * @sizeOf(Entry));
        defer elements.deinit();
        builder.transient_bytes = elements.bytes;
        defer builder.transient_bytes = 0;
        for (elements.values.items) |payload| {
            const a = try payloadAttrs(payload, &.{ 1, 2, 3 });
            if (!mem.eql(u8, try a.text(1), name) or !mem.eql(u8, try a.text(2), if (index == 0) "banned_ipv4" else "banned_ipv6")) return error.ForeignState;
            var items = nl.Attributes{ .bytes = try a.get(3) };
            while (items.next() catch return error.Incomplete) |item| {
                if (item.kind != 1 or (item.flags & 0x4000) != 0) return error.UnknownState;
                if (comptime build_options.diag) diag_mod.count(.dump_elements, 1);
                try builder.add(try decodeSetElement(item.value, index));
            }
        }
    }
    builder.present = true;
}

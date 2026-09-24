// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const native_endian = @import("builtin").cpu.arch.endian();
const linux = std.os.linux;
const mem = std.mem;
const shared = @import("shared");
const engine = @import("engine_test");
const nftables = engine.firewall.nftables;
const netlink = engine.firewall.netlink;
const NFT_MSG = nftables.NFT_MSG;
const NFTA_TABLE = nftables.NFTA_TABLE;
const NFTA_CHAIN = nftables.NFTA_CHAIN;
const NFTA_HOOK = nftables.NFTA_HOOK;
const NFTA_SET = nftables.NFTA_SET;
const NFTA_SET_ELEM = nftables.NFTA_SET_ELEM;
const NFTA_DATA_VALUE = nftables.NFTA_DATA_VALUE;
const NLA_F_NESTED = nftables.NLA_F_NESTED;
const NFT_SET_TIMEOUT = nftables.NFT_SET_TIMEOUT;
const NFT_TYPE = nftables.NFT_TYPE;
const NF_INET_HOOK = nftables.NF_INET_HOOK;
const NFTA_RULE = nftables.NFTA_RULE;
const NFTA_EXPR = nftables.NFTA_EXPR;
const NFTA_PAYLOAD = nftables.NFTA_PAYLOAD;
const NFTA_LOOKUP = nftables.NFTA_LOOKUP;
const NFTA_IMMEDIATE = nftables.NFTA_IMMEDIATE;
const NFTA_DATA = nftables.NFTA_DATA;
const NFTA_VERDICT = nftables.NFTA_VERDICT;
const NFT_PAYLOAD = nftables.NFT_PAYLOAD;
const NFT_REG = nftables.NFT_REG;
const NF_VERDICT = nftables.NF_VERDICT;
const IPV4_SADDR_OFFSET = nftables.IPV4_SADDR_OFFSET;
const IPV4_SADDR_LEN = nftables.IPV4_SADDR_LEN;
const IPV6_SADDR_OFFSET = nftables.IPV6_SADDR_OFFSET;
const IPV6_SADDR_LEN = nftables.IPV6_SADDR_LEN;
const buildTablePayload = nftables.buildTablePayload;
const buildSetPayload = nftables.buildSetPayload;
const buildSetElemAddPayload = nftables.buildSetElemAddPayload;
const buildSetElemDelPayload = nftables.buildSetElemDelPayload;
const buildDeleteTablePayload = nftables.buildDeleteTablePayload;
const buildChainPayload = nftables.buildChainPayload;
const buildDropRulePayload = nftables.buildDropRulePayload;
const NftablesBackend = nftables.NftablesBackend;
const ProbeResult = nftables.ProbeResult;
const probeReason = nftables.probeReason;
const probeReasonFromInitError = nftables.probeReasonFromInitError;
const probeReasonFromAckError = nftables.probeReasonFromAckError;
const probeAvailable = nftables.probeAvailable;
const backend = nftables.TestAccess.backendModule;
const nlaAlign = nftables.TestAccess.alignAttribute;
const appendAttr = nftables.TestAccess.appendAttribute;
const appendU32BE = nftables.TestAccess.appendU32BigEndian;
const appendStringNul = nftables.TestAccess.appendNulString;
const isAvailableImpl = nftables.TestAccess.availableImpl;
const mapNetlinkErr = nftables.TestAccess.mapNetlinkError;

test "nftables: NFT_MSG ids match kernel header" {
    try std.testing.expectEqual(@as(u16, 0), NFT_MSG.NEWTABLE);
    try std.testing.expectEqual(@as(u16, 3), NFT_MSG.NEWCHAIN);
    try std.testing.expectEqual(@as(u16, 9), NFT_MSG.NEWSET);
    try std.testing.expectEqual(@as(u16, 12), NFT_MSG.NEWSETELEM);
    try std.testing.expectEqual(@as(u16, 14), NFT_MSG.DELSETELEM);
}

test "nftables: attribute ids match kernel header (SYS-004 regression)" {
    try std.testing.expectEqual(@as(u16, 11), NFTA_SET.TIMEOUT);
    try std.testing.expectEqual(@as(u16, 4), NFTA_SET_ELEM.TIMEOUT);
    try std.testing.expectEqual(@as(u16, 1), NFTA_SET_ELEM.KEY);

    try std.testing.expectEqual(@as(u16, 1), NFTA_CHAIN.TABLE);
    try std.testing.expectEqual(@as(u16, 3), NFTA_CHAIN.NAME);
    try std.testing.expectEqual(@as(u16, 4), NFTA_CHAIN.HOOK);
    try std.testing.expectEqual(@as(u16, 5), NFTA_CHAIN.POLICY);
    try std.testing.expectEqual(@as(u16, 7), NFTA_CHAIN.TYPE);

    try std.testing.expectEqual(@as(u16, 1), NFTA_HOOK.HOOKNUM);
    try std.testing.expectEqual(@as(u16, 2), NFTA_HOOK.PRIORITY);

    try std.testing.expectEqual(@as(u16, 1), NFTA_RULE.TABLE);
    try std.testing.expectEqual(@as(u16, 2), NFTA_RULE.CHAIN);
    try std.testing.expectEqual(@as(u16, 4), NFTA_RULE.EXPRESSIONS);
    try std.testing.expectEqual(@as(u16, 1), NFTA_EXPR.NAME);
    try std.testing.expectEqual(@as(u16, 2), NFTA_EXPR.DATA);

    try std.testing.expectEqual(@as(u16, 1), NFTA_PAYLOAD.DREG);
    try std.testing.expectEqual(@as(u16, 2), NFTA_PAYLOAD.BASE);
    try std.testing.expectEqual(@as(u16, 3), NFTA_PAYLOAD.OFFSET);
    try std.testing.expectEqual(@as(u16, 4), NFTA_PAYLOAD.LEN);
    try std.testing.expectEqual(@as(u16, 1), NFTA_LOOKUP.SET);
    try std.testing.expectEqual(@as(u16, 2), NFTA_LOOKUP.SREG);
    try std.testing.expectEqual(@as(u16, 1), NFTA_IMMEDIATE.DREG);
    try std.testing.expectEqual(@as(u16, 2), NFTA_IMMEDIATE.DATA);
    try std.testing.expectEqual(@as(u16, 2), NFTA_DATA.VERDICT);
    try std.testing.expectEqual(@as(u16, 1), NFTA_VERDICT.CODE);

    try std.testing.expectEqual(@as(u32, 1), NF_INET_HOOK.LOCAL_IN);
    try std.testing.expectEqual(@as(u32, 0), NFT_REG.VERDICT);
    try std.testing.expectEqual(@as(u32, 1), NFT_REG.REG_1);
    try std.testing.expectEqual(@as(u32, 0), NF_VERDICT.DROP);
    try std.testing.expectEqual(@as(u32, 1), NF_VERDICT.ACCEPT);
    try std.testing.expectEqual(@as(u32, 1), NFT_PAYLOAD.NETWORK_HEADER);
}

test "nftables: buildChainPayload emits table + name + hook + type + policy" {
    var buf: [256]u8 = undefined;
    const out = try buildChainPayload(
        &buf,
        netlink.NFPROTO.INET,
        "fail2zig",
        "input",
        NF_INET_HOOK.LOCAL_IN,
        -1,
        "filter",
        NF_VERDICT.ACCEPT,
    );

    var seen_table = false;
    var seen_name = false;
    var seen_hook = false;
    var seen_type = false;
    var seen_policy = false;
    var hook_hooknum_ok = false;
    var hook_priority_ok = false;

    var i: usize = 4;
    while (i + 4 <= out.len) {
        const attr_len = mem.readInt(u16, out[i..][0..2], native_endian);
        const attr_type_raw = mem.readInt(u16, out[i + 2 ..][0..2], native_endian);
        const attr_type = attr_type_raw & ~NLA_F_NESTED;
        const payload_start = i + 4;
        const payload_end = i + attr_len;
        if (payload_end > out.len or attr_len < 4) break;
        const payload = out[payload_start..payload_end];

        switch (attr_type) {
            NFTA_CHAIN.TABLE => seen_table = true,
            NFTA_CHAIN.NAME => seen_name = true,
            NFTA_CHAIN.TYPE => seen_type = true,
            NFTA_CHAIN.POLICY => {
                seen_policy = true;
                try std.testing.expectEqual(NF_VERDICT.ACCEPT, mem.readInt(u32, payload[0..4], .big));
            },
            NFTA_CHAIN.HOOK => {
                seen_hook = true;
                var j: usize = 0;
                while (j + 4 <= payload.len) {
                    const sub_len = mem.readInt(u16, payload[j..][0..2], native_endian);
                    const sub_type = mem.readInt(u16, payload[j + 2 ..][0..2], native_endian) & ~NLA_F_NESTED;
                    if (sub_len < 8 or j + sub_len > payload.len) break;
                    const sub_payload = payload[j + 4 .. j + sub_len];
                    if (sub_type == NFTA_HOOK.HOOKNUM) {
                        hook_hooknum_ok = (mem.readInt(u32, sub_payload[0..4], .big) == NF_INET_HOOK.LOCAL_IN);
                    } else if (sub_type == NFTA_HOOK.PRIORITY) {
                        const raw = mem.readInt(u32, sub_payload[0..4], .big);
                        const signed: i32 = @bitCast(raw);
                        hook_priority_ok = (signed == -1);
                    }
                    j += nlaAlign(sub_len);
                }
            },
            else => {},
        }
        i += nlaAlign(attr_len);
    }

    try std.testing.expect(seen_table);
    try std.testing.expect(seen_name);
    try std.testing.expect(seen_hook);
    try std.testing.expect(seen_type);
    try std.testing.expect(seen_policy);
    try std.testing.expect(hook_hooknum_ok);
    try std.testing.expect(hook_priority_ok);
}

test "nftables: buildDropRulePayload references set and emits drop verdict" {
    var buf: [1024]u8 = undefined;
    const out = try buildDropRulePayload(
        &buf,
        netlink.NFPROTO.INET,
        "fail2zig",
        "input",
        "banned_ipv4",
        netlink.NFPROTO.IPV4,
        IPV4_SADDR_OFFSET,
        IPV4_SADDR_LEN,
    );

    const set_name = "banned_ipv4";
    var saw_set = false;
    var saw_drop = false;
    var saw_payload_expr = false;
    var saw_lookup_expr = false;
    var saw_immediate_expr = false;

    if (out.len >= set_name.len) {
        var i: usize = 0;
        while (i + set_name.len <= out.len) : (i += 1) {
            if (std.mem.eql(u8, out[i .. i + set_name.len], set_name)) {
                saw_set = true;
                break;
            }
        }
    }

    const verdict_sig = [_]u8{ 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 };
    if (out.len >= verdict_sig.len) {
        var i: usize = 0;
        while (i + verdict_sig.len <= out.len) : (i += 1) {
            if (std.mem.eql(u8, out[i .. i + verdict_sig.len], &verdict_sig)) {
                saw_drop = true;
                break;
            }
        }
    }

    const names = [_][]const u8{ "payload\x00", "lookup\x00", "immediate\x00" };
    var found = [_]bool{ false, false, false };
    for (names, 0..) |name, k| {
        var i: usize = 0;
        while (i + name.len <= out.len) : (i += 1) {
            if (std.mem.eql(u8, out[i .. i + name.len], name)) {
                found[k] = true;
                break;
            }
        }
    }
    saw_payload_expr = found[0];
    saw_lookup_expr = found[1];
    saw_immediate_expr = found[2];

    try std.testing.expect(saw_set);
    try std.testing.expect(saw_drop);
    try std.testing.expect(saw_payload_expr);
    try std.testing.expect(saw_lookup_expr);
    try std.testing.expect(saw_immediate_expr);
}

test "nftables: buildDropRulePayload emits meta+cmp nfproto guard (SYS-006 regression)" {
    var buf: [1024]u8 = undefined;
    const out_v4 = try buildDropRulePayload(
        &buf,
        netlink.NFPROTO.INET,
        "fail2zig",
        "input",
        "banned_ipv4",
        netlink.NFPROTO.IPV4,
        IPV4_SADDR_OFFSET,
        IPV4_SADDR_LEN,
    );

    const needed = [_][]const u8{ "meta\x00", "cmp\x00", "payload\x00", "lookup\x00", "immediate\x00" };
    for (needed) |name| {
        var found = false;
        var i: usize = 0;
        while (i + name.len <= out_v4.len) : (i += 1) {
            if (std.mem.eql(u8, out_v4[i .. i + name.len], name)) {
                found = true;
                break;
            }
        }
        try std.testing.expect(found);
    }

    const ipv4_sig = [_]u8{ 0x05, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00 };
    var saw_v4 = false;
    var i: usize = 0;
    while (i + ipv4_sig.len <= out_v4.len) : (i += 1) {
        if (std.mem.eql(u8, out_v4[i .. i + ipv4_sig.len], &ipv4_sig)) {
            saw_v4 = true;
            break;
        }
    }
    try std.testing.expect(saw_v4);

    var buf2: [1024]u8 = undefined;
    const out_v6 = try buildDropRulePayload(
        &buf2,
        netlink.NFPROTO.INET,
        "fail2zig",
        "input",
        "banned_ipv6",
        netlink.NFPROTO.IPV6,
        IPV6_SADDR_OFFSET,
        IPV6_SADDR_LEN,
    );
    const ipv6_sig = [_]u8{ 0x05, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x00, 0x00 };
    var saw_v6 = false;
    i = 0;
    while (i + ipv6_sig.len <= out_v6.len) : (i += 1) {
        if (std.mem.eql(u8, out_v6[i .. i + ipv6_sig.len], &ipv6_sig)) {
            saw_v6 = true;
            break;
        }
    }
    try std.testing.expect(saw_v6);
}

test "nftables: buildDropRulePayload IPv6 uses offset=8 and len=16" {
    var buf: [1024]u8 = undefined;
    const out = try buildDropRulePayload(
        &buf,
        netlink.NFPROTO.INET,
        "fail2zig",
        "input",
        "banned_ipv6",
        netlink.NFPROTO.IPV6,
        IPV6_SADDR_OFFSET,
        IPV6_SADDR_LEN,
    );
    const off_be = [_]u8{ 0x00, 0x00, 0x00, 0x08 };
    const len_be = [_]u8{ 0x00, 0x00, 0x00, 0x10 };
    var saw_off = false;
    var saw_len = false;
    var i: usize = 0;
    while (i + 4 <= out.len) : (i += 1) {
        if (!saw_off and std.mem.eql(u8, out[i .. i + 4], &off_be)) saw_off = true;
        if (!saw_len and std.mem.eql(u8, out[i .. i + 4], &len_be)) saw_len = true;
    }
    try std.testing.expect(saw_off);
    try std.testing.expect(saw_len);
}

test "nftables: buildSetPayload omits NFTA_SET_TIMEOUT when timeout is 0 (SYS-003 regression)" {
    var buf: [256]u8 = undefined;
    const out = try buildSetPayload(
        &buf,
        netlink.NFPROTO.INET,
        "fail2zig",
        "banned_ipv4",
        1,
        NFT_TYPE.IPV4_ADDR,
        4,
        0,
    );

    var saw_timeout = false;
    var saw_id = false;
    var i: usize = 4;
    while (i + 4 <= out.len) {
        const attr_len = mem.readInt(u16, out[i..][0..2], native_endian);
        const attr_type = mem.readInt(u16, out[i + 2 ..][0..2], native_endian) & ~NLA_F_NESTED;
        if (attr_len < 4) break;
        if (attr_type == NFTA_SET.TIMEOUT) saw_timeout = true;
        if (attr_type == NFTA_SET.ID) saw_id = true;
        i += nlaAlign(attr_len);
    }
    try std.testing.expect(!saw_timeout);
    try std.testing.expect(saw_id);
}

test "nftables: buildDeleteTablePayload matches buildTablePayload shape" {
    var a: [64]u8 = undefined;
    var b: [64]u8 = undefined;
    const new_payload = try buildTablePayload(&a, netlink.NFPROTO.INET, "fail2zig");
    const del_payload = try buildDeleteTablePayload(&b, netlink.NFPROTO.INET, "fail2zig");
    try std.testing.expectEqualSlices(u8, new_payload, del_payload);
}

test "nftables: appendAttr emits correct TLV layout" {
    var buf: [32]u8 = undefined;
    const end = try appendAttr(&buf, 0, NFTA_TABLE.NAME, "abc");
    try std.testing.expectEqual(@as(usize, 8), end);
    try std.testing.expectEqual(@as(u16, 7), mem.readInt(u16, buf[0..2], native_endian));
    try std.testing.expectEqual(@as(u16, NFTA_TABLE.NAME), mem.readInt(u16, buf[2..4], native_endian));
    try std.testing.expectEqualSlices(u8, "abc", buf[4..7]);
    try std.testing.expectEqual(@as(u8, 0), buf[7]);
}

test "nftables: appendStringNul includes terminating NUL" {
    var buf: [16]u8 = undefined;
    const end = try appendStringNul(&buf, 0, NFTA_TABLE.NAME, "ab");
    try std.testing.expectEqual(@as(usize, 8), end);
    try std.testing.expectEqual(@as(u16, 7), mem.readInt(u16, buf[0..2], native_endian));
    try std.testing.expectEqualStrings("ab", buf[4..6]);
    try std.testing.expectEqual(@as(u8, 0), buf[6]);
}

test "nftables: appendU32BE writes network byte order" {
    var buf: [16]u8 = undefined;
    const end = try appendU32BE(&buf, 0, NFTA_SET.KEY_TYPE, NFT_TYPE.IPV4_ADDR);
    try std.testing.expectEqual(@as(usize, 8), end);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00, 0x00, 0x07 }, buf[4..8]);
}

test "nftables: buildTablePayload contains nfgenmsg + name TLV" {
    var buf: [64]u8 = undefined;
    const out = try buildTablePayload(&buf, netlink.NFPROTO.INET, "fail2zig");

    try std.testing.expectEqual(@as(u8, netlink.NFPROTO.INET), out[0]);
    try std.testing.expectEqual(@as(u8, 0), out[1]);
    try std.testing.expectEqual(@as(u16, 0), mem.readInt(u16, out[2..4], .big));

    const tlv_len = mem.readInt(u16, out[4..6], native_endian);
    const tlv_type = mem.readInt(u16, out[6..8], native_endian);
    try std.testing.expectEqual(@as(u16, NFTA_TABLE.NAME), tlv_type);
    try std.testing.expectEqual(@as(u16, 4 + 9), tlv_len);
    try std.testing.expectEqualStrings("fail2zig", out[8..16]);
    try std.testing.expectEqual(@as(u8, 0), out[16]);
}

test "nftables: buildSetPayload sets TIMEOUT flag and correct key type" {
    var buf: [128]u8 = undefined;
    const out = try buildSetPayload(
        &buf,
        netlink.NFPROTO.INET,
        "fail2zig",
        "banned_ipv4",
        42,
        NFT_TYPE.IPV4_ADDR,
        4,
        600_000,
    );

    var seen_flags = false;
    var seen_key_type = false;
    var seen_key_len = false;
    var seen_timeout = false;
    var seen_table = false;
    var seen_name = false;
    var i: usize = 4;
    while (i + 4 <= out.len) {
        const attr_len = mem.readInt(u16, out[i..][0..2], native_endian);
        const attr_type = mem.readInt(u16, out[i + 2 ..][0..2], native_endian);
        const payload_start = i + 4;
        const payload_end = i + attr_len;
        if (payload_end > out.len) break;
        const payload = out[payload_start..payload_end];
        switch (attr_type) {
            NFTA_SET.TABLE => seen_table = true,
            NFTA_SET.NAME => seen_name = true,
            NFTA_SET.FLAGS => {
                seen_flags = true;
                try std.testing.expectEqual(
                    NFT_SET_TIMEOUT,
                    mem.readInt(u32, payload[0..4], .big),
                );
            },
            NFTA_SET.KEY_TYPE => {
                seen_key_type = true;
                try std.testing.expectEqual(
                    NFT_TYPE.IPV4_ADDR,
                    mem.readInt(u32, payload[0..4], .big),
                );
            },
            NFTA_SET.KEY_LEN => {
                seen_key_len = true;
                try std.testing.expectEqual(@as(u32, 4), mem.readInt(u32, payload[0..4], .big));
            },
            NFTA_SET.TIMEOUT => {
                seen_timeout = true;
                try std.testing.expectEqual(
                    @as(u64, 600_000),
                    mem.readInt(u64, payload[0..8], .big),
                );
            },
            else => {},
        }
        i += nlaAlign(attr_len);
    }
    try std.testing.expect(seen_table);
    try std.testing.expect(seen_name);
    try std.testing.expect(seen_flags);
    try std.testing.expect(seen_key_type);
    try std.testing.expect(seen_key_len);
    try std.testing.expect(seen_timeout);
}

test "nftables: buildSetElemAddPayload for IPv4 carries big-endian key + timeout" {
    var buf: [256]u8 = undefined;
    var key: [4]u8 = undefined;
    mem.writeInt(u32, &key, 0xC0A80101, .big);
    const out = try buildSetElemAddPayload(
        &buf,
        netlink.NFPROTO.INET,
        "fail2zig",
        "banned_ipv4",
        &key,
        30_000,
    );
    var hits: usize = 0;
    if (out.len >= 4) {
        var i: usize = 0;
        while (i + 4 <= out.len) : (i += 1) {
            if (out[i] == 0xC0 and out[i + 1] == 0xA8 and out[i + 2] == 0x01 and out[i + 3] == 0x01) {
                hits += 1;
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 1), hits);

    var timeout_hits: usize = 0;
    if (out.len >= 8) {
        var i: usize = 0;
        while (i + 8 <= out.len) : (i += 1) {
            if (mem.readInt(u64, out[i..][0..8], .big) == 30_000) timeout_hits += 1;
        }
    }
    try std.testing.expect(timeout_hits >= 1);
}

test "nftables: buildSetElemAddPayload for IPv6 emits 16-byte key" {
    var buf: [256]u8 = undefined;
    var key: [16]u8 = undefined;
    mem.writeInt(u128, &key, 1, .big);
    const out = try buildSetElemAddPayload(
        &buf,
        netlink.NFPROTO.INET,
        "fail2zig",
        "banned_ipv6",
        &key,
        60_000,
    );
    var saw_key = false;
    var i: usize = 0;
    while (i + 4 + 16 <= out.len) : (i += 1) {
        const attr_len = mem.readInt(u16, out[i..][0..2], native_endian);
        const attr_type = mem.readInt(u16, out[i + 2 ..][0..2], native_endian) & ~NLA_F_NESTED;
        if (attr_type != NFTA_DATA_VALUE or attr_len != 4 + 16) continue;
        const payload = out[i + 4 .. i + 4 + 16];
        var all_zero_except_last = true;
        for (payload[0..15]) |b| if (b != 0) {
            all_zero_except_last = false;
        };
        if (all_zero_except_last and payload[15] == 1) {
            saw_key = true;
            break;
        }
    }
    try std.testing.expect(saw_key);
}

test "nftables: buildSetElemDelPayload omits timeout attribute" {
    var buf: [256]u8 = undefined;
    var key: [4]u8 = undefined;
    mem.writeInt(u32, &key, 0x0A000001, .big);
    const out = try buildSetElemDelPayload(
        &buf,
        netlink.NFPROTO.INET,
        "fail2zig",
        "banned_ipv4",
        &key,
    );
    var contains_timeout = false;
    var i: usize = 4;
    while (i + 4 <= out.len) {
        const attr_len = mem.readInt(u16, out[i..][0..2], native_endian);
        const attr_type = mem.readInt(u16, out[i + 2 ..][0..2], native_endian) & ~NLA_F_NESTED;
        if (attr_type == NFTA_SET_ELEM.TIMEOUT and attr_len == 12) contains_timeout = true;
        if (attr_len < 4) break;
        i += nlaAlign(attr_len);
    }
    try std.testing.expect(!contains_timeout);
}

test "nftables: NftablesBackend uninit ban returns NotAvailable" {
    var be: backend.Backend = .{ .nftables = NftablesBackend{} };
    const ip = try shared.IpAddress.parse("1.2.3.4");
    const jail = try shared.JailId.fromSlice("sshd");
    try std.testing.expectError(error.NotAvailable, be.ban(ip, jail, 600));
}

test "nftables: isAvailable on zeroed struct reports probeAvailable result" {
    var be = NftablesBackend{};
    const got = isAvailableImpl(@ptrCast(&be));
    try std.testing.expectEqual(probeAvailable(), got);
}

test "nftables: probeAvailable agrees with probeReason (SYS-014)" {
    const reason = probeReason();
    try std.testing.expectEqual(reason == .available, probeAvailable());
}

test "nftables: probe maps each netlink init failure to its cause (SYS-014)" {
    try std.testing.expectEqual(ProbeResult.kernel_unsupported, probeReasonFromInitError(error.ProtocolUnsupported));
    try std.testing.expectEqual(ProbeResult.permission_denied, probeReasonFromInitError(error.PermissionDenied));
    try std.testing.expectEqual(ProbeResult.transient, probeReasonFromInitError(error.SocketFailed));
    try std.testing.expectEqual(ProbeResult.transient, probeReasonFromInitError(error.Timeout));
}

test "nftables: probe maps each GETGEN ack failure to its cause (SYS-022)" {
    try std.testing.expectEqual(ProbeResult.permission_denied, probeReasonFromAckError(error.PermissionDenied));
    try std.testing.expectEqual(ProbeResult.kernel_unsupported, probeReasonFromAckError(error.InvalidArgument));
    try std.testing.expectEqual(ProbeResult.transient, probeReasonFromAckError(error.Timeout));
    try std.testing.expectEqual(ProbeResult.transient, probeReasonFromAckError(error.NetlinkError));
}

test "nftables: netlink EPERM maps to BackendError.PermissionDenied (SYS-022)" {
    try std.testing.expectEqual(backend.BackendError.PermissionDenied, mapNetlinkErr(error.PermissionDenied));
    try std.testing.expectEqual(backend.BackendError.NotAvailable, mapNetlinkErr(error.ProtocolUnsupported));
}

test "nftables: probe without CAP_NET_ADMIN reports permission_denied (SYS-022)" {
    if (testHasCapNetAdmin()) return error.SkipZigTest;
    try std.testing.expectEqual(ProbeResult.permission_denied, probeReason());
}

test "nftables: probe with CAP_NET_ADMIN never reports permission_denied (SYS-022)" {
    if (!testHasCapNetAdmin()) return error.SkipZigTest;
    try std.testing.expect(probeReason() != .permission_denied);
}

fn testHasCapNetAdmin() bool {
    if (linux.geteuid() == 0) return true;
    var buf: [4096]u8 = undefined;
    const status = std.fs.cwd().readFile("/proc/self/status", &buf) catch return false;
    var lines = std.mem.splitScalar(u8, status, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "CapEff:")) continue;
        const hex = std.mem.trim(u8, line["CapEff:".len..], " \t");
        const caps = std.fmt.parseInt(u64, hex, 16) catch return false;
        return (caps >> linux.CAP.NET_ADMIN) & 1 == 1;
    }
    return false;
}

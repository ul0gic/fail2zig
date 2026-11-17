// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Defines the nf_tables netlink numbers and encodes the table, set, chain, rule and set-element message payloads.
// Holds: Every attribute and payload writer checks the remaining buffer first and returns BufferTooSmall instead of writing past it.

const std = @import("std");
const native_endian = @import("builtin").cpu.arch.endian();
const mem = std.mem;

const netlink = @import("netlink.zig");
const canonical = @import("scope.zig");

// Why: Unless marked otherwise, the numbers below are from include/uapi/linux/netfilter/nf_tables.h.
pub const NFT_MSG = struct {
    pub const NEWTABLE: u16 = 0;
    pub const GETTABLE: u16 = 1;
    pub const DELTABLE: u16 = 2;
    pub const NEWCHAIN: u16 = 3;
    pub const GETCHAIN: u16 = 4;
    pub const NEWRULE: u16 = 6;
    pub const GETRULE: u16 = 7;
    pub const DELRULE: u16 = 8;
    pub const NEWSET: u16 = 9;
    pub const GETSET: u16 = 10;
    pub const NEWSETELEM: u16 = 12;
    pub const GETSETELEM: u16 = 13;
    pub const DELSETELEM: u16 = 14;
    pub const NEWGEN: u16 = 15;
    pub const GETGEN: u16 = 16;
};

pub const NFTA_TABLE = struct {
    pub const NAME: u16 = 1;
    pub const FLAGS: u16 = 2;
};

pub const NFTA_CHAIN = struct {
    pub const TABLE: u16 = 1;
    pub const NAME: u16 = 3;
    pub const HOOK: u16 = 4;
    pub const POLICY: u16 = 5;
    pub const TYPE: u16 = 7;
};

pub const NFTA_HOOK = struct {
    pub const HOOKNUM: u16 = 1;
    pub const PRIORITY: u16 = 2;
};

pub const NFTA_SET = struct {
    pub const TABLE: u16 = 1;
    pub const NAME: u16 = 2;
    pub const FLAGS: u16 = 3;
    pub const KEY_TYPE: u16 = 4;
    pub const KEY_LEN: u16 = 5;
    pub const ID: u16 = 10;
    pub const TIMEOUT: u16 = 11;
};

pub const NFTA_SET_ELEM_LIST = struct {
    pub const TABLE: u16 = 1;
    pub const SET: u16 = 2;
    pub const ELEMENTS: u16 = 3;
};

pub const NFTA_LIST_ELEM: u16 = 1;

pub const NFTA_SET_ELEM = struct {
    pub const KEY: u16 = 1;
    pub const FLAGS: u16 = 3;
    pub const TIMEOUT: u16 = 4;
};

pub const NFTA_GEN = struct {
    pub const ID: u16 = 1;
};

pub const NFTA_DATA_VALUE: u16 = 1;

pub const NLA_F_NESTED: u16 = 1 << 15;

pub const NFT_SET_TIMEOUT: u32 = 16;

// Why: Key types are nft userspace datatype ids (TYPE_IPADDR, TYPE_IP6ADDR in nftables' include/datatype.h), not kernel values.
pub const NFT_TYPE = struct {
    pub const IPV4_ADDR: u32 = 7;
    pub const IPV6_ADDR: u32 = 8;
};

// Why: Hook numbers from include/uapi/linux/netfilter.h.
pub const NF_INET_HOOK = struct {
    pub const LOCAL_IN: u32 = 1;
    pub const FORWARD: u32 = 2;
};

pub const NFTA_RULE = struct {
    pub const TABLE: u16 = 1;
    pub const CHAIN: u16 = 2;
    pub const HANDLE: u16 = 3;
    pub const EXPRESSIONS: u16 = 4;
    pub const USERDATA: u16 = 7;
};

pub const NFTA_EXPR = struct {
    pub const NAME: u16 = 1;
    pub const DATA: u16 = 2;
};

pub const NFTA_PAYLOAD = struct {
    pub const DREG: u16 = 1;
    pub const BASE: u16 = 2;
    pub const OFFSET: u16 = 3;
    pub const LEN: u16 = 4;
};

pub const NFTA_LOOKUP = struct {
    pub const SET: u16 = 1;
    pub const SREG: u16 = 2;
};

pub const NFTA_IMMEDIATE = struct {
    pub const DREG: u16 = 1;
    pub const DATA: u16 = 2;
};

pub const NFTA_DATA = struct {
    pub const VALUE: u16 = 1;
    pub const VERDICT: u16 = 2;
};

pub const NFTA_VERDICT = struct {
    pub const CODE: u16 = 1;
};

pub const NFTA_META = struct {
    pub const DREG: u16 = 1;
    pub const KEY: u16 = 2;
};

pub const NFT_META = struct {
    pub const NFPROTO: u32 = 15;
    pub const L4PROTO: u32 = 16;
};

pub const NFTA_CMP = struct {
    pub const SREG: u16 = 1;
    pub const OP: u16 = 2;
    pub const DATA: u16 = 3;
};

pub const NFT_CMP = struct {
    pub const EQ: u32 = 0;
    pub const LTE: u32 = 3;
    pub const GTE: u32 = 5;
};

pub const NFTA_BITWISE = struct {
    pub const SREG: u16 = 1;
    pub const DREG: u16 = 2;
    pub const LEN: u16 = 3;
    pub const MASK: u16 = 4;
    pub const XOR: u16 = 5;
};

pub const NFT_PAYLOAD = struct {
    pub const NETWORK_HEADER: u32 = 1;
    pub const TRANSPORT_HEADER: u32 = 2;
};

pub const NFT_REG = struct {
    pub const VERDICT: u32 = 0;
    pub const REG_1: u32 = 1;
};

// Why: NF_DROP and NF_ACCEPT from include/uapi/linux/netfilter.h.
pub const NF_VERDICT = struct {
    pub const DROP: u32 = 0;
    pub const ACCEPT: u32 = 1;
};

// Why: Source address offsets in the IPv4 header (RFC 791 section 3.1) and the IPv6 header (RFC 8200 section 3).
pub const IPV4_SADDR_OFFSET: u32 = 12;
pub const IPV4_SADDR_LEN: u32 = 4;
pub const IPV6_SADDR_OFFSET: u32 = 8;
pub const IPV6_SADDR_LEN: u32 = 16;

// Why: Attribute alignment and header length from include/uapi/linux/netlink.h.
const NLA_ALIGNTO: usize = 4;
const NLA_HDRLEN: usize = 4;

pub fn nlaAlign(len: usize) usize {
    return (len + NLA_ALIGNTO - 1) & ~@as(usize, NLA_ALIGNTO - 1);
}

pub fn appendAttr(
    buf: []u8,
    offset: usize,
    attr_type: u16,
    value: []const u8,
) netlink.Error!usize {
    const total = NLA_HDRLEN + value.len;
    const aligned = nlaAlign(total);
    if (offset + aligned > buf.len) return error.BufferTooSmall;
    mem.writeInt(u16, buf[offset..][0..2], @intCast(total), native_endian);
    mem.writeInt(u16, buf[offset + 2 ..][0..2], attr_type, native_endian);
    if (value.len > 0) {
        @memcpy(buf[offset + NLA_HDRLEN .. offset + total], value);
    }
    if (aligned > total) {
        @memset(buf[offset + total .. offset + aligned], 0);
    }
    return offset + aligned;
}

pub fn appendU32BE(
    buf: []u8,
    offset: usize,
    attr_type: u16,
    value: u32,
) netlink.Error!usize {
    var bytes: [4]u8 = undefined;
    mem.writeInt(u32, &bytes, value, .big);
    return appendAttr(buf, offset, attr_type, &bytes);
}

fn appendU64BE(
    buf: []u8,
    offset: usize,
    attr_type: u16,
    value: u64,
) netlink.Error!usize {
    var bytes: [8]u8 = undefined;
    mem.writeInt(u64, &bytes, value, .big);
    return appendAttr(buf, offset, attr_type, &bytes);
}

pub fn appendStringNul(
    buf: []u8,
    offset: usize,
    attr_type: u16,
    str: []const u8,
) netlink.Error!usize {
    const total = NLA_HDRLEN + str.len + 1;
    const aligned = nlaAlign(total);
    if (offset + aligned > buf.len) return error.BufferTooSmall;
    mem.writeInt(u16, buf[offset..][0..2], @intCast(total), native_endian);
    mem.writeInt(u16, buf[offset + 2 ..][0..2], attr_type, native_endian);
    @memcpy(buf[offset + NLA_HDRLEN .. offset + NLA_HDRLEN + str.len], str);
    buf[offset + NLA_HDRLEN + str.len] = 0;
    if (aligned > total) {
        @memset(buf[offset + total .. offset + aligned], 0);
    }
    return offset + aligned;
}

fn beginNested(
    buf: []u8,
    offset: usize,
    attr_type: u16,
) netlink.Error!usize {
    if (offset + NLA_HDRLEN > buf.len) return error.BufferTooSmall;
    mem.writeInt(u16, buf[offset..][0..2], 0, native_endian);
    mem.writeInt(u16, buf[offset + 2 ..][0..2], attr_type | NLA_F_NESTED, native_endian);
    return offset + NLA_HDRLEN;
}

fn endNested(buf: []u8, header_offset: usize, cur_offset: usize) netlink.Error!usize {
    const inner_len = cur_offset - header_offset;
    const total = NLA_HDRLEN + inner_len;
    const aligned = nlaAlign(total);
    mem.writeInt(u16, buf[header_offset - NLA_HDRLEN ..][0..2], @intCast(total), native_endian);
    if (aligned > total) {
        if (cur_offset + (aligned - total) > buf.len) return error.BufferTooSmall;
        @memset(buf[cur_offset .. cur_offset + (aligned - total)], 0);
        return cur_offset + (aligned - total);
    }
    return cur_offset;
}

pub fn buildTablePayload(
    buf: []u8,
    family: u8,
    table_name: []const u8,
) netlink.Error![]const u8 {
    if (buf.len < @sizeOf(netlink.nfgenmsg)) return error.BufferTooSmall;
    const ng: *netlink.nfgenmsg = @alignCast(@ptrCast(&buf[0]));
    ng.* = .{ .nfgen_family = family, .version = 0, .res_id = 0 };
    var offset: usize = @sizeOf(netlink.nfgenmsg);
    offset = try appendStringNul(buf, offset, NFTA_TABLE.NAME, table_name);
    return buf[0..offset];
}

pub fn buildSetQueryPayload(buf: []u8, table_name: []const u8, set_name: []const u8) netlink.Error![]const u8 {
    if (buf.len < @sizeOf(netlink.nfgenmsg)) return error.BufferTooSmall;
    const header = netlink.nfgenmsg{ .nfgen_family = netlink.NFPROTO.INET, .version = 0, .res_id = 0 };
    @memcpy(buf[0..@sizeOf(netlink.nfgenmsg)], mem.asBytes(&header));
    var offset: usize = @sizeOf(netlink.nfgenmsg);
    offset = try appendStringNul(buf, offset, NFTA_SET_ELEM_LIST.TABLE, table_name);
    offset = try appendStringNul(buf, offset, NFTA_SET_ELEM_LIST.SET, set_name);
    return buf[0..offset];
}

pub fn buildOwnedTablePayload(buf: []u8, table_name: []const u8, marker: []const u8) netlink.Error![]const u8 {
    const base = try buildTablePayload(buf, netlink.NFPROTO.INET, table_name);
    // Why: Attribute 6 is NFTA_TABLE_USERDATA; the readback refuses a table under this name without the same marker there.
    const end = try appendAttr(buf, base.len, 6, marker);
    return buf[0..end];
}

pub fn buildSetPayload(
    buf: []u8,
    family: u8,
    table_name: []const u8,
    set_name: []const u8,
    set_id: u32,
    key_type: u32,
    key_len: u32,
    default_timeout_ms: u64,
) netlink.Error![]const u8 {
    if (buf.len < @sizeOf(netlink.nfgenmsg)) return error.BufferTooSmall;
    const ng: *netlink.nfgenmsg = @alignCast(@ptrCast(&buf[0]));
    ng.* = .{ .nfgen_family = family, .version = 0, .res_id = 0 };
    var offset: usize = @sizeOf(netlink.nfgenmsg);
    offset = try appendStringNul(buf, offset, NFTA_SET.TABLE, table_name);
    offset = try appendStringNul(buf, offset, NFTA_SET.NAME, set_name);
    offset = try appendU32BE(buf, offset, NFTA_SET.FLAGS, NFT_SET_TIMEOUT);
    offset = try appendU32BE(buf, offset, NFTA_SET.KEY_TYPE, key_type);
    offset = try appendU32BE(buf, offset, NFTA_SET.KEY_LEN, key_len);
    offset = try appendU32BE(buf, offset, NFTA_SET.ID, set_id);
    if (default_timeout_ms > 0) {
        offset = try appendU64BE(buf, offset, NFTA_SET.TIMEOUT, default_timeout_ms);
    }
    return buf[0..offset];
}

pub fn buildSetElemAddPayload(
    buf: []u8,
    family: u8,
    table_name: []const u8,
    set_name: []const u8,
    key_bytes: []const u8,
    timeout_ms: u64,
) netlink.Error![]const u8 {
    return buildSetElemPayload(buf, family, table_name, set_name, key_bytes, timeout_ms);
}

pub fn buildSetElemDelPayload(
    buf: []u8,
    family: u8,
    table_name: []const u8,
    set_name: []const u8,
    key_bytes: []const u8,
) netlink.Error![]const u8 {
    return buildSetElemPayload(buf, family, table_name, set_name, key_bytes, 0);
}

pub fn buildDeleteTablePayload(
    buf: []u8,
    family: u8,
    table_name: []const u8,
) netlink.Error![]const u8 {
    return buildTablePayload(buf, family, table_name);
}

pub fn buildChainPayload(
    buf: []u8,
    family: u8,
    table_name: []const u8,
    chain_name: []const u8,
    hooknum: u32,
    priority: i32,
    chain_type: []const u8,
    policy: u32,
) netlink.Error![]const u8 {
    if (buf.len < @sizeOf(netlink.nfgenmsg)) return error.BufferTooSmall;
    const ng: *netlink.nfgenmsg = @alignCast(@ptrCast(&buf[0]));
    ng.* = .{ .nfgen_family = family, .version = 0, .res_id = 0 };
    var offset: usize = @sizeOf(netlink.nfgenmsg);

    offset = try appendStringNul(buf, offset, NFTA_CHAIN.TABLE, table_name);
    offset = try appendStringNul(buf, offset, NFTA_CHAIN.NAME, chain_name);

    const hook_start = try beginNested(buf, offset, NFTA_CHAIN.HOOK);
    offset = hook_start;
    offset = try appendU32BE(buf, offset, NFTA_HOOK.HOOKNUM, hooknum);
    offset = try appendU32BE(buf, offset, NFTA_HOOK.PRIORITY, @bitCast(priority));
    offset = try endNested(buf, hook_start, offset);

    offset = try appendStringNul(buf, offset, NFTA_CHAIN.TYPE, chain_type);
    offset = try appendU32BE(buf, offset, NFTA_CHAIN.POLICY, policy);
    return buf[0..offset];
}

pub fn buildDropRulePayload(
    buf: []u8,
    family: u8,
    table_name: []const u8,
    chain_name: []const u8,
    set_name: []const u8,
    nfproto: u8,
    saddr_offset: u32,
    saddr_len: u32,
) netlink.Error![]const u8 {
    if (buf.len < @sizeOf(netlink.nfgenmsg)) return error.BufferTooSmall;
    const ng: *netlink.nfgenmsg = @alignCast(@ptrCast(&buf[0]));
    ng.* = .{ .nfgen_family = family, .version = 0, .res_id = 0 };
    var offset: usize = @sizeOf(netlink.nfgenmsg);

    offset = try appendStringNul(buf, offset, NFTA_RULE.TABLE, table_name);
    offset = try appendStringNul(buf, offset, NFTA_RULE.CHAIN, chain_name);

    const exprs_start = try beginNested(buf, offset, NFTA_RULE.EXPRESSIONS);
    offset = exprs_start;

    const e0_start = try beginNested(buf, offset, NFTA_LIST_ELEM);
    offset = e0_start;
    offset = try appendStringNul(buf, offset, NFTA_EXPR.NAME, "meta");
    const e0_data = try beginNested(buf, offset, NFTA_EXPR.DATA);
    offset = e0_data;
    offset = try appendU32BE(buf, offset, NFTA_META.DREG, NFT_REG.REG_1);
    offset = try appendU32BE(buf, offset, NFTA_META.KEY, NFT_META.NFPROTO);
    offset = try endNested(buf, e0_data, offset);
    offset = try endNested(buf, e0_start, offset);

    const e1_start = try beginNested(buf, offset, NFTA_LIST_ELEM);
    offset = e1_start;
    offset = try appendStringNul(buf, offset, NFTA_EXPR.NAME, "cmp");
    const e1_data = try beginNested(buf, offset, NFTA_EXPR.DATA);
    offset = e1_data;
    offset = try appendU32BE(buf, offset, NFTA_CMP.SREG, NFT_REG.REG_1);
    offset = try appendU32BE(buf, offset, NFTA_CMP.OP, NFT_CMP.EQ);
    const cmp_data_attr = try beginNested(buf, offset, NFTA_CMP.DATA);
    offset = cmp_data_attr;
    offset = try appendAttr(buf, offset, NFTA_DATA.VALUE, &[_]u8{nfproto});
    offset = try endNested(buf, cmp_data_attr, offset);
    offset = try endNested(buf, e1_data, offset);
    offset = try endNested(buf, e1_start, offset);

    const e2_start = try beginNested(buf, offset, NFTA_LIST_ELEM);
    offset = e2_start;
    offset = try appendStringNul(buf, offset, NFTA_EXPR.NAME, "payload");
    const e2_data = try beginNested(buf, offset, NFTA_EXPR.DATA);
    offset = e2_data;
    offset = try appendU32BE(buf, offset, NFTA_PAYLOAD.DREG, NFT_REG.REG_1);
    offset = try appendU32BE(buf, offset, NFTA_PAYLOAD.BASE, NFT_PAYLOAD.NETWORK_HEADER);
    offset = try appendU32BE(buf, offset, NFTA_PAYLOAD.OFFSET, saddr_offset);
    offset = try appendU32BE(buf, offset, NFTA_PAYLOAD.LEN, saddr_len);
    offset = try endNested(buf, e2_data, offset);
    offset = try endNested(buf, e2_start, offset);

    const e3_start = try beginNested(buf, offset, NFTA_LIST_ELEM);
    offset = e3_start;
    offset = try appendStringNul(buf, offset, NFTA_EXPR.NAME, "lookup");
    const e3_data = try beginNested(buf, offset, NFTA_EXPR.DATA);
    offset = e3_data;
    offset = try appendStringNul(buf, offset, NFTA_LOOKUP.SET, set_name);
    offset = try appendU32BE(buf, offset, NFTA_LOOKUP.SREG, NFT_REG.REG_1);
    offset = try endNested(buf, e3_data, offset);
    offset = try endNested(buf, e3_start, offset);

    const e4_start = try beginNested(buf, offset, NFTA_LIST_ELEM);
    offset = e4_start;
    offset = try appendStringNul(buf, offset, NFTA_EXPR.NAME, "immediate");
    const e4_data = try beginNested(buf, offset, NFTA_EXPR.DATA);
    offset = e4_data;
    offset = try appendU32BE(buf, offset, NFTA_IMMEDIATE.DREG, NFT_REG.VERDICT);
    const e4_data_attr = try beginNested(buf, offset, NFTA_IMMEDIATE.DATA);
    offset = e4_data_attr;
    const verdict_outer = try beginNested(buf, offset, NFTA_DATA.VERDICT);
    offset = verdict_outer;
    offset = try appendU32BE(buf, offset, NFTA_VERDICT.CODE, NF_VERDICT.DROP);
    offset = try endNested(buf, verdict_outer, offset);
    offset = try endNested(buf, e4_data_attr, offset);
    offset = try endNested(buf, e4_data, offset);
    offset = try endNested(buf, e4_start, offset);

    offset = try endNested(buf, exprs_start, offset);
    return buf[0..offset];
}

pub const max_scope_rule_parts: usize = 30;
pub const ScopeBuildError = netlink.Error || canonical.Error || error{InvalidRulePart};
pub const RulePart = struct { protocol: ?canonical.Protocol, port: ?canonical.PortRange };

pub fn scopeRulePartCount(scope: canonical.Scope) ScopeBuildError!usize {
    try scope.validate();
    const protocols: usize = if (scope.protocols.isAll()) 1 else blk: {
        var count: usize = 0;
        inline for (.{ canonical.Protocol.tcp, .udp, .icmp_v4, .icmp_v6 }) |value|
            count += @intFromBool(scope.protocols.contains(value));
        break :blk count;
    };
    const ports: usize = if (scope.ports.isAll()) 1 else scope.ports.len;
    const count = std.math.mul(usize, protocols, ports) catch return error.InvalidRulePart;
    if (count == 0 or count > max_scope_rule_parts) return error.InvalidRulePart;
    return count;
}

pub fn scopeRulePart(scope: canonical.Scope, wanted: usize) ScopeBuildError!RulePart {
    const count = try scopeRulePartCount(scope);
    if (wanted >= count) return error.InvalidRulePart;
    var protocols: [4]?canonical.Protocol = @splat(null);
    var protocol_count: usize = 0;
    if (scope.protocols.isAll()) {
        protocol_count = 1;
    } else {
        inline for (.{ canonical.Protocol.tcp, .udp, .icmp_v4, .icmp_v6 }) |value| {
            if (scope.protocols.contains(value)) {
                protocols[protocol_count] = value;
                protocol_count += 1;
            }
        }
    }
    const port_count: usize = if (scope.ports.isAll()) 1 else scope.ports.len;
    const protocol_index = wanted / port_count;
    const port_index = wanted % port_count;
    return .{
        .protocol = if (scope.protocols.isAll()) null else protocols[protocol_index],
        .port = if (scope.ports.isAll()) null else scope.ports.ranges[port_index],
    };
}

fn appendExpressionStart(buf: []u8, offset: usize, name: []const u8) netlink.Error!struct { list: usize, data: usize, offset: usize } {
    const list = try beginNested(buf, offset, NFTA_LIST_ELEM);
    var next = try appendStringNul(buf, list, NFTA_EXPR.NAME, name);
    const data = try beginNested(buf, next, NFTA_EXPR.DATA);
    next = data;
    return .{ .list = list, .data = data, .offset = next };
}

fn appendExpressionEnd(buf: []u8, value: anytype) netlink.Error!usize {
    const data_end = try endNested(buf, value.data, value.offset);
    return endNested(buf, value.list, data_end);
}

fn appendMetaLoad(buf: []u8, offset: usize, key: u32) netlink.Error!usize {
    var expression = try appendExpressionStart(buf, offset, "meta");
    expression.offset = try appendU32BE(buf, expression.offset, NFTA_META.DREG, NFT_REG.REG_1);
    expression.offset = try appendU32BE(buf, expression.offset, NFTA_META.KEY, key);
    return appendExpressionEnd(buf, expression);
}

fn appendPayloadLoad(buf: []u8, offset: usize, base: u32, at: u32, len: u32) netlink.Error!usize {
    var expression = try appendExpressionStart(buf, offset, "payload");
    expression.offset = try appendU32BE(buf, expression.offset, NFTA_PAYLOAD.DREG, NFT_REG.REG_1);
    expression.offset = try appendU32BE(buf, expression.offset, NFTA_PAYLOAD.BASE, base);
    expression.offset = try appendU32BE(buf, expression.offset, NFTA_PAYLOAD.OFFSET, at);
    expression.offset = try appendU32BE(buf, expression.offset, NFTA_PAYLOAD.LEN, len);
    return appendExpressionEnd(buf, expression);
}

fn appendCompare(buf: []u8, offset: usize, operation: u32, value: []const u8) netlink.Error!usize {
    var expression = try appendExpressionStart(buf, offset, "cmp");
    expression.offset = try appendU32BE(buf, expression.offset, NFTA_CMP.SREG, NFT_REG.REG_1);
    expression.offset = try appendU32BE(buf, expression.offset, NFTA_CMP.OP, operation);
    const data = try beginNested(buf, expression.offset, NFTA_CMP.DATA);
    expression.offset = try appendAttr(buf, data, NFTA_DATA.VALUE, value);
    expression.offset = try endNested(buf, data, expression.offset);
    return appendExpressionEnd(buf, expression);
}

fn appendBitwiseMask(buf: []u8, offset: usize, mask: []const u8) netlink.Error!usize {
    var expression = try appendExpressionStart(buf, offset, "bitwise");
    expression.offset = try appendU32BE(buf, expression.offset, NFTA_BITWISE.SREG, NFT_REG.REG_1);
    expression.offset = try appendU32BE(buf, expression.offset, NFTA_BITWISE.DREG, NFT_REG.REG_1);
    expression.offset = try appendU32BE(buf, expression.offset, NFTA_BITWISE.LEN, @intCast(mask.len));
    const mask_data = try beginNested(buf, expression.offset, NFTA_BITWISE.MASK);
    expression.offset = try appendAttr(buf, mask_data, NFTA_DATA.VALUE, mask);
    expression.offset = try endNested(buf, mask_data, expression.offset);
    const zero: [16]u8 = @splat(0);
    const xor_data = try beginNested(buf, expression.offset, NFTA_BITWISE.XOR);
    expression.offset = try appendAttr(buf, xor_data, NFTA_DATA.VALUE, zero[0..mask.len]);
    expression.offset = try endNested(buf, xor_data, expression.offset);
    return appendExpressionEnd(buf, expression);
}

fn appendDrop(buf: []u8, offset: usize) netlink.Error!usize {
    var expression = try appendExpressionStart(buf, offset, "immediate");
    expression.offset = try appendU32BE(buf, expression.offset, NFTA_IMMEDIATE.DREG, NFT_REG.VERDICT);
    const data = try beginNested(buf, expression.offset, NFTA_IMMEDIATE.DATA);
    const verdict = try beginNested(buf, data, NFTA_DATA.VERDICT);
    expression.offset = try appendU32BE(buf, verdict, NFTA_VERDICT.CODE, NF_VERDICT.DROP);
    expression.offset = try endNested(buf, verdict, expression.offset);
    expression.offset = try endNested(buf, data, expression.offset);
    return appendExpressionEnd(buf, expression);
}

pub fn buildScopedDropRulePayload(
    buf: []u8,
    table_name: []const u8,
    chain_name: []const u8,
    scope: canonical.Scope,
    part_index: usize,
    userdata: []const u8,
) ScopeBuildError![]const u8 {
    const part = try scopeRulePart(scope, part_index);
    // Why: NFT_USERDATA_MAXLEN is 256.
    if (userdata.len == 0 or userdata.len > 256) return error.InvalidRulePart;
    if (buf.len < @sizeOf(netlink.nfgenmsg)) return error.BufferTooSmall;
    const ng: *netlink.nfgenmsg = @alignCast(@ptrCast(&buf[0]));
    ng.* = .{ .nfgen_family = netlink.NFPROTO.INET, .version = 0, .res_id = 0 };
    var offset: usize = @sizeOf(netlink.nfgenmsg);
    offset = try appendStringNul(buf, offset, NFTA_RULE.TABLE, table_name);
    offset = try appendStringNul(buf, offset, NFTA_RULE.CHAIN, chain_name);
    const expressions = try beginNested(buf, offset, NFTA_RULE.EXPRESSIONS);
    offset = expressions;

    offset = try appendMetaLoad(buf, offset, NFT_META.NFPROTO);
    offset = try appendCompare(buf, offset, NFT_CMP.EQ, &.{if (scope.subject.family == .v4) netlink.NFPROTO.IPV4 else netlink.NFPROTO.IPV6});
    const address_len: u32 = if (scope.subject.family == .v4) 4 else 16;
    offset = try appendPayloadLoad(buf, offset, NFT_PAYLOAD.NETWORK_HEADER, if (scope.subject.family == .v4) IPV4_SADDR_OFFSET else IPV6_SADDR_OFFSET, address_len);
    const width: u8 = if (scope.subject.family == .v4) 32 else 128;
    if (scope.subject.prefix != width) {
        var mask: [16]u8 = @splat(0);
        for (0..scope.subject.prefix) |bit_index| mask[bit_index / 8] |= @as(u8, 0x80) >> @intCast(bit_index % 8);
        offset = try appendBitwiseMask(buf, offset, mask[0..address_len]);
    }
    offset = try appendCompare(buf, offset, NFT_CMP.EQ, scope.subject.address[0..address_len]);
    if (part.protocol) |protocol| {
        offset = try appendMetaLoad(buf, offset, NFT_META.L4PROTO);
        // Why: IP protocol numbers from the IANA registry (protocols(5)).
        const number: u8 = switch (protocol) {
            .tcp => 6,
            .udp => 17,
            .icmp_v4 => 1,
            .icmp_v6 => 58,
            .all => return error.InvalidRulePart,
        };
        offset = try appendCompare(buf, offset, NFT_CMP.EQ, &.{number});
    }
    if (part.port) |port| {
        // Why: The destination port is bytes 2..4 of both the TCP header (RFC 9293 section 3.1) and the UDP header (RFC 768).
        offset = try appendPayloadLoad(buf, offset, NFT_PAYLOAD.TRANSPORT_HEADER, 2, 2);
        var first: [2]u8 = undefined;
        mem.writeInt(u16, &first, port.first, .big);
        offset = try appendCompare(buf, offset, if (port.first == port.last) NFT_CMP.EQ else NFT_CMP.GTE, &first);
        if (port.first != port.last) {
            var last: [2]u8 = undefined;
            mem.writeInt(u16, &last, port.last, .big);
            offset = try appendCompare(buf, offset, NFT_CMP.LTE, &last);
        }
    }
    offset = try appendDrop(buf, offset);
    offset = try endNested(buf, expressions, offset);
    offset = try appendAttr(buf, offset, NFTA_RULE.USERDATA, userdata);
    return buf[0..offset];
}

pub fn buildRuleDeletePayload(buf: []u8, table_name: []const u8, chain_name: []const u8, handle: u64) netlink.Error![]const u8 {
    if (handle == 0 or buf.len < @sizeOf(netlink.nfgenmsg)) return error.BufferTooSmall;
    const ng: *netlink.nfgenmsg = @alignCast(@ptrCast(&buf[0]));
    ng.* = .{ .nfgen_family = netlink.NFPROTO.INET, .version = 0, .res_id = 0 };
    var offset: usize = @sizeOf(netlink.nfgenmsg);
    offset = try appendStringNul(buf, offset, NFTA_RULE.TABLE, table_name);
    offset = try appendStringNul(buf, offset, NFTA_RULE.CHAIN, chain_name);
    offset = try appendU64BE(buf, offset, NFTA_RULE.HANDLE, handle);
    return buf[0..offset];
}

fn buildSetElemPayload(
    buf: []u8,
    family: u8,
    table_name: []const u8,
    set_name: []const u8,
    key_bytes: []const u8,
    timeout_ms: u64,
) netlink.Error![]const u8 {
    if (buf.len < @sizeOf(netlink.nfgenmsg)) return error.BufferTooSmall;
    const ng: *netlink.nfgenmsg = @alignCast(@ptrCast(&buf[0]));
    ng.* = .{ .nfgen_family = family, .version = 0, .res_id = 0 };
    var offset: usize = @sizeOf(netlink.nfgenmsg);
    offset = try appendStringNul(buf, offset, NFTA_SET_ELEM_LIST.TABLE, table_name);
    offset = try appendStringNul(buf, offset, NFTA_SET_ELEM_LIST.SET, set_name);

    const elements_start = try beginNested(buf, offset, NFTA_SET_ELEM_LIST.ELEMENTS);
    offset = elements_start;

    const list_elem_start = try beginNested(buf, offset, NFTA_LIST_ELEM);
    offset = list_elem_start;

    const key_start = try beginNested(buf, offset, NFTA_SET_ELEM.KEY);
    offset = key_start;
    offset = try appendAttr(buf, offset, NFTA_DATA_VALUE, key_bytes);
    offset = try endNested(buf, key_start, offset);

    if (timeout_ms > 0) {
        offset = try appendU64BE(buf, offset, NFTA_SET_ELEM.TIMEOUT, timeout_ms);
    }
    offset = try endNested(buf, list_elem_start, offset);
    offset = try endNested(buf, elements_start, offset);
    return buf[0..offset];
}

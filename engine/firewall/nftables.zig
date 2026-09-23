// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const native_endian = @import("builtin").cpu.arch.endian();
const linux = std.os.linux;
const mem = std.mem;

const shared = @import("shared");
const backend = @import("backend.zig");
const netlink = @import("netlink.zig");
const canonical = @import("scope.zig");

pub const NFT_MSG = struct {
    pub const NEWTABLE: u16 = 0;
    pub const GETTABLE: u16 = 1;
    pub const DELTABLE: u16 = 2;
    pub const NEWCHAIN: u16 = 3;
    pub const GETCHAIN: u16 = 4;
    pub const DELCHAIN: u16 = 5;
    pub const NEWRULE: u16 = 6;
    pub const GETRULE: u16 = 7;
    pub const DELRULE: u16 = 8;
    pub const NEWSET: u16 = 9;
    pub const GETSET: u16 = 10;
    pub const DELSET: u16 = 11;
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
    pub const TIMEOUT: u16 = 4;
};

pub const NFTA_DATA_VALUE: u16 = 1;

pub const NLA_F_NESTED: u16 = 1 << 15;

pub const NFT_SET_TIMEOUT: u32 = 16;

pub const NFT_TYPE = struct {
    pub const IPV4_ADDR: u32 = 7;
    pub const IPV6_ADDR: u32 = 8;
};

pub const NF_INET_HOOK = struct {
    pub const PREROUTING: u32 = 0;
    pub const LOCAL_IN: u32 = 1;
    pub const FORWARD: u32 = 2;
    pub const LOCAL_OUT: u32 = 3;
    pub const POSTROUTING: u32 = 4;
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
    pub const LL_HEADER: u32 = 0;
    pub const NETWORK_HEADER: u32 = 1;
    pub const TRANSPORT_HEADER: u32 = 2;
};

pub const NFT_REG = struct {
    pub const VERDICT: u32 = 0;
    pub const REG_1: u32 = 1;
};

pub const NF_VERDICT = struct {
    pub const DROP: u32 = 0;
    pub const ACCEPT: u32 = 1;
};

pub const IPV4_SADDR_OFFSET: u32 = 12;
pub const IPV4_SADDR_LEN: u32 = 4;
pub const IPV6_SADDR_OFFSET: u32 = 8;
pub const IPV6_SADDR_LEN: u32 = 16;

const NLA_ALIGNTO: usize = 4;
const NLA_HDRLEN: usize = 4;

fn nlaAlign(len: usize) usize {
    return (len + NLA_ALIGNTO - 1) & ~@as(usize, NLA_ALIGNTO - 1);
}

fn appendAttr(
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

fn appendU32BE(
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

fn appendStringNul(
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

pub const NftablesBackend = struct {
    allocator: ?std.mem.Allocator = null,
    config: ?backend.BackendConfig = null,
    initialized: bool = false,
    sock: ?netlink.NetlinkSocket = null,

    pub fn tableName(self: *const NftablesBackend) []const u8 {
        return if (self.config) |c| c.table_name else "fail2zig";
    }

    pub fn priority(self: *const NftablesBackend) i32 {
        return if (self.config) |c| c.priority else -1;
    }
};

pub const vtable: backend.BackendVTable = .{
    .initFn = initImpl,
    .deinitFn = deinitImpl,
    .banFn = banImpl,
    .unbanFn = unbanImpl,
    .listBansFn = listBansImpl,
    .flushFn = flushImpl,
    .isAvailableFn = isAvailableImpl,
};

pub const ProbeResult = enum {
    available,
    kernel_unsupported,
    permission_denied,
    transient,
};

const PROBE_RECV_TIMEOUT_MS: u64 = 2000;

pub fn probeReason() ProbeResult {
    var sock = netlink.NetlinkSocket.init(linux.NETLINK.NETFILTER) catch |err| {
        return probeReasonFromInitError(err);
    };
    defer sock.close();
    sock.setRecvTimeout(PROBE_RECV_TIMEOUT_MS) catch return .transient;

    var msg_buf: [64]u8 = undefined;
    var builder = netlink.MessageBuilder.init(&msg_buf);
    const seq = sock.nextSeq();
    const ng: netlink.nfgenmsg = .{ .nfgen_family = netlink.NFPROTO.UNSPEC };
    builder.append(
        netlink.nfnlMsgType(netlink.NFNL.SUBSYS_NFTABLES, NFT_MSG.GETGEN),
        linux.NLM_F_REQUEST | linux.NLM_F_ACK,
        seq,
        sock.port_id,
        std.mem.asBytes(&ng),
    ) catch return .transient;
    sock.send(builder.bytes()) catch return .transient;

    var ack_buf: [1024]u8 = undefined;
    sock.drainAck(&[_]u32{seq}, &ack_buf) catch |err| return probeReasonFromAckError(err);
    return .available;
}

pub fn probeReasonFromInitError(err: netlink.Error) ProbeResult {
    return switch (err) {
        error.ProtocolUnsupported => .kernel_unsupported,
        error.PermissionDenied => .permission_denied,
        else => .transient,
    };
}

pub fn probeReasonFromAckError(err: netlink.Error) ProbeResult {
    return switch (err) {
        error.PermissionDenied => .permission_denied,
        error.InvalidArgument => .kernel_unsupported,
        else => .transient,
    };
}

pub fn probeAvailable() bool {
    return probeReason() == .available;
}

fn castSelf(ctx: *anyopaque) *NftablesBackend {
    return @ptrCast(@alignCast(ctx));
}

fn sendScaffold(self: *NftablesBackend) backend.BackendError!void {
    var sock_ptr = &(self.sock orelse return error.NotAvailable);
    const table_name = self.tableName();

    {
        var del_buf: [256]u8 = undefined;
        const del_payload = buildDeleteTablePayload(
            &del_buf,
            netlink.NFPROTO.INET,
            table_name,
        ) catch |e| return mapNetlinkErr(e);

        var batch_buf: [512]u8 = undefined;
        var batch = netlink.Batch.init(&batch_buf);
        const begin_seq = sock_ptr.nextSeq();
        batch.begin(begin_seq, sock_ptr.port_id, netlink.NFNL.SUBSYS_NFTABLES) catch |e| return mapNetlinkErr(e);
        const del_seq = sock_ptr.nextSeq();
        batch.add(
            netlink.nfnlMsgType(netlink.NFNL.SUBSYS_NFTABLES, NFT_MSG.DELTABLE),
            linux.NLM_F_REQUEST | linux.NLM_F_ACK,
            del_seq,
            sock_ptr.port_id,
            del_payload,
        ) catch |e| return mapNetlinkErr(e);
        const end_seq = sock_ptr.nextSeq();
        const out = batch.commit(end_seq, sock_ptr.port_id, netlink.NFNL.SUBSYS_NFTABLES) catch |e| return mapNetlinkErr(e);

        sock_ptr.send(out) catch return error.SystemError;

        var ack_buf: [2048]u8 = undefined;
        sock_ptr.drainAck(&[_]u32{del_seq}, &ack_buf) catch |e| switch (e) {
            error.NotFound => {},
            error.PermissionDenied => {
                logPermissionDenied();
                return error.PermissionDenied;
            },
            else => return mapNetlinkErr(e),
        };
    }

    const table_priority = self.priority();

    var payload_bufs: [5][512]u8 = undefined;
    const table_payload = buildTablePayload(
        &payload_bufs[0],
        netlink.NFPROTO.INET,
        table_name,
    ) catch |e| return mapNetlinkErr(e);
    const set_v4_payload = buildSetPayload(
        &payload_bufs[1],
        netlink.NFPROTO.INET,
        table_name,
        "banned_ipv4",
        1,
        NFT_TYPE.IPV4_ADDR,
        IPV4_SADDR_LEN,
        0,
    ) catch |e| return mapNetlinkErr(e);
    const set_v6_payload = buildSetPayload(
        &payload_bufs[2],
        netlink.NFPROTO.INET,
        table_name,
        "banned_ipv6",
        2,
        NFT_TYPE.IPV6_ADDR,
        IPV6_SADDR_LEN,
        0,
    ) catch |e| return mapNetlinkErr(e);
    const chain_payload = buildChainPayload(
        &payload_bufs[3],
        netlink.NFPROTO.INET,
        table_name,
        "input",
        NF_INET_HOOK.LOCAL_IN,
        table_priority,
        "filter",
        NF_VERDICT.ACCEPT,
    ) catch |e| return mapNetlinkErr(e);
    const rule_v4_payload = buildDropRulePayload(
        &payload_bufs[4],
        netlink.NFPROTO.INET,
        table_name,
        "input",
        "banned_ipv4",
        netlink.NFPROTO.IPV4,
        IPV4_SADDR_OFFSET,
        IPV4_SADDR_LEN,
    ) catch |e| return mapNetlinkErr(e);
    var rule_v6_buf: [512]u8 = undefined;
    const rule_v6_payload = buildDropRulePayload(
        &rule_v6_buf,
        netlink.NFPROTO.INET,
        table_name,
        "input",
        "banned_ipv6",
        netlink.NFPROTO.IPV6,
        IPV6_SADDR_OFFSET,
        IPV6_SADDR_LEN,
    ) catch |e| return mapNetlinkErr(e);

    var install_buf: [4096]u8 = undefined;
    var install = netlink.Batch.init(&install_buf);
    const ibegin_seq = sock_ptr.nextSeq();
    install.begin(ibegin_seq, sock_ptr.port_id, netlink.NFNL.SUBSYS_NFTABLES) catch |e| return mapNetlinkErr(e);

    const create_flags: u16 = linux.NLM_F_REQUEST | linux.NLM_F_ACK | linux.NLM_F_CREATE;

    const table_seq = sock_ptr.nextSeq();
    install.add(
        netlink.nfnlMsgType(netlink.NFNL.SUBSYS_NFTABLES, NFT_MSG.NEWTABLE),
        create_flags,
        table_seq,
        sock_ptr.port_id,
        table_payload,
    ) catch |e| return mapNetlinkErr(e);

    const set_v4_seq = sock_ptr.nextSeq();
    install.add(
        netlink.nfnlMsgType(netlink.NFNL.SUBSYS_NFTABLES, NFT_MSG.NEWSET),
        create_flags,
        set_v4_seq,
        sock_ptr.port_id,
        set_v4_payload,
    ) catch |e| return mapNetlinkErr(e);

    const set_v6_seq = sock_ptr.nextSeq();
    install.add(
        netlink.nfnlMsgType(netlink.NFNL.SUBSYS_NFTABLES, NFT_MSG.NEWSET),
        create_flags,
        set_v6_seq,
        sock_ptr.port_id,
        set_v6_payload,
    ) catch |e| return mapNetlinkErr(e);

    const chain_seq = sock_ptr.nextSeq();
    install.add(
        netlink.nfnlMsgType(netlink.NFNL.SUBSYS_NFTABLES, NFT_MSG.NEWCHAIN),
        create_flags,
        chain_seq,
        sock_ptr.port_id,
        chain_payload,
    ) catch |e| return mapNetlinkErr(e);

    const rule_v4_seq = sock_ptr.nextSeq();
    install.add(
        netlink.nfnlMsgType(netlink.NFNL.SUBSYS_NFTABLES, NFT_MSG.NEWRULE),
        create_flags,
        rule_v4_seq,
        sock_ptr.port_id,
        rule_v4_payload,
    ) catch |e| return mapNetlinkErr(e);

    const rule_v6_seq = sock_ptr.nextSeq();
    install.add(
        netlink.nfnlMsgType(netlink.NFNL.SUBSYS_NFTABLES, NFT_MSG.NEWRULE),
        create_flags,
        rule_v6_seq,
        sock_ptr.port_id,
        rule_v6_payload,
    ) catch |e| return mapNetlinkErr(e);

    const iend_seq = sock_ptr.nextSeq();
    const out = install.commit(iend_seq, sock_ptr.port_id, netlink.NFNL.SUBSYS_NFTABLES) catch |e| return mapNetlinkErr(e);

    sock_ptr.send(out) catch return error.SystemError;

    var install_ack: [4096]u8 = undefined;
    const labeled = [_]struct { seq: u32, step: []const u8 }{
        .{ .seq = table_seq, .step = "NEWTABLE" },
        .{ .seq = set_v4_seq, .step = "NEWSET banned_ipv4" },
        .{ .seq = set_v6_seq, .step = "NEWSET banned_ipv6" },
        .{ .seq = chain_seq, .step = "NEWCHAIN input" },
        .{ .seq = rule_v4_seq, .step = "NEWRULE saddr@banned_ipv4 drop" },
        .{ .seq = rule_v6_seq, .step = "NEWRULE saddr@banned_ipv6 drop" },
    };
    for (labeled) |item| {
        sock_ptr.drainAck(&[_]u32{item.seq}, &install_ack) catch |e| {
            if (e == error.PermissionDenied) {
                logPermissionDenied();
            } else {
                std.log.warn(
                    "nftables: scaffold step '{s}' failed: {s}",
                    .{ item.step, @errorName(e) },
                );
            }
            return mapNetlinkErr(e);
        };
    }
}

fn logPermissionDenied() void {
    std.log.err(
        "nftables: permission denied installing the firewall scaffold — " ++
            "missing CAP_NET_ADMIN. Run fail2zig as root or grant the " ++
            "capability (e.g. setcap cap_net_admin+ep). Refusing to run unprotected.",
        .{},
    );
}

fn initImpl(
    ctx: *anyopaque,
    config: backend.BackendConfig,
    allocator: std.mem.Allocator,
) backend.BackendError!void {
    const self = castSelf(ctx);
    if (self.initialized) return;
    self.allocator = allocator;
    self.config = config;

    var sock = netlink.NetlinkSocket.init(linux.NETLINK.NETFILTER) catch |err| switch (err) {
        error.PermissionDenied => return error.PermissionDenied,
        else => return error.NotAvailable,
    };

    sock.setRecvTimeout(5000) catch |e| {
        std.log.warn("nftables: could not set recv timeout: {s}", .{@errorName(e)});
        sock.close();
        return error.NotAvailable;
    };
    self.sock = sock;

    sendScaffold(self) catch |err| {
        std.log.warn("nftables: scaffold install failed: {s}", .{@errorName(err)});
        self.sock.?.close();
        self.sock = null;
        return err;
    };

    self.initialized = true;
    std.log.info(
        "nftables: scaffold installed (table=inet/{s}, chain=input, sets=[banned_ipv4, banned_ipv6])",
        .{self.tableName()},
    );
}

fn deinitImpl(ctx: *anyopaque) void {
    const self = castSelf(ctx);
    if (self.sock) |*s| s.close();
    self.sock = null;
    self.initialized = false;
}

fn banImpl(
    ctx: *anyopaque,
    ip: shared.IpAddress,
    jail: shared.JailId,
    duration: shared.Duration,
) backend.BackendError!void {
    _ = jail;
    const self = castSelf(ctx);
    putElement(self, ip, duration, false) catch |err| switch (err) {
        error.AlreadyBanned => putElement(self, ip, duration, true) catch |replace_err| switch (replace_err) {
            error.NotBanned => try putElement(self, ip, duration, false),
            else => return replace_err,
        },
        else => return err,
    };
}

fn putElement(self: *NftablesBackend, ip: shared.IpAddress, duration: shared.Duration, replace: bool) backend.BackendError!void {
    if (!self.initialized) return error.NotAvailable;
    var sock_ptr = &(self.sock orelse return error.NotAvailable);

    const milliseconds = std.math.mul(u64, duration, 1000) catch return error.SystemError;
    var msg_buf: [512]u8 = undefined;
    const payload = switch (ip) {
        .ipv4 => |v| blk: {
            var key: [4]u8 = undefined;
            mem.writeInt(u32, &key, v, .big);
            break :blk buildSetElemAddPayload(
                &msg_buf,
                netlink.NFPROTO.INET,
                self.tableName(),
                "banned_ipv4",
                &key,
                milliseconds,
            ) catch |e| return mapNetlinkErr(e);
        },
        .ipv6 => |v| blk: {
            var key: [16]u8 = undefined;
            mem.writeInt(u128, &key, v, .big);
            break :blk buildSetElemAddPayload(
                &msg_buf,
                netlink.NFPROTO.INET,
                self.tableName(),
                "banned_ipv6",
                &key,
                milliseconds,
            ) catch |e| return mapNetlinkErr(e);
        },
    };

    var batch_buf: [1024]u8 = undefined;
    var batch = netlink.Batch.init(&batch_buf);
    const begin_seq = sock_ptr.nextSeq();
    batch.begin(begin_seq, sock_ptr.port_id, netlink.NFNL.SUBSYS_NFTABLES) catch |e| return mapNetlinkErr(e);
    var sequences: [2]u32 = undefined;
    var sequence_count: usize = 0;
    if (replace) {
        var key: [16]u8 = undefined;
        const key_bytes = switch (ip) {
            .ipv4 => |v| blk: {
                mem.writeInt(u32, key[0..4], v, .big);
                break :blk key[0..4];
            },
            .ipv6 => |v| blk: {
                mem.writeInt(u128, &key, v, .big);
                break :blk key[0..16];
            },
        };
        var del_buf: [512]u8 = undefined;
        const del_payload = buildSetElemDelPayload(&del_buf, netlink.NFPROTO.INET, self.tableName(), if (ip == .ipv4) "banned_ipv4" else "banned_ipv6", key_bytes) catch |e| return mapNetlinkErr(e);
        const del_seq = sock_ptr.nextSeq();
        batch.add(netlink.nfnlMsgType(netlink.NFNL.SUBSYS_NFTABLES, NFT_MSG.DELSETELEM), linux.NLM_F_REQUEST | linux.NLM_F_ACK, del_seq, sock_ptr.port_id, del_payload) catch |e| return mapNetlinkErr(e);
        sequences[sequence_count] = del_seq;
        sequence_count += 1;
    }
    const elem_seq = sock_ptr.nextSeq();
    sequences[sequence_count] = elem_seq;
    sequence_count += 1;
    batch.add(
        netlink.nfnlMsgType(netlink.NFNL.SUBSYS_NFTABLES, NFT_MSG.NEWSETELEM),
        linux.NLM_F_REQUEST | linux.NLM_F_ACK | linux.NLM_F_CREATE | linux.NLM_F_EXCL,
        elem_seq,
        sock_ptr.port_id,
        payload,
    ) catch |e| return mapNetlinkErr(e);
    const end_seq = sock_ptr.nextSeq();
    const out = batch.commit(end_seq, sock_ptr.port_id, netlink.NFNL.SUBSYS_NFTABLES) catch |e| return mapNetlinkErr(e);

    sock_ptr.send(out) catch return error.SystemError;

    var ack_buf: [1024]u8 = undefined;
    sock_ptr.drainAck(sequences[0..sequence_count], &ack_buf) catch |e| return mapNetlinkErr(e);
}

fn unbanImpl(
    ctx: *anyopaque,
    ip: shared.IpAddress,
    jail: shared.JailId,
) backend.BackendError!void {
    _ = jail;
    const self = castSelf(ctx);
    if (!self.initialized) return error.NotAvailable;
    var sock_ptr = &(self.sock orelse return error.NotAvailable);

    var msg_buf: [512]u8 = undefined;
    const payload = switch (ip) {
        .ipv4 => |v| blk: {
            var key: [4]u8 = undefined;
            mem.writeInt(u32, &key, v, .big);
            break :blk buildSetElemDelPayload(
                &msg_buf,
                netlink.NFPROTO.INET,
                self.tableName(),
                "banned_ipv4",
                &key,
            ) catch |e| return mapNetlinkErr(e);
        },
        .ipv6 => |v| blk: {
            var key: [16]u8 = undefined;
            mem.writeInt(u128, &key, v, .big);
            break :blk buildSetElemDelPayload(
                &msg_buf,
                netlink.NFPROTO.INET,
                self.tableName(),
                "banned_ipv6",
                &key,
            ) catch |e| return mapNetlinkErr(e);
        },
    };

    var batch_buf: [1024]u8 = undefined;
    var batch = netlink.Batch.init(&batch_buf);
    const begin_seq = sock_ptr.nextSeq();
    batch.begin(begin_seq, sock_ptr.port_id, netlink.NFNL.SUBSYS_NFTABLES) catch |e| return mapNetlinkErr(e);
    const elem_seq = sock_ptr.nextSeq();
    batch.add(
        netlink.nfnlMsgType(netlink.NFNL.SUBSYS_NFTABLES, NFT_MSG.DELSETELEM),
        linux.NLM_F_REQUEST | linux.NLM_F_ACK,
        elem_seq,
        sock_ptr.port_id,
        payload,
    ) catch |e| return mapNetlinkErr(e);
    const end_seq = sock_ptr.nextSeq();
    const out = batch.commit(end_seq, sock_ptr.port_id, netlink.NFNL.SUBSYS_NFTABLES) catch |e| return mapNetlinkErr(e);

    sock_ptr.send(out) catch return error.SystemError;

    var ack_buf: [1024]u8 = undefined;
    sock_ptr.drainAck(&[_]u32{elem_seq}, &ack_buf) catch |e| return mapNetlinkErr(e);
}

fn listBansImpl(
    ctx: *anyopaque,
    jail: shared.JailId,
    allocator: std.mem.Allocator,
) backend.BackendError![]shared.IpAddress {
    _ = ctx;
    _ = jail;
    return try allocator.alloc(shared.IpAddress, 0);
}

fn flushImpl(ctx: *anyopaque, jail: shared.JailId) backend.BackendError!void {
    _ = jail;
    const self = castSelf(ctx);
    if (!self.initialized) return error.NotAvailable;
    return;
}

fn isAvailableImpl(ctx: *anyopaque) bool {
    const self = castSelf(ctx);
    if (self.initialized) return true;
    return probeAvailable();
}

fn mapNetlinkErr(err: netlink.Error) backend.BackendError {
    return switch (err) {
        error.PermissionDenied => backend.BackendError.PermissionDenied,
        error.ProtocolUnsupported => backend.BackendError.NotAvailable,
        error.AlreadyExists => backend.BackendError.AlreadyBanned,
        error.NotFound => backend.BackendError.NotBanned,
        error.BufferTooSmall,
        error.InvalidBatchState,
        error.SocketFailed,
        error.SendFailed,
        error.RecvFailed,
        error.NetlinkError,
        error.InvalidArgument,
        error.Timeout,
        error.TruncatedMessage,
        => backend.BackendError.SystemError,
    };
}

// Expose only internals exercised by the out-of-module component tests.
pub const TestAccess = if (@import("builtin").is_test) struct {
    pub const backendModule = backend;
    pub const alignAttribute = nlaAlign;
    pub const appendAttribute = appendAttr;
    pub const appendU32BigEndian = appendU32BE;
    pub const appendNulString = appendStringNul;
    pub const availableImpl = isAvailableImpl;
    pub const mapNetlinkError = mapNetlinkErr;
} else struct {};

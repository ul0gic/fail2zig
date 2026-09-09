// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const linux = std.os.linux;
const mem = std.mem;

const shared = @import("shared");
const backend = @import("backend.zig");
const netlink = @import("netlink.zig");

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

// Kernel ABI: TIMEOUT is 11; 10 is NFTA_SET_ID and the kernel silently accepts it with no timeout.
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

// Kernel ABI: TIMEOUT is 4; 6 is USERDATA and yields untimed elements with garbage comments.
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
    pub const EXPRESSIONS: u16 = 4;
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
};

pub const NFTA_CMP = struct {
    pub const SREG: u16 = 1;
    pub const OP: u16 = 2;
    pub const DATA: u16 = 3;
};

pub const NFT_CMP = struct {
    pub const EQ: u32 = 0;
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
    mem.writeInt(u16, buf[offset..][0..2], @intCast(total), .little);
    mem.writeInt(u16, buf[offset + 2 ..][0..2], attr_type, .little);
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
    mem.writeInt(u16, buf[offset..][0..2], @intCast(total), .little);
    mem.writeInt(u16, buf[offset + 2 ..][0..2], attr_type, .little);
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
    mem.writeInt(u16, buf[offset..][0..2], 0, .little);
    mem.writeInt(u16, buf[offset + 2 ..][0..2], attr_type | NLA_F_NESTED, .little);
    return offset + NLA_HDRLEN;
}

fn endNested(buf: []u8, header_offset: usize, cur_offset: usize) netlink.Error!usize {
    const inner_len = cur_offset - header_offset;
    const total = NLA_HDRLEN + inner_len;
    const aligned = nlaAlign(total);
    mem.writeInt(u16, buf[header_offset - NLA_HDRLEN ..][0..2], @intCast(total), .little);
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

pub fn probeReason() ProbeResult {
    var sock = netlink.NetlinkSocket.init(linux.NETLINK.NETFILTER) catch |err| {
        return probeReasonFromInitError(err);
    };
    sock.close();
    return .available;
}

pub fn probeReasonFromInitError(err: netlink.Error) ProbeResult {
    return switch (err) {
        error.ProtocolUnsupported => .kernel_unsupported,
        error.PermissionDenied => .permission_denied,
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
                return error.NotAvailable;
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

    var sock = netlink.NetlinkSocket.init(linux.NETLINK.NETFILTER) catch {
        return error.NotAvailable;
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
    if (!self.initialized) return error.NotAvailable;
    var sock_ptr = &(self.sock orelse return error.NotAvailable);

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
                duration * 1000,
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
                duration * 1000,
            ) catch |e| return mapNetlinkErr(e);
        },
    };

    var batch_buf: [1024]u8 = undefined;
    var batch = netlink.Batch.init(&batch_buf);
    const begin_seq = sock_ptr.nextSeq();
    batch.begin(begin_seq, sock_ptr.port_id, netlink.NFNL.SUBSYS_NFTABLES) catch |e| return mapNetlinkErr(e);
    const elem_seq = sock_ptr.nextSeq();
    batch.add(
        netlink.nfnlMsgType(netlink.NFNL.SUBSYS_NFTABLES, NFT_MSG.NEWSETELEM),
        linux.NLM_F_REQUEST | linux.NLM_F_ACK | linux.NLM_F_CREATE,
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
        error.PermissionDenied => backend.BackendError.NotAvailable,
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
        const attr_len = mem.readInt(u16, out[i..][0..2], .little);
        const attr_type_raw = mem.readInt(u16, out[i + 2 ..][0..2], .little);
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
                    const sub_len = mem.readInt(u16, payload[j..][0..2], .little);
                    const sub_type = mem.readInt(u16, payload[j + 2 ..][0..2], .little) & ~NLA_F_NESTED;
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
        const attr_len = mem.readInt(u16, out[i..][0..2], .little);
        const attr_type = mem.readInt(u16, out[i + 2 ..][0..2], .little) & ~NLA_F_NESTED;
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
    try std.testing.expectEqual(@as(u16, 7), mem.readInt(u16, buf[0..2], .little));
    try std.testing.expectEqual(@as(u16, NFTA_TABLE.NAME), mem.readInt(u16, buf[2..4], .little));
    try std.testing.expectEqualSlices(u8, "abc", buf[4..7]);
    try std.testing.expectEqual(@as(u8, 0), buf[7]);
}

test "nftables: appendStringNul includes terminating NUL" {
    var buf: [16]u8 = undefined;
    const end = try appendStringNul(&buf, 0, NFTA_TABLE.NAME, "ab");
    try std.testing.expectEqual(@as(usize, 8), end);
    try std.testing.expectEqual(@as(u16, 7), mem.readInt(u16, buf[0..2], .little));
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

    const tlv_len = mem.readInt(u16, out[4..6], .little);
    const tlv_type = mem.readInt(u16, out[6..8], .little);
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
        const attr_len = mem.readInt(u16, out[i..][0..2], .little);
        const attr_type = mem.readInt(u16, out[i + 2 ..][0..2], .little);
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
        const attr_len = mem.readInt(u16, out[i..][0..2], .little);
        const attr_type = mem.readInt(u16, out[i + 2 ..][0..2], .little) & ~NLA_F_NESTED;
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
        const attr_len = mem.readInt(u16, out[i..][0..2], .little);
        const attr_type = mem.readInt(u16, out[i + 2 ..][0..2], .little) & ~NLA_F_NESTED;
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

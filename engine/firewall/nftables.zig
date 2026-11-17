// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Runs the nftables backend over netlink: the scaffold install, element bans and unbans, the probe and event decoding.
// Holds: The table, both sets, the input chain and both drop rules go to the kernel in one batch, so it commits all of them or none.

const std = @import("std");
const linux = std.os.linux;
const mem = std.mem;

const shared = @import("shared");
const backend = @import("backend.zig");
const netlink = @import("netlink.zig");
const nft_message = @import("nftables_message.zig");

pub const NFT_MSG = nft_message.NFT_MSG;
pub const NFTA_TABLE = nft_message.NFTA_TABLE;
pub const NFTA_CHAIN = nft_message.NFTA_CHAIN;
pub const NFTA_HOOK = nft_message.NFTA_HOOK;
pub const NFTA_SET = nft_message.NFTA_SET;
pub const NFTA_SET_ELEM = nft_message.NFTA_SET_ELEM;
pub const NFTA_DATA_VALUE = nft_message.NFTA_DATA_VALUE;
pub const NLA_F_NESTED = nft_message.NLA_F_NESTED;
pub const NFT_SET_TIMEOUT = nft_message.NFT_SET_TIMEOUT;
pub const NFT_TYPE = nft_message.NFT_TYPE;
pub const NF_INET_HOOK = nft_message.NF_INET_HOOK;
pub const NFTA_RULE = nft_message.NFTA_RULE;
pub const NFTA_EXPR = nft_message.NFTA_EXPR;
pub const NFTA_PAYLOAD = nft_message.NFTA_PAYLOAD;
pub const NFTA_LOOKUP = nft_message.NFTA_LOOKUP;
pub const NFTA_IMMEDIATE = nft_message.NFTA_IMMEDIATE;
pub const NFTA_DATA = nft_message.NFTA_DATA;
pub const NFTA_VERDICT = nft_message.NFTA_VERDICT;
pub const NFT_PAYLOAD = nft_message.NFT_PAYLOAD;
pub const NFT_REG = nft_message.NFT_REG;
pub const NF_VERDICT = nft_message.NF_VERDICT;
pub const IPV4_SADDR_OFFSET = nft_message.IPV4_SADDR_OFFSET;
pub const IPV4_SADDR_LEN = nft_message.IPV4_SADDR_LEN;
pub const IPV6_SADDR_OFFSET = nft_message.IPV6_SADDR_OFFSET;
pub const IPV6_SADDR_LEN = nft_message.IPV6_SADDR_LEN;
pub const max_scope_rule_parts = nft_message.max_scope_rule_parts;
pub const scopeRulePartCount = nft_message.scopeRulePartCount;
pub const scopeRulePart = nft_message.scopeRulePart;
pub const buildTablePayload = nft_message.buildTablePayload;
pub const buildSetQueryPayload = nft_message.buildSetQueryPayload;
pub const buildOwnedTablePayload = nft_message.buildOwnedTablePayload;
pub const buildSetPayload = nft_message.buildSetPayload;
pub const buildSetElemAddPayload = nft_message.buildSetElemAddPayload;
pub const buildSetElemDelPayload = nft_message.buildSetElemDelPayload;
pub const buildDeleteTablePayload = nft_message.buildDeleteTablePayload;
pub const buildChainPayload = nft_message.buildChainPayload;
pub const buildDropRulePayload = nft_message.buildDropRulePayload;
pub const buildScopedDropRulePayload = nft_message.buildScopedDropRulePayload;
pub const buildRuleDeletePayload = nft_message.buildRuleDeletePayload;
const NFTA_SET_ELEM_LIST = nft_message.NFTA_SET_ELEM_LIST;
const NFTA_GEN = nft_message.NFTA_GEN;
const nlaAlign = nft_message.nlaAlign;
const appendAttr = nft_message.appendAttr;
const appendU32BE = nft_message.appendU32BE;
const appendStringNul = nft_message.appendStringNul;

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

pub const ElementEvent = struct {
    removed: bool,
    family: u8,
    table: []const u8,
    set: []const u8,
    elements: []const u8,
    pid: u32,
    generation: u16,
};
pub const GenerationEvent = struct { id: u32, pid: u32 };
pub const Event = union(enum) { elements: ElementEvent, generation: GenerationEvent, other: u16 };

pub fn decodeEvent(item: netlink.MessageIterator.View) netlink.Error!Event {
    const kind = @intFromEnum(item.hdr.type);
    if (kind >> 8 != netlink.NFNL.SUBSYS_NFTABLES) return .{ .other = kind };
    if (item.payload.len < @sizeOf(netlink.nfgenmsg)) return error.TruncatedMessage;
    const message: u16 = kind & 0xff;
    switch (message) {
        NFT_MSG.NEWSETELEM, NFT_MSG.DELSETELEM => {
            var table: ?[]const u8 = null;
            var set: ?[]const u8 = null;
            var elements: []const u8 = &.{};
            var attrs = netlink.Attributes{ .bytes = item.payload[@sizeOf(netlink.nfgenmsg)..] };
            while (try attrs.next()) |attr| switch (attr.kind) {
                NFTA_SET_ELEM_LIST.TABLE => table = attributeText(attr.value),
                NFTA_SET_ELEM_LIST.SET => set = attributeText(attr.value),
                NFTA_SET_ELEM_LIST.ELEMENTS => elements = attr.value,
                else => {},
            };
            return .{ .elements = .{
                .removed = message == NFT_MSG.DELSETELEM,
                .family = item.payload[0],
                .table = table orelse return error.TruncatedMessage,
                .set = set orelse return error.TruncatedMessage,
                .elements = elements,
                .pid = item.hdr.pid,
                .generation = mem.readInt(u16, item.payload[2..4], .big),
            } };
        },
        NFT_MSG.NEWGEN => return .{ .generation = .{ .id = try generationId(item.payload), .pid = item.hdr.pid } },
        else => return .{ .other = kind },
    }
}

fn attributeText(value: []const u8) []const u8 {
    return if (value.len > 0 and value[value.len - 1] == 0) value[0 .. value.len - 1] else value;
}

fn generationId(payload: []const u8) netlink.Error!u32 {
    if (payload.len < @sizeOf(netlink.nfgenmsg)) return error.TruncatedMessage;
    var attrs = netlink.Attributes{ .bytes = payload[@sizeOf(netlink.nfgenmsg)..] };
    while (try attrs.next()) |attr| if (attr.kind == NFTA_GEN.ID) {
        if (attr.value.len != 4) return error.TruncatedMessage;
        return mem.readInt(u32, attr.value[0..4], .big);
    };
    return error.NetlinkError;
}

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

    // Why: The table is deleted first so the install starts from nothing; NotFound means no table was there.
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
    // Why: NLM_F_EXCL refuses an element already present, so a repeat ban deletes and re-adds it in one batch to set the new timeout.
    putElement(self, ip, duration, false) catch |err| switch (err) {
        error.AlreadyBanned => putElement(self, ip, duration, true) catch |replace_err| switch (replace_err) {
            // Why: An element that expired or was removed after the first attempt fails the delete, so the plain add runs again.
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
        batch.add(
            netlink.nfnlMsgType(netlink.NFNL.SUBSYS_NFTABLES, NFT_MSG.DELSETELEM),
            linux.NLM_F_REQUEST | linux.NLM_F_ACK,
            del_seq,
            sock_ptr.port_id,
            del_payload,
        ) catch |e| return mapNetlinkErr(e);
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
        error.EventsOverflowed,
        error.RecvFailed,
        error.NetlinkError,
        error.InvalidArgument,
        error.Timeout,
        error.TruncatedMessage,
        error.DumpInterrupted,
        => backend.BackendError.SystemError,
    };
}

pub const TestAccess = if (@import("builtin").is_test) struct {
    pub const backendModule = backend;
    pub const alignAttribute = nlaAlign;
    pub const appendAttribute = appendAttr;
    pub const appendU32BigEndian = appendU32BE;
    pub const appendNulString = appendStringNul;
    pub const availableImpl = isAvailableImpl;
    pub const mapNetlinkError = mapNetlinkErr;
} else struct {};

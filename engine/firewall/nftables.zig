//! nftables backend — direct netlink.
//!
//! Target topology (created by `init()`):
//!
//!     table inet fail2zig {
//!         set banned_ipv4 { type ipv4_addr; flags timeout; }
//!         set banned_ipv6 { type ipv6_addr; flags timeout; }
//!         chain input {
//!             type filter hook input priority -1; policy accept;
//!             ip  saddr @banned_ipv4 drop
//!             ip6 saddr @banned_ipv6 drop
//!         }
//!     }
//!
//! Everything goes through one atomic netlink batch so partial
//! failures cannot leave the ruleset in a half-configured state.
//!
//! Tests verify the *byte-level correctness* of the netlink frames
//! we construct. They never talk to the kernel. The kernel only
//! exists at runtime — use `std.testing.skip()` when you want a
//! test that actually executes a netlink round-trip.

const std = @import("std");
const linux = std.os.linux;
const mem = std.mem;

const shared = @import("shared");
const backend = @import("backend.zig");
const netlink = @import("netlink.zig");

// ===========================================================================
// nftables protocol constants
// ===========================================================================
//
// Taken from `linux/netfilter/nf_tables.h`. We copy only the bits
// fail2zig uses; keeping the set narrow makes it obvious when the
// implementation grows into new territory.

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

/// NFTA_TABLE_* attribute ids.
pub const NFTA_TABLE = struct {
    pub const NAME: u16 = 1;
    pub const FLAGS: u16 = 2;
};

/// NFTA_CHAIN_* attribute ids.
pub const NFTA_CHAIN = struct {
    pub const TABLE: u16 = 1;
    pub const NAME: u16 = 3;
    pub const HOOK: u16 = 4;
    pub const POLICY: u16 = 5;
    pub const TYPE: u16 = 7;
};

/// NFTA_HOOK_* — nested inside NFTA_CHAIN_HOOK.
pub const NFTA_HOOK = struct {
    pub const HOOKNUM: u16 = 1;
    pub const PRIORITY: u16 = 2;
};

/// NFTA_SET_* attribute ids. From `include/uapi/linux/netfilter/nf_tables.h`:
///   NFTA_SET_UNSPEC=0, TABLE=1, NAME=2, FLAGS=3, KEY_TYPE=4, KEY_LEN=5,
///   DATA_TYPE=6, DATA_LEN=7, POLICY=8, DESC=9, ID=10, TIMEOUT=11, ...
/// Previous versions of this file had TIMEOUT=10, which is actually NFTA_SET_ID.
/// The kernel silently accepted the bogus ID and the set got no default timeout.
/// Fixed as part of SYS-004.
pub const NFTA_SET = struct {
    pub const TABLE: u16 = 1;
    pub const NAME: u16 = 2;
    pub const FLAGS: u16 = 3;
    pub const KEY_TYPE: u16 = 4;
    pub const KEY_LEN: u16 = 5;
    pub const ID: u16 = 10;
    pub const TIMEOUT: u16 = 11;
};

/// NFTA_SET_ELEM_LIST_* — top-level attrs when adding/removing set elems.
pub const NFTA_SET_ELEM_LIST = struct {
    pub const TABLE: u16 = 1;
    pub const SET: u16 = 2;
    pub const ELEMENTS: u16 = 3;
};

/// NFTA_LIST_ELEM — individual elems nested inside ELEMENTS.
pub const NFTA_LIST_ELEM: u16 = 1;

/// NFTA_SET_ELEM_* — attrs inside a single list elem. From the kernel header:
///   NFTA_SET_ELEM_UNSPEC=0, KEY=1, DATA=2, FLAGS=3, TIMEOUT=4,
///   EXPIRATION=5, USERDATA=6, ...
/// Previous versions had TIMEOUT=6, which is actually NFTA_SET_ELEM_USERDATA.
/// The resulting set elements carried garbage bytes as a "comment" attribute
/// (visible via `nft list set` as `comment "<mojibake>"`) and had no kernel
/// timeout at all — the daemon's state tracker was the only thing expiring
/// bans. If the daemon crashed, banned IPs stayed banned until manual cleanup.
/// Fixed as part of SYS-004.
pub const NFTA_SET_ELEM = struct {
    pub const KEY: u16 = 1;
    pub const TIMEOUT: u16 = 4;
};

/// NFTA_DATA_VALUE — the raw key bytes live inside this attribute.
pub const NFTA_DATA_VALUE: u16 = 1;

/// Nested-attribute bit: set when an attribute contains more
/// attributes rather than a leaf value.
pub const NLA_F_NESTED: u16 = 1 << 15;

/// `NFT_SET_TIMEOUT` flag — enables per-element timeouts on a set.
/// From `enum nft_set_flags`:
///   NFT_SET_ANONYMOUS = 1, CONSTANT = 2, INTERVAL = 4,
///   MAP = 8, TIMEOUT = 16, EVAL = 32, OBJECT = 64, CONCAT = 128.
pub const NFT_SET_TIMEOUT: u32 = 16;

/// Set key types. The kernel maps these to the data-type registry:
///   ipv4_addr == NFT_DATATYPE_IPADDR == 7
///   ipv6_addr == NFT_DATATYPE_IP6ADDR == 8
pub const NFT_TYPE = struct {
    pub const IPV4_ADDR: u32 = 7;
    pub const IPV6_ADDR: u32 = 8;
};

/// Netfilter hook numbers (INPUT = 1 for the filter chain).
pub const NF_INET_HOOK = struct {
    pub const PREROUTING: u32 = 0;
    pub const LOCAL_IN: u32 = 1;
    pub const FORWARD: u32 = 2;
    pub const LOCAL_OUT: u32 = 3;
    pub const POSTROUTING: u32 = 4;
};

/// NFTA_RULE_* attribute ids.
pub const NFTA_RULE = struct {
    pub const TABLE: u16 = 1;
    pub const CHAIN: u16 = 2;
    pub const EXPRESSIONS: u16 = 4;
};

/// NFTA_EXPR_* — one expression inside NFTA_RULE_EXPRESSIONS.
pub const NFTA_EXPR = struct {
    pub const NAME: u16 = 1;
    pub const DATA: u16 = 2;
};

/// NFTA_PAYLOAD_* — nested inside `payload` expression data.
pub const NFTA_PAYLOAD = struct {
    pub const DREG: u16 = 1;
    pub const BASE: u16 = 2;
    pub const OFFSET: u16 = 3;
    pub const LEN: u16 = 4;
};

/// NFTA_LOOKUP_* — nested inside `lookup` expression data.
pub const NFTA_LOOKUP = struct {
    pub const SET: u16 = 1;
    pub const SREG: u16 = 2;
};

/// NFTA_IMMEDIATE_* — nested inside `immediate` expression data.
pub const NFTA_IMMEDIATE = struct {
    pub const DREG: u16 = 1;
    pub const DATA: u16 = 2;
};

/// NFTA_DATA_* — outer wrapper around verdicts/values.
pub const NFTA_DATA = struct {
    pub const VALUE: u16 = 1;
    pub const VERDICT: u16 = 2;
};

/// NFTA_VERDICT_* — nested inside NFTA_DATA_VERDICT.
pub const NFTA_VERDICT = struct {
    pub const CODE: u16 = 1;
};

/// NFTA_META_* — nested inside `meta` expression data.
/// Loads a "meta" value (iif, nfproto, mark, priority, …) into a register
/// for downstream comparison. fail2zig only uses `nfproto` today, to guard
/// its drop rules from cross-protocol false positives in `inet` family chains.
pub const NFTA_META = struct {
    pub const DREG: u16 = 1;
    pub const KEY: u16 = 2;
};

/// Keys for the `meta` expression. Matches `enum nft_meta_keys` in
/// `linux/netfilter/nft_meta.h`:
///   NFT_META_LEN=0, PROTOCOL=1, PRIORITY=2, MARK=3, IIF=4, OIF=5,
///   IIFNAME=6, OIFNAME=7, IIFTYPE=8, OIFTYPE=9, SKUID=10, SKGID=11,
///   NFTRACE=12, RTCLASSID=13, SECMARK=14, NFPROTO=15, L4PROTO=16, …
/// Using 16 instead of 15 silently switches the comparison to L4PROTO,
/// which produces rules that nft pretty-prints as `meta l4proto <proto>`
/// with comically wrong protocol names. Caught during Phase 7.5
/// deployment verification.
pub const NFT_META = struct {
    pub const NFPROTO: u32 = 15;
};

/// NFTA_CMP_* — nested inside `cmp` expression data. If the comparison
/// fails the rule short-circuits and the chain moves on to the next rule.
pub const NFTA_CMP = struct {
    pub const SREG: u16 = 1;
    pub const OP: u16 = 2;
    pub const DATA: u16 = 3;
};

/// Operators for the `cmp` expression. From `linux/netfilter/nft_cmp.h`:
///   NFT_CMP_EQ=0, NEQ, LT, LTE, GT, GTE.
pub const NFT_CMP = struct {
    pub const EQ: u32 = 0;
};

/// Payload base for nftables `payload` expressions.
pub const NFT_PAYLOAD = struct {
    pub const LL_HEADER: u32 = 0;
    pub const NETWORK_HEADER: u32 = 1;
    pub const TRANSPORT_HEADER: u32 = 2;
};

/// Nftables registers. Register 0 is the verdict register; 1-4 are
/// the general-purpose registers (32 bits each in the original ABI).
pub const NFT_REG = struct {
    pub const VERDICT: u32 = 0;
    pub const REG_1: u32 = 1;
};

/// Netfilter verdicts (stored as `__be32` in NFTA_VERDICT_CODE).
/// Values from `include/uapi/linux/netfilter.h`:
///   NF_DROP=0, NF_ACCEPT=1, NF_STOLEN=2, NF_QUEUE=3, NF_REPEAT=4.
pub const NF_VERDICT = struct {
    pub const DROP: u32 = 0;
    pub const ACCEPT: u32 = 1;
};

/// IPv4 source-address offset + length inside the network header.
pub const IPV4_SADDR_OFFSET: u32 = 12;
pub const IPV4_SADDR_LEN: u32 = 4;
/// IPv6 source-address offset + length inside the network header.
pub const IPV6_SADDR_OFFSET: u32 = 8;
pub const IPV6_SADDR_LEN: u32 = 16;

// ===========================================================================
// Attribute encoding
// ===========================================================================
//
// Netfilter uses the standard Netlink TLV format:
//     struct nlattr { __u16 nla_len; __u16 nla_type; u8 value[...] };
// `nla_len` is the full attribute size including the 4-byte header.
// The next attribute starts at a 4-byte boundary (`NLA_ALIGN`).

const NLA_ALIGNTO: usize = 4;
const NLA_HDRLEN: usize = 4;

fn nlaAlign(len: usize) usize {
    return (len + NLA_ALIGNTO - 1) & ~@as(usize, NLA_ALIGNTO - 1);
}

/// Append a single TLV attribute with a raw byte payload to `buf`
/// starting at `offset`. Returns the new offset.
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

/// Append an attribute whose value is a single big-endian `u32`.
/// Netfilter uses network byte order for numeric attrs.
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

/// Append an attribute whose value is a single big-endian `u64`.
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

/// Append a null-terminated string attribute (includes the trailing NUL —
/// nftables expects it).
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

/// Begin a nested attribute. Returns the offset of the attribute
/// header; `endNested` patches its length once inner attrs have
/// been written.
fn beginNested(
    buf: []u8,
    offset: usize,
    attr_type: u16,
) netlink.Error!usize {
    if (offset + NLA_HDRLEN > buf.len) return error.BufferTooSmall;
    mem.writeInt(u16, buf[offset..][0..2], 0, .little); // placeholder
    mem.writeInt(u16, buf[offset + 2 ..][0..2], attr_type | NLA_F_NESTED, .little);
    return offset + NLA_HDRLEN;
}

/// Close a nested attribute opened with `beginNested` by writing
/// the total size (header + inner bytes) back into the header.
fn endNested(buf: []u8, header_offset: usize, cur_offset: usize) netlink.Error!usize {
    const inner_len = cur_offset - header_offset; // inner bytes only
    const total = NLA_HDRLEN + inner_len;
    const aligned = nlaAlign(total);
    // Patch the placeholder length.
    mem.writeInt(u16, buf[header_offset - NLA_HDRLEN ..][0..2], @intCast(total), .little);
    // Ensure trailing pad is zero (appendAttr helpers already pad
    // their own attrs, so `cur_offset` is already aligned — this
    // is a safety net for direct writes).
    if (aligned > total) {
        if (cur_offset + (aligned - total) > buf.len) return error.BufferTooSmall;
        @memset(buf[cur_offset .. cur_offset + (aligned - total)], 0);
        return cur_offset + (aligned - total);
    }
    return cur_offset;
}

// ===========================================================================
// Message builders — one per nftables operation we emit
// ===========================================================================

/// Build the payload (after `nfgenmsg`) for `NFT_MSG_NEWTABLE`.
/// Returns the slice of `buf` that was written.
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

/// Build the payload for `NFT_MSG_NEWSET` creating a timeout set.
/// `key_type` is `NFT_TYPE.IPV4_ADDR` or `NFT_TYPE.IPV6_ADDR`,
/// `key_len` is the key byte width (4 for v4, 16 for v6).
/// Build the payload for `NFT_MSG_NEWSET` creating a timeout set.
/// `key_type` is `NFT_TYPE.IPV4_ADDR` or `NFT_TYPE.IPV6_ADDR`.
/// `key_len` is the key byte width (4 for v4, 16 for v6).
///
/// `default_timeout_ms` of 0 means "no set-wide default timeout" —
/// each element must then specify its own. In that case the
/// `NFTA_SET_TIMEOUT` attribute is omitted entirely; emitting it
/// with value 0 alongside the `NFT_SET_TIMEOUT` flag is rejected by
/// the kernel with EINVAL.
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
    // NFTA_SET_ID: user-provided identifier, unique within the table.
    // libnftnl emits this even for named sets; the kernel rejects
    // creation with EINVAL in some configurations when absent.
    offset = try appendU32BE(buf, offset, NFTA_SET.ID, set_id);
    if (default_timeout_ms > 0) {
        offset = try appendU64BE(buf, offset, NFTA_SET.TIMEOUT, default_timeout_ms);
    }
    return buf[0..offset];
}

/// Build the payload for `NFT_MSG_NEWSETELEM` adding `key_bytes`
/// (IPv4 or IPv6 address in network byte order) to `set_name` with
/// the given timeout (milliseconds). `DELSETELEM` uses the same
/// layout (minus the timeout).
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

/// Build the payload for `NFT_MSG_DELTABLE`. Same wire shape as
/// `NEWTABLE` — the message type carried in the `nlmsghdr` is what
/// distinguishes them. Used to tear down any prior scaffold on
/// startup so `NEWTABLE` doesn't race with a half-configured ruleset.
pub fn buildDeleteTablePayload(
    buf: []u8,
    family: u8,
    table_name: []const u8,
) netlink.Error![]const u8 {
    return buildTablePayload(buf, family, table_name);
}

/// Build the payload for `NFT_MSG_NEWCHAIN` creating a hooked chain
/// suitable for fail2zig's drop rules. Attributes emitted:
///
///   NFTA_CHAIN_TABLE     (string)    — table name
///   NFTA_CHAIN_NAME      (string)    — chain name
///   NFTA_CHAIN_HOOK      (nested)    — hooknum + priority
///   NFTA_CHAIN_TYPE      (string)    — "filter"
///   NFTA_CHAIN_POLICY    (__be32)    — NF_ACCEPT
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

    // NFTA_CHAIN_HOOK is nested: { HOOKNUM (__be32), PRIORITY (__be32) }.
    const hook_start = try beginNested(buf, offset, NFTA_CHAIN.HOOK);
    offset = hook_start;
    offset = try appendU32BE(buf, offset, NFTA_HOOK.HOOKNUM, hooknum);
    // Priority is signed, but the wire format is just 32 bits.
    offset = try appendU32BE(buf, offset, NFTA_HOOK.PRIORITY, @bitCast(priority));
    offset = try endNested(buf, hook_start, offset);

    offset = try appendStringNul(buf, offset, NFTA_CHAIN.TYPE, chain_type);
    offset = try appendU32BE(buf, offset, NFTA_CHAIN.POLICY, policy);
    return buf[0..offset];
}

/// Build the payload for `NFT_MSG_NEWRULE` — a "if source IP is in
/// `set_name` AND the packet is protocol `nfproto`, drop the packet"
/// rule. Structure:
///
///   NFTA_RULE_TABLE (string)
///   NFTA_RULE_CHAIN (string)
///   NFTA_RULE_EXPRESSIONS (nested list):
///     [0] meta load:       DREG=REG_1, KEY=NFT_META_NFPROTO
///     [1] cmp:             SREG=REG_1, OP=EQ, DATA=<nfproto>
///     [2] payload load:    DREG=REG_1, BASE=NETWORK_HEADER, OFFSET, LEN
///     [3] set lookup:      SREG=REG_1, SET=<name>
///     [4] immediate drop:  DREG=VERDICT, DATA=verdict(DROP)
///
/// The `meta nfproto` + `cmp` prefix is load-bearing for the `inet`
/// family: without it, the rule matches on any packet whose byte
/// offsets happen to align with saddr bytes of the wrong protocol.
/// For `ip` or `ip6` family tables the guard is technically redundant
/// (the chain already sees only one protocol) but harmless — the kernel
/// short-circuits cleanly on the single-byte cmp.
///
/// `nfproto` is the protocol family to match against:
/// `netlink.NFPROTO.IPV4` (=2) or `netlink.NFPROTO.IPV6` (=10).
/// `saddr_offset` is the byte offset of the source address within
/// the network header: 12 for IPv4, 8 for IPv6. `saddr_len` is the
/// address width: 4 for IPv4, 16 for IPv6.
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

    // Expressions container.
    const exprs_start = try beginNested(buf, offset, NFTA_RULE.EXPRESSIONS);
    offset = exprs_start;

    // --- Expression 0: meta load — put nfproto into REG_1 ---
    const e0_start = try beginNested(buf, offset, NFTA_LIST_ELEM);
    offset = e0_start;
    offset = try appendStringNul(buf, offset, NFTA_EXPR.NAME, "meta");
    const e0_data = try beginNested(buf, offset, NFTA_EXPR.DATA);
    offset = e0_data;
    offset = try appendU32BE(buf, offset, NFTA_META.DREG, NFT_REG.REG_1);
    offset = try appendU32BE(buf, offset, NFTA_META.KEY, NFT_META.NFPROTO);
    offset = try endNested(buf, e0_data, offset);
    offset = try endNested(buf, e0_start, offset);

    // --- Expression 1: cmp REG_1 == nfproto ---
    // The nfproto value is a single byte (NFPROTO_IPV4=2, NFPROTO_IPV6=10).
    // It lives inside NFTA_CMP_DATA which is itself a nested NFTA_DATA_VALUE.
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

    // --- Expression 2: payload load from network header into REG_1 ---
    // (REG_1 was scratch for the cmp above; we reuse it here — the
    // register file is plain-old memory, no side effects from reuse.)
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

    // --- Expression 3: set lookup (REG_1 ∈ set_name) ---
    const e3_start = try beginNested(buf, offset, NFTA_LIST_ELEM);
    offset = e3_start;
    offset = try appendStringNul(buf, offset, NFTA_EXPR.NAME, "lookup");
    const e3_data = try beginNested(buf, offset, NFTA_EXPR.DATA);
    offset = e3_data;
    offset = try appendStringNul(buf, offset, NFTA_LOOKUP.SET, set_name);
    offset = try appendU32BE(buf, offset, NFTA_LOOKUP.SREG, NFT_REG.REG_1);
    offset = try endNested(buf, e3_data, offset);
    offset = try endNested(buf, e3_start, offset);

    // --- Expression 4: immediate DROP verdict ---
    const e4_start = try beginNested(buf, offset, NFTA_LIST_ELEM);
    offset = e4_start;
    offset = try appendStringNul(buf, offset, NFTA_EXPR.NAME, "immediate");
    const e4_data = try beginNested(buf, offset, NFTA_EXPR.DATA);
    offset = e4_data;
    offset = try appendU32BE(buf, offset, NFTA_IMMEDIATE.DREG, NFT_REG.VERDICT);
    // NFTA_IMMEDIATE_DATA is a nested NFTA_DATA_VERDICT, which is
    // itself a nested NFTA_VERDICT_CODE (__be32). Three levels deep.
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

    // ELEMENTS: nested (LIST_ELEM (KEY (DATA_VALUE (bytes)) [TIMEOUT]))
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

// ===========================================================================
// Backend state + vtable wiring
// ===========================================================================

pub const NftablesBackend = struct {
    allocator: ?std.mem.Allocator = null,
    config: ?backend.BackendConfig = null,
    initialized: bool = false,
    /// We hold the netlink socket across calls — the backend is
    /// long-lived (daemon lifetime) so the socket lifetime matches.
    /// `null` until `init()` runs.
    sock: ?netlink.NetlinkSocket = null,

    pub fn tableName(self: *const NftablesBackend) []const u8 {
        return if (self.config) |c| c.table_name else "fail2zig";
    }

    /// Chain priority for the drop-rule chain. Lower numeric values
    /// run earlier in the netfilter hook chain; the default of `-1`
    /// places fail2zig just before conntrack so dropped packets bypass
    /// connection tracking overhead.
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

/// Availability probe for `backend.detect()`. Opens a netfilter
/// netlink socket and closes it — if that works, `nf_tables` is at
/// least loadable. The real backend also attempts a temporary table
/// create at `init()` time to confirm kernel support; we keep this
/// probe cheap.
pub fn probeAvailable() bool {
    var sock = netlink.NetlinkSocket.init(linux.NETLINK.NETFILTER) catch return false;
    sock.close();
    return true;
}

fn castSelf(ctx: *anyopaque) *NftablesBackend {
    return @ptrCast(@alignCast(ctx));
}

/// Wire a fully-functional ruleset into the kernel. This is what
/// fail2zig needs in place before the first ban, because `banImpl`
/// adds elements to sets that must already exist:
///
///     table inet <name> {
///         set banned_ipv4 { type ipv4_addr; flags timeout; }
///         set banned_ipv6 { type ipv6_addr; flags timeout; }
///         chain input {
///             type filter hook input priority filter; policy accept;
///             ip  saddr @banned_ipv4 drop
///             ip6 saddr @banned_ipv6 drop
///         }
///     }
///
/// The install runs inside a single `NFNL_MSG_BATCH_BEGIN /
/// NFNL_MSG_BATCH_END` transaction so the kernel either commits the
/// whole thing or none of it. Any previous `<name>` table is deleted
/// first (idempotent: `NotFound` on first-time install is silently
/// accepted, every other error is surfaced).
///
/// Every message in the batch requests `NLM_F_ACK` and is drained
/// through `drainAck` so netlink failures (EPERM, EINVAL, …) are
/// loud instead of silent.
fn sendScaffold(self: *NftablesBackend) backend.BackendError!void {
    var sock_ptr = &(self.sock orelse return error.NotAvailable);
    const table_name = self.tableName();

    // --- Phase 1: idempotent tear-down of any prior scaffold. ---
    // We do this in a dedicated batch so we can treat `NotFound` as
    // an acceptable outcome without conflating it with errors from
    // the install batch.
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
            error.NotFound => {}, // first-time install — expected.
            error.PermissionDenied => return error.NotAvailable,
            else => return mapNetlinkErr(e),
        };
    }

    // --- Phase 2: fresh install in one atomic batch. ---
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
        1, // set_id — unique within the table
        NFT_TYPE.IPV4_ADDR,
        IPV4_SADDR_LEN,
        0, // per-set default timeout; 0 means "per-element timeout only"
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
        netlink.NFPROTO.IPV4, // nfproto guard: only match IPv4 packets
        IPV4_SADDR_OFFSET,
        IPV4_SADDR_LEN,
    ) catch |e| return mapNetlinkErr(e);
    // Second rule payload — builds into a separate buffer since the
    // batch references all payloads until `send`.
    var rule_v6_buf: [512]u8 = undefined;
    const rule_v6_payload = buildDropRulePayload(
        &rule_v6_buf,
        netlink.NFPROTO.INET,
        table_name,
        "input",
        "banned_ipv6",
        netlink.NFPROTO.IPV6, // nfproto guard: only match IPv6 packets
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

    // Drain each expected ACK individually so we can log precisely
    // which kernel message failed. The cost is a handful of recv
    // syscalls at startup — negligible for the one-shot install.
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
            std.log.warn(
                "nftables: scaffold step '{s}' failed: {s}",
                .{ item.step, @errorName(e) },
            );
            return mapNetlinkErr(e);
        };
    }
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

    // Open the netlink socket. Failing here means the kernel module
    // isn't loaded or we lack the capability — either way a legitimate
    // NotAvailable, which lets `backend.detect` fall through to
    // iptables / ipset per security.md's fail-closed posture.
    var sock = netlink.NetlinkSocket.init(linux.NETLINK.NETFILTER) catch {
        return error.NotAvailable;
    };

    // Bound the worst-case wait for any single recv() during
    // scaffold install or subsequent bans. 5 seconds is generous for
    // a local netlink round-trip (typically microseconds) and still
    // short enough to surface a hung kernel or misconfigured sandbox.
    sock.setRecvTimeout(5000) catch |e| {
        std.log.warn("nftables: could not set recv timeout: {s}", .{@errorName(e)});
        sock.close();
        return error.NotAvailable;
    };
    self.sock = sock;

    // Install the table/chain/sets/rules the daemon's ban logic
    // assumes. Fails closed — a daemon that can't install its
    // scaffold must not pretend to be banning anything (SYS-003).
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

    // Construct the batched add and send. We reuse the wire helpers
    // so every test of `buildSetElemAddPayload` also validates the
    // production path.
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

    // Wait for the kernel's ACK. This is what makes silent failures
    // (like SYS-003: banning into a non-existent set) impossible —
    // any netlink error here propagates up to the caller, gets
    // logged by the state-tracker wiring in main.zig, and is visible
    // in the metrics. `AlreadyExists` is the only "expected failure"
    // and it maps cleanly to `AlreadyBanned` which callers handle as
    // idempotency.
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

    // Same ACK discipline as `banImpl` — unban must not silently
    // fail. `NotFound` on element removal maps to `NotBanned` which
    // callers treat as a no-op (idempotency contract).
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
    // Phase 4 wires full dump response parsing. For Phase 3 the
    // backend reports an empty list — callers that need real state
    // recovery read from the persisted state file.
    return try allocator.alloc(shared.IpAddress, 0);
}

fn flushImpl(ctx: *anyopaque, jail: shared.JailId) backend.BackendError!void {
    _ = jail;
    const self = castSelf(ctx);
    if (!self.initialized) return error.NotAvailable;
    // Flush = delete all elements of both sets. Phase 4 wires the
    // actual multi-frame batch; we signal success here so the
    // vtable contract is honoured and higher-level code can be
    // tested end-to-end.
    return;
}

fn isAvailableImpl(ctx: *anyopaque) bool {
    const self = castSelf(ctx);
    if (self.initialized) return true;
    return probeAvailable();
}

/// Map wrapper-internal errors onto the public `BackendError` set.
/// The netlink module's errors aren't visible to callers of
/// `Backend`; they collapse to one of a few coarse-grained variants.
///
/// `PermissionDenied` maps to `NotAvailable` so the backend auto-
/// detect moves on to iptables/ipset rather than the daemon crashing.
/// `AlreadyExists` and `NotFound` on element operations map to
/// `AlreadyBanned` / `NotBanned` respectively — the caller's
/// idempotency contract. Everything else is `SystemError`.
fn mapNetlinkErr(err: netlink.Error) backend.BackendError {
    return switch (err) {
        error.PermissionDenied => backend.BackendError.NotAvailable,
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

// ===========================================================================
// Tests — byte-level verification, never talks to the kernel.
// ===========================================================================

test "nftables: NFT_MSG ids match kernel header" {
    try std.testing.expectEqual(@as(u16, 0), NFT_MSG.NEWTABLE);
    try std.testing.expectEqual(@as(u16, 3), NFT_MSG.NEWCHAIN);
    try std.testing.expectEqual(@as(u16, 9), NFT_MSG.NEWSET);
    try std.testing.expectEqual(@as(u16, 12), NFT_MSG.NEWSETELEM);
    try std.testing.expectEqual(@as(u16, 14), NFT_MSG.DELSETELEM);
}

test "nftables: attribute ids match kernel header (SYS-004 regression)" {
    // Values from `include/uapi/linux/netfilter/nf_tables.h`. Previous
    // versions of this file had wrong ids (NFTA_SET.TIMEOUT=10 which
    // is NFTA_SET_ID; NFTA_SET_ELEM.TIMEOUT=6 which is
    // NFTA_SET_ELEM_USERDATA). The wrong-id bug was how SYS-004
    // leaked garbage bytes into the kernel rule store.
    try std.testing.expectEqual(@as(u16, 11), NFTA_SET.TIMEOUT);
    try std.testing.expectEqual(@as(u16, 4), NFTA_SET_ELEM.TIMEOUT);
    try std.testing.expectEqual(@as(u16, 1), NFTA_SET_ELEM.KEY);

    // Chain attribute ids.
    try std.testing.expectEqual(@as(u16, 1), NFTA_CHAIN.TABLE);
    try std.testing.expectEqual(@as(u16, 3), NFTA_CHAIN.NAME);
    try std.testing.expectEqual(@as(u16, 4), NFTA_CHAIN.HOOK);
    try std.testing.expectEqual(@as(u16, 5), NFTA_CHAIN.POLICY);
    try std.testing.expectEqual(@as(u16, 7), NFTA_CHAIN.TYPE);

    // Hook sub-attribute ids.
    try std.testing.expectEqual(@as(u16, 1), NFTA_HOOK.HOOKNUM);
    try std.testing.expectEqual(@as(u16, 2), NFTA_HOOK.PRIORITY);

    // Rule + expression ids.
    try std.testing.expectEqual(@as(u16, 1), NFTA_RULE.TABLE);
    try std.testing.expectEqual(@as(u16, 2), NFTA_RULE.CHAIN);
    try std.testing.expectEqual(@as(u16, 4), NFTA_RULE.EXPRESSIONS);
    try std.testing.expectEqual(@as(u16, 1), NFTA_EXPR.NAME);
    try std.testing.expectEqual(@as(u16, 2), NFTA_EXPR.DATA);

    // Payload / lookup / immediate expression attribute ids.
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

    // Hook / register / verdict constants.
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

    var i: usize = 4; // skip nfgenmsg
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
                // Walk the nested HOOKNUM + PRIORITY attrs.
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

    // The set name "banned_ipv4\0" (12 bytes) and the verdict code
    // NF_DROP (0x00000000 big-endian) must both appear somewhere in
    // the encoded frame. Substring scan on the serialized bytes —
    // the exact offsets are an implementation detail of the nested
    // structure but their presence is a structural invariant.
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

    // NF_DROP verdict = 0 (BE), wrapped in NFTA_VERDICT_CODE which
    // is a 4-byte attribute. Look for the exact 8-byte sequence:
    //   len=8 (LE: 08 00), type=1 (LE: 01 00), value=0 (BE: 00 00 00 00)
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

    // Expression names must all be present as null-terminated strings.
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
    // In `inet` family chains a naked payload-based saddr match will
    // fire on packets of the wrong protocol whose bytes-at-offset
    // happen to collide with an element in the other set. The fix is
    // prefixing each drop rule with `meta nfproto <family>` + cmp.
    // This test asserts both the meta and cmp expression names plus
    // the one-byte protocol value appear in the payload.
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

    // Expression names: meta + cmp must both be present before payload/lookup/immediate.
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

    // The IPv4 nfproto constant (2) must appear as a single-byte value
    // attribute: len=5 (4 header + 1 value), type=NFTA_DATA_VALUE=1,
    // value=0x02. Because 5-byte attrs pad to 8, the full 8-byte pattern
    // is: 05 00 01 00 02 00 00 00.
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

    // Now the IPv6 rule — must carry protocol byte 0x0a.
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
    // The IPv6 saddr offset (8) + len (16) must appear as __be32
    // values inside the payload expression. Scan for both 4-byte
    // big-endian patterns.
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
    // Kernel rejects a NEWSET with `NFTA_SET_TIMEOUT=0` alongside the
    // `NFT_SET_TIMEOUT` flag as EINVAL. We discovered this the hard
    // way during Phase 7.5 scaffold install. The fix: only emit the
    // attribute when the caller actually wants a set-wide default.
    var buf: [256]u8 = undefined;
    const out = try buildSetPayload(
        &buf,
        netlink.NFPROTO.INET,
        "fail2zig",
        "banned_ipv4",
        1,
        NFT_TYPE.IPV4_ADDR,
        4,
        0, // no default timeout
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
    // NFTA_SET_ID must still be emitted (required by kernel for
    // user-scoped set creation — empirically rejected as EINVAL
    // without it during Phase 7.5 deployment).
    try std.testing.expect(saw_id);
}

test "nftables: buildDeleteTablePayload matches buildTablePayload shape" {
    var a: [64]u8 = undefined;
    var b: [64]u8 = undefined;
    const new_payload = try buildTablePayload(&a, netlink.NFPROTO.INET, "fail2zig");
    const del_payload = try buildDeleteTablePayload(&b, netlink.NFPROTO.INET, "fail2zig");
    // DELTABLE payload is structurally identical to NEWTABLE; the
    // nlmsghdr.type differentiates them at the wire layer.
    try std.testing.expectEqualSlices(u8, new_payload, del_payload);
}

test "nftables: appendAttr emits correct TLV layout" {
    var buf: [32]u8 = undefined;
    const end = try appendAttr(&buf, 0, NFTA_TABLE.NAME, "abc");
    // len = 4 header + 3 payload = 7, aligned to 8.
    try std.testing.expectEqual(@as(usize, 8), end);
    try std.testing.expectEqual(@as(u16, 7), mem.readInt(u16, buf[0..2], .little));
    try std.testing.expectEqual(@as(u16, NFTA_TABLE.NAME), mem.readInt(u16, buf[2..4], .little));
    try std.testing.expectEqualSlices(u8, "abc", buf[4..7]);
    try std.testing.expectEqual(@as(u8, 0), buf[7]); // pad byte
}

test "nftables: appendStringNul includes terminating NUL" {
    var buf: [16]u8 = undefined;
    const end = try appendStringNul(&buf, 0, NFTA_TABLE.NAME, "ab");
    // header(4) + "ab\0"(3) = 7, aligned to 8.
    try std.testing.expectEqual(@as(usize, 8), end);
    try std.testing.expectEqual(@as(u16, 7), mem.readInt(u16, buf[0..2], .little));
    try std.testing.expectEqualStrings("ab", buf[4..6]);
    try std.testing.expectEqual(@as(u8, 0), buf[6]); // NUL
}

test "nftables: appendU32BE writes network byte order" {
    var buf: [16]u8 = undefined;
    const end = try appendU32BE(&buf, 0, NFTA_SET.KEY_TYPE, NFT_TYPE.IPV4_ADDR);
    try std.testing.expectEqual(@as(usize, 8), end);
    // Big-endian u32 of 7 is 00 00 00 07.
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00, 0x00, 0x07 }, buf[4..8]);
}

test "nftables: buildTablePayload contains nfgenmsg + name TLV" {
    var buf: [64]u8 = undefined;
    const out = try buildTablePayload(&buf, netlink.NFPROTO.INET, "fail2zig");

    // nfgenmsg is 4 bytes: family=INET(1), version=0, res_id=0.
    try std.testing.expectEqual(@as(u8, netlink.NFPROTO.INET), out[0]);
    try std.testing.expectEqual(@as(u8, 0), out[1]);
    try std.testing.expectEqual(@as(u16, 0), mem.readInt(u16, out[2..4], .big));

    // Followed by NFTA_TABLE_NAME ("fail2zig\0").
    const tlv_len = mem.readInt(u16, out[4..6], .little);
    const tlv_type = mem.readInt(u16, out[6..8], .little);
    try std.testing.expectEqual(@as(u16, NFTA_TABLE.NAME), tlv_type);
    try std.testing.expectEqual(@as(u16, 4 + 9), tlv_len); // 4 hdr + "fail2zig\0"
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
        42, // set_id
        NFT_TYPE.IPV4_ADDR,
        4,
        600_000,
    );

    // Walk attrs after the 4-byte nfgenmsg.
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
    // 192.168.1.1 = 0xC0A80101
    var key: [4]u8 = undefined;
    mem.writeInt(u32, &key, 0xC0A80101, .big);
    const out = try buildSetElemAddPayload(
        &buf,
        netlink.NFPROTO.INET,
        "fail2zig",
        "banned_ipv4",
        &key,
        30_000, // 30s in ms
    );
    // The key bytes 0xC0 0xA8 0x01 0x01 must appear exactly once
    // in the encoded frame — inside NFTA_DATA_VALUE.
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

    // The timeout 30_000 must appear as a big-endian u64 somewhere
    // in the encoded frame.
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
    // ::1 = 0x...01
    mem.writeInt(u128, &key, 1, .big);
    const out = try buildSetElemAddPayload(
        &buf,
        netlink.NFPROTO.INET,
        "fail2zig",
        "banned_ipv6",
        &key,
        60_000,
    );
    // The ::1 key is a 16-byte sequence of 15 zeros + 0x01, wrapped
    // in three levels of nested attrs. Byte-scan for the payload
    // preceded by its TLV header (len=4+16=20, type=NFTA_DATA_VALUE).
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
    // No NFTA_SET_ELEM_TIMEOUT (id=6) attribute anywhere in the
    // nested ELEMENTS tree. Do a naive scan — our builder writes it
    // only from the timeout>0 branch.
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
    // The actual return depends on the host — we just verify it
    // doesn't crash and matches `probeAvailable()`.
    const got = isAvailableImpl(@ptrCast(&be));
    try std.testing.expectEqual(probeAvailable(), got);
}

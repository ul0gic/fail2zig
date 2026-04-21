// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Safe Zig wrapper around Linux netlink sockets.
//!
//! Scope: the wrapper is deliberately narrow — just what the
//! nftables backend needs. We support:
//!
//!   * Opening an `AF_NETLINK / SOCK_RAW / SOCK_CLOEXEC` socket
//!     bound to port 0 (kernel assigns the pid).
//!   * Sending a single message or a batch of messages atomically.
//!   * Receiving responses, parsing `NLMSG_ERROR`, handling
//!     multi-part replies (`NLM_F_MULTI` / `NLMSG_DONE`).
//!   * Constructing well-formed `nlmsghdr` frames with correct
//!     alignment (`NLMSG_ALIGNTO = 4`).
//!
//! Every C-adjacent surface is wrapped in a safe Zig type. Callers
//! never see raw `*[*c]` pointers or naked file descriptors. All
//! FDs carry `SOCK_CLOEXEC`.

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const mem = std.mem;

/// Alignment used by netlink headers/attributes. From
/// `linux/netlink.h`: `#define NLMSG_ALIGNTO 4U`.
pub const NLMSG_ALIGNTO: usize = 4;

/// Round `len` up to the next `NLMSG_ALIGNTO` boundary.
pub fn nlmsgAlign(len: usize) usize {
    return (len + NLMSG_ALIGNTO - 1) & ~@as(usize, NLMSG_ALIGNTO - 1);
}

/// Size of the netlink message header (`struct nlmsghdr`). 16 bytes
/// — kept as a compile-time constant so callers can size buffers
/// without reaching for `@sizeOf`.
pub const NLMSG_HDRLEN: usize = nlmsgAlign(@sizeOf(linux.nlmsghdr));

/// Errors raised by the wrapper. These map cleanly onto
/// `BackendError.SystemError` at the backend boundary.
pub const Error = error{
    /// `socket(2)` or `bind(2)` failed.
    SocketFailed,
    /// `send(2)` / `sendto(2)` failed.
    SendFailed,
    /// `recv(2)` / `recvfrom(2)` failed.
    RecvFailed,
    /// Peer returned an `NLMSG_ERROR` with a non-zero errno.
    NetlinkError,
    /// The kernel said the named object (table/set/chain/rule/element)
    /// does not exist. Specific-enough to inform install / idempotency
    /// decisions — e.g. "DELTABLE failed with NotFound" is expected on
    /// first-time install.
    NotFound,
    /// The kernel said the object already exists. Used for idempotent
    /// install checks.
    AlreadyExists,
    /// The kernel denied the operation — missing CAP_NET_ADMIN or
    /// some other permissions failure.
    PermissionDenied,
    /// The kernel rejected our message as malformed. This is almost
    /// always a bug in our payload builders; log loudly.
    InvalidArgument,
    /// Drain timed out before all expected ACKs arrived.
    Timeout,
    /// Response was shorter than expected / malformed.
    TruncatedMessage,
    /// Caller's buffer was too small for the response.
    BufferTooSmall,
    /// Batch state machine used out of order.
    InvalidBatchState,
};

/// Map a kernel-returned errno (as delivered in an `NLMSG_ERROR`
/// payload, already sign-flipped so it's a positive errno value) to
/// one of our specific `Error` variants. Unknown errnos collapse to
/// `NetlinkError` so callers can still handle the message fault.
pub fn errnoToError(errno: i32) Error {
    // `parseNlmsgerr` returns the signed kernel value (typically
    // negative). We care about the positive errno magnitude.
    const v: i32 = if (errno < 0) -errno else errno;
    // errno values from `include/uapi/asm-generic/errno-base.h` and
    // `errno.h`. Only the ones relevant to nftables operations.
    return switch (v) {
        2 => error.NotFound, // ENOENT
        13 => error.PermissionDenied, // EACCES
        1 => error.PermissionDenied, // EPERM
        17 => error.AlreadyExists, // EEXIST
        22 => error.InvalidArgument, // EINVAL
        else => error.NetlinkError,
    };
}

/// Owning handle for a netlink socket.
pub const NetlinkSocket = struct {
    fd: posix.socket_t,
    /// Monotonically-increasing sequence number. Kernel echoes
    /// this in ACKs so callers can correlate request/response.
    seq: u32 = 1,
    /// Port ID assigned by the kernel at bind time.
    port_id: u32 = 0,

    /// Open a netlink socket on the given protocol family (e.g.
    /// `NETLINK.NETFILTER`) and bind it with `pid = 0` so the
    /// kernel picks a unique port id for us.
    pub fn init(protocol: u32) Error!NetlinkSocket {
        // Always pass SOCK_CLOEXEC per security.md — we don't want
        // the socket fd leaking into subprocess spawns.
        const flags = posix.SOCK.RAW | posix.SOCK.CLOEXEC;
        const fd = posix.socket(posix.AF.NETLINK, flags, @intCast(protocol)) catch {
            return error.SocketFailed;
        };
        errdefer posix.close(fd);

        var addr: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
        posix.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.nl)) catch {
            return error.SocketFailed;
        };

        // Read back the kernel-assigned port id via getsockname.
        var sa: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
        var sa_len: posix.socklen_t = @sizeOf(linux.sockaddr.nl);
        posix.getsockname(fd, @ptrCast(&sa), &sa_len) catch {
            return error.SocketFailed;
        };

        return .{ .fd = fd, .port_id = sa.pid };
    }

    pub fn close(self: *NetlinkSocket) void {
        posix.close(self.fd);
        self.fd = -1;
    }

    /// Allocate and return the next sequence number. Wraps on
    /// overflow (kernel doesn't care — we use these as opaque
    /// request correlation tags).
    pub fn nextSeq(self: *NetlinkSocket) u32 {
        const s = self.seq;
        self.seq = if (s == std.math.maxInt(u32)) 1 else s + 1;
        return s;
    }

    /// Send a prepared netlink frame (one or more concatenated,
    /// properly-aligned `nlmsghdr + payload` messages). Caller
    /// owns the buffer.
    pub fn send(self: *NetlinkSocket, msg: []const u8) Error!void {
        var addr: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
        const n = posix.sendto(
            self.fd,
            msg,
            0,
            @ptrCast(&addr),
            @sizeOf(linux.sockaddr.nl),
        ) catch {
            return error.SendFailed;
        };
        if (n != msg.len) return error.SendFailed;
    }

    /// Receive a single netlink datagram into `buf`. Returns the
    /// slice that was actually filled. The caller is responsible
    /// for walking multiple `nlmsghdr` frames within that slice
    /// via `MessageIterator`.
    pub fn recv(self: *NetlinkSocket, buf: []u8) Error![]u8 {
        const n = posix.recv(self.fd, buf, 0) catch |err| switch (err) {
            error.WouldBlock => return error.Timeout,
            else => return error.RecvFailed,
        };
        if (n == 0) return error.TruncatedMessage;
        return buf[0..n];
    }

    /// Set the socket's receive timeout. `drainAck` uses this to
    /// bound the worst-case wait for netlink responses. Passing 0
    /// disables the timeout (blocking recv forever).
    pub fn setRecvTimeout(self: *NetlinkSocket, ms: u64) Error!void {
        const secs: i64 = @intCast(ms / 1000);
        const usecs: i64 = @intCast((ms % 1000) * 1000);
        const tv: posix.timeval = .{ .sec = secs, .usec = usecs };
        posix.setsockopt(
            self.fd,
            posix.SOL.SOCKET,
            posix.SO.RCVTIMEO,
            mem.asBytes(&tv),
        ) catch return error.SocketFailed;
    }

    /// Drain netlink responses until every sequence number in
    /// `expected_seqs` has been ACK'd or any returns an errno.
    ///
    /// Nftables ACK semantics (from `linux/net/netfilter/nfnetlink.c`):
    /// every message sent with `NLM_F_ACK` produces exactly one
    /// `NLMSG_ERROR` reply carrying either errno=0 (success) or a
    /// negative errno. Unmatched message types are skipped.
    ///
    /// `scratch` is a caller-owned receive buffer — typically 8 KiB
    /// suffices for a single batch ACK, but callers sending many
    /// messages per batch may want more.
    ///
    /// On any non-zero errno this returns the specific `Error`
    /// variant mapped by `errnoToError`. The caller decides whether
    /// that particular failure is fatal or expected (e.g. DELTABLE
    /// on first-time install legitimately returns `NotFound`).
    pub fn drainAck(
        self: *NetlinkSocket,
        expected_seqs: []const u32,
        scratch: []u8,
    ) Error!void {
        if (expected_seqs.len == 0) return;

        // Track which seqs are still outstanding. For small N (<=64
        // which covers every batch we realistically build) a bitset
        // over a `u64` is enough; we degrade to an O(N) linear scan
        // above that.
        var bits: u64 = 0;
        const use_bitset = expected_seqs.len <= 64;
        if (use_bitset) {
            bits = if (expected_seqs.len == 64) std.math.maxInt(u64) else (@as(u64, 1) << @intCast(expected_seqs.len)) - 1;
        }
        // O(N) fallback for larger batches — avoided in practice but
        // keeps the surface robust.
        var done_flags = [_]bool{false} ** 256;

        while (true) {
            const anyPending = if (use_bitset) bits != 0 else blk: {
                var pending = false;
                for (done_flags[0..expected_seqs.len]) |d| if (!d) {
                    pending = true;
                    break;
                };
                break :blk pending;
            };
            if (!anyPending) return;

            const data = try self.recv(scratch);
            var it = MessageIterator.init(data);
            while (it.next()) |msg| {
                // NLMSG_ERROR is type 2 in the standard netlink type
                // space. Hard-coded here rather than via
                // `linux.NetlinkMessageType.ERROR` because the enum
                // name varies across Zig 0.14 / 0.15.
                if (@intFromEnum(msg.hdr.type) != @as(u16, 2)) continue;
                const errno = try parseNlmsgerr(msg.payload);
                // Correlate by the *inner* seq (which is msg.hdr.seq
                // echoed back). `parseNlmsgerr` skips past the errno
                // field; the header inside the payload is the one
                // we originally sent, but its seq equals msg.hdr.seq.
                const seq = msg.hdr.seq;
                var matched_idx: ?usize = null;
                for (expected_seqs, 0..) |s, idx| {
                    if (s == seq) {
                        matched_idx = idx;
                        break;
                    }
                }
                if (matched_idx == null) continue; // stray ACK, ignore
                if (errno != 0) return errnoToError(errno);
                if (use_bitset) {
                    bits &= ~(@as(u64, 1) << @intCast(matched_idx.?));
                } else {
                    done_flags[matched_idx.?] = true;
                }
            }
        }
    }
};

/// Construct a netlink frame in a caller-provided buffer. The
/// builder never allocates — it operates on a fixed slice and
/// returns `error.BufferTooSmall` when the message won't fit.
///
/// Layout:
///     +--------------+----------------------+
///     | nlmsghdr (16)| payload (payload.len)|   aligned to 4
///     +--------------+----------------------+
pub const MessageBuilder = struct {
    buf: []u8,
    offset: usize = 0,

    pub fn init(buf: []u8) MessageBuilder {
        return .{ .buf = buf };
    }

    /// Append one netlink message. Returns the byte range occupied
    /// by the new message (header + payload, with trailing padding
    /// to the next 4-byte boundary).
    pub fn append(
        self: *MessageBuilder,
        msg_type: u16,
        flags: u16,
        seq: u32,
        pid: u32,
        payload: []const u8,
    ) Error!void {
        const total = NLMSG_HDRLEN + payload.len;
        const aligned = nlmsgAlign(total);
        if (self.offset + aligned > self.buf.len) return error.BufferTooSmall;

        // Header
        const hdr_ptr: *linux.nlmsghdr = @alignCast(@ptrCast(&self.buf[self.offset]));
        hdr_ptr.* = .{
            .len = @intCast(total),
            .type = @enumFromInt(msg_type),
            .flags = flags,
            .seq = seq,
            .pid = pid,
        };

        // Payload
        if (payload.len > 0) {
            @memcpy(
                self.buf[self.offset + NLMSG_HDRLEN .. self.offset + total],
                payload,
            );
        }
        // Zero any padding bytes we added by aligning up. This
        // keeps the kernel trace output clean and avoids leaking
        // uninitialised stack memory over the wire.
        if (aligned > total) {
            @memset(self.buf[self.offset + total .. self.offset + aligned], 0);
        }

        self.offset += aligned;
    }

    pub fn bytes(self: *const MessageBuilder) []const u8 {
        return self.buf[0..self.offset];
    }
};

/// Walks a received buffer one `nlmsghdr` at a time.
pub const MessageIterator = struct {
    buf: []const u8,
    offset: usize = 0,

    pub fn init(buf: []const u8) MessageIterator {
        return .{ .buf = buf };
    }

    pub const View = struct {
        hdr: linux.nlmsghdr,
        payload: []const u8,
    };

    pub fn next(self: *MessageIterator) ?View {
        if (self.offset + NLMSG_HDRLEN > self.buf.len) return null;
        const hdr: *const linux.nlmsghdr = @alignCast(@ptrCast(&self.buf[self.offset]));
        const len: usize = @intCast(hdr.len);
        if (len < NLMSG_HDRLEN) return null;
        if (self.offset + len > self.buf.len) return null;

        const payload = self.buf[self.offset + NLMSG_HDRLEN .. self.offset + len];
        const aligned = nlmsgAlign(len);
        self.offset = if (self.offset + aligned <= self.buf.len)
            self.offset + aligned
        else
            self.buf.len;
        return .{ .hdr = hdr.*, .payload = payload };
    }
};

/// Parse an `NLMSG_ERROR` payload. Layout:
///     struct nlmsgerr { __s32 error; struct nlmsghdr msg; ... }
/// Returns the raw (negated) errno the kernel sent back; `0`
/// means success ACK.
pub fn parseNlmsgerr(payload: []const u8) Error!i32 {
    if (payload.len < @sizeOf(i32)) return error.TruncatedMessage;
    return mem.readInt(i32, payload[0..@sizeOf(i32)], .little);
}

/// Subsystem IDs for `NFNL_SUBSYS_*` — the upper byte of the
/// netlink message type field when talking to netfilter.
pub const NFNL = struct {
    pub const SUBSYS_NFTABLES: u16 = 10;
    pub const SUBSYS_IPSET: u16 = 6;
};

/// Pack an `NFNL_SUBSYS_*` subsystem ID with a subsystem-specific
/// message ID into a 16-bit netlink type. This is the canonical
/// encoding for netfilter netlink messages.
pub fn nfnlMsgType(subsys: u16, msg: u16) u16 {
    return (subsys << 8) | (msg & 0xff);
}

/// Minimal netfilter-netlink header that sits between the
/// `nlmsghdr` and the message-specific payload. From
/// `linux/netfilter/nfnetlink.h`:
///     struct nfgenmsg {
///         __u8  nfgen_family;
///         __u8  version;
///         __be16 res_id;
///     };
pub const nfgenmsg = extern struct {
    nfgen_family: u8,
    version: u8 = 0,
    /// Big-endian on the wire. Callers that care set it explicitly
    /// via `std.mem.nativeToBig`.
    res_id: u16 = 0,
};

/// Address families used in `nfgen_family`. Subset — we only use
/// `INET` (for `inet` family tables) and `UNSPEC` (ipset, which
/// doesn't care).
pub const NFPROTO = struct {
    pub const UNSPEC: u8 = 0;
    pub const INET: u8 = 1;
    pub const IPV4: u8 = 2;
    pub const IPV6: u8 = 10;
};

// ===========================================================================
// Batch support
// ===========================================================================

/// Transaction state for an atomic nftables batch. The nftables
/// kernel implementation requires every batch to be bracketed by
/// `NFNL_MSG_BATCH_BEGIN` and `NFNL_MSG_BATCH_END` generic netlink
/// messages carrying the subsystem ID in `res_id`.
pub const Batch = struct {
    builder: MessageBuilder,
    /// Cached sequence number of the BEGIN frame — the kernel
    /// correlates the whole batch by this.
    begin_seq: u32 = 0,
    opened: bool = false,

    /// Control messages defined in `linux/netfilter/nfnetlink.h`.
    pub const NFNL_MSG_BATCH_BEGIN: u16 = 0x10;
    pub const NFNL_MSG_BATCH_END: u16 = 0x11;

    pub fn init(buf: []u8) Batch {
        return .{ .builder = MessageBuilder.init(buf) };
    }

    /// Open the batch. Writes a BEGIN frame carrying the target
    /// subsystem (typically `NFNL.SUBSYS_NFTABLES`) in `res_id`.
    pub fn begin(self: *Batch, seq: u32, pid: u32, subsys: u16) Error!void {
        if (self.opened) return error.InvalidBatchState;
        const ng: nfgenmsg = .{
            .nfgen_family = NFPROTO.UNSPEC,
            .version = 0,
            .res_id = mem.nativeToBig(u16, subsys),
        };
        const payload = mem.asBytes(&ng);
        try self.builder.append(
            NFNL_MSG_BATCH_BEGIN,
            linux.NLM_F_REQUEST,
            seq,
            pid,
            payload,
        );
        self.begin_seq = seq;
        self.opened = true;
    }

    /// Append a message to the open batch.
    pub fn add(
        self: *Batch,
        msg_type: u16,
        flags: u16,
        seq: u32,
        pid: u32,
        payload: []const u8,
    ) Error!void {
        if (!self.opened) return error.InvalidBatchState;
        try self.builder.append(msg_type, flags, seq, pid, payload);
    }

    /// Close the batch with an END frame. The returned slice is
    /// the complete multi-message buffer ready to pass to
    /// `NetlinkSocket.send`.
    pub fn commit(self: *Batch, seq: u32, pid: u32, subsys: u16) Error![]const u8 {
        if (!self.opened) return error.InvalidBatchState;
        const ng: nfgenmsg = .{
            .nfgen_family = NFPROTO.UNSPEC,
            .version = 0,
            .res_id = mem.nativeToBig(u16, subsys),
        };
        const payload = mem.asBytes(&ng);
        try self.builder.append(
            NFNL_MSG_BATCH_END,
            linux.NLM_F_REQUEST,
            seq,
            pid,
            payload,
        );
        self.opened = false;
        return self.builder.bytes();
    }
};

// ===========================================================================
// Tests
// ===========================================================================

test "netlink: alignment rounds up to 4" {
    try std.testing.expectEqual(@as(usize, 0), nlmsgAlign(0));
    try std.testing.expectEqual(@as(usize, 4), nlmsgAlign(1));
    try std.testing.expectEqual(@as(usize, 4), nlmsgAlign(3));
    try std.testing.expectEqual(@as(usize, 4), nlmsgAlign(4));
    try std.testing.expectEqual(@as(usize, 8), nlmsgAlign(5));
    try std.testing.expectEqual(@as(usize, 16), nlmsgAlign(13));
    try std.testing.expectEqual(@as(usize, 16), nlmsgAlign(16));
}

test "netlink: header length is 16 bytes" {
    try std.testing.expectEqual(@as(usize, 16), NLMSG_HDRLEN);
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(linux.nlmsghdr));
}

test "netlink: MessageBuilder writes correct header bytes" {
    var buf: [32]u8 = undefined;
    var b = MessageBuilder.init(&buf);
    const payload = [_]u8{ 0xAA, 0xBB };
    try b.append(0x1234, linux.NLM_F_REQUEST | linux.NLM_F_ACK, 0x42, 0x1000, &payload);

    // Expected frame: [len=18 | type=0x1234 | flags=0x05 | seq=0x42 | pid=0x1000 | payload 2B | pad 2B]
    const out = b.bytes();
    try std.testing.expectEqual(@as(usize, 20), out.len); // 16 hdr + 4 (2B payload + 2B pad)
    try std.testing.expectEqual(@as(u32, 18), mem.readInt(u32, out[0..4], .little));
    try std.testing.expectEqual(@as(u16, 0x1234), mem.readInt(u16, out[4..6], .little));
    try std.testing.expectEqual(
        @as(u16, linux.NLM_F_REQUEST | linux.NLM_F_ACK),
        mem.readInt(u16, out[6..8], .little),
    );
    try std.testing.expectEqual(@as(u32, 0x42), mem.readInt(u32, out[8..12], .little));
    try std.testing.expectEqual(@as(u32, 0x1000), mem.readInt(u32, out[12..16], .little));
    try std.testing.expectEqual(@as(u8, 0xAA), out[16]);
    try std.testing.expectEqual(@as(u8, 0xBB), out[17]);
    // Padding bytes must be zeroed.
    try std.testing.expectEqual(@as(u8, 0), out[18]);
    try std.testing.expectEqual(@as(u8, 0), out[19]);
}

test "netlink: MessageBuilder returns BufferTooSmall" {
    var buf: [8]u8 = undefined;
    var b = MessageBuilder.init(&buf);
    try std.testing.expectError(
        error.BufferTooSmall,
        b.append(0x01, 0, 1, 0, &[_]u8{}),
    );
}

test "netlink: MessageIterator walks multiple frames" {
    var buf: [128]u8 = undefined;
    var b = MessageBuilder.init(&buf);
    try b.append(0x10, 0, 1, 0, &[_]u8{ 0xDE, 0xAD });
    try b.append(0x20, 0, 2, 0, &[_]u8{ 0xBE, 0xEF, 0xCA, 0xFE });
    try b.append(0x30, 0, 3, 0, &[_]u8{});

    var it = MessageIterator.init(b.bytes());
    const a = it.next() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u16, 0x10), @intFromEnum(a.hdr.type));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD }, a.payload);

    const b2 = it.next() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u16, 0x20), @intFromEnum(b2.hdr.type));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xBE, 0xEF, 0xCA, 0xFE }, b2.payload);

    const c = it.next() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u16, 0x30), @intFromEnum(c.hdr.type));
    try std.testing.expectEqualSlices(u8, &[_]u8{}, c.payload);

    try std.testing.expect(it.next() == null);
}

test "netlink: parseNlmsgerr extracts errno" {
    const payload = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF }; // -1 as i32 LE
    try std.testing.expectEqual(@as(i32, -1), try parseNlmsgerr(&payload));

    const ok = [_]u8{ 0x00, 0x00, 0x00, 0x00 };
    try std.testing.expectEqual(@as(i32, 0), try parseNlmsgerr(&ok));

    try std.testing.expectError(
        error.TruncatedMessage,
        parseNlmsgerr(&[_]u8{ 0x00, 0x00 }),
    );
}

test "netlink: nfnlMsgType packs subsys + msg" {
    try std.testing.expectEqual(
        @as(u16, (10 << 8) | 2),
        nfnlMsgType(NFNL.SUBSYS_NFTABLES, 2),
    );
    try std.testing.expectEqual(
        @as(u16, (6 << 8) | 9),
        nfnlMsgType(NFNL.SUBSYS_IPSET, 9),
    );
    // Msg byte must be masked to 8 bits.
    try std.testing.expectEqual(
        @as(u16, (10 << 8) | 0x55),
        nfnlMsgType(10, 0x155),
    );
}

test "netlink: Batch emits BEGIN and END frames around added messages" {
    var buf: [256]u8 = undefined;
    var batch = Batch.init(&buf);

    try batch.begin(1, 0x4242, NFNL.SUBSYS_NFTABLES);
    try batch.add(
        nfnlMsgType(NFNL.SUBSYS_NFTABLES, 2), // NFT_MSG_NEWTABLE
        linux.NLM_F_REQUEST | linux.NLM_F_ACK | linux.NLM_F_CREATE,
        2,
        0x4242,
        &[_]u8{ 0xAA, 0xBB, 0xCC, 0xDD },
    );
    const out = try batch.commit(3, 0x4242, NFNL.SUBSYS_NFTABLES);

    var it = MessageIterator.init(out);
    const begin = it.next() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        @as(u16, Batch.NFNL_MSG_BATCH_BEGIN),
        @intFromEnum(begin.hdr.type),
    );
    try std.testing.expectEqual(@as(u32, 1), begin.hdr.seq);
    // res_id is big-endian on the wire — kernel expects SUBSYS_NFTABLES.
    try std.testing.expectEqual(@as(u8, NFPROTO.UNSPEC), begin.payload[0]);
    const res_id_begin = mem.readInt(u16, begin.payload[2..4], .big);
    try std.testing.expectEqual(@as(u16, NFNL.SUBSYS_NFTABLES), res_id_begin);

    const mid = it.next() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        @as(u16, nfnlMsgType(NFNL.SUBSYS_NFTABLES, 2)),
        @intFromEnum(mid.hdr.type),
    );
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB, 0xCC, 0xDD }, mid.payload);

    const end = it.next() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        @as(u16, Batch.NFNL_MSG_BATCH_END),
        @intFromEnum(end.hdr.type),
    );
    try std.testing.expectEqual(@as(u32, 3), end.hdr.seq);

    try std.testing.expect(it.next() == null);
}

test "netlink: Batch rejects out-of-order operations" {
    var buf: [128]u8 = undefined;
    var batch = Batch.init(&buf);

    // add before begin
    try std.testing.expectError(
        error.InvalidBatchState,
        batch.add(0x10, 0, 1, 0, &[_]u8{}),
    );

    // double begin
    try batch.begin(1, 0, NFNL.SUBSYS_NFTABLES);
    try std.testing.expectError(
        error.InvalidBatchState,
        batch.begin(2, 0, NFNL.SUBSYS_NFTABLES),
    );

    // commit closes; subsequent add must fail
    _ = try batch.commit(2, 0, NFNL.SUBSYS_NFTABLES);
    try std.testing.expectError(
        error.InvalidBatchState,
        batch.add(0x10, 0, 3, 0, &[_]u8{}),
    );
}

test "netlink: open real socket or skip when not privileged" {
    // Opening a netlink socket does NOT require root on any modern
    // kernel, but binding may fail in restricted sandboxes. Skip
    // when we can't create the socket at all.
    var sock = NetlinkSocket.init(linux.NETLINK.NETFILTER) catch {
        return error.SkipZigTest;
    };
    defer sock.close();

    try std.testing.expect(sock.fd >= 0);
    try std.testing.expect(sock.port_id != 0);
    try std.testing.expectEqual(@as(u32, 1), sock.nextSeq());
    try std.testing.expectEqual(@as(u32, 2), sock.nextSeq());
}

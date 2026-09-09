// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;
const mem = std.mem;

pub const NLMSG_ALIGNTO: usize = 4;

pub fn nlmsgAlign(len: usize) usize {
    return (len + NLMSG_ALIGNTO - 1) & ~@as(usize, NLMSG_ALIGNTO - 1);
}

pub const NLMSG_HDRLEN: usize = nlmsgAlign(@sizeOf(linux.nlmsghdr));

pub const Error = error{
    SocketFailed,
    ProtocolUnsupported,
    SendFailed,
    RecvFailed,
    NetlinkError,
    NotFound,
    AlreadyExists,
    PermissionDenied,
    InvalidArgument,
    Timeout,
    TruncatedMessage,
    BufferTooSmall,
    InvalidBatchState,
};

pub fn errnoToError(errno: i32) Error {
    const v: i32 = if (errno < 0) -errno else errno;
    return switch (v) {
        2 => error.NotFound,
        13 => error.PermissionDenied,
        1 => error.PermissionDenied,
        17 => error.AlreadyExists,
        22 => error.InvalidArgument,
        else => error.NetlinkError,
    };
}

pub const NetlinkSocket = struct {
    fd: posix.socket_t,
    seq: u32 = 1,
    port_id: u32 = 0,

    pub fn init(protocol: u32) Error!NetlinkSocket {
        const flags = posix.SOCK.RAW | posix.SOCK.CLOEXEC;
        const fd = posix.socket(posix.AF.NETLINK, flags, @intCast(protocol)) catch |err| switch (err) {
            error.ProtocolNotSupported,
            error.AddressFamilyNotSupported,
            error.ProtocolFamilyNotAvailable,
            => return error.ProtocolUnsupported,
            error.PermissionDenied => return error.PermissionDenied,
            else => return error.SocketFailed,
        };
        errdefer posix.close(fd);

        var addr: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
        posix.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.nl)) catch {
            return error.SocketFailed;
        };

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

    pub fn nextSeq(self: *NetlinkSocket) u32 {
        const s = self.seq;
        self.seq = if (s == std.math.maxInt(u32)) 1 else s + 1;
        return s;
    }

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

    pub fn recv(self: *NetlinkSocket, buf: []u8) Error![]u8 {
        const n = posix.recv(self.fd, buf, 0) catch |err| switch (err) {
            error.WouldBlock => return error.Timeout,
            else => return error.RecvFailed,
        };
        if (n == 0) return error.TruncatedMessage;
        return buf[0..n];
    }

    pub fn setRecvTimeout(self: *NetlinkSocket, ms: u64) Error!void {
        // timeval field widths are target-dependent (i32 on 32-bit musl); @FieldType keeps armv7 compiling.
        const secs: @FieldType(posix.timeval, "sec") = @intCast(ms / 1000);
        const usecs: @FieldType(posix.timeval, "usec") = @intCast((ms % 1000) * 1000);
        const tv: posix.timeval = .{ .sec = secs, .usec = usecs };
        posix.setsockopt(
            self.fd,
            posix.SOL.SOCKET,
            posix.SO.RCVTIMEO,
            mem.asBytes(&tv),
        ) catch return error.SocketFailed;
    }

    pub fn drainAck(
        self: *NetlinkSocket,
        expected_seqs: []const u32,
        scratch: []u8,
    ) Error!void {
        if (expected_seqs.len == 0) return;

        var bits: u64 = 0;
        const use_bitset = expected_seqs.len <= 64;
        if (use_bitset) {
            bits = if (expected_seqs.len == 64) std.math.maxInt(u64) else (@as(u64, 1) << @intCast(expected_seqs.len)) - 1;
        }
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
                if (@intFromEnum(msg.hdr.type) != @as(u16, 2)) continue;
                const errno = try parseNlmsgerr(msg.payload);

                if (errno != 0) return errnoToError(errno);

                const seq = msg.hdr.seq;
                var matched_idx: ?usize = null;
                for (expected_seqs, 0..) |s, idx| {
                    if (s == seq) {
                        matched_idx = idx;
                        break;
                    }
                }
                if (matched_idx == null) continue;
                if (use_bitset) {
                    bits &= ~(@as(u64, 1) << @intCast(matched_idx.?));
                } else {
                    done_flags[matched_idx.?] = true;
                }
            }
        }
    }
};

pub const MessageBuilder = struct {
    buf: []u8,
    offset: usize = 0,

    pub fn init(buf: []u8) MessageBuilder {
        return .{ .buf = buf };
    }

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

        const hdr_ptr: *linux.nlmsghdr = @alignCast(@ptrCast(&self.buf[self.offset]));
        hdr_ptr.* = .{
            .len = @intCast(total),
            .type = @enumFromInt(msg_type),
            .flags = flags,
            .seq = seq,
            .pid = pid,
        };

        if (payload.len > 0) {
            @memcpy(
                self.buf[self.offset + NLMSG_HDRLEN .. self.offset + total],
                payload,
            );
        }
        if (aligned > total) {
            @memset(self.buf[self.offset + total .. self.offset + aligned], 0);
        }

        self.offset += aligned;
    }

    pub fn bytes(self: *const MessageBuilder) []const u8 {
        return self.buf[0..self.offset];
    }
};

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

pub fn parseNlmsgerr(payload: []const u8) Error!i32 {
    if (payload.len < @sizeOf(i32)) return error.TruncatedMessage;
    return mem.readInt(i32, payload[0..@sizeOf(i32)], .little);
}

pub const NFNL = struct {
    pub const SUBSYS_NFTABLES: u16 = 10;
    pub const SUBSYS_IPSET: u16 = 6;
};

pub fn nfnlMsgType(subsys: u16, msg: u16) u16 {
    return (subsys << 8) | (msg & 0xff);
}

pub const nfgenmsg = extern struct {
    nfgen_family: u8,
    version: u8 = 0,
    res_id: u16 = 0,
};

pub const NFPROTO = struct {
    pub const UNSPEC: u8 = 0;
    pub const INET: u8 = 1;
    pub const IPV4: u8 = 2;
    pub const IPV6: u8 = 10;
};

pub const Batch = struct {
    builder: MessageBuilder,
    begin_seq: u32 = 0,
    opened: bool = false,

    pub const NFNL_MSG_BATCH_BEGIN: u16 = 0x10;
    pub const NFNL_MSG_BATCH_END: u16 = 0x11;

    pub fn init(buf: []u8) Batch {
        return .{ .builder = MessageBuilder.init(buf) };
    }

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

    const out = b.bytes();
    try std.testing.expectEqual(@as(usize, 20), out.len);
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
    const payload = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF };
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
        nfnlMsgType(NFNL.SUBSYS_NFTABLES, 2),
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

    try std.testing.expectError(
        error.InvalidBatchState,
        batch.add(0x10, 0, 1, 0, &[_]u8{}),
    );

    try batch.begin(1, 0, NFNL.SUBSYS_NFTABLES);
    try std.testing.expectError(
        error.InvalidBatchState,
        batch.begin(2, 0, NFNL.SUBSYS_NFTABLES),
    );

    _ = try batch.commit(2, 0, NFNL.SUBSYS_NFTABLES);
    try std.testing.expectError(
        error.InvalidBatchState,
        batch.add(0x10, 0, 3, 0, &[_]u8{}),
    );
}

test "netlink: open real socket or skip when not privileged" {
    var sock = NetlinkSocket.init(linux.NETLINK.NETFILTER) catch {
        return error.SkipZigTest;
    };
    defer sock.close();

    try std.testing.expect(sock.fd >= 0);
    try std.testing.expect(sock.port_id != 0);
    try std.testing.expectEqual(@as(u32, 1), sock.nextSeq());
    try std.testing.expectEqual(@as(u32, 2), sock.nextSeq());
}

test "netlink: init maps an unsupported netlink protocol to ProtocolUnsupported (SYS-014)" {
    const bogus_protocol: u32 = 255;
    const result = NetlinkSocket.init(bogus_protocol);
    if (result) |sock| {
        var s = sock;
        s.close();
        return error.SkipZigTest;
    } else |err| switch (err) {
        error.ProtocolUnsupported => {},
        else => return error.SkipZigTest,
    }
}

fn testSocketpair() ?[2]i32 {
    var fds: [2]i32 = undefined;
    const rc = linux.socketpair(posix.AF.UNIX, posix.SOCK.DGRAM, 0, &fds);
    if (linux.E.init(rc) != .SUCCESS) return null;
    return fds;
}

fn buildNlmsgErr(buf: []u8, seq: u32, errno: i32) []const u8 {
    var b = MessageBuilder.init(buf);
    var payload: [4]u8 = undefined;
    mem.writeInt(i32, &payload, errno, .little);
    b.append(@as(u16, 2), 0, seq, 0, &payload) catch unreachable;
    return b.bytes();
}

test "netlink: drainAck surfaces a non-zero errno on an UNEXPECTED seq (SYS-014)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const fds = testSocketpair() orelse return error.SkipZigTest;
    var writer_open = true;
    defer posix.close(fds[1]);
    defer if (writer_open) posix.close(fds[0]);

    var frame_buf: [64]u8 = undefined;
    const frame = buildNlmsgErr(&frame_buf, 1, -1);
    _ = posix.send(fds[0], frame, 0) catch return error.SkipZigTest;
    posix.close(fds[0]);
    writer_open = false;

    var sock = NetlinkSocket{ .fd = fds[1] };
    sock.setRecvTimeout(500) catch return error.SkipZigTest;
    var scratch: [256]u8 = undefined;
    const result = sock.drainAck(&[_]u32{2}, &scratch);
    try std.testing.expectError(error.PermissionDenied, result);
}

test "netlink: drainAck maps each errno class on an unexpected seq (SYS-014)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const Case = struct { errno: i32, want: anyerror };
    const cases = [_]Case{
        .{ .errno = -1, .want = error.PermissionDenied },
        .{ .errno = -13, .want = error.PermissionDenied },
        .{ .errno = -2, .want = error.NotFound },
        .{ .errno = -17, .want = error.AlreadyExists },
        .{ .errno = -22, .want = error.InvalidArgument },
    };
    for (cases) |c| {
        const fds = testSocketpair() orelse return error.SkipZigTest;
        defer posix.close(fds[1]);
        var frame_buf: [64]u8 = undefined;
        const frame = buildNlmsgErr(&frame_buf, 1, c.errno);
        _ = posix.send(fds[0], frame, 0) catch return error.SkipZigTest;
        posix.close(fds[0]);
        var sock = NetlinkSocket{ .fd = fds[1] };
        sock.setRecvTimeout(500) catch return error.SkipZigTest;
        var scratch: [256]u8 = undefined;
        try std.testing.expectError(c.want, sock.drainAck(&[_]u32{2}, &scratch));
    }
}

test "netlink: drainAck does NOT surface a SUCCESS ack on an unexpected seq (SYS-014)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const fds = testSocketpair() orelse return error.SkipZigTest;
    defer posix.close(fds[1]);
    var frame_buf: [64]u8 = undefined;
    const frame = buildNlmsgErr(&frame_buf, 99, 0);
    _ = posix.send(fds[0], frame, 0) catch return error.SkipZigTest;
    posix.close(fds[0]);

    var sock = NetlinkSocket{ .fd = fds[1] };
    sock.setRecvTimeout(200) catch return error.SkipZigTest;
    var scratch: [256]u8 = undefined;
    const result = sock.drainAck(&[_]u32{2}, &scratch);
    try std.testing.expect(result == error.Timeout or result == error.TruncatedMessage);
}

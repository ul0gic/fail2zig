// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const native_endian = @import("builtin").cpu.arch.endian();
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
    DumpInterrupted,
    EventsOverflowed,
};

pub const StrictMessages = struct {
    bytes: []const u8,
    offset: usize = 0,

    pub fn next(self: *StrictMessages) Error!?MessageIterator.View {
        if (self.offset == self.bytes.len) return null;
        const tail = self.bytes[self.offset..];
        if (tail.len < NLMSG_HDRLEN) return error.TruncatedMessage;
        const hdr: linux.nlmsghdr = @bitCast(tail[0..@sizeOf(linux.nlmsghdr)].*);
        const len: usize = hdr.len;
        if (len < NLMSG_HDRLEN or len > tail.len) return error.TruncatedMessage;
        const padded = std.math.add(usize, len, 3) catch return error.TruncatedMessage;
        const aligned = padded & ~@as(usize, 3);
        if (aligned > tail.len) return error.TruncatedMessage;
        self.offset += aligned;
        return .{ .hdr = hdr, .payload = tail[NLMSG_HDRLEN..len] };
    }
};

pub const Attributes = struct {
    bytes: []const u8,
    offset: usize = 0,
    pub const View = struct { kind: u16, flags: u16, value: []const u8 };

    pub fn next(self: *Attributes) Error!?View {
        if (self.offset == self.bytes.len) return null;
        const tail = self.bytes[self.offset..];
        if (tail.len < 4) return error.TruncatedMessage;
        const len: usize = mem.readInt(u16, tail[0..2], native_endian);
        const kind = mem.readInt(u16, tail[2..4], native_endian);
        if (len < 4 or len > tail.len) return error.TruncatedMessage;
        const aligned = (len + 3) & ~@as(usize, 3);
        if (aligned > tail.len) return error.TruncatedMessage;
        self.offset += aligned;
        return .{ .kind = kind & 0x3fff, .flags = kind & 0xc000, .value = tail[4..len] };
    }
};

pub fn recvKernel(sock: *NetlinkSocket, scratch: []u8) Error![]const u8 {
    var sender: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
    var iov = posix.iovec{ .base = scratch.ptr, .len = scratch.len };
    var msg: linux.msghdr = .{
        .name = @ptrCast(&sender),
        .namelen = @sizeOf(linux.sockaddr.nl),
        .iov = @ptrCast(&iov),
        .iovlen = 1,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };
    const rc = linux.recvmsg(sock.fd, &msg, 0);
    switch (linux.E.init(rc)) {
        .SUCCESS => {},
        .AGAIN => return error.Timeout,
        else => return error.RecvFailed,
    }
    try validateKernelEnvelope(sender, msg.namelen, msg.flags, rc, scratch.len);
    return scratch[0..rc];
}

pub fn recvEvents(sock: *NetlinkSocket, scratch: []u8) Error!?[]const u8 {
    var sender: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
    var iov = posix.iovec{ .base = scratch.ptr, .len = scratch.len };
    var msg: linux.msghdr = .{
        .name = @ptrCast(&sender),
        .namelen = @sizeOf(linux.sockaddr.nl),
        .iov = @ptrCast(&iov),
        .iovlen = 1,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };
    const rc = linux.recvmsg(sock.fd, &msg, linux.MSG.DONTWAIT);
    switch (linux.E.init(rc)) {
        .SUCCESS => {},
        .AGAIN => return null,
        .NOBUFS => return error.EventsOverflowed,
        else => return error.RecvFailed,
    }
    const expected_groups = @as(u32, 1) << @intCast(sock.group - 1);
    if (msg.namelen != @sizeOf(linux.sockaddr.nl) or sender.family != posix.AF.NETLINK or sender.pid != 0 or sender.groups != expected_groups) return error.RecvFailed;
    if ((msg.flags & (linux.MSG.TRUNC | linux.MSG.CTRUNC)) != 0 or rc == 0 or rc > scratch.len) return error.TruncatedMessage;
    return scratch[0..rc];
}

pub fn sendKernel(sock: *NetlinkSocket, bytes: []const u8, timeout_ms: u64) Error!void {
    if (timeout_ms == 0 or timeout_ms > 2000) return error.InvalidArgument;
    const value = posix.timeval{ .sec = @intCast(timeout_ms / 1000), .usec = @intCast((timeout_ms % 1000) * 1000) };
    posix.setsockopt(sock.fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, mem.asBytes(&value)) catch return error.SocketFailed;
    var address = linux.sockaddr.nl{ .pid = 0, .groups = 0 };
    const sent = posix.sendto(sock.fd, bytes, 0, @ptrCast(&address), @sizeOf(linux.sockaddr.nl)) catch |err| return switch (err) {
        error.WouldBlock => error.Timeout,
        else => error.SendFailed,
    };
    if (sent != bytes.len) return error.SendFailed;
}

fn validateKernelEnvelope(sender: linux.sockaddr.nl, name_len: usize, flags: i32, received: usize, capacity: usize) Error!void {
    if (name_len != @sizeOf(linux.sockaddr.nl) or sender.family != posix.AF.NETLINK or
        sender.pid != 0 or sender.groups != 0) return error.RecvFailed;
    if ((flags & (linux.MSG.TRUNC | linux.MSG.CTRUNC)) != 0 or received == 0 or received > capacity)
        return error.TruncatedMessage;
}

pub const Dump = struct {
    sequence: u32,
    message_type: u16,
    port_id: u32,
    complete: bool = false,
    generation: ?u16 = null,
    count: usize = 0,
    max_messages: usize = 65_536,

    pub fn accept(self: *Dump, item: MessageIterator.View) Error!?[]const u8 {
        if (self.count >= self.max_messages) return error.BufferTooSmall;
        self.count += 1;
        if (item.hdr.seq != self.sequence) return null;
        if (self.complete or (item.hdr.pid != 0 and item.hdr.pid != self.port_id)) return error.NetlinkError;
        // NLM_F_DUMP_INTR: the kernel's generation moved during this dump, so the
        // reply is not one consistent picture and the whole dump must be re-read.
        if ((item.hdr.flags & 0x10) != 0) return error.DumpInterrupted;
        const kind = @intFromEnum(item.hdr.type);
        if (kind == 2) {
            if (item.payload.len < 4 + NLMSG_HDRLEN) return error.TruncatedMessage;
            const request: linux.nlmsghdr = @bitCast(item.payload[4..][0..@sizeOf(linux.nlmsghdr)].*);
            if (request.seq != self.sequence) return error.NetlinkError;
            const code = try parseNlmsgerr(item.payload);
            if (code != 0) return safeErrno(code);
            return null;
        }
        if (kind == 3) {
            if (item.payload.len != 0) {
                const code = try parseNlmsgerr(item.payload);
                if (code != 0) return safeErrno(code);
            }
            self.complete = true;
            return null;
        }
        if (kind != self.message_type or (item.hdr.flags & 2) == 0) return error.NetlinkError;
        if (item.payload.len < @sizeOf(nfgenmsg)) return error.TruncatedMessage;
        // nfgenmsg.res_id, big-endian at payload bytes 2..4, is the base sequence; Linux 6.12 never sets NLM_F_DUMP_INTR on set-element dumps.
        const generation = mem.readInt(u16, item.payload[2..4], .big);
        if (self.generation) |first| {
            if (first != generation) return error.DumpInterrupted;
        } else {
            self.generation = generation;
        }
        return item.payload;
    }
};

fn safeErrno(code: i32) Error {
    if (code == std.math.minInt(i32)) return error.NetlinkError;
    return errnoToError(code);
}

pub const max_related = 4096;
pub const Acknowledgments = struct {
    required: []const u32,
    related: []const u32,
    port_id: u32,
    seen: u64 = 0,
    count: usize = 0,

    pub fn init(required: []const u32, related: []const u32, port_id: u32) Error!Acknowledgments {
        if (required.len == 0 or required.len > 64 or related.len > max_related) return error.InvalidArgument;
        for (required, 0..) |seq, index| {
            if (mem.indexOfScalar(u32, related, seq) == null or mem.indexOfScalar(u32, required[0..index], seq) != null) return error.InvalidArgument;
        }
        return .{ .required = required, .related = related, .port_id = port_id };
    }
    pub fn complete(self: *const Acknowledgments) bool {
        const mask = if (self.required.len == 64) std.math.maxInt(u64) else (@as(u64, 1) << @intCast(self.required.len)) - 1;
        return self.seen == mask;
    }
    pub fn accept(self: *Acknowledgments, item: MessageIterator.View) Error!void {
        if (self.count >= 65_536) return error.BufferTooSmall;
        self.count += 1;
        if (mem.indexOfScalar(u32, self.related, item.hdr.seq) == null) return;
        if ((item.hdr.pid != 0 and item.hdr.pid != self.port_id) or @intFromEnum(item.hdr.type) != 2) return error.NetlinkError;
        if (item.payload.len < 4 + NLMSG_HDRLEN) return error.TruncatedMessage;
        const request: linux.nlmsghdr = @bitCast(item.payload[4..][0..@sizeOf(linux.nlmsghdr)].*);
        if (request.seq != item.hdr.seq) return error.NetlinkError;
        const code = try parseNlmsgerr(item.payload);
        if (code != 0) return safeErrno(code);
        if (mem.indexOfScalar(u32, self.required, item.hdr.seq)) |index| self.seen |= @as(u64, 1) << @intCast(index);
    }
};

pub fn receiveAcknowledgments(sock: *NetlinkSocket, required: []const u32, related: []const u32, timeout_ms: u64) Error!void {
    if (timeout_ms == 0 or timeout_ms > 2000) return error.InvalidArgument;
    var state = try Acknowledgments.init(required, related, sock.port_id);
    var timer = std.time.Timer.start() catch return error.SocketFailed;
    var bytes: [8192]u8 = undefined;
    var datagrams: usize = 0;
    while (!state.complete()) {
        const elapsed = timer.read() / std.time.ns_per_ms;
        if (elapsed >= timeout_ms) return error.Timeout;
        if (datagrams >= 65_536) return error.BufferTooSmall;
        datagrams += 1;
        try sock.setRecvTimeout(timeout_ms - elapsed);
        var messages = StrictMessages{ .bytes = try recvKernel(sock, &bytes) };
        while (try messages.next()) |item| try state.accept(item);
    }
}

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

// linux/netlink.h: SOL_NETLINK option joining one multicast group by number.
const NETLINK_ADD_MEMBERSHIP: u32 = 1;
// 4 MiB holds about forty 1,024-element install batches of events between the worker's 100 ms drains.
pub const event_receive_bytes: u32 = 4 << 20;

pub const NetlinkSocket = struct {
    fd: posix.socket_t,
    seq: u32 = 1,
    port_id: u32 = 0,
    group: u32 = 0,

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

    pub fn initEvents(group: u32) Error!NetlinkSocket {
        if (group == 0 or group > 32) return error.InvalidArgument;
        var sock = try init(linux.NETLINK.NETFILTER);
        errdefer sock.close();
        posix.setsockopt(sock.fd, linux.SOL.NETLINK, NETLINK_ADD_MEMBERSHIP, mem.asBytes(&group)) catch |err| return switch (err) {
            error.PermissionDenied => error.PermissionDenied,
            else => error.SocketFailed,
        };
        const bytes: u32 = event_receive_bytes;
        posix.setsockopt(sock.fd, posix.SOL.SOCKET, linux.SO.RCVBUFFORCE, mem.asBytes(&bytes)) catch {
            posix.setsockopt(sock.fd, posix.SOL.SOCKET, posix.SO.RCVBUF, mem.asBytes(&bytes)) catch return error.SocketFailed;
        };
        sock.group = group;
        return sock;
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

    pub fn setSendBuffer(self: *NetlinkSocket, bytes: u32) Error!void {
        const value = mem.asBytes(&bytes);
        posix.setsockopt(self.fd, posix.SOL.SOCKET, linux.SO.SNDBUFFORCE, value) catch {
            posix.setsockopt(self.fd, posix.SOL.SOCKET, posix.SO.SNDBUF, value) catch return error.SocketFailed;
        };
    }

    pub fn setRecvTimeout(self: *NetlinkSocket, ms: u64) Error!void {
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
    return mem.readInt(i32, payload[0..@sizeOf(i32)], native_endian);
}

pub const NFNL = struct {
    pub const SUBSYS_NFTABLES: u16 = 10;
    pub const SUBSYS_IPSET: u16 = 6;
    pub const GRP_NFTABLES: u32 = 7;
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
        // The kernel queues the END ack only after the commit succeeded (Linux 6.12 nfnetlink.c); it is the proof the batch committed.
        try self.builder.append(
            NFNL_MSG_BATCH_END,
            linux.NLM_F_REQUEST | linux.NLM_F_ACK,
            seq,
            pid,
            payload,
        );
        self.opened = false;
        return self.builder.bytes();
    }
};

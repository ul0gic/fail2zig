// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! IPC protocol between the fail2zig daemon and fail2zig-client.
//!
//! Wire format:
//!   [u32 payload_size little-endian][payload_size bytes of body]
//!
//! Command body:
//!   [u8 command_id][command-specific fields]
//!
//! Response body:
//!   [u8 response_tag][response-specific fields]

const std = @import("std");
const types = @import("types.zig");

pub const IpAddress = types.IpAddress;
pub const JailId = types.JailId;
pub const Duration = types.Duration;

/// Hard cap on the size of a single message payload. Prevents DoS via
/// attacker-claimed multi-gigabyte length prefixes on an unprivileged socket.
pub const max_payload_size: u32 = 1 << 20; // 1 MiB

pub const CommandId = enum(u8) {
    status = 0,
    ban = 1,
    unban = 2,
    list = 3,
    list_jails = 4,
    reload = 5,
    version = 6,
};

pub const Command = union(CommandId) {
    status: void,
    ban: Ban,
    unban: Unban,
    list: List,
    list_jails: void,
    reload: void,
    version: void,

    pub const Ban = struct {
        ip: IpAddress,
        jail: JailId,
        duration: ?Duration,
    };

    pub const Unban = struct {
        ip: IpAddress,
        jail: ?JailId,
    };

    pub const List = struct {
        jail: ?JailId,
    };
};

pub const ResponseTag = enum(u8) {
    ok = 0,
    err = 1,
};

pub const Response = union(ResponseTag) {
    ok: Ok,
    err: Err,

    pub const Ok = struct { payload: []const u8 };
    pub const Err = struct { code: u16, message: []const u8 };

    /// Free slices owned by a response that was produced by deserializeResponse.
    pub fn deinit(self: Response, allocator: std.mem.Allocator) void {
        switch (self) {
            .ok => |o| allocator.free(o.payload),
            .err => |e| allocator.free(e.message),
        }
    }
};

pub const DeserializeError = error{
    EndOfStream,
    InvalidCommandId,
    InvalidResponseTag,
    InvalidOptionalMarker,
    InvalidIpTag,
    PayloadTooLarge,
    JailIdEmpty,
    JailIdTooLong,
    OutOfMemory,
    ReadFailed,
};

// ============================================================================
// Commands
// ============================================================================

pub fn serializeCommand(cmd: Command, writer: anytype) @TypeOf(writer).Error!void {
    const body_size = commandBodySize(cmd);
    try writer.writeInt(u32, body_size, .little);
    try writeCommandBody(cmd, writer);
}

pub fn deserializeCommand(reader: anytype) DeserializeError!Command {
    const size = readU32(reader) catch |e| return mapReadErr(e);
    if (size > max_payload_size) return error.PayloadTooLarge;
    return readCommandBody(reader);
}

fn commandBodySize(cmd: Command) u32 {
    const body: u32 = switch (cmd) {
        .status, .list_jails, .reload, .version => 0,
        .ban => |b| ipSize(b.ip) + jailIdSize(b.jail) + optDurationSize(b.duration),
        .unban => |u| ipSize(u.ip) + optJailIdSize(u.jail),
        .list => |l| optJailIdSize(l.jail),
    };
    return 1 + body; // +1 for command tag
}

fn writeCommandBody(cmd: Command, writer: anytype) @TypeOf(writer).Error!void {
    try writer.writeByte(@intFromEnum(std.meta.activeTag(cmd)));
    switch (cmd) {
        .status, .list_jails, .reload, .version => {},
        .ban => |b| {
            try writeIp(b.ip, writer);
            try writeJailId(b.jail, writer);
            try writeOptionalDuration(b.duration, writer);
        },
        .unban => |u| {
            try writeIp(u.ip, writer);
            try writeOptionalJailId(u.jail, writer);
        },
        .list => |l| try writeOptionalJailId(l.jail, writer),
    }
}

fn readCommandBody(reader: anytype) DeserializeError!Command {
    const tag_byte = readByte(reader) catch |e| return mapReadErr(e);
    const id = std.meta.intToEnum(CommandId, tag_byte) catch return error.InvalidCommandId;
    return switch (id) {
        .status => .{ .status = {} },
        .list_jails => .{ .list_jails = {} },
        .reload => .{ .reload = {} },
        .version => .{ .version = {} },
        .ban => blk: {
            const ip = try readIp(reader);
            const jail = try readJailId(reader);
            const dur = try readOptionalDuration(reader);
            break :blk .{ .ban = .{ .ip = ip, .jail = jail, .duration = dur } };
        },
        .unban => blk: {
            const ip = try readIp(reader);
            const jail = try readOptionalJailId(reader);
            break :blk .{ .unban = .{ .ip = ip, .jail = jail } };
        },
        .list => blk: {
            const jail = try readOptionalJailId(reader);
            break :blk .{ .list = .{ .jail = jail } };
        },
    };
}

// ============================================================================
// Responses
// ============================================================================

pub fn serializeResponse(resp: Response, writer: anytype) @TypeOf(writer).Error!void {
    const body_size = responseBodySize(resp);
    try writer.writeInt(u32, body_size, .little);
    try writeResponseBody(resp, writer);
}

pub fn deserializeResponse(reader: anytype, allocator: std.mem.Allocator) DeserializeError!Response {
    const size = readU32(reader) catch |e| return mapReadErr(e);
    if (size > max_payload_size) return error.PayloadTooLarge;

    const tag_byte = readByte(reader) catch |e| return mapReadErr(e);
    const tag = std.meta.intToEnum(ResponseTag, tag_byte) catch return error.InvalidResponseTag;
    switch (tag) {
        .ok => {
            const plen = readU32(reader) catch |e| return mapReadErr(e);
            if (plen > max_payload_size) return error.PayloadTooLarge;
            const buf = try allocator.alloc(u8, plen);
            errdefer allocator.free(buf);
            readNoEof(reader, buf) catch |e| return mapReadErr(e);
            return .{ .ok = .{ .payload = buf } };
        },
        .err => {
            const code = readU16(reader) catch |e| return mapReadErr(e);
            const mlen = readU32(reader) catch |e| return mapReadErr(e);
            if (mlen > max_payload_size) return error.PayloadTooLarge;
            const buf = try allocator.alloc(u8, mlen);
            errdefer allocator.free(buf);
            readNoEof(reader, buf) catch |e| return mapReadErr(e);
            return .{ .err = .{ .code = code, .message = buf } };
        },
    }
}

fn responseBodySize(resp: Response) u32 {
    const body: u32 = switch (resp) {
        .ok => |o| 4 + @as(u32, @intCast(o.payload.len)),
        .err => |e| 2 + 4 + @as(u32, @intCast(e.message.len)),
    };
    return 1 + body;
}

fn writeResponseBody(resp: Response, writer: anytype) @TypeOf(writer).Error!void {
    try writer.writeByte(@intFromEnum(std.meta.activeTag(resp)));
    switch (resp) {
        .ok => |o| {
            try writer.writeInt(u32, @intCast(o.payload.len), .little);
            try writer.writeAll(o.payload);
        },
        .err => |e| {
            try writer.writeInt(u16, e.code, .little);
            try writer.writeInt(u32, @intCast(e.message.len), .little);
            try writer.writeAll(e.message);
        },
    }
}

// ============================================================================
// Field encoders / decoders
// ============================================================================

fn ipSize(ip: IpAddress) u32 {
    return switch (ip) {
        .ipv4 => 1 + 4,
        .ipv6 => 1 + 16,
    };
}

fn jailIdSize(j: JailId) u32 {
    return 1 + @as(u32, j.len);
}

fn optJailIdSize(j: ?JailId) u32 {
    return if (j) |jj| 1 + jailIdSize(jj) else 1;
}

fn optDurationSize(d: ?Duration) u32 {
    return if (d != null) 1 + 8 else 1;
}

fn writeIp(ip: IpAddress, writer: anytype) @TypeOf(writer).Error!void {
    switch (ip) {
        .ipv4 => |v| {
            try writer.writeByte(4);
            try writer.writeInt(u32, v, .big);
        },
        .ipv6 => |v| {
            try writer.writeByte(6);
            try writer.writeInt(u128, v, .big);
        },
    }
}

fn readIp(reader: anytype) DeserializeError!IpAddress {
    const tag = readByte(reader) catch |e| return mapReadErr(e);
    return switch (tag) {
        4 => .{ .ipv4 = readU32Big(reader) catch |e| return mapReadErr(e) },
        6 => .{ .ipv6 = readU128Big(reader) catch |e| return mapReadErr(e) },
        else => error.InvalidIpTag,
    };
}

fn writeJailId(jail: JailId, writer: anytype) @TypeOf(writer).Error!void {
    try writer.writeByte(jail.len);
    try writer.writeAll(jail.slice());
}

fn readJailId(reader: anytype) DeserializeError!JailId {
    const len = readByte(reader) catch |e| return mapReadErr(e);
    if (len == 0) return error.JailIdEmpty;
    if (len > JailId.max_len) return error.JailIdTooLong;
    var jail: JailId = .{};
    readNoEof(reader, jail.bytes[0..len]) catch |e| return mapReadErr(e);
    jail.len = len;
    return jail;
}

fn writeOptionalJailId(opt: ?JailId, writer: anytype) @TypeOf(writer).Error!void {
    if (opt) |jail| {
        try writer.writeByte(1);
        try writeJailId(jail, writer);
    } else {
        try writer.writeByte(0);
    }
}

fn readOptionalJailId(reader: anytype) DeserializeError!?JailId {
    const marker = readByte(reader) catch |e| return mapReadErr(e);
    return switch (marker) {
        0 => null,
        1 => try readJailId(reader),
        else => error.InvalidOptionalMarker,
    };
}

fn writeOptionalDuration(opt: ?Duration, writer: anytype) @TypeOf(writer).Error!void {
    if (opt) |d| {
        try writer.writeByte(1);
        try writer.writeInt(u64, d, .little);
    } else {
        try writer.writeByte(0);
    }
}

fn readOptionalDuration(reader: anytype) DeserializeError!?Duration {
    const marker = readByte(reader) catch |e| return mapReadErr(e);
    return switch (marker) {
        0 => null,
        1 => readU64(reader) catch |e| return mapReadErr(e),
        else => error.InvalidOptionalMarker,
    };
}

// ============================================================================
// Reader primitives (wrap `anytype` reader, normalize errors)
// ============================================================================

fn readByte(reader: anytype) !u8 {
    return try reader.readByte();
}

fn readU16(reader: anytype) !u16 {
    return try reader.readInt(u16, .little);
}

fn readU32(reader: anytype) !u32 {
    return try reader.readInt(u32, .little);
}

fn readU64(reader: anytype) !u64 {
    return try reader.readInt(u64, .little);
}

fn readU32Big(reader: anytype) !u32 {
    return try reader.readInt(u32, .big);
}

fn readU128Big(reader: anytype) !u128 {
    return try reader.readInt(u128, .big);
}

fn readNoEof(reader: anytype, buf: []u8) !void {
    try reader.readNoEof(buf);
}

fn mapReadErr(err: anyerror) DeserializeError {
    return switch (err) {
        error.EndOfStream => error.EndOfStream,
        error.OutOfMemory => error.OutOfMemory,
        error.JailIdEmpty => error.JailIdEmpty,
        error.JailIdTooLong => error.JailIdTooLong,
        error.InvalidOptionalMarker => error.InvalidOptionalMarker,
        error.InvalidIpTag => error.InvalidIpTag,
        else => error.ReadFailed,
    };
}

// ============================================================================
// Tests
// ============================================================================

fn roundtripCommand(cmd: Command) !Command {
    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try serializeCommand(cmd, stream.writer());
    stream.reset();
    return try deserializeCommand(stream.reader());
}

test "Command: roundtrip status" {
    const out = try roundtripCommand(.{ .status = {} });
    try std.testing.expect(out == .status);
}

test "Command: roundtrip list_jails" {
    const out = try roundtripCommand(.{ .list_jails = {} });
    try std.testing.expect(out == .list_jails);
}

test "Command: roundtrip reload" {
    const out = try roundtripCommand(.{ .reload = {} });
    try std.testing.expect(out == .reload);
}

test "Command: roundtrip version" {
    const out = try roundtripCommand(.{ .version = {} });
    try std.testing.expect(out == .version);
}

test "Command: roundtrip ban ipv4 with duration" {
    const cmd: Command = .{ .ban = .{
        .ip = try IpAddress.parse("192.168.1.1"),
        .jail = try JailId.fromSlice("sshd"),
        .duration = 600,
    } };
    const out = try roundtripCommand(cmd);
    try std.testing.expect(IpAddress.eql(out.ban.ip, cmd.ban.ip));
    try std.testing.expect(JailId.eql(out.ban.jail, cmd.ban.jail));
    try std.testing.expectEqual(@as(?Duration, 600), out.ban.duration);
}

test "Command: roundtrip ban ipv6 without duration" {
    const cmd: Command = .{ .ban = .{
        .ip = try IpAddress.parse("::1"),
        .jail = try JailId.fromSlice("nginx"),
        .duration = null,
    } };
    const out = try roundtripCommand(cmd);
    try std.testing.expect(IpAddress.eql(out.ban.ip, cmd.ban.ip));
    try std.testing.expect(JailId.eql(out.ban.jail, cmd.ban.jail));
    try std.testing.expectEqual(@as(?Duration, null), out.ban.duration);
}

test "Command: roundtrip unban with jail" {
    const cmd: Command = .{ .unban = .{
        .ip = try IpAddress.parse("10.0.0.5"),
        .jail = try JailId.fromSlice("postfix"),
    } };
    const out = try roundtripCommand(cmd);
    try std.testing.expect(IpAddress.eql(out.unban.ip, cmd.unban.ip));
    try std.testing.expect(out.unban.jail != null);
    try std.testing.expect(JailId.eql(out.unban.jail.?, cmd.unban.jail.?));
}

test "Command: roundtrip unban without jail" {
    const cmd: Command = .{ .unban = .{
        .ip = try IpAddress.parse("10.0.0.5"),
        .jail = null,
    } };
    const out = try roundtripCommand(cmd);
    try std.testing.expectEqual(@as(?JailId, null), out.unban.jail);
}

test "Command: roundtrip list with jail" {
    const cmd: Command = .{ .list = .{
        .jail = try JailId.fromSlice("sshd"),
    } };
    const out = try roundtripCommand(cmd);
    try std.testing.expect(out.list.jail != null);
    try std.testing.expect(JailId.eql(out.list.jail.?, cmd.list.jail.?));
}

test "Command: roundtrip list without jail" {
    const cmd: Command = .{ .list = .{ .jail = null } };
    const out = try roundtripCommand(cmd);
    try std.testing.expectEqual(@as(?JailId, null), out.list.jail);
}

test "Command: reject unknown command id" {
    const bytes = [_]u8{ 0x01, 0x00, 0x00, 0x00, 0xFF }; // size=1, tag=0xFF
    var stream = std.io.fixedBufferStream(&bytes);
    try std.testing.expectError(
        error.InvalidCommandId,
        deserializeCommand(stream.reader()),
    );
}

test "Command: reject oversized payload" {
    var bytes = [_]u8{0} ** 4;
    std.mem.writeInt(u32, bytes[0..4], max_payload_size + 1, .little);
    var stream = std.io.fixedBufferStream(&bytes);
    try std.testing.expectError(
        error.PayloadTooLarge,
        deserializeCommand(stream.reader()),
    );
}

test "Response: roundtrip ok" {
    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const resp: Response = .{ .ok = .{ .payload = "hello world" } };
    try serializeResponse(resp, stream.writer());
    stream.reset();
    const out = try deserializeResponse(stream.reader(), std.testing.allocator);
    defer out.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("hello world", out.ok.payload);
}

test "Response: roundtrip err" {
    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const resp: Response = .{ .err = .{ .code = 42, .message = "not found" } };
    try serializeResponse(resp, stream.writer());
    stream.reset();
    const out = try deserializeResponse(stream.reader(), std.testing.allocator);
    defer out.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u16, 42), out.err.code);
    try std.testing.expectEqualStrings("not found", out.err.message);
}

test "Response: roundtrip empty ok payload" {
    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const resp: Response = .{ .ok = .{ .payload = "" } };
    try serializeResponse(resp, stream.writer());
    stream.reset();
    const out = try deserializeResponse(stream.reader(), std.testing.allocator);
    defer out.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), out.ok.payload.len);
}

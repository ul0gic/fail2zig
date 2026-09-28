// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const shared = @import("shared");

const Entry = struct {
    row: std.json.Value,
    address: shared.IpAddress,
    prefix: u8,
    explicit_prefix: bool,
    jail: []const u8,
    original_index: usize,
};

/// Returns a newly allocated JSON array. The caller owns the returned bytes.
/// Invalid JSON, missing or malformed sort keys, and an oversized result fail
/// before any output is returned. Allocation failures remain OutOfMemory.
pub fn sortPayload(allocator: std.mem.Allocator, payload_json: []const u8) ![]u8 {
    const max_payload: usize = shared.protocol.max_payload_size;
    if (payload_json.len > max_payload) return error.PayloadTooLarge;

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, payload_json, .{
        .allocate = .alloc_always,
        .max_value_len = max_payload,
    }) catch |err| return if (err == error.OutOfMemory) err else error.InvalidListPayload;
    defer parsed.deinit();
    const rows = switch (parsed.value) {
        .array => |array| array.items,
        else => return error.InvalidListPayload,
    };

    const entries = try allocator.alloc(Entry, rows.len);
    defer allocator.free(entries);
    for (rows, 0..) |row, index| {
        const object = switch (row) {
            .object => |value| value,
            else => return error.InvalidListPayload,
        };
        const ip = switch (object.get("ip") orelse return error.InvalidListPayload) {
            .string => |value| value,
            else => return error.InvalidListPayload,
        };
        const jail = switch (object.get("jail") orelse return error.InvalidListPayload) {
            .string => |value| value,
            else => return error.InvalidListPayload,
        };
        _ = shared.JailId.fromSlice(jail) catch return error.InvalidListPayload;
        const scope = parseScope(ip) catch return error.InvalidListPayload;
        entries[index] = .{
            .row = row,
            .address = scope.address,
            .prefix = scope.prefix,
            .explicit_prefix = scope.explicit_prefix,
            .jail = jail,
            .original_index = index,
        };
    }

    std.sort.pdq(Entry, entries, {}, lessThan);

    // The IPC response has a 1 MiB limit. A fixed writer also bounds any
    // expansion while serializing preserved, otherwise unrecognized fields.
    const buffer = try allocator.alloc(u8, max_payload);
    defer allocator.free(buffer);
    var stream = std.io.fixedBufferStream(buffer);
    const writer = stream.writer();
    writer.writeByte('[') catch return error.PayloadTooLarge;
    for (entries, 0..) |entry, index| {
        if (index != 0) writer.writeByte(',') catch return error.PayloadTooLarge;
        std.json.stringify(entry.row, .{}, writer) catch return error.PayloadTooLarge;
    }
    writer.writeByte(']') catch return error.PayloadTooLarge;
    return allocator.dupe(u8, stream.getWritten());
}

const Scope = struct {
    address: shared.IpAddress,
    prefix: u8,
    explicit_prefix: bool,
};

fn parseScope(ip: []const u8) !Scope {
    const slash = std.mem.indexOfScalar(u8, ip, '/');
    const address_text = if (slash) |index| ip[0..index] else ip;
    var address = try shared.IpAddress.parse(address_text);
    const ipv6_text = std.mem.indexOfScalar(u8, address_text, ':') != null;

    // The shared parser normalizes IPv4-mapped IPv6 to IPv4 for enforcement.
    // Preserve its original family only in this display sort key.
    if (ipv6_text) switch (address) {
        .ipv4 => |value| address = .{ .ipv6 = @as(u128, 0x0000_0000_0000_0000_0000_ffff_0000_0000) | value },
        .ipv6 => {},
    };

    const width: u8 = switch (address) {
        .ipv4 => 32,
        .ipv6 => 128,
    };
    const prefix: u8 = if (slash) |index| blk: {
        const digits = ip[index + 1 ..];
        if (digits.len == 0) return error.Invalid;
        for (digits) |digit| if (digit < '0' or digit > '9') return error.Invalid;
        const value = std.fmt.parseUnsigned(u8, digits, 10) catch return error.Invalid;
        if (value > width) return error.Invalid;
        break :blk value;
    } else width;
    return .{ .address = address, .prefix = prefix, .explicit_prefix = slash != null };
}

fn lessThan(_: void, left: Entry, right: Entry) bool {
    const address_order = switch (left.address) {
        .ipv4 => |a| switch (right.address) {
            .ipv4 => |b| std.math.order(a, b),
            .ipv6 => .lt,
        },
        .ipv6 => |a| switch (right.address) {
            .ipv4 => .gt,
            .ipv6 => |b| std.math.order(a, b),
        },
    };
    if (address_order != .eq) return address_order == .lt;
    if (left.prefix != right.prefix) return left.prefix < right.prefix;
    if (left.explicit_prefix != right.explicit_prefix) return !left.explicit_prefix;
    const jail_order = std.mem.order(u8, left.jail, right.jail);
    if (jail_order != .eq) return jail_order == .lt;
    return left.original_index < right.original_index;
}

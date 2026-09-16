// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const dns = @import("native_dns.zig");
const Ip = @import("shared").IpAddress;
const Cidr = @import("state.zig").Cidr;
pub const version: u16 = 1;
pub const max_entries = 1024;
pub const max_hostnames = 16;
pub const max_file_bytes = 64 * 1024;
pub const max_checkpoint_bytes = 64 * 1024;
pub const Entry = union(enum) { network: Cidr, self: Ip, hostname: dns.Name };
pub const Options = struct {
    parent_generation: [32]u8,
    resolver_generation: [32]u8,
    family: dns.Family = .both,
    self_required: bool = false,
    self_ready: bool = false,
    self_addresses: []const Ip = &.{},
};
pub const Dependency = struct { request: dns.Request, revision: u64, valid_until_us: i64 };
pub const Decision = struct {
    kind: enum { ignored, not_ignored, pending },
    origin: enum { literal, self, hostname, no_match, unavailable },
    dependencies: [max_hostnames]Dependency = undefined,
    count: u8 = 0,
    request: ?dns.Request = null,
};
pub const Snapshot = struct {
    allocator: std.mem.Allocator,
    options: Options,
    entries: []Entry,
    payload: []u8,
    generation: [32]u8,
    pub fn create(allocator: std.mem.Allocator, options: Options, values: []const []const u8) !*Snapshot {
        if (options.self_required and !options.self_ready) return error.SelfStateUnavailable;
        const self_count = if (options.self_required) options.self_addresses.len else 0;
        if (values.len > max_entries or self_count > max_entries - values.len) return error.IgnoreLimit;
        const entries = try allocator.alloc(Entry, values.len + self_count);
        errdefer allocator.free(entries);
        var hostnames: usize = 0;
        for (values, 0..) |value, i| {
            if (value.len == 0 or value.len > 254 or std.mem.indexOfAny(u8, value, " \t\r\n\x00") != null) return error.InvalidIgnoreEntry;
            if (Cidr.parse(value)) |network| entries[i] = .{ .network = network } else |_| {
                const hostname = dns.Name.init(value) catch return error.InvalidIgnoreEntry;
                hostnames += 1;
                if (hostnames > max_hostnames) return error.IgnoreDependencyLimit;
                entries[i] = .{ .hostname = hostname };
            }
        }
        for (options.self_addresses[0..self_count], 0..) |ip, i| {
            try validateIp(ip);
            entries[values.len + i] = .{ .self = ip };
        }
        return build(allocator, options, entries);
    }
    fn build(allocator: std.mem.Allocator, options: Options, entries: []Entry) !*Snapshot {
        const owner = try allocator.create(Snapshot);
        errdefer allocator.destroy(owner);
        var bytes = std.ArrayList(u8).init(allocator);
        errdefer bytes.deinit();
        var header = [_]u8{0} ** 80;
        @memcpy(header[0..4], "F2NI");
        std.mem.writeInt(u16, header[4..6], version, .little);
        header[6] = @intFromBool(options.self_required);
        header[7] = switch (options.family) {
            .v4 => 4,
            .v6 => 6,
            .both => 10,
        };
        @memcpy(header[8..40], &options.parent_generation);
        @memcpy(header[40..72], &options.resolver_generation);
        std.mem.writeInt(u16, header[72..74], @intCast(entries.len), .little);
        try bytes.appendSlice(&header);
        for (entries) |entry| {
            var encoded: [256]u8 = undefined;
            const length = try encodeValue(entry, &encoded);
            if (length > max_checkpoint_bytes - bytes.items.len) return error.IgnoreLimit;
            try bytes.appendSlice(encoded[0..length]);
        }
        const payload = try bytes.toOwnedSlice();
        var generation: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(payload, &generation, .{});
        var held = options;
        held.self_addresses = &.{};
        owner.* = .{ .allocator = allocator, .options = held, .entries = entries, .payload = payload, .generation = generation };
        return owner;
    }
    pub fn destroy(self: *Snapshot) void {
        const allocator = self.allocator;
        allocator.free(self.entries);
        allocator.free(self.payload);
        allocator.destroy(self);
    }
    pub fn fromText(allocator: std.mem.Allocator, options: Options, text: []const u8) !*Snapshot {
        if (text.len > max_file_bytes or std.mem.indexOfScalar(u8, text, 0) != null) return error.IgnoreLimit;
        var values: [max_entries][]const u8 = undefined;
        var count: usize = 0;
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |line| {
            if (line.len > 1024) return error.IgnoreLimit;
            const uncommented = line[0 .. std.mem.indexOfScalar(u8, line, '#') orelse line.len];
            const value = std.mem.trim(u8, uncommented, " \r\t");
            if (value.len == 0) continue;
            if (count == max_entries) return error.IgnoreLimit;
            values[count] = value;
            count += 1;
        }
        return create(allocator, options, values[0..count]);
    }
    pub fn fromFile(allocator: std.mem.Allocator, options: Options, path: []const u8) !*Snapshot {
        if (!std.fs.path.isAbsolute(path) or path.len > 4096 or std.mem.indexOfScalar(u8, path, 0) != null) return error.InvalidIgnorePath;
        const fd = try std.posix.open(path, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true, .NOFOLLOW = true }, 0);
        const file = std.fs.File{ .handle = fd };
        defer file.close();
        const before = try std.posix.fstat(fd);
        if (!std.posix.S.ISREG(before.mode) or before.mode & 0o022 != 0 or (before.uid != 0 and before.uid != std.os.linux.geteuid())) return error.UntrustedIgnoreFile;
        if (before.size < 0 or before.size > max_file_bytes) return error.IgnoreLimit;
        const bytes = try allocator.alloc(u8, @intCast(before.size));
        defer allocator.free(bytes);
        if (try file.readAll(bytes) != bytes.len) return error.IgnoreFileChanged;
        var extra: [1]u8 = undefined;
        if (try file.read(&extra) != 0) return error.IgnoreFileChanged;
        const after = try std.posix.fstat(fd);
        if (before.size != after.size or !std.meta.eql(before.mtim, after.mtim) or !std.meta.eql(before.ctim, after.ctim)) return error.IgnoreFileChanged;
        return fromText(allocator, options, bytes);
    }
    pub fn restore(allocator: std.mem.Allocator, expected: Options, bytes: []const u8) !*Snapshot {
        if (expected.self_required and !expected.self_ready) return error.SelfStateUnavailable;
        if (bytes.len < 80 or bytes.len > max_checkpoint_bytes or !std.mem.eql(u8, bytes[0..4], "F2NI")) return error.InvalidIgnoreCheckpoint;
        if (std.mem.readInt(u16, bytes[4..6], .little) != version or bytes[6] > 1 or !std.mem.allEqual(u8, bytes[74..80], 0)) return error.UnsupportedIgnoreCheckpoint;
        const family: dns.Family = switch (bytes[7]) {
            4 => .v4,
            6 => .v6,
            10 => .both,
            else => return error.InvalidIgnoreCheckpoint,
        };
        if (!std.mem.eql(u8, bytes[8..40], &expected.parent_generation) or !std.mem.eql(u8, bytes[40..72], &expected.resolver_generation) or
            family != expected.family or (bytes[6] == 1) != expected.self_required) return error.IgnoreGenerationMismatch;
        const count = std.mem.readInt(u16, bytes[72..74], .little);
        if (count > max_entries) return error.IgnoreLimit;
        const entries = try allocator.alloc(Entry, count);
        errdefer allocator.free(entries);
        var at: usize = 80;
        var hostnames: usize = 0;
        var self_count: usize = 0;
        for (entries) |*entry| {
            if (bytes.len - at < 3) return error.InvalidIgnoreCheckpoint;
            const tag = bytes[at];
            const length = std.mem.readInt(u16, bytes[at + 1 ..][0..2], .little);
            at += 3;
            if (length > bytes.len - at) return error.InvalidIgnoreCheckpoint;
            const data = bytes[at .. at + length];
            at += length;
            entry.* = try decodeValue(tag, data);
            if (entry.* == .hostname) {
                hostnames += 1;
                if (hostnames > max_hostnames) return error.IgnoreDependencyLimit;
            }
            if (entry.* == .self and !expected.self_required) return error.InvalidIgnoreCheckpoint;
            if (entry.* == .self) {
                if (self_count >= expected.self_addresses.len or !entry.self.eql(expected.self_addresses[self_count])) return error.IgnoreSelfGenerationMismatch;
                self_count += 1;
            }
        }
        if (expected.self_required and self_count != expected.self_addresses.len) return error.IgnoreSelfGenerationMismatch;
        if (at != bytes.len) return error.InvalidIgnoreCheckpoint;
        return build(allocator, expected, entries);
    }
    pub fn check(self: *const Snapshot, ip: Ip, cache: ?*const dns.Cache, now_us: i64) !Decision {
        try validateIp(ip);
        for (self.entries) |entry| switch (entry) {
            .network => |network| if (network.contains(ip)) return .{ .kind = .ignored, .origin = .literal },
            .self => |address| if (address.eql(ip)) return .{ .kind = .ignored, .origin = .self },
            .hostname => {},
        };
        var decision = Decision{ .kind = .not_ignored, .origin = .no_match };
        var seen: [max_hostnames]dns.Name = undefined;
        var seen_count: usize = 0;
        for (self.entries) |entry| if (entry == .hostname) {
            var duplicate = false;
            for (seen[0..seen_count]) |prior| if (std.mem.eql(u8, prior.slice(), entry.hostname.slice())) {
                duplicate = true;
                break;
            };
            if (duplicate) continue;
            seen[seen_count] = entry.hostname;
            seen_count += 1;
            const request = dns.Request{ .name = entry.hostname, .family = self.options.family, .generation = self.options.resolver_generation };
            const saved = if (cache) |owner| try owner.lookup(request, now_us) else null;
            if (saved) |snapshot| {
                const dependency = Dependency{ .request = request, .revision = snapshot.revision, .valid_until_us = snapshot.result.valid_until_us };
                for (snapshot.result.answer.addresses[0..snapshot.result.answer.count]) |address| if (address.eql(ip)) {
                    var matched = Decision{ .kind = .ignored, .origin = .hostname, .count = 1 };
                    matched.dependencies[0] = dependency;
                    return matched;
                };
                decision.dependencies[decision.count] = dependency;
                decision.count += 1;
            } else {
                decision.kind = .pending;
                decision.origin = .unavailable;
                if (decision.request == null) decision.request = request;
            }
        };
        return decision;
    }
};
pub const Owner = struct {
    live: *Snapshot,
    revision: u64,
    in_flight: bool = false,
    pub const Stage = struct {
        owner: *Owner,
        next: *Snapshot,
        old: *Snapshot,
        expected_revision: u64,
        published: bool = false,
        pub fn publish(self: *Stage) void {
            self.owner.live = self.next;
            self.owner.revision = self.expected_revision + 1;
            self.published = true;
        }
        pub fn release(self: *Stage) void {
            if (self.published) self.old.destroy() else self.next.destroy();
            self.owner.in_flight = false;
        }
    };
    pub fn prepare(self: *Owner, replacement: *Snapshot) !Stage {
        if (self.in_flight) return error.IgnoreBusy;
        if (self.revision >= std.math.maxInt(i64) or replacement == self.live) return error.InvalidIgnoreRevision;
        self.in_flight = true;
        return .{ .owner = self, .next = replacement, .old = self.live, .expected_revision = self.revision };
    }
    pub fn deinit(self: *Owner) void {
        self.live.destroy();
    }
};
fn validateIp(ip: Ip) !void {
    if (ip == .ipv6) {
        const canonical = Ip.fromIpv6Bits(ip.ipv6) catch return error.InvalidIgnoreEntry;
        if (!canonical.eql(ip)) return error.InvalidIgnoreEntry;
    }
}
fn encodeValue(entry: Entry, bytes: *[256]u8) !usize {
    var length: u16 = 0;
    switch (entry) {
        .hostname => |hostname| {
            try hostname.validate();
            bytes[0] = 1;
            length = hostname.text.len;
            @memcpy(bytes[3 .. 3 + length], hostname.slice());
        },
        .self => |ip| switch (ip) {
            .ipv4 => |v| {
                bytes[0] = 14;
                length = 4;
                std.mem.writeInt(u32, bytes[3..7], v, .big);
            },
            .ipv6 => |v| {
                bytes[0] = 16;
                length = 16;
                std.mem.writeInt(u128, bytes[3..19], v, .big);
            },
        },
        .network => |network| switch (network) {
            .v4 => |v| {
                bytes[0] = 4;
                length = 5;
                bytes[3] = @intCast(@popCount(v.mask));
                std.mem.writeInt(u32, bytes[4..8], v.net, .big);
            },
            .v6 => |v| {
                bytes[0] = 6;
                length = 17;
                bytes[3] = @intCast(@popCount(v.mask));
                std.mem.writeInt(u128, bytes[4..20], v.net, .big);
            },
        },
    }
    std.mem.writeInt(u16, bytes[1..3], length, .little);
    return 3 + @as(usize, length);
}
fn decodeValue(tag: u8, bytes: []const u8) !Entry {
    return switch (tag) {
        1 => blk: {
            const name = dns.Name.init(bytes) catch return error.InvalidIgnoreCheckpoint;
            if (!std.mem.eql(u8, name.slice(), bytes)) return error.InvalidIgnoreCheckpoint;
            break :blk .{ .hostname = name };
        },
        4 => blk: {
            if (bytes.len != 5 or bytes[0] > 32) return error.InvalidIgnoreCheckpoint;
            const mask: u32 = if (bytes[0] == 0) 0 else @as(u32, std.math.maxInt(u32)) << @as(u5, @intCast(32 - @as(u16, bytes[0])));
            const net = std.mem.readInt(u32, bytes[1..5], .big);
            if (net & mask != net) return error.InvalidIgnoreCheckpoint;
            break :blk .{ .network = .{ .v4 = .{ .net = net, .mask = mask } } };
        },
        6 => blk: {
            if (bytes.len != 17 or bytes[0] > 128) return error.InvalidIgnoreCheckpoint;
            const mask: u128 = if (bytes[0] == 0) 0 else @as(u128, std.math.maxInt(u128)) << @as(u7, @intCast(128 - @as(u16, bytes[0])));
            const net = std.mem.readInt(u128, bytes[1..17], .big);
            if (net & mask != net) return error.InvalidIgnoreCheckpoint;
            break :blk .{ .network = .{ .v6 = .{ .net = net, .mask = mask } } };
        },
        14 => if (bytes.len == 4) .{ .self = .{ .ipv4 = std.mem.readInt(u32, bytes[0..4], .big) } } else error.InvalidIgnoreCheckpoint,
        16 => blk: {
            if (bytes.len != 16) return error.InvalidIgnoreCheckpoint;
            const ip = Ip{ .ipv6 = std.mem.readInt(u128, bytes[0..16], .big) };
            validateIp(ip) catch return error.InvalidIgnoreCheckpoint;
            break :blk .{ .self = ip };
        },
        else => error.InvalidIgnoreCheckpoint,
    };
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const shared = @import("shared");
const registry = @import("../filters/registry.zig");
const parser = @import("parser.zig");
const Cidr = @import("state.zig").Cidr;
const policy = @import("source_time_policy.zig");
const stored = @import("native_detection_record.zig");
const ignore_set = @import("native_ignore_set.zig");

pub const version: u16 = 3;
const legacy_version: u16 = 2;
pub const Body = enum { whole, syslog };
pub const Options = struct {
    filter: []const u8,
    body: Body,
    ignore: []const []const u8 = &.{},
    ignores: ?*const *const ignore_set.EffectiveIgnore = null,
    ignore_capacity: usize,
    max_decoded_bytes: u32,
};
pub const Match = struct {
    subject: shared.IpAddress,
    filter: []const u8,
    pattern: []const u8,
    pattern_index: u16,
};
pub const Candidate = struct { match: Match, time: policy.Evidence };
pub const Result = union(enum) {
    time_excluded,
    malformed_body,
    no_match,
    unenforceable: Match,
    ignored: Match,
    candidate: Candidate,
};

pub const Detector = struct {
    entry: registry.Entry,
    body: Body,
    ignores: *const *const ignore_set.EffectiveIgnore,
    owned_cell: ?**ignore_set.EffectiveIgnore,
    max_decoded_bytes: u32,
    generation: [32]u8,
    legacy_generation: [32]u8,

    pub fn init(allocator: std.mem.Allocator, options: Options) !Detector {
        if (options.max_decoded_bytes == 0 or options.max_decoded_bytes > @import("source_text.zig").max_record_bytes) return error.InvalidDetectorLimit;
        const patterns = registry.get(options.filter) orelse return error.UnknownFilter;
        const entry = for (registry.entries) |entry| {
            if (entry.patterns.ptr == patterns.ptr) break entry;
        } else unreachable;
        if (std.mem.eql(u8, entry.name, "recidive")) return error.InternalEventsRequired;
        if (options.ignore.len > options.ignore_capacity) return error.IgnoreCapacityExceeded;
        const cidrs = try allocator.alloc(Cidr, options.ignore.len);
        defer allocator.free(cidrs);
        for (options.ignore, cidrs) |spec, *cidr| {
            const address = shared.types.TimedEntry.addressText(spec);
            if (address.len == 0 or address.len > 64) return error.InvalidStaticIgnore;
            cidr.* = Cidr.parse(address) catch return error.InvalidStaticIgnore;
        }
        const encoded = try std.json.stringifyAlloc(allocator, cidrs, .{});
        defer allocator.free(encoded);
        var owned_cell: ?**ignore_set.EffectiveIgnore = null;
        if (options.ignores == null) {
            const cell = try allocator.create(*ignore_set.EffectiveIgnore);
            errdefer allocator.destroy(cell);
            cell.* = try ignore_set.EffectiveIgnore.build(allocator, options.ignore, &.{}, &.{}, &.{}, 0);
            owned_cell = cell;
        }
        return .{
            .entry = entry,
            .body = options.body,
            .ignores = options.ignores orelse owned_cell.?,
            .owned_cell = owned_cell,
            .max_decoded_bytes = options.max_decoded_bytes,
            .generation = digest(entry.name, options, version, null),
            .legacy_generation = digest(entry.name, options, legacy_version, encoded),
        };
    }

    fn digest(name: []const u8, options: Options, version_value: u16, encoded: ?[]const u8) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("fail2zig-native-builtin\x00");
        var numbers: [6]u8 = undefined;
        std.mem.writeInt(u16, numbers[0..2], version_value, .little);
        std.mem.writeInt(u32, numbers[2..6], options.max_decoded_bytes, .little);
        hash.update(&numbers);
        hash.update(name);
        hash.update(&.{0});
        hash.update(@tagName(options.body));
        if (encoded) |list| hash.update(list);
        var out: [32]u8 = undefined;
        hash.final(&out);
        return out;
    }

    pub fn deinit(self: *Detector, allocator: std.mem.Allocator) void {
        if (self.owned_cell) |cell| {
            cell.*.deinit(allocator);
            allocator.destroy(cell);
        }
        self.* = undefined;
    }

    pub fn consumer(self: *const Detector) stored.Consumer {
        return .{ .generation = self.generation, .context = self, .evaluate = consume };
    }
    pub fn legacyConsumer(self: *const Detector) stored.Consumer {
        return .{ .generation = self.legacy_generation, .context = self, .evaluate = consume };
    }
    fn consume(decoded: []const u8, admitted: policy.Result, context: ?*const anyopaque) !stored.Outcome {
        const self: *const Detector = @ptrCast(@alignCast(context.?));
        const result = try self.evaluate(decoded, admitted);
        var outcome = stored.Outcome{
            .kind = switch (result) {
                .time_excluded => .time_excluded,
                .malformed_body => .malformed_body,
                .no_match => .no_match,
                .unenforceable => .unenforceable,
                .ignored => .ignored,
                .candidate => .candidate,
            },
            .generation = self.generation,
            .filter = try stored.Name.init(self.entry.name),
        };
        const matched: ?Match = switch (result) {
            .unenforceable, .ignored => |value| value,
            .candidate => |value| value.match,
            else => null,
        };
        if (matched) |value| {
            outcome.pattern = try stored.Name.init(value.pattern);
            outcome.pattern_index = value.pattern_index;
            outcome.subject = switch (value.subject) {
                .ipv4 => |v| .{ .v4 = std.mem.toBytes(std.mem.nativeToBig(u32, v)) },
                .ipv6 => |v| .{ .v6 = std.mem.toBytes(std.mem.nativeToBig(u128, v)) },
            };
        }
        try outcome.validate(admitted);
        return outcome;
    }

    pub fn evaluate(self: *const Detector, decoded: []const u8, admitted: policy.Result) !Result {
        if (decoded.len > self.max_decoded_bytes) return error.RecordTooLarge;
        if (!std.unicode.utf8ValidateSlice(decoded) or std.mem.indexOfScalar(u8, decoded, 0) != null or
            std.mem.indexOfAny(u8, decoded, "\r\n") != null) return error.InvalidDecodedRecord;
        const evidence = switch (admitted) {
            .eligible => |value| value,
            .obsolete, .rejected => return .time_excluded,
        };
        const body = switch (self.body) {
            .whole => decoded,
            .syslog => blk: {
                const extracted = parser.stripSyslogPrefix(decoded);
                if (extracted.ptr == decoded.ptr) return .malformed_body;
                break :blk extracted;
            },
        };
        for (self.entry.patterns, 0..) |pattern, index| {
            const parsed = pattern.match(body) orelse continue;
            const matched = Match{ .subject = parsed.ip, .filter = self.entry.name, .pattern = pattern.name, .pattern_index = @intCast(index) };
            if (parsed.ip.isUnenforceable()) return .{ .unenforceable = matched };
            if (self.ignores.*.check(parsed.ip) != null) return .{ .ignored = matched };
            return .{ .candidate = .{ .match = matched, .time = evidence } };
        }
        return .no_match;
    }
};

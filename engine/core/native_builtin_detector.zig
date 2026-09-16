// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const shared = @import("shared");
const registry = @import("../filters/registry.zig");
const parser = @import("parser.zig");
const Cidr = @import("state.zig").Cidr;
const policy = @import("source_time_policy.zig");
const stored = @import("native_detection_record.zig");

pub const version: u16 = 2;
pub const Body = enum { whole, syslog };
pub const Options = struct {
    filter: []const u8,
    body: Body,
    ignore: []const []const u8 = &.{},
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
    ignores: []const Cidr,
    max_decoded_bytes: u32,
    generation: [32]u8,

    pub fn init(allocator: std.mem.Allocator, options: Options) !Detector {
        if (options.max_decoded_bytes == 0 or options.max_decoded_bytes > @import("source_text.zig").max_record_bytes) return error.InvalidDetectorLimit;
        const patterns = registry.get(options.filter) orelse return error.UnknownFilter;
        const entry = for (registry.entries) |entry| {
            if (entry.patterns.ptr == patterns.ptr) break entry;
        } else unreachable;
        if (std.mem.eql(u8, entry.name, "recidive")) return error.InternalEventsRequired;
        if (options.ignore.len > options.ignore_capacity) return error.IgnoreCapacityExceeded;
        const ignores = try allocator.alloc(Cidr, options.ignore.len);
        errdefer allocator.free(ignores);
        for (options.ignore, ignores) |spec, *cidr| {
            if (spec.len == 0 or spec.len > 64) return error.InvalidStaticIgnore;
            cidr.* = Cidr.parse(spec) catch return error.InvalidStaticIgnore;
        }
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("fail2zig-native-builtin\x00");
        var numbers: [6]u8 = undefined;
        std.mem.writeInt(u16, numbers[0..2], version, .little);
        std.mem.writeInt(u32, numbers[2..6], options.max_decoded_bytes, .little);
        hash.update(&numbers);
        hash.update(entry.name);
        hash.update(&.{0});
        hash.update(@tagName(options.body));
        const encoded = try std.json.stringifyAlloc(allocator, ignores, .{});
        defer allocator.free(encoded);
        hash.update(encoded);
        var generation: [32]u8 = undefined;
        hash.final(&generation);
        return .{ .entry = entry, .body = options.body, .ignores = ignores, .max_decoded_bytes = options.max_decoded_bytes, .generation = generation };
    }

    pub fn deinit(self: *Detector, allocator: std.mem.Allocator) void {
        allocator.free(self.ignores);
        self.* = undefined;
    }

    pub fn consumer(self: *const Detector) stored.Consumer {
        return .{ .generation = self.generation, .context = self, .evaluate = consume };
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
            for (self.ignores) |cidr| if (cidr.contains(parsed.ip)) return .{ .ignored = matched };
            return .{ .candidate = .{ .match = matched, .time = evidence } };
        }
        return .no_match;
    }
};

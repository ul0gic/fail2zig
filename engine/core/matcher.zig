// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const shared = @import("shared");
const parser = @import("parser.zig");

pub const MAX_PATTERNS: usize = 256;

pub const PatternDef = struct {
    pattern: []const u8,
    jail: shared.JailId,
    id: u16,
};

pub const MatchResult = struct {
    ip: shared.IpAddress,
    timestamp: ?shared.Timestamp,
    jail: shared.JailId,
    pattern_id: u16,
};

pub const Matcher = struct {
    fns: []const parser.MatchFn,
    ids: []const u16,
    jails: []const shared.JailId,
    min_line_len: usize,
    first_byte_mask: [256]bool,

    pub fn init(comptime patterns: []const PatternDef) Matcher {
        comptime {
            if (patterns.len == 0) @compileError("Matcher.init: at least one pattern required");
            if (patterns.len > MAX_PATTERNS) {
                @compileError("Matcher.init: too many patterns (max 256)");
            }
        }

        const built = comptime buildCompiled(patterns);
        return .{
            .fns = built.fns_slice,
            .ids = built.ids_slice,
            .jails = built.jails_slice,
            .min_line_len = built.min_line_len,
            .first_byte_mask = built.first_byte_mask,
        };
    }

    pub fn match(self: *const Matcher, line: []const u8) ?MatchResult {
        if (line.len < self.min_line_len) {
            @branchHint(.unlikely);
            return null;
        }
        if (line.len >= 1 and !self.first_byte_mask[line[0]]) {
            @branchHint(.unlikely);
            return null;
        }

        for (self.fns, self.ids, self.jails) |f, id, jail| {
            if (f(line)) |r| {
                return .{
                    .ip = r.ip,
                    .timestamp = r.timestamp,
                    .jail = jail,
                    .pattern_id = id,
                };
            }
        }
        return null;
    }

    pub fn len(self: *const Matcher) usize {
        return self.fns.len;
    }
};

const Built = struct {
    fns_slice: []const parser.MatchFn,
    ids_slice: []const u16,
    jails_slice: []const shared.JailId,
    min_line_len: usize,
    first_byte_mask: [256]bool,
};

fn buildCompiled(comptime patterns: []const PatternDef) Built {
    comptime {
        @setEvalBranchQuota(200_000);
        var fns_arr: [patterns.len]parser.MatchFn = undefined;
        var ids_arr: [patterns.len]u16 = undefined;
        var jails_arr: [patterns.len]shared.JailId = undefined;
        var min_line_len: usize = std.math.maxInt(usize);
        var first_byte_mask: [256]bool = [_]bool{false} ** 256;

        for (patterns, 0..) |p, i| {
            fns_arr[i] = parser.compile(p.pattern);
            ids_arr[i] = p.id;
            jails_arr[i] = p.jail;

            const fixed = fixedLen(p.pattern);
            if (fixed < min_line_len) min_line_len = fixed;

            if (firstAnchoredByte(p.pattern)) |b| {
                first_byte_mask[b] = true;
            } else {
                for (&first_byte_mask) |*slot| slot.* = true;
            }
        }
        if (min_line_len == std.math.maxInt(usize)) min_line_len = 0;

        const fns_const = fns_arr;
        const ids_const = ids_arr;
        const jails_const = jails_arr;
        return .{
            .fns_slice = &fns_const,
            .ids_slice = &ids_const,
            .jails_slice = &jails_const,
            .min_line_len = min_line_len,
            .first_byte_mask = first_byte_mask,
        };
    }
}

fn fixedLen(comptime pattern: []const u8) usize {
    comptime {
        var total: usize = 0;
        var i: usize = 0;
        while (i < pattern.len) {
            if (pattern[i] == '<') {
                var j = i + 1;
                while (j < pattern.len and pattern[j] != '>') : (j += 1) {}
                const name = pattern[i + 1 .. j];
                if (std.mem.eql(u8, name, "IP")) {
                    total += 7;
                } else if (std.mem.eql(u8, name, "TIMESTAMP")) {
                    total += 10;
                } else if (std.mem.eql(u8, name, "HOST")) {
                    total += 1;
                } else if (std.mem.eql(u8, name, "*")) {}
                i = j + 1;
            } else {
                total += 1;
                i += 1;
            }
        }
        return total;
    }
}

fn firstAnchoredByte(comptime pattern: []const u8) ?u8 {
    comptime {
        if (pattern.len == 0) return null;
        if (pattern[0] == '<') return null;
        return pattern[0];
    }
}

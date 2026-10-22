// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const config = @import("../config/native.zig");
const retry_config = @import("../config/native_retry_policy.zig");
const retry = @import("../core/native_retry.zig");
const ignore_set = @import("../core/native_ignore_set.zig");
const banip = @import("../config/native_banip.zig");
const shared = @import("shared");

pub const max_reasons = 32;
pub const max_reason_bytes = 240;
pub const max_jails = 64;

pub const RuntimeCount = struct { jail: []const u8, runtime_only: u16 };

pub const Kind = enum { noop, live, restart_required, rejected };

pub const Reason = struct {
    len: u8 = 0,
    bytes: [max_reason_bytes]u8 = undefined,
    pub fn slice(self: *const Reason) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const PolicyChange = struct {
    jail: []const u8,
    next: retry.Policy,
};

pub const JailDelta = struct {
    added: [max_jails][]const u8 = undefined,
    added_count: u8 = 0,
    removed: [max_jails][]const u8 = undefined,
    removed_count: u8 = 0,

    pub fn addedSlice(self: *const JailDelta) []const []const u8 {
        return self.added[0..self.added_count];
    }
    pub fn removedSlice(self: *const JailDelta) []const []const u8 {
        return self.removed[0..self.removed_count];
    }
};

pub const Classification = struct {
    kind: Kind = .noop,
    log_level: ?config.LogLevel = null,
    policies: [64]PolicyChange = undefined,
    policy_count: u8 = 0,
    ignore_jails: [max_jails][]const u8 = undefined,
    ignore_count: u8 = 0,
    jails: JailDelta = .{},
    banip_jails: [max_jails][]const u8 = undefined,
    banip_count: u8 = 0,
    decay_jails: [max_jails][]const u8 = undefined,
    decay_count: u8 = 0,
    reasons: [max_reasons]Reason = undefined,
    reason_count: u8 = 0,

    fn note(self: *Classification, comptime fmt: []const u8, args: anytype) void {
        if (self.reason_count == max_reasons) return;
        var reason: Reason = .{};
        const written = std.fmt.bufPrint(&reason.bytes, fmt, args) catch blk: {
            @memcpy(reason.bytes[0..3], "...");
            break :blk reason.bytes[0..3];
        };
        reason.len = @intCast(written.len);
        self.reasons[self.reason_count] = reason;
        self.reason_count += 1;
    }
    fn restart(self: *Classification, comptime fmt: []const u8, args: anytype) void {
        if (self.kind != .rejected) self.kind = .restart_required;
        self.note(fmt, args);
    }
    fn reject(self: *Classification, comptime fmt: []const u8, args: anytype) void {
        self.kind = .rejected;
        self.note(fmt, args);
    }
    fn live(self: *Classification) void {
        if (self.kind == .noop) self.kind = .live;
    }
    pub fn reasonSlice(self: *const Classification) []const Reason {
        return self.reasons[0..self.reason_count];
    }
    pub fn ignoreSlice(self: *const Classification) []const []const u8 {
        return self.ignore_jails[0..self.ignore_count];
    }
    pub fn policySlice(self: *const Classification) []const PolicyChange {
        return self.policies[0..self.policy_count];
    }
    pub fn banipSlice(self: *const Classification) []const []const u8 {
        return self.banip_jails[0..self.banip_count];
    }
    pub fn decaySlice(self: *const Classification) []const []const u8 {
        return self.decay_jails[0..self.decay_count];
    }
    fn listJail(self: *Classification, list: [][]const u8, count: *u8, jail: []const u8, comptime what: []const u8) void {
        for (list[0..count.*]) |listed| if (std.mem.eql(u8, listed, jail)) return;
        if (count.* == list.len) {
            self.reject("jails: too many " ++ what ++ " changes", .{});
            return;
        }
        list[count.*] = jail;
        count.* += 1;
        self.live();
    }
};

fn globalsEqual(a: *const config.GlobalConfig, b: *const config.GlobalConfig, out: *Classification) void {
    inline for (std.meta.fields(config.GlobalConfig)) |field| {
        if (comptime std.mem.eql(u8, field.name, "log_level")) continue;
        const left = @field(a, field.name);
        const right = @field(b, field.name);
        if (!valuesEqual(field.type, left, right)) out.restart("global.{s}", .{field.name});
    }
    if (a.log_level != b.log_level) {
        out.log_level = b.log_level;
        out.live();
    }
}

fn valuesEqual(comptime T: type, a: T, b: T) bool {
    return switch (@typeInfo(T)) {
        .pointer => |info| switch (info.size) {
            .slice => if (info.child == u8) std.mem.eql(u8, a, b) else sliceEqual(info.child, a, b),
            else => a == b,
        },
        .optional => |info| if (a == null or b == null) (a == null and b == null) else valuesEqual(info.child, a.?, b.?),
        else => std.meta.eql(a, b),
    };
}

fn sliceEqual(comptime T: type, a: []const T, b: []const T) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| if (!valuesEqual(T, left, right)) return false;
    return true;
}

fn findJail(cfg: *const config.Config, name: []const u8) ?*const config.JailConfig {
    for (cfg.jails) |*jail| if (std.mem.eql(u8, jail.name, name)) return jail;
    return null;
}

fn distinctConfigured(literals: []const []const u8) usize {
    var seen: [ignore_set.max_entries_per_part]shared.types.IgnoreEntry = undefined;
    var count: usize = 0;
    for (literals) |literal| {
        const entry = (shared.types.TimedEntry.parse(literal, null) catch continue).entry;
        var duplicate = false;
        for (seen[0..count]) |prior| {
            if (prior.order(entry) == .eq) duplicate = true;
        }
        if (duplicate) continue;
        if (count == seen.len) return literals.len;
        seen[count] = entry;
        count += 1;
    }
    return count;
}

fn runtimeOnly(counts: []const RuntimeCount, jail: []const u8) u16 {
    for (counts) |count| if (std.mem.eql(u8, count.jail, jail)) return count.runtime_only;
    return 0;
}

pub fn classify(current: *const config.Config, proposed: *const config.Config, max_subjects: u32) Classification {
    return classifyWithRuntime(current, proposed, max_subjects, &.{}, null);
}

pub fn classifyWithRuntime(current: *const config.Config, proposed: *const config.Config, max_subjects: u32, runtime_counts: []const RuntimeCount, conflict: ?banip.BanListConflict) Classification {
    var out: Classification = .{};
    globalsEqual(&current.global, &proposed.global, &out);
    if (conflict) |found| out.reject("jails.{s}.banip: {s} is also in ignoreip", .{ found.jail, found.address[0..found.address_len] });
    for (proposed.jails) |*jail| {
        if (findJail(current, jail.name) != null) continue;
        _ = retry_config.fromJail(jail, proposed.defaults, max_subjects) catch |err| {
            out.reject("jails.{s}: {s}", .{ jail.name, @errorName(err) });
            continue;
        };
        out.listJail(&out.jails.added, &out.jails.added_count, jail.name, "added jail");
    }
    for (current.jails) |*jail| {
        const next = findJail(proposed, jail.name) orelse {
            out.listJail(&out.jails.removed, &out.jails.removed_count, jail.name, "removed jail");
            continue;
        };
        inline for (.{ "enabled", "logpath", "source", "filter", "timestamp", "timezone_offset_minutes", "timezone", "timezone_ambiguity", "journal_executables", "journal_executables_explicit", "rule_files", "ignore_file", "on_truncation", "compatibility_pending" }) |name| {
            const T = @TypeOf(@field(jail, name));
            if (!valuesEqual(T, @field(jail, name), @field(next, name))) out.restart("jails.{s}.{s}", .{ jail.name, name });
        }
        if (jail.rule_files.len != 0) {
            if (!valuesEqual(@TypeOf(jail.ignoreip), jail.ignoreip, next.ignoreip)) out.restart("jails.{s}.ignoreip", .{jail.name});
        } else {
            const before_literals = jail.ignoreip orelse current.defaults.ignoreip;
            const after_literals = next.ignoreip orelse proposed.defaults.ignoreip;
            if (!sliceEqual([]const u8, before_literals, after_literals)) {
                const configured = distinctConfigured(after_literals);
                const runtime = runtimeOnly(runtime_counts, jail.name);
                if (configured + runtime > ignore_set.distinct_bound) {
                    out.reject("jails.{s}.ignoreip: {d} configured and {d} runtime-only entries exceed the {d}-entry limit; remove runtime entries with fail2zig ignore remove or shorten ignoreip", .{ jail.name, configured, runtime, ignore_set.distinct_bound });
                } else {
                    out.listJail(&out.ignore_jails, &out.ignore_count, jail.name, "ignoreip");
                }
            }
        }
        const before = config.resolveJailFromConfig(jail, current.defaults);
        const after = config.resolveJailFromConfig(next, proposed.defaults);
        if (before.ignoreself != after.ignoreself or !std.meta.eql(before.ignoretime_s, after.ignoretime_s))
            out.listJail(&out.ignore_jails, &out.ignore_count, jail.name, "ignoreip");
        if (!sliceEqual([]const u8, before.banip, after.banip))
            out.listJail(&out.banip_jails, &out.banip_count, jail.name, "banip");
        if (before.bantime_increment_decay != after.bantime_increment_decay)
            out.listJail(&out.decay_jails, &out.decay_count, jail.name, "bantime_increment_decay");
        if (before.banaction != after.banaction) out.restart("jails.{s}.banaction", .{jail.name});
        if (before.findtime != after.findtime) out.restart("jails.{s}.findtime: bound to the source plan window", .{jail.name});
        const policy_changed = before.maxretry != after.maxretry or before.bantime != after.bantime or before.bantime_kind != after.bantime_kind or !std.meta.eql(before.bantime_increment, after.bantime_increment);
        if (!policy_changed) continue;
        if (!jail.enabled) {
            out.restart("jails.{s}: policy edit on a disabled jail applies at restart", .{jail.name});
            continue;
        }
        const source = if (next.source == .auto) proposed.defaults.source else next.source;
        if (source == .internal) {
            out.restart("jails.{s}: retry policy is bound to the internal source generation", .{jail.name});
            continue;
        }
        const policy = retry_config.fromJail(next, proposed.defaults, max_subjects) catch |err| {
            out.reject("jails.{s}: {s}", .{ jail.name, @errorName(err) });
            continue;
        };
        if (out.policy_count == out.policies.len) {
            out.reject("jails: too many policy changes", .{});
            continue;
        }
        out.policies[out.policy_count] = .{ .jail = jail.name, .next = policy };
        out.policy_count += 1;
        out.live();
    }
    if (out.kind == .restart_required or out.kind == .rejected) {
        out.policy_count = 0;
        out.ignore_count = 0;
        out.jails = .{};
        out.banip_count = 0;
        out.decay_count = 0;
    }
    return out;
}

pub fn digestBytes(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}

pub fn generationId(config_digest: [32]u8, committed_us: i64) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("fail2zig-config-generation-v1\x00");
    hash.update(&config_digest);
    var clock: [8]u8 = undefined;
    std.mem.writeInt(i64, &clock, committed_us, .little);
    hash.update(&clock);
    var out: [32]u8 = undefined;
    hash.final(&out);
    return out;
}

pub fn jailDigest(name: []const u8, policy: retry.Policy, plan_generation: [32]u8) ![32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("fail2zig-config-generation-jail-v1\x00");
    hash.update(name);
    hash.update(&try policy.identity());
    hash.update(&try policy.escalation.encode());
    hash.update(&plan_generation);
    var out: [32]u8 = undefined;
    hash.final(&out);
    return out;
}

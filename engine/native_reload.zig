// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

//! Configuration reload: build and classify a proposed generation without touching
//! runtime state. The daemon applies only `live` classifications at a worker tick boundary
//! after the durable transition committed; everything else leaves the current generation,
//! ingestion and protection untouched and is reported with exact reasons.
//!
//! Live-changeable per jail: maxretry, bantime, bantime_kind and bantime_increment
//! (retry policy bytes under an unchanged plan generation), plus global log_level and the
//! contents of a custom jail's ignore_file. Every other key is restart-only by the frozen
//! classification table because it is bound into a durable plan/effect generation.

const std = @import("std");
const config = @import("config/native.zig");
const retry_config = @import("config/native_retry_policy.zig");
const retry = @import("core/native_retry.zig");

pub const max_reasons = 32;
pub const max_reason_bytes = 160;

pub const Kind = enum { noop, live, restart_required, rejected };

pub const Reason = struct {
    len: u8 = 0,
    bytes: [max_reason_bytes]u8 = undefined,
    pub fn slice(self: *const Reason) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const PolicyChange = struct {
    /// Index into the current configuration's enabled-jail order (the coordinator's jail slice).
    jail: []const u8,
    next: retry.Policy,
};

pub const Classification = struct {
    kind: Kind = .noop,
    log_level: ?config.LogLevel = null,
    policies: [64]PolicyChange = undefined,
    policy_count: u8 = 0,
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
    pub fn policySlice(self: *const Classification) []const PolicyChange {
        return self.policies[0..self.policy_count];
    }
};

/// Restart-only global keys; `log_level` is the only live global key.
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

/// Compare the running configuration against a fully validated proposal.
pub fn classify(current: *const config.Config, proposed: *const config.Config, per_jail_subjects: u32) Classification {
    var out: Classification = .{};
    globalsEqual(&current.global, &proposed.global, &out);
    if (current.jails.len != proposed.jails.len) out.restart("jails: set size {d} -> {d}", .{ current.jails.len, proposed.jails.len });
    for (proposed.jails) |*jail| if (findJail(current, jail.name) == null) out.restart("jails.{s}: added", .{jail.name});
    for (current.jails) |*jail| {
        const next = findJail(proposed, jail.name) orelse {
            out.restart("jails.{s}: removed", .{jail.name});
            continue;
        };
        // Plan/generation-bound keys: any difference needs a restart with state migration.
        inline for (.{ "enabled", "logpath", "source", "filter", "timestamp", "timezone_offset_minutes", "timezone", "timezone_ambiguity", "journal_executables", "rule_files", "ignore_file", "ignoreip", "compatibility_pending" }) |name| {
            const T = @TypeOf(@field(jail, name));
            if (!valuesEqual(T, @field(jail, name), @field(next, name))) out.restart("jails.{s}.{s}", .{ jail.name, name });
        }
        const before = config.resolveJailFromConfig(jail, current.defaults);
        const after = config.resolveJailFromConfig(next, proposed.defaults);
        if (before.banaction != after.banaction) out.restart("jails.{s}.banaction", .{jail.name});
        // The retry window is bound into the source processor plan, so findtime cannot move live.
        if (before.findtime != after.findtime) out.restart("jails.{s}.findtime: bound to the source plan window", .{jail.name});
        const policy_changed = before.maxretry != after.maxretry or before.bantime != after.bantime or before.bantime_kind != after.bantime_kind or !std.meta.eql(before.bantime_increment, after.bantime_increment);
        if (!policy_changed) continue;
        // A jail disabled in the file has no live generation to re-key; its policy edit takes
        // effect at restart, and saying so keeps `jail enable` from running a stale policy unseen.
        if (!jail.enabled) {
            out.restart("jails.{s}: policy edit on a disabled jail applies at restart", .{jail.name});
            continue;
        }
        const source = if (next.source == .auto) proposed.defaults.source else next.source;
        if (source == .internal) {
            out.restart("jails.{s}: retry policy is bound to the internal source generation", .{jail.name});
            continue;
        }
        const policy = retry_config.fromJail(next, proposed.defaults, per_jail_subjects) catch |err| {
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
    if (out.kind == .restart_required or out.kind == .rejected) out.policy_count = 0;
    return out;
}

pub fn digestBytes(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}

/// Generation identity binds the config digest and the commit clock; equal files reloaded
/// twice yield distinct generations so replayed responses cannot alias.
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
    hash.update(&try policy.encode());
    hash.update(&try policy.escalation.encode());
    hash.update(&plan_generation);
    var out: [32]u8 = undefined;
    hash.final(&out);
    return out;
}

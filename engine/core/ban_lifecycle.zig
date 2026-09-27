// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const shared = @import("shared");
const state = @import("state.zig");
const tracker_map = @import("tracker_map.zig");
const firewall = @import("../firewall/backend.zig");
const metrics_mod = @import("metrics.zig");

pub const Lifecycle = struct {
    trackers: *tracker_map.TrackerMap,
    backend: ?*firewall.Backend,
    metrics: ?*metrics_mod.Metrics = null,
    event_ctx: ?*anyopaque = null,
    on_ban: ?*const fn (?*anyopaque, shared.IpAddress, shared.JailId, shared.Duration) void = null,
    on_unban: ?*const fn (?*anyopaque, shared.IpAddress, shared.JailId) void = null,
    cursor: usize = 0,
    hook_ctx: ?*anyopaque = null,
    ban_hook: ?*const fn (?*anyopaque, shared.IpAddress, shared.JailId, shared.Duration) firewall.BackendError!void = null,
    unban_hook: ?*const fn (?*anyopaque, shared.IpAddress, shared.JailId) firewall.BackendError!void = null,

    fn sharedSet(self: *const Lifecycle) bool {
        return self.backend != null or self.ban_hook != null;
    }

    pub fn latestExpiry(self: *const Lifecycle, ip: shared.IpAddress, excluded: ?shared.JailId, now: shared.Timestamp) ?shared.Timestamp {
        var latest: ?shared.Timestamp = null;
        var it = self.trackers.iterator();
        while (it.next()) |entry| {
            const st = entry.value_ptr.*.get(ip) orelse continue;
            if (excluded) |j| if (std.mem.eql(u8, st.jail.slice(), j.slice())) continue;
            if (st.ban_state != .banned or !st.enforced) continue;
            const expiry = st.ban_expiry orelse continue;
            if (expiry <= now) continue;
            latest = @max(latest orelse expiry, expiry);
        }
        return latest;
    }

    fn put(self: *Lifecycle, ip: shared.IpAddress, jail: shared.JailId, duration: shared.Duration) firewall.BackendError!void {
        if (self.ban_hook) |hook| return hook(self.hook_ctx, ip, jail, duration);
        const be = self.backend orelse return error.NotAvailable;
        return be.ban(ip, jail, duration);
    }

    fn remove(self: *Lifecycle, ip: shared.IpAddress, jail: shared.JailId) firewall.BackendError!void {
        if (self.unban_hook) |hook| return hook(self.hook_ctx, ip, jail);
        const be = self.backend orelse return error.NotAvailable;
        return be.unban(ip, jail);
    }

    pub fn apply(self: *Lifecycle, ip: shared.IpAddress, jail: shared.JailId, now: shared.Timestamp) firewall.BackendError!void {
        const tracker = self.trackers.getOrLegacy(jail.slice()) orelse return error.NotAvailable;
        const st = tracker.mutable(ip) orelse return error.NotBanned;
        const expiry = st.ban_expiry orelse return error.NotBanned;
        if (expiry <= now) return error.NotBanned;
        if (st.enforced) {
            const desired = if (self.sharedSet()) self.latestExpiry(ip, null, now) orelse expiry else expiry;
            try self.put(ip, jail, @intCast(desired -| now));
            st.applied = true;
        }
        if (!st.confirmed) {
            st.confirmed = true;
            tracker.recordLifetimeBan();
            if (self.metrics) |m| {
                m.incrementBans();
                m.jailIncrementBans(jail.slice());
            }
            if (st.enforced) if (self.on_ban) |notify| notify(self.event_ctx, ip, jail, @intCast(expiry -| now));
        }
    }

    pub fn release(self: *Lifecycle, ip: shared.IpAddress, jail: shared.JailId, now: shared.Timestamp) firewall.BackendError!void {
        const tracker = self.trackers.getOrLegacy(jail.slice()) orelse return error.NotAvailable;
        const st = tracker.mutable(ip) orelse return error.NotBanned;
        if (st.ban_state != .banned) return error.NotBanned;
        if (st.enforced) {
            if (if (self.sharedSet()) self.latestExpiry(ip, jail, now) else null) |expiry| {
                try self.put(ip, jail, @intCast(expiry -| now));
            } else {
                self.remove(ip, jail) catch |err| switch (err) {
                    error.NotBanned => {},
                    else => return err,
                };
            }
        }
        const enforced = st.enforced;
        const confirmed = st.confirmed;
        tracker.clearBan(ip);
        if (confirmed) if (self.metrics) |m| {
            m.incrementUnbans();
            m.jailIncrementUnbans(jail.slice());
        };
        if (enforced) if (self.on_unban) |notify| notify(self.event_ctx, ip, jail);
    }

    pub fn sweep(self: *Lifecycle, now: shared.Timestamp) void {
        const Item = struct { ip: shared.IpAddress, jail: shared.JailId, expired: bool };
        var batch: [64]Item = undefined;
        var count: usize = 0;
        var seen: usize = 0;
        var it = self.trackers.iterator();
        while (it.next()) |entry| {
            var states = entry.value_ptr.*.iterator();
            while (states.next()) |kv| {
                const st = kv.value_ptr;
                if (st.ban_state != .banned) continue;
                const expired = (st.ban_expiry orelse continue) <= now;
                if (!expired and (!st.enforced or st.applied)) continue;
                const index = seen;
                seen += 1;
                if (index < self.cursor or count == batch.len) continue;
                batch[count] = .{ .ip = kv.key_ptr.*, .jail = st.jail, .expired = expired };
                count += 1;
            }
        }
        var processed: usize = 0;
        var timer = std.time.Timer.start() catch return;
        for (batch[0..count]) |item| {
            processed += 1;
            if (item.expired) {
                self.release(item.ip, item.jail, now) catch |err|
                    std.log.warn("ban lifecycle: removal pending for {} jail='{s}': {s}", .{ item.ip, item.jail.slice(), @errorName(err) });
            } else {
                self.apply(item.ip, item.jail, now) catch |err|
                    std.log.warn("ban lifecycle: enforcement pending for {} jail='{s}': {s}", .{ item.ip, item.jail.slice(), @errorName(err) });
            }
            if (timer.read() >= 100 * std.time.ns_per_ms) break;
        }
        self.cursor = if (self.cursor + processed >= seen) 0 else self.cursor + processed;
    }
};

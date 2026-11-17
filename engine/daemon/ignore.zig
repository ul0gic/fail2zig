// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Builds each jail's effective ignore list from configured literals, stored runtime entries, deadlines and host addresses.
// Holds: A new list replaces the old one under the coordinator mutex; the displaced list is freed after the swap.

const std = @import("std");
const shared = @import("shared");
const config = @import("../config/config.zig");
const consumer_plan = @import("../config/consumer_plan.zig");
const resource = @import("../runtime/resource_budget.zig");
const durable = @import("../store/store.zig");
const ignore_set = @import("../detect/ignore_set.zig");
const custom_ignore = @import("../detect/ignore.zig");
const RuntimeIgnoreEntry = @import("../store/ignore_entries.zig").RuntimeIgnoreEntry;
const daemon = @import("daemon.zig");
const Jail = daemon.Jail;

pub fn Methods(comptime Coordinator: type) type {
    return struct {
        const PreparedCustomPolicy = Coordinator.PreparedCustomPolicy;
        const DeadlineMode = Coordinator.DeadlineMode;
        const PreparedIgnoreDeadlines = Coordinator.PreparedIgnoreDeadlines;
        const quiet_interval_ms = Coordinator.quiet_interval_ms;
        const findConfigJail = Coordinator.findConfigJail;

        pub fn ignoreCell(jail: *const Jail) ?**ignore_set.EffectiveIgnore {
            return switch (jail.plan) {
                .file => |plan| plan.ignore_cell,
                .journal => |plan| plan.ignore_cell,
                .internal => null,
            };
        }

        pub fn prepareCustomPolicy(self: *Coordinator, jail: *Jail, cfg: *const config.Config, now_us: i64, initial: bool) !?PreparedCustomPolicy {
            const runtime = jail.consumer orelse return null;
            const assets = jail.custom_plan orelse return error.ConsumerRuntimeNotReady;
            const configured = findConfigJail(cfg, jail.name) orelse return error.UnknownJail;
            const cost = resource.Cost{
                .bytes = @sizeOf(custom_ignore.Snapshot) + custom_ignore.max_entries * @sizeOf(custom_ignore.Entry) + 2 * custom_ignore.max_checkpoint_bytes + custom_ignore.max_file_bytes,
                .allocations = 4,
                .fds = @intFromBool(!initial and configured.ignore_file != null),
            };
            const token = try self.resources.reserve(.configuration, cost);
            var held = false;
            defer if (!held) self.resources.release(token) catch |failure| std.log.err("native: custom policy reservation release failed: {s}", .{@errorName(failure)});
            const next = if (initial)
                try custom_ignore.Snapshot.restore(self.allocator, assets.ignore_options, assets.initial_ignore.payload)
            else
                try consumer_plan.Prepared.buildIgnore(self.allocator, runtime.ignores.live.options, configured.ignoreip orelse cfg.defaults.ignoreip, configured.ignore_file);
            const policy = try runtime.preparePolicy(next, now_us) orelse return null;
            held = true;
            return .{ .policy = policy, .reservation = token };
        }

        fn ignoreLiterals(cfg: *const config.Config, jail_cfg: ?*const config.JailConfig) []const []const u8 {
            const value = jail_cfg orelse return &.{};
            return value.ignoreip orelse cfg.defaults.ignoreip;
        }

        pub fn configuredIgnoreDeadlines(allocator: std.mem.Allocator, store: *durable.Store, name: []const u8, literals: []const []const u8, ignoretime_s: ?u64, mode: DeadlineMode, now_us: i64) ![]?i64 {
            const prepared = try prepareIgnoreDeadlines(allocator, store, name, literals, ignoretime_s, mode, now_us);
            allocator.free(prepared.entries);
            allocator.free(prepared.stored);
            return prepared.literals;
        }

        pub fn prepareIgnoreDeadlines(allocator: std.mem.Allocator, store: *durable.Store, name: []const u8, literals: []const []const u8, ignoretime_s: ?u64, mode: DeadlineMode, now_us: i64) !PreparedIgnoreDeadlines {
            var timed = try allocator.alloc(shared.types.TimedEntry, literals.len);
            errdefer allocator.free(timed);
            const count = try ignore_set.configuredEntries(literals, ignoretime_s, timed);
            timed = try allocator.realloc(timed, count);
            const stored = try allocator.alloc(?i64, count);
            errdefer allocator.free(stored);
            switch (mode) {
                .apply => try store.applyConfigDeadlines(.ignoreip, name, timed, now_us, stored),
                .read => try store.configEntryDeadlines(.ignoreip, name, timed, stored),
                .preview => try store.previewConfigDeadlines(.ignoreip, name, timed, now_us, stored),
            }
            const deadlines = try allocator.alloc(?i64, literals.len);
            var next: usize = 0;
            for (literals, deadlines) |literal, *slot| {
                slot.* = null;
                _ = shared.types.TimedEntry.parse(literal, ignoretime_s) catch continue;
                slot.* = stored[next];
                next += 1;
            }
            return .{ .entries = timed, .stored = stored, .literals = deadlines };
        }

        pub fn selfAddressList(self: *const Coordinator) []const shared.IpAddress {
            return if (self.self_addresses) |list| list.addresses else &.{};
        }

        pub fn readSelfAddresses(self: *Coordinator) ?shared.self_addresses.SelfAddresses {
            return shared.self_addresses.read(self.allocator) catch |failure| {
                std.log.warn("native: this host's addresses could not be read: {s}; ignoreself covers no address until the next reload", .{@errorName(failure)});
                return null;
            };
        }

        pub fn effectiveIgnore(self: *Coordinator, cfg: *const config.Config, name: []const u8, own: []const shared.IpAddress, mode: DeadlineMode, now_us: i64) !*ignore_set.EffectiveIgnore {
            const jail_cfg = findConfigJail(cfg, name);
            const literals = ignoreLiterals(cfg, jail_cfg);
            const resolved: ?config.ResolvedJailConfig = if (jail_cfg) |value| config.resolveJailFromConfig(value, cfg.defaults) else null;
            const deadlines = try configuredIgnoreDeadlines(self.allocator, &self.store, name, literals, if (resolved) |value| value.ignoretime_s else null, mode, now_us);
            defer self.allocator.free(deadlines);
            return self.effectiveIgnoreWithDeadlines(cfg, name, own, deadlines, now_us);
        }

        pub fn effectiveIgnoreWithDeadlines(self: *Coordinator, cfg: *const config.Config, name: []const u8, own: []const shared.IpAddress, deadlines: []const ?i64, now_us: i64) !*ignore_set.EffectiveIgnore {
            var runtime: [ignore_set.max_entries_per_part]RuntimeIgnoreEntry = undefined;
            const count = try self.store.ignoreEntries(name, &runtime);
            const jail_cfg = findConfigJail(cfg, name);
            const literals = ignoreLiterals(cfg, jail_cfg);
            const resolved: ?config.ResolvedJailConfig = if (jail_cfg) |value| config.resolveJailFromConfig(value, cfg.defaults) else null;
            const listed: []const shared.IpAddress = if (resolved != null and resolved.?.ignoreself) own else &.{};
            return ignore_set.EffectiveIgnore.build(self.allocator, literals, deadlines, runtime[0..count], listed, now_us);
        }

        pub fn previewIgnoreDeadlines(self: *Coordinator, cfg: *const config.Config, name: []const u8, now_us: i64) !PreparedIgnoreDeadlines {
            const jail_cfg = findConfigJail(cfg, name);
            const ignoretime_s = if (jail_cfg) |value| config.resolveJailFromConfig(value, cfg.defaults).ignoretime_s else null;
            return prepareIgnoreDeadlines(self.allocator, &self.store, name, ignoreLiterals(cfg, jail_cfg), ignoretime_s, .preview, now_us);
        }

        pub fn replaceIgnoreList(self: *Coordinator, jail: *Jail, next: *ignore_set.EffectiveIgnore) void {
            const cell = ignoreCell(jail) orelse return next.deinit(self.allocator);
            var runtime_only: u16 = 0;
            for (next.entries) |item| runtime_only += @intFromBool(item.source == .runtime);
            self.mutex.lock();
            const previous = cell.*;
            cell.* = next;
            jail.ignore_runtime_only = runtime_only;
            self.mutex.unlock();
            previous.deinit(self.allocator);
        }

        pub fn applyIgnoreDeadlines(self: *Coordinator, cfg: *const config.Config, name: []const u8, now_us: i64) !void {
            const jail_cfg = findConfigJail(cfg, name);
            const ignoretime_s = if (jail_cfg) |value| config.resolveJailFromConfig(value, cfg.defaults).ignoretime_s else null;
            self.allocator.free(try configuredIgnoreDeadlines(self.allocator, &self.store, name, ignoreLiterals(cfg, jail_cfg), ignoretime_s, .apply, now_us));
        }

        fn rebuildIgnoreList(self: *Coordinator, jail: *Jail, now_us: i64) !void {
            if (ignoreCell(jail) == null) return;
            self.replaceIgnoreList(jail, try self.effectiveIgnore(self.live_cfg, jail.name, self.selfAddressList(), .read, now_us));
        }

        pub fn rebuildIgnoreLists(self: *Coordinator) !void {
            const now = self.clock.wallUs();
            for (self.jails) |*jail| {
                if (ignoreCell(jail) == null) {
                    try self.applyIgnoreDeadlines(self.live_cfg, jail.name, now);
                    continue;
                }
                const next = try self.effectiveIgnore(self.live_cfg, jail.name, self.selfAddressList(), .apply, now);
                if (next.over_bound) std.log.warn(
                    "native: jail={} has {d} ignore entries ({d} configured, {d} runtime-only), above the {d}-entry limit; all apply; fail2zig ignore add is refused until the count is {d} or less",
                    .{ std.zig.fmtEscapes(jail.name), next.entries.len, next.configured_count, next.entries.len - next.configured_count, ignore_set.distinct_bound, ignore_set.distinct_bound },
                );
                self.replaceIgnoreList(jail, next);
            }
            var stored: [256]durable.Store.IgnoreJailCount = undefined;
            const stored_count = try self.store.ignoreEntryJails(&stored);
            for (stored[0..stored_count]) |item| {
                const name = item.jail[0..item.jail_len];
                if (findConfigJail(self.live_cfg, name) != null) continue;
                std.log.warn("native: {d} runtime ignore entries are stored for jail {}, which is not configured; they are not effective", .{ item.count, std.zig.fmtEscapes(name) });
            }
        }

        pub fn ignoreSourceText(source: ?ignore_set.Source) ?[]const u8 {
            return switch (source orelse return null) {
                .config => "config",
                .runtime => "runtime",
                .both => "config+runtime",
                .self => "self",
            };
        }

        pub fn expireIgnoreEntries(self: *Coordinator, now_ms: u64) !void {
            if (self.last_ignore_expiry_ms) |last| if (now_ms -| last < quiet_interval_ms) return;
            self.last_ignore_expiry_ms = now_ms;
            const now = self.clock.wallUs();
            var changed: [256]durable.Store.IgnoreJailCount = undefined;
            const count = try self.store.expireIgnoreEntries(now, &changed);
            for (changed[0..count]) |item| std.log.info("native: jail={} {d} runtime ignore entries expired", .{ std.zig.fmtEscapes(item.jail[0..item.jail_len]), item.count });
            for (self.jails) |*jail| {
                const cell = ignoreCell(jail) orelse continue;
                var due = if (cell.*.next_deadline_us) |deadline| deadline <= now else false;
                for (changed[0..count]) |item| due = due or std.mem.eql(u8, item.jail[0..item.jail_len], jail.name);
                if (due) try self.rebuildIgnoreList(jail, now);
            }
        }
    };
}

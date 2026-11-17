// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Builds the legacy ban list and the ignore page from published daemon state and the read-only store.
// Holds: A ban list or ignore page whose store read overlapped a newer published generation is refused, never mixed.

const std = @import("std");
const shared = @import("shared");
const config = @import("../config/config.zig");
const detection = @import("../detect/detection_record.zig");
const inspection = @import("../firewall/inspection.zig");
const durable = @import("../store/store.zig");
const ignore_set = @import("../detect/ignore_set.zig");
const custom_ignore = @import("../detect/ignore.zig");
const dns = @import("../detect/dns.zig");
const Cidr = @import("../detect/cidr.zig").Cidr;
const native_banip = @import("../config/banip.zig");
const RuntimeIgnoreEntry = @import("../store/ignore_entries.zig").RuntimeIgnoreEntry;
const query_v1 = @import("../net/query_v1.zig");
const daemon = @import("daemon.zig");
const max_jails = daemon.max_jails;
const Jail = daemon.Jail;
const query_mod = @import("query.zig");
const BanCapture = query_mod.BanCapture;
const CaptureMemory = query_mod.CaptureMemory;
const ExpiredBan = query_mod.ExpiredBan;
const ignore_capture_bytes = query_mod.ignore_capture_bytes;
const ignore_string_bytes = query_mod.ignore_string_bytes;
const IgnoreJail = query_mod.IgnoreJail;
const IgnoreProjection = query_mod.IgnoreProjection;
const legacy_allowance = query_mod.legacy_allowance;
const legacy_capture_bytes = query_mod.legacy_capture_bytes;
const legacy_item_bound = query_mod.legacy_item_bound;
const LegacyBanItem = query_mod.LegacyBanItem;

pub fn Methods(comptime Coordinator: type) type {
    return struct {
        const beginConfigRead = Coordinator.beginConfigRead;
        const configuredIgnoreDeadlines = Coordinator.configuredIgnoreDeadlines;
        const findConfigJail = Coordinator.findConfigJail;
        const formatListSubject = Coordinator.formatListSubject;
        const ignoreCell = Coordinator.ignoreCell;
        const ignoreSourceText = Coordinator.ignoreSourceText;
        const monotonic = Coordinator.monotonic;
        const observationMs = Coordinator.observationMs;
        const readExpired = Coordinator.readExpired;
        const redacted_text = Coordinator.redacted_text;
        fn appendLegacy(items: []LegacyBanItem, count: *usize, value: LegacyBanItem) !void {
            if (count.* == legacy_item_bound) return error.SnapshotLimit;
            items[count.*] = value;
            count.* += 1;
        }
        pub fn writeBans(self: *Coordinator, out: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator, selected: ?shared.JailId) !void {
            var memory = try CaptureMemory.init(a, legacy_capture_bytes);
            defer memory.deinit(a);
            const items = try memory.fixed.allocator().alloc(LegacyBanItem, legacy_item_bound + 1);
            var count: usize = 0;
            var names: [max_jails][]const u8 = undefined;
            var bans: [max_jails]BanCapture = undefined;
            var jail_count: usize = 0;
            var generation: [32]u8 = undefined;
            var now: i64 = undefined;
            {
                self.mutex.lock();
                defer self.mutex.unlock();
                generation = self.published_generation;
                const sampled_wall = self.observationWall();
                const observation = self.worker_observation.read(observationMs(), sampled_wall);
                now = sampled_wall orelse self.start_us;
                const known = self.confirmationKnown(monotonic(self));
                for (self.jails, 0..) |jail, slot| {
                    names[slot] = try memory.text(jail.name);
                    bans[slot] = .{ .name = names[slot], .entries = &.{} };
                    jail_count += 1;
                    if (selected) |name| if (!std.mem.eql(u8, name.slice(), jail.name)) continue;
                    if (self.jailEnforces(&jail)) {
                        if (self.owner_publication_pending) return error.SnapshotLimit;
                    } else if (jail.retry_revision == null) return error.SnapshotLimit;
                    bans[slot] = try self.captureBan(&memory, names[slot]);
                    if (self.jailEnforces(&jail)) {
                        const range = jail.owner_range;
                        for (self.owner_active[range.start..][0..range.len], self.owner_confirmed[range.start..][0..range.len]) |owner, confirmed| {
                            if (!observation.clock_uncertain and sampled_wall != null and !owner.lease.live(now)) continue;
                            try appendLegacy(
                                items,
                                &count,
                                .{
                                    .scope = owner.scope.canonical,
                                    .jail_slot = @intCast(slot),
                                    .origin = owner.origin,
                                    .expiry_us = if (owner.lease == .finite) owner.lease.finite else null,
                                    .permanent = owner.lease == .permanent,
                                    .ordinal = owner.ordinal,
                                    .confirmed = confirmed and known,
                                    .expired = false,
                                },
                            );
                        }
                    } else for (jail.active) |decision| {
                        if (!observation.clock_uncertain and sampled_wall != null and !decision.lease.live(now)) continue;
                        const address: shared.IpAddress = switch (decision.subject) {
                            .v4 => |value| .{ .ipv4 = std.mem.readInt(u32, &value, .big) },
                            .v6 => |value| .{ .ipv6 = std.mem.readInt(u128, &value, .big) },
                        };
                        try appendLegacy(
                            items,
                            &count,
                            .{
                                .scope = .{ .subject = inspection.canonical_scope.Subject.host(address) },
                                .jail_slot = @intCast(slot),
                                .origin = .detection,
                                .expiry_us = if (decision.lease == .finite) decision.lease.finite else null,
                                .permanent = decision.lease == .permanent,
                                .ordinal = decision.ordinal,
                                .confirmed = false,
                                .expired = false,
                            },
                        );
                    }
                }
            }
            if (self.history_reader) |*reader| {
                beginConfigRead(reader, generation) catch |failure| switch (failure) {
                    error.InvalidatedCursor => return error.SnapshotLimit,
                    else => return failure,
                };
                errdefer reader.rollback();
                var expired: [native_banip.max_banip_entries]ExpiredBan = undefined;
                for (bans[0..jail_count], 0..) |ban, slot| {
                    const found = try readExpired(reader, ban, now, &expired);
                    for (expired[0..found]) |entry| {
                        const address = entry.entry.network();
                        const bits: u8 = if (entry.entry.family == .v4) 32 else 128;
                        const subject = if (entry.entry.prefix == bits) inspection.canonical_scope.Subject.host(address) else try inspection.canonical_scope.Subject.network(
                            address,
                            entry.entry.prefix,
                        );
                        try appendLegacy(
                            items,
                            &count,
                            .{
                                .scope = .{ .subject = subject },
                                .jail_slot = @intCast(slot),
                                .origin = .config,
                                .expiry_us = entry.expires_us,
                                .permanent = false,
                                .ordinal = 0,
                                .confirmed = false,
                                .expired = true,
                            },
                        );
                    }
                }
                try reader.commitTransaction();
                // Why: The store read ran outside the mutex, so a generation published meanwhile refuses the page instead of mixing two.
                if (!self.unchanged(generation)) return error.SnapshotLimit;
            }
            var sink = query_v1.ByteSink{ .out = out, .allocator = a, .limit = legacy_allowance };
            const writer = sink.writer();
            writer.writeByte('[') catch |failure| switch (failure) {
                error.ResponseTooLarge => return error.SnapshotLimit,
                else => return failure,
            };
            for (items[0..count], 0..) |item, index| {
                if (index != 0) writer.writeByte(',') catch |failure| switch (failure) {
                    error.ResponseTooLarge => return error.SnapshotLimit,
                    else => return failure,
                };
                var buffer: [64]u8 = undefined;
                const formatted = try formatListSubject(item.scope.subject, &buffer);
                std.json.stringify(.{ .ip = formatted, .jail = names[item.jail_slot], .origin = @tagName(item.origin), .expired = item.expired, .expiry_us = item.expiry_us, .ban_expiry = if (item.expiry_us) |value| @as(?i64, @divFloor(value, 1_000_000)) else null, .permanent = item.permanent, .ban_count = item.ordinal, .enforced = item.confirmed, .confirmed = item.confirmed }, .{}, writer) catch |failure| switch (failure) {
                    error.ResponseTooLarge => return error.SnapshotLimit,
                    else => return failure,
                };
            }
            writer.writeByte(']') catch |failure| switch (failure) {
                error.ResponseTooLarge => return error.SnapshotLimit,
                else => return failure,
            };
        }
        pub fn writeIgnoreJail(out: *query_v1.JsonStream, name: []const u8, enabled: bool, ignore_file: ?[]const u8, items: []const ignore_set.Item, hostnames: []const []const u8, limit: ?u16, redact: bool, now_us: i64) !void {
            try out.beginObject();
            try out.objectField("jail");
            try out.write(name);
            try out.objectField("enabled");
            try out.write(enabled);
            try out.objectField("count");
            try out.write(items.len + hostnames.len);
            if (limit) |value| {
                try out.objectField("limit");
                try out.write(value);
            }
            try out.objectField("ignore_file");
            try out.write(if (ignore_file != null and redact) @as(?[]const u8, redacted_text) else ignore_file);
            try out.objectField("entries");
            try out.beginArray();
            for (items) |item| {
                var buffer: [64]u8 = undefined;
                try out.beginObject();
                try out.objectField("address");
                try out.write(if (redact) redacted_text else item.entry.canonical(&buffer));
                try out.objectField("source");
                try out.write(ignoreSourceText(item.source).?);
                const expired = if (item.expires_us) |deadline| deadline <= now_us else false;
                try out.objectField("expires_us");
                try out.write(item.expires_us);
                try out.objectField("remaining_s");
                if (item.expires_us) |deadline| try out.write(if (expired) 0 else @as(u64, @intCast(@divFloor(deadline - now_us + std.time.us_per_s - 1, std.time.us_per_s)))) else try out.write(null);
                try out.objectField("expired");
                try out.write(expired);
                try out.endObject();
            }
            for (hostnames) |literal| {
                try out.beginObject();
                try out.objectField("address");
                try out.write(if (redact) redacted_text else literal);
                try out.objectField("source");
                try out.write("config");
                try out.objectField("expires_us");
                try out.write(null);
                try out.objectField("remaining_s");
                try out.write(null);
                try out.objectField("expired");
                try out.write(false);
                try out.endObject();
            }
            try out.endArray();
            try out.endObject();
        }
        fn configuredIgnoreItems(arena: std.mem.Allocator, reader: *durable.Store, name: []const u8, literals: []const []const u8, runtime: []const RuntimeIgnoreEntry, own: []const shared.IpAddress, ignoretime_s: ?u64, ignoreself: bool, now_us: i64, hostnames: *[]const []const u8) ![]const ignore_set.Item {
            const deadlines = try configuredIgnoreDeadlines(arena, reader, name, literals, ignoretime_s, .read, now_us);
            const parseable = try arena.alloc([]const u8, literals.len);
            const parseable_deadlines = try arena.alloc(?i64, literals.len);
            const names = try arena.alloc([]const u8, literals.len);
            var parseable_count: usize = 0;
            var name_count: usize = 0;
            for (literals, deadlines) |literal, deadline| {
                if (shared.types.TimedEntry.parse(literal, null)) |_| {
                    parseable[parseable_count] = literal;
                    parseable_deadlines[parseable_count] = deadline;
                    parseable_count += 1;
                } else |_| {
                    names[name_count] = literal;
                    name_count += 1;
                }
            }
            std.sort.pdq([]const u8, names[0..name_count], {}, hostnameLess);
            hostnames.* = names[0..name_count];
            const listed: []const shared.IpAddress = if (ignoreself) own else &.{};
            const list = try ignore_set.EffectiveIgnore.build(arena, parseable[0..parseable_count], parseable_deadlines[0..parseable_count], runtime, listed, now_us);
            return list.entries;
        }
        pub fn hostnameLess(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
        fn ignoreNetwork(network: Cidr) shared.types.IgnoreEntry {
            var address = [_]u8{0} ** 16;
            return switch (network) {
                .v4 => |value| blk: {
                    std.mem.writeInt(u32, address[0..4], value.net, .big);
                    break :blk .{ .family = .v4, .address = address, .prefix = @intCast(@popCount(value.mask)) };
                },
                .v6 => |value| blk: {
                    std.mem.writeInt(u128, &address, value.net, .big);
                    break :blk .{ .family = .v6, .address = address, .prefix = @intCast(@popCount(value.mask)) };
                },
            };
        }
        fn ignoreSelf(address: shared.IpAddress) shared.types.IgnoreEntry {
            return ignoreNetwork(switch (address) {
                .ipv4 => |value| .{ .v4 = .{ .net = value, .mask = std.math.maxInt(u32) } },
                .ipv6 => |value| .{ .v6 = .{ .net = value, .mask = std.math.maxInt(u128) } },
            });
        }
        // Why: buildIgnore puts configured entries before ignore_file values, so the first configured_count entries are configuration.
        fn copyCustomIgnore(memory: *CaptureMemory, snapshot: *const custom_ignore.Snapshot, configured_count: usize) !IgnoreProjection {
            if (snapshot.entries.len > custom_ignore.max_entries or configured_count > snapshot.entries.len) return error.IgnoreLimit;
            const allocator = memory.fixed.allocator();
            const items = try allocator.alloc(ignore_set.Item, snapshot.entries.len);
            const hostnames = try allocator.alloc([]const u8, custom_ignore.max_hostnames);
            var count: usize = 0;
            var names: usize = 0;
            for (snapshot.entries, 0..) |entry, index| {
                if (index < configured_count) {
                    switch (entry) {
                        .network => |network| {
                            items[count] = .{ .entry = ignoreNetwork(network), .source = .config };
                            count += 1;
                        },
                        .hostname => |name| {
                            if (names == hostnames.len) return error.IgnoreDependencyLimit;
                            hostnames[names] = try memory.text(name.slice());
                            names += 1;
                        },
                        .self => return error.InvalidIgnoreEntry,
                    }
                } else if (entry == .self) {
                    items[count] = .{ .entry = ignoreSelf(entry.self), .source = .self };
                    count += 1;
                }
            }
            return .{ .items = items[0..count], .hostnames = hostnames[0..names] };
        }
        fn configuredCustomIgnore(memory: *CaptureMemory, literals: []const []const u8) !IgnoreProjection {
            if (literals.len > custom_ignore.max_entries) return error.IgnoreLimit;
            const allocator = memory.fixed.allocator();
            const items = try allocator.alloc(ignore_set.Item, literals.len);
            const hostnames = try allocator.alloc([]const u8, custom_ignore.max_hostnames);
            var count: usize = 0;
            var names: usize = 0;
            for (literals) |literal| {
                if (literal.len == 0 or literal.len > 254 or std.mem.indexOfAny(u8, literal, " \t\r\n\x00") != null) return error.InvalidIgnoreEntry;
                if (Cidr.parse(literal)) |network| {
                    items[count] = .{ .entry = ignoreNetwork(network), .source = .config };
                    count += 1;
                } else |_| {
                    const name = dns.Name.init(literal) catch return error.InvalidIgnoreEntry;
                    if (names == hostnames.len) return error.IgnoreDependencyLimit;
                    hostnames[names] = try memory.text(name.slice());
                    names += 1;
                }
            }
            return .{ .items = items[0..count], .hostnames = hostnames[0..names] };
        }
        fn normalizeCustomIgnore(projection: IgnoreProjection) IgnoreProjection {
            std.sort.pdq(ignore_set.Item, projection.items, {}, struct {
                fn less(_: void, x: ignore_set.Item, y: ignore_set.Item) bool {
                    const order = x.entry.order(y.entry);
                    return if (order == .eq) @intFromEnum(x.source) < @intFromEnum(y.source) else order == .lt;
                }
            }.less);
            var count: usize = 0;
            for (projection.items) |item| {
                if (count != 0 and projection.items[count - 1].entry.order(item.entry) == .eq and projection.items[count - 1].source == item.source) continue;
                projection.items[count] = item;
                count += 1;
            }
            std.sort.pdq([]const u8, projection.hostnames, {}, hostnameLess);
            var names: usize = 0;
            for (projection.hostnames) |name| {
                if (names != 0 and std.mem.eql(u8, projection.hostnames[names - 1], name)) continue;
                projection.hostnames[names] = name;
                names += 1;
            }
            return .{ .items = projection.items[0..count], .hostnames = projection.hostnames[0..names] };
        }
        fn copyIgnoreJail(self: *const Coordinator, memory: *CaptureMemory, name: []const u8, runtime: ?*const Jail) !IgnoreJail {
            const cfg = findConfigJail(self.live_cfg, name);
            const resolved: ?config.ResolvedJailConfig = if (cfg) |value| config.resolveJailFromConfig(value, self.live_cfg.defaults) else null;
            const literals = if (cfg) |value| value.ignoreip orelse self.live_cfg.defaults.ignoreip else &.{};
            const custom = if (runtime) |jail| jail.custom_plan != null else if (cfg) |value| value.rule_files.len != 0 else false;
            var items: ?[]ignore_set.Item = null;
            var hostnames: [][]const u8 = &.{};
            if (runtime) |jail| {
                if (custom) {
                    const consumer = jail.consumer orelse return error.HistoryUnavailable;
                    const view = try copyCustomIgnore(memory, consumer.ignores.live, literals.len);
                    items = view.items;
                    hostnames = view.hostnames;
                } else if (ignoreCell(jail)) |cell| items = try memory.fixed.allocator().dupe(ignore_set.Item, cell.*.entries);
            } else if (custom) {
                if (cfg.?.enabled) return error.HistoryUnavailable;
                if (literals.len > custom_ignore.max_entries) return error.IgnoreLimit;
                for (literals) |literal| if (literal.len > 254) return error.InvalidIgnoreEntry;
            }
            return .{
                .name = try memory.text(name),
                .enabled = if (runtime) |jail| jail.admin_enabled else false,
                .ignore_file = if (cfg) |value| (if (value.ignore_file) |path| try memory.text(path) else null) else null,
                .items = items,
                .hostnames = hostnames,
                .custom = custom,
                .literals = if (items == null) try memory.texts(literals) else &.{},
                .ignoretime_s = if (resolved) |value| value.ignoretime_s else null,
                .ignoreself = resolved != null and resolved.?.ignoreself,
            };
        }
        pub fn ignoreRender(ctx: ?*anyopaque, arena: std.mem.Allocator, jail_filter: ?[]const u8, redact: bool, out: *query_v1.JsonStream) anyerror!void {
            const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
            const reader = if (self.history_reader) |*value| value else return error.HistoryUnavailable;
            var memory = try CaptureMemory.init(self.allocator, ignore_capture_bytes);
            defer memory.deinit(self.allocator);
            _ = arena;
            memory.string_limit = ignore_string_bytes;
            var captures: [max_jails + 1]IgnoreJail = undefined;
            var count: usize = 0;
            var configured: [config.max_configured_jails]detection.Name = undefined;
            var configured_count: usize = 0;
            var own: []const shared.IpAddress = undefined;
            var generation: [32]u8 = undefined;
            var revision: u64 = undefined;
            var now: i64 = undefined;
            var fallback = false;
            {
                self.mutex.lock();
                defer self.mutex.unlock();
                generation = self.published_generation;
                revision = self.published_revision;
                now = self.observationWall() orelse self.start_us;
                own = try memory.fixed.allocator().dupe(shared.IpAddress, self.selfAddressList());
                for (self.live_cfg.jails, 0..) |cfg, i| configured[i] = try detection.Name.init(cfg.name);
                configured_count = self.live_cfg.jails.len;
                for (self.jails) |*jail| {
                    if (jail.retiring and jail.custom_plan != null and findConfigJail(self.live_cfg, jail.name) == null) continue;
                    if (jail_filter) |name| if (!std.mem.eql(u8, name, jail.name)) continue;
                    captures[count] = try self.copyIgnoreJail(&memory, jail.name, jail);
                    count += 1;
                }
                if (jail_filter) |name| if (count == 0) {
                    captures[0] = try self.copyIgnoreJail(&memory, name, null);
                    count = 1;
                    fallback = true;
                };
            }
            std.sort.pdq(IgnoreJail, captures[0..count], {}, struct {
                fn less(_: void, x: IgnoreJail, y: IgnoreJail) bool {
                    return std.mem.lessThan(u8, x.name, y.name);
                }
            }.less);
            try beginConfigRead(reader, generation);
            errdefer reader.rollback();
            if (try reader.adminRevision() != revision) return error.InvalidatedCursor;
            var stored: [128]durable.Store.IgnoreJailCount = undefined;
            const stored_count = try reader.ignoreEntryJailsTx(&stored);
            var filtered: [ignore_set.max_entries_per_part]RuntimeIgnoreEntry = undefined;
            const filtered_count = if (fallback and !captures[0].custom) try reader.ignoreEntriesTx(captures[0].name, &filtered) else 0;
            if (fallback and filtered_count == 0) {
                var found = false;
                for (configured[0..configured_count]) |name| if (std.mem.eql(u8, name.slice(), captures[0].name)) {
                    found = true;
                    break;
                };
                if (!found) return error.UnknownJail;
            }
            const built = try memory.fixed.allocator().alloc(struct { items: []const ignore_set.Item, hostnames: []const []const u8 }, count);
            for (captures[0..count], built) |jail, *view| {
                if (jail.custom) {
                    const projection = normalizeCustomIgnore(if (jail.items) |items| .{ .items = items, .hostnames = jail.hostnames } else try configuredCustomIgnore(&memory, jail.literals));
                    view.* = .{ .items = projection.items, .hostnames = projection.hostnames };
                    continue;
                }
                var hostnames: []const []const u8 = &.{};
                const items: []const ignore_set.Item = if (jail.items) |values| values else try configuredIgnoreItems(
                    memory.fixed.allocator(),
                    reader,
                    jail.name,
                    jail.literals,
                    if (fallback) filtered[0..filtered_count] else &.{},
                    if (fallback) &.{} else own,
                    jail.ignoretime_s,
                    jail.ignoreself,
                    now,
                    &hostnames,
                );
                view.* = .{ .items = items, .hostnames = hostnames };
            }
            try reader.commitTransaction();
            if (!self.unchanged(generation)) return error.InvalidatedCursor;
            try out.objectField("limit");
            try out.write(ignore_set.distinct_bound);
            try out.objectField("jails");
            try out.beginArray();
            for (captures[0..count], built) |jail, view| try writeIgnoreJail(
                out,
                jail.name,
                jail.enabled,
                jail.ignore_file,
                view.items,
                view.hostnames,
                if (jail.custom) custom_ignore.max_entries else null,
                redact,
                now,
            );
            try out.endArray();
            try out.objectField("unconfigured");
            try out.beginArray();
            if (jail_filter == null) for (stored[0..stored_count]) |item| {
                const name = item.jail[0..item.jail_len];
                var found = false;
                for (configured[0..configured_count]) |cfg| if (std.mem.eql(u8, cfg.slice(), name)) {
                    found = true;
                    break;
                };
                if (found) continue;
                try out.beginObject();
                try out.objectField("jail");
                try out.write(name);
                try out.objectField("runtime_entries");
                try out.write(item.count);
                try out.endObject();
            };
            try out.endArray();
        }
    };
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Builds the status, ban list, metrics, health and version 1 query pages from published daemon state and the read-only store.
// Holds: Published state is copied while the coordinator mutex is held; rendering and store reads run only after it is released.

const std = @import("std");
const shared = @import("shared");
const config = @import("../config/config.zig");
const detection = @import("../detect/detection_record.zig");
const effect = @import("../effect/effect.zig");
const effect_runtime = @import("../runtime/effect_runtime.zig");
const firewall_observation = effect_runtime.observation;
const history = @import("../effect/effect_history.zig");
const retry = @import("../detect/retry.zig");
const inspection = @import("../firewall/inspection.zig");
const durable = @import("../store/store.zig");
const ignore_set = @import("../detect/ignore_set.zig");
const custom_ignore = @import("../detect/ignore.zig");
const dns = @import("../detect/dns.zig");
const native_banip = @import("../config/banip.zig");
const query_v1 = @import("../net/query_v1.zig");
const metrics_mod = @import("../diag/metrics.zig");
const resource = @import("../runtime/resource_budget.zig");
const ban_origin = @import("../effect/ban_origin.zig");
const daemon = @import("daemon.zig");
const max_jails = daemon.max_jails;
const Jail = daemon.Jail;

pub const LossJson = struct { sequence: u64, wall_us: i64, reason: []const u8, inode: u64, committed_offset: u64, observed_size: ?u64 };
pub const SourceJson = struct {
    jail: []const u8,
    kind: []const u8,
    path: ?[]const u8,
    on_truncation: ?[]const u8,
    state: []const u8,
    cause: ?[]const u8,
    inode: ?u64,
    committed_offset: ?u64,
    observed_size: ?u64,
    repair: ?[]const u8,
    loss_events: u16,
    last_loss: ?LossJson,
};

pub const legacy_allowance = shared.protocol.max_payload_size - 16;
pub const legacy_item_bound = (legacy_allowance - 1) / 115;
pub const LegacyBanItem = struct {
    scope: inspection.CanonicalScope,
    jail_slot: u8,
    origin: shared.types.Origin,
    expiry_us: ?i64,
    permanent: bool,
    ordinal: u64,
    confirmed: bool,
    expired: bool,
};
pub const BanCapture = struct { name: []const u8, entries: []const shared.types.TimedEntry };
const capture_padding = (max_jails * 12 + 4) * (@alignOf(u128) - 1);
pub const status_capture_bytes = query_v1.max_response_bytes + max_jails * daemon.max_source_status_per_jail * @sizeOf(SourceJson) + capture_padding;
pub const legacy_capture_bytes = max_jails * 64 + (legacy_item_bound + 1) * @sizeOf(LegacyBanItem) + max_jails * native_banip.max_banip_entries * @sizeOf(shared.types.TimedEntry) + capture_padding;
// Why: Every JSON string costs at least two quote bytes, so a config view that fits the response bound has at most half as many strings.
const config_capture_bytes = query_v1.max_response_bytes + (query_v1.max_response_bytes / 2) * @sizeOf([]const u8) + max_jails * @sizeOf(query_v1.JailConfig) + capture_padding;
const match_capture_bytes = query_v1.max_items_per_page * retry.max_evidence_text_bytes;
const history_capture_bytes = match_capture_bytes + query_v1.max_items_per_page * 64 + capture_padding;
const scopes_capture_bytes = max_jails * 64 + max_jails * @sizeOf(query_v1.JailScopes) + query_v1.max_items_per_page * @sizeOf(query_v1.ScopeItem) + max_jails * native_banip.max_banip_entries * @sizeOf(shared.types.TimedEntry) + capture_padding;
const scopes_detail_capture_bytes = scopes_capture_bytes + match_capture_bytes;
pub const ignore_string_bytes = max_jails * (custom_ignore.max_entries * 254 + 4096 + 64) + custom_ignore.max_hostnames * 254;
const ignore_builtin_workspace: usize = custom_ignore.max_entries * (3 * @sizeOf([]const u8) + 3 * @sizeOf(?i64) + @sizeOf(shared.types.TimedEntry)) +
    2 * (2 * ignore_set.max_entries_per_part + shared.self_addresses.max_self_addresses) * @sizeOf(ignore_set.Item) + @sizeOf(ignore_set.EffectiveIgnore);
const ignore_custom_workspace: usize = custom_ignore.max_entries * (@sizeOf(ignore_set.Item) + @sizeOf([]const u8)) + custom_ignore.max_hostnames * @sizeOf([]const u8);
pub const ignore_capture_bytes = ignore_string_bytes + max_jails * @as(usize, @max(ignore_builtin_workspace, ignore_custom_workspace)) +
    shared.self_addresses.max_self_addresses * @sizeOf(shared.IpAddress) + max_jails * @sizeOf(IgnoreProjection) + capture_padding;
const capture_bytes = @max(@max(status_capture_bytes, legacy_capture_bytes), @max(config_capture_bytes, @max(history_capture_bytes, @max(scopes_detail_capture_bytes, ignore_capture_bytes))));

pub fn queryCaptureCost() resource.Cost {
    // Why: A rendered response and its final owned copy are live at once, so two response bounds are charged.
    const expiry_scratch = native_banip.max_banip_entries * (@sizeOf(ExpiredBan) + @sizeOf(?i64));
    const match_scratch = history.max_page * (@sizeOf(durable.Store.OperatorOwner) + 2 * @sizeOf(history.Event) + @sizeOf(?[]u8) + @sizeOf(*query_v1.ScopeItem)) + query_v1.max_items_per_page * @sizeOf(query_v1.HistoryEvent);
    const capture_stack = @sizeOf(custom_ignore.Entry) + @sizeOf(dns.Name) + match_scratch + expiry_scratch + config.max_configured_jails * @sizeOf(detection.Name) + max_jails * @sizeOf(BanCapture) + (max_jails + 1) * @sizeOf(IgnoreJail) + @sizeOf(metrics_mod.Snapshot);
    return .{ .bytes = capture_bytes + 2 * query_v1.max_response_bytes + capture_stack, .allocations = 6, .fds = 0 };
}
pub const ExpiredBan = struct { entry: shared.types.IgnoreEntry, decision_id: [32]u8, expires_us: i64 };
pub const IgnoreJail = struct {
    name: []const u8,
    enabled: bool,
    ignore_file: ?[]const u8,
    items: ?[]ignore_set.Item,
    hostnames: [][]const u8 = &.{},
    custom: bool = false,
    literals: []const []const u8,
    ignoretime_s: ?u64,
    ignoreself: bool,
};
pub const IgnoreProjection = struct { items: []ignore_set.Item, hostnames: [][]const u8 };
pub const CaptureMemory = struct {
    backing: []u8,
    fixed: std.heap.FixedBufferAllocator,
    strings: usize = 0,
    string_limit: usize = query_v1.max_response_bytes,
    pub fn init(a: std.mem.Allocator, capacity: usize) !CaptureMemory {
        const backing = try a.alloc(u8, capacity);
        return .{ .backing = backing, .fixed = std.heap.FixedBufferAllocator.init(backing) };
    }
    pub fn deinit(self: *CaptureMemory, a: std.mem.Allocator) void {
        a.free(self.backing);
    }
    pub fn text(self: *CaptureMemory, value: []const u8) ![]const u8 {
        if (value.len > self.string_limit - self.strings) return error.ResponseTooLarge;
        self.strings += value.len;
        return self.fixed.allocator().dupe(u8, value);
    }
    pub fn texts(self: *CaptureMemory, values: []const []const u8) ![]const []const u8 {
        if (values.len > query_v1.max_response_bytes / 2) return error.ResponseTooLarge;
        const result = try self.fixed.allocator().alloc([]const u8, values.len);
        for (values, result) |value, *slot| slot.* = try self.text(value);
        return result;
    }
};

pub fn Methods(comptime Coordinator: type) type {
    return struct {
        const CaptureFence = struct {
            generation: [32]u8,
            epoch: ?u64,
            mark: @FieldType(Coordinator, "published_owners_mark"),
            health_generation: @FieldType(@FieldType(Coordinator, "published_health"), "generation"),
            pending: bool,
            names: [max_jails]detection.Name = undefined,
            retry_revisions: [max_jails]?u64 = undefined,
            active_counts: [max_jails]usize = undefined,
            count: usize,
        };
        fn captureFence(self: *const Coordinator) !CaptureFence {
            var result = CaptureFence{
                .generation = self.published_generation,
                .epoch = self.owner_read_epoch,
                .mark = self.published_owners_mark,
                .health_generation = self.published_health.generation,
                .pending = self.owner_publication_pending,
                .count = self.jails.len,
            };
            for (self.jails, 0..) |jail, i| {
                result.names[i] = try detection.Name.init(jail.name);
                result.retry_revisions[i] = if (self.jailEnforces(&jail)) null else jail.retry_revision;
                result.active_counts[i] = if (self.jailEnforces(&jail)) 0 else jail.active.len;
            }
            return result;
        }
        fn fenceMatches(self: *const Coordinator, fence: *const CaptureFence) bool {
            if (!std.mem.eql(
                u8,
                &fence.generation,
                &self.published_generation,
            ) or fence.epoch != self.owner_read_epoch or !std.meta.eql(fence.mark, self.published_owners_mark) or fence.health_generation != self.published_health.generation or fence.pending != self.owner_publication_pending or fence.count != self.jails.len) return false;
            for (self.jails, fence.names[0..fence.count], 0..) |jail, name, i| {
                if (!std.mem.eql(u8, jail.name, name.slice())) return false;
                if (!self.jailEnforces(&jail) and (jail.retry_revision != fence.retry_revisions[i] or jail.active.len != fence.active_counts[i])) return false;
            }
            return true;
        }
        const findConfigJail = Coordinator.findConfigJail;
        const continuityRender = Coordinator.continuityRender;
        const healthCallback = Coordinator.healthCallback;
        const HistoryQuery = Coordinator.HistoryQuery;
        const historyRead = Coordinator.historyRead;
        const ignoreRender = Coordinator.ignoreRender;
        const monotonic = Coordinator.monotonic;
        const observationMs = Coordinator.observationMs;
        const statusCallback = Coordinator.statusCallback;
        const StatusQuery = Coordinator.StatusQuery;
        pub const redacted_text = "<redacted>";
        pub fn captureBan(self: *const Coordinator, memory: *CaptureMemory, name: []const u8) !BanCapture {
            const jail_cfg = findConfigJail(self.live_cfg, name) orelse return .{ .name = name, .entries = &.{} };
            const literals = jail_cfg.banip orelse self.live_cfg.defaults.banip;
            const entries = try memory.fixed.allocator().alloc(shared.types.TimedEntry, literals.len);
            for (literals, entries) |literal, *entry| entry.* = try shared.types.TimedEntry.parse(literal, null);
            return .{ .name = name, .entries = entries };
        }
        pub fn readExpired(reader: *durable.Store, ban: BanCapture, now_us: i64, output: []ExpiredBan) !usize {
            var deadlines: [native_banip.max_banip_entries]?i64 = undefined;
            try reader.configEntryDeadlines(.banip, ban.name, ban.entries, deadlines[0..ban.entries.len]);
            var count: usize = 0;
            for (ban.entries, deadlines[0..ban.entries.len]) |item, deadline| {
                const expires = deadline orelse continue;
                if (expires > now_us) continue;
                const entry = ban_origin.BanListEntry{ .entry = item.entry, .jail = ban.name, .duration_s = item.duration_s };
                output[count] = .{ .entry = item.entry, .decision_id = entry.decisionId(), .expires_us = expires };
                count += 1;
            }
            return count;
        }
        // Holds: The read transaction stays open only when the store's latest config generation is published and equals the captured one.
        pub fn beginConfigRead(reader: *durable.Store, generation: [32]u8) !void {
            try reader.beginRead();
            errdefer reader.rollback();
            const head = try reader.latestConfigGeneration() orelse return error.InvalidatedCursor;
            if (!head.published or !std.mem.eql(u8, &head.generation, &generation)) return error.InvalidatedCursor;
        }
        pub fn unchanged(self: *Coordinator, generation: [32]u8) bool {
            self.mutex.lock();
            defer self.mutex.unlock();
            return std.mem.eql(u8, &generation, &self.published_generation);
        }
        pub fn expiredKey(index: usize) query_v1.ItemKey {
            var bytes = [_]u8{0xff} ** 33;
            std.mem.writeInt(u16, bytes[31..33], @intCast(index), .big);
            return query_v1.ItemKey.init(&bytes);
        }
        pub fn expiredIndex(cursor: []const u8) ?usize {
            if (cursor.len != 33 or !std.mem.allEqual(u8, cursor[0..31], 0xff)) return null;
            return std.mem.readInt(u16, cursor[31..33], .big);
        }
        pub fn expiredScopeItem(expired: ExpiredBan, index: usize) !query_v1.ScopeItem {
            const address = expired.entry.network();
            const full: u8 = if (expired.entry.family == .v4) 32 else 128;
            const subject = if (expired.entry.prefix == full) inspection.canonical_scope.Subject.host(address) else try inspection.canonical_scope.Subject.network(address, expired.entry.prefix);
            return .{
                .scope = try query_v1.projectScope(.{ .subject = subject }),
                .lease = .finite,
                .deadline_us = expired.expires_us,
                .decision_id = expired.decision_id,
                .confirmed = false,
                .ban_count = 0,
                .key = expiredKey(index),
                .origin = .config,
                .expired = true,
            };
        }
        pub fn jailNameLess(self: *const Coordinator, a: usize, b: usize) bool {
            return std.mem.lessThan(u8, self.jails[a].name, self.jails[b].name);
        }
        pub fn firewallOrigin(ctx: ?*anyopaque, scope: inspection.CanonicalScope) ?shared.types.Origin {
            const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
            self.mutex.lock();
            defer self.mutex.unlock();
            const installation = self.startup_installation orelse return null;
            const exact = effect.Scope.exact(scope) catch return null;
            const key = exact.key(installation) catch return null;
            var order: [max_jails]usize = undefined;
            for (self.jails, 0..) |_, i| order[i] = i;
            std.sort.pdq(usize, order[0..self.jails.len], @as(*const Coordinator, self), jailNameLess);
            for (order[0..self.jails.len]) |slot| {
                const range = self.jails[slot].owner_range;
                var low: usize = 0;
                var high = range.len;
                while (low < high) {
                    const middle = low + (high - low) / 2;
                    if (std.mem.order(u8, &self.owner_active[range.start + middle].key, &key) == .lt) low = middle + 1 else high = middle;
                }
                if (low < range.len) {
                    const owner = self.owner_active[range.start + low];
                    if (std.mem.eql(u8, &owner.key, &key)) return owner.origin;
                }
            }
            return null;
        }
        pub fn firewallRead(ctx: ?*anyopaque, request: firewall_observation.PageRequest, out: *firewall_observation.Page) anyerror!void {
            const cache: *firewall_observation.Cache = @ptrCast(@alignCast(ctx.?));
            try cache.readPage(request, out);
        }
        fn copyConfig(self: *Coordinator, memory: *CaptureMemory, redact: bool) !query_v1.ConfigView {
            const cfg = self.live_cfg;
            const jails = try memory.fixed.allocator().alloc(query_v1.JailConfig, self.jails.len);
            var string_slots: usize = 0;
            for (self.jails, jails) |jail, *row| {
                const source = findConfigJail(cfg, jail.name);
                const paths = if (source) |value| value.logpath else &.{};
                const ignores = if (source) |value| value.ignoreip orelse cfg.defaults.ignoreip else &.{};
                string_slots = std.math.add(usize, string_slots, paths.len + ignores.len) catch return error.ResponseTooLarge;
                if (string_slots > query_v1.max_response_bytes / 2) return error.ResponseTooLarge;
                const owned_paths = try memory.fixed.allocator().alloc([]const u8, paths.len);
                for (paths, owned_paths) |value, *owned| owned.* = if (redact) redacted_text else try memory.text(value);
                const owned_ignores = try memory.fixed.allocator().alloc([]const u8, ignores.len);
                for (ignores, owned_ignores) |value, *owned| owned.* = if (redact) redacted_text else try memory.text(value);
                row.* = .{
                    .name = try memory.text(jail.name),
                    .enabled = jail.admin_enabled,
                    .filter = try memory.text(if (source) |value| value.filter else ""),
                    .source = @tagName(jail.plan),
                    .logpath = owned_paths,
                    .maxretry = jail.policy.maxretry,
                    .findtime = @intCast(@divTrunc(jail.policy.window_us, 1_000_000)),
                    .bantime = if (jail.policy.duration == .finite_us) @intCast(@divTrunc(jail.policy.duration.finite_us, 1_000_000)) else 0,
                    .bantime_permanent = jail.policy.duration == .permanent,
                    .banaction = if (self.jailEnforces(&jail)) self.published_backend else "log-only",
                    .ignoreip = owned_ignores,
                    .history_max_matches = @min(
                        cfg.global.history_max_matches,
                        if (source) |value| value.history_max_matches orelse cfg.global.history_max_matches else cfg.global.history_max_matches,
                    ),
                    .history_max_matches_inherited = if (source) |value| value.history_max_matches == null else true,
                };
            }
            return .{
                .jails = jails,
                .global = .{
                    .log_level = @tagName(cfg.global.log_level),
                    .firewall = @tagName(cfg.global.firewall),
                    .metrics_enabled = cfg.global.metrics_enabled,
                    .metrics_bind = try memory.text(cfg.global.metrics_bind),
                    .metrics_port = cfg.global.metrics_port,
                    .socket_path = if (redact) redacted_text else try memory.text(cfg.global.socket_path),
                    .state_file = if (redact) redacted_text else try memory.text(cfg.global.state_file),
                    .dns_server = if (redact) redacted_text else if (cfg.global.dns_server) |value| try memory.text(value) else null,
                    .timezone_root = if (redact) redacted_text else try memory.text(cfg.global.timezone_root),
                    .history_max_matches = cfg.global.history_max_matches,
                },
            };
        }
        // Holds: Every return to the mutex checks the fence first, so a page never joins rows from two publications.
        fn copyScopes(self: *Coordinator, memory: *CaptureMemory, body: []const u8, parse_arena: std.mem.Allocator, fence: *const CaptureFence) !query_v1.ScopesView {
            const allocator = memory.fixed.allocator();
            const jails = try allocator.alloc(query_v1.JailScopes, fence.count);
            for (jails, fence.names[0..fence.count]) |*jail, name| jail.* = .{ .name = try memory.text(name.slice()), .items = &.{}, .count = 0 };
            const window = query_v1.scopesWindow(parse_arena, body) orelse return .{ .jails = jails };
            var selected: ?usize = null;
            if (window.jail) |name| {
                for (jails, 0..) |jail, i| if (std.mem.eql(u8, jail.name, name)) {
                    selected = i;
                    break;
                };
                if (selected == null) return .{ .jails = jails };
            }
            const first: usize = if (window.cursor_jail) |slot| slot else selected orelse 0;
            if (first >= fence.count or (selected != null and selected.? != first)) return .{ .jails = jails };
            const storage = try allocator.alloc(query_v1.ScopeItem, window.limit);
            var filled: usize = 0;
            var now: i64 = undefined;
            var known: bool = undefined;
            self.mutex.lock();
            if (!self.fenceMatches(fence)) {
                self.mutex.unlock();
                return error.InvalidatedCursor;
            }
            now = self.observationWall() orelse self.start_us;
            known = self.confirmationKnown(monotonic(self));
            self.mutex.unlock();
            const reader = if (self.history_reader) |*value| value else return error.HistoryUnavailable;
            try beginConfigRead(reader, fence.generation);
            errdefer reader.rollback();
            const installation = if (window.details) try reader.readInstallation() else null;
            var owners: [effect.max_page]durable.Store.OperatorOwner = undefined;
            var lines: [effect.max_page]?[]u8 = undefined;
            var owner_items: [effect.max_page]*query_v1.ScopeItem = undefined;
            var owner_count: usize = 0;
            var expired: [native_banip.max_banip_entries]ExpiredBan = undefined;
            var i = first;
            while (i < fence.count) : (i += 1) {
                if (selected != null and selected.? != i) break;
                var live: usize = undefined;
                var start: usize = 0;
                var ban: BanCapture = undefined;
                {
                    self.mutex.lock();
                    defer self.mutex.unlock();
                    if (!self.fenceMatches(fence)) return error.InvalidatedCursor;
                    const jail = &self.jails[i];
                    if (self.jailEnforces(jail) and fence.pending) return error.HistoryUnavailable;
                    if (!self.jailEnforces(jail) and jail.retry_revision == null) return error.HistoryUnavailable;
                    live = if (self.jailEnforces(jail)) jail.owner_range.len else jail.active.len;
                    start = if (i == first and window.cursor_jail != null) self.keysetStart(jail, window.cursor_key.slice(), live) else 0;
                    // Why: With the page full, one more live row proves another page exists, so its payload is not read.
                    if (filled == storage.len and live > start) {
                        jails[i].count = live;
                        break;
                    }
                    ban = try self.captureBan(memory, jails[i].name);
                }
                const expired_count = try readExpired(reader, ban, now, &expired);
                const total = live + expired_count;
                if (start > total) return error.InvalidatedCursor;
                const take = @min(storage.len - filled, total - start);
                const items = storage[filled..][0..take];
                var k: usize = 0;
                var enforcing: bool = undefined;
                const live_take = @min(take, live -| start);
                {
                    self.mutex.lock();
                    defer self.mutex.unlock();
                    if (!self.fenceMatches(fence)) return error.InvalidatedCursor;
                    const jail = &self.jails[i];
                    enforcing = self.jailEnforces(jail);
                    if (enforcing) {
                        const range = jail.owner_range;
                        for (items[0..live_take], 0..) |*item, offset| {
                            const index = range.start + start + offset;
                            const owner = self.owner_active[index];
                            item.* = .{
                                .scope = try query_v1.projectScope(owner.scope.canonical),
                                .lease = if (owner.lease == .permanent) .permanent else .finite,
                                .deadline_us = if (owner.lease == .finite) owner.lease.finite else null,
                                .decision_id = owner.decision_id,
                                .confirmed = self.owner_confirmed[index] and known and owner.lease.live(now),
                                .ban_count = owner.ordinal,
                                .key = query_v1.ItemKey.init(&owner.key),
                                .origin = owner.origin,
                            };
                        }
                    } else for (items[0..live_take], jail.active[@min(start, live)..][0..live_take]) |*item, decision| {
                        const address: shared.IpAddress = switch (decision.subject) {
                            .v4 => |value| .{ .ipv4 = std.mem.readInt(u32, &value, .big) },
                            .v6 => |value| .{ .ipv6 = std.mem.readInt(u128, &value, .big) },
                        };
                        item.* = .{
                            .scope = try query_v1.projectScope(.{ .subject = inspection.canonical_scope.Subject.host(address) }),
                            .lease = if (decision.lease == .permanent) .permanent else .finite,
                            .deadline_us = if (decision.lease == .finite) decision.lease.finite else null,
                            .decision_id = null,
                            .confirmed = false,
                            .ban_count = decision.ordinal,
                            .key = decisionKey(decision.subject),
                            .origin = .detection,
                        };
                    }
                    k = live_take;
                }
                if (window.details and enforcing and live_take != 0) {
                    const installed = installation orelse return error.HistoryUnavailable;
                    var batch: usize = 0;
                    while (batch < live_take) {
                        const count = @min(owners.len - owner_count, live_take - batch);
                        {
                            self.mutex.lock();
                            defer self.mutex.unlock();
                            if (!self.fenceMatches(fence)) return error.InvalidatedCursor;
                            const range = self.jails[i].owner_range;
                            @memcpy(owners[owner_count..][0..count], self.owner_active[range.start + start + batch ..][0..count]);
                        }
                        for (items[batch..][0..count], owner_items[owner_count..][0..count]) |*item, *destination| destination.* = item;
                        owner_count += count;
                        batch += count;
                        if (owner_count == owners.len) {
                            try reader.retainedMatchesForOwnersTx(allocator, installed, now, owners[0..owner_count], lines[0..owner_count]);
                            for (owner_items[0..owner_count], lines[0..owner_count]) |item, line| item.match = line;
                            owner_count = 0;
                        }
                    }
                }
                while (k < items.len) : (k += 1) items[k] = try expiredScopeItem(expired[start + k - live], start + k - live);
                jails[i] = .{ .name = jails[i].name, .items = items, .count = total, .offset = start };
                filled += take;
                if (filled == storage.len and start + take < total) break;
            }
            if (owner_count != 0) {
                try reader.retainedMatchesForOwnersTx(allocator, installation orelse return error.HistoryUnavailable, now, owners[0..owner_count], lines[0..owner_count]);
                for (owner_items[0..owner_count], lines[0..owner_count]) |item, line| item.match = line;
            }
            try reader.commitTransaction();
            self.mutex.lock();
            defer self.mutex.unlock();
            if (!self.fenceMatches(fence)) return error.InvalidatedCursor;
            return .{ .jails = jails };
        }
        pub fn queryResponse(self: *Coordinator, a: std.mem.Allocator, body: []const u8, peer_class: query_v1.PeerClass) !shared.Response {
            return self.queryResponseInner(a, body, peer_class) catch |failure| switch (failure) {
                error.ResponseTooLarge => .{ .err = .{ .code = 413, .message = try a.dupe(u8, "response exceeds 1 MiB") } },
                error.InvalidatedCursor => .{ .err = .{ .code = 409, .message = try a.dupe(u8, "cursor expired or observation changed; restart pagination without a cursor") } },
                error.HistoryUnavailable => .{ .err = .{ .code = 503, .message = try a.dupe(u8, "query source is not available") } },
                else => return failure,
            };
        }
        fn queryResponseInner(self: *Coordinator, a: std.mem.Allocator, body: []const u8, peer_class: query_v1.PeerClass) !shared.Response {
            var arena_state = std.heap.ArenaAllocator.init(a);
            defer arena_state.deinit();
            const arena = arena_state.allocator();
            const requested_kind = query_v1.requestedKind(arena, body);
            if (peer_class == .monitor and requested_kind != null and query_v1.requiresAdmin(requested_kind.?)) {
                const result = try query_v1.handle(a, body, peer_class, [_]u8{0} ** 32, .{});
                return switch (result) {
                    .payload => |bytes| .{ .ok = .{ .payload = bytes } },
                    .failure => |failure| .{ .err = .{ .code = failure.code, .message = try a.dupe(u8, failure.message) } },
                };
            }
            if (requested_kind == .stats) {
                self.mutex.lock();
                var snapshot = self.published_stats;
                const generation = if (snapshot.available) self.stats_generation else self.published_generation;
                const now_ms = observationMs();
                const now_wall = self.observationWall();
                const observation = self.worker_observation.read(now_ms, now_wall);
                if (snapshot.available) {
                    const effect_ms = monotonic(self);
                    const known = self.knowledge(effect_ms) orelse .none;
                    snapshot.knowledge = @tagName(known);
                    snapshot.knowledge_age_ms = if (known == .none) null else self.knowledgeAgeMs(effect_ms);
                    if (known == .none) snapshot.last_observed_installed = null;
                    if (!observation.clock_uncertain) {
                        if (now_ms) |now| if (self.stats_published_ms) |then| {
                            if (now >= then) snapshot.snapshot_age_ms = now - then;
                        };
                        if (now_wall) |now| snapshot.uptime_seconds = @intCast(@max(0, @divTrunc(now -| self.start_us, 1_000_000)));
                    }
                } else {
                    snapshot.reason = if (self.backend_failure != null or self.suppress_enforcement) "backend_unavailable" else if (self.startup_backend != null) "not_published" else "log_only";
                    snapshot.backend = if (self.startup_backend) |backend| @tagName(backend) else null;
                }
                self.mutex.unlock();
                const result = try query_v1.handle(a, body, peer_class, generation, .{ .stats = snapshot });
                return switch (result) {
                    .payload => |bytes| .{ .ok = .{ .payload = bytes } },
                    .failure => |failure| .{ .err = .{ .code = failure.code, .message = try a.dupe(u8, failure.message) } },
                };
            }
            const firewall_request = requested_kind == .firewall;
            const requested_details = (requested_kind == .history or requested_kind == .scopes) and query_v1.requestedDetails(arena, body);
            const history_details = requested_kind == .history and requested_details;
            const capture_needed = requested_kind == .config or requested_kind == .scopes or history_details;
            var memory: ?CaptureMemory = if (capture_needed) try CaptureMemory.init(
                a,
                if (requested_kind == .config) config_capture_bytes else if (history_details) history_capture_bytes else if (requested_details) scopes_detail_capture_bytes else scopes_capture_bytes,
            ) else null;
            defer if (memory) |*value| value.deinit(a);
            var generation: [32]u8 = undefined;
            var config_view: ?query_v1.ConfigView = null;
            var scopes_view: ?query_v1.ScopesView = null;
            var firewall_source: ?query_v1.FirewallSource = null;
            var fence: ?CaptureFence = null;
            {
                self.mutex.lock();
                defer self.mutex.unlock();
                generation = self.published_generation;
                if (firewall_request or requested_kind == .scopes) fence = try self.captureFence();
                if (firewall_request) {
                    firewall_source = if (self.firewall_observation_cache) |cache| .{ .cache = .{
                        .ctx = cache,
                        .read = firewallRead,
                        .origin_ctx = self,
                        .origin = firewallOrigin,
                    } } else .{ .unavailable = self.firewall_observation_unavailable };
                } else if (requested_kind == .config) config_view = try self.copyConfig(&memory.?, peer_class == .monitor);
            }
            if (requested_kind == .scopes) scopes_view = try self.copyScopes(&memory.?, body, arena, &fence.?);
            var status_query = StatusQuery{ .coordinator = self, .redact = peer_class == .monitor };
            var history_query = HistoryQuery{ .coordinator = self, .generation = generation, .details = history_details, .memory = if (history_details) &memory.? else null };
            const result = try query_v1.handle(
                a,
                body,
                peer_class,
                generation,
                .{
                    .status = .{ .ctx = &status_query, .stamped = true, .func = statusCallback },
                    .health = .{ .ctx = self, .func = healthCallback },
                    .config = config_view,
                    .scopes = scopes_view,
                    .history = .{ .ctx = &history_query, .read = historyRead },
                    .firewall = firewall_source,
                    .ignore = .{ .ctx = self, .render = ignoreRender },
                    .continuity = .{ .ctx = self, .render = continuityRender },
                },
            );
            if ((requested_kind == .ignore or requested_kind == .health or history_details) and !self.unchanged(generation)) {
                result.deinit(a);
                return error.InvalidatedCursor;
            }
            if (firewall_request) {
                self.mutex.lock();
                const coherent = self.fenceMatches(&fence.?);
                self.mutex.unlock();
                if (!coherent) {
                    result.deinit(a);
                    return error.InvalidatedCursor;
                }
            }
            return switch (result) {
                .payload => |bytes| .{ .ok = .{ .payload = bytes } },
                .failure => |failure| .{ .err = .{ .code = failure.code, .message = try a.dupe(u8, failure.message) } },
            };
        }
        pub fn decisionKey(subject: detection.Subject) query_v1.ItemKey {
            var bytes: [17]u8 = undefined;
            return switch (subject) {
                .v4 => |v| blk: {
                    bytes[0] = 4;
                    @memcpy(bytes[1..5], &v);
                    break :blk query_v1.ItemKey.init(bytes[0..5]);
                },
                .v6 => |v| blk: {
                    bytes[0] = 6;
                    @memcpy(bytes[1..17], &v);
                    break :blk query_v1.ItemKey.init(bytes[0..17]);
                },
            };
        }
        pub fn keysetStart(self: *const Coordinator, jail: *const Jail, cursor: []const u8, live: usize) usize {
            if (expiredIndex(cursor)) |index| return live + index + 1;
            var low: usize = 0;
            var high = live;
            while (low < high) {
                const middle = low + (high - low) / 2;
                const key = if (self.jailEnforces(jail)) query_v1.ItemKey.init(&self.owner_active[jail.owner_range.start + middle].key) else decisionKey(jail.active[middle].subject);
                if (std.mem.order(u8, key.slice(), cursor) == .gt) high = middle else low = middle + 1;
            }
            return low;
        }
    };
}

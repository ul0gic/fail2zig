// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const shared = @import("shared");
const config = @import("config/native.zig");
const detection = @import("core/native_detection_record.zig");
const effect = @import("core/native_effect.zig");
const effect_runtime = @import("runtime/native_effect_runtime.zig");
const firewall_observation = effect_runtime.observation;
const history = @import("core/native_effect_history.zig");
const retry = @import("core/native_retry.zig");
const inspection = @import("firewall/inspection.zig");
const durable = @import("core/record_store.zig");
const pipeline = @import("core/record_pipeline.zig");
const files = @import("core/durable_file_source.zig");
const ignore_set = @import("core/native_ignore_set.zig");
const custom_ignore = @import("core/native_ignore.zig");
const dns = @import("core/native_dns.zig");
const Cidr = @import("core/state.zig").Cidr;
const native_banip = @import("config/native_banip.zig");
const RuntimeIgnoreEntry = @import("store/ignore_entries.zig").RuntimeIgnoreEntry;
const build_options = @import("build_options");
const version = build_options.version;
const diag_mod = @import("core/diag.zig");
const query_v1 = @import("net/query_v1.zig");
const readiness = @import("core/readiness.zig");
const metrics_mod = @import("core/metrics.zig");
const resource = @import("runtime/native_resource_budget.zig");
const http = @import("net/http.zig");
const ban_origin = @import("core/ban_origin.zig");
const daemon = @import("native_daemon.zig");
const max_jails = daemon.max_jails;
const max_sources_per_jail = daemon.max_sources_per_jail;
const Jail = daemon.Jail;
const SourceStatus = daemon.SourceStatus;

const LossJson = struct { sequence: u64, wall_us: i64, reason: []const u8, inode: u64, committed_offset: u64, observed_size: ?u64 };
const SourceJson = struct {
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

const legacy_allowance = shared.protocol.max_payload_size - 16;
const legacy_item_bound = (legacy_allowance - 1) / 115;
const LegacyBanItem = struct {
    scope: inspection.CanonicalScope,
    jail_slot: u8,
    origin: shared.types.Origin,
    expiry_us: ?i64,
    permanent: bool,
    ordinal: u64,
    confirmed: bool,
    expired: bool,
};
const BanCapture = struct { name: []const u8, entries: []const shared.types.TimedEntry };
// Captures use exact fixed backing allocations; outputs reserve their admitted byte cap.
const capture_padding = (max_jails * 12 + 4) * (@alignOf(u128) - 1);
const status_capture_bytes = query_v1.max_response_bytes + max_jails * daemon.max_source_status_per_jail * @sizeOf(SourceJson) + capture_padding;
const legacy_capture_bytes = max_jails * 64 + (legacy_item_bound + 1) * @sizeOf(LegacyBanItem) + max_jails * native_banip.max_banip_entries * @sizeOf(shared.types.TimedEntry) + capture_padding;
// Even an empty JSON string needs two quote bytes: no fitting config can exceed this slot bound.
const config_capture_bytes = query_v1.max_response_bytes + (query_v1.max_response_bytes / 2) * @sizeOf([]const u8) + max_jails * @sizeOf(query_v1.JailConfig) + capture_padding;
const match_capture_bytes = query_v1.max_items_per_page * retry.max_evidence_text_bytes;
const history_capture_bytes = match_capture_bytes + query_v1.max_items_per_page * 64 + capture_padding;
const scopes_capture_bytes = max_jails * 64 + max_jails * @sizeOf(query_v1.JailScopes) + query_v1.max_items_per_page * @sizeOf(query_v1.ScopeItem) + max_jails * native_banip.max_banip_entries * @sizeOf(shared.types.TimedEntry) + capture_padding;
const scopes_detail_capture_bytes = scopes_capture_bytes + match_capture_bytes;
const ignore_string_bytes = max_jails * (custom_ignore.max_entries * 254 + 4096 + 64) + custom_ignore.max_hostnames * 254;
const ignore_builtin_workspace: usize = custom_ignore.max_entries * (3 * @sizeOf([]const u8) + 3 * @sizeOf(?i64) + @sizeOf(shared.types.TimedEntry)) +
    2 * (2 * ignore_set.max_entries_per_part + shared.self_addresses.max_self_addresses) * @sizeOf(ignore_set.Item) + @sizeOf(ignore_set.EffectiveIgnore);
const ignore_custom_workspace: usize = custom_ignore.max_entries * (@sizeOf(ignore_set.Item) + @sizeOf([]const u8)) + custom_ignore.max_hostnames * @sizeOf([]const u8);
const ignore_capture_bytes = ignore_string_bytes + max_jails * @as(usize, @max(ignore_builtin_workspace, ignore_custom_workspace)) +
    shared.self_addresses.max_self_addresses * @sizeOf(shared.IpAddress) + max_jails * @sizeOf(IgnoreProjection) + capture_padding;
const capture_bytes = @max(@max(status_capture_bytes, legacy_capture_bytes), @max(config_capture_bytes, @max(history_capture_bytes, @max(scopes_detail_capture_bytes, ignore_capture_bytes))));

pub fn queryCaptureCost() resource.Cost {
    // A bounded response can overlap its final owned copy; captures use one exact backing allocation.
    const expiry_scratch = native_banip.max_banip_entries * (@sizeOf(ExpiredBan) + @sizeOf(?i64));
    const match_scratch = history.max_page * (@sizeOf(durable.Store.OperatorOwner) + 2 * @sizeOf(history.Event) + @sizeOf(?[]u8) + @sizeOf(*query_v1.ScopeItem)) + query_v1.max_items_per_page * @sizeOf(query_v1.HistoryEvent);
    const capture_stack = @sizeOf(custom_ignore.Entry) + @sizeOf(dns.Name) + match_scratch + expiry_scratch + config.max_configured_jails * @sizeOf(detection.Name) + max_jails * @sizeOf(BanCapture) + (max_jails + 1) * @sizeOf(IgnoreJail) + @sizeOf(metrics_mod.Snapshot);
    return .{ .bytes = capture_bytes + 2 * query_v1.max_response_bytes + capture_stack, .allocations = 6, .fds = 0 };
}
const ExpiredBan = struct { entry: shared.types.IgnoreEntry, decision_id: [32]u8, expires_us: i64 };
const IgnoreJail = struct {
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
const IgnoreProjection = struct { items: []ignore_set.Item, hostnames: [][]const u8 };
const CaptureMemory = struct {
    backing: []u8,
    fixed: std.heap.FixedBufferAllocator,
    strings: usize = 0,
    string_limit: usize = query_v1.max_response_bytes,
    fn init(a: std.mem.Allocator, capacity: usize) !CaptureMemory {
        const backing = try a.alloc(u8, capacity);
        return .{ .backing = backing, .fixed = std.heap.FixedBufferAllocator.init(backing) };
    }
    fn deinit(self: *CaptureMemory, a: std.mem.Allocator) void {
        a.free(self.backing);
    }
    fn text(self: *CaptureMemory, value: []const u8) ![]const u8 {
        if (value.len > self.string_limit - self.strings) return error.ResponseTooLarge;
        self.strings += value.len;
        return self.fixed.allocator().dupe(u8, value);
    }
    fn texts(self: *CaptureMemory, values: []const []const u8) ![]const []const u8 {
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
            var result = CaptureFence{ .generation = self.published_generation, .epoch = self.owner_read_epoch, .mark = self.published_owners_mark, .health_generation = self.published_health.generation, .pending = self.owner_publication_pending, .count = self.jails.len };
            for (self.jails, 0..) |jail, i| {
                result.names[i] = try detection.Name.init(jail.name);
                result.retry_revisions[i] = if (self.jailEnforces(&jail)) null else jail.retry_revision;
                result.active_counts[i] = if (self.jailEnforces(&jail)) 0 else jail.active.len;
            }
            return result;
        }
        fn fenceMatches(self: *const Coordinator, fence: *const CaptureFence) bool {
            if (!std.mem.eql(u8, &fence.generation, &self.published_generation) or fence.epoch != self.owner_read_epoch or !std.meta.eql(fence.mark, self.published_owners_mark) or fence.health_generation != self.published_health.generation or fence.pending != self.owner_publication_pending or fence.count != self.jails.len) return false;
            for (self.jails, fence.names[0..fence.count], 0..) |jail, name, i| {
                if (!std.mem.eql(u8, jail.name, name.slice())) return false;
                if (!self.jailEnforces(&jail) and (jail.retry_revision != fence.retry_revisions[i] or jail.active.len != fence.active_counts[i])) return false;
            }
            return true;
        }
        const configuredIgnoreDeadlines = Coordinator.configuredIgnoreDeadlines;
        const findConfigJail = Coordinator.findConfigJail;
        const formatListSubject = Coordinator.formatListSubject;
        const ignoreCell = Coordinator.ignoreCell;
        const ignoreSourceText = Coordinator.ignoreSourceText;
        const jailPaused = Coordinator.jailPaused;
        const monotonic = Coordinator.monotonic;
        const observationMs = Coordinator.observationMs;
        const observationSound = Coordinator.observationSound;
        const quiet_interval_ms = Coordinator.quiet_interval_ms;
        const sessionProcessor = Coordinator.sessionProcessor;
        const redacted_text = "<redacted>";
        pub fn sourceStatusOrder(_: void, a: *const SourceStatus, b: *const SourceStatus) bool {
            return switch (std.mem.order(u8, a.jail, b.jail)) {
                .lt => true,
                .gt => false,
                .eq => std.mem.lessThan(u8, a.path orelse "", b.path orelse ""),
            };
        }
        pub fn lossJson(event: files.LossEvent) LossJson {
            return .{ .sequence = event.sequence, .wall_us = event.wall_us, .reason = @tagName(event.reason), .inode = event.inode, .committed_offset = event.committed_offset, .observed_size = event.observed_size };
        }
        fn captureSources(self: *const Coordinator, memory: *CaptureMemory, redact: bool) ![]SourceJson {
            var count: usize = 0;
            for (self.jails) |jail| count += jail.source_status.len;
            const result = try memory.fixed.allocator().alloc(SourceJson, count);
            var offset: usize = 0;
            for (self.jails) |jail| for (jail.source_status) |entry| {
                result[offset] = .{
                    .jail = try memory.text(entry.jail),
                    .kind = @tagName(entry.kind),
                    .path = if (entry.path) |path| (if (redact) redacted_text else try memory.text(path)) else null,
                    .on_truncation = if (entry.on_truncation) |policy| @tagName(policy) else null,
                    .state = @tagName(entry.state),
                    .cause = if (entry.cause) |cause| try memory.text(cause) else null,
                    .inode = entry.inode,
                    .committed_offset = entry.committed_offset,
                    .observed_size = entry.observed_size,
                    .repair = if (entry.repair) |repair| (if (redact) redacted_text else try memory.text(repair)) else null,
                    .loss_events = entry.loss_events,
                    .last_loss = if (entry.last_loss) |event| lossJson(event) else null,
                };
                offset += 1;
            };
            return result;
        }
        fn renderSources(writer: anytype, sources: []SourceJson) !void {
            std.sort.pdq(SourceJson, sources, {}, struct {
                fn less(_: void, x: SourceJson, y: SourceJson) bool {
                    return switch (std.mem.order(u8, x.jail, y.jail)) {
                        .lt => true,
                        .gt => false,
                        .eq => std.mem.lessThan(u8, x.path orelse "", y.path orelse ""),
                    };
                }
            }.less);
            try std.json.stringify(sources, .{}, writer);
        }
        fn rangeConfirmed(self: *const Coordinator, jail: *const Jail, now: i64, known: bool) u32 {
            if (!known or !self.jailEnforces(jail)) return 0;
            const range = jail.owner_range;
            var count: u32 = 0;
            for (self.owner_active[range.start..][0..range.len], self.owner_confirmed[range.start..][0..range.len]) |owner, confirmed| {
                if (confirmed and owner.lease.live(now)) count += 1;
            }
            return count;
        }
        pub fn statusPayload(self: *Coordinator, out: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator, redact: bool) !void {
            return self.statusPayloadLimit(out, a, redact, legacy_allowance);
        }
        pub fn statusPayloadLimit(self: *Coordinator, out: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator, redact: bool, limit: usize) !void {
            var memory = try CaptureMemory.init(a, status_capture_bytes);
            defer memory.deinit(a);
            var generation_hex: [64]u8 = undefined;
            const captured = blk: {
                self.mutex.lock();
                defer self.mutex.unlock();
                const gate = self.published_health;
                const sampled_wall = self.observationWall();
                const sampled_ms = observationMs();
                const effect_ms = monotonic(self);
                const observation = self.worker_observation.read(sampled_ms, sampled_wall);
                var healthy = gate.phase == .healthy and observationSound(observation);
                var decisions: u64 = 0;
                var installed: u32 = 0;
                var unhealthy_sources: u32 = 0;
                var paused_sources: u32 = 0;
                var missing_sources: u32 = 0;
                var missing_known = true;
                var unpaused_unhealthy: u32 = 0;
                var blocked_source: ?[]const u8 = null;
                const now = sampled_wall orelse self.start_us;
                for (self.jails) |jail| {
                    if (jail.plan == .file and (!jail.source_signature.built or !jail.source_signature.presence_known)) missing_known = false;
                    healthy = healthy and jail.healthy;
                    if (!jail.healthy) unhealthy_sources += 1;
                    if (!jail.healthy and !jailPaused(&jail)) unpaused_unhealthy += 1;
                    if (!jail.healthy and blocked_source == null) if (jail.source_error) |cause| if (pipeline.Pipeline.commitBlocked(cause)) {
                        blocked_source = @errorName(cause);
                    };
                    for (jail.source_status) |entry| {
                        paused_sources += @intFromBool(entry.state == .paused);
                        missing_sources += @intFromBool(entry.state == .missing);
                    }
                    decisions +|= jail.summary.decisions;
                    installed +|= self.rangeConfirmed(&jail, now, self.confirmationKnown(effect_ms));
                }
                if (self.published_effects) |effects| healthy = healthy and !(effects.uncertain and !self.published_view.transient_uncertain);
                if (self.backend_failure != null) healthy = false;
                const known = self.knowledge(effect_ms);
                const withdrawn = if (self.published_effects) |effects| effects.withdrawn else false;
                const protection: []const u8 = if (!healthy or withdrawn) "degraded" else if (self.published_effects == null) "log-only" else if (known.? == .none) "unknown" else if (known.? == .stale or self.overBlocking()) "degraded" else "active";
                const active_bans: ?u32 = if (known) |k| (if (k == .none) null else self.published_view.installed_live) else installed;
                const knowledge_cause: ?[]const u8 = if (known) |k| switch (k) {
                    .stale => "ReadbackStale",
                    .none => if (self.published_effects.?.cause == null) "ReadbackPending" else null,
                    .fresh => null,
                } else null;
                generation_hex = std.fmt.bytesToHex(self.published_generation, .lower);
                const effect_diagnostic = if (self.published_effects) |effects| effects.diagnostic else null;
                const none_cause: []const u8 = if (paused_sources != 0 and unpaused_unhealthy == 0) "SourcePaused" else blocked_source orelse "none";
                break :blk .{ .payload = .{ .version = version, .runtime = "native", .generation = &generation_hex, .mutation_revision = self.published_revision, .state = protection, .protection = protection, .protection_cause = if (self.backend_failure) |failure| @as(?[]const u8, @errorName(failure)) else null, .active_bans = active_bans, .total_bans = self.published_confirmations, .knowledge = if (known) |k| @as(?[]const u8, @tagName(k)) else null, .confirmed_at_us = if (known != null and known.? != .none) self.published_view.readback_wall_us else null, .knowledge_age_ms = if (known != null and known.? != .none) self.knowledgeAgeMs(effect_ms) else null, .pending_bans = if (known != null) @as(?u64, self.published_view.pending) else null, .oldest_pending_ms = if (known != null) ageMs(now, self.published_view.oldest_pending_us) else null, .overdue_removals = if (known != null) @as(?u64, self.published_view.overdue_blocking) else null, .oldest_overdue_ms = if (known != null) ageMs(now, self.published_view.oldest_overdue_blocking_us) else null, .overdue_bookkeeping = if (known != null) @as(?u64, self.published_view.overdue -| self.published_view.overdue_blocking) else null, .dump_interrupted = if (known != null) @as(?u64, self.published_view.dump_interrupted) else null, .storage = @tagName(gate.phase), .cause = if (gate.phase == .intervention and gate.last_failure != null) @errorName(gate.last_failure.?.cause) else if (observation.clock_uncertain) "ClockUncertain" else if (observation.stalled) "WorkerStalled" else if (withdrawn) "FirewallWithdrawn" else if (known != null and known.? == .none and knowledge_cause != null) knowledge_cause.? else if (self.overBlocking()) "EffectRemovalOverdue" else if (knowledge_cause) |cause| cause else if (gate.last_failure) |failure| @errorName(failure.cause) else if (self.published_effects) |effects| if (effects.cause) |cause| @errorName(cause) else none_cause else if (self.backend_failure) |failure| @errorName(failure) else none_cause, .sqlite_code = if (gate.last_failure) |failure| failure.diagnostics.sqlite_code else null, .next_retry_ms = gate.next_retry_ms, .committed_records = gate.committed_records, .decisions_total = decisions, .jails_active = self.jails.len, .unhealthy_sources = unhealthy_sources, .missing_sources = if (missing_known) @as(?u32, missing_sources) else null, .backend = self.published_backend, .effect_backend = if (effect_diagnostic) |detail| @as(?[]const u8, @tagName(detail.backend)) else null, .effect_stage = if (effect_diagnostic) |detail| @as(?[]const u8, @tagName(detail.stage)) else null, .effect_cause = if (effect_diagnostic) |detail| @as(?[]const u8, @errorName(detail.cause)) else null, .effect_mutation = if (effect_diagnostic) |detail| @as(?[]const u8, @tagName(detail.mutation)) else null, .effects_uncertain = observation.expiry_uncertain or (if (self.published_effects) |effects| effects.uncertain else false), .overdue_effects = if (self.published_effects) |effects| effects.overdue else 0, .worker_busy = observation.busy, .worker_stalled = observation.stalled, .worker_busy_age_ms = observation.busy_age_ms, .worker_heartbeat_age_ms = observation.heartbeat_age_ms, .clock_uncertain = observation.clock_uncertain, .expiry_overdue = observation.expiry_overdue, .expiry_uncertain = observation.expiry_uncertain, .next_committed_expiry_us = observation.next_committed_expiry_us, .memory_admission_bytes = self.resources.snapshot().used_bytes, .uptime_seconds = if (observation.clock_uncertain) @as(?u64, null) else @as(u64, @intCast(@max(0, @divTrunc(now -| self.start_us, 1_000_000)))) }, .paused = paused_sources, .footprint = self.published_footprint, .pool = self.published_pool, .sources = try self.captureSources(&memory, redact) };
            };
            var sink = query_v1.ByteSink{ .out = out, .allocator = a, .limit = limit };
            const writer = sink.writer();
            const payload_start = out.items.len;
            try std.json.stringify(captured.payload, .{ .emit_null_optional_fields = false }, writer);
            if (out.items.len == payload_start or out.items[out.items.len - 1] != '}') return error.InvalidStatusPayload;
            out.items.len -= 1;
            try writer.print(",\"paused_sources\":{d}", .{captured.paused});
            if (captured.footprint) |footprint| try writer.print(",\"state_file_bytes\":{d},\"state_file_pages\":{d},\"state_file_max_pages\":{d}", .{ footprint.bytes, footprint.pages, footprint.max_pages });
            try writer.print(",\"pool_sample_available\":{},\"pool_sample_pending\":{},\"pool_sample_as_of_us\":", .{ captured.pool.sample != null, captured.pool.pending });
            try std.json.stringify(if (captured.pool.sample) |sample| @as(?i64, sample.as_of_us) else null, .{}, writer);
            if (captured.pool.sample) |sample| {
                const pool = sample.occupancy;
                try writer.print(",\"pool_tracked\":{d},\"pool_banned\":{d},\"pool_tracking_limit\":{d},\"pool_ban_limit\":{d}", .{ pool.tracked, pool.banned, pool.tracking_limit, pool.ban_limit });
            }
            try writer.writeAll(",\"sources\":");
            try renderSources(writer, captured.sources);
            try writer.print(",\"schema_version\":{d}}}", .{query_v1.schema_version});
        }
        pub fn knowledgeAgeMs(self: *const Coordinator, now_ms: ?u64) ?u64 {
            const readback = self.published_view.readback_ns orelse return null;
            const now = now_ms orelse return null;
            return ((now *| std.time.ns_per_ms) -| readback) / std.time.ns_per_ms;
        }
        pub fn ageMs(now_us: i64, then_us: ?i64) ?u64 {
            const then = then_us orelse return null;
            return @intCast(@max(0, @divTrunc(now_us -| then, 1000)));
        }
        fn captureBan(self: *const Coordinator, memory: *CaptureMemory, name: []const u8) !BanCapture {
            const jail_cfg = findConfigJail(self.live_cfg, name) orelse return .{ .name = name, .entries = &.{} };
            const literals = jail_cfg.banip orelse self.live_cfg.defaults.banip;
            const entries = try memory.fixed.allocator().alloc(shared.types.TimedEntry, literals.len);
            for (literals, entries) |literal, *entry| entry.* = try shared.types.TimedEntry.parse(literal, null);
            return .{ .name = name, .entries = entries };
        }
        fn readExpired(reader: *durable.Store, ban: BanCapture, now_us: i64, output: []ExpiredBan) !usize {
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
        fn beginConfigRead(reader: *durable.Store, generation: [32]u8) !void {
            try reader.beginRead();
            errdefer reader.rollback();
            const head = try reader.latestConfigGeneration() orelse return error.InvalidatedCursor;
            if (!head.published or !std.mem.eql(u8, &head.generation, &generation)) return error.InvalidatedCursor;
        }
        fn unchanged(self: *Coordinator, generation: [32]u8) bool {
            self.mutex.lock();
            defer self.mutex.unlock();
            return std.mem.eql(u8, &generation, &self.published_generation);
        }
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
                            try appendLegacy(items, &count, .{ .scope = owner.scope.canonical, .jail_slot = @intCast(slot), .origin = owner.origin, .expiry_us = if (owner.lease == .finite) owner.lease.finite else null, .permanent = owner.lease == .permanent, .ordinal = owner.ordinal, .confirmed = confirmed and known, .expired = false });
                        }
                    } else for (jail.active) |decision| {
                        if (!observation.clock_uncertain and sampled_wall != null and !decision.lease.live(now)) continue;
                        const address: shared.IpAddress = switch (decision.subject) {
                            .v4 => |value| .{ .ipv4 = std.mem.readInt(u32, &value, .big) },
                            .v6 => |value| .{ .ipv6 = std.mem.readInt(u128, &value, .big) },
                        };
                        try appendLegacy(items, &count, .{ .scope = .{ .subject = inspection.canonical_scope.Subject.host(address) }, .jail_slot = @intCast(slot), .origin = .detection, .expiry_us = if (decision.lease == .finite) decision.lease.finite else null, .permanent = decision.lease == .permanent, .ordinal = decision.ordinal, .confirmed = false, .expired = false });
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
                        const subject = if (entry.entry.prefix == bits) inspection.canonical_scope.Subject.host(address) else try inspection.canonical_scope.Subject.network(address, entry.entry.prefix);
                        try appendLegacy(items, &count, .{ .scope = .{ .subject = subject }, .jail_slot = @intCast(slot), .origin = .config, .expiry_us = entry.expires_us, .permanent = false, .ordinal = 0, .confirmed = false, .expired = true });
                    }
                }
                try reader.commitTransaction();
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
            return .{ .scope = try query_v1.projectScope(.{ .subject = subject }), .lease = .finite, .deadline_us = expired.expires_us, .decision_id = expired.decision_id, .confirmed = false, .ban_count = 0, .key = expiredKey(index), .origin = .config, .expired = true };
        }
        pub fn metrics(ctx: ?*anyopaque, out: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator) !void {
            const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
            self.mutex.lock();
            const captured = blk: {
                defer self.mutex.unlock();
                const observation = self.observedWorker();
                var snapshot = self.metrics_state.snapshot();
                snapshot.native = .{ .storage_healthy = self.published_health.phase == .healthy and observationSound(observation), .committed_records = self.published_health.committed_records, .worker_stalled = observation.stalled, .worker_busy = observation.busy, .worker_heartbeat_age_ms = observation.heartbeat_age_ms, .worker_busy_age_ms = observation.busy_age_ms, .clock_uncertain = observation.clock_uncertain, .expiry_overdue = observation.expiry_overdue, .expiry_uncertain = observation.expiry_uncertain };
                snapshot.pool_sample_available = self.published_pool.sample != null;
                snapshot.pool_sample_pending = self.published_pool.pending;
                snapshot.pool_sample_as_of_us = if (self.published_pool.sample) |sample| sample.as_of_us else null;
                if (self.published_pool.sample) |sample| {
                    const pool = sample.occupancy;
                    snapshot.pool_tracked = pool.tracked;
                    snapshot.pool_banned = pool.banned;
                    snapshot.pool_tracking_limit = pool.tracking_limit;
                    snapshot.pool_ban_limit = pool.ban_limit;
                }
                const now = self.observationWall() orelse self.start_us;
                const effect_ms = monotonic(self);
                var live: usize = 0;
                for (snapshot.perJail()) |series| {
                    const jail = self.findJail(series.name()) orelse continue;
                    var kept = series;
                    kept.active_bans = self.rangeConfirmed(jail, now, self.confirmationKnown(effect_ms));
                    kept.source_state = sourceState(jail);
                    snapshot.jails[live] = kept;
                    live += 1;
                }
                snapshot.jails_len = live;
                break :blk .{ .snapshot = snapshot, .clock = if (comptime build_options.diag) self.clock.snapshot() else {} };
            };
            var sink = query_v1.ByteSink{ .out = out, .allocator = a, .limit = http.max_response_bytes };
            const writer = sink.writer();
            try metrics_mod.renderPrometheus(&captured.snapshot, writer);
            if (comptime build_options.diag) try diag_mod.writeMetrics(writer);
            if (comptime build_options.diag) {
                const sample = captured.clock;
                try writer.print("f2z_diag_clock_rate {d}\nf2z_diag_clock_wall_us {d}\nf2z_diag_clock_regressions {d}\n", .{ sample.rate, sample.wall_us, sample.regressions });
            }
        }
        pub fn sourceState(jail: *const Jail) u8 {
            if (jail.source_error) |cause| if (pipeline.Pipeline.commitBlocked(cause)) return 3;
            if (jail.source_missing) return 2;
            if (jailPaused(jail) or !jail.healthy) return 1;
            return 0;
        }
        pub fn healthView(ctx: ?*anyopaque, out: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator) !void {
            const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
            const report = self.readinessReport();
            var sink = query_v1.ByteSink{ .out = out, .allocator = a, .limit = http.max_response_bytes };
            try readiness.writeJson(report, sink.writer());
        }
        const StatusQuery = struct { coordinator: *Coordinator, redact: bool };
        pub fn statusCallback(ctx: ?*anyopaque, a: std.mem.Allocator, out: *std.ArrayList(u8)) anyerror!void {
            const query: *StatusQuery = @ptrCast(@alignCast(ctx.?));
            var unmanaged: std.ArrayListUnmanaged(u8) = .{};
            defer unmanaged.deinit(a);
            try query.coordinator.statusPayload(&unmanaged, a, query.redact);
            if (unmanaged.items.len > query_v1.max_response_bytes) return error.ResponseTooLarge;
            try out.ensureTotalCapacityPrecise(query_v1.max_response_bytes);
            out.appendSliceAssumeCapacity(unmanaged.items);
        }
        pub fn healthCallback(ctx: ?*anyopaque, a: std.mem.Allocator, out: *std.ArrayList(u8)) anyerror!void {
            var unmanaged: std.ArrayListUnmanaged(u8) = .{};
            defer unmanaged.deinit(a);
            try healthView(ctx, &unmanaged, a);
            if (unmanaged.items.len > query_v1.max_response_bytes) return error.ResponseTooLarge;
            try out.ensureTotalCapacityPrecise(query_v1.max_response_bytes);
            out.appendSliceAssumeCapacity(unmanaged.items);
        }
        pub fn continuityRender(ctx: ?*anyopaque, arena: std.mem.Allocator, cursor: ?u64, limit: u16, redact: bool, out: *query_v1.JsonStream) anyerror!void {
            const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
            const reader = if (self.history_reader) |*value| value else return error.HistoryUnavailable;
            const events = try arena.alloc(files.LossEvent, limit);
            const count = try reader.continuityEvents(null, cursor, events, arena);
            try out.objectField("items");
            try out.beginArray();
            for (events[0..count]) |event| {
                try out.beginObject();
                try out.objectField("sequence");
                try out.write(event.sequence);
                try out.objectField("jail");
                try out.write(event.jail);
                try out.objectField("path");
                try out.write(if (redact) redacted_text else event.path);
                try out.objectField("wall_us");
                try out.write(event.wall_us);
                try out.objectField("reason");
                try out.write(@tagName(event.reason));
                try out.objectField("inode");
                try out.write(event.inode);
                try out.objectField("committed_offset");
                try out.write(event.committed_offset);
                try out.objectField("observed_size");
                try out.write(event.observed_size);
                try out.endObject();
            }
            try out.endArray();
            try out.objectField("next_cursor");
            if (count == limit and count != 0) {
                var buffer: [20]u8 = undefined;
                try out.write(try std.fmt.bufPrint(&buffer, "{d}", .{events[count - 1].sequence}));
            } else try out.write(null);
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
        pub fn jailNameLess(self: *const Coordinator, a: usize, b: usize) bool {
            return std.mem.lessThan(u8, self.jails[a].name, self.jails[b].name);
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
        // buildIgnore stores the configured prefix before file values and tagged self entries.
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
            return .{ .name = try memory.text(name), .enabled = if (runtime) |jail| jail.admin_enabled else false, .ignore_file = if (cfg) |value| (if (value.ignore_file) |path| try memory.text(path) else null) else null, .items = items, .hostnames = hostnames, .custom = custom, .literals = if (items == null) try memory.texts(literals) else &.{}, .ignoretime_s = if (resolved) |value| value.ignoretime_s else null, .ignoreself = resolved != null and resolved.?.ignoreself };
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
                const items: []const ignore_set.Item = if (jail.items) |values| values else try configuredIgnoreItems(memory.fixed.allocator(), reader, jail.name, jail.literals, if (fallback) filtered[0..filtered_count] else &.{}, if (fallback) &.{} else own, jail.ignoretime_s, jail.ignoreself, now, &hostnames);
                view.* = .{ .items = items, .hostnames = hostnames };
            }
            try reader.commitTransaction();
            if (!self.unchanged(generation)) return error.InvalidatedCursor;
            try out.objectField("limit");
            try out.write(ignore_set.distinct_bound);
            try out.objectField("jails");
            try out.beginArray();
            for (captures[0..count], built) |jail, view| try writeIgnoreJail(out, jail.name, jail.enabled, jail.ignore_file, view.items, view.hostnames, if (jail.custom) custom_ignore.max_entries else null, redact, now);
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
        const HistoryQuery = struct { coordinator: *Coordinator, generation: [32]u8, details: bool, memory: ?*CaptureMemory };
        pub fn historyRead(ctx: ?*anyopaque, jail: ?[]const u8, after_sequence: u64, limit: u16, out: *std.ArrayList(query_v1.HistoryEvent)) anyerror!query_v1.HistoryRead {
            const query: *HistoryQuery = @ptrCast(@alignCast(ctx.?));
            const self = query.coordinator;
            if (!query.details) return historyReadPlain(self, jail, after_sequence, limit, out);
            const memory = query.memory orelse return error.HistoryUnavailable;
            const reader = if (self.history_reader) |*value| value else return error.HistoryUnavailable;
            try beginConfigRead(reader, query.generation);
            errdefer reader.rollback();
            const installation = try reader.readInstallation();
            var after = after_sequence;
            var more = false;
            if (installation) |installed| {
                var events: [history.max_page]history.Event = undefined;
                var selected: [history.max_page]history.Event = undefined;
                var count: usize = 0;
                var appended: usize = 0;
                var pages: usize = 0;
                while (appended + count < limit and pages < history_scan_pages) : (pages += 1) {
                    const page = try reader.confirmedEffectPageTx(installed, after, null, &events);
                    more = page.more;
                    if (page.count == 0) break;
                    for (events[0..page.count]) |event| {
                        if (appended + count == limit) break;
                        after = event.sequence;
                        if (jail) |wanted| if (!std.mem.eql(u8, wanted, event.jail.slice())) continue;
                        selected[count] = event;
                        count += 1;
                        if (count == selected.len) {
                            try appendHistoryMatches(memory, reader, installed, selected[0..count], out);
                            appended += count;
                            count = 0;
                        }
                    }
                    more = after < page.token.head_sequence;
                    if (!more) break;
                }
                if (count != 0) try appendHistoryMatches(memory, reader, installed, selected[0..count], out);
            }
            try reader.commitTransaction();
            if (!self.unchanged(query.generation)) return error.InvalidatedCursor;
            return .{ .more = more, .resume_after = after };
        }
        fn appendHistoryMatches(memory: *CaptureMemory, reader: *durable.Store, installation: effect.Installation, events: []const history.Event, out: *std.ArrayList(query_v1.HistoryEvent)) !void {
            var lines: [history.max_page]?[]u8 = undefined;
            try reader.retainedMatchesForEventsTx(memory.fixed.allocator(), installation, events, lines[0..events.len]);
            for (events, lines[0..events.len]) |event, line| {
                try out.append(.{ .sequence = event.sequence, .event_id = event.event_id, .jail = try memory.text(event.jail.slice()), .decision_id = event.decision_id, .confirmed_us = event.confirmed_us, .scope = try query_v1.projectScope(event.scope.canonical), .native_retry = event.native_retry, .origin = event.origin, .match = line });
            }
        }
        const history_scan_pages = 16;
        fn historyReadPlain(ctx: ?*anyopaque, jail: ?[]const u8, after_sequence: u64, limit: u16, out: *std.ArrayList(query_v1.HistoryEvent)) anyerror!query_v1.HistoryRead {
            const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
            const reader = if (self.history_reader) |*value| value else return error.HistoryUnavailable;
            const installation = try reader.readInstallation() orelse return .{ .more = false, .resume_after = after_sequence };
            var events: [history.max_page]history.Event = undefined;
            var after = after_sequence;
            var appended: usize = 0;
            var pages: usize = 0;
            while (appended < limit and pages < history_scan_pages) : (pages += 1) {
                const page = try reader.confirmedEffectPage(installation, after, null, &events);
                if (page.count == 0) return .{ .more = false, .resume_after = after };
                for (events[0..page.count]) |event| {
                    if (appended == limit) return .{ .more = true, .resume_after = after };
                    after = event.sequence;
                    if (jail) |wanted| if (!std.mem.eql(u8, wanted, event.jail.slice())) continue;
                    try out.append(.{ .sequence = event.sequence, .event_id = event.event_id, .jail = try out.allocator.dupe(u8, event.jail.slice()), .decision_id = event.decision_id, .confirmed_us = event.confirmed_us, .scope = try query_v1.projectScope(event.scope.canonical), .native_retry = event.native_retry, .origin = event.origin });
                    appended += 1;
                }
                if (!page.more) return .{ .more = false, .resume_after = after };
            }
            return .{ .more = true, .resume_after = after };
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
                row.* = .{ .name = try memory.text(jail.name), .enabled = jail.admin_enabled, .filter = try memory.text(if (source) |value| value.filter else ""), .source = @tagName(jail.plan), .logpath = owned_paths, .maxretry = jail.policy.maxretry, .findtime = @intCast(@divTrunc(jail.policy.window_us, 1_000_000)), .bantime = if (jail.policy.duration == .finite_us) @intCast(@divTrunc(jail.policy.duration.finite_us, 1_000_000)) else 0, .bantime_permanent = jail.policy.duration == .permanent, .banaction = if (self.jailEnforces(&jail)) self.published_backend else "log-only", .ignoreip = owned_ignores, .history_max_matches = @min(cfg.global.history_max_matches, if (source) |value| value.history_max_matches orelse cfg.global.history_max_matches else cfg.global.history_max_matches), .history_max_matches_inherited = if (source) |value| value.history_max_matches == null else true };
            }
            return .{ .jails = jails, .global = .{ .log_level = @tagName(cfg.global.log_level), .firewall = @tagName(cfg.global.firewall), .metrics_enabled = cfg.global.metrics_enabled, .metrics_bind = try memory.text(cfg.global.metrics_bind), .metrics_port = cfg.global.metrics_port, .socket_path = if (redact) redacted_text else try memory.text(cfg.global.socket_path), .state_file = if (redact) redacted_text else try memory.text(cfg.global.state_file), .dns_server = if (redact) redacted_text else if (cfg.global.dns_server) |value| try memory.text(value) else null, .timezone_root = if (redact) redacted_text else try memory.text(cfg.global.timezone_root), .history_max_matches = cfg.global.history_max_matches } };
        }
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
                    // A following live row proves that another page exists without reading its payload.
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
                            item.* = .{ .scope = try query_v1.projectScope(owner.scope.canonical), .lease = if (owner.lease == .permanent) .permanent else .finite, .deadline_us = if (owner.lease == .finite) owner.lease.finite else null, .decision_id = owner.decision_id, .confirmed = self.owner_confirmed[index] and known and owner.lease.live(now), .ban_count = owner.ordinal, .key = query_v1.ItemKey.init(&owner.key), .origin = owner.origin };
                        }
                    } else for (items[0..live_take], jail.active[@min(start, live)..][0..live_take]) |*item, decision| {
                        const address: shared.IpAddress = switch (decision.subject) {
                            .v4 => |value| .{ .ipv4 = std.mem.readInt(u32, &value, .big) },
                            .v6 => |value| .{ .ipv6 = std.mem.readInt(u128, &value, .big) },
                        };
                        item.* = .{ .scope = try query_v1.projectScope(.{ .subject = inspection.canonical_scope.Subject.host(address) }), .lease = if (decision.lease == .permanent) .permanent else .finite, .deadline_us = if (decision.lease == .finite) decision.lease.finite else null, .decision_id = null, .confirmed = false, .ban_count = decision.ordinal, .key = decisionKey(decision.subject), .origin = .detection };
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
            var memory: ?CaptureMemory = if (capture_needed) try CaptureMemory.init(a, if (requested_kind == .config) config_capture_bytes else if (history_details) history_capture_bytes else if (requested_details) scopes_detail_capture_bytes else scopes_capture_bytes) else null;
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
                    firewall_source = if (self.firewall_observation_cache) |cache| .{ .cache = .{ .ctx = cache, .read = firewallRead, .origin_ctx = self, .origin = firewallOrigin } } else .{ .unavailable = self.firewall_observation_unavailable };
                } else if (requested_kind == .config) config_view = try self.copyConfig(&memory.?, peer_class == .monitor);
            }
            if (requested_kind == .scopes) scopes_view = try self.copyScopes(&memory.?, body, arena, &fence.?);
            var status_query = StatusQuery{ .coordinator = self, .redact = peer_class == .monitor };
            var history_query = HistoryQuery{ .coordinator = self, .generation = generation, .details = history_details, .memory = if (history_details) &memory.? else null };
            const result = try query_v1.handle(a, body, peer_class, generation, .{ .status = .{ .ctx = &status_query, .stamped = true, .func = statusCallback }, .health = .{ .ctx = self, .func = healthCallback }, .config = config_view, .scopes = scopes_view, .history = .{ .ctx = &history_query, .read = historyRead }, .firewall = firewall_source, .ignore = .{ .ctx = self, .render = ignoreRender }, .continuity = .{ .ctx = self, .render = continuityRender } });
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

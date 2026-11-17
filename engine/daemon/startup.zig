// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Opens and admits the state store at startup, reports startup progress and admits the configuration generation.
// Holds: A state whose schema version or installation differs from the snapshot taken before the backend probe is refused.

const std = @import("std");
const config = @import("../config/config.zig");
const consumer_bridge = @import("../detect/consumer_coordinator.zig");
const durable = @import("../store/store.zig");
const sessions = @import("../source/file_session.zig");
const files = @import("../source/durable_file_source.zig");
const custom_ignore = @import("../detect/ignore.zig");
const journal_sessions = @import("../source/journal_session.zig");
const reload_mod = @import("../runtime/reload.zig");
const readiness = @import("../platform/readiness.zig");
const sd_notify = @import("../platform/sd_notify.zig");
const daemon = @import("daemon.zig");
const max_jails = daemon.max_jails;
const max_sources_per_jail = daemon.max_sources_per_jail;
const Jail = daemon.Jail;

pub fn Methods(comptime Coordinator: type) type {
    return struct {
        const monotonic = Coordinator.monotonic;
        const internalGeneration = Coordinator.internalGeneration;
        const readiness_progress_ceiling_ns = Coordinator.readiness_progress_ceiling_ns;
        const ConfigAdmission = Coordinator.ConfigAdmission;
        const retentionUpdate = Coordinator.retentionUpdate;
        const GenerationMode = Coordinator.GenerationMode;

        pub fn reportStartup(self: *Coordinator, phase: sd_notify.Phase, label: []const u8, done: u64, total: u64) void {
            if (self.startup_progress) |progress| progress.report(phase, label, done, total);
        }

        pub fn reportReadinessProgress(self: *Coordinator, report: readiness.Report) void {
            var verified: u64 = 0;
            var pending: ?readiness.Component = null;
            for (report.components, 0..) |state, i| {
                if (state == .ok) verified += 1 else if (pending == null) pending = @enumFromInt(i);
            }
            const done = verified +| self.readiness_history_pages +| if (self.effects) |manager| manager.counters.install_batches else 0;
            const now = std.time.nanoTimestamp();
            if (self.readiness_progress_started_ns == null or done != self.readiness_progress_done) {
                self.readiness_progress_started_ns = now;
                self.readiness_progress_done = done;
            }
            // Why: After 300 s without progress no report is sent, so a stalled start stops extending the systemd start timeout.
            if (now - self.readiness_progress_started_ns.? > readiness_progress_ceiling_ns) return;
            self.reportStartup(.readiness, if (pending) |component| component.name() else "readiness", done, 0);
        }

        pub fn prepareStore(self: *Coordinator) !void {
            self.store.runtime_path = self.cfg.global.state_file;
            try self.store.configureRuntimeLimits();
            try self.store.prepareCurrentSchema(.{
                .maximum_pending = durable.Limits.pending_receipts,
                .migration = self.loadRepairOptions(),
                .progress = if (self.startup_progress) |progress| progress.migrationHook() else null,
            });
            try self.retireUnconfiguredJails();
            try self.retireUnusedSharedDns();
            try self.rekeySavedGenerations();
            try self.completeGenerationRekeys();
            try self.rebuildIgnoreLists();
            // Why: The new receipt limit is applied only after the retirements above have removed the old jail population's rows.
            const maximum_pending = self.jails.len * max_sources_per_jail;
            if (try self.store.pendingReceiptCount() > maximum_pending) return error.ReceiptLimit;
            self.store.receipt_limit = maximum_pending;
        }

        pub fn admitStore(self: *Coordinator) !void {
            try self.prepareStore();
            try self.validateAdmission();
            if (!self.generation_admitted) {
                const admitted = try self.admitConfigGeneration();
                self.published_generation = admitted.generation;
                self.published_config_digest = admitted.digest;
                self.generation_admitted = true;
            }
            try self.readAdminState();
        }

        pub fn readAdminState(self: *Coordinator) !void {
            self.published_revision = try self.store.adminRevision();
            for (self.jails) |*jail| {
                var state: durable.Store.JailAdminState = undefined;
                if (try self.store.jailAdminState(jail.name, &state)) {
                    jail.disable_progress = if (state.enabled) null else .{ .request_id = state.request_id };
                    self.mutex.lock();
                    jail.admin_paused = state.paused;
                    jail.admin_enabled = state.enabled;
                    jail.disable_cleanup_pending = !state.enabled;
                    self.mutex.unlock();
                }
            }
        }

        fn rekeySavedGenerations(self: *Coordinator) !void {
            var rekeyed_jails: u32 = 0;
            var rekeyed_rows: u32 = 0;
            for (self.jails) |*jail| {
                if (jail.custom_plan != null) continue;
                const live_policy = jail.policy;
                if (try self.store.readRetryPolicy(jail.name)) |saved| jail.policy.max_subjects = saved.policy.max_subjects;
                const legacy = self.plannedGeneration(jail, .legacy) catch |err| {
                    jail.policy = live_policy;
                    return err;
                };
                jail.policy = live_policy;
                const planned = try self.plannedGeneration(jail, .planned);
                const cursors: durable.Store.CursorRekey = switch (jail.plan) {
                    .file => |*plan| blk: {
                        const processing = plan.sessionOptions().processing;
                        break :blk .{ .file = .{
                            .legacy = files.FileSource.framingBinding(processing.encoding, legacy, processing.max_record_bytes),
                            .planned = files.FileSource.framingBinding(processing.encoding, planned, processing.max_record_bytes),
                        } };
                    },
                    .journal => .journal,
                    .internal => .none,
                };
                const report = try self.store.rekeySavedGenerations(jail.name, legacy, planned, cursors);
                const rows = @as(u64, report.retry_rows) + report.pending_receipts + report.manifests + report.cursors;
                if (rows == 0) continue;
                rekeyed_jails += 1;
                rekeyed_rows +|= @intCast(@min(rows, std.math.maxInt(u32)));
            }
            if (rekeyed_jails != 0) std.log.info(
                "native storage: saved detection generations rekeyed without the ignore list or the subject share: jails={d} rows={d}; no ban, deadline, checkpoint or retry subject changed",
                .{ rekeyed_jails, rekeyed_rows },
            );
        }

        fn completeGenerationRekeys(self: *Coordinator) !void {
            for (self.jails) |*jail| {
                if (jail.custom_plan) |assets| {
                    const state = try self.store.customIgnoreState(self.allocator, jail.name) orelse continue;
                    defer state.deinit(self.allocator);
                    if (state.value.format_version != custom_ignore.version) continue;
                    if (!std.mem.eql(u8, &state.parent, &assets.parent_generation)) return error.CustomLegacyIdentityMismatch;
                    const current = try custom_ignore.Snapshot.restore(self.allocator, assets.ignore_options, state.value.payload.?);
                    current.destroy();
                    const policy = try self.store.readRetryPolicy(jail.name) orelse return error.RetryAdmissionRequired;
                    if (!std.mem.eql(
                        u8,
                        &policy.generation,
                        &try self.plannedGeneration(jail, .planned),
                    ) or !try durable.Store.retryPoliciesEqual(policy.policy, jail.policy)) return error.RetryGenerationMismatch;
                }
                const repair = try self.store.completeGenerationRekey(jail.name);
                if (repair.receipts == 0 and repair.cursors == 0) continue;
                std.log.info(
                    "native storage: generation rekey completed: jail={} receipts={d} cursors={d}; left by an earlier policy reload; no ban, deadline, checkpoint position or record changed",
                    .{ std.zig.fmtEscapes(jail.name), repair.receipts, repair.cursors },
                );
            }
        }

        fn loadRepairOptions(self: *Coordinator) durable.load_repair.Options {
            return .{ .state_path = self.cfg.global.state_file, .now_us = self.clock.wallUs(), .history_max_matches = self.cfg.global.history_max_matches };
        }

        // Holds: A schema version, or from schema 11 an installation, differing from the snapshot taken before the probe is refused.
        pub fn validatePreflightInstallation(self: *Coordinator) !void {
            const expected = if (self.preflight_schema_version == 0) 0 else @max(self.preflight_schema_version, 2);
            if (self.store.schema_version != expected) return error.NativeStateChanged;
            if (self.preflight_schema_version < 11) return;
            const current = try self.store.readInstallation();
            if (!std.meta.eql(current, self.preflight_installation)) return error.InstallationMismatch;
        }

        pub fn admitConfigGeneration(self: *Coordinator) !ConfigAdmission {
            const digest = try self.configDigest();
            var retention_rows: [config.max_configured_jails]durable.Store.JailRetentionLimit = undefined;
            const retention = try retentionUpdate(self.live_cfg, &retention_rows);
            if (try self.store.latestConfigGeneration()) |head| {
                if (head.published and std.mem.eql(u8, &head.config_digest, &digest)) {
                    _ = try self.store.setRetentionPolicies(retention);
                    return .{ .generation = head.generation, .digest = digest };
                }
                if (!head.published) return error.ConfigGenerationUnpublished;
            }
            const now = self.clock.wallUs();
            const generation = reload_mod.generationId(digest, now);
            var jails: [max_jails]durable.Store.ConfigGenerationJail = undefined;
            for (self.jails, 0..) |*jail, i| jails[i] = .{
                .jail = jail.name,
                .digest = try reload_mod.jailDigest(jail.name, jail.policy, try self.plannedGeneration(jail, .planned)),
                .allowlist_snapshot = if (jail.custom_plan) |assets| assets.initial_ignore.payload else "",
            };
            try self.store.recordConfigGeneration(
                .{ .generation = generation, .config_digest = digest, .config_path = self.config_path, .committed_us = now, .published = true, .mutation_revision = try self.store.adminRevision() },
                jails[0..self.jails.len],
                retention,
            );
            return .{ .generation = generation, .digest = digest };
        }

        pub fn validateAdmission(self: *Coordinator) !void {
            var names: [max_jails][]const u8 = undefined;
            for (self.jails, 0..) |jail, i| names[i] = jail.name;
            try self.store.validateRuntimeOwnerNames(names[0..self.jails.len]);
            for (self.jails) |jail| if (jail.custom_plan != null) try self.store.validateCustomSourceManifests(jail.name);
            var admissions: [max_jails]durable.Store.RuntimeAdmission = undefined;
            for (self.jails, 0..) |*jail, i| admissions[i] = .{
                .jail = jail.name,
                .generation = try self.plannedGeneration(jail, .planned),
                .policy = jail.policy,
                .custom = jail.custom_plan != null,
            };
            self.store.validateRuntimeAdmissions(admissions[0..self.jails.len], if (self.custom_jails != 0 and self.dns_server != null) self.dns_generation else null) catch |err| {
                if (err == error.RetryGenerationMismatch) std.log.err(
                    "native: source/profile or policy differs from saved state; restore the previous source configuration and SSH executable layout before restarting; retain the database",
                    .{},
                );
                return err;
            };
            if (self.startup_installation) |selected| if (try self.store.readInstallation()) |saved| {
                if (!std.meta.eql(saved, selected)) return error.InstallationMismatch;
            } else if (self.startup_installation_persisted) return error.InstallationMismatch;
        }

        fn preflightSource(_: []const u8, _: [32]u8, _: ?*anyopaque) anyerror!void {
            return error.ConsumerRuntimeNotReady;
        }

        pub fn plannedGeneration(self: *Coordinator, jail: *Jail, mode: GenerationMode) ![32]u8 {
            var registry = consumer_bridge.Registry.init([_]u8{0} ** 32);
            if (jail.custom_plan) |assets| {
                var settings = assets.settings;
                settings.journal_origin = switch (jail.plan) {
                    .file => null,
                    .journal => |value| &value.profile,
                    .internal => null,
                };
                settings.monotonic_ms = monotonic;
                settings.authority_revision = if (self.dns_server != null) 1 else 0;
                registry.generation = try consumer_bridge.generationFromPolicy(settings, assets.programs, assets.initial_ignore, if (self.dns_server != null) self.dns_generation else null);
            }
            var scratch: [2048]u8 = undefined;
            return switch (jail.plan) {
                .file => |*plan| blk: {
                    var options = if (mode == .legacy) plan.legacySessionOptions() else plan.sessionOptions();
                    options.retry = jail.policy;
                    options.retry_hash = if (mode == .legacy) .stored else .identity;
                    options.suppress_retry_enforcement = self.suppress_enforcement;
                    if (jail.custom_plan != null) {
                        options.staged_detection = registry.consumer();
                        options.consumer_sources = .{ .context = null, .admit = preflightSource };
                    }
                    const processor = try sessions.Session.prepareProcessor(self.allocator, options, plan.specs, &scratch, .{ .us = 0 });
                    break :blk processor.generation;
                },
                .journal => |plan| blk: {
                    var options = if (mode == .legacy) plan.legacySessionOptions() else plan.sessionOptions();
                    options.retry = jail.policy;
                    options.retry_hash = if (mode == .legacy) .stored else .identity;
                    options.suppress_retry_enforcement = self.suppress_enforcement;
                    if (jail.custom_plan != null) {
                        options.staged_detection = registry.consumer();
                        options.consumer_sources = .{ .context = null, .admit = preflightSource };
                    }
                    const processor = try journal_sessions.Session.prepareProcessor(self.allocator, options, &scratch, .{ .us = 0 });
                    break :blk processor.generation;
                },
                .internal => |generation| if (mode == .legacy) try internalGeneration(jail.name, jail.policy, .stored) else generation,
            };
        }
    };
}

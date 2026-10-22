// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const shared = @import("shared");
const config = @import("config/native.zig");
const retry = @import("core/native_retry.zig");
const resource = @import("runtime/native_resource_budget.zig");
const durable = @import("core/record_store.zig");
const ignore_set = @import("core/native_ignore_set.zig");
const native_banip = @import("config/native_banip.zig");
const build_options = @import("build_options");
const diag_mod = @import("core/diag.zig");
const reload_mod = @import("runtime/native_reload.zig");
const log_level = @import("core/log_level.zig");
const readiness = @import("core/readiness.zig");
const audit = @import("core/audit.zig");
const daemon = @import("native_daemon.zig");
const max_jails = daemon.max_jails;
fn notifyReloadReady(report: readiness.Report, notifier: anytype) void {
    if (!report.ready) return;
    _ = notifier.ready() catch |err| std.log.warn("sd_notify READY failed after reload: {s}", .{@errorName(err)});
}

pub fn Methods(comptime Coordinator: type) type {
    return struct {
        const ReloadKind = Coordinator.ReloadKind;
        const ReloadOutcome = Coordinator.ReloadOutcome;
        const ReloadRequest = Coordinator.ReloadRequest;
        const bindDecay = Coordinator.bindDecay;
        const decayWindow = Coordinator.decayWindow;
        const findConfigJail = Coordinator.findConfigJail;
        const ignoreCell = Coordinator.ignoreCell;
        const includeJail = Coordinator.includeJail;
        const resolvedSource = Coordinator.resolvedSource;
        const wallClockEffect = Coordinator.wallClockEffect;
        pub fn jailReservationCost(jail: *const config.JailConfig, source: config.LogSource) !resource.Cost {
            var plan: resource.Plan = .{ .live = .{} };
            try includeJail(&plan, jail, source, try resource.currentEnvironment());
            var cost = try plan.live.plus(plan.restore_overlap);
            for (plan.workspaces) |workspace| cost = try cost.plus(workspace);
            return cost;
        }
        pub fn stageReload(self: *Coordinator, wait_ms: u64) ReloadOutcome {
            const arena = self.allocator.create(std.heap.ArenaAllocator) catch return ReloadOutcome.single(.rejected, "out of memory", .{});
            arena.* = std.heap.ArenaAllocator.init(self.allocator);
            var keep_arena = false;
            defer if (!keep_arena) {
                arena.deinit();
                self.allocator.destroy(arena);
            };
            var diag: config.Diagnostic = .{};
            const file = std.fs.cwd().openFile(self.config_path, .{}) catch |err| return ReloadOutcome.single(.rejected, "config: open: {s}", .{@errorName(err)});
            defer file.close();
            const stat = std.posix.fstat(file.handle) catch |err| return ReloadOutcome.single(.rejected, "config: stat: {s}", .{@errorName(err)});
            config.Config.checkConfigPerms(stat.mode, stat.gid) catch |err| return ReloadOutcome.single(.rejected, "config: {s}", .{@errorName(err)});
            const bytes = file.readToEndAlloc(arena.allocator(), 16 * 1024 * 1024) catch |err| return ReloadOutcome.single(.rejected, "config: read: {s}", .{@errorName(err)});
            const proposed = arena.allocator().create(config.Config) catch return ReloadOutcome.single(.rejected, "out of memory", .{});
            proposed.* = config.Config.parseDiag(arena.allocator(), bytes, &diag) catch |err| return ReloadOutcome.single(.rejected, "config: {s}:{d}:{d}: {s}", .{ self.config_path, diag.line, diag.col, @errorName(err) });
            var validation_diag: config.ValidationDiagnostic = .{};
            config.validateDiag(proposed, &validation_diag) catch |err| {
                var out = ReloadOutcome.single(.rejected, "config: validation failed: {s}", .{@errorName(err)});
                const detail = validation_diag.render(&out.reasons[1].bytes);
                out.reasons[1].len = @intCast(detail.len);
                out.reason_count = 2;
                return out;
            };
            const digest = reload_mod.digestBytes(bytes);
            const classified = self.inspectPublicationLocked(ReloadClassificationInput{ .proposed = proposed }, classifyReloadLocked);
            const current_generation = classified.generation;
            const classification = classified.classification;
            var out = ReloadOutcome{ .kind = switch (classification.kind) {
                .noop => .noop,
                .live => .applied,
                .restart_required => .restart_required,
                .rejected => .rejected,
            }, .generation = current_generation, .reasons = classification.reasons, .reason_count = classification.reason_count };
            if (classification.kind != .live and !(classification.kind == .noop and self.hasAllowlistFiles())) return out;
            const request = self.allocator.create(ReloadRequest) catch return ReloadOutcome.single(.rejected, "out of memory", .{});
            request.* = .{ .classification = classification, .config_digest = digest, .proposed = proposed, .arena = arena };
            keep_arena = true;
            self.mutex.lock();
            if (self.reload_request != null) {
                self.mutex.unlock();
                self.freeRequest(request);
                return ReloadOutcome.single(.rejected, "reload already in progress", .{});
            }
            self.reload_request = request;
            var timer = std.time.Timer.start() catch null;
            while (!request.done) {
                const elapsed_ms: u64 = if (timer) |*t| t.read() / std.time.ns_per_ms else wait_ms;
                if (elapsed_ms >= wait_ms) break;
                self.reload_wake.timedWait(&self.mutex, (wait_ms - elapsed_ms) * std.time.ns_per_ms) catch {};
            }
            if (!request.done) {
                if (self.reload_request == request) {
                    self.reload_request = null;
                    self.mutex.unlock();
                    self.freeRequest(request);
                    return ReloadOutcome.single(.rejected, "worker did not accept the reload within {d} ms; no state was changed", .{wait_ms});
                }
                request.abandoned = true;
                self.mutex.unlock();
                return ReloadOutcome.single(.uncertain, "worker is still applying the reload; inspect status generation", .{});
            }
            out = request.outcome.?;
            self.mutex.unlock();
            self.freeRequest(request);
            return out;
        }
        pub fn applyReload(self: *Coordinator, request: *ReloadRequest) void {
            const diag_span = if (comptime build_options.diag) diag_mod.enter(.reload) else {};
            defer if (comptime build_options.diag) diag_mod.leave(diag_span);
            const outcome = self.applyReloadInner(request) catch |err| ReloadOutcome.single(.rejected, "reload failed before publication: {s}; current generation retained", .{@errorName(err)});
            self.mutex.lock();
            request.outcome = outcome;
            request.done = true;
            const abandoned = request.abandoned;
            self.reload_wake.broadcast();
            self.mutex.unlock();
            if (abandoned) self.freeRequest(request);
            std.log.info("native reload: outcome={s}", .{@tagName(outcome.kind)});
        }
        pub fn namedIn(names: []const []const u8, name: []const u8) bool {
            for (names) |value| if (std.mem.eql(u8, value, name)) return true;
            return false;
        }
        pub fn applyReloadInner(self: *Coordinator, request: *ReloadRequest) !ReloadOutcome {
            try self.gate.admitMutation();
            if (self.notifier) |notifier| _ = notifier.reloading() catch {};
            defer if (self.notifier) |notifier| {
                notifyReloadReady(self.readinessReport(), notifier);
            };
            const now = self.clock.wallUs();
            const generation = reload_mod.generationId(request.config_digest, now);
            const classification = &request.classification;
            const proposed = request.proposed;
            const removed = classification.jails.removedSlice();
            var reservations: [max_jails]?resource.Token = [_]?resource.Token{null} ** max_jails;
            var reserved: usize = 0;
            defer for (reservations[0..reserved]) |pending| if (pending) |token| self.resources.release(token) catch |failure| {
                std.log.err("native reload: jail reservation release failed: {s}", .{@errorName(failure)});
            };
            for (classification.jails.addedSlice()) |name| {
                const jail_cfg = findConfigJail(proposed, name) orelse return error.UnknownJail;
                if (!jail_cfg.enabled) continue;
                const cost = try jailReservationCost(jail_cfg, resolvedSource(proposed, jail_cfg));
                reservations[reserved] = self.resources.reserve(.configuration, cost) catch |failure|
                    return ReloadOutcome.single(.rejected, "jails.{s}: not admitted: {s}; nothing was applied", .{ name, @errorName(failure) });
                reserved += 1;
            }
            var transitions: [max_jails]durable.Store.PolicyTransition = undefined;
            var digests: [max_jails]durable.Store.ConfigGenerationJail = undefined;
            var count: usize = 0;
            for (classification.policySlice()) |change| {
                const jail = self.findJail(change.jail) orelse return error.UnknownJail;
                const current_generation = try self.plannedGeneration(jail, .planned);
                const previous = jail.policy;
                const next_policy = change.next;
                jail.policy = next_policy;
                const next_generation = self.plannedGeneration(jail, .planned) catch |err| {
                    jail.policy = previous;
                    return err;
                };
                jail.policy = previous;
                const rebinding: ?durable.Store.CursorRebinding = switch (jail.plan) {
                    .file => |*plan| blk: {
                        const processing = plan.sessionOptions().processing;
                        break :blk .{ .old = @import("core/durable_file_source.zig").FileSource.framingBinding(processing.encoding, current_generation, processing.max_record_bytes), .new = @import("core/durable_file_source.zig").FileSource.framingBinding(processing.encoding, next_generation, processing.max_record_bytes) };
                    },
                    else => null,
                };
                transitions[count] = .{ .jail = jail.name, .generation = current_generation, .next_generation = next_generation, .expected = previous, .next = next_policy, .cursor_rebinding = rebinding };
                count += 1;
            }
            var outcome = ReloadOutcome{ .kind = .applied, .generation = generation };
            var refreshed: usize = 0;
            for (self.jails) |*jail| {
                const consumer = jail.consumer orelse continue;
                const path = self.ignoreFilePath(jail.name) orelse continue;
                const result = consumer.refreshAllowlist(path, now) catch |err| {
                    if (outcome.reason_count < reload_mod.max_reasons) {
                        var reason: reload_mod.Reason = .{};
                        const written = std.fmt.bufPrint(&reason.bytes, "jails.{s}: allowlist retained: {s}", .{ jail.name, @errorName(err) }) catch reason.bytes[0..0];
                        reason.len = @intCast(written.len);
                        outcome.reasons[outcome.reason_count] = reason;
                        outcome.reason_count += 1;
                    }
                    continue;
                };
                if (result == .applied) refreshed += 1;
            }
            var fresh_self = self.readSelfAddresses();
            defer if (fresh_self) |*list| list.deinit(self.allocator);
            const fresh_own: []const shared.IpAddress = if (fresh_self) |list| list.addresses else &.{};
            var next_lists: [max_jails]?*ignore_set.EffectiveIgnore = [_]?*ignore_set.EffectiveIgnore{null} ** max_jails;
            defer for (next_lists) |pending| if (pending) |list| list.deinit(self.allocator);
            var ignore_changes: usize = 0;
            for (self.jails, 0..) |*jail, i| {
                if (jail.retiring or namedIn(removed, jail.name)) continue;
                const changed = namedIn(classification.ignoreSlice(), jail.name);
                const jail_cfg = findConfigJail(proposed, jail.name);
                const own = if (jail_cfg) |value| config.resolveJailFromConfig(value, proposed.defaults).ignoreself else false;
                if (!changed and !own) continue;
                if (ignoreCell(jail) == null) {
                    if (changed) try self.applyIgnoreDeadlines(proposed, jail.name, now);
                    continue;
                }
                next_lists[i] = try self.effectiveIgnore(proposed, jail.name, fresh_own, if (changed) .apply else .read, now);
                ignore_changes += @intFromBool(changed);
            }
            var decays: [max_jails]retry.EscalationDecay = undefined;
            for (classification.decaySlice(), 0..) |name, i| {
                const jail_cfg = findConfigJail(proposed, name) orelse return error.UnknownJail;
                decays[i] = try decayWindow(config.resolveJailFromConfig(jail_cfg, proposed.defaults).bantime_increment_decay);
            }
            const base = self.jails.len;
            var created: usize = 0;
            errdefer for (self.jail_storage[base..][0..created]) |*jail| {
                if (jail.custom_plan != null) self.custom_jails -= 1;
                self.releaseJail(jail);
            };
            for (classification.jails.addedSlice()) |name| {
                const jail_cfg = findConfigJail(proposed, name) orelse return error.UnknownJail;
                if (!jail_cfg.enabled) continue;
                if (base + created == max_jails) return error.NativeJailLimit;
                self.jail_storage[base + created] = try self.createJail(proposed, jail_cfg, resolvedSource(proposed, jail_cfg));
                self.jail_storage[base + created].reservation = reservations[created];
                reservations[created] = null;
                created += 1;
                const jail = &self.jail_storage[base + created - 1];
                if (ignoreCell(jail) != null) {
                    next_lists[base + created - 1] = try self.effectiveIgnore(proposed, jail.name, fresh_own, .apply, now);
                } else try self.applyIgnoreDeadlines(proposed, jail.name, now);
            }
            var retiring: usize = 0;
            for (removed) |name| retiring += @intFromBool(self.findJail(name) != null);
            const changes = count + refreshed + ignore_changes + classification.banipSlice().len + classification.decaySlice().len + created + retiring;
            if (changes == 0) {
                outcome.kind = .noop;
                outcome.generation = self.published_generation;
                return outcome;
            }
            var digest_count: usize = 0;
            for (self.jail_storage[0 .. base + created], 0..) |*jail, i| {
                if (i < base and (jail.retiring or namedIn(removed, jail.name))) continue;
                var next = jail.policy;
                for (transitions[0..count]) |change| if (std.mem.eql(u8, change.jail, jail.name)) {
                    next = change.next;
                };
                const allowlist = if (jail.consumer) |consumer| consumer.ignores.live.payload else if (jail.custom_plan) |assets| assets.initial_ignore.payload else "";
                digests[digest_count] = .{ .jail = jail.name, .digest = try reload_mod.jailDigest(jail.name, next, try self.plannedGeneration(jail, .planned)), .allowlist_snapshot = allowlist };
                digest_count += 1;
            }
            if (self.live_arena_backs_jails) try self.retained_arenas.ensureUnusedCapacity(self.allocator, 1);
            self.store.commitReloadGeneration(transitions[0..count], .{ .generation = generation, .config_digest = request.config_digest, .config_path = self.config_path, .committed_us = now, .published = true, .mutation_revision = 0 }, digests[0..digest_count], .{ .prepared_us = now, .context = self, .read = wallClockEffect }) catch |err| {
                if (refreshed != 0) return ReloadOutcome.single(.partial, "allowlists refreshed but the policy generation was not committed: {s}", .{@errorName(err)});
                return err;
            };
            const committed_revision = self.store.adminRevision();
            self.mutex.lock();
            if (committed_revision) |revision| self.published_revision = revision else |_| {}
            for (transitions[0..count]) |change| if (self.findJail(change.jail)) |jail| {
                jail.policy = change.next;
                jail.rekeyed = !std.mem.eql(u8, &change.generation, &change.next_generation);
                jail.retry_revision = null;
            };
            if (count != 0) self.owner_read_epoch = null;
            if (classification.log_level) |level| log_level.set(std.meta.stringToEnum(std.log.Level, @tagName(level)) orelse .info);
            self.replaceLiveConfigLocked(request.arena, proposed, created != 0);
            request.arena = null;
            self.jails = self.jail_storage[0 .. base + created];
            for (removed) |name| if (self.findJail(name)) |jail| {
                jail.retiring = true;
            };
            if (fresh_self) |list| {
                if (self.self_addresses) |*old| old.deinit(self.allocator);
                self.self_addresses = list;
                fresh_self = null;
            }
            self.published_generation = generation;
            self.published_config_digest = request.config_digest;
            self.mutex.unlock();
            for (classification.decaySlice(), 0..) |name, i| if (self.findJail(name)) |jail| {
                jail.decay = decays[i];
                bindDecay(jail);
            };
            for (classification.banipSlice()) |name| if (self.findJail(name)) |jail| {
                jail.banlist_pending = true;
            };
            for (self.jails, 0..) |*jail, i| if (next_lists[i]) |list| {
                next_lists[i] = null;
                self.replaceIgnoreList(jail, list);
            };
            if (count != 0 or created != 0) self.gate.requestRebuild() catch |err| std.log.warn("native reload: source rebuild not started: {s}; it starts with the next recovery", .{@errorName(err)});
            if (committed_revision) |_| {} else |err| {
                outcome.kind = .partial;
                if (outcome.reason_count < reload_mod.max_reasons) {
                    var reason: reload_mod.Reason = .{};
                    const written = std.fmt.bufPrint(&reason.bytes, "generation applied but the mutation revision was not read back: {s}; restart fail2zig before changing bans", .{@errorName(err)}) catch reason.bytes[0..0];
                    reason.len = @intCast(written.len);
                    outcome.reasons[outcome.reason_count] = reason;
                    outcome.reason_count += 1;
                }
            }
            return outcome;
        }
        pub fn hasAllowlistFiles(self: *Coordinator) bool {
            for (self.jails) |*jail| if (jail.custom_plan != null and self.ignoreFilePath(jail.name) != null) return true;
            return false;
        }
        pub fn inspectPublicationLocked(self: *Coordinator, context: anytype, comptime inspect: anytype) @typeInfo(@TypeOf(inspect)).@"fn".return_type.? {
            self.mutex.lock();
            defer self.mutex.unlock();
            return inspect(self, context);
        }
        const ReloadClassificationInput = struct { proposed: *const config.Config };
        const ReloadClassificationSnapshot = struct {
            generation: [32]u8,
            classification: reload_mod.Classification,
        };
        pub fn classifyReloadLocked(self: *Coordinator, input: ReloadClassificationInput) ReloadClassificationSnapshot {
            var counts: [max_jails]reload_mod.RuntimeCount = undefined;
            for (self.jails, 0..) |jail, i| counts[i] = .{ .jail = jail.name, .runtime_only = jail.ignore_runtime_only };
            var found: native_banip.BanListConflict = undefined;
            const conflict: ?native_banip.BanListConflict = if (native_banip.findConflict(input.proposed, &found)) found else null;
            return .{ .generation = self.published_generation, .classification = reload_mod.classifyWithRuntime(self.live_cfg, input.proposed, retry.max_pool_subjects, counts[0..self.jails.len], conflict) };
        }
        pub fn replaceLiveConfigLocked(self: *Coordinator, arena: ?*std.heap.ArenaAllocator, proposed: *const config.Config, backs_jails: bool) void {
            if (self.live_arena) |old| {
                if (self.live_arena_backs_jails) {
                    self.retained_arenas.appendAssumeCapacity(old);
                } else {
                    old.deinit();
                    self.allocator.destroy(old);
                }
            }
            self.live_arena = arena;
            self.live_arena_backs_jails = backs_jails;
            self.live_cfg = proposed;
        }
        pub fn ignoreFilePath(self: *Coordinator, name: []const u8) ?[]const u8 {
            for (self.live_cfg.jails) |*jail| if (std.mem.eql(u8, jail.name, name)) return jail.ignore_file;
            return null;
        }
        pub fn auditReload(kind: ReloadKind, peer_uid: u32) void {
            audit.write(.{ .command = "reload", .target = "-", .jail = null, .peer_uid = peer_uid, .outcome = @tagName(kind) });
        }
        pub fn reloadResponse(self: *Coordinator, out: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator, peer_uid: u32) !shared.Response {
            var outcome = self.stageReload(2000);
            auditReload(outcome.kind, peer_uid);
            if (std.mem.allEqual(u8, &outcome.generation, 0)) {
                self.mutex.lock();
                outcome.generation = self.published_generation;
                self.mutex.unlock();
            }
            const w = out.writer(a);
            try w.print("{{\"schema_version\":1,\"outcome\":\"{s}\",\"generation\":\"{s}\",\"reasons\":[", .{ @tagName(outcome.kind), &std.fmt.bytesToHex(outcome.generation, .lower) });
            for (outcome.reasonSlice(), 0..) |reason, i| {
                if (i > 0) try w.writeByte(',');
                try std.json.encodeJsonString(reason.slice(), .{}, w);
            }
            try w.writeAll("]}");
            return switch (outcome.kind) {
                .applied, .noop => .{ .ok = .{ .payload = try out.toOwnedSlice(a) } },
                .rejected => .{ .err = .{ .code = 409, .message = try out.toOwnedSlice(a) } },
                .restart_required => .{ .err = .{ .code = 412, .message = try out.toOwnedSlice(a) } },
                .uncertain => .{ .err = .{ .code = 508, .message = try out.toOwnedSlice(a) } },
                .partial => .{ .err = .{ .code = 507, .message = try out.toOwnedSlice(a) } },
            };
        }
    };
}

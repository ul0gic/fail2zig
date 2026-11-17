// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Publishes the pool, jail, owner, source-status and health snapshots that IPC and HTTP readers see.
// Holds: READY is sent once, and only after the readiness report shows every component verified.

const std = @import("std");
const shared = @import("shared");
const retry = @import("../detect/retry.zig");
const detection = @import("../detect/detection_record.zig");
const effect = @import("../effect/effect.zig");
const effect_runtime = @import("../runtime/effect_runtime.zig");
const durable = @import("../store/store.zig");
const pipeline = @import("../source/record_pipeline.zig");
const files = @import("../source/durable_file_source.zig");
const journal_sessions = @import("../source/journal_session.zig");
const build_options = @import("build_options");
const diag_mod = @import("../diag/diag.zig");
const sd_notify = @import("../platform/sd_notify.zig");
const daemon = @import("daemon.zig");
const max_jails = daemon.max_jails;
const max_sources_per_jail = daemon.max_sources_per_jail;
const Source = daemon.Source;
const EffectMark = daemon.EffectMark;
const Jail = daemon.Jail;
const SourceStatus = daemon.SourceStatus;
const SourceSignature = daemon.SourceSignature;

pub fn Methods(comptime Coordinator: type) type {
    return struct {
        const observationMs = Coordinator.observationMs;
        const sessionProcessor = Coordinator.sessionProcessor;
        const capacityWaiting = Coordinator.capacityWaiting;
        const OptionalNumber = Coordinator.OptionalNumber;
        const ControlEscaped = Coordinator.ControlEscaped;
        const shell_safe = Coordinator.shell_safe;
        const quiet_interval_ms = Coordinator.quiet_interval_ms;

        pub fn publishPool(self: *Coordinator, now_ms: u64) !void {
            if (!self.published_pool.pending) if (self.last_pool_ms) |last| if (now_ms -| last < quiet_interval_ms) return;
            self.last_pool_ms = now_ms;
            const sample = try self.store.retryPoolOccupancy(self.clock.wallUs());
            if (sample) |value| self.metrics_state.setPoolOccupancy(value.occupancy.tracked, value.occupancy.banned);
            for (self.jails) |jail| {
                self.metrics_state.jailSetPoolEvictions(jail.name, self.store.evictionCount(jail.name));
                const processor = sessionProcessor(&jail);
                self.metrics_state.jailSetFailuresCounted(jail.name, jail.failures_carried +| if (processor) |value| value.failures_counted else 0);
                self.metrics_state.jailSetIgnoredDetections(jail.name, jail.ignored_carried +| if (processor) |value| value.ignored_detections else 0);
                self.metrics_state.jailSetBansTotal(jail.name, jail.summary.decisions +| jail.manual_bans +| jail.config_bans);
            }
            const footprint = try self.store.stateFileFootprint();
            const confirmations = try self.confirmedEvents();
            self.metrics_state.setStateFile(footprint.bytes, footprint.pages, footprint.used_pages);
            var waiting_sources: u32 = 0;
            for (self.jails) |*jail| waiting_sources += @intFromBool(capacityWaiting(jail));
            self.metrics_state.setCapacity(footprint.capacity_pages, footprint.owed_pages, self.store.intake_closed, waiting_sources);
            self.mutex.lock();
            if (sample) |value| self.published_pool.sample = value;
            self.published_pool.pending = sample == null;
            if (comptime build_options.diag) diag_mod.gauge(.retry_projection_pending_state, @intFromBool(sample == null));
            self.metrics_state.setPoolSample(self.published_pool.sample != null, self.published_pool.pending, if (self.published_pool.sample) |value| value.as_of_us else null);
            self.published_footprint = footprint;
            self.published_intake_waiting = self.store.intake_closed;
            self.published_confirmations = confirmations;
            self.mutex.unlock();
        }

        pub fn publishJail(self: *Coordinator, jail: *Jail) !void {
            const diag_span = if (comptime build_options.diag) diag_mod.enter(.publish) else {};
            defer if (comptime build_options.diag) diag_mod.leave(diag_span);
            const now = self.clock.wallUs();
            const summary = self.store.retryJailSummary(jail.name) catch |failure| {
                if (failure == error.RetryEligibilityPending) {
                    self.retryPublicationPending(jail);
                    return;
                }
                return failure;
            };
            const revision = try self.store.revision(jail.name);
            const expired = if (jail.next_expiry_us) |deadline| now >= deadline else false;
            const enforces = self.jailEnforces(jail);
            const healthy = jail.session.?.healthy();
            if (jail.published_once and !expired and jail.retry_revision == summary.revision) {
                self.mutex.lock();
                jail.revision = revision;
                jail.healthy = healthy;
                self.mutex.unlock();
                return;
            }
            var count: usize = 0;
            if (!enforces) {
                if (self.decision_scratch.len == 0) self.decision_scratch = try self.allocator.alloc(durable.Store.ActiveDecision, retry.max_pool_subjects);
                if (jail.retry_revision == summary.revision) {
                    for (jail.active) |decision| if (decision.lease.live(now)) {
                        self.decision_scratch[count] = decision;
                        count += 1;
                    };
                } else count = self.store.retryLiveDecisions(jail.name, now, self.decision_scratch) catch |failure| {
                    if (failure == error.RetryEligibilityPending) {
                        self.retryPublicationPending(jail);
                        return;
                    }
                    return failure;
                };
            }
            const active = try self.allocator.dupe(durable.Store.ActiveDecision, self.decision_scratch[0..count]);
            var next_expiry: ?i64 = null;
            var prior: usize = 0;
            for (active) |decision| {
                if (decision.lease == .finite) next_expiry = if (next_expiry) |deadline| @min(deadline, decision.lease.finite) else decision.lease.finite;
                while (prior < jail.active.len and subjectOrder(jail.active[prior].subject, decision.subject) == .lt) prior += 1;
                const already_published = prior < jail.active.len and std.meta.eql(jail.active[prior].subject, decision.subject) and jail.active[prior].ordinal == decision.ordinal;
                if (jail.published_once and !already_published) {
                    const address: shared.IpAddress = switch (decision.subject) {
                        .v4 => |v| .{ .ipv4 = std.mem.readInt(u32, &v, .big) },
                        .v6 => |v| .{ .ipv6 = std.mem.readInt(u128, &v, .big) },
                    };
                    std.log.info("would-ban: jail='{s}' ip={}", .{ jail.name, address });
                }
            }
            self.mutex.lock();
            defer self.mutex.unlock();
            self.allocator.free(jail.active);
            jail.active = active;
            jail.summary = .{ .decisions = summary.decisions };
            jail.retry_revision = summary.revision;
            jail.published_once = true;
            jail.next_expiry_us = next_expiry;
            jail.revision = revision;
            jail.healthy = healthy;
        }

        pub fn retryPublicationPending(self: *Coordinator, jail: ?*Jail) void {
            self.effect_backlog = true;
            self.mutex.lock();
            defer self.mutex.unlock();
            if (jail) |value| value.retry_revision = null;
            self.published_pool.pending = true;
            if (comptime build_options.diag) diag_mod.gauge(.retry_projection_pending_state, 1);
            self.metrics_state.setPoolSample(self.published_pool.sample != null, true, if (self.published_pool.sample) |value| value.as_of_us else null);
        }

        fn subjectOrder(a: detection.Subject, b: detection.Subject) std.math.Order {
            const tag = std.math.order(@intFromEnum(std.meta.activeTag(a)), @intFromEnum(std.meta.activeTag(b)));
            if (tag != .eq) return tag;
            return switch (a) {
                .v4 => |left| std.mem.order(u8, &left, &b.v4),
                .v6 => |left| std.mem.order(u8, &left, &b.v6),
            };
        }

        fn effectMark(self: *const Coordinator, enforces: bool) EffectMark {
            const epoch = self.store.effect_publication_epoch;
            const manager = self.effects orelse return .{ .view_revision = 0, .epoch = epoch, .trusted = false, .enforces = enforces };
            const trusted = !manager.status.uncertain or (manager.status.cause != null and effect_runtime.transientCause(manager.status.cause.?));
            return .{ .view_revision = manager.view_revision, .epoch = epoch, .trusted = trusted, .enforces = enforces };
        }

        fn confirmedEvents(self: *Coordinator) !u64 {
            if (self.effects == null) return 0;
            const epoch = self.store.effect_publication_epoch;
            if (self.confirmations_epoch == epoch) return self.confirmations_count;
            self.confirmations_count = try self.store.confirmedEffectEvents();
            self.confirmations_epoch = epoch;
            return self.confirmations_count;
        }

        fn ownerConfirmed(self: *const Coordinator, owner: durable.Store.OperatorOwner, now: i64) bool {
            const manager = self.effects orelse return false;
            if (manager.cached_epoch == null or manager.cached_epoch.? != self.store.effect_publication_epoch) return false;
            return owner.lease.live(now) and manager.confirmedKey(owner.key, now);
        }

        fn ownerLess(_: void, left: durable.Store.OperatorOwner, right: durable.Store.OperatorOwner) bool {
            const jail = std.mem.order(u8, left.jail.slice(), right.jail.slice());
            return if (jail == .eq) std.mem.order(u8, &left.key, &right.key) == .lt else jail == .lt;
        }

        fn ownerKeyLess(_: void, left: [32]u8, right: [32]u8) bool {
            return std.mem.order(u8, &left, &right) == .lt;
        }

        fn changedOwner(keys: []const [32]u8, key: [32]u8) bool {
            var first: usize = 0;
            var end = keys.len;
            while (first < end) {
                const middle = first + (end - first) / 2;
                switch (std.mem.order(u8, &keys[middle], &key)) {
                    .lt => first = middle + 1,
                    .gt => end = middle,
                    .eq => return true,
                }
            }
            return false;
        }

        fn changedOwnerKeys(self: *Coordinator, epoch: u64, keys: [][32]u8) ?usize {
            const previous = self.owner_read_epoch orelse return null;
            if (epoch == std.math.maxInt(u64) or epoch <= previous or epoch - previous > durable.Store.attribution_ring) return null;
            var count: usize = 0;
            var next = previous + 1;
            while (next <= epoch) : (next += 1) {
                const change = self.store.attributedChange(next) orelse return null;
                if (change.count > keys.len - count) return null;
                @memcpy(keys[count..][0..change.count], change.slice());
                count += change.count;
            }
            std.sort.pdq([32]u8, keys[0..count], {}, ownerKeyLess);
            var unique: usize = 0;
            for (keys[0..count]) |key| {
                if (unique != 0 and std.mem.eql(u8, &keys[unique - 1], &key)) continue;
                keys[unique] = key;
                unique += 1;
            }
            return unique;
        }

        fn replaceChangedOwners(self: *Coordinator, keys: []const [32]u8, now: i64) !usize {
            var replacements: usize = 0;
            for (keys) |key| {
                const available = @min(effect.max_page, self.owner_scratch.len - replacements);
                replacements += try self.store.operatorOwnersForScope(key, now, self.owner_scratch[replacements..][0..available]);
            }
            std.sort.pdq(durable.Store.OperatorOwner, self.owner_scratch[0..replacements], {}, ownerLess);
            var retained: usize = 0;
            for (self.owner_active[0..self.owner_count]) |owner| if (owner.lease.live(now) and !changedOwner(keys, owner.key)) {
                retained += 1;
            };
            if (retained > self.owner_scratch.len - replacements) return error.EffectCapacity;
            const count = retained + replacements;
            var old = self.owner_count;
            var incoming = replacements;
            var write = count;
            while (write != 0) {
                while (old != 0 and (!self.owner_active[old - 1].lease.live(now) or changedOwner(keys, self.owner_active[old - 1].key))) old -= 1;
                write -= 1;
                if (incoming != 0 and (old == 0 or ownerLess({}, self.owner_active[old - 1], self.owner_scratch[incoming - 1]))) {
                    incoming -= 1;
                    self.owner_scratch[write] = self.owner_scratch[incoming];
                } else {
                    old -= 1;
                    self.owner_scratch[write] = self.owner_active[old];
                }
            }
            return count;
        }

        fn publishOwnerRanges(self: *Coordinator, count: usize) void {
            var slots: [max_jails]usize = undefined;
            for (self.jails, 0..) |*jail, i| {
                jail.owner_range = .{};
                slots[i] = i;
            }
            const Order = struct {
                fn less(jails: []const Jail, left: usize, right: usize) bool {
                    return std.mem.order(u8, jails[left].name, jails[right].name) == .lt;
                }
            };
            std.sort.pdq(usize, slots[0..self.jails.len], @as([]const Jail, self.jails), Order.less);
            var cursor: usize = 0;
            for (slots[0..self.jails.len]) |slot| {
                const jail = &self.jails[slot];
                while (cursor < count and std.mem.order(u8, self.owner_scratch[cursor].jail.slice(), jail.name) == .lt) cursor += 1;
                const first = cursor;
                while (cursor < count and std.mem.eql(u8, self.owner_scratch[cursor].jail.slice(), jail.name)) cursor += 1;
                jail.owner_range = .{ .start = first, .len = cursor - first };
            }
        }

        // Holds: Owners are published only if the manager's cached epoch still equals the store's after the read; otherwise StaleEffect.
        pub fn publishOwners(self: *Coordinator) !void {
            const diag_span = if (comptime build_options.diag) diag_mod.enter(.owners) else {};
            defer if (comptime build_options.diag) diag_mod.leave(diag_span);
            const manager = self.effects orelse return;
            if (manager.withdrawn) {
                self.mutex.lock();
                defer self.mutex.unlock();
                self.owner_rebuild = null;
                self.owner_publication_pending = false;
                @memset(self.owner_confirmed[0..self.owner_count], false);
                self.published_owners_mark = null;
                return;
            }
            const expected_epoch = manager.cached_epoch orelse return error.StaleEffect;
            const fatal = manager.status.uncertain and !(manager.status.cause != null and effect_runtime.transientCause(manager.status.cause.?));
            if (fatal or expected_epoch != self.store.effect_publication_epoch) return error.StaleEffect;
            const mark = self.effectMark(true);
            const reread = self.owner_read_epoch != expected_epoch;
            if (self.owner_rebuild == null and !reread and std.meta.eql(self.published_owners_mark, mark)) return;
            const now = self.clock.wallUs();
            var count: usize = 0;
            if (self.owner_rebuild) |state| {
                if (state.epoch != expected_epoch) self.owner_rebuild = null;
            }
            if (self.owner_rebuild == null and reread) {
                var keys: [durable.Store.attribution_ring * durable.Store.attribution_batch][32]u8 = undefined;
                if (self.changedOwnerKeys(expected_epoch, &keys)) |changed| {
                    count = try self.replaceChangedOwners(keys[0..changed], now);
                } else {
                    self.owner_rebuild = .{ .epoch = expected_epoch };
                    self.mutex.lock();
                    self.owner_publication_pending = true;
                    self.mutex.unlock();
                }
            } else if (self.owner_rebuild == null) for (self.owner_active[0..self.owner_count]) |owner| if (owner.lease.live(now)) {
                self.owner_scratch[count] = owner;
                count += 1;
            };
            if (self.owner_rebuild) |*state| {
                const remaining = self.owner_scratch.len - state.count;
                if (remaining == 0) {
                    var probe: [1]durable.Store.OperatorOwner = undefined;
                    if (try self.store.operatorOwnerPage(now, &probe, state.after) != 0) return error.EffectCapacity;
                } else {
                    const want = @min(durable.Store.owner_page_rows, remaining);
                    const got = try self.store.operatorOwnerPage(now, self.owner_scratch[state.count..][0..want], state.after);
                    state.count += got;
                    if (got == want) {
                        state.after = self.owner_scratch[state.count - 1];
                        self.effect_backlog = true;
                        return;
                    }
                }
                for (self.owner_scratch[0..state.count]) |owner| if (owner.lease.live(now)) {
                    self.owner_scratch[count] = owner;
                    count += 1;
                };
                self.owner_rebuild = null;
            }
            for (self.owner_scratch[0..count], 0..) |owner, i| self.owner_scratch_confirmed[i] = self.ownerConfirmed(owner, now);
            if (expected_epoch != self.store.effect_publication_epoch or manager.cached_epoch == null or manager.cached_epoch.? != expected_epoch) return error.StaleEffect;
            self.mutex.lock();
            defer self.mutex.unlock();
            self.publishOwnerRanges(count);
            @memcpy(self.owner_active[0..count], self.owner_scratch[0..count]);
            @memcpy(self.owner_confirmed[0..count], self.owner_scratch_confirmed[0..count]);
            self.owner_count = count;
            self.owner_read_epoch = expected_epoch;
            self.published_owners_mark = mark;
            self.owner_publication_pending = false;
        }

        pub fn publishSource(self: *Coordinator, jail: *Jail) !void {
            const source = jail.session.?;
            const cause: ?anyerror = switch (source) {
                .file => |value| value.repairSnapshot().last_cause orelse value.blocked_cause,
                .journal => |value| value.repairSnapshot().last_cause orelse value.blockedCause(),
                .internal => self.history_wait,
            };
            const healthy = source.healthy() and !(source == .internal and cause != null);
            const missing = source == .file and source.file.awaitingPath();
            const diagnostic = switch (source) {
                .journal => |value| if (value.failureDiagnostic()) |detail|
                    (if (cause != null and detail.cause == cause.?) detail else null)
                else
                    null,
                else => null,
            };
            self.mutex.lock();
            const previous_cause = jail.source_error;
            const previous_diagnostic = jail.source_diagnostic;
            const changed = jail.healthy != healthy or previous_cause != cause or !std.meta.eql(previous_diagnostic, diagnostic);
            jail.healthy = healthy;
            jail.source_missing = missing;
            jail.source_error = cause;
            jail.source_diagnostic = diagnostic;
            self.mutex.unlock();
            if (source == .file) for (0..2 * source.file.sources.max_sources) |_| {
                const report = source.file.nextUnreportedContinuityFailure() orelse break;
                if (comptime build_options.diag) diag_mod.event(.source_paused, .{ .subject = jail.name, .cause = @tagName(report.failure.kind) });
                std.log.err(
                    "file source for jail '{'}' path '{'}' cannot resume its checkpoint: {}; unknown extent of unread data lost; source paused pending repair",
                    .{ std.zig.fmtEscapes(jail.name), std.zig.fmtEscapes(report.path), report.failure },
                );
            };
            if (source == .journal and changed) {
                if (cause) |failure| {
                    if (!pipeline.Pipeline.commitBlocked(failure)) logJournalFailure(jail, failure, diagnostic);
                } else if (healthy and jail.last_journal_notice != null) {
                    jail.last_journal_notice = null;
                    std.log.info("journal source for jail '{'}' recovered", .{std.zig.fmtEscapes(jail.name)});
                }
            }
            try self.refreshSourceStatus(jail);
        }

        pub fn publishBlocked(self: *Coordinator, jail: *Jail, cause: anyerror) !void {
            if (jail.healthy or jail.source_error == null or jail.source_error.? != cause) try self.publishSource(jail);
        }

        pub fn startupSourceRefusal(self: *Coordinator, jail: *Jail, failure: anyerror) !bool {
            if (failure != error.SourceInterventionRequired) return false;
            const source = jail.session.?;
            if (source == .file) for (0..2 * source.file.sources.max_sources) |_| {
                _ = source.file.nextUnreportedContinuityFailure() orelse break;
            };
            try self.publishSource(jail);
            try self.logPausedAtStartup(jail);
            self.verify_jail += 1;
            return true;
        }

        fn logPausedAtStartup(self: *Coordinator, jail: *Jail) !void {
            const tail_unrepairable = "; other jails enforce; no offline repair applies to this cause; see fail2zig status";
            var logged = false;
            if (jail.session.? == .file) {
                const session = jail.session.?.file;
                for (session.repair_states[0..@min(session.repair_count, session.sources.sources.items.len)], 0..) |*state, index| {
                    const facts = session.pausedSource(index) orelse continue;
                    logged = true;
                    const cause = @errorName(state.snapshot().last_cause orelse error.SourceInterventionRequired);
                    var detail_buffer: [192]u8 = undefined;
                    const detail = switch (facts.cause) {
                        .resume_lost => try std.fmt.bufPrint(
                            &detail_buffer,
                            " (inode={d} committed_offset={d} size={})",
                            .{ facts.inode, facts.committed_offset, OptionalNumber{ .value = facts.observed_size } },
                        ),
                        .rotated_incarnation_lost => try std.fmt.bufPrint(
                            &detail_buffer,
                            " (removed inode={d} committed_offset={d} last_size={}; current inode={})",
                            .{ facts.inode, facts.committed_offset, OptionalNumber{ .value = facts.observed_size }, OptionalNumber{ .value = facts.current_inode } },
                        ),
                        .other => "",
                    };
                    const repair_line = if (facts.repair_token) |token| try repairCommand(self.allocator, jail.name, facts.path, token[0..facts.repair_token_len]) else null;
                    defer if (repair_line) |text| self.allocator.free(text);
                    if (repair_line != null and facts.path_absent)
                        std.log.warn(
                            "native: jail={} source=file path={} paused at startup: {s}{s}; the file is absent; other jails enforce; once a file exists at the path, stop fail2zig and run: {}",
                            .{ std.zig.fmtEscapes(jail.name), std.zig.fmtEscapes(facts.path), cause, detail, ControlEscaped{ .text = repair_line.? } },
                        )
                    else if (repair_line) |text|
                        std.log.warn(
                            "native: jail={} source=file path={} paused at startup: {s}{s}; other jails enforce; to repair, stop fail2zig and run: {}",
                            .{ std.zig.fmtEscapes(jail.name), std.zig.fmtEscapes(facts.path), cause, detail, ControlEscaped{ .text = text } },
                        )
                    else
                        std.log.warn(
                            "native: jail={} source=file path={} paused at startup: {s}{s}" ++ tail_unrepairable,
                            .{ std.zig.fmtEscapes(jail.name), std.zig.fmtEscapes(facts.path), cause, detail },
                        );
                }
            }
            if (logged) return;
            const snapshot = switch (jail.session.?) {
                .file => |session| session.repairSnapshot(),
                .journal => |session| session.repairSnapshot(),
                .internal => return,
            };
            std.log.warn(
                "native: jail={} source={s} paused at startup: {s}" ++ tail_unrepairable,
                .{ std.zig.fmtEscapes(jail.name), @tagName(jail.plan), @errorName(snapshot.last_cause orelse error.SourceInterventionRequired) },
            );
        }

        fn sourceSignature(source: Source) SourceSignature {
            var signature = SourceSignature{ .built = true };
            switch (source) {
                .file => |session| {
                    signature.sources = session.sources.sources.items.len;
                    signature.configured = session.sources.configuredCount();
                    signature.presence_revision = session.sources.presence_revision;
                    for (0..signature.configured) |i| {
                        const presence = session.sources.configuredStatus(i).?.presence;
                        if (presence == .unknown or presence == .failed) signature.presence_known = false;
                    }
                    for (session.repair_states[0..@min(session.repair_count, max_sources_per_jail)], 0..) |*state, index| {
                        const snapshot = state.snapshot();
                        if (snapshot.phase == .intervention) signature.causes[index] = snapshot.last_cause orelse error.SourceInterventionRequired;
                    }
                    const discovery = session.discovery_repair.snapshot();
                    if (discovery.phase == .intervention) signature.causes[max_sources_per_jail] = discovery.last_cause orelse error.SourceInterventionRequired;
                    if (session.recorded_loss) |loss| signature.loss_sequence = loss.sequence;
                },
                .journal => |session| {
                    const snapshot = session.repairSnapshot();
                    if (snapshot.phase == .intervention) signature.causes[max_sources_per_jail] = snapshot.last_cause orelse error.SourceInterventionRequired;
                },
                .internal => {},
            }
            return signature;
        }

        fn sameSignature(a: SourceSignature, b: SourceSignature) bool {
            return a.built == b.built and a.sources == b.sources and a.configured == b.configured and a.presence_revision == b.presence_revision and a.presence_known == b.presence_known and a.loss_sequence == b.loss_sequence and a.stuck == b.stuck and std.mem.eql(
                ?anyerror,
                &a.causes,
                &b.causes,
            );
        }

        pub fn refreshSourceStatus(self: *Coordinator, jail: *Jail) !void {
            const source = jail.session orelse return;
            var signature = sourceSignature(source);
            if (!jail.healthy and source != .internal and std.mem.allEqual(?anyerror, &signature.causes, null)) signature.stuck = jail.source_error;
            if (sameSignature(jail.source_signature, signature)) return self.refreshReadingOffsets(jail);
            var arena = std.heap.ArenaAllocator.init(self.allocator);
            errdefer arena.deinit();
            const entries = try self.buildSourceStatus(jail, arena.allocator(), signature.stuck);
            self.mutex.lock();
            const previous = jail.source_status_arena;
            jail.source_status = entries;
            jail.source_status_arena = arena;
            jail.source_signature = signature;
            self.mutex.unlock();
            if (previous) |old| {
                var released = old;
                released.deinit();
            }
        }

        fn refreshReadingOffsets(self: *Coordinator, jail: *Jail) void {
            if (jail.source_status.len == 0) return;
            const session = switch (jail.session orelse return) {
                .file => |value| value,
                else => return,
            };
            self.mutex.lock();
            defer self.mutex.unlock();
            for (jail.source_status) |*entry| {
                if (entry.state != .reading) continue;
                const path = entry.path orelse continue;
                for (session.sources.sources.items) |source| {
                    if (!std.mem.eql(u8, source.path, path)) continue;
                    const saved = source.committed orelse break;
                    entry.inode = saved.inode;
                    entry.committed_offset = saved.offset;
                    entry.observed_size = saved.observed_size;
                    break;
                }
            }
        }

        fn buildSourceStatus(self: *Coordinator, jail: *Jail, arena: std.mem.Allocator, stuck: ?anyerror) ![]SourceStatus {
            var list = std.ArrayListUnmanaged(SourceStatus){};
            switch (jail.session.?) {
                .file => |session| {
                    var paused_seen = false;
                    const count = @min(session.repair_count, session.sources.sources.items.len);
                    for (session.sources.sources.items[0..count], session.repair_states[0..count], 0..) |source, *state, index| {
                        const facts = session.pausedSource(index);
                        var newest: files.LossEvent = undefined;
                        const events = try self.store.continuitySummary(jail.name, source.path, &newest);
                        if (facts == null and events == 0) continue;
                        const path = try arena.dupe(u8, source.path);
                        var entry = SourceStatus{
                            .jail = jail.name,
                            .kind = .file,
                            .path = path,
                            .on_truncation = jail.on_truncation,
                            .state = .reading,
                            .cause = null,
                            .inode = null,
                            .committed_offset = null,
                            .observed_size = null,
                            .repair = null,
                            .loss_events = events,
                            .last_loss = null,
                        };
                        if (events != 0) {
                            newest.jail = jail.name;
                            newest.path = path;
                            newest.source_id = "";
                            entry.last_loss = newest;
                        }
                        if (facts) |paused| {
                            paused_seen = true;
                            entry.state = .paused;
                            entry.cause = @errorName(state.snapshot().last_cause orelse error.SourceInterventionRequired);
                            entry.inode = paused.inode;
                            entry.committed_offset = paused.committed_offset;
                            entry.observed_size = paused.observed_size;
                            if (paused.repair_token) |token| entry.repair = try repairCommand(arena, jail.name, source.path, token[0..paused.repair_token_len]);
                        } else if (source.committed) |saved| {
                            entry.inode = saved.inode;
                            entry.committed_offset = saved.offset;
                            entry.observed_size = saved.observed_size;
                        }
                        try list.append(arena, entry);
                    }
                    if (!paused_seen) {
                        const snapshot = session.repairSnapshot();
                        if (snapshot.phase == .intervention) try list.append(arena, pausedWithoutPath(jail, .file, snapshot.last_cause));
                    }
                    for (0..session.sources.configuredCount()) |i| {
                        const configured = session.sources.configuredStatus(i).?;
                        if (configured.presence != .missing) continue;
                        var paused = false;
                        for (list.items) |entry| if (entry.state == .paused and entry.path != null and std.mem.eql(u8, entry.path.?, configured.pattern)) {
                            paused = true;
                            break;
                        };
                        if (paused) continue;
                        try list.append(
                            arena,
                            .{
                                .jail = jail.name,
                                .kind = .file,
                                .path = try arena.dupe(u8, configured.pattern),
                                .on_truncation = jail.on_truncation,
                                .state = .missing,
                                .cause = null,
                                .inode = null,
                                .committed_offset = null,
                                .observed_size = null,
                                .repair = null,
                                .loss_events = 0,
                                .last_loss = null,
                            },
                        );
                    }
                },
                .journal => |session| {
                    const snapshot = session.repairSnapshot();
                    if (snapshot.phase == .intervention) try list.append(arena, pausedWithoutPath(jail, .journal, snapshot.last_cause));
                },
                .internal => {},
            }
            if (stuck) |cause| for (list.items) |entry| {
                if (entry.state == .paused) break;
            } else try list.append(arena, stuckWithoutPath(jail, cause));
            std.sort.pdq(SourceStatus, list.items, {}, sourceStatusLess);
            return list.toOwnedSlice(arena);
        }

        fn pausedWithoutPath(jail: *const Jail, kind: @FieldType(SourceStatus, "kind"), cause: ?anyerror) SourceStatus {
            return .{
                .jail = jail.name,
                .kind = kind,
                .path = null,
                .on_truncation = if (kind == .file) jail.on_truncation else null,
                .state = .paused,
                .cause = @errorName(cause orelse error.SourceInterventionRequired),
                .inode = null,
                .committed_offset = null,
                .observed_size = null,
                .repair = null,
                .loss_events = 0,
                .last_loss = null,
            };
        }

        fn stuckWithoutPath(jail: *const Jail, cause: anyerror) SourceStatus {
            const kind: @FieldType(SourceStatus, "kind") = if (jail.plan == .journal) .journal else .file;
            return .{
                .jail = jail.name,
                .kind = kind,
                .path = null,
                .on_truncation = if (kind == .file) jail.on_truncation else null,
                .state = if (pipeline.Pipeline.commitBlocked(cause)) .waiting else .broken,
                .cause = @errorName(cause),
                .inode = null,
                .committed_offset = null,
                .observed_size = null,
                .repair = null,
                .loss_events = 0,
                .last_loss = null,
            };
        }

        fn sourceStatusLess(_: void, a: SourceStatus, b: SourceStatus) bool {
            return std.mem.lessThan(u8, a.path orelse "", b.path orelse "");
        }

        fn writeShellArgument(writer: anytype, argument: []const u8) !void {
            const bare = argument.len != 0 and for (argument) |byte| {
                if (std.mem.indexOfScalar(u8, shell_safe, byte) == null) break false;
            } else true;
            if (bare) return writer.writeAll(argument);
            try writer.writeByte('\'');
            for (argument) |byte| {
                if (byte == '\'') try writer.writeAll("'\\''") else try writer.writeByte(byte);
            }
            try writer.writeByte('\'');
        }

        fn repairCommand(allocator: std.mem.Allocator, jail: []const u8, path: []const u8, token: []const u8) ![]u8 {
            var text = std.ArrayList(u8).init(allocator);
            errdefer text.deinit();
            const writer = text.writer();
            try writer.writeAll("fail2zig repair-source --jail ");
            try writeShellArgument(writer, jail);
            try writer.writeAll(" --source ");
            try writeShellArgument(writer, path);
            try writer.writeAll(" --token ");
            try writeShellArgument(writer, token);
            try writer.writeAll(" --acknowledge-truncation");
            return text.toOwnedSlice();
        }

        fn writePausedStatus(self: *Coordinator, writer: anytype) !bool {
            var paused: usize = 0;
            var first: ?SourceStatus = null;
            for (self.jails) |*jail| for (jail.source_status) |entry| if (entry.state == .paused) {
                if (first == null) first = entry;
                paused += 1;
            };
            const only = first orelse return false;
            if (paused == 1) {
                try writer.print("Enforcing; 1 source paused: {}", .{std.zig.fmtEscapes(only.jail)});
                if (only.path) |path| try writer.print(" {}", .{std.zig.fmtEscapes(path)});
                try writer.print(" ({s}); see fail2zig status", .{only.cause orelse "SourceInterventionRequired"});
                return true;
            }
            try writer.print("Enforcing; {d} sources paused (", .{paused});
            var listed: usize = 0;
            var previous: []const u8 = "";
            for (self.jails) |*jail| for (jail.source_status) |entry| if (entry.state == .paused) {
                if (listed != 0 and std.mem.eql(u8, previous, entry.jail)) continue;
                if (listed != 0) try writer.writeAll(", ");
                try writer.print("{}", .{std.zig.fmtEscapes(entry.jail)});
                previous = entry.jail;
                listed += 1;
            };
            try writer.writeAll("); see fail2zig status");
            return true;
        }

        pub fn journalFailureDetail(jail: *const Jail, failure: anyerror) ?journal_sessions.FailureDiagnostic {
            const source = jail.session orelse return null;
            return switch (source) {
                .journal => |value| if (value.failureDiagnostic()) |detail| (if (detail.cause == failure) detail else null) else null,
                else => null,
            };
        }

        pub fn logJournalFailure(jail: *Jail, failure: anyerror, diagnostic: ?journal_sessions.FailureDiagnostic) void {
            const notice = diagnostic orelse journal_sessions.FailureDiagnostic{ .cause = failure, .exit_code = null, .signal = null, .stderr_present = false };
            if (std.meta.eql(jail.last_journal_notice, @as(?journal_sessions.FailureDiagnostic, notice))) return;
            jail.last_journal_notice = notice;
            std.log.warn("journal source for jail '{'}' is unhealthy: {s}; journalctl exit={?d}, signal={?d}, stderr_present={}; inspect journal access and selection", .{
                std.zig.fmtEscapes(jail.name),                             @errorName(failure),
                if (diagnostic) |detail| detail.exit_code else null,       if (diagnostic) |detail| detail.signal else null,
                if (diagnostic) |detail| detail.stderr_present else false,
            });
        }

        pub fn publishHealth(self: *Coordinator) void {
            const snapshot = self.gate.snapshot();
            var next_expiry: ?i64 = null;
            var expiry_current = self.effects == null;
            if (self.effects) |manager| {
                expiry_current = !self.store.reopen_required and manager.cached_epoch != null and manager.cached_epoch.? == self.store.effect_publication_epoch;
                if (expiry_current) for (manager.live[0..manager.count]) |entry| {
                    if (entry.status == .expired or entry.status == .absent or entry.status == .superseded) continue;
                    if (entry.desired == .finite) next_expiry = if (next_expiry) |prior| @min(prior, entry.desired.finite) else entry.desired.finite;
                };
            }
            self.mutex.lock();
            var wall_floor = snapshot.receipt_clock_floor_us;
            if (self.effects) |manager| wall_floor = if (wall_floor) |floor| @max(floor, manager.last_wall_us) else manager.last_wall_us;
            if (self.store_open) {
                if (self.store.consumer_clock_floor_us) |floor| wall_floor = if (wall_floor) |prior| @max(prior, floor) else floor;
            }
            if (wall_floor) |floor| self.worker_observation.wall_floor_us = if (self.worker_observation.wall_floor_us) |prior| @max(prior, floor) else floor;
            self.worker_observation.publication(observationMs(), self.observationWall(), next_expiry, expiry_current);
            self.published_health = snapshot;
            if (self.effects) |manager| {
                self.published_effects = manager.status;
                if (manager.cached_epoch == null or manager.cached_epoch.? != self.store.effect_publication_epoch) self.published_effects.?.ready = false;
                self.published_backend = @tagName(manager.installation.backend);
                self.published_view = .{
                    .readback_ns = manager.last_readback_ns,
                    .readback_wall_us = manager.last_readback_wall_us,
                    .installed_live = manager.installed_live,
                    .pending = manager.counters.pending,
                    .oldest_pending_us = manager.counters.oldest_pending_us,
                    .overdue = manager.counters.overdue,
                    .oldest_overdue_us = manager.counters.oldest_overdue_us,
                    .overdue_blocking = manager.counters.overdue_blocking,
                    .oldest_overdue_blocking_us = manager.counters.oldest_overdue_blocking_us,
                    .dump_interrupted = manager.counters.dump_interrupted,
                    .verify_interval_ns = manager.verify_interval_ns,
                    .wake_interval_ns = manager.wake_interval_ns,
                    .transient_uncertain = manager.status.uncertain and manager.status.cause != null and effect_runtime.transientCause(manager.status.cause.?),
                    .events_subscribed = manager.events_subscribed,
                    .events_healthy = manager.events_healthy,
                };
                self.published_stats = .{
                    .available = true,
                    .reason = null,
                    .backend = @tagName(manager.installation.backend),
                    .view_ready = self.published_effects.?.ready,
                    .view_entries = manager.count,
                    .last_observed_installed = manager.installed_live,
                    .pending_live_dispatches = manager.counters.pending,
                    .overdue_blocking_removals = manager.counters.overdue_blocking,
                    .overdue_bookkeeping = manager.counters.overdue_bookkeeping,
                    .accepted_readbacks = manager.counters.full_readbacks,
                    .dump_interruptions = manager.counters.dump_interrupted,
                    .acknowledged_batches = manager.counters.acknowledged_batches,
                    .events_applied = manager.counters.events_applied,
                    .events_dropped = manager.counters.events_dropped,
                    .view_rebuilds = manager.counters.rebuilds_completed,
                    .view_restarts = manager.counters.rebuild_restarts,
                    .incremental_updates = manager.counters.incremental_updates,
                    .expiry_batches = manager.counters.expiry_batches,
                    .expiries_prepared = manager.counters.expiries_prepared,
                    .retirement_batches = self.retire_batches,
                    .retry_subjects_retired = self.retired_total,
                    .retry_subjects_examined = self.retire_examined,
                    .retirement_pinned_state = self.retire_pinned_state,
                    .retirement_pinned_effect = self.retire_pinned_effect,
                    .retirement_refused = self.retire_refused,
                };
                self.stats_published_ms = observationMs();
                self.stats_generation = self.published_generation;
            }
            self.mutex.unlock();
            if (self.effects) |manager| {
                const detail = manager.status.diagnostic;
                if (!std.meta.eql(self.last_effect_notice, detail)) {
                    if (detail) |failure| {
                        std.log.warn("firewall {s}: {s} failed ({s}); mutation={s}; enforcement confirmation pending", .{
                            @tagName(failure.backend), @tagName(failure.stage), @errorName(failure.cause), @tagName(failure.mutation),
                        });
                    } else if (manager.status.ready) {
                        std.log.info("firewall {s}: readback recovered", .{@tagName(manager.installation.backend)});
                    }
                    self.last_effect_notice = detail;
                }
            }
            if (snapshot.notice_sequence != self.last_notice) {
                self.last_notice = snapshot.notice_sequence;
                std.log.info(
                    "native ingestion: {s}; cause={s}; committed={d}",
                    .{ @tagName(snapshot.phase), if (snapshot.last_failure) |failure| @errorName(failure.cause) else "none", snapshot.committed_records },
                );
            }
            // Holds: READY is sent once, and only after readinessReport reports every component verified.
            if (!self.notified_ready) {
                const report = self.readinessReport();
                if (report.ready) {
                    self.notified_ready = true;
                    if (comptime build_options.diag) diag_mod.startupReady();
                    if (self.startup_progress) |progress| progress.finish();
                    if (self.notifier) |notifier| {
                        var text_buffer: [4 * sd_notify.max_status_bytes]u8 = undefined;
                        var stream = std.io.fixedBufferStream(&text_buffer);
                        const paused = self.writePausedStatus(stream.writer()) catch |err| switch (err) {
                            error.NoSpaceLeft => true,
                        };
                        _ = (if (paused) notifier.readyWithStatus(stream.getWritten()) else notifier.ready()) catch |err| std.log.warn("sd_notify READY failed: {s}", .{@errorName(err)});
                    }
                    std.log.info("native: ready; all readiness components verified", .{});
                } else self.reportReadinessProgress(report);
            }
            self.notifyReloadReady();
        }
    };
}

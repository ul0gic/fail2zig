// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Durable migration journal over the schema-23 run/step tables. Intent is
//! written before every mutation and the observed outcome after it, so a
//! resumed command classifies by inspecting durable and observed state rather
//! than replaying a step whose effect it cannot see.
const std = @import("std");
const durable = @import("../core/record_store.zig");

pub const Store = durable.Store;
pub const State = Store.MigrationState;
pub const Step = Store.MigrationStep;
pub const Outcome = Store.MigrationOutcome;
pub const StepRow = Store.MigrationStepRow;
pub const StagedCounts = Store.StagedCounts;

pub const report_version: u32 = 1;
pub const max_steps: usize = 64;
pub const max_detail_bytes: usize = 4096;
pub const max_recovery_point_bytes: usize = 4096;

pub const Error = durable.Error || error{
    AlreadyExists,
    RunMissing,
    StepOpen,
    StepMissing,
    NoPendingStep,
    ClockReversed,
    DetailTooLarge,
    IncompatibleHost,
    IncompatibleSourceDb,
    IncompatibleSourceConfig,
    IncompatiblePlan,
    IncompatibleGeneration,
    TooManySteps,
    ObserverFailed,
};

/// Observable inputs that must match before a run may continue.
pub const Identity = struct {
    host_id: [32]u8,
    source_db_fp: [32]u8,
    source_cfg_fp: [32]u8,
    plan_fp: [32]u8,
    recovery_point: []const u8,
    generation: [32]u8,
};

/// `sha256("fail2zig-migration-host-v1" ‖ machine_id ‖ 0x00 ‖ hostname)`. Both
/// inputs are trimmed; a missing machine id hashes as empty so the host id is
/// still stable per hostname, and any change to either refuses resume.
pub fn hostId(machine_id: []const u8, hostname: []const u8) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("fail2zig-migration-host-v1");
    hasher.update(std.mem.trim(u8, machine_id, " \r\n\t"));
    hasher.update(&[_]u8{0});
    hasher.update(std.mem.trim(u8, hostname, " \r\n\t"));
    return hasher.finalResult();
}

/// Host id from `/etc/machine-id` and the kernel hostname.
pub fn localHostId() [32]u8 {
    var machine: [64]u8 = undefined;
    const machine_id = blk: {
        const file = std.fs.openFileAbsolute("/etc/machine-id", .{}) catch break :blk "";
        defer file.close();
        const n = file.readAll(&machine) catch break :blk "";
        break :blk machine[0..n];
    };
    var name_buffer: [std.posix.HOST_NAME_MAX]u8 = undefined;
    const hostname = std.posix.gethostname(&name_buffer) catch "";
    return hostId(machine_id, hostname);
}

pub const Protection = enum { present, absent, partial, uncertain, unknown };

/// What the caller observed after inspecting real state for one step.
pub const Observation = struct {
    destination: Protection = .unknown,
    source: Protection = .unknown,
    detail: []const u8 = "",
};

/// Kernel/owner readback supplied by the caller; the journal never reaches the
/// firewall itself. Called only for steps whose effect is outside the store.
pub const Observer = struct {
    ctx: ?*anyopaque,
    observe: *const fn (ctx: ?*anyopaque, step: Step, run: *const Store.MigrationRun, staged: StagedCounts) anyerror!Observation,
};

pub const Refusal = struct { reason: []const u8, step: ?Step };

pub const Resume = union(enum) {
    /// Nothing is pending; the next step to run.
    continue_from: Step,
    /// The interrupted step left no durable effect and is safe to run again.
    repeat_step: Step,
    /// The run cannot proceed automatically; the reason names why.
    refuse: Refusal,
    /// A mutation left partial effect; the operator must restore the recovery point.
    rollback_required: Refusal,
    complete,
    rolled_back,
};

pub const Pending = struct { seq: u64, step: Step, started_us: i64 };

pub const Journal = struct {
    store: *Store,
    allocator: std.mem.Allocator,
    run: Store.MigrationRun,
    last_observation: Observation = .{},

    /// Records a new run. Fingerprints are stored verbatim; `now_us` is both
    /// created and updated time so the store's ordering check always holds.
    pub fn create(allocator: std.mem.Allocator, store: *Store, run_id: [32]u8, identity: Identity, now_us: i64) Error!Journal {
        if (identity.recovery_point.len > max_recovery_point_bytes) return error.DetailTooLarge;
        if (now_us < 0) return error.ClockReversed;
        const recovery_point = try allocator.dupe(u8, identity.recovery_point);
        errdefer allocator.free(recovery_point);
        const run = Store.MigrationRun{
            .run_id = run_id,
            .host_id = identity.host_id,
            .source_db_fp = identity.source_db_fp,
            .source_cfg_fp = identity.source_cfg_fp,
            .plan_fp = identity.plan_fp,
            .recovery_point = recovery_point,
            .generation = identity.generation,
            .state = .planned,
            .created_us = now_us,
            .updated_us = now_us,
        };
        store.createMigrationRun(run) catch |err| return switch (err) {
            error.MigrationRunExists => error.AlreadyExists,
            else => err,
        };
        return .{ .store = store, .allocator = allocator, .run = run };
    }

    /// Reopens an existing run and refuses unless every fingerprint still
    /// matches the inputs the caller can observe now. Host first: a run
    /// journal copied to another machine must never drive that machine.
    pub fn open(allocator: std.mem.Allocator, store: *Store, run_id: [32]u8, identity: Identity) Error!Journal {
        const run = (try store.migrationRun(allocator, run_id)) orelse return error.RunMissing;
        errdefer allocator.free(run.recovery_point);
        if (!std.mem.eql(u8, &run.host_id, &identity.host_id)) return error.IncompatibleHost;
        if (!std.mem.eql(u8, &run.source_db_fp, &identity.source_db_fp)) return error.IncompatibleSourceDb;
        if (!std.mem.eql(u8, &run.source_cfg_fp, &identity.source_cfg_fp)) return error.IncompatibleSourceConfig;
        if (!std.mem.eql(u8, &run.plan_fp, &identity.plan_fp)) return error.IncompatiblePlan;
        if (!std.mem.eql(u8, &run.generation, &identity.generation)) return error.IncompatibleGeneration;
        if (run.updated_us < run.created_us) return error.ClockReversed;
        return .{ .store = store, .allocator = allocator, .run = run };
    }

    pub fn deinit(self: *Journal) void {
        self.allocator.free(self.run.recovery_point);
        self.* = undefined;
    }

    pub fn runId(self: *const Journal) [32]u8 {
        return self.run.run_id;
    }

    pub fn state(self: *const Journal) State {
        return self.run.state;
    }

    /// Writes the intent of `step` durably before the caller performs it.
    pub fn begin(self: *Journal, step: Step, intent: []const u8, now_us: i64) Error!Pending {
        if (intent.len > max_detail_bytes) return error.DetailTooLarge;
        if (now_us < 0 or now_us < self.run.updated_us) return error.ClockReversed;
        const seq = self.store.beginMigrationStep(self.run.run_id, step, intent, now_us) catch |err| return switch (err) {
            error.MigrationStepOpen => error.StepOpen,
            error.MigrationRunMissing => error.RunMissing,
            else => err,
        };
        self.run.updated_us = now_us;
        return .{ .seq = seq, .step = step, .started_us = now_us };
    }

    /// Settles a pending step with what was actually observed. The store
    /// refuses a finish time before the start time; that is reported as
    /// `ClockReversed` here before any write is attempted.
    pub fn finish(self: *Journal, pending: Pending, outcome: Outcome, detail: []const u8, new_state: ?State, now_us: i64) Error!void {
        if (outcome == .pending) return error.InvalidMigrationRow;
        if (detail.len > max_detail_bytes) return error.DetailTooLarge;
        if (now_us < pending.started_us) return error.ClockReversed;
        self.store.finishMigrationStep(self.run.run_id, pending.seq, outcome, detail, new_state, now_us) catch |err| return switch (err) {
            error.MigrationStepMissing => error.StepMissing,
            error.MigrationRunMissing => error.RunMissing,
            else => err,
        };
        if (new_state) |value| self.run.state = value;
        self.run.updated_us = @max(self.run.updated_us, now_us);
    }

    /// Steps in sequence order, bounded to `max_steps`.
    pub fn steps(self: *Journal, output: *[max_steps]StepRow) Error![]StepRow {
        const count = try self.store.migrationSteps(self.run.run_id, output);
        return output[0..count];
    }

    pub fn pendingStep(self: *Journal) Error!?Pending {
        var rows: [max_steps]StepRow = undefined;
        const listed = try self.steps(&rows);
        if (listed.len == max_steps) return error.TooManySteps;
        for (listed) |row| if (row.outcome == .pending) return .{ .seq = row.seq, .step = row.step, .started_us = row.started_us };
        return null;
    }

    /// Classifies an interrupted or finished run. A pending step is settled
    /// with the outcome the inspection supports and the decision says what a
    /// caller may do next; a completed mutation is never scheduled again.
    pub fn classify(self: *Journal, observer: Observer, now_us: i64) Error!Resume {
        var rows: [max_steps]StepRow = undefined;
        const listed = try self.steps(&rows);
        if (listed.len == max_steps) return error.TooManySteps;

        var open_step: ?StepRow = null;
        var last_settled: ?StepRow = null;
        for (listed) |row| {
            if (row.outcome == .pending) open_step = row else last_settled = row;
        }

        if (open_step) |row| return self.settleInterrupted(row, observer, now_us);

        switch (self.run.state) {
            .complete => return .complete,
            .rolled_back => return .rolled_back,
            .failed => return .{ .refuse = .{ .reason = "run-failed", .step = if (last_settled) |s| s.step else null } },
            else => {},
        }
        const last = last_settled orelse return .{ .continue_from = .validate_plan };
        return switch (last.outcome) {
            .success => if (nextStep(last.step)) |next| .{ .continue_from = next } else .complete,
            .partial => .{ .rollback_required = .{ .reason = "partial-effect-recorded", .step = last.step } },
            .rollback_failed => .{ .refuse = .{ .reason = "rollback-failed-manual-recovery", .step = last.step } },
            .uncertain => .{ .refuse = .{ .reason = "uncertain-effect-recorded", .step = last.step } },
            .incompatible, .validation_failed, .operational_failure => .{ .refuse = .{ .reason = "prior-step-failed", .step = last.step } },
            .pending => error.InvalidMigrationRow,
        };
    }

    fn settleInterrupted(self: *Journal, row: StepRow, observer: Observer, now_us: i64) Error!Resume {
        const pending_step = Pending{ .seq = row.seq, .step = row.step, .started_us = row.started_us };
        if (now_us < row.started_us) return error.ClockReversed;
        switch (row.step) {
            // No durable effect precedes these; the interruption is recorded and the step reruns.
            .validate_plan, .check_drift, .capture_recovery_point, .verify_protection => {
                try self.finish(pending_step, .operational_failure, "interrupted-before-outcome", null, now_us);
                return .{ .repeat_step = row.step };
            },
            .stage_destination => {
                const staged = try self.store.stagedMigrationCounts(self.run.run_id);
                // Staging is one transaction: any rows mean the whole staging committed.
                if (staged.owners != 0 or staged.history != 0) {
                    try self.finish(pending_step, .success, "staged-rows-present-after-interruption", .staged, now_us);
                    return .{ .continue_from = .activate_owners };
                }
                try self.finish(pending_step, .operational_failure, "no-staged-rows-after-interruption", null, now_us);
                return .{ .repeat_step = .stage_destination };
            },
            .quiesce_source, .activate_owners, .complete, .rollback => {
                const staged = try self.store.stagedMigrationCounts(self.run.run_id);
                const observed = observer.observe(observer.ctx, row.step, &self.run, staged) catch return error.ObserverFailed;
                if (observed.detail.len > max_detail_bytes) return error.DetailTooLarge;
                self.last_observation = observed;
                return self.settleObserved(pending_step, observed, now_us);
            },
        }
    }

    fn settleObserved(self: *Journal, pending_step: Pending, observed: Observation, now_us: i64) Error!Resume {
        const step = pending_step.step;
        const relevant: Protection = switch (step) {
            .quiesce_source, .rollback => observed.source,
            else => observed.destination,
        };
        switch (step) {
            .quiesce_source => switch (relevant) {
                .present, .partial => {
                    try self.finish(pending_step, .success, observed.detail, .quiesced, now_us);
                    return .{ .continue_from = .stage_destination };
                },
                // Stopping source ingestion is repeatable; nothing durable was changed.
                .absent, .unknown, .uncertain => {
                    try self.finish(pending_step, .operational_failure, observed.detail, null, now_us);
                    return .{ .repeat_step = .quiesce_source };
                },
            },
            .activate_owners => switch (relevant) {
                .present => {
                    try self.finish(pending_step, .success, observed.detail, .activating, now_us);
                    return .{ .continue_from = .verify_protection };
                },
                // Activation replays exactly from the staged rows, so an absent effect may rerun.
                .absent => {
                    try self.finish(pending_step, .operational_failure, observed.detail, null, now_us);
                    return .{ .repeat_step = .activate_owners };
                },
                .partial => {
                    try self.finish(pending_step, .partial, observed.detail, null, now_us);
                    return .{ .rollback_required = .{ .reason = "activation-partial", .step = step } };
                },
                .uncertain, .unknown => {
                    try self.finish(pending_step, .uncertain, observed.detail, null, now_us);
                    return .{ .refuse = .{ .reason = "activation-uncertain-inspect-before-retry", .step = step } };
                },
            },
            .complete => switch (relevant) {
                .present => {
                    try self.finish(pending_step, .success, observed.detail, .complete, now_us);
                    return .complete;
                },
                else => {
                    try self.finish(pending_step, .uncertain, observed.detail, null, now_us);
                    return .{ .refuse = .{ .reason = "completion-unverified", .step = step } };
                },
            },
            .rollback => switch (relevant) {
                .present => {
                    try self.finish(pending_step, .success, observed.detail, .rolled_back, now_us);
                    return .rolled_back;
                },
                .absent, .partial => {
                    try self.finish(pending_step, .rollback_failed, observed.detail, .failed, now_us);
                    return .{ .refuse = .{ .reason = "rollback-failed-manual-recovery", .step = step } };
                },
                .uncertain, .unknown => {
                    try self.finish(pending_step, .uncertain, observed.detail, null, now_us);
                    return .{ .refuse = .{ .reason = "rollback-unverified", .step = step } };
                },
            },
            else => return error.InvalidMigrationRow,
        }
    }

    /// Versioned operator report; `blockers` carries the refusal reasons the
    /// caller collected. Sizes are bounded by `max_steps` and the store limits.
    pub fn report(self: *Journal, allocator: std.mem.Allocator, blockers: []const []const u8) Error!Report {
        var rows: [max_steps]StepRow = undefined;
        const listed = try self.steps(&rows);
        const owned = try allocator.alloc(ReportStep, listed.len);
        errdefer allocator.free(owned);
        var overall: Outcome = .pending;
        for (listed, 0..) |row, i| {
            owned[i] = .{ .seq = row.seq, .step = row.step, .outcome = row.outcome, .started_us = row.started_us, .finished_us = row.finished_us };
            overall = row.outcome;
        }
        return .{
            .run_id_hex = std.fmt.bytesToHex(self.run.run_id, .lower),
            .state = self.run.state,
            .steps = owned,
            .truncated = listed.len == max_steps,
            .outcome = overall,
            .observed_protection = .{ .destination = self.last_observation.destination, .source = self.last_observation.source },
            .blockers = blockers,
            .created_us = self.run.created_us,
            .updated_us = self.run.updated_us,
        };
    }
};

/// Fixed forward order; `rollback` is entered only by explicit decision.
pub fn nextStep(step: Step) ?Step {
    return switch (step) {
        .validate_plan => .check_drift,
        .check_drift => .capture_recovery_point,
        .capture_recovery_point => .quiesce_source,
        .quiesce_source => .stage_destination,
        .stage_destination => .activate_owners,
        .activate_owners => .verify_protection,
        .verify_protection => .complete,
        .complete, .rollback => null,
    };
}

/// True for steps whose effect lives outside the journal's own tables.
pub fn mutates(step: Step) bool {
    return switch (step) {
        .validate_plan, .check_drift, .verify_protection => false,
        .capture_recovery_point, .quiesce_source, .stage_destination, .activate_owners, .complete, .rollback => true,
    };
}

pub const ReportStep = struct {
    seq: u64,
    step: Step,
    outcome: Outcome,
    started_us: i64,
    finished_us: ?i64,
};

pub const ObservedProtection = struct { destination: Protection, source: Protection };

pub const Report = struct {
    report_version: u32 = report_version,
    run_id_hex: [64]u8,
    state: State,
    steps: []const ReportStep,
    truncated: bool,
    outcome: Outcome,
    observed_protection: ObservedProtection,
    blockers: []const []const u8,
    created_us: i64,
    updated_us: i64,

    pub fn deinit(self: *Report, allocator: std.mem.Allocator) void {
        allocator.free(self.steps);
        self.* = undefined;
    }

    /// Enums serialize as their names; `run_id_hex` as a string.
    pub fn writeJson(self: *const Report, writer: anytype) !void {
        var out = std.json.writeStream(writer, .{});
        try out.beginObject();
        try out.objectField("report_version");
        try out.write(self.report_version);
        try out.objectField("run_id");
        try out.write(&self.run_id_hex);
        try out.objectField("state");
        try out.write(@tagName(self.state));
        try out.objectField("outcome");
        try out.write(@tagName(self.outcome));
        try out.objectField("created_us");
        try out.write(self.created_us);
        try out.objectField("updated_us");
        try out.write(self.updated_us);
        try out.objectField("steps");
        try out.beginArray();
        for (self.steps) |step| {
            try out.beginObject();
            try out.objectField("seq");
            try out.write(step.seq);
            try out.objectField("step");
            try out.write(@tagName(step.step));
            try out.objectField("outcome");
            try out.write(@tagName(step.outcome));
            try out.objectField("started_us");
            try out.write(step.started_us);
            try out.objectField("finished_us");
            try out.write(step.finished_us);
            try out.endObject();
        }
        try out.endArray();
        try out.objectField("steps_truncated");
        try out.write(self.truncated);
        try out.objectField("observed_protection");
        try out.beginObject();
        try out.objectField("destination");
        try out.write(@tagName(self.observed_protection.destination));
        try out.objectField("source");
        try out.write(@tagName(self.observed_protection.source));
        try out.endObject();
        try out.objectField("blockers");
        try out.beginArray();
        for (self.blockers) |blocker| try out.write(blocker);
        try out.endArray();
        try out.endObject();
    }
};

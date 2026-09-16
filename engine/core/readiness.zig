// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const storage_health = @import("storage_health.zig");

pub const Component = enum(u3) {
    config = 0,
    storage = 1,
    sources = 2,
    clock = 3,
    enforcement = 4,
    admin = 5,

    pub const count = 6;

    pub fn name(self: Component) []const u8 {
        return @tagName(self);
    }
};

pub const State = enum {
    ok,
    degraded,
    failed,
    unknown,

    pub fn name(self: State) []const u8 {
        return @tagName(self);
    }
};

pub const Jail = struct {
    healthy: bool,
    source_error: bool,
    enforce: bool,
};

pub const Effects = struct {
    ready: bool,
    uncertain: bool,
    overdue: bool,
};

pub const Inputs = struct {
    config_loaded: bool,
    storage_phase: ?storage_health.Phase,
    worker: ?storage_health.WorkerStatus,
    jails: []const Jail,
    effects: ?Effects,
    admin_generation_admitted: bool,
    admin_serving: bool = true,
};

pub const Report = struct {
    components: [Component.count]State,
    ready: bool,
    cause: ?[]const u8,

    pub fn state(self: Report, component: Component) State {
        return self.components[@intFromEnum(component)];
    }
};

pub fn derive(inputs: Inputs) Report {
    var components: [Component.count]State = undefined;
    var cause: ?[]const u8 = null;

    const config: Verdict = if (inputs.config_loaded) .{ .state = .ok } else .{ .state = .failed, .cause = "configuration not admitted" };
    const storage = deriveStorage(inputs.storage_phase, inputs.worker);
    const sources = deriveSources(inputs.jails);
    const clock = deriveClock(inputs.worker);
    const enforcement = deriveEnforcement(inputs.jails, inputs.effects);
    const admin = deriveAdmin(inputs.admin_generation_admitted, inputs.admin_serving);

    const verdicts = [Component.count]Verdict{ config, storage, sources, clock, enforcement, admin };
    for (verdicts, 0..) |v, i| {
        components[i] = v.state;
        if (cause == null and v.state != .ok) cause = v.cause;
    }
    return .{ .components = components, .ready = cause == null, .cause = cause };
}

const Verdict = struct {
    state: State,
    cause: ?[]const u8 = null,
};

fn deriveStorage(phase: ?storage_health.Phase, worker: ?storage_health.WorkerStatus) Verdict {
    const p = phase orelse return .{ .state = .unknown, .cause = "storage not yet published" };
    return switch (p) {
        .starting => .{ .state = .unknown, .cause = "storage starting" },
        .healthy => if (worker != null and worker.?.stalled)
            .{ .state = .degraded, .cause = "storage worker stalled" }
        else
            .{ .state = .ok },
        .paused => .{ .state = .degraded, .cause = "storage paused" },
        .recovering => .{ .state = .degraded, .cause = "storage recovering" },
        .intervention => .{ .state = .failed, .cause = "storage requires intervention" },
    };
}

fn deriveSources(jails: []const Jail) Verdict {
    if (jails.len == 0) return .{ .state = .unknown, .cause = "no enabled jail sources" };
    var waiting = false;
    for (jails) |jail| {
        if (jail.source_error) return .{ .state = .failed, .cause = "source continuity lost" };
        if (!jail.healthy) waiting = true;
    }
    if (waiting) return .{ .state = .degraded, .cause = "source not yet admitted" };
    return .{ .state = .ok };
}

fn deriveClock(worker: ?storage_health.WorkerStatus) Verdict {
    const w = worker orelse return .{ .state = .unknown, .cause = "clock not yet observed" };
    if (w.clock_uncertain) return .{ .state = .failed, .cause = "clock uncertain" };
    return .{ .state = .ok };
}

fn deriveEnforcement(jails: []const Jail, effects: ?Effects) Verdict {
    var enforcing = false;
    for (jails) |jail| {
        if (jail.enforce) enforcing = true;
    }
    if (!enforcing) return .{ .state = .ok };
    const e = effects orelse return .{ .state = .unknown, .cause = "enforcement not yet reported" };
    if (!e.ready) return .{ .state = .failed, .cause = "enforcement backend unavailable" };
    if (e.uncertain) return .{ .state = .degraded, .cause = "enforcement effects uncertain" };
    if (e.overdue) return .{ .state = .degraded, .cause = "enforcement expiries overdue" };
    return .{ .state = .ok };
}

fn deriveAdmin(generation_admitted: bool, serving: bool) Verdict {
    if (!generation_admitted) return .{ .state = .failed, .cause = "administrative generation not admitted" };
    if (!serving) return .{ .state = .degraded, .cause = "administrative socket refusing new connections" };
    return .{ .state = .ok };
}

pub const schema_version: u32 = 1;

pub fn writeJson(report: Report, writer: anytype) @TypeOf(writer).Error!void {
    try writer.print("{{\"schema_version\":{d},\"ready\":{s},\"components\":{{", .{ schema_version, if (report.ready) "true" else "false" });
    inline for (std.meta.fields(Component), 0..) |field, i| {
        if (i != 0) try writer.writeByte(',');
        try writer.print("\"{s}\":\"{s}\"", .{ field.name, report.components[i].name() });
    }
    try writer.writeAll("},\"cause\":");
    if (report.cause) |cause| {
        try writer.writeByte('"');
        try std.json.encodeJsonStringChars(cause, .{}, writer);
        try writer.writeByte('"');
    } else {
        try writer.writeAll("null");
    }
    try writer.writeByte('}');
}

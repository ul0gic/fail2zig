// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Internal effective-config projection for the qualified native journal path.
//! Host identity/executables are explicit inputs, not guessed from message tags.
const std = @import("std");
const config = @import("native.zig");
const builtin = @import("../core/native_builtin_detector.zig");
const journal = @import("../core/native_journal_detector.zig");
const origin = @import("../core/native_journal_origin.zig");
const session = @import("../core/native_journal_session.zig");
const processing = @import("../core/native_source_processor.zig");
const transport = @import("../core/native_journal_transport.zig");
pub const Settings = struct {
    machine_id: []const u8,
    executables: []const []const u8,
    journal: transport.Options = .{},
    source_id: []const u8 = "system-journal",
    ignore_capacity: usize,
    max_record_bytes: u32 = 2048,
    max_decoded_bytes: u32 = 2048,
};
pub const Plan = struct {
    allocator: std.mem.Allocator,
    base: builtin.Detector,
    qualified: journal.Detector,
    processing: processing.Options,
    journal: transport.Options,
    source_id: []const u8,

    /// Stable owner: the qualified consumer points to this plan's base detector.
    /// Immutable configuration and executable-path slices must outlive the plan.
    /// Preparation performs no source IO, database mutation or command execution.
    pub fn create(a: std.mem.Allocator, cfg: *const config.Config, jail_index: usize, parent: [32]u8, settings: Settings) !*Plan {
        if (jail_index >= cfg.jails.len) return error.UnknownJail;
        const jail = &cfg.jails[jail_index];
        if (!jail.enabled) return error.DisabledJail;
        if (jail.name.len == 0 or jail.name.len > 64 or std.mem.indexOfScalar(u8, jail.name, 0) != null) return error.InvalidJail;
        if (cfg.global.compatibility_pending or jail.compatibility_pending) return error.CompatibilityNotAdmitted;
        const source = if (jail.source == .auto) cfg.defaults.source else jail.source;
        if (source == .auto) return error.SourceSelectionRequired;
        if (source != .journald) return error.InvalidJournalSource;
        if (settings.source_id.len == 0 or settings.source_id.len > 512 or std.mem.indexOfScalar(u8, settings.source_id, 0) != null) return error.InvalidJournalSource;
        if (settings.max_record_bytes == 0 or settings.max_record_bytes > 64 * 1024 or settings.max_decoded_bytes == 0 or settings.max_decoded_bytes > 64 * 1024) return error.InvalidJournalProcessing;
        const seconds = jail.effectiveFindtime(cfg.defaults);
        if (seconds == 0) return error.InvalidFindtime;
        const window = std.math.mul(i64, std.math.cast(i64, seconds) orelse return error.InvalidFindtime, 1_000_000) catch return error.InvalidFindtime;
        const profile = try origin.Profile.init(settings.machine_id, settings.executables);
        try transport.validate(settings.journal);
        const self = try a.create(Plan);
        errdefer a.destroy(self);
        self.allocator = a;
        self.base = try builtin.Detector.init(a, .{ .filter = jail.filter, .body = .whole, .ignore = jail.ignoreip orelse cfg.defaults.ignoreip, .ignore_capacity = settings.ignore_capacity, .max_decoded_bytes = settings.max_decoded_bytes });
        errdefer self.base.deinit(a);
        self.qualified = try journal.Detector.init(&self.base, profile);
        self.processing = .{ .jail = jail.name, .parent_generation = parent, .timestamp = .journal, .window_us = window, .max_record_bytes = settings.max_record_bytes, .max_decoded_bytes = settings.max_decoded_bytes };
        self.journal = settings.journal;
        self.source_id = settings.source_id;
        return self;
    }
    pub fn sessionOptions(self: *const Plan) session.Options {
        return .{ .processing = self.processing, .detection = self.qualified.consumer(), .journal = self.journal, .source_id = self.source_id };
    }
    pub fn destroy(self: *Plan) void {
        const a = self.allocator;
        self.base.deinit(a);
        a.destroy(self);
    }
};

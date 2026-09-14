// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Internal configuration projection for native file detection. No new public
//! configuration syntax and no automatic source selection or daemon activation.
const std = @import("std");
const config = @import("native.zig");
const processing = @import("../core/native_source_processor.zig");
const detector = @import("../core/native_builtin_detector.zig");
const session = @import("../core/native_file_session.zig");
const files = @import("../core/durable_file_source.zig");
const durable = @import("../core/record_store.zig");

pub const Settings = struct {
    timestamp: processing.TimestampSource,
    body: detector.Body,
    start: files.Start,
    max_sources: usize,

    ignore_capacity: usize,
    /// The caller supplies a required durable staged consumer before admission.
    custom: bool = false,
    encoding: @import("../core/source_text.zig").Encoding = .utf8,
    bom: @import("../core/source_text.zig").Bom = .preserve,
    max_record_bytes: u32 = 2048,
    max_decoded_bytes: u32 = 2048,
};

pub const Plan = struct {
    processing: processing.Options,
    detection: ?detector.Detector,
    specs: []session.Spec,
    max_sources: usize,

    /// Keep the plan at a stable address for the lifetime of the created session.
    /// Caller supplies shared admission and clocks on this value before creation.
    pub fn sessionOptions(self: *const Plan) session.Options {
        return .{ .processing = self.processing, .detection = if (self.detection) |*value| value.consumer() else null, .max_sources = self.max_sources };
    }

    /// Config strings must remain immutable and outlive this plan and its sessions. The
    /// plan owns the spec array and detector CIDRs. No filesystem probe, DNS,
    /// subprocess, database or firewall work occurs during this projection.
    pub fn init(allocator: std.mem.Allocator, cfg: *const config.Config, jail_index: usize, parent_generation: [32]u8, settings: Settings) !Plan {
        if (jail_index >= cfg.jails.len) return error.UnknownJail;
        const jail = &cfg.jails[jail_index];
        if (!jail.enabled) return error.DisabledJail;
        if (cfg.global.compatibility_pending or jail.compatibility_pending) return error.CompatibilityNotAdmitted;
        const source = if (jail.source == .auto) cfg.defaults.source else jail.source;
        switch (source) {
            .auto => return error.SourceSelectionRequired,
            .journald => return error.JournalOriginPolicyRequired,
            .internal => return error.InternalEventsRequired,
            .file => {},
        }
        if (settings.timestamp == .journal) return error.InvalidFileTimestampSource;
        if (settings.max_sources == 0 or settings.max_sources > 4096 or jail.logpath.len == 0 or jail.logpath.len > settings.max_sources) return error.InvalidSourceLimit;
        for (jail.logpath) |path| if (path.len == 0 or path.len > durable.Limits.source_bytes or std.mem.indexOfScalar(u8, path, 0) != null) return error.InvalidSourceSpecification;
        const seconds = jail.effectiveFindtime(cfg.defaults);
        if (seconds == 0) return error.InvalidFindtime;
        const window_us = std.math.mul(i64, std.math.cast(i64, seconds) orelse return error.InvalidFindtime, 1_000_000) catch return error.InvalidFindtime;
        // A syslog body must use the timestamp from that same envelope. Require
        // the already-supported explicit BSD or ISO field, never a second date
        // elsewhere in the message or implicit receipt time.
        if (settings.body == .syslog) {
            if (settings.timestamp != .field) return error.SyslogTimestampRequired;
            const field = settings.timestamp.field;
            if (field.start != 0) return error.SyslogTimestampRequired;
            switch (field.format) {
                .syslog => if (field.boundary != .length or field.boundary.length != 15) return error.SyslogTimestampRequired,
                .iso8601 => if (field.boundary != .delimiter or field.boundary.delimiter != ' ') return error.SyslogTimestampRequired,
                else => return error.SyslogTimestampRequired,
            }
        }
        var detection: ?detector.Detector = if (settings.custom) null else try detector.Detector.init(allocator, .{
            .filter = jail.filter,
            .body = settings.body,
            .ignore = jail.ignoreip orelse cfg.defaults.ignoreip,
            .ignore_capacity = settings.ignore_capacity,
            .max_decoded_bytes = settings.max_decoded_bytes,
        });
        errdefer if (detection) |*value| value.deinit(allocator);
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("fail2zig-native-file-detection-v1\x00");
        hash.update(&parent_generation);
        if (detection) |value| hash.update(&value.generation) else hash.update("required-staged-consumer");
        var generation: [32]u8 = undefined;
        hash.final(&generation);
        const options = processing.Options{
            .jail = jail.name,
            .parent_generation = generation,
            .timestamp = settings.timestamp,
            .encoding = settings.encoding,
            .bom = settings.bom,
            .window_us = window_us,
            .max_record_bytes = settings.max_record_bytes,
            .max_decoded_bytes = settings.max_decoded_bytes,
        };
        // Reuse the processor's authoritative validation, including bounded
        // codecs and mandatory year/timezone context. Allocation is startup-only.
        const scratch = try allocator.alloc(u8, settings.max_decoded_bytes);
        defer allocator.free(scratch);
        _ = try processing.Processor.init(allocator, options, scratch, .{ .us = 0 });
        const specs = try allocator.alloc(session.Spec, jail.logpath.len);
        for (specs, jail.logpath) |*spec, path| spec.* = .{ .pattern = path, .start = settings.start };
        return .{ .processing = options, .detection = detection, .specs = specs, .max_sources = settings.max_sources };
    }

    pub fn deinit(self: *Plan, allocator: std.mem.Allocator) void {
        if (self.detection) |*value| value.deinit(allocator);
        allocator.free(self.specs);
        self.* = undefined;
    }
};

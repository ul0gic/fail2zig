// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");

pub const LogSelection = struct {
    raw_backend: []const u8 = "auto",
    logpath_present: bool = false,
    matched_files: usize = 0,
    journalmatch_present: bool = false,
    skip_if_nologs: bool = false,
    systemd_if_nologs: bool = true,
    global_systemd_if_nologs: bool = true,
    allow_no_files: bool = false,
};
pub const Prepared = struct {
    disposition: enum { admit, skip, missing_logs },
    backend: []const u8,
    switched_to_journal: bool = false,
    ignores_logpaths: bool = false,
    diagnostic: ?[]const u8 = null,
};

pub fn prepare(input: LogSelection) Prepared {
    var result = Prepared{ .disposition = .admit, .backend = input.raw_backend };
    if (std.mem.startsWith(u8, input.raw_backend, "systemd")) {
        result.ignores_logpaths = true;
        return result;
    }
    if (!input.logpath_present or input.matched_files != 0) return result;
    result.diagnostic = "missing-log-files";
    if (std.mem.startsWith(u8, input.raw_backend, "auto") and input.systemd_if_nologs and
        input.global_systemd_if_nologs and input.journalmatch_present)
    {
        result.backend = "systemd";
        result.switched_to_journal = true;
        return result;
    }
    result.disposition = if (input.skip_if_nologs) .skip else if (input.allow_no_files) .admit else .missing_logs;
    return result;
}

pub const Backend = enum { pyinotify, polling, systemd };
pub const SourceKind = enum { file, journal };
const ordered = [_]Backend{ .pyinotify, .polling, .systemd };
pub const Selection = struct {
    backend: Backend,
    source_kind: SourceKind,
    attempts: usize,
    explicit_fallback: bool,
};

pub fn select(parsed_name: []const u8, context: ?*anyopaque, initialize: *const fn (Backend, ?*anyopaque) anyerror!void) !Selection {
    const automatic = std.ascii.eqlIgnoreCase(parsed_name, "auto");
    var start: usize = 0;
    if (!automatic) {
        while (start < ordered.len and !std.ascii.eqlIgnoreCase(parsed_name, @tagName(ordered[start]))) : (start += 1) {}
        if (start == ordered.len) return error.UnknownBackend;
    }
    for (ordered[start..], start..) |backend, index| {
        initialize(backend, context) catch |err| {
            if (err == error.DependencyUnavailable) continue;
            return err;
        };
        return .{ .backend = backend, .source_kind = if (backend == .systemd) .journal else .file, .attempts = index - start + 1, .explicit_fallback = !automatic and index != start };
    }
    return error.NoAvailableBackend;
}

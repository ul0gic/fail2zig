// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Plans one jail's log source from fail2ban-format options: backend selector, log paths, journal matches, ignore and processing.
// Holds: An option that fails to resolve is kept as a diagnostic, never dropped, and bind refuses a plan with any plan-level diagnostic.

const std = @import("std");
const config = @import("fail2ban.zig");
const policy = @import("../source/source_policy.zig");
const Allocator = std.mem.Allocator;

pub const Parameter = struct { name: []const u8, value: []const u8 };
pub const Path = struct {
    raw: []const u8,
    pattern: []const u8,
    start_spelling: []const u8,
    explicit_start: bool,
    start: ?@import("../source/durable_file_source.zig").Start,
};
pub const FilterDefaults = struct {
    values: ?*const std.StringArrayHashMapUnmanaged([]const u8) = null,
    asset_index: ?usize = null,
    config_root: ?[]const u8 = null,
    error_name: ?[]const u8 = null,
};
pub const Option = struct {
    reader: ?config.ResolvedOption,
    error_name: ?[]const u8 = null,
    derived_filter_asset: ?usize = null,
};
pub const IPv6 = struct {
    option: Option,
    policy: enum { automatic, enabled, disabled, invalid },
    adapter_value: ?[]const u8 = null,

    pub fn adapterValue(self: IPv6) ?[]const u8 {
        return switch (self.policy) {
            .automatic => "auto",
            .enabled => "yes",
            .disabled => "no",
            .invalid => null,
        };
    }
};
pub const IgnorePlan = struct {
    schema_version: u32 = 1,
    admission: []const u8 = "prepared-only",
    jail: []const u8,
    ignoreip: Option,
    ignoreself: Option,
    usedns: Option,
    ignorecache: Option,
    ignorecommand: Option,
    allowipv6: IPv6,
    diagnostics: []const []const u8,
};

pub const Processing = struct {
    encoding: ?[]const u8,
    default_tz: ?[]const u8,
    date_patterns: []const []const u8,
    max_lines: ?usize,
    findtime: Option,
    diagnostics: []const []const u8,
};

pub const Plan = struct {
    schema_version: u32 = 1,
    admission: []const u8 = "prepared-only",
    jail: []const u8,
    backend: Option,
    backend_name: ?[]const u8,
    backend_parameters: []const Parameter,
    logpath: Option,
    paths: []const Path,
    journalmatch: Option,
    skip_if_nologs: Option,
    systemd_if_nologs: Option,
    logencoding: Option,
    logtimezone: Option,
    datepattern: Option,
    maxlines: Option,
    allowipv6: IPv6,
    ignore: IgnorePlan,
    processing: Processing,
    diagnostics: []const []const u8,
    runtime_defaults: struct { logencoding: []const u8 = "auto", maxlines: usize = 1 } = .{},

    pub const Availability = enum { available, dependency_unavailable, initialization_failed };
    pub const Environment = struct {
        matched_files: usize,
        backend_availability: [3]Availability,
        global_systemd_if_nologs: bool = true,
        allow_no_files: bool = false,
    };
    pub const Binding = struct {
        client: policy.Prepared,
        selected: ?policy.Selection = null,
        parameters: []const Parameter = &.{},
        admission: []const u8 = "prepared-only",
    };

    pub fn bind(self: Plan, allocator: Allocator, environment: Environment) !Binding {
        if (self.diagnostics.len != 0) return error.InvalidSourcePlan;
        const backend = string(self.backend) orelse return error.InvalidSourcePlan;
        var result = Binding{ .client = policy.prepare(.{
            .raw_backend = backend,
            .logpath_present = present(self.logpath),
            .matched_files = environment.matched_files,
            .journalmatch_present = present(self.journalmatch),
            .skip_if_nologs = boolean(self.skip_if_nologs),
            .systemd_if_nologs = boolean(self.systemd_if_nologs),
            .global_systemd_if_nologs = environment.global_systemd_if_nologs,
            .allow_no_files = environment.allow_no_files,
        }) };
        if (result.client.disposition != .admit) return result;
        const selector = try config.parseSelector(allocator, result.client.backend);
        result.parameters = try parameters(allocator, &selector.parameters);
        const Factory = struct {
            fn observed(backend_id: policy.Backend, context: ?*anyopaque) !void {
                const state: *const [3]Availability = @ptrCast(@alignCast(context.?));
                switch (state[@intFromEnum(backend_id)]) {
                    .available => {},
                    .dependency_unavailable => return error.DependencyUnavailable,
                    .initialization_failed => return error.InitializationFailed,
                }
            }
        };
        var observed = environment.backend_availability;
        result.selected = try policy.select(selector.name, &observed, Factory.observed);
        return result;
    }
};

fn parameters(allocator: Allocator, map: *const std.StringArrayHashMapUnmanaged([]const u8)) ![]const Parameter {
    var result = std.ArrayList(Parameter).init(allocator);
    var entries = map.iterator();
    while (entries.next()) |entry| try result.append(.{ .name = entry.key_ptr.*, .value = entry.value_ptr.* });
    return result.toOwnedSlice();
}
pub fn string(option: Option) ?[]const u8 {
    const value = option.reader orelse return null;
    return if (value.value == .string) value.value.string else null;
}
fn present(option: Option) bool {
    return option.derived_filter_asset != null or (if (option.reader) |reader| reader.presence != .absent else false);
}
fn boolean(option: Option) bool {
    return if (option.reader) |reader| reader.value == .boolean and reader.value.boolean else false;
}
fn read(allocator: Allocator, ini: *const config.ParsedIni, section: []const u8, key: []const u8, kind: config.CanonicalType, fallback: config.CanonicalValue, defaults: FilterDefaults) !Option {
    const default_id = try std.fmt.allocPrint(allocator, "fail2ban-1.1.1/source-plan/{s}/{s}", .{ section, key });
    var option = Option{ .reader = config.readTypedOption(allocator, ini, section, key, kind, fallback, default_id) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return .{ .reader = null, .error_name = @errorName(err) },
    } };
    if (option.reader.?.presence == .absent) {
        if (defaults.values) |values| if (values.get(key)) |value| {
            var parsed = try config.parseIniSource(allocator, "prepared-filter-default", "[Definition]\n");
            // Why: Doubling '%' makes the reader take the filter default literally instead of interpolating it again.
            const literal = try std.mem.replaceOwned(u8, allocator, value, "%", "%%");
            try parsed.sections.getPtr("Definition").?.keys.put(allocator, key, literal);
            const converted = config.readTypedOption(allocator, &parsed, "Definition", key, kind, fallback, default_id) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => {
                    option.error_name = @errorName(err);
                    return option;
                },
            };
            option.reader.?.value = converted.value;
            option.reader.?.resolution = converted.resolution;
            option.reader.?.raw = value;
            option.derived_filter_asset = defaults.asset_index;
        };
    }
    return option;
}

pub fn prepare(allocator: Allocator, source_ini: *const config.ParsedIni, jail_name: []const u8, globals: *const config.ParsedIni, filter_defaults: FilterDefaults) !Plan {
    var reader_graph = source_ini.*;
    if (filter_defaults.config_root) |root| {
        reader_graph.sections = try source_ini.sections.clone(allocator);
        var defaults = if (source_ini.section("DEFAULT")) |section| section.* else config.Section{ .name = "DEFAULT" };
        defaults.keys = try defaults.keys.clone(allocator);
        try defaults.keys.put(allocator, "fail2ban_confpath", root);
        try defaults.keys.put(allocator, "fail2ban_version", "1.1.1");
        try reader_graph.sections.put(allocator, "DEFAULT", defaults);
    }
    const ini = &reader_graph;
    const backend = try read(allocator, ini, jail_name, "backend", .string, .{ .string = "auto" }, .{});
    const logpath = try read(allocator, ini, jail_name, "logpath", .string, .null_value, .{});
    const ipv6_option = try read(allocator, globals, "Definition", "allowipv6", .string, .{ .string = "auto" }, .{});
    const ipv6_text = string(ipv6_option);
    var ipv6: IPv6 = .{
        .option = ipv6_option,
        .policy = if (ipv6_text) |value| if (std.mem.eql(
            u8,
            value,
            "auto",
        )) .automatic else if (std.ascii.eqlIgnoreCase(value, "1") or std.ascii.eqlIgnoreCase(value, "true") or std.ascii.eqlIgnoreCase(value, "on") or std.ascii.eqlIgnoreCase(value, "yes")) .enabled else .disabled else .invalid,
    };
    ipv6.adapter_value = ipv6.adapterValue();
    var ignore = IgnorePlan{
        .jail = jail_name,
        .ignoreip = try read(allocator, ini, jail_name, "ignoreip", .string, .null_value, .{}),
        .ignoreself = try read(allocator, ini, jail_name, "ignoreself", .boolean, .null_value, .{}),
        .usedns = try read(allocator, ini, jail_name, "usedns", .string, .null_value, filter_defaults),
        .ignorecache = try read(allocator, ini, jail_name, "ignorecache", .string, .null_value, .{}),
        .ignorecommand = try read(allocator, ini, jail_name, "ignorecommand", .string, .null_value, .{}),
        .allowipv6 = ipv6,
        .diagnostics = &.{},
    };
    var ignore_diagnostics = std.ArrayList([]const u8).init(allocator);
    inline for (.{ "ignoreip", "ignoreself", "usedns", "ignorecache", "ignorecommand" }) |field| {
        if (@field(ignore, field).error_name) |name| try ignore_diagnostics.append(name);
    }
    if (ipv6_option.error_name) |name| try ignore_diagnostics.append(name);
    if (filter_defaults.error_name) |name| try ignore_diagnostics.append(name);
    ignore.diagnostics = try ignore_diagnostics.toOwnedSlice();
    var result = Plan{
        .jail = jail_name,
        .backend = backend,
        .backend_name = null,
        .backend_parameters = &.{},
        .logpath = logpath,
        .paths = &.{},
        .journalmatch = try read(allocator, ini, jail_name, "journalmatch", .string, .null_value, filter_defaults),
        .skip_if_nologs = try read(allocator, ini, jail_name, "skip_if_nologs", .boolean, .{ .boolean = false }, .{}),
        .systemd_if_nologs = try read(allocator, ini, jail_name, "systemd_if_nologs", .boolean, .{ .boolean = true }, .{}),
        .logencoding = try read(allocator, ini, jail_name, "logencoding", .string, .null_value, .{}),
        .logtimezone = try read(allocator, ini, jail_name, "logtimezone", .string, .null_value, .{}),
        .datepattern = try read(allocator, ini, jail_name, "datepattern", .string, .null_value, filter_defaults),
        .maxlines = try read(allocator, ini, jail_name, "maxlines", .integer, .null_value, filter_defaults),
        .allowipv6 = ipv6,
        .ignore = ignore,
        .processing = undefined,
        .diagnostics = &.{},
    };
    var diagnostics = std.ArrayList([]const u8).init(allocator);
    if (filter_defaults.error_name) |name| try diagnostics.append(name);
    inline for (.{ "backend", "logpath", "journalmatch", "skip_if_nologs", "systemd_if_nologs", "logencoding", "logtimezone", "datepattern", "maxlines" }) |field| {
        if (@field(result, field).error_name) |name| try diagnostics.append(name);
    }
    if (ipv6_option.error_name) |name| try diagnostics.append(name);
    if (string(backend)) |value| {
        const selector = config.parseSelector(allocator, value) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => null,
        };
        if (selector) |selected| {
            result.backend_name = selected.name;
            result.backend_parameters = try parameters(allocator, &selected.parameters);
        } else try diagnostics.append("InvalidBackendSelector");
    }
    var paths = std.ArrayList(Path).init(allocator);
    if (string(logpath)) |raw| {
        var lines = std.mem.splitScalar(u8, raw, '\n');
        while (lines.next()) |line| {
            // Why: The word after a logpath line's last space is its start mode, head or tail; a line without one starts at head.
            const split = std.mem.lastIndexOfScalar(u8, line, ' ');
            const pattern = if (split) |index| line[0..index] else line;
            const spelling = if (split) |index| line[index + 1 ..] else "head";
            const start: ?@import("../source/durable_file_source.zig").Start = if (std.ascii.eqlIgnoreCase(spelling, "head")) .head else if (std.ascii.eqlIgnoreCase(spelling, "tail")) .tail else null;
            try paths.append(.{ .raw = line, .pattern = pattern, .start_spelling = spelling, .explicit_start = split != null, .start = start });
        }
    }
    var processing_diagnostics = std.ArrayList([]const u8).init(allocator);
    if (filter_defaults.error_name) |name| try processing_diagnostics.append(name);
    var patterns = std.ArrayList([]const u8).init(allocator);
    if (string(result.datepattern)) |raw| {
        var lines = std.mem.splitScalar(u8, raw, '\n');
        while (lines.next()) |line| {
            const pattern = try trimPythonWhitespace(line);
            if (pattern.len != 0) try patterns.append(pattern);
        }
    }
    var max_lines: ?usize = 1;
    if (result.maxlines.reader) |reader| {
        if (reader.value == .integer) max_lines = std.fmt.parseInt(usize, reader.value.integer, 10) catch null;
    }
    if (max_lines) |n| if (n == 0 or n > 1000) {
        max_lines = null;
    };
    if (max_lines == null) try processing_diagnostics.append("UnsupportedMaxLines");
    const findtime = try read(allocator, ini, jail_name, "findtime", .string, .null_value, .{});
    inline for (.{ "logencoding", "logtimezone", "datepattern", "maxlines" }) |field| {
        if (@field(result, field).error_name) |name| try processing_diagnostics.append(name);
    }
    if (findtime.error_name) |name| try processing_diagnostics.append(name);
    result.processing = .{
        .encoding = string(result.logencoding) orelse "auto",
        .default_tz = string(result.logtimezone),
        .date_patterns = try patterns.toOwnedSlice(),
        .max_lines = max_lines,
        .findtime = findtime,
        .diagnostics = try processing_diagnostics.toOwnedSlice(),
    };
    result.paths = try paths.toOwnedSlice();
    result.diagnostics = try diagnostics.toOwnedSlice();
    return result;
}

fn trimPythonWhitespace(input: []const u8) ![]const u8 {
    const view = std.unicode.Utf8View.init(input) catch return error.InvalidEncoding;
    var iter = view.iterator();
    var begin: ?usize = null;
    var end: usize = 0;
    while (iter.nextCodepointSlice()) |bytes| {
        const cp = std.unicode.utf8Decode(bytes) catch return error.InvalidEncoding;
        const white = switch (cp) {
            0x09...0x0d, 0x1c...0x20, 0x85, 0xa0, 0x1680, 0x2000...0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000 => true,
            else => false,
        };
        if (!white) {
            if (begin == null) begin = iter.i - bytes.len;
            end = iter.i;
        }
    }
    return input[begin orelse end .. end];
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Effective journal arguments before opening any journal. Environment paths and
//! readability are explicit captured inputs, allowing deterministic preparation.
const std = @import("std");
const config = @import("../config/fail2ban.zig");
const matching = @import("durable_file_source.zig");
const Allocator = std.mem.Allocator;
const local_only: u8 = 1;
const runtime_only: u8 = 2;
const system_only: u8 = 4;
const current_user: u8 = 8;

/// Pure prepared selector values; validation never loads or opens a reader.
pub const Selection = struct {
    flags: u32 = 4,
    namespace: ?[]const u8 = null,
    directory: ?[]const u8 = null,
    files: ?[]const []const u8 = null,
    matches: []const []const u8 = &.{},
    pub fn validate(self: Selection) !void {
        if (self.flags > std.math.maxInt(c_int)) return error.InvalidFlags;
        if (self.directory != null and self.files != null) return error.ConflictingJournalSelection;
        if (self.namespace != null and (self.directory != null or self.files != null)) return error.ConflictingJournalSelection;
        var total: usize = 0;
        for ([_]?[]const u8{ self.namespace, self.directory }) |maybe| if (maybe) |value| {
            if (value.len > 4096 or std.mem.indexOfScalar(u8, value, 0) != null) return error.InvalidJournalSelection;
            total += value.len;
        };
        if (self.files) |paths| {
            if (paths.len > 4096) return error.JournalSelectionLimit;
            for (paths) |path| {
                if (path.len > 4096 or std.mem.indexOfScalar(u8, path, 0) != null) return error.InvalidJournalSelection;
                total += path.len;
            }
        }
        if (self.matches.len > 4096) return error.JournalSelectionLimit;
        for (self.matches) |m| {
            if (m.len > 65536) return error.JournalSelectionLimit;
            total += m.len;
        }
        if (total > 1024 * 1024) return error.JournalSelectionLimit;
        var need_match = true;
        for (self.matches) |m| {
            if (std.mem.eql(u8, m, "+")) {
                if (need_match) return error.InvalidMatch;
                need_match = true;
            } else {
                const eq = std.mem.indexOfScalar(u8, m, '=') orelse return error.InvalidMatch;
                if (eq == 0 or std.mem.indexOfScalar(u8, m, 0) != null) return error.InvalidMatch;
                for (m[0..eq]) |c| if (!(std.ascii.isUpper(c) or std.ascii.isDigit(c) or c == '_')) return error.InvalidMatch;
                need_match = false;
            }
        }
        if (self.matches.len > 0 and need_match) return error.InvalidMatch;
    }
};

pub const Options = struct {
    path: ?[]const u8 = null,
    /// Already split journalfiles list. Null means the argument was absent.
    files: ?[]const []const u8 = null,
    flags: ?[]const u8 = null,
    rotated: []const u8 = "0",
    namespace: ?[]const u8 = null,
};
pub const Environment = struct {
    state_logs: []const u8 = "/var/log",
    runtime_logs: []const u8 = "/run/log",
    effective_uid: u32,
    default_flags: ?[]const u8 = null,
    readable: *const fn ([]const u8, ?*anyopaque) anyerror!bool = nativeReadable,
    context: ?*anyopaque = null,
    max_files: usize = 4096,
};
/// Presence and null are retained separately because _getJournalArgs exposes both.
/// All returned storage belongs to the caller's arena.
pub const Prepared = struct {
    flags_present: bool = false,
    flags: ?[]const u8 = null,
    path_present: bool = false,
    path: ?[]const u8 = null,
    files_present: bool = false,
    files: ?[]const []const u8 = null,
    namespace_present: bool = false,
    namespace: ?[]const u8 = null,

    pub fn selectionDiagnostic(self: Prepared) ?[]const u8 {
        return if (self.namespace != null and (self.path != null or self.files != null)) "ignored_namespace" else null;
    }

    pub fn selection(self: Prepared, matches: []const []const u8) !Selection {
        // python-systemd's Reader chooses LOCAL_ONLY only when path/files are None.
        const flags: i64 = if (self.flags) |text| std.fmt.parseInt(i64, text, 10) catch return error.InvalidFlags else (if (self.path == null and self.files == null) local_only else 0);
        if (flags < 0 or flags > std.math.maxInt(c_int)) return error.InvalidFlags;
        if (self.path == null) if (self.files) |paths| if (paths.len == 0) return error.EmptyJournalFiles;
        const result = Selection{ .flags = @intCast(flags), .directory = self.path, .files = self.files, .namespace = if (self.path != null or self.files != null) null else self.namespace, .matches = matches };
        try result.validate();
        return result;
    }
};

fn validateString(value: []const u8) !void {
    if (value.len > 4096 or std.mem.indexOfScalar(u8, value, 0) != null) return error.InvalidJournalArgument;
}
fn parseFlags(allocator: Allocator, value: []const u8) ![]const u8 {
    try validateString(value);
    return (try config.canonicalInteger(allocator, value)) orelse error.InvalidFlags;
}
/// Python bit tests on arbitrarily large integers only require these low bits.
fn flagBits(value: []const u8) u8 {
    var modulo: u8 = 0;
    for (value) |digit| {
        if (digit == '-') continue;
        modulo = @intCast((@as(u16, modulo) * 10 + digit - '0') % 16);
    }
    return if (value[0] == '-') (16 - modulo) % 16 else modulo;
}

fn truth(value: ?[]const u8) bool {
    return if (value) |text| text.len != 0 else false;
}
fn hasFiles(value: ?[]const []const u8) bool {
    return if (value) |paths| paths.len != 0 else false;
}
fn boolValue(value: []const u8) bool {
    return std.ascii.eqlIgnoreCase(value, "1") or std.ascii.eqlIgnoreCase(value, "on") or std.ascii.eqlIgnoreCase(value, "true") or std.ascii.eqlIgnoreCase(value, "yes");
}

/// String journalfiles syntax splits commas and Unicode whitespace, like splitwords.
pub fn splitFiles(allocator: Allocator, text: []const u8) ![]const []const u8 {
    try validateString(text);
    var result = std.ArrayList([]const u8).init(allocator);
    var view = try std.unicode.Utf8View.init(text);
    var it = view.iterator();
    var start: ?usize = null;
    while (it.nextCodepoint()) |cp| {
        const length = std.unicode.utf8CodepointSequenceLength(cp) catch unreachable;
        const before = it.i - length;
        const separator = cp == ',' or cp == ' ' or (cp >= 9 and cp <= 13) or (cp >= 0x1c and cp <= 0x20) or cp == 0x85 or cp == 0xa0 or cp == 0x1680 or (cp >= 0x2000 and cp <= 0x200a) or cp == 0x2028 or cp == 0x2029 or cp == 0x202f or cp == 0x205f or cp == 0x3000;
        if (separator) {
            if (start) |first| try result.append(try allocator.dupe(u8, text[first..before]));
            start = null;
        } else if (start == null) start = before;
    }
    if (start) |first| try result.append(try allocator.dupe(u8, text[first..]));
    return result.toOwnedSlice();
}

pub fn prepare(allocator: Allocator, options: Options, environment: Environment) !Prepared {
    if (environment.max_files == 0 or environment.max_files > 65536) return error.JournalSelectionLimit;
    try validateString(environment.state_logs);
    try validateString(environment.runtime_logs);
    try validateString(options.rotated);
    for ([_]?[]const u8{ options.path, options.namespace }) |value| if (value) |text| try validateString(text);
    var result = Prepared{ .path_present = options.path != null, .path = options.path, .files_present = options.files != null, .namespace_present = options.namespace != null, .namespace = options.namespace };
    if (options.files) |patterns| {
        if (patterns.len > environment.max_files) return error.JournalSelectionLimit;
        var files = std.ArrayList([]const u8).init(allocator);
        for (patterns) |pattern| {
            try validateString(pattern);
            try appendGlob(allocator, pattern, &files, environment.max_files);
        }
        result.files = try sortedUnique(allocator, files.items);
    }
    const rotated = boolValue(options.rotated);
    if (options.flags) |flags| {
        result.flags_present = true;
        result.flags = try parseFlags(allocator, flags);
    } else if (!hasFiles(result.files) and !truth(result.path)) {
        result.flags_present = true;
        if (environment.default_flags) |flags| result.flags = try parseFlags(allocator, flags) else if (rotated) result.flags = "4";
    }
    if (!rotated and !hasFiles(result.files) and !truth(result.namespace)) {
        const effective_flags: ?u8 = if (result.flags_present) (if (result.flags) |text| flagBits(text) else null) else 1;
        result.files_present = true;
        result.files = try discover(allocator, effective_flags, result.path, environment);
        if (hasFiles(result.files)) {
            result.flags_present = true;
            result.flags = null;
            result.path_present = true;
            result.path = null;
        }
    }
    return result;
}

fn nativeReadable(path: []const u8, _: ?*anyopaque) !bool {
    std.posix.access(path, std.posix.R_OK) catch return false;
    return true;
}
fn sortedUnique(allocator: Allocator, input: [][]const u8) ![]const []const u8 {
    std.mem.sort([]const u8, input, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.less);
    var result = std.ArrayList([]const u8).init(allocator);
    for (input) |path| {
        if (result.items.len == 0 or !std.mem.eql(u8, path, result.items[result.items.len - 1])) try result.append(path);
    }
    return result.toOwnedSlice();
}
fn discover(allocator: Allocator, flags: ?u8, path: ?[]const u8, environment: Environment) !?[]const []const u8 {
    var files = std.ArrayList([]const u8).init(allocator);
    if (truth(path)) {
        try addJournals(allocator, path.?, flags, environment.effective_uid, &files, environment.max_files);
    } else {
        if (flags == null or flags.? & runtime_only == 0) {
            const base = try std.fs.path.join(allocator, &.{ environment.state_logs, "journal", "*" });
            try addJournals(allocator, base, flags, environment.effective_uid, &files, environment.max_files);
        }
        const base = try std.fs.path.join(allocator, &.{ environment.runtime_logs, "journal", "*" });
        try addJournals(allocator, base, flags, environment.effective_uid, &files, environment.max_files);
    }
    const unique = try sortedUnique(allocator, files.items);
    var accepted = std.ArrayList([]const u8).init(allocator);
    for (unique) |file| {
        if (environment.effective_uid != 0 and !try environment.readable(file, environment.context)) continue;
        try accepted.append(file);
    }
    return if (accepted.items.len == 0) null else try accepted.toOwnedSlice();
}
fn addJournals(allocator: Allocator, path: []const u8, flags: ?u8, uid: u32, files: *std.ArrayList([]const u8), limit: usize) !void {
    if (flags == null or flags.? & system_only != 0) try appendJournalPattern(allocator, path, "system.journal", files, limit);
    if (flags != null and flags.? & current_user != 0) {
        const pattern = try std.fmt.allocPrint(allocator, "user-{d}.journal", .{uid});
        try appendJournalPattern(allocator, path, pattern, files, limit);
    }
    if (flags == null or flags.? & (system_only | current_user) == 0) try appendJournalPattern(allocator, path, "*.journal", files, limit);
}
fn appendJournalPattern(allocator: Allocator, path: []const u8, leaf: []const u8, files: *std.ArrayList([]const u8), limit: usize) !void {
    var matches = std.ArrayList([]const u8).init(allocator);
    try appendGlob(allocator, try std.fs.path.join(allocator, &.{ path, leaf }), &matches, limit);
    for (matches.items) |match| {
        if (std.mem.indexOfScalar(u8, std.fs.path.basename(match), '@') != null) continue;
        if (files.items.len >= limit) return error.JournalSelectionLimit;
        try files.append(match);
    }
}

/// Python nonrecursive glob semantics: include directories and broken symlinks,
/// retain lexical relative paths, and suppress filesystem lookup errors.
fn appendGlob(allocator: Allocator, pattern: []const u8, result: *std.ArrayList([]const u8), limit: usize) !void {
    if (pattern.len == 0) return;
    const remaining = std.mem.trimLeft(u8, pattern, "/");
    const prefix = pattern[0 .. pattern.len - remaining.len];
    if (remaining.len == 0) {
        var directory = std.fs.cwd().openDir(pattern, .{}) catch return;
        directory.close();
        return appendResult(allocator, pattern, result, limit);
    }
    try globAt(allocator, prefix, remaining, result, limit);
}
fn globAt(allocator: Allocator, base: []const u8, remaining: []const u8, result: *std.ArrayList([]const u8), limit: usize) !void {
    const slash = std.mem.indexOfScalar(u8, remaining, '/');
    const component = if (slash) |index| remaining[0..index] else remaining;
    const rest = if (slash) |index| remaining[index + 1 ..] else "";
    const directory = if (base.len == 0) "." else base;
    var dir = std.fs.cwd().openDir(directory, .{ .iterate = true }) catch return;
    defer dir.close();
    const magic = std.mem.indexOfAny(u8, component, "*?[") != null;
    if (!magic) {
        const next = try std.fmt.allocPrint(allocator, "{s}{s}", .{ base, component });
        if (slash != null) {
            if (rest.len == 0) {
                var child = std.fs.cwd().openDir(next, .{}) catch return;
                child.close();
                try appendResult(allocator, try std.fmt.allocPrint(allocator, "{s}/", .{next}), result, limit);
            } else try globAt(allocator, try std.fmt.allocPrint(allocator, "{s}/", .{next}), rest, result, limit);
        } else {
            _ = std.posix.fstatat(dir.fd, component, std.posix.AT.SYMLINK_NOFOLLOW) catch return;
            try appendResult(allocator, next, result, limit);
        }
        return;
    }
    var it = dir.iterate();
    while (it.next() catch null) |entry| {
        if (!matching.matchComponent(component, entry.name)) continue;
        const next = try std.fmt.allocPrint(allocator, "{s}{s}", .{ base, entry.name });
        if (slash != null) {
            if (rest.len == 0) {
                var child = std.fs.cwd().openDir(next, .{}) catch continue;
                child.close();
                try appendResult(allocator, try std.fmt.allocPrint(allocator, "{s}/", .{next}), result, limit);
            } else try globAt(allocator, try std.fmt.allocPrint(allocator, "{s}/", .{next}), rest, result, limit);
        } else try appendResult(allocator, next, result, limit);
    }
}
fn appendResult(allocator: Allocator, path: []const u8, result: *std.ArrayList([]const u8), limit: usize) !void {
    if (result.items.len >= limit) return error.JournalSelectionLimit;
    try result.append(try allocator.dupe(u8, path));
}

test "journal policy validates prepared selectors without a reader" {
    try (Selection{ .files = &.{"/original/system.journal"}, .matches = &.{ "_SYSTEMD_UNIT=sshd.service", "+", "SYSLOG_IDENTIFIER=sshd" } }).validate();
    try std.testing.expectError(error.ConflictingJournalSelection, (Selection{ .directory = "/original", .files = &.{"/original/system.journal"} }).validate());
    try std.testing.expectError(error.InvalidJournalSelection, (Selection{ .directory = "/original\x00hidden" }).validate());
    try std.testing.expectError(error.InvalidMatch, (Selection{ .matches = &.{ "_SYSTEMD_UNIT=sshd.service", "+" } }).validate());
    try std.testing.expectError(error.InvalidMatch, (Selection{ .matches = &.{"lowercase=invalid"} }).validate());
    try std.testing.expectError(error.InvalidFlags, (Selection{ .flags = std.math.maxInt(u32) }).validate());
}

test "journal policy separates absent flags from rotated default and explicit empty selection" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const env = Environment{ .state_logs = "/nonexistent-f2z-policy-state", .runtime_logs = "/nonexistent-f2z-policy-run", .effective_uid = 0 };
    const normal = try prepare(a, .{}, env);
    try std.testing.expect(normal.flags_present and normal.flags == null and normal.files_present and normal.files == null);
    try std.testing.expectEqual(@as(u32, 1), (try normal.selection(&.{})).flags);
    const rotated = try prepare(a, .{ .rotated = "yes" }, env);
    try std.testing.expectEqualStrings("4", rotated.flags.?);
    try std.testing.expect(!rotated.files_present);
    const empty = try prepare(a, .{ .files = &.{}, .rotated = "yes" }, env);
    try std.testing.expectEqual(@as(usize, 0), empty.files.?.len);
    try std.testing.expectError(error.EmptyJournalFiles, empty.selection(&.{}));
    const namespaced = try prepare(a, .{ .namespace = "original" }, env);
    try std.testing.expect(!namespaced.files_present);
    try std.testing.expectEqual(@as(u32, 1), (try namespaced.selection(&.{})).flags);
}

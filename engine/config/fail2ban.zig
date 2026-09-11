// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");

pub const Error = error{
    FileNotFound,
    AccessDenied,
    ReadFailed,
    FileTooLarge,
    UnterminatedSection,
    EmptySectionName,
    KeyWithoutValue,
    TooManySections,
    TooManyKeysInSection,
    TooManyFiles,
    InterpolationCycle,
    InterpolationOverflow,
    InterpolationUnterminated,
    OutOfMemory,
    InvalidPath,
    UnsupportedRegex,
    IncludeDepthExceeded,
    InterpolationMissingOption,
    InvalidParameter,
    DuplicateSection,
    DuplicateOption,
    InvalidEncoding,
};

pub const max_file_bytes: usize = 1024 * 1024;
pub const max_sections: usize = 256;
pub const max_keys_per_section: usize = 64;
pub const max_files_per_dir: usize = 1024;
pub const max_interp_depth: usize = 10;
pub const max_value_bytes: usize = 16 * 1024;

pub const Warning = struct {
    source: []const u8,
    line: u32,
    message: []const u8,
};

pub const Origin = struct {
    source: []const u8,
    line: u32,
    raw: []const u8,
};

pub const Assignment = struct {
    section: []const u8,
    key: []const u8,
    origin: Origin,
};

pub const SourceEdge = enum { layer, before, after, local };

pub const SourceOccurrence = struct {
    edge: SourceEdge,
    original_path: []const u8,
    resolved_target: []const u8,
    parent_path: ?[]const u8,
    path: []const u8,
    bytes: []const u8,
    sha256: [32]u8,
};

pub const Section = struct {
    name: []const u8,
    keys: std.StringArrayHashMapUnmanaged([]const u8) = .{},

    origins: std.StringArrayHashMapUnmanaged(Origin) = .{},
    previous: std.StringArrayHashMapUnmanaged([]const u8) = .{},

    pub fn get(self: *const Section, key: []const u8) ?[]const u8 {
        return self.keys.get(key);
    }
};

pub const ParsedIni = struct {
    assignments: std.ArrayListUnmanaged(Assignment) = .{},
    sources: std.ArrayListUnmanaged(SourceOccurrence) = .{},
    sections: std.StringArrayHashMapUnmanaged(Section) = .{},
    warnings: std.ArrayListUnmanaged(Warning) = .{},

    pub fn section(self: *const ParsedIni, name: []const u8) ?*const Section {
        return self.sections.getPtr(name);
    }

    pub fn userSections(self: *const ParsedIni) SectionIter {
        return .{ .inner = self.sections.iterator(), .skip = "DEFAULT" };
    }

    pub const SectionIter = struct {
        inner: std.StringArrayHashMapUnmanaged(Section).Iterator,
        skip: []const u8,

        pub fn next(self: *SectionIter) ?*Section {
            while (self.inner.next()) |entry| {
                if (std.mem.eql(u8, entry.key_ptr.*, self.skip) or std.mem.eql(u8, entry.key_ptr.*, "INCLUDES")) continue;
                return entry.value_ptr;
            }
            return null;
        }
    };
};

const RawLine = struct {
    line_no: u32,
    text: []const u8,
    indented: bool,
};

fn tokenizeLines(arena: std.mem.Allocator, src: []const u8) Error![]RawLine {
    var list = std.ArrayListUnmanaged(RawLine){};
    errdefer list.deinit(arena);

    var i: usize = 0;
    var line_no: u32 = 1;
    while (i < src.len) {
        const start = i;
        while (i < src.len and src[i] != '\n') : (i += 1) {}
        var end = i;
        if (end > start and src[end - 1] == '\r') end -= 1;
        const text = src[start..end];
        const indented = text.len > 0 and (text[0] == ' ' or text[0] == '\t');
        try list.append(arena, .{
            .line_no = line_no,
            .text = text,
            .indented = indented,
        });
        if (i < src.len) i += 1;
        line_no += 1;
    }
    return try list.toOwnedSlice(arena);
}

pub fn parseIniSource(
    arena: std.mem.Allocator,
    source_label: []const u8,
    src: []const u8,
) Error!ParsedIni {
    if (src.len > max_file_bytes) return error.FileTooLarge;
    if (!std.unicode.utf8ValidateSlice(src)) return error.InvalidEncoding;

    var result = ParsedIni{};
    errdefer result.sections.deinit(arena);

    const lines = try tokenizeLines(arena, src);

    var current: ?*Section = null;
    var pending_key: ?[]const u8 = null;
    var pending_line: u32 = 0;
    var pending_indent: usize = 0;
    var pending_value = std.ArrayListUnmanaged(u8){};
    errdefer pending_value.deinit(arena);

    for (lines) |ln| {
        const content = std.mem.trim(u8, ln.text, " \t");
        if (content.len > 0 and (content[0] == '#' or content[0] == ';')) continue;
        if (content.len == 0 and pending_key != null) {
            try pending_value.append(arena, '\n');
            continue;
        }
        const indent = ln.text.len - stripLeadingSpace(ln.text).len;
        if (indent > pending_indent and pending_key != null) {
            const stripped = stripInlineComment(std.mem.trim(u8, ln.text, " \t"));
            if (stripped.len == 0) {
                try pending_value.append(arena, '\n');
                continue;
            }
            if (pending_value.items.len + 1 + stripped.len > max_value_bytes) {
                return error.InterpolationOverflow;
            }
            try pending_value.append(arena, '\n');
            try pending_value.appendSlice(arena, stripped);
            continue;
        }

        if (pending_key) |key| {
            try commitKey(arena, current, key, try pending_value.toOwnedSlice(arena), source_label, pending_line);
            try result.assignments.append(arena, .{ .section = current.?.name, .key = key, .origin = current.?.origins.get(key).? });
            pending_value = std.ArrayListUnmanaged(u8){};
            pending_key = null;
        }

        const trimmed = std.mem.trim(u8, ln.text, " \t");
        if (trimmed.len == 0) continue;
        if (trimmed[0] == '#' or trimmed[0] == ';') continue;

        if (trimmed[0] == '[') {
            // ConfigParser matches a greedy nonempty [header] prefix, permits
            // trailing text, and preserves whitespace inside the header.
            const header = stripInlineComment(trimmed);
            const close = std.mem.lastIndexOfScalar(u8, header, ']') orelse return error.UnterminatedSection;
            const name = header[1..close];
            if (name.len == 0) return error.EmptySectionName;

            if (result.sections.count() >= max_sections and
                result.sections.get(name) == null)
            {
                return error.TooManySections;
            }

            if (!std.mem.eql(u8, name, "DEFAULT") and result.sections.contains(name)) return error.DuplicateSection;
            const gop = try result.sections.getOrPut(arena, name);
            if (!gop.found_existing) {
                gop.value_ptr.* = .{ .name = name };
            }
            current = gop.value_ptr;
            continue;
        }

        const sep_idx = findSeparator(trimmed) orelse {
            return error.KeyWithoutValue;
        };

        const key = try std.ascii.allocLowerString(arena, std.mem.trim(u8, trimmed[0..sep_idx], " \t"));
        if (key.len == 0) return error.KeyWithoutValue;
        const value = stripInlineComment(std.mem.trim(u8, trimmed[sep_idx + 1 ..], " \t"));

        if (current == null) {
            return error.EmptySectionName;
        }

        pending_key = key;
        pending_line = ln.line_no;
        pending_indent = indent;
        pending_value = std.ArrayListUnmanaged(u8){};
        try pending_value.appendSlice(arena, value);
    }

    if (pending_key) |key| {
        try commitKey(arena, current, key, try pending_value.toOwnedSlice(arena), source_label, pending_line);
        try result.assignments.append(arena, .{ .section = current.?.name, .key = key, .origin = current.?.origins.get(key).? });
    }

    return result;
}

fn commitKey(
    arena: std.mem.Allocator,
    section_opt: ?*Section,
    key: []const u8,
    value: []const u8,
    source: []const u8,
    line: u32,
) Error!void {
    const sec = section_opt orelse return;
    if (sec.keys.contains(key)) return error.DuplicateOption;
    if (sec.keys.count() >= max_keys_per_section and sec.keys.get(key) == null) {
        return error.TooManyKeysInSection;
    }
    const normalized = std.mem.trimRight(u8, value, " \t\r\n");
    try sec.keys.put(arena, key, normalized);
    try sec.origins.put(arena, key, .{ .source = source, .line = line, .raw = normalized });
}

fn appendWarning(
    arena: std.mem.Allocator,
    result: *ParsedIni,
    source_label: []const u8,
    line_no: u32,
    message: []const u8,
) Error!void {
    const src_copy = try arena.dupe(u8, source_label);
    const msg_copy = try arena.dupe(u8, message);
    try result.warnings.append(arena, .{
        .source = src_copy,
        .line = line_no,
        .message = msg_copy,
    });
}

fn stripLeadingSpace(s: []const u8) []const u8 {
    var i: usize = 0;
    while (i < s.len and (s[i] == ' ' or s[i] == '\t')) : (i += 1) {}
    return s[i..];
}

fn findSeparator(s: []const u8) ?usize {
    var eq_idx: ?usize = null;
    var colon_idx: ?usize = null;
    for (s, 0..) |c, i| {
        if (c == '=' and eq_idx == null) eq_idx = i;
        if (c == ':' and colon_idx == null) colon_idx = i;
        if (eq_idx != null and colon_idx != null) break;
    }
    if (eq_idx) |ei| {
        if (colon_idx) |ci| return if (ei < ci) ei else ci;
        return ei;
    }
    return colon_idx;
}

// Resolve from raw origins, never from another field's previously expanded result.
// This preserves consumer context and literal percent escapes across repeated reads.
pub fn resolve(arena: std.mem.Allocator, ini: *const ParsedIni, section_name: []const u8, key: []const u8) Error!?[]const u8 {
    const sec = ini.section(section_name) orelse return null;
    const raw = rawGet(sec, key) orelse if (ini.section("DEFAULT")) |d| rawGet(d, key) else null;
    return if (raw) |v| try expandValue(arena, ini, section_name, v, 0, key) else null;
}

fn rawGet(sec: *const Section, key: []const u8) ?[]const u8 {
    if (sec.origins.get(key)) |o| return o.raw;
    return sec.get(key);
}

pub fn interpolate(arena: std.mem.Allocator, ini: *ParsedIni) Error!void {
    var it = ini.sections.iterator();
    while (it.next()) |entry| {
        var keys = entry.value_ptr.keys.iterator();
        while (keys.next()) |kv| {
            kv.value_ptr.* = (resolve(arena, ini, entry.key_ptr.*, kv.key_ptr.*) catch |err| switch (err) {
                error.InterpolationCycle, error.InterpolationOverflow, error.InterpolationUnterminated, error.InterpolationMissingOption => {
                    const origin = entry.value_ptr.origins.get(kv.key_ptr.*);
                    try appendWarning(arena, ini, if (origin) |o| o.source else entry.key_ptr.*, if (origin) |o| o.line else 0, @errorName(err));
                    continue;
                },
                else => return err,
            }) orelse kv.value_ptr.*;
        }
    }
}

fn expandValue(arena: std.mem.Allocator, ini: *const ParsedIni, section_name: []const u8, src: []const u8, depth: usize, self_key: []const u8) Error![]const u8 {
    if (depth >= max_interp_depth) return error.InterpolationCycle;
    var out = std.ArrayListUnmanaged(u8){};
    _ = self_key;
    const local = ini.section(section_name).?;
    const defaults = ini.section("DEFAULT");
    var i: usize = 0;
    while (i < src.len) {
        if (src[i] == '%' and i + 1 < src.len and src[i + 1] == '%') {
            try out.append(arena, '%');
            i += 2;
        } else if (src[i] == '%' and i + 1 < src.len and src[i + 1] == '(') {
            const close = std.mem.indexOfScalarPos(u8, src, i + 2, ')') orelse return error.InterpolationUnterminated;
            if (close + 1 >= src.len or src[close + 1] != 's') return error.InterpolationUnterminated;
            const name = try std.ascii.allocLowerString(arena, src[i + 2 .. close]);
            var raw: ?[]const u8 = null;
            if (std.mem.eql(u8, name, "__name__")) {
                raw = section_name;
            } else if (std.mem.indexOfScalar(u8, name, '/')) |slash| {
                const prefix = name[0..slash];
                const option = name[slash + 1 ..];
                if (std.mem.eql(u8, prefix, "known")) {
                    raw = rawGet(local, name) orelse local.previous.get(option);
                } else if (!std.mem.eql(u8, prefix, "default")) {
                    // BasicInterpolation folds the complete variable name before lookup.
                    const other = ini.section(prefix) orelse return error.InterpolationMissingOption;
                    raw = rawGet(other, option);
                }
                if (raw == null) if (defaults) |d| {
                    raw = rawGet(d, option);
                };
            } else {
                raw = rawGet(local, name);
                if (raw == null) if (defaults) |d| {
                    raw = rawGet(d, name);
                };
            }
            const value = raw orelse return error.InterpolationMissingOption;
            // BasicInterpolation recurses only when the replacement contains %.
            try out.appendSlice(arena, if (std.mem.indexOfScalar(u8, value, '%') != null) try expandValue(arena, ini, section_name, value, depth + 1, "") else value);
            i = close + 2;
        } else {
            if (src[i] == '%') return error.InterpolationUnterminated;
            try out.append(arena, src[i]);
            i += 1;
        }
        if (out.items.len > max_value_bytes) return error.InterpolationOverflow;
    }
    return try out.toOwnedSlice(arena);
}

fn stripInlineComment(value: []const u8) []const u8 {
    for (value, 0..) |c, i| {
        if (c == ';' and (i == 0 or std.ascii.isWhitespace(value[i - 1]))) return std.mem.trimRight(u8, value[0..i], " \t");
    }
    return value;
}

fn mergeInto(
    arena: std.mem.Allocator,
    base: *ParsedIni,
    override: ParsedIni,
) Error!void {
    var sec_it = override.sections.iterator();
    while (sec_it.next()) |entry| {
        const original_name = entry.key_ptr.*;
        const condition = std.mem.indexOfScalar(u8, original_name, '?');
        const name = if (condition) |q| original_name[0..q] else original_name;
        const src_sec = entry.value_ptr;
        if (base.sections.count() >= max_sections and base.section(name) == null) return error.TooManySections;
        const gop = try base.sections.getOrPut(arena, name);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{ .name = name };
        }
        var key_it = src_sec.keys.iterator();
        while (key_it.next()) |kv| {
            const key = if (condition) |q| try std.fmt.allocPrint(arena, "{s}{s}", .{ kv.key_ptr.*, original_name[q..] }) else kv.key_ptr.*;
            if (gop.value_ptr.keys.count() >= max_keys_per_section and
                gop.value_ptr.keys.get(key) == null)
            {
                return error.TooManyKeysInSection;
            }
            if (!std.mem.eql(u8, name, "DEFAULT")) {
                if (rawGet(gop.value_ptr, key)) |previous| try gop.value_ptr.previous.put(arena, key, previous);
            }
            try gop.value_ptr.keys.put(arena, key, kv.value_ptr.*);
            if (src_sec.origins.get(kv.key_ptr.*)) |origin| try gop.value_ptr.origins.put(arena, key, origin);
        }
    }

    try base.assignments.appendSlice(arena, override.assignments.items);
    for (override.warnings.items) |w| {
        try base.warnings.append(arena, w);
    }
}

pub fn loadJailConfig(arena: std.mem.Allocator, source_dir: []const u8) Error!ParsedIni {
    return loadConfig(arena, source_dir, "jail");
}

pub fn loadConfig(arena: std.mem.Allocator, source_dir: []const u8, stem: []const u8) Error!ParsedIni {
    var result = ParsedIni{};
    var files = std.ArrayListUnmanaged([]const u8){};
    const drop_dir = try std.fmt.allocPrint(arena, "{s}.d", .{stem});
    for ([_][]const u8{ ".conf", ".local" }) |extension| {
        try files.append(arena, try std.fmt.allocPrint(arena, "{s}{s}", .{ stem, extension }));
        const full_dir = try std.fs.path.join(arena, &.{ source_dir, drop_dir });
        if (try openOptionalDir(full_dir)) |handle| {
            var dir = handle;
            defer dir.close();
            for (try collectConfigFiles(arena, &dir, extension)) |name| try files.append(arena, try std.fs.path.join(arena, &.{ drop_dir, name }));
        }
    }
    var stack = std.ArrayListUnmanaged([]const u8){};
    for (files.items) |path| try loadOccurrence(arena, &result, source_dir, path, files.items, &stack, .layer);
    try interpolate(arena, &result);
    return result;
}

fn loadOccurrence(arena: std.mem.Allocator, result: *ParsedIni, root: []const u8, path: []const u8, top: []const []const u8, stack: *std.ArrayListUnmanaged([]const u8), source_edge: SourceEdge) Error!void {
    const full = if (std.fs.path.isAbsolute(path)) try std.fs.path.resolve(arena, &.{path}) else try std.fs.path.resolve(arena, &.{ root, path });
    for (stack.items) |ancestor| if (std.mem.eql(u8, ancestor, full)) {
        try appendWarning(arena, result, full, 0, "include cycle skipped");
        return;
    };
    if (stack.items.len >= 64) return error.IncludeDepthExceeded;
    const bytes = (try readOptionalFile(arena, "", full)) orelse {
        try loadAdjacentLocal(arena, result, root, full, top, stack);
        return;
    };
    const target = std.fs.cwd().realpathAlloc(arena, full) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.AccessDenied => return error.AccessDenied,
        else => return error.ReadFailed,
    };
    if (result.sources.items.len >= max_files_per_dir) return error.TooManyFiles;
    try stack.append(arena, full);
    defer _ = stack.pop();
    var parsed = try parseIniSource(arena, full, bytes);
    for ([_][]const u8{ "before", "after" }) |edge| {
        if (std.mem.eql(u8, edge, "after")) {
            try mergeInto(arena, result, parsed);
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
            try result.sources.append(arena, .{ .edge = source_edge, .original_path = path, .resolved_target = target, .parent_path = if (stack.items.len > 1) stack.items[stack.items.len - 2] else null, .path = full, .bytes = bytes, .sha256 = digest });
        }
        if (try resolve(arena, &parsed, "INCLUDES", edge)) |value| {
            var lines = std.mem.splitScalar(u8, value, '\n');
            while (lines.next()) |line| {
                const include = std.mem.trim(u8, line, " \t");
                if (include.len == 0) continue;
                try loadOccurrence(arena, result, std.fs.path.dirname(full).?, include, &.{}, stack, if (std.mem.eql(u8, edge, "before")) .before else .after);
            }
        }
    }
    try loadAdjacentLocal(arena, result, root, full, top, stack);
}

fn loadAdjacentLocal(arena: std.mem.Allocator, result: *ParsedIni, root: []const u8, full: []const u8, top: []const []const u8, stack: *std.ArrayListUnmanaged([]const u8)) Error!void {
    if (!std.mem.endsWith(u8, full, ".local")) {
        const ext = std.fs.path.extension(full);
        const local = try std.fmt.allocPrint(arena, "{s}.local", .{full[0 .. full.len - ext.len]});
        var listed = false;
        for (top) |entry| {
            const candidate = try std.fs.path.resolve(arena, &.{ root, entry });
            if (std.mem.eql(u8, candidate, local)) {
                listed = true;
                break;
            }
        }
        if (!listed) try loadOccurrence(arena, result, "", local, &.{}, stack, .local);
    }
}

fn readOptionalFile(
    arena: std.mem.Allocator,
    source_dir: []const u8,
    rel_path: []const u8,
) Error!?[]const u8 {
    const full = std.fs.path.join(arena, &[_][]const u8{ source_dir, rel_path }) catch return error.OutOfMemory;
    const file = std.fs.cwd().openFile(full, .{}) catch |err| switch (err) {
        error.FileNotFound => return null,
        error.AccessDenied => return error.AccessDenied,
        else => return error.ReadFailed,
    };
    defer file.close();

    const bytes = file.readToEndAlloc(arena, max_file_bytes) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.FileTooBig => return error.FileTooLarge,
        else => return error.ReadFailed,
    };
    return bytes;
}

fn openOptionalDir(path: []const u8) Error!?std.fs.Dir {
    const dir = std.fs.cwd().openDir(path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return null,
        error.AccessDenied => return error.AccessDenied,
        error.NotDir => return null,
        else => return error.ReadFailed,
    };
    return dir;
}

fn collectConfigFiles(arena: std.mem.Allocator, dir: *std.fs.Dir, extension: []const u8) Error![]const []const u8 {
    var list = std.ArrayListUnmanaged([]const u8){};
    errdefer list.deinit(arena);

    var it = dir.iterate();
    while (it.next() catch return error.ReadFailed) |entry| {
        if (entry.kind != .file and entry.kind != .sym_link) continue;
        if (!std.mem.endsWith(u8, entry.name, extension)) continue;
        if (list.items.len >= max_files_per_dir) return error.TooManyFiles;
        const name_copy = try arena.dupe(u8, entry.name);
        try list.append(arena, name_copy);
    }

    const slice = try list.toOwnedSlice(arena);
    std.mem.sort([]const u8, slice, {}, stringLessThan);
    return slice;
}

fn stringLessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

pub const TranslatedPattern = struct {
    original: []const u8,
    pattern: []const u8,
};

pub const ParsedFilter = struct {
    failregex: []const TranslatedPattern = &.{},
    ignoreregex: []const TranslatedPattern = &.{},
    warnings: []const Warning = &.{},
};

pub fn parseFilterSource(
    arena: std.mem.Allocator,
    source_label: []const u8,
    src: []const u8,
) Error!ParsedFilter {
    var ini = try parseIniSource(arena, source_label, src);
    try interpolate(arena, &ini);

    var warnings = std.ArrayListUnmanaged(Warning){};
    errdefer warnings.deinit(arena);

    const def_sec = findSectionCaseInsensitive(&ini, "Definition");

    var failregex_list = std.ArrayListUnmanaged(TranslatedPattern){};
    errdefer failregex_list.deinit(arena);
    var ignoreregex_list = std.ArrayListUnmanaged(TranslatedPattern){};
    errdefer ignoreregex_list.deinit(arena);

    if (def_sec) |sec| {
        if (sec.get("failregex")) |raw| {
            try translatePatternList(arena, source_label, raw, &failregex_list, &warnings);
        }
        if (sec.get("ignoreregex")) |raw| {
            try translatePatternList(arena, source_label, raw, &ignoreregex_list, &warnings);
        }
    } else {
        try appendWarningList(arena, &warnings, source_label, 0, "filter has no [Definition] section");
    }

    for (ini.warnings.items) |w| try warnings.append(arena, w);

    return .{
        .failregex = try failregex_list.toOwnedSlice(arena),
        .ignoreregex = try ignoreregex_list.toOwnedSlice(arena),
        .warnings = try warnings.toOwnedSlice(arena),
    };
}

pub fn parseFilterFile(
    arena: std.mem.Allocator,
    path: []const u8,
) Error!ParsedFilter {
    const file = std.fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return error.FileNotFound,
        error.AccessDenied => return error.AccessDenied,
        else => return error.ReadFailed,
    };
    defer file.close();
    const bytes = file.readToEndAlloc(arena, max_file_bytes) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.FileTooBig => return error.FileTooLarge,
        else => return error.ReadFailed,
    };
    return parseFilterSource(arena, path, bytes);
}

fn appendWarningList(
    arena: std.mem.Allocator,
    list: *std.ArrayListUnmanaged(Warning),
    source_label: []const u8,
    line_no: u32,
    message: []const u8,
) Error!void {
    try list.append(arena, .{
        .source = try arena.dupe(u8, source_label),
        .line = line_no,
        .message = try arena.dupe(u8, message),
    });
}

fn findSectionCaseInsensitive(ini: *const ParsedIni, name: []const u8) ?*const Section {
    var it = ini.sections.iterator();
    while (it.next()) |e| {
        if (asciiEqlIgnoreCase(e.key_ptr.*, name)) return e.value_ptr;
    }
    return null;
}

fn asciiEqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        const la = std.ascii.toLower(ca);
        const lb = std.ascii.toLower(cb);
        if (la != lb) return false;
    }
    return true;
}

fn translatePatternList(
    arena: std.mem.Allocator,
    source_label: []const u8,
    raw: []const u8,
    out: *std.ArrayListUnmanaged(TranslatedPattern),
    warn: *std.ArrayListUnmanaged(Warning),
) Error!void {
    var it = std.mem.splitScalar(u8, raw, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t");
        if (trimmed.len == 0) continue;

        const translated = translatePythonRegex(arena, trimmed) catch |err| switch (err) {
            error.UnsupportedRegex => {
                try appendWarningList(arena, warn, source_label, 0, "unsupported regex feature; pattern skipped");
                continue;
            },
            else => return err,
        };

        if (!std.mem.containsAtLeast(u8, translated, 1, "<IP>")) {
            try appendWarningList(arena, warn, source_label, 0, "translated pattern has no <IP> token; skipped");
            continue;
        }

        try out.append(arena, .{
            .original = try arena.dupe(u8, trimmed),
            .pattern = translated,
        });
    }
}

pub fn translatePythonRegex(
    arena: std.mem.Allocator,
    regex: []const u8,
) Error![]const u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(arena);
    try out.ensureTotalCapacity(arena, regex.len);

    var i: usize = 0;
    while (i < regex.len) {
        const c = regex[i];

        if (c == '^' or c == '$') {
            i += 1;
            continue;
        }

        if (c == '\\') {
            if (i + 1 >= regex.len) return error.UnsupportedRegex;
            const nxt = regex[i + 1];
            switch (nxt) {
                's', 'S' => {
                    try appendWildcard(&out, arena);
                    i += 2;
                    continue;
                },
                'w', 'W' => {
                    try appendWildcard(&out, arena);
                    i += 2;
                    continue;
                },
                'd' => {
                    if (tryConsumeIpv4Literal(regex, i)) |consumed| {
                        try out.appendSlice(arena, "<IP>");
                        i = consumed;
                        continue;
                    }
                    try appendWildcard(&out, arena);
                    i += 2;
                    if (i < regex.len and isQuantifier(regex[i])) i += 1;
                    continue;
                },
                'D' => {
                    try appendWildcard(&out, arena);
                    i += 2;
                    continue;
                },
                '.', '+', '*', '?', '(', ')', '[', ']', '{', '}', '|', '^', '$', '\\', '/', ' ', '\t', '-', '#', '"', '\'' => {
                    try out.append(arena, nxt);
                    i += 2;
                    continue;
                },
                'n' => {
                    try out.append(arena, '\n');
                    i += 2;
                    continue;
                },
                't' => {
                    try out.append(arena, '\t');
                    i += 2;
                    continue;
                },
                '1'...'9' => return error.UnsupportedRegex,
                else => {
                    try out.append(arena, nxt);
                    i += 2;
                    continue;
                },
            }
        }

        if (c == '(') {
            if (i + 2 < regex.len and regex[i + 1] == '?') {
                const p = regex[i + 2];
                if (p == '=' or p == '!' or p == '(') return error.UnsupportedRegex;
                if (p == '<' and i + 3 < regex.len) {
                    const q = regex[i + 3];
                    if (q == '=' or q == '!') return error.UnsupportedRegex;
                }
            }

            if (findHostInGroup(regex[i..])) |host_end| {
                try out.appendSlice(arena, "<IP>");
                i += host_end;
                continue;
            }

            const end = findMatchingParen(regex, i) orelse return error.UnsupportedRegex;
            const inner_start = innerGroupStart(regex, i);
            const inner = regex[inner_start..end];
            const inner_translated = try translatePythonRegex(arena, inner);
            if (std.mem.indexOfScalar(u8, inner, '|') != null) {
                try appendWildcard(&out, arena);
            } else {
                try out.appendSlice(arena, inner_translated);
            }
            i = end + 1;
            if (i < regex.len and isQuantifier(regex[i])) {
                try appendWildcard(&out, arena);
                i += 1;
            }
            continue;
        }

        if (c == '[') {
            const end = std.mem.indexOfScalarPos(u8, regex, i + 1, ']') orelse return error.UnsupportedRegex;
            i = end + 1;
            try appendWildcard(&out, arena);
            if (i < regex.len and isQuantifier(regex[i])) i += 1;
            continue;
        }

        if (c == '.') {
            try appendWildcard(&out, arena);
            i += 1;
            if (i < regex.len and isQuantifier(regex[i])) i += 1;
            continue;
        }

        if (c == '<') {
            const close = std.mem.indexOfScalarPos(u8, regex, i + 1, '>') orelse return error.UnsupportedRegex;
            const name = regex[i + 1 .. close];
            if (asciiEqlIgnoreCase(name, "HOST")) {
                try out.appendSlice(arena, "<IP>");
            } else if (asciiEqlIgnoreCase(name, "IP")) {
                try out.appendSlice(arena, "<IP>");
            } else if (asciiEqlIgnoreCase(name, "TIMESTAMP")) {
                try out.appendSlice(arena, "<TIMESTAMP>");
            } else {
                try appendWildcard(&out, arena);
            }
            i = close + 1;
            continue;
        }

        if (c == '*' or c == '+' or c == '?') {
            i += 1;
            continue;
        }

        try out.append(arena, c);
        i += 1;
    }

    return try out.toOwnedSlice(arena);
}

fn isQuantifier(c: u8) bool {
    return c == '*' or c == '+' or c == '?';
}

fn appendWildcard(out: *std.ArrayListUnmanaged(u8), arena: std.mem.Allocator) Error!void {
    const items = out.items;
    if (items.len >= 3 and std.mem.eql(u8, items[items.len - 3 ..], "<*>")) return;
    try out.appendSlice(arena, "<*>");
}

fn tryConsumeIpv4Literal(regex: []const u8, start: usize) ?usize {
    const canonical = "\\d+\\.\\d+\\.\\d+\\.\\d+";
    if (start + canonical.len > regex.len) return null;
    if (!std.mem.eql(u8, regex[start .. start + canonical.len], canonical)) return null;
    return start + canonical.len;
}

fn findHostInGroup(slice: []const u8) ?usize {
    var i: usize = 1;
    if (i < slice.len and slice[i] == '?') {
        i += 1;
        if (i < slice.len and slice[i] == 'P') {
            i += 1;
            if (i >= slice.len or slice[i] != '<') return null;
            i += 1;
            while (i < slice.len and slice[i] != '>') : (i += 1) {}
            if (i >= slice.len) return null;
            i += 1;
        } else if (i < slice.len and slice[i] == ':') {
            i += 1;
        } else return null;
    }
    const host_tok = "<HOST>";
    if (i + host_tok.len > slice.len) return null;
    if (!std.mem.eql(u8, slice[i .. i + host_tok.len], host_tok)) return null;
    i += host_tok.len;
    if (i >= slice.len or slice[i] != ')') return null;
    return i + 1;
}

fn findMatchingParen(regex: []const u8, open_idx: usize) ?usize {
    var depth: usize = 0;
    var i: usize = open_idx;
    while (i < regex.len) : (i += 1) {
        const c = regex[i];
        if (c == '\\' and i + 1 < regex.len) {
            i += 1;
            continue;
        }
        if (c == '(') depth += 1;
        if (c == ')') {
            depth -= 1;
            if (depth == 0) return i;
        }
    }
    return null;
}

fn innerGroupStart(regex: []const u8, open_idx: usize) usize {
    var i = open_idx + 1;
    if (i < regex.len and regex[i] == '?') {
        i += 1;
        if (i < regex.len and regex[i] == ':') {
            i += 1;
        } else if (i < regex.len and regex[i] == 'P') {
            i += 1;
            if (i < regex.len and regex[i] == '<') {
                i += 1;
                while (i < regex.len and regex[i] != '>') : (i += 1) {}
                if (i < regex.len) i += 1;
            }
        }
    }
    return i;
}

pub const ActionBackend = enum {
    nftables,
    iptables,
    ipset,
    log_only,
};

pub const ParsedAction = struct {
    name: []const u8,
    backend: ActionBackend,
    actionstart: []const u8 = "",
    actionstop: []const u8 = "",
    actionban: []const u8 = "",
    actionunban: []const u8 = "",
    actioncheck: []const u8 = "",
    warnings: []const Warning = &.{},
};

pub fn parseActionSource(
    arena: std.mem.Allocator,
    action_name: []const u8,
    src: []const u8,
) Error!ParsedAction {
    var ini = try parseIniSource(arena, action_name, src);
    try interpolate(arena, &ini);

    var warnings = std.ArrayListUnmanaged(Warning){};
    errdefer warnings.deinit(arena);

    const backend = mapActionNameToBackend(action_name);
    if (backend == .log_only) {
        try appendWarningList(
            arena,
            &warnings,
            action_name,
            0,
            "action name not recognized; mapped to log-only backend",
        );
    }

    const def_sec = findSectionCaseInsensitive(&ini, "Definition");
    var result = ParsedAction{
        .name = try arena.dupe(u8, action_name),
        .backend = backend,
    };

    if (def_sec) |sec| {
        if (sec.get("actionstart")) |v| result.actionstart = v;
        if (sec.get("actionstop")) |v| result.actionstop = v;
        if (sec.get("actionban")) |v| result.actionban = v;
        if (sec.get("actionunban")) |v| result.actionunban = v;
        if (sec.get("actioncheck")) |v| result.actioncheck = v;
    } else {
        try appendWarningList(arena, &warnings, action_name, 0, "action has no [Definition] section");
    }

    for (ini.warnings.items) |w| try warnings.append(arena, w);
    result.warnings = try warnings.toOwnedSlice(arena);
    return result;
}

pub fn parseActionFile(
    arena: std.mem.Allocator,
    path: []const u8,
) Error!ParsedAction {
    const basename = std.fs.path.basename(path);
    const stem = if (std.mem.endsWith(u8, basename, ".conf"))
        basename[0 .. basename.len - ".conf".len]
    else
        basename;

    const file = std.fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return error.FileNotFound,
        error.AccessDenied => return error.AccessDenied,
        else => return error.ReadFailed,
    };
    defer file.close();
    const bytes = file.readToEndAlloc(arena, max_file_bytes) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.FileTooBig => return error.FileTooLarge,
        else => return error.ReadFailed,
    };
    return parseActionSource(arena, stem, bytes);
}

pub fn mapActionNameToBackend(name: []const u8) ActionBackend {
    if (std.mem.startsWith(u8, name, "nftables")) return .nftables;
    if (std.mem.startsWith(u8, name, "iptables")) return .iptables;
    if (std.mem.startsWith(u8, name, "ipset")) return .ipset;
    return .log_only;
}

const testing = std.testing;

test "fail2ban: parse minimal section" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src =
        \\[sshd]
        \\enabled = true
        \\maxretry = 3
    ;
    var ini = try parseIniSource(arena.allocator(), "jail.conf", src);
    try testing.expectEqual(@as(usize, 1), ini.sections.count());
    const sec = ini.section("sshd").?;
    try testing.expectEqualStrings("true", sec.get("enabled").?);
    try testing.expectEqualStrings("3", sec.get("maxretry").?);
}

test "fail2ban: parse tolerates comments both # and ;" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src =
        \\# hash comment
        \\; semicolon comment
        \\[sshd]
        \\# another
        \\maxretry = 5 # trailing NOT stripped
        \\findtime: 600
    ;
    var ini = try parseIniSource(arena.allocator(), "test", src);
    const sec = ini.section("sshd").?;
    try testing.expectEqualStrings("5 # trailing NOT stripped", sec.get("maxretry").?);
    try testing.expectEqualStrings("600", sec.get("findtime").?);
}

test "fail2ban: parse multi-line value via indent continuation" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src =
        \\[Definition]
        \\failregex = first pattern
        \\            second pattern
        \\            third pattern
        \\ignoreregex = solo
    ;
    var ini = try parseIniSource(arena.allocator(), "test", src);
    const sec = ini.section("Definition").?;
    const fr = sec.get("failregex").?;
    try testing.expect(std.mem.indexOf(u8, fr, "first pattern") != null);
    try testing.expect(std.mem.indexOf(u8, fr, "second pattern") != null);
    try testing.expect(std.mem.indexOf(u8, fr, "third pattern") != null);
    try testing.expectEqualStrings("solo", sec.get("ignoreregex").?);
}

test "fail2ban: parse DEFAULT interpolation" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src =
        \\[DEFAULT]
        \\bantime = 600
        \\findtime = 600
        \\maxretry = 5
        \\
        \\[sshd]
        \\enabled = true
        \\bantime = %(default/bantime)s
        \\custom = ban=%(bantime)s find=%(findtime)s
    ;
    var ini = try parseIniSource(arena.allocator(), "test", src);
    try interpolate(arena.allocator(), &ini);

    const sshd = ini.section("sshd").?;
    try testing.expectEqualStrings("600", sshd.get("bantime").?);
    try testing.expectEqualStrings("ban=600 find=600", sshd.get("custom").?);
}

test "fail2ban: interpolate detects cycles and keeps raw" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src =
        \\[DEFAULT]
        \\a = %(b)s
        \\b = %(a)s
        \\
        \\[x]
        \\v = %(a)s
    ;
    var ini = try parseIniSource(arena.allocator(), "test", src);
    try interpolate(arena.allocator(), &ini);
    try testing.expect(ini.warnings.items.len > 0);
}

test "fail2ban: parse section headers rejected when unterminated" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src = "[sshd\nfoo = 1\n";
    try testing.expectError(error.UnterminatedSection, parseIniSource(arena.allocator(), "test", src));
}

test "fail2ban: realistic jail.conf snippet" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src =
        \\[DEFAULT]
        \\bantime = 3600
        \\findtime = 600
        \\maxretry = 5
        \\ignoreip = 127.0.0.1/8 10.0.0.0/8
        \\backend = systemd
        \\
        \\[sshd]
        \\enabled = true
        \\port = ssh
        \\filter = sshd
        \\logpath = /var/log/auth.log
        \\maxretry = 3
        \\bantime = %(default/bantime)s
        \\
        \\[nginx-http-auth]
        \\enabled = true
        \\filter = nginx-http-auth
        \\logpath = /var/log/nginx/error.log
        \\
        \\[recidive]
        \\enabled = false
        \\logpath = /var/log/fail2ban.log
        \\bantime  = 604800
        \\findtime = 86400
        \\maxretry = 5
    ;
    var ini = try parseIniSource(arena.allocator(), "jail.conf", src);
    try interpolate(arena.allocator(), &ini);

    try testing.expect(ini.section("sshd") != null);
    try testing.expect(ini.section("nginx-http-auth") != null);
    try testing.expect(ini.section("recidive") != null);

    const sshd = ini.section("sshd").?;
    try testing.expectEqualStrings("sshd", sshd.get("filter").?);
    try testing.expectEqualStrings("3", sshd.get("maxretry").?);
    try testing.expectEqualStrings("3600", sshd.get("bantime").?);
    try testing.expectEqualStrings("systemd", ini.section("DEFAULT").?.get("backend").?);
    try testing.expect(sshd.get("backend") == null);
}

test "fail2ban: merge jail.conf + jail.local override" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const base =
        \\[DEFAULT]
        \\bantime = 600
        \\[sshd]
        \\enabled = false
        \\filter = sshd
        \\maxretry = 5
    ;
    const override =
        \\[sshd]
        \\enabled = true
        \\maxretry = 3
    ;

    var result = try parseIniSource(arena.allocator(), "jail.conf", base);
    const ov = try parseIniSource(arena.allocator(), "jail.local", override);
    try mergeInto(arena.allocator(), &result, ov);
    try interpolate(arena.allocator(), &result);

    const sshd = result.section("sshd").?;
    try testing.expectEqualStrings("true", sshd.get("enabled").?);
    try testing.expectEqualStrings("3", sshd.get("maxretry").?);
    try testing.expectEqualStrings("sshd", sshd.get("filter").?);
}

test "fail2ban: loadJailConfig reads jail.conf + jail.local + jail.d" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{
        .sub_path = "jail.conf",
        .data =
        \\[DEFAULT]
        \\bantime = 600
        \\[sshd]
        \\enabled = false
        ,
    });
    try tmp.dir.writeFile(.{
        .sub_path = "jail.local",
        .data =
        \\[sshd]
        \\enabled = true
        ,
    });
    try tmp.dir.makeDir("jail.d");
    try tmp.dir.writeFile(.{
        .sub_path = "jail.d/00-extra.conf",
        .data =
        \\[nginx]
        \\enabled = true
        \\filter = nginx
        ,
    });

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const path = try tmp.dir.realpathAlloc(arena.allocator(), ".");
    var ini = try loadJailConfig(arena.allocator(), path);

    const sshd = ini.section("sshd").?;
    try testing.expectEqualStrings("true", sshd.get("enabled").?);
    const nginx = ini.section("nginx").?;
    try testing.expectEqualStrings("true", nginx.get("enabled").?);
}

test "fail2ban: too many sections triggers typed error" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var buf = std.ArrayListUnmanaged(u8){};
    defer buf.deinit(arena.allocator());
    var i: usize = 0;
    while (i < max_sections + 2) : (i += 1) {
        try buf.writer(arena.allocator()).print("[s{d}]\nk = v\n", .{i});
    }
    try testing.expectError(
        error.TooManySections,
        parseIniSource(arena.allocator(), "test", buf.items),
    );
}

test "fail2ban: translate simple sshd pattern via <HOST>" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src =
        \\[Definition]
        \\failregex = ^Failed password for .* from <HOST>$
    ;
    const f = try parseFilterSource(arena.allocator(), "sshd.conf", src);
    try testing.expectEqual(@as(usize, 1), f.failregex.len);
    try testing.expectEqualStrings("Failed password for <*> from <IP>", f.failregex[0].pattern);
}

test "fail2ban: translate multi-line failregex" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src =
        \\[Definition]
        \\failregex = ^Failed password for .* from <HOST>$
        \\            ^Invalid user .* from <HOST>$
        \\            ^Connection closed by <HOST>$
    ;
    const f = try parseFilterSource(arena.allocator(), "sshd.conf", src);
    try testing.expectEqual(@as(usize, 3), f.failregex.len);
    try testing.expect(std.mem.indexOf(u8, f.failregex[0].pattern, "<IP>") != null);
    try testing.expect(std.mem.indexOf(u8, f.failregex[1].pattern, "<IP>") != null);
    try testing.expect(std.mem.indexOf(u8, f.failregex[2].pattern, "<IP>") != null);
}

test "fail2ban: translate explicit IPv4 regex to <IP>" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src =
        \\[Definition]
        \\failregex = ^Rejected from \d+\.\d+\.\d+\.\d+ for abuse$
    ;
    const f = try parseFilterSource(arena.allocator(), "custom.conf", src);
    try testing.expectEqual(@as(usize, 1), f.failregex.len);
    try testing.expectEqualStrings("Rejected from <IP> for abuse", f.failregex[0].pattern);
}

test "fail2ban: translate unsupported lookahead generates warning" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src =
        \\[Definition]
        \\failregex = ^Foo from <HOST>(?=bar)$
    ;
    const f = try parseFilterSource(arena.allocator(), "weird.conf", src);
    try testing.expectEqual(@as(usize, 0), f.failregex.len);
    try testing.expect(f.warnings.len >= 1);
}

test "fail2ban: translate backreference is rejected" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src =
        \\[Definition]
        \\failregex = ^(\w+) \1 from <HOST>$
    ;
    const f = try parseFilterSource(arena.allocator(), "weird.conf", src);
    try testing.expectEqual(@as(usize, 0), f.failregex.len);
    try testing.expect(f.warnings.len >= 1);
}

test "fail2ban: translate realistic postfix pattern" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src =
        \\[Definition]
        \\failregex = ^.* postfix/smtpd.*: NOQUEUE: reject: RCPT from \S+\[<HOST>\]: .*$
    ;
    const f = try parseFilterSource(arena.allocator(), "postfix.conf", src);
    try testing.expectEqual(@as(usize, 1), f.failregex.len);
    try testing.expect(std.mem.indexOf(u8, f.failregex[0].pattern, "<IP>") != null);
}

test "fail2ban: translate missing [Definition] warns" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src =
        \\[Init]
        \\foo = bar
    ;
    const f = try parseFilterSource(arena.allocator(), "empty.conf", src);
    try testing.expectEqual(@as(usize, 0), f.failregex.len);
    try testing.expect(f.warnings.len >= 1);
}

test "fail2ban: action iptables-multiport maps to iptables" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src =
        \\[Definition]
        \\actionstart = iptables -N f2b-<name>
        \\actionstop = iptables -X f2b-<name>
        \\actionban = iptables -I f2b-<name> -s <ip> -j DROP
        \\actionunban = iptables -D f2b-<name> -s <ip> -j DROP
    ;
    const a = try parseActionSource(arena.allocator(), "iptables-multiport", src);
    try testing.expectEqual(ActionBackend.iptables, a.backend);
    try testing.expect(std.mem.indexOf(u8, a.actionban, "iptables") != null);
    for (a.warnings) |w| {
        try testing.expect(std.mem.indexOf(u8, w.message, "not recognized") == null);
    }
}

test "fail2ban: action nftables-allports maps to nftables" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src = "[Definition]\nactionban = nft add element <ip>\n";
    const a = try parseActionSource(arena.allocator(), "nftables-allports", src);
    try testing.expectEqual(ActionBackend.nftables, a.backend);
}

test "fail2ban: action ipset-proto6 maps to ipset" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src = "[Definition]\nactionban = ipset add f2b <ip>\n";
    const a = try parseActionSource(arena.allocator(), "ipset-proto6", src);
    try testing.expectEqual(ActionBackend.ipset, a.backend);
}

test "fail2ban: action sendmail-whois maps to log-only with warning" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src =
        \\[Definition]
        \\actionstart =
        \\actionstop =
        \\actionban = printf "From: fail2ban\nTo: admin\n" | mail
    ;
    const a = try parseActionSource(arena.allocator(), "sendmail-whois", src);
    try testing.expectEqual(ActionBackend.log_only, a.backend);
    var found_warning = false;
    for (a.warnings) |w| {
        if (std.mem.indexOf(u8, w.message, "not recognized") != null) found_warning = true;
    }
    try testing.expect(found_warning);
}

test "fail2ban: mapActionNameToBackend direct" {
    try testing.expectEqual(ActionBackend.iptables, mapActionNameToBackend("iptables"));
    try testing.expectEqual(ActionBackend.iptables, mapActionNameToBackend("iptables-multiport"));
    try testing.expectEqual(ActionBackend.iptables, mapActionNameToBackend("iptables-allports"));
    try testing.expectEqual(ActionBackend.nftables, mapActionNameToBackend("nftables"));
    try testing.expectEqual(ActionBackend.nftables, mapActionNameToBackend("nftables-multiport"));
    try testing.expectEqual(ActionBackend.ipset, mapActionNameToBackend("ipset-proto6-allports"));
    try testing.expectEqual(ActionBackend.log_only, mapActionNameToBackend("sendmail"));
    try testing.expectEqual(ActionBackend.log_only, mapActionNameToBackend("route"));
}

test "p2 config layers includes previous values and provenance" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makeDir("jail.d");
    try tmp.dir.writeFile(.{ .sub_path = "base.conf", .data = "[sample]\nmaxretry=2\n" });
    try tmp.dir.writeFile(.{ .sub_path = "jail.conf", .data = "[INCLUDES]\nbefore=base.conf\n[sample]\nvalue=base\n" });
    try tmp.dir.writeFile(.{ .sub_path = "jail.d/10.conf", .data = "[sample]\nmaxretry=3\nvalue=%(known/value)s-conf\n" });
    try tmp.dir.writeFile(.{ .sub_path = "jail.local", .data = "[sample]\nmaxretry=7\n" });
    try tmp.dir.writeFile(.{ .sub_path = "jail.d/20.local", .data = "[sample]\nmaxretry=9\nempty=\ncustom=x\n" });
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const path = try tmp.dir.realpathAlloc(a, ".");
    var ini = try loadJailConfig(a, path);
    const sec = ini.section("sample").?;
    try testing.expectEqualStrings("9", sec.get("maxretry").?);
    try testing.expectEqualStrings("base-conf", sec.get("value").?);
    try testing.expectEqualStrings("", sec.get("empty").?);
    try testing.expect(sec.get("absent") == null);
    try testing.expectEqual(@as(usize, 5), ini.sources.items.len);
    try testing.expectEqual(@as(u32, 2), sec.origins.get("maxretry").?.line);
    try testing.expect(std.mem.endsWith(u8, sec.origins.get("maxretry").?.source, "20.local"));
    try testing.expectEqualStrings("7", sec.previous.get("maxretry").?); // previous is updated only when overwritten
}

test "p2 config after and included local order" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "jail.conf", .data = "[INCLUDES]\nafter=extra.conf\n[sample]\nmaxretry=2\n" });
    try tmp.dir.writeFile(.{ .sub_path = "extra.conf", .data = "[sample]\nmaxretry=8\n" });
    try tmp.dir.writeFile(.{ .sub_path = "extra.local", .data = "[sample]\nmaxretry=9\n" });
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var ini = try loadJailConfig(arena.allocator(), try tmp.dir.realpathAlloc(arena.allocator(), "."));
    try testing.expectEqualStrings("9", ini.section("sample").?.get("maxretry").?);
}

test "p2 config raw interpolation preserves context and repeated percent escapes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var ini = try parseIniSource(a, "fixture", "[DEFAULT]\nword=base\nexpr=%(word)s\n[One]\nword=local\nvalue=%(expr)s %% %(other/text)s %(__name__)s\n[other]\ntext=other\n");
    try interpolate(a, &ini);
    try testing.expectEqualStrings("local % other One", ini.section("One").?.get("value").?);
    try interpolate(a, &ini);
    try testing.expectEqualStrings("local % other One", ini.section("One").?.get("value").?);
    try testing.expectEqualStrings("%(expr)s %% %(other/text)s %(__name__)s", ini.section("One").?.origins.get("value").?.raw);
}

test "p2 config missing interpolation remains explicit error and source diagnostic" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var ini = try parseIniSource(a, "fixture", "[x]\nMAXRETRY=%(missing)s ; comment\n");
    try testing.expectError(error.InterpolationMissingOption, resolve(a, &ini, "x", "maxretry"));
    try interpolate(a, &ini);
    try testing.expectEqual(@as(u32, 2), ini.warnings.items[0].line);
    try testing.expectEqualStrings("fixture", ini.warnings.items[0].source);
}

/// Open selector parameters remain strings until their consumer converts them.
/// Commas inside quoted values and nested brackets do not split parameters.
pub const Selector = struct {
    name: []const u8,
    parameters: std.StringArrayHashMapUnmanaged([]const u8) = .{},
};

/// Parse an asset name followed by ordered parameter groups. Repeated keys in
/// later groups replace earlier values, including conditional parameter names.
pub fn parseSelector(arena: std.mem.Allocator, input: []const u8) Error!Selector {
    const text = std.mem.trim(u8, input, " \t\r\n");
    const open = std.mem.indexOfScalar(u8, text, '[') orelse {
        if (text.len == 0) return error.InvalidParameter;
        return .{ .name = try arena.dupe(u8, text) };
    };
    const name = std.mem.trim(u8, text[0..open], " \t\r\n");
    if (name.len == 0) return error.InvalidParameter;
    var result = Selector{ .name = try arena.dupe(u8, name) };
    var i = open;
    while (i < text.len) {
        while (i < text.len and std.ascii.isWhitespace(text[i])) : (i += 1) {}
        if (i == text.len) break;
        if (text[i] != '[') return error.InvalidParameter;
        i += 1;
        while (true) {
            while (i < text.len and std.ascii.isWhitespace(text[i])) : (i += 1) {}
            if (i == text.len) return error.InvalidParameter;
            if (text[i] == ']') {
                i += 1;
                break;
            }
            const key_start = i;
            while (i < text.len and text[i] != '=' and text[i] != ',' and text[i] != ']') : (i += 1) {}
            if (i == text.len or text[i] != '=') return error.InvalidParameter;
            // The first '=' belongs to a conditional key such as n?family=inet6.
            if (std.mem.indexOfScalar(u8, text[key_start..i], '?') != null) {
                i += 1;
                while (i < text.len and text[i] != '=' and text[i] != ',' and text[i] != ']') : (i += 1) {}
                if (i == text.len or text[i] != '=') return error.InvalidParameter;
            }
            const key = std.mem.trim(u8, text[key_start..i], " \t\r\n");
            if (key.len == 0) return error.InvalidParameter;
            i += 1;
            while (i < text.len and std.ascii.isWhitespace(text[i])) : (i += 1) {}
            var value: []const u8 = undefined;
            if (i < text.len and (text[i] == '\'' or text[i] == '"')) {
                const quote = text[i];
                i += 1;
                const value_start = i;
                while (i < text.len and text[i] != quote) : (i += 1) {}
                if (i == text.len) return error.InvalidParameter;
                value = std.mem.trim(u8, text[value_start..i], " \t\r\n");
                i += 1;
                while (i < text.len and std.ascii.isWhitespace(text[i])) : (i += 1) {}
            } else {
                const value_start = i;
                while (i < text.len and text[i] != ',' and text[i] != ']') : (i += 1) {}
                value = std.mem.trim(u8, text[value_start..i], " \t\r\n");
            }
            if (i == text.len or (text[i] != ',' and text[i] != ']')) return error.InvalidParameter;
            if (result.parameters.count() >= max_keys_per_section and !result.parameters.contains(key)) return error.TooManyKeysInSection;
            try result.parameters.put(arena, try arena.dupe(u8, key), try arena.dupe(u8, value));
            if (text[i] == ',') i += 1;
        }
    }
    return result;
}

/// Ordered action instances: whitespace separates instances only outside brackets
/// and quotes. The asset parser remains responsible for parameter syntax.
pub fn splitSelectors(arena: std.mem.Allocator, input: []const u8) Error![]const []const u8 {
    var result = std.ArrayListUnmanaged([]const u8){};
    var start: usize = 0;
    var depth: usize = 0;
    var quote: u8 = 0;
    var i: usize = 0;
    while (i < input.len) : (i += 1) {
        const c = input[i];
        if (quote != 0) {
            if (c == quote) quote = 0;
            continue;
        }
        if (depth > 0 and (c == '\'' or c == '"')) {
            quote = c;
            continue;
        }
        if (c == '[') depth += 1;
        if (c == ']') {
            if (depth == 0) return error.InvalidParameter;
            depth -= 1;
        }
        if (depth == 0 and std.ascii.isWhitespace(c)) {
            var next = i;
            while (next < input.len and std.ascii.isWhitespace(input[next])) : (next += 1) {}
            if (next < input.len and input[next] == '[') continue;
            const selection = std.mem.trim(u8, input[start..i], " \t\r\n");
            if (selection.len > 0) try result.append(arena, selection);
            start = next;
            i = if (next == 0) 0 else next - 1;
        }
    }
    if (depth != 0 or quote != 0) return error.InvalidParameter;
    const selection = std.mem.trim(u8, input[start..], " \t\r\n");
    if (selection.len > 0) try result.append(arena, selection);
    return try result.toOwnedSlice(arena);
}

pub const ParameterizedAsset = struct {
    selector: Selector,
    config: ParsedIni,
    // This is a lossless preparation view. Runtime tags and conditional branches
    // stay explicit; admitting/executing a filter/action belongs to its consumer.
    definition: std.StringArrayHashMapUnmanaged([]const u8) = .{},
    init: std.StringArrayHashMapUnmanaged([]const u8) = .{},
};

pub fn loadParameterizedAsset(arena: std.mem.Allocator, root: []const u8, directory: []const u8, input: []const u8) Error!ParameterizedAsset {
    const selector = try parseSelector(arena, input);
    const stem = try std.fs.path.join(arena, &.{ directory, selector.name });
    var asset = ParameterizedAsset{ .selector = selector, .config = try loadConfig(arena, root, stem) };
    if (asset.config.section("DEFAULT")) |sec| {
        var it = sec.keys.iterator();
        while (it.next()) |kv| try asset.definition.put(arena, kv.key_ptr.*, (resolveWithParameters(arena, &asset.config, "Definition", kv.key_ptr.*, &selector.parameters) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => null,
        }) orelse kv.value_ptr.*);
    }
    if (asset.config.section("Definition")) |sec| {
        var it = sec.keys.iterator();
        while (it.next()) |kv| try asset.definition.put(arena, kv.key_ptr.*, (resolveWithParameters(arena, &asset.config, "Definition", kv.key_ptr.*, &selector.parameters) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => null,
        }) orelse kv.value_ptr.*);
    }
    if (asset.config.section("Init")) |sec| {
        var it = sec.keys.iterator();
        while (it.next()) |kv| {
            const selected = if (std.mem.indexOfScalar(u8, kv.key_ptr.*, '?')) |q| selector.parameters.get(kv.key_ptr.*[0..q]) orelse kv.value_ptr.* else kv.value_ptr.*;
            try asset.init.put(arena, kv.key_ptr.*, selected);
            if (!std.mem.startsWith(u8, kv.key_ptr.*, "known/")) try asset.init.put(arena, try std.fmt.allocPrint(arena, "known/{s}", .{kv.key_ptr.*}), kv.value_ptr.*);
        }
    }
    var params = selector.parameters.iterator();
    while (params.next()) |kv| try asset.init.put(arena, kv.key_ptr.*, kv.value_ptr.*);
    return asset;
}

test "p2 config selectors preserve open empty and quoted nested parameters" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var selector = try parseSelector(arena.allocator(), "custom[mode=aggressive, opaque='a,b', empty=, list='[x,y]']");
    try testing.expectEqualStrings("custom", selector.name);
    try testing.expectEqualStrings("a,b", selector.parameters.get("opaque").?);
    try testing.expectEqualStrings("", selector.parameters.get("empty").?);
    try testing.expectEqualStrings("[x,y]", selector.parameters.get("list").?);
    try testing.expectError(error.InvalidParameter, parseSelector(arena.allocator(), "custom[x='broken]"));
    try testing.expectError(error.InvalidParameter, parseSelector(arena.allocator(), "custom[list=[x,y]]"));
}

test "p2 config self interpolation is a cycle not default inheritance" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var ini = try parseIniSource(a, "fixture", "[DEFAULT]\nx=5\n[jail]\nx=%(x)s\n");
    try testing.expectError(error.InterpolationCycle, resolve(a, &ini, "jail", "x"));
}

pub fn resolveWithParameters(arena: std.mem.Allocator, ini: *const ParsedIni, section_name: []const u8, key: []const u8, parameters: *const std.StringArrayHashMapUnmanaged([]const u8)) Error!?[]const u8 {
    var view = ini.*;
    view.sections = try ini.sections.clone(arena);
    const section = view.sections.getPtr(section_name) orelse return null;
    section.keys = try section.keys.clone(arena);
    section.origins = try section.origins.clone(arena);
    var params = parameters.iterator();
    while (params.next()) |kv| {
        try section.keys.put(arena, kv.key_ptr.*, kv.value_ptr.*);
        try section.origins.put(arena, kv.key_ptr.*, .{ .source = "selector", .line = 0, .raw = kv.value_ptr.* });
    }
    return resolve(arena, &view, section_name, key);
}

/// Returns static parameter expansion only. Unknown tags are preserved exactly:
/// event tags and executable custom getters must be handled by later consumers.
pub fn combineAsset(arena: std.mem.Allocator, asset: *const ParameterizedAsset, condition: []const u8) Error!std.StringArrayHashMapUnmanaged([]const u8) {
    var combined = try asset.definition.clone(arena);
    var init = asset.init.iterator();
    while (init.next()) |kv| try combined.put(arena, kv.key_ptr.*, kv.value_ptr.*);
    const output_count = combined.count();
    // Include section-qualified helpers for the reader's late getCombOption
    // fallback without invoking custom getters or touching external resources.
    var sections = asset.config.sections.iterator();
    while (sections.next()) |section| {
        var keys = section.value_ptr.keys.iterator();
        while (keys.next()) |kv| {
            const qualified = try std.fmt.allocPrint(arena, "{s}/{s}", .{ section.key_ptr.*, kv.key_ptr.* });
            if (!combined.contains(qualified)) try combined.put(arena, qualified, kv.value_ptr.*);
        }
    }
    var out = std.StringArrayHashMapUnmanaged([]const u8){};
    var it = combined.iterator();
    var index: usize = 0;
    while (it.next()) |kv| {
        if (index == output_count) break;
        index += 1;
        const value = try expandTags(arena, &combined, kv.value_ptr.*, condition, 0);
        try out.put(arena, kv.key_ptr.*, value);
    }
    return out;
}

fn expandTags(arena: std.mem.Allocator, values: *const std.StringArrayHashMapUnmanaged([]const u8), raw: []const u8, condition: []const u8, depth: usize) Error![]const u8 {
    if (depth >= 64) return error.InterpolationCycle;
    var out = std.ArrayListUnmanaged(u8){};
    var i: usize = 0;
    while (i < raw.len) {
        if (raw[i] == '<') {
            if (std.mem.indexOfScalarPos(u8, raw, i + 1, '>')) |close| {
                const name = raw[i + 1 .. close];
                var replacement: ?[]const u8 = null;
                if (condition.len > 0) {
                    replacement = values.get(try std.fmt.allocPrint(arena, "{s}?{s}", .{ name, condition }));
                } else {
                    // A conditional base is deferred until the runtime family is known.
                    var keys = values.iterator();
                    var deferred = false;
                    while (keys.next()) |kv| {
                        if (kv.key_ptr.len > name.len and std.mem.startsWith(u8, kv.key_ptr.*, name) and kv.key_ptr.*[name.len] == '?') {
                            deferred = true;
                            break;
                        }
                    }
                    if (deferred) {
                        try out.appendSlice(arena, raw[i .. close + 1]);
                        i = close + 1;
                        continue;
                    }
                }
                if (replacement == null) replacement = values.get(name);
                if (replacement) |value| {
                    try out.appendSlice(arena, try expandTags(arena, values, value, condition, depth + 1));
                    i = close + 1;
                    if (out.items.len > max_value_bytes) return error.InterpolationOverflow;
                    continue;
                }
            }
        }
        try out.append(arena, raw[i]);
        i += 1;
        if (out.items.len > max_value_bytes) return error.InterpolationOverflow;
    }
    const expanded = try out.toOwnedSlice(arena);
    // Resolve tags assembled by adjacent substitutions as well as nested tags.
    if (!std.mem.eql(u8, raw, expanded) and std.mem.indexOfScalar(u8, expanded, '<') != null) return expandTags(arena, values, expanded, condition, depth + 1);
    return expanded;
}

test "p2 config static tags conditional deferral and cycles" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var values = std.StringArrayHashMapUnmanaged([]const u8){};
    try values.put(a, "mode", "normal");
    try values.put(a, "nested", "<mode>");
    try values.put(a, "family", "v4");
    try values.put(a, "family?family=inet6", "v6");
    try testing.expectEqualStrings("normal <family> <HOST>", try expandTags(a, &values, "<nested> <family> <HOST>", "", 0));
    try testing.expectEqualStrings("normal v6 <HOST>", try expandTags(a, &values, "<nested> <family> <HOST>", "family=inet6", 0));
    try values.put(a, "loop", "<loop>");
    try testing.expectError(error.InterpolationCycle, expandTags(a, &values, "<loop>", "", 0));
}

test "p2 config selector precedence applies before percent interpolation" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var ini = try parseIniSource(a, "fixture", "[Definition]\nmode=normal\nresult=%(mode)s\n");
    var params = std.StringArrayHashMapUnmanaged([]const u8){};
    try params.put(a, "mode", "custom");
    try testing.expectEqualStrings("custom", (try resolveWithParameters(a, &ini, "Definition", "result", &params)).?);
    try testing.expectEqualStrings("normal", (try resolve(a, &ini, "Definition", "result")).?);
}

pub const CanonicalType = enum { string, integer, boolean };
pub const CanonicalValue = union(enum) { null_value, string: []const u8, integer: []const u8, boolean: bool };
pub const ResolvedOption = struct {
    presence: enum { absent, explicit, derived },
    resolution: enum { resolved, reference_fallback },
    value_type: CanonicalType,
    raw: ?[]const u8,
    value: CanonicalValue,
    origin: ?Origin,
    default_identity: []const u8,
};

/// Consumer defaults are explicit arguments, because early/global and jail phases
/// have different defaults. Arbitrary-sized integers use canonical decimal text;
/// narrowing to a runtime integer remains an explicit consumer admission step.
pub fn readTypedOption(arena: std.mem.Allocator, ini: *const ParsedIni, section_name: []const u8, key: []const u8, value_type: CanonicalType, fallback: CanonicalValue, default_identity: []const u8) Error!ResolvedOption {
    const local = ini.section(section_name);
    const def = ini.section("DEFAULT");
    const own = if (local) |sec| sec.origins.get(key) else null;
    const inherited = if (def) |sec| sec.origins.get(key) else null;
    const origin = own orelse inherited;
    const value = try resolve(arena, ini, section_name, key);
    var result = ResolvedOption{ .presence = if (own != null) .explicit else if (inherited != null) .derived else .absent, .resolution = .resolved, .value_type = value_type, .raw = if (origin) |o| o.raw else null, .value = fallback, .origin = origin, .default_identity = default_identity };
    const raw = value orelse return result;
    switch (value_type) {
        .string => result.value = .{ .string = raw },
        .boolean => {
            const lower = try std.ascii.allocLowerString(arena, raw);
            // ConfigReader uses helpers._as_bool, not ConfigParser.getboolean.
            result.value = .{ .boolean = std.mem.eql(u8, lower, "1") or std.mem.eql(u8, lower, "yes") or std.mem.eql(u8, lower, "true") or std.mem.eql(u8, lower, "on") };
        },
        .integer => {
            if (try canonicalInteger(arena, raw)) |integer| result.value = .{ .integer = integer } else result.resolution = .reference_fallback;
        },
    }
    return result;
}

pub fn canonicalInteger(arena: std.mem.Allocator, raw: []const u8) Error!?[]const u8 {
    const ascii = (try normalizeInteger(arena, raw)) orelse return null;
    const text = std.mem.trim(u8, ascii, " \t\r\n\x0b\x0c");
    if (text.len == 0) return null;
    var i: usize = 0;
    const negative = text[0] == '-';
    if (negative or text[0] == '+') i += 1;
    if (i == text.len) return null;
    var digits = std.ArrayListUnmanaged(u8){};
    while (i < text.len) : (i += 1) {
        const c = text[i];
        if (c == '_') {
            if (i == 0 or i + 1 >= text.len or !std.ascii.isDigit(text[i - 1]) or !std.ascii.isDigit(text[i + 1])) return null;
            continue;
        }
        if (!std.ascii.isDigit(c)) return null;
        try digits.append(arena, c);
    }
    var first: usize = 0;
    while (first + 1 < digits.items.len and digits.items[first] == '0') : (first += 1) {}
    if (negative and !(digits.items.len - first == 1 and digits.items[first] == '0')) return try std.fmt.allocPrint(arena, "-{s}", .{digits.items[first..]});
    return try arena.dupe(u8, digits.items[first..]);
}

test "p2 config conversion distinguishes empty missing inherited and fallback" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var ini = try parseIniSource(a, "fixture", "[DEFAULT]\nflag=yes\n[x]\nempty=\nbad=perhaps\nhuge=+000123456789012345678901234567890\n");
    const empty = try readTypedOption(a, &ini, "x", "empty", .string, .null_value, "test");
    try testing.expectEqual(.explicit, empty.presence);
    try testing.expectEqualStrings("", empty.value.string);
    const missing = try readTypedOption(a, &ini, "x", "missing", .string, .null_value, "test");
    try testing.expectEqual(.absent, missing.presence);
    const inherited = try readTypedOption(a, &ini, "x", "flag", .boolean, .null_value, "test");
    try testing.expectEqual(.derived, inherited.presence);
    try testing.expect(inherited.value.boolean);
    const bad = try readTypedOption(a, &ini, "x", "bad", .boolean, .null_value, "test");
    try testing.expectEqual(.resolved, bad.resolution);
    try testing.expect(!bad.value.boolean);
    const huge = try readTypedOption(a, &ini, "x", "huge", .integer, .null_value, "test");
    try testing.expectEqualStrings("123456789012345678901234567890", huge.value.integer);
}

test "p2 config syntax failures and indented assignments are explicit" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectError(error.DuplicateOption, parseIniSource(a, "fixture", "[x]\nA=1\na=2\n"));
    try testing.expectError(error.DuplicateSection, parseIniSource(a, "fixture", "[x]\na=1\n[x]\nb=2\n"));
    try testing.expectError(error.KeyWithoutValue, parseIniSource(a, "fixture", "[x]\ninvalid\n"));
    try testing.expectError(error.InvalidEncoding, parseIniSource(a, "fixture", "[x]\na=\xff\n"));
    var ini = try parseIniSource(a, "fixture", " [x]\n a=one\n   continued ; ignored\n b=two\n");
    try testing.expectEqualStrings("one\ncontinued", ini.section("x").?.get("a").?);
    try testing.expectEqualStrings("two", ini.section("x").?.get("b").?);
}

pub const ConfigDocument = struct {
    schema_version: u32 = 1,
    reference_profile: []const u8 = "fail2ban-1.1.1",
    config_generation: [32]u8,
    source: ParsedIni,
};

/// Source preparation is immutable to consumers: updates create a fresh document.
/// Generation identity binds ordered occurrences, paths, edge roles and byte hashes.
pub fn prepareConfigDocument(arena: std.mem.Allocator, root: []const u8, stem: []const u8) Error!ConfigDocument {
    const source = try loadConfig(arena, root, stem);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("fail2zig-config-source-v1\x00fail2ban-1.1.1\x00");
    for (source.sources.items) |occurrence| {
        var size: [8]u8 = undefined;
        std.mem.writeInt(u64, &size, @intCast(occurrence.path.len), .little);
        hash.update(&size);
        hash.update(occurrence.path);
        std.mem.writeInt(u64, &size, @intCast(occurrence.resolved_target.len), .little);
        hash.update(&size);
        hash.update(occurrence.resolved_target);
        hash.update(&.{@intFromEnum(occurrence.edge)});
        hash.update(&occurrence.sha256);
    }
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return .{ .source = source, .config_generation = digest };
}

// Unicode 15.1 Nd blocks, matching the pinned Python 3.13 reference profile.
// This table normalizes numeric configuration only, not log text or regex input.
fn normalizeInteger(arena: std.mem.Allocator, raw: []const u8) Error!?[]const u8 {
    const zeroes = [_]u21{ 0x30, 0x660, 0x6f0, 0x7c0, 0x966, 0x9e6, 0xa66, 0xae6, 0xb66, 0xbe6, 0xc66, 0xce6, 0xd66, 0xde6, 0xe50, 0xed0, 0xf20, 0x1040, 0x1090, 0x17e0, 0x1810, 0x1946, 0x19d0, 0x1a80, 0x1a90, 0x1b50, 0x1bb0, 0x1c40, 0x1c50, 0xa620, 0xa8d0, 0xa900, 0xa9d0, 0xa9f0, 0xaa50, 0xabf0, 0xff10, 0x104a0, 0x10d30, 0x11066, 0x110f0, 0x11136, 0x111d0, 0x112f0, 0x11450, 0x114d0, 0x11650, 0x116c0, 0x11730, 0x118e0, 0x11950, 0x11c50, 0x11d50, 0x11da0, 0x11f50, 0x16a60, 0x16ac0, 0x16b50, 0x1d7ce, 0x1d7d8, 0x1d7e2, 0x1d7ec, 0x1d7f6, 0x1e140, 0x1e2f0, 0x1e4f0, 0x1e950, 0x1fbf0 };
    const view = std.unicode.Utf8View.init(raw) catch return null;
    var iter = view.iterator();
    var out = std.ArrayListUnmanaged(u8){};
    while (iter.nextCodepoint()) |cp| {
        if (cp < 128) {
            try out.append(arena, @intCast(cp));
            continue;
        }
        if (cp == 0x85 or cp == 0xa0 or cp == 0x1680 or (cp >= 0x2000 and cp <= 0x200a) or cp == 0x2028 or cp == 0x2029 or cp == 0x202f or cp == 0x205f or cp == 0x3000) {
            try out.append(arena, ' ');
            continue;
        }
        var found = false;
        for (zeroes) |zero| {
            if (cp >= zero and cp < zero + 10) {
                try out.append(arena, @as(u8, @intCast(cp - zero)) + '0');
                found = true;
                break;
            }
        }
        if (!found) return null;
    }
    return try out.toOwnedSlice(arena);
}

test "p2 config integer unicode decimal profile and separator validation" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings("123", (try canonicalInteger(a, "\u{2003}+٠١_٢٣\u{a0}")).?);
    try testing.expect((try canonicalInteger(a, "1__2")) == null);
    try testing.expect((try canonicalInteger(a, "_12")) == null);
    try testing.expect((try canonicalInteger(a, "12_")) == null);
    try testing.expect((try canonicalInteger(a, "²")) == null);
}

test "p2 config symlink retargeting changes generation with identical content" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "one.conf", .data = "[probe]\nx=one\n" });
    try tmp.dir.writeFile(.{ .sub_path = "two.conf", .data = "[probe]\nx=one\n" });
    try tmp.dir.symLink("one.conf", "jail.conf", .{});
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const root = try tmp.dir.realpathAlloc(a, ".");
    const before = try prepareConfigDocument(a, root, "jail");
    try tmp.dir.deleteFile("jail.conf");
    try tmp.dir.symLink("two.conf", "jail.conf", .{});
    const after = try prepareConfigDocument(a, root, "jail");
    try testing.expect(!std.mem.eql(u8, &before.config_generation, &after.config_generation));
    try testing.expectEqualStrings(before.source.sources.items[0].bytes, after.source.sources.items[0].bytes);
    try testing.expect(!std.mem.eql(u8, before.source.sources.items[0].resolved_target, after.source.sources.items[0].resolved_target));
}

test "p2 selectors preserve multiline groups ordered actions and conditional keys" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const values = try splitSelectors(a, "first[a=' one ',b=two][a=last,\nx?family=inet6=value]\nsecond[port='80,443']");
    try testing.expectEqual(@as(usize, 2), values.len);
    const first = try parseSelector(a, values[0]);
    try testing.expectEqualStrings("first", first.name);
    try testing.expectEqualStrings("last", first.parameters.get("a").?);
    try testing.expectEqualStrings("value", first.parameters.get("x?family=inet6").?);
    const second = try parseSelector(a, values[1]);
    try testing.expectEqualStrings("80,443", second.parameters.get("port").?);
    const quoted = try parseSelector(a, "original[value=' trimmed ']");
    try testing.expectEqualStrings("trimmed", quoted.parameters.get("value").?);
    try testing.expectError(error.InvalidParameter, parseSelector(a, "original[x='unterminated]"));
    try testing.expectError(error.InvalidParameter, splitSelectors(a, "original[x=unfinished"));
}

test "p2 interpolation depth counts only recursive percent replacements" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for ([_]usize{ 9, 10, 11 }) |hops| {
        for ([_][]const u8{ "literal", "100%%" }) |terminal| {
            var bytes = std.ArrayList(u8).init(a);
            try bytes.appendSlice("[probe]\n");
            for (0..hops) |i| try bytes.writer().print("v{d}=%(v{d})s\n", .{ i, i + 1 });
            try bytes.writer().print("v{d}={s}\n", .{ hops, terminal });
            var parsed = try parseIniSource(a, "original-depth", bytes.items);
            const limit: usize = if (std.mem.eql(u8, terminal, "literal")) 10 else 9;
            if (hops <= limit) {
                try testing.expectEqualStrings(if (terminal.len == 7) "literal" else "100%", (try resolve(a, &parsed, "probe", "v0")).?);
            } else try testing.expectError(error.InterpolationCycle, resolve(a, &parsed, "probe", "v0"));
        }
    }
}

test "p2 section headers preserve spaces and accept greedy prefix match" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var parsed = try parseIniSource(a, "original-header", "[ probe ] trailing text\nv=one\n[other] ; ignored ]\nv=two\n[nested]suffix] trailing\nv=three\n");
    try testing.expectEqualStrings("one", (try resolve(a, &parsed, " probe ", "v")).?);
    try testing.expectEqualStrings("two", (try resolve(a, &parsed, "other", "v")).?);
    try testing.expectEqualStrings("three", (try resolve(a, &parsed, "nested]suffix", "v")).?);
    try testing.expectError(error.UnterminatedSection, parseIniSource(a, "original-header", "[bad ; ignored ]\nv=one\n"));
}

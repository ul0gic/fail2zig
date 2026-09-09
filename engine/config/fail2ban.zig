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
};

pub const max_file_bytes: usize = 1024 * 1024;
pub const max_sections: usize = 256;
pub const max_keys_per_section: usize = 64;
pub const max_files_per_dir: usize = 1024;
pub const max_interp_depth: usize = 16;
pub const max_value_bytes: usize = 16 * 1024;

pub const Warning = struct {
    source: []const u8,
    line: u32,
    message: []const u8,
};

pub const Section = struct {
    name: []const u8,
    keys: std.StringArrayHashMapUnmanaged([]const u8) = .{},

    pub fn get(self: *const Section, key: []const u8) ?[]const u8 {
        return self.keys.get(key);
    }
};

pub const ParsedIni = struct {
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
                if (std.mem.eql(u8, entry.key_ptr.*, self.skip)) continue;
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

    var result = ParsedIni{};
    errdefer result.sections.deinit(arena);

    const lines = try tokenizeLines(arena, src);

    var current: ?*Section = null;
    var pending_key: ?[]const u8 = null;
    var pending_value = std.ArrayListUnmanaged(u8){};
    errdefer pending_value.deinit(arena);

    for (lines) |ln| {
        if (ln.indented and pending_key != null) {
            const stripped = stripLeadingSpace(ln.text);
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
            try commitKey(arena, current, key, try pending_value.toOwnedSlice(arena));
            pending_value = std.ArrayListUnmanaged(u8){};
            pending_key = null;
        }

        const trimmed = std.mem.trim(u8, ln.text, " \t");
        if (trimmed.len == 0) continue;
        if (trimmed[0] == '#' or trimmed[0] == ';') continue;

        if (trimmed[0] == '[') {
            if (trimmed.len < 2 or trimmed[trimmed.len - 1] != ']') {
                return error.UnterminatedSection;
            }
            const name = std.mem.trim(u8, trimmed[1 .. trimmed.len - 1], " \t");
            if (name.len == 0) return error.EmptySectionName;

            if (result.sections.count() >= max_sections and
                result.sections.get(name) == null)
            {
                return error.TooManySections;
            }

            const gop = try result.sections.getOrPut(arena, name);
            if (!gop.found_existing) {
                gop.value_ptr.* = .{ .name = name };
            }
            current = gop.value_ptr;
            continue;
        }

        const sep_idx = findSeparator(trimmed) orelse {
            try appendWarning(arena, &result, source_label, ln.line_no, "line has no '=' or ':' separator; ignoring");
            continue;
        };

        const key = std.mem.trim(u8, trimmed[0..sep_idx], " \t");
        if (key.len == 0) return error.KeyWithoutValue;
        const value = std.mem.trim(u8, trimmed[sep_idx + 1 ..], " \t");

        if (current == null) {
            try appendWarning(arena, &result, source_label, ln.line_no, "key outside of any section; ignoring");
            continue;
        }

        pending_key = key;
        pending_value = std.ArrayListUnmanaged(u8){};
        try pending_value.appendSlice(arena, value);
    }

    if (pending_key) |key| {
        try commitKey(arena, current, key, try pending_value.toOwnedSlice(arena));
    }

    return result;
}

fn commitKey(
    arena: std.mem.Allocator,
    section_opt: ?*Section,
    key: []const u8,
    value: []const u8,
) Error!void {
    const sec = section_opt orelse return;
    if (sec.keys.count() >= max_keys_per_section and sec.keys.get(key) == null) {
        return error.TooManyKeysInSection;
    }
    try sec.keys.put(arena, key, value);
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

pub fn interpolate(arena: std.mem.Allocator, ini: *ParsedIni) Error!void {
    const default_section = ini.section("DEFAULT");

    var it = ini.sections.iterator();
    while (it.next()) |entry| {
        const sec_name = entry.key_ptr.*;
        const sec = entry.value_ptr;
        if (std.mem.eql(u8, sec_name, "DEFAULT")) continue;

        var keys_it = sec.keys.iterator();
        while (keys_it.next()) |kv| {
            const key_name = kv.key_ptr.*;
            const expanded = expandValue(
                arena,
                kv.value_ptr.*,
                sec,
                default_section,
                0,
                key_name,
            ) catch |err| switch (err) {
                error.InterpolationCycle,
                error.InterpolationOverflow,
                error.InterpolationUnterminated,
                => {
                    try appendWarning(arena, ini, sec_name, 0, @errorName(err));
                    continue;
                },
                else => return err,
            };
            kv.value_ptr.* = expanded;
        }
    }

    if (default_section) |def| {
        var keys_it = def.keys.iterator();
        while (keys_it.next()) |kv| {
            const key_name = kv.key_ptr.*;
            const expanded = expandValue(
                arena,
                kv.value_ptr.*,
                def,
                null,
                0,
                key_name,
            ) catch |err| switch (err) {
                error.InterpolationCycle,
                error.InterpolationOverflow,
                error.InterpolationUnterminated,
                => {
                    try appendWarning(arena, ini, "DEFAULT", 0, @errorName(err));
                    continue;
                },
                else => return err,
            };
            kv.value_ptr.* = expanded;
        }
    }
}

fn expandValue(
    arena: std.mem.Allocator,
    src: []const u8,
    local: *const Section,
    default: ?*const Section,
    depth: usize,
    self_key: []const u8,
) Error![]const u8 {
    if (depth >= max_interp_depth) return error.InterpolationCycle;

    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(arena);
    try out.ensureTotalCapacity(arena, src.len);

    var i: usize = 0;
    while (i < src.len) {
        const c = src[i];
        if (c == '%' and i + 1 < src.len and src[i + 1] == '(') {
            var j: usize = i + 2;
            while (j < src.len and src[j] != ')') : (j += 1) {}
            if (j >= src.len or j + 1 >= src.len or src[j + 1] != 's') {
                return error.InterpolationUnterminated;
            }
            const name = src[i + 2 .. j];
            if (name.len == 0) return error.InterpolationUnterminated;

            const self_ref = self_key.len > 0 and std.mem.eql(u8, name, self_key);
            const raw_local = if (self_ref) null else local.get(name);
            const raw = raw_local orelse if (default) |d| d.get(name) else null;
            if (raw == null) {
                try out.appendSlice(arena, src[i .. j + 2]);
                i = j + 2;
                continue;
            }

            const expanded = try expandValue(arena, raw.?, local, default, depth + 1, "");
            if (out.items.len + expanded.len > max_value_bytes) {
                return error.InterpolationOverflow;
            }
            try out.appendSlice(arena, expanded);
            i = j + 2;
            continue;
        }
        if (c == '%' and i + 1 < src.len and src[i + 1] == '%') {
            try out.append(arena, '%');
            i += 2;
            continue;
        }
        try out.append(arena, c);
        i += 1;
    }

    return try out.toOwnedSlice(arena);
}

fn mergeInto(
    arena: std.mem.Allocator,
    base: *ParsedIni,
    override: ParsedIni,
) Error!void {
    var sec_it = override.sections.iterator();
    while (sec_it.next()) |entry| {
        const name = entry.key_ptr.*;
        const src_sec = entry.value_ptr;
        const gop = try base.sections.getOrPut(arena, name);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{ .name = name };
        }
        var key_it = src_sec.keys.iterator();
        while (key_it.next()) |kv| {
            if (gop.value_ptr.keys.count() >= max_keys_per_section and
                gop.value_ptr.keys.get(kv.key_ptr.*) == null)
            {
                return error.TooManyKeysInSection;
            }
            try gop.value_ptr.keys.put(arena, kv.key_ptr.*, kv.value_ptr.*);
        }
    }

    for (override.warnings.items) |w| {
        try base.warnings.append(arena, w);
    }
}

pub fn loadJailConfig(arena: std.mem.Allocator, source_dir: []const u8) Error!ParsedIni {
    var result = ParsedIni{};

    if (try readOptionalFile(arena, source_dir, "jail.conf")) |bytes| {
        const parsed = try parseIniSource(arena, "jail.conf", bytes);
        try mergeInto(arena, &result, parsed);
    }

    if (try readOptionalFile(arena, source_dir, "jail.local")) |bytes| {
        const parsed = try parseIniSource(arena, "jail.local", bytes);
        try mergeInto(arena, &result, parsed);
    }

    const jail_d = try std.fs.path.join(arena, &[_][]const u8{ source_dir, "jail.d" });
    if (openOptionalDir(jail_d)) |maybe_dir| {
        if (maybe_dir) |handle| {
            var dir = handle;
            defer dir.close();
            const entries = try collectConfFiles(arena, &dir);
            for (entries) |name| {
                const sub_path = try std.fs.path.join(arena, &[_][]const u8{ "jail.d", name });
                const rel = try std.fs.path.join(arena, &[_][]const u8{ source_dir, "jail.d", name });
                const bytes = (try readOptionalFile(arena, source_dir, sub_path)) orelse {
                    _ = rel;
                    continue;
                };
                const parsed = try parseIniSource(arena, sub_path, bytes);
                try mergeInto(arena, &result, parsed);
            }
        }
    } else |err| return err;

    try interpolate(arena, &result);
    return result;
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

fn collectConfFiles(arena: std.mem.Allocator, dir: *std.fs.Dir) Error![]const []const u8 {
    var list = std.ArrayListUnmanaged([]const u8){};
    errdefer list.deinit(arena);

    var it = dir.iterate();
    while (it.next() catch return error.ReadFailed) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".conf")) continue;
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
        \\bantime = %(bantime)s
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
        \\bantime = %(bantime)s
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

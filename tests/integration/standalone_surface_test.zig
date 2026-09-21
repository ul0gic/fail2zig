// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const standalone_test_options = @import("standalone_test_options");

const testing = std.testing;
const max_scanned_files: usize = 4096;
const max_file_bytes: usize = 2 * 1024 * 1024;
const max_elf_bytes: usize = 128 * 1024 * 1024;
const max_elf_program_headers: usize = 128;
const max_elf_needed_entries: usize = 256;

const required_files = [_][]const u8{
    "Makefile",
    "build.zig",
    "build.zig.zon",
};

const required_directories = [_][]const u8{
    "engine",
    "client",
    "shared",
    "tests",
    "scripts",
    "deploy",
    "vendor/sqlite",
    ".github/workflows",
};

const frozen_directories = [_]struct {
    path: []const u8,
    entries: usize,
}{
    .{ .path = "engine/compat", .entries = 2 },
    .{ .path = "vendor/sqlite", .entries = 3 },
};

const FrozenFile = struct {
    path: []const u8,
    size: u64,
    sha256: []const u8,
};

const frozen_files = [_]FrozenFile{
    .{ .path = "engine/compat/date_profile.json", .size = 4_806, .sha256 = "86009fdec328dd34bc5719fee315ea4416b8da2e22351ae66508591f37b015e3" },
    .{ .path = "engine/compat/COPYING.date-profile", .size = 19_789, .sha256 = "744bead43dfe32473d05f404b42d0fddd64e183612e4fe70037781983f8d2943" },
    .{ .path = "vendor/sqlite/README.md", .size = 1_914, .sha256 = "4fc5d7ce88b0cbcc7dba5d18768f5b01a0980c5a1b67739cdfd54b8f1aee97da" },
    .{ .path = "vendor/sqlite/sqlite3.c", .size = 9_515_341, .sha256 = "b1dd5d74ec7f29055a6684fa06fb3c2f6821c87dd38f9a458dfd2e8a1db28189" },
    .{ .path = "vendor/sqlite/sqlite3.h", .size = 690_838, .sha256 = "919e7f2e8ed1d8f56ac17b412b8971c76aa5d1a879752cc6058f75e7d5910e1d" },
};

const Finding = struct {
    path: []u8,
    line: usize,
    reason: []const u8,

    fn deinit(self: Finding, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
    }
};

const Hit = struct {
    line: usize,
    reason: []const u8,
};

fn isFrozenData(path: []const u8) bool {
    for (frozen_files) |item| {
        if (std.mem.eql(u8, path, item.path)) return true;
    }
    return false;
}

fn scansContents(path: []const u8) bool {
    const extension = std.fs.path.extension(path);
    return extension.len == 0 or
        std.mem.eql(u8, extension, ".zig") or
        std.mem.eql(u8, extension, ".zon") or
        std.mem.eql(u8, extension, ".sh") or
        std.mem.eql(u8, extension, ".bash") or
        std.mem.eql(u8, extension, ".yml") or
        std.mem.eql(u8, extension, ".yaml") or
        std.mem.eql(u8, extension, ".toml") or
        std.mem.eql(u8, extension, ".service") or
        std.mem.eql(u8, extension, ".local") or
        std.mem.eql(u8, extension, ".example");
}

fn isWordByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '_' or byte == '-';
}

fn isInterpreterExtension(path: []const u8) bool {
    return std.ascii.eqlIgnoreCase(std.fs.path.extension(path), "." ++ "py");
}

fn hasInterpreterPath(line: []const u8) bool {
    const suffix = "." ++ "py";
    var offset: usize = 0;
    while (std.mem.indexOfPos(u8, line, offset, suffix)) |index| {
        const end = index + suffix.len;
        if (end == line.len or !isWordByte(line[end])) return true;
        offset = end;
    }
    return false;
}

fn containsToken(line: []const u8, token: []const u8) bool {
    var offset: usize = 0;
    while (std.mem.indexOfPos(u8, line, offset, token)) |index| {
        const before_ok = index == 0 or !isWordByte(line[index - 1]);
        const end = index + token.len;
        const after_ok = end == line.len or !isWordByte(line[end]);
        if (before_ok and after_ok) return true;
        offset = end;
    }
    return false;
}

fn isComment(path: []const u8, line: []const u8) bool {
    const trimmed = std.mem.trimLeft(u8, line, " \t");
    const extension = std.fs.path.extension(path);
    if (std.mem.eql(u8, extension, ".zig") or std.mem.eql(u8, extension, ".zon")) {
        return std.mem.startsWith(u8, trimmed, "//");
    }
    if (std.mem.eql(u8, extension, ".service") and std.mem.startsWith(u8, trimmed, ";")) {
        return true;
    }
    return std.mem.startsWith(u8, trimmed, "#") and !std.mem.startsWith(u8, trimmed, "#!");
}

fn hasInterpreterToken(line: []const u8) bool {
    const interpreter = "py" ++ "thon";
    return containsToken(line, interpreter) or
        containsToken(line, interpreter ++ "3") or
        containsToken(line, "py" ++ "py");
}

fn hasInterpreterShebang(root: std.fs.Dir, path: []const u8) !bool {
    var file = try root.openFile(path, .{});
    defer file.close();
    var buffer: [512]u8 = undefined;
    const count = try file.read(&buffer);
    const first_line_end = std.mem.indexOfScalar(u8, buffer[0..count], '\n') orelse count;
    const first_line = std.mem.trimLeft(u8, buffer[0..first_line_end], " \t");
    return std.mem.startsWith(u8, first_line, "#!") and hasInterpreterToken(first_line);
}

fn findForbiddenUse(path: []const u8, contents: []const u8) ?Hit {
    if (isInterpreterExtension(path)) {
        return .{ .line = 1, .reason = "interpreter source file" };
    }

    const search_path = "PYTHON" ++ "PATH";

    var lines = std.mem.splitScalar(u8, contents, '\n');
    var line_number: usize = 0;
    while (lines.next()) |line| {
        line_number += 1;
        const trimmed = std.mem.trimLeft(u8, line, " \t");
        if (line_number == 1 and std.mem.startsWith(u8, trimmed, "#!") and
            hasInterpreterToken(trimmed))
        {
            return .{ .line = line_number, .reason = "interpreter shebang" };
        }
        if (isComment(path, line)) continue;
        if (std.mem.indexOf(u8, line, search_path) != null) {
            return .{ .line = line_number, .reason = "interpreter module search path" };
        }
        if (hasInterpreterPath(line)) {
            return .{ .line = line_number, .reason = "interpreter source path" };
        }
        if (hasInterpreterToken(line)) {
            return .{ .line = line_number, .reason = "interpreter command or embedded snippet" };
        }
    }
    return null;
}

fn inspectFile(
    allocator: std.mem.Allocator,
    root: std.fs.Dir,
    path: []const u8,
    findings: *std.ArrayList(Finding),
) !void {
    if (isFrozenData(path)) return;
    if (isInterpreterExtension(path)) {
        try findings.append(.{
            .path = try allocator.dupe(u8, path),
            .line = 1,
            .reason = "interpreter source file",
        });
        return;
    }
    if (try hasInterpreterShebang(root, path)) {
        try findings.append(.{
            .path = try allocator.dupe(u8, path),
            .line = 1,
            .reason = "interpreter shebang",
        });
        return;
    }
    if (!scansContents(path)) return;

    const contents = try root.readFileAlloc(allocator, path, max_file_bytes);
    defer allocator.free(contents);
    if (findForbiddenUse(path, contents)) |hit| {
        try findings.append(.{
            .path = try allocator.dupe(u8, path),
            .line = hit.line,
            .reason = hit.reason,
        });
    }
}

fn appendPathFinding(
    allocator: std.mem.Allocator,
    findings: *std.ArrayList(Finding),
    path: []const u8,
    reason: []const u8,
) !void {
    try findings.append(.{
        .path = try allocator.dupe(u8, path),
        .line = 0,
        .reason = reason,
    });
}

fn openRequiredDirectoryNoFollow(root: std.fs.Dir, path: []const u8) !std.fs.Dir {
    var current = root;
    var current_owned = false;
    errdefer if (current_owned) current.close();

    var components = std.mem.splitScalar(u8, path, '/');
    while (components.next()) |component| {
        if (component.len == 0) return error.InvalidRequiredSurfacePath;
        const next = try current.openDir(component, .{
            .iterate = true,
            .no_follow = true,
        });
        if (current_owned) current.close();
        current = next;
        current_owned = true;
    }
    if (!current_owned) return error.InvalidRequiredSurfacePath;
    return current;
}

fn requiredFileKind(root: std.fs.Dir, path: []const u8) !std.fs.File.Kind {
    const dirname = std.fs.path.dirname(path);
    var parent = if (dirname) |name|
        try openRequiredDirectoryNoFollow(root, name)
    else
        root;
    defer if (dirname != null) parent.close();

    const basename = std.fs.path.basename(path);
    var iterator = parent.iterate();
    while (try iterator.next()) |entry| {
        if (std.mem.eql(u8, entry.name, basename)) return entry.kind;
    }
    return error.FileNotFound;
}

fn scanRequiredSurface(
    allocator: std.mem.Allocator,
    root: std.fs.Dir,
    findings: *std.ArrayList(Finding),
) !usize {
    var scanned: usize = 0;
    for (required_files) |path| {
        const kind = try requiredFileKind(root, path);
        if (kind != .file) {
            try appendPathFinding(
                allocator,
                findings,
                path,
                if (kind == .sym_link) "symbolic link in required surface" else "non-file in required surface",
            );
            continue;
        }
        try inspectFile(allocator, root, path, findings);
        scanned += 1;
    }

    for (required_directories) |directory_path| {
        var directory = openRequiredDirectoryNoFollow(root, directory_path) catch |err| switch (err) {
            error.SymLinkLoop => {
                try appendPathFinding(allocator, findings, directory_path, "symbolic link in required surface");
                continue;
            },
            else => |other| return other,
        };
        defer directory.close();
        var walker = try directory.walk(allocator);
        defer walker.deinit();
        while (try walker.next()) |entry| {
            scanned += 1;
            if (scanned > max_scanned_files) return error.StandaloneSurfaceTooLarge;
            const path = try std.fs.path.join(allocator, &.{ directory_path, entry.path });
            defer allocator.free(path);
            switch (entry.kind) {
                .file => try inspectFile(allocator, root, path, findings),
                .directory => {},
                .sym_link => try appendPathFinding(allocator, findings, path, "symbolic link in required surface"),
                else => try appendPathFinding(allocator, findings, path, "unsupported entry kind in required surface"),
            }
        }
    }
    return scanned;
}

fn expectFrozenDirectoryCount(root: std.fs.Dir, path: []const u8, expected: usize) !void {
    var directory = try root.openDir(path, .{ .iterate = true });
    defer directory.close();
    var iterator = directory.iterate();
    var actual: usize = 0;
    while (try iterator.next()) |_| actual += 1;
    if (actual != expected) {
        std.debug.print("frozen data inventory changed: {s} has {d} entries, expected {d}\n", .{ path, actual, expected });
        return error.TestFrozenInventoryChanged;
    }
}

fn expectFrozenFile(root: std.fs.Dir, item: FrozenFile) !void {
    var file = try root.openFile(item.path, .{});
    defer file.close();
    const stat = try file.stat();
    if (stat.size != item.size) {
        std.debug.print("frozen data size changed: {s} has {d} bytes, expected {d}\n", .{ item.path, stat.size, item.size });
        return error.TestFrozenIdentityChanged;
    }

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [16 * 1024]u8 = undefined;
    while (true) {
        const count = try file.read(&buffer);
        if (count == 0) break;
        hasher.update(buffer[0..count]);
    }
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    hasher.final(&digest);
    const actual = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, &actual, item.sha256)) {
        std.debug.print("frozen data digest changed: {s} has {s}, expected {s}\n", .{ item.path, &actual, item.sha256 });
        return error.TestFrozenIdentityChanged;
    }
}

const ElfClass = enum {
    elf32,
    elf64,
};

const ElfProgramHeader = struct {
    kind: u32,
    offset: u64,
    virtual_address: u64,
    file_size: u64,
};

fn boundedSlice(bytes: []const u8, offset: u64, length: usize) ![]const u8 {
    const start = std.math.cast(usize, offset) orelse return error.ElfOffsetTooLarge;
    const end = std.math.add(usize, start, length) catch return error.ElfOffsetTooLarge;
    if (end > bytes.len) return error.TruncatedElf;
    return bytes[start..end];
}

fn readElfU16(bytes: []const u8, offset: u64, endian: std.builtin.Endian) !u16 {
    const field = try boundedSlice(bytes, offset, 2);
    return std.mem.readInt(u16, field[0..2], endian);
}

fn readElfU32(bytes: []const u8, offset: u64, endian: std.builtin.Endian) !u32 {
    const field = try boundedSlice(bytes, offset, 4);
    return std.mem.readInt(u32, field[0..4], endian);
}

fn readElfU64(bytes: []const u8, offset: u64, endian: std.builtin.Endian) !u64 {
    const field = try boundedSlice(bytes, offset, 8);
    return std.mem.readInt(u64, field[0..8], endian);
}

fn addElfOffset(base: u64, delta: u64) !u64 {
    return std.math.add(u64, base, delta) catch error.ElfOffsetTooLarge;
}

fn isForbiddenSharedLibrary(name: []const u8) bool {
    const basename = std.fs.path.basename(name);
    if (std.mem.indexOf(u8, basename, ".so") == null) return false;
    return std.mem.startsWith(u8, basename, "lib" ++ "py" ++ "thon") or
        std.mem.startsWith(u8, basename, "libsystemd") or
        std.mem.startsWith(u8, basename, "libsqlite");
}

fn inspectElfNeeded(bytes: []const u8) !usize {
    if (bytes.len < 16 or !std.mem.eql(u8, bytes[0..4], "\x7fELF")) return error.NotElf;
    if (bytes[6] != 1) return error.UnsupportedElfVersion;

    const class: ElfClass = switch (bytes[4]) {
        1 => .elf32,
        2 => .elf64,
        else => return error.UnsupportedElfClass,
    };
    const endian: std.builtin.Endian = switch (bytes[5]) {
        1 => .little,
        2 => .big,
        else => return error.UnsupportedElfEncoding,
    };
    const header_size: usize = switch (class) {
        .elf32 => 52,
        .elf64 => 64,
    };
    if (bytes.len < header_size) return error.TruncatedElf;

    const program_offset = switch (class) {
        .elf32 => @as(u64, try readElfU32(bytes, 28, endian)),
        .elf64 => try readElfU64(bytes, 32, endian),
    };
    const program_entry_size = switch (class) {
        .elf32 => try readElfU16(bytes, 42, endian),
        .elf64 => try readElfU16(bytes, 54, endian),
    };
    const program_count = switch (class) {
        .elf32 => try readElfU16(bytes, 44, endian),
        .elf64 => try readElfU16(bytes, 56, endian),
    };
    const minimum_program_size: u16 = switch (class) {
        .elf32 => 32,
        .elf64 => 56,
    };
    if (program_count > max_elf_program_headers) return error.TooManyElfProgramHeaders;
    if (program_count != 0 and program_entry_size < minimum_program_size) {
        return error.InvalidElfProgramHeaderSize;
    }

    var headers: [max_elf_program_headers]ElfProgramHeader = undefined;
    for (0..program_count) |index| {
        const relative = std.math.mul(
            u64,
            @as(u64, @intCast(index)),
            @as(u64, program_entry_size),
        ) catch return error.ElfOffsetTooLarge;
        const offset = try addElfOffset(program_offset, relative);
        _ = try boundedSlice(bytes, offset, minimum_program_size);

        const header: ElfProgramHeader = switch (class) {
            .elf32 => .{
                .kind = try readElfU32(bytes, offset, endian),
                .offset = try readElfU32(bytes, try addElfOffset(offset, 4), endian),
                .virtual_address = try readElfU32(bytes, try addElfOffset(offset, 8), endian),
                .file_size = try readElfU32(bytes, try addElfOffset(offset, 16), endian),
            },
            .elf64 => .{
                .kind = try readElfU32(bytes, offset, endian),
                .offset = try readElfU64(bytes, try addElfOffset(offset, 8), endian),
                .virtual_address = try readElfU64(bytes, try addElfOffset(offset, 16), endian),
                .file_size = try readElfU64(bytes, try addElfOffset(offset, 32), endian),
            },
        };
        const file_size = std.math.cast(usize, header.file_size) orelse return error.ElfOffsetTooLarge;
        _ = try boundedSlice(bytes, header.offset, file_size);
        headers[index] = header;
    }

    var needed_offsets: [max_elf_needed_entries]u64 = undefined;
    var needed_count: usize = 0;
    var string_address: ?u64 = null;
    var string_size: ?u64 = null;
    var dynamic_found = false;

    for (headers[0..program_count]) |header| {
        if (header.kind != 2) continue;
        dynamic_found = true;
        const entry_size: u64 = switch (class) {
            .elf32 => 8,
            .elf64 => 16,
        };
        if (header.file_size % entry_size != 0) return error.InvalidElfDynamicSize;

        var terminated = false;
        const dynamic_count = header.file_size / entry_size;
        for (0..dynamic_count) |index| {
            const relative = std.math.mul(
                u64,
                @as(u64, @intCast(index)),
                entry_size,
            ) catch return error.ElfOffsetTooLarge;
            const offset = try addElfOffset(header.offset, relative);
            const tag: u64 = switch (class) {
                .elf32 => try readElfU32(bytes, offset, endian),
                .elf64 => try readElfU64(bytes, offset, endian),
            };
            const value_offset = try addElfOffset(offset, switch (class) {
                .elf32 => 4,
                .elf64 => 8,
            });
            const value: u64 = switch (class) {
                .elf32 => try readElfU32(bytes, value_offset, endian),
                .elf64 => try readElfU64(bytes, value_offset, endian),
            };
            switch (tag) {
                0 => {
                    terminated = true;
                    break;
                },
                1 => {
                    if (needed_count == needed_offsets.len) return error.TooManyElfNeededEntries;
                    needed_offsets[needed_count] = value;
                    needed_count += 1;
                },
                5 => {
                    if (string_address != null and string_address.? != value) return error.ConflictingElfStringTables;
                    string_address = value;
                },
                10 => {
                    if (string_size != null and string_size.? != value) return error.ConflictingElfStringSizes;
                    string_size = value;
                },
                else => {},
            }
        }
        if (!terminated) return error.UnterminatedElfDynamicTable;
    }

    if (!dynamic_found or needed_count == 0) return needed_count;
    const table_address = string_address orelse return error.MissingElfStringTable;
    const table_size_u64 = string_size orelse return error.MissingElfStringSize;
    const table_size = std.math.cast(usize, table_size_u64) orelse return error.ElfOffsetTooLarge;

    var string_table: ?[]const u8 = null;
    for (headers[0..program_count]) |header| {
        if (header.kind != 1 or table_address < header.virtual_address) continue;
        const delta = table_address - header.virtual_address;
        if (delta > header.file_size or table_size_u64 > header.file_size - delta) continue;
        string_table = try boundedSlice(bytes, try addElfOffset(header.offset, delta), table_size);
        break;
    }
    const strings = string_table orelse return error.UnmappedElfStringTable;

    for (needed_offsets[0..needed_count]) |needed_offset| {
        const start = std.math.cast(usize, needed_offset) orelse return error.ElfOffsetTooLarge;
        if (start >= strings.len) return error.InvalidElfNeededOffset;
        const tail = strings[start..];
        const end = std.mem.indexOfScalar(u8, tail, 0) orelse return error.UnterminatedElfNeededName;
        const name = tail[0..end];
        if (name.len == 0) return error.EmptyElfNeededName;
        if (isForbiddenSharedLibrary(name)) {
            std.debug.print("forbidden shared dependency in fail2zig artifact: {s}\n", .{name});
            return error.ForbiddenStandaloneDependency;
        }
    }
    return needed_count;
}

fn inspectDaemonArtifact(allocator: std.mem.Allocator, path: []const u8) !usize {
    var file = if (std.fs.path.isAbsolute(path))
        try std.fs.openFileAbsolute(path, .{})
    else
        try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const stat = try file.stat();
    if (stat.kind != .file) return error.DaemonArtifactNotFile;
    if (stat.size > max_elf_bytes) return error.DaemonArtifactTooLarge;
    const bytes = try file.readToEndAlloc(allocator, max_elf_bytes);
    defer allocator.free(bytes);
    return inspectElfNeeded(bytes);
}

test "standalone surface: required product and release paths have no interpreter dependency" {
    const allocator = testing.allocator;
    var root = try std.fs.openDirAbsolute(standalone_test_options.repo_root, .{ .iterate = true });
    defer root.close();

    var findings = std.ArrayList(Finding).init(allocator);
    defer {
        for (findings.items) |finding| finding.deinit(allocator);
        findings.deinit();
    }

    const scanned = try scanRequiredSurface(allocator, root, &findings);
    try testing.expect(scanned > required_files.len);
    for (findings.items) |finding| {
        std.debug.print("standalone dependency at {s}:{d}: {s}\n", .{ finding.path, finding.line, finding.reason });
    }
    try testing.expectEqual(@as(usize, 0), findings.items.len);
}

test "standalone surface: scanner distinguishes executable use from historical text" {
    try testing.expect(findForbiddenUse("tool.sh", "exec " ++ "py" ++ "thon3 -c 'import json'\n") != null);
    try testing.expect(findForbiddenUse("tool.sh", "exec ./check." ++ "py --release\n") != null);
    try testing.expect(findForbiddenUse("manifest.zig", "const helper = \"tools/check." ++ "py\";\n") != null);
    try testing.expect(findForbiddenUse("tool.sh", "PYTHON" ++ "PATH=/tmp exec tool\n") != null);
    try testing.expect(findForbiddenUse("tool.sh", "exec ./check." ++ "pyc\n") == null);
    try testing.expect(findForbiddenUse("tool.sh", "# " ++ "py" ++ "thon3 is mentioned historically\nexec zig test\n") == null);
    try testing.expect(findForbiddenUse("source.zig", "// " ++ "py" ++ "thon-systemd historical behavior\nconst ok = true;\n") == null);
    try testing.expect(!scansContents("historical/README.md"));
    try testing.expect(!scansContents("fixtures/service.conf"));
    try testing.expect(!scansContents("fixtures/evidence.json"));
}

test "standalone surface: required paths identify symbolic links without following them" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var target = try tmp.dir.createFile("target", .{});
    target.close();
    try tmp.dir.symLink("target", "alias", .{});

    try testing.expectEqual(std.fs.File.Kind.file, try requiredFileKind(tmp.dir, "target"));
    try testing.expectEqual(std.fs.File.Kind.sym_link, try requiredFileKind(tmp.dir, "alias"));
}

test "standalone surface: dependency and derived-data identities are frozen" {
    var root = try std.fs.openDirAbsolute(standalone_test_options.repo_root, .{ .iterate = true });
    defer root.close();

    for (frozen_directories) |directory| {
        try expectFrozenDirectoryCount(root, directory.path, directory.entries);
    }
    for (frozen_files) |item| try expectFrozenFile(root, item);
}

test "standalone surface: built fail2zig has no forbidden shared runtime dependencies" {
    _ = try inspectDaemonArtifact(testing.allocator, standalone_test_options.daemon_path);
}

test "standalone surface: ELF dependency policy is exact and malformed input refuses" {
    try testing.expect(isForbiddenSharedLibrary("lib" ++ "py" ++ "thon3.13.so.1.0"));
    try testing.expect(isForbiddenSharedLibrary("/usr/lib/libsystemd.so.0"));
    try testing.expect(isForbiddenSharedLibrary("libsqlite3.so.0"));
    try testing.expect(!isForbiddenSharedLibrary("libc.so.6"));
    try testing.expect(!isForbiddenSharedLibrary("libsqlite-compat-data"));
    try testing.expectError(error.NotElf, inspectElfNeeded("not an ELF artifact"));
}

test "standalone surface: five release artifacts have exact static ELF identities" {
    const release_dir = standalone_test_options.release_dir orelse return error.SkipZigTest;
    const targets = [_]struct { name: []const u8, class: u8, endian: std.builtin.Endian, machine: u16 }{
        .{ .name = "x86_64-linux-musl", .class = 2, .endian = .little, .machine = 62 },
        .{ .name = "aarch64-linux-musl", .class = 2, .endian = .little, .machine = 183 },
        .{ .name = "arm-linux-musleabihf", .class = 1, .endian = .little, .machine = 40 },
        .{ .name = "mips-linux-musleabi", .class = 1, .endian = .big, .machine = 8 },
        .{ .name = "mipsel-linux-musleabi", .class = 1, .endian = .little, .machine = 8 },
    };
    for (targets) |target| {
        const name = try std.fmt.allocPrint(testing.allocator, "{s}/fail2zig-v0.4.2-{s}", .{ release_dir, target.name });
        defer testing.allocator.free(name);
        const bytes = try std.fs.cwd().readFileAlloc(testing.allocator, name, max_elf_bytes);
        defer testing.allocator.free(bytes);
        try testing.expectEqual(@as(usize, 0), try inspectElfNeeded(bytes));
        try testing.expectEqual(target.class, bytes[4]);
        try testing.expectEqual(@as(u8, if (target.endian == .little) 1 else 2), bytes[5]);
        try testing.expectEqual(target.machine, try readElfU16(bytes, 18, target.endian));
        const offset: u64 = if (target.class == 1) try readElfU32(bytes, 28, target.endian) else try readElfU64(bytes, 32, target.endian);
        const size = try readElfU16(bytes, if (target.class == 1) 42 else 54, target.endian);
        const count = try readElfU16(bytes, if (target.class == 1) 44 else 56, target.endian);
        for (0..count) |index| {
            const position = try addElfOffset(offset, @as(u64, @intCast(index)) * size);
            try testing.expect((try readElfU32(bytes, position, target.endian)) != 3);
        }
    }
}

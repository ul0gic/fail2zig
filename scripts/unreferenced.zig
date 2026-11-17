// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Lists source files no build root reaches and declarations no live identifier refers to, one path:line per finding, for review.
// Holds: Reports only: it changes no file and exits 0 whenever its inputs parse, so a finding is a place to look, never a verdict.

const std = @import("std");
const Ast = std.zig.Ast;

// Why: The language or the standard library calls these by name, so no identifier in the tree refers to them.
const implicit = [_][]const u8{ "main", "panic", "format", "jsonStringify", "jsonParse", "jsonParseFromValue", "std_options", "build", "_" };

const max_source_bytes = 16 * 1024 * 1024;
const max_why_lines = 20;

const Counts = std.StringHashMap(u32);

const Import = struct { token: Ast.TokenIndex, target: usize };

const Declaration = struct {
    name_token: Ast.TokenIndex,
    first: Ast.TokenIndex,
    last: Ast.TokenIndex,
    public: bool,
    dead: bool = false,
};

const File = struct {
    path: []const u8,
    tree: Ast,
    imports: []Import,
    declarations: []Declaration,
    dead: []bool,
    counts: Counts,
    root: bool = false,
    live: bool = false,
    reported: bool = false,
    parent: ?usize = null,
};

const Finding = struct {
    path: []const u8,
    line: usize,
    kind: []const u8,
    name: []const u8,
    pass: usize,

    fn before(_: void, a: Finding, b: Finding) bool {
        return switch (std.mem.order(u8, a.path, b.path)) {
            .lt => true,
            .gt => false,
            .eq => a.line < b.line,
        };
    }
};

pub fn main() !void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const args = try std.process.argsAlloc(a);
    var why: ?[]const u8 = null;
    var inputs = std.ArrayList([]const u8).init(a);
    var index: usize = 1;
    while (index < args.len) : (index += 1) {
        if (std.mem.eql(u8, args[index], "--why")) {
            index += 1;
            if (index == args.len) return error.WhyNeedsAPathOrName;
            why = args[index];
        } else try inputs.append(args[index]);
    }
    if (inputs.items.len < 2) return error.UsageBuildFileThenFolders;

    var paths = std.ArrayList([]const u8).init(a);
    try paths.append(try std.fs.path.resolve(a, &.{inputs.items[0]}));
    for (inputs.items[1..]) |folder| try collect(a, folder, &paths);

    var by_path = std.StringHashMap(usize).init(a);
    for (paths.items, 0..) |path, file| try by_path.put(path, file);

    const files = try a.alloc(File, paths.items.len);
    for (paths.items, 0..) |path, file| files[file] = try load(a, path, by_path);
    try markRoots(a, &files[0], files, by_path);

    var findings = std.ArrayList(Finding).init(a);
    var global = Counts.init(a);
    var pass: usize = 1;
    // Why: A dead referrer keeps its target looking alive, so each pass drops what the last one found and counts again.
    while (true) : (pass += 1) {
        try reach(a, files);
        try count(files, &global);
        var changed = false;
        for (files) |*file| {
            if (!file.live) {
                if (!file.reported) {
                    file.reported = true;
                    changed = true;
                    try findings.append(.{ .path = file.path, .line = 1, .kind = "file", .name = "no build root reaches this file", .pass = pass });
                }
                continue;
            }
            for (file.declarations) |*declaration| {
                if (declaration.dead or file.dead[declaration.name_token]) continue;
                const name = file.tree.tokenSlice(declaration.name_token);
                if (isImplicit(name)) continue;
                const seen = if (declaration.public) global.get(name).? else file.counts.get(name).?;
                // Why: A declaration's mentions of itself, such as a recursive call, are not uses by anything else.
                if (seen != ownMentions(file, declaration.*, name)) continue;
                declaration.dead = true;
                changed = true;
                @memset(file.dead[declaration.first .. declaration.last + 1], true);
                const line = file.tree.tokenLocation(0, declaration.name_token).line + 1;
                try findings.append(.{ .path = file.path, .line = line, .kind = if (declaration.public) "public" else "private", .name = name, .pass = pass });
            }
        }
        if (!changed) break;
    }
    std.mem.sort(Finding, findings.items, {}, Finding.before);

    var buffered = std.io.bufferedWriter(std.io.getStdOut().writer());
    const out = buffered.writer();
    if (why) |target| {
        try explain(a, out, files, by_path, target);
    } else {
        for (findings.items) |finding| {
            try out.print("{s}:{d}: {s}: {s}", .{ finding.path, finding.line, finding.kind, finding.name });
            if (finding.pass > 1) try out.print(" (exposed in pass {d})", .{finding.pass});
            try out.writeByte('\n');
        }
        try out.print("unreferenced: {d} findings in {d} files read, {d} passes\n", .{ findings.items.len, files.len, pass });
    }
    try buffered.flush();
}

fn collect(a: std.mem.Allocator, folder: []const u8, paths: *std.ArrayList([]const u8)) !void {
    var dir = try std.fs.cwd().openDir(folder, .{ .iterate = true });
    defer dir.close();
    var walker = try dir.walk(a);
    defer walker.deinit();
    while (try walker.next()) |entry| {
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.path, ".zig")) continue;
        try paths.append(try std.fs.path.resolve(a, &.{ folder, entry.path }));
    }
}

fn load(a: std.mem.Allocator, path: []const u8, by_path: std.StringHashMap(usize)) !File {
    const source = try std.fs.cwd().readFileAllocOptions(a, path, max_source_bytes, null, @alignOf(u8), 0);
    const tree = try Ast.parse(a, source, .zig);
    if (tree.errors.len != 0) {
        std.debug.print("unreferenced: {s} does not parse\n", .{path});
        return error.SourceDoesNotParse;
    }
    const tags = tree.tokens.items(.tag);

    var imports = std.ArrayList(Import).init(a);
    for (tags, 0..) |tag, at| {
        if (tag != .string_literal or at < 2 or tags[at - 2] != .builtin) continue;
        const token: Ast.TokenIndex = @intCast(at);
        if (!std.mem.eql(u8, tree.tokenSlice(token - 2), "@import")) continue;
        const text = unquote(tree.tokenSlice(token));
        if (!std.mem.endsWith(u8, text, ".zig")) continue;
        const resolved = try std.fs.path.resolve(a, &.{ std.fs.path.dirname(path) orelse ".", text });
        if (by_path.get(resolved)) |target| try imports.append(.{ .token = token, .target = target });
    }

    var declarations = std.ArrayList(Declaration).init(a);
    var node: Ast.Node.Index = 0;
    while (node < tree.nodes.len) : (node += 1) {
        var container_buffer: [2]Ast.Node.Index = undefined;
        const container = tree.fullContainerDecl(&container_buffer, node) orelse continue;
        for (container.ast.members) |member| {
            var name_token: Ast.TokenIndex = undefined;
            var public = false;
            var proto_buffer: [1]Ast.Node.Index = undefined;
            if (tree.fullVarDecl(member)) |variable| {
                // Why: An extern or export symbol is referred to by the linker, which no identifier count can see.
                if (variable.extern_export_token != null) continue;
                name_token = variable.ast.mut_token + 1;
                public = variable.visib_token != null;
            } else if (tree.fullFnProto(&proto_buffer, member)) |function| {
                if (function.extern_export_inline_token) |keyword| if (tags[keyword] != .keyword_inline) continue;
                name_token = function.name_token orelse continue;
                public = function.visib_token != null;
            } else continue;
            try declarations.append(.{ .name_token = name_token, .first = tree.firstToken(member), .last = tree.lastToken(member), .public = public });
        }
    }

    const dead = try a.alloc(bool, tags.len);
    @memset(dead, false);
    return .{ .path = path, .tree = tree, .imports = try imports.toOwnedSlice(), .declarations = try declarations.toOwnedSlice(), .dead = dead, .counts = Counts.init(a) };
}

// Does:  Marks as a root every file the build file names in a string ending in .zig, and the build file itself.
fn markRoots(a: std.mem.Allocator, build_file: *File, files: []File, by_path: std.StringHashMap(usize)) !void {
    build_file.root = true;
    const tags = build_file.tree.tokens.items(.tag);
    for (tags, 0..) |tag, at| {
        if (tag != .string_literal) continue;
        const text = unquote(build_file.tree.tokenSlice(@intCast(at)));
        if (!std.mem.endsWith(u8, text, ".zig")) continue;
        if (by_path.get(try std.fs.path.resolve(a, &.{text}))) |target| files[target].root = true;
    }
}

// Does:  Marks live every file reachable from a root through imports that sit outside dead declarations, recording who reached it.
fn reach(a: std.mem.Allocator, files: []File) !void {
    var queue = std.ArrayList(usize).init(a);
    for (files, 0..) |*file, at| {
        file.live = file.root;
        file.parent = null;
        if (file.root) try queue.append(at);
    }
    var next: usize = 0;
    while (next < queue.items.len) : (next += 1) {
        const from = queue.items[next];
        for (files[from].imports) |import| {
            if (files[from].dead[import.token] or files[import.target].live) continue;
            files[import.target].live = true;
            files[import.target].parent = from;
            try queue.append(import.target);
        }
    }
}

fn count(files: []File, global: *Counts) !void {
    global.clearRetainingCapacity();
    for (files) |*file| {
        file.counts.clearRetainingCapacity();
        if (!file.live) continue;
        const tags = file.tree.tokens.items(.tag);
        for (tags, 0..) |tag, at| {
            if (file.dead[at]) continue;
            const name = mention(file.tree, tag, @intCast(at)) orelse continue;
            try bump(&file.counts, name);
            try bump(global, name);
        }
    }
}

// Does:  Returns the name a token mentions: an identifier, or a string that is exactly a name, as @hasDecl and @field take.
fn mention(tree: Ast, tag: std.zig.Token.Tag, token: Ast.TokenIndex) ?[]const u8 {
    switch (tag) {
        .identifier => return tree.tokenSlice(token),
        .string_literal => {
            const text = unquote(tree.tokenSlice(token));
            return if (isIdentifier(text)) text else null;
        },
        else => return null,
    }
}

fn ownMentions(file: *const File, declaration: Declaration, name: []const u8) u32 {
    const tags = file.tree.tokens.items(.tag);
    var found: u32 = 0;
    var token = declaration.first;
    while (token <= declaration.last) : (token += 1) {
        if (file.dead[token]) continue;
        const mentioned = mention(file.tree, tags[token], token) orelse continue;
        if (std.mem.eql(u8, mentioned, name)) found += 1;
    }
    return found;
}

// Does:  Answers --why: for a file, the import chain from a build root; for a name, where live code mentions it.
fn explain(a: std.mem.Allocator, out: anytype, files: []File, by_path: std.StringHashMap(usize), target: []const u8) !void {
    if (by_path.get(try std.fs.path.resolve(a, &.{target}))) |wanted| {
        if (!files[wanted].live) return out.print("{s}: no build root reaches this file\n", .{files[wanted].path});
        var chain = std.ArrayList(usize).init(a);
        var at: ?usize = wanted;
        while (at) |file| : (at = files[file].parent) try chain.append(file);
        std.mem.reverse(usize, chain.items);
        for (chain.items, 0..) |file, depth| {
            try out.writeByteNTimes(' ', depth * 2);
            try out.print("{s}{s}\n", .{ files[file].path, if (depth == 0) " (build root)" else "" });
        }
        return;
    }
    var shown: usize = 0;
    var total: usize = 0;
    for (files) |*file| {
        if (!file.live) continue;
        const tags = file.tree.tokens.items(.tag);
        for (tags, 0..) |tag, at| {
            if (file.dead[at]) continue;
            const name = mention(file.tree, tag, @intCast(at)) orelse continue;
            if (!std.mem.eql(u8, name, target)) continue;
            total += 1;
            if (shown == max_why_lines) continue;
            shown += 1;
            try out.print("{s}:{d}\n", .{ file.path, file.tree.tokenLocation(0, @intCast(at)).line + 1 });
        }
    }
    try out.print("{s}: {d} live mentions, {d} shown\n", .{ target, total, shown });
}

fn bump(counts: *Counts, name: []const u8) !void {
    const entry = try counts.getOrPut(name);
    entry.value_ptr.* = (if (entry.found_existing) entry.value_ptr.* else 0) + 1;
}

fn unquote(quoted: []const u8) []const u8 {
    return quoted[1 .. quoted.len - 1];
}

fn isImplicit(name: []const u8) bool {
    for (implicit) |known| if (std.mem.eql(u8, known, name)) return true;
    return false;
}

fn isIdentifier(text: []const u8) bool {
    if (text.len == 0 or std.ascii.isDigit(text[0])) return false;
    for (text) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '_') return false;
    return true;
}

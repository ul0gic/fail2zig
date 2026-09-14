// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Immutable, bounded configuration preparation. Parsing retains provenance;
//! only exact-generation consumer bindings can produce an admitted projection.
//! No source session, SQLite store, resolver, executable action or effect runs.
const std = @import("std");
const ini = @import("fail2ban.zig");
const context = @import("filter_context.zig");
const source = @import("source_plan.zig");
const native = @import("native.zig");
const processing = @import("../core/native_source_processor.zig");
const dns = @import("../core/native_dns.zig");
pub const version: u16 = 1;
pub const Limits = struct {
    arena_bytes: usize = 16 * 1024 * 1024,
    source_bytes: usize = 8 * 1024 * 1024,
    occurrences: usize = 1024,
    visited_entries: usize = 65536,
    include_depth: usize = 64,
    jails: usize = 128,
    fn validate(self: Limits) !void {
        if (self.arena_bytes < 4096 or self.arena_bytes > 32 * 1024 * 1024 or self.source_bytes == 0 or self.source_bytes > 16 * 1024 * 1024 or
            self.occurrences == 0 or self.occurrences > 1024 or self.visited_entries == 0 or self.visited_entries > 65536 or
            self.include_depth == 0 or self.include_depth > 64 or self.jails == 0 or self.jails > 128) return error.InvalidEffectiveLimit;
    }
};
pub const Option = struct { name: []const u8, value: ?[]const u8, origin: ?ini.Origin, error_name: ?[]const u8 };
pub const Asset = struct {
    kind: enum { filter, action, banaction },
    selector: []const u8,
    prepared: ini.ParameterizedAsset,
    combined: std.StringArrayHashMapUnmanaged([]const u8),
    generation: [32]u8,
};
pub const Jail = struct {
    name: []const u8,
    enabled: ini.ResolvedOption,
    options: []Option,
    assets: []Asset,
    source: source.Plan,
    generation: [32]u8,
};
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    buffer: []u8,
    arena: std.heap.FixedBufferAllocator,
    root: []const u8,
    limits: Limits,
    source_bytes: usize = 0,
    visited_entries: usize = 0,
    occurrences: usize = 0,
    document: ini.ConfigDocument = undefined,
    globals: ini.ConfigDocument = undefined,
    jails: []Jail = &.{},
    generation: [32]u8 = undefined,
    pub fn create(allocator: std.mem.Allocator, root: []const u8, limits: Limits) !*Prepared {
        try limits.validate();
        if (!std.fs.path.isAbsolute(root) or root.len > 4096 or std.mem.indexOfScalar(u8, root, 0) != null) return error.InvalidConfigRoot;
        const self = try allocator.create(Prepared);
        errdefer allocator.destroy(self);
        const buffer = try allocator.alloc(u8, limits.arena_bytes);
        errdefer allocator.free(buffer);
        self.* = .{ .allocator = allocator, .buffer = buffer, .arena = std.heap.FixedBufferAllocator.init(buffer), .root = root, .limits = limits };
        self.root = try self.alloc().dupe(u8, root);
        self.document = try self.documentFor("jail");
        self.globals = try self.documentFor("fail2ban");
        var jails = std.ArrayList(Jail).init(self.alloc());
        var sections = self.document.source.userSections();
        while (sections.next()) |section| {
            if (jails.items.len == limits.jails) return error.EffectiveJailLimit;
            try jails.append(try self.prepareJail(section.name));
        }
        self.jails = try jails.toOwnedSlice();
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("fail2zig-native-effective-v1\x00");
        hash.update(&self.document.config_generation);
        hash.update(&self.globals.config_generation);
        for (self.jails) |jail| hash.update(&jail.generation);
        hash.final(&self.generation);
        return self;
    }
    pub fn destroy(self: *Prepared) void {
        const allocator = self.allocator;
        allocator.free(self.buffer);
        allocator.destroy(self);
    }
    pub fn memoryBytes(self: *const Prepared) usize {
        return @sizeOf(Prepared) + self.buffer.len;
    }
    fn alloc(self: *Prepared) std.mem.Allocator {
        return self.arena.allocator();
    }
    fn documentFor(self: *Prepared, stem: []const u8) !ini.ConfigDocument {
        const graph = try self.load(stem);
        return .{ .source = graph, .config_generation = graphDigest(graph) };
    }
    /// Equivalent layer/include ordering to the existing reader, with an
    /// aggregate byte/occurrence/arena bound and every directory entry charged.
    fn load(self: *Prepared, stem: []const u8) anyerror!ini.ParsedIni {
        const a = self.alloc();
        var files = std.ArrayList([]const u8).init(a);
        const directory = try std.fmt.allocPrint(a, "{s}/{s}.d", .{ self.root, stem });
        for ([_][]const u8{ ".conf", ".local" }) |extension| {
            try files.append(try std.fmt.allocPrint(a, "{s}{s}", .{ stem, extension }));
            var dir = std.fs.openDirAbsolute(directory, .{ .iterate = true }) catch |err| switch (err) {
                error.FileNotFound, error.NotDir => continue,
                else => return err,
            };
            defer dir.close();
            var selected = std.ArrayList([]const u8).init(a);
            var iterator = dir.iterate();
            while (try iterator.next()) |entry| {
                if (self.visited_entries == self.limits.visited_entries) return error.ConfigDirectoryLimit;
                self.visited_entries += 1;
                if (entry.kind != .file and entry.kind != .sym_link) continue;
                if (!std.mem.endsWith(u8, entry.name, extension)) continue;
                if (selected.items.len == self.limits.occurrences) return error.ConfigOccurrenceLimit;
                try selected.append(try std.fmt.allocPrint(a, "{s}.d/{s}", .{ stem, entry.name }));
            }
            std.mem.sort([]const u8, selected.items, {}, less);
            try files.appendSlice(selected.items);
        }
        var graph = ini.ParsedIni{};
        var stack = std.ArrayList([]const u8).init(a);
        for (files.items) |path| try self.occurrence(&graph, self.root, path, files.items, &stack, .layer);
        try ini.interpolate(a, &graph);
        return graph;
    }
    fn occurrence(self: *Prepared, graph: *ini.ParsedIni, root: []const u8, path: []const u8, top: []const []const u8, stack: *std.ArrayList([]const u8), edge: ini.SourceEdge) anyerror!void {
        if (path.len > 4096 or std.mem.indexOfScalar(u8, path, 0) != null or std.mem.indexOfScalar(u8, root, 0) != null) return error.InvalidConfigPath;
        const a = self.alloc();
        const full = try std.fs.path.resolve(a, &.{ root, path });
        if (full.len > 4096) return error.InvalidConfigPath;
        for (stack.items) |ancestor| if (std.mem.eql(u8, ancestor, full)) {
            try graph.warnings.append(a, .{ .source = full, .line = 0, .message = "include cycle skipped" });
            return;
        };
        if (stack.items.len >= self.limits.include_depth) return error.IncludeDepthExceeded;
        const file = (try self.readFile(full)) orelse {
            try self.adjacent(graph, root, full, top, stack);
            return;
        };
        if (self.occurrences == self.limits.occurrences) return error.ConfigOccurrenceLimit;
        self.occurrences += 1;
        try stack.append(full);
        defer _ = stack.pop();
        var parsed = try ini.parseIniSource(a, full, file.bytes);
        for ([_][]const u8{ "before", "after" }) |role| {
            if (std.mem.eql(u8, role, "after")) {
                try merge(a, graph, parsed);
                try graph.sources.append(a, .{ .edge = edge, .original_path = path, .resolved_target = file.target, .parent_path = if (stack.items.len > 1) stack.items[stack.items.len - 2] else null, .path = full, .bytes = file.bytes, .sha256 = file.digest });
            }
            if (try ini.resolve(a, &parsed, "INCLUDES", role)) |value| {
                var lines = std.mem.splitScalar(u8, value, '\n');
                while (lines.next()) |line| {
                    const include = std.mem.trim(u8, line, " \t");
                    if (include.len != 0) try self.occurrence(graph, std.fs.path.dirname(full).?, include, &.{}, stack, if (std.mem.eql(u8, role, "before")) .before else .after);
                }
            }
        }
        try self.adjacent(graph, root, full, top, stack);
    }
    fn adjacent(self: *Prepared, graph: *ini.ParsedIni, root: []const u8, full: []const u8, top: []const []const u8, stack: *std.ArrayList([]const u8)) anyerror!void {
        if (!validAbsolute(full)) return error.InvalidConfigPath;
        if (std.mem.endsWith(u8, full, ".local")) return;
        const extension = std.fs.path.extension(full);
        const local = try std.fmt.allocPrint(self.alloc(), "{s}.local", .{full[0 .. full.len - extension.len]});
        for (top) |entry| {
            const candidate = try std.fs.path.resolve(self.alloc(), &.{ root, entry });
            if (std.mem.eql(u8, candidate, local)) return;
        }
        try self.occurrence(graph, "", local, &.{}, stack, .local);
    }
    const File = struct { bytes: []const u8, target: []const u8, digest: [32]u8 };
    fn readFile(self: *Prepared, path: []const u8) !?File {
        if (!validAbsolute(path)) return error.InvalidConfigPath;
        const fd = std.posix.open(path, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true }, 0) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
        const file = std.fs.File{ .handle = fd };
        defer file.close();
        const before = try std.posix.fstat(fd);
        if (!std.posix.S.ISREG(before.mode) or before.mode & 0o022 != 0 or (before.uid != 0 and before.uid != std.os.linux.geteuid())) return error.UntrustedConfigFile;
        if (before.size < 0 or before.size > ini.max_file_bytes or @as(u64, @intCast(before.size)) > self.limits.source_bytes - self.source_bytes) return error.ConfigSourceByteLimit;
        const bytes = try self.alloc().alloc(u8, @intCast(before.size));
        self.source_bytes += bytes.len;
        if (try file.readAll(bytes) != bytes.len) return error.ConfigChanged;
        var extra: [1]u8 = undefined;
        if (try file.read(&extra) != 0) return error.ConfigChanged;
        const after = try std.posix.fstat(fd);
        if (before.size != after.size or !std.meta.eql(before.mtim, after.mtim) or !std.meta.eql(before.ctim, after.ctim)) return error.ConfigChanged;
        const target = try std.fs.realpathAlloc(self.alloc(), path);
        const selected = try std.posix.fstatat(std.posix.AT.FDCWD, target, 0);
        if (selected.dev != before.dev or selected.ino != before.ino) return error.ConfigChanged;
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        return .{ .bytes = bytes, .target = target, .digest = digest };
    }
    fn asset(self: *Prepared, kind: @FieldType(Asset, "kind"), selector_text: []const u8) !Asset {
        const a = self.alloc();
        const selector = try ini.parseSelector(a, selector_text);
        if (selector.name.len == 0 or selector.name.len > 128 or std.mem.indexOfAny(u8, selector.name, "/\\\x00") != null or std.mem.eql(u8, selector.name, ".") or std.mem.eql(u8, selector.name, "..")) return error.InvalidAssetName;
        const stem = try std.fmt.allocPrint(a, "{s}/{s}", .{ if (kind == .filter) "filter.d" else "action.d", selector.name });
        var prepared = ini.ParameterizedAsset{ .selector = selector, .config = try self.load(stem) };
        for ([_][]const u8{ "DEFAULT", "Definition" }) |section_name| if (prepared.config.section(section_name)) |section| {
            var entries = section.keys.iterator();
            while (entries.next()) |entry| try prepared.definition.put(a, entry.key_ptr.*, entry.value_ptr.*);
        };
        if (prepared.config.section("Init")) |section| {
            var entries = section.keys.iterator();
            while (entries.next()) |entry| {
                const value = if (std.mem.indexOfScalar(u8, entry.key_ptr.*, '?')) |at| selector.parameters.get(entry.key_ptr.*[0..at]) orelse entry.value_ptr.* else entry.value_ptr.*;
                try prepared.init.put(a, entry.key_ptr.*, value);
                if (!std.mem.startsWith(u8, entry.key_ptr.*, "known/")) try prepared.init.put(a, try std.fmt.allocPrint(a, "known/{s}", .{entry.key_ptr.*}), entry.value_ptr.*);
            }
        }
        var parameters = selector.parameters.iterator();
        while (parameters.next()) |entry| try prepared.init.put(a, entry.key_ptr.*, entry.value_ptr.*);
        if (kind != .filter) try definition(a, &prepared, &selector.parameters);
        const combined = try ini.combineAsset(a, &prepared, "");
        return .{ .kind = kind, .selector = selector_text, .prepared = prepared, .combined = combined, .generation = assetDigest(kind, selector_text, prepared.config, combined) };
    }
    /// Same initial-known/final-jail parameter phases as filter_context.prepare,
    /// using the bounded preloaded asset instead of its filesystem loader.
    fn filterContext(self: *Prepared, original: ini.ParsedIni, jail: []const u8, item: *Asset, backend: []const u8) !ini.ParsedIni {
        const a = self.alloc();
        var parameters = try item.prepared.selector.parameters.clone(a);
        if (!parameters.contains("backend")) try parameters.put(a, "backend", backend);
        if (!parameters.contains("filter")) try parameters.put(a, "filter", item.selector);
        const selected = item.prepared.selector.parameters.get("logtype");
        const own = if (item.prepared.config.section("Definition")) |section| section.keys.contains("logtype") else false;
        if ((selected == null or selected.?.len == 0) and !own) {
            const logtype: []const u8 = if (std.mem.startsWith(u8, backend, "systemd")) "journal" else "file";
            try parameters.put(a, "logtype", logtype);
            try item.prepared.init.put(a, "logtype", logtype);
        }
        try definition(a, &item.prepared, &parameters);
        const known = try ini.combineAsset(a, &item.prepared, "");
        var graph = try context.readerDefaults(a, &original, self.root);
        const section = graph.sections.getPtr(jail) orelse return error.UnknownEffectiveJail;
        section.keys = try section.keys.clone(a);
        var entries = known.iterator();
        while (entries.next()) |entry| {
            if (std.mem.startsWith(u8, entry.key_ptr.*, "known/") or std.mem.eql(u8, entry.key_ptr.*, "__name__")) continue;
            try section.keys.put(a, try std.fmt.allocPrint(a, "known/{s}", .{entry.key_ptr.*}), entry.value_ptr.*);
        }
        for ([_][]const u8{ "usedns", "prefregex", "ignoreregex", "failregex", "maxlines", "datepattern", "journalmatch" }) |key| {
            if (try ini.resolve(a, &graph, jail, key)) |value| if (!item.prepared.selector.parameters.contains(key)) try parameters.put(a, key, value);
        }
        try definition(a, &item.prepared, &parameters);
        item.combined = try ini.combineAsset(a, &item.prepared, "");
        item.generation = assetDigest(item.kind, item.selector, item.prepared.config, item.combined);
        return graph;
    }
    fn prepareJail(self: *Prepared, name: []const u8) !Jail {
        const a = self.alloc();
        if (name.len == 0 or name.len > 64 or std.mem.indexOfScalar(u8, name, 0) != null) return error.InvalidEffectiveJail;
        var graph = try context.readerDefaults(a, &self.document.source, self.root);
        const enabled = try ini.readTypedOption(a, &graph, name, "enabled", .boolean, .{ .boolean = false }, "jail-reader:enabled=false");
        var assets = std.ArrayList(Asset).init(a);
        var defaults = source.FilterDefaults{ .config_root = self.root };
        for ([_]@FieldType(Asset, "kind"){ .filter, .action, .banaction }) |kind| {
            const selection = (try ini.resolve(a, &graph, name, @tagName(kind))) orelse if (kind == .filter) name else continue;
            const selectors = try ini.splitSelectors(a, selection);
            if (selectors.len > 16) return error.EffectiveAssetLimit;
            for (selectors) |selector| {
                if (std.mem.trim(u8, selector, " \t\r\n").len == 0) continue;
                var item = try self.asset(kind, selector);
                if (kind == .filter) {
                    if (defaults.values != null) return error.MultipleEffectiveFilters;
                    graph = try self.filterContext(graph, name, &item, (try ini.resolve(a, &graph, name, "backend")) orelse "auto");
                    const retained = try a.create(@TypeOf(item.combined));
                    retained.* = item.combined;
                    defaults.values = retained;
                    defaults.asset_index = assets.items.len;
                }
                try assets.append(item);
            }
        }
        var keys = std.StringArrayHashMapUnmanaged(void){};
        for ([_][]const u8{ "DEFAULT", name }) |section_name| if (self.document.source.section(section_name)) |section| {
            for (section.keys.keys()) |key| try keys.put(a, key, {});
        };
        var options = std.ArrayList(Option).init(a);
        for (keys.keys()) |key| {
            const own = self.document.source.section(name).?;
            const default = self.document.source.section("DEFAULT");
            const origin = own.origins.get(key) orelse if (default) |section| section.origins.get(key) else null;
            var err_name: ?[]const u8 = null;
            const value = ini.resolve(a, &graph, name, key) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => blk: {
                    err_name = @errorName(err);
                    break :blk null;
                },
            };
            try options.append(.{ .name = key, .value = value, .origin = origin, .error_name = err_name });
        }
        const plan = try source.prepare(a, &graph, name, &self.globals.source, defaults);
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("fail2zig-native-effective-jail-v1\x00");
        hash.update(&self.document.config_generation);
        hash.update(&self.globals.config_generation);
        hashText(&hash, name);
        for (options.items) |option| {
            hashText(&hash, option.name);
            hashText(&hash, option.value orelse "");
            hashText(&hash, option.error_name orelse "");
        }
        for (assets.items) |item| hash.update(&item.generation);
        var generation: [32]u8 = undefined;
        hash.final(&generation);
        return .{ .name = name, .enabled = enabled, .options = try options.toOwnedSlice(), .assets = try assets.toOwnedSlice(), .source = plan, .generation = generation };
    }
};
fn less(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.lessThan(u8, left, right);
}
fn hashText(hash: *std.crypto.hash.sha2.Sha256, text: []const u8) void {
    var length: [8]u8 = undefined;
    std.mem.writeInt(u64, &length, @intCast(text.len), .little);
    hash.update(&length);
    hash.update(text);
}
fn graphDigest(graph: ini.ParsedIni) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("fail2zig-native-config-graph-v1\x00fail2ban-1.1.1\x00");
    for (graph.sources.items) |occurrence| {
        hashText(&hash, occurrence.path);
        hashText(&hash, occurrence.original_path);
        hashText(&hash, occurrence.resolved_target);
        hashText(&hash, occurrence.parent_path orelse "");
        hash.update(&.{@intFromEnum(occurrence.edge)});
        hash.update(&occurrence.sha256);
    }
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return digest;
}
fn assetDigest(kind: @FieldType(Asset, "kind"), selector: []const u8, graph: ini.ParsedIni, combined: std.StringArrayHashMapUnmanaged([]const u8)) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("fail2zig-native-config-asset-v1\x00");
    hash.update(&.{@intFromEnum(kind)});
    hashText(&hash, selector);
    hash.update(&graphDigest(graph));
    for (combined.keys(), combined.values()) |key, value| {
        hashText(&hash, key);
        hashText(&hash, value);
    }
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return digest;
}
fn definition(a: std.mem.Allocator, asset: *ini.ParameterizedAsset, parameters: *const std.StringArrayHashMapUnmanaged([]const u8)) !void {
    var entries = asset.definition.iterator();
    while (entries.next()) |entry| entry.value_ptr.* = parameters.get(entry.key_ptr.*) orelse (try ini.resolveWithParameters(a, &asset.config, "Definition", entry.key_ptr.*, parameters)) orelse entry.value_ptr.*;
}
// Merge uses the established raw-origin previous-value and conditional-section
// semantics. Filesystem traversal is deliberately separate from this pure phase.
fn merge(a: std.mem.Allocator, base: *ini.ParsedIni, override: ini.ParsedIni) !void {
    var sections = override.sections.iterator();
    while (sections.next()) |entry| {
        const original = entry.key_ptr.*;
        const condition = std.mem.indexOfScalar(u8, original, '?');
        const name = if (condition) |at| original[0..at] else original;
        if (base.sections.count() >= ini.max_sections and base.section(name) == null) return error.TooManySections;
        const slot = try base.sections.getOrPut(a, name);
        if (!slot.found_existing) slot.value_ptr.* = .{ .name = name };
        var keys = entry.value_ptr.keys.iterator();
        while (keys.next()) |key| {
            const selected = if (condition) |at| try std.fmt.allocPrint(a, "{s}{s}", .{ key.key_ptr.*, original[at..] }) else key.key_ptr.*;
            if (slot.value_ptr.keys.count() >= ini.max_keys_per_section and !slot.value_ptr.keys.contains(selected)) return error.TooManyKeysInSection;
            if (!std.mem.eql(u8, name, "DEFAULT")) {
                const previous = if (slot.value_ptr.origins.get(selected)) |origin| origin.raw else slot.value_ptr.get(selected);
                if (previous) |value| try slot.value_ptr.previous.put(a, selected, value);
            }
            try slot.value_ptr.keys.put(a, selected, key.value_ptr.*);
            if (entry.value_ptr.origins.get(key.key_ptr.*)) |origin| try slot.value_ptr.origins.put(a, selected, origin);
        }
    }
    try base.assignments.appendSlice(a, override.assignments.items);
    try base.warnings.appendSlice(a, override.warnings.items);
}

pub const AssetBinding = struct { generation: [32]u8 };
pub const Binding = struct {
    jail: []const u8,
    prepared_generation: [32]u8,
    rule_generation: [32]u8,
    native_filter: []const u8,
    assets: []const AssetBinding,
    source_kind: native.LogSource,
    timestamp: processing.TimestampSource,
    encoding: @import("../core/source_text.zig").Encoding = .utf8,
    family: dns.Family = .both,
    hostname_subject: bool = false,
    resolver: ?std.net.Address = null,
    resolver_generation: [32]u8 = [_]u8{0} ** 32,
    effect: native.BanAction = .@"log-only",
    effect_scope_generation: [32]u8,
    journal_origin_generation: [32]u8 = [_]u8{0} ** 32,
    pub fn jsonStringify(self: Binding, writer: anytype) !void {
        try writer.beginObject();
        inline for (.{ "jail", "prepared_generation", "rule_generation", "native_filter", "assets", "source_kind", "timestamp", "encoding", "family", "hostname_subject", "resolver_generation", "effect", "effect_scope_generation", "journal_origin_generation" }) |field| {
            try writer.objectField(field);
            try writer.write(@field(self, field));
        }
        try writer.objectField("resolver");
        if (self.resolver) |server| {
            var bytes: [128]u8 = undefined;
            try writer.write(try std.fmt.bufPrint(&bytes, "{}", .{server}));
        } else try writer.write(null);
        try writer.endObject();
    }
};
/// Caller keeps this value at a stable address while reading its slice fields.
/// Diagnostics own their bytes and survive failed projection arena cleanup.
pub const Diagnostic = struct {
    jail: []const u8 = "",
    key: []const u8 = "",
    detail: []const u8 = "",
    jail_bytes: [64]u8 = undefined,
    key_bytes: [128]u8 = undefined,
    detail_bytes: [512]u8 = undefined,
    truncated: bool = false,
};
pub const GlobalBinding = struct {
    prepared_generation: [32]u8,
    /// Explicit native target; source fail2ban SQLite is read-only migration input.
    state_file: []const u8,
    retention_generation: [32]u8 = [_]u8{0} ** 32,
};
pub const GlobalSettings = struct {
    allow_ipv6: enum { automatic, enabled, disabled } = .automatic,
    source_dbfile: ?[]const u8 = null,
    retention: ?struct { purge_age_seconds: ?u64, max_matches: ?u32, consumer_generation: [32]u8 } = null,
};
pub const ConsumerSettings = struct {
    binding: Binding,
    source: source.Plan,
    ignore: struct { values: []const []const u8, self_required: bool, dns_mode: enum { no, yes, warn } },
    processing: processing.Options,
};
pub const Projection = struct {
    allocator: std.mem.Allocator,
    buffer: []u8,
    arena: std.heap.FixedBufferAllocator,
    config: native.Config,
    globals: GlobalSettings = .{},
    consumers: []ConsumerSettings,
    generation: [32]u8,
    /// Prepared, original and binding owners must outlive this projection.
    /// Unsupported settings fail here, before Store.open or source/effect work.
    /// Original compatibility_pending flags are never edited in place.
    pub fn create(allocator: std.mem.Allocator, prepared: *const Prepared, original: *const native.Config, bindings: []const Binding, diagnostic: *Diagnostic) !*Projection {
        return createWithGlobal(allocator, prepared, original, null, bindings, diagnostic);
    }
    pub fn createWithGlobal(allocator: std.mem.Allocator, prepared: *const Prepared, original: *const native.Config, global_binding: ?GlobalBinding, bindings: []const Binding, diagnostic: *Diagnostic) !*Projection {
        diagnostic.* = .{};
        if (bindings.len > prepared.limits.jails) return error.EffectiveJailLimit;
        for (original.jails) |jail| if (jail.enabled) {
            var present = false;
            for (prepared.jails) |candidate| if (std.mem.eql(u8, jail.name, candidate.name)) {
                if (candidate.enabled.value != .boolean or !candidate.enabled.value.boolean) return fail(diagnostic, jail.name, "enabled", "disabling existing protection requires explicit retirement", error.OriginalJailRetirementRequired);
                present = true;
                break;
            };
            if (!present) return fail(diagnostic, jail.name, "jail", "enabled native jail has no prepared projection", error.UnprojectedOriginalJail);
        };
        const self = try allocator.create(Projection);
        errdefer allocator.destroy(self);
        const buffer = try allocator.alloc(u8, 4 * 1024 * 1024);
        errdefer allocator.free(buffer);
        self.* = .{ .allocator = allocator, .buffer = buffer, .arena = std.heap.FixedBufferAllocator.init(buffer), .config = original.*, .consumers = undefined, .generation = undefined };
        const a = self.arena.allocator();
        try checkGlobals(prepared, diagnostic);
        try self.projectGlobals(prepared, global_binding, diagnostic);
        self.config.jails = try a.alloc(native.JailConfig, prepared.jails.len);
        var consumers = std.ArrayList(ConsumerSettings).init(a);
        var consumed = [_]bool{false} ** 128;
        var identity = std.crypto.hash.sha2.Sha256.init(.{});
        identity.update("fail2zig-native-projection-v1\x00");
        identity.update(&prepared.generation);
        for (prepared.jails, self.config.jails) |jail, *out| {
            out.* = .{ .name = jail.name, .enabled = false, .compatibility_pending = true };
            for (original.jails) |prior| if (std.mem.eql(u8, prior.name, jail.name)) {
                out.* = prior;
                out.enabled = false;
                out.compatibility_pending = true;
                break;
            };
            if (jail.enabled.value != .boolean) return fail(diagnostic, jail.name, "enabled", "invalid typed enabled value", error.InvalidEffectiveValue);
            if (!jail.enabled.value.boolean) continue;
            var selected: ?usize = null;
            for (bindings, 0..) |binding, index| if (std.mem.eql(u8, binding.jail, jail.name)) {
                if (selected != null) return fail(diagnostic, jail.name, "binding", "duplicate consumer binding", error.DuplicateEffectiveBinding);
                selected = index;
            };
            const index = selected orelse return fail(diagnostic, jail.name, "binding", "enabled jail has no qualified consumer binding", error.MissingEffectiveBinding);
            consumed[index] = true;
            const binding = bindings[index];
            if (!std.mem.eql(u8, &binding.prepared_generation, &jail.generation) or zero(binding.rule_generation) or zero(binding.effect_scope_generation))
                return fail(diagnostic, jail.name, "binding", "consumer generation differs from prepared configuration", error.EffectiveGenerationMismatch);
            try checkJail(jail, binding, diagnostic);
            const findtime = try seconds(optionValue(jail, "findtime") orelse "600");
            const bantime = try seconds(optionValue(jail, "bantime") orelse "600");
            const maxretry_text = optionValue(jail, "maxretry") orelse "5";
            const maxretry = std.fmt.parseInt(u32, maxretry_text, 10) catch return fail(diagnostic, jail.name, "maxretry", maxretry_text, error.InvalidEffectiveValue);
            if (maxretry == 0 or maxretry > native.max_supported_retry) return fail(diagnostic, jail.name, "maxretry", maxretry_text, error.InvalidEffectiveValue);
            var paths = std.ArrayList([]const u8).init(a);
            for (jail.source.paths) |path| {
                if (binding.source_kind == .file and (path.start == null or path.pattern.len == 0 or path.pattern.len > 512)) return fail(diagnostic, jail.name, "logpath", path.raw, error.InvalidEffectiveValue);
                try paths.append(path.pattern);
            }
            if (binding.source_kind == .file and paths.items.len == 0) return fail(diagnostic, jail.name, "logpath", "explicit file source requires a path", error.InvalidEffectiveValue);
            var ignores = std.ArrayList([]const u8).init(a);
            var needs_dns = binding.hostname_subject;
            if (optionValue(jail, "ignoreip")) |raw| {
                var tokens = std.mem.tokenizeAny(u8, raw, " \t\r\n");
                while (tokens.next()) |token| {
                    if (ignores.items.len == 1024) return error.EffectiveIgnoreLimit;
                    if (@import("../core/state.zig").Cidr.parse(token)) |_| {} else |_| {
                        _ = dns.Name.init(token) catch return fail(diagnostic, jail.name, "ignoreip", token, error.InvalidEffectiveValue);
                        needs_dns = true;
                    }
                    try ignores.append(token);
                }
            }
            const dns_text = source.string(jail.source.ignore.usedns) orelse "warn";
            const dns_mode: @FieldType(@FieldType(ConsumerSettings, "ignore"), "dns_mode") = if (std.mem.eql(u8, dns_text, "no")) .no else if (std.mem.eql(u8, dns_text, "yes")) .yes else if (std.mem.eql(u8, dns_text, "warn")) .warn else return fail(diagnostic, jail.name, "usedns", dns_text, error.InvalidEffectiveValue);
            if (binding.hostname_subject and dns_mode == .no) return fail(diagnostic, jail.name, "usedns", "hostname subjects disabled by usedns=no", error.InvalidEffectiveValue);
            if (needs_dns) {
                const resolver = binding.resolver orelse return fail(diagnostic, jail.name, "resolver", "numeric resolver binding required", error.RequiredEffectiveState);
                if ((resolver.any.family != std.posix.AF.INET and resolver.any.family != std.posix.AF.INET6) or resolver.getPort() == 0 or zero(binding.resolver_generation)) return error.InvalidEffectiveValue;
            }
            var self_required = true;
            if (jail.source.ignore.ignoreself.reader) |reader| if (reader.value == .boolean) {
                self_required = reader.value.boolean;
            };
            out.* = .{ .name = jail.name, .enabled = true, .filter = binding.native_filter, .source = binding.source_kind, .logpath = try paths.toOwnedSlice(), .maxretry = maxretry, .findtime = findtime, .bantime = bantime, .banaction = binding.effect, .ignoreip = try ignores.toOwnedSlice(), .compatibility_pending = false };
            // Existing native Config is a compatibility seam; authoritative time,
            // family, source modes and consumers remain in these typed settings.
            const window_us = std.math.mul(i64, @intCast(findtime), 1_000_000) catch return error.InvalidEffectiveValue;
            var consumer_hash = std.crypto.hash.sha2.Sha256.init(.{});
            consumer_hash.update("fail2zig-effective-consumer-binding-v1\x00");
            consumer_hash.update(&jail.generation);
            try std.json.stringify(binding, .{}, HashWriter{ .context = &consumer_hash });
            var consumer_generation: [32]u8 = undefined;
            consumer_hash.final(&consumer_generation);
            try consumers.append(.{ .binding = binding, .source = jail.source, .ignore = .{ .values = out.ignoreip.?, .self_required = self_required, .dns_mode = dns_mode }, .processing = .{
                .jail = jail.name,
                .parent_generation = consumer_generation,
                .timestamp = binding.timestamp,
                .encoding = binding.encoding,
                .window_us = window_us,
            } });
            var scratch: [2048]u8 = undefined;
            _ = try processing.Processor.init(a, consumers.items[consumers.items.len - 1].processing, &scratch, .{ .us = 0 });
            try std.json.stringify(binding, .{}, HashWriter{ .context = &identity });
        }
        for (bindings, 0..) |binding, index| if (!consumed[index]) return fail(diagnostic, binding.jail, "binding", "binding names no enabled prepared jail", error.UnusedEffectiveBinding);
        self.config.global.compatibility_pending = false;
        self.config.global.native_ingestion = true;
        if (self.config.global.compatibility_manifest.len > native.max_config_bytes) return error.ConfigSourceByteLimit;
        try std.json.stringify(self.config.global, .{}, HashWriter{ .context = &identity });
        try std.json.stringify(self.config.defaults, .{}, HashWriter{ .context = &identity });
        try std.json.stringify(self.globals, .{}, HashWriter{ .context = &identity });
        // Retain the complete original manifest; parsing never erases its source
        // evidence. Native admission is represented by this separate owner.
        self.consumers = try consumers.toOwnedSlice();
        identity.final(&self.generation);
        return self;
    }
    pub fn destroy(self: *Projection) void {
        const a = self.allocator;
        a.free(self.buffer);
        a.destroy(self);
    }
    fn projectGlobals(self: *Projection, prepared: *const Prepared, binding: ?GlobalBinding, diag: *Diagnostic) !void {
        const a = self.arena.allocator();
        if (binding) |proof| if (!std.mem.eql(u8, &proof.prepared_generation, &prepared.globals.config_generation)) return error.EffectiveGenerationMismatch;
        if (try globalValue(a, prepared, "loglevel")) |level| {
            self.config.global.log_level = if (std.ascii.eqlIgnoreCase(level, "DEBUG")) .debug else if (std.ascii.eqlIgnoreCase(level, "INFO")) .info else if (std.ascii.eqlIgnoreCase(level, "WARN") or std.ascii.eqlIgnoreCase(level, "WARNING")) .warn else if (std.ascii.eqlIgnoreCase(level, "ERROR")) .err else return fail(diag, "", "loglevel", level, error.UnsupportedEffectiveGlobal);
        }
        if (try globalValue(a, prepared, "logtarget")) |target| if (!std.ascii.eqlIgnoreCase(target, "STDERR")) return fail(diag, "", "logtarget", target, error.UnsupportedEffectiveGlobal);
        const socket_setting = try globalValue(a, prepared, "socket");
        if (socket_setting) |path| {
            if (!validAbsolute(path) or path.len >= 108) return fail(diag, "", "socket", path, error.InvalidEffectiveValue);
            self.config.global.socket_path = path;
        }
        if (try globalValue(a, prepared, "allowipv6")) |raw| {
            self.globals.allow_ipv6 = if (std.ascii.eqlIgnoreCase(raw, "auto")) .automatic else if (std.ascii.eqlIgnoreCase(raw, "yes") or std.ascii.eqlIgnoreCase(raw, "true") or std.mem.eql(u8, raw, "1") or std.ascii.eqlIgnoreCase(raw, "on")) .enabled else if (std.ascii.eqlIgnoreCase(raw, "no") or std.ascii.eqlIgnoreCase(raw, "false") or std.mem.eql(u8, raw, "0") or std.ascii.eqlIgnoreCase(raw, "off")) .disabled else return fail(diag, "", "allowipv6", raw, error.InvalidEffectiveValue);
        }
        if (try globalValue(a, prepared, "dbfile")) |path| {
            if (path.len > 4096 or std.mem.indexOfScalar(u8, path, 0) != null) return fail(diag, "", "dbfile", "invalid database source path", error.InvalidEffectiveValue);
            if (std.ascii.eqlIgnoreCase(path, "none") or path.len == 0) return fail(diag, "", "dbfile", "required persistence cannot be disabled", error.RequiredEffectiveState);
            const proof = binding orelse return fail(diag, "", "dbfile", "explicit separate native state target required", error.RequiredEffectiveState);
            if (!validAbsolute(proof.state_file) or !std.mem.eql(u8, proof.state_file, self.config.global.state_file)) return fail(diag, "", "dbfile", "native state target binding differs from original native Config", error.EffectiveGenerationMismatch);
            const source_path = try std.fs.path.resolve(a, &.{ prepared.root, path });
            const source_canonical = try canonicalStatePath(a, source_path);
            const target_canonical = try canonicalStatePath(a, proof.state_file);
            if (std.mem.eql(u8, source_canonical, target_canonical)) return fail(diag, "", "dbfile", "source and target resolve to the same database", error.UnsafeStateProjection);
            const source_stat = std.posix.fstatat(std.posix.AT.FDCWD, source_canonical, 0) catch |err| switch (err) {
                error.FileNotFound => null,
                else => return err,
            };
            const target_stat = std.posix.fstatat(std.posix.AT.FDCWD, target_canonical, 0) catch |err| switch (err) {
                error.FileNotFound => null,
                else => return err,
            };
            if (source_stat != null and target_stat != null and source_stat.?.dev == target_stat.?.dev and source_stat.?.ino == target_stat.?.ino) return error.UnsafeStateProjection;
            self.globals.source_dbfile = path;
        }
        if (socket_setting) |path| {
            if (try sameStatePath(a, path, self.config.global.state_file)) return fail(diag, "", "socket", "socket would alias native state", error.UnsafeStateProjection);
            if (self.globals.source_dbfile) |source_path| {
                const absolute = try std.fs.path.resolve(a, &.{ prepared.root, source_path });
                if (try sameStatePath(a, path, absolute)) return fail(diag, "", "socket", "socket would alias imported state", error.UnsafeStateProjection);
            }
        }
        const purge = try globalValue(a, prepared, "dbpurgeage");
        const maximum = try globalValue(a, prepared, "dbmaxmatches");
        if (purge != null or maximum != null) {
            const proof = binding orelse return fail(diag, "", "retention", "resource consumer binding required", error.RequiredEffectiveState);
            if (zero(proof.retention_generation)) return fail(diag, "", "retention", "resource consumer has not admitted retention settings", error.RequiredEffectiveState);
            const max_matches = if (maximum) |raw| std.fmt.parseInt(u32, raw, 10) catch return error.InvalidEffectiveValue else null;
            if (max_matches) |number| if (number > 1024) return error.InvalidEffectiveValue;
            self.globals.retention = .{ .purge_age_seconds = if (purge) |raw| try seconds(raw) else null, .max_matches = max_matches, .consumer_generation = proof.retention_generation };
        }
    }
};
fn validAbsolute(path: []const u8) bool {
    return path.len > 0 and path.len <= 4096 and std.fs.path.isAbsolute(path) and std.mem.indexOfScalar(u8, path, 0) == null;
}
fn globalValue(a: std.mem.Allocator, prepared: *const Prepared, key: []const u8) !?[]const u8 {
    const section: []const u8 = if (prepared.globals.source.section("Definition") != null) "Definition" else "DEFAULT";
    return ini.resolve(a, &prepared.globals.source, section, key);
}
fn canonicalStatePath(a: std.mem.Allocator, path: []const u8) ![]const u8 {
    if (!validAbsolute(path)) return error.InvalidEffectiveValue;
    return std.fs.realpathAlloc(a, path) catch |err| switch (err) {
        error.FileNotFound => blk: {
            const parent = std.fs.path.dirname(path) orelse return error.InvalidEffectiveValue;
            const canonical = try std.fs.realpathAlloc(a, parent);
            break :blk try std.fs.path.join(a, &.{ canonical, std.fs.path.basename(path) });
        },
        else => return err,
    };
}
fn sameStatePath(a: std.mem.Allocator, left: []const u8, right: []const u8) !bool {
    const first = try canonicalStatePath(a, left);
    const second = try canonicalStatePath(a, right);
    if (std.mem.eql(u8, first, second)) return true;
    const one = std.posix.fstatat(std.posix.AT.FDCWD, first, 0) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    const two = std.posix.fstatat(std.posix.AT.FDCWD, second, 0) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return one.dev == two.dev and one.ino == two.ino;
}
fn zero(generation: [32]u8) bool {
    return std.mem.allEqual(u8, &generation, 0);
}
const HashWriter = std.io.Writer(*std.crypto.hash.sha2.Sha256, error{NoSpaceLeft}, hashWrite);
fn hashWrite(hash: *std.crypto.hash.sha2.Sha256, bytes: []const u8) error{NoSpaceLeft}!usize {
    hash.update(bytes);
    return bytes.len;
}
fn fail(diag: *Diagnostic, jail: []const u8, key: []const u8, detail: []const u8, err: anyerror) anyerror {
    diag.* = .{};
    const jail_len = @min(jail.len, diag.jail_bytes.len);
    const key_len = @min(key.len, diag.key_bytes.len);
    const detail_len = @min(detail.len, diag.detail_bytes.len);
    @memcpy(diag.jail_bytes[0..jail_len], jail[0..jail_len]);
    @memcpy(diag.key_bytes[0..key_len], key[0..key_len]);
    @memcpy(diag.detail_bytes[0..detail_len], detail[0..detail_len]);
    diag.jail = diag.jail_bytes[0..jail_len];
    diag.key = diag.key_bytes[0..key_len];
    diag.detail = diag.detail_bytes[0..detail_len];
    diag.truncated = jail.len > jail_len or key.len > key_len or detail.len > detail_len;
    return err;
}
fn optionValue(jail: Jail, key: []const u8) ?[]const u8 {
    for (jail.options) |option| if (std.mem.eql(u8, option.name, key)) return option.value;
    return null;
}
fn checkGlobals(prepared: *const Prepared, diag: *Diagnostic) !void {
    var sections = prepared.globals.source.sections.iterator();
    while (sections.next()) |section| {
        if (std.mem.eql(u8, section.key_ptr.*, "INCLUDES")) continue;
        if (!std.mem.eql(u8, section.key_ptr.*, "DEFAULT") and !std.mem.eql(u8, section.key_ptr.*, "Definition")) return fail(diag, "", section.key_ptr.*, "unsupported global section", error.UnsupportedEffectiveGlobal);
        for (section.value_ptr.keys.keys()) |key| {
            // Other global runtime settings need their own exact native mapping;
            // an imported source graph cannot authorize guessed logging/state IO.
            var supported = false;
            for ([_][]const u8{ "allowipv6", "loglevel", "logtarget", "socket", "dbfile", "dbpurgeage", "dbmaxmatches" }) |name| if (std.mem.eql(u8, key, name)) {
                supported = true;
                break;
            };
            if (!supported) return fail(diag, "", key, "global setting lacks a typed native projection", error.UnsupportedEffectiveGlobal);
        }
    }
}
fn checkJail(jail: Jail, binding: Binding, diag: *Diagnostic) !void {
    if (binding.source_kind != .file and binding.source_kind != .journald) return fail(diag, jail.name, "backend", "source binding is not resolved", error.RequiredEffectiveState);
    if (binding.source_kind == .journald and (binding.timestamp != .journal or zero(binding.journal_origin_generation))) return fail(diag, jail.name, "journal", "qualified journal origin and timestamp required", error.RequiredEffectiveState);
    if (binding.source_kind == .file and binding.timestamp == .journal) return error.InvalidEffectiveValue;
    if (binding.native_filter.len == 0 or binding.native_filter.len > 128) return error.InvalidEffectiveValue;
    if (jail.source.diagnostics.len != 0 or jail.source.processing.diagnostics.len != 0 or jail.source.ignore.diagnostics.len != 0) return fail(diag, jail.name, "source", "source plan contains unresolved diagnostics", error.InvalidEffectiveValue);
    const backend = jail.source.backend_name orelse return error.InvalidEffectiveValue;
    if (std.ascii.eqlIgnoreCase(backend, "systemd") and binding.source_kind != .journald) return error.InvalidEffectiveValue;
    if (std.ascii.eqlIgnoreCase(backend, "polling") and binding.source_kind != .file) return error.InvalidEffectiveValue;
    if (!std.ascii.eqlIgnoreCase(backend, "auto") and !std.ascii.eqlIgnoreCase(backend, "systemd") and !std.ascii.eqlIgnoreCase(backend, "polling")) return fail(diag, jail.name, "backend", backend, error.UnsupportedEffectiveOption);
    if (binding.family != .v4 and jail.source.allowipv6.policy == .disabled) return error.InvalidEffectiveValue;
    if (jail.source.allowipv6.policy == .invalid) return error.InvalidEffectiveValue;
    const allowed = [_][]const u8{ "enabled", "filter", "backend", "logpath", "maxretry", "findtime", "bantime", "ignoreip", "ignoreself", "usedns", "logencoding", "logtimezone", "datepattern", "maxlines", "journalmatch", "skip_if_nologs", "systemd_if_nologs", "action", "banaction", "port", "protocol", "chain", "prefregex", "failregex", "ignoreregex" };
    for (jail.options) |option| {
        if (option.error_name) |err| return fail(diag, jail.name, option.name, err, error.InvalidEffectiveValue);
        var admitted = false;
        for (allowed) |key| if (std.mem.eql(u8, key, option.name)) {
            admitted = true;
            break;
        };
        if (!admitted) return fail(diag, jail.name, option.name, option.value orelse "", error.UnsupportedEffectiveOption);
    }
    if (binding.assets.len != jail.assets.len) return fail(diag, jail.name, "asset", "every filter/action asset needs explicit qualification", error.UnqualifiedEffectiveAsset);
    for (jail.assets, binding.assets) |asset, proof| {
        if (!std.mem.eql(u8, &asset.generation, &proof.generation)) return fail(diag, jail.name, asset.selector, "asset bytes/parameters differ from qualified consumer", error.UnqualifiedEffectiveAsset);
    }
}
/// Checked integer duration grammar: additive decimal terms with s/m/h/d/w.
/// Unsupported fractions/formulas/permanent durations remain explicit refusal.
fn seconds(raw: []const u8) !u64 {
    if (raw.len == 0 or raw.len > 256) return error.InvalidEffectiveDuration;
    var at: usize = 0;
    var total: u64 = 0;
    while (at < raw.len) {
        while (at < raw.len and std.ascii.isWhitespace(raw[at])) : (at += 1) {}
        if (at == raw.len) break;
        const begin = at;
        while (at < raw.len and std.ascii.isDigit(raw[at])) : (at += 1) {}
        if (at == begin) return error.InvalidEffectiveDuration;
        const number = std.fmt.parseInt(u64, raw[begin..at], 10) catch return error.InvalidEffectiveDuration;
        var multiplier: u64 = 1;
        if (at < raw.len and !std.ascii.isWhitespace(raw[at])) {
            multiplier = switch (raw[at]) {
                's' => 1,
                'm' => 60,
                'h' => 3600,
                'd' => 86400,
                'w' => 604800,
                else => return error.InvalidEffectiveDuration,
            };
            at += 1;
        }
        total = std.math.add(u64, total, std.math.mul(u64, number, multiplier) catch return error.InvalidEffectiveDuration) catch return error.InvalidEffectiveDuration;
    }
    if (total == 0 or total > @as(u64, std.math.maxInt(i64)) / 1_000_000) return error.InvalidEffectiveDuration;
    return total;
}

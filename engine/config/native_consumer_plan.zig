// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Owned startup assets. No source polling, DNS, SQL or firewall operations.
const std = @import("std");
const native = @import("native.zig");
const rules = @import("../core/native_rules.zig");
const ignore = @import("../core/native_ignore.zig");
const bridge = @import("../core/native_consumer_coordinator.zig");
const detection = @import("../core/native_detection_record.zig");
const consumer = @import("../core/native_consumer.zig");

/// Version 2 separates asset semantics from operational configuration. Previous
/// persisted generations require explicit admission; this module never migrates.
pub const version: u16 = 2;
pub const max_rule_bytes = 4096;
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    owned_programs: [bridge.max_rules]*rules.Program = undefined,
    program_views: [bridge.max_rules]*const rules.Program = undefined,
    count: usize = 0,
    programs: []const *const rules.Program = &.{},
    jail_name: []u8,
    logical_source: []const u8 = "",
    parent_generation: [32]u8 = undefined,
    ignore_options: ignore.Options = undefined,
    initial_ignore: *ignore.Snapshot = undefined,
    settings: bridge.Settings = undefined,
    /// Requested retained allocator bytes, excluding allocator metadata.
    reserved_bytes: usize = 0,
    /// Conservative peak allocator reservation during this bounded preparation.
    preparation_bytes: usize = 0,

    pub fn create(a: std.mem.Allocator, cfg: *const native.Config, jail_index: usize, resolver_generation: [32]u8) !*Prepared {
        if (jail_index >= cfg.jails.len) return error.UnknownJail;
        const jail = &cfg.jails[jail_index];
        if (!cfg.global.native_ingestion) return error.NativeIngestionRequired;
        if (!jail.enabled) return error.DisabledJail;
        if (cfg.global.compatibility_pending or jail.compatibility_pending) return error.CompatibilityNotAdmitted;
        if (jail.rule_files.len == 0 or jail.rule_files.len > bridge.max_rules) return error.InvalidNativeRules;
        if (jail.name.len == 0 or jail.name.len > 64 or std.mem.indexOfScalar(u8, jail.name, 0) != null) return error.InvalidJail;
        const filter = try detection.Name.init(jail.filter);
        if (filter.len == 0) return error.InvalidNativeRules;
        const source = if (jail.source == .auto) cfg.defaults.source else jail.source;
        if (source != .file and source != .journald) return error.SourceSelectionRequired;
        const literals = jail.ignoreip orelse cfg.defaults.ignoreip;
        if (literals.len > ignore.max_entries) return error.IgnoreLimit;
        for (literals) |value| if (value.len == 0 or value.len > 254 or std.mem.indexOfAny(u8, value, " \t\r\n\x00") != null) return error.InvalidIgnoreEntry;
        for (jail.rule_files, 0..) |path, index| {
            try validatePath(path);
            for (jail.rule_files[0..index]) |prior| if (std.mem.eql(u8, path, prior)) return error.DuplicateRuleFile;
        }
        if (jail.ignore_file) |path| try validatePath(path);
        const self = try a.create(Prepared);
        errdefer a.destroy(self);
        self.* = .{ .allocator = a, .jail_name = try a.dupe(u8, jail.name) };
        errdefer a.free(self.jail_name);
        errdefer for (self.owned_programs[0..self.count]) |program| program.destroy();
        var hash = Hash.init();
        try hash.part("fail2zig-native-consumer-plan-v2");
        try hash.part(&resolver_generation);
        // Bind the effective asset policy, not logging/control/resource settings
        // or shadowed defaults. Source specs, codec/time, retry and origin policy
        // are bound by the final session/processor generation. Operational
        // validation remains mandatory before admission; hash equality grants
        // no permission to bypass it. No borrowed Config slices survive here.
        try std.json.stringify(.{
            .jail_name = jail.name,
            .filter = jail.filter,
            .resolved_source = source,
            .effective_ignoreip = literals,
        }, .{}, hash.writer());
        var hostname_rules: usize = 0;
        for (jail.rule_files) |path| {
            const bytes = try readProtected(a, path, max_rule_bytes, null);
            defer a.free(bytes);
            try hash.part(path);
            try hash.part(bytes);
            const program = try rules.Program.create(a, bytes, .{});
            errdefer program.destroy();
            const spec = program.metadata();
            if (self.count != 0 and !std.mem.eql(u8, spec.source, self.logical_source)) return error.ConsumerSourceMismatch;
            for (self.owned_programs[0..self.count]) |prior| if (std.mem.eql(u8, prior.metadata().id, spec.id)) return error.DuplicateRuleId;
            try hash.part(&program.generation);
            if (spec.subject_kind == .hostname) hostname_rules += 1;
            self.logical_source = if (self.count == 0) spec.source else self.logical_source;
            self.owned_programs[self.count] = program;
            self.program_views[self.count] = program;
            self.count += 1;
        }
        self.programs = self.program_views[0..self.count];
        const file_text = if (jail.ignore_file) |path| try readProtected(a, path, ignore.max_file_bytes, null) else null;
        defer if (file_text) |bytes| a.free(bytes);
        if (file_text) |bytes| {
            try hash.part(jail.ignore_file.?);
            try hash.part(bytes);
        }
        // Same line/comment boundary as Snapshot.fromText. Snapshot.create is
        // the authoritative address/network/hostname parser for the full union.
        var values: [ignore.max_entries][]const u8 = undefined;
        @memcpy(values[0..literals.len], literals);
        var value_count = literals.len;
        if (file_text) |bytes| {
            if (std.mem.indexOfScalar(u8, bytes, 0) != null) return error.IgnoreLimit;
            var lines = std.mem.splitScalar(u8, bytes, '\n');
            while (lines.next()) |line| {
                if (line.len > 1024) return error.IgnoreLimit;
                const uncommented = line[0 .. std.mem.indexOfScalar(u8, line, '#') orelse line.len];
                const value = std.mem.trim(u8, uncommented, " \r\t");
                if (value.len == 0) continue;
                if (value_count == values.len) return error.IgnoreLimit;
                values[value_count] = value;
                value_count += 1;
            }
        }
        self.parent_generation = hash.state.finalResult();
        self.ignore_options = .{ .parent_generation = self.parent_generation, .resolver_generation = resolver_generation, .family = .both };
        const snapshot = try ignore.Snapshot.create(a, self.ignore_options, values[0..value_count]);
        errdefer snapshot.destroy();
        var hostname_count = hostname_rules;
        for (snapshot.entries) |entry| if (entry == .hostname) {
            hostname_count += 1;
        };
        if (hostname_count != 0 and std.mem.allEqual(u8, &resolver_generation, 0)) return error.HostnameResolutionRequired;
        // Reserve ignore + resolver dependencies, matching the consumer bridge.
        if (hostname_count > consumer.max_dependencies - 2) return error.ConsumerCapacity;
        self.initial_ignore = snapshot;
        self.settings = .{ .jail = self.jail_name, .logical_source = self.logical_source, .filter = filter, .parent_generation = self.parent_generation, .ignore_generation = snapshot.generation, .family = .both, .journal = source == .journald };
        self.reserved_bytes = @sizeOf(Prepared) + self.jail_name.len + self.count * @sizeOf(rules.Program) + @sizeOf(ignore.Snapshot) + snapshot.entries.len * @sizeOf(ignore.Entry) + snapshot.payload.len;
        self.preparation_bytes = try reservationBytes(self.count);
        return self;
    }

    pub fn destroy(self: *Prepared) void {
        const a = self.allocator;
        self.initial_ignore.destroy();
        for (self.owned_programs[0..self.count]) |program| program.destroy();
        a.free(self.jail_name);
        a.destroy(self);
    }
};

/// Includes maximum retained snapshot and bounded ArrayList growth/copy during
/// serialization, plus one protected file buffer. Stack and allocator overhead
/// are separate coordinator reservations; file descriptors peak at one.
pub fn reservationBytes(rule_count: usize) !usize {
    if (rule_count == 0 or rule_count > bridge.max_rules) return error.InvalidNativeRules;
    return @sizeOf(Prepared) + 64 + rule_count * @sizeOf(rules.Program) + @sizeOf(ignore.Snapshot) + ignore.max_entries * @sizeOf(ignore.Entry) + 4 * ignore.max_checkpoint_bytes + ignore.max_file_bytes;
}

fn validatePath(path: []const u8) !void {
    if (path.len == 0 or path.len >= std.fs.max_path_bytes or !std.fs.path.isAbsolute(path) or std.mem.indexOfScalar(u8, path, 0) != null) return error.InvalidConsumerPath;
}
const ReadHook = struct { context: ?*anyopaque, call: *const fn (?*anyopaque) anyerror!void };
fn readProtected(a: std.mem.Allocator, path: []const u8, cap: usize, hook: ?ReadHook) ![]u8 {
    try validatePath(path);
    const fd = try std.posix.open(path, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true, .NOFOLLOW = true }, 0);
    const file = std.fs.File{ .handle = fd };
    defer file.close();
    const before = try std.posix.fstat(fd);
    if (!std.posix.S.ISREG(before.mode) or before.mode & 0o022 != 0 or (before.uid != 0 and before.uid != std.os.linux.geteuid())) return error.UntrustedConsumerFile;
    if (before.size < 0 or before.size > cap) return error.ConsumerFileLimit;
    const bytes = try a.alloc(u8, @intCast(before.size));
    errdefer a.free(bytes);
    if (try file.readAll(bytes) != bytes.len) return error.ConsumerFileChanged;
    var extra: [1]u8 = undefined;
    if (try file.read(&extra) != 0) return error.ConsumerFileChanged;
    if (hook) |observer| try observer.call(observer.context);
    const after = try std.posix.fstat(fd);
    if (before.dev != after.dev or before.ino != after.ino or before.mode != after.mode or before.uid != after.uid or before.gid != after.gid or before.size != after.size or !std.meta.eql(before.mtim, after.mtim) or !std.meta.eql(before.ctim, after.ctim)) return error.ConsumerFileChanged;
    return bytes;
}
const Hash = struct {
    state: std.crypto.hash.sha2.Sha256,
    remaining: usize = native.max_config_bytes + 8 * max_rule_bytes + ignore.max_file_bytes + 64 * 1024,
    fn init() Hash {
        return .{ .state = std.crypto.hash.sha2.Sha256.init(.{}) };
    }
    fn write(self: *Hash, bytes: []const u8) error{ConsumerConfigLimit}!usize {
        if (bytes.len > self.remaining) return error.ConsumerConfigLimit;
        self.remaining -= bytes.len;
        self.state.update(bytes);
        return bytes.len;
    }
    fn writer(self: *Hash) std.io.Writer(*Hash, error{ConsumerConfigLimit}, write) {
        return .{ .context = self };
    }
    fn part(self: *Hash, bytes: []const u8) !void {
        var size: [8]u8 = undefined;
        std.mem.writeInt(u64, &size, bytes.len, .little);
        _ = try self.write(&size);
        _ = try self.write(bytes);
    }
};

test "native consumer plan: actual protected file changes invalidate its complete read" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "asset", .data = "original", .flags = .{ .mode = 0o600 } });
    const path = try tmp.dir.realpathAlloc(std.testing.allocator, "asset");
    defer std.testing.allocator.free(path);
    const Change = struct {
        fn mutate(context: ?*anyopaque) !void {
            const dir: *std.fs.Dir = @ptrCast(@alignCast(context.?));
            try dir.writeFile(.{ .sub_path = "asset", .data = "changed and longer" });
        }
    };
    try std.testing.expectError(error.ConsumerFileChanged, readProtected(std.testing.allocator, path, 4096, .{ .context = &tmp.dir, .call = Change.mutate }));
}

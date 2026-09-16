// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const t = std.testing;
const plan = @import("config/native_consumer_plan.zig");
const native = @import("config/native.zig");
const rules = @import("core/native_rules.zig");
const ignore = @import("core/native_ignore.zig");
const resolver = [_]u8{7} ** 32;
extern "c" fn mkfifo(path: [*:0]const u8, mode: c_uint) c_int;

fn fdCount() !usize {
    var dir = try std.fs.openDirAbsolute("/proc/self/fd", .{ .iterate = true });
    defer dir.close();
    var iterator = dir.iterate();
    var count: usize = 0;
    while (try iterator.next() != null) count += 1;
    return count;
}

const Fixture = struct {
    tmp: t.TmpDir,
    root: []u8,
    paths: [8][]u8 = undefined,
    count: usize = 0,
    jails: [1]native.JailConfig = .{.{ .name = "fixture", .filter = "custom", .source = .file, .timestamp = .undated }},
    fn init() !Fixture {
        var tmp = t.tmpDir(.{});
        errdefer tmp.cleanup();
        return .{ .tmp = tmp, .root = try tmp.dir.realpathAlloc(t.allocator, ".") };
    }
    fn deinit(self: *Fixture) void {
        for (self.paths[0..self.count]) |path| t.allocator.free(path);
        t.allocator.free(self.root);
        self.tmp.cleanup();
    }
    fn add(self: *Fixture, id: []const u8, source: []const u8, hostname: bool) !void {
        var name: [32]u8 = undefined;
        const filename = try std.fmt.bufPrint(&name, "rule-{d}.json", .{self.count});
        const bytes = try std.json.stringifyAlloc(t.allocator, rules.Spec{ .id = id, .source = source, .format = .json, .subject = "peer", .subject_kind = if (hostname) .hostname else .ip, .conditions = &.{.{ .field = "result", .text = "denied" }} }, .{});
        defer t.allocator.free(bytes);
        try self.tmp.dir.writeFile(.{ .sub_path = filename, .data = bytes, .flags = .{ .mode = 0o600 } });
        self.paths[self.count] = try std.fs.path.join(t.allocator, &.{ self.root, filename });
        self.count += 1;
    }
    fn config(self: *Fixture) native.Config {
        self.jails[0].rule_files = self.paths[0..self.count];
        return .{ .global = .{ .native_ingestion = true }, .jails = &self.jails };
    }
};

test "native consumer plan: owned rule and ignore union survives configuration and file changes" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.add("login", "application", false);
    try f.tmp.dir.writeFile(.{ .sub_path = "ignore", .data = "# original exclusions\n2001:db8::/32 # network\ntrusted.example\n", .flags = .{ .mode = 0o600 } });
    const path = try std.fs.path.join(t.allocator, &.{ f.root, "ignore" });
    defer t.allocator.free(path);
    f.jails[0].ignore_file = path;
    f.jails[0].ignoreip = &.{"192.0.2.0/24"};
    var cfg = f.config();
    cfg.defaults.ignoreip = &.{"198.51.100.0/24"};
    const prepared = try plan.Prepared.create(t.allocator, &cfg, 0, resolver);
    defer prepared.destroy();
    try t.expectEqual(@as(usize, 3), prepared.initial_ignore.entries.len);
    try t.expectEqualStrings("application", prepared.logical_source);
    try t.expectEqualStrings("fixture", prepared.settings.jail);
    try t.expect(prepared.reserved_bytes <= prepared.preparation_bytes);
    try t.expectEqual(prepared.preparation_bytes, try plan.reservationBytes(1));
    try t.expectEqual(.ignored, (try prepared.initial_ignore.check(try rules.Ip.parse("192.0.2.19"), null, 0)).kind);
    try t.expectEqual(.ignored, (try prepared.initial_ignore.check(try rules.Ip.parse("2001:db8::19"), null, 0)).kind);
    try t.expectEqual(.pending, (try prepared.initial_ignore.check(try rules.Ip.parse("198.51.100.19"), null, 0)).kind);
    try f.tmp.dir.writeFile(.{ .sub_path = "rule-0.json", .data = "broken" });
    try f.tmp.dir.writeFile(.{ .sub_path = "ignore", .data = "broken input\n" });
    f.jails[0].name = "changed";
    var scratch: rules.Scratch = .{};
    const outcome = try prepared.programs[0].evaluate(.{ .source = "application", .record = "{\"peer\":\"203.0.113.7\",\"result\":\"denied\"}" }, &scratch);
    try t.expectEqual(.candidate, outcome.kind);
    try t.expectEqualStrings("fixture", prepared.settings.jail);
    try t.expectEqual(@as(usize, 3), prepared.initial_ignore.entries.len);
}

test "native consumer plan: defaults apply only without a jail override including explicit empty" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.add("login", "application", false);
    var cfg = f.config();
    cfg.defaults.ignoreip = &.{"192.0.2.0/24"};
    const inherited = try plan.Prepared.create(t.allocator, &cfg, 0, resolver);
    defer inherited.destroy();
    try t.expectEqual(@as(usize, 1), inherited.initial_ignore.entries.len);
    f.jails[0].ignoreip = &.{};
    const empty = try plan.Prepared.create(t.allocator, &cfg, 0, resolver);
    defer empty.destroy();
    try t.expectEqual(@as(usize, 0), empty.initial_ignore.entries.len);
    try t.expect(!std.mem.eql(u8, &inherited.parent_generation, &empty.parent_generation));
}

test "native consumer plan: ordered raw assets and resolver policy bind deterministic generations" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.add("login", "application", false);
    try f.add("other", "application", false);
    var cfg = f.config();
    const first = try plan.Prepared.create(t.allocator, &cfg, 0, resolver);
    defer first.destroy();
    const repeat = try plan.Prepared.create(t.allocator, &cfg, 0, resolver);
    defer repeat.destroy();
    try t.expectEqualSlices(u8, &first.parent_generation, &repeat.parent_generation);
    var changed_resolver = resolver;
    changed_resolver[0] ^= 1;
    const dns = try plan.Prepared.create(t.allocator, &cfg, 0, changed_resolver);
    defer dns.destroy();
    try t.expect(!std.mem.eql(u8, &first.parent_generation, &dns.parent_generation));
    const file = try f.tmp.dir.openFile("rule-0.json", .{ .mode = .write_only });
    defer file.close();
    try file.seekFromEnd(0);
    try file.writeAll(" \n");
    const bytes = try plan.Prepared.create(t.allocator, &cfg, 0, resolver);
    defer bytes.destroy();
    try t.expectEqualSlices(u8, &first.programs[0].generation, &bytes.programs[0].generation);
    try t.expect(!std.mem.eql(u8, &first.parent_generation, &bytes.parent_generation));
    const swap = f.paths[0];
    f.paths[0] = f.paths[1];
    f.paths[1] = swap;
    const reordered = try plan.Prepared.create(t.allocator, &cfg, 0, resolver);
    defer reordered.destroy();
    try t.expect(!std.mem.eql(u8, &bytes.parent_generation, &reordered.parent_generation));
}

test "native consumer plan: operational changes preserve rule and immutable ignore identities" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.add("login", "application", false);
    f.jails[0].ignoreip = &.{"192.0.2.0/24"};
    var cfg = f.config();
    const original = try plan.Prepared.create(t.allocator, &cfg, 0, resolver);
    defer original.destroy();
    const baseline = cfg.global;
    const changes = .{
        .{ "log_level", native.LogLevel.debug },
        .{ "native_memory_ceiling_mb", @as(u32, 512) },
        .{ "native_fd_ceiling", @as(u32, 4096) },
        .{ "memory_ceiling_mb", @as(u32, 128) },
        .{ "metrics_enabled", false },
        .{ "metrics_bind", @as([]const u8, "127.0.0.2") },
        .{ "metrics_port", @as(u16, 9200) },
        .{ "websocket_max_clients", @as(u32, 32) },
        .{ "socket_path", @as([]const u8, "/run/fail2zig/other.sock") },
        .{ "pid_file", @as([]const u8, "/run/fail2zig/other.pid") },
        .{ "compatibility_manifest", @as([]const u8, "/var/lib/fail2zig/inspection.json") },
    };
    inline for (changes) |change| {
        cfg.global = baseline;
        @field(cfg.global, change[0]) = change[1];
        const operational = try plan.Prepared.create(t.allocator, &cfg, 0, resolver);
        defer operational.destroy();
        try t.expectEqualSlices(u8, &original.parent_generation, &operational.parent_generation);
        try t.expectEqualSlices(u8, &original.programs[0].generation, &operational.programs[0].generation);
        try t.expectEqualSlices(u8, &original.initial_ignore.generation, &operational.initial_ignore.generation);
        try t.expectEqualSlices(u8, original.initial_ignore.payload, operational.initial_ignore.payload);
    }
    cfg.global = baseline;
    cfg.global.compatibility_pending = true;
    try t.expectError(error.CompatibilityNotAdmitted, plan.Prepared.create(t.allocator, &cfg, 0, resolver));
    cfg.global = baseline;
    cfg.global.native_ingestion = false;
    try t.expectError(error.NativeIngestionRequired, plan.Prepared.create(t.allocator, &cfg, 0, resolver));
}

test "native consumer plan: effective inheritance is stable while changed exclusions remain distinct" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.add("login", "application", false);
    f.jails[0].source = .auto;
    var cfg = f.config();
    cfg.defaults.source = .file;
    cfg.defaults.ignoreip = &.{"192.0.2.0/24"};
    const inherited = try plan.Prepared.create(t.allocator, &cfg, 0, resolver);
    defer inherited.destroy();
    f.jails[0].source = .file;
    f.jails[0].ignoreip = &.{"192.0.2.0/24"};
    f.jails[0].maxretry = 5;
    f.jails[0].findtime = 600;
    f.jails[0].bantime = 600;
    cfg.defaults.source = .journald;
    cfg.defaults.ignoreip = &.{"198.51.100.0/24"};
    cfg.defaults.maxretry = 9;
    cfg.defaults.findtime = 300;
    cfg.defaults.bantime = 900;
    const overridden = try plan.Prepared.create(t.allocator, &cfg, 0, resolver);
    defer overridden.destroy();
    try t.expectEqualSlices(u8, &inherited.parent_generation, &overridden.parent_generation);
    try t.expectEqualSlices(u8, &inherited.initial_ignore.generation, &overridden.initial_ignore.generation);
    f.jails[0].ignoreip = &.{"198.51.100.0/24"};
    const changed = try plan.Prepared.create(t.allocator, &cfg, 0, resolver);
    defer changed.destroy();
    try t.expect(!std.mem.eql(u8, &overridden.parent_generation, &changed.parent_generation));
    const peer = try rules.Ip.parse("192.0.2.9");
    try t.expectEqual(.ignored, (try overridden.initial_ignore.check(peer, null, 0)).kind);
    try t.expectEqual(.not_ignored, (try changed.initial_ignore.check(peer, null, 0)).kind);
}

test "native consumer plan: source owner filter and changed rule predicate bind different identities" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.add("login", "application", false);
    var cfg = f.config();
    const original = try plan.Prepared.create(t.allocator, &cfg, 0, resolver);
    defer original.destroy();
    const baseline = f.jails[0];
    const changes = .{
        .{ "source", native.LogSource.journald },
        .{ "name", @as([]const u8, "other-owner") },
        .{ "filter", @as([]const u8, "other-filter") },
    };
    inline for (changes) |change| {
        f.jails[0] = baseline;
        @field(f.jails[0], change[0]) = change[1];
        const changed = try plan.Prepared.create(t.allocator, &cfg, 0, resolver);
        defer changed.destroy();
        try t.expect(!std.mem.eql(u8, &original.parent_generation, &changed.parent_generation));
    }
    f.jails[0] = baseline;
    try f.tmp.dir.writeFile(.{ .sub_path = "rule-0.json", .data = 
        \\{"id":"login","source":"application","format":"json","subject":"peer","conditions":[{"field":"result","text":"locked"}]}
    });
    const changed = try plan.Prepared.create(t.allocator, &cfg, 0, resolver);
    defer changed.destroy();
    try t.expect(!std.mem.eql(u8, &original.parent_generation, &changed.parent_generation));
    try t.expect(!std.mem.eql(u8, &original.programs[0].generation, &changed.programs[0].generation));
    var scratch: rules.Scratch = .{};
    const input = rules.Input{ .source = "application", .record = "{\"peer\":\"203.0.113.9\",\"result\":\"denied\"}" };
    try t.expectEqual(.candidate, (try original.programs[0].evaluate(input, &scratch)).kind);
    try t.expectEqual(.no_match, (try changed.programs[0].evaluate(input, &scratch)).kind);
}

test "native consumer plan: identical protected bytes at another path retain explicit asset identity" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.add("login", "application", false);
    var cfg = f.config();
    const original = try plan.Prepared.create(t.allocator, &cfg, 0, resolver);
    defer original.destroy();
    try f.tmp.dir.rename("rule-0.json", "relocated.json");
    const relocated = try std.fs.path.join(t.allocator, &.{ f.root, "relocated.json" });
    defer t.allocator.free(relocated);
    const paths = [_][]const u8{relocated};
    f.jails[0].rule_files = &paths;
    const changed = try plan.Prepared.create(t.allocator, &cfg, 0, resolver);
    defer changed.destroy();
    try t.expectEqualSlices(u8, &original.programs[0].generation, &changed.programs[0].generation);
    try t.expect(!std.mem.eql(u8, &original.parent_generation, &changed.parent_generation));
    try t.expectEqual(@as(u16, 2), plan.version);
}

test "native consumer plan: duplicate rule identity paths and mismatched logical sources refuse" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.add("same", "application", false);
    try f.add("same", "application", false);
    var cfg = f.config();
    try t.expectError(error.DuplicateRuleId, plan.Prepared.create(t.allocator, &cfg, 0, resolver));
    const old = f.paths[1];
    f.paths[1] = f.paths[0];
    try t.expectError(error.DuplicateRuleFile, plan.Prepared.create(t.allocator, &cfg, 0, resolver));
    f.paths[1] = old;
    const bytes = try std.json.stringifyAlloc(t.allocator, rules.Spec{ .id = "different", .source = "other", .format = .json, .subject = "peer", .conditions = &.{.{ .field = "result", .text = "denied" }} }, .{});
    defer t.allocator.free(bytes);
    try f.tmp.dir.writeFile(.{ .sub_path = "rule-1.json", .data = bytes });
    try t.expectError(error.ConsumerSourceMismatch, plan.Prepared.create(t.allocator, &cfg, 0, resolver));
}

test "native consumer plan: every allocator failure cleans partially prepared owners" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.add("first", "application", false);
    try f.add("second", "application", false);
    try f.tmp.dir.writeFile(.{ .sub_path = "ignore", .data = "192.0.2.0/24\ntrusted.example\n", .flags = .{ .mode = 0o600 } });
    const path = try std.fs.path.join(t.allocator, &.{ f.root, "ignore" });
    defer t.allocator.free(path);
    f.jails[0].ignore_file = path;
    var cfg = f.config();
    const Check = struct {
        fn run(a: std.mem.Allocator, config: *const native.Config) !void {
            const prepared = try plan.Prepared.create(a, config, 0, resolver);
            defer prepared.destroy();
        }
    };
    const before = try fdCount();
    try t.checkAllAllocationFailures(t.allocator, Check.run, .{&cfg});
    try t.expectEqual(before, try fdCount());
}

test "native consumer plan: nonregular symlink and writable files refuse without blocking" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.add("login", "application", false);
    var cfg = f.config();
    var file = try f.tmp.dir.openFile("rule-0.json", .{ .mode = .read_write });
    try file.chmod(0o620);
    file.close();
    try t.expectError(error.UntrustedConsumerFile, plan.Prepared.create(t.allocator, &cfg, 0, resolver));
    try f.tmp.dir.rename("rule-0.json", "original");
    try f.tmp.dir.symLink("original", "rule-0.json", .{});
    try t.expectError(error.SymLinkLoop, plan.Prepared.create(t.allocator, &cfg, 0, resolver));
    try f.tmp.dir.deleteFile("rule-0.json");
    try f.tmp.dir.makeDir("rule-0.json");
    try t.expectError(error.UntrustedConsumerFile, plan.Prepared.create(t.allocator, &cfg, 0, resolver));
    try f.tmp.dir.deleteDir("rule-0.json");
    const terminated = try t.allocator.dupeZ(u8, f.paths[0]);
    defer t.allocator.free(terminated);
    try t.expectEqual(@as(c_int, 0), mkfifo(terminated, 0o600));
    try t.expectError(error.UntrustedConsumerFile, plan.Prepared.create(t.allocator, &cfg, 0, resolver));
}

test "native consumer plan: exact rule byte boundary unknown fields and ignore limits refuse" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.add("login", "application", false);
    var cfg = f.config();
    var bytes: [4097]u8 = @splat(' ');
    const original = try f.tmp.dir.readFileAlloc(t.allocator, "rule-0.json", 4096);
    defer t.allocator.free(original);
    @memcpy(bytes[0..original.len], original);
    try f.tmp.dir.writeFile(.{ .sub_path = "rule-0.json", .data = bytes[0..4096] });
    const exact = try plan.Prepared.create(t.allocator, &cfg, 0, resolver);
    exact.destroy();
    try f.tmp.dir.writeFile(.{ .sub_path = "rule-0.json", .data = &bytes });
    try t.expectError(error.ConsumerFileLimit, plan.Prepared.create(t.allocator, &cfg, 0, resolver));
    try f.tmp.dir.writeFile(.{ .sub_path = "rule-0.json", .data = "{\"unknown\":true}" });
    try t.expectError(error.InvalidRule, plan.Prepared.create(t.allocator, &cfg, 0, resolver));
    try f.tmp.dir.writeFile(.{ .sub_path = "rule-0.json", .data = original });
    f.jails[0].ignoreip = &.{"invalid whitespace"};
    try t.expectError(error.InvalidIgnoreEntry, plan.Prepared.create(t.allocator, &cfg, 0, resolver));
    var values: [ignore.max_entries + 1][]const u8 = @splat("192.0.2.0/24");
    f.jails[0].ignoreip = &values;
    try t.expectError(error.IgnoreLimit, plan.Prepared.create(t.allocator, &cfg, 0, resolver));
    f.jails[0].ignoreip = values[0..ignore.max_entries];
    const full = try plan.Prepared.create(t.allocator, &cfg, 0, resolver);
    defer full.destroy();
    try t.expectEqual(@as(usize, ignore.max_entries), full.initial_ignore.entries.len);
}

test "native consumer plan: hostname policy and union dependency bound are admitted before runtime" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.add("hostname", "application", true);
    var cfg = f.config();
    try t.expectError(error.HostnameResolutionRequired, plan.Prepared.create(t.allocator, &cfg, 0, [_]u8{0} ** 32));
    const names = [_][]const u8{"trusted.example"} ** 14;
    f.jails[0].ignoreip = &names;
    try t.expectError(error.ConsumerCapacity, plan.Prepared.create(t.allocator, &cfg, 0, resolver));
    f.jails[0].ignoreip = names[0..13];
    const admitted = try plan.Prepared.create(t.allocator, &cfg, 0, resolver);
    defer admitted.destroy();
    try t.expectEqual(@as(usize, 13), admitted.initial_ignore.entries.len);
}

test "native consumer plan: explicit journal settings retain external origin and clock prerequisite" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.add("journal", "application", false);
    f.jails[0].source = .journald;
    var cfg = f.config();
    const prepared = try plan.Prepared.create(t.allocator, &cfg, 0, resolver);
    defer prepared.destroy();
    try t.expect(prepared.settings.journal);
    try t.expect(prepared.settings.journal_origin == null);
    try t.expect(prepared.settings.monotonic_ms == null);
    f.jails[0].source = .auto;
    try t.expectError(error.SourceSelectionRequired, plan.Prepared.create(t.allocator, &cfg, 0, resolver));
    f.jails[0].source = .file;
    cfg.global.compatibility_pending = true;
    try t.expectError(error.CompatibilityNotAdmitted, plan.Prepared.create(t.allocator, &cfg, 0, resolver));
}

test "native consumer plan: rule cardinality admits exactly eight and rejects empty or ninth" {
    var f = try Fixture.init();
    defer f.deinit();
    var cfg = f.config();
    try t.expectError(error.InvalidNativeRules, plan.Prepared.create(t.allocator, &cfg, 0, resolver));
    for (0..8) |i| {
        var id: [16]u8 = undefined;
        try f.add(try std.fmt.bufPrint(&id, "rule-{d}", .{i}), "application", false);
    }
    cfg = f.config();
    const prepared = try plan.Prepared.create(t.allocator, &cfg, 0, resolver);
    defer prepared.destroy();
    try t.expectEqual(@as(usize, 8), prepared.programs.len);
    try t.expect(prepared.reserved_bytes <= try plan.reservationBytes(8));
    const ninth = [_][]const u8{f.paths[0]} ** 9;
    f.jails[0].rule_files = &ninth;
    try t.expectError(error.InvalidNativeRules, plan.Prepared.create(t.allocator, &cfg, 0, resolver));
}

test "native consumer plan: ignore file cap comments line bounds and last owner remain exact" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.add("login", "application", false);
    const path = try std.fs.path.join(t.allocator, &.{ f.root, "ignore" });
    defer t.allocator.free(path);
    const bytes = try t.allocator.alloc(u8, ignore.max_file_bytes + 1);
    defer t.allocator.free(bytes);
    @memset(bytes, '\n');
    const entry = "192.0.2.0/24\n";
    @memcpy(bytes[0..entry.len], entry);
    try f.tmp.dir.writeFile(.{ .sub_path = "ignore", .data = bytes[0..ignore.max_file_bytes], .flags = .{ .mode = 0o600 } });
    f.jails[0].ignore_file = path;
    var cfg = f.config();
    const old = try plan.Prepared.create(t.allocator, &cfg, 0, resolver);
    defer old.destroy();
    try t.expectEqual(@as(usize, 1), old.initial_ignore.entries.len);
    try f.tmp.dir.writeFile(.{ .sub_path = "ignore", .data = bytes });
    try t.expectError(error.ConsumerFileLimit, plan.Prepared.create(t.allocator, &cfg, 0, resolver));
    try f.tmp.dir.writeFile(.{ .sub_path = "ignore", .data = "192.0.2.0/24\x00\n" });
    try t.expectError(error.IgnoreLimit, plan.Prepared.create(t.allocator, &cfg, 0, resolver));
    @memset(bytes[0..1025], '#');
    try f.tmp.dir.writeFile(.{ .sub_path = "ignore", .data = bytes[0..1025] });
    try t.expectError(error.IgnoreLimit, plan.Prepared.create(t.allocator, &cfg, 0, resolver));
    try t.expectEqual(.ignored, (try old.initial_ignore.check(try rules.Ip.parse("192.0.2.19"), null, 0)).kind);
    try f.tmp.dir.writeFile(.{ .sub_path = "ignore", .data = "198.51.100.0/24\n" });
    const replacement = try plan.Prepared.create(t.allocator, &cfg, 0, resolver);
    defer replacement.destroy();
    try t.expect(!std.mem.eql(u8, &old.parent_generation, &replacement.parent_generation));
    try t.expectEqual(.not_ignored, (try replacement.initial_ignore.check(try rules.Ip.parse("192.0.2.19"), null, 0)).kind);
}

test "native consumer plan: ignore files have the same protected file admission as rules" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.add("login", "application", false);
    const path = try std.fs.path.join(t.allocator, &.{ f.root, "ignore" });
    defer t.allocator.free(path);
    f.jails[0].ignore_file = path;
    var cfg = f.config();
    const before = try fdCount();
    try t.expectError(error.FileNotFound, plan.Prepared.create(t.allocator, &cfg, 0, resolver));
    try f.tmp.dir.writeFile(.{ .sub_path = "ignore", .data = "192.0.2.0/24\n", .flags = .{ .mode = 0o666 } });
    var file = try f.tmp.dir.openFile("ignore", .{ .mode = .read_write });
    try file.chmod(0o666);
    file.close();
    try t.expectError(error.UntrustedConsumerFile, plan.Prepared.create(t.allocator, &cfg, 0, resolver));
    try f.tmp.dir.deleteFile("ignore");
    try f.tmp.dir.symLink("rule-0.json", "ignore", .{});
    try t.expectError(error.SymLinkLoop, plan.Prepared.create(t.allocator, &cfg, 0, resolver));
    try t.expectEqual(before, try fdCount());
}

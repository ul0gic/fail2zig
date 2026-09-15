// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Read-only inspection of a fail2ban configuration tree. Produces a manifest
//! with one disposition per protection group and asset. Never writes, never
//! executes imported expressions, never resolves names.
const std = @import("std");
const fail2ban = @import("../config/fail2ban.zig");
const filter_context = @import("../config/filter_context.zig");
const registry = @import("../filters/registry.zig");
const duration = @import("../config/duration.zig");
const IpAddress = @import("shared").IpAddress;

pub const schema_version: u32 = 1;

pub const Error = fail2ban.Error || error{
    SourceUnreadable,
    NoJailConfiguration,
    TooManyGroups,
    TooManyAssets,
    ManifestTooLarge,
};

pub const Limits = struct {
    max_groups: usize = 256,
    max_assets: usize = 1024,
    max_manifest_bytes: usize = 16 * 1024 * 1024,
};

pub const Options = struct {
    source_dir: []const u8,
    reference_profile: []const u8 = "fail2ban-1.1.1",
    /// Supplied by the CLI from build options; the library has no version module.
    tool_version: []const u8 = "unknown",
    limits: Limits = .{},
};

pub const DispositionKind = enum { supported, operator_change, blocker, not_enabled };

pub const Disposition = struct {
    kind: DispositionKind,
    reasons: []const []const u8 = &.{},
};

pub const SourceFile = struct {
    path: []const u8,
    sha256: [32]u8,
    edge: fail2ban.SourceEdge,
};

pub const Mapping = struct {
    service: []const u8,
    builtin_filter: ?[]const u8,
    scope: []const u8,
    duration: []const u8,
};

pub const Group = struct {
    name: []const u8,
    enabled: bool,
    filter: []const u8,
    backend: []const u8,
    logpaths: []const []const u8,
    journalmatch: ?[]const u8,
    ports: ?[]const u8,
    protocol: ?[]const u8,
    chain: ?[]const u8,
    bantime: ?[]const u8,
    findtime: ?[]const u8,
    maxretry: ?[]const u8,
    ignoreip: []const []const u8,
    disposition: Disposition,
    mapping: Mapping,
};

pub const AssetKind = enum { filter, action };
pub const StockState = enum { modified, stock, unknown };

pub const Asset = struct {
    name: []const u8,
    kind: AssetKind,
    sha256: [32]u8,
    modified_vs_stock: StockState,
    disposition: Disposition,
};

pub const UnknownValue = struct {
    section: []const u8,
    key: []const u8,
    provenance: []const u8,
};

pub const ExitClass = enum { success, rejected, usage };

pub const Manifest = struct {
    arena: std.heap.ArenaAllocator,
    tool_version: []const u8,
    reference_profile: []const u8,
    source_dir: []const u8,
    files: []const SourceFile,
    groups: []const Group,
    assets: []const Asset,
    unknown_values: []const UnknownValue,

    pub fn deinit(self: *Manifest) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

/// Keys with a known reference meaning. Anything else is retained as data.
const known_keys = [_][]const u8{
    "enabled",           "filter",               "logpath",             "backend",             "journalmatch",
    "port",              "protocol",             "chain",               "bantime",             "findtime",
    "maxretry",          "ignoreip",             "ignoreself",          "ignorecommand",       "action",
    "banaction",         "banaction_allports",   "action_",             "action_mw",           "action_mwl",
    "action_xarf",       "action_cf_mwl",        "action_blocklist_de", "action_abuseipdb",    "mta",
    "destemail",         "sender",               "sendername",          "usedns",              "logencoding",
    "logtimezone",       "datepattern",          "prefregex",           "failregex",           "ignoreregex",
    "bantime.increment", "bantime.factor",       "bantime.formula",     "bantime.multipliers", "bantime.maxtime",
    "bantime.rndtime",   "bantime.overalljails", "fail2ban_agent",      "mode",                "maxlines",
    "maxmatches",        "skip_if_nologs",       "dbpurgeage",          "dbfile",              "loglevel",
    "logtarget",         "socket",               "pidfile",             "dbmaxmatches",        "allowipv6",
};

/// Keys whose value the disposition actually consumes. Interpolation failures elsewhere in
/// DEFAULT (mail/notification templates that reference unset options) are how the stock
/// jail.conf ships; the reference ConfigReader only interpolates a value when it is read.
const consumed_keys = [_][]const u8{
    "enabled",              "filter",          "backend",             "logpath",         "journalmatch",
    "port",                 "protocol",        "chain",               "bantime",         "findtime",
    "maxretry",             "ignoreip",        "ignorecommand",       "usedns",          "action",
    "banaction",            "failregex",       "ignoreregex",         "prefregex",       "bantime.increment",
    "bantime.factor",       "bantime.formula", "bantime.multipliers", "bantime.maxtime", "bantime.rndtime",
    "bantime.overalljails",
};

/// Stock default of `usedns` in the reference jail.conf; stricter settings need no change.
const stock_usedns = "warn";
/// Reference placeholder meaning "the action's own default chain".
const known_chain_tag = "<known/chain>";

const StockAsset = struct { kind: AssetKind, file: []const u8, version: []const u8, sha256: *const [64]u8 };

/// SHA-256 of every stock filter.d/action.d file (including their include closure) that the
/// builtin registry and supported backends correspond to, taken from the pinned upstream
/// fail2ban 1.1.1 and 1.1.0 trees. A file whose bytes match is stock; a known name with other
/// bytes is modified; a name outside the table cannot be verified.
const stock_assets = [_]StockAsset{
    .{ .kind = .filter, .file = "apache-auth.conf", .version = "1.1.1/1.1.0", .sha256 = "dd83cc792f517486b0d06033c1ac1897673f0eec7c66d82f5545908fad91df0c" },
    .{ .kind = .filter, .file = "apache-badbots.conf", .version = "1.1.1", .sha256 = "48bf26a914ddaecd7cda13e480addca1165c0589baf222ad1e97fd4a01e093db" },
    .{ .kind = .filter, .file = "apache-overflows.conf", .version = "1.1.1", .sha256 = "d55dcde8260c6ef01c5029daa3b379937957effb8a17c09a67202a72b3d478d0" },
    .{ .kind = .filter, .file = "apache-common.conf", .version = "1.1.1/1.1.0", .sha256 = "ab19e7cc129bd6ce7e0543e7e7f7486e782cbd4cc25295982c2980ca1a5d5549" },
    .{ .kind = .filter, .file = "botsearch-common.conf", .version = "1.1.1/1.1.0", .sha256 = "7bcd2e9bacd42c42a38e3597b86c642f002938dc02026e20600227350a16301e" },
    .{ .kind = .filter, .file = "common.conf", .version = "1.1.1/1.1.0", .sha256 = "ebf00cecd2c4227189ca8e8d55049fe21cf2379e7d388cb160bc6c4caa63e4fa" },
    .{ .kind = .filter, .file = "courier-auth.conf", .version = "1.1.1/1.1.0", .sha256 = "44627f46ce0eb2048ef6d80c5558c2856e0cd5d94b895d99f68c4dadb5856d51" },
    .{ .kind = .filter, .file = "courier-smtp.conf", .version = "1.1.1/1.1.0", .sha256 = "c92091b56bbc4f11b185e6e2178345b92cbb779fe20067a4bf9863ca0e3c9c20" },
    .{ .kind = .filter, .file = "dovecot.conf", .version = "1.1.1", .sha256 = "cadbb84cc87505c7b14b2a887da2a1b5954e1ce45c8a8d5fc02225fbbdeb8e55" },
    .{ .kind = .filter, .file = "mysqld-auth.conf", .version = "1.1.1", .sha256 = "dd8007dd1e6e78fdcdb7f94c3970b20e34b89e62c81e2074dd1bc9546940ca05" },
    .{ .kind = .filter, .file = "named-refused.conf", .version = "1.1.1/1.1.0", .sha256 = "16203f2687a657ef485904e8d0720da2df0b7f5cadc1ca081894b482744956ab" },
    .{ .kind = .filter, .file = "nginx-botsearch.conf", .version = "1.1.1/1.1.0", .sha256 = "b56be847e47c527ea077f3a462f31f1a2346464736f6f7ff4947c9356bbe23a7" },
    .{ .kind = .filter, .file = "nginx-error-common.conf", .version = "1.1.1/1.1.0", .sha256 = "7683e18d7b7efc84f8baa8fb84d199a917bb12aada0b1651cf56311719de62d3" },
    .{ .kind = .filter, .file = "nginx-http-auth.conf", .version = "1.1.1", .sha256 = "5edb47d93de013816efe898275b952838eb49d3ac4ce73b4ae361899740d52a6" },
    .{ .kind = .filter, .file = "nginx-limit-req.conf", .version = "1.1.1", .sha256 = "23c0da545364d5fad001cbdfba80fc03e855597b0a3af03e27df0769cc0ba516" },
    .{ .kind = .filter, .file = "postfix.conf", .version = "1.1.1", .sha256 = "7f26309cd44217c4ab67d3735b198330bcdbbf94a064041cffaad8813542c1b3" },
    .{ .kind = .filter, .file = "proftpd.conf", .version = "1.1.1/1.1.0", .sha256 = "84ea809bef4fcbf62e721cbd1ed489eea67017d135995241f759eb39734a1967" },
    .{ .kind = .filter, .file = "recidive.conf", .version = "1.1.1", .sha256 = "88a6eef524219291408e91986741cb81c5516db6e066f8af1bc5015dac87502a" },
    .{ .kind = .filter, .file = "sshd.conf", .version = "1.1.1", .sha256 = "d88b5e62a8afe537eab00cfc55c42db0140529c1d655ba2843f4c5603225a3ec" },
    .{ .kind = .filter, .file = "vsftpd.conf", .version = "1.1.1", .sha256 = "40891acc2a1f177ff5aa465140c3ca667c158a310204633230161340bcebe639" },
    .{ .kind = .action, .file = "nftables.conf", .version = "1.1.1", .sha256 = "6487b2e9cdcd98515d4fecf7cc2f5e40da7c3409c36b6c675f94f76c2c6c3472" },
    .{ .kind = .action, .file = "nftables-allports.conf", .version = "1.1.1/1.1.0", .sha256 = "68558b09a2c7a9d013d770ae0d09e9323c08c3fcf260718f49611ec357662ee7" },
    .{ .kind = .action, .file = "nftables-multiport.conf", .version = "1.1.1/1.1.0", .sha256 = "9c552cb2fb83e42081486f898a5a3104736547c1c8432ad32cd754c6612b4c64" },
    .{ .kind = .action, .file = "iptables.conf", .version = "1.1.1", .sha256 = "92a1c6100a40534c4bf763cb3d34b1881e494b574ecd4bd25a91672bbbe8e59d" },
    .{ .kind = .action, .file = "iptables-allports.conf", .version = "1.1.1/1.1.0", .sha256 = "360a3b3203cdfc728631a8db56952512ee84f8e0926eaedc2a85cf67c8dd8029" },
    .{ .kind = .action, .file = "iptables-multiport.conf", .version = "1.1.1/1.1.0", .sha256 = "e9a26be50381bdf5805420b2e32456db5347f6f8a6a27835071d5a1159e136d9" },
    .{ .kind = .action, .file = "iptables-multiport-log.conf", .version = "1.1.1/1.1.0", .sha256 = "2b36074142838e6c0ff3f28c00565748c6405da597340bf4b3da0f1363275c69" },
    .{ .kind = .action, .file = "iptables-new.conf", .version = "1.1.1/1.1.0", .sha256 = "d37c74fa8c0a897f6e17eb01aab926b4bd1545ec16edccf554b1569beac85bcd" },
    .{ .kind = .action, .file = "iptables-ipset.conf", .version = "1.1.1", .sha256 = "266228c915ef382c69501a0c779d30e5e111fb6129f307e863083548e07fbcd9" },
    .{ .kind = .action, .file = "iptables-ipset-proto4.conf", .version = "1.1.1/1.1.0", .sha256 = "2d6e50bba9ad4926a00c263d83404239cb413009db2fc414bd3b595570a41bb8" },
    .{ .kind = .action, .file = "iptables-ipset-proto6.conf", .version = "1.1.1/1.1.0", .sha256 = "ff552c20887c7b5a11478e84e62f312c2e6dfaa2a41dfbb156c753dc0bc0e717" },
    .{ .kind = .action, .file = "iptables-ipset-proto6-allports.conf", .version = "1.1.1/1.1.0", .sha256 = "4cc9fd133205b5b75468a994381c12a34f58db479ece82d3da6c8df0a702a89a" },
    .{ .kind = .action, .file = "iptables-xt_recent-echo.conf", .version = "1.1.1", .sha256 = "fead7880e884e75dba55ead36555733de4d996b9832ac0be6c7d64b5e2bf7cd5" },
    .{ .kind = .filter, .file = "apache-badbots.conf", .version = "1.1.0", .sha256 = "9d9548dc5e7e81283ba4de38ff19770f66cd7051143980f0e40139fcf7b63ad6" },
    .{ .kind = .filter, .file = "apache-overflows.conf", .version = "1.1.0", .sha256 = "10570f82138142d50e6f0f732a2889090d00d83b5a108da4b5b959813cea0f9d" },
    .{ .kind = .filter, .file = "dovecot.conf", .version = "1.1.0", .sha256 = "3f8e1df8bd41e7acbc34bab411edbc4825c84d0bea38bfd51b2d74108e330a62" },
    .{ .kind = .filter, .file = "mysqld-auth.conf", .version = "1.1.0", .sha256 = "1b9fda30fdec6daa514379ccfe0752a1a8146cf8d750e823643d4e02fbff4a93" },
    .{ .kind = .filter, .file = "nginx-http-auth.conf", .version = "1.1.0", .sha256 = "554e03807bbcee6c92e593453cfa8798f7f9e98f81ed4f76072ec38ed4992c2b" },
    .{ .kind = .filter, .file = "nginx-limit-req.conf", .version = "1.1.0", .sha256 = "487db46de7c2abbaf08ce2ce6ba8f83e79862b3c706b3d10071a28a2d877b9d4" },
    .{ .kind = .filter, .file = "postfix.conf", .version = "1.1.0", .sha256 = "dab17ccf6cb00b11a34ebdafbb8fa616fb37d64ff996f8fa416cab654888b35c" },
    .{ .kind = .filter, .file = "recidive.conf", .version = "1.1.0", .sha256 = "71439d9b89790e5206562d814a83c3dd306d0a9d5741d8c8bfa71f9dc6f4c5ee" },
    .{ .kind = .filter, .file = "sshd.conf", .version = "1.1.0", .sha256 = "eb3baebca03400e4d66a8132fedebd17fdfd42319abe046c818e445ad23fcb2e" },
    .{ .kind = .filter, .file = "vsftpd.conf", .version = "1.1.0", .sha256 = "08f8cc1163825aac8d3b30a2432c6b92a74e504685914189a5ef274a84514d64" },
    .{ .kind = .action, .file = "nftables.conf", .version = "1.1.0", .sha256 = "9f22efdb0c6835202781559d261e87375d8a56e400847bf8664fd23c91b1d51a" },
    .{ .kind = .action, .file = "iptables.conf", .version = "1.1.0", .sha256 = "c939094ee6a85e9738e98144f51a30b54cddeea8c1fdf3a5e6daeb15a9adad69" },
    .{ .kind = .action, .file = "iptables-ipset.conf", .version = "1.1.0", .sha256 = "a8e64588e24153f71148a6cbb77222b7733369f86970cab1eeddfd30619d5492" },
    .{ .kind = .action, .file = "iptables-xt_recent-echo.conf", .version = "1.1.0", .sha256 = "325696fb996771790782133c4fd725f4a6d5f2676da6549ce327fab8151511a4" },
};

const StockMatch = enum { stock, modified, unknown };

fn stockMatch(kind: AssetKind, path: []const u8, sha256: [32]u8) StockMatch {
    const base = std.fs.path.basename(path);
    const hex = std.fmt.bytesToHex(sha256, .lower);
    var known = false;
    for (stock_assets) |entry| {
        if (entry.kind != kind or !std.mem.eql(u8, entry.file, base)) continue;
        known = true;
        if (std.mem.eql(u8, entry.sha256, &hex)) return .stock;
    }
    return if (known) .modified else .unknown;
}

pub fn inspect(allocator: std.mem.Allocator, options: Options) Error!Manifest {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    errdefer arena_state.deinit();
    const a = arena_state.allocator();

    var root = std.fs.cwd().openDir(options.source_dir, .{}) catch return error.SourceUnreadable;
    root.close();

    const ini = try fail2ban.loadJailConfig(a, options.source_dir);
    if (ini.sources.items.len == 0) return error.NoJailConfiguration;

    var builder = Builder{ .a = a, .ini = &ini, .options = options };
    const files = try builder.collectFiles(&ini);
    try builder.collectGroups();

    std.mem.sort(Asset, builder.assets.items, {}, assetLessThan);
    std.mem.sort(Group, builder.groups.items, {}, groupLessThan);
    std.mem.sort(UnknownValue, builder.unknown.items, {}, unknownLessThan);

    var manifest = Manifest{
        .arena = arena_state,
        .tool_version = try a.dupe(u8, options.tool_version),
        .reference_profile = try a.dupe(u8, options.reference_profile),
        .source_dir = try a.dupe(u8, options.source_dir),
        .files = files,
        .groups = try builder.groups.toOwnedSlice(a),
        .assets = try builder.assets.toOwnedSlice(a),
        .unknown_values = try builder.unknown.toOwnedSlice(a),
    };
    var counting = std.io.countingWriter(std.io.null_writer);
    renderJson(&manifest, counting.writer()) catch return error.OutOfMemory;
    if (counting.bytes_written > options.limits.max_manifest_bytes) return error.ManifestTooLarge;
    return manifest;
}

pub fn exitClass(manifest: *const Manifest) ExitClass {
    for (manifest.groups) |g| {
        if (!g.enabled) continue;
        switch (g.disposition.kind) {
            .operator_change, .blocker => return .rejected,
            .supported, .not_enabled => {},
        }
    }
    return .success;
}

const Builder = struct {
    a: std.mem.Allocator,
    ini: *const fail2ban.ParsedIni,
    options: Options,
    /// Reader graph with the reference's implicit `fail2ban_version`/`fail2ban_confpath` options.
    graph: ?fail2ban.ParsedIni = null,
    groups: std.ArrayListUnmanaged(Group) = .{},
    assets: std.ArrayListUnmanaged(Asset) = .{},
    unknown: std.ArrayListUnmanaged(UnknownValue) = .{},

    fn collectFiles(self: *Builder, ini: *const fail2ban.ParsedIni) Error![]const SourceFile {
        var list = std.ArrayListUnmanaged(SourceFile){};
        for (ini.sources.items) |occ| {
            try list.append(self.a, .{ .path = try self.displayPath(occ.path), .sha256 = occ.sha256, .edge = occ.edge });
        }
        const slice = try list.toOwnedSlice(self.a);
        std.mem.sort(SourceFile, slice, {}, fileLessThan);
        return slice;
    }

    fn displayPath(self: *Builder, full: []const u8) Error![]const u8 {
        const root = std.fs.path.resolve(self.a, &.{self.options.source_dir}) catch return error.OutOfMemory;
        if (std.mem.startsWith(u8, full, root) and full.len > root.len and full[root.len] == '/') {
            return try self.a.dupe(u8, full[root.len + 1 ..]);
        }
        return try self.a.dupe(u8, full);
    }

    fn collectGroups(self: *Builder) Error!void {
        // DEFAULT is not a group, but its unknown keys still need provenance.
        if (self.ini.section("DEFAULT")) |def| try self.recordUnknownKeys(def);
        var it = self.ini.userSections();
        while (it.next()) |sec| {
            if (self.groups.items.len >= self.options.limits.max_groups) return error.TooManyGroups;
            try self.recordUnknownKeys(sec);
            try self.groups.append(self.a, try self.buildGroup(sec));
        }
    }

    fn recordUnknownKeys(self: *Builder, sec: *const fail2ban.Section) Error!void {
        var it = sec.keys.iterator();
        while (it.next()) |kv| {
            if (isKnownKey(kv.key_ptr.*)) continue;
            const origin = sec.origins.get(kv.key_ptr.*);
            const provenance = if (origin) |o|
                try std.fmt.allocPrint(self.a, "{s}:{d}", .{ try self.displayPath(o.source), o.line })
            else
                try self.a.dupe(u8, "inherited");
            try self.unknown.append(self.a, .{ .section = sec.name, .key = kv.key_ptr.*, .provenance = provenance });
        }
    }

    const Effective = struct {
        values: std.StringArrayHashMapUnmanaged([]const u8) = .{},
        failures: std.ArrayListUnmanaged([]const u8) = .{},

        fn get(self: *const Effective, key: []const u8) ?[]const u8 {
            const v = self.values.get(key) orelse return null;
            const trimmed = std.mem.trim(u8, v, " \t\r\n");
            return trimmed;
        }
    };

    fn readerGraph(self: *Builder) Error!*const fail2ban.ParsedIni {
        if (self.graph == null) self.graph = try filter_context.readerDefaults(self.a, self.ini, self.options.source_dir);
        return &self.graph.?;
    }

    fn effectiveView(self: *Builder, name: []const u8) Error!Effective {
        var eff = Effective{};
        const graph = try self.readerGraph();
        for ([_]?*const fail2ban.Section{ self.ini.section("DEFAULT"), self.ini.section(name) }) |maybe| {
            const sec = maybe orelse continue;
            var it = sec.keys.iterator();
            while (it.next()) |kv| {
                const key = kv.key_ptr.*;
                if (!isConsumedKey(key)) continue;
                const value = fail2ban.resolve(self.a, graph, name, key) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => blk: {
                        try eff.failures.append(self.a, try std.fmt.allocPrint(self.a, "interpolation-error:{s}:{s}", .{ key, @errorName(err) }));
                        break :blk kv.value_ptr.*;
                    },
                };
                try eff.values.put(self.a, key, value orelse kv.value_ptr.*);
            }
        }
        return eff;
    }

    fn buildGroup(self: *Builder, sec: *const fail2ban.Section) Error!Group {
        const a = self.a;
        const eff = try self.effectiveView(sec.name);
        var reasons = std.ArrayListUnmanaged([]const u8){};
        var kind: DispositionKind = .supported;
        const enabled = if (eff.get("enabled")) |v| parseBool(v) else false;

        for (eff.failures.items) |f| try self.addReason(&reasons, &kind, .blocker, f);

        // Filter identity. Selector parameters change the reference regex set.
        const filter_raw = eff.get("filter") orelse sec.name;
        const filter_name = blk: {
            const sel = fail2ban.parseSelector(a, filter_raw) catch {
                try self.addReason(&reasons, &kind, .blocker, try std.fmt.allocPrint(a, "invalid-filter-selector:{s}", .{filter_raw}));
                break :blk filter_raw;
            };
            if (sel.parameters.count() > 0 and !try self.parametersAreDefaults(filter_raw, &sel)) try self.addReason(&reasons, &kind, .operator_change, "filter-parameters-unverified");
            break :blk sel.name;
        };
        const builtin: ?[]const u8 = if (registry.get(filter_name) != null) filter_name else null;
        if (builtin == null) try self.addReason(&reasons, &kind, .blocker, try std.fmt.allocPrint(a, "custom-filter:{s}", .{filter_name}));
        _ = try self.inspectAsset(.filter, filter_name, builtin != null, &reasons, &kind);
        if (eff.get("failregex") != null or eff.get("ignoreregex") != null or eff.get("prefregex") != null) {
            try self.addReason(&reasons, &kind, .blocker, "inline-regex-override");
        }

        const backend = eff.get("backend") orelse "auto";
        var logpaths = std.ArrayListUnmanaged([]const u8){};
        if (eff.get("logpath")) |raw| {
            var lines = std.mem.splitScalar(u8, raw, '\n');
            while (lines.next()) |line| {
                const entry = std.mem.trim(u8, line, " \t\r");
                if (entry.len == 0) continue;
                try logpaths.append(a, entry);
                if (std.mem.indexOfAny(u8, entry, " \t") != null) try self.addReason(&reasons, &kind, .operator_change, "logpath-tail-flag");
                if (std.mem.indexOfAny(u8, entry, "*?[") != null) try self.addReason(&reasons, &kind, .operator_change, "logpath-glob");
            }
        }
        const journal = std.mem.startsWith(u8, backend, "systemd");
        const file_backend = isFileBackend(backend);
        if (!journal and !file_backend) {
            try self.addReason(&reasons, &kind, .blocker, try std.fmt.allocPrint(a, "unsupported-backend:{s}", .{backend}));
        } else if (!journal and logpaths.items.len == 0) {
            try self.addReason(&reasons, &kind, .blocker, "logpath-missing");
        }

        var scope: []const u8 = "host";
        const action_raw = eff.get("action");
        const banaction = eff.get("banaction") orelse "iptables-multiport";
        var selectors: []const []const u8 = &.{banaction};
        if (action_raw) |raw| {
            selectors = fail2ban.splitSelectors(a, raw) catch blk: {
                try self.addReason(&reasons, &kind, .blocker, "invalid-action-selector");
                break :blk &.{};
            };
            if (selectors.len == 0) try self.addReason(&reasons, &kind, .blocker, "action-empty");
        }
        var backend_names = std.ArrayListUnmanaged([]const u8){};
        for (selectors) |selector| {
            const sel = fail2ban.parseSelector(a, selector) catch {
                try self.addReason(&reasons, &kind, .blocker, try std.fmt.allocPrint(a, "invalid-action-selector:{s}", .{selector}));
                continue;
            };
            const mapped = fail2ban.mapActionNameToBackend(sel.name);
            if (mapped == .log_only) {
                const present = try self.inspectAsset(.action, sel.name, false, &reasons, &kind);
                const label: []const u8 = if (present) "custom-action-script" else "unknown-action";
                try self.addReason(&reasons, &kind, .blocker, try std.fmt.allocPrint(a, "{s}:{s}", .{ label, sel.name }));
                continue;
            }
            try backend_names.append(a, @tagName(mapped));
            _ = try self.inspectAsset(.action, sel.name, true, &reasons, &kind);
            const type_param = sel.parameters.get("type");
            const allports = std.mem.indexOf(u8, sel.name, "allports") != null or (type_param != null and std.mem.eql(u8, type_param.?, "allports"));
            // Native owners are host-scoped; the plan reports the widening as a semantic change.
            if (!allports) scope = "port";
        }
        const protocol = eff.get("protocol");
        if (protocol) |p| {
            if (!std.mem.eql(u8, p, "tcp") and !std.mem.eql(u8, p, "udp") and !std.mem.eql(u8, p, "all")) {
                try self.addReason(&reasons, &kind, .blocker, try std.fmt.allocPrint(a, "unsupported-protocol:{s}", .{p}));
            }
        }
        const chain = eff.get("chain");
        if (chain) |c| if (!std.mem.eql(u8, c, known_chain_tag) and !std.mem.eql(u8, c, "INPUT") and !std.mem.eql(u8, c, "input")) {
            try self.addReason(&reasons, &kind, .blocker, try std.fmt.allocPrint(a, "unsupported-chain:{s}", .{c}));
        };

        const bantime = eff.get("bantime");
        var duration_text: []const u8 = "default";
        if (bantime) |raw| duration_text = try self.classifyDuration(raw, "bantime", true, &reasons, &kind);
        if (eff.get("findtime")) |raw| _ = try self.classifyDuration(raw, "findtime", false, &reasons, &kind);
        const maxretry = eff.get("maxretry");
        if (maxretry) |raw| {
            const n = std.fmt.parseInt(u32, raw, 10) catch 0;
            if (n < 1 or n > 128) try self.addReason(&reasons, &kind, .operator_change, try std.fmt.allocPrint(a, "maxretry-out-of-range:{s}", .{raw}));
        }
        for ([_][]const u8{ "bantime.formula", "bantime.multipliers", "bantime.factor", "bantime.maxtime", "bantime.rndtime", "bantime.overalljails" }) |key| {
            if (eff.get(key) != null) try self.addReason(&reasons, &kind, .operator_change, "bantime-increment");
        }
        if (eff.get("bantime.increment")) |v| if (parseBool(v)) try self.addReason(&reasons, &kind, .operator_change, "bantime-increment");

        var ignoreip = std.ArrayListUnmanaged([]const u8){};
        if (eff.get("ignoreip")) |raw| {
            var tokens = std.mem.tokenizeAny(u8, raw, " \t\r\n,");
            while (tokens.next()) |token| {
                try ignoreip.append(a, token);
                if (!isLiteralAddressOrCidr(token)) try self.addReason(&reasons, &kind, .operator_change, try std.fmt.allocPrint(a, "ignoreip-hostname:{s}", .{token}));
            }
        }
        if (eff.get("ignorecommand")) |cmd| if (cmd.len > 0) try self.addReason(&reasons, &kind, .blocker, "ignorecommand");
        if (eff.get("usedns")) |v| if (!std.mem.eql(u8, v, "no") and !std.mem.eql(u8, v, stock_usedns)) try self.addReason(&reasons, &kind, .operator_change, "usedns");

        const disposition = if (enabled)
            Disposition{ .kind = kind, .reasons = try reasons.toOwnedSlice(a) }
        else
            Disposition{ .kind = .not_enabled };

        return .{
            .name = sec.name,
            .enabled = enabled,
            .filter = filter_raw,
            .backend = backend,
            .logpaths = try logpaths.toOwnedSlice(a),
            .journalmatch = eff.get("journalmatch"),
            .ports = eff.get("port"),
            .protocol = protocol,
            .chain = chain,
            .bantime = bantime,
            .findtime = eff.get("findtime"),
            .maxretry = maxretry,
            .ignoreip = try ignoreip.toOwnedSlice(a),
            .disposition = disposition,
            .mapping = .{
                .service = sec.name,
                .builtin_filter = builtin,
                .scope = scope,
                .duration = duration_text,
            },
        };
    }

    fn classifyDuration(self: *Builder, raw: []const u8, key: []const u8, allow_permanent: bool, reasons: *std.ArrayListUnmanaged([]const u8), kind: *DispositionKind) Error![]const u8 {
        const parsed = duration.parse(raw, false) catch {
            try self.addReason(reasons, kind, .blocker, try std.fmt.allocPrint(self.a, "invalid-{s}:{s}", .{ key, raw }));
            return "invalid";
        };
        switch (parsed) {
            .permanent => {
                if (!allow_permanent) try self.addReason(reasons, kind, .blocker, try std.fmt.allocPrint(self.a, "invalid-{s}:{s}", .{ key, raw }));
                return "permanent";
            },
            .finite => {
                const seconds = parsed.nativeSeconds() catch {
                    try self.addReason(reasons, kind, .blocker, try std.fmt.allocPrint(self.a, "invalid-{s}:{s}", .{ key, raw }));
                    return "invalid";
                };
                if (seconds == 0) {
                    try self.addReason(reasons, kind, .blocker, try std.fmt.allocPrint(self.a, "zero-{s}", .{key}));
                    return "invalid";
                }
                return try std.fmt.allocPrint(self.a, "{d}s", .{seconds});
            },
            .legacy_unknown => unreachable, // parse(raw, false) never yields it
        }
    }

    /// Selector parameters that equal the filter's own defaults (`[Init]`, else the value the
    /// definition declares, as the stock `filter = %(__name__)s[mode=%(mode)s]` form relies on)
    /// change nothing; anything else does.
    fn parametersAreDefaults(self: *Builder, selector: []const u8, sel: *const fail2ban.Selector) Error!bool {
        const asset = fail2ban.loadParameterizedAsset(self.a, self.options.source_dir, "filter.d", selector) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return false,
        };
        if (asset.config.sources.items.len == 0) return false;
        var it = sel.parameters.iterator();
        while (it.next()) |kv| {
            var key_buf: [160]u8 = undefined;
            const known = std.fmt.bufPrint(&key_buf, "known/{s}", .{kv.key_ptr.*}) catch return false;
            const default = asset.init.get(known) orelse sectionValue(&asset.config, "Definition", kv.key_ptr.*) orelse sectionValue(&asset.config, "DEFAULT", kv.key_ptr.*) orelse return false;
            if (!std.mem.eql(u8, std.mem.trim(u8, default, " \t"), std.mem.trim(u8, kv.value_ptr.*, " \t\"'"))) return false;
        }
        return true;
    }

    /// Records the on-disk asset when present. Returns whether it exists.
    /// A present definition can never be proven equal to the compiled builtin here.
    fn inspectAsset(self: *Builder, asset_kind: AssetKind, name: []const u8, recognized: bool, reasons: *std.ArrayListUnmanaged([]const u8), kind: *DispositionKind) Error!bool {
        const dir = switch (asset_kind) {
            .filter => "filter.d",
            .action => "action.d",
        };
        const stem = try std.fs.path.join(self.a, &.{ dir, name });
        const loaded = fail2ban.loadConfig(self.a, self.options.source_dir, stem) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                try self.addReason(reasons, kind, .blocker, try std.fmt.allocPrint(self.a, "asset-unreadable:{s}:{s}", .{ stem, @errorName(err) }));
                return false;
            },
        };
        if (loaded.sources.items.len == 0) return false;
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        var state: StockState = .stock;
        for (loaded.sources.items) |occ| {
            hash.update(&occ.sha256);
            if (isOverlay(occ, name)) {
                state = .modified;
                continue;
            }
            switch (stockMatch(asset_kind, occ.path, occ.sha256)) {
                .stock => {},
                .modified => state = .modified,
                .unknown => if (state == .stock) {
                    state = .unknown;
                },
            }
        }
        var digest: [32]u8 = undefined;
        hash.final(&digest);
        const label = @tagName(asset_kind);
        var asset_reasons = std.ArrayListUnmanaged([]const u8){};
        var asset_kind_disposition: DispositionKind = .supported;
        if (!recognized) {
            try self.addReason(&asset_reasons, &asset_kind_disposition, .blocker, try std.fmt.allocPrint(self.a, "custom-{s}", .{label}));
        } else if (state != .stock) {
            const reason = if (state == .modified)
                try std.fmt.allocPrint(self.a, "stock-{s}-modified", .{label})
            else
                try std.fmt.allocPrint(self.a, "stock-{s}-unverified", .{label});
            try self.addReason(&asset_reasons, &asset_kind_disposition, .operator_change, reason);
            try self.addReason(reasons, kind, .operator_change, reason);
        }
        var duplicate = false;
        for (self.assets.items) |existing| if (existing.kind == asset_kind and std.mem.eql(u8, existing.name, name)) {
            duplicate = true;
        };
        if (!duplicate) {
            if (self.assets.items.len >= self.options.limits.max_assets) return error.TooManyAssets;
            try self.assets.append(self.a, .{
                .name = try self.a.dupe(u8, name),
                .kind = asset_kind,
                .sha256 = digest,
                .modified_vs_stock = state,
                .disposition = .{ .kind = asset_kind_disposition, .reasons = try asset_reasons.toOwnedSlice(self.a) },
            });
        }
        return true;
    }

    fn addReason(self: *Builder, reasons: *std.ArrayListUnmanaged([]const u8), kind: *DispositionKind, severity: DispositionKind, reason: []const u8) Error!void {
        for (reasons.items) |existing| if (std.mem.eql(u8, existing, reason)) return;
        try reasons.append(self.a, reason);
        if (severity == .blocker or kind.* == .supported) kind.* = severity;
    }
};

fn isConsumedKey(key: []const u8) bool {
    for (consumed_keys) |k| if (std.mem.eql(u8, k, key)) return true;
    return false;
}

/// `.local` files and `<name>.d/` drop-ins are operator overlays by definition; an INCLUDES
/// target such as `common.conf` is part of the stock closure and verified by hash instead.
fn isOverlay(occ: fail2ban.SourceOccurrence, name: []const u8) bool {
    if (occ.edge == .local or std.mem.endsWith(u8, occ.path, ".local")) return true;
    var buf: [128]u8 = undefined;
    const marker = std.fmt.bufPrint(&buf, "/{s}.d/", .{name}) catch return true;
    return std.mem.indexOf(u8, occ.path, marker) != null;
}

fn sectionValue(ini: *const fail2ban.ParsedIni, section: []const u8, key: []const u8) ?[]const u8 {
    const sec = ini.section(section) orelse return null;
    return sec.get(key);
}

fn isKnownKey(key: []const u8) bool {
    for (known_keys) |k| if (std.mem.eql(u8, k, key)) return true;
    return false;
}

fn isFileBackend(backend: []const u8) bool {
    for ([_][]const u8{ "auto", "polling", "pyinotify", "gamin" }) |n| if (std.mem.eql(u8, n, backend)) return true;
    return false;
}

fn parseBool(raw: []const u8) bool {
    const v = std.mem.trim(u8, raw, " \t\r\n");
    for ([_][]const u8{ "true", "yes", "on", "1" }) |t| if (std.ascii.eqlIgnoreCase(v, t)) return true;
    return false;
}

fn isLiteralAddressOrCidr(token: []const u8) bool {
    const slash = std.mem.indexOfScalar(u8, token, '/');
    const addr_text = if (slash) |s| token[0..s] else token;
    const addr = IpAddress.parse(addr_text) catch return false;
    if (slash) |s| {
        const prefix = std.fmt.parseInt(u8, token[s + 1 ..], 10) catch return false;
        const max: u8 = switch (addr) {
            .ipv4 => 32,
            .ipv6 => 128,
        };
        return prefix <= max;
    }
    return true;
}

fn fileLessThan(_: void, x: SourceFile, y: SourceFile) bool {
    return std.mem.order(u8, x.path, y.path) == .lt;
}
fn groupLessThan(_: void, x: Group, y: Group) bool {
    return std.mem.order(u8, x.name, y.name) == .lt;
}
fn assetLessThan(_: void, x: Asset, y: Asset) bool {
    if (x.kind != y.kind) return @intFromEnum(x.kind) < @intFromEnum(y.kind);
    return std.mem.order(u8, x.name, y.name) == .lt;
}
fn unknownLessThan(_: void, x: UnknownValue, y: UnknownValue) bool {
    const s = std.mem.order(u8, x.section, y.section);
    if (s != .eq) return s == .lt;
    return std.mem.order(u8, x.key, y.key) == .lt;
}

// JSON rendering: fixed key order, no map iteration, inputs pre-sorted.
fn jsonString(writer: anytype, s: []const u8) !void {
    try std.json.stringify(s, .{}, writer);
}

fn jsonOptString(writer: anytype, s: ?[]const u8) !void {
    if (s) |v| try jsonString(writer, v) else try writer.writeAll("null");
}

fn jsonStringList(writer: anytype, items: []const []const u8) !void {
    try writer.writeByte('[');
    for (items, 0..) |item, i| {
        if (i > 0) try writer.writeByte(',');
        try jsonString(writer, item);
    }
    try writer.writeByte(']');
}

fn jsonHex(writer: anytype, digest: [32]u8) !void {
    try writer.print("\"{s}\"", .{std.fmt.fmtSliceHexLower(&digest)});
}

fn jsonDisposition(writer: anytype, d: Disposition) !void {
    try writer.writeAll("{\"kind\":");
    try jsonString(writer, @tagName(d.kind));
    try writer.writeAll(",\"reasons\":");
    try jsonStringList(writer, d.reasons);
    try writer.writeByte('}');
}

pub fn renderJson(manifest: *const Manifest, writer: anytype) !void {
    try writer.print("{{\"schema_version\":{d},\"tool_version\":", .{schema_version});
    try jsonString(writer, manifest.tool_version);
    try writer.writeAll(",\"reference_profile\":");
    try jsonString(writer, manifest.reference_profile);
    try writer.writeAll(",\"source\":{\"dir\":");
    try jsonString(writer, manifest.source_dir);
    try writer.writeAll(",\"files\":[");
    for (manifest.files, 0..) |f, i| {
        if (i > 0) try writer.writeByte(',');
        try writer.writeAll("{\"path\":");
        try jsonString(writer, f.path);
        try writer.writeAll(",\"sha256\":");
        try jsonHex(writer, f.sha256);
        try writer.writeAll(",\"edge\":");
        try jsonString(writer, @tagName(f.edge));
        try writer.writeByte('}');
    }
    try writer.writeAll("]},\"groups\":[");
    for (manifest.groups, 0..) |g, i| {
        if (i > 0) try writer.writeByte(',');
        try writer.writeAll("{\"name\":");
        try jsonString(writer, g.name);
        try writer.print(",\"enabled\":{},\"filter\":", .{g.enabled});
        try jsonString(writer, g.filter);
        try writer.writeAll(",\"backend\":");
        try jsonString(writer, g.backend);
        try writer.writeAll(",\"logpaths\":");
        try jsonStringList(writer, g.logpaths);
        try writer.writeAll(",\"journalmatch\":");
        try jsonOptString(writer, g.journalmatch);
        try writer.writeAll(",\"ports\":");
        try jsonOptString(writer, g.ports);
        try writer.writeAll(",\"protocol\":");
        try jsonOptString(writer, g.protocol);
        try writer.writeAll(",\"chain\":");
        try jsonOptString(writer, g.chain);
        try writer.writeAll(",\"bantime\":");
        try jsonOptString(writer, g.bantime);
        try writer.writeAll(",\"findtime\":");
        try jsonOptString(writer, g.findtime);
        try writer.writeAll(",\"maxretry\":");
        try jsonOptString(writer, g.maxretry);
        try writer.writeAll(",\"ignoreip\":");
        try jsonStringList(writer, g.ignoreip);
        try writer.writeAll(",\"disposition\":");
        try jsonDisposition(writer, g.disposition);
        try writer.writeAll(",\"mapping\":{\"service\":");
        try jsonString(writer, g.mapping.service);
        try writer.writeAll(",\"builtin_filter\":");
        try jsonOptString(writer, g.mapping.builtin_filter);
        try writer.writeAll(",\"scope\":");
        try jsonString(writer, g.mapping.scope);
        try writer.writeAll(",\"duration\":");
        try jsonString(writer, g.mapping.duration);
        try writer.writeAll("}}");
    }
    try writer.writeAll("],\"assets\":[");
    for (manifest.assets, 0..) |asset, i| {
        if (i > 0) try writer.writeByte(',');
        try writer.writeAll("{\"name\":");
        try jsonString(writer, asset.name);
        try writer.writeAll(",\"kind\":");
        try jsonString(writer, @tagName(asset.kind));
        try writer.writeAll(",\"sha256\":");
        try jsonHex(writer, asset.sha256);
        try writer.writeAll(",\"modified_vs_stock\":");
        try writer.writeAll(switch (asset.modified_vs_stock) {
            .modified => "true",
            .stock => "false",
            .unknown => "\"unknown\"",
        });
        try writer.writeAll(",\"disposition\":");
        try jsonDisposition(writer, asset.disposition);
        try writer.writeByte('}');
    }
    try writer.writeAll("],\"unknown_values\":[");
    for (manifest.unknown_values, 0..) |u, i| {
        if (i > 0) try writer.writeByte(',');
        try writer.writeAll("{\"section\":");
        try jsonString(writer, u.section);
        try writer.writeAll(",\"key\":");
        try jsonString(writer, u.key);
        try writer.writeAll(",\"provenance\":");
        try jsonString(writer, u.provenance);
        try writer.writeByte('}');
    }
    try writer.writeAll("]}\n");
}

pub fn renderTable(manifest: *const Manifest, writer: anytype) !void {
    try writer.print("source: {s} ({d} files, profile {s})\n", .{ manifest.source_dir, manifest.files.len, manifest.reference_profile });
    try writer.writeAll("GROUP                 ENABLED  FILTER                DISPOSITION      REASONS\n");
    for (manifest.groups) |g| {
        try writer.print("{s:<21} {s:<8} {s:<21} {s:<16} ", .{ g.name, if (g.enabled) "yes" else "no", g.filter, @tagName(g.disposition.kind) });
        try writeReasons(writer, g.disposition.reasons);
    }
    if (manifest.assets.len > 0) {
        try writer.writeAll("ASSET                 KIND     STOCK      DISPOSITION      REASONS\n");
        for (manifest.assets) |asset| {
            const stock = switch (asset.modified_vs_stock) {
                .modified => "modified",
                .stock => "stock",
                .unknown => "unknown",
            };
            try writer.print("{s:<21} {s:<8} {s:<10} {s:<16} ", .{ asset.name, @tagName(asset.kind), stock, @tagName(asset.disposition.kind) });
            try writeReasons(writer, asset.disposition.reasons);
        }
    }
    if (manifest.unknown_values.len > 0) {
        try writer.writeAll("UNKNOWN VALUES\n");
        for (manifest.unknown_values) |u| try writer.print("  [{s}] {s} ({s})\n", .{ u.section, u.key, u.provenance });
    }
    try writer.print("exit: {s}\n", .{@tagName(exitClass(manifest))});
}

fn writeReasons(writer: anytype, reasons: []const []const u8) !void {
    if (reasons.len == 0) {
        try writer.writeAll("-\n");
        return;
    }
    for (reasons, 0..) |r, i| {
        if (i > 0) try writer.writeAll(", ");
        try writer.writeAll(r);
    }
    try writer.writeByte('\n');
}

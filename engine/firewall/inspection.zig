// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Reads back, creates and changes this installation's kernel firewall state through nftables netlink or iptables and ipset.
// Holds: An iptables or ipset readback is returned only when two reads agree in structure and entries; otherwise it fails as Changed.

const std = @import("std");
const shared = @import("shared");
const build_options = @import("build_options");
const diag_mod = @import("../diag/diag.zig");
const nl = @import("netlink.zig");
pub const nft = @import("nftables.zig");
const command = @import("command.zig");
const linux = std.os.linux;
const mem = std.mem;
const deadlineUnits = @import("inspection_entries.zig").deadlineUnits;
const timingTransport = @import("inspection_entries.zig").timingTransport;
const entryScope = @import("inspection_entries.zig").entryScope;
const entryIndex = @import("inspection_entries.zig").entryIndex;
const findEntry = @import("inspection_entries.zig").findEntry;
const sameEntries = @import("inspection_entries.zig").sameEntries;
const effectMatches = @import("inspection_entries.zig").effectMatches;
const entryLess = @import("inspection_entries.zig").entryLess;
const Builder = @import("inspection_builder.zig").Builder;
const AttrMap = @import("inspection_nft_read.zig").AttrMap;
const netlinkError = @import("inspection_nft_read.zig").netlinkError;
const dump = @import("inspection_nft_read.zig").dump;
const nftSetAttrs = @import("inspection_nft_read.zig").nftSetAttrs;
const readNft = @import("inspection_nft_read.zig").readNft;
pub const decodeSetElement = @import("inspection_nft_read.zig").decodeSetElement;
const Tokens = @import("inspection_tool_read.zig").Tokens;
const scanSavedTables = @import("inspection_tool_read.zig").scanSavedTables;
const buildFixedScopedArgv = @import("inspection_tool_read.zig").buildFixedScopedArgv;
const parseIptables = @import("inspection_tool_read.zig").parseIptables;
const parseIpset = @import("inspection_tool_read.zig").parseIpset;
const readTools = @import("inspection_tool_read.zig").readTools;
pub const setName = @import("inspection_tool_read.zig").setName;

pub const Transport = enum { nftables, iptables, ipset };
pub const canonical_scope = @import("scope.zig");
pub const CanonicalScope = canonical_scope.Scope;
pub const Error = error{
    UnknownState,
    ForeignState,
    Incomplete,
    Changed,
    DumpInterrupted,
    EventsLost,
    LimitExceeded,
    UnsupportedScope,
    ExpiredIntent,
    UnsupportedDeadline,
    InvalidInstallation,
    ToolUnavailable,
    PermissionDenied,
    Timeout,
    OutOfMemory,
    SystemError,
};
pub const OperationStage = enum { admission_probe, admission_dispatch, admission_verify, readback, effect_dispatch, effect_verify };
pub const MutationDisposition = enum { not_started, outcome_uncertain };
pub const FailureContext = struct {
    backend: Transport,
    stage: OperationStage,
    cause: Error,
    mutation: MutationDisposition,
};

pub const MutationProgress = struct { requested: bool = false };
pub const max_withdraw_messages: usize = 64;
pub const withdraw_batch_bytes: usize = 8192;
pub const max_install_messages: usize = 1024;
pub const install_batch_bytes: usize = 512 * 1024;

pub fn batchable(scope: CanonicalScope) bool {
    return hostScope(scope);
}
pub const InstallOutcome = struct { result: InstallResult, consumed: usize };

pub fn validateCanonicalScope(_: Transport, scope: CanonicalScope) Error!void {
    scope.validate() catch return error.UnsupportedScope;
}
fn validateRealizedScope(transport: Transport, scope: CanonicalScope) Error!void {
    try validateCanonicalScope(transport, scope);
}

pub fn subjectAddress(subject: canonical_scope.Subject) shared.IpAddress {
    return switch (subject.family) {
        .v4 => .{ .ipv4 = mem.readInt(u32, subject.address[0..4], .big) },
        .v6 => .{ .ipv6 = mem.readInt(u128, &subject.address, .big) },
    };
}

pub fn withdrawCost(scope: CanonicalScope) Error!usize {
    if (hostScope(scope)) return 1;
    return nft.scopeRulePartCount(scope) catch error.UnsupportedScope;
}

pub fn hostScope(scope: CanonicalScope) bool {
    _ = legacyAddress(scope) catch return false;
    return true;
}

pub fn legacyAddress(scope: CanonicalScope) Error!shared.IpAddress {
    scope.validate() catch return error.UnsupportedScope;
    if (scope.subject.kind != .host or !scope.protocols.isAll() or !scope.ports.isAll()) return error.UnsupportedScope;
    return subjectAddress(scope.subject);
}
pub const Installation = struct {
    id: [16]u8,
    transport: Transport,
    pub fn validate(self: Installation) Error!void {
        if (mem.allEqual(u8, &self.id, 0)) return error.InvalidInstallation;
    }
    // Why: The name is also an iptables chain, which iptables limits to 28 characters, and with a two-character suffix an ipset name.
    pub fn name(self: Installation, buf: *[28]u8) []const u8 {
        const hex = std.fmt.bytesToHex(self.id, .lower);
        @memcpy(buf[0..4], "f2z_");
        @memcpy(buf[4..], hex[0..24]);
        return buf;
    }
    pub fn marker(self: Installation, buf: *[44]u8) []const u8 {
        @memcpy(buf[0..12], "fail2zig:v1:");
        @memcpy(buf[12..], &std.fmt.bytesToHex(self.id, .lower));
        return buf;
    }
};

pub const Scope = struct {
    address: shared.IpAddress,
    prefix: u8,
    protocol: enum { any, tcp, udp } = .any,
    ports: ?struct { first: u16, last: u16 } = null,
    direction: enum { input, output, forward } = .input,
    verdict: enum { drop, reject } = .drop,
    interface: ?[]const u8 = null,
    pub fn validate(self: Scope) Error!void {
        if (self.prefix != (if (self.address == .ipv4) @as(u8, 32) else 128) or
            self.protocol != .any or self.ports != null or self.direction != .input or
            self.verdict != .drop or self.interface != null) return error.UnsupportedScope;
    }
};

pub fn canonicalizeLegacyScope(scope: Scope) Error!CanonicalScope {
    try scope.validate();
    const result = CanonicalScope{ .subject = canonical_scope.Subject.host(scope.address) };
    try validateCanonicalScope(.nftables, result);
    return result;
}

pub const max_inventory_entries: usize = 131_072;
const max_inventory_bytes: usize = 64 * 1024 * 1024;
const max_dump_attempts: usize = 3;
pub const Limits = struct {
    max_entries: usize = max_inventory_entries,
    max_bytes: usize = max_inventory_bytes,
    max_messages: usize = max_inventory_entries,
    timeout_ms: u64 = 5000,
    pub fn validate(self: Limits) Error!void {
        if (self.max_entries == 0 or self.max_entries > max_inventory_entries or self.max_bytes == 0 or
            self.max_bytes > max_inventory_bytes or self.max_messages == 0 or self.max_messages > max_inventory_entries or
            self.timeout_ms == 0 or self.timeout_ms > 5000) return error.LimitExceeded;
    }
};
pub const Entry = struct {
    address: shared.IpAddress,
    scope: ?CanonicalScope = null,
    remaining_ms: ?u64 = null,
    deadline_us: ?i64 = null,
    effect_id: ?[32]u8 = null,
    partial: bool = false,
};
pub const HostBatchEntry = struct {
    entry: Entry,
    original: usize,
    fn less(_: void, a: @This(), b: @This()) bool {
        return entryLess({}, a.entry, b.entry);
    }
};

pub const scoped_rule_metadata_bytes: usize = 140;
pub const scoped_comment_prefix = "f2zs:";
pub const scoped_comment_payload_bytes: usize = std.base64.standard.Encoder.calcSize(scoped_rule_metadata_bytes);
pub const scoped_comment_bytes: usize = scoped_comment_prefix.len + scoped_comment_payload_bytes;
pub const ScopedRuleMetadata = struct {
    effect_id: [32]u8,
    part: u8,
    count: u8,
    deadline_us: ?i64,
    scope: CanonicalScope,

    pub fn encode(self: ScopedRuleMetadata) Error![scoped_rule_metadata_bytes]u8 {
        self.scope.validate() catch return error.UnsupportedScope;
        const part_count = nft.scopeRulePartCount(self.scope) catch return error.UnsupportedScope;
        if (mem.allEqual(u8, &self.effect_id, 0) or self.count != part_count or self.part >= self.count)
            return error.UnsupportedScope;
        if (self.deadline_us) |deadline| if (deadline <= 0) return error.UnsupportedDeadline;
        var bytes = [_]u8{0} ** scoped_rule_metadata_bytes;
        @memcpy(bytes[0..4], "F2ZS");
        bytes[4] = 1;
        bytes[5] = @intFromBool(self.deadline_us != null);
        bytes[6] = self.part;
        bytes[7] = self.count;
        @memcpy(bytes[8..40], &self.effect_id);
        if (self.deadline_us) |deadline| mem.writeInt(i64, bytes[40..48], deadline, .little);
        const scope = self.scope.encode() catch return error.UnsupportedScope;
        @memcpy(bytes[48..140], &scope);
        return bytes;
    }

    pub fn decode(bytes: []const u8) Error!ScopedRuleMetadata {
        if (bytes.len != scoped_rule_metadata_bytes or !mem.eql(u8, bytes[0..4], "F2ZS") or bytes[4] != 1 or bytes[5] > 1)
            return error.UnknownState;
        const value = ScopedRuleMetadata{
            .effect_id = bytes[8..40].*,
            .part = bytes[6],
            .count = bytes[7],
            .deadline_us = if (bytes[5] == 1) mem.readInt(i64, bytes[40..48], .little) else null,
            .scope = canonical_scope.Scope.decode(bytes[48..140]) catch return error.UnknownState,
        };
        const canonical_bytes = value.encode() catch return error.UnknownState;
        if (!mem.eql(u8, bytes, &canonical_bytes)) return error.UnknownState;
        return value;
    }

    pub fn encodeComment(self: ScopedRuleMetadata) Error![scoped_comment_bytes]u8 {
        const wire = try self.encode();
        var result: [scoped_comment_bytes]u8 = undefined;
        @memcpy(result[0..scoped_comment_prefix.len], scoped_comment_prefix);
        _ = std.base64.standard.Encoder.encode(result[scoped_comment_prefix.len..], &wire);
        return result;
    }

    pub fn decodeComment(value: []const u8) Error!ScopedRuleMetadata {
        if (value.len != scoped_comment_bytes or !mem.startsWith(u8, value, scoped_comment_prefix)) return error.UnknownState;
        const payload = value[scoped_comment_prefix.len..];
        if ((std.base64.standard.Decoder.calcSizeForSlice(payload) catch return error.UnknownState) != scoped_rule_metadata_bytes) return error.UnknownState;
        var wire: [scoped_rule_metadata_bytes]u8 = undefined;
        std.base64.standard.Decoder.decode(&wire, payload) catch return error.UnknownState;
        const metadata = try decode(&wire);
        if (!mem.eql(u8, value, &try metadata.encodeComment())) return error.UnknownState;
        return metadata;
    }
};
pub const StructureProof = enum(u8) { unverified, exact_v1 };

pub const Snapshot = struct {
    allocator: mem.Allocator,
    installation: Installation,
    state: enum { absent, owned },
    entries: []Entry,
    capacity: usize = 0,
    fingerprint: [32]u8,
    structure_proof: StructureProof = .unverified,
    observed_start_ns: u64,
    observed_end_ns: u64,
    pub fn deinit(self: *Snapshot) void {
        self.allocator.free(self.entries.ptr[0..@max(self.capacity, self.entries.len)]);
        self.* = undefined;
    }
    pub fn find(self: *const Snapshot, scope: CanonicalScope) Error!?usize {
        return entryIndex(self.entries, scope);
    }
    pub fn page(self: *const Snapshot, offset: usize) Error![]const Entry {
        if (offset > self.entries.len) return error.Incomplete;
        return self.entries[offset..@min(self.entries.len, offset + @min(@as(usize, 64), self.entries.len - offset))];
    }
    pub fn upsertHost(self: *Snapshot, entry: Entry) Error!bool {
        if (entry.scope != null) return error.UnsupportedScope;
        if (try entryIndex(self.entries, entryScope(entry))) |index| {
            self.entries[index] = entry;
            return false;
        }
        const len = self.entries.len;
        const held = @max(self.capacity, len);
        if (len == held) {
            const wanted = held + held / 2 + 8;
            const grown = self.allocator.realloc(self.entries.ptr[0..held], wanted) catch return error.OutOfMemory;
            self.entries = grown[0..len];
            self.capacity = wanted;
        }
        const room = self.entries.ptr[0 .. len + 1];
        var index = len;
        while (index > 0 and entryLess({}, entry, room[index - 1])) : (index -= 1) room[index] = room[index - 1];
        room[index] = entry;
        self.entries = room;
        return true;
    }
    pub fn upsertHosts(self: *Snapshot, batch: []HostBatchEntry, added: []bool) Error!void {
        if (batch.len > max_install_messages or added.len != batch.len) return error.LimitExceeded;
        for (batch, 0..) |candidate, index| {
            if (candidate.entry.scope != null or candidate.original != index) return error.UnsupportedScope;
            added[index] = false;
        }
        mem.sortUnstable(HostBatchEntry, batch, {}, HostBatchEntry.less);
        if (batch.len > 1) {
            for (batch[1..], 1..) |candidate, index| {
                if (!entryLess({}, batch[index - 1].entry, candidate.entry)) return error.UnsupportedScope;
            }
        }

        const len = self.entries.len;
        var existing: usize = 0;
        var additions: usize = 0;
        for (batch) |candidate| {
            while (existing < len and entryLess({}, self.entries[existing], candidate.entry)) existing += 1;
            if (existing == len or entryLess({}, candidate.entry, self.entries[existing])) {
                added[candidate.original] = true;
                additions += 1;
            } else if (!std.meta.eql(entryScope(self.entries[existing]), entryScope(candidate.entry))) {
                return error.UnknownState;
            }
        }

        const required = len + additions;
        const held = @max(self.capacity, len);
        if (required > held) {
            const wanted = @max(required, held + held / 2 + 8);
            const grown = self.allocator.realloc(self.entries.ptr[0..held], wanted) catch return error.OutOfMemory;
            self.entries = grown[0..len];
            self.capacity = wanted;
        }
        const room = self.entries.ptr[0..required];
        var old = len;
        var incoming = batch.len;
        var write = required;
        while (incoming > 0) {
            if (old > 0 and entryLess({}, batch[incoming - 1].entry, room[old - 1])) {
                write -= 1;
                old -= 1;
                room[write] = room[old];
            } else {
                write -= 1;
                incoming -= 1;
                room[write] = batch[incoming].entry;
                if (old > 0 and !entryLess({}, room[old - 1], batch[incoming].entry)) old -= 1;
            }
        }
        self.entries = room;
    }
    pub fn removeHost(self: *Snapshot, entry: Entry) Error!bool {
        if (entry.scope != null) return error.UnsupportedScope;
        const index = try entryIndex(self.entries, entryScope(entry)) orelse return false;
        mem.copyForwards(Entry, self.entries[index .. self.entries.len - 1], self.entries[index + 1 ..]);
        self.capacity = @max(self.capacity, self.entries.len);
        self.entries = self.entries.ptr[0 .. self.entries.len - 1];
        return true;
    }
};

pub const EventDelta = struct { added: u32 = 0, replaced: u32 = 0, removed: u32 = 0, missing: u32 = 0 };
pub const EventSink = struct { context: *anyopaque, apply: *const fn (*anyopaque, nft.Event) Error!void };

pub const DurableInstallationIntent = struct {
    installation: Installation,
    intent_id: [32]u8,
    revision: u64,
    pub fn validate(self: DurableInstallationIntent, installation: Installation) Error!void {
        try self.installation.validate();
        if (!mem.eql(u8, &self.installation.id, &installation.id) or self.installation.transport != installation.transport or
            mem.allEqual(u8, &self.intent_id, 0) or self.revision == 0 or self.revision > std.math.maxInt(i64)) return error.InvalidInstallation;
    }
};
pub const AdmissionResult = union(enum) {
    installed: struct { snapshot: Snapshot, created: bool },
    uncertain: FailureContext,
    pub fn deinit(self: *AdmissionResult) void {
        switch (self.*) {
            .installed => |*result| result.snapshot.deinit(),
            .uncertain => {},
        }
        self.* = undefined;
    }
};

pub const Lease = union(enum) { permanent, finite_deadline_us: i64 };
pub const EffectOperation = union(enum) { ensure_present: Lease, ensure_absent };
pub const ClockSample = struct { wall_us: i64 };
pub const DispatchToken = struct {
    installation: Installation,
    effect_id: [32]u8,
    aggregate_revision: u64,
    scope: CanonicalScope,
    operation: EffectOperation,
};
pub const EffectResult = union(enum) {
    verified: struct { snapshot: Snapshot, changed: bool, observed_start_wall_us: i64, observed_wall_us: i64 },
    uncertain: FailureContext,
    pub fn deinit(self: *EffectResult) void {
        switch (self.*) {
            .verified => |*v| v.snapshot.deinit(),
            .uncertain => {},
        }
        self.* = undefined;
    }
};
pub const InstallResult = union(enum) {
    verified: struct { snapshot: Snapshot, changed: bool, observed_start_wall_us: i64, observed_wall_us: i64 },
    acknowledged: struct { sent_wall_us: i64, acked_wall_us: i64, port_id: u32 },
    uncertain: FailureContext,
    pub fn deinit(self: *InstallResult) void {
        switch (self.*) {
            .verified => |*v| v.snapshot.deinit(),
            .acknowledged, .uncertain => {},
        }
        self.* = undefined;
    }
};

pub const ExactObservation = struct {
    snapshot: Snapshot,
    matches_desired: bool,
    observed_wall_us: i64,
    pub fn deinit(self: *ExactObservation) void {
        self.snapshot.deinit();
        self.* = undefined;
    }
};

pub const Inspector = struct {
    allocator: mem.Allocator,
    installation: Installation,
    limits: Limits,
    iptables_path: []const u8 = "/usr/sbin/iptables",
    ip6tables_path: []const u8 = "/usr/sbin/ip6tables",
    iptables_restore_path: []const u8 = "/usr/sbin/iptables-restore",
    ip6tables_restore_path: []const u8 = "/usr/sbin/ip6tables-restore",
    ipset_path: []const u8 = "/usr/sbin/ipset",
    iptables_legacy_save_path: []const u8 = "/usr/sbin/iptables-legacy-save",
    ip6tables_legacy_save_path: []const u8 = "/usr/sbin/ip6tables-legacy-save",
    work_messages: usize = 0,
    retained_bytes: usize = 0,
    live_bytes: usize = 0,
    dump_interruptions: u64 = 0,
    events: ?nl.NetlinkSocket = null,
    install: ?nl.NetlinkSocket = null,
    last_install_port: u32 = 0,
    clock_rate: if (build_options.diag) u32 else void = if (build_options.diag) 1 else {},
    test_fault_after_mutations: if (@import("builtin").is_test) ?usize else void = if (@import("builtin").is_test) null else {},
    test_between_reads: if (@import("builtin").is_test) ?*const fn (*Inspector) void else void = if (@import("builtin").is_test) null else {},

    pub fn open(allocator: mem.Allocator, installation: Installation, limits: Limits) Error!Inspector {
        try installation.validate();
        try limits.validate();
        return .{ .allocator = allocator, .installation = installation, .limits = limits };
    }
    pub fn close(self: *Inspector) void {
        self.unsubscribe();
        self.dropInstallSocket();
    }
    pub fn dropInstallSocket(self: *Inspector) void {
        if (self.install) |*sock| sock.close();
        self.install = null;
    }
    pub fn subscribe(self: *Inspector) Error!void {
        if (self.installation.transport != .nftables or self.events != null) return;
        self.events = nl.NetlinkSocket.initEvents(nl.NFNL.GRP_NFTABLES) catch |err| return netlinkError(err);
    }
    pub fn unsubscribe(self: *Inspector) void {
        if (self.events) |*sock| sock.close();
        self.events = null;
    }
    pub fn subscribed(self: *const Inspector) bool {
        return self.events != null;
    }

    pub fn admitInstallation(self: *Inspector, intent: DurableInstallationIntent) Error!AdmissionResult {
        try intent.validate(self.installation);
        var before = try self.inspect();
        if (before.state == .owned) return .{ .installed = .{ .snapshot = before, .created = false } };
        before.deinit();
        var timer = std.time.Timer.start() catch return error.SystemError;
        self.work_messages = 0;
        self.retained_bytes = 0;
        self.live_bytes = 0;
        var progress = MutationProgress{};
        self.createInstallation(&timer, &progress) catch |err| return .{ .uncertain = self.failure(.admission_dispatch, err, progress) };
        var after = self.inspect() catch |err| return .{ .uncertain = self.failure(.admission_verify, err, progress) };
        if (after.state != .owned) {
            after.deinit();
            return .{ .uncertain = self.failure(.admission_verify, error.Incomplete, progress) };
        }
        return .{ .installed = .{ .snapshot = after, .created = true } };
    }

    pub fn inspectReservedNamespace(self: *Inspector) Error!void {
        self.work_messages = 0;
        self.retained_bytes = 0;
        self.live_bytes = 0;
        var timer = std.time.Timer.start() catch return error.SystemError;
        for (0..2) |_| {
            var sock = nl.NetlinkSocket.init(linux.NETLINK.NETFILTER) catch |err| return netlinkError(err);
            defer sock.close();
            const kinds = [_][3]u16{
                .{ nft.NFT_MSG.GETTABLE, nft.NFT_MSG.NEWTABLE, 1 },
                .{ nft.NFT_MSG.GETCHAIN, nft.NFT_MSG.NEWCHAIN, 3 },
                .{ nft.NFT_MSG.GETSET, nft.NFT_MSG.NEWSET, 2 },
            };
            for (kinds) |kind| {
                var records = try dump(self, &sock, kind[0], kind[1], &.{ 0, 0, 0, 0 }, &timer, 0);
                defer records.deinit();
                for (records.values.items) |payload| {
                    // Why: 1, 2, 3, 5, 7 and 10 are the NFPROTO families nf_tables tables use (include/uapi/linux/netfilter.h).
                    if (payload.len < 4 or payload[1] != 0 or mem.indexOfScalar(u8, &.{ 1, 2, 3, 5, 7, 10 }, payload[0]) == null) return error.UnknownState;
                    const attributes = try AttrMap.parse(payload[4..], &.{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 });
                    if (reservedName(try attributes.text(kind[2]))) return error.ForeignState;
                    if (kind[0] != nft.NFT_MSG.GETTABLE and reservedName(try attributes.text(1))) return error.ForeignState;
                }
            }
            if (self.installation.transport != .nftables) {
                for ([_][]const u8{ self.iptables_legacy_save_path, self.ip6tables_legacy_save_path }) |binary| {
                    const result = try self.run(&.{binary}, &timer);
                    defer result.deinit(self.allocator);
                    if (result.stderr.len != 0) return error.UnknownState;
                    try scanSavedTables(result.stdout);
                }
            }
            if (self.installation.transport == .ipset) {
                const sets = try self.run(&.{ self.ipset_path, "list", "-name" }, &timer);
                defer sets.deinit(self.allocator);
                if (sets.stderr.len != 0) return error.UnknownState;
                if (sets.stdout.len != 0 and sets.stdout[sets.stdout.len - 1] != '\n') return error.Incomplete;
                var names = mem.tokenizeScalar(u8, sets.stdout, '\n');
                while (names.next()) |name| {
                    // Why: IPSET_MAXNAMELEN is 32 including the NUL (include/uapi/linux/netfilter/ipset/ip_set.h).
                    if (name.len == 0 or name.len > 31 or mem.indexOfAny(u8, name, " \t\r") != null) return error.UnknownState;
                    if (reservedName(name)) return error.ForeignState;
                }
            }
        }
        try self.checkTime(&timer);
    }

    pub fn observeExact(self: *Inspector, token: DispatchToken, clock: ClockSample) Error!ExactObservation {
        try (DurableInstallationIntent{ .installation = token.installation, .intent_id = token.effect_id, .revision = token.aggregate_revision }).validate(self.installation);
        try validateRealizedScope(self.installation.transport, token.scope);
        if (clock.wall_us < 0) return error.UnsupportedDeadline;
        var elapsed = std.time.Timer.start() catch return error.SystemError;
        var snapshot = try self.inspect();
        errdefer snapshot.deinit();
        if (snapshot.state != .owned) return error.InvalidInstallation;
        const end = try self.clockAt(clock, &elapsed);
        return .{
            .snapshot = snapshot,
            .matches_desired = self.kernelMatches(token.operation, try findEntry(snapshot.entries, token.scope, token.effect_id), clock.wall_us, end),
            .observed_wall_us = end,
        };
    }

    pub fn matchesSnapshot(self: *const Inspector, snapshot: *const Snapshot, token: DispatchToken, wall_start_us: i64, wall_end_us: i64) Error!bool {
        try (DurableInstallationIntent{ .installation = token.installation, .intent_id = token.effect_id, .revision = token.aggregate_revision }).validate(self.installation);
        try validateRealizedScope(self.installation.transport, token.scope);
        if (!mem.eql(
            u8,
            &snapshot.installation.id,
            &self.installation.id,
        ) or snapshot.installation.transport != self.installation.transport or snapshot.state != .owned) return error.InvalidInstallation;
        if (wall_start_us < 0 or wall_end_us < wall_start_us) return error.UnsupportedDeadline;
        const wall_duration: u64 = @intCast(wall_end_us - wall_start_us);
        if (wall_duration > self.fromKernelUs(self.limits.timeout_ms * 1000) or snapshot.observed_end_ns < snapshot.observed_start_ns or
            snapshot.observed_end_ns > self.limits.timeout_ms * std.time.ns_per_ms) return error.Incomplete;
        if (wall_duration < (snapshot.observed_end_ns - snapshot.observed_start_ns) / std.time.ns_per_us) return error.Incomplete;
        if (snapshot.entries.len > self.limits.max_entries or snapshot.entries.len > self.limits.max_bytes / @sizeOf(Entry)) return error.LimitExceeded;
        return self.kernelMatches(token.operation, try findEntry(snapshot.entries, token.scope, token.effect_id), wall_start_us, wall_end_us);
    }

    pub fn applyExact(self: *Inspector, token: DispatchToken, clock: ClockSample) Error!EffectResult {
        try (DurableInstallationIntent{ .installation = token.installation, .intent_id = token.effect_id, .revision = token.aggregate_revision }).validate(self.installation);
        try validateRealizedScope(self.installation.transport, token.scope);
        _ = try self.kernelUnits(token.operation, timingTransport(self.installation.transport, token.scope), clock.wall_us);
        var elapsed = std.time.Timer.start() catch return error.SystemError;
        var baseline = try self.inspect();
        defer baseline.deinit();
        const held = self.retained_bytes;
        self.retained_bytes = held + baseline.entries.len * @sizeOf(Entry);
        defer self.retained_bytes = held;
        var result = try self.applyFromBaseline(token, .{ .wall_us = try self.clockAt(clock, &elapsed) }, &baseline);
        if (result == .verified and !result.verified.changed) result.verified.observed_start_wall_us = clock.wall_us;
        return result;
    }

    pub fn applyFromBaseline(self: *Inspector, token: DispatchToken, clock: ClockSample, baseline: *const Snapshot) Error!EffectResult {
        try (DurableInstallationIntent{ .installation = token.installation, .intent_id = token.effect_id, .revision = token.aggregate_revision }).validate(self.installation);
        const transport = self.installation.transport;
        try validateRealizedScope(transport, token.scope);
        _ = try self.kernelUnits(token.operation, timingTransport(transport, token.scope), clock.wall_us);
        if (!mem.eql(u8, &baseline.installation.id, &self.installation.id) or baseline.installation.transport != transport or baseline.state != .owned) return error.InvalidInstallation;
        var elapsed = std.time.Timer.start() catch return error.SystemError;
        const existing = try findEntry(baseline.entries, token.scope, token.effect_id);
        const noop = switch (token.operation) {
            .ensure_absent => existing == null,
            .ensure_present => |lease| if (existing) |entry| if (entry.scope != null)
                !entry.partial and switch (lease) {
                    .permanent => entry.deadline_us == null,
                    .finite_deadline_us => |deadline| entry.deadline_us != null and entry.deadline_us.? == deadline,
                }
            else
                (transport == .iptables or (lease == .permanent and entry.remaining_ms == null)) else false,
        };
        if (noop) {
            const end = try self.clockAt(clock, &elapsed);
            _ = try self.kernelUnits(token.operation, timingTransport(transport, token.scope), end);
            return .{ .verified = .{ .snapshot = try copySnapshot(self.allocator, baseline), .changed = false, .observed_start_wall_us = clock.wall_us, .observed_wall_us = end } };
        }
        const units = try self.kernelUnits(token.operation, timingTransport(transport, token.scope), try self.clockAt(clock, &elapsed));
        var phase = std.time.Timer.start() catch return error.SystemError;
        self.work_messages = 0;
        self.live_bytes = 0;
        var progress = MutationProgress{};
        self.mutateExact(token, existing, units, &phase, &progress) catch |err| return .{ .uncertain = self.failure(.effect_dispatch, err, progress) };
        const observation_start = self.clockAt(clock, &elapsed) catch |err| return .{ .uncertain = self.failure(.effect_verify, err, progress) };
        var after = self.inspect() catch |err| return .{ .uncertain = self.failure(.effect_verify, err, progress) };
        const observation_end = self.clockAt(clock, &elapsed) catch |err| {
            after.deinit();
            return .{ .uncertain = self.failure(.effect_verify, err, progress) };
        };
        const after_entry = findEntry(after.entries, token.scope, token.effect_id) catch |err| {
            after.deinit();
            return .{ .uncertain = self.failure(.effect_verify, err, progress) };
        };
        if (after.state != .owned or !self.kernelMatches(token.operation, after_entry, observation_start, observation_end)) {
            after.deinit();
            return .{ .uncertain = self.failure(.effect_verify, error.Changed, progress) };
        }
        return .{ .verified = .{ .snapshot = after, .changed = true, .observed_start_wall_us = observation_start, .observed_wall_us = observation_end } };
    }
    pub fn withdrawBatch(self: *Inspector, tokens: []const DispatchToken, clock: ClockSample, baseline: *const Snapshot) Error!EffectResult {
        const transport = self.installation.transport;
        if (tokens.len > max_withdraw_messages) return error.LimitExceeded;
        for (tokens) |token| {
            try (DurableInstallationIntent{ .installation = token.installation, .intent_id = token.effect_id, .revision = token.aggregate_revision }).validate(self.installation);
            try validateRealizedScope(transport, token.scope);
            if (token.operation != .ensure_absent) return error.UnsupportedScope;
            _ = try self.kernelUnits(token.operation, timingTransport(transport, token.scope), clock.wall_us);
        }
        if (!mem.eql(u8, &baseline.installation.id, &self.installation.id) or baseline.installation.transport != transport or baseline.state != .owned) return error.InvalidInstallation;
        var elapsed = std.time.Timer.start() catch return error.SystemError;
        var phase = std.time.Timer.start() catch return error.SystemError;
        self.work_messages = 0;
        self.live_bytes = 0;
        var progress = MutationProgress{};
        self.withdrawEntries(tokens, baseline, &phase, &progress) catch |err| return .{ .uncertain = self.failure(.effect_dispatch, err, progress) };
        const observation_start = self.clockAt(clock, &elapsed) catch |err| return .{ .uncertain = self.failure(.effect_verify, err, progress) };
        var after = self.inspect() catch |err| return .{ .uncertain = self.failure(.effect_verify, err, progress) };
        const observation_end = self.clockAt(clock, &elapsed) catch |err| {
            after.deinit();
            return .{ .uncertain = self.failure(.effect_verify, err, progress) };
        };
        if (after.state != .owned) {
            after.deinit();
            return .{ .uncertain = self.failure(.effect_verify, error.Changed, progress) };
        }
        return .{ .verified = .{ .snapshot = after, .changed = progress.requested, .observed_start_wall_us = observation_start, .observed_wall_us = observation_end } };
    }
    fn withdrawEntries(self: *Inspector, tokens: []const DispatchToken, baseline: *const Snapshot, timer: *std.time.Timer, progress: *MutationProgress) Error!void {
        var present: [max_withdraw_messages]DispatchToken = undefined;
        var installed: [max_withdraw_messages]Entry = undefined;
        var present_count: usize = 0;
        for (tokens) |token| {
            installed[present_count] = try findEntry(baseline.entries, token.scope, token.effect_id) orelse continue;
            present[present_count] = token;
            present_count += 1;
        }
        if (present_count == 0) return;
        if (self.installation.transport != .nftables) {
            for (present[0..present_count], installed[0..present_count]) |token, entry| try self.mutateExact(token, entry, 0, timer, progress);
            return;
        }
        return self.withdrawNft(present[0..present_count], timer, progress);
    }
    pub fn installBatch(self: *Inspector, tokens: []const DispatchToken, clock: ClockSample, baseline: *const Snapshot) Error!InstallOutcome {
        const transport = self.installation.transport;
        if (tokens.len == 0 or tokens.len > max_install_messages) return error.LimitExceeded;
        for (tokens) |token| {
            try (DurableInstallationIntent{ .installation = token.installation, .intent_id = token.effect_id, .revision = token.aggregate_revision }).validate(self.installation);
            try validateRealizedScope(transport, token.scope);
            if (token.operation != .ensure_present) return error.UnsupportedScope;
            _ = try legacyAddress(token.scope);
            _ = try self.kernelUnits(token.operation, timingTransport(transport, token.scope), clock.wall_us);
        }
        if (!mem.eql(u8, &baseline.installation.id, &self.installation.id) or baseline.installation.transport != transport or baseline.state != .owned) return error.InvalidInstallation;
        var elapsed = std.time.Timer.start() catch return error.SystemError;
        var phase = std.time.Timer.start() catch return error.SystemError;
        self.work_messages = 0;
        self.live_bytes = 0;
        var progress = MutationProgress{};
        const sent_wall_us = self.clockAt(clock, &elapsed) catch |err| return .{ .result = .{ .uncertain = self.failure(.effect_dispatch, err, progress) }, .consumed = tokens.len };
        const installed = switch (transport) {
            .nftables => self.installNft(tokens, clock, baseline, &elapsed, &phase, &progress),
            .ipset => self.installIpset(tokens, clock, &elapsed, &phase, &progress),
            .iptables => self.installIptables(tokens, baseline, &phase, &progress),
        };
        const consumed = installed catch |err| return .{ .result = .{ .uncertain = self.failure(.effect_dispatch, err, progress) }, .consumed = tokens.len };
        const observation_start = self.clockAt(clock, &elapsed) catch |err| return .{ .result = .{ .uncertain = self.failure(.effect_verify, err, progress) }, .consumed = consumed };
        if (transport == .nftables) return .{
            .result = .{ .acknowledged = .{ .sent_wall_us = sent_wall_us, .acked_wall_us = observation_start, .port_id = self.last_install_port } },
            .consumed = consumed,
        };
        var after = self.inspect() catch |err| return .{ .result = .{ .uncertain = self.failure(.effect_verify, err, progress) }, .consumed = consumed };
        var transferred = false;
        defer if (!transferred) after.deinit();
        const observation_end = self.clockAt(clock, &elapsed) catch |err| return .{ .result = .{ .uncertain = self.failure(.effect_verify, err, progress) }, .consumed = consumed };
        if (after.state != .owned) return .{ .result = .{ .uncertain = self.failure(.effect_verify, error.Changed, progress) }, .consumed = consumed };
        for (tokens[0..consumed]) |token| {
            const entry = findEntry(after.entries, token.scope, token.effect_id) catch |err| return .{ .result = .{ .uncertain = self.failure(.effect_verify, err, progress) }, .consumed = consumed };
            if (!self.kernelMatches(token.operation, entry, observation_start, observation_end)) return .{
                .result = .{ .uncertain = self.failure(.effect_verify, error.Changed, progress) },
                .consumed = consumed,
            };
        }
        transferred = true;
        return .{ .result = .{ .verified = .{ .snapshot = after, .changed = true, .observed_start_wall_us = observation_start, .observed_wall_us = observation_end } }, .consumed = consumed };
    }
    fn failure(self: *const Inspector, stage: OperationStage, cause: Error, progress: MutationProgress) FailureContext {
        return .{
            .backend = self.installation.transport,
            .stage = stage,
            .cause = cause,
            .mutation = if (progress.requested) .outcome_uncertain else .not_started,
        };
    }

    pub fn afterMutation(self: *Inspector, count: usize) Error!void {
        if (comptime @import("builtin").is_test) {
            if (self.test_fault_after_mutations) |limit| if (count == limit) return error.Timeout;
        }
    }

    pub fn clockAt(self: *const Inspector, clock: ClockSample, timer: *std.time.Timer) Error!i64 {
        const elapsed = std.math.cast(i64, self.fromKernelUs(timer.read() / std.time.ns_per_us)) orelse return error.UnsupportedDeadline;
        return std.math.add(i64, clock.wall_us, elapsed) catch error.UnsupportedDeadline;
    }
    pub fn kernelUnits(self: *const Inspector, operation: EffectOperation, transport: Transport, now_us: i64) Error!u64 {
        return deadlineUnits(self.kernelOperation(operation, now_us), transport, now_us);
    }
    fn kernelMatches(self: *const Inspector, operation: EffectOperation, entry: ?Entry, start_us: i64, end_us: i64) bool {
        const transport = self.installation.transport;
        if (comptime build_options.diag) if (entry) |present| if (present.scope == null and end_us >= start_us) {
            const kernel_end = start_us + @as(i64, @intCast(self.toKernelUs(@intCast(end_us - start_us))));
            return effectMatches(self.kernelOperation(operation, start_us), transport, entry, start_us, kernel_end);
        };
        return effectMatches(operation, transport, entry, start_us, end_us);
    }
    // Why: Kernel timeouts run in real time, so under a diagnostic clock rate the span to the deadline is divided by that rate.
    fn kernelOperation(self: *const Inspector, operation: EffectOperation, anchor_us: i64) EffectOperation {
        if (comptime !build_options.diag) return operation;
        if (operation != .ensure_present or operation.ensure_present == .permanent) return operation;
        const deadline = operation.ensure_present.finite_deadline_us;
        if (deadline <= anchor_us) return operation;
        return .{ .ensure_present = .{ .finite_deadline_us = anchor_us + @as(i64, @intCast(self.toKernelUs(@intCast(deadline - anchor_us)))) } };
    }
    pub fn toKernelUs(self: *const Inspector, virtual_us: u64) u64 {
        if (comptime !build_options.diag) return virtual_us;
        if (self.clock_rate <= 1) return virtual_us;
        return virtual_us / self.clock_rate + @intFromBool(virtual_us % self.clock_rate != 0);
    }
    fn fromKernelUs(self: *const Inspector, kernel_us: u64) u64 {
        if (comptime !build_options.diag) return kernel_us;
        return if (self.clock_rate <= 1) kernel_us else kernel_us *| self.clock_rate;
    }

    pub fn inspect(self: *Inspector) Error!Snapshot {
        const diag_span = if (comptime build_options.diag) diag_mod.enter(.dump) else {};
        defer if (comptime build_options.diag) diag_mod.leave(diag_span);
        const held = self.retained_bytes;
        defer self.retained_bytes = held;
        var timer = std.time.Timer.start() catch return error.SystemError;
        // Why: A netlink dump detects a moved generation itself; tool output has none, so it is read twice and compared.
        if (self.installation.transport == .nftables) return self.readCoherent(&timer);
        self.work_messages = 0;
        var first = try self.readOnce(&timer);
        defer first.snapshot.deinit();
        self.retained_bytes = held + first.snapshot.entries.len * @sizeOf(Entry);
        if (comptime @import("builtin").is_test) {
            if (self.test_between_reads) |hook| hook(self);
        }
        var second = try self.readOnce(&timer);
        errdefer second.snapshot.deinit();
        if (!mem.eql(u8, &first.structure, &second.structure)) return error.Changed;
        if (!sameEntries(first.snapshot.entries, second.snapshot.entries, null, second.snapshot.observed_end_ns - first.snapshot.observed_start_ns, self.installation.transport)) return error.Changed;
        second.snapshot.structure_proof = if (second.snapshot.state == .owned) .exact_v1 else .unverified;
        second.snapshot.observed_start_ns = first.snapshot.observed_start_ns;
        return second.snapshot;
    }
    // Holds: Only DumpInterrupted is retried, at most max_dump_attempts reads in all, each with a fresh work count.
    fn readCoherent(self: *Inspector, timer: *std.time.Timer) Error!Snapshot {
        var attempt: usize = 1;
        while (true) : (attempt += 1) {
            self.work_messages = 0;
            var reading = self.readOnce(timer) catch |err| {
                if (err != error.DumpInterrupted) return err;
                self.dump_interruptions += 1;
                if (attempt == max_dump_attempts) return err;
                continue;
            };
            reading.snapshot.structure_proof = if (reading.snapshot.state == .owned) .exact_v1 else .unverified;
            return reading.snapshot;
        }
    }
    const Reading = struct { snapshot: Snapshot, structure: [32]u8 };
    fn readOnce(self: *Inspector, timer: *std.time.Timer) Error!Reading {
        var limits = self.limits;
        if (self.retained_bytes >= limits.max_bytes) return error.LimitExceeded;
        limits.max_bytes -= self.retained_bytes;
        var builder = Builder.init(self.allocator, self.installation, limits);
        defer builder.deinit();
        const start = timer.read();
        switch (self.installation.transport) {
            .nftables => try readNft(self, &builder, timer),
            .iptables, .ipset => try readTools(self, &builder, timer),
        }
        try self.checkTime(timer);
        const structure = builder.structureDigest();
        return .{ .snapshot = try builder.finish(start, timer.read()), .structure = structure };
    }
    pub fn checkTime(self: *Inspector, timer: *std.time.Timer) Error!void {
        _ = try self.remainingMs(timer);
    }
    pub fn remainingMs(self: *Inspector, timer: *std.time.Timer) Error!u64 {
        const elapsed = timer.read() / std.time.ns_per_ms;
        if (elapsed >= self.limits.timeout_ms) return error.Timeout;
        return self.limits.timeout_ms - elapsed;
    }
    pub fn chargeMessages(self: *Inspector, count: usize) Error!void {
        if (count > self.limits.max_messages - self.work_messages) return error.LimitExceeded;
        self.work_messages += count;
    }
    pub fn run(self: *Inspector, argv: []const []const u8, timer: *std.time.Timer) Error!command.Result {
        return self.runTracked(argv, timer, null);
    }
    pub fn runTracked(self: *Inspector, argv: []const []const u8, timer: *std.time.Timer, progress: ?*MutationProgress) Error!command.Result {
        return self.runTool(argv, null, timer, progress);
    }
    pub fn runTool(self: *Inspector, argv: []const []const u8, input: ?[]const u8, timer: *std.time.Timer, progress: ?*MutationProgress) Error!command.Result {
        try self.checkTime(timer);
        std.fs.accessAbsolute(argv[0], .{}) catch return error.ToolUnavailable;
        const remaining = try self.remainingMs(timer);
        const reserved = self.retained_bytes + self.live_bytes;
        if (reserved >= self.limits.max_bytes) return error.LimitExceeded;
        const allowance = (self.limits.max_bytes - reserved) / 4;
        if (progress) |value| value.requested = true;
        const result = (if (input) |bytes|
            command.runBoundedInput(self.allocator, argv, bytes, @min(remaining, 2000), @min(allowance, command.max_stdout_bytes), @min(allowance, 4096))
        else
            command.runBounded(self.allocator, argv, @min(remaining, 2000), @min(allowance, command.max_stdout_bytes), @min(allowance, 4096))) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.PermissionDenied => error.PermissionDenied,
            error.Timeout => error.Timeout,
            error.OutputLimit => error.LimitExceeded,
            error.SpawnFailed => error.ToolUnavailable,
            else => error.SystemError,
        };
        errdefer result.deinit(self.allocator);
        if (result.stdout.len > self.limits.max_bytes - self.retained_bytes) return error.LimitExceeded;
        try self.chargeMessages(mem.count(u8, result.stdout, "\n"));
        if (result.code != 0) {
            if (std.ascii.indexOfIgnoreCase(result.stderr, "permission denied") != null or
                std.ascii.indexOfIgnoreCase(result.stderr, "operation not permitted") != null) return error.PermissionDenied;
            return error.UnknownState;
        }
        return result;
    }

    pub usingnamespace @import("inspection_nft_change.zig").Methods(@This());

    pub usingnamespace @import("inspection_tool_change.zig").Methods(@This());
};

pub fn reservedName(name: []const u8) bool {
    return std.ascii.startsWithIgnoreCase(name, "f2z_") or std.ascii.startsWithIgnoreCase(name, "fail2zig");
}

fn copySnapshot(allocator: mem.Allocator, source: *const Snapshot) Error!Snapshot {
    var copy = source.*;
    copy.allocator = allocator;
    copy.entries = try allocator.dupe(Entry, source.entries);
    copy.capacity = copy.entries.len;
    return copy;
}

const Self = @This();
pub const TestAccess = if (@import("builtin").is_test) struct {
    pub const builderInit = Self.Builder.init;
    pub const builderDeinit = Self.Builder.deinit;
    pub const builderAdd = Self.Builder.add;
    pub const builderFinish = Self.Builder.finish;
    pub const tokensParse = Self.Tokens.parse;
    pub const attrMapParse = Self.AttrMap.parse;
    pub const nftSetAttrs = Self.nftSetAttrs;
    pub const buildFixedScopedArgv = Self.buildFixedScopedArgv;
    pub const parseIptables = Self.parseIptables;
    pub const parseIpset = Self.parseIpset;
    pub const deadlineUnits = Self.deadlineUnits;
    pub const effectMatches = Self.effectMatches;
    pub const scanSavedTables = Self.scanSavedTables;
    pub const entryScope = Self.entryScope;
    pub const findEntry = Self.findEntry;
} else struct {};

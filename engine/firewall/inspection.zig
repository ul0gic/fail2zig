// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const shared = @import("shared");
const nl = @import("netlink.zig");
const nft = @import("nftables.zig");
const command = @import("command.zig");
const linux = std.os.linux;
const mem = std.mem;

pub const Transport = enum { nftables, iptables, ipset };
pub const canonical_scope = @import("scope.zig");
pub const CanonicalScope = canonical_scope.Scope;
pub const Error = error{ UnknownState, ForeignState, Incomplete, Changed, DumpInterrupted, LimitExceeded, UnsupportedScope, ExpiredIntent, UnsupportedDeadline, InvalidInstallation, ToolUnavailable, PermissionDenied, Timeout, OutOfMemory, SystemError };
pub const OperationStage = enum { admission_probe, admission_dispatch, admission_verify, readback, effect_dispatch, effect_verify };
pub const MutationDisposition = enum { not_started, outcome_uncertain };
pub const FailureContext = struct {
    backend: Transport,
    stage: OperationStage,
    cause: Error,
    mutation: MutationDisposition,
};

const MutationProgress = struct { requested: bool = false };

pub fn validateCanonicalScope(_: Transport, scope: CanonicalScope) Error!void {
    scope.validate() catch return error.UnsupportedScope;
}
fn validateRealizedScope(transport: Transport, scope: CanonicalScope) Error!void {
    try validateCanonicalScope(transport, scope);
}

fn subjectAddress(subject: canonical_scope.Subject) shared.IpAddress {
    return switch (subject.family) {
        .v4 => .{ .ipv4 = mem.readInt(u32, subject.address[0..4], .big) },
        .v6 => .{ .ipv6 = mem.readInt(u128, &subject.address, .big) },
    };
}

fn legacyAddress(scope: CanonicalScope) Error!shared.IpAddress {
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

/// The largest inventory any `Limits` admits.
pub const max_inventory_entries: usize = 65_536;
/// Readings of one nftables inventory before an interrupted dump is reported.
const max_dump_attempts: usize = 3;
pub const Limits = struct {
    max_entries: usize = max_inventory_entries,
    max_bytes: usize = 16 * 1024 * 1024,
    max_messages: usize = 65_536,
    timeout_ms: u64 = 5000,
    pub fn validate(self: Limits) Error!void {
        if (self.max_entries == 0 or self.max_entries > max_inventory_entries or self.max_bytes == 0 or
            self.max_bytes > 16 * 1024 * 1024 or self.max_messages == 0 or self.max_messages > 65_536 or
            self.timeout_ms == 0 or self.timeout_ms > 5000) return error.LimitExceeded;
    }
};
pub const Entry = struct {
    address: shared.IpAddress,
    scope: ?CanonicalScope = null,
    remaining_ms: ?u64 = null,
    deadline_us: ?i64 = null,
    effect_id: ?[32]u8 = null,
    /// A validated owned scoped group with parts missing, repeated or dated
    /// differently: still ours, never a match, so the entry is re-dispatched.
    partial: bool = false,
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
    fingerprint: [32]u8,
    // Only a complete, stable inspector readback establishes this scaffold proof.
    structure_proof: StructureProof = .unverified,
    observed_start_ns: u64,
    observed_end_ns: u64,
    pub fn deinit(self: *Snapshot) void {
        self.allocator.free(self.entries);
        self.* = undefined;
    }
    /// Position of the entry for exactly `scope`, if installed.
    pub fn find(self: *const Snapshot, scope: CanonicalScope) Error!?usize {
        return entryIndex(self.entries, scope);
    }
    pub fn page(self: *const Snapshot, offset: usize) Error![]const Entry {
        if (offset > self.entries.len) return error.Incomplete;
        return self.entries[offset..@min(self.entries.len, offset + @min(@as(usize, 64), self.entries.len - offset))];
    }
};

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
    /// `snapshot` was read within [observed_start_wall_us, observed_wall_us].
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
    ipset_path: []const u8 = "/usr/sbin/ipset",
    iptables_legacy_save_path: []const u8 = "/usr/sbin/iptables-legacy-save",
    ip6tables_legacy_save_path: []const u8 = "/usr/sbin/ip6tables-legacy-save",
    work_messages: usize = 0,
    retained_bytes: usize = 0,
    live_bytes: usize = 0,
    /// nftables dumps the kernel flagged as interrupted, including those retried at once.
    dump_interruptions: u64 = 0,
    test_fault_after_mutations: if (@import("builtin").is_test) ?usize else void = if (@import("builtin").is_test) null else {},
    test_fault_readback: if (@import("builtin").is_test) ?Error else void = if (@import("builtin").is_test) null else {},
    /// Runs between the two passes of a tool-transport inventory read only.
    test_between_reads: if (@import("builtin").is_test) ?*const fn (*Inspector) void else void = if (@import("builtin").is_test) null else {},
    /// Inventory reads started, one per `inspect` call, including those inside `applyExact`.
    test_inspections: if (@import("builtin").is_test) usize else void = if (@import("builtin").is_test) 0 else {},

    pub fn open(allocator: mem.Allocator, installation: Installation, limits: Limits) Error!Inspector {
        try installation.validate();
        try limits.validate();
        return .{ .allocator = allocator, .installation = installation, .limits = limits };
    }
    pub fn close(_: *Inspector) void {}

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
        const end = try clockAt(clock, &elapsed);
        return .{ .snapshot = snapshot, .matches_desired = effectMatches(token.operation, self.installation.transport, try findEntry(snapshot.entries, token.scope, token.effect_id), clock.wall_us, end), .observed_wall_us = end };
    }

    pub fn matchesSnapshot(self: *const Inspector, snapshot: *const Snapshot, token: DispatchToken, wall_start_us: i64, wall_end_us: i64) Error!bool {
        try (DurableInstallationIntent{ .installation = token.installation, .intent_id = token.effect_id, .revision = token.aggregate_revision }).validate(self.installation);
        try validateRealizedScope(self.installation.transport, token.scope);
        if (!mem.eql(u8, &snapshot.installation.id, &self.installation.id) or snapshot.installation.transport != self.installation.transport or snapshot.state != .owned) return error.InvalidInstallation;
        if (wall_start_us < 0 or wall_end_us < wall_start_us) return error.UnsupportedDeadline;
        const wall_duration: u64 = @intCast(wall_end_us - wall_start_us);
        if (wall_duration > self.limits.timeout_ms * 1000 or snapshot.observed_end_ns < snapshot.observed_start_ns or
            snapshot.observed_end_ns > self.limits.timeout_ms * std.time.ns_per_ms) return error.Incomplete;
        if (wall_duration < (snapshot.observed_end_ns - snapshot.observed_start_ns) / std.time.ns_per_us) return error.Incomplete;
        if (snapshot.entries.len > self.limits.max_entries or snapshot.entries.len > self.limits.max_bytes / @sizeOf(Entry)) return error.LimitExceeded;
        return effectMatches(token.operation, self.installation.transport, try findEntry(snapshot.entries, token.scope, token.effect_id), wall_start_us, wall_end_us);
    }

    /// Reads the inventory and applies from it. Tool transports use this path: a stale
    /// `existed` there would produce a duplicate insert, not a rejected batch.
    pub fn applyExact(self: *Inspector, token: DispatchToken, clock: ClockSample) Error!EffectResult {
        try (DurableInstallationIntent{ .installation = token.installation, .intent_id = token.effect_id, .revision = token.aggregate_revision }).validate(self.installation);
        try validateRealizedScope(self.installation.transport, token.scope);
        _ = try deadlineUnits(token.operation, timingTransport(self.installation.transport, token.scope), clock.wall_us);
        var elapsed = std.time.Timer.start() catch return error.SystemError;
        var baseline = try self.inspect();
        defer baseline.deinit();
        // The pre-read is held across the mutation and its readback, so it stays charged.
        const held = self.retained_bytes;
        self.retained_bytes = held + baseline.entries.len * @sizeOf(Entry);
        defer self.retained_bytes = held;
        var result = try self.applyFromBaseline(token, .{ .wall_us = try clockAt(clock, &elapsed) }, &baseline);
        // A no-op was judged from the pre-read, which this call observed from its start.
        if (result == .verified and !result.verified.changed) result.verified.observed_start_wall_us = clock.wall_us;
        return result;
    }

    /// The single mutate-and-verify path. `baseline` is the caller's accepted readback of
    /// this installation: it decides whether the entry exists and whether the desired
    /// state already holds. The caller keeps ownership of `baseline` and, when it holds
    /// it across calls, has charged it to `retained_bytes` itself. A no-op returns
    /// `changed = false` with a copy of `baseline` that the caller owns, observed over
    /// this call's window. Otherwise the kernel is mutated and exactly one readback is
    /// returned, judged for the target scope only; any other difference from the
    /// baseline is kernel expiry or foreign change, which the next readback classifies.
    /// A batch the kernel rejected whole is `error.Changed` with `mutation = .not_started`.
    pub fn applyFromBaseline(self: *Inspector, token: DispatchToken, clock: ClockSample, baseline: *const Snapshot) Error!EffectResult {
        try (DurableInstallationIntent{ .installation = token.installation, .intent_id = token.effect_id, .revision = token.aggregate_revision }).validate(self.installation);
        const transport = self.installation.transport;
        try validateRealizedScope(transport, token.scope);
        _ = try deadlineUnits(token.operation, timingTransport(transport, token.scope), clock.wall_us);
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
            const end = try clockAt(clock, &elapsed);
            _ = try deadlineUnits(token.operation, timingTransport(transport, token.scope), end);
            return .{ .verified = .{ .snapshot = try copySnapshot(self.allocator, baseline), .changed = false, .observed_start_wall_us = clock.wall_us, .observed_wall_us = end } };
        }
        const units = try deadlineUnits(token.operation, timingTransport(transport, token.scope), try clockAt(clock, &elapsed));
        var phase = std.time.Timer.start() catch return error.SystemError;
        self.work_messages = 0;
        self.live_bytes = 0;
        var progress = MutationProgress{};
        self.mutateExact(token, existing, units, &phase, &progress) catch |err| return .{ .uncertain = self.failure(.effect_dispatch, err, progress) };
        const observation_start = clockAt(clock, &elapsed) catch |err| return .{ .uncertain = self.failure(.effect_verify, err, progress) };
        var after = self.inspect() catch |err| return .{ .uncertain = self.failure(.effect_verify, err, progress) };
        const observation_end = clockAt(clock, &elapsed) catch |err| {
            after.deinit();
            return .{ .uncertain = self.failure(.effect_verify, err, progress) };
        };
        const after_entry = findEntry(after.entries, token.scope, token.effect_id) catch |err| {
            after.deinit();
            return .{ .uncertain = self.failure(.effect_verify, err, progress) };
        };
        if (after.state != .owned or !effectMatches(token.operation, transport, after_entry, observation_start, observation_end)) {
            after.deinit();
            return .{ .uncertain = self.failure(.effect_verify, error.Changed, progress) };
        }
        return .{ .verified = .{ .snapshot = after, .changed = true, .observed_start_wall_us = observation_start, .observed_wall_us = observation_end } };
    }
    fn failure(self: *const Inspector, stage: OperationStage, cause: Error, progress: MutationProgress) FailureContext {
        return .{
            .backend = self.installation.transport,
            .stage = stage,
            .cause = cause,
            .mutation = if (progress.requested) .outcome_uncertain else .not_started,
        };
    }

    fn mutateExact(self: *Inspector, token: DispatchToken, existing: ?Entry, units: u64, timer: *std.time.Timer, progress: *MutationProgress) Error!void {
        var name_buf: [28]u8 = undefined;
        const name = self.installation.name(&name_buf);
        if (self.installation.transport == .nftables) {
            try self.mutateNft(token, name, existing != null, units, timer, progress);
            try self.afterMutation(1);
            return;
        }
        const scoped_address = legacyAddress(token.scope) catch return self.mutateFixedScoped(token, name, timer, progress);
        var address_buf: [64]u8 = undefined;
        const address = std.fmt.bufPrint(&address_buf, "{}", .{scoped_address}) catch return error.UnsupportedScope;
        var count: usize = 0;
        if (self.installation.transport == .ipset) {
            var set_buf: [31]u8 = undefined;
            const set = try setName(name, scoped_address == .ipv6, &set_buf);
            if (token.operation == .ensure_absent) {
                try self.mutateCommand(&.{ self.ipset_path, "del", set, address }, timer, &count, progress);
            } else {
                var timeout_buf: [24]u8 = undefined;
                const timeout = std.fmt.bufPrint(&timeout_buf, "{d}", .{units}) catch return error.UnsupportedDeadline;
                try self.mutateCommand(&.{ self.ipset_path, "add", set, address, "timeout", timeout, "-exist" }, timer, &count, progress);
            }
        } else {
            const binary = if (scoped_address == .ipv4) self.iptables_path else self.ip6tables_path;
            if (token.operation == .ensure_absent) try self.mutateCommand(&.{ binary, "-w", "1", "-D", name, "-s", address, "-j", "DROP" }, timer, &count, progress) else try self.mutateCommand(&.{ binary, "-w", "1", "-I", name, "1", "-s", address, "-j", "DROP" }, timer, &count, progress);
        }
    }
    /// Converges one scoped effect's fixed-argv rules from whatever validated owned state
    /// the chain holds: every missing part of the wanted metadata is inserted first, then
    /// every rule of the effect with other metadata, and every repeated part, is deleted,
    /// so protection never lapses across a renewal. Each invocation is bounded by the
    /// call's timer; a failure after the first one is an uncertain outcome whose readback
    /// shows the partial entry for the next dispatch.
    fn mutateFixedScoped(self: *Inspector, token: DispatchToken, name: []const u8, timer: *std.time.Timer, progress: *MutationProgress) Error!void {
        const v6 = token.scope.subject.family == .v6;
        const binary = if (v6) self.ip6tables_path else self.iptables_path;
        const part_count = nft.scopeRulePartCount(token.scope) catch return error.UnsupportedScope;
        const installed = try self.listFixedScoped(token, name, binary, v6, timer);
        var metadata = ScopedRuleMetadata{ .effect_id = token.effect_id, .part = 0, .count = @intCast(part_count), .deadline_us = null, .scope = token.scope };
        var mutations: usize = 0;
        if (token.operation == .ensure_present) {
            metadata.deadline_us = leaseDeadline(token.operation.ensure_present);
            for (0..part_count) |part| {
                if (installed.count(metadata.deadline_us, part) != 0) continue;
                metadata.part = @intCast(part);
                try self.runFixedScoped(binary, name, metadata, .insert, timer, &mutations, progress);
            }
        }
        for (installed.variants[0..installed.len]) |variant| {
            const kept: u16 = @intFromBool(token.operation == .ensure_present and variant.deadline_us == leaseDeadline(token.operation.ensure_present));
            metadata.deadline_us = variant.deadline_us;
            for (0..part_count) |part| {
                if (variant.counts[part] <= kept) continue;
                metadata.part = @intCast(part);
                for (0..variant.counts[part] - kept) |_| try self.runFixedScoped(binary, name, metadata, .delete, timer, &mutations, progress);
            }
        }
        if (mutations == 0) return error.Changed;
    }
    fn runFixedScoped(self: *Inspector, binary: []const u8, chain: []const u8, metadata: ScopedRuleMetadata, operation: FixedScopedOperation, timer: *std.time.Timer, mutations: *usize, progress: *MutationProgress) Error!void {
        var argv: [24][]const u8 = undefined;
        var subject_buf: [64]u8 = undefined;
        var port_buf: [16]u8 = undefined;
        var comment_buf: [scoped_comment_bytes]u8 = undefined;
        try self.mutateCommand(try buildFixedScopedArgv(&argv, &subject_buf, &port_buf, &comment_buf, binary, chain, metadata, operation), timer, mutations, progress);
    }
    /// The effect's rules as `iptables -S` lists them now, validated exactly as the
    /// readback validates them, so a stale baseline can only add or remove work here.
    fn listFixedScoped(self: *Inspector, token: DispatchToken, name: []const u8, binary: []const u8, v6: bool, timer: *std.time.Timer) Error!FixedScopedVariants {
        const result = try self.run(&.{ binary, "-w", "1", "-S" }, timer);
        defer result.deinit(self.allocator);
        if (result.stdout.len == 0 or result.stdout[result.stdout.len - 1] != '\n') return error.Incomplete;
        var found = FixedScopedVariants{};
        var lines = mem.splitScalar(u8, result.stdout, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            const t = try Tokens.parse(line);
            if (t.count < 2) return error.UnknownState;
            if (!mem.eql(u8, t.values[0], "-A") or !mem.eql(u8, t.values[1], name)) continue;
            const metadata = (try fixedScopedMetadata(t, name, v6)) orelse continue;
            if (!mem.eql(u8, &metadata.effect_id, &token.effect_id)) continue;
            if (!std.meta.eql(metadata.scope, token.scope)) return error.ForeignState;
            found.note(metadata.deadline_us, metadata.part);
        }
        return found;
    }
    fn mutateNft(self: *Inspector, token: DispatchToken, name: []const u8, existed: bool, timeout_ms: u64, timer: *std.time.Timer, progress: *MutationProgress) Error!void {
        if (legacyAddress(token.scope)) |_| return self.mutateLegacyNft(token, name, existed, timeout_ms, timer, progress) else |_| {}
        return self.mutateScopedNft(token, name, timer, progress);
    }
    fn mutateLegacyNft(self: *Inspector, token: DispatchToken, name: []const u8, existed: bool, timeout_ms: u64, timer: *std.time.Timer, progress: *MutationProgress) Error!void {
        var sock = nl.NetlinkSocket.init(linux.NETLINK.NETFILTER) catch |err| return netlinkError(err);
        defer sock.close();
        var key_buf: [16]u8 = undefined;
        const scoped_address = try legacyAddress(token.scope);
        const key: []const u8 = switch (scoped_address) {
            .ipv4 => |v| blk: {
                mem.writeInt(u32, key_buf[0..4], v, .big);
                break :blk key_buf[0..4];
            },
            .ipv6 => |v| blk: {
                mem.writeInt(u128, &key_buf, v, .big);
                break :blk &key_buf;
            },
        };
        const set = if (scoped_address == .ipv4) "banned_ipv4" else "banned_ipv6";
        var payloads: [2][512]u8 align(4) = undefined;
        var batch_buf: [2048]u8 align(4) = undefined;
        var batch = nl.Batch.init(&batch_buf);
        var related: [4]u32 = undefined;
        related[0] = sock.nextSeq();
        batch.begin(related[0], sock.port_id, nl.NFNL.SUBSYS_NFTABLES) catch |err| return netlinkError(err);
        var count: usize = 1;
        if (existed) {
            const payload = nft.buildSetElemDelPayload(&payloads[0], nl.NFPROTO.INET, name, set, key) catch |err| return netlinkError(err);
            related[count] = sock.nextSeq();
            count += 1;
            batch.add(nl.nfnlMsgType(nl.NFNL.SUBSYS_NFTABLES, nft.NFT_MSG.DELSETELEM), linux.NLM_F_REQUEST | linux.NLM_F_ACK, related[count - 1], sock.port_id, payload) catch |err| return netlinkError(err);
        }
        if (token.operation == .ensure_present) {
            const payload = nft.buildSetElemAddPayload(&payloads[1], nl.NFPROTO.INET, name, set, key, timeout_ms) catch |err| return netlinkError(err);
            related[count] = sock.nextSeq();
            count += 1;
            batch.add(nl.nfnlMsgType(nl.NFNL.SUBSYS_NFTABLES, nft.NFT_MSG.NEWSETELEM), linux.NLM_F_REQUEST | linux.NLM_F_ACK | linux.NLM_F_CREATE | linux.NLM_F_EXCL, related[count - 1], sock.port_id, payload) catch |err| return netlinkError(err);
        }
        related[count] = sock.nextSeq();
        const bytes = batch.commit(related[count], sock.port_id, nl.NFNL.SUBSYS_NFTABLES) catch |err| return netlinkError(err);
        const send_timeout = @min(try self.remainingMs(timer), 2000);
        progress.requested = true;
        nl.sendKernel(&sock, bytes, send_timeout) catch |err| return netlinkError(err);
        nl.receiveAcknowledgments(&sock, related[1..count], related[0 .. count + 1], @min(try self.remainingMs(timer), 2000)) catch |err| return rejectedBatch(err, progress);
    }

    /// Converges one scoped effect in a single atomic batch: every validated owned rule
    /// carrying the effect id is deleted, whatever its part or deadline, and all wanted
    /// parts are added. The batch acknowledges at most 64 messages, so the handles
    /// deleted per dispatch are bounded to one group's worth; any beyond that stay a
    /// partial entry in the readback and the next dispatch removes them.
    fn mutateScopedNft(self: *Inspector, token: DispatchToken, name: []const u8, timer: *std.time.Timer, progress: *MutationProgress) Error!void {
        const part_count = nft.scopeRulePartCount(token.scope) catch |err| return scopeBuildError(err);
        if (part_count > nft.max_scope_rule_parts) return error.LimitExceeded;
        var sock = nl.NetlinkSocket.init(linux.NETLINK.NETFILTER) catch |err| return netlinkError(err);
        defer sock.close();

        var request_buf: [256]u8 align(4) = undefined;
        const request = nft.buildTablePayload(&request_buf, nl.NFPROTO.INET, name) catch |err| return netlinkError(err);
        var rules = try dump(self, &sock, nft.NFT_MSG.GETRULE, nft.NFT_MSG.NEWRULE, request, timer, 0);
        defer rules.deinit();
        var handles: [nft.max_scope_rule_parts]u64 = undefined;
        var handle_count: usize = 0;
        for (rules.values.items) |payload| {
            const attributes = try payloadAttrs(payload, &.{ 1, 2, 3, 4, 6, 7, 8 });
            if (!mem.eql(u8, try attributes.text(1), name) or !mem.eql(u8, try attributes.text(2), "input") or attributes.values[7] == null) continue;
            const metadata = try ScopedRuleMetadata.decode(try attributes.get(7));
            if (!mem.eql(u8, &metadata.effect_id, &token.effect_id)) continue;
            if (!std.meta.eql(metadata.scope, token.scope)) return error.ForeignState;
            try validateScopedDropRule(name, attributes, metadata);
            const handle = try attributes.number(u64, 3);
            if (handle == 0) return error.UnknownState;
            if (handle_count == handles.len) continue;
            handles[handle_count] = handle;
            handle_count += 1;
        }

        var payloads: [nft.max_scope_rule_parts * 2][2048]u8 align(4) = undefined;
        var batch_bytes: [128 * 1024]u8 align(4) = undefined;
        var related: [nft.max_scope_rule_parts * 2 + 2]u32 = undefined;
        var batch = nl.Batch.init(&batch_bytes);
        related[0] = sock.nextSeq();
        batch.begin(related[0], sock.port_id, nl.NFNL.SUBSYS_NFTABLES) catch |err| return netlinkError(err);
        var count: usize = 1;
        for (handles[0..handle_count], 0..) |handle, index| {
            const payload = nft.buildRuleDeletePayload(&payloads[index], name, "input", handle) catch |err| return netlinkError(err);
            related[count] = sock.nextSeq();
            batch.add(nl.nfnlMsgType(nl.NFNL.SUBSYS_NFTABLES, nft.NFT_MSG.DELRULE), linux.NLM_F_REQUEST | linux.NLM_F_ACK, related[count], sock.port_id, payload) catch |err| return netlinkError(err);
            count += 1;
        }
        if (token.operation == .ensure_present) {
            const deadline = leaseDeadline(token.operation.ensure_present);
            for (0..part_count) |part| {
                const metadata = ScopedRuleMetadata{ .effect_id = token.effect_id, .part = @intCast(part), .count = @intCast(part_count), .deadline_us = deadline, .scope = token.scope };
                const userdata = try metadata.encode();
                const payload = nft.buildScopedDropRulePayload(&payloads[handle_count + part], name, "input", token.scope, part, &userdata) catch |err| return scopeBuildError(err);
                related[count] = sock.nextSeq();
                batch.add(nl.nfnlMsgType(nl.NFNL.SUBSYS_NFTABLES, nft.NFT_MSG.NEWRULE), linux.NLM_F_REQUEST | linux.NLM_F_ACK | linux.NLM_F_CREATE | linux.NLM_F_EXCL | 0x800, related[count], sock.port_id, payload) catch |err| return netlinkError(err);
                count += 1;
            }
        }
        // Nothing to delete and nothing to add: the baseline's `existed` was stale.
        if (count == 1) return error.Changed;
        related[count] = sock.nextSeq();
        const bytes = batch.commit(related[count], sock.port_id, nl.NFNL.SUBSYS_NFTABLES) catch |err| return netlinkError(err);
        const send_timeout = @min(try self.remainingMs(timer), 2000);
        progress.requested = true;
        nl.sendKernel(&sock, bytes, send_timeout) catch |err| return netlinkError(err);
        nl.receiveAcknowledgments(&sock, related[1..count], related[0 .. count + 1], @min(try self.remainingMs(timer), 2000)) catch |err| return rejectedBatch(err, progress);
    }

    fn afterMutation(self: *Inspector, count: usize) Error!void {
        if (comptime @import("builtin").is_test) {
            if (self.test_fault_after_mutations) |limit| if (count == limit) return error.Timeout;
        }
    }
    fn mutateCommand(self: *Inspector, argv: []const []const u8, timer: *std.time.Timer, count: *usize, progress: *MutationProgress) Error!void {
        const result = try self.runTracked(argv, timer, progress);
        defer result.deinit(self.allocator);
        if (result.stdout.len != 0) return error.UnknownState;
        count.* += 1;
        try self.afterMutation(count.*);
    }
    fn createInstallation(self: *Inspector, timer: *std.time.Timer, progress: *MutationProgress) Error!void {
        var name_buf: [28]u8 = undefined;
        const name = self.installation.name(&name_buf);
        var marker_buf: [44]u8 = undefined;
        const marker = self.installation.marker(&marker_buf);
        if (self.installation.transport == .nftables) {
            try self.createNft(name, marker, timer, progress);
            try self.afterMutation(1);
            return;
        }
        var mutations: usize = 0;
        for ([_][]const u8{ self.iptables_path, self.ip6tables_path }, 0..) |binary, index| {
            try self.mutateCommand(&.{ binary, "-w", "1", "-N", name }, timer, &mutations, progress);
            try self.mutateCommand(&.{ binary, "-w", "1", "-A", name, "-m", "comment", "--comment", marker, "-j", "RETURN" }, timer, &mutations, progress);
            if (self.installation.transport == .ipset) {
                var set_buf: [31]u8 = undefined;
                const set = try setName(name, index == 1, &set_buf);
                try self.mutateCommand(&.{ self.ipset_path, "create", set, "hash:ip", "family", if (index == 0) "inet" else "inet6", "timeout", "0", "maxelem", "65536" }, timer, &mutations, progress);
                try self.mutateCommand(&.{ binary, "-w", "1", "-I", name, "1", "-m", "set", "--match-set", set, "src", "-j", "DROP" }, timer, &mutations, progress);
            }
            try self.mutateCommand(&.{ binary, "-w", "1", "-I", "INPUT", "1", "-m", "comment", "--comment", marker, "-j", name }, timer, &mutations, progress);
        }
    }
    fn createNft(self: *Inspector, name: []const u8, marker: []const u8, timer: *std.time.Timer, progress: *MutationProgress) Error!void {
        var sock = nl.NetlinkSocket.init(linux.NETLINK.NETFILTER) catch |err| return netlinkError(err);
        defer sock.close();
        var payloads: [6][1024]u8 align(4) = undefined;
        const data = [_][]const u8{
            nft.buildOwnedTablePayload(&payloads[0], name, marker) catch |err| return netlinkError(err),
            nft.buildSetPayload(&payloads[1], nl.NFPROTO.INET, name, "banned_ipv4", 1, nft.NFT_TYPE.IPV4_ADDR, 4, 0) catch |err| return netlinkError(err),
            nft.buildSetPayload(&payloads[2], nl.NFPROTO.INET, name, "banned_ipv6", 2, nft.NFT_TYPE.IPV6_ADDR, 16, 0) catch |err| return netlinkError(err),
            nft.buildChainPayload(&payloads[3], nl.NFPROTO.INET, name, "input", 1, -1, "filter", 1) catch |err| return netlinkError(err),
            nft.buildDropRulePayload(&payloads[4], nl.NFPROTO.INET, name, "input", "banned_ipv4", nl.NFPROTO.IPV4, 12, 4) catch |err| return netlinkError(err),
            nft.buildDropRulePayload(&payloads[5], nl.NFPROTO.INET, name, "input", "banned_ipv6", nl.NFPROTO.IPV6, 8, 16) catch |err| return netlinkError(err),
        };
        var batch_bytes: [8192]u8 align(4) = undefined;
        var batch = nl.Batch.init(&batch_bytes);
        var related: [8]u32 = undefined;
        related[0] = sock.nextSeq();
        batch.begin(related[0], sock.port_id, nl.NFNL.SUBSYS_NFTABLES) catch |err| return netlinkError(err);
        const kinds = [_]u16{ nft.NFT_MSG.NEWTABLE, nft.NFT_MSG.NEWSET, nft.NFT_MSG.NEWSET, nft.NFT_MSG.NEWCHAIN, nft.NFT_MSG.NEWRULE, nft.NFT_MSG.NEWRULE };
        for (data, kinds, 1..) |payload, kind, index| {
            related[index] = sock.nextSeq();
            batch.add(nl.nfnlMsgType(nl.NFNL.SUBSYS_NFTABLES, kind), linux.NLM_F_REQUEST | linux.NLM_F_ACK | linux.NLM_F_CREATE | linux.NLM_F_EXCL, related[index], sock.port_id, payload) catch |err| return netlinkError(err);
        }
        related[7] = sock.nextSeq();
        const bytes = batch.commit(related[7], sock.port_id, nl.NFNL.SUBSYS_NFTABLES) catch |err| return netlinkError(err);
        const send_timeout = @min(try self.remainingMs(timer), 2000);
        progress.requested = true;
        nl.sendKernel(&sock, bytes, send_timeout) catch |err| return netlinkError(err);
        nl.receiveAcknowledgments(&sock, related[1..7], &related, @min(try self.remainingMs(timer), 2000)) catch |err| return netlinkError(err);
    }

    pub fn inspect(self: *Inspector) Error!Snapshot {
        if (comptime @import("builtin").is_test) {
            self.test_inspections += 1;
            if (self.test_fault_readback) |fault| return fault;
        }
        // Bytes of a snapshot the caller still holds stay charged against the limit.
        const held = self.retained_bytes;
        defer self.retained_bytes = held;
        var timer = std.time.Timer.start() catch return error.SystemError;
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
    /// The kernel serves each nftables dump at one generation and flags a dump whose
    /// generation moved, so a single pass is a coherent picture of the owned objects.
    /// An interrupted dump is re-read at once within the same time budget; each retry
    /// discards the interrupted messages, so it starts a fresh work count.
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
    fn checkTime(self: *Inspector, timer: *std.time.Timer) Error!void {
        _ = try self.remainingMs(timer);
    }
    fn remainingMs(self: *Inspector, timer: *std.time.Timer) Error!u64 {
        const elapsed = timer.read() / std.time.ns_per_ms;
        if (elapsed >= self.limits.timeout_ms) return error.Timeout;
        return self.limits.timeout_ms - elapsed;
    }
    fn chargeMessages(self: *Inspector, count: usize) Error!void {
        if (count > self.limits.max_messages - self.work_messages) return error.LimitExceeded;
        self.work_messages += count;
    }
    fn run(self: *Inspector, argv: []const []const u8, timer: *std.time.Timer) Error!command.Result {
        return self.runTracked(argv, timer, null);
    }
    fn runTracked(self: *Inspector, argv: []const []const u8, timer: *std.time.Timer, progress: ?*MutationProgress) Error!command.Result {
        try self.checkTime(timer);
        std.fs.accessAbsolute(argv[0], .{}) catch return error.ToolUnavailable;
        const remaining = try self.remainingMs(timer);
        const reserved = self.retained_bytes + self.live_bytes;
        if (reserved >= self.limits.max_bytes) return error.LimitExceeded;
        const allowance = (self.limits.max_bytes - reserved) / 4;
        if (progress) |value| value.requested = true;
        const result = command.runBounded(self.allocator, argv, @min(remaining, 2000), @min(allowance, 1024 * 1024), @min(allowance, 4096)) catch |err| return switch (err) {
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
};

fn reservedName(name: []const u8) bool {
    return std.ascii.startsWithIgnoreCase(name, "f2z_") or std.ascii.startsWithIgnoreCase(name, "fail2zig");
}
fn scanSavedTables(output: []const u8) Error!void {
    if (output.len != 0 and output[output.len - 1] != '\n') return error.Incomplete;
    var lines = mem.tokenizeScalar(u8, output, '\n');
    var in_table = false;
    while (lines.next()) |line| {
        if (line[0] == '#') continue;
        if (line[0] == '*') {
            if (in_table or line.len < 2) return error.Incomplete;
            in_table = true;
        } else if (mem.eql(u8, line, "COMMIT")) {
            if (!in_table) return error.Incomplete;
            in_table = false;
        } else if (line[0] == ':') {
            if (!in_table) return error.Incomplete;
            const end = mem.indexOfScalar(u8, line, ' ') orelse return error.Incomplete;
            if (reservedName(line[1..end])) return error.ForeignState;
        } else if (mem.startsWith(u8, line, "-A ")) {
            if (!in_table) return error.Incomplete;
            const tokens = try Tokens.parse(line);
            for (tokens.values[0..tokens.count]) |token| if (reservedName(token)) return error.ForeignState;
        } else return error.UnknownState;
    }
    if (in_table) return error.Incomplete;
}

fn clockAt(clock: ClockSample, timer: *std.time.Timer) Error!i64 {
    const elapsed = std.math.cast(i64, timer.read() / std.time.ns_per_us) orelse return error.UnsupportedDeadline;
    return std.math.add(i64, clock.wall_us, elapsed) catch error.UnsupportedDeadline;
}
fn deadlineUnits(operation: EffectOperation, transport: Transport, now_us: i64) Error!u64 {
    if (now_us < 0) return error.UnsupportedDeadline;
    if (operation != .ensure_present or operation.ensure_present == .permanent) return 0;
    const deadline = operation.ensure_present.finite_deadline_us;
    if (deadline <= now_us) return error.ExpiredIntent;
    const delta: u64 = @intCast(deadline - now_us);
    const quantum: u64 = if (transport == .ipset) 1_000_000 else 1000;
    const units = delta / quantum + @intFromBool(delta % quantum != 0);
    if (transport == .ipset and units > 2_147_483) return error.UnsupportedDeadline;
    return units;
}
fn timingTransport(transport: Transport, scope: CanonicalScope) Transport {
    if (transport == .ipset) {
        _ = legacyAddress(scope) catch return .iptables;
    }
    return transport;
}
fn entryScope(entry: Entry) CanonicalScope {
    return entry.scope orelse .{ .subject = canonical_scope.Subject.host(entry.address) };
}
/// Snapshot entries are ordered by `entryLess` with no repeated scope, as
/// `Builder.finish` enforces, so an exact scope occupies at most one position.
fn entryIndex(entries: []const Entry, scope: CanonicalScope) Error!?usize {
    // A scope that cannot be encoded is invalid and so equals no installed entry.
    const key = scope.encode() catch return null;
    var low: usize = 0;
    var high = entries.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        const probe = entryScope(entries[middle]).encode() catch return error.UnknownState;
        switch (mem.order(u8, &probe, &key)) {
            .lt => low = middle + 1,
            .gt => high = middle,
            .eq => return if (std.meta.eql(entryScope(entries[middle]), scope)) middle else null,
        }
    }
    return null;
}
fn findEntry(entries: []const Entry, scope: CanonicalScope, effect_id: [32]u8) Error!?Entry {
    const entry = entries[try entryIndex(entries, scope) orelse return null];
    if (entry.scope != null and (entry.effect_id == null or !mem.eql(u8, &entry.effect_id.?, &effect_id))) return error.ForeignState;
    return entry;
}
/// Kernel set-element timeouts equal the ban deadline, so the kernel removes an element
/// on schedule without any mutation by us. Two sorted readbacks describe the same owned
/// state when every entry matches, except that an element whose remaining timeout could
/// have elapsed within `window_ns` may be missing from the later one. Any other added,
/// missing or altered entry is a change and must not be accepted as ownership proof.
fn sameEntries(before: []const Entry, after: []const Entry, except: ?CanonicalScope, window_ns: u64, transport: Transport) bool {
    var i: usize = 0;
    var j: usize = 0;
    while (i < before.len or j < after.len) {
        if (except) |scope| {
            if (i < before.len and std.meta.eql(entryScope(before[i]), scope)) {
                i += 1;
                continue;
            }
            if (j < after.len and std.meta.eql(entryScope(after[j]), scope)) {
                j += 1;
                continue;
            }
        }
        if (i == before.len) return false;
        if (j == after.len or entryLess({}, before[i], after[j])) {
            if (!expiredWithin(before[i], window_ns, transport)) return false;
            i += 1;
            continue;
        }
        const old = before[i];
        const new = after[j];
        if (!std.meta.eql(entryScope(old), entryScope(new)) or !std.meta.eql(old.effect_id, new.effect_id) or
            old.deadline_us != new.deadline_us or old.partial != new.partial or (old.remaining_ms == null) != (new.remaining_ms == null)) return false;
        if (old.remaining_ms) |remaining| if (new.remaining_ms.? > remaining) return false;
        i += 1;
        j += 1;
    }
    return true;
}
fn expiredWithin(entry: Entry, window_ns: u64, transport: Transport) bool {
    const remaining = entry.remaining_ms orelse return false;
    const remaining_us = std.math.mul(u64, remaining, 1000) catch return false;
    return remaining_us <= window_ns / std.time.ns_per_us +| 1 +| timeoutToleranceUs(transport);
}
/// ipset reports whole seconds and nftables reports milliseconds at jiffy granularity.
fn timeoutToleranceUs(transport: Transport) u64 {
    return if (transport == .ipset) 1_000_000 else 10_000;
}
fn effectMatches(operation: EffectOperation, transport: Transport, entry: ?Entry, start_us: i64, end_us: i64) bool {
    if (operation == .ensure_absent) return entry == null;
    const present = entry orelse return false;
    if (present.partial) return false;
    if (operation.ensure_present == .finite_deadline_us and operation.ensure_present.finite_deadline_us <= end_us) return false;
    if (present.scope != null) {
        if (operation.ensure_present == .permanent) return present.deadline_us == null;
        return present.deadline_us != null and present.deadline_us.? == operation.ensure_present.finite_deadline_us;
    }
    if (transport == .iptables) return present.remaining_ms == null;
    if (operation.ensure_present == .permanent) return present.remaining_ms == null;
    const remaining = present.remaining_ms orelse return false;
    const deadline = operation.ensure_present.finite_deadline_us;
    if (deadline <= end_us) return false;
    const tolerance = timeoutToleranceUs(transport);
    const upper: u64 = @intCast(deadline - start_us);
    const lower: u64 = @intCast(deadline - end_us);
    const observed = std.math.mul(u64, remaining, 1000) catch return false;
    const observed_upper = std.math.add(u64, observed, tolerance) catch return false;
    return observed <= upper + tolerance and observed_upper >= lower;
}

const Builder = struct {
    allocator: mem.Allocator,
    installation: Installation,
    limits: Limits,
    entries: std.ArrayList(Entry),
    present: bool = false,
    transient_bytes: usize = 0,
    topology: std.crypto.hash.sha2.Sha256 = std.crypto.hash.sha2.Sha256.init(.{}),
    fn init(a: mem.Allocator, i: Installation, limits: Limits) Builder {
        return .{ .allocator = a, .installation = i, .limits = limits, .entries = std.ArrayList(Entry).init(a) };
    }
    fn deinit(self: *Builder) void {
        self.entries.deinit();
    }
    fn add(self: *Builder, e: Entry) Error!void {
        if (self.entries.items.len >= self.limits.max_entries or
            self.entries.items.len >= self.limits.max_bytes / @sizeOf(Entry)) return error.LimitExceeded;
        if (self.transient_bytes > self.limits.max_bytes) return error.LimitExceeded;
        const capacity_limit = @min(self.limits.max_entries, (self.limits.max_bytes - self.transient_bytes) / (2 * @sizeOf(Entry)));
        if (self.entries.items.len >= capacity_limit) return error.LimitExceeded;
        if (self.entries.items.len == self.entries.capacity) {
            const capacity = @min(capacity_limit, self.entries.capacity + self.entries.capacity / 2 + 8);
            try self.entries.ensureTotalCapacityPrecise(capacity);
        }
        self.entries.appendAssumeCapacity(e);
    }
    /// Tables, chains, sets, rules and markers only; entries are compared separately.
    fn structureDigest(self: *const Builder) [32]u8 {
        var structure = self.topology;
        structure.update(&.{@intFromBool(self.present)});
        var digest: [32]u8 = undefined;
        structure.final(&digest);
        return digest;
    }
    fn finish(self: *Builder, start: u64, end: u64) Error!Snapshot {
        mem.sort(Entry, self.entries.items, {}, entryLess);
        for (self.entries.items, 0..) |e, index| {
            if (index > 0 and !entryLess({}, self.entries.items[index - 1], e)) return error.UnknownState;
            const scope_bytes = entryScope(e).encode() catch return error.UnknownState;
            self.topology.update(&scope_bytes);
            self.topology.update(&.{ @intFromBool(e.remaining_ms != null), @intFromBool(e.deadline_us != null), @intFromBool(e.effect_id != null), @intFromBool(e.partial) });
            if (e.deadline_us) |deadline| self.topology.update(mem.asBytes(&deadline));
            if (e.effect_id) |identity| self.topology.update(&identity);
        }
        self.topology.update(&.{@intFromBool(self.present)});
        var fingerprint: [32]u8 = undefined;
        self.topology.final(&fingerprint);
        return .{ .allocator = self.allocator, .installation = self.installation, .state = if (self.present) .owned else .absent, .entries = try self.entries.toOwnedSlice(), .fingerprint = fingerprint, .observed_start_ns = start, .observed_end_ns = end };
    }
};
fn entryLess(_: void, a: Entry, b: Entry) bool {
    const left = entryScope(a).encode() catch return false;
    const right = entryScope(b).encode() catch return false;
    return mem.order(u8, &left, &right) == .lt;
}

const Tokens = struct {
    values: [32][]const u8 = undefined,
    count: usize = 0,
    fn parse(line: []const u8) Error!Tokens {
        var out: Tokens = .{};
        var at: usize = 0;
        while (at < line.len) {
            if (line[at] == ' ' or line[at] == '\t') {
                at += 1;
                continue;
            }
            if (out.count == out.values.len) return error.LimitExceeded;
            const quoted = line[at] == '"';
            if (quoted) at += 1;
            const begin = at;
            while (at < line.len and (if (quoted) line[at] != '"' else line[at] != ' ' and line[at] != '\t')) : (at += 1) {
                if (line[at] == '\\' or line[at] < 32 or (!quoted and line[at] == '"')) return error.UnknownState;
            }
            out.values[out.count] = line[begin..at];
            out.count += 1;
            if (quoted) {
                if (at == line.len) return error.Incomplete;
                at += 1;
                if (at < line.len and line[at] != ' ' and line[at] != '\t') return error.UnknownState;
            }
        }
        return out;
    }
    fn is(self: Tokens, expected: []const []const u8) bool {
        if (self.count != expected.len) return false;
        for (expected, self.values[0..self.count]) |a, b| if (!mem.eql(u8, a, b)) return false;
        return true;
    }
};

fn hostAddress(text: []const u8, v6: bool) Error!shared.IpAddress {
    var host = text;
    if (mem.indexOfScalar(u8, text, '/')) |slash| {
        if (!mem.eql(u8, text[slash..], if (v6) "/128" else "/32")) return error.UnsupportedScope;
        host = text[0..slash];
    }
    const address = shared.IpAddress.parse(host) catch return error.UnknownState;
    if ((address == .ipv6) != v6) return error.UnknownState;
    return address;
}

fn scopedSubjectText(scope: CanonicalScope, buf: *[64]u8) Error![]const u8 {
    return std.fmt.bufPrint(buf, "{}/{}", .{ subjectAddress(scope.subject), scope.subject.prefix }) catch error.LimitExceeded;
}

fn scopedPortText(port: canonical_scope.PortRange, buf: *[16]u8) Error![]const u8 {
    return if (port.first == port.last)
        std.fmt.bufPrint(buf, "{d}", .{port.first}) catch error.LimitExceeded
    else
        std.fmt.bufPrint(buf, "{d}:{d}", .{ port.first, port.last }) catch error.LimitExceeded;
}

fn scopedProtocolText(protocol: canonical_scope.Protocol) Error![]const u8 {
    return switch (protocol) {
        .tcp => "tcp",
        .udp => "udp",
        .icmp_v4 => "icmp",
        .icmp_v6 => "ipv6-icmp",
        .all => error.UnsupportedScope,
    };
}

const FixedScopedOperation = enum { insert, delete };

fn buildFixedScopedArgv(
    argv: *[24][]const u8,
    subject_buf: *[64]u8,
    port_buf: *[16]u8,
    comment_buf: *[scoped_comment_bytes]u8,
    binary: []const u8,
    chain: []const u8,
    metadata: ScopedRuleMetadata,
    operation: FixedScopedOperation,
) Error![]const []const u8 {
    const part = nft.scopeRulePart(metadata.scope, metadata.part) catch return error.UnsupportedScope;
    const comment = try metadata.encodeComment();
    comment_buf.* = comment;
    const subject = try scopedSubjectText(metadata.scope, subject_buf);
    var count: usize = 0;
    const append = struct {
        fn value(values: *[24][]const u8, at: *usize, text: []const u8) Error!void {
            if (at.* == values.len) return error.LimitExceeded;
            values[at.*] = text;
            at.* += 1;
        }
    }.value;
    try append(argv, &count, binary);
    try append(argv, &count, "-w");
    try append(argv, &count, "1");
    try append(argv, &count, if (operation == .insert) "-I" else "-D");
    try append(argv, &count, chain);
    if (operation == .insert) try append(argv, &count, "1");
    try append(argv, &count, "-s");
    try append(argv, &count, subject);
    if (part.protocol) |protocol| {
        const protocol_text = try scopedProtocolText(protocol);
        try append(argv, &count, "-p");
        try append(argv, &count, protocol_text);
        if (protocol == .tcp or protocol == .udp) {
            try append(argv, &count, "-m");
            try append(argv, &count, protocol_text);
        }
    }
    if (part.port) |port| {
        try append(argv, &count, "--dport");
        try append(argv, &count, try scopedPortText(port, port_buf));
    }
    try append(argv, &count, "-m");
    try append(argv, &count, "comment");
    try append(argv, &count, "--comment");
    try append(argv, &count, comment_buf);
    try append(argv, &count, "-j");
    try append(argv, &count, "DROP");
    return argv[0..count];
}

fn fixedScopedMetadata(tokens: Tokens, chain: []const u8, v6: bool) Error!?ScopedRuleMetadata {
    if (tokens.count < 10 or !mem.eql(u8, tokens.values[tokens.count - 6], "-m") or
        !mem.eql(u8, tokens.values[tokens.count - 5], "comment") or
        !mem.eql(u8, tokens.values[tokens.count - 4], "--comment") or
        !mem.startsWith(u8, tokens.values[tokens.count - 3], scoped_comment_prefix) or
        !mem.eql(u8, tokens.values[tokens.count - 2], "-j") or
        !mem.eql(u8, tokens.values[tokens.count - 1], "DROP")) return null;
    const metadata = try ScopedRuleMetadata.decodeComment(tokens.values[tokens.count - 3]);
    if ((metadata.scope.subject.family == .v6) != v6) return error.ForeignState;
    var argv: [24][]const u8 = undefined;
    var subject_buf: [64]u8 = undefined;
    var port_buf: [16]u8 = undefined;
    var comment_buf: [scoped_comment_bytes]u8 = undefined;
    const expected = try buildFixedScopedArgv(&argv, &subject_buf, &port_buf, &comment_buf, if (v6) "/usr/sbin/ip6tables" else "/usr/sbin/iptables", chain, metadata, .delete);
    if (tokens.count != expected.len - 3 or !mem.eql(u8, tokens.values[0], "-A") or !mem.eql(u8, tokens.values[1], chain)) return error.ForeignState;
    for (tokens.values[2..tokens.count], expected[5..]) |actual, wanted| if (!mem.eql(u8, actual, wanted)) return error.ForeignState;
    return metadata;
}

/// The rules of one effect id, each already validated as our exact scoped drop for its
/// own metadata. Parts that disagree on the deadline or repeat are our own interrupted
/// mutation, so the group is reported partial rather than failing the readback; a
/// scope that differs within one effect id is not ours to repair.
const ScopedGroup = struct { metadata: ScopedRuleMetadata, parts: u32 = 0, partial: bool = false };

fn collectScopedGroup(groups: *std.ArrayList(ScopedGroup), metadata: ScopedRuleMetadata, limits: Limits) Error!void {
    var group_index: ?usize = null;
    for (groups.items, 0..) |group, index| if (mem.eql(u8, &group.metadata.effect_id, &metadata.effect_id)) {
        group_index = index;
        break;
    };
    if (group_index == null) {
        if (groups.items.len >= limits.max_entries or groups.items.len >= limits.max_bytes / @sizeOf(ScopedGroup)) return error.LimitExceeded;
        try groups.append(.{ .metadata = metadata });
        group_index = groups.items.len - 1;
    }
    const group = &groups.items[group_index.?];
    if (!std.meta.eql(group.metadata.scope, metadata.scope) or group.metadata.count != metadata.count or metadata.part >= 32)
        return error.ForeignState;
    if (group.metadata.deadline_us != metadata.deadline_us) group.partial = true;
    const bit = @as(u32, 1) << @intCast(metadata.part);
    if (group.parts & bit != 0) group.partial = true;
    group.parts |= bit;
}

fn finishScopedGroups(builder: *Builder, groups: []const ScopedGroup) Error!void {
    for (groups) |group| {
        const wanted = (@as(u32, 1) << @intCast(group.metadata.count)) - 1;
        try builder.add(.{
            .address = subjectAddress(group.metadata.scope.subject),
            .scope = group.metadata.scope,
            .deadline_us = group.metadata.deadline_us,
            .effect_id = group.metadata.effect_id,
            .partial = group.partial or group.parts != wanted,
        });
    }
}

/// Rules of one scoped effect as `iptables -S` lists them, counted per metadata variant
/// and part. Bounded so the recovery work of one dispatch is finite; rules beyond the
/// bound remain a partial entry in the readback and wait for the next dispatch.
const FixedScopedVariants = struct {
    const max_variants = 8;
    const Variant = struct { deadline_us: ?i64, counts: [nft.max_scope_rule_parts]u16 = @splat(0) };
    variants: [max_variants]Variant = undefined,
    len: usize = 0,
    fn note(self: *FixedScopedVariants, deadline_us: ?i64, part: u8) void {
        for (self.variants[0..self.len]) |*variant| if (variant.deadline_us == deadline_us) {
            variant.counts[part] +|= 1;
            return;
        };
        if (self.len == max_variants) return;
        self.variants[self.len] = .{ .deadline_us = deadline_us };
        self.variants[self.len].counts[part] = 1;
        self.len += 1;
    }
    fn count(self: *const FixedScopedVariants, deadline_us: ?i64, part: usize) u16 {
        for (self.variants[0..self.len]) |variant| if (variant.deadline_us == deadline_us) return variant.counts[part];
        return 0;
    }
};

fn leaseDeadline(lease: Lease) ?i64 {
    return switch (lease) {
        .permanent => null,
        .finite_deadline_us => |deadline| deadline,
    };
}

fn copySnapshot(allocator: mem.Allocator, source: *const Snapshot) Error!Snapshot {
    var copy = source.*;
    copy.allocator = allocator;
    copy.entries = try allocator.dupe(Entry, source.entries);
    return copy;
}

fn parseIptables(builder: *Builder, output: []const u8, v6: bool) Error!bool {
    if (output.len == 0 or output[output.len - 1] != '\n') return error.Incomplete;
    var name_buf: [28]u8 = undefined;
    const name = builder.installation.name(&name_buf);
    var marker_buf: [44]u8 = undefined;
    const marker = builder.installation.marker(&marker_buf);
    var chain = false;
    var mark = false;
    var jump_count: usize = 0;
    var rules: usize = 0;
    var policy_seen = [_]bool{ false, false, false };
    var lookup = false;
    var input_rules: usize = 0;
    var scoped = std.ArrayList(ScopedGroup).init(builder.allocator);
    defer scoped.deinit();
    var lines = mem.splitScalar(u8, output, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        rules += 1;
        if (rules > builder.limits.max_messages) return error.LimitExceeded;
        const t = try Tokens.parse(line);
        if (t.count < 2) return error.UnknownState;
        if (mem.eql(u8, t.values[0], "-P")) {
            if (t.count != 3) return error.UnknownState;
            const index: usize = if (mem.eql(u8, t.values[1], "INPUT")) 0 else if (mem.eql(u8, t.values[1], "FORWARD")) 1 else if (mem.eql(u8, t.values[1], "OUTPUT")) 2 else return error.UnknownState;
            if (policy_seen[index] or (!mem.eql(u8, t.values[2], "ACCEPT") and !mem.eql(u8, t.values[2], "DROP"))) return error.UnknownState;
            policy_seen[index] = true;
            continue;
        }
        if (mem.eql(u8, t.values[0], "-N")) {
            if (t.count != 2) return error.UnknownState;
            if (mem.eql(u8, t.values[1], name)) {
                if (chain) return error.UnknownState;
                chain = true;
            }
            continue;
        }
        if (!mem.eql(u8, t.values[0], "-A")) return error.UnknownState;
        if (mem.eql(u8, t.values[1], "INPUT")) input_rules += 1;
        if (mem.eql(u8, t.values[1], name)) {
            if (!chain or mark) return error.ForeignState;
            if (t.is(&.{ "-A", name, "-m", "comment", "--comment", marker, "-j", "RETURN" })) {
                mark = true;
                continue;
            }
            if (try fixedScopedMetadata(t, name, v6)) |metadata| {
                try collectScopedGroup(&scoped, metadata, builder.limits);
                continue;
            }
            if (builder.installation.transport == .iptables) {
                if (t.count != 6 or !mem.eql(u8, t.values[2], "-s") or !mem.eql(u8, t.values[4], "-j") or !mem.eql(u8, t.values[5], "DROP")) return error.ForeignState;
                try builder.add(.{ .address = try hostAddress(t.values[3], v6) });
            } else {
                var set_buf: [31]u8 = undefined;
                const set = try setName(name, v6, &set_buf);
                if (!t.is(&.{ "-A", name, "-m", "set", "--match-set", set, "src", "-j", "DROP" })) return error.ForeignState;
                if (lookup) return error.ForeignState;
                lookup = true;
                builder.topology.update(line);
            }
        } else {
            var references = false;
            for (t.values[2..t.count], 2..) |value, index| {
                if ((mem.eql(u8, value, "-j") or mem.eql(u8, value, "-g")) and index + 1 < t.count and mem.eql(u8, t.values[index + 1], name)) references = true;
            }
            if (references) {
                if (!t.is(&.{ "-A", "INPUT", "-m", "comment", "--comment", marker, "-j", name })) return error.ForeignState;
                jump_count += 1;
                if (input_rules != 1) return error.ForeignState;
            }
        }
    }
    if (!policy_seen[0] or !policy_seen[1] or !policy_seen[2]) return error.Incomplete;
    if (!chain) {
        if (mark or jump_count != 0) return error.ForeignState;
        return false;
    }
    if (!mark or jump_count != 1) return error.ForeignState;
    if (builder.installation.transport == .ipset and !lookup) return error.ForeignState;
    try finishScopedGroups(builder, scoped.items);
    builder.topology.update(marker);
    return true;
}

pub fn setName(name: []const u8, v6: bool, buf: *[31]u8) Error![]const u8 {
    return std.fmt.bufPrint(buf, "{s}_{s}", .{ name, if (v6) "6" else "4" }) catch error.LimitExceeded;
}

fn parseIpset(builder: *Builder, output: []const u8, v6: bool) Error!bool {
    if (output.len != 0 and output[output.len - 1] != '\n') return error.Incomplete;
    var name_buf: [28]u8 = undefined;
    var set_buf: [31]u8 = undefined;
    const name = try setName(builder.installation.name(&name_buf), v6, &set_buf);
    var created = false;
    var lines = mem.splitScalar(u8, output, '\n');
    var count: usize = 0;
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        count += 1;
        if (count > builder.limits.max_messages) return error.LimitExceeded;
        const t = try Tokens.parse(line);
        if (t.count < 2) return error.UnknownState;
        if (!mem.eql(u8, t.values[1], name)) continue;
        if (mem.eql(u8, t.values[0], "create")) {
            if (created or t.count < 5 or !mem.eql(u8, t.values[2], "hash:ip")) return error.ForeignState;
            var family = false;
            var timeout = false;
            var at: usize = 3;
            while (at < t.count) : (at += 2) {
                if (at + 1 >= t.count) return error.UnknownState;
                const key = t.values[at];
                const value = t.values[at + 1];
                if (mem.eql(u8, key, "family")) {
                    if (family or !mem.eql(u8, value, if (v6) "inet6" else "inet")) return error.ForeignState;
                    family = true;
                } else if (mem.eql(u8, key, "timeout")) {
                    if (timeout or !mem.eql(u8, value, "0")) return error.ForeignState;
                    timeout = true;
                } else if (mem.eql(u8, key, "hashsize") or mem.eql(u8, key, "maxelem") or mem.eql(u8, key, "bucketsize") or mem.eql(u8, key, "initval")) {
                    _ = std.fmt.parseInt(u64, value, 0) catch return error.UnknownState;
                } else return error.ForeignState;
            }
            if (!family or !timeout) return error.ForeignState;
            created = true;
        } else if (mem.eql(u8, t.values[0], "add")) {
            if (!created or (t.count != 3 and t.count != 5)) return error.UnknownState;
            var remaining: ?u64 = null;
            if (t.count == 5) {
                if (!mem.eql(u8, t.values[3], "timeout")) return error.UnknownState;
                const seconds = std.fmt.parseInt(u64, t.values[4], 10) catch return error.UnknownState;
                if (seconds != 0) remaining = std.math.mul(u64, seconds, 1000) catch return error.UnknownState;
            }
            try builder.add(.{ .address = try hostAddress(t.values[2], v6), .remaining_ms = remaining });
        } else return error.UnknownState;
    }
    return created;
}

fn readTools(self: *Inspector, builder: *Builder, timer: *std.time.Timer) Error!void {
    defer self.live_bytes = 0;
    var presence: [2]bool = undefined;
    for ([_][]const u8{ self.iptables_path, self.ip6tables_path }, 0..) |binary, index| {
        self.live_bytes = builder.entries.capacity * @sizeOf(Entry);
        const result = try self.run(&.{ binary, "-w", "1", "-S" }, timer);
        defer result.deinit(self.allocator);
        builder.transient_bytes = result.stdout.len + result.stderr.len;
        defer builder.transient_bytes = 0;
        presence[index] = try parseIptables(builder, result.stdout, index == 1);
    }
    if (presence[0] != presence[1]) return error.ForeignState;
    if (self.installation.transport == .ipset) {
        self.live_bytes = builder.entries.capacity * @sizeOf(Entry);
        const result = try self.run(&.{ self.ipset_path, "save" }, timer);
        defer result.deinit(self.allocator);
        builder.transient_bytes = result.stdout.len + result.stderr.len;
        defer builder.transient_bytes = 0;
        for (0..2) |index| {
            if (try parseIpset(builder, result.stdout, index == 1) != presence[index]) return error.ForeignState;
        }
    }
    builder.present = presence[0];
}

const AttrMap = struct {
    values: [32]?[]const u8 = @splat(null),
    flags: [32]u16 = @splat(0),
    fn parse(bytes: []const u8, allowed: []const u16) Error!AttrMap {
        var map: AttrMap = .{};
        var it = nl.Attributes{ .bytes = bytes };
        while (it.next() catch return error.Incomplete) |a| {
            if (a.kind >= map.values.len or mem.indexOfScalar(u16, allowed, a.kind) == null) return error.UnknownState;
            if (map.values[a.kind] != null) return error.UnknownState;
            if ((a.flags & 0x8000) != 0) try validateNested(a.value, 0);
            map.values[a.kind] = a.value;
            map.flags[a.kind] = a.flags;
        }
        return map;
    }
    fn get(self: AttrMap, kind: usize) Error![]const u8 {
        return self.values[kind] orelse error.Incomplete;
    }
    fn text(self: AttrMap, kind: usize) Error![]const u8 {
        if (self.flags[kind] != 0) return error.UnknownState;
        const value = try self.get(kind);
        if (value.len == 0 or value[value.len - 1] != 0 or mem.indexOfScalar(u8, value[0 .. value.len - 1], 0) != null) return error.UnknownState;
        return value[0 .. value.len - 1];
    }
    fn number(self: AttrMap, comptime T: type, kind: usize) Error!T {
        if ((self.flags[kind] & 0x8000) != 0) return error.UnknownState;
        const value = try self.get(kind);
        if (value.len != @sizeOf(T)) return error.UnknownState;
        return mem.readInt(T, value[0..@sizeOf(T)], .big);
    }
};
fn validateNested(bytes: []const u8, depth: usize) Error!void {
    if (depth >= 16) return error.LimitExceeded;
    var it = nl.Attributes{ .bytes = bytes };
    while (it.next() catch return error.Incomplete) |a| {
        if ((a.flags & 0x8000) != 0) try validateNested(a.value, depth + 1);
    }
}
const Records = struct {
    allocator: mem.Allocator,
    values: std.ArrayList([]u8),
    bytes: usize = 0,
    fn deinit(self: *Records) void {
        for (self.values.items) |value| self.allocator.free(value);
        self.values.deinit();
    }
};
fn netlinkError(err: nl.Error) Error {
    return switch (err) {
        error.PermissionDenied => error.PermissionDenied,
        error.Timeout => error.Timeout,
        error.TruncatedMessage => error.Incomplete,
        error.BufferTooSmall => error.LimitExceeded,
        error.DumpInterrupted => error.DumpInterrupted,
        else => error.UnknownState,
    };
}
/// The kernel applies a batch whole or rejects it whole, so an element or rule the
/// baseline misjudged rejects the batch with nothing applied: a non-mutation.
fn rejectedBatch(err: nl.Error, progress: *MutationProgress) Error {
    switch (err) {
        error.AlreadyExists, error.NotFound => {
            progress.requested = false;
            return error.Changed;
        },
        else => return netlinkError(err),
    }
}
fn scopeBuildError(err: anyerror) Error {
    return switch (err) {
        error.PermissionDenied => error.PermissionDenied,
        error.Timeout => error.Timeout,
        error.OutOfMemory => error.OutOfMemory,
        error.BufferTooSmall => error.LimitExceeded,
        error.SendFailed, error.RecvFailed, error.SocketFailed => error.SystemError,
        else => error.UnsupportedScope,
    };
}
fn dump(self: *Inspector, sock: *nl.NetlinkSocket, request_type: u16, response_type: u16, request: []const u8, timer: *std.time.Timer, reserved: usize) Error!Records {
    var records = Records{ .allocator = self.allocator, .values = std.ArrayList([]u8).init(self.allocator) };
    errdefer records.deinit();
    try self.checkTime(timer);
    var outgoing: [1024]u8 align(4) = undefined;
    var message = nl.MessageBuilder.init(&outgoing);
    const sequence = sock.nextSeq();
    message.append(nl.nfnlMsgType(nl.NFNL.SUBSYS_NFTABLES, request_type), linux.NLM_F_REQUEST | 0x300, sequence, sock.port_id, request) catch |err| return netlinkError(err);
    nl.sendKernel(sock, message.bytes(), @min(try self.remainingMs(timer), 2000)) catch |err| return netlinkError(err);
    var state = nl.Dump{ .sequence = sequence, .message_type = nl.nfnlMsgType(nl.NFNL.SUBSYS_NFTABLES, response_type), .port_id = sock.port_id, .max_messages = self.limits.max_messages };
    var scratch: [65536]u8 = undefined;
    var datagrams: usize = 0;
    while (!state.complete) {
        try self.checkTime(timer);
        datagrams += 1;
        if (datagrams > self.limits.max_messages) return error.LimitExceeded;
        const remaining = try self.remainingMs(timer);
        sock.setRecvTimeout(@max(@as(u64, 1), @min(remaining, 2000))) catch |err| return netlinkError(err);
        const bytes = nl.recvKernel(sock, &scratch) catch |err| return netlinkError(err);
        var messages = nl.StrictMessages{ .bytes = bytes };
        while (messages.next() catch |err| return netlinkError(err)) |item| {
            try self.chargeMessages(1);
            if (state.accept(item) catch |err| return netlinkError(err)) |payload| {
                const cost = std.math.add(usize, payload.len, 2 * @sizeOf([]u8)) catch return error.LimitExceeded;
                const used = std.math.add(usize, records.bytes, reserved + self.retained_bytes) catch return error.LimitExceeded;
                if (used > self.limits.max_bytes or cost > self.limits.max_bytes - used) return error.LimitExceeded;
                const owned = try self.allocator.dupe(u8, payload);
                errdefer self.allocator.free(owned);
                try records.values.append(owned);
                records.bytes += cost;
            }
        }
    }
    return records;
}
fn payloadAttrs(payload: []const u8, allowed: []const u16) Error!AttrMap {
    if (payload.len < 4 or payload[0] != nl.NFPROTO.INET or payload[1] != 0) return error.UnknownState;
    return AttrMap.parse(payload[4..], allowed);
}
fn equalAttributes(a: []const u8, b: []const u8, depth: usize, optional_zero_attr: ?u16) Error!bool {
    if (depth > 16) return error.LimitExceeded;
    var ai = nl.Attributes{ .bytes = a };
    var actual: [32]?nl.Attributes.View = @splat(null);
    var count: usize = 0;
    while (ai.next() catch return error.Incomplete) |av| {
        if (av.kind >= actual.len or actual[av.kind] != null) return error.UnknownState;
        actual[av.kind] = av;
        count += 1;
    }
    var bi = nl.Attributes{ .bytes = b };
    while (bi.next() catch return error.Incomplete) |bv| {
        if (bv.kind >= actual.len) return error.UnknownState;
        const av = actual[bv.kind] orelse return false;
        actual[bv.kind] = null;
        count -= 1;
        if ((bv.flags & 0x8000) != 0) {
            if ((av.flags & 0x4000) != 0 or !try equalAttributes(av.value, bv.value, depth + 1, null)) return false;
        } else if (av.flags != bv.flags or !mem.eql(u8, av.value, bv.value)) return false;
    }
    if (count == 0) return true;
    if (optional_zero_attr) |kind| {
        if (count == 1) {
            const value = actual[kind] orelse return false;
            return value.flags == 0 and mem.eql(u8, value.value, &.{ 0, 0, 0, 0 });
        }
    }
    return false;
}
/// A rule carrying our metadata is ours only when its expression is the exact scoped
/// drop for that metadata. The same check gates readback and recovery deletion, so
/// recovery never deletes a rule the readback would not have accepted as ours.
fn validateScopedDropRule(table: []const u8, attributes: AttrMap, metadata: ScopedRuleMetadata) Error!void {
    const part_count = nft.scopeRulePartCount(metadata.scope) catch |err| return scopeBuildError(err);
    if (part_count != metadata.count) return error.ForeignState;
    var expected_buf: [2048]u8 align(4) = undefined;
    const expected = nft.buildScopedDropRulePayload(&expected_buf, table, "input", metadata.scope, metadata.part, try attributes.get(7)) catch |err| return scopeBuildError(err);
    const expected_attrs = try payloadAttrs(expected, &.{ 1, 2, 4, 7 });
    if (!try equalExpressions(try attributes.get(4), try expected_attrs.get(4))) return error.ForeignState;
}
fn equalExpressions(a: []const u8, b: []const u8) Error!bool {
    var actual = nl.Attributes{ .bytes = a };
    var expected = nl.Attributes{ .bytes = b };
    while (expected.next() catch return error.Incomplete) |e| {
        const observed = (actual.next() catch return error.Incomplete) orelse return false;
        if (e.kind != 1 or observed.kind != 1 or (observed.flags & 0x4000) != 0) return false;
        const ea = try AttrMap.parse(e.value, &.{ 1, 2 });
        const oa = try AttrMap.parse(observed.value, &.{ 1, 2 });
        const name = try ea.text(1);
        if (!mem.eql(u8, name, try oa.text(1))) return false;
        const optional_zero_attr: ?u16 = if (mem.eql(u8, name, "lookup")) 5 else if (mem.eql(u8, name, "bitwise")) 6 else null;
        if (!try equalAttributes(try oa.get(2), try ea.get(2), 0, optional_zero_attr)) return false;
    }
    return (actual.next() catch return error.Incomplete) == null;
}

fn readNft(self: *Inspector, builder: *Builder, timer: *std.time.Timer) Error!void {
    var sock = nl.NetlinkSocket.init(linux.NETLINK.NETFILTER) catch |err| return netlinkError(err);
    defer sock.close();
    var name_buf: [28]u8 = undefined;
    const name = self.installation.name(&name_buf);
    var marker_buf: [44]u8 = undefined;
    const marker = self.installation.marker(&marker_buf);
    var found = false;
    {
        var tables = try dump(self, &sock, nft.NFT_MSG.GETTABLE, nft.NFT_MSG.NEWTABLE, &.{ nl.NFPROTO.INET, 0, 0, 0 }, timer, 0);
        defer tables.deinit();
        for (tables.values.items) |payload| {
            const attrs = try payloadAttrs(payload, &.{ 1, 2, 3, 4, 5, 6, 7 });
            if (!mem.eql(u8, try attrs.text(1), name)) continue;
            if (found) return error.UnknownState;
            found = true;
            if (!mem.eql(u8, try attrs.get(6), marker) or try attrs.number(u32, 2) != 0) return error.ForeignState;
            builder.topology.update(try attrs.get(4));
        }
    }
    if (!found) return;
    var request_buf: [256]u8 align(4) = undefined;
    const request = nft.buildTablePayload(&request_buf, nl.NFPROTO.INET, name) catch |err| return netlinkError(err);
    {
        var chains = try dump(self, &sock, nft.NFT_MSG.GETCHAIN, nft.NFT_MSG.NEWCHAIN, request, timer, 0);
        defer chains.deinit();
        var chain_count: usize = 0;
        for (chains.values.items) |payload| {
            const a = try payloadAttrs(payload, &.{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 });
            if (!mem.eql(u8, try a.text(1), name)) continue;
            chain_count += 1;
            if (chain_count != 1 or !mem.eql(u8, try a.text(3), "input") or
                !mem.eql(u8, try a.text(7), "filter") or try a.number(u32, 5) != 1) return error.ForeignState;
            const hook = try AttrMap.parse(try a.get(4), &.{ 1, 2 });
            if (try hook.number(u32, 1) != 1 or try hook.number(i32, 2) != -1) return error.ForeignState;
            if (a.values[10] != null and try a.number(u32, 10) != 1) return error.ForeignState;
            builder.topology.update(try a.get(2));
        }
        if (chain_count != 1) return error.ForeignState;
    }
    {
        var sets = try dump(self, &sock, nft.NFT_MSG.GETSET, nft.NFT_MSG.NEWSET, request, timer, 0);
        defer sets.deinit();
        var seen = [_]bool{ false, false };
        for (sets.values.items) |payload| {
            const a = try payloadAttrs(payload, &.{ 1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 14, 16 });
            if (!mem.eql(u8, try a.text(1), name)) continue;
            const set = try a.text(2);
            const index: usize = if (mem.eql(u8, set, "banned_ipv4")) 0 else if (mem.eql(u8, set, "banned_ipv6")) 1 else return error.ForeignState;
            if (seen[index]) return error.UnknownState;
            seen[index] = true;
            if (try a.number(u32, 3) != nft.NFT_SET_TIMEOUT or try a.number(u32, 4) != (if (index == 0) @as(u32, 7) else 8) or
                try a.number(u32, 5) != (if (index == 0) @as(u32, 4) else 16)) return error.ForeignState;
            if (a.values[11] != null and try a.number(u64, 11) != 0) return error.ForeignState;
            if (a.values[16]) |handle| {
                if (handle.len != 8) return error.UnknownState;
                builder.topology.update(handle);
            }
        }
        if (!seen[0] or !seen[1]) return error.ForeignState;
    }
    {
        var rules = try dump(self, &sock, nft.NFT_MSG.GETRULE, nft.NFT_MSG.NEWRULE, request, timer, 0);
        defer rules.deinit();
        var seen = [_]bool{ false, false };
        var scoped = std.ArrayList(ScopedGroup).init(self.allocator);
        defer scoped.deinit();
        for (rules.values.items) |payload| {
            const a = try payloadAttrs(payload, &.{ 1, 2, 3, 4, 6, 7, 8 });
            if (!mem.eql(u8, try a.text(1), name)) continue;
            if (!mem.eql(u8, try a.text(2), "input")) return error.ForeignState;
            var matched = false;
            for (0..2) |index| {
                var expected_buf: [512]u8 align(4) = undefined;
                const expected = nft.buildDropRulePayload(&expected_buf, nl.NFPROTO.INET, name, "input", if (index == 0) "banned_ipv4" else "banned_ipv6", if (index == 0) nl.NFPROTO.IPV4 else nl.NFPROTO.IPV6, if (index == 0) 12 else 8, if (index == 0) 4 else 16) catch |err| return netlinkError(err);
                const expected_attrs = try payloadAttrs(expected, &.{ 1, 2, 4 });
                if (try equalExpressions(try a.get(4), try expected_attrs.get(4))) {
                    if (seen[index]) return error.UnknownState;
                    seen[index] = true;
                    matched = true;
                    builder.topology.update(try a.get(3));
                    break;
                }
            }
            if (matched) {
                if (a.values[7] != null) return error.ForeignState;
                continue;
            }
            const metadata = try ScopedRuleMetadata.decode(try a.get(7));
            try validateScopedDropRule(name, a, metadata);
            _ = try a.number(u64, 3);
            try collectScopedGroup(&scoped, metadata, builder.limits);
            builder.topology.update(try a.get(3));
        }
        if (!seen[0] or !seen[1]) return error.ForeignState;
        try finishScopedGroups(builder, scoped.items);
    }
    for (0..2) |index| {
        var element_request_buf: [256]u8 = undefined;
        const query = nft.buildSetQueryPayload(&element_request_buf, name, if (index == 0) "banned_ipv4" else "banned_ipv6") catch |err| return netlinkError(err);
        var elements = try dump(self, &sock, nft.NFT_MSG.GETSETELEM, nft.NFT_MSG.NEWSETELEM, query, timer, builder.entries.capacity * @sizeOf(Entry));
        defer elements.deinit();
        builder.transient_bytes = elements.bytes;
        defer builder.transient_bytes = 0;
        for (elements.values.items) |payload| {
            const a = try payloadAttrs(payload, &.{ 1, 2, 3 });
            if (!mem.eql(u8, try a.text(1), name) or !mem.eql(u8, try a.text(2), if (index == 0) "banned_ipv4" else "banned_ipv6")) return error.ForeignState;
            var items = nl.Attributes{ .bytes = try a.get(3) };
            while (items.next() catch return error.Incomplete) |item| {
                if (item.kind != 1 or (item.flags & 0x4000) != 0) return error.UnknownState;
                const e = try AttrMap.parse(item.value, &.{ 1, 3, 4, 5, 8 });
                if (e.values[3] != null and try e.number(u32, 3) != 0) return error.ForeignState;
                const key = try AttrMap.parse(try e.get(1), &.{1});
                const bytes = try key.get(1);
                if (bytes.len != (if (index == 0) @as(usize, 4) else 16)) return error.UnknownState;
                var remaining: ?u64 = null;
                if (e.values[4] != null) {
                    if (try e.number(u64, 4) != 0) remaining = try e.number(u64, 5);
                } else if (e.values[5] != null) return error.UnknownState;
                const address: shared.IpAddress = if (index == 0) .{ .ipv4 = mem.readInt(u32, bytes[0..4], .big) } else .{ .ipv6 = mem.readInt(u128, bytes[0..16], .big) };
                try builder.add(.{ .address = address, .remaining_ms = remaining });
            }
        }
    }
    builder.present = true;
}

const Self = @This();
pub const TestAccess = if (@import("builtin").is_test) struct {
    pub const Builder = Self.Builder;
    pub const builderInit = Self.Builder.init;
    pub const builderDeinit = Self.Builder.deinit;
    pub const builderAdd = Self.Builder.add;
    pub const builderFinish = Self.Builder.finish;
    pub const tokensParse = Self.Tokens.parse;
    pub const attrMapParse = Self.AttrMap.parse;
    pub const buildFixedScopedArgv = Self.buildFixedScopedArgv;
    pub const parseIptables = Self.parseIptables;
    pub const parseIpset = Self.parseIpset;
    pub const deadlineUnits = Self.deadlineUnits;
    pub const effectMatches = Self.effectMatches;
    pub const scanSavedTables = Self.scanSavedTables;
    pub const entryLess = Self.entryLess;
    pub const sameEntries = Self.sameEntries;
    pub const entryScope = Self.entryScope;
    pub const findEntry = Self.findEntry;
} else struct {};

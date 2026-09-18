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
pub const Error = error{ UnknownState, ForeignState, Incomplete, Changed, LimitExceeded, UnsupportedScope, ExpiredIntent, UnsupportedDeadline, InvalidInstallation, ToolUnavailable, PermissionDenied, Timeout, OutOfMemory, SystemError };
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

pub const Limits = struct {
    max_entries: usize = 65_536,
    max_bytes: usize = 16 * 1024 * 1024,
    max_messages: usize = 65_536,
    timeout_ms: u64 = 5000,
    pub fn validate(self: Limits) Error!void {
        if (self.max_entries == 0 or self.max_entries > 65_536 or self.max_bytes == 0 or
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
pub const Snapshot = struct {
    allocator: mem.Allocator,
    installation: Installation,
    state: enum { absent, owned },
    entries: []Entry,
    fingerprint: [32]u8,
    observed_start_ns: u64,
    observed_end_ns: u64,
    pub fn deinit(self: *Snapshot) void {
        self.allocator.free(self.entries);
        self.* = undefined;
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
    verified: struct { snapshot: Snapshot, changed: bool, observed_wall_us: i64 },
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
    test_fault_after_mutations: if (@import("builtin").is_test) ?usize else void = if (@import("builtin").is_test) null else {},

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

    pub fn applyExact(self: *Inspector, token: DispatchToken, clock: ClockSample) Error!EffectResult {
        try (DurableInstallationIntent{ .installation = token.installation, .intent_id = token.effect_id, .revision = token.aggregate_revision }).validate(self.installation);
        try validateRealizedScope(self.installation.transport, token.scope);
        _ = try deadlineUnits(token.operation, timingTransport(self.installation.transport, token.scope), clock.wall_us);
        var elapsed = std.time.Timer.start() catch return error.SystemError;
        var before = try self.inspect();
        if (before.state != .owned) {
            before.deinit();
            return error.InvalidInstallation;
        }
        const existing = try findEntry(before.entries, token.scope, token.effect_id);
        const other_hash = otherEntriesHash(before.entries, token.scope);
        const noop = switch (token.operation) {
            .ensure_absent => existing == null,
            .ensure_present => |lease| if (existing) |entry| if (entry.scope != null)
                switch (lease) {
                    .permanent => entry.deadline_us == null,
                    .finite_deadline_us => |deadline| entry.deadline_us != null and entry.deadline_us.? == deadline,
                }
            else
                (self.installation.transport == .iptables or (lease == .permanent and entry.remaining_ms == null)) else false,
        };
        const before_end = clockAt(clock, &elapsed) catch |err| {
            before.deinit();
            return err;
        };
        _ = deadlineUnits(token.operation, timingTransport(self.installation.transport, token.scope), before_end) catch |err| {
            before.deinit();
            return err;
        };
        if (noop) return .{ .verified = .{ .snapshot = before, .changed = false, .observed_wall_us = before_end } };
        before.deinit();
        const units = try deadlineUnits(token.operation, timingTransport(self.installation.transport, token.scope), try clockAt(clock, &elapsed));
        var phase = std.time.Timer.start() catch return error.SystemError;
        self.work_messages = 0;
        self.retained_bytes = 0;
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
        if (after.state != .owned or !mem.eql(u8, &other_hash, &otherEntriesHash(after.entries, token.scope)) or
            !effectMatches(token.operation, self.installation.transport, after_entry, observation_start, observation_end))
        {
            after.deinit();
            return .{ .uncertain = self.failure(.effect_verify, error.Changed, progress) };
        }
        return .{ .verified = .{ .snapshot = after, .changed = true, .observed_wall_us = observation_end } };
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
        const scoped_address = legacyAddress(token.scope) catch return self.mutateFixedScoped(token, name, existing, timer, progress);
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
    fn mutateFixedScoped(self: *Inspector, token: DispatchToken, name: []const u8, existing: ?Entry, timer: *std.time.Timer, progress: *MutationProgress) Error!void {
        const binary = if (token.scope.subject.family == .v4) self.iptables_path else self.ip6tables_path;
        const part_count = nft.scopeRulePartCount(token.scope) catch return error.UnsupportedScope;
        var mutations: usize = 0;
        if (token.operation == .ensure_present) {
            const deadline: ?i64 = if (token.operation.ensure_present == .finite_deadline_us) token.operation.ensure_present.finite_deadline_us else null;
            for (0..part_count) |part| {
                const metadata = ScopedRuleMetadata{ .effect_id = token.effect_id, .part = @intCast(part), .count = @intCast(part_count), .deadline_us = deadline, .scope = token.scope };
                var argv: [24][]const u8 = undefined;
                var subject_buf: [64]u8 = undefined;
                var port_buf: [16]u8 = undefined;
                var comment_buf: [scoped_comment_bytes]u8 = undefined;
                try self.mutateCommand(try buildFixedScopedArgv(&argv, &subject_buf, &port_buf, &comment_buf, binary, name, metadata, .insert), timer, &mutations, progress);
            }
        }
        if (existing) |prior| {
            if (prior.scope == null or prior.effect_id == null or !mem.eql(u8, &prior.effect_id.?, &token.effect_id)) return error.ForeignState;
            for (0..part_count) |part| {
                const metadata = ScopedRuleMetadata{ .effect_id = token.effect_id, .part = @intCast(part), .count = @intCast(part_count), .deadline_us = prior.deadline_us, .scope = token.scope };
                var argv: [24][]const u8 = undefined;
                var subject_buf: [64]u8 = undefined;
                var port_buf: [16]u8 = undefined;
                var comment_buf: [scoped_comment_bytes]u8 = undefined;
                try self.mutateCommand(try buildFixedScopedArgv(&argv, &subject_buf, &port_buf, &comment_buf, binary, name, metadata, .delete), timer, &mutations, progress);
            }
        }
        if (mutations == 0) return error.Changed;
    }
    fn mutateNft(self: *Inspector, token: DispatchToken, name: []const u8, existed: bool, timeout_ms: u64, timer: *std.time.Timer, progress: *MutationProgress) Error!void {
        if (legacyAddress(token.scope)) |_| return self.mutateLegacyNft(token, name, existed, timeout_ms, timer, progress) else |_| {}
        return self.mutateScopedNft(token, name, existed, timer, progress);
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
        nl.receiveAcknowledgments(&sock, related[1..count], related[0 .. count + 1], @min(try self.remainingMs(timer), 2000)) catch |err| return netlinkError(err);
    }

    fn mutateScopedNft(self: *Inspector, token: DispatchToken, name: []const u8, existed: bool, timer: *std.time.Timer, progress: *MutationProgress) Error!void {
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
        var seen: u32 = 0;
        var existing_deadline: ?i64 = null;
        var deadline_initialized = false;
        for (rules.values.items) |payload| {
            const attributes = try payloadAttrs(payload, &.{ 1, 2, 3, 4, 6, 7, 8 });
            if (!mem.eql(u8, try attributes.text(1), name) or !mem.eql(u8, try attributes.text(2), "input") or attributes.values[7] == null) continue;
            const metadata = try ScopedRuleMetadata.decode(try attributes.get(7));
            if (!mem.eql(u8, &metadata.effect_id, &token.effect_id)) continue;
            if (!std.meta.eql(metadata.scope, token.scope) or metadata.count != part_count or metadata.part >= 32) return error.ForeignState;
            if (!deadline_initialized) {
                existing_deadline = metadata.deadline_us;
                deadline_initialized = true;
            } else if (metadata.deadline_us != existing_deadline) return error.ForeignState;
            const bit = @as(u32, 1) << @intCast(metadata.part);
            if (seen & bit != 0 or handle_count == handles.len) return error.UnknownState;
            seen |= bit;
            handles[handle_count] = try attributes.number(u64, 3);
            if (handles[handle_count] == 0) return error.UnknownState;
            handle_count += 1;
        }
        const wanted = (@as(u32, 1) << @intCast(part_count)) - 1;
        if (existed != (handle_count != 0) or (handle_count != 0 and (handle_count != part_count or seen != wanted))) return error.Changed;

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
            const deadline: ?i64 = if (token.operation.ensure_present == .finite_deadline_us) token.operation.ensure_present.finite_deadline_us else null;
            for (0..part_count) |part| {
                const metadata = ScopedRuleMetadata{ .effect_id = token.effect_id, .part = @intCast(part), .count = @intCast(part_count), .deadline_us = deadline, .scope = token.scope };
                const userdata = try metadata.encode();
                const payload = nft.buildScopedDropRulePayload(&payloads[handle_count + part], name, "input", token.scope, part, &userdata) catch |err| return scopeBuildError(err);
                related[count] = sock.nextSeq();
                batch.add(nl.nfnlMsgType(nl.NFNL.SUBSYS_NFTABLES, nft.NFT_MSG.NEWRULE), linux.NLM_F_REQUEST | linux.NLM_F_ACK | linux.NLM_F_CREATE | linux.NLM_F_EXCL | 0x800, related[count], sock.port_id, payload) catch |err| return netlinkError(err);
                count += 1;
            }
        }
        if (count == 1) return error.Changed;
        related[count] = sock.nextSeq();
        const bytes = batch.commit(related[count], sock.port_id, nl.NFNL.SUBSYS_NFTABLES) catch |err| return netlinkError(err);
        const send_timeout = @min(try self.remainingMs(timer), 2000);
        progress.requested = true;
        nl.sendKernel(&sock, bytes, send_timeout) catch |err| return netlinkError(err);
        nl.receiveAcknowledgments(&sock, related[1..count], related[0 .. count + 1], @min(try self.remainingMs(timer), 2000)) catch |err| return netlinkError(err);
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
        self.work_messages = 0;
        self.retained_bytes = 0;
        defer self.retained_bytes = 0;
        var timer = std.time.Timer.start() catch return error.SystemError;
        var first = try self.readOnce(&timer);
        defer first.deinit();
        self.retained_bytes = first.entries.len * @sizeOf(Entry);
        var second = try self.readOnce(&timer);
        errdefer second.deinit();
        if (first.entries.len != second.entries.len or !mem.eql(u8, &first.fingerprint, &second.fingerprint)) return error.Changed;
        for (first.entries, second.entries) |before, after| {
            if (!std.meta.eql(entryScope(before), entryScope(after)) or !std.meta.eql(before.effect_id, after.effect_id) or before.deadline_us != after.deadline_us) return error.Changed;
            if (before.remaining_ms) |remaining| {
                if ((after.remaining_ms orelse return error.Changed) > remaining) return error.Changed;
            }
        }
        second.observed_start_ns = first.observed_start_ns;
        return second;
    }
    fn readOnce(self: *Inspector, timer: *std.time.Timer) Error!Snapshot {
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
        return builder.finish(start, timer.read());
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
fn findEntry(entries: []const Entry, scope: CanonicalScope, effect_id: [32]u8) Error!?Entry {
    for (entries) |entry| {
        if (!std.meta.eql(entryScope(entry), scope)) continue;
        if (entry.scope != null and (entry.effect_id == null or !mem.eql(u8, &entry.effect_id.?, &effect_id))) return error.ForeignState;
        return entry;
    }
    return null;
}
fn otherEntriesHash(entries: []const Entry, except: CanonicalScope) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    for (entries) |entry| {
        const candidate = entryScope(entry);
        if (std.meta.eql(candidate, except)) continue;
        const bytes = candidate.encode() catch continue;
        hash.update(&bytes);
        hash.update(&.{ @intFromBool(entry.remaining_ms != null), @intFromBool(entry.deadline_us != null), @intFromBool(entry.effect_id != null) });
        if (entry.deadline_us) |deadline| hash.update(mem.asBytes(&deadline));
        if (entry.effect_id) |identity| hash.update(&identity);
    }
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}
fn effectMatches(operation: EffectOperation, transport: Transport, entry: ?Entry, start_us: i64, end_us: i64) bool {
    if (operation == .ensure_absent) return entry == null;
    const present = entry orelse return false;
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
    const tolerance: u64 = if (transport == .ipset) 1_000_000 else 10_000;
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
    fn finish(self: *Builder, start: u64, end: u64) Error!Snapshot {
        mem.sort(Entry, self.entries.items, {}, entryLess);
        for (self.entries.items, 0..) |e, index| {
            if (index > 0 and !entryLess({}, self.entries.items[index - 1], e)) return error.UnknownState;
            const scope_bytes = entryScope(e).encode() catch return error.UnknownState;
            self.topology.update(&scope_bytes);
            self.topology.update(&.{ @intFromBool(e.remaining_ms != null), @intFromBool(e.deadline_us != null), @intFromBool(e.effect_id != null) });
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

fn buildFixedScopedArgv(
    argv: *[24][]const u8,
    subject_buf: *[64]u8,
    port_buf: *[16]u8,
    comment_buf: *[scoped_comment_bytes]u8,
    binary: []const u8,
    chain: []const u8,
    metadata: ScopedRuleMetadata,
    operation: enum { insert, delete },
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

const FixedScopedGroup = struct { metadata: ScopedRuleMetadata, parts: u32 = 0 };

fn collectFixedScopedGroup(groups: *std.ArrayList(FixedScopedGroup), metadata: ScopedRuleMetadata, limits: Limits) Error!void {
    var group_index: ?usize = null;
    for (groups.items, 0..) |group, index| if (mem.eql(u8, &group.metadata.effect_id, &metadata.effect_id)) {
        group_index = index;
        break;
    };
    if (group_index == null) {
        if (groups.items.len >= limits.max_entries or groups.items.len >= limits.max_bytes / @sizeOf(FixedScopedGroup)) return error.LimitExceeded;
        try groups.append(.{ .metadata = metadata });
        group_index = groups.items.len - 1;
    }
    const group = &groups.items[group_index.?];
    if (!std.meta.eql(group.metadata.scope, metadata.scope) or group.metadata.count != metadata.count or
        group.metadata.deadline_us != metadata.deadline_us or metadata.part >= 32)
        return error.ForeignState;
    const bit = @as(u32, 1) << @intCast(metadata.part);
    if (group.parts & bit != 0) return error.UnknownState;
    group.parts |= bit;
}

fn finishFixedScopedGroups(builder: *Builder, groups: []const FixedScopedGroup) Error!void {
    for (groups) |group| {
        const wanted = (@as(u32, 1) << @intCast(group.metadata.count)) - 1;
        if (group.parts != wanted) return error.Incomplete;
        try builder.add(.{
            .address = subjectAddress(group.metadata.scope.subject),
            .scope = group.metadata.scope,
            .deadline_us = group.metadata.deadline_us,
            .effect_id = group.metadata.effect_id,
        });
    }
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
    var scoped = std.ArrayList(FixedScopedGroup).init(builder.allocator);
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
                try collectFixedScopedGroup(&scoped, metadata, builder.limits);
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
    try finishFixedScopedGroups(builder, scoped.items);
    builder.topology.update(marker);
    return true;
}

fn setName(name: []const u8, v6: bool, buf: *[31]u8) Error![]const u8 {
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
        else => error.UnknownState,
    };
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
        const ScopedGroup = struct { metadata: ScopedRuleMetadata, parts: u32 = 0 };
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
            const part_count = nft.scopeRulePartCount(metadata.scope) catch |err| return scopeBuildError(err);
            if (part_count != metadata.count) return error.ForeignState;
            var expected_buf: [2048]u8 align(4) = undefined;
            const expected = nft.buildScopedDropRulePayload(&expected_buf, name, "input", metadata.scope, metadata.part, try a.get(7)) catch |err| return scopeBuildError(err);
            const expected_attrs = try payloadAttrs(expected, &.{ 1, 2, 4, 7 });
            if (!try equalExpressions(try a.get(4), try expected_attrs.get(4))) return error.ForeignState;
            _ = try a.number(u64, 3);
            var group_index: ?usize = null;
            for (scoped.items, 0..) |group, index| if (mem.eql(u8, &group.metadata.effect_id, &metadata.effect_id)) {
                group_index = index;
                break;
            };
            if (group_index == null) {
                if (scoped.items.len >= builder.limits.max_entries or scoped.items.len >= builder.limits.max_bytes / @sizeOf(ScopedGroup)) return error.LimitExceeded;
                try scoped.append(.{ .metadata = metadata });
                group_index = scoped.items.len - 1;
            }
            const group = &scoped.items[group_index.?];
            if (!std.meta.eql(group.metadata.scope, metadata.scope) or group.metadata.count != metadata.count or
                group.metadata.deadline_us != metadata.deadline_us or metadata.part >= 32)
                return error.ForeignState;
            const bit = @as(u32, 1) << @intCast(metadata.part);
            if (group.parts & bit != 0) return error.UnknownState;
            group.parts |= bit;
            builder.topology.update(try a.get(3));
        }
        if (!seen[0] or !seen[1]) return error.ForeignState;
        for (scoped.items) |group| {
            const wanted = if (group.metadata.count == 32) std.math.maxInt(u32) else (@as(u32, 1) << @intCast(group.metadata.count)) - 1;
            if (group.parts != wanted) return error.Incomplete;
            try builder.add(.{
                .address = subjectAddress(group.metadata.scope.subject),
                .scope = group.metadata.scope,
                .deadline_us = group.metadata.deadline_us,
                .effect_id = group.metadata.effect_id,
            });
        }
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

test "native firewall: typed projection refuses scope widening" {
    const address = try shared.IpAddress.parse("192.0.2.3");
    try (Scope{ .address = address, .prefix = 32 }).validate();
    try std.testing.expectError(error.UnsupportedScope, (Scope{ .address = address, .prefix = 24 }).validate());
    try std.testing.expectError(error.UnsupportedScope, (Scope{ .address = address, .prefix = 32, .protocol = .tcp }).validate());
}

test "native firewall: every transport shares the frozen N3 validation gate" {
    const selected = CanonicalScope{
        .subject = try canonical_scope.Subject.parseNetwork("2001:db8::/64"),
        .protocols = try canonical_scope.Protocols.list(&.{ .tcp, .udp }),
        .ports = try canonical_scope.Ports.list(&.{canonical_scope.PortRange.one(443)}),
    };
    for ([_]Transport{ .nftables, .ipset, .iptables }) |transport| try validateCanonicalScope(transport, selected);

    var unsupported = selected;
    unsupported.topology.hook = .forward;
    for ([_]Transport{ .nftables, .ipset, .iptables }) |transport|
        try std.testing.expectError(error.UnsupportedScope, validateCanonicalScope(transport, unsupported));

    const address = try shared.IpAddress.parse("192.0.2.7");
    const legacy = try canonicalizeLegacyScope(.{ .address = address, .prefix = 32 });
    try std.testing.expect(legacy.subject.kind == .host);
    try std.testing.expect(legacy.protocols.isAll());
    try std.testing.expect(legacy.ports.isAll());
}

test "native firewall: fixed scoped argv comment and readback are canonical" {
    const scope = CanonicalScope{
        .subject = try canonical_scope.Subject.parseNetwork("198.51.100.0/24"),
        .protocols = try canonical_scope.Protocols.one(.udp),
        .ports = try canonical_scope.Ports.list(&.{ canonical_scope.PortRange.one(35271), .{ .first = 35280, .last = 35282 } }),
    };
    var output = std.ArrayList(u8).init(std.testing.allocator);
    defer output.deinit();
    try output.appendSlice(policies ++ test_chain);
    for (0..2) |part| {
        const metadata = ScopedRuleMetadata{
            .effect_id = [_]u8{0x6e} ** 32,
            .part = @intCast(part),
            .count = 2,
            .deadline_us = 9_000_000,
            .scope = scope,
        };
        const comment = try metadata.encodeComment();
        try std.testing.expectEqualDeep(metadata, try ScopedRuleMetadata.decodeComment(&comment));
        var argv: [24][]const u8 = undefined;
        var subject_buf: [64]u8 = undefined;
        var port_buf: [16]u8 = undefined;
        var comment_buf: [scoped_comment_bytes]u8 = undefined;
        const command_argv = try buildFixedScopedArgv(&argv, &subject_buf, &port_buf, &comment_buf, "/usr/sbin/iptables", test_name, metadata, .insert);
        try std.testing.expectEqualStrings("/usr/sbin/iptables", command_argv[0]);
        try std.testing.expectEqualStrings("-I", command_argv[3]);
        try std.testing.expectEqualStrings("198.51.100.0/24", command_argv[7]);
        try std.testing.expectEqualStrings(if (part == 0) "35271" else "35280:35282", command_argv[13]);
        try output.writer().print("-A {s} -s 198.51.100.0/24 -p udp -m udp --dport {s} -m comment --comment \"{s}\" -j DROP\n", .{ test_name, if (part == 0) "35271" else "35280:35282", &comment });
    }
    try output.appendSlice(test_end);
    var builder = Builder.init(std.testing.allocator, test_id, .{});
    defer builder.deinit();
    try std.testing.expect(try parseIptables(&builder, output.items, false));
    try std.testing.expectEqual(@as(usize, 1), builder.entries.items.len);
    try std.testing.expectEqualDeep(scope, builder.entries.items[0].scope.?);
    try std.testing.expectEqual(@as(?i64, 9_000_000), builder.entries.items[0].deadline_us);
    try std.testing.expectEqualSlices(u8, &([_]u8{0x6e} ** 32), &builder.entries.items[0].effect_id.?);

    var malformed = try (ScopedRuleMetadata{ .effect_id = [_]u8{0x6e} ** 32, .part = 0, .count = 2, .deadline_us = 9_000_000, .scope = scope }).encodeComment();
    malformed[malformed.len - 1] = if (malformed[malformed.len - 1] == 'A') 'B' else 'A';
    try std.testing.expectError(error.UnknownState, ScopedRuleMetadata.decodeComment(&malformed));
}

const test_id = Installation{ .id = [_]u8{0x31} ** 16, .transport = .iptables };
const test_name = "f2z_313131313131313131313131";
const test_marker = "fail2zig:v1:31313131313131313131313131313131";
const policies = "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n";
const test_chain = "-N " ++ test_name ++ "\n-A INPUT -m comment --comment \"" ++ test_marker ++ "\" -j " ++ test_name ++ "\n";
const test_end = "-A " ++ test_name ++ " -m comment --comment \"" ++ test_marker ++ "\" -j RETURN\n";

test "native firewall: complete iptables read distinguishes owned empty and absent" {
    var b = Builder.init(std.testing.allocator, test_id, .{});
    defer b.deinit();
    try std.testing.expect(!try parseIptables(&b, policies, false));
    try std.testing.expect(try parseIptables(&b, policies ++ test_chain ++ test_end, false));
    try std.testing.expectEqual(@as(usize, 0), b.entries.items.len);
    try std.testing.expectError(error.Incomplete, parseIptables(&b, "", false));
    try std.testing.expectError(error.Incomplete, parseIptables(&b, "-P INPUT ACCEPT\n", false));
}
test "native firewall: foreign, widened and bypassed iptables topology refuses" {
    var b = Builder.init(std.testing.allocator, test_id, .{});
    defer b.deinit();
    try std.testing.expectError(error.ForeignState, parseIptables(&b, policies ++ test_chain, false));
    try std.testing.expectError(error.ForeignState, parseIptables(&b, policies ++ test_chain ++ test_end ++ "-A " ++ test_name ++ " -s 192.0.2.1/32 -j DROP\n", false));
    try std.testing.expectError(error.UnsupportedScope, parseIptables(&b, policies ++ test_chain ++ "-A " ++ test_name ++ " -s 192.0.2.0/24 -j DROP\n" ++ test_end, false));
    try std.testing.expectError(error.ForeignState, parseIptables(&b, policies ++ "-A INPUT -j ACCEPT\n" ++ test_chain ++ test_end, false));
}
fn allocationFixture(allocator: mem.Allocator) !void {
    var b = Builder.init(allocator, test_id, .{});
    defer b.deinit();
    _ = try parseIptables(&b, policies ++ test_chain ++ "-A " ++ test_name ++ " -s 192.0.2.1/32 -j DROP\n" ++ test_end, false);
    _ = try parseIptables(&b, policies ++ test_chain ++ "-A " ++ test_name ++ " -s 2001:db8::1/128 -j DROP\n" ++ test_end, true);
    b.present = true;
    var snapshot = try b.finish(0, 1);
    defer snapshot.deinit();
    try std.testing.expectEqual(@as(usize, 2), snapshot.entries.len);
    try std.testing.expectEqual(@as(usize, 0), (try snapshot.page(2)).len);
    try std.testing.expectError(error.Incomplete, snapshot.page(3));
}
test "native firewall: dual-family snapshots release all failing allocations" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationFixture, .{});
}
test "native firewall: duplicate and entry budget failures cannot return complete" {
    var b = Builder.init(std.testing.allocator, test_id, .{ .max_entries = 1 });
    defer b.deinit();
    const entry = Entry{ .address = try shared.IpAddress.parse("192.0.2.1") };
    try b.add(entry);
    try std.testing.expectError(error.LimitExceeded, b.add(entry));
    b.limits.max_entries = 2;
    try b.add(entry);
    try std.testing.expectError(error.UnknownState, b.finish(0, 1));
}
test "native firewall: ipset strict member and finite timeout parsing" {
    var id = test_id;
    id.transport = .ipset;
    var b = Builder.init(std.testing.allocator, id, .{});
    defer b.deinit();
    const create = "create " ++ test_name ++ "_4 hash:ip family inet hashsize 1024 maxelem 65536 timeout 0\n";
    try std.testing.expect(try parseIpset(&b, create ++ "add " ++ test_name ++ "_4 192.0.2.1 timeout 19\n", false));
    try std.testing.expectEqual(@as(?u64, 19_000), b.entries.items[0].remaining_ms);
    try std.testing.expectError(error.UnknownState, parseIpset(&b, create ++ "add " ++ test_name ++ "_4 malformed\n", false));
    try std.testing.expectError(error.ForeignState, parseIpset(&b, "create " ++ test_name ++ "_4 hash:net family inet timeout 0\n", false));
    try std.testing.expectError(error.UnknownState, parseIpset(&b, create ++ "add " ++ test_name ++ "_4 192.0.2.1 timeout 18446744073709551615\n", false));
}
test "native firewall: tokenizer never evaluates or silently truncates syntax" {
    try std.testing.expectError(error.Incomplete, Tokens.parse("-A chain --comment \"unterminated"));
    try std.testing.expectError(error.UnknownState, Tokens.parse("-A chain --comment a\\b"));
    try std.testing.expectError(error.UnknownState, Tokens.parse("-A chain --comment \"one\"two"));
    const t = try Tokens.parse("-A chain --comment \"$(literal)\"");
    try std.testing.expectEqualStrings("$(literal)", t.values[3]);
}
test "native firewall: attribute duplicate unknown and length bounds" {
    var bytes: [16]u8 = @splat(0);
    mem.writeInt(u16, bytes[0..2], 8, @import("builtin").cpu.arch.endian());
    mem.writeInt(u16, bytes[2..4], 1, @import("builtin").cpu.arch.endian());
    @memcpy(bytes[8..16], bytes[0..8]);
    try std.testing.expectError(error.UnknownState, AttrMap.parse(&bytes, &.{1}));
    try std.testing.expectError(error.UnknownState, AttrMap.parse(bytes[0..8], &.{2}));
    try std.testing.expectError(error.Incomplete, AttrMap.parse(bytes[0..7], &.{1}));
}

test "native firewall: original deadline quantization and finite verification reject widening" {
    const finite = EffectOperation{ .ensure_present = .{ .finite_deadline_us = 2_100_001 } };
    try std.testing.expectEqual(@as(u64, 1101), try deadlineUnits(finite, .nftables, 1_000_000));
    try std.testing.expectEqual(@as(u64, 2), try deadlineUnits(finite, .ipset, 1_000_000));
    try std.testing.expectEqual(@as(u64, 1), try deadlineUnits(finite, .ipset, 2_100_000));
    try std.testing.expectError(error.ExpiredIntent, deadlineUnits(finite, .iptables, 2_100_001));
    const max = EffectOperation{ .ensure_present = .{ .finite_deadline_us = 2_147_483_000_001 } };
    try std.testing.expectEqual(@as(u64, 2_147_483), try deadlineUnits(max, .ipset, 1));
    try std.testing.expectError(error.UnsupportedDeadline, deadlineUnits(max, .ipset, 0));
    const address = try shared.IpAddress.parse("192.0.2.7");
    try std.testing.expect(!effectMatches(finite, .nftables, .{ .address = address, .remaining_ms = null }, 1_000_000, 1_000_100));
    try std.testing.expect(!effectMatches(finite, .nftables, .{ .address = address, .remaining_ms = 30_000 }, 1_000_000, 1_000_100));
    try std.testing.expect(!effectMatches(finite, .ipset, .{ .address = address, .remaining_ms = 30_000 }, 1_000_000, 1_000_100));
    try std.testing.expect(!effectMatches(finite, .ipset, .{ .address = address, .remaining_ms = std.math.maxInt(u64) / 1000 }, 1_000_000, 1_000_100));
}
test "native firewall: reserved inventory refuses incomplete framing and all legacy prefixes" {
    try scanSavedTables("# comment\n*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n");
    try std.testing.expectError(error.Incomplete, scanSavedTables("*filter\n:INPUT ACCEPT [0:0]\n"));
    try std.testing.expectError(error.Incomplete, scanSavedTables("COMMIT\n"));
    try std.testing.expectError(error.ForeignState, scanSavedTables("*mangle\n:FAIL2ZIG-old - [0:0]\nCOMMIT\n"));
    try std.testing.expectError(error.ForeignState, scanSavedTables("*filter\n:f2z_lost - [0:0]\nCOMMIT\n"));
}

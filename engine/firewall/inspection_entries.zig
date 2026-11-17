// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Orders, finds and compares snapshot entries and converts effect deadlines into kernel timeout units.
// Holds: Hosts sort by family then address and scopes by their encoded bytes, and a deadline converts to timeout units rounded up.

const std = @import("std");
const shared = @import("shared");
const canonical_scope = @import("scope.zig");
const mem = @import("std").mem;
const CanonicalScope = @import("inspection.zig").CanonicalScope;
const EffectOperation = @import("inspection.zig").EffectOperation;
const Entry = @import("inspection.zig").Entry;
const Error = @import("inspection.zig").Error;
const Lease = @import("inspection.zig").Lease;
const Transport = @import("inspection.zig").Transport;
const legacyAddress = @import("inspection.zig").legacyAddress;
const subjectAddress = @import("inspection.zig").subjectAddress;

pub fn deadlineUnits(operation: EffectOperation, transport: Transport, now_us: i64) Error!u64 {
    if (now_us < 0) return error.UnsupportedDeadline;
    if (operation != .ensure_present or operation.ensure_present == .permanent) return 0;
    const deadline = operation.ensure_present.finite_deadline_us;
    if (deadline <= now_us) return error.ExpiredIntent;
    const delta: u64 = @intCast(deadline - now_us);
    const quantum: u64 = if (transport == .ipset) 1_000_000 else 1000;
    // Why: Rounding up keeps the kernel timeout from ending before the deadline.
    const units = delta / quantum + @intFromBool(delta % quantum != 0);
    if (transport == .ipset and units > 2_147_483) return error.UnsupportedDeadline;
    return units;
}
// Why: Under ipset, a scope other than a plain host is an iptables rule, so it is timed as iptables.
pub fn timingTransport(transport: Transport, scope: CanonicalScope) Transport {
    if (transport == .ipset) {
        _ = legacyAddress(scope) catch return .iptables;
    }
    return transport;
}
pub fn entryScope(entry: Entry) CanonicalScope {
    return entry.scope orelse .{ .subject = canonical_scope.Subject.host(entry.address) };
}
// Holds: Equals bytes 0..32 of Scope.encode in scope.zig, so scopeOrder sorts scopes exactly as their encoded bytes compare.
fn scopeHeader(scope: CanonicalScope) [32]u8 {
    var bytes = [_]u8{0} ** 32;
    bytes[0] = canonical_scope.encoded_version;
    bytes[1] = @intFromEnum(scope.subject.family);
    bytes[2] = @intFromEnum(scope.subject.kind);
    bytes[3] = scope.subject.prefix;
    bytes[4] = scope.protocols.mask;
    bytes[5] = scope.ports.len;
    bytes[6] = scope.ports.endpoint_units;
    bytes[7] = @intFromEnum(scope.topology.match);
    bytes[8] = @intFromEnum(scope.topology.hook);
    bytes[9] = @intFromEnum(scope.topology.plane);
    bytes[10] = @intFromEnum(scope.topology.path);
    bytes[11] = @intFromEnum(scope.topology.interface);
    bytes[12] = @intFromEnum(scope.topology.attachment);
    bytes[13] = @intFromEnum(scope.verdict);
    bytes[14] = @intFromEnum(scope.target);
    @memcpy(bytes[16..32], &scope.subject.address);
    return bytes;
}
fn scopeOrder(a: CanonicalScope, b: CanonicalScope) std.math.Order {
    const header = mem.order(u8, &scopeHeader(a), &scopeHeader(b));
    if (header != .eq) return header;
    for (a.ports.slice(), b.ports.slice()) |left, right| {
        if (left.first != right.first) return std.math.order(left.first, right.first);
        if (left.last != right.last) return std.math.order(left.last, right.last);
    }
    return .eq;
}
fn hostOrder(a: shared.IpAddress, b: shared.IpAddress) std.math.Order {
    return switch (a) {
        .ipv4 => |left| switch (b) {
            .ipv4 => |right| std.math.order(left, right),
            .ipv6 => .lt,
        },
        .ipv6 => |left| switch (b) {
            .ipv4 => .gt,
            .ipv6 => |right| std.math.order(left, right),
        },
    };
}
fn entryOrder(entry: Entry, scope: CanonicalScope, host: ?shared.IpAddress) std.math.Order {
    if (entry.scope == null) if (host) |address| return hostOrder(entry.address, address);
    return scopeOrder(entryScope(entry), scope);
}
pub fn entryIndex(entries: []const Entry, scope: CanonicalScope) Error!?usize {
    _ = scope.encode() catch return null;
    const address = subjectAddress(scope.subject);
    const host: ?shared.IpAddress = if (std.meta.eql(scope, CanonicalScope{ .subject = canonical_scope.Subject.host(address) })) address else null;
    var low: usize = 0;
    var high = entries.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        switch (entryOrder(entries[middle], scope, host)) {
            .lt => low = middle + 1,
            .gt => high = middle,
            .eq => return if (std.meta.eql(entryScope(entries[middle]), scope)) middle else null,
        }
    }
    return null;
}
pub fn findEntry(entries: []const Entry, scope: CanonicalScope, effect_id: [32]u8) Error!?Entry {
    const entry = entries[try entryIndex(entries, scope) orelse return null];
    if (entry.scope != null and (entry.effect_id == null or !mem.eql(u8, &entry.effect_id.?, &effect_id))) return error.ForeignState;
    return entry;
}
// Why: An element whose remaining timeout fits in window_ns can expire between the two reads, so its absence is not a change.
pub fn sameEntries(before: []const Entry, after: []const Entry, except: ?CanonicalScope, window_ns: u64, transport: Transport) bool {
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
// Why: ipset reports whole seconds, and nftables timeouts start after the send and round to jiffies; one second covers both.
fn timeoutToleranceUs(transport: Transport) u64 {
    _ = transport;
    return 1_000_000;
}
pub fn effectMatches(operation: EffectOperation, transport: Transport, entry: ?Entry, start_us: i64, end_us: i64) bool {
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
pub fn entryLess(_: void, a: Entry, b: Entry) bool {
    if (a.scope == null and b.scope == null) return hostOrder(a.address, b.address) == .lt;
    return scopeOrder(entryScope(a), entryScope(b)) == .lt;
}

pub fn leaseDeadline(lease: Lease) ?i64 {
    return switch (lease) {
        .permanent => null,
        .finite_deadline_us => |deadline| deadline,
    };
}

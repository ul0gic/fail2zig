// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const shared = @import("shared");

const IpAddress = shared.IpAddress;
const JailId = shared.JailId;
const Timestamp = shared.Timestamp;
const Duration = shared.Duration;
const BanState = shared.BanState;

pub const EvictionPolicy = enum {
    evict_oldest,
    ban_all_and_alert,
    drop_oldest_unbanned,
};

pub const BanTimeIncrement = struct {
    enabled: bool = false,
    multiplier: f64 = 1.0,
    factor: f64 = 1.0,
    formula: Formula = .exponential,
    max_bantime: Duration = 86_400 * 7,

    pub const Formula = enum { linear, exponential };
};

pub const Config = struct {
    max_entries: u32 = 4096,
    findtime: Duration = 600,
    maxretry: u32 = 5,
    bantime: Duration = 600,
    bantime_increment: BanTimeIncrement = .{},
    eviction_policy: EvictionPolicy = .drop_oldest_unbanned,
};

pub const approx_bytes_per_entry: usize = 1536;

pub fn capacityFromBudget(bytes: usize) u32 {
    const est = bytes / approx_bytes_per_entry;
    if (est == 0) return 1;
    if (est > std.math.maxInt(u32)) return std.math.maxInt(u32);
    return @intCast(est);
}

pub const max_attempts_per_ip: usize = 128;

pub const IpState = struct {
    jail: JailId,
    attempt_count: u32,
    ban_count: u32,
    first_attempt: Timestamp,
    last_attempt: Timestamp,
    ban_state: BanState,
    ban_expiry: ?Timestamp,
    /// True only when the dispatcher handed this ban to the firewall; a log-only would-ban stays false so reconcile/expiry never touch the backend for it (BUG-012).
    enforced: bool = false,

    ring: [max_attempts_per_ip]Timestamp,
    ring_len: u8,

    fn pruneRing(self: *IpState, cutoff: Timestamp) void {
        var write: usize = 0;
        var read: usize = 0;
        while (read < self.ring_len) : (read += 1) {
            if (self.ring[read] >= cutoff) {
                self.ring[write] = self.ring[read];
                write += 1;
            }
        }
        self.ring_len = @intCast(write);
    }

    fn pushRing(self: *IpState, ts: Timestamp) void {
        if (self.ring_len < max_attempts_per_ip) {
            self.ring[self.ring_len] = ts;
            self.ring_len += 1;
            return;
        }
        var min_i: usize = 0;
        var min_v: Timestamp = self.ring[0];
        var i: usize = 1;
        while (i < self.ring_len) : (i += 1) {
            if (self.ring[i] < min_v) {
                min_v = self.ring[i];
                min_i = i;
            }
        }
        self.ring[min_i] = ts;
    }

    pub fn isBanned(self: *const IpState) bool {
        return self.ban_state == .banned;
    }
};

pub const BanDecision = struct {
    ip: IpAddress,
    jail: JailId,
    duration: Duration,
    ban_count: u32,
};

pub const Cidr = union(enum) {
    v4: struct { net: u32, mask: u32 },
    v6: struct { net: u128, mask: u128 },

    pub const ParseError = error{InvalidCidr};

    pub fn parse(s: []const u8) ParseError!Cidr {
        var prefix: ?u8 = null;
        var addr_part: []const u8 = s;
        if (std.mem.indexOfScalar(u8, s, '/')) |idx| {
            if (idx == 0 or idx == s.len - 1) return error.InvalidCidr;
            addr_part = s[0..idx];
            const p = std.fmt.parseInt(u8, s[idx + 1 ..], 10) catch
                return error.InvalidCidr;
            prefix = p;
        }

        const ip = IpAddress.parse(addr_part) catch return error.InvalidCidr;
        switch (ip) {
            .ipv4 => |v| {
                const p = prefix orelse 32;
                if (p > 32) return error.InvalidCidr;
                const mask = maskIpv4(p);
                return .{ .v4 = .{ .net = v & mask, .mask = mask } };
            },
            .ipv6 => |v| {
                const p = prefix orelse 128;
                if (p > 128) return error.InvalidCidr;
                const mask = maskIpv6(p);
                return .{ .v6 = .{ .net = v & mask, .mask = mask } };
            },
        }
    }

    pub fn contains(self: Cidr, ip: IpAddress) bool {
        return switch (self) {
            .v4 => |n| switch (ip) {
                .ipv4 => |v| (v & n.mask) == n.net,
                .ipv6 => false,
            },
            .v6 => |n| switch (ip) {
                .ipv6 => |v| (v & n.mask) == n.net,
                .ipv4 => false,
            },
        };
    }
};

fn maskIpv4(prefix: u8) u32 {
    if (prefix == 0) return 0;
    if (prefix >= 32) return 0xFFFF_FFFF;
    // Arithmetic shift avoids the UB of << 32 on a 32-bit value.
    return @as(u32, 0xFFFF_FFFF) << @intCast(32 - prefix);
}

fn maskIpv6(prefix: u8) u128 {
    if (prefix == 0) return 0;
    if (prefix >= 128) return ~@as(u128, 0);
    const ones: u128 = ~@as(u128, 0);
    return ones << @intCast(128 - prefix);
}

pub const Stats = struct {
    entry_count: usize = 0,
    attempts_observed: u64 = 0,
    bans_triggered: u64 = 0,
    ignored_attempts: u64 = 0,
    evictions: u64 = 0,
};

pub const Error = error{
    OutOfMemory,
    CapacityZero,
    InvalidIgnoreCidr,
};

const Map = std.AutoHashMap(IpAddress, IpState);

pub const StateTracker = struct {
    allocator: std.mem.Allocator,
    config: Config,
    map: Map,
    ignore: std.ArrayList(Cidr),
    stats_inner: Stats,
    lifetime_bans: u64 = 0,

    reserved: bool = false,

    pub fn init(allocator: std.mem.Allocator, config: Config) Error!StateTracker {
        if (config.max_entries == 0) return error.CapacityZero;

        const map = Map.init(allocator);
        const ignore = std.ArrayList(Cidr).init(allocator);

        return .{
            .allocator = allocator,
            .config = config,
            .map = map,
            .ignore = ignore,
            .stats_inner = .{},
            .lifetime_bans = 0,
            .reserved = false,
        };
    }

    pub fn ensureReserved(self: *StateTracker) Error!void {
        if (self.reserved) return;
        self.map.ensureTotalCapacity(self.config.max_entries) catch return error.OutOfMemory;
        self.reserved = true;
    }

    pub fn recordLifetimeBan(self: *StateTracker) void {
        self.lifetime_bans += 1;
    }

    pub fn seedLifetimeBans(self: *StateTracker, count: u64) void {
        self.lifetime_bans = count;
    }

    pub fn deinit(self: *StateTracker) void {
        self.map.deinit();
        self.ignore.deinit();
        self.* = undefined;
    }

    pub fn addIgnoreCidr(self: *StateTracker, spec: []const u8) Error!void {
        const c = Cidr.parse(spec) catch return error.InvalidIgnoreCidr;
        self.ignore.append(c) catch return error.OutOfMemory;
    }

    pub fn isIgnored(self: *const StateTracker, ip: IpAddress) bool {
        for (self.ignore.items) |c| {
            if (c.contains(ip)) return true;
        }
        return false;
    }

    pub fn recordAttempt(
        self: *StateTracker,
        ip: IpAddress,
        jail: JailId,
        timestamp: Timestamp,
    ) Error!?BanDecision {
        if (self.isIgnored(ip)) {
            self.stats_inner.ignored_attempts += 1;
            return null;
        }
        self.stats_inner.attempts_observed += 1;

        try self.ensureReserved();

        const gop = self.map.getOrPut(ip) catch return error.OutOfMemory;
        if (!gop.found_existing) {
            if (self.map.count() > self.config.max_entries) {
                _ = self.map.remove(ip);
                const evicted_any = self.evictForInsert(timestamp);
                self.stats_inner.evictions += @intFromBool(evicted_any);
                if (!evicted_any) {
                    std.log.warn(
                        "state: capacity reached and no entry evictable; dropping attempt",
                        .{},
                    );
                    return null;
                }
                const gop2 = self.map.getOrPut(ip) catch return error.OutOfMemory;
                gop2.value_ptr.* = freshState(jail, timestamp);
            } else {
                gop.value_ptr.* = freshState(jail, timestamp);
            }
        } else {
            const st = gop.value_ptr;
            st.attempt_count +%= 1;
            st.last_attempt = timestamp;
            _ = &jail;
        }

        const st = self.map.getPtr(ip) orelse return null;

        const findtime_i64: Timestamp = @intCast(@min(self.config.findtime, std.math.maxInt(Timestamp)));
        const cutoff: Timestamp = timestamp -| findtime_i64;
        st.pruneRing(cutoff);
        st.pushRing(timestamp);

        if (st.ban_state != .banned and st.ring_len >= self.config.maxretry) {
            const new_ban_count = st.ban_count + 1;
            const duration = computeBantime(
                self.config.bantime,
                self.config.bantime_increment,
                new_ban_count - 1,
            );
            st.ban_state = .banned;
            st.enforced = false;
            st.ban_count = new_ban_count;
            // Saturate instead of overflow: a huge duration or near-max clock must not crash the daemon on first ban.
            const duration_i64: Timestamp = @intCast(@min(duration, std.math.maxInt(Timestamp)));
            st.ban_expiry = std.math.add(Timestamp, timestamp, duration_i64) catch blk: {
                std.log.warn("state: ban_expiry overflow, clamping to Timestamp max", .{});
                break :blk std.math.maxInt(Timestamp);
            };
            st.ring_len = 0;
            self.stats_inner.bans_triggered += 1;
            return BanDecision{
                .ip = ip,
                .jail = st.jail,
                .duration = duration,
                .ban_count = new_ban_count,
            };
        }
        return null;
    }

    pub fn clearBan(self: *StateTracker, ip: IpAddress) void {
        if (self.map.getPtr(ip)) |st| {
            st.ban_state = .expired;
            st.ban_expiry = null;
            st.enforced = false;
            st.ring_len = 0;
        }
    }

    pub fn markEnforced(self: *StateTracker, ip: IpAddress) void {
        if (self.map.getPtr(ip)) |st| {
            if (st.ban_state == .banned) st.enforced = true;
        }
    }

    pub fn forget(self: *StateTracker, ip: IpAddress) void {
        _ = self.map.remove(ip);
    }

    pub fn contains(self: *const StateTracker, ip: IpAddress) bool {
        return self.map.contains(ip);
    }

    pub fn get(self: *const StateTracker, ip: IpAddress) ?*const IpState {
        return self.map.getPtr(ip);
    }

    pub fn iterator(self: *const StateTracker) Map.Iterator {
        return self.map.iterator();
    }

    pub fn stats(self: *const StateTracker) Stats {
        var s = self.stats_inner;
        s.entry_count = self.map.count();
        return s;
    }

    pub fn evict(self: *StateTracker) ?IpState {
        return switch (self.config.eviction_policy) {
            .evict_oldest => self.evictOldest(true),
            .drop_oldest_unbanned => self.evictOldest(false),
            .ban_all_and_alert => blk: {
                std.log.warn(
                    "state: capacity reached under ban_all_and_alert policy ({d} entries)",
                    .{self.map.count()},
                );
                break :blk null;
            },
        };
    }

    fn evictOldest(self: *StateTracker, evict_banned: bool) ?IpState {
        var oldest_key: ?IpAddress = null;
        var oldest_val: Timestamp = std.math.maxInt(Timestamp);
        var it = self.map.iterator();
        while (it.next()) |entry| {
            if (!evict_banned and entry.value_ptr.ban_state == .banned) continue;
            if (entry.value_ptr.last_attempt < oldest_val) {
                oldest_val = entry.value_ptr.last_attempt;
                oldest_key = entry.key_ptr.*;
            }
        }
        if (oldest_key) |k| {
            const removed = self.map.fetchRemove(k);
            if (removed) |kv| return kv.value;
        }
        return null;
    }

    fn evictForInsert(self: *StateTracker, _: Timestamp) bool {
        const before = self.map.count();
        _ = self.evict();
        return self.map.count() < before;
    }
};

fn freshState(jail: JailId, timestamp: Timestamp) IpState {
    return .{
        .jail = jail,
        .attempt_count = 1,
        .ban_count = 0,
        .first_attempt = timestamp,
        .last_attempt = timestamp,
        .ban_state = .monitoring,
        .ban_expiry = null,
        .ring = [_]Timestamp{0} ** max_attempts_per_ip,
        .ring_len = 0,
    };
}

pub fn computeBantime(base: Duration, incr: BanTimeIncrement, ban_count: u32) Duration {
    if (!incr.enabled or ban_count == 0) {
        return @min(base, incr.max_bantime);
    }
    const base_f: f64 = @floatFromInt(base);
    const n: f64 = @floatFromInt(ban_count);
    const scaled: f64 = switch (incr.formula) {
        .exponential => base_f * incr.multiplier * std.math.pow(f64, incr.factor, n),
        .linear => base_f * incr.multiplier * (1.0 + incr.factor * n),
    };
    if (!std.math.isFinite(scaled) or scaled <= 0.0) {
        return incr.max_bantime;
    }
    if (scaled >= @as(f64, @floatFromInt(incr.max_bantime))) {
        return incr.max_bantime;
    }
    const rounded: u64 = @intFromFloat(scaled);
    return @min(rounded, incr.max_bantime);
}

const testing = std.testing;

fn tIp(comptime s: []const u8) IpAddress {
    return IpAddress.parse(s) catch unreachable;
}

fn tJail(comptime s: []const u8) JailId {
    return JailId.fromSlice(s) catch unreachable;
}

test "state: init and deinit" {
    var tracker = try StateTracker.init(testing.allocator, .{});
    defer tracker.deinit();
    try testing.expectEqual(@as(usize, 0), tracker.stats().entry_count);
}

test "state: init rejects zero capacity" {
    try testing.expectError(
        error.CapacityZero,
        StateTracker.init(testing.allocator, .{ .max_entries = 0 }),
    );
}

test "state: QA-002 init defers bucket reservation until first insert" {
    var tracker = try StateTracker.init(testing.allocator, .{ .max_entries = 4096 });
    defer tracker.deinit();
    try testing.expect(!tracker.reserved);
    try testing.expectEqual(@as(usize, 0), tracker.map.capacity());

    _ = try tracker.recordAttempt(tIp("1.2.3.4"), tJail("sshd"), 1_000);
    try testing.expect(tracker.reserved);
    try testing.expect(tracker.map.capacity() >= 4096);
}

test "state: QA-002 an ignored IP does not trigger reservation" {
    var tracker = try StateTracker.init(testing.allocator, .{ .max_entries = 4096 });
    defer tracker.deinit();
    try tracker.addIgnoreCidr("1.2.3.4");
    _ = try tracker.recordAttempt(tIp("1.2.3.4"), tJail("sshd"), 1_000);
    try testing.expect(!tracker.reserved);
    try testing.expectEqual(@as(usize, 0), tracker.map.capacity());
}

test "state: QA-002 lazy init preserves first-insert eviction correctness" {
    var tracker = try StateTracker.init(testing.allocator, .{
        .max_entries = 3,
        .maxretry = 100,
        .findtime = 10_000,
        .eviction_policy = .evict_oldest,
    });
    defer tracker.deinit();
    const jail = tJail("sshd");
    _ = try tracker.recordAttempt(tIp("1.1.1.1"), jail, 1_000);
    _ = try tracker.recordAttempt(tIp("2.2.2.2"), jail, 2_000);
    _ = try tracker.recordAttempt(tIp("3.3.3.3"), jail, 3_000);
    _ = try tracker.recordAttempt(tIp("4.4.4.4"), jail, 4_000);
    try testing.expectEqual(@as(u32, 3), tracker.stats().entry_count);
    try testing.expect(!tracker.contains(tIp("1.1.1.1")));
    try testing.expect(tracker.contains(tIp("4.4.4.4")));
}

test "state: record single attempt below threshold" {
    var tracker = try StateTracker.init(testing.allocator, .{
        .maxretry = 3,
        .findtime = 600,
    });
    defer tracker.deinit();

    const ip = tIp("1.2.3.4");
    const jail = tJail("sshd");
    const dec = try tracker.recordAttempt(ip, jail, 1_000);
    try testing.expect(dec == null);

    const st = tracker.get(ip).?;
    try testing.expectEqual(@as(u32, 1), st.attempt_count);
    try testing.expectEqual(@as(u8, 1), st.ring_len);
    try testing.expectEqual(@as(Timestamp, 1_000), st.first_attempt);
    try testing.expectEqual(@as(Timestamp, 1_000), st.last_attempt);
    try testing.expectEqual(BanState.monitoring, st.ban_state);
}

test "state: crossing threshold triggers a BanDecision" {
    var tracker = try StateTracker.init(testing.allocator, .{
        .maxretry = 3,
        .findtime = 600,
        .bantime = 600,
    });
    defer tracker.deinit();

    const ip = tIp("1.2.3.4");
    const jail = tJail("sshd");

    try testing.expect((try tracker.recordAttempt(ip, jail, 1_000)) == null);
    try testing.expect((try tracker.recordAttempt(ip, jail, 1_100)) == null);
    const dec = (try tracker.recordAttempt(ip, jail, 1_200)).?;

    try testing.expect(IpAddress.eql(dec.ip, ip));
    try testing.expect(JailId.eql(dec.jail, jail));
    try testing.expectEqual(@as(u32, 1), dec.ban_count);
    try testing.expectEqual(@as(Duration, 600), dec.duration);

    const st = tracker.get(ip).?;
    try testing.expectEqual(BanState.banned, st.ban_state);
    try testing.expectEqual(@as(u32, 1), st.ban_count);
    try testing.expectEqual(@as(?Timestamp, 1_800), st.ban_expiry);
}

test "state: additional attempts after ban don't re-fire within same window" {
    var tracker = try StateTracker.init(testing.allocator, .{
        .maxretry = 3,
        .findtime = 600,
    });
    defer tracker.deinit();

    const ip = tIp("1.2.3.4");
    const jail = tJail("sshd");

    _ = try tracker.recordAttempt(ip, jail, 1_000);
    _ = try tracker.recordAttempt(ip, jail, 1_100);
    const first = (try tracker.recordAttempt(ip, jail, 1_200)).?;
    try testing.expectEqual(@as(u32, 1), first.ban_count);

    const second = try tracker.recordAttempt(ip, jail, 1_250);
    try testing.expect(second == null);
}

test "state: independent IPs tracked independently" {
    var tracker = try StateTracker.init(testing.allocator, .{
        .maxretry = 2,
        .findtime = 600,
    });
    defer tracker.deinit();

    const jail = tJail("sshd");
    const a = tIp("1.1.1.1");
    const b = tIp("2.2.2.2");

    try testing.expect((try tracker.recordAttempt(a, jail, 1_000)) == null);
    try testing.expect((try tracker.recordAttempt(b, jail, 1_000)) == null);
    const dec_a = (try tracker.recordAttempt(a, jail, 1_010)).?;
    try testing.expect(IpAddress.eql(dec_a.ip, a));
    try testing.expect(tracker.get(b).?.ban_state == .monitoring);
}

test "state: 3 attempts spread over 10 minutes don't cross findtime=300" {
    var tracker = try StateTracker.init(testing.allocator, .{
        .maxretry = 3,
        .findtime = 300,
    });
    defer tracker.deinit();

    const ip = tIp("9.9.9.9");
    const jail = tJail("sshd");

    try testing.expect((try tracker.recordAttempt(ip, jail, 1_000)) == null);
    try testing.expect((try tracker.recordAttempt(ip, jail, 1_400)) == null);
    try testing.expect((try tracker.recordAttempt(ip, jail, 1_800)) == null);

    const st = tracker.get(ip).?;
    try testing.expectEqual(@as(u8, 1), st.ring_len);
    try testing.expectEqual(BanState.monitoring, st.ban_state);
    try testing.expectEqual(@as(u32, 3), st.attempt_count);
}

test "state: 3 attempts in 2 minutes with findtime=300 crosses threshold" {
    var tracker = try StateTracker.init(testing.allocator, .{
        .maxretry = 3,
        .findtime = 300,
    });
    defer tracker.deinit();

    const ip = tIp("9.9.9.9");
    const jail = tJail("sshd");

    try testing.expect((try tracker.recordAttempt(ip, jail, 1_000)) == null);
    try testing.expect((try tracker.recordAttempt(ip, jail, 1_060)) == null);
    const dec = (try tracker.recordAttempt(ip, jail, 1_120)).?;
    try testing.expectEqual(@as(u32, 1), dec.ban_count);
}

test "state: findtime prune keeps only in-window timestamps" {
    var tracker = try StateTracker.init(testing.allocator, .{
        .maxretry = 100,
        .findtime = 300,
    });
    defer tracker.deinit();

    const ip = tIp("5.5.5.5");
    const jail = tJail("sshd");

    _ = try tracker.recordAttempt(ip, jail, 1_000);
    _ = try tracker.recordAttempt(ip, jail, 1_100);
    _ = try tracker.recordAttempt(ip, jail, 1_200);
    _ = try tracker.recordAttempt(ip, jail, 2_000);

    const st = tracker.get(ip).?;
    try testing.expectEqual(@as(u8, 1), st.ring_len);
    try testing.expectEqual(@as(Timestamp, 2_000), st.ring[0]);
}

test "state: evict_oldest removes the oldest last_attempt entry" {
    var tracker = try StateTracker.init(testing.allocator, .{
        .max_entries = 8,
        .maxretry = 100,
        .findtime = 10_000,
        .eviction_policy = .evict_oldest,
    });
    defer tracker.deinit();

    const jail = tJail("sshd");
    _ = try tracker.recordAttempt(tIp("1.1.1.1"), jail, 1_000);
    _ = try tracker.recordAttempt(tIp("2.2.2.2"), jail, 2_000);
    _ = try tracker.recordAttempt(tIp("3.3.3.3"), jail, 3_000);

    const evicted = tracker.evict().?;
    try testing.expectEqual(@as(Timestamp, 1_000), evicted.last_attempt);
    try testing.expect(!tracker.contains(tIp("1.1.1.1")));
    try testing.expect(tracker.contains(tIp("2.2.2.2")));
    try testing.expect(tracker.contains(tIp("3.3.3.3")));
}

test "state: drop_oldest_unbanned skips banned entries" {
    var tracker = try StateTracker.init(testing.allocator, .{
        .max_entries = 8,
        .maxretry = 1,
        .findtime = 10_000,
        .bantime = 60,
        .eviction_policy = .drop_oldest_unbanned,
    });
    defer tracker.deinit();

    const jail = tJail("sshd");
    _ = try tracker.recordAttempt(tIp("1.1.1.1"), jail, 1_000);
    try testing.expect(tracker.get(tIp("1.1.1.1")).?.ban_state == .banned);

    tracker.config.maxretry = 100;
    _ = try tracker.recordAttempt(tIp("2.2.2.2"), jail, 2_000);
    _ = try tracker.recordAttempt(tIp("3.3.3.3"), jail, 3_000);

    const evicted = tracker.evict().?;
    try testing.expectEqual(@as(Timestamp, 2_000), evicted.last_attempt);
    try testing.expect(tracker.contains(tIp("1.1.1.1")));
    try testing.expect(!tracker.contains(tIp("2.2.2.2")));
    try testing.expect(tracker.contains(tIp("3.3.3.3")));
}

test "state: drop_oldest_unbanned returns null when every entry is banned" {
    var tracker = try StateTracker.init(testing.allocator, .{
        .max_entries = 8,
        .maxretry = 1,
        .findtime = 10_000,
        .eviction_policy = .drop_oldest_unbanned,
    });
    defer tracker.deinit();

    const jail = tJail("sshd");
    _ = try tracker.recordAttempt(tIp("1.1.1.1"), jail, 1_000);
    _ = try tracker.recordAttempt(tIp("2.2.2.2"), jail, 2_000);
    try testing.expect(tracker.get(tIp("1.1.1.1")).?.ban_state == .banned);
    try testing.expect(tracker.get(tIp("2.2.2.2")).?.ban_state == .banned);
    try testing.expect(tracker.evict() == null);
}

test "state: computeBantime disabled returns base" {
    const base: Duration = 600;
    const incr: BanTimeIncrement = .{ .enabled = false, .max_bantime = 10_000 };
    try testing.expectEqual(base, computeBantime(base, incr, 0));
    try testing.expectEqual(base, computeBantime(base, incr, 5));
}

test "state: computeBantime exponential doubles per ban_count" {
    const base: Duration = 600;
    const incr: BanTimeIncrement = .{
        .enabled = true,
        .multiplier = 1.0,
        .factor = 2.0,
        .formula = .exponential,
        .max_bantime = 604_800,
    };
    try testing.expectEqual(@as(Duration, 600), computeBantime(base, incr, 0));
    try testing.expectEqual(@as(Duration, 1_200), computeBantime(base, incr, 1));
    try testing.expectEqual(@as(Duration, 2_400), computeBantime(base, incr, 2));
    try testing.expectEqual(@as(Duration, 4_800), computeBantime(base, incr, 3));
}

test "state: computeBantime caps at max_bantime" {
    const base: Duration = 600;
    const incr: BanTimeIncrement = .{
        .enabled = true,
        .multiplier = 1.0,
        .factor = 2.0,
        .formula = .exponential,
        .max_bantime = 5_000,
    };
    try testing.expectEqual(@as(Duration, 5_000), computeBantime(base, incr, 4));
    try testing.expectEqual(@as(Duration, 5_000), computeBantime(base, incr, 20));
}

test "state: computeBantime linear scales additively" {
    const base: Duration = 600;
    const incr: BanTimeIncrement = .{
        .enabled = true,
        .multiplier = 1.0,
        .factor = 1.0,
        .formula = .linear,
        .max_bantime = 100_000,
    };
    try testing.expectEqual(@as(Duration, 600), computeBantime(base, incr, 0));
    try testing.expectEqual(@as(Duration, 1_200), computeBantime(base, incr, 1));
    try testing.expectEqual(@as(Duration, 1_800), computeBantime(base, incr, 2));
}

test "state: recordAttempt escalates bantime across repeated bans" {
    var tracker = try StateTracker.init(testing.allocator, .{
        .maxretry = 2,
        .findtime = 600,
        .bantime = 600,
        .bantime_increment = .{
            .enabled = true,
            .multiplier = 1.0,
            .factor = 2.0,
            .formula = .exponential,
            .max_bantime = 10_000,
        },
    });
    defer tracker.deinit();

    const ip = tIp("4.4.4.4");
    const jail = tJail("sshd");

    _ = try tracker.recordAttempt(ip, jail, 100);
    const d1 = (try tracker.recordAttempt(ip, jail, 110)).?;
    try testing.expectEqual(@as(Duration, 600), d1.duration);

    tracker.clearBan(ip);
    _ = try tracker.recordAttempt(ip, jail, 1_000);
    const d2 = (try tracker.recordAttempt(ip, jail, 1_010)).?;
    try testing.expectEqual(@as(u32, 2), d2.ban_count);
    try testing.expectEqual(@as(Duration, 1_200), d2.duration);

    tracker.clearBan(ip);
    _ = try tracker.recordAttempt(ip, jail, 5_000);
    const d3 = (try tracker.recordAttempt(ip, jail, 5_010)).?;
    try testing.expectEqual(@as(u32, 3), d3.ban_count);
    try testing.expectEqual(@as(Duration, 2_400), d3.duration);
}

test "state: ban_all_and_alert is non-destructive and returns null" {
    var tracker = try StateTracker.init(testing.allocator, .{
        .max_entries = 8,
        .maxretry = 100,
        .findtime = 10_000,
        .eviction_policy = .ban_all_and_alert,
    });
    defer tracker.deinit();

    const jail = tJail("sshd");
    _ = try tracker.recordAttempt(tIp("1.1.1.1"), jail, 1_000);
    _ = try tracker.recordAttempt(tIp("2.2.2.2"), jail, 2_000);

    try testing.expect(tracker.evict() == null);
    try testing.expect(tracker.contains(tIp("1.1.1.1")));
    try testing.expect(tracker.contains(tIp("2.2.2.2")));
}

test "state: Cidr.parse ipv4 exact host" {
    const c = try Cidr.parse("10.0.0.5");
    try testing.expect(c.contains(tIp("10.0.0.5")));
    try testing.expect(!c.contains(tIp("10.0.0.6")));
}

test "state: Cidr.parse ipv4 /24" {
    const c = try Cidr.parse("192.168.1.0/24");
    try testing.expect(c.contains(tIp("192.168.1.1")));
    try testing.expect(c.contains(tIp("192.168.1.50")));
    try testing.expect(c.contains(tIp("192.168.1.255")));
    try testing.expect(!c.contains(tIp("192.168.2.1")));
    try testing.expect(!c.contains(tIp("10.0.0.1")));
}

test "state: Cidr.parse ipv4 /0 matches everything" {
    const c = try Cidr.parse("0.0.0.0/0");
    try testing.expect(c.contains(tIp("0.0.0.0")));
    try testing.expect(c.contains(tIp("1.2.3.4")));
    try testing.expect(c.contains(tIp("255.255.255.255")));
}

test "state: Cidr.parse ipv6 /32" {
    const c = try Cidr.parse("2001:db8::/32");
    try testing.expect(c.contains(tIp("2001:db8::1")));
    try testing.expect(c.contains(tIp("2001:db8:ffff::1")));
    try testing.expect(!c.contains(tIp("2001:db9::1")));
}

test "state: Cidr.parse rejects malformed specs" {
    try testing.expectError(error.InvalidCidr, Cidr.parse(""));
    try testing.expectError(error.InvalidCidr, Cidr.parse("/24"));
    try testing.expectError(error.InvalidCidr, Cidr.parse("1.2.3.4/"));
    try testing.expectError(error.InvalidCidr, Cidr.parse("1.2.3.4/33"));
    try testing.expectError(error.InvalidCidr, Cidr.parse("::/129"));
    try testing.expectError(error.InvalidCidr, Cidr.parse("not-an-ip"));
    try testing.expectError(error.InvalidCidr, Cidr.parse("1.2.3.4/abc"));
}

test "state: ipv4 and ipv6 CIDRs do not cross-match" {
    const v4 = try Cidr.parse("10.0.0.0/8");
    const v6 = try Cidr.parse("::/0");
    try testing.expect(v4.contains(tIp("::ffff:10.0.0.1")));
    try testing.expect(v6.contains(tIp("::1")));
    try testing.expect(!v6.contains(tIp("1.2.3.4")));
}

test "state: isIgnored blocks recordAttempt from making progress" {
    var tracker = try StateTracker.init(testing.allocator, .{
        .maxretry = 2,
        .findtime = 600,
    });
    defer tracker.deinit();
    try tracker.addIgnoreCidr("192.168.1.0/24");

    const ip_ignored = tIp("192.168.1.50");
    const ip_tracked = tIp("192.168.2.50");
    const jail = tJail("sshd");

    try testing.expect((try tracker.recordAttempt(ip_ignored, jail, 1_000)) == null);
    try testing.expect((try tracker.recordAttempt(ip_ignored, jail, 1_010)) == null);
    try testing.expect(!tracker.contains(ip_ignored));
    try testing.expectEqual(@as(u64, 2), tracker.stats().ignored_attempts);

    _ = try tracker.recordAttempt(ip_tracked, jail, 1_000);
    const dec = (try tracker.recordAttempt(ip_tracked, jail, 1_010)).?;
    try testing.expect(IpAddress.eql(dec.ip, ip_tracked));
}

test "state: addIgnoreCidr rejects malformed CIDR" {
    var tracker = try StateTracker.init(testing.allocator, .{});
    defer tracker.deinit();
    try testing.expectError(error.InvalidIgnoreCidr, tracker.addIgnoreCidr("garbage"));
}

test "state: ring buffer caps at max_attempts_per_ip, evicting oldest" {
    var tracker = try StateTracker.init(testing.allocator, .{
        .maxretry = std.math.maxInt(u32),
        .findtime = 100_000,
    });
    defer tracker.deinit();

    const ip = tIp("7.7.7.7");
    const jail = tJail("sshd");

    var t: Timestamp = 0;
    while (t < @as(Timestamp, max_attempts_per_ip + 10)) : (t += 1) {
        _ = try tracker.recordAttempt(ip, jail, t);
    }
    const st = tracker.get(ip).?;
    try testing.expectEqual(@as(u8, max_attempts_per_ip), st.ring_len);
    var min_v: Timestamp = std.math.maxInt(Timestamp);
    for (st.ring[0..st.ring_len]) |v| {
        if (v < min_v) min_v = v;
    }
    try testing.expect(min_v >= 10);
}

test "state: extreme bantime does not overflow ban_expiry (SEC-004)" {
    var tracker = try StateTracker.init(testing.allocator, .{
        .maxretry = 2,
        .findtime = 600,
        .bantime = std.math.maxInt(u64),
        .bantime_increment = .{
            .enabled = false,
            .max_bantime = std.math.maxInt(u64),
        },
    });
    defer tracker.deinit();

    const ip = tIp("1.2.3.4");
    const jail = tJail("sshd");
    try testing.expect((try tracker.recordAttempt(ip, jail, 1_000)) == null);
    const dec = (try tracker.recordAttempt(ip, jail, 1_100)).?;
    try testing.expect(IpAddress.eql(dec.ip, ip));
    const st = tracker.get(ip).?;
    try testing.expectEqual(@as(?Timestamp, std.math.maxInt(Timestamp)), st.ban_expiry);
}

test "state: extreme findtime does not overflow cutoff (SEC-004)" {
    var tracker = try StateTracker.init(testing.allocator, .{
        .maxretry = 2,
        .findtime = std.math.maxInt(u64),
        .bantime = 600,
    });
    defer tracker.deinit();
    const ip = tIp("1.2.3.4");
    const jail = tJail("sshd");
    _ = try tracker.recordAttempt(ip, jail, 1_000);
}

test "state: ipv4-mapped IPv6 does not create a second tracker entry (SEC-001)" {
    var tracker = try StateTracker.init(testing.allocator, .{
        .maxretry = 3,
        .findtime = 600,
        .bantime = 600,
    });
    defer tracker.deinit();

    const v4 = tIp("1.2.3.4");
    const mapped = tIp("::ffff:1.2.3.4");
    try testing.expect(IpAddress.eql(v4, mapped));

    const jail = tJail("sshd");
    try testing.expect((try tracker.recordAttempt(v4, jail, 1_000)) == null);
    try testing.expect((try tracker.recordAttempt(v4, jail, 1_100)) == null);
    const dec = (try tracker.recordAttempt(mapped, jail, 1_200)).?;
    try testing.expect(IpAddress.eql(dec.ip, v4));
    try testing.expectEqual(@as(usize, 1), tracker.stats().entry_count);
}

test "state: a fresh ban is a would-ban until markEnforced; clearBan resets it (BUG-012)" {
    var tracker = try StateTracker.init(testing.allocator, .{ .max_entries = 8, .maxretry = 1, .findtime = 600, .bantime = 300 });
    defer tracker.deinit();
    const ip = tIp("203.0.113.12");
    const jail = tJail("sshd");
    try testing.expect((try tracker.recordAttempt(ip, jail, 1_000)) != null);
    try testing.expect(!tracker.get(ip).?.enforced);

    tracker.markEnforced(ip);
    try testing.expect(tracker.get(ip).?.enforced);

    tracker.clearBan(ip);
    try testing.expect(!tracker.get(ip).?.enforced);
    try testing.expectEqual(BanState.expired, tracker.get(ip).?.ban_state);

    tracker.markEnforced(ip);
    try testing.expect(!tracker.get(ip).?.enforced);
}

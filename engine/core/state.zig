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
    enforced: bool = false,
    applied: bool = false,
    confirmed: bool = false,

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
    CapacityReached,
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
        self.lifetime_bans +|= 1;
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

        if (!self.map.contains(ip) and self.map.count() >= self.config.max_entries) {
            const evicted_any = self.evictForInsert(timestamp);
            self.stats_inner.evictions += @intFromBool(evicted_any);
            if (!evicted_any) {
                std.log.warn("state: capacity reached and no entry evictable; dropping attempt", .{});
                return null;
            }
        }
        const gop = self.map.getOrPut(ip) catch return error.OutOfMemory;
        if (!gop.found_existing) {
            gop.value_ptr.* = freshState(jail, timestamp);
        } else {
            gop.value_ptr.attempt_count +|= 1;
            gop.value_ptr.last_attempt = timestamp;
        }

        const st = self.map.getPtr(ip) orelse return null;

        const findtime_i64: Timestamp = @intCast(@min(self.config.findtime, std.math.maxInt(Timestamp)));
        const cutoff: Timestamp = timestamp -| findtime_i64;
        st.pruneRing(cutoff);
        st.pushRing(timestamp);

        if (st.ban_state != .banned and st.ring_len >= self.config.maxretry) {
            const new_ban_count = st.ban_count +| 1;
            const duration = computeBantime(
                self.config.bantime,
                self.config.bantime_increment,
                new_ban_count - 1,
            );
            st.ban_state = .banned;
            st.enforced = false;
            st.applied = false;
            st.confirmed = false;
            st.ban_count = new_ban_count;
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
            st.applied = false;
            st.confirmed = false;
            st.ring_len = 0;
        }
    }

    pub fn manualBan(self: *StateTracker, ip: IpAddress, jail: JailId, now: Timestamp, duration: Duration) Error!void {
        try self.ensureReserved();
        if (!self.map.contains(ip)) {
            if (self.map.count() >= self.config.max_entries and self.evictOldest(false) == null)
                return error.CapacityReached;
            try self.map.put(ip, freshState(jail, now));
            self.map.getPtr(ip).?.attempt_count = 0;
        }
        const st = self.map.getPtr(ip).?;
        if (st.ban_state != .banned) {
            st.ban_count +|= 1;
            st.confirmed = false;
        }
        const expiry = now +| @as(Timestamp, @intCast(@min(duration, std.math.maxInt(Timestamp))));
        st.ban_expiry = @max(st.ban_expiry orelse expiry, expiry);
        st.ban_state = .banned;
        st.enforced = true;
        st.applied = false;
        st.ring_len = 0;
    }

    pub fn mutable(self: *StateTracker, ip: IpAddress) ?*IpState {
        return self.map.getPtr(ip);
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
    if (!incr.enabled) return base;
    if (ban_count == 0) {
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

//! Per-IP state tracker for the fail2zig ban lifecycle.
//!
//! `StateTracker` holds a pre-allocated `std.AutoHashMap` keyed by
//! `IpAddress`. Each entry (`IpState`) carries the attempt history, ban
//! state, and recidive counter for one offender. The hot path —
//! `recordAttempt` — walks a bounded ring buffer of recent attempt
//! timestamps, drops entries older than `findtime`, counts what remains,
//! and raises a `BanDecision` when the count crosses `maxretry`.
//!
//! Memory is fixed: the map's bucket count is pre-computed from the
//! component budget at construction time, so the tracker cannot grow
//! past its ceiling under attack. When the map fills, the configured
//! eviction policy decides whose record to drop.
//!
//! Threading: single-threaded. The engine's event loop owns the tracker
//! and all mutation runs on the loop thread. Callers embedding this in
//! a multi-threaded harness must serialize externally.
//!
//! All input that reaches `recordAttempt` is attacker-controlled (IP
//! address, jail tag, timestamp from a parsed log line). We treat it as
//! such: every path is explicit, no `@panic`, no `unreachable` on
//! attacker-reachable inputs.

const std = @import("std");
const shared = @import("shared");

const IpAddress = shared.IpAddress;
const JailId = shared.JailId;
const Timestamp = shared.Timestamp;
const Duration = shared.Duration;
const BanState = shared.BanState;

// ============================================================================
// Configuration
// ============================================================================

/// Eviction policy when the tracker hits its capacity.
pub const EvictionPolicy = enum {
    /// Remove the entry whose `last_attempt` is the oldest, regardless of
    /// ban state. Simple, deterministic.
    evict_oldest,
    /// Ban every entry currently tracked and emit a loud warning. Trades
    /// false-positive risk for never-miss-a-real-attacker behaviour under
    /// memory pressure.
    ban_all_and_alert,
    /// Remove the oldest entry that is NOT currently banned. Preserves
    /// ban state across pressure but may reject a new attacker if every
    /// tracked IP is already banned.
    drop_oldest_unbanned,
};

/// Bantime-increment knobs — mirrors `config.native.BanTimeIncrement` but
/// lives here so the state module has zero config-layer imports.
pub const BanTimeIncrement = struct {
    enabled: bool = false,
    /// Multiplier applied once on every ban (constant factor).
    multiplier: f64 = 1.0,
    /// Per-ban factor. Used differently for linear vs exponential:
    /// * linear      -> added ban_count times (multiplier * factor * ban_count)
    /// * exponential -> raised to ban_count (multiplier * factor^ban_count)
    factor: f64 = 1.0,
    formula: Formula = .exponential,
    /// Upper cap — no computed bantime may exceed this.
    max_bantime: Duration = 86_400 * 7,

    pub const Formula = enum { linear, exponential };
};

/// Tracker configuration. Derived by the daemon from the global
/// per-jail config; unit tests construct one directly.
pub const Config = struct {
    /// Maximum per-IP entries. See `capacityFromBudget` for the default
    /// bytes-to-entries translation.
    max_entries: u32 = 4096,
    /// Findtime window: attempts older than `now - findtime` don't count.
    findtime: Duration = 600,
    /// Attempts required within the findtime window to trigger a ban.
    maxretry: u32 = 5,
    /// Base bantime. `BanTimeIncrement` scales this for repeat offenders.
    bantime: Duration = 600,
    /// Recidive escalation.
    bantime_increment: BanTimeIncrement = .{},
    /// Eviction policy when `max_entries` is reached.
    eviction_policy: EvictionPolicy = .drop_oldest_unbanned,
};

/// Rough byte estimate per tracked IP: HashMap bucket overhead (~48B on
/// 64-bit), plus `IpState` (~1.3KB with the 128-entry ring), plus slack.
/// Documented here so `capacityFromBudget` is auditable.
pub const approx_bytes_per_entry: usize = 1536;

/// Translate a byte budget into a reasonable entry capacity. The caller
/// may pass a smaller capacity directly if they want to run tighter.
pub fn capacityFromBudget(bytes: usize) u32 {
    const est = bytes / approx_bytes_per_entry;
    if (est == 0) return 1;
    if (est > std.math.maxInt(u32)) return std.math.maxInt(u32);
    return @intCast(est);
}

// ============================================================================
// Per-IP state
// ============================================================================

/// Max attempt timestamps retained per IP. 128 is big enough for every
/// realistic `maxretry` while bounded tightly to keep `IpState` inside
/// one page even for thousands of tracked IPs.
pub const max_attempts_per_ip: usize = 128;

/// Per-IP record.
///
/// Field ordering places hot fields (`ban_state`, `attempt_count`,
/// `ring_len`, `last_attempt`) near the top so they share a cache line
/// on typical 64B cache-line CPUs. The ring buffer lives at the end; it
/// is cold on the fast-reject paths.
pub const IpState = struct {
    /// Owning jail. Copied by value; JailId is a fixed-size struct.
    jail: JailId,
    /// Lifetime attempt count across all attempts we've ever seen for
    /// this IP. Monotonic — not reset by findtime pruning. Useful for
    /// metrics / audit, not for the ban decision.
    attempt_count: u32,
    /// Number of times this IP has been banned (recidive counter).
    ban_count: u32,
    /// First attempt timestamp we ever observed for this IP.
    first_attempt: Timestamp,
    /// Last attempt timestamp. Updated on every record, pre-findtime-prune.
    last_attempt: Timestamp,
    /// Current ban state.
    ban_state: BanState,
    /// Absolute expiry of the active ban, null when not banned.
    ban_expiry: ?Timestamp,

    /// Ring buffer of attempt timestamps within the findtime window.
    /// Entries are NOT kept sorted — new attempts are appended, and
    /// `pruneFindtime` compacts stale ones out in a single pass. The
    /// caller never relies on ordering, only on count-of-live-entries.
    ring: [max_attempts_per_ip]Timestamp,
    /// Number of valid timestamps in `ring[0..ring_len]`.
    ring_len: u8,

    /// Remove timestamps older than `cutoff` from the ring buffer. Uses
    /// an in-place two-pointer compaction.
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

    /// Push `ts` onto the ring, dropping the oldest entry if full. The
    /// oldest entry (lowest timestamp) is located by linear scan — the
    /// ring is bounded at 128 so this is ~128 comparisons in the worst
    /// case, well inside the allocation-free budget.
    fn pushRing(self: *IpState, ts: Timestamp) void {
        if (self.ring_len < max_attempts_per_ip) {
            self.ring[self.ring_len] = ts;
            self.ring_len += 1;
            return;
        }
        // Full — overwrite the oldest.
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

    /// True if this IP currently has an active ban.
    pub fn isBanned(self: *const IpState) bool {
        return self.ban_state == .banned;
    }
};

// ============================================================================
// Ban decision
// ============================================================================

/// Payload returned by `recordAttempt` when a threshold is crossed.
/// Caller feeds this into the firewall backend.
pub const BanDecision = struct {
    ip: IpAddress,
    jail: JailId,
    duration: Duration,
    /// 1 for a first-time ban, 2 for the second, etc. Useful for
    /// logging and metrics.
    ban_count: u32,
};

// ============================================================================
// Ignore list (CIDR + exact)
// ============================================================================

/// A parsed CIDR net. IPv4 and IPv6 stay in their native integer widths
/// so mask comparison stays a single `&` / `==`.
pub const Cidr = union(enum) {
    v4: struct { net: u32, mask: u32 },
    v6: struct { net: u128, mask: u128 },

    pub const ParseError = error{InvalidCidr};

    /// Parse strings like `192.168.1.0/24`, `10.0.0.1` (= `/32`),
    /// `2001:db8::/32`, or `::1` (= `/128`). Rejects trailing garbage.
    pub fn parse(s: []const u8) ParseError!Cidr {
        // Split on '/'. If no '/', treat as host address (full-width mask).
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

    /// True if `ip` is contained in this CIDR.
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
    // Arithmetic shift avoids the UB of `<< 32` on a 32-bit value.
    return @as(u32, 0xFFFF_FFFF) << @intCast(32 - prefix);
}

fn maskIpv6(prefix: u8) u128 {
    if (prefix == 0) return 0;
    if (prefix >= 128) return ~@as(u128, 0);
    const ones: u128 = ~@as(u128, 0);
    return ones << @intCast(128 - prefix);
}

// ============================================================================
// Stats
// ============================================================================

pub const Stats = struct {
    /// Live entries in the map.
    entry_count: usize = 0,
    /// How many times `recordAttempt` was called.
    attempts_observed: u64 = 0,
    /// How many ban decisions have been raised.
    bans_triggered: u64 = 0,
    /// How many IPs were skipped because they matched the ignore list.
    ignored_attempts: u64 = 0,
    /// How many evictions have fired since init (across all policies).
    evictions: u64 = 0,
};

// ============================================================================
// StateTracker
// ============================================================================

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

    /// Initialize with an explicit capacity (in IP entries). Pre-allocates
    /// hash-map buckets so the steady-state path never needs a rehash.
    pub fn init(allocator: std.mem.Allocator, config: Config) Error!StateTracker {
        if (config.max_entries == 0) return error.CapacityZero;

        var map = Map.init(allocator);
        errdefer map.deinit();
        map.ensureTotalCapacity(config.max_entries) catch return error.OutOfMemory;

        const ignore = std.ArrayList(Cidr).init(allocator);

        return .{
            .allocator = allocator,
            .config = config,
            .map = map,
            .ignore = ignore,
            .stats_inner = .{},
        };
    }

    pub fn deinit(self: *StateTracker) void {
        self.map.deinit();
        self.ignore.deinit();
        self.* = undefined;
    }

    // ---------- Ignore list ----------

    /// Add a CIDR (or exact IP) to the ignore list. Rejects malformed
    /// input with a typed error rather than silently dropping.
    pub fn addIgnoreCidr(self: *StateTracker, spec: []const u8) Error!void {
        const c = Cidr.parse(spec) catch return error.InvalidIgnoreCidr;
        self.ignore.append(c) catch return error.OutOfMemory;
    }

    /// True if `ip` is covered by any ignore entry.
    pub fn isIgnored(self: *const StateTracker, ip: IpAddress) bool {
        for (self.ignore.items) |c| {
            if (c.contains(ip)) return true;
        }
        return false;
    }

    // ---------- Core: record an attempt ----------

    /// Record one attempt for `ip` in `jail` at `timestamp`.
    ///
    /// Flow:
    ///   1. Skip if `ip` is in the ignore list.
    ///   2. Lookup or create `IpState`. If the map is full, run the
    ///      configured eviction policy — if eviction cannot free a slot
    ///      (e.g. `ban_all_and_alert`), drop the attempt (return null)
    ///      so the tracker stays inside its ceiling.
    ///   3. Append `timestamp` to the ring, prune entries older than
    ///      `now - findtime`.
    ///   4. If live ring size >= `maxretry` AND the IP is not already
    ///      banned, emit a `BanDecision`.
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

        const gop = self.map.getOrPut(ip) catch return error.OutOfMemory;
        if (!gop.found_existing) {
            // New entry. If the map is at capacity, the getOrPut above
            // already used one of the reserved buckets; we enforce the
            // logical capacity via `config.max_entries`.
            if (self.map.count() > self.config.max_entries) {
                // Remove the just-inserted entry, then try to evict an
                // old one to make space for it.
                _ = self.map.remove(ip);
                const evicted_any = self.evictForInsert(timestamp);
                self.stats_inner.evictions += @intFromBool(evicted_any);
                if (!evicted_any) {
                    // Nothing could be evicted — drop the attempt. Better
                    // than growing past the ceiling.
                    std.log.warn(
                        "state: capacity reached and no entry evictable; dropping attempt",
                        .{},
                    );
                    return null;
                }
                // Retry the insert now that there's room.
                const gop2 = self.map.getOrPut(ip) catch return error.OutOfMemory;
                gop2.value_ptr.* = freshState(jail, timestamp);
            } else {
                gop.value_ptr.* = freshState(jail, timestamp);
            }
        } else {
            const st = gop.value_ptr;
            st.attempt_count +%= 1;
            st.last_attempt = timestamp;
            // Keep the jail fresh; a single attacker may roam across
            // jails in theory. In practice we pin to first-seen.
            _ = &jail;
        }

        const st = self.map.getPtr(ip) orelse return null;

        // Prune + push. Order matters: prune first so a new attempt
        // that lands long after the previous window collapses the ring
        // to just itself.
        //
        // SEC-004: clamp findtime to fit in a Timestamp before casting.
        // A pathological config (`findtime` set to a Duration > i64 max)
        // would panic in .ReleaseSafe on the @intCast below. Saturate.
        const findtime_i64: Timestamp = @intCast(@min(self.config.findtime, std.math.maxInt(Timestamp)));
        const cutoff: Timestamp = timestamp -| findtime_i64;
        st.pruneRing(cutoff);
        st.pushRing(timestamp);

        // Threshold check: only if currently monitoring (not already banned).
        if (st.ban_state != .banned and st.ring_len >= self.config.maxretry) {
            const new_ban_count = st.ban_count + 1;
            const duration = computeBantime(
                self.config.bantime,
                self.config.bantime_increment,
                new_ban_count - 1,
            );
            st.ban_state = .banned;
            st.ban_count = new_ban_count;
            // SEC-004: saturate on overflow rather than panicking. A
            // Duration > i64 max (operator-config typo) or a wall-clock
            // timestamp close to i64 max would otherwise crash the daemon
            // on the first ban. Clamp to Timestamp max so the ban stays
            // effectively permanent until explicitly cleared.
            const duration_i64: Timestamp = @intCast(@min(duration, std.math.maxInt(Timestamp)));
            st.ban_expiry = std.math.add(Timestamp, timestamp, duration_i64) catch blk: {
                std.log.warn("state: ban_expiry overflow, clamping to Timestamp max", .{});
                break :blk std.math.maxInt(Timestamp);
            };
            // Clear the ring so that another immediate attempt doesn't
            // re-fire a second ban within the same findtime window.
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

    /// Explicitly clear a ban (e.g. on expiry timer). Idempotent.
    pub fn clearBan(self: *StateTracker, ip: IpAddress) void {
        if (self.map.getPtr(ip)) |st| {
            st.ban_state = .expired;
            st.ban_expiry = null;
            st.ring_len = 0;
        }
    }

    /// Remove an entry entirely (e.g. after ban expiry + cooldown).
    pub fn forget(self: *StateTracker, ip: IpAddress) void {
        _ = self.map.remove(ip);
    }

    /// True if the tracker has an entry for `ip`.
    pub fn contains(self: *const StateTracker, ip: IpAddress) bool {
        return self.map.contains(ip);
    }

    /// Get a read-only view of an IP's state. Caller must not mutate.
    pub fn get(self: *const StateTracker, ip: IpAddress) ?*const IpState {
        return self.map.getPtr(ip);
    }

    /// Iterator handle for expired-ban scanning and state persistence.
    pub fn iterator(self: *const StateTracker) Map.Iterator {
        return self.map.iterator();
    }

    /// Snapshot stats.
    pub fn stats(self: *const StateTracker) Stats {
        var s = self.stats_inner;
        s.entry_count = self.map.count();
        return s;
    }

    // ---------- Eviction ----------

    /// Run the configured eviction policy once. Returns the evicted
    /// state (copied by value), or null if nothing could be evicted.
    /// Exposed for tests; the record path uses `evictForInsert`.
    pub fn evict(self: *StateTracker) ?IpState {
        return switch (self.config.eviction_policy) {
            .evict_oldest => self.evictOldest(true),
            .drop_oldest_unbanned => self.evictOldest(false),
            .ban_all_and_alert => blk: {
                // Signal the caller. The tracker does not know how to
                // actually push bans to the firewall — that is the
                // daemon's job. We emit a structured warning and leave
                // the map untouched so the pressure persists until the
                // operator reacts.
                std.log.warn(
                    "state: capacity reached under ban_all_and_alert policy ({d} entries)",
                    .{self.map.count()},
                );
                break :blk null;
            },
        };
    }

    /// `ignore_banned = true`  ->  consider every entry (policy: evict_oldest)
    /// `ignore_banned = false` ->  skip banned entries (policy: drop_oldest_unbanned)
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

// ============================================================================
// Helpers
// ============================================================================

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

/// Compute the effective bantime for a given `ban_count` (0 = first ban).
pub fn computeBantime(base: Duration, incr: BanTimeIncrement, ban_count: u32) Duration {
    if (!incr.enabled or ban_count == 0) {
        return @min(base, incr.max_bantime);
    }
    const base_f: f64 = @floatFromInt(base);
    const n: f64 = @floatFromInt(ban_count);
    const scaled: f64 = switch (incr.formula) {
        .exponential => base_f * incr.multiplier * std.math.pow(f64, incr.factor, n),
        // Linear interpretation: base * multiplier * (1 + factor*n). With
        // default multiplier=1, factor=1, n=1 this yields 2*base — matches
        // a simple "doubling per ban" feel without the explosive shape.
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

// ============================================================================
// Tests
// ============================================================================

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

    // Immediate retry must NOT produce a fresh ban decision (already banned).
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
    // B still below threshold.
    try testing.expect(tracker.get(b).?.ban_state == .monitoring);
}

// ------- 4.1.2: findtime window tests -------

test "state: 3 attempts spread over 10 minutes don't cross findtime=300" {
    var tracker = try StateTracker.init(testing.allocator, .{
        .maxretry = 3,
        .findtime = 300,
    });
    defer tracker.deinit();

    const ip = tIp("9.9.9.9");
    const jail = tJail("sshd");

    // 0s, 400s, 800s — attempts are each > 300s after the previous,
    // so the ring never accumulates 3 live entries.
    try testing.expect((try tracker.recordAttempt(ip, jail, 1_000)) == null);
    try testing.expect((try tracker.recordAttempt(ip, jail, 1_400)) == null);
    try testing.expect((try tracker.recordAttempt(ip, jail, 1_800)) == null);

    const st = tracker.get(ip).?;
    // Pruning leaves only the most recent attempt each time.
    try testing.expectEqual(@as(u8, 1), st.ring_len);
    try testing.expectEqual(BanState.monitoring, st.ban_state);
    // Lifetime attempt count still reflects all 3 observations.
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
        .maxretry = 100, // high enough that we never ban; we inspect state.
        .findtime = 300,
    });
    defer tracker.deinit();

    const ip = tIp("5.5.5.5");
    const jail = tJail("sshd");

    _ = try tracker.recordAttempt(ip, jail, 1_000);
    _ = try tracker.recordAttempt(ip, jail, 1_100);
    _ = try tracker.recordAttempt(ip, jail, 1_200);
    // Jump > findtime ahead. The three earlier entries all become stale;
    // only the new one survives pruning.
    _ = try tracker.recordAttempt(ip, jail, 2_000);

    const st = tracker.get(ip).?;
    try testing.expectEqual(@as(u8, 1), st.ring_len);
    try testing.expectEqual(@as(Timestamp, 2_000), st.ring[0]);
}

// ------- 4.1.3: eviction policy tests -------

test "state: evict_oldest removes the oldest last_attempt entry" {
    var tracker = try StateTracker.init(testing.allocator, .{
        .max_entries = 8,
        .maxretry = 100,
        .findtime = 10_000,
        .eviction_policy = .evict_oldest,
    });
    defer tracker.deinit();

    const jail = tJail("sshd");
    // Three entries with strictly increasing last_attempt timestamps.
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
        .maxretry = 1, // single attempt bans
        .findtime = 10_000,
        .bantime = 60,
        .eviction_policy = .drop_oldest_unbanned,
    });
    defer tracker.deinit();

    const jail = tJail("sshd");
    // `1.1.1.1` attempts once and is immediately banned (maxretry=1).
    _ = try tracker.recordAttempt(tIp("1.1.1.1"), jail, 1_000);
    try testing.expect(tracker.get(tIp("1.1.1.1")).?.ban_state == .banned);

    // Reset maxretry so the next IPs stay monitoring.
    tracker.config.maxretry = 100;
    _ = try tracker.recordAttempt(tIp("2.2.2.2"), jail, 2_000);
    _ = try tracker.recordAttempt(tIp("3.3.3.3"), jail, 3_000);

    // Policy must skip the banned IP and evict the oldest unbanned one.
    const evicted = tracker.evict().?;
    try testing.expectEqual(@as(Timestamp, 2_000), evicted.last_attempt);
    try testing.expect(tracker.contains(tIp("1.1.1.1"))); // banned retained
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

// ------- 4.1.4: bantime increment tests -------

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
    // ban_count is "previous bans" — 0 for the first ban.
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
    // 600 * 2^4 = 9600 > 5000 -> capped.
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
    // Linear: base * multiplier * (1 + factor*n)
    // n=0 -> 600 * 1 = 600
    // n=1 -> 600 * 2 = 1200
    // n=2 -> 600 * 3 = 1800
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

    // First ban window.
    _ = try tracker.recordAttempt(ip, jail, 100);
    const d1 = (try tracker.recordAttempt(ip, jail, 110)).?;
    try testing.expectEqual(@as(Duration, 600), d1.duration);

    // Simulate ban expiry + re-offense.
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
    // Entries untouched — the daemon's alert path (outside this module)
    // is responsible for reacting to the warning log.
    try testing.expect(tracker.contains(tIp("1.1.1.1")));
    try testing.expect(tracker.contains(tIp("2.2.2.2")));
}

// ------- 4.1.5: ignore IP / CIDR tests -------

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
    // SEC-001: `::ffff:10.0.0.1` is canonicalized to the IPv4 variant at
    // parse time, so it MUST be treated as 10.0.0.1 and match the v4 CIDR.
    // That's the whole point of the fix — the state tracker can't be
    // tricked into seeing two distinct keys for the same attacker.
    try testing.expect(v4.contains(tIp("::ffff:10.0.0.1")));
    try testing.expect(v6.contains(tIp("::1")));
    try testing.expect(!v6.contains(tIp("1.2.3.4"))); // v4 value
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

    // Ignored IP leaves no trace in the tracker.
    try testing.expect((try tracker.recordAttempt(ip_ignored, jail, 1_000)) == null);
    try testing.expect((try tracker.recordAttempt(ip_ignored, jail, 1_010)) == null);
    try testing.expect(!tracker.contains(ip_ignored));
    try testing.expectEqual(@as(u64, 2), tracker.stats().ignored_attempts);

    // Non-ignored IP is tracked and ban-able.
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
        .maxretry = std.math.maxInt(u32), // never fire a ban
        .findtime = 100_000, // never prune
    });
    defer tracker.deinit();

    const ip = tIp("7.7.7.7");
    const jail = tJail("sshd");

    // Push more than 128 attempts so the ring overflows.
    var t: Timestamp = 0;
    while (t < @as(Timestamp, max_attempts_per_ip + 10)) : (t += 1) {
        _ = try tracker.recordAttempt(ip, jail, t);
    }
    const st = tracker.get(ip).?;
    try testing.expectEqual(@as(u8, max_attempts_per_ip), st.ring_len);
    // Smallest value still in the ring must be > 9 (the first 10 were
    // overwritten by oldest-wins replacement).
    var min_v: Timestamp = std.math.maxInt(Timestamp);
    for (st.ring[0..st.ring_len]) |v| {
        if (v < min_v) min_v = v;
    }
    try testing.expect(min_v >= 10);
}

test "state: extreme bantime does not overflow ban_expiry (SEC-004)" {
    // Operator config error: bantime = u64::MAX AND the bantime-increment
    // cap is disabled (max_bantime = u64::MAX). In .ReleaseSafe the naive
    // `timestamp + @intCast(duration)` path would panic; with the SEC-004
    // clamp the daemon saturates at Timestamp max without crashing.
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
    // Ban fired without panicking; expiry is clamped to Timestamp max.
    try testing.expect(IpAddress.eql(dec.ip, ip));
    const st = tracker.get(ip).?;
    try testing.expectEqual(@as(?Timestamp, std.math.maxInt(Timestamp)), st.ban_expiry);
}

test "state: extreme findtime does not overflow cutoff (SEC-004)" {
    // Operator config error: findtime = u64::MAX. The cutoff computation
    // must saturate rather than panic.
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
    // The ban-evasion path: attempts for `1.2.3.4` and `::ffff:1.2.3.4`
    // must collapse into the same state entry so maxretry isn't doubled.
    var tracker = try StateTracker.init(testing.allocator, .{
        .maxretry = 3,
        .findtime = 600,
        .bantime = 600,
    });
    defer tracker.deinit();

    const v4 = tIp("1.2.3.4");
    const mapped = tIp("::ffff:1.2.3.4");
    // After SEC-001, both parse to the same IpAddress value.
    try testing.expect(IpAddress.eql(v4, mapped));

    const jail = tJail("sshd");
    // Two attempts under v4, one under mapped form — third trigger MUST ban.
    try testing.expect((try tracker.recordAttempt(v4, jail, 1_000)) == null);
    try testing.expect((try tracker.recordAttempt(v4, jail, 1_100)) == null);
    const dec = (try tracker.recordAttempt(mapped, jail, 1_200)).?;
    try testing.expect(IpAddress.eql(dec.ip, v4));
    // Only one entry in the tracker.
    try testing.expectEqual(@as(usize, 1), tracker.stats().entry_count);
}

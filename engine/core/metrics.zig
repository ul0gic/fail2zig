//! Metrics collector — lock-free atomic counters for the fail2zig daemon.
//!
//! The daemon's hot paths (log parser, state tracker, firewall backend)
//! touch these counters on every event; the cold paths (HTTP metrics
//! endpoint, IPC status command, WebSocket broadcast) read them via
//! `snapshot()`. All operations use `.monotonic` ordering — we only
//! need per-counter atomicity, not cross-counter consistency. Readers
//! accept that a snapshot may capture the "middle" of a batch update;
//! for rate-limiting and operator display that is correct by design.
//!
//! Per-jail stats live in a fixed-size array, indexed by a jail name
//! we look up with a linear scan. 64 jails is a deliberate ceiling —
//! exceeding it is a configuration smell, not a deployment pattern,
//! and we'd rather surface the limit than silently grow.
//!
//! No allocations: the struct and its per-jail array are embedded in
//! the daemon's long-lived context. Construct once at startup, never
//! resize.

const std = @import("std");

/// Hard upper bound on per-jail slots. Matches the configuration cap
/// in `config.native` (no jail configuration beyond this ceiling is
/// allowed). If a jail is registered beyond this, updates for it are
/// silently ignored and a debug log is emitted once.
pub const max_jails: usize = 64;

/// Max jail-name length. Must be >= JailId.max_len in shared/types.zig
/// so every valid jail id fits.
pub const max_jail_name_len: usize = 64;

/// Counter ordering used for every atomic update. `.monotonic` is
/// enough because these are independent counters — no cross-counter
/// invariants to preserve.
const counter_order: std.builtin.AtomicOrder = .monotonic;

// ============================================================================
// Per-jail record
// ============================================================================

/// One fixed-size entry per jail. Zero-initialized; `name_len == 0`
/// marks an empty slot.
pub const PerJail = struct {
    name_buf: [max_jail_name_len]u8 = [_]u8{0} ** max_jail_name_len,
    name_len: u8 = 0,
    lines_parsed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    lines_matched: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    bans_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    unbans_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    active_bans: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    parse_errors: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub fn name(self: *const PerJail) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

// ============================================================================
// Snapshot (non-atomic, owned by caller)
// ============================================================================

pub const PerJailSnapshot = struct {
    name_buf: [max_jail_name_len]u8,
    name_len: u8,
    lines_parsed: u64,
    lines_matched: u64,
    bans_total: u64,
    unbans_total: u64,
    active_bans: u32,
    parse_errors: u64,

    pub fn name(self: *const PerJailSnapshot) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

pub const Snapshot = struct {
    lines_parsed: u64 = 0,
    lines_matched: u64 = 0,
    bans_total: u64 = 0,
    unbans_total: u64 = 0,
    active_bans: u32 = 0,
    parse_errors: u64 = 0,
    memory_bytes_used: u64 = 0,
    jails: [max_jails]PerJailSnapshot = undefined,
    jails_len: usize = 0,

    pub fn perJail(self: *const Snapshot) []const PerJailSnapshot {
        return self.jails[0..self.jails_len];
    }
};

// ============================================================================
// Metrics
// ============================================================================

pub const Metrics = struct {
    // Global counters. Field order is intentional: hottest counters
    // first so they land on the same cache line on typical 64B CPUs.
    lines_parsed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    lines_matched: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    bans_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    unbans_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    active_bans: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    parse_errors: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    memory_bytes_used: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    // Per-jail entries + number of currently-populated slots. The
    // `jails_len` field is written only when a new jail is registered;
    // after startup it's effectively read-only, so we keep it as a
    // plain `usize` with release-store semantics on first write.
    jails: [max_jails]PerJail = [_]PerJail{.{}} ** max_jails,
    jails_len: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

    /// Construct an empty Metrics. All counters start at zero.
    pub fn init() Metrics {
        return .{};
    }

    // ----- Global increments -----

    pub fn incrementParsed(self: *Metrics) void {
        _ = self.lines_parsed.fetchAdd(1, counter_order);
    }

    pub fn incrementMatched(self: *Metrics) void {
        _ = self.lines_matched.fetchAdd(1, counter_order);
    }

    pub fn incrementBans(self: *Metrics) void {
        _ = self.bans_total.fetchAdd(1, counter_order);
        _ = self.active_bans.fetchAdd(1, counter_order);
    }

    pub fn incrementUnbans(self: *Metrics) void {
        _ = self.unbans_total.fetchAdd(1, counter_order);
        // Active bans is a gauge; saturate at zero rather than underflow.
        const prev = self.active_bans.load(counter_order);
        if (prev > 0) {
            _ = self.active_bans.fetchSub(1, counter_order);
        }
    }

    pub fn incrementParseErrors(self: *Metrics) void {
        _ = self.parse_errors.fetchAdd(1, counter_order);
    }

    pub fn setMemoryBytes(self: *Metrics, bytes: u64) void {
        self.memory_bytes_used.store(bytes, counter_order);
    }

    /// Directly set the `active_bans` gauge without bumping the
    /// `bans_total` lifetime counter. Used when reconciling state from
    /// disk at startup — those bans aren't new, they're just being
    /// re-surfaced to the running process, so the gauge is the thing
    /// that needs correcting and the counter stays honest (SYS-007).
    pub fn setActiveBans(self: *Metrics, count: u32) void {
        self.active_bans.store(count, counter_order);
    }

    // ----- Per-jail operations -----

    /// Register a jail so future per-jail updates under this name can
    /// route to a slot. If the jail is already registered, this is a
    /// no-op. Returns the slot index, or null if the max_jails cap has
    /// been reached.
    ///
    /// Called once per configured jail at startup. NOT hot-path.
    pub fn registerJail(self: *Metrics, name: []const u8) ?usize {
        if (name.len == 0 or name.len > max_jail_name_len) return null;
        // Linear scan for existing.
        const live = self.jails_len.load(.acquire);
        for (self.jails[0..live], 0..) |*slot, i| {
            if (slot.name_len == name.len and
                std.mem.eql(u8, slot.name_buf[0..slot.name_len], name))
            {
                return i;
            }
        }
        if (live >= max_jails) return null;
        var slot = &self.jails[live];
        @memcpy(slot.name_buf[0..name.len], name);
        slot.name_len = @intCast(name.len);
        self.jails_len.store(live + 1, .release);
        return live;
    }

    /// Find the slot index for an already-registered jail, or null if
    /// it hasn't been registered. Cheap (linear scan of <=64 entries).
    pub fn jailIndex(self: *const Metrics, name: []const u8) ?usize {
        const live = self.jails_len.load(.acquire);
        for (self.jails[0..live], 0..) |*slot, i| {
            if (slot.name_len == name.len and
                std.mem.eql(u8, slot.name_buf[0..slot.name_len], name))
            {
                return i;
            }
        }
        return null;
    }

    pub fn jailIncrementParsed(self: *Metrics, jail: []const u8) void {
        if (self.jailIndex(jail)) |i| {
            _ = self.jails[i].lines_parsed.fetchAdd(1, counter_order);
        }
    }

    pub fn jailIncrementMatched(self: *Metrics, jail: []const u8) void {
        if (self.jailIndex(jail)) |i| {
            _ = self.jails[i].lines_matched.fetchAdd(1, counter_order);
        }
    }

    pub fn jailIncrementBans(self: *Metrics, jail: []const u8) void {
        if (self.jailIndex(jail)) |i| {
            _ = self.jails[i].bans_total.fetchAdd(1, counter_order);
            _ = self.jails[i].active_bans.fetchAdd(1, counter_order);
        }
    }

    /// Per-jail counterpart of `setActiveBans`.
    pub fn jailSetActiveBans(self: *Metrics, jail: []const u8, count: u32) void {
        if (self.jailIndex(jail)) |i| {
            self.jails[i].active_bans.store(count, counter_order);
        }
    }

    pub fn jailIncrementUnbans(self: *Metrics, jail: []const u8) void {
        if (self.jailIndex(jail)) |i| {
            _ = self.jails[i].unbans_total.fetchAdd(1, counter_order);
            const prev = self.jails[i].active_bans.load(counter_order);
            if (prev > 0) {
                _ = self.jails[i].active_bans.fetchSub(1, counter_order);
            }
        }
    }

    pub fn jailIncrementParseErrors(self: *Metrics, jail: []const u8) void {
        if (self.jailIndex(jail)) |i| {
            _ = self.jails[i].parse_errors.fetchAdd(1, counter_order);
        }
    }

    // ----- Snapshot -----

    /// Take a consistent-per-counter snapshot of all global and
    /// per-jail values. Returned by value (no allocation).
    pub fn snapshot(self: *const Metrics) Snapshot {
        var s = Snapshot{};
        s.lines_parsed = self.lines_parsed.load(counter_order);
        s.lines_matched = self.lines_matched.load(counter_order);
        s.bans_total = self.bans_total.load(counter_order);
        s.unbans_total = self.unbans_total.load(counter_order);
        s.active_bans = self.active_bans.load(counter_order);
        s.parse_errors = self.parse_errors.load(counter_order);
        s.memory_bytes_used = self.memory_bytes_used.load(counter_order);

        const live = self.jails_len.load(.acquire);
        s.jails_len = live;
        for (self.jails[0..live], 0..) |*slot, i| {
            s.jails[i] = .{
                .name_buf = slot.name_buf,
                .name_len = slot.name_len,
                .lines_parsed = slot.lines_parsed.load(counter_order),
                .lines_matched = slot.lines_matched.load(counter_order),
                .bans_total = slot.bans_total.load(counter_order),
                .unbans_total = slot.unbans_total.load(counter_order),
                .active_bans = slot.active_bans.load(counter_order),
                .parse_errors = slot.parse_errors.load(counter_order),
            };
        }
        return s;
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "metrics: init produces zeroed counters" {
    var m = Metrics.init();
    const s = m.snapshot();
    try testing.expectEqual(@as(u64, 0), s.lines_parsed);
    try testing.expectEqual(@as(u64, 0), s.bans_total);
    try testing.expectEqual(@as(u32, 0), s.active_bans);
    try testing.expectEqual(@as(usize, 0), s.jails_len);
}

test "metrics: incrementParsed / incrementBans move the global counters" {
    var m = Metrics.init();
    m.incrementParsed();
    m.incrementParsed();
    m.incrementBans();
    m.incrementParseErrors();

    const s = m.snapshot();
    try testing.expectEqual(@as(u64, 2), s.lines_parsed);
    try testing.expectEqual(@as(u64, 1), s.bans_total);
    try testing.expectEqual(@as(u32, 1), s.active_bans);
    try testing.expectEqual(@as(u64, 1), s.parse_errors);
}

test "metrics: incrementUnbans saturates at zero" {
    var m = Metrics.init();
    m.incrementUnbans();
    m.incrementUnbans();
    const s = m.snapshot();
    try testing.expectEqual(@as(u32, 0), s.active_bans);
    try testing.expectEqual(@as(u64, 2), s.unbans_total);
}

test "metrics: registerJail and jailIndex round-trip" {
    var m = Metrics.init();
    const idx_sshd = m.registerJail("sshd").?;
    const idx_nginx = m.registerJail("nginx").?;
    try testing.expectEqual(@as(usize, 0), idx_sshd);
    try testing.expectEqual(@as(usize, 1), idx_nginx);

    try testing.expectEqual(@as(usize, 0), m.jailIndex("sshd").?);
    try testing.expectEqual(@as(usize, 1), m.jailIndex("nginx").?);
    try testing.expectEqual(@as(?usize, null), m.jailIndex("unknown"));
}

test "metrics: registerJail rejects empty and overlong names" {
    var m = Metrics.init();
    try testing.expectEqual(@as(?usize, null), m.registerJail(""));
    const too_long = [_]u8{'a'} ** (max_jail_name_len + 1);
    try testing.expectEqual(@as(?usize, null), m.registerJail(&too_long));
}

test "metrics: registerJail dedupes duplicate registration" {
    var m = Metrics.init();
    const a = m.registerJail("sshd").?;
    const b = m.registerJail("sshd").?;
    try testing.expectEqual(a, b);
    try testing.expectEqual(@as(usize, 1), m.snapshot().jails_len);
}

test "metrics: per-jail counters increment independently" {
    var m = Metrics.init();
    _ = m.registerJail("sshd").?;
    _ = m.registerJail("nginx").?;
    m.jailIncrementParsed("sshd");
    m.jailIncrementParsed("sshd");
    m.jailIncrementParsed("nginx");
    m.jailIncrementBans("sshd");

    const s = m.snapshot();
    try testing.expectEqual(@as(usize, 2), s.jails_len);
    for (s.perJail()) |pj| {
        if (std.mem.eql(u8, pj.name(), "sshd")) {
            try testing.expectEqual(@as(u64, 2), pj.lines_parsed);
            try testing.expectEqual(@as(u64, 1), pj.bans_total);
        } else if (std.mem.eql(u8, pj.name(), "nginx")) {
            try testing.expectEqual(@as(u64, 1), pj.lines_parsed);
            try testing.expectEqual(@as(u64, 0), pj.bans_total);
        }
    }
}

test "metrics: max_jails ceiling prevents registration beyond cap" {
    var m = Metrics.init();
    var i: usize = 0;
    while (i < max_jails) : (i += 1) {
        var buf: [16]u8 = undefined;
        const name = try std.fmt.bufPrint(&buf, "jail{d}", .{i});
        try testing.expect(m.registerJail(name) != null);
    }
    try testing.expectEqual(@as(?usize, null), m.registerJail("overflow"));
}

test "metrics: snapshot is a stable by-value copy" {
    var m = Metrics.init();
    m.incrementParsed();
    const s1 = m.snapshot();
    m.incrementParsed();
    const s2 = m.snapshot();
    try testing.expectEqual(@as(u64, 1), s1.lines_parsed);
    try testing.expectEqual(@as(u64, 2), s2.lines_parsed);
}

test "metrics: setMemoryBytes updates the memory gauge" {
    var m = Metrics.init();
    m.setMemoryBytes(12345);
    try testing.expectEqual(@as(u64, 12345), m.snapshot().memory_bytes_used);
    m.setMemoryBytes(67890);
    try testing.expectEqual(@as(u64, 67890), m.snapshot().memory_bytes_used);
}

// Threading stress test: 4 threads x 1000 increments. Post-condition
// must be exactly 4000 — any race would bleed.
test "metrics: concurrent incrementParsed across 4 threads sums correctly" {
    var m = Metrics.init();
    const Worker = struct {
        fn run(metrics: *Metrics) void {
            var i: u32 = 0;
            while (i < 1000) : (i += 1) {
                metrics.incrementParsed();
            }
        }
    };

    var ths: [4]std.Thread = undefined;
    for (&ths) |*t| {
        t.* = try std.Thread.spawn(.{}, Worker.run, .{&m});
    }
    for (ths) |t| t.join();

    try testing.expectEqual(@as(u64, 4000), m.snapshot().lines_parsed);
}

test "metrics: concurrent mixed operations preserve totals" {
    var m = Metrics.init();
    _ = m.registerJail("sshd").?;

    const Worker = struct {
        fn run(metrics: *Metrics) void {
            var i: u32 = 0;
            while (i < 500) : (i += 1) {
                metrics.incrementParsed();
                metrics.incrementMatched();
                metrics.incrementBans();
                metrics.incrementUnbans();
                metrics.jailIncrementParsed("sshd");
            }
        }
    };

    var ths: [4]std.Thread = undefined;
    for (&ths) |*t| {
        t.* = try std.Thread.spawn(.{}, Worker.run, .{&m});
    }
    for (ths) |t| t.join();

    const s = m.snapshot();
    try testing.expectEqual(@as(u64, 2000), s.lines_parsed);
    try testing.expectEqual(@as(u64, 2000), s.lines_matched);
    try testing.expectEqual(@as(u64, 2000), s.bans_total);
    try testing.expectEqual(@as(u64, 2000), s.unbans_total);
    try testing.expectEqual(@as(u64, 2000), s.perJail()[0].lines_parsed);
    // active_bans increments by ban, decrements by unban -> net 0.
    try testing.expectEqual(@as(u32, 0), s.active_bans);
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! `fail2zig rule-test`: offline evaluation of one input against one builtin service or
//! native rule file using the daemon's own decoder, time admission and detectors. It
//! never opens the state store, the firewall or the daemon socket. Time admission is
//! reported per line but an obsolete event still exercises the rule, because operators
//! test historical logs; a rejected timestamp is a `reject` sample exactly as ingestion
//! would exclude it. Samples carry identity and reason only; raw lines appear solely
//! with `--print-lines`.

const std = @import("std");
const shared = @import("shared");
const posix = std.posix;

const registry = @import("../filters/registry.zig");
const builtin_detector = @import("../core/native_builtin_detector.zig");
const rules = @import("../core/native_rules.zig");
const text = @import("../core/source_text.zig");
const time = @import("../core/native_time.zig");
const policy = @import("../core/source_time_policy.zig");
const inference = @import("../core/year_inference.zig");
const timezone = @import("../core/native_timezone.zig");
const journal = @import("../core/native_journal_transport.zig");
const dns = @import("../core/native_dns.zig");
const config_mod = @import("../config/native.zig");

pub const ExitClass = shared.ExitClass;
pub const Output = enum { json, table };
pub const Identity = enum { raw, dns };
pub const TimestampKind = enum { iso8601, syslog, epoch_seconds, common_log, undated };

pub const max_file_bytes: u64 = 64 * 1024 * 1024;
pub const max_line_bytes: usize = 64 * 1024;
pub const default_max_lines: u32 = 1_000_000;
pub const default_limit: u32 = 20;
pub const default_window_us: i64 = 600 * 1_000_000;
pub const dns_timeout_ms: u64 = 1500;
const journal_batch: u16 = 128;

pub const Input = union(enum) {
    file: []const u8,
    record: []const u8,
    journal: []const []const u8,
};

pub const Rule = union(enum) {
    service: []const u8,
    rule_file: []const u8,
};

pub const Options = struct {
    input: Input,
    rule: Rule,
    config: ?[]const u8 = null,
    jail: ?[]const u8 = null,
    timestamp: ?TimestampKind = null,
    time_zone: ?[]const u8 = null,
    timezone_root: []const u8 = "/usr/share/zoneinfo",
    tz_offset_minutes: ?i16 = null,
    year: ?u16 = null,
    encoding: text.Encoding = .utf8,
    identity: Identity = .raw,
    dns_server: ?[]const u8 = null,
    ignore: []const []const u8 = &.{},
    max_lines: u32 = default_max_lines,
    limit: u32 = default_limit,
    output: Output = .json,
    print_lines: bool = false,
    /// Receipt and processing clock; wall clock when null.
    now_us: ?i64 = null,
    window_us: i64 = default_window_us,
    journal_executable: []const u8 = "/usr/bin/journalctl",
    journal_since_us: ?i64 = null,
};

pub const Outcome = enum { match, miss, ignore, reject };

pub const Sample = struct {
    line_no: u64,
    outcome: Outcome,
    reason: []const u8,
    identity: ?[]const u8 = null,
    event_time_us: ?i64 = null,
    time: ?[]const u8 = null,
    pattern: ?[]const u8 = null,
    correlation: ?Correlation = null,
    line: ?[]const u8 = null,

    pub const Correlation = struct { key: []const u8, phase: []const u8 };
};

pub const Counts = struct { matched: u64 = 0, missed: u64 = 0, ignored: u64 = 0, rejected: u64 = 0 };

pub const Report = struct {
    arena: std.heap.ArenaAllocator,
    input_kind: []const u8,
    input_path: ?[]const u8,
    lines_read: u64 = 0,
    rule_kind: []const u8,
    rule_name: []const u8,
    counts: Counts = .{},
    samples: std.ArrayListUnmanaged(Sample) = .{},
    /// Samples beyond `--limit` are counted but not retained.
    samples_omitted: u64 = 0,

    pub fn deinit(self: *Report) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub const Error = error{
    InputNotFound,
    InputNotRegular,
    InputTooLarge,
    InputUnreadable,
    UnknownService,
    InternalEventsRequired,
    RuleFileNotFound,
    RuleFileTooLarge,
    RuleFileInvalid,
    ConfigNotFound,
    ConfigInvalid,
    JailNotFound,
    TimestampRequired,
    TimezoneRequired,
    TimezoneUnavailable,
    InvalidIgnore,
    DnsServerRequired,
    DnsServerInvalid,
    JournalUnavailable,
    JournalFailed,
    JournalMalformed,
    OutOfMemory,
};

pub const max_ignore_flags: usize = 64;

pub fn run(allocator: std.mem.Allocator, args: []const []const u8, stdout: anytype, stderr: anytype) ExitClass {
    var ignore_buf: [max_ignore_flags][]const u8 = undefined;
    const options = parseArgs(args, &ignore_buf, stderr) orelse return usage(stderr);
    var report = evaluate(allocator, options) catch |err| {
        stderr.print("rule-test: {s}\n", .{describe(err)}) catch {};
        return .rejected;
    };
    defer report.deinit();
    switch (options.output) {
        .json => writeJson(&report, stdout) catch return .usage,
        .table => writeTable(&report, stdout) catch return .usage,
    }
    return .success;
}

fn usage(stderr: anytype) ExitClass {
    stderr.writeAll(
        \\usage:
        \\  fail2zig rule-test (--file <path> | --record "<line>" | --journal [<match>...])
        \\                     (--service <name> | --rule-file <path>)
        \\                     [--config <path>] [--jail <name>]
        \\                     [--timestamp iso8601|syslog|epoch_seconds|common_log|undated]
        \\                     [--time-zone <id>] [--tz-offset <minutes>] [--year <yyyy>]
        \\                     [--encoding utf8|ascii|latin1|utf16le|utf16be|utf32le|utf32be]
        \\                     [--identity raw|dns --dns-server <ip:port>] [--ignore <cidr>]...
        \\                     [--max-lines <n>] [--limit <n>] [--output json|table] [--print-lines]
        \\                     [--now <epoch-seconds>] [--window <seconds>]
        \\
    ) catch {};
    return .usage;
}

fn describe(err: anyerror) []const u8 {
    return switch (err) {
        error.InputNotFound => "input not found",
        error.InputNotRegular => "input is not a regular file",
        error.InputTooLarge => "input exceeds 64 MiB",
        error.InputUnreadable => "input could not be read",
        error.UnknownService => "unknown service name",
        error.InternalEventsRequired => "service consumes internal events, not log lines",
        error.RuleFileNotFound => "rule file not found",
        error.RuleFileTooLarge => "rule file exceeds 4096 bytes",
        error.RuleFileInvalid => "rule file rejected by the native rule grammar",
        error.ConfigNotFound => "config not found",
        error.ConfigInvalid => "config rejected",
        error.JailNotFound => "no jail in config selects this rule",
        error.TimestampRequired => "timestamp format required (--timestamp or --config)",
        error.TimezoneRequired => "syslog timestamps need --tz-offset, --time-zone or --config",
        error.TimezoneUnavailable => "named time zone could not be loaded",
        error.InvalidIgnore => "invalid ignore entry",
        error.DnsServerRequired => "--identity dns requires --dns-server <ip:port>",
        error.DnsServerInvalid => "--dns-server must be an ip:port with a nonzero port",
        error.JournalUnavailable => "journalctl is not available on this host",
        error.JournalFailed => "journalctl failed",
        error.JournalMalformed => "journalctl produced a malformed record",
        error.OutOfMemory => "out of memory",
        else => @errorName(err),
    };
}

/// `ignore_buf` outlives the returned options; `--ignore` values are stored there.
pub fn parseArgs(args: []const []const u8, ignore_buf: *[max_ignore_flags][]const u8, stderr: anytype) ?Options {
    var input: ?Input = null;
    var rule: ?Rule = null;
    var out: Options = .{ .input = undefined, .rule = undefined };
    const ignores = ignore_buf;
    var ignore_count: usize = 0;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        const value: ?[]const u8 = if (i + 1 < args.len) args[i + 1] else null;
        if (std.mem.eql(u8, a, "--file")) {
            if (input != null) return dup(stderr, "input");
            input = .{ .file = value orelse return missing(stderr, a) };
            i += 1;
        } else if (std.mem.eql(u8, a, "--record")) {
            if (input != null) return dup(stderr, "input");
            input = .{ .record = value orelse return missing(stderr, a) };
            i += 1;
        } else if (std.mem.eql(u8, a, "--journal")) {
            if (input != null) return dup(stderr, "input");
            const start = i + 1;
            var end = start;
            while (end < args.len and !std.mem.startsWith(u8, args[end], "--")) : (end += 1) {}
            input = .{ .journal = args[start..end] };
            i = end - 1;
        } else if (std.mem.eql(u8, a, "--service")) {
            if (rule != null) return dup(stderr, "rule selection");
            rule = .{ .service = value orelse return missing(stderr, a) };
            i += 1;
        } else if (std.mem.eql(u8, a, "--rule-file")) {
            if (rule != null) return dup(stderr, "rule selection");
            rule = .{ .rule_file = value orelse return missing(stderr, a) };
            i += 1;
        } else if (std.mem.eql(u8, a, "--config")) {
            out.config = value orelse return missing(stderr, a);
            i += 1;
        } else if (std.mem.eql(u8, a, "--jail")) {
            out.jail = value orelse return missing(stderr, a);
            i += 1;
        } else if (std.mem.eql(u8, a, "--timestamp")) {
            out.timestamp = std.meta.stringToEnum(TimestampKind, value orelse return missing(stderr, a)) orelse return bad(stderr, a, value.?);
            i += 1;
        } else if (std.mem.eql(u8, a, "--time-zone")) {
            out.time_zone = value orelse return missing(stderr, a);
            i += 1;
        } else if (std.mem.eql(u8, a, "--tz-offset")) {
            out.tz_offset_minutes = std.fmt.parseInt(i16, value orelse return missing(stderr, a), 10) catch return bad(stderr, a, value.?);
            i += 1;
        } else if (std.mem.eql(u8, a, "--year")) {
            const year = std.fmt.parseInt(u16, value orelse return missing(stderr, a), 10) catch return bad(stderr, a, value.?);
            if (year < 1 or year > 9999) return bad(stderr, a, value.?);
            out.year = year;
            i += 1;
        } else if (std.mem.eql(u8, a, "--encoding")) {
            out.encoding = std.meta.stringToEnum(text.Encoding, value orelse return missing(stderr, a)) orelse return bad(stderr, a, value.?);
            i += 1;
        } else if (std.mem.eql(u8, a, "--identity")) {
            out.identity = std.meta.stringToEnum(Identity, value orelse return missing(stderr, a)) orelse return bad(stderr, a, value.?);
            i += 1;
        } else if (std.mem.eql(u8, a, "--dns-server")) {
            out.dns_server = value orelse return missing(stderr, a);
            i += 1;
        } else if (std.mem.eql(u8, a, "--ignore")) {
            if (ignore_count == ignores.len) return bad(stderr, a, "too many entries");
            ignores[ignore_count] = value orelse return missing(stderr, a);
            ignore_count += 1;
            i += 1;
        } else if (std.mem.eql(u8, a, "--max-lines")) {
            const n = std.fmt.parseInt(u32, value orelse return missing(stderr, a), 10) catch return bad(stderr, a, value.?);
            if (n == 0) return bad(stderr, a, value.?);
            out.max_lines = n;
            i += 1;
        } else if (std.mem.eql(u8, a, "--limit")) {
            const n = std.fmt.parseInt(u32, value orelse return missing(stderr, a), 10) catch return bad(stderr, a, value.?);
            if (n > 10_000) return bad(stderr, a, value.?);
            out.limit = n;
            i += 1;
        } else if (std.mem.eql(u8, a, "--output")) {
            out.output = std.meta.stringToEnum(Output, value orelse return missing(stderr, a)) orelse return bad(stderr, a, value.?);
            i += 1;
        } else if (std.mem.eql(u8, a, "--print-lines")) {
            out.print_lines = true;
        } else if (std.mem.eql(u8, a, "--now")) {
            const seconds = std.fmt.parseInt(i64, value orelse return missing(stderr, a), 10) catch return bad(stderr, a, value.?);
            out.now_us = (time.Timestamp.fromSeconds(seconds) catch return bad(stderr, a, value.?)).us;
            i += 1;
        } else if (std.mem.eql(u8, a, "--window")) {
            const seconds = std.fmt.parseInt(u32, value orelse return missing(stderr, a), 10) catch return bad(stderr, a, value.?);
            out.window_us = @as(i64, seconds) * 1_000_000;
            i += 1;
        } else if (std.mem.eql(u8, a, "--journal-executable")) {
            out.journal_executable = value orelse return missing(stderr, a);
            i += 1;
        } else if (std.mem.eql(u8, a, "--journal-since")) {
            const seconds = std.fmt.parseInt(i64, value orelse return missing(stderr, a), 10) catch return bad(stderr, a, value.?);
            out.journal_since_us = (time.Timestamp.fromSeconds(seconds) catch return bad(stderr, a, value.?)).us;
            i += 1;
        } else {
            stderr.print("error: unknown argument '{s}'\n", .{a}) catch {};
            return null;
        }
    }
    out.input = input orelse {
        stderr.writeAll("error: one of --file, --record or --journal is required\n") catch {};
        return null;
    };
    out.rule = rule orelse {
        stderr.writeAll("error: one of --service or --rule-file is required\n") catch {};
        return null;
    };
    if (out.identity == .dns and out.dns_server == null) {
        stderr.writeAll("error: --identity dns requires --dns-server\n") catch {};
        return null;
    }
    if (out.time_zone != null and out.tz_offset_minutes != null) {
        stderr.writeAll("error: --time-zone and --tz-offset are exclusive\n") catch {};
        return null;
    }
    out.ignore = ignores[0..ignore_count];
    return out;
}

fn dup(stderr: anytype, what: []const u8) ?Options {
    stderr.print("error: exactly one {s} is allowed\n", .{what}) catch {};
    return null;
}

fn missing(stderr: anytype, flag: []const u8) ?Options {
    stderr.print("error: {s} requires a value\n", .{flag}) catch {};
    return null;
}

fn bad(stderr: anytype, flag: []const u8, value: []const u8) ?Options {
    stderr.print("error: invalid value for {s}: '{s}'\n", .{ flag, value }) catch {};
    return null;
}

/// Field selection mirrors the daemon's native file projection for each format.
const TimeField = struct {
    format: time.Format,
    start: u32 = 0,
    boundary: union(enum) { length: u8, delimiter: u8 },
    context: time.Context = .{},
    infer_year: bool = false,
    zone: ?*const timezone.Zone = null,
};

const TimeSource = union(enum) { field: TimeField, journal, undated };

const Evaluator = union(enum) {
    service: builtin_detector.Detector,
    rule: *rules.Program,
};

const Session = struct {
    allocator: std.mem.Allocator,
    options: Options,
    report: *Report,
    evaluator: Evaluator,
    time_source: TimeSource,
    body: builtin_detector.Body,
    zone: ?*timezone.Zone,
    now: time.Timestamp,
    scratch: []u8,
    rule_scratch: *rules.Scratch,
    resolver: ?Resolver,

    const processFile = processFileImpl;
    const processJournal = processJournalImpl;
    const processLine = processLineImpl;
    const processBytes = processBytesImpl;
    const processDecoded = processDecodedImpl;
    const record = recordImpl;
    const identityForHostname = identityForHostnameImpl;

    fn deinit(self: *Session) void {
        switch (self.evaluator) {
            .service => |*d| d.deinit(self.allocator),
            .rule => |p| p.destroy(),
        }
        if (self.zone) |z| {
            z.deinit();
            self.allocator.destroy(z);
        }
        if (self.resolver) |*r| r.deinit();
        self.allocator.free(self.scratch);
        self.allocator.destroy(self.rule_scratch);
    }
};

pub fn evaluate(allocator: std.mem.Allocator, options: Options) Error!Report {
    var report = Report{
        .arena = std.heap.ArenaAllocator.init(allocator),
        .input_kind = @tagName(std.meta.activeTag(options.input)),
        .input_path = switch (options.input) {
            .file => |p| p,
            else => null,
        },
        .rule_kind = @tagName(std.meta.activeTag(options.rule)),
        .rule_name = "",
    };
    errdefer report.deinit();

    var session = try openSession(allocator, options, &report);
    defer session.deinit();

    switch (options.input) {
        .record => |line| try session.processLine(1, line),
        .file => |path| try session.processFile(path),
        .journal => |matches| try session.processJournal(matches),
    }
    return report;
}

const service_defaults = [_]struct { name: []const u8, timestamp: TimestampKind }{
    .{ .name = "apache-auth", .timestamp = .undated },
    .{ .name = "apache-badbots", .timestamp = .undated },
    .{ .name = "apache-overflows", .timestamp = .undated },
    .{ .name = "nginx-botsearch", .timestamp = .undated },
    .{ .name = "nginx-http-auth", .timestamp = .undated },
    .{ .name = "nginx-limit-req", .timestamp = .undated },
};

fn defaultTimestamp(service: []const u8) TimestampKind {
    for (service_defaults) |entry| if (std.mem.eql(u8, entry.name, service)) return entry.timestamp;
    return .syslog;
}

const Resolved = struct {
    timestamp: ?TimestampKind,
    tz_offset_minutes: ?i16,
    time_zone: ?[]const u8,
    ignore: []const []const u8,
};

fn openSession(allocator: std.mem.Allocator, options: Options, report: *Report) Error!Session {
    const now: time.Timestamp = .{ .us = options.now_us orelse std.time.microTimestamp() };
    var resolved = Resolved{ .timestamp = options.timestamp, .tz_offset_minutes = options.tz_offset_minutes, .time_zone = options.time_zone, .ignore = options.ignore };
    var timezone_root = options.timezone_root;
    if (options.config) |path| try resolveFromConfig(report.arena.allocator(), path, options, &resolved, &timezone_root);

    const evaluator: Evaluator = switch (options.rule) {
        .service => |name| blk: {
            if (registry.get(name) == null) return error.UnknownService;
            report.rule_name = name;
            if (resolved.timestamp == null) resolved.timestamp = defaultTimestamp(name);
            break :blk .{ .service = undefined };
        },
        .rule_file => |path| blk: {
            const bytes = std.fs.cwd().readFileAlloc(allocator, path, 4096) catch |err| return switch (err) {
                error.FileNotFound => error.RuleFileNotFound,
                error.FileTooBig => error.RuleFileTooLarge,
                error.OutOfMemory => error.OutOfMemory,
                else => error.RuleFileInvalid,
            };
            defer allocator.free(bytes);
            const program = rules.Program.create(allocator, bytes, .{}) catch |err| return switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                else => error.RuleFileInvalid,
            };
            report.rule_name = try report.arena.allocator().dupe(u8, program.metadata().id);
            if (resolved.timestamp == null) resolved.timestamp = .undated;
            break :blk .{ .rule = program };
        },
    };
    var evaluator_owned = evaluator;
    errdefer switch (evaluator_owned) {
        .rule => |p| p.destroy(),
        .service => {},
    };

    const timestamp: TimestampKind = if (options.input == .journal) .undated else resolved.timestamp orelse return error.TimestampRequired;
    const body: builtin_detector.Body = if (options.rule == .service and options.input != .journal and (timestamp == .iso8601 or timestamp == .syslog)) .syslog else .whole;

    var zone: ?*timezone.Zone = null;
    errdefer if (zone) |z| {
        z.deinit();
        allocator.destroy(z);
    };
    var time_source: TimeSource = .undated;
    if (options.input == .journal) {
        time_source = .journal;
    } else switch (timestamp) {
        .undated => {},
        .iso8601 => time_source = .{ .field = .{ .format = .iso8601, .boundary = .{ .delimiter = ' ' }, .context = .{ .year = options.year } } },
        .epoch_seconds => time_source = .{ .field = .{ .format = .epoch_seconds, .boundary = .{ .delimiter = ' ' } } },
        .common_log => time_source = .{ .field = .{ .format = .common_log, .start = 1, .boundary = .{ .length = 26 } } },
        .syslog => {
            var field = TimeField{ .format = .syslog, .boundary = .{ .length = 15 }, .infer_year = options.year == null };
            if (resolved.time_zone) |id| {
                const z = try allocator.create(timezone.Zone);
                errdefer allocator.destroy(z);
                z.* = timezone.Zone.load(allocator, timezone_root, id, .reject) catch |err| return switch (err) {
                    error.OutOfMemory => error.OutOfMemory,
                    else => error.TimezoneUnavailable,
                };
                zone = z;
                field.zone = z;
                field.context = .{ .year = options.year, .offset_seconds = 0 };
            } else {
                const minutes: i32 = resolved.tz_offset_minutes orelse 0;
                field.context = .{ .year = options.year, .offset_seconds = minutes * 60 };
            }
            time_source = .{ .field = field };
        },
    }

    if (evaluator_owned == .service) {
        evaluator_owned.service = builtin_detector.Detector.init(allocator, .{
            .filter = options.rule.service,
            .body = body,
            .ignore = resolved.ignore,
            .ignore_capacity = 128,
            .max_decoded_bytes = max_line_bytes,
        }) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.InternalEventsRequired => error.InternalEventsRequired,
            error.UnknownFilter => error.UnknownService,
            error.InvalidStaticIgnore, error.IgnoreCapacityExceeded => error.InvalidIgnore,
            else => error.InvalidIgnore,
        };
    }
    errdefer if (evaluator_owned == .service) evaluator_owned.service.deinit(allocator);

    var resolver: ?Resolver = null;
    if (options.identity == .dns) {
        const spec = options.dns_server orelse return error.DnsServerRequired;
        resolver = Resolver.init(spec) catch return error.DnsServerInvalid;
    }
    errdefer if (resolver) |*r| r.deinit();

    const scratch = try allocator.alloc(u8, text.max_record_bytes);
    errdefer allocator.free(scratch);
    const rule_scratch = try allocator.create(rules.Scratch);
    rule_scratch.* = .{};

    return .{
        .allocator = allocator,
        .options = options,
        .report = report,
        .evaluator = evaluator_owned,
        .time_source = time_source,
        .body = body,
        .zone = zone,
        .now = now,
        .scratch = scratch,
        .rule_scratch = rule_scratch,
        .resolver = resolver,
    };
}

fn resolveFromConfig(arena: std.mem.Allocator, path: []const u8, options: Options, out: *Resolved, timezone_root: *[]const u8) Error!void {
    const cfg = config_mod.Config.loadFile(arena, path) catch |err| return switch (err) {
        error.FileNotFound => error.ConfigNotFound,
        error.OutOfMemory => error.OutOfMemory,
        else => error.ConfigInvalid,
    };
    timezone_root.* = cfg.global.timezone_root;
    const jail: *const config_mod.JailConfig = blk: {
        for (cfg.jails) |*jail| {
            if (options.jail) |name| {
                if (std.mem.eql(u8, jail.name, name)) break :blk jail;
                continue;
            }
            switch (options.rule) {
                .service => |name| if (jail.enabled and std.mem.eql(u8, jail.filter, name)) break :blk jail,
                .rule_file => |file| for (jail.rule_files) |candidate| if (std.mem.eql(u8, candidate, file)) break :blk jail,
            }
        }
        return error.JailNotFound;
    };
    if (out.timestamp == null) if (jail.timestamp) |ts| {
        out.timestamp = std.meta.stringToEnum(TimestampKind, @tagName(ts)).?;
    };
    if (out.tz_offset_minutes == null and out.time_zone == null) {
        out.tz_offset_minutes = jail.timezone_offset_minutes;
        out.time_zone = jail.timezone;
    }
    if (out.ignore.len == 0) out.ignore = jail.ignoreip orelse cfg.defaults.ignoreip;
}

// ---------------------------------------------------------------------------
// Input drivers
// ---------------------------------------------------------------------------

const read_chunk: usize = 256 * 1024;

fn processFileImpl(self: *Session, path: []const u8) Error!void {
    const file = std.fs.cwd().openFile(path, .{}) catch |err| return switch (err) {
        error.FileNotFound => error.InputNotFound,
        error.IsDir => error.InputNotRegular,
        else => error.InputUnreadable,
    };
    defer file.close();
    const st = posix.fstat(file.handle) catch return error.InputUnreadable;
    if (!posix.S.ISREG(st.mode)) return error.InputNotRegular;
    if (st.size < 0 or @as(u64, @intCast(st.size)) > max_file_bytes) return error.InputTooLarge;

    const width = self.options.encoding.width();
    const buf = try self.allocator.alloc(u8, read_chunk + max_line_bytes + 4);
    defer self.allocator.free(buf);
    var len: usize = 0;
    var offset: u64 = 0;
    var line_no: u64 = 0;
    var eof = false;
    var skipping = false;
    while (true) {
        if (!eof and len < buf.len) {
            const n = file.read(buf[len..]) catch return error.InputUnreadable;
            if (n == 0) eof = true else len += n;
        }
        if (len == 0) break;
        const window = buf[0..@min(len, max_line_bytes + width)];
        const framed = text.frame(self.options.encoding, window, offset) catch null;
        if (framed) |f| {
            if (skipping) {
                skipping = false;
            } else {
                if (line_no == self.options.max_lines) break;
                line_no += 1;
                try self.processBytes(line_no, f.payload, offset);
            }
            offset += f.consumed;
            std.mem.copyForwards(u8, buf[0 .. len - f.consumed], buf[f.consumed..len]);
            len -= f.consumed;
            continue;
        }
        if (eof and len <= max_line_bytes) {
            if (!skipping and line_no < self.options.max_lines) {
                line_no += 1;
                const tail = buf[0 .. len - (len % width)];
                try self.processBytes(line_no, tail, offset);
            }
            break;
        }
        if (len < buf.len and !eof) continue;
        // No newline inside the bound: count one rejected line, then discard through the
        // next newline so the following line is still evaluated.
        if (!skipping) {
            if (line_no == self.options.max_lines) break;
            line_no += 1;
            try self.record(line_no, .reject, "line_too_long", null, null, null, null, null, null);
            skipping = true;
        }
        var drop = len - (len % width);
        if (text.frame(self.options.encoding, buf[0..drop], offset) catch null) |f| {
            drop = f.consumed;
            skipping = false;
        }
        offset += drop;
        std.mem.copyForwards(u8, buf[0 .. len - drop], buf[drop..len]);
        len -= drop;
        if (eof and len == 0) break;
    }
    self.report.lines_read = line_no;
}

fn processJournalImpl(self: *Session, matches: []const []const u8) Error!void {
    std.fs.cwd().access(self.options.journal_executable, .{}) catch return error.JournalUnavailable;
    const options = journal.Options{ .executable = self.options.journal_executable, .matches = matches, .batch_records = journal_batch };
    journal.validate(options) catch return error.JournalFailed;
    const output = try self.allocator.alloc(u8, journal.parse_bytes);
    defer self.allocator.free(output);
    const scratch = try self.allocator.alloc(u8, journal.parse_bytes);
    defer self.allocator.free(scratch);
    var query: journal.Query = .{ .since_us = self.options.journal_since_us orelse @max(0, self.now.us - 3600 * 1_000_000) };
    var cursor_buf: [journal.max_cursor_bytes]u8 = undefined;
    var line_no: u64 = 0;
    var last_batch: usize = journal_batch;
    while (last_batch == journal_batch and line_no < self.options.max_lines) {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const argv = journal.argv(arena.allocator(), options, query, journal_batch + 1) catch return error.JournalFailed;
        var diagnostic: journal.Diagnostic = .{};
        const produced = journal.execute(arena.allocator(), argv, output, &diagnostic, options.timeout_ms, null) catch return error.JournalFailed;
        var lines = std.mem.splitScalar(u8, produced, '\n');
        var batch: usize = 0;
        var first = query == .cursor;
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            const entry = journal.decode(scratch, line, max_line_bytes) catch return error.JournalMalformed;
            if (first) {
                first = false;
                if (std.mem.eql(u8, entry.cursor, cursor_buf[0..query.cursor.len])) continue;
            }
            batch += 1;
            if (line_no == self.options.max_lines) break;
            line_no += 1;
            const stamp: ?time.Timestamp = if (entry.realtime_us) |us| time.Timestamp.fromJournal(us) catch null else null;
            try self.processDecoded(line_no, entry.message, if (stamp) |s| .{ .parsed = s } else .{ .rejected = .missing }, null);
            @memcpy(cursor_buf[0..entry.cursor.len], entry.cursor);
            query = .{ .cursor = cursor_buf[0..entry.cursor.len] };
        }
        last_batch = batch;
    }
    self.report.lines_read = line_no;
}

// ---------------------------------------------------------------------------
// Per-line evaluation
// ---------------------------------------------------------------------------

const ParsedTime = struct { input: policy.Input, inferred_year: ?u16 = null };

fn fieldInput(field: TimeField, decoded: []const u8, receipt: time.Timestamp) !ParsedTime {
    if (field.start >= decoded.len) return .{ .input = .{ .rejected = .missing } };
    const remaining = decoded[field.start..];
    const value = switch (field.boundary) {
        .length => |length| if (remaining.len < length) return .{ .input = .{ .rejected = .malformed } } else remaining[0..length],
        .delimiter => |delimiter| remaining[0 .. std.mem.indexOfScalar(u8, remaining[0..@min(remaining.len, 65)], delimiter) orelse @min(remaining.len, 65)],
    };
    if (value.len == 0) return .{ .input = .{ .rejected = .missing } };
    if (field.zone) |zone| {
        if (field.infer_year) {
            const parsed = inference.inferZoned(value, receipt, zone) catch |err| return mapTimeError(err);
            return .{ .input = .{ .parsed = parsed.timestamp }, .inferred_year = parsed.year };
        }
        const local = time.parse(.syslog, value, .{ .year = field.context.year, .offset_seconds = 0 }) catch |err| return mapTimeError(err);
        const selected = zone.resolveLocalMicros(local.us) catch |err| return mapTimeError(err);
        return .{ .input = .{ .parsed = .{ .us = selected.utc_us } } };
    }
    if (!field.infer_year) return .{ .input = try policy.parseField(field.format, value, field.context) };
    const parsed = inference.infer(value, receipt, field.context.offset_seconds.?) catch |err| return mapTimeError(err);
    return .{ .input = .{ .parsed = parsed.timestamp }, .inferred_year = parsed.year };
}

fn mapTimeError(err: anyerror) !ParsedTime {
    return switch (err) {
        error.InvalidTimestamp, error.AmbiguousYear, error.LocalTimeGap, error.AmbiguousLocalTime => .{ .input = .{ .rejected = .malformed } },
        error.TimeOutOfRange => .{ .input = .{ .rejected = .out_of_range } },
        error.MissingYear, error.MissingTimezone => .{ .input = .{ .rejected = .malformed } },
        else => err,
    };
}

fn processLineImpl(self: *Session, line_no: u64, line: []const u8) Error!void {
    self.report.lines_read = line_no;
    if (line.len > max_line_bytes) return self.record(line_no, .reject, "line_too_long", null, null, null, null, null, null);
    try self.processBytes(line_no, line, 0);
}

fn processBytesImpl(self: *Session, line_no: u64, raw: []const u8, offset: u64) Error!void {
    const decoded = text.decode(self.options.encoding, raw, self.scratch, offset, .strip_stream_start) catch {
        return self.record(line_no, .reject, "invalid_encoding", null, null, null, null, null, null);
    };
    if (!std.unicode.utf8ValidateSlice(decoded) or std.mem.indexOfScalar(u8, decoded, 0) != null or std.mem.indexOfAny(u8, decoded, "\r\n") != null) {
        return self.record(line_no, .reject, "invalid_record", null, null, null, null, null, decoded);
    }
    const input: policy.Input = switch (self.time_source) {
        .field => |field| (fieldInput(field, decoded, self.now) catch return self.record(line_no, .reject, "time-context-unavailable", null, null, null, null, null, decoded)).input,
        .journal => .{ .rejected = .missing },
        .undated => .{ .rejected = .missing },
    };
    try self.processDecoded(line_no, decoded, input, null);
}

fn processDecodedImpl(self: *Session, line_no: u64, decoded: []const u8, input: policy.Input, _: ?void) Error!void {
    const admitted = policy.evaluate(if (self.time_source == .undated) .undated else .timestamped, input, self.now, self.now, self.options.window_us) catch {
        return self.record(line_no, .reject, "time-evaluation-failed", null, null, null, null, null, decoded);
    };
    const disposition = admitted.disposition();
    const evidence: policy.Evidence = switch (admitted) {
        .eligible, .obsolete => |e| e,
        .rejected => return self.record(line_no, .reject, disposition, null, null, disposition, null, null, decoded),
    };
    switch (self.evaluator) {
        .service => |*detector| {
            const result = detector.evaluate(decoded, .{ .eligible = evidence }) catch |err| {
                const reason: []const u8 = if (err == error.RecordTooLarge) "record_too_large" else "invalid_record";
                return self.record(line_no, .reject, reason, null, null, disposition, null, null, decoded);
            };
            const matched: ?builtin_detector.Match = switch (result) {
                .unenforceable, .ignored => |m| m,
                .candidate => |c| c.match,
                else => null,
            };
            var identity_buf: [64]u8 = undefined;
            const identity: ?[]const u8 = if (matched) |m| std.fmt.bufPrint(&identity_buf, "{}", .{m.subject}) catch null else null;
            const pattern: ?[]const u8 = if (matched) |m| m.pattern else null;
            switch (result) {
                .candidate => try self.record(line_no, .match, "matched", identity, evidence.timestamp.us, disposition, pattern, null, decoded),
                .no_match => try self.record(line_no, .miss, "no_match", null, evidence.timestamp.us, disposition, null, null, decoded),
                .malformed_body => try self.record(line_no, .reject, "malformed_body", null, evidence.timestamp.us, disposition, null, null, decoded),
                .unenforceable => try self.record(line_no, .ignore, "unenforceable", identity, evidence.timestamp.us, disposition, pattern, null, decoded),
                .ignored => try self.record(line_no, .ignore, "ignored", identity, evidence.timestamp.us, disposition, pattern, null, decoded),
                .time_excluded => try self.record(line_no, .reject, disposition, null, null, disposition, null, null, decoded),
            }
        },
        .rule => |program| {
            const observation = program.analyze(.{ .source = program.metadata().source, .record = decoded }, self.rule_scratch) catch |err| {
                const reason: []const u8 = switch (err) {
                    error.RecordTooLarge => "record_too_large",
                    error.ResourceLimit => "resource_limit",
                };
                return self.record(line_no, .reject, reason, null, null, disposition, null, null, decoded);
            };
            const outcome = observation.outcome;
            const kind: Outcome = switch (outcome.kind) {
                .candidate => .match,
                .no_match, .awaiting_context => .miss,
                .excluded => .ignore,
                .rejected => .reject,
            };
            var identity_buf: [320]u8 = undefined;
            var identity: ?[]const u8 = null;
            if (outcome.subject) |subject| identity = switch (subject) {
                .address => |ip| std.fmt.bufPrint(&identity_buf, "{}", .{ip}) catch null,
                .hostname => |name| try self.identityForHostname(&identity_buf, name),
            };
            var correlation: ?Sample.Correlation = null;
            if (observation.correlation) |c| correlation = .{ .key = c.key.slice(), .phase = @tagName(c.phase) };
            try self.record(line_no, kind, @tagName(outcome.reason), identity, evidence.timestamp.us, disposition, null, correlation, decoded);
        },
    }
}

fn identityForHostnameImpl(self: *Session, buf: []u8, name: rules.Hostname) Error!?[]const u8 {
    const resolver = if (self.resolver) |*r| r else return std.fmt.bufPrint(buf, "{s}", .{name.slice()}) catch null;
    const resolved = resolver.resolve(name);
    return switch (resolved) {
        .address => |ip| std.fmt.bufPrint(buf, "{s}={}", .{ name.slice(), ip }) catch null,
        .failed => |reason| std.fmt.bufPrint(buf, "{s} (dns:{s})", .{ name.slice(), @tagName(reason) }) catch null,
    };
}

fn recordImpl(
    self: *Session,
    line_no: u64,
    outcome: Outcome,
    reason: []const u8,
    identity: ?[]const u8,
    event_time_us: ?i64,
    time_disposition: ?[]const u8,
    pattern: ?[]const u8,
    correlation: ?Sample.Correlation,
    decoded: ?[]const u8,
) Error!void {
    switch (outcome) {
        .match => self.report.counts.matched += 1,
        .miss => self.report.counts.missed += 1,
        .ignore => self.report.counts.ignored += 1,
        .reject => self.report.counts.rejected += 1,
    }
    if (self.report.samples.items.len >= self.options.limit) {
        self.report.samples_omitted += 1;
        return;
    }
    const arena = self.report.arena.allocator();
    var sample = Sample{
        .line_no = line_no,
        .outcome = outcome,
        .reason = reason,
        .event_time_us = event_time_us,
        .time = time_disposition,
        .pattern = pattern,
    };
    if (identity) |id| sample.identity = try arena.dupe(u8, id);
    if (correlation) |c| sample.correlation = .{ .key = try arena.dupe(u8, c.key), .phase = c.phase };
    if (self.options.print_lines) if (decoded) |d| {
        sample.line = try arena.dupe(u8, d);
    };
    try self.report.samples.append(arena, sample);
}

// ---------------------------------------------------------------------------
// DNS identity (opt-in only)
// ---------------------------------------------------------------------------

const Resolver = struct {
    client: dns.Client,

    const Resolution = union(enum) { address: shared.IpAddress, failed: dns.Reason };

    fn init(spec: []const u8) !Resolver {
        const colon = std.mem.lastIndexOfScalar(u8, spec, ':') orelse return error.DnsServerInvalid;
        const host = std.mem.trim(u8, spec[0..colon], "[]");
        const port = std.fmt.parseInt(u16, spec[colon + 1 ..], 10) catch return error.DnsServerInvalid;
        const address = std.net.Address.parseIp(host, port) catch return error.DnsServerInvalid;
        var generation: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash("fail2zig-rule-test-dns", &generation, .{});
        return .{ .client = dns.Client.init(address, generation) catch return error.DnsServerInvalid };
    }

    fn deinit(self: *Resolver) void {
        self.client.deinit();
    }

    /// Bounded, synchronous: one request, at most `dns_timeout_ms` of polling.
    fn resolve(self: *Resolver, name: rules.Hostname) Resolution {
        const start_ms = monotonicMs();
        self.client.begin(.{ .name = name, .family = .both, .generation = self.client.generation }, start_ms) catch |err| {
            return .{ .failed = if (err == error.InvalidHostname) .invalid else .unavailable };
        };
        while (true) {
            const now_ms = monotonicMs();
            const result = self.client.poll(now_ms, std.time.microTimestamp()) catch return .{ .failed = .unavailable };
            if (result) |r| {
                if (r.answer.kind == .positive and r.answer.count > 0) return .{ .address = r.answer.addresses[0] };
                return .{ .failed = if (r.answer.reason == .none) .incomplete else r.answer.reason };
            }
            if (now_ms - start_ms >= dns_timeout_ms) {
                self.client.deinit();
                return .{ .failed = .timeout };
            }
            std.time.sleep(5 * std.time.ns_per_ms);
        }
    }
};

fn monotonicMs() u64 {
    const ts = posix.clock_gettime(.MONOTONIC) catch return 0;
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / 1_000_000;
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

pub const schema_version: u32 = 1;

pub fn writeJson(report: *const Report, writer: anytype) !void {
    var ws = std.json.writeStream(writer, .{});
    try ws.beginObject();
    try ws.objectField("schema_version");
    try ws.write(schema_version);
    try ws.objectField("input");
    try ws.beginObject();
    try ws.objectField("kind");
    try ws.write(report.input_kind);
    if (report.input_path) |p| {
        try ws.objectField("path");
        try ws.write(p);
    }
    try ws.objectField("lines_read");
    try ws.write(report.lines_read);
    try ws.endObject();
    try ws.objectField("rule");
    try ws.beginObject();
    try ws.objectField("kind");
    try ws.write(report.rule_kind);
    try ws.objectField("name");
    try ws.write(report.rule_name);
    try ws.endObject();
    try ws.objectField("counts");
    try ws.write(report.counts);
    try ws.objectField("samples_omitted");
    try ws.write(report.samples_omitted);
    try ws.objectField("samples");
    try ws.beginArray();
    for (report.samples.items) |s| {
        try ws.beginObject();
        try ws.objectField("line_no");
        try ws.write(s.line_no);
        try ws.objectField("outcome");
        try ws.write(@tagName(s.outcome));
        try ws.objectField("reason");
        try ws.write(s.reason);
        if (s.identity) |v| {
            try ws.objectField("identity");
            try ws.write(v);
        }
        if (s.event_time_us) |v| {
            try ws.objectField("event_time_us");
            try ws.write(v);
        }
        if (s.time) |v| {
            try ws.objectField("time");
            try ws.write(v);
        }
        if (s.pattern) |v| {
            try ws.objectField("pattern");
            try ws.write(v);
        }
        if (s.correlation) |c| {
            try ws.objectField("correlation");
            try ws.beginObject();
            try ws.objectField("key");
            try ws.write(c.key);
            try ws.objectField("phase");
            try ws.write(c.phase);
            try ws.endObject();
        }
        if (s.line) |v| {
            try ws.objectField("line");
            try ws.write(v);
        }
        try ws.endObject();
    }
    try ws.endArray();
    try ws.endObject();
    try writer.writeByte('\n');
}

pub fn writeTable(report: *const Report, writer: anytype) !void {
    try writer.print("input\t{s}\t{s}\tlines_read={d}\n", .{ report.input_kind, report.input_path orelse "-", report.lines_read });
    try writer.print("rule\t{s}\t{s}\n", .{ report.rule_kind, report.rule_name });
    try writer.print("counts\tmatched={d}\tmissed={d}\tignored={d}\trejected={d}\n", .{ report.counts.matched, report.counts.missed, report.counts.ignored, report.counts.rejected });
    try writer.writeAll("line\toutcome\treason\tidentity\tevent_time_us\ttime\tpattern\n");
    for (report.samples.items) |s| {
        try writer.print("{d}\t{s}\t{s}\t{s}\t", .{ s.line_no, @tagName(s.outcome), s.reason, s.identity orelse "-" });
        if (s.event_time_us) |v| try writer.print("{d}", .{v}) else try writer.writeByte('-');
        try writer.print("\t{s}\t{s}", .{ s.time orelse "-", s.pattern orelse "-" });
        if (s.correlation) |c| try writer.print("\t{s}:{s}", .{ c.key, c.phase });
        if (s.line) |v| try writer.print("\t{s}", .{v});
        try writer.writeByte('\n');
    }
    if (report.samples_omitted != 0) try writer.print("omitted\t{d}\n", .{report.samples_omitted});
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const shared = @import("shared");

pub const Error = error{
    FileNotFound,
    AccessDenied,
    UnexpectedToken,
    UnterminatedString,
    InvalidEscape,
    InvalidInteger,
    InvalidFloat,
    InvalidBool,
    InvalidArray,
    DuplicateKey,
    UnknownSection,
    UnknownKey,
    MissingRequired,
    InvalidValue,
    TooManyJails,
    OutOfMemory,
    ReadFailed,
};

pub const Diagnostic = struct {
    line: u32 = 1,
    col: u32 = 1,
    message: []const u8 = "",
};

pub const LogLevel = enum { debug, info, warn, err };

pub const BanAction = enum { nftables, iptables, ipset, @"log-only" };

pub const LogSource = enum { auto, file, journald };

pub const BantimeFormula = enum { linear, exponential };

pub const BanTimeIncrement = struct {
    enabled: bool = false,
    multiplier: f64 = 1.0,
    factor: f64 = 1.0,
    formula: BantimeFormula = .linear,
    max_bantime: shared.Duration = 86_400 * 7,
};

pub const GlobalConfig = struct {
    log_level: LogLevel = .info,
    pid_file: []const u8 = "/run/fail2zig/fail2zig.pid",
    socket_path: []const u8 = "/run/fail2zig/fail2zig.sock",
    state_file: []const u8 = "/var/lib/fail2zig/state.bin",
    memory_ceiling_mb: u32 = 64,
    metrics_bind: []const u8 = "127.0.0.1",
    metrics_port: u16 = 9100,
    websocket_max_clients: u32 = 16,
};

pub const websocket_hard_max_clients: u32 = 1024;

pub const JailDefaults = struct {
    bantime: shared.Duration = 600,
    findtime: shared.Duration = 600,
    maxretry: u32 = 5,
    banaction: BanAction = .nftables,
    ignoreip: []const []const u8 = &.{},
    bantime_increment: BanTimeIncrement = .{},
};

pub const JailConfig = struct {
    name: []const u8,
    enabled: bool = true,
    logpath: []const []const u8 = &.{},
    source: LogSource = .auto,
    filter: []const u8 = "",
    maxretry: ?u32 = null,
    findtime: ?shared.Duration = null,
    bantime: ?shared.Duration = null,
    banaction: ?BanAction = null,
    ignoreip: ?[]const []const u8 = null,
    bantime_increment: BanTimeIncrement = .{},
    bantime_increment_explicit: bool = false,

    pub fn effectiveBantime(self: *const JailConfig, def: JailDefaults) shared.Duration {
        return self.bantime orelse def.bantime;
    }
    pub fn effectiveFindtime(self: *const JailConfig, def: JailDefaults) shared.Duration {
        return self.findtime orelse def.findtime;
    }
    pub fn effectiveMaxretry(self: *const JailConfig, def: JailDefaults) u32 {
        return self.maxretry orelse def.maxretry;
    }
    pub fn effectiveBanaction(self: *const JailConfig, def: JailDefaults) BanAction {
        return self.banaction orelse def.banaction;
    }
};

pub const ResolvedJailConfig = struct {
    name: []const u8,
    enabled: bool,
    maxretry: u32,
    findtime: shared.Duration,
    bantime: shared.Duration,
    banaction: BanAction,
    bantime_increment: BanTimeIncrement,
};

pub fn resolveJail(cfg: *const Config, jail_name: []const u8) ?ResolvedJailConfig {
    for (cfg.jails) |*j| {
        if (std.mem.eql(u8, j.name, jail_name)) {
            return resolveJailFromConfig(j, cfg.defaults);
        }
    }
    return null;
}

pub fn resolveJailFromConfig(j: *const JailConfig, defaults: JailDefaults) ResolvedJailConfig {
    return .{
        .name = j.name,
        .enabled = j.enabled,
        .maxretry = j.effectiveMaxretry(defaults),
        .findtime = j.effectiveFindtime(defaults),
        .bantime = j.effectiveBantime(defaults),
        .banaction = j.effectiveBanaction(defaults),
        .bantime_increment = if (j.bantime_increment_explicit)
            j.bantime_increment
        else
            defaults.bantime_increment,
    };
}

pub const Config = struct {
    global: GlobalConfig = .{},
    defaults: JailDefaults = .{},
    jails: []JailConfig = &.{},
    diag: Diagnostic = .{},

    pub fn loadFile(arena: std.mem.Allocator, path: []const u8) Error!Config {
        const file = std.fs.cwd().openFile(path, .{}) catch |err| return switch (err) {
            error.FileNotFound => error.FileNotFound,
            error.AccessDenied => error.AccessDenied,
            else => error.ReadFailed,
        };
        defer file.close();

        const max_size: usize = 1024 * 1024;
        const bytes = file.readToEndAlloc(arena, max_size) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.ReadFailed,
        };
        return parse(arena, bytes);
    }

    pub fn parse(arena: std.mem.Allocator, source: []const u8) Error!Config {
        var p = Parser.init(arena, source);
        return p.parseConfig();
    }

    pub fn load(allocator: std.mem.Allocator, path: []const u8) Error!Config {
        return loadFile(allocator, path);
    }
};

pub const ValidationError = error{
    InvalidBantime,
    InvalidFindtime,
    InvalidMaxretry,
    MemoryCeilingTooLow,
    UnknownFilter,
    EmptyJailName,
    DuplicateJailName,
};

pub fn validate(cfg: *const Config) ValidationError!void {
    if (cfg.global.memory_ceiling_mb < 16) {
        std.log.warn("config: memory_ceiling_mb={d} is below 16MB floor", .{cfg.global.memory_ceiling_mb});
        return error.MemoryCeilingTooLow;
    }
    if (cfg.defaults.bantime == 0) {
        std.log.warn("config: defaults.bantime must be > 0", .{});
        return error.InvalidBantime;
    }
    if (cfg.defaults.findtime == 0) {
        std.log.warn("config: defaults.findtime must be > 0", .{});
        return error.InvalidFindtime;
    }
    if (cfg.defaults.maxretry == 0) {
        std.log.warn("config: defaults.maxretry must be > 0", .{});
        return error.InvalidMaxretry;
    }

    const sock_dir = std.fs.path.dirname(cfg.global.socket_path) orelse "/";
    if (sock_dir.len > 0) {
        std.fs.cwd().access(sock_dir, .{}) catch {
            std.log.warn("config: socket_path parent directory not found (created at startup): {s}", .{sock_dir});
        };
    }

    for (cfg.jails, 0..) |j, i| {
        if (j.name.len == 0) return error.EmptyJailName;

        var k: usize = i + 1;
        while (k < cfg.jails.len) : (k += 1) {
            if (std.mem.eql(u8, j.name, cfg.jails[k].name)) {
                std.log.warn("config: duplicate jail name: {s}", .{j.name});
                return error.DuplicateJailName;
            }
        }

        if (j.bantime) |b| if (b == 0) return error.InvalidBantime;
        if (j.findtime) |f| if (f == 0) return error.InvalidFindtime;
        if (j.maxretry) |m| if (m == 0) return error.InvalidMaxretry;

        for (j.logpath) |lp| {
            std.fs.cwd().access(lp, .{}) catch {
                std.log.warn("config: jail '{s}' logpath not found (may appear later): {s}", .{ j.name, lp });
            };
        }

        if (j.enabled) {
            const would_use_journald = switch (j.source) {
                .journald => true,
                .auto => !anyLogpathExists(j.logpath) and filterSupportsJournald(j.filter),
                .file => false,
            };
            if (would_use_journald and !journalctlPresent()) {
                std.log.warn(
                    "config: jail '{s}' source resolves to journald but journalctl not found at {s}",
                    .{ j.name, journalctl_path },
                );
            }
        }

        if (j.filter.len == 0 and j.enabled) {
            std.log.warn("config: jail '{s}' has no filter declared", .{j.name});
        }
    }
}

const Parser = struct {
    arena: std.mem.Allocator,
    src: []const u8,
    pos: usize,
    line: u32,
    col: u32,

    global: GlobalConfig,
    defaults: JailDefaults,
    jails: std.ArrayList(JailConfig),
    seen_keys: std.ArrayList([]const u8),

    const TOP_GLOBAL: []const u8 = "global";
    const TOP_DEFAULTS: []const u8 = "defaults";
    const TOP_JAILS: []const u8 = "jails";
    const MAX_JAILS: usize = 256;

    fn init(arena: std.mem.Allocator, src: []const u8) Parser {
        return .{
            .arena = arena,
            .src = src,
            .pos = 0,
            .line = 1,
            .col = 1,
            .global = .{},
            .defaults = .{},
            .jails = std.ArrayList(JailConfig).init(arena),
            .seen_keys = std.ArrayList([]const u8).init(arena),
        };
    }

    fn eof(self: *const Parser) bool {
        return self.pos >= self.src.len;
    }

    fn peek(self: *const Parser) u8 {
        return self.src[self.pos];
    }

    fn advance(self: *Parser) void {
        if (self.eof()) return;
        const c = self.src[self.pos];
        self.pos += 1;
        if (c == '\n') {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
    }

    fn diag(self: *const Parser) Diagnostic {
        return .{ .line = self.line, .col = self.col };
    }

    fn skipSpaceTabs(self: *Parser) void {
        while (!self.eof()) {
            const c = self.peek();
            if (c == ' ' or c == '\t') self.advance() else break;
        }
    }

    fn skipTrailing(self: *Parser) void {
        self.skipSpaceTabs();
        if (!self.eof() and self.peek() == '#') {
            while (!self.eof() and self.peek() != '\n') self.advance();
        }
    }

    fn expectEndOfLine(self: *Parser) Error!void {
        self.skipTrailing();
        if (self.eof()) return;
        if (self.peek() != '\n') return error.UnexpectedToken;
        self.advance();
    }

    fn skipBlankAndComments(self: *Parser) void {
        while (!self.eof()) {
            const c = self.peek();
            switch (c) {
                ' ', '\t', '\n', '\r' => self.advance(),
                '#' => while (!self.eof() and self.peek() != '\n') self.advance(),
                else => break,
            }
        }
    }

    fn parseConfig(self: *Parser) Error!Config {
        var current_section: []const u8 = "";
        while (true) {
            self.skipBlankAndComments();
            if (self.eof()) break;

            if (self.peek() == '[') {
                const name = try self.parseSectionHeader();
                current_section = name;
                try self.expectEndOfLine();
                continue;
            }

            const key = try self.parseBareKey();
            self.skipSpaceTabs();
            if (self.eof() or self.peek() != '=') return error.UnexpectedToken;
            self.advance();
            self.skipSpaceTabs();

            try self.dispatchKeyValue(current_section, key);
            try self.expectEndOfLine();
        }

        return .{
            .global = self.global,
            .defaults = self.defaults,
            .jails = try self.jails.toOwnedSlice(),
            .diag = .{ .line = self.line, .col = self.col },
        };
    }

    fn parseSectionHeader(self: *Parser) Error![]const u8 {
        if (self.peek() != '[') return error.UnexpectedToken;
        self.advance();
        const start = self.pos;
        while (!self.eof() and self.peek() != ']' and self.peek() != '\n') self.advance();
        if (self.eof() or self.peek() != ']') return error.UnexpectedToken;
        const name = self.src[start..self.pos];
        self.advance();
        const trimmed = std.mem.trim(u8, name, " \t");
        if (trimmed.len == 0) return error.UnexpectedToken;
        return trimmed;
    }

    fn parseBareKey(self: *Parser) Error![]const u8 {
        const start = self.pos;
        while (!self.eof()) {
            const c = self.peek();
            switch (c) {
                'a'...'z', 'A'...'Z', '0'...'9', '_', '-' => self.advance(),
                else => break,
            }
        }
        if (self.pos == start) return error.UnexpectedToken;
        return self.src[start..self.pos];
    }

    const Value = union(enum) {
        string: []const u8,
        int: i64,
        float: f64,
        boolean: bool,
        str_array: []const []const u8,
    };

    fn parseValue(self: *Parser) Error!Value {
        if (self.eof()) return error.UnexpectedToken;
        const c = self.peek();
        switch (c) {
            '"' => return .{ .string = try self.parseString() },
            '[' => return .{ .str_array = try self.parseStringArray() },
            't', 'f' => return .{ .boolean = try self.parseBool() },
            '-', '0'...'9' => return self.parseNumber(),
            else => return error.UnexpectedToken,
        }
    }

    fn parseString(self: *Parser) Error![]const u8 {
        if (self.peek() != '"') return error.UnexpectedToken;
        self.advance();
        const start = self.pos;
        var has_escape = false;
        while (true) {
            if (self.eof()) return error.UnterminatedString;
            const c = self.peek();
            if (c == '\n') return error.UnterminatedString;
            if (c == '\\') {
                has_escape = true;
                self.advance();
                if (self.eof()) return error.InvalidEscape;
                const esc = self.peek();
                if (esc != '"' and esc != '\\' and esc != 'n' and esc != 't') {
                    return error.InvalidEscape;
                }
                self.advance();
                continue;
            }
            if (c == '"') break;
            self.advance();
        }
        const end = self.pos;
        self.advance();

        if (!has_escape) return self.src[start..end];

        var buf = std.ArrayList(u8).init(self.arena);
        errdefer buf.deinit();
        var i: usize = start;
        while (i < end) : (i += 1) {
            const c = self.src[i];
            if (c == '\\' and i + 1 < end) {
                const esc = self.src[i + 1];
                const out: u8 = switch (esc) {
                    '"' => '"',
                    '\\' => '\\',
                    'n' => '\n',
                    't' => '\t',
                    else => return error.InvalidEscape,
                };
                try buf.append(out);
                i += 1;
                continue;
            }
            try buf.append(c);
        }
        return try buf.toOwnedSlice();
    }

    fn parseBool(self: *Parser) Error!bool {
        const rest = self.src[self.pos..];
        if (std.mem.startsWith(u8, rest, "true")) {
            for (0..4) |_| self.advance();
            return true;
        }
        if (std.mem.startsWith(u8, rest, "false")) {
            for (0..5) |_| self.advance();
            return false;
        }
        return error.InvalidBool;
    }

    fn parseInt(self: *Parser) Error!i64 {
        const start = self.pos;
        if (self.peek() == '-') self.advance();
        const digit_start = self.pos;
        while (!self.eof()) {
            const c = self.peek();
            if (c < '0' or c > '9') break;
            self.advance();
        }
        if (self.pos == digit_start) return error.InvalidInteger;
        const slice = self.src[start..self.pos];
        return std.fmt.parseInt(i64, slice, 10) catch return error.InvalidInteger;
    }

    fn parseNumber(self: *Parser) Error!Value {
        const start = self.pos;
        if (self.peek() == '-') self.advance();
        const digit_start = self.pos;
        while (!self.eof()) {
            const c = self.peek();
            if (c < '0' or c > '9') break;
            self.advance();
        }
        if (self.pos == digit_start) return error.InvalidInteger;
        if (self.eof() or self.peek() != '.') {
            const slice = self.src[start..self.pos];
            const n = std.fmt.parseInt(i64, slice, 10) catch return error.InvalidInteger;
            return .{ .int = n };
        }
        self.advance();
        const frac_start = self.pos;
        while (!self.eof()) {
            const c = self.peek();
            if (c < '0' or c > '9') break;
            self.advance();
        }
        if (self.pos == frac_start) return error.InvalidFloat;
        const slice = self.src[start..self.pos];
        const f = std.fmt.parseFloat(f64, slice) catch return error.InvalidFloat;
        return .{ .float = f };
    }

    fn parseStringArray(self: *Parser) Error![]const []const u8 {
        if (self.peek() != '[') return error.UnexpectedToken;
        self.advance();

        var items = std.ArrayList([]const u8).init(self.arena);
        errdefer items.deinit();

        while (true) {
            self.skipWhitespaceAcrossLines();
            if (self.eof()) return error.InvalidArray;
            if (self.peek() == ']') {
                self.advance();
                return try items.toOwnedSlice();
            }
            if (self.peek() != '"') return error.InvalidArray;
            const s = try self.parseString();
            try items.append(s);
            self.skipWhitespaceAcrossLines();
            if (self.eof()) return error.InvalidArray;
            const c = self.peek();
            if (c == ',') {
                self.advance();
                continue;
            }
            if (c == ']') {
                self.advance();
                return try items.toOwnedSlice();
            }
            return error.InvalidArray;
        }
    }

    fn skipWhitespaceAcrossLines(self: *Parser) void {
        while (!self.eof()) {
            const c = self.peek();
            switch (c) {
                ' ', '\t', '\n', '\r' => self.advance(),
                '#' => while (!self.eof() and self.peek() != '\n') self.advance(),
                else => break,
            }
        }
    }

    fn dispatchKeyValue(self: *Parser, section: []const u8, key: []const u8) Error!void {
        if (section.len == 0) return error.UnexpectedToken;
        if (std.mem.eql(u8, section, TOP_GLOBAL)) {
            return self.applyGlobalKey(key);
        }
        if (std.mem.eql(u8, section, TOP_DEFAULTS)) {
            return self.applyDefaultsKey(key);
        }
        if (std.mem.startsWith(u8, section, "jails.")) {
            const jail_name = section[6..];
            return self.applyJailKey(jail_name, key);
        }
        if (std.mem.startsWith(u8, section, "jails.") or std.mem.eql(u8, section, TOP_JAILS)) {
            return error.UnknownSection;
        }
        return error.UnknownSection;
    }

    fn applyGlobalKey(self: *Parser, key: []const u8) Error!void {
        const v = try self.parseValue();
        if (std.mem.eql(u8, key, "log_level")) {
            const s = try asString(v);
            self.global.log_level = try parseLogLevel(s);
        } else if (std.mem.eql(u8, key, "pid_file")) {
            self.global.pid_file = try asString(v);
        } else if (std.mem.eql(u8, key, "socket_path")) {
            self.global.socket_path = try asString(v);
        } else if (std.mem.eql(u8, key, "state_file")) {
            self.global.state_file = try asString(v);
        } else if (std.mem.eql(u8, key, "memory_ceiling_mb")) {
            const n = try asInt(v);
            if (n < 0) return error.InvalidValue;
            self.global.memory_ceiling_mb = @intCast(n);
        } else if (std.mem.eql(u8, key, "metrics_bind")) {
            self.global.metrics_bind = try asString(v);
        } else if (std.mem.eql(u8, key, "metrics_port")) {
            const n = try asInt(v);
            if (n < 0 or n > 65535) return error.InvalidValue;
            self.global.metrics_port = @intCast(n);
        } else if (std.mem.eql(u8, key, "websocket_max_clients")) {
            const n = try asInt(v);
            if (n <= 0 or n > websocket_hard_max_clients) return error.InvalidValue;
            self.global.websocket_max_clients = @intCast(n);
        } else return error.UnknownKey;
    }

    fn applyDefaultsKey(self: *Parser, key: []const u8) Error!void {
        const v = try self.parseValue();
        if (std.mem.eql(u8, key, "bantime")) {
            const n = try asInt(v);
            if (n < 0) return error.InvalidValue;
            self.defaults.bantime = @intCast(n);
        } else if (std.mem.eql(u8, key, "findtime")) {
            const n = try asInt(v);
            if (n < 0) return error.InvalidValue;
            self.defaults.findtime = @intCast(n);
        } else if (std.mem.eql(u8, key, "maxretry")) {
            const n = try asInt(v);
            if (n < 0) return error.InvalidValue;
            self.defaults.maxretry = @intCast(n);
        } else if (std.mem.eql(u8, key, "banaction")) {
            const s = try asString(v);
            self.defaults.banaction = try parseBanAction(s);
        } else if (std.mem.eql(u8, key, "ignoreip")) {
            self.defaults.ignoreip = try asStringArray(v);
        } else if (std.mem.eql(u8, key, "bantime_increment_enabled")) {
            self.defaults.bantime_increment.enabled = try asBool(v);
        } else if (std.mem.eql(u8, key, "bantime_increment_multiplier")) {
            self.defaults.bantime_increment.multiplier = try asFloat(v);
        } else if (std.mem.eql(u8, key, "bantime_increment_factor")) {
            self.defaults.bantime_increment.factor = try asFloat(v);
        } else if (std.mem.eql(u8, key, "bantime_increment_formula")) {
            const s = try asString(v);
            if (std.mem.eql(u8, s, "linear")) {
                self.defaults.bantime_increment.formula = .linear;
            } else if (std.mem.eql(u8, s, "exponential")) {
                self.defaults.bantime_increment.formula = .exponential;
            } else return error.InvalidValue;
        } else if (std.mem.eql(u8, key, "bantime_increment_max_bantime")) {
            const n = try asInt(v);
            if (n < 0) return error.InvalidValue;
            self.defaults.bantime_increment.max_bantime = @intCast(n);
        } else return error.UnknownKey;
    }

    fn applyJailKey(self: *Parser, jail_name: []const u8, key: []const u8) Error!void {
        const v = try self.parseValue();
        const j = try self.findOrCreateJail(jail_name);

        if (std.mem.eql(u8, key, "enabled")) {
            j.enabled = try asBool(v);
        } else if (std.mem.eql(u8, key, "filter")) {
            j.filter = try asString(v);
        } else if (std.mem.eql(u8, key, "logpath")) {
            j.logpath = try asStringArray(v);
        } else if (std.mem.eql(u8, key, "source")) {
            const s = try asString(v);
            j.source = try parseLogSource(s);
        } else if (std.mem.eql(u8, key, "maxretry")) {
            const n = try asInt(v);
            if (n < 0) return error.InvalidValue;
            j.maxretry = @intCast(n);
        } else if (std.mem.eql(u8, key, "findtime")) {
            const n = try asInt(v);
            if (n < 0) return error.InvalidValue;
            j.findtime = @intCast(n);
        } else if (std.mem.eql(u8, key, "bantime")) {
            const n = try asInt(v);
            if (n < 0) return error.InvalidValue;
            j.bantime = @intCast(n);
        } else if (std.mem.eql(u8, key, "banaction")) {
            const s = try asString(v);
            j.banaction = try parseBanAction(s);
        } else if (std.mem.eql(u8, key, "ignoreip")) {
            j.ignoreip = try asStringArray(v);
        } else if (std.mem.eql(u8, key, "bantime_increment_enabled")) {
            j.bantime_increment.enabled = try asBool(v);
            j.bantime_increment_explicit = true;
        } else if (std.mem.eql(u8, key, "bantime_increment_multiplier")) {
            j.bantime_increment.multiplier = try asFloat(v);
            j.bantime_increment_explicit = true;
        } else if (std.mem.eql(u8, key, "bantime_increment_factor")) {
            j.bantime_increment.factor = try asFloat(v);
            j.bantime_increment_explicit = true;
        } else if (std.mem.eql(u8, key, "bantime_increment_formula")) {
            const s = try asString(v);
            if (std.mem.eql(u8, s, "linear")) {
                j.bantime_increment.formula = .linear;
            } else if (std.mem.eql(u8, s, "exponential")) {
                j.bantime_increment.formula = .exponential;
            } else return error.InvalidValue;
            j.bantime_increment_explicit = true;
        } else if (std.mem.eql(u8, key, "bantime_increment_max_bantime")) {
            const n = try asInt(v);
            if (n < 0) return error.InvalidValue;
            j.bantime_increment.max_bantime = @intCast(n);
            j.bantime_increment_explicit = true;
        } else return error.UnknownKey;
    }

    fn findOrCreateJail(self: *Parser, name: []const u8) Error!*JailConfig {
        for (self.jails.items) |*existing| {
            if (std.mem.eql(u8, existing.name, name)) return existing;
        }
        if (self.jails.items.len >= MAX_JAILS) return error.TooManyJails;
        try self.jails.append(.{ .name = name });
        return &self.jails.items[self.jails.items.len - 1];
    }
};

fn asString(v: Parser.Value) Error![]const u8 {
    return switch (v) {
        .string => |s| s,
        else => error.InvalidValue,
    };
}

fn asInt(v: Parser.Value) Error!i64 {
    return switch (v) {
        .int => |n| n,
        else => error.InvalidValue,
    };
}

fn asFloat(v: Parser.Value) Error!f64 {
    return switch (v) {
        .int => |n| @floatFromInt(n),
        .float => |f| f,
        else => error.InvalidValue,
    };
}

fn asBool(v: Parser.Value) Error!bool {
    return switch (v) {
        .boolean => |b| b,
        else => error.InvalidValue,
    };
}

fn asStringArray(v: Parser.Value) Error![]const []const u8 {
    return switch (v) {
        .str_array => |a| a,
        else => error.InvalidValue,
    };
}

fn parseLogLevel(s: []const u8) Error!LogLevel {
    if (std.mem.eql(u8, s, "debug")) return .debug;
    if (std.mem.eql(u8, s, "info")) return .info;
    if (std.mem.eql(u8, s, "warn")) return .warn;
    if (std.mem.eql(u8, s, "err")) return .err;
    return error.InvalidValue;
}

pub const journalctl_path: []const u8 = "/usr/bin/journalctl";

pub fn anyLogpathExists(logpath: []const []const u8) bool {
    for (logpath) |lp| {
        if (lp.len == 0) continue;
        std.fs.cwd().access(lp, .{ .mode = .read_only }) catch continue;
        return true;
    }
    return false;
}

pub fn filterSupportsJournald(filter: []const u8) bool {
    return std.mem.eql(u8, filter, "sshd");
}

pub fn journalctlPresent() bool {
    std.fs.cwd().access(journalctl_path, .{ .mode = .read_only }) catch return false;
    return true;
}

fn parseBanAction(s: []const u8) Error!BanAction {
    if (std.mem.eql(u8, s, "nftables")) return .nftables;
    if (std.mem.eql(u8, s, "iptables")) return .iptables;
    if (std.mem.eql(u8, s, "ipset")) return .ipset;
    if (std.mem.eql(u8, s, "log-only")) return .@"log-only";
    return error.InvalidValue;
}

fn parseLogSource(s: []const u8) Error!LogSource {
    if (std.mem.eql(u8, s, "auto")) return .auto;
    if (std.mem.eql(u8, s, "file")) return .file;
    if (std.mem.eql(u8, s, "journald")) return .journald;
    return error.InvalidValue;
}

test "native: parse minimal config" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src =
        \\[global]
        \\log_level = "warn"
        \\memory_ceiling_mb = 128
        \\
        \\[defaults]
        \\bantime = 3600
        \\findtime = 600
        \\maxretry = 5
        \\banaction = "nftables"
    ;
    const cfg = try Config.parse(arena.allocator(), src);

    try std.testing.expectEqual(LogLevel.warn, cfg.global.log_level);
    try std.testing.expectEqual(@as(u32, 128), cfg.global.memory_ceiling_mb);
    try std.testing.expectEqual(@as(shared.Duration, 3600), cfg.defaults.bantime);
    try std.testing.expectEqual(BanAction.nftables, cfg.defaults.banaction);
}

test "native: parse defaults retains zero-copy string slices" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src =
        \\[global]
        \\pid_file = "/tmp/pf.pid"
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    const s = cfg.global.pid_file;
    const src_start = @intFromPtr(src.ptr);
    const s_start = @intFromPtr(s.ptr);
    try std.testing.expect(s_start >= src_start);
    try std.testing.expect(s_start + s.len <= src_start + src.len);
    try std.testing.expectEqualStrings("/tmp/pf.pid", s);
}

test "native: parse jails section with overrides" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src =
        \\[defaults]
        \\bantime = 600
        \\findtime = 600
        \\maxretry = 5
        \\
        \\[jails.sshd]
        \\enabled = true
        \\filter = "sshd"
        \\logpath = ["/var/log/auth.log", "/var/log/secure"]
        \\maxretry = 3
        \\
        \\[jails.nginx]
        \\enabled = false
        \\filter = "nginx-http-auth"
        \\logpath = ["/var/log/nginx/error.log"]
    ;
    const cfg = try Config.parse(arena.allocator(), src);

    try std.testing.expectEqual(@as(usize, 2), cfg.jails.len);
    try std.testing.expectEqualStrings("sshd", cfg.jails[0].name);
    try std.testing.expect(cfg.jails[0].enabled);
    try std.testing.expectEqualStrings("sshd", cfg.jails[0].filter);
    try std.testing.expectEqual(@as(usize, 2), cfg.jails[0].logpath.len);
    try std.testing.expectEqualStrings("/var/log/auth.log", cfg.jails[0].logpath[0]);
    try std.testing.expectEqual(@as(?u32, 3), cfg.jails[0].maxretry);

    try std.testing.expectEqualStrings("nginx", cfg.jails[1].name);
    try std.testing.expect(!cfg.jails[1].enabled);

    const eff_find = cfg.jails[0].effectiveFindtime(cfg.defaults);
    try std.testing.expectEqual(@as(shared.Duration, 600), eff_find);
    const eff_mr = cfg.jails[0].effectiveMaxretry(cfg.defaults);
    try std.testing.expectEqual(@as(u32, 3), eff_mr);
}

test "native: jail source defaults to auto when unset" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[jails.sshd]
        \\filter = "sshd"
        \\logpath = ["/var/log/auth.log"]
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    try std.testing.expectEqual(@as(usize, 1), cfg.jails.len);
    try std.testing.expectEqual(LogSource.auto, cfg.jails[0].source);
}

test "native: jail source parses file / journald / auto" {
    const cases = [_]struct { tok: []const u8, want: LogSource }{
        .{ .tok = "file", .want = .file },
        .{ .tok = "journald", .want = .journald },
        .{ .tok = "auto", .want = .auto },
    };
    for (cases) |c| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        var buf: [128]u8 = undefined;
        const src = try std.fmt.bufPrint(
            &buf,
            "[jails.sshd]\nfilter = \"sshd\"\nsource = \"{s}\"\n",
            .{c.tok},
        );
        const cfg = try Config.parse(arena.allocator(), src);
        try std.testing.expectEqual(c.want, cfg.jails[0].source);
    }
}

test "native: jail source rejects an unknown token" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[jails.sshd]
        \\filter = "sshd"
        \\source = "syslog"
    ;
    try std.testing.expectError(error.InvalidValue, Config.parse(arena.allocator(), src));
}

test "native: unknown journalmatch key still trips UnknownKey (v1 has no override)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[jails.sshd]
        \\filter = "sshd"
        \\source = "journald"
        \\journalmatch = "_SYSTEMD_UNIT=ssh.service"
    ;
    try std.testing.expectError(error.UnknownKey, Config.parse(arena.allocator(), src));
}

test "native: anyLogpathExists is existence-based, not configured-based (SYS-015)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "present.log", .data = "x" });

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const present = try tmp.dir.realpathAlloc(arena.allocator(), "present.log");
    const absent = try std.fmt.allocPrint(arena.allocator(), "{s}/nope.log", .{std.fs.path.dirname(present).?});

    try std.testing.expect(!anyLogpathExists(&.{}));
    try std.testing.expect(!anyLogpathExists(&.{""}));
    try std.testing.expect(!anyLogpathExists(&.{absent}));
    try std.testing.expect(!anyLogpathExists(&.{ "", absent }));

    try std.testing.expect(anyLogpathExists(&.{present}));
    try std.testing.expect(anyLogpathExists(&.{ "", absent, present }));
}

test "native: filterSupportsJournald is sshd-only in v1" {
    try std.testing.expect(filterSupportsJournald("sshd"));
    try std.testing.expect(!filterSupportsJournald("nginx-http-auth"));
    try std.testing.expect(!filterSupportsJournald("apache-auth"));
    try std.testing.expect(!filterSupportsJournald(""));
    try std.testing.expect(!filterSupportsJournald("sshd-ddos"));
}

test "native: validate does not fail when a jail resolves to journald" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[global]
        \\memory_ceiling_mb = 32
        \\socket_path = "/tmp/fail2zig-sys015.sock"
        \\[defaults]
        \\bantime = 600
        \\findtime = 600
        \\maxretry = 5
        \\[jails.sshd]
        \\filter = "sshd"
        \\source = "journald"
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    try validate(&cfg);
}

test "native: parse bantime_increment config" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src =
        \\[jails.sshd]
        \\filter = "sshd"
        \\bantime_increment_enabled = true
        \\bantime_increment_multiplier = 2
        \\bantime_increment_formula = "exponential"
        \\bantime_increment_max_bantime = 604800
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    try std.testing.expectEqual(@as(usize, 1), cfg.jails.len);
    const bi = cfg.jails[0].bantime_increment;
    try std.testing.expect(bi.enabled);
    try std.testing.expectEqual(@as(f64, 2.0), bi.multiplier);
    try std.testing.expectEqual(BantimeFormula.exponential, bi.formula);
    try std.testing.expectEqual(@as(shared.Duration, 604800), bi.max_bantime);
}

test "native: bantime_increment accepts fractional factor in defaults" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[defaults]
        \\bantime = 600
        \\findtime = 600
        \\maxretry = 5
        \\bantime_increment_enabled = true
        \\bantime_increment_factor = 1.5
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    try std.testing.expect(cfg.defaults.bantime_increment.enabled);
    try std.testing.expectEqual(@as(f64, 1.5), cfg.defaults.bantime_increment.factor);
}

test "native: bantime_increment accepts fractional multiplier in defaults" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[defaults]
        \\bantime = 600
        \\findtime = 600
        \\maxretry = 5
        \\bantime_increment_enabled = true
        \\bantime_increment_multiplier = 2.5
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    try std.testing.expectEqual(@as(f64, 2.5), cfg.defaults.bantime_increment.multiplier);
}

test "native: bantime_increment accepts fractional factor in per-jail block" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[jails.sshd]
        \\filter = "sshd"
        \\bantime_increment_enabled = true
        \\bantime_increment_factor = 1.75
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    try std.testing.expectEqual(@as(usize, 1), cfg.jails.len);
    try std.testing.expectEqual(@as(f64, 1.75), cfg.jails[0].bantime_increment.factor);
}

test "native: bantime_increment still accepts integer factor/multiplier (regression)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[defaults]
        \\bantime = 600
        \\findtime = 600
        \\maxretry = 5
        \\bantime_increment_enabled = true
        \\bantime_increment_factor = 2
        \\bantime_increment_multiplier = 3
        \\[jails.sshd]
        \\filter = "sshd"
        \\bantime_increment_enabled = true
        \\bantime_increment_factor = 4
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    try std.testing.expectEqual(@as(f64, 2.0), cfg.defaults.bantime_increment.factor);
    try std.testing.expectEqual(@as(f64, 3.0), cfg.defaults.bantime_increment.multiplier);
    try std.testing.expectEqual(@as(usize, 1), cfg.jails.len);
    try std.testing.expectEqual(@as(f64, 4.0), cfg.jails[0].bantime_increment.factor);
}

test "native: parse rejects unclosed string" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src = "[global]\nlog_level = \"info\n";
    try std.testing.expectError(error.UnterminatedString, Config.parse(arena.allocator(), src));
}

test "native: parse rejects invalid integer" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src = "[defaults]\nbantime = not-a-number\n";
    try std.testing.expectError(error.UnexpectedToken, Config.parse(arena.allocator(), src));
}

test "native: parse rejects unknown section" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src = "[unknown]\nfoo = 1\n";
    try std.testing.expectError(error.UnknownSection, Config.parse(arena.allocator(), src));
}

test "native: parse rejects unknown key" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src = "[global]\nbogus_key = 1\n";
    try std.testing.expectError(error.UnknownKey, Config.parse(arena.allocator(), src));
}

test "native: parse tolerates comments and blank lines" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src =
        \\# header
        \\
        \\[global] # section comment
        \\log_level = "debug" # trailing
        \\memory_ceiling_mb = 64
        \\
        \\# between sections
        \\[defaults]
        \\bantime = 600 # seconds
        \\findtime = 600
        \\maxretry = 5
        \\banaction = "iptables"
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    try std.testing.expectEqual(LogLevel.debug, cfg.global.log_level);
    try std.testing.expectEqual(BanAction.iptables, cfg.defaults.banaction);
}

test "native: parse string escapes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src =
        \\[global]
        \\state_file = "/var/\"lib\"/fail2zig.bin"
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    try std.testing.expectEqualStrings("/var/\"lib\"/fail2zig.bin", cfg.global.state_file);
}

test "native: validate rejects memory ceiling below floor" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src =
        \\[global]
        \\memory_ceiling_mb = 8
        \\[defaults]
        \\bantime = 600
        \\findtime = 600
        \\maxretry = 5
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    try std.testing.expectError(error.MemoryCeilingTooLow, validate(&cfg));
}

test "native: validate rejects bantime=0" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src =
        \\[defaults]
        \\bantime = 0
        \\findtime = 600
        \\maxretry = 5
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    try std.testing.expectError(error.InvalidBantime, validate(&cfg));
}

test "native: validate rejects duplicate jail names" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src =
        \\[global]
        \\memory_ceiling_mb = 32
        \\socket_path = "/tmp/fail2zig-test-validate.sock"
        \\[defaults]
        \\bantime = 600
        \\findtime = 600
        \\maxretry = 5
        \\[jails.sshd]
        \\filter = "sshd"
    ;
    var cfg = try Config.parse(arena.allocator(), src);

    var jails_buf = try arena.allocator().alloc(JailConfig, 2);
    jails_buf[0] = cfg.jails[0];
    jails_buf[1] = .{ .name = "sshd", .filter = "sshd" };
    cfg.jails = jails_buf;
    try std.testing.expectError(error.DuplicateJailName, validate(&cfg));
}

test "native: validate warns on missing socket dir, does not fail" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src =
        \\[global]
        \\memory_ceiling_mb = 32
        \\socket_path = "/definitely-does-not-exist-xyz/sock"
        \\[defaults]
        \\bantime = 600
        \\findtime = 600
        \\maxretry = 5
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    try validate(&cfg);
}

test "native: validate accepts healthy config" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src =
        \\[global]
        \\memory_ceiling_mb = 32
        \\socket_path = "/tmp/fail2zig.sock"
        \\[defaults]
        \\bantime = 600
        \\findtime = 600
        \\maxretry = 5
        \\[jails.sshd]
        \\filter = "sshd"
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    try validate(&cfg);
}

test "native: load file not found" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(
        error.FileNotFound,
        Config.loadFile(arena.allocator(), "/nonexistent/fail2zig.toml"),
    );
}

test "native: loadFile parses a tmp file" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const contents =
        \\[global]
        \\memory_ceiling_mb = 32
    ;
    try tmp.dir.writeFile(.{ .sub_path = "cfg.toml", .data = contents });

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const real = try tmp.dir.realpathAlloc(arena.allocator(), "cfg.toml");
    const cfg = try Config.loadFile(arena.allocator(), real);
    try std.testing.expectEqual(@as(u32, 32), cfg.global.memory_ceiling_mb);
}

test "native: parse a full example with all options" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src =
        \\[global]
        \\log_level = "info"
        \\pid_file = "/run/fail2zig.pid"
        \\socket_path = "/tmp/fail2zig.sock"
        \\state_file = "/var/lib/fail2zig/state.bin"
        \\memory_ceiling_mb = 64
        \\
        \\[defaults]
        \\bantime = 600
        \\findtime = 600
        \\maxretry = 5
        \\banaction = "nftables"
        \\ignoreip = ["127.0.0.1", "10.0.0.0/8"]
        \\
        \\[jails.sshd]
        \\enabled = true
        \\filter = "sshd"
        \\logpath = ["/var/log/auth.log"]
        \\maxretry = 3
        \\bantime = 3600
        \\bantime_increment_enabled = true
        \\bantime_increment_formula = "exponential"
        \\bantime_increment_max_bantime = 604800
        \\
        \\[jails.nginx-http-auth]
        \\enabled = true
        \\filter = "nginx-http-auth"
        \\logpath = ["/var/log/nginx/error.log"]
        \\ignoreip = ["192.168.0.0/16"]
    ;

    const cfg = try Config.parse(arena.allocator(), src);
    try std.testing.expectEqual(@as(usize, 2), cfg.jails.len);
    try std.testing.expectEqual(@as(usize, 2), cfg.defaults.ignoreip.len);
    try std.testing.expectEqualStrings("127.0.0.1", cfg.defaults.ignoreip[0]);
    try std.testing.expectEqual(@as(shared.Duration, 3600), cfg.jails[0].bantime.?);
    try std.testing.expect(cfg.jails[0].bantime_increment.enabled);
    try std.testing.expectEqualStrings("nginx-http-auth", cfg.jails[1].name);
    try std.testing.expectEqual(@as(usize, 1), cfg.jails[1].ignoreip.?.len);
}

test "native: websocket_max_clients default is 16" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[global]
        \\memory_ceiling_mb = 32
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    try std.testing.expectEqual(@as(u32, 16), cfg.global.websocket_max_clients);
}

test "native: websocket_max_clients accepts 16, 128, and hard cap" {
    const cases = [_]u32{ 16, 128, websocket_hard_max_clients };
    for (cases) |v| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var buf: [128]u8 = undefined;
        const src = try std.fmt.bufPrint(
            &buf,
            "[global]\nwebsocket_max_clients = {d}\n",
            .{v},
        );
        const cfg = try Config.parse(arena.allocator(), src);
        try std.testing.expectEqual(v, cfg.global.websocket_max_clients);
    }
}

test "native: websocket_max_clients rejects 0" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[global]
        \\websocket_max_clients = 0
    ;
    try std.testing.expectError(error.InvalidValue, Config.parse(arena.allocator(), src));
}

test "native: resolveJail returns null for unknown jail" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[defaults]
        \\bantime = 600
        \\findtime = 600
        \\maxretry = 5
        \\[jails.sshd]
        \\filter = "sshd"
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    try std.testing.expect(resolveJail(&cfg, "nope") == null);
}

test "native: resolveJail uses per-jail values when set" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[defaults]
        \\bantime = 600
        \\findtime = 600
        \\maxretry = 5
        \\[jails.aggressive]
        \\filter = "sshd"
        \\maxretry = 1
        \\findtime = 10
        \\bantime = 30
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    const r = resolveJail(&cfg, "aggressive").?;
    try std.testing.expectEqual(@as(u32, 1), r.maxretry);
    try std.testing.expectEqual(@as(shared.Duration, 10), r.findtime);
    try std.testing.expectEqual(@as(shared.Duration, 30), r.bantime);
}

test "native: resolveJail falls back to defaults for unset fields" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[defaults]
        \\bantime = 1800
        \\findtime = 900
        \\maxretry = 7
        \\[jails.sshd]
        \\filter = "sshd"
        \\maxretry = 2
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    const r = resolveJail(&cfg, "sshd").?;
    try std.testing.expectEqual(@as(u32, 2), r.maxretry);
    try std.testing.expectEqual(@as(shared.Duration, 900), r.findtime);
    try std.testing.expectEqual(@as(shared.Duration, 1800), r.bantime);
}

test "native: resolveJail inherits defaults bantime_increment when jail is silent" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[defaults]
        \\bantime = 600
        \\findtime = 600
        \\maxretry = 5
        \\bantime_increment_enabled = true
        \\bantime_increment_factor = 3
        \\bantime_increment_formula = "exponential"
        \\bantime_increment_max_bantime = 86400
        \\[jails.sshd]
        \\filter = "sshd"
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    const r = resolveJail(&cfg, "sshd").?;
    try std.testing.expect(r.bantime_increment.enabled);
    try std.testing.expectEqual(@as(f64, 3.0), r.bantime_increment.factor);
    try std.testing.expectEqual(BantimeFormula.exponential, r.bantime_increment.formula);
}

test "native: resolveJail takes per-jail bantime_increment when present" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\[defaults]
        \\bantime = 600
        \\findtime = 600
        \\maxretry = 5
        \\bantime_increment_enabled = true
        \\bantime_increment_factor = 2
        \\[jails.sshd]
        \\filter = "sshd"
        \\bantime_increment_enabled = true
        \\bantime_increment_factor = 5
    ;
    const cfg = try Config.parse(arena.allocator(), src);
    const r = resolveJail(&cfg, "sshd").?;
    try std.testing.expect(r.bantime_increment.enabled);
    try std.testing.expectEqual(@as(f64, 5.0), r.bantime_increment.factor);
}

test "native: websocket_max_clients rejects values above hard cap" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    const src = try std.fmt.bufPrint(
        &buf,
        "[global]\nwebsocket_max_clients = {d}\n",
        .{websocket_hard_max_clients + 1},
    );
    try std.testing.expectError(error.InvalidValue, Config.parse(arena.allocator(), src));
}

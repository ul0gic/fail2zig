// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Parses the native configuration file into typed global, default and jail settings.
// Holds: An unknown section or key, a repeated key, or a value of the wrong type fails the parse with its line; none is ignored.

const std = @import("std");
const shared = @import("shared");
const native_duration = @import("duration.zig");
const Error = @import("config.zig").Error;
const Diagnostic = @import("config.zig").Diagnostic;
const Config = @import("config.zig").Config;
const GlobalConfig = @import("config.zig").GlobalConfig;
const JailDefaults = @import("config.zig").JailDefaults;
const JailConfig = @import("config.zig").JailConfig;
const LogLevel = @import("config.zig").LogLevel;
const LogFormat = @import("config.zig").LogFormat;
const LogSource = @import("config.zig").LogSource;
const BanAction = @import("config.zig").BanAction;
const TruncationPolicy = @import("config.zig").TruncationPolicy;
const FirewallSelection = @import("config.zig").FirewallSelection;
const OnNoBackend = @import("config.zig").OnNoBackend;
const max_config_bytes = @import("config.zig").max_config_bytes;
const max_configured_jails = @import("config.zig").max_configured_jails;
const max_ban_duration = @import("config.zig").max_ban_duration;
const max_supported_retry = @import("config.zig").max_supported_retry;
const mapBackendAlias = @import("config.zig").mapBackendAlias;
const anyLogpathExists = @import("config.zig").anyLogpathExists;
const filterSupportsJournald = @import("config.zig").filterSupportsJournald;
const journalctlPresent = @import("config.zig").journalctlPresent;

pub const Parser = struct {
    arena: std.mem.Allocator,
    src: []const u8,
    pos: usize,
    line: u32,
    col: u32,

    global: GlobalConfig,
    defaults: JailDefaults,
    jails: std.ArrayList(JailConfig),
    seen_keys: std.StringHashMap(void),
    jail_source_origin: std.ArrayList(SourceOrigin),
    jail_truncation_key: std.ArrayList(?TruncationKey),
    defaults_source_origin: SourceOrigin = .unset,
    legacy_banaction_used: bool = false,

    cur_section: []const u8 = "",
    cur_key: []const u8 = "",
    hint: []const u8 = "",
    section_pos: Pos = .{},
    key_pos: Pos = .{},
    value_pos: Pos = .{},

    const Pos = struct { line: u32 = 1, col: u32 = 1 };
    const TruncationKey = struct { pos: Pos, section: []const u8 };
    const SourceOrigin = enum { unset, source, backend };

    const TOP_GLOBAL: []const u8 = "global";
    const TOP_DEFAULTS: []const u8 = "defaults";
    const TOP_JAILS: []const u8 = "jails";
    const MAX_JAILS: usize = max_configured_jails;

    pub fn init(arena: std.mem.Allocator, src: []const u8) Parser {
        return .{
            .arena = arena,
            .src = src,
            .pos = 0,
            .line = 1,
            .col = 1,
            .global = .{},
            .defaults = .{},
            .jails = std.ArrayList(JailConfig).init(arena),
            .seen_keys = std.StringHashMap(void).init(arena),
            .jail_source_origin = std.ArrayList(SourceOrigin).init(arena),
            .jail_truncation_key = std.ArrayList(?TruncationKey).init(arena),
        };
    }

    fn here(self: *const Parser) Pos {
        return .{ .line = self.line, .col = self.col };
    }

    fn fillDiag(self: *const Parser, err: Error, out: *Diagnostic) void {
        const pos: Pos = switch (err) {
            error.UnknownSection => self.section_pos,
            error.UnknownKey,
            error.DuplicateKey,
            error.TooManyJails,
            error.TruncationPolicyNotFileSource,
            error.TruncationPolicyNotAllowedInDefaults,
            => self.key_pos,
            error.InvalidValue,
            error.InvalidTruncationPolicy,
            error.InvalidInteger,
            error.InvalidFloat,
            error.InvalidBool,
            error.InvalidArray,
            error.UnterminatedString,
            error.InvalidEscape,
            => self.value_pos,
            else => self.here(),
        };
        out.line = pos.line;
        out.col = pos.col;
        out.hint = self.hint;
        out.key_len = Diagnostic.copyName(&out.key_buf, self.cur_key);
        out.section_len = Diagnostic.copyName(&out.section_buf, self.cur_section);
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

    pub fn parseConfig(self: *Parser, out: *Diagnostic) Error!Config {
        return self.parseBody() catch |err| {
            self.fillDiag(err, out);
            return err;
        };
    }

    fn parseBody(self: *Parser) Error!Config {
        while (true) {
            self.skipBlankAndComments();
            if (self.eof()) break;

            if (self.peek() == '[') {
                self.cur_section = "";
                self.cur_key = "";
                self.section_pos = self.here();
                self.cur_section = try self.parseSectionHeader();
                try self.expectEndOfLine();
                continue;
            }

            self.key_pos = self.here();
            self.cur_key = try self.parseBareKey();
            try self.noteKeySeen(self.cur_section, self.cur_key);
            self.skipSpaceTabs();
            if (self.eof() or self.peek() != '=') return error.UnexpectedToken;
            self.advance();
            self.skipSpaceTabs();
            self.value_pos = self.here();

            try self.dispatchKeyValue(self.cur_section, self.cur_key);
            try self.expectEndOfLine();
        }

        // Why: [defaults] may follow a jail section, so source inheritance and the truncation check wait until the whole file is read.
        for (self.jails.items, self.jail_source_origin.items) |*j, origin| {
            if (origin == .unset) j.source = self.defaults.source;
        }
        for (self.jails.items, self.jail_truncation_key.items) |*j, maybe_key| {
            const key = maybe_key orelse continue;
            const hint: []const u8 = switch (resolvedSource(j)) {
                .file => continue,
                .journald => truncation_not_file_hint ++ "journald",
                .internal => truncation_not_file_hint ++ "internal",
            };
            self.cur_key = "on_truncation";
            self.cur_section = key.section;
            self.key_pos = key.pos;
            self.hint = hint;
            return error.TruncationPolicyNotFileSource;
        }

        return .{
            .global = self.global,
            .defaults = self.defaults,
            .jails = try self.jails.toOwnedSlice(),
            .diag = .{ .line = self.line, .col = self.col },
            .legacy_banaction_used = self.legacy_banaction_used,
        };
    }

    fn noteKeySeen(self: *Parser, section: []const u8, key: []const u8) Error!void {
        const composite = try std.fmt.allocPrint(self.arena, "{s}\x00{s}", .{ section, key });
        const gop = self.seen_keys.getOrPut(composite) catch return error.OutOfMemory;
        if (gop.found_existing) return error.DuplicateKey;
    }

    fn policySpelling(self: *Parser, key: []const u8) Error!void {
        const alias = if (std.mem.eql(u8, key, "enforce")) "banaction" else "enforce";
        const composite = try std.fmt.allocPrint(self.arena, "{s}\x00{s}", .{ self.cur_section, alias });
        if (self.seen_keys.contains(composite)) {
            self.hint = "enforce and banaction conflict in the same section; global.firewall selects the backend";
            return error.InvalidValue;
        }
        if (std.mem.eql(u8, key, "banaction")) self.legacy_banaction_used = true;
    }

    fn parseSectionHeader(self: *Parser) Error![]const u8 {
        if (self.peek() != '[') return error.UnexpectedToken;
        self.advance();
        self.skipSpaceTabs();
        const jails_prefix = "jails.";
        const rest = self.src[self.pos..];
        if (rest.len > jails_prefix.len and std.mem.startsWith(u8, rest, jails_prefix) and
            (rest[jails_prefix.len] == '"' or rest[jails_prefix.len] == '\''))
        {
            for (0..jails_prefix.len) |_| self.advance();
            const jail_name = try self.parseQuotedJailName();
            self.skipSpaceTabs();
            if (self.eof() or self.peek() != ']') return error.UnexpectedToken;
            self.advance();
            return try std.fmt.allocPrint(self.arena, jails_prefix ++ "{s}", .{jail_name});
        }
        const start = self.pos;
        while (!self.eof() and self.peek() != ']' and self.peek() != '\n') self.advance();
        if (self.eof() or self.peek() != ']') return error.UnexpectedToken;
        const name = self.src[start..self.pos];
        self.advance();
        const trimmed = std.mem.trim(u8, name, " \t");
        if (trimmed.len == 0) return error.UnexpectedToken;
        return trimmed;
    }

    fn parseQuotedJailName(self: *Parser) Error![]const u8 {
        self.value_pos = self.here();
        const quote = self.peek();
        self.advance();
        const start = self.pos;
        while (true) {
            if (self.eof() or self.peek() == '\n') return error.UnterminatedString;
            const c = self.peek();
            if (c == quote) break;
            if (c == '\\' and quote == '"') {
                self.hint = "escape sequences are not supported in a quoted jail name; use a literal-quoted name";
                return error.InvalidEscape;
            }
            self.advance();
        }
        const name = self.src[start..self.pos];
        self.advance();
        return name;
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
        if (std.mem.eql(u8, key, "firewall_namespace")) {
            const path = try asString(v);
            if (!std.fs.path.isAbsolute(path) or path.len > 256 or std.mem.indexOfScalar(u8, path, 0) != null or
                std.mem.indexOf(u8, path, "/self/") != null or std.mem.indexOf(u8, path, "/thread-self/") != null) return error.InvalidValue;
            self.global.firewall_namespace = path;
        } else if (std.mem.eql(u8, key, "timezone_root")) {
            const path = try asString(v);
            if (!std.fs.path.isAbsolute(path) or path.len > 4096 or std.mem.indexOfScalar(u8, path, 0) != null) return error.InvalidValue;
            self.global.timezone_root = path;
        } else if (std.mem.eql(u8, key, "native_ingestion")) {
            self.global.native_ingestion = try asBool(v);
        } else if (std.mem.eql(u8, key, "compatibility_manifest")) {
            const manifest = try asString(v);
            _ = try decodeCompatibilityManifest(self.arena, manifest);
            self.global.compatibility_manifest = manifest;
        } else if (std.mem.eql(u8, key, "compatibility_pending")) {
            self.global.compatibility_pending = try asBool(v);
        } else if (std.mem.eql(u8, key, "log_level")) {
            const s = try asString(v);
            self.global.log_level = try parseLogLevel(s);
        } else if (std.mem.eql(u8, key, "log_format")) {
            self.global.log_format = std.meta.stringToEnum(LogFormat, try asString(v)) orelse {
                self.hint = "expected text or json";
                return error.InvalidValue;
            };
        } else if (std.mem.eql(u8, key, "log_target")) {
            const s = try asString(v);
            if (!std.mem.eql(u8, s, "stderr") and (!std.fs.path.isAbsolute(s) or s.len >= std.fs.max_path_bytes or std.mem.indexOfScalar(u8, s, 0) != null)) return error.InvalidValue;
            self.global.log_target = s;
        } else if (std.mem.eql(u8, key, "pid_file")) {
            self.global.pid_file = try asString(v);
            std.log.warn("config: pid_file is a deprecated compatibility key and is not written; use systemd MainPID", .{});
        } else if (std.mem.eql(u8, key, "socket_path")) {
            self.global.socket_path = try asString(v);
        } else if (std.mem.eql(u8, key, "state_file")) {
            self.global.state_file = try asString(v);
        } else if (std.mem.eql(u8, key, "memory_ceiling_mb")) {
            const n = try asInt(v);
            if (n < 0 or n > std.math.maxInt(u32)) return error.InvalidValue;
            self.global.memory_ceiling_mb = @intCast(n);
        } else if (std.mem.eql(u8, key, "native_memory_ceiling_mb")) {
            const n = try asInt(v);
            if (n <= 0 or n > std.math.maxInt(u32)) return error.InvalidValue;
            self.global.native_memory_ceiling_mb = @intCast(n);
        } else if (std.mem.eql(u8, key, "native_fd_ceiling")) {
            const n = try asInt(v);
            if (n <= 0 or n > std.math.maxInt(u32)) return error.InvalidValue;
            self.global.native_fd_ceiling = @intCast(n);
        } else if (std.mem.eql(u8, key, "metrics_enabled")) {
            self.global.metrics_enabled = try asBool(v);
        } else if (std.mem.eql(u8, key, "metrics_bind")) {
            self.global.metrics_bind = try asString(v);
        } else if (std.mem.eql(u8, key, "metrics_port")) {
            const n = try asInt(v);
            if (n == 0) {
                self.hint = metrics_port_zero_hint;
                return error.InvalidValue;
            }
            if (n < 0 or n > 65535) return error.InvalidValue;
            self.global.metrics_port = @intCast(n);
        } else if (std.mem.eql(u8, key, "websocket_max_clients")) {
            _ = try asInt(v);
            std.log.warn("config: websocket_max_clients is a deprecated compatibility key with no effect; remove it", .{});
        } else if (std.mem.eql(u8, key, "history_retention")) {
            const n = try asInt(v);
            // Why: History pruning multiplies retention into i64 microseconds, so a larger value would overflow there.
            if (n < 0 or n > @divTrunc(std.math.maxInt(i64), 1_000_000)) return error.InvalidValue;
            self.global.history_retention = @intCast(n);
        } else if (std.mem.eql(u8, key, "history_max_matches")) {
            const n = try asInt(v);
            if (n < 0 or n > 1024) return error.InvalidValue;
            self.global.history_max_matches = @intCast(n);
        } else if (std.mem.eql(u8, key, "on_no_backend")) {
            const s = try asString(v);
            self.global.on_no_backend = try parseOnNoBackend(s);
        } else if (std.mem.eql(u8, key, "firewall")) {
            const s = try asString(v);
            self.global.firewall = try parseFirewallSelection(s);
        } else if (std.mem.eql(u8, key, "dns_server")) {
            self.global.dns_server = try asString(v);
        } else if (std.mem.eql(u8, key, "dns_port")) {
            const n = try asInt(v);
            if (n <= 0 or n > 65535) return error.InvalidValue;
            self.global.dns_port = @intCast(n);
        } else return error.UnknownKey;
    }

    fn applyDefaultsKey(self: *Parser, key: []const u8) Error!void {
        const v = try self.parseValue();
        if (std.mem.eql(u8, key, "bantime")) {
            if (v == .string and std.mem.eql(u8, v.string, "permanent")) {
                self.defaults.bantime_kind = .permanent;
            } else {
                self.defaults.bantime = try asDuration(v, max_ban_duration);
                self.defaults.bantime_kind = .finite;
            }
        } else if (std.mem.eql(u8, key, "findtime")) {
            self.defaults.findtime = try asDuration(v, std.math.maxInt(i64));
        } else if (std.mem.eql(u8, key, "maxretry")) {
            const n = try asInt(v);
            if (n < 0 or n > max_supported_retry) {
                self.hint = "maxretry must be between 1 and 128 (bounded attempt history)";
                return error.InvalidValue;
            }
            self.defaults.maxretry = @intCast(n);
        } else if (std.mem.eql(u8, key, "enforce")) {
            try self.policySpelling(key);
            self.defaults.banaction = if (try asBool(v)) .nftables else .@"log-only";
        } else if (std.mem.eql(u8, key, "banaction")) {
            try self.policySpelling(key);
            const s = try asString(v);
            self.defaults.banaction = try parseBanAction(s);
        } else if (std.mem.eql(u8, key, "on_truncation")) {
            self.hint = "set on_truncation in each file jail that needs it";
            return error.TruncationPolicyNotAllowedInDefaults;
        } else if (std.mem.eql(u8, key, "ignoreip")) {
            self.defaults.ignoreip = try asStringArray(v);
        } else if (std.mem.eql(u8, key, "banip")) {
            self.defaults.banip = try asStringArray(v);
        } else if (std.mem.eql(u8, key, "ignoreself")) {
            self.defaults.ignoreself = try asBool(v);
        } else if (std.mem.eql(u8, key, "bantime_increment_decay")) {
            self.defaults.bantime_increment_decay = try self.hintedDuration(v);
        } else if (std.mem.eql(u8, key, "ignoretime")) {
            self.defaults.ignoretime = try self.hintedDuration(v);
        } else if (std.mem.eql(u8, key, "source")) {
            if (self.defaults_source_origin == .backend) return error.InvalidValue;
            self.defaults.source = try parseLogSource(try asString(v));
            self.defaults_source_origin = .source;
        } else if (std.mem.eql(u8, key, "backend")) {
            if (self.defaults_source_origin == .source) return error.InvalidValue;
            self.defaults.source = try backendAlias(self.cur_section, try asString(v));
            self.defaults_source_origin = .backend;
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
        } else if (std.mem.eql(u8, key, "bantime_increment_scope")) {
            const s = try asString(v);
            if (std.mem.eql(u8, s, "per-jail")) {
                self.defaults.bantime_increment.scope = .per_jail;
            } else if (std.mem.eql(u8, s, "overall")) {
                self.defaults.bantime_increment.scope = .overall;
            } else return error.InvalidValue;
        } else if (std.mem.eql(u8, key, "bantime_increment_max_bantime")) {
            self.defaults.bantime_increment.max_bantime = try asDuration(v, max_ban_duration);
        } else if (std.mem.eql(u8, key, "bantime_increment_jitter")) {
            self.defaults.bantime_increment.jitter = try asDuration(v, max_ban_duration);
        } else return error.UnknownKey;
    }

    fn applyJailKey(self: *Parser, jail_name: []const u8, key: []const u8) Error!void {
        const v = try self.parseValue();
        const idx = try self.findOrCreateJail(jail_name);
        const j = &self.jails.items[idx];
        const origin = &self.jail_source_origin.items[idx];

        if (std.mem.eql(u8, key, "timestamp")) {
            j.timestamp = std.meta.stringToEnum(@typeInfo(@TypeOf(j.timestamp)).optional.child, try asString(v)) orelse return error.InvalidValue;
        } else if (std.mem.eql(u8, key, "timezone_offset_minutes")) {
            const n = try asInt(v);
            if (n < -1439 or n > 1439) return error.InvalidValue;
            j.timezone_offset_minutes = @intCast(n);
        } else if (std.mem.eql(u8, key, "timezone")) {
            const identifier = try asString(v);
            @import("../time/timezone.zig").validateIdentifier(identifier) catch return error.InvalidValue;
            j.timezone = identifier;
        } else if (std.mem.eql(u8, key, "timezone_ambiguity")) {
            j.timezone_ambiguity = std.meta.stringToEnum(@import("../time/timezone.zig").Ambiguity, try asString(v)) orelse return error.InvalidValue;
        } else if (std.mem.eql(u8, key, "journal_executables")) {
            j.journal_executables = try asStringArray(v);
            j.journal_executables_explicit = true;
        } else if (std.mem.eql(u8, key, "rule_files")) {
            j.rule_files = try asStringArray(v);
        } else if (std.mem.eql(u8, key, "ignore_file")) {
            j.ignore_file = try asString(v);
        } else if (std.mem.eql(u8, key, "compatibility_pending")) {
            j.compatibility_pending = try asBool(v);
        } else if (std.mem.eql(u8, key, "enabled")) {
            j.enabled = try asBool(v);
        } else if (std.mem.eql(u8, key, "history_max_matches")) {
            const n = try asInt(v);
            if (n < 0 or n > 1024) return error.InvalidValue;
            j.history_max_matches = @intCast(n);
        } else if (std.mem.eql(u8, key, "filter")) {
            j.filter = try asString(v);
        } else if (std.mem.eql(u8, key, "logpath")) {
            j.logpath = try asStringArray(v);
        } else if (std.mem.eql(u8, key, "source")) {
            if (origin.* == .backend) return error.InvalidValue;
            j.source = try parseLogSource(try asString(v));
            origin.* = .source;
        } else if (std.mem.eql(u8, key, "backend")) {
            if (origin.* == .source) return error.InvalidValue;
            j.source = try backendAlias(self.cur_section, try asString(v));
            origin.* = .backend;
        } else if (std.mem.eql(u8, key, "maxretry")) {
            const n = try asInt(v);
            if (n < 0 or n > max_supported_retry) {
                self.hint = "maxretry must be between 1 and 128 (bounded attempt history)";
                return error.InvalidValue;
            }
            j.maxretry = @intCast(n);
        } else if (std.mem.eql(u8, key, "findtime")) {
            j.findtime = try asDuration(v, std.math.maxInt(i64));
        } else if (std.mem.eql(u8, key, "bantime")) {
            if (v == .string and std.mem.eql(u8, v.string, "permanent")) {
                j.bantime = null;
                j.bantime_kind = .permanent;
            } else {
                j.bantime = try asDuration(v, max_ban_duration);
                j.bantime_kind = .finite;
            }
        } else if (std.mem.eql(u8, key, "enforce")) {
            try self.policySpelling(key);
            j.banaction = if (try asBool(v)) .nftables else .@"log-only";
        } else if (std.mem.eql(u8, key, "banaction")) {
            try self.policySpelling(key);
            const s = try asString(v);
            j.banaction = try parseBanAction(s);
        } else if (std.mem.eql(u8, key, "on_truncation")) {
            j.on_truncation = try self.parseTruncationPolicy(v);
            self.jail_truncation_key.items[idx] = .{ .pos = self.key_pos, .section = self.cur_section };
        } else if (std.mem.eql(u8, key, "ignoreip")) {
            j.ignoreip = try asStringArray(v);
        } else if (std.mem.eql(u8, key, "banip")) {
            j.banip = try asStringArray(v);
        } else if (std.mem.eql(u8, key, "ignoreself")) {
            j.ignoreself = try asBool(v);
        } else if (std.mem.eql(u8, key, "bantime_increment_decay")) {
            j.bantime_increment_decay = try self.hintedDuration(v);
        } else if (std.mem.eql(u8, key, "ignoretime")) {
            j.ignoretime = try self.hintedDuration(v);
        } else if (std.mem.eql(u8, key, "bantime_increment_enabled")) {
            j.bantime_increment.enabled = try asBool(v);
            j.bantime_increment_explicit = true;
            j.bantime_increment_fields |= 1;
        } else if (std.mem.eql(u8, key, "bantime_increment_multiplier")) {
            j.bantime_increment.multiplier = try asFloat(v);
            j.bantime_increment_explicit = true;
            j.bantime_increment_fields |= 2;
        } else if (std.mem.eql(u8, key, "bantime_increment_factor")) {
            j.bantime_increment.factor = try asFloat(v);
            j.bantime_increment_explicit = true;
            j.bantime_increment_fields |= 4;
        } else if (std.mem.eql(u8, key, "bantime_increment_formula")) {
            const s = try asString(v);
            if (std.mem.eql(u8, s, "linear")) {
                j.bantime_increment.formula = .linear;
            } else if (std.mem.eql(u8, s, "exponential")) {
                j.bantime_increment.formula = .exponential;
            } else return error.InvalidValue;
            j.bantime_increment_explicit = true;
            j.bantime_increment_fields |= 8;
        } else if (std.mem.eql(u8, key, "bantime_increment_scope")) {
            const s = try asString(v);
            if (std.mem.eql(u8, s, "per-jail")) {
                j.bantime_increment.scope = .per_jail;
            } else if (std.mem.eql(u8, s, "overall")) {
                j.bantime_increment.scope = .overall;
            } else return error.InvalidValue;
            j.bantime_increment_explicit = true;
            j.bantime_increment_fields |= 32;
        } else if (std.mem.eql(u8, key, "bantime_increment_max_bantime")) {
            j.bantime_increment.max_bantime = try asDuration(v, max_ban_duration);
            j.bantime_increment_explicit = true;
            j.bantime_increment_fields |= 16;
        } else if (std.mem.eql(u8, key, "bantime_increment_jitter")) {
            j.bantime_increment.jitter = try asDuration(v, max_ban_duration);
            j.bantime_increment_explicit = true;
            j.bantime_increment_fields |= 64;
        } else return error.UnknownKey;
    }

    fn hintedDuration(self: *Parser, v: Value) Error!shared.Duration {
        return asDuration(v, max_ban_duration) catch |failure| {
            self.hint = "invalid duration";
            return failure;
        };
    }

    fn findOrCreateJail(self: *Parser, name: []const u8) Error!usize {
        for (self.jails.items, 0..) |existing, i| {
            if (std.mem.eql(u8, existing.name, name)) return i;
        }
        if (self.jails.items.len >= MAX_JAILS) return error.TooManyJails;
        try self.jails.append(.{ .name = name });
        errdefer _ = self.jails.pop();
        try self.jail_source_origin.append(.unset);
        try self.jail_truncation_key.append(null);
        return self.jails.items.len - 1;
    }

    fn parseTruncationPolicy(self: *Parser, v: Value) Error!TruncationPolicy {
        if (v == .string) if (std.meta.stringToEnum(TruncationPolicy, v.string)) |policy| return policy;
        self.hint = "accepted values: \"refuse\", \"restart\"";
        return error.InvalidTruncationPolicy;
    }
};

fn backendAlias(section: []const u8, s: []const u8) Error!LogSource {
    const mapped = mapBackendAlias(s) orelse return error.InvalidValue;
    std.log.warn(
        "config: [{s}] 'backend' is a deprecated fail2ban compatibility alias; use source = \"{s}\"",
        .{ section, @tagName(mapped) },
    );
    return mapped;
}

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

fn asDuration(v: Parser.Value, maximum: u64) Error!shared.Duration {
    const seconds: u64 = switch (v) {
        .int => |n| if (n >= 0) @intCast(n) else return error.InvalidValue,
        .string => |s| try native_duration.parse(s),
        else => return error.InvalidValue,
    };
    if (seconds > maximum) return error.InvalidValue;
    return seconds;
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

const truncation_not_file_hint = "on_truncation applies only to a jail whose source is file; this jail's source is ";

fn resolvedSource(j: *const JailConfig) enum { file, journald, internal } {
    return switch (j.source) {
        .auto => if (!anyLogpathExists(j.logpath) and filterSupportsJournald(j.filter) and journalctlPresent()) .journald else .file,
        .file => .file,
        .journald => .journald,
        .internal => .internal,
    };
}

fn parseBanAction(s: []const u8) Error!BanAction {
    if (std.mem.eql(u8, s, "nftables")) return .nftables;
    if (std.mem.eql(u8, s, "iptables")) return .iptables;
    if (std.mem.eql(u8, s, "ipset")) return .ipset;
    if (std.mem.eql(u8, s, "log-only")) return .@"log-only";
    return error.InvalidValue;
}

pub const metrics_port_zero_hint: []const u8 = "metrics_port = 0 does not disable the endpoint; set metrics_enabled = false";

fn parseFirewallSelection(s: []const u8) Error!FirewallSelection {
    if (std.mem.eql(u8, s, "auto")) return .auto;
    if (std.mem.eql(u8, s, "nftables")) return .nftables;
    if (std.mem.eql(u8, s, "ipset")) return .ipset;
    if (std.mem.eql(u8, s, "iptables")) return .iptables;
    return error.InvalidValue;
}

fn parseOnNoBackend(s: []const u8) Error!OnNoBackend {
    if (std.mem.eql(u8, s, "fail-closed")) return .@"fail-closed";
    if (std.mem.eql(u8, s, "log-only")) return .@"log-only";
    return error.InvalidValue;
}

fn parseLogSource(s: []const u8) Error!LogSource {
    if (std.mem.eql(u8, s, "auto")) return .auto;
    if (std.mem.eql(u8, s, "file")) return .file;
    if (std.mem.eql(u8, s, "journald")) return .journald;
    if (std.mem.eql(u8, s, "internal")) return .internal;
    return error.InvalidValue;
}

pub fn decodeCompatibilityManifest(arena: std.mem.Allocator, manifest: []const u8) Error!std.json.Value {
    if (manifest.len > max_config_bytes) return error.FileTooLarge;
    const value = std.json.parseFromSliceLeaky(std.json.Value, arena, manifest, .{ .allocate = .alloc_always }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidValue,
    };
    if (value != .object) return error.InvalidValue;
    const version = value.object.get("schema_version") orelse return error.InvalidValue;
    if (version != .integer or version.integer != 1) return error.InvalidValue;
    const admission = value.object.get("admission") orelse return error.InvalidValue;
    if (admission != .string or !std.mem.eql(u8, admission.string, "prepared")) return error.InvalidValue;
    return value;
}

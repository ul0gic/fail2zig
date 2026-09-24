// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const testing = std.testing;
const config = @import("engine_test").config.fail2ban;
const max_sections = config.max_sections;
const parseIniSource = config.parseIniSource;
const resolve = config.resolve;
const interpolate = config.interpolate;
const loadJailConfig = config.loadJailConfig;
const parseFilterSource = config.parseFilterSource;
const ActionBackend = config.ActionBackend;
const parseActionSource = config.parseActionSource;
const mapActionNameToBackend = config.mapActionNameToBackend;
const parseSelector = config.parseSelector;
const splitSelectors = config.splitSelectors;
const resolveWithParameters = config.resolveWithParameters;
const readTypedOption = config.readTypedOption;
const canonicalInteger = config.canonicalInteger;
const prepareConfigDocument = config.prepareConfigDocument;
const mergeInto = config.test_access.merge_into;
const expandTags = config.test_access.expand_tags;

test "fail2ban: parse minimal section" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src =
        \\[sshd]
        \\enabled = true
        \\maxretry = 3
    ;
    var ini = try parseIniSource(arena.allocator(), "jail.conf", src);
    try testing.expectEqual(@as(usize, 1), ini.sections.count());
    const sec = ini.section("sshd").?;
    try testing.expectEqualStrings("true", sec.get("enabled").?);
    try testing.expectEqualStrings("3", sec.get("maxretry").?);
}

test "fail2ban: parse tolerates comments both # and ;" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src =
        \\# hash comment
        \\; semicolon comment
        \\[sshd]
        \\# another
        \\maxretry = 5 # trailing NOT stripped
        \\findtime: 600
    ;
    var ini = try parseIniSource(arena.allocator(), "test", src);
    const sec = ini.section("sshd").?;
    try testing.expectEqualStrings("5 # trailing NOT stripped", sec.get("maxretry").?);
    try testing.expectEqualStrings("600", sec.get("findtime").?);
}

test "fail2ban: parse multi-line value via indent continuation" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src =
        \\[Definition]
        \\failregex = first pattern
        \\            second pattern
        \\            third pattern
        \\ignoreregex = solo
    ;
    var ini = try parseIniSource(arena.allocator(), "test", src);
    const sec = ini.section("Definition").?;
    const fr = sec.get("failregex").?;
    try testing.expect(std.mem.indexOf(u8, fr, "first pattern") != null);
    try testing.expect(std.mem.indexOf(u8, fr, "second pattern") != null);
    try testing.expect(std.mem.indexOf(u8, fr, "third pattern") != null);
    try testing.expectEqualStrings("solo", sec.get("ignoreregex").?);
}

test "fail2ban: parse DEFAULT interpolation" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src =
        \\[DEFAULT]
        \\bantime = 600
        \\findtime = 600
        \\maxretry = 5
        \\
        \\[sshd]
        \\enabled = true
        \\bantime = %(default/bantime)s
        \\custom = ban=%(bantime)s find=%(findtime)s
    ;
    var ini = try parseIniSource(arena.allocator(), "test", src);
    try interpolate(arena.allocator(), &ini);

    const sshd = ini.section("sshd").?;
    try testing.expectEqualStrings("600", sshd.get("bantime").?);
    try testing.expectEqualStrings("ban=600 find=600", sshd.get("custom").?);
}

test "fail2ban: interpolate detects cycles and keeps raw" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src =
        \\[DEFAULT]
        \\a = %(b)s
        \\b = %(a)s
        \\
        \\[x]
        \\v = %(a)s
    ;
    var ini = try parseIniSource(arena.allocator(), "test", src);
    try interpolate(arena.allocator(), &ini);
    try testing.expect(ini.warnings.items.len > 0);
}

test "fail2ban: parse section headers rejected when unterminated" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src = "[sshd\nfoo = 1\n";
    try testing.expectError(error.UnterminatedSection, parseIniSource(arena.allocator(), "test", src));
}

test "fail2ban: realistic jail.conf snippet" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src =
        \\[DEFAULT]
        \\bantime = 3600
        \\findtime = 600
        \\maxretry = 5
        \\ignoreip = 127.0.0.1/8 10.0.0.0/8
        \\backend = systemd
        \\
        \\[sshd]
        \\enabled = true
        \\port = ssh
        \\filter = sshd
        \\logpath = /var/log/auth.log
        \\maxretry = 3
        \\bantime = %(default/bantime)s
        \\
        \\[nginx-http-auth]
        \\enabled = true
        \\filter = nginx-http-auth
        \\logpath = /var/log/nginx/error.log
        \\
        \\[recidive]
        \\enabled = false
        \\logpath = /var/log/fail2ban.log
        \\bantime  = 604800
        \\findtime = 86400
        \\maxretry = 5
    ;
    var ini = try parseIniSource(arena.allocator(), "jail.conf", src);
    try interpolate(arena.allocator(), &ini);

    try testing.expect(ini.section("sshd") != null);
    try testing.expect(ini.section("nginx-http-auth") != null);
    try testing.expect(ini.section("recidive") != null);

    const sshd = ini.section("sshd").?;
    try testing.expectEqualStrings("sshd", sshd.get("filter").?);
    try testing.expectEqualStrings("3", sshd.get("maxretry").?);
    try testing.expectEqualStrings("3600", sshd.get("bantime").?);
    try testing.expectEqualStrings("systemd", ini.section("DEFAULT").?.get("backend").?);
    try testing.expect(sshd.get("backend") == null);
}

test "fail2ban: merge jail.conf + jail.local override" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const base =
        \\[DEFAULT]
        \\bantime = 600
        \\[sshd]
        \\enabled = false
        \\filter = sshd
        \\maxretry = 5
    ;
    const override =
        \\[sshd]
        \\enabled = true
        \\maxretry = 3
    ;

    var result = try parseIniSource(arena.allocator(), "jail.conf", base);
    const ov = try parseIniSource(arena.allocator(), "jail.local", override);
    try mergeInto(arena.allocator(), &result, ov);
    try interpolate(arena.allocator(), &result);

    const sshd = result.section("sshd").?;
    try testing.expectEqualStrings("true", sshd.get("enabled").?);
    try testing.expectEqualStrings("3", sshd.get("maxretry").?);
    try testing.expectEqualStrings("sshd", sshd.get("filter").?);
}

test "fail2ban: loadJailConfig reads jail.conf + jail.local + jail.d" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{
        .sub_path = "jail.conf",
        .data =
        \\[DEFAULT]
        \\bantime = 600
        \\[sshd]
        \\enabled = false
        ,
    });
    try tmp.dir.writeFile(.{
        .sub_path = "jail.local",
        .data =
        \\[sshd]
        \\enabled = true
        ,
    });
    try tmp.dir.makeDir("jail.d");
    try tmp.dir.writeFile(.{
        .sub_path = "jail.d/00-extra.conf",
        .data =
        \\[nginx]
        \\enabled = true
        \\filter = nginx
        ,
    });

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const path = try tmp.dir.realpathAlloc(arena.allocator(), ".");
    var ini = try loadJailConfig(arena.allocator(), path);

    const sshd = ini.section("sshd").?;
    try testing.expectEqualStrings("true", sshd.get("enabled").?);
    const nginx = ini.section("nginx").?;
    try testing.expectEqualStrings("true", nginx.get("enabled").?);
}

test "fail2ban: too many sections triggers typed error" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var buf = std.ArrayListUnmanaged(u8){};
    defer buf.deinit(arena.allocator());
    var i: usize = 0;
    while (i < max_sections + 2) : (i += 1) {
        try buf.writer(arena.allocator()).print("[s{d}]\nk = v\n", .{i});
    }
    try testing.expectError(
        error.TooManySections,
        parseIniSource(arena.allocator(), "test", buf.items),
    );
}

test "fail2ban: translate simple sshd pattern via <HOST>" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src =
        \\[Definition]
        \\failregex = ^Failed password for .* from <HOST>$
    ;
    const f = try parseFilterSource(arena.allocator(), "sshd.conf", src);
    try testing.expectEqual(@as(usize, 1), f.failregex.len);
    try testing.expectEqualStrings("Failed password for <*> from <IP>", f.failregex[0].pattern);
}

test "fail2ban: translate multi-line failregex" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src =
        \\[Definition]
        \\failregex = ^Failed password for .* from <HOST>$
        \\            ^Invalid user .* from <HOST>$
        \\            ^Connection closed by <HOST>$
    ;
    const f = try parseFilterSource(arena.allocator(), "sshd.conf", src);
    try testing.expectEqual(@as(usize, 3), f.failregex.len);
    try testing.expect(std.mem.indexOf(u8, f.failregex[0].pattern, "<IP>") != null);
    try testing.expect(std.mem.indexOf(u8, f.failregex[1].pattern, "<IP>") != null);
    try testing.expect(std.mem.indexOf(u8, f.failregex[2].pattern, "<IP>") != null);
}

test "fail2ban: translate explicit IPv4 regex to <IP>" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src =
        \\[Definition]
        \\failregex = ^Rejected from \d+\.\d+\.\d+\.\d+ for abuse$
    ;
    const f = try parseFilterSource(arena.allocator(), "custom.conf", src);
    try testing.expectEqual(@as(usize, 1), f.failregex.len);
    try testing.expectEqualStrings("Rejected from <IP> for abuse", f.failregex[0].pattern);
}

test "fail2ban: translate unsupported lookahead generates warning" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src =
        \\[Definition]
        \\failregex = ^Foo from <HOST>(?=bar)$
    ;
    const f = try parseFilterSource(arena.allocator(), "weird.conf", src);
    try testing.expectEqual(@as(usize, 0), f.failregex.len);
    try testing.expect(f.warnings.len >= 1);
}

test "fail2ban: translate backreference is rejected" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src =
        \\[Definition]
        \\failregex = ^(\w+) \1 from <HOST>$
    ;
    const f = try parseFilterSource(arena.allocator(), "weird.conf", src);
    try testing.expectEqual(@as(usize, 0), f.failregex.len);
    try testing.expect(f.warnings.len >= 1);
}

test "fail2ban: translate realistic postfix pattern" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src =
        \\[Definition]
        \\failregex = ^.* postfix/smtpd.*: NOQUEUE: reject: RCPT from \S+\[<HOST>\]: .*$
    ;
    const f = try parseFilterSource(arena.allocator(), "postfix.conf", src);
    try testing.expectEqual(@as(usize, 1), f.failregex.len);
    try testing.expect(std.mem.indexOf(u8, f.failregex[0].pattern, "<IP>") != null);
}

test "fail2ban: translate missing [Definition] warns" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src =
        \\[Init]
        \\foo = bar
    ;
    const f = try parseFilterSource(arena.allocator(), "empty.conf", src);
    try testing.expectEqual(@as(usize, 0), f.failregex.len);
    try testing.expect(f.warnings.len >= 1);
}

test "fail2ban: action iptables-multiport maps to iptables" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src =
        \\[Definition]
        \\actionstart = iptables -N f2b-<name>
        \\actionstop = iptables -X f2b-<name>
        \\actionban = iptables -I f2b-<name> -s <ip> -j DROP
        \\actionunban = iptables -D f2b-<name> -s <ip> -j DROP
    ;
    const a = try parseActionSource(arena.allocator(), "iptables-multiport", src);
    try testing.expectEqual(ActionBackend.iptables, a.backend);
    try testing.expect(std.mem.indexOf(u8, a.actionban, "iptables") != null);
    for (a.warnings) |w| {
        try testing.expect(std.mem.indexOf(u8, w.message, "not recognized") == null);
    }
}

test "fail2ban: action nftables-allports maps to nftables" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src = "[Definition]\nactionban = nft add element <ip>\n";
    const a = try parseActionSource(arena.allocator(), "nftables-allports", src);
    try testing.expectEqual(ActionBackend.nftables, a.backend);
}

test "fail2ban: action ipset-proto6 maps to ipset" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src = "[Definition]\nactionban = ipset add f2b <ip>\n";
    const a = try parseActionSource(arena.allocator(), "ipset-proto6", src);
    try testing.expectEqual(ActionBackend.ipset, a.backend);
}

test "fail2ban: action sendmail-whois maps to log-only with warning" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const src =
        \\[Definition]
        \\actionstart =
        \\actionstop =
        \\actionban = printf "From: fail2ban\nTo: admin\n" | mail
    ;
    const a = try parseActionSource(arena.allocator(), "sendmail-whois", src);
    try testing.expectEqual(ActionBackend.log_only, a.backend);
    var found_warning = false;
    for (a.warnings) |w| {
        if (std.mem.indexOf(u8, w.message, "not recognized") != null) found_warning = true;
    }
    try testing.expect(found_warning);
}

test "fail2ban: mapActionNameToBackend direct" {
    try testing.expectEqual(ActionBackend.iptables, mapActionNameToBackend("iptables"));
    try testing.expectEqual(ActionBackend.iptables, mapActionNameToBackend("iptables-multiport"));
    try testing.expectEqual(ActionBackend.iptables, mapActionNameToBackend("iptables-allports"));
    try testing.expectEqual(ActionBackend.nftables, mapActionNameToBackend("nftables"));
    try testing.expectEqual(ActionBackend.nftables, mapActionNameToBackend("nftables-multiport"));
    try testing.expectEqual(ActionBackend.ipset, mapActionNameToBackend("ipset-proto6-allports"));
    try testing.expectEqual(ActionBackend.log_only, mapActionNameToBackend("sendmail"));
    try testing.expectEqual(ActionBackend.log_only, mapActionNameToBackend("route"));
}

test "p2 config layers includes previous values and provenance" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makeDir("jail.d");
    try tmp.dir.writeFile(.{ .sub_path = "base.conf", .data = "[sample]\nmaxretry=2\n" });
    try tmp.dir.writeFile(.{ .sub_path = "jail.conf", .data = "[INCLUDES]\nbefore=base.conf\n[sample]\nvalue=base\n" });
    try tmp.dir.writeFile(.{ .sub_path = "jail.d/10.conf", .data = "[sample]\nmaxretry=3\nvalue=%(known/value)s-conf\n" });
    try tmp.dir.writeFile(.{ .sub_path = "jail.local", .data = "[sample]\nmaxretry=7\n" });
    try tmp.dir.writeFile(.{ .sub_path = "jail.d/20.local", .data = "[sample]\nmaxretry=9\nempty=\ncustom=x\n" });
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const path = try tmp.dir.realpathAlloc(a, ".");
    var ini = try loadJailConfig(a, path);
    const sec = ini.section("sample").?;
    try testing.expectEqualStrings("9", sec.get("maxretry").?);
    try testing.expectEqualStrings("base-conf", sec.get("value").?);
    try testing.expectEqualStrings("", sec.get("empty").?);
    try testing.expect(sec.get("absent") == null);
    try testing.expectEqual(@as(usize, 5), ini.sources.items.len);
    try testing.expectEqual(@as(u32, 2), sec.origins.get("maxretry").?.line);
    try testing.expect(std.mem.endsWith(u8, sec.origins.get("maxretry").?.source, "20.local"));
    try testing.expectEqualStrings("7", sec.previous.get("maxretry").?);
}

test "p2 config after and included local order" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "jail.conf", .data = "[INCLUDES]\nafter=extra.conf\n[sample]\nmaxretry=2\n" });
    try tmp.dir.writeFile(.{ .sub_path = "extra.conf", .data = "[sample]\nmaxretry=8\n" });
    try tmp.dir.writeFile(.{ .sub_path = "extra.local", .data = "[sample]\nmaxretry=9\n" });
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var ini = try loadJailConfig(arena.allocator(), try tmp.dir.realpathAlloc(arena.allocator(), "."));
    try testing.expectEqualStrings("9", ini.section("sample").?.get("maxretry").?);
}

test "p2 config raw interpolation preserves context and repeated percent escapes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var ini = try parseIniSource(a, "fixture", "[DEFAULT]\nword=base\nexpr=%(word)s\n[One]\nword=local\nvalue=%(expr)s %% %(other/text)s %(__name__)s\n[other]\ntext=other\n");
    try interpolate(a, &ini);
    try testing.expectEqualStrings("local % other One", ini.section("One").?.get("value").?);
    try interpolate(a, &ini);
    try testing.expectEqualStrings("local % other One", ini.section("One").?.get("value").?);
    try testing.expectEqualStrings("%(expr)s %% %(other/text)s %(__name__)s", ini.section("One").?.origins.get("value").?.raw);
}

test "p2 config missing interpolation remains explicit error and source diagnostic" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var ini = try parseIniSource(a, "fixture", "[x]\nMAXRETRY=%(missing)s ; comment\n");
    try testing.expectError(error.InterpolationMissingOption, resolve(a, &ini, "x", "maxretry"));
    try interpolate(a, &ini);
    try testing.expectEqual(@as(u32, 2), ini.warnings.items[0].line);
    try testing.expectEqualStrings("fixture", ini.warnings.items[0].source);
}

test "p2 config selectors preserve open empty and quoted nested parameters" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var selector = try parseSelector(arena.allocator(), "custom[mode=aggressive, opaque='a,b', empty=, list='[x,y]']");
    try testing.expectEqualStrings("custom", selector.name);
    try testing.expectEqualStrings("a,b", selector.parameters.get("opaque").?);
    try testing.expectEqualStrings("", selector.parameters.get("empty").?);
    try testing.expectEqualStrings("[x,y]", selector.parameters.get("list").?);
    try testing.expectError(error.InvalidParameter, parseSelector(arena.allocator(), "custom[x='broken]"));
    try testing.expectError(error.InvalidParameter, parseSelector(arena.allocator(), "custom[list=[x,y]]"));
}

test "p2 config self interpolation is a cycle not default inheritance" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var ini = try parseIniSource(a, "fixture", "[DEFAULT]\nx=5\n[jail]\nx=%(x)s\n");
    try testing.expectError(error.InterpolationCycle, resolve(a, &ini, "jail", "x"));
}

test "p2 config static tags conditional deferral and cycles" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var values = std.StringArrayHashMapUnmanaged([]const u8){};
    try values.put(a, "mode", "normal");
    try values.put(a, "nested", "<mode>");
    try values.put(a, "family", "v4");
    try values.put(a, "family?family=inet6", "v6");
    try testing.expectEqualStrings("normal <family> <HOST>", try expandTags(a, &values, "<nested> <family> <HOST>", "", 0));
    try testing.expectEqualStrings("normal v6 <HOST>", try expandTags(a, &values, "<nested> <family> <HOST>", "family=inet6", 0));
    try values.put(a, "loop", "<loop>");
    try testing.expectError(error.InterpolationCycle, expandTags(a, &values, "<loop>", "", 0));
}

test "p2 config selector precedence applies before percent interpolation" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var ini = try parseIniSource(a, "fixture", "[Definition]\nmode=normal\nresult=%(mode)s\n");
    var params = std.StringArrayHashMapUnmanaged([]const u8){};
    try params.put(a, "mode", "custom");
    try testing.expectEqualStrings("custom", (try resolveWithParameters(a, &ini, "Definition", "result", &params)).?);
    try testing.expectEqualStrings("normal", (try resolve(a, &ini, "Definition", "result")).?);
}

test "p2 config conversion distinguishes empty missing inherited and fallback" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var ini = try parseIniSource(a, "fixture", "[DEFAULT]\nflag=yes\n[x]\nempty=\nbad=perhaps\nhuge=+000123456789012345678901234567890\n");
    const empty = try readTypedOption(a, &ini, "x", "empty", .string, .null_value, "test");
    try testing.expectEqual(.explicit, empty.presence);
    try testing.expectEqualStrings("", empty.value.string);
    const missing = try readTypedOption(a, &ini, "x", "missing", .string, .null_value, "test");
    try testing.expectEqual(.absent, missing.presence);
    const inherited = try readTypedOption(a, &ini, "x", "flag", .boolean, .null_value, "test");
    try testing.expectEqual(.derived, inherited.presence);
    try testing.expect(inherited.value.boolean);
    const bad = try readTypedOption(a, &ini, "x", "bad", .boolean, .null_value, "test");
    try testing.expectEqual(.resolved, bad.resolution);
    try testing.expect(!bad.value.boolean);
    const huge = try readTypedOption(a, &ini, "x", "huge", .integer, .null_value, "test");
    try testing.expectEqualStrings("123456789012345678901234567890", huge.value.integer);
}

test "p2 config syntax failures and indented assignments are explicit" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectError(error.DuplicateOption, parseIniSource(a, "fixture", "[x]\nA=1\na=2\n"));
    try testing.expectError(error.DuplicateSection, parseIniSource(a, "fixture", "[x]\na=1\n[x]\nb=2\n"));
    try testing.expectError(error.KeyWithoutValue, parseIniSource(a, "fixture", "[x]\ninvalid\n"));
    try testing.expectError(error.InvalidEncoding, parseIniSource(a, "fixture", "[x]\na=\xff\n"));
    var ini = try parseIniSource(a, "fixture", " [x]\n a=one\n   continued ; ignored\n b=two\n");
    try testing.expectEqualStrings("one\ncontinued", ini.section("x").?.get("a").?);
    try testing.expectEqualStrings("two", ini.section("x").?.get("b").?);
}

test "p2 config integer unicode decimal profile and separator validation" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings("123", (try canonicalInteger(a, "\u{2003}+٠١_٢٣\u{a0}")).?);
    try testing.expect((try canonicalInteger(a, "1__2")) == null);
    try testing.expect((try canonicalInteger(a, "_12")) == null);
    try testing.expect((try canonicalInteger(a, "12_")) == null);
    try testing.expect((try canonicalInteger(a, "²")) == null);
}

test "p2 config symlink retargeting changes generation with identical content" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "one.conf", .data = "[probe]\nx=one\n" });
    try tmp.dir.writeFile(.{ .sub_path = "two.conf", .data = "[probe]\nx=one\n" });
    try tmp.dir.symLink("one.conf", "jail.conf", .{});
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const root = try tmp.dir.realpathAlloc(a, ".");
    const before = try prepareConfigDocument(a, root, "jail");
    try tmp.dir.deleteFile("jail.conf");
    try tmp.dir.symLink("two.conf", "jail.conf", .{});
    const after = try prepareConfigDocument(a, root, "jail");
    try testing.expect(!std.mem.eql(u8, &before.config_generation, &after.config_generation));
    try testing.expectEqualStrings(before.source.sources.items[0].bytes, after.source.sources.items[0].bytes);
    try testing.expect(!std.mem.eql(u8, before.source.sources.items[0].resolved_target, after.source.sources.items[0].resolved_target));
}

test "p2 selectors preserve multiline groups ordered actions and conditional keys" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const values = try splitSelectors(a, "first[a=' one ',b=two][a=last,\nx?family=inet6=value]\nsecond[port='80,443']");
    try testing.expectEqual(@as(usize, 2), values.len);
    const first = try parseSelector(a, values[0]);
    try testing.expectEqualStrings("first", first.name);
    try testing.expectEqualStrings("last", first.parameters.get("a").?);
    try testing.expectEqualStrings("value", first.parameters.get("x?family=inet6").?);
    const second = try parseSelector(a, values[1]);
    try testing.expectEqualStrings("80,443", second.parameters.get("port").?);
    const quoted = try parseSelector(a, "original[value=' trimmed ']");
    try testing.expectEqualStrings("trimmed", quoted.parameters.get("value").?);
    try testing.expectError(error.InvalidParameter, parseSelector(a, "original[x='unterminated]"));
    try testing.expectError(error.InvalidParameter, splitSelectors(a, "original[x=unfinished"));
}

test "p2 interpolation depth counts only recursive percent replacements" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for ([_]usize{ 9, 10, 11 }) |hops| {
        for ([_][]const u8{ "literal", "100%%" }) |terminal| {
            var bytes = std.ArrayList(u8).init(a);
            try bytes.appendSlice("[probe]\n");
            for (0..hops) |i| try bytes.writer().print("v{d}=%(v{d})s\n", .{ i, i + 1 });
            try bytes.writer().print("v{d}={s}\n", .{ hops, terminal });
            var parsed = try parseIniSource(a, "original-depth", bytes.items);
            const limit: usize = if (std.mem.eql(u8, terminal, "literal")) 10 else 9;
            if (hops <= limit) {
                try testing.expectEqualStrings(if (terminal.len == 7) "literal" else "100%", (try resolve(a, &parsed, "probe", "v0")).?);
            } else try testing.expectError(error.InterpolationCycle, resolve(a, &parsed, "probe", "v0"));
        }
    }
}

test "p2 section headers preserve spaces and accept greedy prefix match" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var parsed = try parseIniSource(a, "original-header", "[ probe ] trailing text\nv=one\n[other] ; ignored ]\nv=two\n[nested]suffix] trailing\nv=three\n");
    try testing.expectEqualStrings("one", (try resolve(a, &parsed, " probe ", "v")).?);
    try testing.expectEqualStrings("two", (try resolve(a, &parsed, "other", "v")).?);
    try testing.expectEqualStrings("three", (try resolve(a, &parsed, "nested]suffix", "v")).?);
    try testing.expectError(error.UnterminatedSection, parseIniSource(a, "original-header", "[bad ; ignored ]\nv=one\n"));
}

#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig maintainers
"""D6/D7 source mapping, reference formatting, and declarative transaction contracts.

This is a design probe, not a daemon, migration command, or compatibility adapter.
Only original configuration/formatting data reaches pinned reference readers.
"""

import argparse
from copy import deepcopy
import hashlib
import json
import itertools
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile


PIN = "f60978618a101427b06924fc932b44350fec2b63"
ROOT = Path(__file__).resolve().parents[2]
DOC = "docs/parity/config-command-contract.md"
WORKER = r'''
import json, logging, resource, sys
resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024,) * 2)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
request = json.loads(sys.stdin.read(16385))
sys.path.insert(0, sys.argv[1])
messages = []
class Collector(logging.Handler):
    def emit(self, record):
        messages.append({'level': record.levelname, 'message': record.getMessage()})
logging.getLogger().addHandler(Collector(logging.WARNING))
if request['operation'] == 'config':
    from fail2ban.client.configreader import ConfigReaderUnshared
    reader = ConfigReaderUnshared(basedir=sys.argv[2])
    if not reader.read('jail'):
        raise RuntimeError('cannot read original configuration fixture')
    value = reader.getOptions('probe', request['options'])
elif request['operation'] == 'format':
    from fail2ban.client.beautifier import Beautifier
    value = Beautifier(request['command']).beautify(request['response'])
elif request['operation'] == 'format_error':
    from fail2ban.client.beautifier import Beautifier
    from fail2ban.exceptions import UnknownJailException, DuplicateJailException
    errors = {'unknown_jail': UnknownJailException,
              'duplicate_jail': DuplicateJailException, 'bad_arity': IndexError}
    value = Beautifier(request['command']).beautifyError(
        errors[request['error']](request['argument']))
elif request['operation'] == 'filter_reload':
    from fail2ban.server.filter import Filter
    f = Filter(None)
    f.setMaxRetry(7)
    f.setFindTime(42)
    f.setMaxLines(3)
    f.setUseDns('raw')
    f.addFailRegex(r'^original <HOST>$')
    f.addIgnoreRegex(r'^ordinary ignored$')
    f.addIgnoreIP('192.0.2.7')
    f.reload(begin=True)
    f.reload(begin=False)
    value = {'maxretry': f.getMaxRetry(), 'findtime': f.getFindTime(),
             'maxlines': f.getMaxLines(), 'usedns': f.getUseDns(),
             'failregex': f.getFailRegex(), 'ignoreregex': f.getIgnoreRegex(),
             'ignoreip': list(f.getIgnoreIP())}
else:
    raise RuntimeError('unrecognized probe operation')
print(json.dumps({'value': value, 'diagnostics': messages}))
'''


ERRORS = {
    "E_SYNTAX": {"class": "usage", "json_exit": 2},
    "E_VALUE": {"class": "validation", "json_exit": 2},
    "E_CONFIG": {"class": "configuration", "json_exit": 1},
    "E_NOT_FOUND": {"class": "target", "json_exit": 1},
    "E_EXISTS": {"class": "target", "json_exit": 1},
    "E_STALE": {"class": "generation", "json_exit": 1},
    "E_BUSY": {"class": "transaction", "json_exit": 1},
    "E_AUTH": {"class": "authorization", "json_exit": 1},
    "E_TRUST_REQUIRED": {"class": "extension", "json_exit": 1},
    "E_UNSUPPORTED": {"class": "capability", "json_exit": 1},
    "E_DEPENDENCY": {"class": "dependency", "json_exit": 1},
    "E_LIMIT": {"class": "capacity", "json_exit": 1},
    "E_TRANSPORT": {"class": "transport", "json_exit": 3},
    "E_DEADLINE": {"class": "operation", "json_exit": 1},
    "E_EFFECT_UNCERTAIN": {"class": "effect", "json_exit": 1},
    "E_INTERNAL": {"class": "internal", "json_exit": 1},
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(argv, *, cwd=None, payload=None):
    result = subprocess.run(argv, cwd=cwd, input=payload, text=True,
                            capture_output=True, timeout=15)
    if result.returncode:
        raise RuntimeError(f"probe command failed: {argv[0]}: {result.stderr[:2048]}")
    return result.stdout.strip()


def reference_check(reference):
    if run(["git", "rev-parse", "HEAD"], cwd=reference) != PIN:
        raise ValueError("reference pin mismatch")
    run(["git", "diff", "--exit-code", "HEAD", "--"], cwd=reference)
    if run(["git", "ls-files", "--others", "--exclude-standard"], cwd=reference):
        raise ValueError("untracked reference content")


def operation_for(template):
    """Classify the already inventoried templates; this is not an argv parser."""
    words = template.split()
    verb = words[0]
    if template == "stop --all":
        return "jail.stop_all"
    if verb in ("start", "restart", "stop"):
        return ("jail." if "<JAIL>" in template else "service.") + verb
    if verb == "reload":
        return "config.reload"
    if verb == "add":
        return "jail.create"
    if verb == "unban":
        return "ban.release_all_jails"
    if verb == "banned":
        return "ban.query_all_jails"
    if verb == "status":
        return "status.snapshot"
    if verb == "stat[istic]s":
        return "status.statistics"
    if verb in ("ping", "echo", "version"):
        return "system." + verb
    if verb == "flushlogs":
        return "logging.reopen"
    internal = {"multi-set": "batch.apply_ordered", "server-status": "system.readiness",
                "server-stream": "config.apply_ordered_stream", "sleep": "diagnostic.delay",
                "config-error": "diagnostic.config_error"}
    if verb in internal:
        return internal[verb]
    if verb not in ("set", "get"):
        raise ValueError(f"unmapped command: {template}")
    access = "write" if verb == "set" else "read"
    if words[1] != "<JAIL>":
        domain = "logging" if words[1] in ("loglevel", "logtarget", "syslogsocket") else "database" if words[1].startswith("db") else "thread" if words[1] == "thread" else "global"
        return f"config.{domain}.{access}"
    key = words[2]
    if key == "action":
        if verb == "get":
            return "extension.property_read_trusted"
        return "extension.property_or_method_dispatch_trusted"
    if key in ("actionproperties", "actionmethods"):
        return "extension.enumerate_trusted"
    if key in ("addaction", "delaction"):
        return "action.attach" if key == "addaction" else "action.detach"
    if key == "actions":
        return "action.list_cached"
    if key == "attempt":
        return "ticket.submit_manual"
    if key in ("banip", "unbanip", "banned"):
        return "ban.query_jail" if verb == "get" else "ban.acquire_jail" if key == "banip" else "ban.release_jail"
    lists = ("ignoreip", "logpath", "journalmatch", "failregex", "ignoreregex")
    base_key = key[3:] if key.startswith(("add", "del")) else key
    if base_key in lists:
        return "config.jail.collection_" + ("add" if key.startswith("add") else "remove" if key.startswith("del") else "read")
    return "config.jail." + access


def operation_errors(operation, template):
    errors = {"E_SYNTAX", "E_VALUE", "E_AUTH", "E_UNSUPPORTED", "E_LIMIT", "E_TRANSPORT", "E_INTERNAL"}
    if "<JAIL>" in template or "<ACT>" in template:
        errors.add("E_NOT_FOUND")
    if operation in ("jail.create", "action.attach"):
        errors.add("E_EXISTS")
    if operation.startswith(("config.", "batch.", "jail.", "service.", "action.", "ban.acquire", "ban.release", "ticket.")) and not operation.endswith((".read", "_read", ".list_cached")):
        errors.update(("E_CONFIG", "E_STALE", "E_BUSY", "E_DEPENDENCY", "E_DEADLINE", "E_EFFECT_UNCERTAIN"))
    if operation.startswith("extension."):
        errors.update(("E_TRUST_REQUIRED", "E_STALE", "E_BUSY", "E_DEPENDENCY", "E_DEADLINE", "E_EFFECT_UNCERTAIN"))
    if operation == "status.snapshot":
        errors.update(("E_DEPENDENCY", "E_DEADLINE"))  # Optional external enrichment.
    return sorted(errors)


def map_commands(audit):
    result = []
    for row in audit["command_mapping"]:
        operation = operation_for(row["template"])
        trusted = operation.startswith("extension.")
        result.append({**row, "structured_operation": operation,
                       "request_fields": ["request_id", "schema_version", "reference_profile",
                                          "base_generation", "target", "arguments", "intent"],
                       "trust_class": "trusted-extension" if trusted else "cached-read" if operation == "action.list_cached" else "authorized-lifecycle" if operation.startswith(("service.", "jail.", "action.", "ban.acquire", "ban.release", "ticket.submit", "config.apply")) else "structured-operation",
                       "possible_errors": operation_errors(operation, row["template"]),
                       "error_mapping": "Operation-specific target/arity/capability/effect predicates must be verified; taxonomy availability is not proof every code applies.",
                       "applicability": "required when invoked by declared profile; internal forms retain caller and admission constraints",
                       "status": "proposed-mapping; no command executed"})
    if len({row["id"] for row in result}) != len(result):
        raise ValueError("duplicate inventoried command id")
    return result


def option_domain(scope, key):
    if scope == "INCLUDES":
        return "source_graph.include_edges"
    if scope in ("environment", "static interpolation"):
        return "profile.resolution_inputs"
    if scope.startswith("global"):
        return "global.typed_options"
    if scope.startswith("backend"):
        return "source.backend_parameters"
    if scope == "ignorecache":
        return "jail.ignore.cache_parameters"
    if key in ("prefregex", "failregex", "ignoreregex", "datepattern", "maxlines", "filter"):
        return "filter.definition_and_parameters"
    if key in ("action", "banaction"):
        return "action.ordered_instances"
    if key.startswith("bantime") or key in ("maxretry", "maxmatches", "findtime"):
        return "jail.policy"
    return "jail.typed_options"


def option_mappings(audit):
    typed = [{**item, "canonical_domain": option_domain(item["scope"], item["key"]),
              "default_identity": {"reader_scope": item["scope"], "reference": item["reference"]},
              "resolution": "retain absent/empty/raw/default origin; convert only at consuming phase"}
             for item in audit["config_option_inventory"]]
    assignments = [{**item, "canonical_domain": "compat.source_graph.assignments",
                    "consumer_disposition": "retain; effective consumer/default/profile expansion unresolved",
                    "platform": "source profile retained; no OS-specific assignment is discarded by this mapping"}
                   for item in audit["stock_assignment_inventory"]]
    catalog = []
    for item in audit["catalog"]:
        for option in item.get("active_option_anchors", []):
            catalog.append({**option, "catalog_path": item["path"],
                            "canonical_domain": "compat." + ("action" if "/action.d/" in item["path"] else "filter") + ".parameter_graph",
                            "requirement_ids": item.get("requirement_ids", []),
                            "resolution": "ordered raw option retained; Definition/Init/conditional/default consumer typing remains phase-specific"})
    return {"typed_options": typed, "stock_assignments": assignments, "catalog_options": catalog}


def reload_matrix(audit):
    """Source-classified effective properties; no lifecycle or extension invocation."""
    groups = [
        ("reset-list", "failregex ignoreregex ignoreip", "server/filter.py:141", "begin clears old list; emitted additions rebuild in stream order", "empty list remains after begin", "add old entry; reload omitting field -> []; emit one new entry -> only new entry"),
        ("retain-scalar", "maxretry maxmatches findtime usedns maxlines prefregex datepattern logtimezone logencoding ignoreself ignorecommand ignorecache bantime", "server/filter.py:148;server/server.py:359;server/server.py:436;server/server.py:478;server/server.py:522", "provided effective setter replaces through its specific consumer", "old value retained when no setter is emitted", "set runtime value; omit effective setter -> retain; emit distinct value -> setter result; explicit empty follows consumer conversion"),
        ("merge-extra", "bantime.increment bantime.factor bantime.formula bantime.multipliers bantime.maxtime bantime.rndtime bantime.overalljails bantime.<EXTRA>", "server/jail.py:225", "merge one key; empty becomes None and removes key, except increment reinserts false; dependent formulas recompute", "old extra key retained", "set maxtime then reload omitted -> retain; explicit empty -> remove; increment empty -> false; unknown key preserved, never evaluated by inspect"),
        ("source-reconcile", "logpath", "server/filter.py:148;server/filter.py:1018;client/jailreader.py:268", "re-added existing path keeps container/cursor; new path uses head/tail and database seek; unseen old paths removed at end", "old paths removed if not re-added", "two paths, re-add one with tail -> existing cursor unchanged; omitted path removed; new path tail boundary tested in P3"),
        ("journal-append", "journalmatch", "server/filter.py:141;server/filtersystemd.py:211;server/filtersystemd.py:228", "existing Python groups retained; emitted groups append (including duplicates); + separates disjunctions", "old groups retained", "reload same group twice -> repeated stored groups; omit -> retained; invalid append restores prior groups or reports restore failure"),
        ("instance-reload", "action", "server/server.py:508;server/actions.py:105;server/actions.py:151", "existing reload+clearAllParams instance clears parameters and is marked for end reload; only marked instances survive end; unmarked entries are flushed/stopped/removed", "unmentioned action removed at end with separate unban/stop effects", "existing command action reload keeps identity; custom reload without clearAllParams is unmarked; newly created/replaced unmarked action also removed at end; record these exact source branches in P4 recorder fixtures"),
        ("graph-selection", "enabled backend filter skip_if_nologs systemd_if_nologs", "client/jailreader.py:257;client/jailreader.py:268;server/server.py:237;server/server.py:296", "effective graph selects emitted jail/stream; same backend reuses jail; changed backend replaces jail; disabled/untouched affected jail removed", "reader defaults and inherited graph decide stream, never generic scalar retention", "same backend keeps object; changed backend recreates; disabled affected jail disappears; nonexistent targeted jail requires if-exists"),
        ("runtime-idle", "idle", "server/server.py:263;server/server.py:296;server/server.py:351", "begin sets idle; successful start resumes; idle is not a persistent file option", "successful reloaded jail resumes regardless prior runtime idle", "idle jail reload/start -> active; failed stream records actual terminal idle/removal disposition"),
        ("global-setter", "loglevel logtarget syslogsocket allowipv6 stacksize dbmaxmatches dbpurgeage", "client/fail2banreader.py:79;client/configurator.py:78;server/server.py:644;server/server.py:780;server/server.py:814;server/transmitter.py:196", "provided setter applied in global stream order; disabled DB retention setters return null with diagnostic and no effect; thread affects subsequent thread creation", "retained only if global setter absent; targeted CLI reload ALSO emits the global stream", "both all-jail and targeted effective global defaults can override overlay; omitted setter retains; disabled DB getter/setter null with no applied retention change"),
        ("database-restricted", "dbfile", "server/server.py:828", "same filename or already-disabled none is no-op; change rejected while jails exist; otherwise open/disable dependency transition", "existing database retained", "same filename with jails succeeds no-op; different filename with jails fails; none case insensitive; no silent second database"),
        ("startup-endpoint", "socket pidfile", "client/fail2banreader.py:42;client/fail2bancmdline.py:208", "client/startup endpoint selection; not a jail reload setter", "running endpoint unchanged by jail reload", "reload with different socket contacts selected endpoint, does not move live socket; actual replacement requires service transition"),
        ("backend-init", "journalpath journalfiles rotated journalflags namespace F2B_SYSTEMD_DEFAULT_FLAGS", "server/jail.py:71;server/filtersystemd.py:111;server/server.py:237", "backend constructor consumes parameters/environment on instance creation; equal full backend selector reuses instance", "existing constructed source retained on same-backend reuse", "changed backend parameter selector recreates source; environment alone on same selector does not reconstruct journal reader"),
        ("consumer-input", "key max-count max-time before after fail2ban_version fail2ban_confpath", "client/configreader.py:206;client/configreader.py:381;server/filter.py:441", "include/interpolation/cache inputs resolve their consuming field; no standalone runtime setter", "follows consumer classification", "changed helper affects dependent effective field; unchanged/unused helper retained with provenance and no invented runtime mutation"),
    ]
    rows = []
    for classification, keys, anchors, provided, omitted, acceptance in groups:
        for key in keys.split():
            rows.append({"property": key, "classification": classification,
                         "reference_paths": ["fail2ban/" + p for p in anchors.split(";")],
                         "effective_setter_present": provided, "effective_setter_absent": omitted,
                         "restart": "new instance constructor/defaults plus emitted stream; transient state continuity requires runtime/migration contract, never assumed",
                         "acceptance": acceptance, "evidence": "source-inspected; reference filter subset separately executed"})
    covered = {row["property"] for row in rows}
    missing = {item["key"] for item in audit["config_option_inventory"]} - covered
    if missing:
        raise ValueError(f"typed properties missing reload classification: {sorted(missing)}")
    return rows


def dynamic_domains():
    """Closed declarations and open extension domains are both explicit obligations."""
    specs = [
        ("bantime-extra", ["increment", "factor", "formula", "multipliers", "maxtime", "rndtime", "overalljails"], "arbitrary suffix is stored; evformula/evmultipliers are internal derived keys, not silently excluded when explicitly addressed", "server/jail.py:225;server/transmitter.py:358", "empty removes except increment false; duration conversion for maxtime/rndtime; space-separated ints for multipliers; factor/formula executable expressions admitted only in trusted policy profile; unknown getter returns null", "success returns stored converted value; conversion/compile/type failure E_VALUE, missing trusted capability E_TRUST_REQUIRED; legacy may have mutated earlier keys before failure"),
        ("thread-option", ["stacksize"], "unknown dictionary keys raise KeyError; template OPTION/VALUE normalizes to one options dictionary in native request", "server/server.py:818;server/transmitter.py:190", "stacksize numeric KiB converted to byte count, OS/threading constraints apply; getter returns dictionary, additional getter argument ignored", "unknown option E_VALUE with legacy KeyError; invalid numeric E_VALUE; unsupported OS size E_DEPENDENCY; earlier dictionary items may already apply; no claimed effect on existing threads"),
        ("status-flavor", ["basic", "short", "stats", "cymru"], "unknown strings warn and follow non-short/non-stats fallback path, not universal rejection", "server/actions.py:721;server/filter.py:995;server/server.py:607;server/transmitter.py:516", "jail/--all/default server selection; Cymru requires admitted resolver and exact row shape; stats returns tuples while status formatting still follows original command", "ordered snapshot rows; warning preserved; optional resolver E_DEPENDENCY/E_DEADLINE; failed beautification returns repr(partially built msg)+repr(response), with warning/error diagnostics"),
        ("statistics-alias", ["stats", "statistic", "statistics"], None, "server/transmitter.py:146;client/beautifier.py:113", "all reach same stats data; stats/statistics format table with encoding-selected ASCII/Unicode; statistic retains raw response formatting", "empty stats/statistics -> No jails found.; singular statistic -> raw empty mapping; do not normalize alias before rendering"),
        ("ban-query", ["--with-time", "--report-absent", "--all"], "separator is arbitrary string; IDs are typed raw/address/network subjects per runtime contract", "server/transmitter.py:372;server/transmitter.py:483;server/actions.py:212;client/beautifier.py:248", "get banip first extra --with-time selects timed rows; other first extra is formatter separator; banned no IDs list, one ID scalar membership, many IDs ordered membership list; report-absent changes unban failure policy", "preserve order/shape; absent vs empty list distinct; unknown subject membership false; nonexistent jail E_NOT_FOUND"),
        ("usedns", ["yes", "warn", "no", "raw"], "case folded strings; native bool aliases yes/no; other strings log error and fall back no", "server/filter.py:258", "DNS resolution only under admitted resolver; parser must not reject reference fallback", "successful no with ERROR diagnostic on invalid string; non-string invalid type E_VALUE"),
        ("booleans", ["1", "on", "true", "yes"], "_as_bool: case-insensitive true set, every other string false; configparser boolean conversion is separate stricter consumer", "helpers.py:88;client/configreader.py:337;server/server.py:359", "keep consumer-specific grammar; absent fallback is reader-specific; explicit empty false in _as_bool", "reference reader invalid bool warning/default; runtime ignoreself unknown string false"),
        ("log-target", ["SYSLOG", "STDOUT", "SYSOUT", "STDERR", "SYSTEMD-JOURNAL", "INHERITED"], "other strings are file paths; bracket options retain facility/padding/format and raw extra parameters", "server/server.py:671", "reserved names case-insensitive; identical target no-op; facility invalid falls back DAEMON with diagnostic; INHERITED preserves handlers", "dependency/path failures typed; no inspection creates file or handler; actual logging format/readback fixture per service profile"),
        ("idle", ["on", "off"], None, "server/transmitter.py:215", "case-sensitive finite words; unlike _as_bool, every other value rejected", "success bool readback; other word E_VALUE with legacy generic Exception text"),
        ("allowipv6", ["auto", "1", "on", "true", "yes"], "only exact auto selects auto-detection; other strings follow _as_bool", "server/server.py:814", "retain input acknowledgement separately from effective boolean/auto resolver state", "setter returns original supplied value; automatic resolver availability is profile-specific"),
        ("log-level", ["CRITICAL", "FATAL", "ERROR", "WARNING", "WARN", "INFO", "DEBUG", "NOTSET", "NOTICE", "MSG", "TRACEDEBUG", "HEAVYDEBUG"], "digits and attributes resolved by pinned logging module; negative numeric string is not digit grammar", "__init__.py:30;helpers.py:246;server/server.py:644", "uppercase before resolution; preserve resolved numeric level and original command flavor", "unknown name E_VALUE; accepted runtime integer levels retained; symbolic aliases format using pinned logging name"),
        ("backend-selector", ["auto", "polling", "pyinotify", "systemd"], "bracket Init parameters and extension/environment values retain exact spelling; availability is profile-specific", "server/jail.py:71;server/filtersystemd.py:111;client/jailreader.py:268", "ordered auto fallback; file head/tail accepts case-insensitive finite tokens, wrong backend log/journal APIs preserve reference no-op/empty behavior", "missing backend E_DEPENDENCY; invalid selector E_VALUE; unavailable platforms remain required profile gates"),
        ("action-member", [], "all names accepted by getattr/setattr/dir, including private explicit access; enumeration excludes underscore names and classifies callable by actual descriptor result", "server/transmitter.py:382;server/transmitter.py:492", "trusted extension service ABI1; retain per-instance identity and member resolution order; methods receive JSON object kwargs, omitted kwargs {}; property mutation returns readback; multi-set returns true and preserves order", "missing member maps legacy AttributeError and typed E_NOT_FOUND; malformed JSON/kwargs E_VALUE; arbitrary extension exceptions E_INTERNAL with class/detail; non-plain result rendered inside trusted service and transported as bounded tagged legacy-rendered text, never pickle"),
        ("numeric-text-open", [], "integer fields, finite decimal/time expressions, codec names, date templates/timezone offsets, regexes, paths and identifiers are consumer-typed open domains", "server/transmitter.py:280;server/filter.py:285;server/filter.py:302;server/filter.py:339;server/filter.py:374;server/filter.py:391", "no imposed native maxretry128 parity ceiling; maxlines >0; decode codec validated; duration semantics runtime contract; arbitrary required regex/profile mode semantics modes contract", "small positive/zero/negative/invalid/empty each follows consumer; expression inspection never executes; unsupported resource profile explicit E_LIMIT")]
    rows = [{"id": key, "finite_values": finite, "open_domain": opened,
             "reference_paths": ["fail2ban/" + p for p in anchors.split(";")],
             "arguments_and_behavior": behavior, "outputs_errors_acceptance": outcome,
             "evidence": "source-inspected contract; only named reference probes are executed"}
            for key, finite, opened, anchors, behavior, outcome in specs]
    rows.append({"id": "reload-flags", "finite_values": ["--restart", "--unban", "--if-exists"],
                 "flag_subsets": [list(combo) for n in range(4) for combo in itertools.combinations(["--restart", "--unban", "--if-exists"], n)],
                 "reference_paths": ["fail2ban/client/fail2banclient.py:309", "fail2ban/server/server.py:296"],
                 "arguments_and_behavior": "leading flags before optional jail/--all; repeated leading flags retained syntactically but server membership tests make repeats inert; unban precedes restart; --if-exists permits missing named target; flag after target with extra token rejected",
                 "outputs_errors_acceptance": "all 8 subsets x all/named-present/named-absent target, duplicate and permutation controls; unknown target fails unless if-exists; invalid order/arity E_SYNTAX; no global atomic rollback claim",
                 "evidence": "source-inspected finite acceptance matrix; no reload executed"})
    return rows


def sqlite_controls():
    """Original in-memory SQLite model; no daemon durability certification."""
    db = sqlite3.connect(":memory:")
    db.executescript("CREATE TABLE generation(id INTEGER PRIMARY KEY, overlay TEXT); CREATE TABLE intent(id TEXT PRIMARY KEY, generation INTEGER REFERENCES generation(id), state TEXT); INSERT INTO generation VALUES(7, 'old');")
    db.execute("PRAGMA foreign_keys=ON")
    for rollback in (True, False):
        db.execute("BEGIN IMMEDIATE")
        db.execute("INSERT INTO generation VALUES(8, 'new-overlay')")
        db.execute("INSERT INTO intent VALUES('original-intent', 8, 'pending')")
        if rollback:
            db.rollback()
            assert db.execute("SELECT max(id) FROM generation").fetchone()[0] == 7
            assert db.execute("SELECT count(*) FROM intent").fetchone()[0] == 0
        else:
            db.commit()
    assert db.execute("SELECT generation,state FROM intent").fetchone() == (8, "pending")
    db.execute("UPDATE intent SET state='uncertain' WHERE id='original-intent'")
    db.commit()
    assert db.execute("SELECT max(id) FROM generation").fetchone()[0] == 8
    db.close()
    return [{"id": "D6-MODEL-sqlite-generation-intent-atomicity", "status": "passed",
             "scope": "in-memory SQL rollback/commit constraints; not WAL/fsync/crash/runtime verification"},
            {"id": "D6-MODEL-effect-outcome-separate", "status": "passed",
             "scope": "uncertain effect cannot undo committed generation; original model only"}]


def alias_mappings(audit):
    definitions = {"-h": "help", "--help": "help", "-V": "client_identity", "--version": "client_identity",
                   "-c": "config_root", "--conf": "config_root", "-s": "native_socket", "--socket": "native_socket",
                   "-p": "pidfile", "--pidfile": "pidfile", "-x": "force_start", "-f": "foreground",
                   "-b": "background", "-d": "config_stream_dump", "--dp": "pretty_config_stream_dump",
                   "--dump-pretty": "pretty_config_stream_dump", "-t": "config_validate", "--test": "config_validate",
                   "-v": "verbosity_increment", "-q": "verbosity_decrement", "-i": "interactive",
                   "--async": "asynchronous_start", "--timeout": "request_deadline", "--str2sec": "duration_parse",
                   "--loglevel": "loglevel", "--logtarget": "logtarget", "--syslogsocket": "syslogsocket", "--pname": "process_name"}
    short, long = audit["client_option_inventory"]
    aliases = []
    opts = short["options"]
    for index, char in enumerate(opts):
        if char != ":":
            aliases.append(("-" + char, index + 1 < len(opts) and opts[index + 1] == ":", short["reference_path"]))
    aliases.extend(("--" + name.rstrip("="), name.endswith("="), long["reference_path"]) for name in long["options"])
    result = []
    for name, takes_value, anchor in aliases:
        if name not in definitions:
            raise ValueError(f"unmapped client alias: {name}")
        result.append({"alias": name, "takes_value": takes_value, "maps_to": definitions[name],
                       "reference": anchor, "status": "proposed; ordered combinations and output/exit fixtures required"})
    return result


def declarative_commit(current, draft, observed_generation, observed_assets):
    """Pure model of a pre-effect config publication barrier; no runtime resources."""
    if observed_generation != current["generation"] or draft["base_generation"] != current["generation"]:
        return deepcopy(current), "E_STALE"
    if draft["asset_hashes"] != observed_assets:
        return deepcopy(current), "E_STALE"
    if draft["unresolved_consumers"]:
        return deepcopy(current), "E_UNSUPPORTED"
    if draft["effect_phase"] != "not_started":
        return deepcopy(current), "E_EFFECT_UNCERTAIN"
    return {"generation": current["generation"] + 1, "disk": deepcopy(draft["disk"]),
            "runtime": deepcopy(draft["runtime"]), "asset_hashes": deepcopy(observed_assets)}, None


def static_export(value):
    # Exact builtin types prevent inspecting descriptors of an extension object.
    if type(value) in (str, int, bool, type(None)):
        return value
    if type(value) is list:
        return [static_export(item) for item in value]
    if type(value) is dict and all(type(key) is str for key in value):
        return {key: static_export(item) for key, item in value.items()}
    raise ValueError("E_TRUST_REQUIRED")


def schema_controls():
    base = {"generation": 7, "disk": {"port": "22"}, "runtime": {"maxretry": 4},
            "asset_hashes": {"filter.conf": "old-hash"}}
    draft = {"base_generation": 7, "disk": {"port": "443"}, "runtime": {"maxretry": 4},
             "asset_hashes": {"filter.conf": "new-hash"}, "unresolved_consumers": [], "effect_phase": "not_started"}
    tests = []
    for label, change, generation, assets, expected in [
        ("stale_generation", {}, 8, draft["asset_hashes"], "E_STALE"),
        ("stale_asset", {}, 7, {"filter.conf": "changed-again"}, "E_STALE"),
        ("unresolved_consumed_option", {"unresolved_consumers": ["custom.option"]}, 7, draft["asset_hashes"], "E_UNSUPPORTED"),
        ("external_effect_not_rollbackable", {"effect_phase": "started"}, 7, draft["asset_hashes"], "E_EFFECT_UNCERTAIN"),
        ("preserve_explicit_runtime_overlay", {}, 7, draft["asset_hashes"], None),
    ]:
        before = deepcopy(base)
        result, error = declarative_commit(base, {**draft, **change}, generation, assets)
        assert error == expected and base == before
        if error:
            assert result == base
        else:
            assert result["generation"] == 8 and result["runtime"] == base["runtime"]
        tests.append({"id": "D6-MODEL-" + label, "status": "passed", "expected_error": expected,
                      "scope": "pure design model only; not runtime reload verification"})
    states = [{"presence": "absent"}, {"presence": "explicit", "raw": ""},
              {"presence": "explicit", "raw": "None"}, {"presence": "derived", "typed": None}]
    assert len({json.dumps(state, sort_keys=True) for state in states}) == 4
    tests.append({"id": "D6-MODEL-value-presence", "status": "passed", "states": states})
    class Extension:
        reads = 0
        @property
        def property_value(self):
            type(self).reads += 1
            return "original harmless value"
    try:
        static_export(Extension())
    except ValueError as error:
        assert str(error) == "E_TRUST_REQUIRED"
    else:
        raise AssertionError("extension object admitted by static export")
    assert Extension.reads == 0
    assert static_export({"cached": "original value"}) == {"cached": "original value"}
    tests.append({"id": "D7-MODEL-static-getter-boundary", "status": "passed", "getter_calls": Extension.reads})
    assert operation_for("stop --all") == "jail.stop_all"
    assert operation_for("stop") == "service.stop"
    assert operation_for("get <JAIL> actionproperties <ACT>") == "extension.enumerate_trusted"
    assert operation_for("get <JAIL> actions") == "action.list_cached"
    try:
        operation_for("unrecognized-original-control")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown command silently mapped")
    tests.append({"id": "D7-MODEL-operation-accounting", "status": "passed",
                  "scope": "classification controls only; no legacy argv parsing or operation executed"})
    return tests


def reference_cases():
    cases = []
    for name, content, options, expected, warning in [
        ("absent-with-default", "[probe]\n", {"label": ["string", "fallback"]}, {"label": "fallback"}, False),
        ("explicit-empty", "[probe]\nlabel =\n", {"label": ["string", "fallback"]}, {"label": ""}, False),
        ("inherited-default", "[DEFAULT]\nlabel = inherited\n[probe]\n", {"label": ["string", "fallback"]}, {"label": "inherited"}, False),
        ("literal-None", "[probe]\nlabel = None\n", {"label": ["string", "fallback"]}, {"label": "None"}, False),
        ("absent-optional", "[probe]\n", {"count": ["int", None]}, {}, False),
        ("invalid-fallback", "[probe]\ncount = ordinary-invalid\n", {"count": ["int", 7]}, {"count": 7}, True),
        ("invalid-null-fallback", "[probe]\ncount = ordinary-invalid\n", {"count": ["int", None]}, {"count": None}, True),
        ("explicit-zero", "[probe]\ncount = 0\n", {"count": ["int", 7]}, {"count": 0}, False),
    ]:
        cases.append({"id": "D6-REF-" + name, "request": {"operation": "config", "options": options},
                      "fixture": content, "expected": expected, "warning_expected": warning})
    for name, command, response, expected in [
        ("ping", ["ping"], "pong", "Server replied: pong"),
        ("version-identifies-target", ["version"], "0.3.1-dev", "0.3.1-dev"),
        ("disabled-database", ["get", "dbfile"], None, "Database currently disabled"),
        ("empty-ignores", ["get", "synthetic", "ignoreip"], [], "No IP address/network is ignored"),
        ("empty-regex", ["get", "synthetic", "failregex"], [], "No regular expression is defined"),
        ("ban-separator", ["get", "synthetic", "banip", ","], ["192.0.2.10", "2001:db8::10"], "192.0.2.10,2001:db8::10"),
        ("ordered-journal-match", ["get", "synthetic", "journalmatch"], [["UNIT=one", "FIELD=two"], ["UNIT=three"]], "Current match filter:\nUNIT=one FIELD=two + UNIT=three"),
        ("stats-empty", ["stats"], {}, "No jails found."),
        ("statistics-empty", ["statistics"], {}, "No jails found."),
        ("statistic-empty-raw", ["statistic"], {}, {}),
        ("ban-empty-separator", ["get", "synthetic", "banip", ""], ["192.0.2.1", "192.0.2.2"], "192.0.2.1192.0.2.2"),
        ("ban-time-lines", ["get", "synthetic", "banip", "--with-time"], ["original timed row one", "original timed row two"], "original timed row one\noriginal timed row two"),
    ]:
        cases.append({"id": "D7-REF-" + name, "request": {"operation": "format", "command": command, "response": response},
                      "expected": expected, "warning_expected": False})
    for error, expected in [("unknown_jail", "Sorry but the jail 'synthetic' does not exist"),
                            ("duplicate_jail", "The jail 'synthetic' already exists"),
                            ("bad_arity", "Sorry but the command is invalid")]:
        cases.append({"id": "D7-REF-" + error, "request": {"operation": "format_error", "command": ["get", "synthetic"],
                      "error": error, "argument": "synthetic"}, "expected": expected, "warning_expected": False})
    cases.append({"id": "D6-REF-filter-reload-list-vs-scalar", "request": {"operation": "filter_reload"},
                  "expected": {"maxretry": 7, "findtime": 42, "maxlines": 3, "usedns": "raw",
                               "failregex": [], "ignoreregex": [], "ignoreip": []}, "warning_expected": False})
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--source-audit", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    reference = args.reference.resolve()
    reference_check(reference)
    source_hashes = {path.relative_to(reference).as_posix(): sha(path)
                     for path in sorted((reference / "fail2ban").rglob("*.py"))}
    owned = {name: sha(ROOT / name) for name in ["tests/parity/config_command_contract_probe.py", DOC,
                                               "docs/parity/runtime-contract.md", "docs/parity/fixture-contract.md"]}
    audit_hash = sha(args.source_audit)
    audit = json.loads(args.source_audit.read_text())
    if audit["reference_commit"] != PIN:
        raise ValueError("source audit reference mismatch")
    commands = map_commands(audit)
    mappings = option_mappings(audit)
    aliases = alias_mappings(audit)
    controls = schema_controls() + sqlite_controls()
    reload_rows = reload_matrix(audit)
    domains = dynamic_domains()
    results = []
    with tempfile.TemporaryDirectory(prefix="p0-config-command-") as temporary:
        work = Path(temporary)
        for case in reference_cases():
            fixture = work / case["id"]
            fixture.mkdir()
            if "fixture" in case:
                (fixture / "jail.conf").write_text(case["fixture"])
            payload = json.dumps(case["request"])
            if len(payload.encode()) > 16384:
                raise ValueError("fixture exceeds bounded input size")
            response = json.loads(run([sys.executable, "-I", "-B", "-X", f"pycache_prefix={work / 'bytecode'}",
                                       "-c", WORKER, str(reference), str(fixture)], payload=payload))
            warning = any(item["level"] == "WARNING" for item in response["diagnostics"])
            error = any(item["level"] in ("ERROR", "CRITICAL") for item in response["diagnostics"])
            equal = response["value"] == case["expected"] and warning == case["warning_expected"] and not error
            results.append({**case, "observed": response, "result": "equal" if equal else "mismatch"})
    reference_check(reference)
    if source_hashes != {path.relative_to(reference).as_posix(): sha(path) for path in sorted((reference / "fail2ban").rglob("*.py"))}:
        raise RuntimeError("reference changed during probe")
    if any(sha(ROOT / name) != value for name, value in owned.items()) or sha(args.source_audit) != audit_hash:
        raise RuntimeError("contract sources changed during probe")
    report = {"schema_version": 1, "reference_commit": PIN, "reference_source_hashes": source_hashes,
              "source_audit_sha256": audit_hash, "contract_source_hashes": owned,
              "scope": "proposed D6/D7 mappings, reference-only formatting/reader cases and pure model invariants; no candidate parity proof",
              "commands": commands, "options": mappings, "client_aliases": aliases,
              "diagnostic_options": [{**item, "structured_operation": "diagnostic.filter.evaluate", "status": "retained; semantics/capability/output fixtures required"} for item in audit["diagnostic_option_inventory"]],
              "error_taxonomy": ERRORS, "reload_property_matrix": reload_rows,
              "dynamic_parameter_domains": domains, "model_controls": controls, "reference_cases": results,
              "counts": {"commands": len(commands), "typed_options": len(mappings["typed_options"]),
                         "stock_assignments": len(mappings["stock_assignments"]), "catalog_options": len(mappings["catalog_options"]),
                         "client_aliases": len(aliases), "diagnostic_options": len(audit["diagnostic_option_inventory"]),
                         "model_controls": len(controls), "reference_equal": sum(case["result"] == "equal" for case in results),
                         "reload_properties": len(reload_rows), "dynamic_domains": len(domains),
                         "reference_mismatches": sum(case["result"] == "mismatch" for case in results)},
              "limits": ["No server/transmitter/action/getter/service operations are invoked.",
                         "Reference beautifier output values are tested; transport, stdout/stderr integration, CLI exit and full flavor matrix are not executed.",
                         "Schema transaction checks are pure design models; no atomic runtime, durability or external-effect rollback claim.",
                         "Source-inspected reload and finite/open domain contracts select behavior; P1/P2/P6 execution must verify effective consumer expansion, per-command errors, aliases and all source/profile branches."]}
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["counts"], sort_keys=True))
    return 1 if report["counts"]["reference_mismatches"] else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, AssertionError, subprocess.SubprocessError) as error:
        print(f"config/command contract error: {error}", file=sys.stderr)
        sys.exit(2)

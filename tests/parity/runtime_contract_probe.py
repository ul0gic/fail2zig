#!/usr/bin/env python3
"""Original data/transaction design probe; no upstream imports or external actions."""
import argparse
import copy
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import platform
import sqlite3
import struct
import sys
import tempfile


class ContractError(ValueError):
    pass


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def frame_decode(raw):
    if len(raw) < 4:
        raise ContractError("short_header")
    length = int.from_bytes(raw[:4], "big")
    if length > 1024 * 1024 or len(raw) != length + 4:
        raise ContractError("frame_length")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ContractError("duplicate_key")
            result[key] = value
        return result

    def nonfinite(_):
        raise ContractError("nonfinite")

    def finite_float(text):
        value = float(text)
        if not math.isfinite(value):
            raise ContractError("nonfinite")
        return value

    value = json.loads(raw[4:].decode("utf-8"), object_pairs_hook=pairs,
                       parse_constant=nonfinite, parse_float=finite_float)
    required = {"wire_version", "kind", "request_id", "daemon_epoch", "worker_epoch",
                "config_generation", "jail_id", "sequence", "capabilities", "payload"}
    if not isinstance(value, dict) or set(value) != required:
        raise ContractError("field_set")
    if type(value["wire_version"]) is not int or value["wire_version"] != 1:
        raise ContractError("version")
    if value["kind"] not in {"hello", "configure", "record", "decision", "action",
                             "result", "checkpoint", "restore", "barrier", "cancel",
                             "health", "close"}:
        raise ContractError("kind")
    if any(not isinstance(value[k], str) or not value[k] for k in
           ("request_id", "daemon_epoch", "worker_epoch", "config_generation", "jail_id")):
        raise ContractError("identity")
    seq = value["sequence"]
    if not isinstance(seq, str) or not seq.isascii() or not seq.isdigit() or str(int(seq)) != seq:
        raise ContractError("sequence")
    if value["capabilities"] != [] or not isinstance(value["payload"], dict):
        raise ContractError("capability_or_payload")
    return value


def frame(value):
    data = canonical_json(value).encode("utf-8")
    return len(data).to_bytes(4, "big") + data


def identity(kind, text):
    if kind == "raw":
        return (kind, text)
    if kind == "address":
        ip = ipaddress.ip_address(text)
        return (kind, ip.version, ip.packed.hex())
    if kind == "network":
        network = ipaddress.ip_network(text, strict=False)
        return (kind, network.version, network.network_address.packed.hex(), network.prefixlen)
    raise ContractError("identity_kind")


def ports(intervals):
    result = []
    for lo, hi in sorted(intervals):
        if type(lo) is not int or type(hi) is not int or not 0 <= lo <= hi <= 65535:
            raise ContractError("port_interval")
        if result and lo <= result[-1][1] + 1:
            result[-1][1] = max(result[-1][1], hi)
        else:
            result.append([lo, hi])
    return result


def scope(subject, selectors, namespace="production"):
    normalized = {}
    for protocol, intervals in selectors.items():
        if type(protocol) is not int or not 0 <= protocol <= 255:
            raise ContractError("protocol")
        normalized[str(protocol)] = None if intervals is None else ports(intervals)
    return canonical_json({"version": 1, "backend": "recorded-native", "subject": subject,
                           "namespace": namespace, "direction": "input", "table": "filter",
                           "chain": "owned", "interface": None, "verdict": "drop",
                           "selectors": normalized})


def timestamp_bits(value):
    if not math.isfinite(value):
        raise ContractError("nonfinite_time")
    return struct.pack(">d", value).hex()


def duration(kind, value=None):
    if kind in {"permanent", "legacy_unknown"} and value is None:
        return {"kind": kind}
    if kind == "finite" and type(value) is int and value >= 0:
        return {"kind": kind, "value": str(value)}
    raise ContractError("duration")


def handover_ready(acknowledgments, epoch, inflight, state_supported):
    required = {"sources", "filters", "failures", "tickets", "actions", "observer", "admin"}
    return (set(acknowledgments) == required and
            all(value == epoch for value in acknowledgments.values()) and
            inflight == 0 and state_supported)


def store(path):
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    connection.executescript("""
        CREATE TABLE IF NOT EXISTS records (occurrence TEXT PRIMARY KEY, event_time TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS tickets (identity TEXT PRIMARY KEY, retries INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS positions (source TEXT PRIMARY KEY, occurrence TEXT NOT NULL,
            FOREIGN KEY (occurrence) REFERENCES records(occurrence));
        CREATE TABLE IF NOT EXISTS operations (request TEXT PRIMARY KEY, generation INTEGER NOT NULL,
            desired TEXT NOT NULL, dispatched INTEGER NOT NULL DEFAULT 0,
            returned TEXT, observed TEXT);
    """)
    return connection


def ingest(connection, occurrence, before_commit=False):
    connection.execute("BEGIN")
    inserted = connection.execute("INSERT OR IGNORE INTO records VALUES (?, ?)",
                                  (occurrence, timestamp_bits(100.25))).rowcount
    if inserted:
        connection.execute("INSERT INTO tickets VALUES ('raw:demo', 1) ON CONFLICT(identity) "
                           "DO UPDATE SET retries=retries+1")
        connection.execute("INSERT INTO operations(request, generation, desired) VALUES (?, 1, 'ban')",
                           (occurrence,))
        connection.execute("INSERT INTO positions VALUES ('source', ?) ON CONFLICT(source) "
                           "DO UPDATE SET occurrence=excluded.occurrence", (occurrence,))
    if not before_commit:
        connection.commit()


def run():
    cases = []

    def equal(name, observed, expected, invariant):
        cases.append({"id": name, "invariant": invariant, "expected": expected,
                      "observed": observed, "passed": observed == expected})

    def rejects(name, function, reason):
        try:
            function()
            observed = "accepted"
        except ContractError as exc:
            observed = str(exc)
        equal(name, observed, reason, "Invalid boundary input is rejected before dispatch")

    base = {"wire_version": 1, "kind": "record", "request_id": "request-1",
            "daemon_epoch": "daemon-A", "worker_epoch": "worker-A", "config_generation": "cfg-1",
            "jail_id": "jail-A", "sequence": "9007199254740993", "capabilities": [], "payload": {}}
    equal("wire-large-sequence", frame_decode(frame(base))["sequence"], base["sequence"],
          "Sequence precision survives transport beyond binary64 integer precision")
    changed = dict(base, wire_version=2)
    rejects("wire-unknown-version", lambda: frame_decode(frame(changed)), "version")
    rejects("wire-boolean-version", lambda: frame_decode(frame(dict(base, wire_version=True))), "version")
    rejects("wire-unknown-capability", lambda: frame_decode(frame(dict(base, capabilities=["other"]))),
            "capability_or_payload")
    rejects("wire-extra-field", lambda: frame_decode(frame(dict(base, unexpected=True))), "field_set")
    rejects("wire-truncated", lambda: frame_decode(frame(base)[:-1]), "frame_length")
    duplicate = b'{"wire_version":1,"wire_version":2}'
    rejects("wire-duplicate-key", lambda: frame_decode(len(duplicate).to_bytes(4, "big") + duplicate),
            "duplicate_key")
    rejects("wire-noncanonical-sequence", lambda: frame_decode(frame(dict(base, sequence="01"))), "sequence")
    # Ordinary numeric boundaries: reject overflow at parse time, including nested data.
    decimal_frame = canonical_json(dict(base, payload={"number": "NUMBER"})).encode()
    for token, label in [(b"1.8e308", "positive"), (b"-1.8e308", "negative")]:
        encoded = decimal_frame.replace(b'"NUMBER"', token)
        rejects("wire-nonfinite-decimal-" + label,
                lambda raw=encoded: frame_decode(len(raw).to_bytes(4, "big") + raw), "nonfinite")
    finite = dict(base, payload={"number": sys.float_info.max})
    equal("wire-largest-finite", frame_decode(frame(finite))["payload"]["number"],
          sys.float_info.max, "Largest finite binary64 value remains a valid numeric payload")
    equal("identity-network-prefix", identity("network", "0.0.0.0/0") != identity("network", "0.0.0.0/32"),
          True, "Explicit prefixes distinguish subjects whose display strings can coincide")
    equal("identity-raw-separation", len({identity("raw", "Example"), identity("raw", "example"),
          identity("raw", " example"), identity("raw", "192.0.2.1"), identity("address", "192.0.2.1")}),
          5, "Raw identity is not case-folded, trimmed or retyped")
    subject = identity("address", "192.0.2.10")
    equal("scope-equivalent-intervals", scope(subject, {6: [(22, 23), (24, 25)]}),
          scope(subject, {6: [(22, 25)]}), "Equivalent numeric closed intervals canonicalize equally")
    equal("scope-protocol-pairs", scope(subject, {6: [(22, 22)], 17: [(53, 53)]}) !=
          scope(subject, {6: [(22, 22), (53, 53)], 17: [(22, 22), (53, 53)]}), True,
          "Canonicalization does not broaden protocol-port pairs")
    equal("scope-missing-all-empty", len({scope(subject, {}), scope(subject, {6: None}),
          scope(subject, {6: []})}), 3, "Absent, all and empty selectors remain distinct")
    equal("scope-namespace", scope(subject, {6: [(22, 22)]}, "A") !=
          scope(subject, {6: [(22, 22)]}, "B"), True, "Namespace is part of scope identity")
    rejects("scope-invalid-port", lambda: ports([(22, 65536)]), "port_interval")
    owners = {("jail-A", "action", "owner-A"), ("jail-B", "action", "owner-B")}
    owners.remove(("jail-A", "action", "owner-A"))
    equal("scope-owner-release", len(owners) > 0, True, "Releasing one owner does not remove another's desired effect")
    values = [100.25, 1700000000.125, -0.0, math.nextafter(60.0, math.inf)]
    equal("time-exact-roundtrip", [timestamp_bits(struct.unpack(">d", bytes.fromhex(timestamp_bits(v)))[0])
          for v in values], [timestamp_bits(v) for v in values], "Reference binary64 values survive without integer rounding")
    rejects("time-nonfinite", lambda: timestamp_bits(math.inf), "nonfinite_time")
    equal("duration-tags", [duration("finite", 0), duration("permanent"), duration("legacy_unknown")],
          [{"kind": "finite", "value": "0"}, {"kind": "permanent"}, {"kind": "legacy_unknown"}],
          "Zero, permanent and unknown history are not interchangeable")
    rejects("duration-negative-finite", lambda: duration("finite", -1), "duration")

    with tempfile.TemporaryDirectory(prefix="f2z-runtime-contract-") as temporary:
        path = Path(temporary) / "state.db"
        db = store(path)
        ingest(db, "journal-cursor-A", before_commit=True)
        db.close()  # SQLite rolls back this uncommitted transaction; not an OS crash test.
        db = store(path)
        equal("state-precommit-rollback", [db.execute("SELECT count(*) FROM " + table).fetchone()[0]
              for table in ("records", "tickets", "positions", "operations")], [0, 0, 0, 0],
              "An uncommitted record cannot leave a cursor, retry or action intent")
        ingest(db, "journal-cursor-A")
        db.close()
        db = store(path)
        ingest(db, "journal-cursor-A")
        equal("state-committed-replay", [db.execute("SELECT retries FROM tickets").fetchone()[0],
              db.execute("SELECT count(*) FROM operations").fetchone()[0]], [1, 1],
              "Replaying an already committed occurrence does not duplicate retries or intent")
        ingest(db, "journal-cursor-B")
        equal("state-same-time-occurrences", [db.execute("SELECT count(DISTINCT event_time) FROM records").fetchone()[0],
              db.execute("SELECT retries FROM tickets").fetchone()[0]], [1, 2],
              "Distinct actual source occurrences at one timestamp both count")
        db.execute("UPDATE operations SET dispatched=1 WHERE request='journal-cursor-A'")
        db.commit()
        db.close()
        db = store(path)
        dispatched, returned, observed = db.execute("SELECT dispatched, returned, observed FROM operations "
                                                    "WHERE request='journal-cursor-A'").fetchone()
        equal("state-dispatch-no-receipt", "uncertain" if dispatched and returned is None else "settled",
              "uncertain", "Dispatch without a durable receipt cannot establish effect or safe retry")
        equal("state-no-fabricated-observation", observed, None,
              "A process dispatch does not prove installed protection")
        db.close()

    desired = {"generation": 2, "state": "absent", "observed": "unknown"}
    receipt = {"generation": 1, "observed": "present"}
    after = copy.deepcopy(desired)
    if receipt["generation"] == desired["generation"]:
        after["observed"] = receipt["observed"]
    equal("state-stale-receipt", after, desired,
          "A late ban receipt cannot overwrite a newer unban intent")
    ack = dict.fromkeys(("sources", "filters", "failures", "tickets", "actions", "observer", "admin"), "epoch-A")
    equal("handover-complete-barrier", handover_ready(ack, "epoch-A", 0, True), True,
          "All writers acknowledge one epoch with supported state and no in-flight effects")
    missing = dict(ack)
    del missing["observer"]
    equal("handover-missing-observer", handover_ready(missing, "epoch-A", 0, True), False,
          "Jail/filter pause without observer acknowledgment cannot authorize export")
    equal("handover-stale-ack", handover_ready(dict(ack, actions="epoch-old"), "epoch-A", 0, True), False,
          "Acknowledgments from different barriers cannot be combined")
    equal("handover-inflight", handover_ready(ack, "epoch-A", 1, True), False,
          "Unsettled effects need a separate explicit transfer contract")
    equal("handover-unknown-extension", handover_ready(ack, "epoch-A", 0, False), False,
          "Unknown extension state blocks full-state handover")
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    if output.is_relative_to(root):
        parser.error("output must be outside the repository")
    cases = run()
    source = Path(__file__).resolve()
    report = {"schema_version": 1, "kind": "original-runtime-contract-model-probe",
              "script": str(source.relative_to(root)), "script_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
              "python": sys.version, "platform": platform.platform(), "sqlite": sqlite3.sqlite_version,
              "case_count": len(cases), "passed": sum(case["passed"] for case in cases),
              "failed": sum(not case["passed"] for case in cases), "cases": cases,
              "limits": ["Original model and SQLite transaction probe; no candidate or reference implementation parity tested",
                         "Connection-close rollback is not power-loss or OS-crash fault injection",
                         "No production IPC, process containment, action, source adapter, network or lab operation",
                         "Extension ABI and safe installation into uninstrumented live sources remain feasibility risks"]}
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ("case_count", "passed", "failed")}))
    return bool(report["failed"])


if __name__ == "__main__":
    raise SystemExit(main())

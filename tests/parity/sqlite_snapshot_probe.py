#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig maintainers
"""Exercise D5 read-only snapshots against private synthetic SQLite fixtures only."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import sqlite3
import sys
import tempfile

REFERENCE_COMMIT = "f60978618a101427b06924fc932b44350fec2b63"
# Original fixture SQL mirrors the documented columns of upstream schema v4.
# No upstream module or administrator database is opened by this program.
SCHEMA = """
CREATE TABLE fail2banDb(version INTEGER);
INSERT INTO fail2banDb VALUES(4);
CREATE TABLE jails(name TEXT NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 1);
CREATE TABLE logs(jail TEXT NOT NULL, path TEXT, firstlinemd5 TEXT,
  lastfilepos INTEGER DEFAULT 0, FOREIGN KEY(jail) REFERENCES jails(name),
  UNIQUE(jail,path));
CREATE TABLE bans(jail TEXT NOT NULL, ip TEXT, timeofban INTEGER NOT NULL,
  bantime INTEGER NOT NULL, bancount INTEGER NOT NULL DEFAULT 1, data JSON,
  FOREIGN KEY(jail) REFERENCES jails(name));
CREATE TABLE bips(ip TEXT NOT NULL, jail TEXT NOT NULL, timeofban INTEGER NOT NULL,
  bantime INTEGER NOT NULL, bancount INTEGER NOT NULL DEFAULT 1, data JSON,
  PRIMARY KEY(ip,jail), FOREIGN KEY(jail) REFERENCES jails(name));
"""
COLUMNS = {
    "fail2banDb": ["version"],
    "jails": ["name", "enabled"],
    "logs": ["jail", "path", "firstlinemd5", "lastfilepos"],
    "bans": ["jail", "ip", "timeofban", "bantime", "bancount", "data"],
    "bips": ["ip", "jail", "timeofban", "bantime", "bancount", "data"],
}
EVENTS = [
    ("sshd", "192.0.2.10", 1000, 60, 1, '{"matches":["original synthetic old failure"]}'),
    ("sshd", "192.0.2.10", 1900, 600, 2, '{"matches":["original synthetic recent failure"]}'),
    ("sshd", "2001:db8::20", 1500, -1, 1, '{"matches":[],"note":"permanent"}'),
    ("web", "192.0.2.10", 1800, 60, 1, '{"matches":["original synthetic other jail failure"]}'),
]
OBSERVATION_TIME = 2000


class ProbeFailure(RuntimeError):
    pass


class UnsupportedSchema(ProbeFailure):
    pass


def require(condition, message):
    if not condition:
        raise ProbeFailure(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hashes(path):
    # -shm is coordination state: read-only WAL readers can change read marks.
    return {suffix or "main": digest(p) if p.exists() else None
            for suffix in ("", "-wal") for p in (Path(str(path) + suffix),)}


def read_only(path):
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=1)
    connection.execute("PRAGMA trusted_schema=OFF")
    return connection


def validate_schema(connection):
    version = connection.execute("SELECT version FROM fail2banDb").fetchall()
    if version != [(4,)]:
        raise UnsupportedSchema(f"unsupported schema marker: {version!r}")
    for table, columns in COLUMNS.items():
        actual = [row[1] for row in connection.execute(f"PRAGMA table_info({table})")]
        if actual != columns:
            raise UnsupportedSchema(f"unexpected columns for {table}: {actual!r}")
    require(connection.execute("PRAGMA quick_check").fetchall() == [("ok",)],
            "fixture integrity check failed")
    require(not connection.execute("PRAGMA foreign_key_check").fetchall(),
            "fixture foreign key check failed")


def export_rows(connection):
    # Identifiers are fixed program constants, never fixture-provided SQL.
    return {table: connection.execute(
        f"SELECT * FROM {table} ORDER BY " + ",".join(map(str, range(1, len(columns) + 1)))
    ).fetchall() for table, columns in COLUMNS.items()}


def snapshot(source, destination):
    connection = read_only(source)
    try:
        connection.execute("BEGIN")
        validate_schema(connection)  # Establish read snapshot before destination exists.
        before = export_rows(connection)
        require(not destination.exists(), "staging destination already exists")
        staged = sqlite3.connect(destination, timeout=1)
        try:
            connection.backup(staged)
            validate_schema(staged)
            after = export_rows(staged)
            require(before == after, "backup/export changed normalized rows")
        finally:
            staged.close()
        return after
    finally:
        connection.close()


def create_fixture(path, journal_mode):
    writer = sqlite3.connect(path, timeout=1)
    writer.execute("PRAGMA foreign_keys=ON")
    actual_mode = writer.execute(f"PRAGMA journal_mode={journal_mode}").fetchone()[0]
    require(actual_mode.upper() == journal_mode, "requested journal mode unavailable")
    writer.execute("PRAGMA wal_autocheckpoint=0")
    writer.executescript(SCHEMA)
    if journal_mode == "WAL":
        require(writer.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0,
                "initial schema checkpoint failed")
    writer.executemany("INSERT INTO jails VALUES(?,?)", [("sshd", 1), ("web", 1)])
    writer.executemany("INSERT INTO logs VALUES(?,?,?,?)", [
        ("sshd", "/synthetic/auth.log", "synthetic-first-line-fingerprint", 123),
        ("web", "systemd-journal", "1970-01-01T00:31:40Z", 1900),
    ])
    writer.executemany("INSERT INTO bans VALUES(?,?,?,?,?,?)", EVENTS)
    for jail, ip, start, duration, count, data in EVENTS:
        writer.execute("INSERT OR REPLACE INTO bips VALUES(?,?,?,?,?,?)",
                       (ip, jail, start, duration, count, data))
    writer.commit()
    return writer


def exercise_mode(work, mode):
    directory = work / mode.lower()
    directory.mkdir(mode=0o700)
    source = directory / "source.sqlite3"
    staged = directory / "staged.sqlite3"
    writer = create_fixture(source, mode)
    try:
        before = source_hashes(source)
        if mode == "WAL":
            require(Path(str(source) + "-wal").stat().st_size > 32, "WAL lacks committed frames")
            # Only this inert copy is opened immutable; never do that to a live WAL source.
            main_only = directory / "main-only.sqlite3"
            main_only.write_bytes(source.read_bytes())
            check = sqlite3.connect(main_only.as_uri() + "?immutable=1", uri=True)
            try:
                main_count = check.execute("SELECT count(*) FROM bans").fetchone()[0]
            finally:
                check.close()
            require(main_count == 0, "fixture does not prove committed data remains WAL-only")
        else:
            main_count = len(EVENTS)
        reader = read_only(source)
        try:
            try:
                reader.execute("INSERT INTO jails VALUES('forbidden-write',1)")
            except sqlite3.OperationalError as error:
                require(error.sqlite_errorcode & 0xFF == sqlite3.SQLITE_READONLY,
                        f"write failed for an unexpected reason: {error}")
            else:
                raise ProbeFailure("mode=ro accepted source SQL mutation")
        finally:
            reader.close()
        rows = snapshot(source, staged)
        active = sorted((ip, jail, start, duration, count)
                        for ip, jail, start, duration, count, _ in rows["bips"]
                        if duration == -1 or start + duration > OBSERVATION_TIME)
        require(len(rows["bans"]) == 4 and len(rows["bips"]) == 3 and len(active) == 2,
                "event/latest/active history distinction was lost")
        require(("192.0.2.10", "sshd", 1900, 600, 2) in active,
                "original expiry or escalation count changed")
        require(("2001:db8::20", "sshd", 1500, -1, 1) in active,
                "permanent marker changed")
        require(source_hashes(source) == before, "snapshot modified source main or WAL bytes")
        # The still-open writer prevents close-time WAL checkpoints until checks finish.
        require(export_rows(writer) == rows, "snapshot modified logical source content")
        return {
            "id": f"d5-snapshot-{mode.lower()}", "result": "pass",
            "journal_mode": mode, "source_sql_write_rejected": True,
            "source_main_and_wal_unchanged": True, "source_rows_unchanged": True,
            "wal_only_committed_rows_proven": mode == "WAL", "main_only_ban_count": main_count,
            "source_sha256": before, "snapshot_sha256": digest(staged),
            "observation_time": OBSERVATION_TIME, "active_owners": active,
            "normalized_export": rows,
        }
    finally:
        writer.close()


def exercise_unknown_schema(work):
    source = work / "unknown.sqlite3"
    target = work / "must-not-exist.sqlite3"
    writer = create_fixture(source, "DELETE")
    writer.execute("UPDATE fail2banDb SET version=5")
    writer.commit()
    writer.close()
    before = source_hashes(source)
    try:
        snapshot(source, target)
    except UnsupportedSchema:
        pass
    else:
        raise ProbeFailure("unknown schema was accepted")
    require(not target.exists(), "unknown schema created staging database")
    require(source_hashes(source) == before, "unknown-schema rejection changed source")
    return {"id": "d5-unknown-schema", "result": "pass", "schema_version": 5,
            "rejected_before_staging": True, "source_unchanged": True,
            "source_sha256": before}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    script_hash = digest(Path(__file__))
    report = {
        "schema_version": 1,
        "scope": "D5 synthetic SQLite prototype only; no production exporter or transient-state proof",
        "reference_commit": REFERENCE_COMMIT,
        "reference_schema_anchor": "fail2ban/server/database.py:114",
        "fixture_schema": SCHEMA, "probe_sha256": script_hash,
        "python_version": sys.version, "sqlite_version": sqlite3.sqlite_version,
        "kernel": platform.release(),
        "namespaces": {name: os.readlink(f"/proc/self/ns/{name}") for name in ("user", "net")},
        "limits": [
            "All source databases are original synthetic fixtures created within private temporary storage.",
            "Snapshot uses mode=ro; source main/WAL hashes and logical rows are checked while fixture writer remains open.",
            "SQLite shared-memory lock/read-mark coordination is excluded from bytewise unchanged claims.",
            "No concurrent writer/lock contention, restrictive WAL directory permissions or interrupted-backup behavior tested.",
            "Exact table columns/version checked; this is not a comprehensive schema-constraint validator.",
            "No transient ticket, runtime override, action queue, source ingestion or cutover continuity proof.",
        ],
        "cases": [],
    }
    with tempfile.TemporaryDirectory(prefix="f2z-d5-sqlite-") as temporary:
        work = Path(temporary)
        report["cases"] = [exercise_mode(work, mode) for mode in ("DELETE", "WAL")]
        report["cases"].append(exercise_unknown_schema(work))
    require(digest(Path(__file__)) == script_hash, "probe source changed during run")
    report["result"] = "pass"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"{len(report['cases'])} D5 synthetic snapshot cases passed; {args.output}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, sqlite3.Error, ProbeFailure) as error:
        print(f"D5 prototype failure: {error}", file=sys.stderr)
        sys.exit(2)

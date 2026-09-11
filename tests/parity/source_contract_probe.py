#!/usr/bin/env python3
"""Compare original private journal fixtures with installed bindings/reference.

Run using a Python with systemd bindings and the pinned fail2ban production modules
on PYTHONPATH. No upstream test bodies, journal services or actions are executed.
"""
from __future__ import annotations
import argparse
import datetime
import hashlib
import inspect
import json
import pathlib
import subprocess
import types
import tempfile


def sha(path: str) -> str:
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--journal", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    from systemd import journal
    from fail2ban.server.filtersystemd import FilterSystemd
    formatter = types.SimpleNamespace(getLogEncoding=lambda: "utf-8", jailName="private-fixture")
    formatter.getJrnEntTime = lambda entry: FilterSystemd.getJrnEntTime(formatter, entry)
    cases = [
        ("all", 0, []),
        ("single", 0, ["SYSLOG_IDENTIFIER=example"]),
        ("and", 0, ["SYSLOG_IDENTIFIER=example", "PRIORITY=3"]),
        ("or", 0, ["SYSLOG_IDENTIFIER=example", "PRIORITY=3", "+", "SYSLOG_IDENTIFIER=other"]),
        ("same-field-or", 0, ["SYSLOG_IDENTIFIER=example", "SYSLOG_IDENTIFIER=other"]),
        ("negative", 0, ["SYSLOG_IDENTIFIER=unmatched"]),
    ] + [(f"flags-{flag}", flag, []) for flag in (1, 2, 4, 8, 12, 16, 32, 64)]
    results = []
    for name, flags, matches in cases:
        expected = []
        try:
            reader = journal.Reader(files=[args.journal], flags=flags)
            for match in matches:
                if match == "+":
                    reader.add_disjunction()
                else:
                    reader.add_match(match)
            reader.seek_head()
            for entry in reader:
                raw_time = entry.get("_SOURCE_REALTIME_TIMESTAMP", entry["__REALTIME_TIMESTAMP"])
                epoch = datetime.datetime(1970, 1, 1, tzinfo=raw_time.tzinfo)
                delta = raw_time - epoch
                timestamp_us = (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds
                expected.append({"message": FilterSystemd.formatJournalEntry(formatter, entry)[0][2],
                                 "cursor": entry["__CURSOR"], "timestamp_us": timestamp_us})
            reader.close()
        except ValueError:
            expected = [{"err": "InvalidJournalSelection"}]
        except OSError as exc:
            expected = [{"err": {1: "AccessDenied", 2: "FileNotFound", 13: "AccessDenied", 22: "InvalidJournalSelection"}.get(exc.errno, "JournalReadFailed")}]
        process = subprocess.run([args.candidate, args.journal, str(flags), *matches], check=True,
                                 text=True, capture_output=True, timeout=15)
        observed = [json.loads(line) for line in process.stdout.splitlines() if line]
        results.append({"case": name, "flags": flags, "matches": matches, "expected": expected,
                        "observed": observed, "agreement": observed == expected})
    from fail2ban.server.filter import FileContainer
    with tempfile.TemporaryDirectory(prefix="f2z-source-pair-") as directory:
        for encoding, framing in (("utf-8", "bytes"), ("utf-16-le", "utf16le"), ("utf-16-be", "utf16be"), ("utf-32-le", "utf32le"), ("utf-32-be", "utf32be")):
            path = pathlib.Path(directory) / (framing + ".log")
            path.write_bytes("\u010a\r\nb\npartial".encode(encoding))
            for start in ("head", "tail"):
                container = FileContainer(str(path), encoding, tail=start == "tail")
                expected = []
                if container.open():
                    while True:
                        byte_start = container.tell()
                        line = container.readline()
                        if line is None:
                            break
                        expected.append({"message": line, "byte_start": byte_start, "byte_end": container.tell()})
                    container.close()
                process = subprocess.run([args.candidate, "--file", str(path), framing, start], check=True, text=True, capture_output=True, timeout=15)
                observed = []
                for value in map(json.loads, process.stdout.splitlines()):
                    observed.append({"message": bytes.fromhex(value["message_hex"]).decode(encoding), "byte_start": value["byte_start"], "byte_end": value["byte_end"]})
                results.append({"case": f"file-{framing}-{start}", "expected": expected, "observed": observed, "agreement": expected == observed})
    evidence = {"schema": 1, "scope": "Private original file/journal source contract; no daemon or action execution",
                "candidate_sha256": sha(args.candidate), "journal_sha256": sha(args.journal),
                "source_sha256": sha(__file__),
                "reference_source": {"path": inspect.getfile(FilterSystemd), "sha256": sha(inspect.getfile(FilterSystemd))},
                "binding_source": {"path": journal.__file__, "sha256": sha(journal.__file__)},
                "cases": results,
                "agreements": sum(case["agreement"] for case in results), "case_count": len(results)}
    pathlib.Path(args.output).write_text(json.dumps(evidence, indent=2) + "\n")
    print(f'{evidence["agreements"]}/{len(results)} private file/journal agreements')
    if evidence["agreements"] != len(results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()

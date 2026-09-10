#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig maintainers
"""Inventory reference sample expectations without executing records or expressions."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


PIN = "f60978618a101427b06924fc932b44350fec2b63"
LOADER = "fail2ban/tests/samplestestcase.py"
LOGS = "fail2ban/tests/files/logs"
DIRECTIVE = re.compile(r"^#+ ?(failJSON|(?:file|filter)Options|addFILE):(.+)$")
TEST_REQUIREMENTS = {
    "zzz-generic-example": ["FLT-02-LOAD", "FLT-03-RE", "FLT-03-HOST", "FLT-04-IGNORE",
                            "TIME-02.001", "TIME-02.003"],
    "zzz-sshd-obsolete-multiline": ["FLT-02-LOAD", "FLT-02-MODES", "FLT-03-RE",
                                     "FLT-04-CAPTURE", "FLT-05-BUFFER", "FLT-05-CONTROL"],
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(args, cwd):
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True,
                          text=True, timeout=15).stdout.strip()


def check_reference(reference):
    if run(["git", "rev-parse", "HEAD"], reference) != PIN:
        raise ValueError("reference commit does not match pin")
    run(["git", "diff", "--exit-code", "HEAD", "--"], reference)
    if run(["git", "ls-files", "--others", "--exclude-standard"], reference):
        raise ValueError("reference checkout contains untracked files")


def parse_file(data, source):
    """Retain metadata and record hashes, never the sample record contents."""
    # FileContainer iterates LF-delimited records. str.splitlines() also splits
    # vertical tabs and would invent a record in the stock selinux-ssh sample.
    lines = data.decode("utf-8").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    events = []
    index = 0
    while index < len(lines):
        line = lines[index].rstrip("\r\n")
        anchor = f"{source}:{index + 1}"
        match = DIRECTIVE.match(line)
        if match:
            kind = match.group(1)
            metadata = json.loads(match.group(2))
            if kind in ("failJSON", "fileOptions") and not isinstance(metadata, dict):
                raise ValueError(f"{anchor}: {kind} must be an object")
            if kind == "filterOptions" and not (
                isinstance(metadata, dict)
                or isinstance(metadata, list) and all(isinstance(item, dict) for item in metadata)
            ):
                raise ValueError(f"{anchor}: filterOptions must contain objects")
            if kind == "addFILE" and not isinstance(metadata, str):
                raise ValueError(f"{anchor}: addFILE must name a file")
            event = {"kind": kind, "anchor": anchor, "metadata": metadata}
            if kind == "failJSON":
                index += 1
                if index >= len(lines):
                    raise ValueError(f"{anchor}: expectation has no following record")
                event["record_anchor"] = f"{source}:{index + 1}"
                event["record_sha256"] = digest(lines[index].rstrip("\r\n").encode())
            events.append(event)
        elif line.strip() and not line.startswith("#"):
            events.append({"kind": "implicit-negative", "anchor": anchor, "metadata": {},
                           "record_anchor": anchor, "record_sha256": digest(line.encode())})
        index += 1
    return events


def conjunction(*guards):
    values = []
    for guard in guards:
        if guard is False:
            return False
        if guard is not True and guard not in values:
            values.append(guard)
    return True if not values else values[0] if len(values) == 1 else {"all": values}


def expression(text, anchor, variable_scope):
    return {"expression": text, "anchor": anchor, "scope": variable_scope,
            "evaluation": "not evaluated"}


def projected_options(options):
    return {key: value for key, value in options.items() if not key.startswith("test.")}


def stock_roots(reference):
    roots = []
    # Mirrors the two source-file selection predicates at the loader footer.
    for directory, test_only in (("config/filter.d", False),
                                 ("fail2ban/tests/config/filter.d", True)):
        for path in sorted((reference / directory).iterdir()):
            selected = (path.name.startswith("zzz-") if test_only
                        else not path.name.endswith("common.conf"))
            if selected and path.name.endswith(".conf") and not path.stem.startswith("."):
                roots.append({"name": path.stem, "test_only": test_only,
                              "filter_path": path.relative_to(reference).as_posix()})
    return roots


def expand(root, files):
    """Follow append-only addFILE ordering; carry expressions as symbolic guards."""
    name = root["name"]
    catalog_requirement = None if root["test_only"] else "FLT-CAT-" + re.sub("[^A-Z0-9]+", "-", name.upper())
    requirement_ids = TEST_REQUIREMENTS.get(name, ["FLT-03"]) if root["test_only"] else [catalog_requirement]
    queue = [(name, [])]
    common = {}
    common_anchor = None
    active = []
    instances = {}
    cases = []
    variants = []
    unresolved = []
    visits = []
    processed = 0

    def instance(options, guard, anchor, order):
        filtered = projected_options(options)
        suffix = options.get("test.filter-name") or (str(filtered) if filtered else "")
        if not isinstance(suffix, str):
            raise ValueError(f"{anchor}: test.filter-name must be a string")
        key = name + suffix
        value = {"id": f"{name}:options:{len(variants) + 1}", "instance_key": key,
                 "requested_filter_options": filtered, "test_options": {
                     k: v for k, v in options.items() if k.startswith("test.")},
                 "merged_options": options, "guard": guard, "anchor": anchor,
                 "option_order": order, "file_options_anchor": common_anchor,
                 "state_continuity": "reference reuses filter instance for this key across records/files"}
        previous = instances.setdefault(key, [])
        if any(item["requested_filter_options"] != filtered for item in previous):
            unresolved.append({"kind": "instance-key-override", "anchor": anchor,
                               "instance_key": key,
                               "reason": "First constructed cached filter wins; conditions determine construction order. Requested options are not necessarily effective options."})
        if previous and any(item["guard"] is not True for item in previous + [value]):
            value["cache_construction"] = "conditional first construction unresolved"
        previous.append(value)
        variants.append(value)
        return value

    while processed < len(queue):
        filename, ancestry = queue[processed]
        processed += 1
        if processed > 1000:
            raise ValueError("addFILE expansion exceeds inventory bound")
        if filename in ancestry:
            raise ValueError(f"cyclic addFILE reference: {filename}")
        if filename not in files:
            raise ValueError(f"missing addFILE/sample file: {filename}")
        visits.append(filename)
        block_guard = True  # ignoreBlock resets for each appended file.
        for event in files[filename]["events"]:
            kind = event["kind"]
            metadata = event["metadata"]
            anchor = event["anchor"]
            if kind == "fileOptions":
                common = metadata.copy()
                common_anchor = anchor
                continue
            if kind == "filterOptions":
                active = []
                block_guard = True
                option_list = metadata if isinstance(metadata, list) else [metadata]
                for order, item in enumerate(option_list):
                    options = {**common, **item}
                    # The reference leaves ignoreBlock unchanged for an option
                    # without test.condition, rather than resetting it per item.
                    if options.get("test.condition"):
                        block_guard = expression(options["test.condition"], anchor,
                                                 {"name": name, "opts": options})
                        unresolved.append({"kind": "test.condition", "anchor": anchor,
                                           "expression": options["test.condition"],
                                           "reason": "Opaque expression retained; activation and block gating unresolved."})
                    active.append(instance(options, block_guard, anchor, order))
                continue
            if kind == "addFILE":
                path = Path(metadata)
                if path.is_absolute() or ".." in path.parts:
                    raise ValueError(f"{anchor}: addFILE must stay inside sample directory")
                queue.append((path.as_posix(), ancestry + [filename]))
                continue

            # _filterTests is populated lazily. Across addFILE boundaries its
            # preceding conditional choices may all be absent, requiring default.
            if not active:
                active = [instance({}, True, anchor, 0)]
            elif (not any(item["guard"] is True for item in active)
                  and not any(item.get("conditional_default") for item in active)):
                absent_guard = {"not_any": [item["guard"] for item in active]}
                fallback = instance({}, absent_guard, anchor, len(active))
                fallback["conditional_default"] = True
                active.append(fallback)
                unresolved.append({"kind": "conditional-default-fallback", "anchor": anchor,
                                   "reason": "If every earlier conditional instance was omitted, loader lazily selects default; preserve symbolic branch."})
            expected = dict(metadata)
            if "match" not in expected:
                expected["match"] = False
            executions = []
            for variant in active:
                constraint = True
                if metadata.get("constraint"):
                    constraint = expression(metadata["constraint"], anchor,
                                            {"name": name, "opts": variant["merged_options"]})
                guard = conjunction(block_guard, variant["guard"], constraint)
                executions.append({"variant_id": variant["id"], "instance_key": variant["instance_key"],
                                   "guard": guard, "eligibility": "unconditional" if guard is True else "unresolved-condition",
                                   "journal_time_policy": "TEST_NOW with optional test.prefix-line" if variant["merged_options"].get("logtype") == "journal" else "parse record timestamp"})
            case_id = f"{name}:{filename}:{event['record_anchor'].rsplit(':', 1)[1]}:visit{processed}"
            cases.append({"id": case_id, "root_filter": name, "test_only": root["test_only"],
                          "catalog_requirement": catalog_requirement,
                          "requirement_ids": requirement_ids,
                          "requirement_mapping": "test-filter semantic families; per-record applicability unresolved" if root["test_only"] else "stock source-catalog association; behavior unverified",
                          "source": anchor, "record_anchor": event["record_anchor"],
                          "record_sha256": event["record_sha256"], "metadata_kind": kind,
                          "expected_metadata": expected, "executions": executions,
                          "status": "inventoried-not-executed",
                          "state_note": "Original source order and prior records matter; cases are not independently replayable by default."})
    return {**root, "file_visit_order": visits, "variants": variants,
            "cases": cases, "unresolved": unresolved}


def controls():
    # Original harmless metadata controls; unknown expression deliberately stays data.
    source = b'''# fileOptions: {"mode":"normal", "logtype":"file"}
# filterOptions: [{"mode":"extra", "test.condition":"DO_NOT_EVALUATE"}, {}]
# failJSON: {"match":true, "host":"192.0.2.10"}
original ordinary record
# addFILE: "extra"
'''
    events = parse_file(source, "control/main")
    extra = parse_file(b'# filterOptions: {"mode":"journal"}\n# failJSON: {"match":false}\nordinary accepted record\n', "control/extra")
    result = expand({"name": "main", "filter_path": "control.conf", "test_only": True}, {
        "main": {"events": events}, "extra": {"events": extra}})
    assert result["file_visit_order"] == ["main", "extra"]
    assert result["variants"][0]["requested_filter_options"] == {"mode": "extra", "logtype": "file"}
    assert result["variants"][1]["guard"] == result["variants"][0]["guard"]
    assert result["cases"][0]["expected_metadata"]["match"] is True
    assert result["cases"][1]["expected_metadata"]["match"] is False
    assert "original ordinary record" not in json.dumps(result)
    assert result["cases"][0]["record_anchor"] == "control/main:4"
    assert result["cases"][0]["record_sha256"] == digest(b"original ordinary record")
    assert all(case["catalog_requirement"] is None for case in result["cases"])
    assert all(case["requirement_ids"] == ["FLT-03"] for case in result["cases"])
    assert not any("FLT-CAT-ZZZ" in requirement for requirements in TEST_REQUIREMENTS.values()
                   for requirement in requirements)
    vertical_tab = parse_file(b'ordinary\vrecord\n', "control/vertical-tab")
    assert len(vertical_tab) == 1
    assert vertical_tab[0]["record_sha256"] == digest(b"ordinary\vrecord")
    try:
        parse_file(b'# failJSON: {"match":true}\n', "control/truncated")
    except ValueError:
        pass
    else:
        raise AssertionError("orphan expectation was not rejected")
    try:
        expand({"name": "loop", "test_only": True}, {
            "loop": {"events": parse_file(b'# addFILE: "loop"\n', "control/loop")}})
    except ValueError:
        pass
    else:
        raise AssertionError("include cycle was not rejected")
    return "passed: metadata merge, conditional carry, append order, no record copy, LF-only line/hash anchors, test-only semantic mapping, malformed block and cycle controls"


def snapshot(reference):
    paths = [reference / LOADER]
    for directory in (LOGS, "config/filter.d", "fail2ban/tests/config/filter.d"):
        paths.extend(path for path in (reference / directory).rglob("*") if path.is_file())
    return {path.relative_to(reference).as_posix(): digest(path.read_bytes()) for path in sorted(paths)}


def loader_anchor(reference, text):
    lines = (reference / LOADER).read_text().splitlines()
    return f"{LOADER}:" + str(next(index for index, line in enumerate(lines, 1) if text in line))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    reference = args.reference.resolve()
    check_reference(reference)
    before = snapshot(reference)
    control_result = controls()
    files = {}
    for path in sorted((reference / LOGS).rglob("*")):
        if path.is_file():
            source = path.relative_to(reference).as_posix()
            files[path.relative_to(reference / LOGS).as_posix()] = {
                "source": source, "sha256": before[source],
                "events": parse_file(path.read_bytes(), source)}
    roots = [expand(root, files) for root in stock_roots(reference)]
    covered_files = {name for root in roots for name in root["file_visit_order"]}
    check_reference(reference)
    if before != snapshot(reference):
        raise RuntimeError("reference sources changed during inventory")
    directive_counts = Counter(event["kind"] for item in files.values() for event in item["events"])
    counts = {
        "sample_files_recursive": len(files), "loader_roots": len(roots),
        "stock_roots": sum(not root["test_only"] for root in roots),
        "test_only_roots": sum(root["test_only"] for root in roots),
        "directive_counts": dict(directive_counts),
        "expanded_record_cases": sum(len(root["cases"]) for root in roots),
        "distinct_record_anchors": len({case["record_anchor"] for root in roots for case in root["cases"]}),
        "symbolic_execution_alternatives": sum(len(case["executions"]) for root in roots for case in root["cases"]),
        "option_variants_including_defaults": sum(len(root["variants"]) for root in roots),
        "distinct_root_local_cache_keys": sum(len({variant["instance_key"] for variant in root["variants"]}) for root in roots),
        "stock_expanded_record_cases": sum(len(root["cases"]) for root in roots if not root["test_only"]),
        "stock_roots_without_declared_negative": [root["name"] for root in roots
            if not root["test_only"] and not any(not case["expected_metadata"]["match"] for case in root["cases"])],
        "symbolic_condition_or_cache_notes": sum(len(root["unresolved"]) for root in roots),
        "not_consumed_by_sample_loader": sorted(set(files) - covered_files),
    }
    report = {
        "schema_version": 1, "reference_commit": PIN, "python_version": sys.version,
        "tool_sha256": digest(Path(__file__).read_bytes()), "source_hashes": before,
        "scope": "Non-executing source inventory; no sample records, conditions, regexes or actions executed",
        "controls": control_result, "counts": counts, "files": files, "roots": roots,
        "loader_contract_anchors": {
            "instance_cache": loader_anchor(reference, "def _readFilter"),
            "configuration_stream": loader_anchor(reference, "for opt in filterConf.convert"),
            "test_option_projection": loader_anchor(reference, "def _filterOptions"),
            "file_queue_and_state": loader_anchor(reference, "filenames = [name]"),
            "metadata_directives": loader_anchor(reference, "jsonREMatch ="),
            "conditions_and_instance_keys": loader_anchor(reference, "fltName = opts.get"),
            "sample_constraints": loader_anchor(reference, "if faildata.get('constraint')"),
            "journal_prefix_time": loader_anchor(reference, "if opts.get('logtype')"),
            "pending_nofail_exclusion": loader_anchor(reference, "if fid is None"),
            "expectation_checks": loader_anchor(reference, "for k, v in faildata.items"),
            "filter_root_selection": loader_anchor(reference, "for basedir_, filter_ in")},
        "unresolved": [
            "All test.condition and constraint strings remain unevaluated symbolic guards; counts are declarations, not runnable or passing cases.",
            "Conditional default fallback branches are conservatively retained and may be logically unreachable under combined guards; no expression satisfiability is claimed.",
            "Effective regex/include/local/interpolation expansion is not performed; options are requested loader combinations, not certified normalized filter definitions.",
            "Cached instance key collisions may make first-construction options win; conditional construction and retained multiline state require runtime fixtures.",
            "Test-only roots have no stock catalog requirement. Their semantic family associations do not establish applicability or coverage for every individual record.",
            "Journal test.prefix-line mutates the loader line inside its variant loop; multiple journal variants can accumulate prefixes. Actual record transformation is intentionally not executed or reproduced.",
            "Date assertions use test-suite time setup, local conversion and optional microseconds; reproduction must preserve exact reference runtime/timezone setup.",
            "Loader scans all regexes, removes pending/nofail matches from asserted failures, and checks regex-use coverage. Metadata alone does not establish runtime coverage.",
            "Nested BSD syslog files are not consumed by this sample loader; other test-module consumers must be mapped separately.",
            "Expected metadata is retained as requested; sample record text is represented only by source anchors and hashes. No fixture redistribution or execution is authorized by this inventory.",
        ],
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    summary = {key: value for key, value in counts.items() if key != "stock_roots_without_declared_negative"}
    summary["stock_roots_without_declared_negative_count"] = len(counts["stock_roots_without_declared_negative"])
    print(json.dumps(summary, sort_keys=True))
    print(f"metadata controls passed; inventory written to {args.output}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, AssertionError, subprocess.SubprocessError) as error:
        print(f"fixture inventory error: {error}", file=sys.stderr)
        sys.exit(2)

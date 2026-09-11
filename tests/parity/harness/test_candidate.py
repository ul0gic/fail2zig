# SPDX-License-Identifier: AGPL-3.0-or-later
"""Adapter failure boundaries; actual Zig builds belong to integration runs."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

try:
    from . import candidate
except ImportError:
    import candidate


class CandidateBoundaries(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="f2z-candidate-unit-")
        self.addCleanup(self.directory.cleanup)
        self.work = Path(self.directory.name)
        self.binary = self.work / "probe"
        self.binary.write_bytes(b"fixture metadata only; never executed")
        self.context = {"work": self.work, "binaries": {kind: {
            "path": str(self.binary), "sha256": candidate._digest(self.binary)}
            for kind in ("config", "effective_config", "ssh_log", "tickets", "persistence")}}
        self.case = {"kind": "config", "input": {"files": {"jail.conf": "[probe]\nmaxretry=3\n"}}}

    def test_unimplemented_capability_is_unsupported(self):
        self.assertEqual(candidate.run_case({"kind": "filter_time"}, self.context)["status"], "unsupported")

    def test_escape_rejected_before_child(self):
        self.case["input"]["files"] = {"../outside": "bad"}
        with patch.object(candidate, "_execute") as execute:
            self.assertEqual(candidate.run_case(self.case, self.context)["status"], "error")
            execute.assert_not_called()

    def test_binary_change_rejected_before_child(self):
        self.binary.write_bytes(b"changed after build")
        with patch.object(candidate, "_execute") as execute:
            self.assertEqual(candidate.run_case(self.case, self.context)["status"], "error")
            execute.assert_not_called()

    def test_fractional_timestamp_does_not_round(self):
        case = {"kind": "tickets", "input": {"events": [1.5], "findtime": 60, "maxretry": 3}}
        self.assertEqual(candidate.run_case(case, self.context)["status"], "unsupported")

    def test_malformed_worker_json_never_passes(self):
        for stdout in ('{"value":"3","value":"4","warnings":0}',
                       '{"value":"3","warnings":true}', '[]',
                       '{"value":"3","warnings":NaN}', '{"value":"3"}'):
            with self.subTest(stdout=stdout), patch.object(candidate, "_execute", return_value=(
                    "ok", {"stdout": stdout, "stderr": "", "returncode": 0})):
                result = candidate.run_case(self.case, self.context)
                self.assertEqual(result["status"], "error")
                self.assertEqual(result["observations"], [])
                self.assertEqual(result["raw"]["stdout"], stdout)

    def test_ticket_boolean_counter_rejected(self):
        case = {"kind": "tickets", "input": {"events": [1], "findtime": 60, "maxretry": 3}}
        stdout = json.dumps({"trace": [{"pending_retry": True, "pending_last_time": 1, "threshold_reached": False}]})
        with patch.object(candidate, "_execute", return_value=("ok", {"stdout": stdout, "stderr": "", "returncode": 0})):
            self.assertEqual(candidate.run_case(case, self.context)["status"], "error")

    def test_ssh_record_requires_sanitized_ordinary_input(self):
        for line in ("sshd[1]: Failed password for real-user from 192.0.2.10 port 22 ssh2",
                     "sshd[1]: Failed password for fixture-user from 203.0.113.1 port 22 ssh2",
                     "sshd[1]: Failed password for fixture-user from 192.0.2.10 port 22 ssh2\n"):
            with self.subTest(line=line), patch.object(candidate, "_execute") as execute:
                result = candidate.run_case({"kind": "ssh_log", "input": {"line": line}}, self.context)
                self.assertEqual(result["status"], "unsupported")
                execute.assert_not_called()

    def test_ssh_conflicting_worker_decision_rejected(self):
        case = {"kind": "ssh_log", "input": {"line": "sshd[1]: Failed password for fixture-user from 192.0.2.10 port 22 ssh2"}}
        with patch.object(candidate, "_execute", return_value=("ok", {
                "stdout": '{"identity":null,"result":"matched"}', "stderr": "", "returncode": 0})):
            self.assertEqual(candidate.run_case(case, self.context)["status"], "error")

    def test_real_timeout_is_reported(self):
        status, raw = candidate._execute([sys.executable, "-I", "-c", "import time; time.sleep(5)"], self.work, timeout=0.1)
        self.assertEqual(status, "timeout")
        self.assertEqual(raw["returncode"], -9)

    def test_clean_environment(self):
        with patch.dict(os.environ, {"F2Z_SENTINEL_SECRET": "must-not-inherit", "SSH_AUTH_SOCK": "/private/socket"}):
            status, raw = candidate._execute([sys.executable, "-I", "-c", "import os,json; print(json.dumps(dict(os.environ)))"], self.work)
        self.assertEqual(status, "ok")
        environment = json.loads(raw["stdout"])
        self.assertNotIn("F2Z_SENTINEL_SECRET", environment)
        self.assertNotIn("SSH_AUTH_SOCK", environment)
        self.assertEqual(environment["TZ"], "UTC")

    def test_output_limit_even_with_successful_child(self):
        for build, size in ((False, 1024 * 1024), (True, 4 * 1024 * 1024 + 1)):
            with self.subTest(build=build):
                status, raw = candidate._execute([sys.executable, "-I", "-c",
                    f"import os; os.write(1, b'x' * {size})"], self.work, build=build)
                self.assertEqual(status, "output_limit")
                self.assertEqual(raw["returncode"], 0)
                self.assertLessEqual(len(raw["stdout"]), 4 * 1024 * 1024 if build else 1024 * 1024)

    def test_overflow_maps_to_error_with_explicit_detail(self):
        with patch.object(candidate, "_execute", return_value=("output_limit", {"stdout": "bounded prefix", "stderr": "", "returncode": 0})):
            result = candidate.run_case(self.case, self.context)
        self.assertEqual(result["status"], "error")
        self.assertTrue(result["details"]["output_limit_reached"])
        self.assertEqual(result["observations"], [])


if __name__ == "__main__":
    unittest.main()

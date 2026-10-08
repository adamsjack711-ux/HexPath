"""Integration tests for the HexPath command-line interface."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hexpath.cli import main
from hexpath.scanner import NmapScanResult


class ScanCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.scope_path = Path(self.temporary_directory.name) / "scope.json"
        self.scope_path.write_text(
            json.dumps({"name": "loopback", "targets": ["::1/128"]}),
            encoding="utf-8",
        )

    def test_plan_prints_validated_command(self) -> None:
        output = StringIO()

        with redirect_stdout(output):
            exit_code = main(
                [
                    "scan",
                    "plan",
                    "--scope",
                    str(self.scope_path),
                    "::1",
                ]
            )

        self.assertEqual(exit_code, 0)
        self.assertIn("nmap -6", output.getvalue())
        self.assertIn("::1/128", output.getvalue())

    @patch("hexpath.cli.parse_nmap_xml")
    @patch("hexpath.cli.run_nmap", return_value="<nmaprun/>")
    def test_run_prints_normalized_json(self, _run_mock, parse_mock) -> None:
        parse_mock.return_value = NmapScanResult(hosts=(), services=())
        output = StringIO()

        with redirect_stdout(output):
            exit_code = main(
                [
                    "scan",
                    "run",
                    "--scope",
                    str(self.scope_path),
                    "--timeout",
                    "10",
                    "::1",
                ]
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(json.loads(output.getvalue()), {"hosts": [], "services": []})

    def test_plan_reports_out_of_scope_target(self) -> None:
        errors = StringIO()

        with redirect_stderr(errors):
            exit_code = main(
                [
                    "scan",
                    "plan",
                    "--scope",
                    str(self.scope_path),
                    "2001:db8::1",
                ]
            )

        self.assertEqual(exit_code, 2)
        self.assertIn("outside authorized scope", errors.getvalue())


if __name__ == "__main__":
    unittest.main()

"""Regression coverage for target-first invocation; never runs a network scan."""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from hexpath.cli import main
from hexpath.state import load_latest_scan
from hexpath.vulnerabilities import CpeIdentity, CpeVulnerabilityResult, ScanVulnerabilityResult

FIXTURE = (Path(__file__).parent / "fixtures/nmap_ipv6_sample.xml").read_text()


class DirectCliTests(unittest.TestCase):
    def setUp(self):
        self.state_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.state_directory.cleanup)
        state_environment = patch.dict(
            os.environ,
            {"HEXPATH_STATE_DIR": self.state_directory.name},
        )
        state_environment.start()
        self.addCleanup(state_environment.stop)

    def call(self, arguments):
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(arguments)
        return code, stdout.getvalue(), stderr.getvalue()

    @patch("hexpath.direct_cli.check_scan_documents")
    @patch("hexpath.direct_cli.run_nmap", return_value=FIXTURE)
    def test_no_cves_scans_and_prints_readable_results_without_cve_requests(self, run, cves):
        code, output, _ = self.call(["2001:db8:1::10", "--no-cves"])
        self.assertEqual(code, 0)
        command = run.call_args.args[0]
        self.assertEqual(command.targets, ("2001:db8:1::10/128",))
        self.assertIn("-sT", command.arguments)
        self.assertNotIn("-sV", command.arguments)
        self.assertIn("22/tcp", output)
        self.assertIn("OpenSSH 9.6", output)
        self.assertIn("open|filtered", output)
        self.assertNotIn("80/tcp", output)
        self.assertIn("CVE lookup skipped", output)
        cves.assert_not_called()

    @patch("hexpath.direct_cli.run_nmap")
    def test_plan_addons_work_before_or_after_target_without_scanning(self, run):
        for arguments in (
            ["192.0.2.10", "-sV", "-O", "-p", "22,443", "-Pn", "--plan"],
            ["-sV", "-O", "-p22,443", "-Pn", "192.0.2.10", "--plan"],
        ):
            code, output, _ = self.call(arguments)
            self.assertEqual(code, 0)
            for flag in ("-sV", "-O", "-p 22,443", "-Pn", "192.0.2.10/32"):
                self.assertIn(flag, output)
        run.assert_not_called()

    @patch("hexpath.direct_cli.run_nmap")
    def test_smb_vuln_flag_adds_safe_scripts_without_scanning(self, run):
        code, output, _ = self.call(["192.0.2.10", "--smb-vuln", "-Pn", "--plan"])
        self.assertEqual(code, 0)
        self.assertIn("--script smb-vuln-ms17-010", output)
        run.assert_not_called()

    def test_smb_vuln_absent_by_default(self):
        code, output, _ = self.call(["192.0.2.10", "--plan"])
        self.assertEqual(code, 0)
        self.assertNotIn("--script", output)

    def test_no_cves_can_keep_explicit_version_probes(self):
        for version_flags, detect_versions in (([], False), (["-sV"], True)):
            with self.subTest(version_flags=version_flags):
                code, output, error = self.call(["192.0.2.10", "-p-", "--plan", "--no-cves", *version_flags])
                self.assertEqual(code, 0)
                self.assertIn("-p 1-65535", output)
                self.assertEqual("-sV" in output, detect_versions)
                self.assertEqual(error, "")

    @patch("hexpath.direct_cli.run_nmap")
    def test_invalid_or_unsafe_inputs_never_run_nmap(self, run):
        for arguments in (
            ["192.0.2.10", "-p", "0"], ["10.0.0.0/8"], ["2001:db8::/32"],
            ["192.0.2.0/24", "-6"], ["192.0.2.10", "2001:db8::10"],
            ["192.0.2.10", "--timeout", "0"], ["192.0.2.3/24"],
        ):
            with self.subTest(arguments=arguments):
                code, _, error = self.call(arguments)
                self.assertEqual(code, 2)
                self.assertIn("error:", error)
        run.assert_not_called()

    @patch("hexpath.direct_cli.run_nmap")
    def test_optional_scope_is_enforced(self, run):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "scope.json"
            path.write_text(json.dumps({"name": "lab", "targets": ["192.0.2.10/32"]}))
            code, _, error = self.call(["192.0.2.11", "--scope", str(path)])
        self.assertEqual(code, 2)
        self.assertIn("outside authorized scope", error)
        run.assert_not_called()

    @patch("hexpath.direct_cli.socket.getaddrinfo")
    def test_hostname_resolved_once_and_pinned_to_validated_ip(self, resolve):
        resolve.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 0))]
        code, output, _ = self.call(["lab.example", "--plan"])
        self.assertEqual(code, 0)
        self.assertIn("192.0.2.10/32", output)
        self.assertNotIn("lab.example", output)
        resolve.assert_called_once()

    @patch("hexpath.direct_cli.check_scan_documents")
    @patch("hexpath.direct_cli.run_nmap", return_value=FIXTURE)
    def test_scan_looks_up_cves_by_default_and_reports_incomplete_coverage(self, run, cves):
        result = ScanVulnerabilityResult((), (), (), 1, ("unknown-service",))
        cves.return_value = result
        for flags in ([], ["--cves"]):
            with self.subTest(flags=flags):
                cves.reset_mock()
                code, output, _ = self.call(["2001:db8:1::10", *flags])
                self.assertEqual(code, 2)
                self.assertIn("-sV", run.call_args.args[0].arguments)
                self.assertIn("Coverage incomplete", output)
                cves.assert_called_once()
                self.assertEqual(load_latest_scan()["cves"], result.to_dict())

    @patch("hexpath.direct_cli.check_scan_documents")
    @patch("hexpath.direct_cli.run_nmap", return_value=FIXTURE)
    def test_default_json_and_saved_results_include_cves(self, run, cves):
        check = CpeVulnerabilityResult(CpeIdentity("cpe:/a:openbsd:openssh:9.6"), True)
        result = ScanVulnerabilityResult((check,), (), (), 1)
        cves.return_value = result
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "scan.json"
            code, output, error = self.call(["2001:db8:1::10", "--json", "-o", str(path)])
            document = json.loads(output)
            self.assertEqual(json.loads(path.read_text()), document)
        self.assertEqual(code, 0)
        self.assertIn("hosts", document)
        self.assertIn("services", document)
        self.assertEqual(document["cves"], result.to_dict())
        cves.assert_called_once()
        self.assertEqual(document["scope"]["targets"], ["2001:db8:1::10/128"])
        self.assertEqual(load_latest_scan(), document)
        self.assertIn("Scanning", error)

    @patch("hexpath.direct_cli.run_nmap")
    def test_no_arguments_show_quick_help_without_scanning(self, run):
        code, output, _ = self.call([])
        self.assertEqual(code, 0)
        self.assertIn("TARGET", output)
        self.assertIn("--cves", output)
        self.assertIn("hexpath path", output)
        run.assert_not_called()

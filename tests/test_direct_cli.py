"""Regression coverage for target-first invocation; never runs a network scan."""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from hexpath.cli import main
from hexpath.direct_cli import render_result
from hexpath.vulnerabilities import ScanVulnerabilityResult

FIXTURE = (Path(__file__).parent / "fixtures/nmap_ipv6_sample.xml").read_text()


class DirectCliTests(unittest.TestCase):
    def call(self, arguments):
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(arguments)
        return code, stdout.getvalue(), stderr.getvalue()

    @patch("hexpath.direct_cli.check_scan_documents")
    @patch("hexpath.direct_cli.run_nmap", return_value=FIXTURE)
    def test_bare_target_scans_and_prints_readable_results_without_cve_requests(self, run, cves):
        code, output, _ = self.call(["2001:db8:1::10"])
        self.assertEqual(code, 0)
        command = run.call_args.args[0]
        self.assertEqual(command.targets, ("2001:db8:1::10/128",))
        self.assertIn("-sT", command.arguments)
        self.assertNotIn("-sV", command.arguments)
        self.assertIn("22/tcp", output)
        self.assertIn("OpenSSH 9.6", output)
        self.assertIn("Information grade: C (50.0/100)", output)
        self.assertIn("Next: Run --cves", output)
        self.assertIn("open|filtered", output)
        self.assertNotIn("80/tcp", output)
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

    def test_custom_ports_do_not_silently_enable_version_probes(self):
        code, output, _ = self.call(["192.0.2.10", "-p-", "--plan"])
        self.assertEqual(code, 0)
        self.assertIn("-p 1-65535", output)
        self.assertNotIn("-sV", output)

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
    def test_cve_option_enables_versions_and_reports_incomplete_coverage(self, run, cves):
        cves.return_value = ScanVulnerabilityResult((), (), (), 1, ("unknown-service",))
        code, output, _ = self.call(["2001:db8:1::10", "--cves"])
        self.assertEqual(code, 2)
        self.assertIn("-sV", run.call_args.args[0].arguments)
        self.assertIn("Coverage incomplete", output)
        cves.assert_called_once()

    @patch("hexpath.direct_cli.run_nmap", return_value=FIXTURE)
    def test_json_and_saved_results_are_clean_and_keep_scan_document_shape(self, run):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "scan.json"
            code, output, error = self.call(["2001:db8:1::10", "--json", "-o", str(path)])
            document = json.loads(output)
            self.assertEqual(json.loads(path.read_text()), document)
        self.assertEqual(code, 0)
        self.assertIn("hosts", document)
        self.assertIn("services", document)
        self.assertEqual(document["host_grades"]["2001:db8:1::10"]["grade"], "C")
        self.assertEqual(document["scope"]["targets"], ["2001:db8:1::10/128"])
        self.assertIn("Scanning", error)

    @patch("hexpath.direct_cli.run_nmap")
    def test_no_arguments_show_quick_help_without_scanning(self, run):
        code, output, _ = self.call([])
        self.assertEqual(code, 0)
        self.assertIn("TARGET", output)
        self.assertIn("--cves", output)
        run.assert_not_called()

    def test_direct_summary_labels_os_guess_and_sanitizes_terminal_controls(self):
        document = {
            "hosts": [{
                "address": "2001:db8::10", "os_name": "Linux\x1b[2J",
                "os_accuracy": 93, "cpes": ["cpe:/o:linux:linux_kernel:5"],
            }],
            "services": [],
        }
        rendered = render_result(document)
        self.assertIn("OS fingerprint guess", rendered)
        self.assertIn("OS CPEs (broad)", rendered)
        self.assertIn("patch level unverified", rendered)
        self.assertNotIn("\x1b", rendered)

    def test_next_check_moves_beyond_generic_probe_when_version_stays_broad(self):
        document = {
            "hosts": [{"address": "2001:db8::10"}],
            "services": [{
                "host": "2001:db8::10", "port": 21, "protocol": "tcp",
                "state": "open", "name": "ftp", "version": "2.0 or later",
            }],
            "command": ["nmap", "-6", "-sV", "2001:db8::10"],
            "host_grades": {"2001:db8::10": {
                "grade": "D", "score": 0.0, "open_services": 1,
                "services_with_exact_cpe": 0,
                "services_with_completed_cve_check": 0,
            }},
        }
        rendered = render_result(document)
        self.assertIn("protocol-specific query or trusted inventory", rendered)
        self.assertNotIn("Next: Add -sV", rendered)

    def test_cve_summary_groups_candidates_by_host_and_bounds_readable_output(self):
        document = {
            "hosts": [{"address": "2001:db8::10"}, {"address": "2001:db8::20"}],
            "services": [
                {"id": "service:[2001:db8::10]:tcp:80", "host": "2001:db8::10",
                 "port": 80, "protocol": "tcp", "state": "open", "name": "http"},
                {"id": "service:[2001:db8::20]:tcp:22", "host": "2001:db8::20",
                 "port": 22, "protocol": "tcp", "state": "open", "name": "ssh"},
            ],
            "cves": {
                "matches": [
                    {"service_id": "service:[2001:db8::10]:tcp:80", "cve_id": f"CVE-2026-{i}"}
                    for i in range(1001, 1006)
                ] + [{"service_id": "service:[2001:db8::20]:tcp:22", "cve_id": "CVE-2026-2001"}],
                "vulnerabilities": [
                    {"id": f"CVE-2026-{i}", "cvss_score": float(i - 1000),
                     "description": "Long finding description that belongs in JSON"}
                    for i in range(1001, 1006)
                ],
                "coverage": {"completed_cpe_checks": 1, "cpe_checks": 2, "invalid_cpes": 1},
                "completed": False,
            },
        }
        rendered = render_result(document)
        first, second = rendered.split("Host: 2001:db8::20", 1)
        self.assertIn("CVE candidates: 5", first)
        self.assertIn("2 more candidate(s); use --json or -o", first)
        self.assertNotIn("CVE-2026-2001", first)
        self.assertIn("CVE candidates: 1", second)
        self.assertIn("CVE-2026-2001", second)
        self.assertNotIn("Long finding description", rendered)
        self.assertIn("Coverage incomplete", rendered)

    def test_host_with_no_open_selected_port_is_not_called_unreachable(self):
        document = {
            "hosts": [{"address": "2001:db8::30"}], "services": [],
            "host_grades": {"2001:db8::30": {
                "grade": "U", "score": None, "open_services": 0,
                "services_with_exact_cpe": 0, "services_with_completed_cve_check": 0,
            }},
        }
        rendered = render_result(document)
        self.assertIn("Host responded; confirm the selected port set", rendered)
        self.assertNotIn("Confirm reachability", rendered)

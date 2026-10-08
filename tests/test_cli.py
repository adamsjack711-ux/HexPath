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
from hexpath.vulnerabilities import (
    CpeIdentity,
    CpeVulnerabilityResult,
    OsvAdvisory,
    PackageIdentity,
    PackageVulnerabilityResult,
    ScanVulnerabilityResult,
)


class QuickCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.directory = Path(self.temporary_directory.name)
        self.scope_path = self.directory / "scope.json"
        self.scope_path.write_text(
            json.dumps({"name": "loopback", "targets": ["::1/128"]}),
            encoding="utf-8",
        )

    def test_scope_init_creates_default_format(self) -> None:
        output_path = self.directory / "new-scope.json"
        output = StringIO()

        with redirect_stdout(output):
            exit_code = main(
                [
                    "scope",
                    "init",
                    "2001:db8:1::/64",
                    "--name",
                    "Lab",
                    "-o",
                    str(output_path),
                ]
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            json.loads(output_path.read_text(encoding="utf-8")),
            {"name": "Lab", "targets": ["2001:db8:1::/64"]},
        )
        self.assertIn("Created", output.getvalue())

    @patch("hexpath.cli.check_scan_documents")
    @patch("hexpath.cli.parse_nmap_xml")
    @patch("hexpath.cli.run_nmap", return_value="<nmaprun/>")
    def test_direct_target_runs_complete_ascii_workflow(
        self,
        run_mock,
        parse_mock,
        check_mock,
    ) -> None:
        parse_mock.return_value = NmapScanResult(hosts=(), services=())
        check_mock.return_value = ScanVulnerabilityResult(
            checks=(),
            vulnerabilities=(),
            matches=(),
            service_count=0,
        )
        result_path = self.directory / "result.json"
        output = StringIO()

        with redirect_stdout(output):
            exit_code = main(
                [
                    "--scope",
                    str(self.scope_path),
                    "-6",
                    "-sV",
                    "-oJ",
                    str(result_path),
                    "::1",
                ]
            )

        self.assertEqual(exit_code, 0)
        self.assertIn("HexPath Network Topology", output.getvalue())
        self.assertIn("CVE coverage: 0/0", output.getvalue())
        self.assertIn("Saved JSON:", output.getvalue())
        result = json.loads(result_path.read_text(encoding="utf-8"))
        self.assertEqual(result["schema_version"], 1)
        self.assertEqual(result["scan"]["vantage"], "entry:scanner")
        self.assertEqual(result["graph"]["nodes"][0]["id"], "entry:scanner")
        self.assertIn("-sV", run_mock.call_args.args[0].arguments)
        parse_mock.assert_called_once_with(
            "<nmaprun/>",
            reference="live-nmap",
            vantage="entry:scanner",
        )

    def test_direct_target_explains_how_to_create_missing_scope(self) -> None:
        errors = StringIO()

        with redirect_stderr(errors):
            exit_code = main(
                [
                    "--scope",
                    str(self.directory / "missing.json"),
                    "::1",
                ]
            )

        self.assertEqual(exit_code, 2)
        self.assertIn("hexpath scope init", errors.getvalue())

    @patch("hexpath.cli.check_scan_documents")
    @patch("hexpath.cli.parse_nmap_xml")
    @patch("hexpath.cli.run_nmap", return_value="<nmaprun/>")
    def test_inline_scope_cidr_needs_no_scope_file(
        self,
        _run_mock,
        parse_mock,
        check_mock,
    ) -> None:
        parse_mock.return_value = NmapScanResult(hosts=(), services=())
        check_mock.return_value = ScanVulnerabilityResult(
            checks=(),
            vulnerabilities=(),
            matches=(),
            service_count=0,
        )

        with redirect_stdout(StringIO()):
            exit_code = main(["--scope", "::1/128", "::1"])

        self.assertEqual(exit_code, 0)

    @patch("hexpath.cli.check_scan_documents")
    @patch("hexpath.cli.parse_nmap_xml")
    @patch("hexpath.cli.run_nmap", return_value="<nmaprun/>")
    def test_from_accepts_plain_authorized_ipv6_address(
        self,
        _run_mock,
        parse_mock,
        check_mock,
    ) -> None:
        parse_mock.return_value = NmapScanResult(
            hosts=(),
            services=(),
            vantage="host:::1",
        )
        check_mock.return_value = ScanVulnerabilityResult(
            checks=(),
            vulnerabilities=(),
            matches=(),
            service_count=0,
        )
        output = StringIO()

        with redirect_stdout(output):
            exit_code = main(
                [
                    "--scope",
                    str(self.scope_path),
                    "--from",
                    "::1",
                    "::1",
                ]
            )

        self.assertEqual(exit_code, 0)
        self.assertIn("[VANTAGE] ::1 <host:::1>", output.getvalue())
        self.assertIn("(no hosts discovered)", output.getvalue())
        scan_document = check_mock.call_args.args[0][0]
        self.assertEqual(scan_document["vantage"], "host:::1")
        self.assertEqual(scan_document["hosts"][0]["id"], "host:::1")


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
        self.assertEqual(
            json.loads(output.getvalue()),
            {"vantage": "entry:scanner", "hosts": [], "services": []},
        )

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


class CveCliTests(unittest.TestCase):
    @patch("hexpath.cli.check_package")
    def test_package_check_prints_provider_result(self, check_mock) -> None:
        package = PackageIdentity(ecosystem="PyPI", name="jinja2", version="2.4.1")
        check_mock.return_value = PackageVulnerabilityResult(
            package=package,
            completed=True,
            advisories=(
                OsvAdvisory(
                    advisory_id="PYSEC-2021-66",
                    aliases=("CVE-2020-28493",),
                    summary="Example OSV result.",
                ),
            ),
        )
        output = StringIO()

        with redirect_stdout(output):
            exit_code = main(
                [
                    "cve",
                    "package",
                    "--ecosystem",
                    "PyPI",
                    "--package",
                    "jinja2",
                    "--version",
                    "2.4.1",
                ]
            )

        document = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(document["status"], "vulnerable")
        self.assertEqual(document["vulnerabilities"][0]["id"], "CVE-2020-28493")

    @patch("hexpath.cli.check_package")
    def test_package_check_returns_failure_for_unknown_coverage(self, check_mock) -> None:
        package = PackageIdentity(ecosystem="npm", name="demo", version="1.0.0")
        check_mock.return_value = PackageVulnerabilityResult(
            package=package,
            completed=False,
            error="OSV request timed out",
        )
        output = StringIO()

        with redirect_stdout(output):
            exit_code = main(
                [
                    "cve",
                    "package",
                    "--ecosystem",
                    "npm",
                    "--package",
                    "demo",
                    "--version",
                    "1.0.0",
                ]
            )

        self.assertEqual(exit_code, 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "unknown")

    @patch("hexpath.cli.check_cpe")
    def test_cpe_check_prints_nvd_result(self, check_mock) -> None:
        cpe = CpeIdentity("cpe:/a:openbsd:openssh:9.6")
        check_mock.return_value = CpeVulnerabilityResult(
            cpe=cpe,
            completed=True,
            vulnerabilities=(),
        )
        output = StringIO()

        with redirect_stdout(output):
            exit_code = main(
                [
                    "cve",
                    "cpe",
                    "--cpe",
                    "cpe:/a:openbsd:openssh:9.6",
                ]
            )

        document = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(document["source"], "NVD")
        self.assertEqual(document["status"], "clean")
        self.assertEqual(document["cpe"], "cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*")

    @patch("hexpath.cli.check_scan_documents")
    def test_scan_check_reads_normalized_scan_json(self, check_mock) -> None:
        check_mock.return_value = ScanVulnerabilityResult(
            checks=(),
            vulnerabilities=(),
            matches=(),
            service_count=0,
        )
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        input_path = Path(temporary_directory.name) / "scan.json"
        input_path.write_text('{"hosts": [], "services": []}', encoding="utf-8")
        output = StringIO()

        with redirect_stdout(output):
            exit_code = main(["cve", "scan", "--input", str(input_path)])

        self.assertEqual(exit_code, 0)
        self.assertEqual(json.loads(output.getvalue())["status"], "clean")
        check_mock.assert_called_once()
        self.assertEqual(len(check_mock.call_args.args[0]), 1)

    @patch("hexpath.cli.check_scan_documents")
    def test_scan_check_accepts_multiple_vantage_files(self, check_mock) -> None:
        check_mock.return_value = ScanVulnerabilityResult(
            checks=(),
            vulnerabilities=(),
            matches=(),
            service_count=0,
        )
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        first_path = Path(temporary_directory.name) / "first.json"
        second_path = Path(temporary_directory.name) / "second.json"
        first_path.write_text('{"hosts": [], "services": []}', encoding="utf-8")
        second_path.write_text('{"hosts": [], "services": []}', encoding="utf-8")

        with redirect_stdout(StringIO()):
            exit_code = main(
                [
                    "cve",
                    "scan",
                    "--input",
                    str(first_path),
                    "--input",
                    str(second_path),
                ]
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(len(check_mock.call_args.args[0]), 2)


class GraphCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.directory = Path(self.temporary_directory.name)

    def test_build_writes_attack_graph_json(self) -> None:
        scan_path = self.directory / "scan.json"
        cve_path = self.directory / "cves.json"
        scan_path.write_text('{"hosts":[],"services":[]}', encoding="utf-8")
        cve_path.write_text(
            '{"vulnerabilities":[],"matches":[]}',
            encoding="utf-8",
        )
        output = StringIO()

        with redirect_stdout(output):
            exit_code = main(
                [
                    "graph",
                    "build",
                    "--scan",
                    str(scan_path),
                    "--cves",
                    str(cve_path),
                    "--json",
                ]
            )

        document = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(document["nodes"][0]["id"], "entry:scanner")
        self.assertEqual(document["edges"], [])

    def test_path_reads_graph_and_runs_dijkstra(self) -> None:
        graph_path = self.directory / "graph.json"
        graph_path.write_text(
            json.dumps(
                {
                    "nodes": [
                        {"id": "entry:scanner", "kind": "entry", "label": "entry"},
                        {"id": "host:target", "kind": "host", "label": "target"},
                    ],
                    "edges": [
                        {
                            "id": "edge-1",
                            "source": "entry:scanner",
                            "target": "host:target",
                            "relationship": "transition",
                            "weight": 2.5,
                            "description": "test transition",
                            "evidence": [
                                {
                                    "source": "test",
                                    "summary": "test evidence",
                                    "level": "observed",
                                    "collected_at": "2026-10-08T18:30:00+00:00",
                                    "reference": None,
                                }
                            ],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        output = StringIO()

        with redirect_stdout(output):
            exit_code = main(
                [
                    "graph",
                    "path",
                    "--graph",
                    str(graph_path),
                    "--target",
                    "host:target",
                    "--json",
                ]
            )

        document = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(document["nodes"], ["entry:scanner", "host:target"])
        self.assertEqual(document["total_weight"], 2.5)

    def test_show_renders_ascii_graph(self) -> None:
        graph_path = self.directory / "graph.json"
        graph_path.write_text(
            json.dumps(
                {
                    "nodes": [
                        {"id": "entry:scanner", "kind": "entry", "label": "entry"},
                        {"id": "host:target", "kind": "host", "label": "target"},
                    ],
                    "edges": [
                        {
                            "id": "edge-1",
                            "source": "entry:scanner",
                            "target": "host:target",
                            "relationship": "candidate_exploit",
                            "weight": 2.5,
                            "description": "test transition",
                            "evidence": [
                                {
                                    "source": "test",
                                    "summary": "test evidence",
                                    "level": "observed",
                                    "collected_at": "2026-10-08T18:30:00+00:00",
                                    "reference": None,
                                }
                            ],
                            "metadata": {"cve_id": "CVE-2026-12345"},
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        output = StringIO()

        with redirect_stdout(output):
            exit_code = main(["graph", "show", "--graph", str(graph_path)])

        rendered = output.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertIn("HexPath Attack Graph", rendered)
        self.assertIn("+--", rendered)
        self.assertIn("-->", rendered)
        self.assertIn("CVE-2026-12345", rendered)


if __name__ == "__main__":
    unittest.main()

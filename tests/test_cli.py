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
from hexpath.models import Evidence, Host, Service
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

    @patch("hexpath.cli.run_nmap")
    def test_selected_target_is_scope_checked_before_scanning(self, run_mock) -> None:
        errors = StringIO()
        with redirect_stderr(errors):
            code = main([
                "--scope", str(self.scope_path), "--target", "2001:db8::2", "::1",
            ])
        self.assertEqual(code, 2)
        self.assertIn("outside authorized scope", errors.getvalue())
        run_mock.assert_not_called()

    @patch("hexpath.cli.check_scan_documents")
    @patch("hexpath.cli.parse_nmap_xml")
    @patch("hexpath.cli.run_nmap", return_value="<nmaprun/>")
    def test_selected_target_prints_and_saves_candidate_route(
        self, _run_mock, parse_mock, check_mock,
    ) -> None:
        observed = Evidence(source="test", summary="observed service", level="observed")
        inferred = Evidence(source="test", summary="CPE candidate", level="inferred")
        service = Service(host="::1", port=22, protocol="tcp", state="open", evidence=(observed,))
        parse_mock.return_value = NmapScanResult(
            hosts=(Host(address="::1", evidence=(observed,)),), services=(service,),
        )
        check_mock.return_value.to_dict.return_value = {
            "vulnerabilities": [{"id": "CVE-2026-12345", "cvss_score": 9.0}],
            "matches": [{
                "service_id": service.record_id, "cve_id": "CVE-2026-12345",
                "confidence": "medium", "reason": "Candidate CPE match",
                "evidence": [inferred.to_dict()],
            }],
            "coverage": {"services_with_cpe": 0, "services": 1},
        }
        check_mock.return_value.matches = (object(),)
        result_path = self.directory / "candidate.json"
        output = StringIO()
        with redirect_stdout(output):
            code = main([
                "--scope", str(self.scope_path), "--target", "::1", "--paths", "2",
                "-oJ", str(result_path), "::1",
            ])
        self.assertEqual(code, 0)
        self.assertIn("HexPath Network Topology", output.getvalue())
        self.assertIn("HexPath Path Comparison", output.getvalue())
        document = json.loads(result_path.read_text())
        self.assertEqual(document["path_comparison"]["requested_paths"], 2)
        self.assertEqual(document["path_comparison"]["paths"][0]["total_weight"], 4.5)

    @patch("hexpath.cli.check_scan_documents")
    @patch("hexpath.cli.parse_nmap_xml")
    @patch("hexpath.cli.run_nmap", return_value="<nmaprun/>")
    def test_selected_host_without_candidate_path_saves_empty_comparison(
        self, _run_mock, parse_mock, check_mock,
    ) -> None:
        parse_mock.return_value = NmapScanResult(
            hosts=(Host(address="::1", evidence=(Evidence(source="test", summary="observed", level="observed"),)),),
            services=(),
        )
        check_mock.return_value = ScanVulnerabilityResult(
            checks=(), vulnerabilities=(), matches=(), service_count=0,
        )
        result_path = self.directory / "selected.json"
        output = StringIO()
        with redirect_stdout(output):
            code = main([
                "--scope", str(self.scope_path), "--target", "host:::1",
                "-oJ", str(result_path), "--json", "::1",
            ])
        self.assertEqual(code, 1)
        document = json.loads(output.getvalue())
        self.assertEqual(document["path_comparison"], {
            "source": "entry:scanner", "target": "host:::1", "paths": [], "requested_paths": 3,
        })
        self.assertEqual(document, json.loads(result_path.read_text()))

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

    def test_scope_init_accepts_both_address_families(self) -> None:
        output_path = self.directory / "dual-stack-scope.json"

        with redirect_stdout(StringIO()):
            exit_code = main(
                [
                    "scope",
                    "init",
                    "192.0.2.0/24",
                    "2001:db8:1::/64",
                    "-o",
                    str(output_path),
                ]
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            json.loads(output_path.read_text(encoding="utf-8"))["targets"],
            ["192.0.2.0/24", "2001:db8:1::/64"],
        )

    @patch("hexpath.cli.collect_server_inventory")
    def test_inventory_prints_ascii_and_saves_json(self, collect_mock) -> None:
        collect_mock.return_value = {
            "source": "server-inventory",
            "server": "aiserver",
            "connection": "aiserver",
            "system": {"os": "Ubuntu", "kernel": "Linux"},
            "interfaces": [],
            "listening_services": [],
            "networks": [],
            "vms": [],
            "container_networks": [],
            "containers": [],
        }
        result_path = self.directory / "inventory.json"
        output = StringIO()

        with redirect_stdout(output):
            exit_code = main(["inventory", "aiserver", "-oJ", str(result_path)])

        self.assertEqual(exit_code, 0)
        self.assertIn("HexPath Full Server Topology", output.getvalue())
        self.assertIn("Saved JSON:", output.getvalue())
        document = json.loads(result_path.read_text(encoding="utf-8"))
        self.assertEqual(document["schema_version"], 1)
        self.assertEqual(document["server"], "aiserver")
        collect_mock.assert_called_once_with(ssh_host="aiserver", timeout_seconds=20)

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
                    "-Pn",
                    "-p",
                    "22,443",
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
        self.assertIn("-Pn", run_mock.call_args.args[0].arguments)
        self.assertIn("22,443", run_mock.call_args.args[0].arguments)
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
    def test_inline_ipv4_scope_runs_ipv4_scan(
        self,
        run_mock,
        parse_mock,
        check_mock,
    ) -> None:
        parse_mock.return_value = NmapScanResult(hosts=(), services=())
        check_mock.return_value = ScanVulnerabilityResult(
            checks=(), vulnerabilities=(), matches=(), service_count=0,
        )

        with redirect_stdout(StringIO()):
            exit_code = main(
                ["--scope", "192.0.2.0/24", "-4", "192.0.2.10"]
            )

        self.assertEqual(exit_code, 0)
        command = run_mock.call_args.args[0]
        self.assertEqual(command.ip_version, 4)
        self.assertNotIn("-6", command.arguments)
        self.assertIn("192.0.2.10/32", command.arguments)

    @patch("hexpath.cli.run_nmap")
    def test_explicit_ipv6_mode_rejects_ipv4_target(self, run_mock) -> None:
        errors = StringIO()

        with redirect_stderr(errors):
            exit_code = main(
                ["--scope", "192.0.2.0/24", "-6", "192.0.2.10"]
            )

        self.assertEqual(exit_code, 2)
        self.assertIn("requested IPv6", errors.getvalue())
        run_mock.assert_not_called()

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
        self.assertIn("SERVER / VANTAGE", output.getvalue())
        self.assertIn("NO HOSTS DISCOVERED", output.getvalue())
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

    def test_plan_prints_ipv4_command_without_ipv6_switch(self) -> None:
        scope_path = self.scope_path.with_name("ipv4-scope.json")
        scope_path.write_text(
            json.dumps({"name": "IPv4 lab", "targets": ["192.0.2.0/24"]}),
            encoding="utf-8",
        )
        output = StringIO()

        with redirect_stdout(output):
            exit_code = main(
                [
                    "scan",
                    "plan",
                    "--scope",
                    str(scope_path),
                    "192.0.2.10",
                ]
            )

        self.assertEqual(exit_code, 0)
        self.assertNotIn(" -6 ", f" {output.getvalue()} ")
        self.assertIn("192.0.2.10/32", output.getvalue())

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

    def comparison_graph_path(self) -> Path:
        path = self.directory / "comparison.json"
        path.write_text(json.dumps({
            "nodes": [
                {"id": "entry:scanner", "kind": "entry", "label": "entry"},
                {"id": "host:2001:db8::1", "kind": "host", "label": "target"},
                {"id": "host:2001:db8::2", "kind": "host", "label": "isolated"},
            ],
            "edges": [
                {
                    "id": f"edge-{index}", "source": "entry:scanner",
                    "target": "host:2001:db8::1", "relationship": "candidate_exploit",
                    "weight": cost, "description": "candidate transition",
                    "evidence": [{
                        "source": "test", "summary": "candidate evidence", "level": "inferred",
                        "collected_at": "2026-10-08T18:30:00+00:00", "reference": None,
                    }],
                    "metadata": {"cve_id": f"CVE-2026-1234{index}", "confidence": "medium"},
                }
                for index, cost in enumerate((2.5, 4.0), 1)
            ],
        }), encoding="utf-8")
        return path

    def test_comparison_json_ranks_paths_and_preserves_evidence(self) -> None:
        output = StringIO()
        with redirect_stdout(output):
            code = main([
                "graph", "paths", "--graph", str(self.comparison_graph_path()),
                "--target", "2001:0db8::1", "--json",
            ])
        document = json.loads(output.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(document["target"], "host:2001:db8::1")
        self.assertEqual([path["rank"] for path in document["paths"]], [1, 2])
        self.assertEqual([path["cost_delta"] for path in document["paths"]], [0, 1.5])
        self.assertEqual(document["paths"][0]["edges"][0]["evidence"][0]["level"], "inferred")

    def test_comparison_ascii_shows_findings_and_cost(self) -> None:
        output = StringIO()
        with redirect_stdout(output):
            code = main([
                "graph", "paths", "--graph", str(self.comparison_graph_path()),
                "--target", "2001:db8::1", "--limit", "1",
            ])
        self.assertEqual(code, 0)
        self.assertIn("CVE-2026-12341 (medium)", output.getvalue())
        self.assertIn("Total cost: 2.50", output.getvalue())
        self.assertNotIn("Route 2", output.getvalue())

    def test_targets_include_unreachable_hosts(self) -> None:
        output = StringIO()
        with redirect_stdout(output):
            code = main(["graph", "targets", "--graph", str(self.comparison_graph_path()), "--json"])
        targets = json.loads(output.getvalue())["targets"]
        self.assertEqual(code, 0)
        self.assertEqual([target["reachable"] for target in targets], [True, False])
        self.assertEqual([target["cost"] for target in targets], [2.5, None])

    def test_comparison_reports_missing_and_unreachable_targets(self) -> None:
        graph_path = self.comparison_graph_path()
        output = StringIO()
        with redirect_stdout(output):
            code = main(["graph", "paths", "--graph", str(graph_path), "--target", "2001:db8::2", "--json"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output.getvalue())["paths"], [])
        errors = StringIO()
        with redirect_stderr(errors):
            code = main(["graph", "paths", "--graph", str(graph_path), "--target", "2001:db8::9"])
        self.assertEqual(code, 2)
        self.assertIn("graph targets", errors.getvalue())

    def test_comparison_rejects_unbounded_limits(self) -> None:
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as exit_error:
            main(["graph", "paths", "--graph", "unused.json", "--target", "::1", "--limit", "21"])
        self.assertEqual(exit_error.exception.code, 2)

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

"""Integration tests for the HexPath command-line interface."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hexpath.cli import build_parser, main
from hexpath.scanner import NmapScanResult
from hexpath.vulnerabilities import (
    CpeIdentity,
    CpeVulnerabilityResult,
    OsvAdvisory,
    PackageIdentity,
    PackageVulnerabilityResult,
    ScanVulnerabilityResult,
)


class CompactCliTests(unittest.TestCase):
    def test_top_level_and_nested_aliases_resolve_to_canonical_commands(self) -> None:
        parser = build_parser()
        cases = (
            (["sc", "c", "-s", "scope.json", "-t", "192.0.2.10"], "scope", "check"),
            (["s", "l"], "scan", "levels"),
            (["s", "p", "-s", "scope.json", "-p", "d", "192.0.2.10"], "scan", "plan"),
            (["c", "c", "-c", "cpe:/a:x:y:1"], "cve", "cpe"),
            (["g", "b", "-s", "scan.json", "-c", "cves.json"], "graph", "build"),
            (["g", "sh", "-g", "graph.json"], "graph", "show"),
            (["g", "v", "-g", "graph.json"], "graph", "validate"),
            (["g", "p", "-g", "graph.json", "-t", "host:a"], "graph", "path"),
            (["g", "t", "-g", "graph.json"], "graph", "targets"),
            (["g", "r", "-g", "graph.json", "-t", "host:a"], "graph", "paths"),
            (["g", "s", "-g", "graph.json", "-t", "host:a"], "graph", "score"),
            (["g", "x", "-g", "graph.json"], "graph", "exposure"),
        )

        for arguments, command, nested_command in cases:
            with self.subTest(arguments=arguments):
                parsed = parser.parse_args(arguments)
                self.assertEqual(parsed.command, command)
                self.assertEqual(
                    getattr(parsed, f"{command}_command"),
                    nested_command,
                )

    def test_short_profile_and_algorithm_values_are_canonicalized(self) -> None:
        parser = build_parser()

        scan = parser.parse_args(
            ["s", "p", "-s", "scope.json", "-p", "s", "192.0.2.10"]
        )
        deep_scan = parser.parse_args(
            ["s", "p", "-s", "scope.json", "-L", "4", "192.0.2.10"]
        )
        path = parser.parse_args(
            ["g", "p", "-g", "graph.json", "-t", "host:a", "-a", "a", "-j"]
        )

        self.assertEqual(scan.profile, "services")
        self.assertEqual(deep_scan.profile, "deep")
        self.assertEqual(path.algorithm, "astar")
        self.assertTrue(path.json)

    def test_version_flag_keeps_hexpath_program_name(self) -> None:
        output = StringIO()

        with redirect_stdout(output), self.assertRaises(SystemExit) as raised:
            main(["-V"])

        self.assertEqual(raised.exception.code, 0)
        self.assertEqual(output.getvalue(), "hexpath 0.1.0\n")


class ScanCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.scope_path = Path(self.temporary_directory.name) / "scope.json"
        self.scope_path.write_text(
            json.dumps({"name": "test lab", "targets": ["2001:db8:1::/64"]}),
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
                    "2001:db8:1::10",
                ]
            )

        self.assertEqual(exit_code, 0)
        self.assertIn("nmap -6", output.getvalue())
        self.assertIn("2001:db8:1::10/128", output.getvalue())

    def test_levels_describe_information_and_relative_wait(self) -> None:
        output = StringIO()

        with redirect_stdout(output):
            exit_code = main(["s", "l", "-j"])

        document = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(len(document["levels"]), 5)
        self.assertEqual(document["levels"][0]["profile"], "discovery")
        self.assertEqual(document["levels"][4]["profile"], "deep")

    def test_plan_accepts_full_information_level(self) -> None:
        output = StringIO()

        with redirect_stdout(output):
            exit_code = main(
                [
                    "s",
                    "p",
                    "-s",
                    str(self.scope_path),
                    "-L",
                    "3",
                    "2001:db8:1::10",
                ]
            )

        self.assertEqual(exit_code, 0)
        self.assertIn("-sV --version-light -p-", output.getvalue())

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
                    "-4",
                    "192.0.2.10",
                ]
            )

        self.assertEqual(exit_code, 0)
        self.assertNotIn(" -6 ", f" {output.getvalue()} ")
        self.assertIn("192.0.2.10/32", output.getvalue())

    @patch("hexpath.cli.run_nmap")
    def test_explicit_ipv6_mode_rejects_ipv4_target(self, run_mock) -> None:
        scope_path = self.scope_path.with_name("ipv4-scope.json")
        scope_path.write_text(
            json.dumps({"name": "IPv4 lab", "targets": ["192.0.2.0/24"]}),
            encoding="utf-8",
        )
        errors = StringIO()

        with redirect_stderr(errors):
            exit_code = main(
                [
                    "scan",
                    "run",
                    "--scope",
                    str(scope_path),
                    "-6",
                    "192.0.2.10",
                ]
            )

        self.assertEqual(exit_code, 2)
        self.assertIn("requested IPv6", errors.getvalue())
        run_mock.assert_not_called()

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
                    "2001:db8:1::10",
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
            checks=(CpeVulnerabilityResult(cpe=CpeIdentity("cpe:/a:x:y:1"), completed=True),),
            vulnerabilities=(),
            matches=(),
            service_count=1,
        )
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        input_path = Path(temporary_directory.name) / "scan.json"
        input_path.write_text(
            '{"hosts": [], "services": [{"id": "s1", "cpes": []}]}', encoding="utf-8"
        )
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
            checks=(CpeVulnerabilityResult(cpe=CpeIdentity("cpe:/a:x:y:1"), completed=True),),
            vulnerabilities=(),
            matches=(),
            service_count=1,
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
        path.write_text(
            json.dumps(
                {
                    "nodes": [
                        {"id": "entry:scanner", "kind": "entry", "label": "entry"},
                        {
                            "id": "host:2001:db8::1",
                            "kind": "host",
                            "label": "target",
                            "metadata": {"hostnames": ["target.lab"]},
                        },
                        {
                            "id": "host:2001:db8::2",
                            "kind": "host",
                            "label": "isolated",
                        },
                    ],
                    "edges": [
                        {
                            "id": f"edge-{index}",
                            "source": "entry:scanner",
                            "target": "host:2001:db8::1",
                            "relationship": "candidate_exploit",
                            "weight": cost,
                            "description": "candidate transition",
                            "evidence": [
                                {
                                    "source": "test",
                                    "summary": "candidate evidence",
                                    "level": "inferred",
                                    "collected_at": "2026-10-08T18:30:00+00:00",
                                    "reference": None,
                                }
                            ],
                            "metadata": {
                                "cve_id": f"CVE-2026-1234{index}",
                                "confidence": "medium",
                            },
                        }
                        for index, cost in enumerate((2.5, 4.0), 1)
                    ],
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_comparison_json_ranks_paths_and_preserves_evidence(self) -> None:
        output = StringIO()

        with redirect_stdout(output):
            exit_code = main(
                [
                    "graph",
                    "paths",
                    "--graph",
                    str(self.comparison_graph_path()),
                    "--target",
                    "2001:0db8::1",
                    "--json",
                ]
            )

        document = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(document["target"], "host:2001:db8::1")
        self.assertEqual([path["rank"] for path in document["paths"]], [1, 2])
        self.assertEqual(
            [path["cost_delta"] for path in document["paths"]],
            [0.0, 1.5],
        )
        self.assertEqual(
            document["paths"][0]["edges"][0]["evidence"][0]["level"],
            "inferred",
        )

    def test_comparison_ascii_shows_findings_and_cost(self) -> None:
        output = StringIO()

        with redirect_stdout(output):
            exit_code = main(
                [
                    "graph",
                    "paths",
                    "--graph",
                    str(self.comparison_graph_path()),
                    "--target",
                    "2001:db8::1",
                    "--limit",
                    "1",
                ]
            )

        self.assertEqual(exit_code, 0)
        self.assertIn("CVE-2026-12341 (medium)", output.getvalue())
        self.assertIn("Total cost: 2.50", output.getvalue())
        self.assertNotIn("Route 2", output.getvalue())

    def test_targets_include_unreachable_hosts(self) -> None:
        output = StringIO()

        with redirect_stdout(output):
            exit_code = main(
                [
                    "graph",
                    "targets",
                    "--graph",
                    str(self.comparison_graph_path()),
                    "--json",
                ]
            )

        targets = json.loads(output.getvalue())["targets"]
        self.assertEqual(exit_code, 0)
        self.assertEqual([target["reachable"] for target in targets], [True, False])
        self.assertEqual([target["cost"] for target in targets], [2.5, None])

    def test_exposure_command_identifies_and_ranks_host_paths(self) -> None:
        output = StringIO()

        with redirect_stdout(output):
            exit_code = main(
                [
                    "g",
                    "x",
                    "-g",
                    str(self.comparison_graph_path()),
                    "-j",
                ]
            )

        document = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(document["algorithm"], "dijkstra")
        self.assertEqual(document["ranking"], "network_score_descending")
        self.assertEqual(document["score_version"], "hexpath-network-v1")
        self.assertEqual(
            document["most_vulnerable_path"]["target"]["id"],
            "host:2001:db8::1",
        )
        self.assertGreater(
            document["most_vulnerable_path"]["network_score"],
            0,
        )
        self.assertIn("components", document["most_vulnerable_path"])
        self.assertEqual(
            document["most_vulnerable_path"]["path"]["total_weight"],
            2.5,
        )
        self.assertEqual(
            [host["id"] for host in document["unreachable_hosts"]],
            ["host:2001:db8::2"],
        )

    def test_score_command_reports_one_host_with_path_evidence(self) -> None:
        output = StringIO()

        with redirect_stdout(output):
            exit_code = main(
                [
                    "graph",
                    "score",
                    "--graph",
                    str(self.comparison_graph_path()),
                    "--target",
                    "2001:db8::1",
                    "--json",
                ]
            )

        document = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(document["target"]["id"], "host:2001:db8::1")
        self.assertEqual(document["score_version"], "hexpath-network-v1")
        self.assertGreater(document["network_score"], 0)
        self.assertEqual(document["path"]["total_weight"], 2.5)
        self.assertEqual(
            document["candidate_findings"][0]["cve_id"],
            "CVE-2026-12341",
        )

    def test_score_command_marks_unreachable_host_unscored(self) -> None:
        output = StringIO()

        with redirect_stdout(output):
            exit_code = main(
                [
                    "graph",
                    "score",
                    "--graph",
                    str(self.comparison_graph_path()),
                    "--target",
                    "2001:db8::2",
                    "--json",
                ]
            )

        document = json.loads(output.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertIsNone(document["network_score"])
        self.assertIn("no evidence-backed directed path", document["reason"])

    def test_validate_command_summarizes_a_valid_graph(self) -> None:
        output = StringIO()

        with redirect_stdout(output):
            exit_code = main(
                [
                    "graph",
                    "validate",
                    "--graph",
                    str(self.comparison_graph_path()),
                    "--json",
                ]
            )

        document = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertTrue(document["valid"])
        self.assertEqual(document["nodes"], 3)
        self.assertEqual(document["edges"], 2)
        self.assertEqual(document["node_kinds"]["host"], 2)
        self.assertEqual(document["entry_nodes"], ["entry:scanner"])

    def test_validate_command_rejects_invalid_graph(self) -> None:
        graph_path = self.directory / "invalid.json"
        graph_path.write_text(
            json.dumps(
                {
                    "nodes": [
                        {"id": "entry:scanner", "kind": "entry", "label": "entry"}
                    ],
                    "edges": [
                        {
                            "id": "bad-edge",
                            "source": "entry:scanner",
                            "target": "host:missing",
                            "relationship": "transition",
                            "weight": 1,
                            "description": "invalid target",
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
        errors = StringIO()

        with redirect_stderr(errors):
            exit_code = main(
                ["graph", "validate", "--graph", str(graph_path), "--json"]
            )

        self.assertEqual(exit_code, 2)
        self.assertIn("unknown target", errors.getvalue())

    def test_vulnerable_command_renders_most_vulnerable_route(self) -> None:
        output = StringIO()

        with redirect_stdout(output):
            exit_code = main(
                [
                    "graph",
                    "vulnerable",
                    "--graph",
                    str(self.comparison_graph_path()),
                    "--limit",
                    "1",
                ]
            )

        self.assertEqual(exit_code, 0)
        self.assertIn("HexPath Network Exposure Ranking", output.getvalue())
        self.assertIn("Score components:", output.getvalue())
        self.assertIn("CVE-2026-12341 (medium)", output.getvalue())
        self.assertIn("Total cost: 2.50", output.getvalue())

    def test_vulnerable_command_returns_one_when_no_host_is_reachable(self) -> None:
        graph_path = self.directory / "unreachable.json"
        graph_path.write_text(
            json.dumps(
                {
                    "nodes": [
                        {"id": "entry:scanner", "kind": "entry", "label": "entry"},
                        {
                            "id": "host:192.0.2.10",
                            "kind": "host",
                            "label": "target",
                        },
                    ],
                    "edges": [],
                }
            ),
            encoding="utf-8",
        )
        output = StringIO()

        with redirect_stdout(output):
            exit_code = main(
                [
                    "graph",
                    "vulnerable",
                    "--graph",
                    str(graph_path),
                    "--json",
                ]
            )

        self.assertEqual(exit_code, 1)
        self.assertIsNone(json.loads(output.getvalue())["most_vulnerable_path"])

    def test_comparison_reports_missing_and_unreachable_targets(self) -> None:
        graph_path = self.comparison_graph_path()
        output = StringIO()
        with redirect_stdout(output):
            exit_code = main(
                [
                    "graph",
                    "paths",
                    "--graph",
                    str(graph_path),
                    "--target",
                    "2001:db8::2",
                    "--json",
                ]
            )
        self.assertEqual(exit_code, 1)
        self.assertEqual(json.loads(output.getvalue())["paths"], [])

        errors = StringIO()
        with redirect_stderr(errors):
            exit_code = main(
                [
                    "graph",
                    "paths",
                    "--graph",
                    str(graph_path),
                    "--target",
                    "2001:db8::9",
                ]
            )
        self.assertEqual(exit_code, 2)
        self.assertIn("graph targets", errors.getvalue())

    def test_comparison_rejects_unbounded_limits(self) -> None:
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as raised:
            main(
                [
                    "graph",
                    "paths",
                    "--graph",
                    "unused.json",
                    "--target",
                    "::1",
                    "--limit",
                    "21",
                ]
            )
        self.assertEqual(raised.exception.code, 2)

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

    def _write_entry_graph(self, entry_ids: list[str]) -> Path:
        graph_path = self.directory / "entry-graph.json"
        evidence = [
            {
                "source": "test",
                "summary": "test evidence",
                "level": "observed",
                "collected_at": "2026-10-08T18:30:00+00:00",
                "reference": None,
            }
        ]
        graph_path.write_text(
            json.dumps(
                {
                    "nodes": [
                        *(
                            {"id": entry_id, "kind": "entry", "label": "entry"}
                            for entry_id in entry_ids
                        ),
                        {"id": "host:target", "kind": "host", "label": "target"},
                    ],
                    "edges": [
                        {
                            "id": f"edge-{index}",
                            "source": entry_id,
                            "target": "host:target",
                            "relationship": "transition",
                            "weight": 2.5,
                            "description": "test transition",
                            "evidence": evidence,
                        }
                        for index, entry_id in enumerate(entry_ids)
                    ],
                }
            ),
            encoding="utf-8",
        )
        return graph_path

    def test_path_defaults_to_custom_entry_node(self) -> None:
        graph_path = self._write_entry_graph(["entry:kali"])
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
        self.assertEqual(document["nodes"], ["entry:kali", "host:target"])

    def test_astar_path_supports_custom_source_json_and_ascii(self) -> None:
        graph_path = self._write_entry_graph(["entry:kali", "entry:vpn"])
        for output_flags in (["--json"], []):
            with self.subTest(output_flags=output_flags):
                output = StringIO()
                with redirect_stdout(output):
                    exit_code = main([
                        "graph", "path", "--graph", str(graph_path),
                        "--source", "entry:vpn", "--target", "host:target",
                        "--algorithm", "astar", *output_flags,
                    ])
                self.assertEqual(exit_code, 0)
                if output_flags:
                    document = json.loads(output.getvalue())
                    self.assertEqual(document["nodes"], ["entry:vpn", "host:target"])
                    self.assertEqual(document["total_weight"], 2.5)
                else:
                    self.assertIn("Total cost: 2.50", output.getvalue())

    def test_astar_defaults_to_entry_and_preserves_unreachable_exit_status(self) -> None:
        graph_path = self._write_entry_graph(["entry:kali"])
        for source_flags, target, expected_status in (
            ([], "host:target", 0),
            (["--source", "host:target"], "entry:kali", 1),
        ):
            with self.subTest(target=target):
                output = StringIO()
                with redirect_stdout(output):
                    exit_code = main([
                        "graph", "path", "--graph", str(graph_path),
                        *source_flags, "--target", target,
                        "--algorithm", "astar", "--json",
                    ])
                self.assertEqual(exit_code, expected_status)
                document = json.loads(output.getvalue())
                if expected_status == 0:
                    self.assertEqual(document["nodes"], ["entry:kali", "host:target"])
                else:
                    self.assertIsNone(document["path"])

    def test_path_rejects_unknown_algorithm(self) -> None:
        graph_path = self._write_entry_graph(["entry:kali"])
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as raised:
            main([
                "graph", "path", "--graph", str(graph_path),
                "--target", "host:target", "--algorithm", "greedy",
            ])
        self.assertEqual(raised.exception.code, 2)

    def test_path_requires_source_when_graph_has_several_entries(self) -> None:
        graph_path = self._write_entry_graph(["entry:kali", "entry:vpn"])
        errors = StringIO()

        with redirect_stdout(StringIO()), redirect_stderr(errors):
            exit_code = main(
                [
                    "graph",
                    "path",
                    "--graph",
                    str(graph_path),
                    "--target",
                    "host:target",
                ]
            )

        self.assertEqual(exit_code, 2)
        self.assertIn("several entry nodes", errors.getvalue())
        self.assertIn("entry:kali, entry:vpn", errors.getvalue())

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

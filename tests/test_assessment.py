"""Exercise the IPv6 pentest workflow without scanning or external API calls."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hexpath.assessment import render_assessment, summarize_assessment, validate_scans
from hexpath.cli import main
from hexpath.graph import ENTRY_NODE_ID
from hexpath.scope import Scope
from hexpath.vulnerabilities import CpeIdentity
from test_graph import sample_documents


class AssessmentTests(unittest.TestCase):
    def setUp(self):
        self.scope = Scope.from_dict({"name": "IPv6 lab", "targets": ["2001:db8::/64"]})
        self.scan, self.cves = sample_documents()
        self.cves.update({
            "completed": True,
            "coverage": {"services": 2},
            "checks": [
                {"cpe": CpeIdentity(service["cpes"][0]).value, "completed": True}
                for service in self.scan["services"]
            ],
        })

    def summarize(self, scans=None, target="host:2001:db8::10"):
        return summarize_assessment(
            self.scope, validate_scans(self.scope, scans or [self.scan]), self.cves,
            source=ENTRY_NODE_ID, target=target,
        )

    def test_reachable_target_is_separate_from_candidate_compromise(self):
        result = self.summarize()
        self.assertTrue(result["target_service_reachable_from_source"])
        self.assertTrue(result["coverage_complete"])
        steps = result["candidate_path"]["steps"]
        self.assertEqual([s["assessment"] for s in steps],
                         ["observed_reachability", "candidate_compromise"])
        rendered = render_assessment(result)
        self.assertIn("access: UNVERIFIED", rendered)
        self.assertIn("required credentials", rendered)

    def test_open_target_without_cve_has_no_path_but_is_reachable(self):
        self.cves["matches"] = []
        result = self.summarize()
        self.assertTrue(result["target_service_reachable_from_source"])
        self.assertIsNone(result["candidate_path"])
        self.assertIn("does not mean secure", render_assessment(result))

    def test_closed_or_uncertain_services_cannot_form_routes(self):
        for state in ("closed", "filtered", "open|filtered", "unknown"):
            with self.subTest(state=state):
                for service in self.scan["services"]:
                    service["state"] = state
                result = self.summarize()
                self.assertFalse(result["target_service_reachable_from_source"])
                self.assertIsNone(result["candidate_path"])
                self.assertEqual(len(result["observations"]), 2)

    def test_unknown_target_is_not_declared_secure(self):
        result = self.summarize(target="host:2001:db8::99")
        self.assertFalse(result["target_observed"])
        self.assertIsNone(result["candidate_path"])

    def test_missing_or_mismatched_coverage_stays_incomplete(self):
        for change in ({"completed": False}, {"coverage": {"services": 7}},
                       {"checks": []}, {"coverage": {}}):
            with self.subTest(change=change):
                original = deepcopy(self.cves)
                self.cves.update(change)
                self.assertFalse(self.summarize()["coverage_complete"])
                self.cves = original

    def test_empty_scan_never_has_complete_coverage(self):
        self.scan = {"hosts": [], "services": []}
        self.cves = {"completed": True, "coverage": {"services": 0},
                     "vulnerabilities": [], "matches": []}
        self.assertFalse(self.summarize()["coverage_complete"])

    def test_terminal_controls_are_sanitized(self):
        self.scan["services"][0]["product"] = "evil\x1b[2J\nFAKE RESULT"
        rendered = render_assessment(self.summarize())
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\nFAKE RESULT", rendered)

    def test_second_vantage_extends_path_only_with_observations(self):
        second = deepcopy(self.scan)
        second = json.loads(json.dumps(second).replace("2001:db8::10", "2001:db8::20"))
        second["vantage"] = "host:2001:db8::10"
        extra = json.loads(json.dumps(self.cves["matches"]).replace("2001:db8::10", "2001:db8::20"))
        self.cves["matches"].extend(extra)
        self.cves["coverage"]["services"] = 4
        result = self.summarize([self.scan, second], "host:2001:db8::20")
        self.assertFalse(result["target_service_reachable_from_source"])
        self.assertEqual(len(result["candidate_path"]["steps"]), 4)
        self.assertEqual(result["candidate_path"]["nodes"][2], "host:2001:db8::10")

    def test_validation_does_not_modify_imported_scans(self):
        self.scan["vantage"] = "host:2001:db8::20"
        before = deepcopy(self.scan)
        scans = validate_scans(self.scope, [self.scan])
        self.assertEqual(self.scan, before)
        origin = scans[0]["hosts"][-1]
        self.assertEqual(origin["id"], "host:2001:db8::20")
        self.assertEqual(origin["evidence"][0]["level"], "inferred")


class AssessmentCliTests(unittest.TestCase):
    def setUp(self):
        AssessmentTests.setUp(self)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        for name, doc in (("scope", {"name": "lab", "targets": ["2001:db8::/64"]}),
                          ("scan", self.scan), ("cves", self.cves)):
            (self.directory / f"{name}.json").write_text(json.dumps(doc))
        self.args = ["assess", "--scope", str(self.directory / "scope.json"),
                     "--target", "2001:db8::10"]

    def offline_args(self):
        return [*self.args, "--scan", str(self.directory / "scan.json"),
                "--cves", str(self.directory / "cves.json")]

    @patch("hexpath.cli.run_nmap")
    @patch("hexpath.cli.check_scan_documents")
    def test_offline_summary_and_evidence_export(self, enrich, scan):
        output = StringIO()
        bundle = self.directory / "assessment.json"
        with redirect_stdout(output):
            code = main([*self.offline_args(), "--output", str(bundle)])
        self.assertEqual(code, 0)
        self.assertIn("HexPath IPv6 Pentest Assessment", output.getvalue())
        self.assertIn("UNVERIFIED", output.getvalue())
        self.assertEqual(json.loads(bundle.read_text())["target"], "host:2001:db8::10")
        scan.assert_not_called()
        enrich.assert_not_called()

    @patch("hexpath.cli.run_nmap")
    @patch("hexpath.cli.check_scan_documents")
    def test_rejects_ipv4_out_of_scope_and_prefixes_before_network(self, enrich, scan):
        for target in ("192.0.2.1", "2001:db8:1::10", "2001:db8::/64"):
            with self.subTest(target=target), redirect_stderr(StringIO()):
                self.assertEqual(main([*self.args, target]), 2)
        scan.assert_not_called()
        enrich.assert_not_called()

    @patch("hexpath.cli.check_scan_documents")
    def test_rejects_ipv4_import_before_enrichment(self, enrich):
        self.scan["hosts"][0]["address"] = "192.0.2.1"
        (self.directory / "scan.json").write_text(json.dumps(self.scan))
        with redirect_stderr(StringIO()):
            code = main([*self.args, "--scan", str(self.directory / "scan.json")])
        self.assertEqual(code, 2)
        enrich.assert_not_called()

    @patch("hexpath.cli.run_nmap")
    def test_saved_cves_cannot_be_used_for_live_scan(self, scan):
        with redirect_stderr(StringIO()):
            code = main([*self.offline_args(), "2001:db8::10"])
        self.assertEqual(code, 2)
        scan.assert_not_called()

    def test_incomplete_json_output_has_nonzero_status(self):
        self.cves["completed"] = False
        (self.directory / "cves.json").write_text(json.dumps(self.cves))
        output = StringIO()
        with redirect_stdout(output):
            code = main([*self.offline_args(), "--json"])
        self.assertEqual(code, 2)
        self.assertFalse(json.loads(output.getvalue())["coverage_complete"])

    def test_malformed_enrichment_is_a_cli_error(self):
        self.cves["checks"] = [{"cpe": {}, "completed": True}]
        (self.directory / "cves.json").write_text(json.dumps(self.cves))
        errors = StringIO()
        with redirect_stderr(errors):
            code = main(self.offline_args())
        self.assertEqual(code, 2)
        self.assertIn("each CVE check must identify its CPE", errors.getvalue())

    def test_stdin_cannot_be_consumed_twice(self):
        with redirect_stderr(StringIO()):
            code = main([*self.args, "--scan", "-", "--cves", "-"])
        self.assertEqual(code, 2)

    @patch("hexpath.cli.run_nmap")
    def test_dual_stack_scope_does_not_enable_ipv4_assessment(self, scan):
        (self.directory / "scope.json").write_text(json.dumps({
            "name": "mixed lab", "targets": ["2001:db8::/64", "192.0.2.0/24"],
        }))
        with redirect_stderr(StringIO()):
            self.assertEqual(main([*self.args, "192.0.2.1"]), 2)
        scan.assert_not_called()

    @patch("hexpath.cli.check_scan_documents")
    @patch("hexpath.cli.run_nmap")
    def test_live_assessment_uses_ipv6_and_reports_incomplete_coverage(self, scan, enrich):
        scan.return_value = '<nmaprun><host><status state="up"/><address addr="2001:db8::10" addrtype="ipv6"/></host></nmaprun>'
        enrich.return_value.to_dict.return_value = {
            "completed": False, "vulnerabilities": [], "matches": [],
        }
        output = StringIO()
        with redirect_stdout(output):
            code = main([*self.args, "2001:db8::10"])
        self.assertEqual(code, 2)
        self.assertIn("-6", scan.call_args.args[0].arguments)
        self.assertIn("INCOMPLETE", output.getvalue())


if __name__ == "__main__":
    unittest.main()

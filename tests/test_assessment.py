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

    def test_summary_leads_with_target_and_names_failed_cpe(self):
        other = deepcopy(self.scan)
        other = json.loads(json.dumps(other).replace("2001:db8::10", "2001:db8::20"))
        self.cves["checks"][0]["completed"] = False
        self.cves["checks"][0]["error"] = "NVD request timed out"
        self.cves["completed"] = False
        self.cves["coverage"]["services"] = 4
        rendered = render_assessment(self.summarize([self.scan, other]))
        self.assertIn("Target services observed: 2", rendered)
        self.assertIn("Other hosts observed: 1", rendered)
        target_section = rendered.split("TARGET EXPOSURE", 1)[1].split("OTHER OBSERVED HOSTS", 1)[0]
        self.assertNotIn("2001:db8::20", target_section)
        self.assertIn("Lookup failed for " + self.cves["checks"][0]["cpe"], rendered)

    def test_repeated_scan_observation_is_listed_once_in_exposure(self):
        result = self.summarize()
        target_observation = next(
            item for item in result["observations"] if item["host"] == "2001:db8::10"
        )
        result["observations"].append(deepcopy(target_observation))
        rendered = render_assessment(result)
        exposure = rendered.split("TARGET EXPOSURE", 1)[1].split("HOST INFORMATION GRADE", 1)[0]
        endpoint = f"[{target_observation['host']}]:{target_observation['port']}/{target_observation['protocol']}"
        self.assertEqual(exposure.count(endpoint), 1)

    def test_open_target_without_cve_has_no_path_but_is_reachable(self):
        self.cves["matches"] = []
        result = self.summarize()
        self.assertTrue(result["target_service_reachable_from_source"])
        self.assertIsNone(result["candidate_path"])
        self.assertIn("does not mean secure", render_assessment(result))

    def test_next_checks_identify_unverified_candidates_without_inventing_a_path(self):
        for match in self.cves["matches"]:
            match.pop("access_supported")
            match.pop("access_basis")
            match.pop("access_evidence")
        result = self.summarize()
        self.assertIsNone(result["candidate_path"])
        self.assertEqual(
            [item["kind"] for item in result["next_checks"]],
            ["verify_cve_conditions", "verify_cve_conditions", "record_probe_coverage"],
        )
        rendered = render_assessment(result)
        self.assertIn("NEXT CHECKS FOR TARGET", rendered)
        self.assertIn("[2001:db8::10]:22/tcp", rendered)
        self.assertIn("observed access effect before asserting a path", rendered)

    def test_next_checks_separate_missing_version_from_failed_lookup(self):
        self.scan["services"][0]["cpes"] = ["cpe:/a:openbsd:openssh"]
        self.cves["checks"][1]["completed"] = False
        self.cves["checks"][1]["error"] = "NVD unavailable"
        result = self.summarize()
        self.assertEqual(
            [item["kind"] for item in result["next_checks"]],
            ["confirm_version", "complete_cve_lookup", "record_probe_coverage"],
        )
        self.assertIn("[2001:db8::10]:22/tcp", result["next_checks"][0]["action"])
        self.assertIn("example:http:1.0", result["next_checks"][1]["cpe"])

    def test_next_checks_do_not_treat_unobserved_ipv6_host_as_clean(self):
        result = self.summarize(target="host:2001:db8::99")
        self.assertEqual(result["host_information"]["grade"], "U")
        self.assertIsNone(result["host_information"]["score"])
        self.assertEqual(
            [item["kind"] for item in result["next_checks"]],
            ["confirm_reachability", "record_probe_coverage"],
        )
        self.assertIn("target was not observed", result["next_checks"][0]["action"])

    def test_host_information_grade_is_evidence_completeness_not_risk(self):
        result = self.summarize()
        self.assertEqual(result["host_information"]["grade"], "A")
        self.assertEqual(result["host_information"]["score"], 100.0)
        self.assertEqual(result["host_information"]["services_with_completed_cve_check"], 2)
        self.assertIn("not a safety rating", render_assessment(result))

        self.scan["services"][0]["cpes"] = ["cpe:/a:openbsd:openssh"]
        self.cves["checks"][1]["completed"] = False
        incomplete = self.summarize()
        self.assertEqual(incomplete["host_information"]["grade"], "D")
        self.assertEqual(incomplete["host_information"]["score"], 25.0)

    def test_os_fingerprint_guess_is_displayed_without_becoming_a_patch_claim(self):
        self.scan["hosts"][0].update({
            "os_name": "Linux 5.x", "os_accuracy": 92,
            "cpes": ["cpe:/o:linux:linux_kernel:5"],
        })
        result = self.summarize()
        self.assertEqual(result["host_information"]["grade"], "A")
        self.assertEqual(result["host_information"]["os_guesses"][0]["nmap_accuracy"], 92)
        rendered = render_assessment(result)
        self.assertIn("Linux 5.x (92% Nmap accuracy)", rendered)
        self.assertIn("patch level unverified", rendered)

    def test_import_rejects_invalid_os_accuracy(self):
        self.scan["hosts"][0]["os_accuracy"] = 101
        with self.assertRaisesRegex(ValueError, "os_accuracy"):
            self.summarize()

    def test_multiple_vantages_with_conflicting_cpes_need_reconciliation(self):
        other = deepcopy(self.scan)
        other["services"][0]["cpes"] = ["cpe:/a:openbsd:openssh:9.7"]
        result = self.summarize([self.scan, other])
        self.assertEqual(result["host_information"]["grade"], "C")
        self.assertIn(self.scan["services"][0]["id"],
                      result["host_information"]["conflicting_service_ids"])
        self.assertIn("reconcile_identity", [item["kind"] for item in result["next_checks"]])

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

    def test_stale_cpe_matches_are_excluded_from_routes(self):
        self.scan["services"][0]["cpes"] = ["cpe:/a:mariadb:mariadb:5.5.5-10.11.14"]
        result = self.summarize()
        self.assertFalse(result["coverage_complete"])
        self.assertGreater(result["excluded_match_count"], 0)
        self.assertIn("CVE link has no completed check for its current CPE",
                      result["excluded_match_reasons"])
        self.assertEqual(len(result["modeled_matches"]), 1)

    def test_coarse_cpe_matches_do_not_create_candidate_path(self):
        for service in self.scan["services"]:
            service["cpes"] = ["cpe:/a:samba:samba:4"]
        result = self.summarize()
        self.assertIsNone(result["candidate_path"])
        self.assertEqual(result["excluded_match_count"], 2)
        self.assertIn("no precise version", render_assessment(result))

    def test_observed_local_evidence_can_rule_out_cve_candidates(self):
        for match in self.cves["matches"]:
            match.pop("access_supported")
            match.pop("access_basis")
            match.pop("access_evidence")
            match["applicability"] = "ruled_out"
            match["applicability_evidence"] = [self.scan["services"][0]["evidence"][0]]
        result = self.summarize()
        self.assertEqual(result["excluded_match_count"], 2)
        self.assertEqual(result["modeled_matches"], [])
        self.assertIsNone(result["candidate_path"])
        self.assertIn("local evidence rules out", render_assessment(result))

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

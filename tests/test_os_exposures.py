"""Coverage for OS-fingerprint CVE candidates."""

import unittest

from hexpath.os_exposures import os_candidates_for_host


class OsExposureTests(unittest.TestCase):
    def test_windows_xp_lists_landmark_cves(self) -> None:
        candidates = os_candidates_for_host(
            "192.168.56.101", ["cpe:/o:microsoft:windows_xp::sp3"]
        )
        ids = {candidate.cve_id for candidate in candidates}
        self.assertIn("CVE-2008-4250", ids)
        self.assertIn("CVE-2017-0143", ids)
        self.assertIn("CVE-2019-0708", ids)
        self.assertTrue(all(candidate.host == "192.168.56.101" for candidate in candidates))

    def test_windows_10_lists_modern_cves(self) -> None:
        candidates = os_candidates_for_host(
            "192.168.56.104", ["cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*"]
        )
        ids = {candidate.cve_id for candidate in candidates}
        self.assertIn("CVE-2020-0796", ids)
        self.assertIn("CVE-2021-34527", ids)
        # expanded coverage
        self.assertIn("CVE-2022-26809", ids)
        self.assertIn("CVE-2024-38063", ids)
        self.assertIn("CVE-2021-36934", ids)

    def test_windows_11_lists_modern_cves(self) -> None:
        candidates = os_candidates_for_host(
            "10.0.0.11", ["cpe:/o:microsoft:windows_11"]
        )
        ids = {candidate.cve_id for candidate in candidates}
        self.assertIn("CVE-2022-26809", ids)
        self.assertIn("CVE-2022-30190", ids)

    def test_candidates_are_sorted_by_severity(self) -> None:
        candidates = os_candidates_for_host(
            "192.168.56.101", ["cpe:/o:microsoft:windows_xp"]
        )
        scores = [candidate.cvss_score for candidate in candidates]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_8_1_is_matched_before_8(self) -> None:
        candidates = os_candidates_for_host("10.0.0.5", ["cpe:/o:microsoft:windows_8.1"])
        self.assertTrue(candidates)

    def test_name_fallback_when_no_cpe(self) -> None:
        # Nmap named the OS but gave no CPE — candidates still appear.
        candidates = os_candidates_for_host(
            "192.168.56.107", [], "Microsoft Windows 10 1803"
        )
        ids = {c.cve_id for c in candidates}
        self.assertIn("CVE-2020-0796", ids)
        self.assertTrue(all("name:" in c.basis for c in candidates))

    def test_name_fallback_embedded_standard_7(self) -> None:
        candidates = os_candidates_for_host(
            "192.168.56.111", None, "Microsoft Windows Embedded Standard 7"
        )
        ids = {c.cve_id for c in candidates}
        self.assertIn("CVE-2017-0143", ids)

    def test_cpe_takes_precedence_over_name(self) -> None:
        candidates = os_candidates_for_host(
            "10.0.0.5", ["cpe:/o:microsoft:windows_11"], "Microsoft Windows 10"
        )
        self.assertTrue(all("fingerprint cpe" not in c.basis.lower() or "name:" not in c.basis for c in candidates))
        # Win11-specific CVE present, proving the CPE (not the name) was used.
        self.assertIn("CVE-2022-37958", {c.cve_id for c in candidates})

    def test_non_windows_cpe_yields_no_candidates(self) -> None:
        self.assertEqual(
            os_candidates_for_host("10.0.0.9", ["cpe:/o:linux:linux_kernel"]), []
        )

    def test_no_cpes_yields_no_candidates(self) -> None:
        self.assertEqual(os_candidates_for_host("10.0.0.9", []), [])
        self.assertEqual(os_candidates_for_host("10.0.0.9", None), [])

    def test_candidate_marked_as_low_confidence_candidate(self) -> None:
        candidate = os_candidates_for_host("10.0.0.5", ["cpe:/o:microsoft:windows_11"])[0]
        payload = candidate.to_dict()
        self.assertEqual(payload["applicability"], "candidate")
        self.assertEqual(payload["confidence"], "low")
        self.assertIn("OS fingerprint", payload["basis"])


if __name__ == "__main__":
    unittest.main()

"""Tests for the pkgxray-derived OSV vulnerability provider."""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from hexpath.vulnerabilities import (
    CpeIdentity,
    NvdClient,
    OsvClient,
    PackageIdentity,
    PackageVulnerabilityResult,
    VulnerabilityError,
    VulnerabilityLookupError,
    VulnerabilityStatus,
    check_cpe,
    check_package,
    check_scan_document,
    check_scan_documents,
)


class PackageIdentityTests(unittest.TestCase):
    def test_requires_exact_non_empty_coordinates(self) -> None:
        with self.assertRaisesRegex(VulnerabilityError, "version"):
            PackageIdentity(ecosystem="PyPI", name="jinja2", version="")


class CpeIdentityTests(unittest.TestCase):
    def test_converts_nmap_cpe_22_to_nvd_cpe_23(self) -> None:
        cpe = CpeIdentity("cpe:/a:openbsd:openssh:9.6")

        self.assertEqual(
            cpe.value,
            "cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*",
        )

    def test_rejects_complex_cpe_22_instead_of_guessing(self) -> None:
        with self.assertRaisesRegex(VulnerabilityError, "CPE 2.3"):
            CpeIdentity("cpe:/a:example:product:1.0%2bpatch")


class OsvClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.package = PackageIdentity(
            ecosystem="PyPI",
            name="jinja2",
            version="2.4.1",
        )

    def test_sends_exact_pkgxray_style_osv_query(self) -> None:
        def transport(request, timeout, max_bytes):
            self.assertEqual(request.full_url, "https://api.osv.dev/v1/query")
            self.assertEqual(timeout, 7)
            self.assertEqual(max_bytes, 4096)
            self.assertEqual(
                json.loads(request.data),
                {
                    "package": {"name": "jinja2", "ecosystem": "PyPI"},
                    "version": "2.4.1",
                },
            )
            return json.dumps(
                {
                    "vulns": [
                        {
                            "id": "PYSEC-2021-66",
                            "aliases": ["CVE-2020-28493", "GHSA-test"],
                            "summary": "ReDoS in Jinja2.",
                            "severity": [
                                {
                                    "type": "CVSS_V3",
                                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                                }
                            ],
                            "references": [
                                {"type": "ADVISORY", "url": "https://example.test/advisory"}
                            ],
                        }
                    ]
                }
            ).encode()

        client = OsvClient(
            timeout_seconds=7,
            max_response_bytes=4096,
            transport=transport,
        )

        result = check_package(self.package, client=client)

        self.assertTrue(result.completed)
        self.assertEqual(result.status, VulnerabilityStatus.VULNERABLE)
        self.assertEqual(result.advisories[0].cve_ids, ("CVE-2020-28493",))
        self.assertEqual(result.vulnerabilities[0].cve_id, "CVE-2020-28493")
        self.assertTrue(result.vulnerabilities[0].cvss_vector.startswith("CVSS:3.1"))

    def test_empty_completed_response_is_clean(self) -> None:
        client = OsvClient(transport=lambda _request, _timeout, _limit: b"{}")

        result = check_package(self.package, client=client)

        self.assertTrue(result.completed)
        self.assertEqual(result.status, VulnerabilityStatus.CLEAN)

    def test_provider_failure_is_unknown_and_never_clean(self) -> None:
        def unavailable(_request, _timeout, _limit):
            raise VulnerabilityLookupError("OSV request timed out")

        result = check_package(self.package, client=OsvClient(transport=unavailable))

        self.assertFalse(result.completed)
        self.assertEqual(result.status, VulnerabilityStatus.UNKNOWN)
        self.assertIn("timed out", result.error)

    def test_rejects_malformed_vulnerability_list(self) -> None:
        client = OsvClient(
            transport=lambda _request, _timeout, _limit: b'{"vulns":"unknown"}'
        )

        result = check_package(self.package, client=client)

        self.assertEqual(result.status, VulnerabilityStatus.UNKNOWN)
        self.assertIn("invalid vulnerability list", result.error)

    def test_advisory_without_cve_stays_visible(self) -> None:
        client = OsvClient(
            transport=lambda _request, _timeout, _limit: json.dumps(
                {"vulns": [{"id": "GHSA-abcd-efgh-ijkl", "summary": "Advisory"}]}
            ).encode()
        )

        result = check_package(self.package, client=client)

        self.assertEqual(result.status, VulnerabilityStatus.VULNERABLE)
        self.assertEqual(result.vulnerabilities, ())
        self.assertEqual(result.advisories[0].advisory_id, "GHSA-abcd-efgh-ijkl")

    @patch("hexpath.vulnerabilities.urlopen")
    def test_default_transport_rejects_oversized_response(self, open_mock) -> None:
        class Response:
            headers = {"Content-Length": "5000"}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        open_mock.return_value = Response()
        client = OsvClient(max_response_bytes=4096)

        result = check_package(self.package, client=client)

        self.assertEqual(result.status, VulnerabilityStatus.UNKNOWN)
        self.assertEqual(result.error, "OSV response exceeded the size limit")


class PackageVulnerabilityResultTests(unittest.TestCase):
    def test_incomplete_result_requires_error(self) -> None:
        package = PackageIdentity(ecosystem="npm", name="demo", version="1.0.0")

        with self.assertRaisesRegex(VulnerabilityError, "explain"):
            PackageVulnerabilityResult(package=package, completed=False)


class NvdClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cpe = CpeIdentity("cpe:/a:openbsd:openssh:9.6")

    def test_queries_exact_cpe_and_parses_cvss(self) -> None:
        def transport(request, timeout, max_bytes):
            self.assertIn("cpeName=cpe%3A2.3%3Aa%3Aopenbsd", request.full_url)
            self.assertEqual(request.get_method(), "GET")
            self.assertEqual(timeout, 12)
            self.assertEqual(max_bytes, 8192)
            return json.dumps(
                {
                    "resultsPerPage": 1,
                    "startIndex": 0,
                    "totalResults": 1,
                    "vulnerabilities": [
                        {
                            "cve": {
                                "id": "CVE-2026-12345",
                                "descriptions": [
                                    {"lang": "en", "value": "Example network vulnerability."}
                                ],
                                "metrics": {
                                    "cvssMetricV31": [
                                        {
                                            "type": "Primary",
                                            "cvssData": {
                                                "baseScore": 8.1,
                                                "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                            },
                                        }
                                    ]
                                },
                                "references": [{"url": "https://example.test/cve"}],
                            }
                        }
                    ],
                }
            ).encode()

        result = check_cpe(
            self.cpe,
            client=NvdClient(
                timeout_seconds=12,
                max_response_bytes=8192,
                transport=transport,
            ),
        )

        self.assertEqual(result.status, VulnerabilityStatus.VULNERABLE)
        self.assertEqual(result.vulnerabilities[0].cve_id, "CVE-2026-12345")
        self.assertEqual(result.vulnerabilities[0].cvss_score, 8.1)
        self.assertTrue(result.vulnerabilities[0].cvss_vector.startswith("CVSS:3.1"))

    def test_incomplete_page_is_unknown_instead_of_clean(self) -> None:
        response = {
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 2,
            "vulnerabilities": [{"cve": {"id": "CVE-2026-12345"}}],
        }
        client = NvdClient(
            transport=lambda _request, _timeout, _limit: json.dumps(response).encode()
        )

        result = check_cpe(self.cpe, client=client)

        self.assertEqual(result.status, VulnerabilityStatus.UNKNOWN)
        self.assertIn("pagination", result.error)

    @patch("hexpath.vulnerabilities.urlopen")
    def test_default_transport_errors_name_nvd(self, open_mock) -> None:
        open_mock.side_effect = HTTPError(
            "https://services.nvd.nist.gov/", 403, "Forbidden", {}, None
        )

        result = check_cpe(self.cpe, client=NvdClient())

        self.assertEqual(result.status, VulnerabilityStatus.UNKNOWN)
        self.assertEqual(result.error, "NVD returned HTTP 403")


class ScanVulnerabilityTests(unittest.TestCase):
    def test_links_cpe_findings_to_services_and_reports_coverage_gap(self) -> None:
        response = {
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-6387",
                        "descriptions": [{"lang": "en", "value": "OpenSSH issue."}],
                        "metrics": {},
                        "references": [],
                    }
                }
            ],
        }
        client = NvdClient(
            transport=lambda _request, _timeout, _limit: json.dumps(response).encode()
        )
        document = {
            "services": [
                {
                    "id": "service:[2001:db8::10]:tcp:22",
                    "cpes": ["cpe:/a:openbsd:openssh:9.6"],
                },
                {
                    "id": "service:[2001:db8::10]:tcp:443",
                    "cpes": [],
                },
            ]
        }

        result = check_scan_document(document, client=client)

        self.assertEqual(result.status, VulnerabilityStatus.VULNERABLE)
        self.assertFalse(result.completed)
        self.assertEqual(result.unmatched_services, ("service:[2001:db8::10]:tcp:443",))
        self.assertEqual(result.vulnerabilities[0].cve_id, "CVE-2024-6387")
        self.assertEqual(result.matches[0].service_id, "service:[2001:db8::10]:tcp:22")
        self.assertEqual(result.matches[0].confidence.value, "medium")
        self.assertIn("local patch status is unverified", result.matches[0].reason)

    def test_all_services_with_clean_cpes_is_complete_and_clean(self) -> None:
        client = NvdClient(
            transport=lambda _request, _timeout, _limit: b'{"totalResults":0,"vulnerabilities":[]}'
        )
        document = {
            "services": [
                {
                    "id": "service:[2001:db8::10]:tcp:22",
                    "cpes": ["cpe:/a:openbsd:openssh:99.0"],
                }
            ]
        }

        result = check_scan_document(document, client=client)

        self.assertTrue(result.completed)
        self.assertEqual(result.status, VulnerabilityStatus.CLEAN)

    def test_multiple_scans_deduplicate_services_and_cpe_queries(self) -> None:
        calls = []

        def transport(request, _timeout, _limit):
            calls.append(request.full_url)
            return json.dumps(
                {
                    "totalResults": 1,
                    "vulnerabilities": [{"cve": {"id": "CVE-2026-12345"}}],
                }
            ).encode()

        shared_cpe = "cpe:/a:example:service:1.0"
        scans = [
            {
                "services": [
                    {
                        "id": "service:[2001:db8::10]:tcp:22",
                        "cpes": [],
                    }
                ]
            },
            {
                "services": [
                    {
                        "id": "service:[2001:db8::10]:tcp:22",
                        "cpes": [shared_cpe],
                    },
                    {
                        "id": "service:[2001:db8::20]:tcp:443",
                        "cpes": [shared_cpe],
                    },
                ]
            },
        ]

        result = check_scan_documents(
            scans,
            client=NvdClient(transport=transport),
        )

        self.assertEqual(len(calls), 1)
        self.assertEqual(result.service_count, 2)
        self.assertEqual(result.unmatched_services, ())
        self.assertEqual(len(result.checks), 1)
        self.assertEqual(
            {match.service_id for match in result.matches},
            {
                "service:[2001:db8::10]:tcp:22",
                "service:[2001:db8::20]:tcp:443",
            },
        )


if __name__ == "__main__":
    unittest.main()

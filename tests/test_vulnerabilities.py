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
    VulnerabilityHttpError,
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
            transport=lambda _request, _timeout, _limit: json.dumps(response).encode(),
            min_interval_seconds=0,
        )

        result = check_cpe(self.cpe, client=client)

        self.assertEqual(result.status, VulnerabilityStatus.UNKNOWN)
        self.assertIn("pagination", result.error)

    @patch("hexpath.vulnerabilities.urlopen")
    def test_default_transport_errors_name_nvd(self, open_mock) -> None:
        open_mock.side_effect = HTTPError(
            "https://services.nvd.nist.gov/", 404, "Not Found", {}, None
        )

        result = check_cpe(self.cpe, client=NvdClient())

        self.assertEqual(result.status, VulnerabilityStatus.UNKNOWN)
        self.assertEqual(result.error, "NVD returned HTTP 404")

    @patch("hexpath.vulnerabilities.urlopen")
    def test_default_transport_honours_retry_after_header(self, open_mock) -> None:
        fake_time = FakeTime()
        open_mock.side_effect = HTTPError(
            "https://services.nvd.nist.gov/",
            429,
            "Too Many Requests",
            {"Retry-After": "7"},
            None,
        )
        client = NvdClient(max_retries=1, sleep=fake_time.sleep, clock=fake_time.clock)

        result = check_cpe(self.cpe, client=client)

        self.assertEqual(open_mock.call_count, 2)
        self.assertEqual(fake_time.sleeps, [7.0])
        self.assertEqual(result.status, VulnerabilityStatus.UNKNOWN)


class FakeTime:
    """A controllable clock so rate-limit tests never really sleep."""

    def __init__(self) -> None:
        self.now = 100.0
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(round(seconds, 4))
        self.now += seconds


def nvd_page(cve_ids: list[str], *, total: int, start: int = 0) -> bytes:
    return json.dumps(
        {
            "resultsPerPage": len(cve_ids),
            "startIndex": start,
            "totalResults": total,
            "vulnerabilities": [{"cve": {"id": cve_id}} for cve_id in cve_ids],
        }
    ).encode()


def throttled(status: int = 429, retry_after: float | None = None) -> VulnerabilityHttpError:
    return VulnerabilityHttpError(
        f"NVD returned HTTP {status}",
        status=status,
        retry_after=retry_after,
    )


class NvdRateLimitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.time = FakeTime()
        self.ssh = CpeIdentity("cpe:/a:openbsd:openssh:9.6")
        self.web = CpeIdentity("cpe:/a:apache:http_server:2.4.58")

    def client(self, transport, **options) -> NvdClient:
        return NvdClient(
            transport=transport,
            sleep=self.time.sleep,
            clock=self.time.clock,
            **options,
        )

    def test_spaces_requests_six_seconds_apart_without_api_key(self) -> None:
        client = self.client(lambda *_args: nvd_page([], total=0))

        check_cpe(self.ssh, client=client)
        check_cpe(self.web, client=client)

        self.assertEqual(self.time.sleeps, [6.0])

    def test_api_key_allows_shorter_spacing(self) -> None:
        client = self.client(lambda *_args: nvd_page([], total=0), api_key="key")

        check_cpe(self.ssh, client=client)
        check_cpe(self.web, client=client)

        self.assertEqual(self.time.sleeps, [0.6])

    def test_no_wait_when_enough_time_has_already_passed(self) -> None:
        client = self.client(lambda *_args: nvd_page([], total=0))

        check_cpe(self.ssh, client=client)
        self.time.now += 10
        check_cpe(self.web, client=client)

        self.assertEqual(self.time.sleeps, [])

    def test_throttled_request_is_retried_with_backoff(self) -> None:
        responses = [throttled(429), nvd_page(["CVE-2024-6387"], total=1)]

        def transport(*_args):
            response = responses.pop(0)
            if isinstance(response, Exception):
                raise response
            return response

        result = check_cpe(self.ssh, client=self.client(transport))

        self.assertEqual(result.status, VulnerabilityStatus.VULNERABLE)
        self.assertEqual(result.vulnerabilities[0].cve_id, "CVE-2024-6387")
        self.assertEqual(self.time.sleeps, [6.0])

    def test_retry_after_header_overrides_backoff(self) -> None:
        responses = [throttled(503, retry_after=20), nvd_page([], total=0)]

        def transport(*_args):
            response = responses.pop(0)
            if isinstance(response, Exception):
                raise response
            return response

        result = check_cpe(self.ssh, client=self.client(transport))

        self.assertTrue(result.completed)
        self.assertEqual(self.time.sleeps, [20.0])

    def test_gives_up_after_max_retries_and_stays_unknown(self) -> None:
        calls = []

        def transport(*_args):
            calls.append(1)
            raise throttled(403)

        result = check_cpe(self.ssh, client=self.client(transport, max_retries=2))

        self.assertEqual(len(calls), 3)
        self.assertEqual(self.time.sleeps, [6.0, 12.0])
        self.assertEqual(result.status, VulnerabilityStatus.UNKNOWN)
        self.assertIn("after 2 retries", result.error)
        self.assertIn("NVD_API_KEY", result.error)

    def test_other_http_errors_are_not_retried(self) -> None:
        calls = []

        def transport(*_args):
            calls.append(1)
            raise throttled(404)

        result = check_cpe(self.ssh, client=self.client(transport))

        self.assertEqual(len(calls), 1)
        self.assertEqual(result.error, "NVD returned HTTP 404")

    def test_rejects_invalid_rate_limit_settings(self) -> None:
        with self.assertRaisesRegex(VulnerabilityError, "min_interval_seconds"):
            NvdClient(min_interval_seconds=-1)
        with self.assertRaisesRegex(VulnerabilityError, "max_retries"):
            NvdClient(max_retries=-1)


class NvdPaginationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.time = FakeTime()
        self.cpe = CpeIdentity("cpe:/o:linux:linux_kernel:6.1")

    def client(self, transport) -> NvdClient:
        return NvdClient(transport=transport, sleep=self.time.sleep, clock=self.time.clock)

    def test_fetches_every_page_until_total_is_reached(self) -> None:
        pages = [
            nvd_page(["CVE-2026-0001", "CVE-2026-0002"], total=3, start=0),
            nvd_page(["CVE-2026-0003"], total=3, start=2),
        ]
        urls = []

        def transport(request, *_args):
            urls.append(request.full_url)
            return pages.pop(0)

        result = check_cpe(self.cpe, client=self.client(transport))

        self.assertTrue(result.completed)
        self.assertEqual(
            [item.cve_id for item in result.vulnerabilities],
            ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"],
        )
        self.assertIn("resultsPerPage=2000", urls[0])
        self.assertIn("startIndex=0", urls[0])
        self.assertIn("startIndex=2", urls[1])
        self.assertEqual(self.time.sleeps, [6.0])

    def test_empty_page_before_total_is_unknown(self) -> None:
        pages = [
            nvd_page(["CVE-2026-0001"], total=3, start=0),
            nvd_page([], total=3, start=1),
        ]

        result = check_cpe(self.cpe, client=self.client(lambda *_args: pages.pop(0)))

        self.assertEqual(result.status, VulnerabilityStatus.UNKNOWN)
        self.assertIn("empty page after 1 of 3", result.error)

    def test_changed_total_between_pages_is_unknown(self) -> None:
        pages = [
            nvd_page(["CVE-2026-0001"], total=2, start=0),
            nvd_page(["CVE-2026-0002"], total=5, start=1),
        ]

        result = check_cpe(self.cpe, client=self.client(lambda *_args: pages.pop(0)))

        self.assertEqual(result.status, VulnerabilityStatus.UNKNOWN)
        self.assertIn("count changed", result.error)


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

    def test_scan_with_no_services_is_unknown_not_clean(self) -> None:
        queried: list[str] = []

        def transport(request, _timeout, _limit):
            queried.append(request.full_url)
            return b'{"totalResults":0,"vulnerabilities":[]}'

        result = check_scan_document(
            {"hosts": [{"id": "host:2001:db8::10"}], "services": []},
            client=NvdClient(transport=transport),
        )

        self.assertEqual(queried, [])
        self.assertEqual(result.service_count, 0)
        self.assertFalse(result.completed)
        self.assertEqual(result.status, VulnerabilityStatus.UNKNOWN)

    def test_unparseable_cpe_is_reported_without_aborting_other_checks(self) -> None:
        queried: list[str] = []

        def transport(request, _timeout, _limit):
            queried.append(request.full_url)
            return b'{"totalResults":0,"vulnerabilities":[]}'

        document = {
            "services": [
                {
                    "id": "service:[2001:db8::10]:tcp:22",
                    "cpes": ["cpe:/a:openbsd:openssh:9.6"],
                },
                {
                    "id": "service:[2001:db8::10]:tcp:8080",
                    "cpes": ["cpe:/a:vendor:prod~uct:1.0"],
                },
            ]
        }

        result = check_scan_document(document, client=NvdClient(transport=transport))
        report = result.to_dict()

        self.assertEqual(len(queried), 1)
        self.assertIn("openssh", queried[0])
        self.assertFalse(result.completed)
        self.assertEqual(result.status, VulnerabilityStatus.UNKNOWN)
        self.assertEqual(result.unmatched_services, ())
        self.assertEqual(report["coverage"]["invalid_cpes"], 1)
        self.assertEqual(
            report["invalid_cpes"][0]["service_id"],
            "service:[2001:db8::10]:tcp:8080",
        )
        self.assertEqual(report["invalid_cpes"][0]["cpe"], "cpe:/a:vendor:prod~uct:1.0")
        self.assertIn("CPE 2.3 format", report["invalid_cpes"][0]["error"])

    def test_findings_still_reported_when_another_cpe_is_unparseable(self) -> None:
        response = {
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-6387",
                        "descriptions": [{"lang": "en", "value": "OpenSSH issue."}],
                    }
                }
            ],
        }
        document = {
            "services": [
                {
                    "id": "service:[2001:db8::10]:tcp:22",
                    "cpes": ["cpe:/a:openbsd:openssh:9.6", "not-a-cpe"],
                }
            ]
        }
        client = NvdClient(
            transport=lambda _request, _timeout, _limit: json.dumps(response).encode()
        )

        result = check_scan_document(document, client=client)

        self.assertEqual(result.status, VulnerabilityStatus.VULNERABLE)
        self.assertFalse(result.completed)
        self.assertEqual(result.matches[0].cve_id, "CVE-2024-6387")
        self.assertEqual(result.invalid_cpes[0].cpe, "not-a-cpe")

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

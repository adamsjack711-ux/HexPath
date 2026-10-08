"""Tests for HexPath's evidence and assessment records."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import unittest

from hexpath.models import (
    AssessmentResult,
    Confidence,
    Evidence,
    EvidenceLevel,
    Host,
    ModelError,
    Service,
    ServiceState,
    TransportProtocol,
    Vulnerability,
    VulnerabilityMatch,
)


COLLECTED_AT = datetime(2026, 10, 8, 18, 30, tzinfo=timezone.utc)


def observed_evidence() -> Evidence:
    return Evidence(
        source="nmap",
        summary="TCP port 22 reported open",
        level=EvidenceLevel.OBSERVED,
        collected_at=COLLECTED_AT,
        reference="scan.xml#host-1-port-22",
    )


def sample_records() -> tuple[
    Host, Service, Vulnerability, VulnerabilityMatch
]:
    evidence = observed_evidence()
    host = Host(
        address="2001:db8:1::10",
        hostnames=("server.lab",),
        evidence=(evidence,),
    )
    service = Service(
        host=host.address,
        port=22,
        protocol=TransportProtocol.TCP,
        state=ServiceState.OPEN,
        name="ssh",
        product="OpenSSH",
        version="9.6",
        cpes=("cpe:/a:openbsd:openssh:9.6",),
        evidence=(evidence,),
    )
    vulnerability = Vulnerability(
        cve_id="cve-2026-12345",
        description="Example vulnerability used by the test suite.",
        cvss_score=7.5,
        cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N",
    )
    match = VulnerabilityMatch(
        service_id=service.record_id,
        cve_id=vulnerability.cve_id,
        confidence=Confidence.MEDIUM,
        reason="The observed product and version overlap the published range.",
        evidence=(evidence,),
    )
    return host, service, vulnerability, match


class EvidenceTests(unittest.TestCase):
    def test_evidence_requires_timezone(self) -> None:
        with self.assertRaisesRegex(ModelError, "timezone"):
            Evidence(
                source="nmap",
                summary="host responded",
                level=EvidenceLevel.OBSERVED,
                collected_at=datetime(2026, 10, 8, 18, 30),
            )

    def test_evidence_accepts_enum_value_as_string(self) -> None:
        evidence = Evidence(
            source="reviewer",
            summary="configuration checked",
            level="validated",
            collected_at=COLLECTED_AT,
        )

        self.assertEqual(evidence.level, EvidenceLevel.VALIDATED)


class HostAndServiceTests(unittest.TestCase):
    def test_host_rejects_ipv4(self) -> None:
        with self.assertRaisesRegex(ModelError, "IPv6"):
            Host(address="192.0.2.10")

    def test_service_has_stable_record_id(self) -> None:
        _, service, _, _ = sample_records()

        self.assertEqual(
            service.record_id,
            "service:[2001:db8:1::10]:tcp:22",
        )
        self.assertEqual(service.cpes, ("cpe:/a:openbsd:openssh:9.6",))

    def test_service_rejects_invalid_port(self) -> None:
        with self.assertRaisesRegex(ModelError, "between 1 and 65535"):
            Service(
                host="2001:db8::1",
                port=70000,
                protocol=TransportProtocol.TCP,
                state=ServiceState.OPEN,
            )

    def _service_with_cpe(self, cpe: str) -> Service:
        return Service(
            host="2001:db8::1",
            port=22,
            protocol=TransportProtocol.TCP,
            state=ServiceState.OPEN,
            cpes=(cpe,),
        )

    def test_service_accepts_well_formed_cpes(self) -> None:
        for cpe in (
            "cpe:/a:openbsd:openssh:9.6",
            "cpe:/o:linux:linux_kernel",
            "cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*",
            "cpe:/a:vendor:prod~uct:1.0",
        ):
            with self.subTest(cpe=cpe):
                self.assertEqual(self._service_with_cpe(cpe).cpes, (cpe,))

    def test_service_rejects_structurally_invalid_cpes(self) -> None:
        for cpe in (
            "cpe:/x:bad:part",
            "cpe:/a",
            "cpe:/a:a:b:c:d:e:f:g",
            "cpe:2.3:a:only:five:fields",
            "not-a-cpe",
        ):
            with self.subTest(cpe=cpe):
                with self.assertRaises(ModelError):
                    self._service_with_cpe(cpe)


class VulnerabilityTests(unittest.TestCase):
    def test_vulnerability_normalizes_cve_identifier(self) -> None:
        vulnerability = Vulnerability(
            cve_id="cve-2026-12345",
            description="Example vulnerability.",
        )

        self.assertEqual(vulnerability.cve_id, "CVE-2026-12345")

    def test_vulnerability_rejects_score_above_ten(self) -> None:
        with self.assertRaisesRegex(ModelError, "between 0.0 and 10.0"):
            Vulnerability(
                cve_id="CVE-2026-12345",
                description="Example vulnerability.",
                cvss_score=10.1,
            )

    def test_match_requires_evidence(self) -> None:
        with self.assertRaisesRegex(ModelError, "supporting evidence"):
            VulnerabilityMatch(
                service_id="service:[2001:db8::1]:tcp:22",
                cve_id="CVE-2026-12345",
                confidence=Confidence.LOW,
                reason="Version information was incomplete.",
                evidence=(),
            )


class AssessmentResultTests(unittest.TestCase):
    def test_rejects_service_without_matching_host(self) -> None:
        _, service, _, _ = sample_records()

        with self.assertRaisesRegex(ModelError, "host not in the assessment"):
            AssessmentResult(
                name="lab scan",
                scope_name="test lab",
                started_at=COLLECTED_AT,
                services=(service,),
            )

    def test_rejects_match_with_unknown_cve(self) -> None:
        host, service, _, match = sample_records()

        with self.assertRaisesRegex(ModelError, "unknown CVE"):
            AssessmentResult(
                name="lab scan",
                scope_name="test lab",
                started_at=COLLECTED_AT,
                hosts=(host,),
                services=(service,),
                vulnerability_matches=(match,),
            )

    def test_serializes_complete_assessment_to_json(self) -> None:
        host, service, vulnerability, match = sample_records()
        result = AssessmentResult(
            assessment_id="assessment-001",
            name="lab scan",
            scope_name="test lab",
            started_at=COLLECTED_AT,
            completed_at=datetime(2026, 10, 8, 18, 35, tzinfo=timezone.utc),
            hosts=(host,),
            services=(service,),
            vulnerabilities=(vulnerability,),
            vulnerability_matches=(match,),
        )

        document = json.loads(result.to_json())

        self.assertEqual(document["assessment_id"], "assessment-001")
        self.assertEqual(document["hosts"][0]["address"], "2001:db8:1::10")
        self.assertEqual(document["services"][0]["product"], "OpenSSH")
        self.assertEqual(
            document["vulnerability_matches"][0]["confidence"],
            "medium",
        )
        self.assertEqual(
            document["vulnerability_matches"][0]["evidence"][0]["level"],
            "observed",
        )


if __name__ == "__main__":
    unittest.main()

"""Core evidence and assessment records used throughout HexPath."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address, ip_address
import json
import re
from typing import Any
from uuid import uuid4


_CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
_CPE_PREFIXES = ("cpe:/", "cpe:2.3:")
IPAddress = IPv4Address | IPv6Address


class ModelError(ValueError):
    """Raised when a HexPath domain record is inconsistent or invalid."""


class EvidenceLevel(StrEnum):
    """How strongly a piece of information has been established."""

    OBSERVED = "observed"
    INFERRED = "inferred"
    VALIDATED = "validated"


class Confidence(StrEnum):
    """Confidence assigned to an inferred relationship."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class TransportProtocol(StrEnum):
    """Transport protocols represented by service records."""

    TCP = "tcp"
    UDP = "udp"
    SCTP = "sctp"


class ServiceState(StrEnum):
    """Relevant service states reported by a scanner."""

    OPEN = "open"
    OPEN_FILTERED = "open|filtered"
    FILTERED = "filtered"
    CLOSED = "closed"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _require_text(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ModelError(f"{field_name} must be a non-empty string")
    return value.strip()


def _require_aware_datetime(value: datetime, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise ModelError(f"{field_name} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ModelError(f"{field_name} must include a timezone")
    return value


def _parse_ip(value: IPAddress | str, field_name: str) -> IPAddress:
    try:
        address = ip_address(value)
    except ValueError as error:
        raise ModelError(f"{field_name} must be a valid IP address") from error
    return address


def _normalize_cve_id(value: str) -> str:
    cve_id = _require_text(value, "cve_id").upper()
    if not _CVE_PATTERN.fullmatch(cve_id):
        raise ModelError("cve_id must use the format CVE-YYYY-NNNN")
    return cve_id


def _normalize_cpe(value: str) -> str:
    cpe = _require_text(value, "cpe")
    if not cpe.startswith(_CPE_PREFIXES):
        raise ModelError("cpe must use CPE 2.2 URI or CPE 2.3 formatted syntax")
    return cpe


def _require_unique(values: tuple[str, ...], record_name: str) -> None:
    if len(values) != len(set(values)):
        raise ModelError(f"assessment contains duplicate {record_name} records")


@dataclass(frozen=True, slots=True)
class Evidence:
    """A traceable statement supporting a HexPath record or relationship."""

    source: str
    summary: str
    level: EvidenceLevel
    collected_at: datetime = field(default_factory=_utc_now)
    reference: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "source", _require_text(self.source, "source"))
        object.__setattr__(self, "summary", _require_text(self.summary, "summary"))
        try:
            level = EvidenceLevel(self.level)
        except ValueError as error:
            raise ModelError(f"invalid evidence level: {self.level!r}") from error
        object.__setattr__(self, "level", level)
        object.__setattr__(
            self,
            "collected_at",
            _require_aware_datetime(self.collected_at, "collected_at"),
        )
        if self.reference is not None:
            object.__setattr__(
                self,
                "reference",
                _require_text(self.reference, "reference"),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "summary": self.summary,
            "level": self.level.value,
            "collected_at": self.collected_at.isoformat(),
            "reference": self.reference,
        }


@dataclass(frozen=True, slots=True)
class Host:
    """An IPv4 or IPv6 host identified during an assessment."""

    address: IPAddress | str
    hostnames: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "address", _parse_ip(self.address, "host address"))
        hostnames = tuple(_require_text(name, "hostname") for name in self.hostnames)
        object.__setattr__(self, "hostnames", hostnames)
        object.__setattr__(self, "evidence", tuple(self.evidence))

    @property
    def record_id(self) -> str:
        return f"host:{self.address.compressed}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.record_id,
            "address": self.address.compressed,
            "hostnames": list(self.hostnames),
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass(frozen=True, slots=True)
class Service:
    """A network service associated with an IP host."""

    host: IPAddress | str
    port: int
    protocol: TransportProtocol
    state: ServiceState
    name: str | None = None
    product: str | None = None
    version: str | None = None
    cpes: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "host", _parse_ip(self.host, "service host"))
        if isinstance(self.port, bool) or not isinstance(self.port, int):
            raise ModelError("service port must be an integer")
        if not 1 <= self.port <= 65535:
            raise ModelError("service port must be between 1 and 65535")
        try:
            protocol = TransportProtocol(self.protocol)
        except ValueError as error:
            raise ModelError(f"invalid transport protocol: {self.protocol!r}") from error
        try:
            state = ServiceState(self.state)
        except ValueError as error:
            raise ModelError(f"invalid service state: {self.state!r}") from error
        object.__setattr__(self, "protocol", protocol)
        object.__setattr__(self, "state", state)
        for field_name in ("name", "product", "version"):
            value = getattr(self, field_name)
            if value is not None:
                object.__setattr__(self, field_name, _require_text(value, field_name))
        cpes = tuple(_normalize_cpe(cpe) for cpe in self.cpes)
        if len(cpes) != len(set(cpes)):
            raise ModelError("service contains duplicate CPE records")
        object.__setattr__(self, "cpes", cpes)
        object.__setattr__(self, "evidence", tuple(self.evidence))

    @property
    def record_id(self) -> str:
        return f"service:[{self.host.compressed}]:{self.protocol.value}:{self.port}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.record_id,
            "host": self.host.compressed,
            "port": self.port,
            "protocol": self.protocol.value,
            "state": self.state.value,
            "name": self.name,
            "product": self.product,
            "version": self.version,
            "cpes": list(self.cpes),
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass(frozen=True, slots=True)
class Vulnerability:
    """Published vulnerability metadata independent of a particular host."""

    cve_id: str
    description: str
    cvss_score: float | None = None
    cvss_vector: str | None = None
    references: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "cve_id", _normalize_cve_id(self.cve_id))
        object.__setattr__(
            self,
            "description",
            _require_text(self.description, "description"),
        )
        if self.cvss_score is not None:
            if isinstance(self.cvss_score, bool) or not isinstance(
                self.cvss_score, (int, float)
            ):
                raise ModelError("cvss_score must be a number")
            score = float(self.cvss_score)
            if not 0.0 <= score <= 10.0:
                raise ModelError("cvss_score must be between 0.0 and 10.0")
            object.__setattr__(self, "cvss_score", score)
        if self.cvss_vector is not None:
            object.__setattr__(
                self,
                "cvss_vector",
                _require_text(self.cvss_vector, "cvss_vector"),
            )
        references = tuple(
            _require_text(reference, "vulnerability reference")
            for reference in self.references
        )
        object.__setattr__(self, "references", references)

    @property
    def record_id(self) -> str:
        return self.cve_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.record_id,
            "description": self.description,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "references": list(self.references),
        }


@dataclass(frozen=True, slots=True)
class VulnerabilityMatch:
    """An evidence-backed candidate link between a service and a CVE."""

    service_id: str
    cve_id: str
    confidence: Confidence
    reason: str
    evidence: tuple[Evidence, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "service_id",
            _require_text(self.service_id, "service_id"),
        )
        object.__setattr__(self, "cve_id", _normalize_cve_id(self.cve_id))
        try:
            confidence = Confidence(self.confidence)
        except ValueError as error:
            raise ModelError(f"invalid confidence: {self.confidence!r}") from error
        object.__setattr__(self, "confidence", confidence)
        object.__setattr__(self, "reason", _require_text(self.reason, "reason"))
        evidence = tuple(self.evidence)
        if not evidence:
            raise ModelError("a vulnerability match must include supporting evidence")
        object.__setattr__(self, "evidence", evidence)

    @property
    def record_id(self) -> str:
        return f"match:{self.service_id}:{self.cve_id}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.record_id,
            "service_id": self.service_id,
            "cve_id": self.cve_id,
            "confidence": self.confidence.value,
            "reason": self.reason,
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass(frozen=True, slots=True)
class AssessmentResult:
    """A consistent, serializable snapshot of one HexPath assessment."""

    name: str
    scope_name: str
    started_at: datetime
    hosts: tuple[Host, ...] = ()
    services: tuple[Service, ...] = ()
    vulnerabilities: tuple[Vulnerability, ...] = ()
    vulnerability_matches: tuple[VulnerabilityMatch, ...] = ()
    completed_at: datetime | None = None
    assessment_id: str = field(default_factory=lambda: str(uuid4()))

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _require_text(self.name, "assessment name"))
        object.__setattr__(
            self,
            "scope_name",
            _require_text(self.scope_name, "scope_name"),
        )
        object.__setattr__(
            self,
            "assessment_id",
            _require_text(self.assessment_id, "assessment_id"),
        )
        started_at = _require_aware_datetime(self.started_at, "started_at")
        object.__setattr__(self, "started_at", started_at)
        if self.completed_at is not None:
            completed_at = _require_aware_datetime(self.completed_at, "completed_at")
            if completed_at < started_at:
                raise ModelError("completed_at cannot be before started_at")
            object.__setattr__(self, "completed_at", completed_at)

        hosts = tuple(self.hosts)
        services = tuple(self.services)
        vulnerabilities = tuple(self.vulnerabilities)
        matches = tuple(self.vulnerability_matches)
        object.__setattr__(self, "hosts", hosts)
        object.__setattr__(self, "services", services)
        object.__setattr__(self, "vulnerabilities", vulnerabilities)
        object.__setattr__(self, "vulnerability_matches", matches)

        host_ids = tuple(host.record_id for host in hosts)
        service_ids = tuple(service.record_id for service in services)
        vulnerability_ids = tuple(item.record_id for item in vulnerabilities)
        match_ids = tuple(match.record_id for match in matches)
        _require_unique(host_ids, "host")
        _require_unique(service_ids, "service")
        _require_unique(vulnerability_ids, "vulnerability")
        _require_unique(match_ids, "vulnerability match")

        host_addresses = {host.address for host in hosts}
        for service in services:
            if service.host not in host_addresses:
                raise ModelError(
                    f"service {service.record_id} refers to a host not in the assessment"
                )

        service_id_set = set(service_ids)
        vulnerability_id_set = set(vulnerability_ids)
        for match in matches:
            if match.service_id not in service_id_set:
                raise ModelError(
                    f"vulnerability match refers to unknown service {match.service_id!r}"
                )
            if match.cve_id not in vulnerability_id_set:
                raise ModelError(
                    f"vulnerability match refers to unknown CVE {match.cve_id!r}"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "name": self.name,
            "scope_name": self.scope_name,
            "started_at": self.started_at.isoformat(),
            "completed_at": (
                self.completed_at.isoformat() if self.completed_at is not None else None
            ),
            "hosts": [host.to_dict() for host in self.hosts],
            "services": [service.to_dict() for service in self.services],
            "vulnerabilities": [item.to_dict() for item in self.vulnerabilities],
            "vulnerability_matches": [
                match.to_dict() for match in self.vulnerability_matches
            ],
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

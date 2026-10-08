"""Known-vulnerability providers used by HexPath.

The OSV client carries forward pkgxray's core lookup invariants: query exact
package versions, bound remote responses, reject malformed results, and never
describe an incomplete lookup as clean.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import json
import math
import re
import time
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from hexpath.models import (
    Confidence,
    Evidence,
    EvidenceLevel,
    Vulnerability,
    VulnerabilityMatch,
)


OSV_QUERY_URL = "https://api.osv.dev/v1/query"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024
NVD_RESULTS_PER_PAGE = 2000
NVD_INTERVAL_WITHOUT_KEY_SECONDS = 6.0
NVD_INTERVAL_WITH_KEY_SECONDS = 0.6
NVD_DEFAULT_MAX_RETRIES = 3
MAX_RETRY_AFTER_SECONDS = 120.0
_RETRYABLE_HTTP_STATUSES = frozenset({403, 429, 503})
_CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$", re.IGNORECASE)


class VulnerabilityError(ValueError):
    """Base error for invalid vulnerability-check inputs."""


class VulnerabilityLookupError(RuntimeError):
    """Raised when a vulnerability provider cannot complete a lookup."""


class VulnerabilityHttpError(VulnerabilityLookupError):
    """A provider answered with an HTTP error status."""

    def __init__(
        self,
        message: str,
        *,
        status: int,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


class VulnerabilityStatus(StrEnum):
    """Outcome of a known-vulnerability lookup."""

    CLEAN = "clean"
    VULNERABLE = "vulnerable"
    UNKNOWN = "unknown"


def _required_text(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise VulnerabilityError(f"{field_name} must be a non-empty string")
    return value.strip()


@dataclass(frozen=True, slots=True)
class PackageIdentity:
    """An exact package coordinate accepted by OSV."""

    ecosystem: str
    name: str
    version: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "ecosystem",
            _required_text(self.ecosystem, "ecosystem"),
        )
        object.__setattr__(self, "name", _required_text(self.name, "package name"))
        object.__setattr__(
            self,
            "version",
            _required_text(self.version, "package version"),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "ecosystem": self.ecosystem,
            "name": self.name,
            "version": self.version,
        }


@dataclass(frozen=True, slots=True)
class CpeIdentity:
    """A service CPE normalized to the CPE 2.3 formatted binding NVD expects."""

    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _normalize_cpe(self.value))

    def to_dict(self) -> dict[str, str]:
        return {"cpe": self.value}


@dataclass(frozen=True, slots=True)
class OsvAdvisory:
    """A validated OSV advisory returned for one exact package identity."""

    advisory_id: str
    aliases: tuple[str, ...] = ()
    summary: str | None = None
    details: str | None = None
    severity_vectors: tuple[str, ...] = ()
    references: tuple[str, ...] = ()

    @property
    def cve_ids(self) -> tuple[str, ...]:
        identifiers = (self.advisory_id, *self.aliases)
        return tuple(
            dict.fromkeys(
                identifier.upper()
                for identifier in identifiers
                if _CVE_PATTERN.fullmatch(identifier)
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.advisory_id,
            "aliases": list(self.aliases),
            "cve_ids": list(self.cve_ids),
            "summary": self.summary,
            "details": self.details,
            "severity_vectors": list(self.severity_vectors),
            "references": list(self.references),
        }


@dataclass(frozen=True, slots=True)
class PackageVulnerabilityResult:
    """A complete, failed, or unknown OSV check for one exact package."""

    package: PackageIdentity
    completed: bool
    advisories: tuple[OsvAdvisory, ...] = ()
    error: str | None = None
    source: str = "OSV"

    def __post_init__(self) -> None:
        object.__setattr__(self, "advisories", tuple(self.advisories))
        if self.completed and self.error is not None:
            raise VulnerabilityError("a completed lookup cannot contain an error")
        if not self.completed and not self.error:
            raise VulnerabilityError("an incomplete lookup must explain its error")
        if not self.completed and self.advisories:
            raise VulnerabilityError("an incomplete lookup cannot contain advisories")

    @property
    def status(self) -> VulnerabilityStatus:
        if not self.completed:
            return VulnerabilityStatus.UNKNOWN
        if self.advisories:
            return VulnerabilityStatus.VULNERABLE
        return VulnerabilityStatus.CLEAN

    @property
    def vulnerabilities(self) -> tuple[Vulnerability, ...]:
        """Convert CVE aliases from OSV advisories into HexPath records."""
        records: dict[str, Vulnerability] = {}
        for advisory in self.advisories:
            description = (
                advisory.summary
                or advisory.details
                or f"Published vulnerability {advisory.advisory_id}"
            )
            vector = next(
                (item for item in advisory.severity_vectors if item.startswith("CVSS:")),
                None,
            )
            for cve_id in advisory.cve_ids:
                if cve_id not in records:
                    records[cve_id] = Vulnerability(
                        cve_id=cve_id,
                        description=description,
                        cvss_vector=vector,
                        references=advisory.references,
                    )
        return tuple(records.values())

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "status": self.status.value,
            "completed": self.completed,
            "error": self.error,
            "package": self.package.to_dict(),
            "advisories": [item.to_dict() for item in self.advisories],
            "vulnerabilities": [item.to_dict() for item in self.vulnerabilities],
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


@dataclass(frozen=True, slots=True)
class CpeVulnerabilityResult:
    """A complete or failed NVD lookup for one service CPE."""

    cpe: CpeIdentity
    completed: bool
    vulnerabilities: tuple[Vulnerability, ...] = ()
    error: str | None = None
    source: str = "NVD"

    def __post_init__(self) -> None:
        object.__setattr__(self, "vulnerabilities", tuple(self.vulnerabilities))
        if self.completed and self.error is not None:
            raise VulnerabilityError("a completed lookup cannot contain an error")
        if not self.completed and not self.error:
            raise VulnerabilityError("an incomplete lookup must explain its error")
        if not self.completed and self.vulnerabilities:
            raise VulnerabilityError("an incomplete lookup cannot contain vulnerabilities")

    @property
    def status(self) -> VulnerabilityStatus:
        if not self.completed:
            return VulnerabilityStatus.UNKNOWN
        if self.vulnerabilities:
            return VulnerabilityStatus.VULNERABLE
        return VulnerabilityStatus.CLEAN

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "status": self.status.value,
            "completed": self.completed,
            "error": self.error,
            "cpe": self.cpe.value,
            "vulnerabilities": [item.to_dict() for item in self.vulnerabilities],
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


@dataclass(frozen=True, slots=True)
class InvalidCpe:
    """A service CPE that could not be normalized and was therefore not checked."""

    service_id: str
    cpe: str
    error: str

    def to_dict(self) -> dict[str, str]:
        return {"service_id": self.service_id, "cpe": self.cpe, "error": self.error}


@dataclass(frozen=True, slots=True)
class ScanVulnerabilityResult:
    """Aggregate CVE candidates and coverage for normalized scan services."""

    checks: tuple[CpeVulnerabilityResult, ...]
    vulnerabilities: tuple[Vulnerability, ...]
    matches: tuple[VulnerabilityMatch, ...]
    service_count: int
    unmatched_services: tuple[str, ...] = ()
    invalid_cpes: tuple[InvalidCpe, ...] = ()

    @property
    def completed(self) -> bool:
        # A scan with no services means nothing was checked, so the lookup is
        # not a completed "clean" result -- it is an absence of coverage.
        if self.service_count == 0:
            return False
        return (
            not self.unmatched_services
            and not self.invalid_cpes
            and all(check.completed for check in self.checks)
        )

    @property
    def status(self) -> VulnerabilityStatus:
        if self.matches:
            return VulnerabilityStatus.VULNERABLE
        if not self.completed:
            return VulnerabilityStatus.UNKNOWN
        return VulnerabilityStatus.CLEAN

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": "NVD",
            "status": self.status.value,
            "completed": self.completed,
            "coverage": {
                "services": self.service_count,
                "services_with_cpe": self.service_count - len(self.unmatched_services),
                "services_without_cpe": len(self.unmatched_services),
                "cpe_checks": len(self.checks),
                "completed_cpe_checks": sum(check.completed for check in self.checks),
                "invalid_cpes": len(self.invalid_cpes),
            },
            "unmatched_services": list(self.unmatched_services),
            "invalid_cpes": [item.to_dict() for item in self.invalid_cpes],
            "checks": [check.to_dict() for check in self.checks],
            "vulnerabilities": [item.to_dict() for item in self.vulnerabilities],
            "matches": [item.to_dict() for item in self.matches],
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


Transport = Callable[[Request, float, int], bytes]


class OsvClient:
    """Small, bounded client for OSV's exact package-version query API."""

    def __init__(
        self,
        *,
        timeout_seconds: float = 15,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        transport: Transport | None = None,
    ) -> None:
        if timeout_seconds <= 0:
            raise VulnerabilityError("timeout_seconds must be greater than zero")
        if max_response_bytes <= 0:
            raise VulnerabilityError("max_response_bytes must be greater than zero")
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self._transport = transport or _response_reader("OSV")

    def query_package(self, package: PackageIdentity) -> tuple[OsvAdvisory, ...]:
        payload = json.dumps(
            {
                "package": {
                    "name": package.name,
                    "ecosystem": package.ecosystem,
                },
                "version": package.version,
            }
        ).encode("utf-8")
        request = Request(
            OSV_QUERY_URL,
            data=payload,
            method="POST",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "hexpath/0.1.0 pkgxray-osv-adapter",
            },
        )
        try:
            raw_response = self._transport(
                request,
                self.timeout_seconds,
                self.max_response_bytes,
            )
            document = json.loads(raw_response)
        except VulnerabilityLookupError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise VulnerabilityLookupError("OSV returned invalid JSON") from error
        except Exception as error:
            raise VulnerabilityLookupError(f"OSV request failed: {error}") from error

        return _parse_osv_response(document)


class NvdClient:
    """Bounded, rate-limited client for exact CPE lookups in the NVD CVE API.

    NVD throttles callers: requests are spaced out (6 seconds apart without an
    API key, 0.6 seconds with one), throttling responses are retried with
    backoff, and results spread over several pages are all fetched.
    """

    def __init__(
        self,
        *,
        timeout_seconds: float = 30,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        api_key: str | None = None,
        transport: Transport | None = None,
        min_interval_seconds: float | None = None,
        max_retries: int = NVD_DEFAULT_MAX_RETRIES,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if timeout_seconds <= 0:
            raise VulnerabilityError("timeout_seconds must be greater than zero")
        if max_response_bytes <= 0:
            raise VulnerabilityError("max_response_bytes must be greater than zero")
        if isinstance(max_retries, bool) or not isinstance(max_retries, int) or max_retries < 0:
            raise VulnerabilityError("max_retries must be a non-negative integer")
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.api_key = api_key.strip() if api_key and api_key.strip() else None
        if min_interval_seconds is None:
            min_interval_seconds = (
                NVD_INTERVAL_WITH_KEY_SECONDS
                if self.api_key is not None
                else NVD_INTERVAL_WITHOUT_KEY_SECONDS
            )
        if not math.isfinite(min_interval_seconds) or min_interval_seconds < 0:
            raise VulnerabilityError("min_interval_seconds must be zero or greater")
        self.min_interval_seconds = float(min_interval_seconds)
        self.max_retries = max_retries
        self._transport = transport or _response_reader("NVD")
        self._sleep = sleep
        self._clock = clock
        self._last_request_at: float | None = None

    def query_cpe(self, cpe: CpeIdentity) -> tuple[Vulnerability, ...]:
        """Return every CVE NVD lists for the CPE, fetching all result pages."""
        collected: dict[str, Vulnerability] = {}
        received = 0
        expected_total: int | None = None
        while True:
            document = self._get_page(cpe, received)
            page, total = _parse_nvd_page(document, expected_start=received)
            if expected_total is None:
                expected_total = total
            elif total != expected_total:
                raise VulnerabilityLookupError(
                    "NVD result count changed during pagination; try the lookup again"
                )
            for vulnerability in page:
                collected.setdefault(vulnerability.cve_id, vulnerability)
            received += len(page)
            if received >= expected_total:
                break
            if not page:
                raise VulnerabilityLookupError(
                    f"NVD returned an empty page after {received} of "
                    f"{expected_total} results"
                )
        if received != expected_total:
            raise VulnerabilityLookupError(
                f"NVD returned {received} results but reported {expected_total}"
            )
        return tuple(collected.values())

    def _get_page(self, cpe: CpeIdentity, start_index: int) -> Any:
        query = urlencode(
            {
                "cpeName": cpe.value,
                "resultsPerPage": NVD_RESULTS_PER_PAGE,
                "startIndex": start_index,
            }
        )
        headers = {
            "Accept": "application/json",
            "User-Agent": "hexpath/0.1.0",
        }
        if self.api_key is not None:
            headers["apiKey"] = self.api_key
        request = Request(f"{NVD_CVE_URL}?{query}", headers=headers, method="GET")

        attempt = 0
        while True:
            self._wait_for_request_slot()
            try:
                raw_response = self._transport(
                    request,
                    self.timeout_seconds,
                    self.max_response_bytes,
                )
            except VulnerabilityHttpError as error:
                if error.status not in _RETRYABLE_HTTP_STATUSES:
                    raise
                if attempt >= self.max_retries:
                    raise VulnerabilityLookupError(
                        f"{error} after {self.max_retries} retries; "
                        + (
                            "NVD may be throttling requests or rejecting the API key"
                            if self.api_key is not None
                            else "NVD is throttling requests "
                            "(set NVD_API_KEY for a higher limit)"
                        )
                    ) from error
                self._sleep(self._retry_delay(error, attempt))
                attempt += 1
                continue
            except VulnerabilityLookupError:
                raise
            except Exception as error:
                raise VulnerabilityLookupError(f"NVD request failed: {error}") from error
            try:
                return json.loads(raw_response)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise VulnerabilityLookupError("NVD returned invalid JSON") from error

    def _wait_for_request_slot(self) -> None:
        if self._last_request_at is not None:
            remaining = self._last_request_at + self.min_interval_seconds - self._clock()
            if remaining > 0:
                self._sleep(remaining)
        self._last_request_at = self._clock()

    def _retry_delay(self, error: VulnerabilityHttpError, attempt: int) -> float:
        if error.retry_after is not None:
            return min(error.retry_after, MAX_RETRY_AFTER_SECONDS)
        return min(
            max(self.min_interval_seconds, 1.0) * (2**attempt),
            MAX_RETRY_AFTER_SECONDS,
        )


def check_package(
    package: PackageIdentity,
    *,
    client: OsvClient | None = None,
) -> PackageVulnerabilityResult:
    """Run an OSV lookup while preserving failure as an unknown outcome."""
    provider = client or OsvClient()
    try:
        advisories = provider.query_package(package)
    except VulnerabilityLookupError as error:
        return PackageVulnerabilityResult(
            package=package,
            completed=False,
            error=str(error),
        )
    return PackageVulnerabilityResult(
        package=package,
        completed=True,
        advisories=advisories,
    )


def check_cpe(
    cpe: CpeIdentity,
    *,
    client: NvdClient | None = None,
) -> CpeVulnerabilityResult:
    """Run an exact NVD CPE lookup while preserving incomplete coverage."""
    provider = client or NvdClient()
    try:
        vulnerabilities = provider.query_cpe(cpe)
    except VulnerabilityLookupError as error:
        return CpeVulnerabilityResult(
            cpe=cpe,
            completed=False,
            error=str(error),
        )
    return CpeVulnerabilityResult(
        cpe=cpe,
        completed=True,
        vulnerabilities=vulnerabilities,
    )


def check_scan_document(
    document: Any,
    *,
    client: NvdClient | None = None,
) -> ScanVulnerabilityResult:
    """Check every unique CPE in one normalized HexPath scan document."""
    return check_scan_documents((document,), client=client)


def check_scan_documents(
    documents: Any,
    *,
    client: NvdClient | None = None,
) -> ScanVulnerabilityResult:
    """Check unique CPEs across one or more normalized HexPath scans."""
    if not isinstance(documents, (list, tuple)) or not documents:
        raise VulnerabilityError("at least one scan document is required")

    cpe_services: dict[CpeIdentity, list[str]] = {}
    service_cpes: dict[str, list[CpeIdentity]] = {}
    invalid_cpes: dict[tuple[str, str], InvalidCpe] = {}
    for document in documents:
        if not isinstance(document, dict) or not isinstance(
            document.get("services"), list
        ):
            raise VulnerabilityError("scan document must contain a services list")
        seen_in_document: set[str] = set()
        for service in document["services"]:
            if not isinstance(service, dict):
                raise VulnerabilityError("scan document contains an invalid service")
            service_id = service.get("id")
            raw_cpes = service.get("cpes")
            if not isinstance(service_id, str) or not service_id.strip():
                raise VulnerabilityError("scan service is missing its identifier")
            if service_id in seen_in_document:
                raise VulnerabilityError(
                    f"scan contains duplicate service {service_id!r}"
                )
            seen_in_document.add(service_id)
            if not isinstance(raw_cpes, list) or any(
                not isinstance(item, str) for item in raw_cpes
            ):
                raise VulnerabilityError(
                    f"scan service {service_id!r} has invalid CPE data"
                )
            identities = service_cpes.setdefault(service_id, [])
            for raw_cpe in raw_cpes:
                try:
                    identity = CpeIdentity(raw_cpe)
                except VulnerabilityError as error:
                    invalid_cpes.setdefault(
                        (service_id, raw_cpe),
                        InvalidCpe(service_id=service_id, cpe=raw_cpe, error=str(error)),
                    )
                    continue
                if identity not in identities:
                    identities.append(identity)

    services_with_invalid_cpe = {item.service_id for item in invalid_cpes.values()}
    unmatched_services = [
        service_id
        for service_id, identities in service_cpes.items()
        if not identities and service_id not in services_with_invalid_cpe
    ]
    for service_id, identities in service_cpes.items():
        for identity in identities:
            linked_services = cpe_services.setdefault(identity, [])
            if service_id not in linked_services:
                linked_services.append(service_id)

    provider = client or NvdClient()
    checks = tuple(check_cpe(cpe, client=provider) for cpe in cpe_services)
    vulnerabilities: dict[str, Vulnerability] = {}
    matches: dict[tuple[str, str], VulnerabilityMatch] = {}
    for check in checks:
        if not check.completed:
            continue
        for vulnerability in check.vulnerabilities:
            vulnerabilities.setdefault(vulnerability.cve_id, vulnerability)
            for service_id in cpe_services[check.cpe]:
                key = (service_id, vulnerability.cve_id)
                if key in matches:
                    continue
                evidence = Evidence(
                    source="nvd",
                    summary=(
                        f"NVD reports {vulnerability.cve_id} as applicable to "
                        f"Nmap CPE {check.cpe.value}"
                    ),
                    level=EvidenceLevel.INFERRED,
                    reference=f"https://nvd.nist.gov/vuln/detail/{vulnerability.cve_id}",
                )
                matches[key] = VulnerabilityMatch(
                    service_id=service_id,
                    cve_id=vulnerability.cve_id,
                    confidence=Confidence.MEDIUM,
                    reason=(
                        "The service CPE reported by Nmap matches an NVD "
                        "applicability statement; local patch status is unverified."
                    ),
                    evidence=(evidence,),
                )

    return ScanVulnerabilityResult(
        checks=checks,
        vulnerabilities=tuple(vulnerabilities.values()),
        matches=tuple(matches.values()),
        service_count=len(service_cpes),
        unmatched_services=tuple(unmatched_services),
        invalid_cpes=tuple(invalid_cpes.values()),
    )


def _response_reader(provider: str) -> Transport:
    """Return a bounded HTTP transport whose errors name the given provider."""

    def read(request: Request, timeout_seconds: float, max_bytes: int) -> bytes:
        return _read_response(
            request,
            timeout_seconds,
            max_bytes,
            provider=provider,
        )

    return read


def _read_response(
    request: Request,
    timeout_seconds: float,
    max_bytes: int,
    *,
    provider: str = "OSV",
) -> bytes:
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            raw_length = response.headers.get("Content-Length")
            if raw_length is not None:
                try:
                    content_length = int(raw_length)
                except ValueError as error:
                    raise VulnerabilityLookupError(
                        f"{provider} returned an invalid Content-Length header"
                    ) from error
                if content_length > max_bytes:
                    raise VulnerabilityLookupError(
                        f"{provider} response exceeded the size limit"
                    )
            body = response.read(max_bytes + 1)
    except HTTPError as error:
        raise VulnerabilityHttpError(
            f"{provider} returned HTTP {error.code}",
            status=error.code,
            retry_after=_retry_after_seconds(error.headers),
        ) from error
    except URLError as error:
        raise VulnerabilityLookupError(
            f"{provider} request failed: {error.reason}"
        ) from error
    except TimeoutError as error:
        raise VulnerabilityLookupError(f"{provider} request timed out") from error

    if len(body) > max_bytes:
        raise VulnerabilityLookupError(f"{provider} response exceeded the size limit")
    return body


def _parse_osv_response(document: Any) -> tuple[OsvAdvisory, ...]:
    if not isinstance(document, dict):
        raise VulnerabilityLookupError("OSV returned an invalid response object")
    raw_vulnerabilities = document.get("vulns", [])
    if not isinstance(raw_vulnerabilities, list):
        raise VulnerabilityLookupError("OSV returned an invalid vulnerability list")
    return tuple(_parse_advisory(item) for item in raw_vulnerabilities)


def _retry_after_seconds(headers: Any) -> float | None:
    """Read a Retry-After header given in seconds; ignore anything else."""
    if headers is None:
        return None
    raw_value = headers.get("Retry-After")
    if raw_value is None:
        return None
    try:
        seconds = float(str(raw_value).strip())
    except ValueError:
        return None
    if not math.isfinite(seconds) or seconds < 0:
        return None
    return seconds


def _parse_nvd_page(
    document: Any,
    *,
    expected_start: int,
) -> tuple[tuple[Vulnerability, ...], int]:
    """Validate one NVD results page and return its CVEs and the overall total."""
    if not isinstance(document, dict):
        raise VulnerabilityLookupError("NVD returned an invalid response object")
    raw_vulnerabilities = document.get("vulnerabilities")
    total_results = document.get("totalResults")
    if (
        not isinstance(raw_vulnerabilities, list)
        or isinstance(total_results, bool)
        or not isinstance(total_results, int)
        or total_results < 0
    ):
        raise VulnerabilityLookupError("NVD returned an invalid vulnerability list")
    start_index = document.get("startIndex", expected_start)
    if start_index != expected_start:
        raise VulnerabilityLookupError(
            f"NVD returned a page starting at {start_index!r} during pagination; "
            f"expected {expected_start}"
        )
    page = tuple(_parse_nvd_vulnerability(item) for item in raw_vulnerabilities)
    return page, total_results


def _parse_nvd_vulnerability(document: Any) -> Vulnerability:
    if not isinstance(document, dict) or not isinstance(document.get("cve"), dict):
        raise VulnerabilityLookupError("NVD returned an invalid CVE record")
    cve = document["cve"]
    cve_id = cve.get("id")
    if not isinstance(cve_id, str) or not _CVE_PATTERN.fullmatch(cve_id):
        raise VulnerabilityLookupError("NVD CVE record has an invalid identifier")

    descriptions = cve.get("descriptions", [])
    if not isinstance(descriptions, list):
        raise VulnerabilityLookupError("NVD CVE record has invalid descriptions")
    description = None
    for entry in descriptions:
        if not isinstance(entry, dict) or not isinstance(entry.get("value"), str):
            raise VulnerabilityLookupError("NVD CVE record has invalid descriptions")
        if entry.get("lang") == "en":
            description = entry["value"].strip()
            break
        if description is None:
            description = entry["value"].strip()
    if not description:
        description = f"Published vulnerability {cve_id}"

    references = cve.get("references", [])
    if not isinstance(references, list):
        raise VulnerabilityLookupError("NVD CVE record has invalid references")
    urls: list[str] = []
    for entry in references:
        if not isinstance(entry, dict) or not isinstance(entry.get("url"), str):
            raise VulnerabilityLookupError("NVD CVE record has invalid references")
        urls.append(entry["url"])
    urls.append(f"https://nvd.nist.gov/vuln/detail/{cve_id.upper()}")

    score, vector = _select_nvd_cvss(cve.get("metrics", {}))
    return Vulnerability(
        cve_id=cve_id,
        description=description,
        cvss_score=score,
        cvss_vector=vector,
        references=tuple(dict.fromkeys(urls)),
    )


def _select_nvd_cvss(metrics: Any) -> tuple[float | None, str | None]:
    if not isinstance(metrics, dict):
        raise VulnerabilityLookupError("NVD CVE record has invalid metrics")
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries is None:
            continue
        if not isinstance(entries, list) or not entries:
            raise VulnerabilityLookupError("NVD CVE record has invalid metrics")
        preferred = next(
            (entry for entry in entries if isinstance(entry, dict) and entry.get("type") == "Primary"),
            entries[0],
        )
        if not isinstance(preferred, dict) or not isinstance(preferred.get("cvssData"), dict):
            raise VulnerabilityLookupError("NVD CVE record has invalid metrics")
        cvss_data = preferred["cvssData"]
        raw_score = cvss_data.get("baseScore")
        raw_vector = cvss_data.get("vectorString")
        if not isinstance(raw_score, (int, float)) or isinstance(raw_score, bool):
            raise VulnerabilityLookupError("NVD CVE record has invalid CVSS score")
        if not isinstance(raw_vector, str) or not raw_vector.strip():
            raise VulnerabilityLookupError("NVD CVE record has invalid CVSS vector")
        return float(raw_score), raw_vector.strip()
    return None, None


def _parse_advisory(document: Any) -> OsvAdvisory:
    if not isinstance(document, dict):
        raise VulnerabilityLookupError("OSV returned an invalid advisory")
    advisory_id = document.get("id")
    if not isinstance(advisory_id, str) or not advisory_id.strip():
        raise VulnerabilityLookupError("OSV advisory is missing its identifier")

    aliases = _string_list(document.get("aliases", []), "aliases")
    severity_entries = document.get("severity", [])
    if not isinstance(severity_entries, list):
        raise VulnerabilityLookupError("OSV advisory has invalid severity data")
    severity_vectors: list[str] = []
    for entry in severity_entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("score"), str):
            raise VulnerabilityLookupError("OSV advisory has invalid severity data")
        severity_vectors.append(entry["score"])

    reference_entries = document.get("references", [])
    if not isinstance(reference_entries, list):
        raise VulnerabilityLookupError("OSV advisory has invalid references")
    references: list[str] = []
    for entry in reference_entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("url"), str):
            raise VulnerabilityLookupError("OSV advisory has invalid references")
        references.append(entry["url"])

    summary = document.get("summary")
    details = document.get("details")
    if summary is not None and not isinstance(summary, str):
        raise VulnerabilityLookupError("OSV advisory has an invalid summary")
    if details is not None and not isinstance(details, str):
        raise VulnerabilityLookupError("OSV advisory has invalid details")

    return OsvAdvisory(
        advisory_id=advisory_id.strip(),
        aliases=aliases,
        summary=summary.strip() if summary and summary.strip() else None,
        details=details.strip() if details and details.strip() else None,
        severity_vectors=tuple(severity_vectors),
        references=tuple(dict.fromkeys(references)),
    )


def _string_list(value: Any, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise VulnerabilityLookupError(f"OSV advisory has invalid {field_name}")
    return tuple(dict.fromkeys(item.strip() for item in value if item.strip()))


def _normalize_cpe(value: str) -> str:
    cpe = _required_text(value, "cpe")
    if cpe.startswith("cpe:2.3:"):
        parts = cpe.split(":")
        if len(parts) != 13 or parts[2] not in {"a", "h", "o"}:
            raise VulnerabilityError("cpe must be a well-formed CPE 2.3 name")
        return cpe
    if not cpe.startswith("cpe:/"):
        raise VulnerabilityError("cpe must use CPE 2.2 URI or CPE 2.3 syntax")

    body = cpe[5:]
    if any(character in body for character in ("\\", "%", "~")):
        raise VulnerabilityError(
            "complex CPE 2.2 names must be supplied in CPE 2.3 format"
        )
    parts = body.split(":")
    if not 3 <= len(parts) <= 7 or parts[0] not in {"a", "h", "o"}:
        raise VulnerabilityError("cpe must be a well-formed CPE 2.2 name")
    parts.extend([""] * (7 - len(parts)))
    normalized = [part if part else "*" for part in parts]
    normalized.extend(["*"] * 4)
    return "cpe:2.3:" + ":".join(normalized)

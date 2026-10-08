"""Scope-safe Nmap command construction, execution, and XML parsing."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from ipaddress import IPv6Address, ip_address
import json
import re
import shutil
import subprocess
from typing import Any
from xml.etree import ElementTree

from hexpath.models import (
    Evidence,
    EvidenceLevel,
    Host,
    ModelError,
    Service,
    ServiceState,
    TransportProtocol,
)
from hexpath.scope import Scope, ScopeError


class ScannerError(RuntimeError):
    """Base error raised by the scanner integration."""


class NmapNotFoundError(ScannerError):
    """Raised when the Nmap executable cannot be located."""


class NmapExecutionError(ScannerError):
    """Raised when Nmap fails or exceeds its time limit."""


class NmapParseError(ScannerError):
    """Raised when Nmap XML cannot be interpreted safely."""


class ScanProfile(StrEnum):
    """Supported Nmap scan profiles."""

    DISCOVERY = "discovery"
    SERVICES = "services"


@dataclass(frozen=True, slots=True)
class NmapCommand:
    """A fully validated Nmap invocation represented without a shell."""

    arguments: tuple[str, ...]
    targets: tuple[str, ...]
    profile: ScanProfile


@dataclass(frozen=True, slots=True)
class NmapScanResult:
    """Normalized hosts and services parsed from one Nmap XML document."""

    hosts: tuple[Host, ...]
    services: tuple[Service, ...]
    vantage: str = "entry:scanner"

    def __post_init__(self) -> None:
        if not isinstance(self.vantage, str) or not self.vantage.strip():
            raise ScannerError("scan vantage must be a non-empty string")
        object.__setattr__(self, "vantage", self.vantage.strip())

    def to_dict(self) -> dict[str, Any]:
        return {
            "vantage": self.vantage,
            "hosts": [host.to_dict() for host in self.hosts],
            "services": [service.to_dict() for service in self.services],
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


def build_nmap_command(
    scope: Scope,
    targets: list[str] | tuple[str, ...],
    profile: ScanProfile | str,
    *,
    executable: str = "nmap",
    skip_discovery: bool = False,
    ports: str | None = None,
) -> NmapCommand:
    """Validate targets against scope and construct a conservative command."""
    if not targets:
        raise ScannerError("at least one scan target is required")

    try:
        selected_profile = ScanProfile(profile)
    except ValueError as error:
        raise ScannerError(f"unsupported scan profile: {profile!r}") from error

    authorized_targets = tuple(
        str(scope.require_authorized_network(target)) for target in targets
    )

    common_arguments = (
        executable,
        "-6",
        "-n",
        "--reason",
        "-oX",
        "-",
    )
    if selected_profile is ScanProfile.DISCOVERY:
        if ports is not None:
            raise ScannerError("ports can be selected only for a service scan")
        profile_arguments = ("-sn",)
    else:
        profile_arguments = ("-sT", "-sV", "--version-light")

    discovery_arguments = ("-Pn",) if skip_discovery else ()
    port_arguments = ("-p", _validate_ports(ports)) if ports is not None else ()
    return NmapCommand(
        arguments=(
            common_arguments
            + discovery_arguments
            + port_arguments
            + profile_arguments
            + authorized_targets
        ),
        targets=authorized_targets,
        profile=selected_profile,
    )


def _validate_ports(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9][0-9,-]*", value):
        raise ScannerError("ports must be numbers or ranges such as 22,80,443 or 1-1024")
    for item in value.split(","):
        if not item:
            raise ScannerError("port list cannot contain empty entries")
        bounds = item.split("-")
        if len(bounds) > 2:
            raise ScannerError(f"invalid port range {item!r}")
        numbers = [int(bound) for bound in bounds]
        if any(number < 1 or number > 65535 for number in numbers):
            raise ScannerError("ports must be between 1 and 65535")
        if len(numbers) == 2 and numbers[0] > numbers[1]:
            raise ScannerError(f"invalid descending port range {item!r}")
    return value


def run_nmap(command: NmapCommand, *, timeout_seconds: int = 300) -> str:
    """Execute a prevalidated Nmap command and return its XML output."""
    executable = command.arguments[0]
    if shutil.which(executable) is None:
        raise NmapNotFoundError(f"Nmap executable not found: {executable}")
    if timeout_seconds <= 0:
        raise NmapExecutionError("timeout_seconds must be greater than zero")

    try:
        process = subprocess.run(
            command.arguments,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        raise NmapExecutionError(
            f"Nmap exceeded the {timeout_seconds}-second time limit"
        ) from error
    except OSError as error:
        raise NmapExecutionError(f"could not start Nmap: {error}") from error

    if process.returncode != 0:
        message = process.stderr.strip() or "Nmap exited without an error message"
        raise NmapExecutionError(
            f"Nmap exited with status {process.returncode}: {message}"
        )

    return process.stdout


def parse_nmap_xml(
    xml_text: str,
    *,
    reference: str = "nmap-xml",
    vantage: str = "entry:scanner",
) -> NmapScanResult:
    """Convert Nmap XML into evidence-backed HexPath records."""
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError as error:
        raise NmapParseError(f"invalid Nmap XML: {error}") from error

    if root.tag != "nmaprun":
        raise NmapParseError("expected an nmaprun XML document")

    collected_at = _parse_start_time(root.attrib.get("start"))
    hosts: list[Host] = []
    services: list[Service] = []

    for host_element in root.findall("host"):
        status_element = host_element.find("status")
        if status_element is None or status_element.attrib.get("state") != "up":
            continue

        address = _find_ipv6_address(host_element)
        if address is None:
            continue

        status_reason = status_element.attrib.get("reason", "unspecified")
        host_evidence = Evidence(
            source="nmap",
            summary=f"Host reported up; reason={status_reason}",
            level=EvidenceLevel.OBSERVED,
            collected_at=collected_at,
            reference=f"{reference}#host-{address.compressed}",
        )
        hostnames = tuple(
            element.attrib["name"]
            for element in host_element.findall("./hostnames/hostname")
            if element.attrib.get("name")
        )
        host = Host(
            address=address,
            hostnames=hostnames,
            evidence=(host_evidence,),
        )
        hosts.append(host)
        services.extend(
            _parse_services(
                host_element,
                address,
                collected_at=collected_at,
                reference=reference,
            )
        )

    return NmapScanResult(
        hosts=tuple(hosts),
        services=tuple(services),
        vantage=vantage,
    )


def require_authorized_vantage(scope: Scope, vantage: str) -> str:
    """Validate and normalize the node from which a scan is observed."""
    if not isinstance(vantage, str) or not vantage.strip():
        raise ScannerError("scan vantage must be a non-empty string")
    value = vantage.strip()
    if value == "entry:scanner":
        return value
    if not value.startswith("host:"):
        raise ScannerError("scan vantage must be entry:scanner or host:<IPv6-address>")
    raw_address = value.removeprefix("host:")
    try:
        address = scope.require_authorized(raw_address)
    except ScopeError as error:
        raise ScannerError(f"invalid scan vantage {value!r}: {error}") from error
    return f"host:{address.compressed}"


def _parse_start_time(raw_start: str | None) -> datetime:
    if raw_start is None:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromtimestamp(int(raw_start), timezone.utc)
    except (ValueError, OSError, OverflowError) as error:
        raise NmapParseError(f"invalid Nmap start timestamp: {raw_start!r}") from error


def _find_ipv6_address(host_element: ElementTree.Element) -> IPv6Address | None:
    for address_element in host_element.findall("address"):
        if address_element.attrib.get("addrtype") != "ipv6":
            continue
        raw_address = address_element.attrib.get("addr")
        if raw_address is None:
            raise NmapParseError("IPv6 address element is missing its address")
        try:
            address = ip_address(raw_address)
        except ValueError as error:
            raise NmapParseError(f"invalid IPv6 address in Nmap XML: {raw_address}") from error
        if not isinstance(address, IPv6Address):
            raise NmapParseError(f"address marked IPv6 is not IPv6: {raw_address}")
        return address
    return None


def _parse_services(
    host_element: ElementTree.Element,
    address: IPv6Address,
    *,
    collected_at: datetime,
    reference: str,
) -> list[Service]:
    services: list[Service] = []
    for port_element in host_element.findall("./ports/port"):
        state_element = port_element.find("state")
        if state_element is None:
            continue
        raw_state = state_element.attrib.get("state")
        if raw_state not in {
            ServiceState.OPEN.value,
            ServiceState.OPEN_FILTERED.value,
            ServiceState.FILTERED.value,
        }:
            continue

        try:
            protocol = TransportProtocol(port_element.attrib["protocol"])
            port = int(port_element.attrib["portid"])
            state = ServiceState(raw_state)
        except (KeyError, ValueError, ModelError) as error:
            raise NmapParseError("invalid port record in Nmap XML") from error

        service_element = port_element.find("service")
        service_attributes: dict[str, Any] = (
            service_element.attrib if service_element is not None else {}
        )
        cpes = (
            tuple(
                dict.fromkeys(
                    element.text.strip()
                    for element in service_element.findall("cpe")
                    if element.text and element.text.strip()
                )
            )
            if service_element is not None
            else ()
        )
        service_evidence = Evidence(
            source="nmap",
            summary=(
                f"{protocol.value}/{port} reported {state.value}; "
                f"reason={state_element.attrib.get('reason', 'unspecified')}"
            ),
            level=EvidenceLevel.OBSERVED,
            collected_at=collected_at,
            reference=(
                f"{reference}#host-{address.compressed}-"
                f"{protocol.value}-{port}"
            ),
        )
        services.append(
            Service(
                host=address,
                port=port,
                protocol=protocol,
                state=state,
                name=service_attributes.get("name"),
                product=service_attributes.get("product"),
                version=service_attributes.get("version"),
                cpes=cpes,
                evidence=(service_evidence,),
            )
        )

    return services

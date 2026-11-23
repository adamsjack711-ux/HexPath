"""Scope-safe Nmap command construction, execution, and XML parsing."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
import json
import os
from pathlib import Path
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
    ScriptFinding,
    Service,
    ServiceState,
    TransportProtocol,
)
from hexpath.scope import Scope, ScopeError


IPAddress = IPv4Address | IPv6Address

# Nmap NSE vulnerability-detection scripts run by the opt-in SMB check. They
# test the vulnerability condition directly, which is what lets HexPath report an
# evidence-backed finding for a service that advertises no version. Some are
# intrusive (ms08-067 in particular can crash an unpatched host), so this check
# is opt-in and intended for an authorized lab, not a production network.
SMB_VULN_SCRIPTS = (
    "smb-vuln-ms17-010",
    "smb-vuln-ms08-067",
    "smb-double-pulsar-backdoor",
    "smb-vuln-cve-2017-7494",
)

# Web and FTP vulnerability-detection scripts. These actively test the condition
# on a web or FTP service (any OS), so an installed, genuinely vulnerable service
# on a Windows host can be confirmed the same way SMB is.
WEB_VULN_SCRIPTS = (
    "http-vuln-cve2017-5638",     # Apache Struts2 content-type RCE
    "http-vuln-cve2017-12617",    # Apache Tomcat PUT JSP RCE
    "http-vuln-cve2015-1427",     # Elasticsearch Groovy sandbox RCE
    "http-vuln-cve2014-3704",     # Drupal "Drupalgeddon" SQL injection
    "http-vuln-cve2011-3192",     # Apache Range header DoS ("Apache Killer")
)
FTP_VULN_SCRIPTS = (
    "ftp-vsftpd-backdoor",        # vsftpd 2.3.4 backdoor
    "ftp-proftpd-backdoor",       # ProFTPD 1.3.3c backdoor
)

# The full vulnerability set run by --vuln, and the ports those services use, so
# the scan reaches them even when they are not in the default top-ports set.
ALL_VULN_SCRIPTS = SMB_VULN_SCRIPTS + WEB_VULN_SCRIPTS + FTP_VULN_SCRIPTS
VULN_PORTS = "21,135,139,445,80,443,8000,8080,8180,8443,9200"

# CVE identifiers used when a script confirms a host vulnerable but its
# structured output does not enumerate them explicitly.
_SCRIPT_FALLBACK_CVES: dict[str, tuple[str, ...]] = {
    "smb-vuln-ms17-010": (
        "CVE-2017-0143",
        "CVE-2017-0144",
        "CVE-2017-0145",
        "CVE-2017-0146",
        "CVE-2017-0147",
        "CVE-2017-0148",
    ),
    "smb-vuln-ms08-067": ("CVE-2008-4250",),
    # DoublePulsar is the implant commonly dropped through the MS17-010 flaw; a
    # detected backdoor maps back to the same vulnerability family.
    "smb-double-pulsar-backdoor": ("CVE-2017-0144",),
    "smb-vuln-cve-2017-7494": ("CVE-2017-7494",),
    "http-vuln-cve2017-5638": ("CVE-2017-5638",),
    "http-vuln-cve2017-12617": ("CVE-2017-12617",),
    "http-vuln-cve2015-1427": ("CVE-2015-1427",),
    "http-vuln-cve2014-3704": ("CVE-2014-3704",),
    "http-vuln-cve2011-3192": ("CVE-2011-3192",),
    "ftp-vsftpd-backdoor": ("CVE-2011-2523",),
    "ftp-proftpd-backdoor": ("CVE-2010-4221",),
}

_CVE_TOKEN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


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

    BASIC = "basic"
    DISCOVERY = "discovery"
    QUICK = "quick"
    SERVICES = "services"
    FULL = "full"
    DEEP = "deep"


SCAN_LEVELS: tuple[dict[str, Any], ...] = (
    {
        "level": 0,
        "profile": ScanProfile.DISCOVERY.value,
        "wait": "fastest",
        "information": "host availability only; no port or service scan",
    },
    {
        "level": 1,
        "profile": ScanProfile.QUICK.value,
        "wait": "short",
        "information": "open state for the 100 most common TCP ports",
    },
    {
        "level": 2,
        "profile": ScanProfile.SERVICES.value,
        "wait": "moderate",
        "information": "top 1,000 TCP ports with light version and CPE probes",
    },
    {
        "level": 3,
        "profile": ScanProfile.FULL.value,
        "wait": "long",
        "information": "all 65,535 TCP ports with light version and CPE probes",
    },
    {
        "level": 4,
        "profile": ScanProfile.DEEP.value,
        "wait": "longest",
        "information": "all TCP ports with every available version probe",
    },
)


def scan_profile_for_level(level: int) -> ScanProfile:
    """Resolve an information level to its fixed, scope-safe scan profile."""
    if isinstance(level, bool) or not isinstance(level, int):
        raise ScannerError("scan level must be an integer from 0 to 4")
    for item in SCAN_LEVELS:
        if item["level"] == level:
            return ScanProfile(item["profile"])
    raise ScannerError("scan level must be an integer from 0 to 4")


def scan_levels_document() -> dict[str, Any]:
    """Return the stable scan-level catalog for terminal and JSON clients."""
    return {
        "levels": [dict(item) for item in SCAN_LEVELS],
        "note": (
            "wait labels are relative; actual duration depends on target count, "
            "latency, filtering, and services"
        ),
    }


def render_scan_levels_ascii() -> str:
    """Render the scan-level catalog in a compact terminal table."""
    lines = [
        "HexPath Scan Levels",
        "===================",
        "Level  Profile     Wait      Information",
    ]
    for item in SCAN_LEVELS:
        lines.append(
            f"{item['level']:<5}  {item['profile']:<10}  {item['wait']:<8}  "
            f"{item['information']}"
        )
    lines.append("")
    lines.append(
        "Durations are relative and vary with target count, latency, filtering, and services."
    )
    return "\n".join(lines)


@dataclass(frozen=True, slots=True)
class NmapCommand:
    """A fully validated Nmap invocation represented without a shell."""

    arguments: tuple[str, ...]
    targets: tuple[str, ...]
    profile: ScanProfile
    ip_version: int | None = None


@dataclass(frozen=True, slots=True)
class NmapScanResult:
    """Normalized hosts and services parsed from one Nmap XML document."""

    hosts: tuple[Host, ...]
    services: tuple[Service, ...]
    vantage: str = "entry:scanner"
    script_findings: tuple[ScriptFinding, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.vantage, str) or not self.vantage.strip():
            raise ScannerError("scan vantage must be a non-empty string")
        object.__setattr__(self, "vantage", self.vantage.strip())
        object.__setattr__(self, "script_findings", tuple(self.script_findings))

    def to_dict(self) -> dict[str, Any]:
        return {
            "vantage": self.vantage,
            "hosts": [host.to_dict() for host in self.hosts],
            "services": [service.to_dict() for service in self.services],
            "script_findings": [finding.to_dict() for finding in self.script_findings],
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
    ip_version: int | None = None,
    os_detection: bool = False,
    vuln_scripts: bool = False,
    all_vuln: bool = False,
    exclude: tuple[str, ...] = (),
) -> NmapCommand:
    """Validate targets against scope and construct a conservative command."""
    if not targets:
        raise ScannerError("at least one scan target is required")

    try:
        selected_profile = ScanProfile(profile)
    except ValueError as error:
        raise ScannerError(f"unsupported scan profile: {profile!r}") from error

    authorized_networks = tuple(
        scope.require_authorized_network(target) for target in targets
    )
    versions = {network.version for network in authorized_networks}
    if len(versions) != 1:
        raise ScannerError(
            "one Nmap command cannot mix IPv4 and IPv6 targets; run one scan per family"
        )
    selected_version = versions.pop()
    if isinstance(ip_version, bool) or ip_version not in (None, 4, 6):
        raise ScannerError("ip_version must be 4, 6, or null")
    if ip_version is not None and ip_version != selected_version:
        raise ScannerError(
            f"IPv{selected_version} targets do not match the requested IPv{ip_version} mode"
        )
    authorized_targets = tuple(str(network) for network in authorized_networks)

    family_arguments = ("-6",) if selected_version == 6 else ()
    common_arguments = (
        executable,
        *family_arguments,
        "-n",
        "--reason",
        "-oX",
        "-",
    )
    profile_arguments = {
        ScanProfile.BASIC: ("-sT",),
        ScanProfile.DISCOVERY: ("-sn",),
        ScanProfile.QUICK: ("-sT", "--top-ports", "100"),
        ScanProfile.SERVICES: ("-sT", "-sV", "--version-light"),
        ScanProfile.FULL: ("-sT", "-sV", "--version-light", "-p-"),
        ScanProfile.DEEP: ("-sT", "-sV", "--version-all", "-p-"),
    }[selected_profile]
    # --vuln needs the web/FTP ports reachable; add them when no ports were set.
    effective_ports = ports
    if all_vuln and effective_ports is None:
        effective_ports = VULN_PORTS
    if effective_ports is not None and selected_profile not in (ScanProfile.BASIC, ScanProfile.SERVICES):
        raise ScannerError("ports can be selected only with the basic or services profile")

    discovery_arguments = ("-Pn",) if skip_discovery else ()
    port_arguments = ("-p", _validate_ports(effective_ports)) if effective_ports is not None else ()
    if os_detection and selected_profile is ScanProfile.DISCOVERY:
        raise ScannerError(
            "OS detection needs a port scan; use it with a scanning profile, "
            "not discovery"
        )
    os_arguments = ("-O",) if os_detection else ()
    if (vuln_scripts or all_vuln) and selected_profile is ScanProfile.DISCOVERY:
        raise ScannerError(
            "vulnerability scripts need a port scan; use them with a scanning "
            "profile, not discovery"
        )
    if all_vuln:
        script_arguments = ("--script", ",".join(ALL_VULN_SCRIPTS))
    elif vuln_scripts:
        script_arguments = ("--script", ",".join(SMB_VULN_SCRIPTS))
    else:
        script_arguments = ()

    exclude_arguments: tuple[str, ...] = ()
    cleaned_exclude = [entry.strip() for entry in exclude if entry.strip()]
    for entry in cleaned_exclude:
        if not _is_valid_exclude_target(entry):
            raise ScannerError(f"invalid exclude target: {entry!r}")
    if cleaned_exclude:
        exclude_arguments = ("--exclude", ",".join(cleaned_exclude))

    return NmapCommand(
        arguments=(
            common_arguments
            + discovery_arguments
            + port_arguments
            + os_arguments
            + script_arguments
            + exclude_arguments
            + profile_arguments
            + authorized_targets
        ),
        targets=authorized_targets,
        profile=selected_profile,
        ip_version=selected_version,
    )


def _is_valid_exclude_target(value: str) -> bool:
    """Accept a single IP address or a CIDR network to exclude from a scan."""
    try:
        ip_address(value)
        return True
    except ValueError:
        pass
    try:
        ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def _validate_ports(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or any(character not in "0123456789,-" for character in value)
    ):
        raise ScannerError(
            "ports must be numbers or ranges such as 22,80,443 or 1-1024"
        )
    for item in value.split(","):
        if not item:
            raise ScannerError("port list cannot contain empty entries")
        bounds = item.split("-")
        if len(bounds) > 2 or any(not bound for bound in bounds):
            raise ScannerError(f"invalid port range {item!r}")
        if any(not bound.isdecimal() for bound in bounds):
            raise ScannerError(
                "ports must be numbers or ranges such as 22,80,443 or 1-1024"
            )
        numbers = [int(bound) for bound in bounds]
        if any(number < 1 or number > 65535 for number in numbers):
            raise ScannerError("ports must be between 1 and 65535")
        if len(numbers) == 2 and numbers[0] > numbers[1]:
            raise ScannerError(f"invalid descending port range {item!r}")
    return value


def run_nmap(command: NmapCommand, *, timeout_seconds: int = 300) -> str:
    """Execute a prevalidated Nmap command and return its XML output."""
    executable = command.arguments[0]
    resolved_executable = resolve_nmap_executable(executable)
    if resolved_executable is None:
        message = f"Nmap executable not found: {executable}"
        if os.name == "nt":
            message += ". Install Nmap from https://nmap.org/download.html#windows"
        raise NmapNotFoundError(message)
    if timeout_seconds <= 0:
        raise NmapExecutionError("timeout_seconds must be greater than zero")

    arguments = (resolved_executable, *command.arguments[1:])
    try:
        process = subprocess.run(
            arguments,
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


def resolve_nmap_executable(
    executable: str = "nmap",
    *,
    platform_name: str | None = None,
    environ: dict[str, str] | None = None,
) -> str | None:
    """Locate Nmap, including the standard Windows installer directories."""
    resolved = shutil.which(executable)
    if resolved is not None:
        return resolved

    requested_path = Path(executable)
    if requested_path.is_file():
        return str(requested_path)

    selected_platform = os.name if platform_name is None else platform_name
    if selected_platform != "nt" or requested_path.name.lower() not in {"nmap", "nmap.exe"}:
        return None

    selected_environment = os.environ if environ is None else environ
    install_roots = (
        selected_environment.get("ProgramFiles"),
        selected_environment.get("ProgramFiles(x86)"),
        selected_environment.get("LOCALAPPDATA"),
    )
    candidates: list[Path] = []
    for root in install_roots:
        if not root:
            continue
        candidates.append(Path(root) / "Nmap" / "nmap.exe")
        if root == selected_environment.get("LOCALAPPDATA"):
            candidates.append(Path(root) / "Programs" / "Nmap" / "nmap.exe")
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return None


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
    script_findings: list[ScriptFinding] = []

    for host_element in root.findall("host"):
        status_element = host_element.find("status")
        if status_element is None or status_element.attrib.get("state") != "up":
            continue

        address = _find_ip_address(host_element)
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
        os_name, os_cpes = _parse_os_fingerprint(host_element)
        host_evidence_records = [host_evidence]
        if os_cpes:
            host_evidence_records.append(
                Evidence(
                    source="nmap",
                    summary=(
                        "OS fingerprint "
                        f"{os_name or 'match'} reported CPEs {', '.join(os_cpes)}; "
                        "network OS detection cannot see patch level"
                    ),
                    level=EvidenceLevel.INFERRED,
                    collected_at=collected_at,
                    reference=f"{reference}#host-{address.compressed}-os",
                )
            )
        host = Host(
            address=address,
            hostnames=hostnames,
            os_name=os_name,
            cpes=os_cpes,
            evidence=tuple(host_evidence_records),
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
        script_findings.extend(
            _parse_script_findings(
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
        script_findings=tuple(script_findings),
    )


def require_authorized_vantage(scope: Scope, vantage: str) -> str:
    """Validate and normalize the node from which a scan is observed."""
    if not isinstance(vantage, str) or not vantage.strip():
        raise ScannerError("scan vantage must be a non-empty string")
    value = vantage.strip()
    if value == "entry:scanner":
        return value
    if not value.startswith("host:"):
        raise ScannerError("scan vantage must be entry:scanner or host:<IP-address>")
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


def _find_ip_address(host_element: ElementTree.Element) -> IPAddress | None:
    for address_element in host_element.findall("address"):
        address_type = address_element.attrib.get("addrtype")
        if address_type not in {"ipv4", "ipv6"}:
            continue
        raw_address = address_element.attrib.get("addr")
        if raw_address is None:
            raise NmapParseError(
                f"{address_type.upper()} address element is missing its address"
            )
        try:
            address = ip_address(raw_address)
        except ValueError as error:
            raise NmapParseError(
                f"invalid {address_type.upper()} address in Nmap XML: {raw_address}"
            ) from error
        expected_type = IPv4Address if address_type == "ipv4" else IPv6Address
        if not isinstance(address, expected_type):
            raise NmapParseError(
                f"address marked {address_type.upper()} is not "
                f"{address_type.upper()}: {raw_address}"
            )
        return address
    return None


def _parse_os_fingerprint(
    host_element: ElementTree.Element,
) -> tuple[str | None, tuple[str, ...]]:
    """Extract the best OS match name and its CPEs from an Nmap <os> block.

    Nmap only emits this when run with OS detection (``-O``), which needs
    elevated privileges. The CPEs it reports describe the operating system
    (for example ``cpe:/o:microsoft:windows_xp``) and carry no patch level,
    so callers must treat any CVE derived from them as low-confidence.
    """
    os_element = host_element.find("os")
    if os_element is None:
        return None, ()

    # osmatch elements are ordered by Nmap from highest to lowest accuracy. Use
    # only the best match for both the name and the CPEs: taking CPEs from every
    # candidate would attach several mutually exclusive operating systems (for
    # example windows_xp and windows_7) to one host and inflate the candidate
    # CVE set with OSes the host is not. Fall back to any CPEs directly under
    # <os> if Nmap emitted no osmatch wrapper.
    os_name: str | None = None
    best_match = os_element.find("osmatch")
    cpe_source = best_match if best_match is not None else os_element
    if best_match is not None:
        candidate = best_match.attrib.get("name")
        if candidate and candidate.strip():
            os_name = candidate.strip()

    cpes: list[str] = []
    for cpe_element in cpe_source.findall(".//cpe"):
        if cpe_element.text is None:
            continue
        value = cpe_element.text.strip()
        # Keep only operating-system CPEs; hardware or application CPEs that
        # sometimes appear under osclass are not what host-level scoring means.
        if value and value not in cpes and _is_os_cpe(value):
            cpes.append(value)

    return os_name, tuple(cpes)


def _is_os_cpe(value: str) -> bool:
    if value.startswith("cpe:2.3:o:"):
        return True
    if value.startswith("cpe:/o:"):
        return True
    return False


def _parse_services(
    host_element: ElementTree.Element,
    address: IPAddress,
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
        if raw_state not in {ServiceState.OPEN.value, ServiceState.OPEN_FILTERED.value}:
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


def _script_state(script: ElementTree.Element, output: str | None) -> str | None:
    """Read the vulnerability state an NSE script reported, if any."""
    for elem in script.iter("elem"):
        if elem.attrib.get("key") == "state" and elem.text and elem.text.strip():
            return elem.text.strip()
    if output:
        match = re.search(r"State:\s*([A-Za-z][A-Za-z ()]+)", output)
        if match:
            return match.group(1).strip()
        if "NOT VULNERABLE" in output.upper():
            return "NOT VULNERABLE"
        if "VULNERABLE" in output.upper():
            return "LIKELY VULNERABLE"
    return None


def _script_title(script: ElementTree.Element) -> str | None:
    for elem in script.iter("elem"):
        if elem.attrib.get("key") == "title" and elem.text and elem.text.strip():
            return elem.text.strip()
    return None


def _script_cve_ids(script: ElementTree.Element, output: str | None) -> tuple[str, ...]:
    found: list[str] = []
    for table in script.iter("table"):
        key = table.attrib.get("key", "")
        if _CVE_TOKEN.fullmatch(key):
            found.append(key.upper())
    texts = [output] + [elem.text for elem in script.iter("elem")]
    for text in texts:
        if text:
            found.extend(match.group(0).upper() for match in _CVE_TOKEN.finditer(text))
    return tuple(dict.fromkeys(found))


# Default port for an SMB vulnerability script reported at host level, where
# Nmap attaches no port element. These scripts all test SMB on 445/tcp.
_SCRIPT_DEFAULT_PORT: dict[str, tuple[int, str]] = {
    "smb-vuln-ms17-010": (445, "tcp"),
    "smb-vuln-ms08-067": (445, "tcp"),
}


def _build_script_finding(
    script: ElementTree.Element,
    address: IPAddress,
    port: int,
    protocol: TransportProtocol,
    *,
    collected_at: datetime,
    reference: str,
) -> ScriptFinding | None:
    output = script.attrib.get("output")
    state = _script_state(script, output)
    if state is None:
        return None
    script_id = script.attrib["id"]
    confirmed = state.strip().upper().startswith("VULNERABLE")
    cve_ids = _script_cve_ids(script, output)
    if confirmed and not cve_ids:
        cve_ids = _SCRIPT_FALLBACK_CVES.get(script_id, ())
    evidence = Evidence(
        source="nmap-script",
        summary=(
            f"Nmap script {script_id} reported state {state} on "
            f"{protocol.value}/{port}; this is a tested condition, "
            "not a version guess"
        ),
        level=EvidenceLevel.OBSERVED if confirmed else EvidenceLevel.INFERRED,
        collected_at=collected_at,
        reference=(
            f"{reference}#host-{address.compressed}-"
            f"{protocol.value}-{port}-{script_id}"
        ),
    )
    return ScriptFinding(
        host=address,
        port=port,
        protocol=protocol,
        script_id=script_id,
        state=state,
        cve_ids=cve_ids,
        title=_script_title(script),
        output=output,
        evidence=(evidence,),
    )


def _parse_script_findings(
    host_element: ElementTree.Element,
    address: IPAddress,
    *,
    collected_at: datetime,
    reference: str,
) -> list[ScriptFinding]:
    """Collect SMB vulnerability-script findings.

    Nmap attaches these either to the scanned port (``ports/port/script``) or,
    commonly for the SMB vulnerability scripts, to the host as a whole
    (``hostscript/script``). Both are read; host-level findings are mapped to
    the SMB port the script tests. Findings are de-duplicated by record id so a
    script reported both ways is not counted twice.
    """
    findings: dict[str, ScriptFinding] = {}

    for port_element in host_element.findall("./ports/port"):
        try:
            protocol = TransportProtocol(port_element.attrib["protocol"])
            port = int(port_element.attrib["portid"])
        except (KeyError, ValueError):
            continue
        for script in port_element.findall("script"):
            if script.attrib.get("id") not in ALL_VULN_SCRIPTS:
                continue
            finding = _build_script_finding(
                script, address, port, protocol,
                collected_at=collected_at, reference=reference,
            )
            if finding is not None:
                findings.setdefault(finding.record_id, finding)

    for script in host_element.findall("./hostscript/script"):
        script_id = script.attrib.get("id")
        if script_id not in SMB_VULN_SCRIPTS:
            continue
        default_port, default_proto = _SCRIPT_DEFAULT_PORT[script_id]
        finding = _build_script_finding(
            script, address, default_port, TransportProtocol(default_proto),
            collected_at=collected_at, reference=reference,
        )
        if finding is not None:
            findings.setdefault(finding.record_id, finding)

    return list(findings.values())

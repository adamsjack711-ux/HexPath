"""Landmark CVE candidates derived from a host's OS fingerprint.

Windows' built-in services advertise no version, so a CPE-based NVD lookup finds
nothing and a Windows host is reported as incomplete coverage. The OS
fingerprint (from ``-O``) still identifies the Windows release, and each release
has a small set of well-known, network-facing CVEs a tester should check.

These are **candidates derived from an OS guess**, not confirmed findings and
not version matches: they are listed for review and never form an access route.
Patch level, which network OS detection cannot see, decides whether any of them
actually applies.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class OsCveCandidate:
    """A landmark CVE associated with a fingerprinted operating system."""

    host: str
    cve_id: str
    cvss_score: float | None
    description: str
    basis: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "description": self.description,
            "basis": self.basis,
            "applicability": "candidate",
            "confidence": "low",
        }


# Landmark network-facing CVEs per Windows release. Keyed by the product token
# that appears in both CPE 2.2 (cpe:/o:microsoft:windows_xp) and CPE 2.3
# (cpe:2.3:o:microsoft:windows_10:...) names. Keys are matched most specific
# first so windows_8.1 wins over windows_8 and the server builds win over the
# bare year. Entries are (cve_id, cvss_score, description).
_EXPOSURES: tuple[tuple[str, tuple[tuple[str, float, str], ...]], ...] = (
    ("microsoft:windows_server_2003", (
        ("CVE-2008-4250", 10.0, "Server service RPC remote code execution (MS08-067)."),
        ("CVE-2017-0143", 8.1, "SMBv1 remote code execution (MS17-010, EternalBlue)."),
        ("CVE-2019-0708", 9.8, "Remote Desktop remote code execution (BlueKeep)."),
    )),
    ("microsoft:windows_xp", (
        ("CVE-2008-4250", 10.0, "Server service RPC remote code execution (MS08-067)."),
        ("CVE-2017-0143", 8.1, "SMBv1 remote code execution (MS17-010, EternalBlue)."),
        ("CVE-2019-0708", 9.8, "Remote Desktop remote code execution (BlueKeep)."),
    )),
    ("microsoft:windows_vista", (
        ("CVE-2017-0143", 8.1, "SMBv1 remote code execution (MS17-010, EternalBlue)."),
        ("CVE-2008-4250", 10.0, "Server service RPC remote code execution (MS08-067)."),
    )),
    ("microsoft:windows_server_2008", (
        ("CVE-2017-0143", 8.1, "SMBv1 remote code execution (MS17-010, EternalBlue)."),
        ("CVE-2019-0708", 9.8, "Remote Desktop remote code execution (BlueKeep)."),
    )),
    ("microsoft:windows_7", (
        ("CVE-2017-0143", 8.1, "SMBv1 remote code execution (MS17-010, EternalBlue)."),
        ("CVE-2019-0708", 9.8, "Remote Desktop remote code execution (BlueKeep)."),
    )),
    ("microsoft:windows_8.1", (
        ("CVE-2017-0143", 8.1, "SMBv1 remote code execution (MS17-010, EternalBlue)."),
    )),
    ("microsoft:windows_8", (
        ("CVE-2017-0143", 8.1, "SMBv1 remote code execution (MS17-010, EternalBlue)."),
    )),
    ("microsoft:windows_server_2012", (
        ("CVE-2017-0143", 8.1, "SMBv1 remote code execution (MS17-010, EternalBlue)."),
        ("CVE-2020-1472", 10.0, "Netlogon elevation of privilege on a domain controller (Zerologon)."),
    )),
    ("microsoft:windows_server_2016", (
        ("CVE-2020-0796", 10.0, "SMBv3 remote code execution (SMBGhost)."),
        ("CVE-2022-26809", 9.8, "Windows RPC runtime remote code execution."),
        ("CVE-2024-38063", 9.8, "Windows TCP/IP IPv6 remote code execution."),
        ("CVE-2021-34527", 8.8, "Print Spooler remote code execution (PrintNightmare)."),
        ("CVE-2020-1472", 10.0, "Netlogon elevation of privilege on a domain controller (Zerologon)."),
    )),
    ("microsoft:windows_server_2019", (
        ("CVE-2020-0796", 10.0, "SMBv3 remote code execution (SMBGhost)."),
        ("CVE-2022-26809", 9.8, "Windows RPC runtime remote code execution."),
        ("CVE-2024-38063", 9.8, "Windows TCP/IP IPv6 remote code execution."),
        ("CVE-2021-34527", 8.8, "Print Spooler remote code execution (PrintNightmare)."),
        ("CVE-2020-1472", 10.0, "Netlogon elevation of privilege on a domain controller (Zerologon)."),
    )),
    ("microsoft:windows_server_2022", (
        ("CVE-2022-26809", 9.8, "Windows RPC runtime remote code execution."),
        ("CVE-2024-38063", 9.8, "Windows TCP/IP IPv6 remote code execution."),
        ("CVE-2021-34527", 8.8, "Print Spooler remote code execution (PrintNightmare)."),
        ("CVE-2022-37958", 8.1, "SPNEGO NEGOEX remote code execution."),
    )),
    ("microsoft:windows_10", (
        ("CVE-2020-0796", 10.0, "SMBv3 remote code execution (SMBGhost)."),
        ("CVE-2022-26809", 9.8, "Windows RPC runtime remote code execution."),
        ("CVE-2024-38063", 9.8, "Windows TCP/IP IPv6 remote code execution."),
        ("CVE-2021-34527", 8.8, "Print Spooler remote code execution (PrintNightmare)."),
        ("CVE-2022-30190", 7.8, "MSDT 'Follina' remote code execution via a crafted document."),
        ("CVE-2023-28252", 7.8, "CLFS driver elevation of privilege (exploited in the wild)."),
        ("CVE-2021-36934", 7.1, "SAM database disclosure 'HiveNightmare / SeriousSAM'."),
    )),
    ("microsoft:windows_11", (
        ("CVE-2022-26809", 9.8, "Windows RPC runtime remote code execution."),
        ("CVE-2024-38063", 9.8, "Windows TCP/IP IPv6 remote code execution."),
        ("CVE-2021-34527", 8.8, "Print Spooler remote code execution (PrintNightmare)."),
        ("CVE-2022-37958", 8.1, "SPNEGO NEGOEX remote code execution."),
        ("CVE-2022-30190", 7.8, "MSDT 'Follina' remote code execution via a crafted document."),
        ("CVE-2023-28252", 7.8, "CLFS driver elevation of privilege (exploited in the wild)."),
    )),
)


def _match_exposures(cpe: str) -> tuple[tuple[str, float, str], ...] | None:
    lowered = cpe.lower()
    for token, exposures in _EXPOSURES:
        if token in lowered:
            return exposures
    return None


def os_candidates_for_host(host: str, cpes: Any) -> list[OsCveCandidate]:
    """Return landmark CVE candidates for a host's OS fingerprint CPEs.

    Candidates are de-duplicated by CVE id, so a host that reports several OS
    CPEs does not list the same CVE twice.
    """
    if not isinstance(cpes, (list, tuple)):
        return []
    candidates: dict[str, OsCveCandidate] = {}
    for cpe in cpes:
        if not isinstance(cpe, str):
            continue
        exposures = _match_exposures(cpe)
        if exposures is None:
            continue
        for cve_id, cvss, description in exposures:
            candidates.setdefault(
                cve_id,
                OsCveCandidate(
                    host=host,
                    cve_id=cve_id,
                    cvss_score=cvss,
                    description=description,
                    basis=f"OS fingerprint {cpe}",
                ),
            )
    return sorted(
        candidates.values(),
        key=lambda item: (-(item.cvss_score or 0.0), item.cve_id),
    )

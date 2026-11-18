"""Compile one normalized scan into a target-oriented candidate path report."""

from __future__ import annotations

from typing import Any

from hexpath.graph import GraphError, vulnerability_cost
from hexpath.models import Confidence


def compile_path_report(
    scan: dict[str, Any],
    cves: dict[str, Any],
) -> dict[str, Any]:
    """Rank observed target services and their CVE candidates."""
    hosts = scan.get("hosts")
    services = scan.get("services")
    vulnerabilities = cves.get("vulnerabilities")
    matches = cves.get("matches")
    if not isinstance(hosts, list) or not isinstance(services, list):
        raise ValueError("latest scan must contain host and service lists")
    if not isinstance(vulnerabilities, list) or not isinstance(matches, list):
        raise ValueError("CVE results must contain vulnerability and match lists")
    if any(not isinstance(item, dict) for item in (*hosts, *services)):
        raise ValueError("scan host and service records must be objects")
    if any(not isinstance(item, dict) for item in (*vulnerabilities, *matches)):
        raise ValueError("CVE vulnerability and match records must be objects")

    vulnerability_by_id = {
        item.get("id"): item
        for item in vulnerabilities
        if isinstance(item.get("id"), str)
    }
    matches_by_service: dict[str, list[dict[str, Any]]] = {}
    for match in matches:
        service_id = match.get("service_id")
        cve_id = match.get("cve_id")
        if not isinstance(service_id, str) or not isinstance(cve_id, str):
            raise ValueError("each CVE match must identify a service and CVE")
        if match.get("applicability") == "ruled_out":
            continue
        matches_by_service.setdefault(service_id, []).append(match)

    host_names = {
        item.get("address"): item.get("hostnames", [])
        for item in hosts
        if isinstance(item.get("address"), str)
    }
    paths: list[dict[str, Any]] = []
    unmatched_services: list[dict[str, Any]] = []
    for service in services:
        if service.get("state") != "open":
            continue
        service_id = service.get("id")
        host = service.get("host")
        if not isinstance(service_id, str) or not isinstance(host, str):
            raise ValueError("each service must identify its record and host")
        service_matches = matches_by_service.get(service_id, [])
        if not service_matches:
            unmatched_services.append(_service_summary(service))
            continue
        for match in service_matches:
            cve_id = match["cve_id"]
            vulnerability = vulnerability_by_id.get(cve_id)
            if vulnerability is None:
                raise ValueError(f"CVE match refers to unknown vulnerability {cve_id!r}")
            confidence = match.get("confidence")
            try:
                priority_cost = vulnerability_cost(
                    vulnerability.get("cvss_score"),
                    Confidence(confidence),
                )
            except (GraphError, TypeError, ValueError) as error:
                raise ValueError(f"invalid CVE match for {cve_id}: {error}") from error
            paths.append({
                "target": {
                    "host": host,
                    "hostnames": host_names.get(host, []),
                },
                "source": scan.get("vantage", "entry:scanner"),
                "endpoint": {
                    "host": host,
                    "port": service.get("port"),
                    "protocol": service.get("protocol"),
                    "state": service.get("state"),
                },
                "service": _service_summary(service),
                "finding": {
                    "cve_id": cve_id,
                    "description": vulnerability.get("description"),
                    "cvss_score": vulnerability.get("cvss_score"),
                    "cvss_vector": vulnerability.get("cvss_vector"),
                    "confidence": confidence,
                    "reason": match.get("reason"),
                    "references": vulnerability.get("references", []),
                },
                "priority_cost": priority_cost,
                "access_evidence_recorded": match.get("access_supported") is True,
                "evidence": match.get("evidence", []),
                "steps": [
                    {
                        "action": "reach_service",
                        "detail": (
                            f"Connect to {host}:{service.get('port')}/"
                            f"{service.get('protocol')} ({service.get('state')})."
                        ),
                    },
                    {
                        "action": "validate_candidate",
                        "detail": (
                            f"Confirm {cve_id} applies to the detected product, version, "
                            "configuration, and patch state."
                        ),
                    },
                    {
                        "action": "authorized_test",
                        "detail": (
                            f"Use an approved test for {cve_id} and record whether it "
                            "produces the expected access."
                        ),
                    },
                ],
            })

    paths.sort(key=_path_sort_key)
    for rank, path in enumerate(paths, 1):
        path["rank"] = rank
    scope = scan.get("scope")
    return {
        "schema_version": "hexpath-path-v1",
        "source": scan.get("vantage", "entry:scanner"),
        "scan_targets": scope.get("targets", []) if isinstance(scope, dict) else [],
        "candidate_paths": paths,
        "recommended_path": paths[0] if paths else None,
        "observed_services_without_cve_candidates": sorted(
            unmatched_services,
            key=lambda item: (
                str(item.get("host")),
                int(item.get("port") or 0),
                str(item.get("protocol")),
            ),
        ),
        "coverage": cves.get("coverage", {}),
        "coverage_complete": cves.get("completed") is True,
    }


def render_path_report(document: dict[str, Any]) -> str:
    """Render the highest-ranked candidate paths for terminal use."""
    paths = document["candidate_paths"]
    lines = [
        "HexPath Candidate Paths",
        "=======================",
        f"Starting point: {document['source']}",
    ]
    if not paths:
        lines.append("No CVE-backed candidate path was found in the latest scan.")
        unmatched = document["observed_services_without_cve_candidates"]
        if unmatched:
            lines.extend(["", "Observed open services without CVE candidates"])
            for service in unmatched:
                lines.append(
                    f"  {service['host']}:{service['port']}/{service['protocol']}  "
                    f"{_service_identity(service)}"
                )
        lines.extend([
            "",
            "Run a service-version scan before path analysis when software identities are missing.",
        ])
        return _render_lines(lines)

    lines.append(f"Candidate paths: {len(paths)}")
    for path in paths:
        endpoint = path["endpoint"]
        finding = path["finding"]
        score = finding.get("cvss_score")
        score_label = f"CVSS {score:.1f}" if isinstance(score, (int, float)) else "CVSS unknown"
        candidate_lines = [
            "",
            (
                f"Path {path['rank']}: {path['source']} -> "
                f"{endpoint['host']}:{endpoint['port']}/{endpoint['protocol']}"
            ),
            f"  1. Port {endpoint['port']}/{endpoint['protocol']} is {endpoint['state']}",
            f"     Service: {_service_identity(path['service'])}",
            f"  2. {finding['cve_id']} | {score_label} | confidence {finding['confidence']}",
            f"     {finding.get('reason') or 'No match reason supplied.'}",
            f"  3. Validate the affected version, configuration, and patch state.",
            f"  4. Run an approved test for {finding['cve_id']} and record the access result.",
            f"  Priority cost: {path['priority_cost']:.2f}",
        ]
        if finding.get("cvss_vector"):
            candidate_lines.append(f"  Vector: {finding['cvss_vector']}")
        if finding.get("description"):
            candidate_lines.append(f"  Summary: {finding['description']}")
        references = finding.get("references")
        if isinstance(references, list) and references:
            candidate_lines.append(f"  Reference: {references[0]}")
        lines.extend(candidate_lines)
    coverage = "complete" if document["coverage_complete"] else "incomplete"
    lines.extend(["", f"CVE lookup coverage: {coverage}"])
    return _render_lines(lines)


def _service_summary(service: dict[str, Any]) -> dict[str, Any]:
    return {
        key: service.get(key)
        for key in (
            "id", "host", "port", "protocol", "state", "name", "product",
            "version", "cpes",
        )
    }


def _service_identity(service: dict[str, Any]) -> str:
    identity = " ".join(
        str(service[key])
        for key in ("product", "name", "version")
        if service.get(key)
    )
    return identity or "unknown service"


def _path_sort_key(path: dict[str, Any]) -> tuple[Any, ...]:
    endpoint = path["endpoint"]
    return (
        path["priority_cost"],
        str(path["target"]["host"]),
        int(endpoint.get("port") or 0),
        str(path["finding"]["cve_id"]),
    )


def _render_lines(lines: list[str]) -> str:
    return "\n".join(
        "".join(character if character.isprintable() else "?" for character in line)
        for line in lines
    )

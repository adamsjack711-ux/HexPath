"""Compile one normalized scan into a target-oriented candidate path report."""

from __future__ import annotations

from typing import Any

from hexpath.graph import GraphError, build_attack_graph, vulnerability_cost
from hexpath.models import Confidence


TERMINAL_HOST_LIMIT = 5
TERMINAL_SERVICE_LIMIT = 5
TERMINAL_CVE_LIMIT = 5


def compile_path_report(
    scan: dict[str, Any] | list[dict[str, Any]],
    cves: dict[str, Any],
) -> dict[str, Any]:
    """Rank observed hosts and show only evidence-backed directed routes."""
    scans = [scan] if isinstance(scan, dict) else scan
    if not isinstance(scans, list) or not scans or any(not isinstance(item, dict) for item in scans):
        raise ValueError("at least one scan document is required")
    hosts_by_id: dict[str, dict[str, Any]] = {}
    services_by_id: dict[str, dict[str, Any]] = {}
    for document in scans:
        raw_hosts = document.get("hosts")
        raw_services = document.get("services")
        if not isinstance(raw_hosts, list) or not isinstance(raw_services, list):
            raise ValueError("each scan must contain host and service lists")
        for item in raw_hosts:
            if not isinstance(item, dict) or not isinstance(item.get("address"), str):
                raise ValueError("scan hosts must have an address")
            hosts_by_id.setdefault(item["address"], item)
        for item in raw_services:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                raise ValueError("scan services must have an id")
            services_by_id.setdefault(item["id"], item)
    hosts = list(hosts_by_id.values())
    services = list(services_by_id.values())
    vulnerabilities = cves.get("vulnerabilities")
    matches = cves.get("matches")
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
    service_sources: dict[str, str] = {}
    for document in scans:
        for service in document["services"]:
            if isinstance(service, dict) and isinstance(service.get("id"), str):
                service_sources.setdefault(service["id"], document.get("vantage", "entry:scanner"))
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
                "source": service.get("vantage") or service_sources.get(
                    service_id, "entry:scanner"
                ),
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
    # A CVE match is a lead for investigation. Only observed access effects
    # can create a directed route through the evidence-backed graph.
    routes: dict[str, dict[str, Any]] = {}
    if any(match.get("access_supported") is True for match in matches):
        graph = build_attack_graph(scans, cves)
        source = graph.default_source()
        for host in hosts:
            address = host.get("address")
            if not isinstance(address, str):
                continue
            route = graph.shortest_path(source, graph.resolve_node(address))
            if route is not None:
                routes[address] = route.to_dict()

    host_summaries = []
    for host in hosts:
        address = host.get("address")
        if not isinstance(address, str):
            continue
        open_services = [
            _service_summary(service) for service in services
            if service.get("host") == address and service.get("state") == "open"
        ]
        candidates = [path for path in paths if path["target"]["host"] == address]
        host_summaries.append({
            "host": address,
            "hostnames": host.get("hostnames", []),
            "open_services": open_services,
            "candidate_count": len(candidates),
            "best_candidate": candidates[0] if candidates else None,
            "priority_cost": candidates[0]["priority_cost"] if candidates else None,
            "supported_route": routes.get(address),
        })
    host_summaries.sort(key=lambda item: (
        item["priority_cost"] is None,
        item["priority_cost"] if item["priority_cost"] is not None else float("inf"),
        -item["candidate_count"],
        item["host"],
    ))
    for rank, host in enumerate(host_summaries, 1):
        host["rank"] = rank
    scope = scans[0].get("scope")
    return {
        "schema_version": "hexpath-path-v1",
        "source": "entry:scanner" if len(scans) > 1 else scans[0].get("vantage", "entry:scanner"),
        "scan_targets": scope.get("targets", []) if isinstance(scope, dict) else [],
        "candidate_paths": paths,
        "recommended_path": paths[0] if paths else None,
        "ranked_hosts": host_summaries,
        "recommended_host": host_summaries[0] if host_summaries and host_summaries[0]["candidate_count"] else None,
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
    """Render a short investigation summary for the highest-ranked hosts."""
    paths = document["candidate_paths"]
    coverage = "complete" if document["coverage_complete"] else "incomplete"
    hosts = document["ranked_hosts"]
    shown_hosts = hosts[:TERMINAL_HOST_LIMIT]
    ports_by_host_and_cve: dict[str, dict[str, dict[str, None]]] = {
        host["host"]: {} for host in shown_hosts
    }
    for path in paths:
        endpoint = path["endpoint"]
        host_cves = ports_by_host_and_cve.get(endpoint["host"])
        if host_cves is not None:
            ports = host_cves.setdefault(path["finding"]["cve_id"], {})
            ports[f"{endpoint['port']}/{endpoint['protocol']}"] = None
    lines = [
        "HexPath Host Investigation Paths",
        "================================",
        f"Starting point: {document['source']}",
        f"CVE lookup coverage: {coverage}",
    ]
    lookup = document["coverage"]
    if isinstance(lookup, dict):
        attempted = lookup.get("cpe_checks")
        completed = lookup.get("completed_cpe_checks")
        if isinstance(attempted, int) and isinstance(completed, int):
            lines.append(f"Software identities checked: {completed}/{attempted}")
        missing = lookup.get("services_without_cpe")
        if isinstance(missing, int) and missing > 0:
            lines.append(f"Services missing a CPE (software identifier): {missing}")
        if attempted == 0 and (missing or lookup.get("invalid_cpes")):
            lines.append("CVE search needs a saved service scan with precise software identities.")
    lines.append(f"Hosts observed: {len(hosts)} | showing {len(shown_hosts)} | CVE leads: {len(paths)}")
    for host in shown_hosts:
        best = host["best_candidate"]
        services = host["open_services"]
        lines.extend([
            "",
            f"{host['rank']}. {host['host']} | Open services: {len(services)}"
            f" | CVE leads: {host['candidate_count']}",
        ])
        host_cves = ports_by_host_and_cve[host["host"]]
        if host_cves:
            lines.append("   CVE candidates and matched ports")
            for cve_id, ports in list(host_cves.items())[:TERMINAL_CVE_LIMIT]:
                lines.append(f"      {cve_id}  {', '.join(ports)}")
            if len(host_cves) > TERMINAL_CVE_LIMIT:
                lines.append(f"      {len(host_cves) - TERMINAL_CVE_LIMIT} more CVEs in the full report")
        elif services:
            lines.append("   Observed open ports")
            for service in services[:TERMINAL_SERVICE_LIMIT]:
                version_note = "" if service.get("version") else " (version unknown)"
                lines.append(
                    f"      {service['port']}/{service['protocol']}  "
                    f"{_service_identity(service)}{version_note}"
                )
            if len(services) > TERMINAL_SERVICE_LIMIT:
                lines.append(f"      {len(services) - TERMINAL_SERVICE_LIMIT} more in the full report")
        route = host["supported_route"]
        if route:
            lines.append(f"   Evidence-backed route: {' -> '.join(route['nodes'])}")
        if not best:
            lines.append("   No CVE candidate in the supplied results.")
            if services:
                lines.append("   1. Confirm product and version from the host inventory.")
            else:
                lines.append("   1. Review which ports and protocols the scan covered.")
            continue
        endpoint = best["endpoint"]
        address = endpoint["host"]
        endpoint_host = f"[{address}]" if ":" in address else address
        finding = best["finding"]
        score = finding.get("cvss_score")
        score_label = f"CVSS {score:.1f}" if isinstance(score, (int, float)) else "CVSS unknown"
        lines.extend([
            (
                f"   1. Review {endpoint_host}:{endpoint['port']}/{endpoint['protocol']}"
                f" ({_service_identity(best['service'])}), observed from {best['source']}."
            ),
            (
                f"   2. Review the unconfirmed {finding['cve_id']} lead "
                f"({score_label}, {finding['confidence']} confidence)."
            ),
            f"      {finding.get('reason') or 'No match reason supplied.'}",
            "   3. Verify the installed version, configuration, and patch status against the advisory.",
        ])
    if hosts and not any(host["supported_route"] for host in hosts):
        lines.extend(["", "No evidence-backed host access route is recorded in these scans."])
    if not hosts:
        lines.extend(["", "No hosts were recorded in the supplied scans."])
    if hosts:
        lines.extend(["", "Use --json or --output for the full report."])
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

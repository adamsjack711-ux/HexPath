"""Compile one normalized scan into a target-oriented candidate path report."""

from __future__ import annotations

from typing import Any

from hexpath.graph import GraphError, build_attack_graph, vulnerability_cost
from hexpath.models import Confidence


def compile_path_report(
    scan: dict[str, Any] | list[dict[str, Any]],
    cves: dict[str, Any],
    *,
    metasploit_modules: dict[str, list[dict[str, Any]]] | None = None,
    metasploit_source: str | None = None,
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
                "metasploit_modules": (
                    metasploit_modules.get(cve_id.upper(), []) if metasploit_modules is not None else []
                ),
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
        "metasploit": {
            "available": metasploit_modules is not None,
            "source": metasploit_source,
            "matched_leads": sum(bool(path["metasploit_modules"]) for path in paths),
        },
    }


def render_path_report(document: dict[str, Any]) -> str:
    """Render the highest-ranked candidate paths for terminal use."""
    paths = document["candidate_paths"]
    coverage = "complete" if document["coverage_complete"] else "incomplete"
    lines = [
        "HexPath Host Investigation Paths",
        "================================",
        f"Starting point: {document['source']}",
        f"CVE lookup coverage: {coverage}",
    ]
    metasploit = document["metasploit"]
    if metasploit["available"]:
        lines.append(f"Metasploit module matches: {metasploit['matched_leads']} leads")
    else:
        lines.append("Metasploit module metadata unavailable; use --metasploit-db PATH.")
    hosts = document["ranked_hosts"]
    lines.extend(["", f"Hosts observed: {len(hosts)}", "Host investigation priority (CVE candidates are unconfirmed)"])
    for host in hosts:
        best = host["best_candidate"]
        lead = (
            f"{best['finding']['cve_id']} on {best['endpoint']['port']}/{best['endpoint']['protocol']}"
            if best else "no CVE candidate"
        )
        lines.append(
            f"  {host['rank']}. {host['host']} | open services {len(host['open_services'])}"
            f" | candidates {host['candidate_count']} | {lead}"
        )
        for service in host["open_services"][:5]:
            lines.append(
                f"     {service['port']}/{service['protocol']}: {_service_identity(service)}"
            )
        if len(host["open_services"]) > 5:
            lines.append(f"     ... {len(host['open_services']) - 5} more open services in JSON")
        route = host["supported_route"]
        if route:
            lines.append(f"     Evidence-backed route: {' -> '.join(route['nodes'])}")
    if not any(host["supported_route"] for host in hosts):
        lines.append("No evidence-backed host access route is recorded in these scans.")
    if not paths:
        lines.append("No CVE-backed investigation lead was found in the supplied scans.")
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

    lines.append(f"Investigation leads: {len(paths)}")
    for path in paths:
        endpoint = path["endpoint"]
        finding = path["finding"]
        score = finding.get("cvss_score")
        score_label = f"CVSS {score:.1f}" if isinstance(score, (int, float)) else "CVSS unknown"
        candidate_lines = [
            "",
            (
                f"Lead {path['rank']}: {path['source']} -> "
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
        modules = path["metasploit_modules"]
        for module in modules[:3]:
            candidate_lines.append(
                f"  Metasploit module: {module['fullname']} ({module['type'] or 'unknown type'})"
            )
        if len(modules) > 3:
            candidate_lines.append(f"  ... {len(modules) - 3} more modules in JSON")
        lines.extend(candidate_lines)
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

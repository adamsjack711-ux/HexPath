"""IPv6 assessment summaries for the terminal and saved assessment bundles."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from hexpath.graph import ENTRY_NODE_ID, build_attack_graph
from hexpath.models import Evidence, EvidenceLevel, Host
from hexpath.scanner import require_authorized_vantage
from hexpath.scope import Scope
from hexpath.vulnerabilities import CpeIdentity, VulnerabilityError


def validate_scans(scope: Scope, documents: list[object]) -> list[dict[str, Any]]:
    """Validate imported addresses before enrichment; preserve original inputs."""
    scans = deepcopy(documents)
    for scan in scans:
        if not isinstance(scan, dict):
            raise ValueError("scan must be an object")
        for name in ("hosts", "services"):
            if not isinstance(scan.get(name), list):
                raise ValueError(f"scan must contain a {name} list")
        vantage = require_authorized_vantage(scope, scan.get("vantage", ENTRY_NODE_ID))
        scan["vantage"] = vantage
        for host in scan["hosts"]:
            if not isinstance(host, dict):
                raise ValueError("host must be an object")
            address = scope.require_authorized(host.get("address"))
            if host.get("id") != f"host:{address}":
                raise ValueError("host id must match its canonical IPv6 address")
        for service in scan["services"]:
            if not isinstance(service, dict):
                raise ValueError("service must be an object")
            cpes = service.get("cpes", [])
            if not isinstance(cpes, list) or any(not isinstance(cpe, str) for cpe in cpes):
                raise ValueError("service CPEs must be a list of strings")
            address = scope.require_authorized(service.get("host"))
            if service.get("host") != str(address):
                raise ValueError("service host must use its canonical IPv6 address")
        if vantage != ENTRY_NODE_ID and not any(h["id"] == vantage for h in scan["hosts"]):
            scan["hosts"].append(Host(
                address=vantage.removeprefix("host:"),
                evidence=(Evidence(
                    source="operator",
                    summary="Operator-declared scan origin; access was not verified by HexPath",
                    level=EvidenceLevel.INFERRED,
                ),),
            ).to_dict())
    return scans


def summarize_assessment(
    scope: Scope, scans: list[dict[str, Any]], cves: object, *, source: str, target: str,
) -> dict[str, Any]:
    """Keep observed exposure separate from hypothetical compromise transitions."""
    if not isinstance(cves, dict):
        raise ValueError("CVE results must be an object")
    coverage = cves.get("coverage", {})
    checks = cves.get("checks", [])
    if not isinstance(coverage, dict) or not isinstance(checks, list) or any(
        not isinstance(check, dict) for check in checks
    ):
        raise ValueError("CVE coverage must be an object and checks a list of objects")
    if any(not isinstance(check.get("cpe"), str) for check in checks):
        raise ValueError("each CVE check must identify its CPE")
    observations = [
        {**service, "vantage": scan["vantage"]}
        for scan in scans for service in scan["services"]
    ]
    modeled_matches, excluded_reasons = _modeled_matches(observations, cves, checks)
    graph_cves = {**cves, "matches": modeled_matches}
    graph = build_attack_graph(scans, graph_cves)
    node_ids = {node.node_id for node in graph.nodes}
    if source not in node_ids:
        raise ValueError(f"source {source!r} has no recorded observations")
    path = graph.shortest_path(source, target) if target in node_ids else None
    target_address = target.removeprefix("host:")
    direct = any(
        item["vantage"] == source and item["host"] == target_address
        and item.get("state") == "open" for item in observations
    )
    steps = []
    if path:
        for edge in path.edges:
            candidate = edge.relationship == "candidate_exploit"
            steps.append({
                **edge.to_dict(),
                "assessment": "candidate_compromise" if candidate else "observed_reachability",
                "next_check": (
                    "Validate applicability, required credentials, exploit conditions, and resulting access."
                    if candidate else "Confirm this observation is still current from the recorded vantage."
                ),
            })
    service_ids = {item["id"] for item in observations}
    expected_cpes = {cpe for item in observations for cpe in item.get("cpes", [])}
    # A bare completed flag, or enrichment for a different scan set, is not coverage.
    try:
        expected_cpes = {CpeIdentity(cpe).value for cpe in expected_cpes}
    except VulnerabilityError:
        expected_cpes = {"invalid CPE"}
    covered_cpes = {check.get("cpe") for check in checks if check.get("completed") is True}
    complete = (
        cves.get("completed") is True and bool(service_ids) and bool(checks)
        and coverage.get("services") == len(service_ids)
        and all(item.get("cpes") for item in observations)
        and expected_cpes <= covered_cpes
        and all(check.get("completed") is True and check.get("screening_complete") is not False
                and check.get("status") != "unknown" for check in checks)
        and not cves.get("unmatched_services") and not cves.get("invalid_cpes")
    )
    return {
        "schema_version": "hexpath-ipv6-assessment-v2",
        "scope": {"name": scope.name, "targets": [str(n) for n in scope.networks]},
        "source": source, "target": target,
        "target_observed": target in node_ids,
        "target_service_reachable_from_source": direct,
        "coverage_complete": complete,
        "coverage": coverage,
        "observations": observations,
        "modeled_matches": modeled_matches,
        "excluded_match_count": sum(excluded_reasons.values()),
        "excluded_match_reasons": excluded_reasons,
        "candidate_path": None if path is None else {
            "nodes": list(path.nodes), "total_cost": path.total_weight, "steps": steps,
        },
        "limitations": [
            "CVE matches are investigation candidates, not confirmed compromise.",
            "CVE matches do not create access paths without observed access-effect evidence.",
            "Path costs rank investigation routes, not exploit success probabilities.",
            "Scan origins are operator declarations; HexPath does not pivot or verify access.",
            "No modeled path does not establish that a target is secure or unreachable.",
        ],
        "scans": scans, "cves": cves, "graph": graph.to_dict(),
    }


def _modeled_matches(
    observations: list[dict[str, Any]], cves: dict[str, Any], checks: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Keep stale or broad CPE links out of candidate routes."""
    service_cpes: dict[str, set[str]] = {}
    for service in observations:
        identities = service_cpes.setdefault(service["id"], set())
        for raw_cpe in service.get("cpes", []):
            try:
                identity = CpeIdentity(raw_cpe)
            except VulnerabilityError:
                continue
            if identity.precise_version:
                identities.add(identity.value)
    completed = {check["cpe"] for check in checks if check.get("completed") is True}
    matches = cves.get("matches", [])
    if not isinstance(matches, list):
        raise ValueError("CVE matches must be a list")
    modeled: list[dict[str, Any]] = []
    excluded: dict[str, int] = {}
    for match in matches:
        if not isinstance(match, dict):
            raise ValueError("CVE matches must contain objects")
        applicability = match.get("applicability", "candidate")
        if applicability not in {"candidate", "ruled_out"}:
            raise ValueError("CVE match applicability must be candidate or ruled_out")
        if applicability == "ruled_out":
            if match.get("access_supported") is True:
                raise ValueError("ruled-out CVE match cannot support access")
            evidence = match.get("applicability_evidence", [])
            if not isinstance(evidence, list) or not any(
                isinstance(item, dict) and item.get("level") == "observed"
                for item in evidence
            ):
                raise ValueError("ruled-out CVE match requires observed applicability evidence")
            reason = "local evidence rules out CVE applicability"
            excluded[reason] = excluded.get(reason, 0) + 1
            continue
        service_id = match.get("service_id")
        if service_id not in service_cpes:
            modeled.append(match)  # Let graph validation report an unknown service.
            continue
        candidates = service_cpes[service_id]
        cpe = match.get("cpe")
        if cpe is None and len(candidates) == 1:
            cpe = next(iter(candidates))  # Legacy evidence with one precise identity.
        if not candidates:
            reason = "service has no precise version CPE"
        elif not isinstance(cpe, str) or cpe not in candidates:
            reason = "CVE link has no attributable matching CPE"
        elif cpe not in completed:
            reason = "CVE link has no completed check for its current CPE"
        else:
            modeled.append(match)
            continue
        excluded[reason] = excluded.get(reason, 0) + 1
    return modeled, excluded


def render_assessment(document: dict[str, Any]) -> str:
    """Render a plain-text CLI summary without trusting terminal control bytes."""
    observations = document["observations"]
    target_address = document["target"].removeprefix("host:")
    target_services = [item for item in observations if item["host"] == target_address]
    other_hosts: dict[str, set[str]] = {}
    for item in observations:
        if item["host"] != target_address:
            other_hosts.setdefault(item["host"], set()).add(item["id"])
    target_ids = {item["id"] for item in target_services}
    matches = document["modeled_matches"]
    target_candidates = {
        match["cve_id"] for match in matches
        if isinstance(match, dict) and match.get("service_id") in target_ids
        and isinstance(match.get("cve_id"), str)
    }
    target_matches = {
        match["cve_id"]: match for match in matches
        if isinstance(match, dict) and match.get("service_id") in target_ids
        and isinstance(match.get("cve_id"), str)
    }
    vulnerabilities = {
        item["id"]: item for item in document["cves"].get("vulnerabilities", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    checks = document["cves"].get("checks", [])
    completed_checks = sum(
        check.get("completed") is True and check.get("screening_complete") is not False
        and check.get("status") != "unknown"
        for check in checks
    )
    lines = [
        "HexPath IPv6 Pentest Assessment", "===============================",
        f"Scope: {document['scope']['name']}",
        f"Starting point: {document['source']}", f"Objective: {document['target']}",
        "", "AT A GLANCE",
        f"  Target services observed: {len(target_ids)}",
        f"  Other hosts observed: {len(other_hosts)}",
        f"  Target CVE candidates: {len(target_candidates)} (not verified vulnerabilities)",
        f"  Target CVE links with observed access-effect evidence: "
        f"{sum(match.get('access_supported') is True for match in target_matches.values())}",
        f"  NVD CPE checks completed: {completed_checks}/{len(checks)}",
        f"  CVE links excluded from routes: {document['excluded_match_count']}",
        "", "TARGET EXPOSURE",
    ]
    for item in target_services:
        lines.append(
            f"  {item['vantage']} -> [{item['host']}]:{item.get('port')}"
            f"/{item.get('protocol')}  {item.get('state')}  "
            f"{item.get('product') or item.get('name') or 'unknown service'} "
            f"{item.get('version') or ''}"
        )
    if not target_services:
        lines.append("  No target services recorded; exposure is unknown.")
    if document["target_service_reachable_from_source"]:
        lines.append("  An open target service was observed from the starting point.")
    elif not document["target_observed"]:
        lines.append("  The target was not observed in these scans.")
    lines.extend(["", "OTHER OBSERVED HOSTS"])
    if other_hosts:
        for host, service_ids in sorted(other_hosts.items()):
            lines.append(f"  {host}: {len(service_ids)} service(s); full evidence is in assessment JSON")
    else:
        lines.append("  None recorded.")
    lines.extend(["", "CVE REVIEW FOR TARGET"])
    if not target_matches:
        lines.append("  No version-supported CVE candidates in the available evidence.")
    else:
        ranked = sorted(target_matches, key=lambda cve_id: (
            -(vulnerabilities.get(cve_id, {}).get("cvss_score") or 0), cve_id,
        ))
        lines.append(f"  Showing {min(10, len(ranked))} of {len(ranked)}; full list is in assessment JSON.")
        for cve_id in ranked[:10]:
            vulnerability = vulnerabilities.get(cve_id, {})
            score = vulnerability.get("cvss_score")
            label = f"CVSS {score:.1f}" if isinstance(score, (int, float)) else "CVSS unknown"
            access = "observed access effect" if target_matches[cve_id].get("access_supported") is True else "access effect unverified"
            lines.append(f"  {cve_id} | {label} | {access}")
            summary = str(vulnerability.get("description") or "No description supplied")
            lines.append(f"     {summary[:140]}{'...' if len(summary) > 140 else ''}")
    lines.extend(["", "ACCESS PATH TO OBJECTIVE"])
    path = document["candidate_path"]
    if path is None:
        lines.append("  No supported access path in the available evidence; this does not mean secure.")
    else:
        lines.append(f"  Investigation cost: {path['total_cost']:.2f}")
        for index, step in enumerate(path["steps"], 1):
            lines.append(
                f"  {index}. {step['assessment']}: {step['source']} -> {step['target']}"
            )
            if step["assessment"] == "candidate_compromise":
                lines.append(
                    f"     {step['metadata']['cve_id']} | confidence: "
                    f"{step['metadata']['confidence']} | access: UNVERIFIED"
                )
            lines.append(f"     Next: {step['next_check']}")
            for evidence in step["evidence"]:
                lines.append(
                    f"     Evidence: {evidence['source']} / {evidence['level']} / "
                    f"{evidence['collected_at']}"
                    + (f" / {evidence['reference']}" if evidence.get("reference") else "")
                )
    lines.extend(["", "COVERAGE AND LIMITATIONS"])
    lines.append("  CVE lookup coverage: " + (
        "complete for supplied service identities" if document["coverage_complete"]
        else "INCOMPLETE / UNKNOWN - unresolved checks remain"
    ))
    for reason, count in document["excluded_match_reasons"].items():
        lines.append(f"  {count} CVE link(s) excluded: {reason}.")
    for check in checks:
        if check.get("error"):
            lines.append(f"  Lookup failed for {check['cpe']}: {check['error']}")
        excluded = check.get("excluded", [])
        if excluded:
            lines.append(f"  NVD records excluded for {check['cpe']}: {len(excluded)}")
            for record in excluded[:5]:
                lines.append(f"    {record['cve_id']}: {record['reason']}")
    for item in document["cves"].get("invalid_cpes", []):
        lines.append(f"  Unchecked CPE on {item['service_id']}: {item['cpe']} ({item['error']})")
    for service_id in document["cves"].get("unmatched_services", []):
        lines.append(f"  No CPE for {service_id}; CVE lookup unavailable.")
    lines.extend(f"  {item}" for item in document["limitations"])
    return "\n".join(
        "".join(c if c.isprintable() else "?" for c in line) for line in lines
    )

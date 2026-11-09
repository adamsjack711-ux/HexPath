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
    graph = build_attack_graph(scans, cves)
    node_ids = {node.node_id for node in graph.nodes}
    if source not in node_ids:
        raise ValueError(f"source {source!r} has no recorded observations")
    path = graph.shortest_path(source, target) if target in node_ids else None
    observations = [
        {**service, "vantage": scan["vantage"]}
        for scan in scans for service in scan["services"]
    ]
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
    coverage = cves.get("coverage", {})
    checks = cves.get("checks", [])
    if not isinstance(coverage, dict) or not isinstance(checks, list) or any(
        not isinstance(check, dict) for check in checks
    ):
        raise ValueError("CVE coverage must be an object and checks a list of objects")
    if any(not isinstance(check.get("cpe"), str) for check in checks):
        raise ValueError("each CVE check must identify its CPE")
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
        and all(check.get("completed") is True for check in checks)
        and not cves.get("unmatched_services") and not cves.get("invalid_cpes")
    )
    return {
        "schema_version": "hexpath-ipv6-assessment-v1",
        "scope": {"name": scope.name, "targets": [str(n) for n in scope.networks]},
        "source": source, "target": target,
        "target_observed": target in node_ids,
        "target_service_reachable_from_source": direct,
        "coverage_complete": complete,
        "coverage": coverage,
        "observations": observations,
        "candidate_path": None if path is None else {
            "nodes": list(path.nodes), "total_cost": path.total_weight, "steps": steps,
        },
        "limitations": [
            "CVE matches are investigation candidates, not confirmed compromise.",
            "Path costs rank investigation routes, not exploit success probabilities.",
            "Scan origins are operator declarations; HexPath does not pivot or verify access.",
            "No modeled path does not establish that a target is secure or unreachable.",
        ],
        "scans": scans, "cves": cves, "graph": graph.to_dict(),
    }


def render_assessment(document: dict[str, Any]) -> str:
    """Render a plain-text CLI summary without trusting terminal control bytes."""
    lines = [
        "HexPath IPv6 Pentest Assessment", "===============================",
        f"Scope: {document['scope']['name']}",
        f"Starting point: {document['source']}", f"Objective: {document['target']}",
        "", "OBSERVED EXPOSURE",
    ]
    for item in document["observations"]:
        lines.append(
            f"  {item['vantage']} -> [{item['host']}]:{item.get('port')}"
            f"/{item.get('protocol')}  {item.get('state')}  "
            f"{item.get('product') or item.get('name') or 'unknown service'} "
            f"{item.get('version') or ''}"
        )
    if not document["observations"]:
        lines.append("  No services recorded; exposure is unknown.")
    if document["target_service_reachable_from_source"]:
        lines.append("  An open target service was observed from the starting point.")
    elif not document["target_observed"]:
        lines.append("  The target was not observed in these scans.")
    lines.extend(["", "CANDIDATE PATH TO OBJECTIVE"])
    path = document["candidate_path"]
    if path is None:
        lines.append("  No modeled path in the available evidence; this does not mean secure.")
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
    for check in document["cves"].get("checks", []):
        if check.get("error"):
            lines.append(f"  Lookup error: {check['error']}")
    lines.extend(f"  {item}" for item in document["limitations"])
    return "\n".join(
        "".join(c if c.isprintable() else "?" for c in line) for line in lines
    )

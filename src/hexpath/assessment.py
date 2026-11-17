"""IPv6 assessment summaries for the terminal and saved assessment bundles."""

from __future__ import annotations

from copy import deepcopy
import re
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
            if "os_name" in host and (
                not isinstance(host["os_name"], str) or not host["os_name"].strip()
            ):
                raise ValueError("host os_name must be a non-empty string")
            if "os_accuracy" in host and (
                isinstance(host["os_accuracy"], bool)
                or not isinstance(host["os_accuracy"], int)
                or not 0 <= host["os_accuracy"] <= 100
            ):
                raise ValueError("host os_accuracy must be an integer from 0 to 100")
            if "cpes" in host and (
                not isinstance(host["cpes"], list)
                or any(not isinstance(cpe, str) for cpe in host["cpes"])
            ):
                raise ValueError("host CPEs must be a list of strings")
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
    next_checks = _next_checks(
        observations, modeled_matches, checks, target_address=target_address,
        source=source, target_observed=target in node_ids,
    )
    host_information = grade_host_information(
        scans, observations, checks, target_address=target_address,
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
        "next_checks": next_checks,
        "host_information": host_information,
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


def grade_host_information(
    scans: list[dict[str, Any]], observations: list[dict[str, Any]],
    checks: list[dict[str, Any]], *, target_address: str,
) -> dict[str, Any]:
    """Grade how complete the supplied service identity and lookup evidence is."""
    services: dict[str, set[str]] = {}
    for service in observations:
        if service.get("host") != target_address or service.get("state") != "open":
            continue
        identities = services.setdefault(service["id"], set())
        for raw_cpe in service.get("cpes", []):
            try:
                cpe = CpeIdentity(raw_cpe)
            except VulnerabilityError:
                continue
            if cpe.precise_version:
                identities.add(cpe.value)
    completed = {
        check.get("cpe") for check in checks
        if check.get("completed") is True
        and check.get("screening_complete") is not False
        and check.get("status") != "unknown"
    }
    exact = sum(len(identities) == 1 for identities in services.values())
    checked = sum(
        len(identities) == 1 and identities <= completed
        for identities in services.values()
    )
    if services:
        score = round(50 * (exact + checked) / len(services), 1)
        grade = "A" if score == 100 else "B" if score >= 75 else "C" if score >= 50 else "D"
    else:
        score, grade = None, "U"
    os_guesses = []
    seen_guesses: set[tuple[str | None, int | None, tuple[str, ...], str]] = set()
    for scan in scans:
        for host in scan["hosts"]:
            if host.get("address") != target_address:
                continue
            name = host.get("os_name")
            accuracy = host.get("os_accuracy")
            cpes = tuple(host.get("cpes", []))
            if not name and not cpes:
                continue
            key = (name, accuracy, cpes, scan["vantage"])
            if key not in seen_guesses:
                seen_guesses.add(key)
                os_guesses.append({
                    "name": name, "nmap_accuracy": accuracy,
                    "cpes": list(cpes), "vantage": scan["vantage"],
                    "evidence_level": "inferred",
                })
    os_guesses.sort(key=lambda item: (-(item["nmap_accuracy"] or 0), item["name"] or ""))
    return {
        "grade": grade, "score": score,
        "open_services": len(services),
        "services_with_exact_cpe": exact,
        "services_with_completed_cve_check": checked,
        "conflicting_service_ids": sorted(
            service_id for service_id, identities in services.items() if len(identities) > 1
        ),
        "os_guesses": os_guesses,
        "meaning": (
            "Evidence completeness for observed open services; not a security or exploitability grade."
        ),
    }


def _next_checks(
    observations: list[dict[str, Any]], matches: list[dict[str, Any]],
    checks: list[dict[str, Any]], *, target_address: str, source: str,
    target_observed: bool,
) -> list[dict[str, Any]]:
    """Turn target-specific evidence gaps into ordered, bounded follow-ups."""
    actions: list[dict[str, Any]] = []
    services: dict[str, list[dict[str, Any]]] = {}
    for item in observations:
        if item["host"] == target_address and item.get("state") == "open":
            services.setdefault(item["id"], []).append(item)
    completed_cpes = {
        check.get("cpe") for check in checks
        if check.get("completed") is True
        and check.get("screening_complete") is not False
        and check.get("status") != "unknown"
    }
    for service_id, sightings in sorted(services.items()):
        service = sightings[0]
        endpoint = (
            f"[{target_address}]:{service.get('port')}/{service.get('protocol')}"
        )
        precise_cpes: set[str] = set()
        for sighting in sightings:
            for raw_cpe in sighting.get("cpes", []):
                try:
                    cpe = CpeIdentity(raw_cpe)
                except VulnerabilityError:
                    continue
                if cpe.precise_version:
                    precise_cpes.add(cpe.value)
        if len(precise_cpes) > 1:
            actions.append({
                "kind": "reconcile_identity", "service_id": service_id,
                "cpes": sorted(precise_cpes),
                "action": (
                    f"Reconcile conflicting exact CPEs recorded for {endpoint} "
                    "before using version-specific CVE results."
                ),
            })
            continue
        elif not precise_cpes:
            actions.append({
                "kind": "confirm_version", "service_id": service_id,
                "action": (
                    f"Confirm the exact software version on {endpoint} using an "
                    "authorized protocol query or trusted inventory before CVE lookup."
                ),
            })
        else:
            for cpe in sorted(precise_cpes - completed_cpes):
                actions.append({
                    "kind": "complete_cve_lookup", "service_id": service_id,
                    "cpe": cpe,
                    "action": f"Complete the CVE lookup for {cpe} on {endpoint}.",
                })
        unverified = sorted({
            match["cve_id"] for match in matches
            if match.get("service_id") == service_id
            and match.get("access_supported") is not True
            and isinstance(match.get("cve_id"), str)
        })
        if unverified:
            actions.append({
                "kind": "verify_cve_conditions", "service_id": service_id,
                "cve_ids": unverified,
                "action": (
                    f"Review applicability and required configuration for "
                    f"{len(unverified)} CVE candidate(s) on {endpoint}; record an "
                    "observed access effect before asserting a path."
                ),
            })
    if not services:
        actions.append({
            "kind": "confirm_reachability", "service_id": None,
            "action": (
                f"Recheck the authorized IPv6 target {target_address} from {source}; "
                "no open target service was recorded."
                if target_observed else
                f"Confirm the IPv6 target seed {target_address} and scan vantage {source}; "
                "the target was not observed."
            ),
        })
    actions.append({
        "kind": "record_probe_coverage", "service_id": None,
        "action": (
            f"Record the IPv6 addresses, TCP/UDP ports, and vantage actually tested "
            f"from {source}; observed services do not establish full scan coverage."
        ),
    })
    return actions


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
    host_information = document.get("host_information", {})
    grade = host_information.get("grade", "U")
    grade_score = host_information.get("score")
    lines = [
        "HexPath IPv6 Pentest Assessment", "===============================",
        f"Scope: {document['scope']['name']}",
        f"Starting point: {document['source']}", f"Objective: {document['target']}",
        "", "AT A GLANCE",
        f"  Target services observed: {len(target_ids)}",
        f"  Host information grade: {grade}"
        + (f" ({grade_score:.1f}/100)" if isinstance(grade_score, (int, float)) else ""),
        f"  Other hosts observed: {len(other_hosts)}",
        f"  Target CVE candidates: {len(target_candidates)} (not verified vulnerabilities)",
        f"  Target CVE links with observed access-effect evidence: "
        f"{sum(match.get('access_supported') is True for match in target_matches.values())}",
        f"  NVD CPE checks completed: {completed_checks}/{len(checks)}",
        f"  CVE links excluded from routes: {document['excluded_match_count']}",
        "", "TARGET EXPOSURE",
    ]
    displayed_exposures: set[tuple[str, str | None]] = set()
    for item in target_services:
        exposure_line = (
            f"  {item['vantage']} -> [{item['host']}]:{item.get('port')}"
            f"/{item.get('protocol')}  {item.get('state')}  "
            f"{item.get('product') or item.get('name') or 'unknown service'} "
            f"{item.get('version') or ''}"
        )
        confirmation = item.get("version_confirmation")
        original = item.get("original_identity")
        confirmation_line = None
        if isinstance(confirmation, dict) and isinstance(original, dict):
            previous = original.get("version") or "unversioned"
            confirmation_line = (
                f"    Version confirmed by {confirmation.get('source', 'protocol probe')}: "
                f"{confirmation.get('version', 'unknown')} "
                f"(original scan: {previous}; "
                f"{confirmation.get('reference', 'reference unavailable')})"
            )
        display_key = (exposure_line, confirmation_line)
        if display_key in displayed_exposures:
            continue
        displayed_exposures.add(display_key)
        lines.append(exposure_line)
        if confirmation_line:
            lines.append(confirmation_line)
    if not target_services:
        lines.append("  No target services recorded; exposure is unknown.")
    if document["target_service_reachable_from_source"]:
        lines.append("  An open target service was observed from the starting point.")
    elif not document["target_observed"]:
        lines.append("  The target was not observed in these scans.")
    lines.extend(["", "HOST INFORMATION GRADE"])
    lines.append(
        f"  {grade}"
        + (f" ({grade_score:.1f}/100)" if isinstance(grade_score, (int, float)) else "")
        + ": completeness of supplied evidence, not a safety rating."
    )
    lines.append(
        f"  Exact CPEs: {host_information.get('services_with_exact_cpe', 0)}/"
        f"{host_information.get('open_services', 0)} open service(s); "
        f"completed CVE checks: {host_information.get('services_with_completed_cve_check', 0)}/"
        f"{host_information.get('open_services', 0)}."
    )
    for service_id in host_information.get("conflicting_service_ids", []):
        lines.append(f"  Conflicting exact CPEs across scans: {service_id}.")
    os_guesses = host_information.get("os_guesses", [])
    if os_guesses:
        for guess in os_guesses:
            accuracy = guess.get("nmap_accuracy")
            lines.append(
                f"  OS fingerprint guess: {guess.get('name') or 'unnamed'}"
                + (f" ({accuracy}% Nmap accuracy)" if accuracy is not None else "")
                + f" from {guess.get('vantage')}; patch level unverified."
            )
            if guess.get("cpes"):
                lines.append("    OS CPEs (broad): " + ", ".join(guess["cpes"]))
    else:
        lines.append("  OS fingerprint: not recorded for this target.")
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
    lines.extend(["", "NEXT CHECKS FOR TARGET"])
    for index, item in enumerate(document.get("next_checks", []), 1):
        lines.append(f"  {index}. {item['action']}")
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


def build_host_information_report(document: dict[str, Any]) -> dict[str, Any]:
    """Project one selected host's scan and CVE evidence without path analysis."""
    address = document["target"].removeprefix("host:")
    information = document["host_information"]
    observations: dict[str, dict[str, Any]] = {}
    for item in document["observations"]:
        if item.get("host") != address or item.get("state") != "open":
            continue
        record = observations.setdefault(item["id"], {
            "id": item["id"], "port": item["port"], "protocol": item["protocol"],
            "software": "unknown", "product": None, "version": None,
            "cpes": set(), "nse_responses": set(),
        })
        record["product"] = item.get("product") or record["product"]
        record["version"] = item.get("version") or record["version"]
        record["software"] = " ".join(
            str(record[key]) for key in ("product", "version") if record.get(key)
        ) or item.get("name") or record["software"]
        record["cpes"].update(item.get("cpes", []))
        record["nse_responses"].update(
            evidence["summary"] for evidence in item.get("evidence", [])
            if isinstance(evidence, dict) and evidence.get("source") == "nmap-nse"
            and isinstance(evidence.get("summary"), str)
        )
    completed_cpes = {
        check.get("cpe") for check in document["cves"].get("checks", [])
        if check.get("completed") is True
        and check.get("screening_complete") is not False
        and check.get("status") != "unknown"
    }
    candidates: dict[str, set[str]] = {}
    for match in document.get("modeled_matches", []):
        if not isinstance(match, dict) or match.get("service_id") not in observations:
            continue
        if isinstance(match.get("cve_id"), str):
            candidates.setdefault(match["service_id"], set()).add(match["cve_id"])
    services = []
    for item in sorted(observations.values(), key=lambda row: (row["protocol"], row["port"])):
        precise = set()
        for raw_cpe in item["cpes"]:
            try:
                identity = CpeIdentity(raw_cpe)
            except VulnerabilityError:
                continue
            if identity.precise_version:
                precise.add(identity.value)
        identity_status = "exact" if len(precise) == 1 else (
            "conflicting" if len(precise) > 1 else "unresolved"
        )
        lookup_status = (
            "complete" if len(precise) == 1 and precise <= completed_cpes else
            "pending" if len(precise) == 1 else "unavailable"
        )
        version_discrepancies = []
        product_token = (item["product"] or "").split(" ", 1)[0]
        probed_version = re.search(r"\d+(?:\.\d+)+", item["version"] or "")
        if product_token and probed_version:
            pattern = re.compile(rf"\b{re.escape(product_token)}\s+(\d+(?:\.\d+)+)", re.I)
            for response in item["nse_responses"]:
                for reported_version in pattern.findall(response):
                    if reported_version != probed_version.group(0):
                        version_discrepancies.append(reported_version)
        services.append({
            "id": item["id"], "port": item["port"], "protocol": item["protocol"],
            "software": item["software"], "identity_status": identity_status,
            "exact_cpes": sorted(precise), "lookup_status": lookup_status,
            "candidate_ids": sorted(candidates.get(item["id"], set())),
            "nse_responses": sorted(item["nse_responses"]),
            "nse_version_discrepancies": sorted(set(version_discrepancies)),
        })
    host_nse = set()
    for scan in document["scans"]:
        for host in scan.get("hosts", []):
            if host.get("address") != address:
                continue
            host_nse.update(
                evidence["summary"] for evidence in host.get("evidence", [])
                if isinstance(evidence, dict) and evidence.get("source") == "nmap-nse"
                and isinstance(evidence.get("summary"), str)
            )
    unresolved = [f"{s['port']}/{s['protocol']}" for s in services
                  if s["identity_status"] == "unresolved"]
    conflicting = [f"{s['port']}/{s['protocol']}" for s in services
                   if s["identity_status"] == "conflicting"]
    pending = [f"{s['port']}/{s['protocol']}" for s in services
               if s["lookup_status"] == "pending"]
    candidate_ids = sorted({cve for service in services for cve in service["candidate_ids"]})
    candidate_ports = [f"{s['port']}/{s['protocol']}" for s in services if s["candidate_ids"]]
    disputed = [s for s in services if s["nse_version_discrepancies"]]
    steps = []
    if not document["target_observed"]:
        steps.append("Confirm the IPv6 address and scan vantage; the target was not observed.")
    elif not services:
        steps.append("Host responded, but no open service was recorded; check intended services and tested ports.")
    for service in disputed:
        endpoint = f"{service['port']}/{service['protocol']}"
        steps.append(
            f"Reconcile version claims on {endpoint}: service probe says "
            f"{service['software']}; NSE response says "
            f"{', '.join(service['nse_version_discrepancies'])}."
        )
    if unresolved:
        steps.append("Confirm exact software versions on " + ", ".join(unresolved)
                     + " with protocol-specific queries or trusted inventory.")
    if conflicting:
        steps.append("Reconcile conflicting exact identities on " + ", ".join(conflicting) + ".")
    if pending:
        steps.append("Complete version-specific CVE lookups for " + ", ".join(pending) + ".")
    if candidate_ids:
        steps.append(
            f"Review local applicability, enabled features, and patch status for "
            f"{len(candidate_ids)} candidate CVE(s) on {', '.join(candidate_ports)}."
        )
    steps.append("Record the IPv6 addresses, TCP/UDP ports, and vantage actually tested; "
                 "service observations do not establish full coverage.")
    return {
        "target": address, "scope": document["scope"]["name"],
        "vantage": document["source"], "target_observed": document["target_observed"],
        "host_information": information, "services": services,
        "candidate_cve_ids": candidate_ids, "host_nse_responses": sorted(host_nse),
        "next_steps": steps,
        "lookup_complete_for_observed_services": bool(services) and
        information["services_with_completed_cve_check"] == len(services),
        "meaning": "Information completeness for observed open services, not a safety or risk grade.",
    }


def render_host_information_report(report: dict[str, Any]) -> str:
    """Present one IPv6 host's information gaps and follow-ups in the terminal."""
    information = report["host_information"]
    score = information["score"]
    grade = information["grade"] + (f" ({score:.1f}/100)" if score is not None else "")
    services = report["services"]
    lines = [
        "HexPath IPv6 Host Information", "=============================",
        f"Target: [{report['target']}]", f"Scope: {report['scope']}",
        f"Scan vantage: {report['vantage']}",
        f"Host observed: {'yes' if report['target_observed'] else 'no'}",
        f"Information grade: {grade} — evidence completeness, not a safety rating",
        f"  Exact CPEs: {information['services_with_exact_cpe']}/{len(services)} open services; "
        f"completed CVE checks: {information['services_with_completed_cve_check']}/{len(services)}",
    ]
    for guess in information.get("os_guesses", [])[:1]:
        accuracy = guess.get("nmap_accuracy")
        lines.append(f"OS fingerprint guess: {guess.get('name') or 'unknown'}"
                     + (f" ({accuracy}% Nmap accuracy)" if accuracy is not None else "")
                     + "; kernel and patch level unverified")
    lines.extend(["", "OPEN SERVICE EVIDENCE"])
    if services:
        lines.append("PORT       SOFTWARE / VERSION                       CPE         CVE CHECK   CANDIDATES")
        for item in services:
            endpoint = f"{item['port']}/{item['protocol']}"
            lines.append(
                f"{endpoint:<10} {item['software'][:40]:<40} "
                f"{item['identity_status']:<11} {item['lookup_status']:<11} "
                f"{len(item['candidate_ids'])}"
            )
    else:
        lines.append("No open service in the supplied observations; this is not a clean result.")
    nse = [(f"{item['port']}/{item['protocol']}", summary)
           for item in services for summary in item["nse_responses"]]
    nse.extend(("host", summary) for summary in report["host_nse_responses"])
    disputed = [item for item in services if item["nse_version_discrepancies"]]
    if disputed:
        lines.extend(["", "VERSION CLAIMS TO RECONCILE"])
        for item in disputed:
            lines.append(
                f"  {item['port']}/{item['protocol']}: service probe {item['software']} "
                f"vs NSE {', '.join(item['nse_version_discrepancies'])}; "
                "the grade does not resolve this discrepancy."
            )
    if nse:
        lines.extend(["", "NMAP SCRIPT RESPONSES (reported, not independently verified)"])
        for endpoint, summary in nse:
            lines.append(f"  {endpoint}: {summary[:350]}{'…' if len(summary) > 350 else ''}")
    lines.extend(["", "CVE AND COVERAGE STATUS"])
    lines.append(f"  {len(report['candidate_cve_ids'])} NVD CPE candidate(s); local applicability unverified.")
    if len(services) != information["services_with_completed_cve_check"]:
        lines.append("  Unchecked services remain; zero candidates on them does not mean clean.")
    lines.extend(["", "NEXT INFORMATION TO COLLECT"])
    for index, step in enumerate(report["next_steps"], 1):
        lines.append(f"  {index}. {step}")
    return "\n".join("".join(c if c.isprintable() else "?" for c in line) for line in lines)

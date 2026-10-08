"""Evidence-aware directed attack graphs and shortest-path analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
import heapq
import json
import math
from typing import Any

from hexpath.models import Confidence, Evidence, EvidenceLevel


ENTRY_NODE_ID = "entry:scanner"


class GraphError(ValueError):
    """Raised when graph input or structure is invalid."""


class NodeKind(StrEnum):
    """Kinds of entities represented in an attack graph."""

    ENTRY = "entry"
    HOST = "host"
    SERVICE = "service"


def _required_text(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GraphError(f"{field_name} must be a non-empty string")
    return value.strip()


@dataclass(frozen=True, slots=True)
class GraphNode:
    """One entry point, host, or service in a directed attack graph."""

    node_id: str
    kind: NodeKind
    label: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "node_id", _required_text(self.node_id, "node_id"))
        object.__setattr__(self, "label", _required_text(self.label, "label"))
        try:
            kind = NodeKind(self.kind)
        except (TypeError, ValueError) as error:
            raise GraphError(f"invalid node kind: {self.kind!r}") from error
        object.__setattr__(self, "kind", kind)
        if not isinstance(self.metadata, dict):
            raise GraphError("node metadata must be an object")
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id,
            "kind": self.kind.value,
            "label": self.label,
            "metadata": self.metadata,
        }


@dataclass(frozen=True, slots=True)
class GraphEdge:
    """One evidence-backed directed transition with a positive cost."""

    edge_id: str
    source: str
    target: str
    relationship: str
    weight: float
    description: str
    evidence: tuple[Evidence, ...]
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for field_name in ("edge_id", "source", "target", "relationship", "description"):
            object.__setattr__(
                self,
                field_name,
                _required_text(getattr(self, field_name), field_name),
            )
        if isinstance(self.weight, bool) or not isinstance(self.weight, (int, float)):
            raise GraphError("edge weight must be a number")
        weight = float(self.weight)
        if not math.isfinite(weight) or weight <= 0:
            raise GraphError("edge weight must be finite and greater than zero")
        object.__setattr__(self, "weight", weight)
        evidence = tuple(self.evidence)
        if not evidence:
            raise GraphError("graph edges must include supporting evidence")
        object.__setattr__(self, "evidence", evidence)
        if not isinstance(self.metadata, dict):
            raise GraphError("edge metadata must be an object")
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.edge_id,
            "source": self.source,
            "target": self.target,
            "relationship": self.relationship,
            "weight": self.weight,
            "description": self.description,
            "evidence": [item.to_dict() for item in self.evidence],
            "metadata": self.metadata,
        }


@dataclass(frozen=True, slots=True)
class ShortestPath:
    """The lowest-cost directed path returned by Dijkstra's algorithm."""

    nodes: tuple[str, ...]
    edges: tuple[GraphEdge, ...]
    total_weight: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": list(self.nodes),
            "edges": [edge.to_dict() for edge in self.edges],
            "total_weight": self.total_weight,
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


@dataclass(frozen=True, slots=True)
class AttackGraph:
    """A validated directed graph with evidence-backed weighted edges."""

    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]

    def __post_init__(self) -> None:
        nodes = tuple(self.nodes)
        edges = tuple(self.edges)
        object.__setattr__(self, "nodes", nodes)
        object.__setattr__(self, "edges", edges)

        node_ids = tuple(node.node_id for node in nodes)
        edge_ids = tuple(edge.edge_id for edge in edges)
        if len(node_ids) != len(set(node_ids)):
            raise GraphError("graph contains duplicate node identifiers")
        if len(edge_ids) != len(set(edge_ids)):
            raise GraphError("graph contains duplicate edge identifiers")
        node_id_set = set(node_ids)
        for edge in edges:
            if edge.source not in node_id_set:
                raise GraphError(f"edge {edge.edge_id!r} has unknown source {edge.source!r}")
            if edge.target not in node_id_set:
                raise GraphError(f"edge {edge.edge_id!r} has unknown target {edge.target!r}")

    def shortest_path(self, source: str, target: str) -> ShortestPath | None:
        """Return the minimum-cost directed path using Dijkstra's algorithm."""
        node_ids = {node.node_id for node in self.nodes}
        if source not in node_ids:
            raise GraphError(f"unknown source node {source!r}")
        if target not in node_ids:
            raise GraphError(f"unknown target node {target!r}")
        if source == target:
            return ShortestPath(nodes=(source,), edges=(), total_weight=0.0)

        adjacency: dict[str, list[GraphEdge]] = {node_id: [] for node_id in node_ids}
        for edge in self.edges:
            adjacency[edge.source].append(edge)

        distances = {source: 0.0}
        previous: dict[str, GraphEdge] = {}
        queue: list[tuple[float, str]] = [(0.0, source)]
        while queue:
            distance, node_id = heapq.heappop(queue)
            if distance != distances.get(node_id):
                continue
            if node_id == target:
                break
            for edge in adjacency[node_id]:
                candidate = distance + edge.weight
                if candidate < distances.get(edge.target, math.inf):
                    distances[edge.target] = candidate
                    previous[edge.target] = edge
                    heapq.heappush(queue, (candidate, edge.target))

        if target not in distances:
            return None

        path_edges: list[GraphEdge] = []
        current = target
        while current != source:
            edge = previous[current]
            path_edges.append(edge)
            current = edge.source
        path_edges.reverse()
        path_nodes = (source, *(edge.target for edge in path_edges))
        return ShortestPath(
            nodes=path_nodes,
            edges=tuple(path_edges),
            total_weight=round(distances[target], 4),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_dict(cls, document: Any) -> "AttackGraph":
        if not isinstance(document, dict):
            raise GraphError("graph document must be an object")
        raw_nodes = document.get("nodes")
        raw_edges = document.get("edges")
        if not isinstance(raw_nodes, list) or not isinstance(raw_edges, list):
            raise GraphError("graph document must contain node and edge lists")
        nodes = tuple(_node_from_dict(item) for item in raw_nodes)
        edges = tuple(_edge_from_dict(item) for item in raw_edges)
        return cls(nodes=nodes, edges=edges)

    @classmethod
    def from_json(cls, value: str) -> "AttackGraph":
        try:
            document = json.loads(value)
        except json.JSONDecodeError as error:
            raise GraphError(f"invalid graph JSON: {error}") from error
        return cls.from_dict(document)


def vulnerability_cost(
    cvss_score: float | None,
    confidence: Confidence | str,
) -> float:
    """Convert severity and confidence into a positive Dijkstra edge cost."""
    try:
        confidence_value = Confidence(confidence)
    except (TypeError, ValueError) as error:
        raise GraphError(f"invalid vulnerability confidence: {confidence!r}") from error
    if cvss_score is None:
        score = 5.0
    elif isinstance(cvss_score, bool) or not isinstance(cvss_score, (int, float)):
        raise GraphError("CVSS score must be a number or null")
    else:
        score = float(cvss_score)
        if not 0.0 <= score <= 10.0:
            raise GraphError("CVSS score must be between 0.0 and 10.0")

    confidence_penalty = {
        Confidence.HIGH: 0.0,
        Confidence.MEDIUM: 1.5,
        Confidence.LOW: 3.0,
    }[confidence_value]
    return round(11.0 - score + confidence_penalty, 2)


def build_attack_graph(
    scan_document: Any,
    cve_document: Any,
    *,
    entry_id: str = ENTRY_NODE_ID,
) -> AttackGraph:
    """Build an attack graph from one or more vantage-aware scan documents."""
    if isinstance(scan_document, dict):
        scan_documents = (scan_document,)
    elif isinstance(scan_document, (list, tuple)) and scan_document:
        scan_documents = tuple(scan_document)
    else:
        raise GraphError("at least one scan document object is required")
    if not isinstance(cve_document, dict):
        raise GraphError("CVE document must be an object")
    raw_vulnerabilities = cve_document.get("vulnerabilities")
    raw_matches = cve_document.get("matches")
    if not isinstance(raw_vulnerabilities, list) or not isinstance(raw_matches, list):
        raise GraphError("CVE document must contain vulnerability and match lists")

    entry_id = _required_text(entry_id, "entry_id")
    nodes: list[GraphNode] = [
        GraphNode(
            node_id=entry_id,
            kind=NodeKind.ENTRY,
            label="Scanner entry point",
            metadata={"origin": "nmap-scan"},
        )
    ]
    edges: list[GraphEdge] = []
    hosts: dict[str, dict[str, Any]] = {}
    services: dict[str, dict[str, Any]] = {}
    service_hosts: dict[str, str] = {}
    observations: dict[tuple[str, str], dict[str, Any]] = {}
    declared_vantages: set[str] = set()

    for document in scan_documents:
        if not isinstance(document, dict):
            raise GraphError("scan document must be an object")
        raw_hosts = document.get("hosts")
        raw_services = document.get("services")
        if not isinstance(raw_hosts, list) or not isinstance(raw_services, list):
            raise GraphError("scan document must contain host and service lists")

        raw_vantage = _required_text(
            document.get("vantage", ENTRY_NODE_ID),
            "scan vantage",
        )
        vantage = entry_id if raw_vantage == ENTRY_NODE_ID else raw_vantage
        if vantage != entry_id and not vantage.startswith("host:"):
            raise GraphError(
                "scan vantage must be entry:scanner or a host node identifier"
            )
        declared_vantages.add(vantage)

        seen_hosts: set[str] = set()
        for raw_host in raw_hosts:
            host = _required_object(raw_host, "host")
            host_id = _document_id(host, "host")
            if host_id in seen_hosts:
                raise GraphError(f"scan contains duplicate host {host_id!r}")
            seen_hosts.add(host_id)
            existing_host = hosts.get(host_id)
            if existing_host is not None and existing_host.get("address") != host.get(
                "address"
            ):
                raise GraphError(f"scan documents disagree about host {host_id!r}")
            hosts.setdefault(host_id, host)

        seen_services: set[str] = set()
        for raw_service in raw_services:
            service = _required_object(raw_service, "service")
            service_id = _document_id(service, "service")
            if service_id in seen_services:
                raise GraphError(f"scan contains duplicate service {service_id!r}")
            seen_services.add(service_id)
            host_address = _required_text(service.get("host"), "service host")
            host_id = f"host:{host_address}"
            if service_id in service_hosts and service_hosts[service_id] != host_id:
                raise GraphError(
                    f"scan documents disagree about service {service_id!r}"
                )
            services.setdefault(service_id, service)
            service_hosts.setdefault(service_id, host_id)

            state = service.get("state")
            evidence = _evidence_list(service.get("evidence", []))
            if not evidence:
                evidence = (
                    Evidence(
                        source="hexpath",
                        summary=(
                            f"Service {service_id} was included in the normalized scan"
                        ),
                        level=EvidenceLevel.INFERRED,
                    ),
                )
            key = (vantage, service_id)
            observation = observations.setdefault(
                key,
                {
                    "weight": 1.0 if state == "open" else 3.0,
                    "states": [],
                    "evidence": [],
                },
            )
            observation["weight"] = min(
                observation["weight"],
                1.0 if state == "open" else 3.0,
            )
            if state not in observation["states"]:
                observation["states"].append(state)
            for item in evidence:
                if item not in observation["evidence"]:
                    observation["evidence"].append(item)

    host_ids = set(hosts)
    for vantage in declared_vantages:
        if vantage != entry_id and vantage not in host_ids:
            raise GraphError(f"scan vantage refers to unknown host {vantage!r}")

    for host_id, host in hosts.items():
        nodes.append(
            GraphNode(
                node_id=host_id,
                kind=NodeKind.HOST,
                label=str(host.get("address", host_id)),
                metadata={
                    "address": host.get("address"),
                    "hostnames": host.get("hostnames", []),
                },
            )
        )

    for service_id, service in services.items():
        host_id = service_hosts[service_id]
        if host_id not in host_ids:
            raise GraphError(f"service {service_id!r} refers to unknown host {host_id!r}")
        product = service.get("product") or service.get("name") or "unknown service"
        version = f" {service['version']}" if service.get("version") else ""
        nodes.append(
            GraphNode(
                node_id=service_id,
                kind=NodeKind.SERVICE,
                label=f"{product}{version}",
                metadata={
                    key: service.get(key)
                    for key in (
                        "host",
                        "port",
                        "protocol",
                        "state",
                        "name",
                        "product",
                        "version",
                        "cpes",
                    )
                },
            )
        )

    for (vantage, service_id), observation in observations.items():
        edges.append(
            GraphEdge(
                edge_id=f"edge:reachability:{vantage}:{service_id}",
                source=vantage,
                target=service_id,
                relationship="observed_reachability",
                weight=observation["weight"],
                description=f"{vantage} reached {service_id}",
                evidence=tuple(observation["evidence"]),
                metadata={"service_states": observation["states"]},
            )
        )

    vulnerabilities: dict[str, dict[str, Any]] = {}
    for raw_vulnerability in raw_vulnerabilities:
        vulnerability = _required_object(raw_vulnerability, "vulnerability")
        cve_id = _document_id(vulnerability, "vulnerability")
        if cve_id in vulnerabilities:
            raise GraphError(f"CVE document contains duplicate vulnerability {cve_id!r}")
        vulnerabilities[cve_id] = vulnerability

    seen_matches: set[tuple[str, str]] = set()
    for raw_match in raw_matches:
        match = _required_object(raw_match, "vulnerability match")
        service_id = _required_text(match.get("service_id"), "match service_id")
        cve_id = _required_text(match.get("cve_id"), "match cve_id")
        key = (service_id, cve_id)
        if key in seen_matches:
            raise GraphError(f"CVE document contains duplicate match {key!r}")
        seen_matches.add(key)
        if service_id not in services:
            raise GraphError(f"vulnerability match refers to unknown service {service_id!r}")
        if cve_id not in vulnerabilities:
            raise GraphError(f"vulnerability match refers to unknown CVE {cve_id!r}")
        try:
            confidence = Confidence(match.get("confidence"))
        except (TypeError, ValueError) as error:
            raise GraphError(
                f"vulnerability match {key!r} has invalid confidence"
            ) from error
        vulnerability = vulnerabilities[cve_id]
        score = vulnerability.get("cvss_score")
        evidence = _evidence_list(match.get("evidence"))
        if not evidence:
            raise GraphError(f"vulnerability match {key!r} has no supporting evidence")
        reason = _required_text(match.get("reason"), "match reason")
        edges.append(
            GraphEdge(
                edge_id=f"edge:exploit:{service_id}:{cve_id}",
                source=service_id,
                target=service_hosts[service_id],
                relationship="candidate_exploit",
                weight=vulnerability_cost(score, confidence),
                description=f"{cve_id} may provide access to {service_hosts[service_id]}",
                evidence=evidence,
                metadata={
                    "cve_id": cve_id,
                    "cvss_score": score,
                    "confidence": confidence.value,
                    "reason": reason,
                },
            )
        )

    return AttackGraph(nodes=tuple(nodes), edges=tuple(edges))


def render_attack_graph_ascii(graph: AttackGraph) -> str:
    """Render a directed graph as a branching ASCII diagram."""
    nodes = {node.node_id: node for node in graph.nodes}
    adjacency: dict[str, list[GraphEdge]] = {node_id: [] for node_id in nodes}
    incoming = {node_id: 0 for node_id in nodes}
    for edge in graph.edges:
        adjacency[edge.source].append(edge)
        incoming[edge.target] += 1
    for edges in adjacency.values():
        edges.sort(key=lambda edge: (edge.weight, edge.target, edge.edge_id))

    roots = [node_id for node_id, count in incoming.items() if count == 0]
    roots.sort(key=lambda node_id: (node_id != ENTRY_NODE_ID, node_id))
    lines = ["HexPath Attack Graph", "===================="]
    expanded: set[str] = set()

    def walk(node_id: str, prefix: str, ancestry: frozenset[str]) -> None:
        expanded.add(node_id)
        outgoing = adjacency[node_id]
        for index, edge in enumerate(outgoing):
            is_last = index == len(outgoing) - 1
            child_prefix = prefix + ("    " if is_last else "|   ")
            target_text = _ascii_node(nodes[edge.target])
            marker = ""
            if edge.target in ancestry:
                marker = " (cycle)"
            elif edge.target in expanded:
                marker = " (reference)"
            lines.append(
                f"{prefix}+-- {_ascii_edge(edge)} --> {target_text}{marker}"
            )
            if not marker:
                walk(edge.target, child_prefix, ancestry | {edge.target})

    for root in roots:
        if root in expanded:
            continue
        if len(lines) > 2:
            lines.append("")
        lines.append(_ascii_node(nodes[root]))
        walk(root, "", frozenset({root}))

    for node_id in sorted(nodes):
        if node_id in expanded:
            continue
        if len(lines) > 2:
            lines.append("")
        lines.append(_ascii_node(nodes[node_id]))
        walk(node_id, "", frozenset({node_id}))

    lines.append("")
    lines.append(f"Nodes: {len(graph.nodes)}  Edges: {len(graph.edges)}")
    return "\n".join(lines)


def render_path_ascii(graph: AttackGraph, path: ShortestPath) -> str:
    """Render one selected path as an ASCII command-line diagram."""
    nodes = {node.node_id: node for node in graph.nodes}
    lines = ["HexPath Lowest-Cost Path", "========================"]
    lines.append(_ascii_node(nodes[path.nodes[0]]))
    for edge in path.edges:
        lines.append("  |")
        lines.append(f"  +-- {_ascii_edge(edge)} -->")
        lines.append(f"      {_ascii_node(nodes[edge.target])}")
    lines.append("")
    lines.append(f"Total cost: {path.total_weight:.2f}")
    return "\n".join(lines)


def _ascii_node(node: GraphNode) -> str:
    return (
        f"[{node.kind.value.upper()}] {_terminal_text(node.label)} "
        f"<{_terminal_text(node.node_id)}>"
    )


def _ascii_edge(edge: GraphEdge) -> str:
    details = [_terminal_text(edge.relationship), f"cost={edge.weight:.2f}"]
    cve_id = edge.metadata.get("cve_id")
    if isinstance(cve_id, str) and cve_id:
        details.append(_terminal_text(cve_id))
    confidence = edge.metadata.get("confidence")
    if isinstance(confidence, str) and confidence:
        details.append(f"confidence={_terminal_text(confidence)}")
    return "[" + ", ".join(details) + "]"


def _terminal_text(value: str) -> str:
    return "".join(character if character.isprintable() else "?" for character in value)


def _required_object(value: Any, record_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GraphError(f"{record_name} must be an object")
    return value


def _document_id(document: dict[str, Any], record_name: str) -> str:
    return _required_text(document.get("id"), f"{record_name} id")


def _evidence_list(value: Any) -> tuple[Evidence, ...]:
    if not isinstance(value, list):
        raise GraphError("evidence must be a list")
    return tuple(_evidence_from_dict(item) for item in value)


def _evidence_from_dict(value: Any) -> Evidence:
    document = _required_object(value, "evidence")
    raw_time = _required_text(document.get("collected_at"), "evidence collected_at")
    try:
        collected_at = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
    except ValueError as error:
        raise GraphError(f"invalid evidence timestamp: {raw_time!r}") from error
    try:
        return Evidence(
            source=document.get("source"),
            summary=document.get("summary"),
            level=document.get("level"),
            collected_at=collected_at,
            reference=document.get("reference"),
        )
    except ValueError as error:
        raise GraphError(f"invalid evidence record: {error}") from error


def _node_from_dict(value: Any) -> GraphNode:
    document = _required_object(value, "node")
    return GraphNode(
        node_id=document.get("id"),
        kind=document.get("kind"),
        label=document.get("label"),
        metadata=document.get("metadata", {}),
    )


def _edge_from_dict(value: Any) -> GraphEdge:
    document = _required_object(value, "edge")
    return GraphEdge(
        edge_id=document.get("id"),
        source=document.get("source"),
        target=document.get("target"),
        relationship=document.get("relationship"),
        weight=document.get("weight"),
        description=document.get("description"),
        evidence=_evidence_list(document.get("evidence")),
        metadata=document.get("metadata", {}),
    )

"""Evidence-aware directed attack graphs and shortest-path analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
import heapq
from ipaddress import IPv6Address
import json
import math
import textwrap
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
        return self._shortest_path(source, target)

    def resolve_node(self, selector: str) -> str:
        """Resolve an exact node ID or an equivalent IPv6 host address."""
        if any(node.node_id == selector for node in self.nodes):
            return selector
        try:
            address = IPv6Address(selector.removeprefix("host:"))
        except ValueError:
            raise GraphError(
                f"unknown node {selector!r}; use 'hexpath graph targets' to list hosts"
            ) from None
        for node in self.nodes:
            if node.kind != NodeKind.HOST:
                continue
            try:
                node_address = IPv6Address(node.node_id.removeprefix("host:"))
            except ValueError:
                continue
            if node_address == address:
                return node.node_id
        raise GraphError(
            f"unknown host {selector!r}; use 'hexpath graph targets' to list hosts"
        )

    def shortest_paths(
        self, source: str, target: str, *, limit: int = 3,
    ) -> tuple[ShortestPath, ...]:
        """Return up to 20 cheapest loop-free paths using Yen's algorithm.

        Edge identities distinguish alternative CVEs on the same service.
        Spur searches use Dijkstra; paths never revisit a node.
        """
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 20:
            raise GraphError("path limit must be an integer between 1 and 20")
        first = self.shortest_path(source, target)
        if first is None:
            return ()
        selected = [first]
        candidates: list[tuple[float, tuple[str, ...], ShortestPath]] = []
        seen = {tuple(edge.edge_id for edge in first.edges)}
        while len(selected) < limit:
            previous = selected[-1]
            for index, spur_node in enumerate(previous.nodes[:-1]):
                root_edges = previous.edges[:index]
                root_ids = tuple(edge.edge_id for edge in root_edges)
                excluded_edges = {
                    path.edges[index].edge_id
                    for path in selected
                    if len(path.edges) > index
                    and tuple(edge.edge_id for edge in path.edges[:index]) == root_ids
                }
                spur = self._shortest_path(
                    spur_node, target,
                    excluded_nodes=frozenset(previous.nodes[:index]),
                    excluded_edges=frozenset(excluded_edges),
                )
                if spur is None:
                    continue
                edges = root_edges + spur.edges
                identity = tuple(edge.edge_id for edge in edges)
                if identity in seen:
                    continue
                seen.add(identity)
                weight = math.fsum(edge.weight for edge in edges)
                path = ShortestPath(
                    nodes=previous.nodes[:index] + spur.nodes,
                    edges=edges,
                    total_weight=round(weight, 4),
                )
                heapq.heappush(candidates, (weight, identity, path))
            if not candidates:
                break
            selected.append(heapq.heappop(candidates)[2])
        return tuple(selected)

    def _shortest_path(
        self, source: str, target: str, *,
        excluded_nodes: frozenset[str] = frozenset(),
        excluded_edges: frozenset[str] = frozenset(),
    ) -> ShortestPath | None:
        node_ids = {node.node_id for node in self.nodes}
        if source not in node_ids:
            raise GraphError(f"unknown source node {source!r}")
        if target not in node_ids:
            raise GraphError(f"unknown target node {target!r}")
        if source == target:
            return ShortestPath(nodes=(source,), edges=(), total_weight=0.0)

        adjacency: dict[str, list[GraphEdge]] = {node_id: [] for node_id in node_ids}
        for edge in self.edges:
            if (
                edge.edge_id not in excluded_edges
                and edge.source not in excluded_nodes
                and edge.target not in excluded_nodes
            ):
                adjacency[edge.source].append(edge)
        for outgoing in adjacency.values():
            outgoing.sort(key=lambda edge: edge.edge_id)

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


@dataclass(frozen=True, slots=True)
class _TopologyTree:
    labels: tuple[str, ...]
    children: tuple["_TopologyTree", ...] = ()


@dataclass(frozen=True, slots=True)
class _RenderedTree:
    lines: tuple[str, ...]
    width: int
    root_center: int


def render_topology_ascii(scan_document: Any, cve_document: Any) -> str:
    """Render the complete topology as a boxed top-down ASCII tree."""
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

    vulnerabilities: dict[str, dict[str, Any]] = {}
    for raw_vulnerability in raw_vulnerabilities:
        vulnerability = _required_object(raw_vulnerability, "vulnerability")
        cve_id = _document_id(vulnerability, "vulnerability")
        vulnerabilities[cve_id] = vulnerability

    service_matches: dict[str, list[dict[str, Any]]] = {}
    for raw_match in raw_matches:
        match = _required_object(raw_match, "vulnerability match")
        service_id = _required_text(match.get("service_id"), "match service_id")
        cve_id = _required_text(match.get("cve_id"), "match cve_id")
        if cve_id not in vulnerabilities:
            raise GraphError(f"vulnerability match refers to unknown CVE {cve_id!r}")
        service_matches.setdefault(service_id, []).append(match)

    lines = ["HexPath Network Topology", "========================"]
    for document_index, document in enumerate(scan_documents):
        if not isinstance(document, dict):
            raise GraphError("scan document must be an object")
        raw_hosts = document.get("hosts")
        raw_services = document.get("services")
        if not isinstance(raw_hosts, list) or not isinstance(raw_services, list):
            raise GraphError("scan document must contain host and service lists")
        vantage = _required_text(
            document.get("vantage", ENTRY_NODE_ID),
            "scan vantage",
        )
        hosts: list[tuple[str, dict[str, Any]]] = []
        host_ids: set[str] = set()
        for raw_host in raw_hosts:
            host = _required_object(raw_host, "host")
            host_id = _document_id(host, "host")
            if host_id in host_ids:
                raise GraphError(f"scan contains duplicate host {host_id!r}")
            host_ids.add(host_id)
            hosts.append((host_id, host))

        services_by_host: dict[str, list[tuple[str, dict[str, Any]]]] = {
            host_id: [] for host_id in host_ids
        }
        seen_services: set[str] = set()
        for raw_service in raw_services:
            service = _required_object(raw_service, "service")
            service_id = _document_id(service, "service")
            if service_id in seen_services:
                raise GraphError(f"scan contains duplicate service {service_id!r}")
            seen_services.add(service_id)
            host_address = _required_text(service.get("host"), "service host")
            host_id = f"host:{host_address}"
            if host_id not in host_ids:
                raise GraphError(f"service {service_id!r} refers to unknown host {host_id!r}")
            services_by_host[host_id].append((service_id, service))

        visible_hosts = [
            item
            for item in hosts
            if item[0] != vantage or services_by_host[item[0]]
        ]
        host_nodes: list[_TopologyTree] = []
        for host_id, host in visible_hosts:
            address = str(host.get("address", host_id))
            raw_hostnames = host.get("hostnames", [])
            hostnames = (
                ", ".join(str(name) for name in raw_hostnames)
                if isinstance(raw_hostnames, list)
                else ""
            )
            host_labels = ("HOST", address, *((hostnames,) if hostnames else ()))
            service_nodes: list[_TopologyTree] = []
            host_services = services_by_host[host_id]
            if not host_services:
                service_nodes.append(_TopologyTree(("NO SERVICES DISCOVERED",)))
            for service_id, service in host_services:
                protocol = str(service.get("protocol", "unknown"))
                port = str(service.get("port", "?"))
                state = str(service.get("state", "unknown")).upper()
                product = service.get("product") or service.get("name") or "unknown service"
                version = f" {service['version']}" if service.get("version") else ""
                finding_nodes: list[_TopologyTree] = []
                matches = service_matches.get(service_id, [])
                if not matches:
                    finding_nodes.append(_TopologyTree(("NO CVE CANDIDATES",)))
                for match in matches:
                    cve_id = _required_text(match.get("cve_id"), "match cve_id")
                    vulnerability = vulnerabilities[cve_id]
                    score = vulnerability.get("cvss_score")
                    score_text = "n/a" if score is None else str(score)
                    confidence = str(match.get("confidence", "unknown")).upper()
                    finding_nodes.append(
                        _TopologyTree(
                            (
                                cve_id,
                                f"CVSS {score_text} | {confidence}",
                            )
                        )
                    )
                service_nodes.append(
                    _TopologyTree(
                        (
                            f"SERVICE {protocol}/{port} {state}",
                            f"{product}{version}",
                        ),
                        tuple(finding_nodes),
                    )
                )
            host_nodes.append(_TopologyTree(host_labels, tuple(service_nodes)))

        if vantage == ENTRY_NODE_ID:
            root_labels = ("SERVER / SCANNER", ENTRY_NODE_ID)
        else:
            root_labels = ("SERVER / VANTAGE", vantage.removeprefix("host:"))
        if not host_nodes:
            host_nodes.append(_TopologyTree(("NO HOSTS DISCOVERED",)))
        rendered = _render_topology_tree(
            _TopologyTree(root_labels, tuple(host_nodes))
        )
        if document_index:
            lines.append("")
        lines.extend(line.rstrip() for line in rendered.lines)

    host_count = sum(
        len(document.get("hosts", []))
        for document in scan_documents
        if isinstance(document, dict)
    )
    service_count = sum(
        len(document.get("services", []))
        for document in scan_documents
        if isinstance(document, dict)
    )
    lines.append("")
    lines.append(
        f"Scans: {len(scan_documents)}  Hosts: {host_count}  "
        f"Services: {service_count}  CVE candidates: {len(raw_matches)}"
    )
    return "\n".join(lines)


def _render_topology_tree(tree: _TopologyTree) -> _RenderedTree:
    box_lines = _topology_box(tree.labels)
    box_width = len(box_lines[0])
    if not tree.children:
        return _RenderedTree(tuple(box_lines), box_width, box_width // 2)

    rendered_children = tuple(_render_topology_tree(child) for child in tree.children)
    if len(rendered_children) == 1:
        child = rendered_children[0]
        root_center = max(box_width // 2, child.root_center)
        box_left = root_center - box_width // 2
        child_left = root_center - child.root_center
        width = max(box_left + box_width, child_left + child.width)
        lines = [(" " * box_left + line).ljust(width) for line in box_lines]
        connector = [" "] * width
        connector[root_center] = "|"
        lines.append("".join(connector))
        lines.extend(
            (" " * child_left + line.ljust(child.width)).ljust(width)
            for line in child.lines
        )
        return _RenderedTree(tuple(lines), width, root_center)

    gap = 4
    children_width = sum(child.width for child in rendered_children) + gap * (
        len(rendered_children) - 1
    )
    width = max(box_width, children_width)
    box_left = (width - box_width) // 2
    child_left = (width - children_width) // 2
    root_center = box_left + box_width // 2

    lines = [
        (" " * box_left + line).ljust(width)
        for line in box_lines
    ]
    child_offsets: list[int] = []
    offset = child_left
    for child in rendered_children:
        child_offsets.append(offset)
        offset += child.width + gap
    child_centers = [
        offset + child.root_center
        for offset, child in zip(child_offsets, rendered_children, strict=True)
    ]

    upper = [" "] * width
    upper[root_center] = "|"
    lines.append("".join(upper))

    branch = [" "] * width
    left = min(root_center, *child_centers)
    right = max(root_center, *child_centers)
    for column in range(left, right + 1):
        branch[column] = "-"
    for column in (root_center, *child_centers):
        branch[column] = "+"
    lines.append("".join(branch))

    lower = [" "] * width
    for center in child_centers:
        lower[center] = "|"
    lines.append("".join(lower))

    child_height = max(len(child.lines) for child in rendered_children)
    for row_index in range(child_height):
        row = [" "] * width
        for offset, child in zip(child_offsets, rendered_children, strict=True):
            if row_index >= len(child.lines):
                continue
            child_line = child.lines[row_index].ljust(child.width)
            row[offset : offset + child.width] = child_line
        lines.append("".join(row))

    return _RenderedTree(tuple(lines), width, root_center)


def _topology_box(labels: tuple[str, ...]) -> list[str]:
    content: list[str] = []
    for label in labels:
        clean_label = _terminal_text(str(label))
        content.extend(
            textwrap.wrap(
                clean_label,
                width=30,
                break_long_words=True,
                break_on_hyphens=False,
            )
            or [""]
        )
    content_width = max(len(line) for line in content)
    border = "+" + "-" * (content_width + 2) + "+"
    return [
        border,
        *(f"| {line.center(content_width)} |" for line in content),
        border,
    ]


def render_server_inventory_ascii(document: Any) -> str:
    """Render complete server inventory as one tree rooted at the server."""
    if not isinstance(document, dict):
        raise GraphError("server inventory must be an object")
    server = _required_text(document.get("server"), "inventory server")
    system = document.get("system")
    if not isinstance(system, dict):
        raise GraphError("server inventory must contain system information")

    interfaces = _inventory_list(document, "interfaces")
    services = _inventory_list(document, "listening_services")
    libvirt_networks = _inventory_list(document, "networks")
    vms = _inventory_list(document, "vms")
    container_networks = _inventory_list(document, "container_networks")
    containers = _inventory_list(document, "containers")

    interface_nodes = tuple(
        _TopologyTree(
            (
                f"INTERFACE {item.get('name', 'unknown')}",
                f"STATE {item.get('state', 'unknown')}",
                *((f"MASTER {item['master']}",) if item.get("master") else ()),
                *(
                    f"{address.get('family', '?')} "
                    f"{address.get('address', '?')}/{address.get('prefixlen', '?')}"
                    for address in item.get("addresses", [])
                    if isinstance(address, dict)
                ),
            )
        )
        for item in interfaces
    )

    service_nodes = tuple(
        _TopologyTree(
            (
                f"{str(item.get('protocol', '?')).upper()} {item.get('state', '?')}",
                str(item.get("local", "unknown endpoint")),
                *((str(item["process"]),) if item.get("process") else ()),
            )
        )
        for item in services
    )

    vm_by_network: dict[str, list[dict[str, Any]]] = {}
    unattached_vms: list[dict[str, Any]] = []
    for vm in vms:
        linked = False
        for interface in vm.get("interfaces", []):
            if not isinstance(interface, dict):
                continue
            network_name = interface.get("network")
            if isinstance(network_name, str) and network_name:
                vm_by_network.setdefault(network_name, []).append(vm)
                linked = True
        if not linked:
            unattached_vms.append(vm)
    libvirt_nodes: list[_TopologyTree] = []
    for network in libvirt_networks:
        name = str(network.get("name", "unknown"))
        vm_nodes = tuple(_vm_inventory_node(vm, name) for vm in vm_by_network.get(name, []))
        if not vm_nodes:
            vm_nodes = (_TopologyTree(("NO ATTACHED VMS",)),)
        libvirt_nodes.append(
            _TopologyTree(
                (
                    f"LIBVIRT NETWORK {name}",
                    "ACTIVE" if network.get("active") else "INACTIVE",
                    *((f"BRIDGE {network['bridge']}",) if network.get("bridge") else ()),
                ),
                vm_nodes,
            )
        )
    if unattached_vms:
        libvirt_nodes.append(
            _TopologyTree(
                ("UNATTACHED VMS",),
                tuple(_vm_inventory_node(vm, None) for vm in unattached_vms),
            )
        )
    containers_by_network: dict[str, list[dict[str, Any]]] = {}
    unattached_containers: list[dict[str, Any]] = []
    for container in containers:
        raw_networks = container.get("networks", [])
        network_names = [
            network.get("name")
            for network in raw_networks
            if isinstance(network, dict) and isinstance(network.get("name"), str)
        ]
        if not network_names:
            unattached_containers.append(container)
        for network_name in network_names:
            containers_by_network.setdefault(network_name, []).append(container)

    docker_nodes: list[_TopologyTree] = []
    for network in container_networks:
        name = str(network.get("name", "unknown"))
        container_nodes = tuple(
            _container_inventory_node(container, name)
            for container in containers_by_network.get(name, [])
        )
        if not container_nodes:
            container_nodes = (_TopologyTree(("NO ATTACHED CONTAINERS",)),)
        subnet_text = ", ".join(str(item) for item in network.get("subnets", []))
        docker_nodes.append(
            _TopologyTree(
                (
                    f"DOCKER NETWORK {name}",
                    f"DRIVER {network.get('driver', 'unknown')}",
                    *((subnet_text,) if subnet_text else ()),
                ),
                container_nodes,
            )
        )
    if unattached_containers:
        docker_nodes.append(
            _TopologyTree(
                ("UNATTACHED CONTAINERS",),
                tuple(
                    _container_inventory_node(container, None)
                    for container in unattached_containers
                ),
            )
        )

    root = _TopologyTree(
        (
            "SERVER",
            server,
            str(system.get("os", "unknown OS")),
            str(system.get("kernel", "unknown kernel")),
        ),
        (
            _TopologyTree(
                ("NETWORK INTERFACES", f"{len(interfaces)} TOTAL"),
                interface_nodes or (_TopologyTree(("NONE FOUND",)),),
            ),
            _TopologyTree(
                ("LISTENING SERVICES", f"{len(services)} TOTAL"),
                service_nodes or (_TopologyTree(("NONE FOUND",)),),
            ),
            _TopologyTree(
                (
                    "LIBVIRT",
                    f"{len(libvirt_networks)} NETWORKS",
                    f"{len(vms)} VMS",
                ),
                tuple(libvirt_nodes) or (_TopologyTree(("NONE FOUND",)),),
            ),
            _TopologyTree(
                (
                    "DOCKER",
                    f"{len(container_networks)} NETWORKS",
                    f"{len(containers)} CONTAINERS",
                ),
                tuple(docker_nodes) or (_TopologyTree(("NONE FOUND",)),),
            ),
        ),
    )
    lines = ["HexPath Full Server Topology", "============================"]
    lines.extend(_render_top_down_inventory_tree(root))
    return "\n".join(lines)


def _inventory_list(document: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = document.get(key)
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise GraphError(f"server inventory {key!r} must be a list of objects")
    return value


def _render_vertical_topology_tree(tree: _TopologyTree) -> list[str]:
    """Render a boxed tree without allowing large sibling sets to span columns."""
    root_box = _topology_box(tree.labels)
    lines = list(root_box)
    if not tree.children:
        return lines
    root_trunk = " " * (len(root_box[0]) // 2)
    lines.append(root_trunk + "|")
    _append_vertical_children(lines, tree.children, root_trunk)
    return lines


def _render_top_down_inventory_tree(tree: _TopologyTree) -> list[str]:
    """Place inventory categories across the screen beneath one server root."""
    root_box = _topology_box(tree.labels)
    if not tree.children:
        return root_box

    gap = 4
    child_blocks = [_render_vertical_topology_tree(child) for child in tree.children]
    child_widths = [max(len(line) for line in block) for block in child_blocks]
    children_width = sum(child_widths) + gap * (len(child_blocks) - 1)
    width = max(len(root_box[0]), children_width)
    root_left = (width - len(root_box[0])) // 2
    root_center = root_left + len(root_box[0]) // 2
    children_left = (width - children_width) // 2

    offsets: list[int] = []
    offset = children_left
    for child_width in child_widths:
        offsets.append(offset)
        offset += child_width + gap
    child_centers = [
        offset + len(block[0]) // 2
        for offset, block in zip(offsets, child_blocks, strict=True)
    ]

    lines = [(" " * root_left + line).rstrip() for line in root_box]
    trunk = [" "] * width
    trunk[root_center] = "|"
    lines.append("".join(trunk).rstrip())

    branch = [" "] * width
    left = min(root_center, *child_centers)
    right = max(root_center, *child_centers)
    for column in range(left, right + 1):
        branch[column] = "-"
    for column in (root_center, *child_centers):
        branch[column] = "+"
    lines.append("".join(branch).rstrip())

    stems = [" "] * width
    for center in child_centers:
        stems[center] = "|"
    lines.append("".join(stems).rstrip())

    height = max(len(block) for block in child_blocks)
    for row_index in range(height):
        row = [" "] * width
        for child_offset, child_width, block in zip(
            offsets,
            child_widths,
            child_blocks,
            strict=True,
        ):
            if row_index >= len(block):
                continue
            child_line = block[row_index].ljust(child_width)
            row[child_offset : child_offset + child_width] = child_line
        lines.append("".join(row).rstrip())
    return lines


def _append_vertical_children(
    lines: list[str],
    children: tuple[_TopologyTree, ...],
    prefix: str,
) -> None:
    for index, child in enumerate(children):
        is_last = index == len(children) - 1
        continuation = "    " if is_last else "|   "
        box = _topology_box(child.labels)
        lines.append(prefix + "+-- " + box[0])
        aligned_prefix = prefix + continuation
        lines.extend(aligned_prefix + line for line in box[1:])
        if child.children:
            child_trunk = aligned_prefix + " " * (len(box[0]) // 2)
            lines.append(child_trunk + "|")
            _append_vertical_children(lines, child.children, child_trunk)


def _vm_inventory_node(vm: dict[str, Any], network_name: str | None) -> _TopologyTree:
    interface_lines: list[str] = []
    for interface in vm.get("interfaces", []):
        if not isinstance(interface, dict):
            continue
        if network_name is not None and interface.get("network") != network_name:
            continue
        details = " / ".join(
            str(value)
            for value in (interface.get("model"), interface.get("mac"))
            if value
        )
        if details:
            interface_lines.append(details)
    memory = vm.get("memory")
    memory_unit = vm.get("memory_unit") or ""
    resource_text = f"{vm.get('vcpus', '?')} vCPU"
    if memory is not None:
        resource_text += f" | {memory} {memory_unit}".rstrip()
    return _TopologyTree(
        (
            f"VM {vm.get('name', 'unknown')}",
            str(vm.get("state", "unknown")).upper(),
            resource_text,
            *interface_lines,
        )
    )


def _container_inventory_node(
    container: dict[str, Any],
    network_name: str | None,
) -> _TopologyTree:
    address_lines: list[str] = []
    for network in container.get("networks", []):
        if not isinstance(network, dict):
            continue
        if network_name is not None and network.get("name") != network_name:
            continue
        for key in ("ipv4", "ipv6"):
            if network.get(key):
                address_lines.append(f"{key.upper()} {network[key]}")
    port_lines = [
        f"PORT {port.get('host') or 'internal'} -> {port.get('container')}"
        for port in container.get("ports", [])
        if isinstance(port, dict)
    ]
    return _TopologyTree(
        (
            f"CONTAINER {container.get('name', 'unknown')}",
            str(container.get("state", "unknown")).upper(),
            str(container.get("image", "unknown image")),
            *address_lines,
            *port_lines,
        )
    )


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


def render_host_targets_ascii(source: str, targets: list[dict[str, Any]]) -> str:
    """Show host selectors, names, and costs with safe terminal text."""
    lines = ["HexPath Host Targets", f"Source: {_terminal_text(source)}"]
    for item in targets:
        status = f"cost={item['cost']:.2f}" if item["reachable"] else "no modeled path"
        hostnames = item.get("hostnames", [])
        names = ", ".join(
            _terminal_text(name) for name in hostnames if isinstance(name, str)
        ) if isinstance(hostnames, list) else ""
        suffix = f" | {names}" if names else ""
        lines.append(f"  {_terminal_text(item['id'])} | {status}{suffix}")
    if not targets:
        lines.append("No host targets in this graph.")
    lines.append("Reachability here requires evidence-backed graph transitions.")
    return "\n".join(lines)


def path_comparison_document(
    source: str, target: str, paths: tuple[ShortestPath, ...], *, limit: int,
) -> dict[str, Any]:
    """Serialize ranked routes while retaining every edge's evidence."""
    best_cost = paths[0].total_weight if paths else 0.0
    return {
        "source": source,
        "target": target,
        "requested_paths": limit,
        "paths": [
            {
                **path.to_dict(),
                "rank": rank,
                "cost_delta": round(path.total_weight - best_cost, 4),
            }
            for rank, path in enumerate(paths, 1)
        ],
    }


def render_path_comparison_ascii(
    graph: AttackGraph, source: str, target: str, paths: tuple[ShortestPath, ...],
) -> str:
    """Compare route cost, candidate CVEs, confidence, and complete transitions."""
    lines = ["HexPath Path Comparison", "======================="]
    lines.append(f"Source: {_terminal_text(source)}")
    lines.append(f"Target: {_terminal_text(target)}")
    if not paths:
        lines.append("No evidence-backed directed path in this graph.")
        return "\n".join(lines)
    lines.extend(["", "Rank  Cost     Delta    Candidate findings"])
    for rank, path in enumerate(paths, 1):
        findings = "; ".join(
            f"{_terminal_text(str(edge.metadata['cve_id']))} "
            f"({_terminal_text(str(edge.metadata.get('confidence', 'unknown')))})"
            for edge in path.edges if edge.metadata.get("cve_id")
        ) or "No candidate CVE transitions"
        delta = path.total_weight - paths[0].total_weight
        lines.append(f"{rank:<4}  {path.total_weight:<7.2f}  +{delta:<7.2f} {findings}")
    for rank, path in enumerate(paths, 1):
        lines.append("")
        rendered = render_path_ascii(graph, path).splitlines()
        lines.extend([f"Route {rank}", *rendered[2:]])
    lines.extend(["", "Costs rank investigation routes; candidate CVEs do not confirm exploitation."])
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

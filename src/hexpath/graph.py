"""Evidence-aware directed attack graphs and shortest-path analysis."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
import heapq
from ipaddress import ip_address
import json
import math
from typing import Any

from hexpath.models import Confidence, Evidence, EvidenceLevel


ENTRY_NODE_ID = "entry:scanner"
# Generated HexPath edges are small (reachability costs are at most 3 and
# vulnerability costs are at most 14). Reject implausibly large imported
# weights before a path sum can overflow to infinity and make a reachable
# target appear unreachable.
MAX_EDGE_WEIGHT = 1_000_000.0
DEFAULT_RENDER_MAX_DEPTH = 100
NETWORK_SCORE_VERSION = "hexpath-network-v1"
NETWORK_SCORE_COMPONENT_MAXIMUMS = {
    "route_accessibility": 30.0,
    "path_depth": 15.0,
    "route_redundancy": 15.0,
    "blast_radius": 15.0,
    "exploit_evidence": 25.0,
}


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
        if weight > MAX_EDGE_WEIGHT:
            raise GraphError(f"edge weight must not exceed {MAX_EDGE_WEIGHT:g}")
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
    """The lowest-cost directed path returned by a pathfinding algorithm."""

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
class HostExposureScore:
    """A versioned network-exposure score for one reachable host path."""

    target: str
    network_score: float
    components: dict[str, float]
    observations: dict[str, Any]
    path: ShortestPath
    score_version: str = NETWORK_SCORE_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "network_score": self.network_score,
            "score_version": self.score_version,
            "components": dict(self.components),
            "component_maximums": dict(NETWORK_SCORE_COMPONENT_MAXIMUMS),
            "observations": dict(self.observations),
            "path": self.path.to_dict(),
        }


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

    def default_source(self) -> str:
        """Return the graph's only entry node, used when no source is given."""
        entries = [node.node_id for node in self.nodes if node.kind is NodeKind.ENTRY]
        if len(entries) == 1:
            return entries[0]
        if not entries:
            raise GraphError("graph has no entry node; pass a source node explicitly")
        raise GraphError(
            "graph has several entry nodes; pass a source node explicitly: "
            + ", ".join(sorted(entries))
        )

    def resolve_node(self, selector: str) -> str:
        """Resolve an exact node identifier or an equivalent IP host address."""
        if any(node.node_id == selector for node in self.nodes):
            return selector
        if not isinstance(selector, str):
            raise GraphError(f"unknown node {selector!r}")
        try:
            address = ip_address(selector.removeprefix("host:"))
        except ValueError:
            raise GraphError(
                f"unknown node {selector!r}; use 'hexpath graph targets' to list hosts"
            ) from None
        for node in self.nodes:
            if node.kind is not NodeKind.HOST:
                continue
            try:
                node_address = ip_address(node.node_id.removeprefix("host:"))
            except ValueError:
                continue
            if node_address == address:
                return node.node_id
        raise GraphError(
            f"unknown host {selector!r}; use 'hexpath graph targets' to list hosts"
        )

    def shortest_path(
        self, source: str, target: str, *, algorithm: str = "dijkstra"
    ) -> ShortestPath | None:
        """Return a minimum-cost path using Dijkstra (default) or A*."""
        if algorithm not in ("dijkstra", "astar"):
            raise GraphError(f"unknown path algorithm {algorithm!r}; use dijkstra or astar")
        node_ids = {node.node_id for node in self.nodes}
        if source not in node_ids:
            raise GraphError(f"unknown source node {source!r}")
        if target not in node_ids:
            raise GraphError(f"unknown target node {target!r}")
        if source == target:
            return ShortestPath(nodes=(source,), edges=(), total_weight=0.0)
        if algorithm == "astar":
            return self._astar_path(source, target)

        return self._dijkstra_path(source, target)

    def ranked_host_paths(self, source: str) -> tuple[ShortestPath, ...]:
        """Rank the least-cost Dijkstra path to every reachable host."""
        node_ids = {node.node_id for node in self.nodes}
        if source not in node_ids:
            raise GraphError(f"unknown source node {source!r}")

        distances, previous = self._dijkstra_search(source)
        paths = [
            _reconstruct_path(
                source,
                node.node_id,
                previous,
                distances[node.node_id],
            )
            for node in self.nodes
            if node.kind is NodeKind.HOST
            and node.node_id != source
            and node.node_id in distances
        ]
        paths.sort(
            key=lambda path: (
                path.total_weight,
                len(path.edges),
                path.nodes[-1],
            )
        )
        return tuple(paths)

    def ranked_host_exposures(self, source: str) -> tuple[HostExposureScore, ...]:
        """Score and rank every reachable host using the network-risk model."""
        topology = self._topology()
        scores = [
            self._score_host_path(source, path, topology=topology)
            for path in self.ranked_host_paths(source)
        ]
        scores.sort(
            key=lambda score: (
                -score.network_score,
                score.path.total_weight,
                len(score.path.edges),
                score.target,
            )
        )
        return tuple(scores)

    def host_exposure(
        self,
        source: str,
        target: str,
    ) -> HostExposureScore | None:
        """Score one host's selected Dijkstra path from a source node."""
        nodes = {node.node_id: node for node in self.nodes}
        if source not in nodes:
            raise GraphError(f"unknown source node {source!r}")
        if target not in nodes:
            raise GraphError(f"unknown target node {target!r}")
        if nodes[target].kind is not NodeKind.HOST:
            raise GraphError("network exposure can only be scored for a host node")
        if source == target:
            raise GraphError("network exposure target must differ from the source")
        path = self.shortest_path(source, target)
        if path is None:
            return None
        topology = self._topology()
        return self._score_host_path(source, path, topology=topology)

    def _score_host_path(
        self,
        source: str,
        path: ShortestPath,
        *,
        topology: tuple[
            dict[str, tuple[str, ...]],
            dict[str, tuple[str, ...]],
            frozenset[str],
        ]
        | None = None,
    ) -> HostExposureScore:
        """Calculate transparent score components for a selected host path."""
        target = path.nodes[-1]
        adjacency, incoming, host_ids = topology or self._topology()

        reachability_factors: list[float] = []
        reachability_counts = {
            "open": 0,
            "uncertain": 0,
            "filtered": 0,
            "unknown": 0,
        }
        for edge in path.edges:
            if edge.relationship != "observed_reachability":
                continue
            states = edge.metadata.get("service_states", [])
            state_values = (
                {str(state).lower() for state in states}
                if isinstance(states, (list, tuple, set))
                else set()
            )
            if "open" in state_values:
                factor = 1.0
                bucket = "open"
            elif "open|filtered" in state_values:
                factor = 0.5
                bucket = "uncertain"
            elif "filtered" in state_values:
                factor = 0.25
                bucket = "filtered"
            else:
                factor = 0.0
                bucket = "unknown"
            reachability_factors.append(factor)
            reachability_counts[bucket] += 1

        accessibility_factor = (
            math.fsum(reachability_factors) / len(reachability_factors)
            if reachability_factors
            else 0.0
        )

        host_compromises = sum(
            node_id in host_ids
            for node_id in path.nodes
            if node_id != source
        )
        depth_factor = 1.0 / host_compromises if host_compromises else 0.0

        independent_routes = self._independent_route_count(
            source,
            target,
            limit=4,
            adjacency=adjacency,
            incoming=incoming,
        )
        redundancy_factor = min(max(independent_routes - 1, 0), 3) / 3.0

        eligible_blast_host_count = len(host_ids) - int(target in host_ids)
        if source != target and source in host_ids:
            eligible_blast_host_count -= 1
        reachable_from_target = self._reachable_hosts(
            target,
            adjacency=adjacency,
            host_ids=host_ids,
        )
        downstream_host_count = sum(
            node_id != target and node_id != source
            for node_id in reachable_from_target
        )
        blast_factor = (
            downstream_host_count / eligible_blast_host_count
            if eligible_blast_host_count
            else 0.0
        )

        exploit_factors: list[float] = []
        missing_cvss = 0
        for edge in path.edges:
            if not edge.metadata.get("cve_id"):
                continue
            raw_cvss = edge.metadata.get("cvss_score")
            if (
                isinstance(raw_cvss, bool)
                or not isinstance(raw_cvss, (int, float))
                or not math.isfinite(float(raw_cvss))
                or not 0.0 <= float(raw_cvss) <= 10.0
            ):
                cvss_factor = 0.5
                missing_cvss += 1
            else:
                cvss_factor = float(raw_cvss) / 10.0
            confidence_factor = {
                "high": 1.0,
                "medium": 0.75,
                "low": 0.5,
            }.get(str(edge.metadata.get("confidence", "")).lower(), 0.25)
            evidence_factor = max(
                (
                    {
                        EvidenceLevel.VALIDATED: 1.0,
                        EvidenceLevel.OBSERVED: 0.85,
                        EvidenceLevel.INFERRED: 0.65,
                    }[item.level]
                    for item in edge.evidence
                ),
                default=0.0,
            )
            exploit_factors.append(
                cvss_factor * confidence_factor * evidence_factor
            )
        exploit_factor = (
            math.fsum(exploit_factors) / len(exploit_factors)
            if exploit_factors
            else 0.0
        )

        components = {
            "route_accessibility": round(
                NETWORK_SCORE_COMPONENT_MAXIMUMS["route_accessibility"]
                * accessibility_factor,
                2,
            ),
            "path_depth": round(
                NETWORK_SCORE_COMPONENT_MAXIMUMS["path_depth"] * depth_factor,
                2,
            ),
            "route_redundancy": round(
                NETWORK_SCORE_COMPONENT_MAXIMUMS["route_redundancy"]
                * redundancy_factor,
                2,
            ),
            "blast_radius": round(
                NETWORK_SCORE_COMPONENT_MAXIMUMS["blast_radius"] * blast_factor,
                2,
            ),
            "exploit_evidence": round(
                NETWORK_SCORE_COMPONENT_MAXIMUMS["exploit_evidence"]
                * exploit_factor,
                2,
            ),
        }
        network_score = round(min(100.0, max(0.0, math.fsum(components.values()))), 2)
        observations: dict[str, Any] = {
            "reachability_edges": len(reachability_factors),
            "reachability_states": reachability_counts,
            "host_compromises": host_compromises,
            "pivot_hosts": max(host_compromises - 1, 0),
            "independent_routes": independent_routes,
            "downstream_hosts": downstream_host_count,
            "eligible_blast_hosts": eligible_blast_host_count,
            "exploit_edges": len(exploit_factors),
            "missing_cvss": missing_cvss,
        }
        return HostExposureScore(
            target=target,
            network_score=network_score,
            components=components,
            observations=observations,
            path=path,
        )

    def _topology(
        self,
    ) -> tuple[
        dict[str, tuple[str, ...]],
        dict[str, tuple[str, ...]],
        frozenset[str],
    ]:
        """Build reusable simple directed topology indexes for scoring."""
        outgoing_sets = {node.node_id: set() for node in self.nodes}
        incoming_sets = {node.node_id: set() for node in self.nodes}
        for edge in self.edges:
            outgoing_sets[edge.source].add(edge.target)
            incoming_sets[edge.target].add(edge.source)
        adjacency = {
            node_id: tuple(sorted(targets))
            for node_id, targets in outgoing_sets.items()
        }
        incoming = {
            node_id: tuple(sorted(sources))
            for node_id, sources in incoming_sets.items()
        }
        host_ids = frozenset(
            node.node_id for node in self.nodes if node.kind is NodeKind.HOST
        )
        return adjacency, incoming, host_ids

    def _reachable_hosts(
        self,
        source: str,
        *,
        adjacency: dict[str, tuple[str, ...]] | None = None,
        host_ids: frozenset[str] | None = None,
    ) -> set[str]:
        """Return host nodes reachable from a node, excluding the source."""
        if adjacency is None or host_ids is None:
            adjacency, _, host_ids = self._topology()
        if not adjacency[source]:
            return set()
        visited = {source}
        pending = deque([source])
        while pending:
            node_id = pending.popleft()
            for target in adjacency[node_id]:
                if target not in visited:
                    visited.add(target)
                    pending.append(target)
        return (visited & host_ids) - {source}

    def _independent_route_count(
        self,
        source: str,
        target: str,
        *,
        limit: int,
        adjacency: dict[str, tuple[str, ...]] | None = None,
        incoming: dict[str, tuple[str, ...]] | None = None,
    ) -> int:
        """Count internally vertex-disjoint routes with a bounded max-flow."""
        if source == target:
            return 1
        if adjacency is None or incoming is None:
            adjacency, incoming, _ = self._topology()
        # The scored path proves at least one route exists. A single unique
        # first or last transition makes a second internally disjoint route
        # impossible, avoiding a max-flow construction for the common case.
        if len(adjacency[source]) <= 1 or len(incoming[target]) <= 1:
            return 1

        # Split every graph node into an input and output vertex. Internal
        # vertices have capacity one, while the endpoints allow up to ``limit``.
        # Duplicate source/target pairs are collapsed so parallel CVE edges on
        # one service do not masquerade as independent network routes.
        residual: dict[tuple[str, str], dict[tuple[str, str], int]] = {}

        def add_capacity(
            start: tuple[str, str],
            end: tuple[str, str],
            capacity: int,
        ) -> None:
            residual.setdefault(start, {})[end] = capacity
            residual.setdefault(end, {}).setdefault(start, 0)

        for node in self.nodes:
            capacity = limit if node.node_id in (source, target) else 1
            add_capacity((node.node_id, "in"), (node.node_id, "out"), capacity)
        for edge_source, edge_targets in adjacency.items():
            for edge_target in edge_targets:
                add_capacity((edge_source, "out"), (edge_target, "in"), 1)

        start = (source, "in")
        end = (target, "out")
        flow = 0
        while flow < limit:
            previous: dict[tuple[str, str], tuple[str, str]] = {}
            pending = deque([start])
            seen = {start}
            while pending and end not in seen:
                vertex = pending.popleft()
                for neighbor in sorted(residual.get(vertex, {})):
                    if residual[vertex][neighbor] > 0 and neighbor not in seen:
                        seen.add(neighbor)
                        previous[neighbor] = vertex
                        pending.append(neighbor)
            if end not in seen:
                break
            current = end
            while current != start:
                predecessor = previous[current]
                residual[predecessor][current] -= 1
                residual[current][predecessor] += 1
                current = predecessor
            flow += 1
        return flow

    def shortest_paths(
        self,
        source: str,
        target: str,
        *,
        limit: int = 3,
    ) -> tuple[ShortestPath, ...]:
        """Return the cheapest loop-free paths using Yen's algorithm.

        Edge identities keep parallel transitions, such as alternative CVEs on
        one service, as distinct routes. Dijkstra is used for each spur search.
        """
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 20:
            raise GraphError("path limit must be an integer between 1 and 20")

        first = self._dijkstra_path(source, target)
        if first is None:
            return ()

        selected = [first]
        candidates: list[tuple[float, tuple[str, ...], ShortestPath]] = []
        seen = {tuple(edge.edge_id for edge in first.edges)}

        while len(selected) < limit:
            previous = selected[-1]
            for index, spur_node in enumerate(previous.nodes[:-1]):
                root_edges = previous.edges[:index]
                root_edge_ids = tuple(edge.edge_id for edge in root_edges)
                excluded_edges = {
                    path.edges[index].edge_id
                    for path in selected
                    if len(path.edges) > index
                    and tuple(edge.edge_id for edge in path.edges[:index])
                    == root_edge_ids
                }
                spur = self._dijkstra_path(
                    spur_node,
                    target,
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
                candidate = ShortestPath(
                    nodes=previous.nodes[:index] + spur.nodes,
                    edges=edges,
                    total_weight=round(weight, 4),
                )
                heapq.heappush(candidates, (weight, identity, candidate))

            if not candidates:
                break
            selected.append(heapq.heappop(candidates)[2])

        return tuple(selected)

    def _dijkstra_path(
        self,
        source: str,
        target: str,
        *,
        excluded_nodes: frozenset[str] = frozenset(),
        excluded_edges: frozenset[str] = frozenset(),
    ) -> ShortestPath | None:
        """Return one cheapest path while optionally excluding graph elements."""
        node_ids = {node.node_id for node in self.nodes}
        if source not in node_ids:
            raise GraphError(f"unknown source node {source!r}")
        if target not in node_ids:
            raise GraphError(f"unknown target node {target!r}")
        if source in excluded_nodes or target in excluded_nodes:
            return None
        if source == target:
            return ShortestPath(nodes=(source,), edges=(), total_weight=0.0)

        distances, previous = self._dijkstra_search(
            source,
            target=target,
            excluded_nodes=excluded_nodes,
            excluded_edges=excluded_edges,
        )
        if target not in distances:
            return None

        return _reconstruct_path(source, target, previous, distances[target])

    def _dijkstra_search(
        self,
        source: str,
        *,
        target: str | None = None,
        excluded_nodes: frozenset[str] = frozenset(),
        excluded_edges: frozenset[str] = frozenset(),
    ) -> tuple[dict[str, float], dict[str, GraphEdge]]:
        """Run Dijkstra once, optionally stopping at a selected target."""
        node_ids = {node.node_id for node in self.nodes}
        if source not in node_ids:
            raise GraphError(f"unknown source node {source!r}")
        if source in excluded_nodes:
            return {}, {}

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
            if target is not None and node_id == target:
                break
            for edge in adjacency[node_id]:
                candidate = distance + edge.weight
                if candidate < distances.get(edge.target, math.inf):
                    distances[edge.target] = candidate
                    previous[edge.target] = edge
                    heapq.heappush(queue, (candidate, edge.target))

        return distances, previous

    def _astar_path(self, source: str, target: str) -> ShortestPath | None:
        """Search with h(node) = minimum hops to target * minimum edge cost.

        Reverse BFS computes hop counts without using weights. Every remaining
        path has at least that many edges, each costing at least the minimum
        weight, so h is an admissible and consistent lower bound. Nodes absent
        from the reverse traversal cannot reach the target and are skipped.
        """
        adjacency: dict[str, list[GraphEdge]] = {
            node.node_id: [] for node in self.nodes
        }
        incoming: dict[str, list[str]] = {node_id: [] for node_id in adjacency}
        minimum_weight = math.inf
        for edge in self.edges:
            adjacency[edge.source].append(edge)
            incoming[edge.target].append(edge.source)
            minimum_weight = min(minimum_weight, edge.weight)

        hops = {target: 0}
        pending = deque([target])
        while pending:
            node_id = pending.popleft()
            for predecessor in incoming[node_id]:
                if predecessor not in hops:
                    hops[predecessor] = hops[node_id] + 1
                    pending.append(predecessor)
        if source not in hops:
            return None

        distances = {source: 0.0}
        previous: dict[str, GraphEdge] = {}
        # Keep g separately from f so outdated queue entries can be discarded.
        queue: list[tuple[float, float, str]] = [
            (hops[source] * minimum_weight, 0.0, source)
        ]
        while queue:
            _, distance, node_id = heapq.heappop(queue)
            if distance != distances.get(node_id):
                continue
            if node_id == target:
                return _reconstruct_path(source, target, previous, distance)
            for edge in adjacency[node_id]:
                if edge.target not in hops:
                    continue
                candidate = distance + edge.weight
                if candidate < distances.get(edge.target, math.inf):
                    distances[edge.target] = candidate
                    previous[edge.target] = edge
                    estimate = candidate + hops[edge.target] * minimum_weight
                    heapq.heappush(queue, (estimate, candidate, edge.target))
        return None

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


def _reconstruct_path(
    source: str,
    target: str,
    previous: dict[str, GraphEdge],
    distance: float,
) -> ShortestPath:
    path_edges: list[GraphEdge] = []
    current = target
    while current != source:
        edge = previous[current]
        path_edges.append(edge)
        current = edge.source
    path_edges.reverse()
    return ShortestPath(
        nodes=(source, *(edge.target for edge in path_edges)),
        edges=tuple(path_edges),
        total_weight=round(distance, 4),
    )


def vulnerability_cost(
    cvss_score: float | None,
    confidence: Confidence | str,
) -> float:
    """Convert severity and confidence into a positive path edge cost."""
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


def render_attack_graph_ascii(
    graph: AttackGraph,
    *,
    max_depth: int = DEFAULT_RENDER_MAX_DEPTH,
) -> str:
    """Render a directed graph as a branching ASCII diagram.

    Branches deeper than ``max_depth`` levels are not indented further; the
    node where the limit was reached is drawn again as a separate tree below,
    so every node and edge is still shown and output stays proportional to
    the graph's size.
    """
    if isinstance(max_depth, bool) or not isinstance(max_depth, int) or max_depth < 1:
        raise GraphError("max_depth must be a positive integer")
    nodes = {node.node_id: node for node in graph.nodes}
    adjacency: dict[str, list[GraphEdge]] = {node_id: [] for node_id in nodes}
    incoming = {node_id: 0 for node_id in nodes}
    for edge in graph.edges:
        adjacency[edge.source].append(edge)
        incoming[edge.target] += 1
    for edges in adjacency.values():
        edges.sort(key=lambda edge: (edge.weight, edge.target, edge.edge_id))

    roots = [node_id for node_id, count in incoming.items() if count == 0]
    roots.sort(key=lambda node_id: (nodes[node_id].kind is not NodeKind.ENTRY, node_id))
    lines = ["HexPath Attack Graph", "===================="]
    expanded: set[str] = set()

    def walk(root: str) -> None:
        # Depth-first walk with an explicit stack instead of recursion, so very
        # long paths cannot exceed Python's recursion limit. Each frame holds a
        # node, its line prefix, and the index of its next outgoing edge. The
        # nodes on the stack are exactly the current branch, which is what
        # cycle detection needs.
        expanded.add(root)
        stack: list[tuple[str, str, int]] = [(root, "", 0)]
        on_branch: set[str] = {root}
        while stack:
            node_id, prefix, index = stack[-1]
            outgoing = adjacency[node_id]
            if index >= len(outgoing):
                stack.pop()
                on_branch.discard(node_id)
                continue
            stack[-1] = (node_id, prefix, index + 1)
            edge = outgoing[index]
            is_last = index == len(outgoing) - 1
            child_prefix = prefix + ("    " if is_last else "|   ")
            target_text = _ascii_node(nodes[edge.target])
            marker = ""
            if edge.target in on_branch:
                marker = " (cycle)"
            elif edge.target in expanded:
                marker = " (reference)"
            elif len(stack) >= max_depth:
                marker = " (continued below: depth limit reached)"
            lines.append(
                f"{prefix}+-- {_ascii_edge(edge)} --> {target_text}{marker}"
            )
            if not marker:
                expanded.add(edge.target)
                on_branch.add(edge.target)
                stack.append((edge.target, child_prefix, 0))

    for root in roots:
        if root in expanded:
            continue
        if len(lines) > 2:
            lines.append("")
        lines.append(_ascii_node(nodes[root]))
        walk(root)

    for node_id in sorted(nodes):
        if node_id in expanded:
            continue
        if len(lines) > 2:
            lines.append("")
        lines.append(_ascii_node(nodes[node_id]))
        walk(node_id)

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


def render_host_targets_ascii(source: str, targets: list[dict[str, Any]]) -> str:
    """Show host selectors, names, and modeled costs with safe terminal text."""
    lines = ["HexPath Host Targets", f"Source: {_terminal_text(source)}"]
    for item in targets:
        status = f"cost={item['cost']:.2f}" if item["reachable"] else "no modeled path"
        hostnames = item.get("hostnames", [])
        names = (
            ", ".join(
                _terminal_text(name) for name in hostnames if isinstance(name, str)
            )
            if isinstance(hostnames, list)
            else ""
        )
        suffix = f" | {names}" if names else ""
        lines.append(f"  {_terminal_text(item['id'])} | {status}{suffix}")
    if not targets:
        lines.append("No host targets in this graph.")
    lines.append("Reachability here requires evidence-backed graph transitions.")
    return "\n".join(lines)


def path_comparison_document(
    source: str,
    target: str,
    paths: tuple[ShortestPath, ...],
    *,
    limit: int,
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
    graph: AttackGraph,
    source: str,
    target: str,
    paths: tuple[ShortestPath, ...],
) -> str:
    """Compare route cost, candidate CVEs, confidence, and transitions."""
    lines = ["HexPath Path Comparison", "======================="]
    lines.append(f"Source: {_terminal_text(source)}")
    lines.append(f"Target: {_terminal_text(target)}")
    if not paths:
        lines.append("No evidence-backed directed path in this graph.")
        return "\n".join(lines)

    lines.extend(["", "Rank  Cost     Delta    Candidate findings"])
    for rank, path in enumerate(paths, 1):
        findings = _path_findings(path)
        delta = path.total_weight - paths[0].total_weight
        lines.append(f"{rank:<4}  {path.total_weight:<7.2f}  +{delta:<7.2f} {findings}")

    for rank, path in enumerate(paths, 1):
        lines.append("")
        rendered = render_path_ascii(graph, path).splitlines()
        lines.extend([f"Route {rank}", *rendered[2:]])
    lines.extend(
        [
            "",
            "Costs rank investigation routes; candidate CVEs do not confirm exploitation.",
        ]
    )
    return "\n".join(lines)


def graph_validation_document(graph: AttackGraph) -> dict[str, Any]:
    """Summarize a graph that passed structural and evidence validation."""
    node_kinds = {
        kind.value: sum(node.kind is kind for node in graph.nodes)
        for kind in NodeKind
    }
    relationship_counts: dict[str, int] = {}
    for edge in graph.edges:
        relationship_counts[edge.relationship] = (
            relationship_counts.get(edge.relationship, 0) + 1
        )
    return {
        "valid": True,
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
        "node_kinds": node_kinds,
        "relationships": dict(sorted(relationship_counts.items())),
        "entry_nodes": sorted(
            node.node_id for node in graph.nodes if node.kind is NodeKind.ENTRY
        ),
    }


def render_graph_validation_ascii(graph: AttackGraph) -> str:
    """Render a concise validation summary for one saved graph."""
    document = graph_validation_document(graph)
    kinds = document["node_kinds"]
    entries = document["entry_nodes"]
    lines = [
        "HexPath Graph Validation",
        "========================",
        "Status: valid",
        f"Nodes: {document['nodes']}  Edges: {document['edges']}",
        (
            f"Kinds: entry={kinds['entry']}  host={kinds['host']}  "
            f"service={kinds['service']}"
        ),
        "Entry nodes: " + (", ".join(entries) if entries else "none"),
    ]
    relationships = document["relationships"]
    if relationships:
        lines.append(
            "Relationships: "
            + ", ".join(
                f"{relationship}={count}"
                for relationship, count in relationships.items()
            )
        )
    else:
        lines.append("Relationships: none")
    return "\n".join(lines)


def host_exposure_document(
    graph: AttackGraph,
    source: str,
    score: HostExposureScore,
) -> dict[str, Any]:
    """Serialize one host's exposure score and retained path evidence."""
    nodes = {node.node_id: node for node in graph.nodes}
    entry = _ranked_host_path_entry(nodes, score, rank=1)
    entry.pop("rank")
    return {
        "algorithm": "dijkstra",
        "source": source,
        "score_interpretation": (
            "higher scores indicate greater modeled network exposure; "
            "this is not a CVSS score or proof of exploitability"
        ),
        **entry,
    }


def render_host_exposure_ascii(
    graph: AttackGraph,
    source: str,
    score: HostExposureScore,
) -> str:
    """Render one selected host's exposure score and component breakdown."""
    nodes = {node.node_id: node for node in graph.nodes}
    target = nodes[score.target]
    lines = [
        "HexPath Host Exposure Score",
        "===========================",
        f"Source: {_terminal_text(source)}",
        f"Target: {_terminal_text(target.node_id)}",
        f"Network score: {score.network_score:.2f}/100",
        f"Score model: {score.score_version}",
        "",
        "Components",
        "----------",
    ]
    lines.extend(
        f"{name}: {value:.2f}/{NETWORK_SCORE_COMPONENT_MAXIMUMS[name]:.0f}"
        for name, value in score.components.items()
    )
    lines.extend(
        [
            "",
            "Selected route",
            "--------------",
            *render_path_ascii(graph, score.path).splitlines()[2:],
            "",
            "Observations: "
            f"routes={score.observations['independent_routes']}, "
            f"pivots={score.observations['pivot_hosts']}, "
            f"downstream_hosts={score.observations['downstream_hosts']}, "
            f"exploit_edges={score.observations['exploit_edges']}",
            "Scores prioritize investigation; they do not prove exploitability or impact.",
        ]
    )
    return "\n".join(lines)


def vulnerable_path_ranking_document(
    graph: AttackGraph,
    source: str,
    scores: tuple[HostExposureScore | ShortestPath, ...],
    *,
    limit: int,
) -> dict[str, Any]:
    """Serialize network exposure scores and their selected Dijkstra paths."""
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 20:
        raise GraphError("path limit must be an integer between 1 and 20")

    exposures = _normalized_exposure_scores(graph, source, scores)
    nodes = {node.node_id: node for node in graph.nodes}
    reported = exposures[:limit]
    reachable_targets = {score.target for score in exposures}
    unreachable = [
        {
            **node.to_dict(),
            "network_score": None,
            "reason": "no evidence-backed directed path from the selected source",
        }
        for node in sorted(graph.nodes, key=lambda item: item.node_id)
        if node.kind is NodeKind.HOST
        and node.node_id != source
        and node.node_id not in reachable_targets
    ]
    entries = [
        _ranked_host_path_entry(nodes, score, rank)
        for rank, score in enumerate(reported, 1)
    ]
    return {
        "algorithm": "dijkstra",
        "source": source,
        "ranking": "network_score_descending",
        "score_version": NETWORK_SCORE_VERSION,
        "score_interpretation": (
            "higher scores indicate greater modeled network exposure; "
            "this is not a CVSS score or proof of exploitability"
        ),
        "component_maximums": dict(NETWORK_SCORE_COMPONENT_MAXIMUMS),
        "path_cost_interpretation": (
            "lower Dijkstra cost identifies the selected evidence-backed route"
        ),
        "analyzed_hosts": len(reachable_targets) + len(unreachable),
        "reachable_hosts": len(reachable_targets),
        "reported_paths": len(entries),
        "most_vulnerable_path": entries[0] if entries else None,
        "alternative_paths": entries[1:],
        "unreachable_hosts": unreachable,
    }


def render_vulnerable_path_ranking_ascii(
    graph: AttackGraph,
    source: str,
    scores: tuple[HostExposureScore | ShortestPath, ...],
    *,
    limit: int,
) -> str:
    """Render network-wide exposure scores and Dijkstra paths."""
    exposures = _normalized_exposure_scores(graph, source, scores)
    document = vulnerable_path_ranking_document(
        graph,
        source,
        exposures,
        limit=limit,
    )
    lines = [
        "HexPath Network Exposure Ranking",
        "================================",
        f"Source: {_terminal_text(source)}",
    ]
    if not exposures:
        lines.append("No evidence-backed directed path reaches another host.")
        lines.append(f"Hosts analyzed: {document['analyzed_hosts']}  Reachable: 0")
        return "\n".join(lines)

    nodes = {node.node_id: node for node in graph.nodes}
    reported = exposures[:limit]
    lines.extend(
        [
            "Higher score indicates greater modeled exposure (0-100).",
            "",
            "Rank  Score   Cost     Target                         Candidate findings",
        ]
    )
    for rank, score in enumerate(reported, 1):
        target = nodes[score.target]
        findings = _path_findings(score.path)
        lines.append(
            f"{rank:<4}  {score.network_score:<6.2f}  "
            f"{score.path.total_weight:<7.2f}  "
            f"{_terminal_text(target.node_id):<29}  {findings}"
        )

    best = reported[0]
    lines.extend(["", "Highest-exposure route", "----------------------"])
    rendered = render_path_ascii(graph, best.path).splitlines()
    lines.extend(rendered[2:])
    lines.append("")
    lines.append(
        "Score components: "
        + ", ".join(
            f"{name}={value:.2f}/{NETWORK_SCORE_COMPONENT_MAXIMUMS[name]:.0f}"
            for name, value in best.components.items()
        )
    )
    lines.append(
        "Observations: "
        f"routes={best.observations['independent_routes']}, "
        f"pivots={best.observations['pivot_hosts']}, "
        f"downstream_hosts={best.observations['downstream_hosts']}, "
        f"exploit_edges={best.observations['exploit_edges']}"
    )
    lines.extend(
        [
            "",
            f"Hosts analyzed: {document['analyzed_hosts']}  "
            f"Reachable: {document['reachable_hosts']}  "
            f"Shown: {document['reported_paths']}",
            f"Score model: {NETWORK_SCORE_VERSION}",
            "Scores prioritize investigation; they do not prove exploitability or impact.",
        ]
    )
    return "\n".join(lines)


def _ranked_host_path_entry(
    nodes: dict[str, GraphNode],
    score: HostExposureScore,
    rank: int,
) -> dict[str, Any]:
    target = nodes[score.target]
    return {
        "rank": rank,
        "network_score": score.network_score,
        "score_version": score.score_version,
        "components": dict(score.components),
        "component_maximums": dict(NETWORK_SCORE_COMPONENT_MAXIMUMS),
        "observations": dict(score.observations),
        "target": target.to_dict(),
        "candidate_findings": [
            {
                "cve_id": edge.metadata["cve_id"],
                "confidence": edge.metadata.get("confidence"),
                "cvss_score": edge.metadata.get("cvss_score"),
            }
            for edge in score.path.edges
            if edge.metadata.get("cve_id")
        ],
        "path": score.path.to_dict(),
    }


def _normalized_exposure_scores(
    graph: AttackGraph,
    source: str,
    values: tuple[HostExposureScore | ShortestPath, ...],
) -> tuple[HostExposureScore, ...]:
    """Accept legacy path tuples while keeping score-ranked public output."""
    topology = graph._topology()
    exposures = [
        value
        if isinstance(value, HostExposureScore)
        else graph._score_host_path(source, value, topology=topology)
        for value in values
    ]
    exposures.sort(
        key=lambda score: (
            -score.network_score,
            score.path.total_weight,
            len(score.path.edges),
            score.target,
        )
    )
    return tuple(exposures)


def _path_findings(path: ShortestPath) -> str:
    findings = "; ".join(
        f"{_terminal_text(str(edge.metadata['cve_id']))} "
        f"({_terminal_text(str(edge.metadata.get('confidence', 'unknown')))})"
        for edge in path.edges
        if edge.metadata.get("cve_id")
    )
    return findings or "No candidate CVE transitions"


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

"""Tests for attack-graph construction and path analysis."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import math
import random
import unittest

from hexpath.graph import (
    ENTRY_NODE_ID,
    AttackGraph,
    GraphEdge,
    GraphError,
    GraphNode,
    NodeKind,
    build_attack_graph,
    render_attack_graph_ascii,
    render_path_ascii,
    vulnerability_cost,
)
from hexpath.models import Confidence, Evidence, EvidenceLevel


COLLECTED_AT = datetime(2026, 10, 8, 18, 30, tzinfo=timezone.utc)


def evidence(summary: str = "Observed during test scan") -> Evidence:
    return Evidence(
        source="test",
        summary=summary,
        level=EvidenceLevel.OBSERVED,
        collected_at=COLLECTED_AT,
        reference="fixture.json",
    )


def sample_documents() -> tuple[dict, dict]:
    host_id = "host:2001:db8::10"
    ssh_id = "service:[2001:db8::10]:tcp:22"
    web_id = "service:[2001:db8::10]:tcp:443"
    observed = evidence().to_dict()
    inferred = Evidence(
        source="nvd",
        summary="NVD CPE applicability match",
        level=EvidenceLevel.INFERRED,
        collected_at=COLLECTED_AT,
        reference="https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
    ).to_dict()
    scan = {
        "hosts": [
            {
                "id": host_id,
                "address": "2001:db8::10",
                "hostnames": ["server.lab"],
                "evidence": [observed],
            }
        ],
        "services": [
            {
                "id": ssh_id,
                "host": "2001:db8::10",
                "port": 22,
                "protocol": "tcp",
                "state": "open",
                "name": "ssh",
                "product": "OpenSSH",
                "version": "9.6",
                "cpes": ["cpe:/a:openbsd:openssh:9.6"],
                "evidence": [observed],
            },
            {
                "id": web_id,
                "host": "2001:db8::10",
                "port": 443,
                "protocol": "tcp",
                "state": "open",
                "name": "https",
                "product": "Example HTTP",
                "version": "1.0",
                "cpes": ["cpe:/a:example:http:1.0"],
                "evidence": [observed],
            },
        ],
    }
    cves = {
        "vulnerabilities": [
            {
                "id": "CVE-2024-6387",
                "description": "Example high-severity issue.",
                "cvss_score": 9.0,
                "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "references": [],
            },
            {
                "id": "CVE-2026-12345",
                "description": "Example moderate issue.",
                "cvss_score": 5.0,
                "cvss_vector": None,
                "references": [],
            },
        ],
        "matches": [
            {
                "service_id": ssh_id,
                "cve_id": "CVE-2024-6387",
                "confidence": "medium",
                "reason": "Exact CPE candidate; patch status unknown.",
                "evidence": [inferred],
            },
            {
                "service_id": web_id,
                "cve_id": "CVE-2026-12345",
                "confidence": "high",
                "reason": "Validated package identity.",
                "evidence": [inferred],
            },
        ],
    }
    return scan, cves


class WeightTests(unittest.TestCase):
    def test_high_severity_and_confidence_produce_lower_cost(self) -> None:
        high_priority = vulnerability_cost(9.8, Confidence.HIGH)
        low_priority = vulnerability_cost(4.0, Confidence.LOW)

        self.assertLess(high_priority, low_priority)

    def test_missing_cvss_uses_neutral_score(self) -> None:
        self.assertEqual(vulnerability_cost(None, Confidence.MEDIUM), 7.5)


class DijkstraTests(unittest.TestCase):
    def test_selects_lowest_total_weight(self) -> None:
        nodes = tuple(
            GraphNode(node_id=name, kind=NodeKind.HOST, label=name)
            for name in ("start", "a", "b", "target")
        )
        edges = (
            GraphEdge("sa", "start", "a", "transition", 1, "start to a", (evidence(),)),
            GraphEdge("at", "a", "target", "transition", 8, "a to target", (evidence(),)),
            GraphEdge("sb", "start", "b", "transition", 3, "start to b", (evidence(),)),
            GraphEdge("bt", "b", "target", "transition", 2, "b to target", (evidence(),)),
        )
        graph = AttackGraph(nodes=nodes, edges=edges)

        path = graph.shortest_path("start", "target")

        self.assertIsNotNone(path)
        self.assertEqual(path.nodes, ("start", "b", "target"))
        self.assertEqual(path.total_weight, 5.0)

    def test_returns_none_when_target_is_unreachable(self) -> None:
        graph = AttackGraph(
            nodes=(
                GraphNode("start", NodeKind.ENTRY, "start"),
                GraphNode("target", NodeKind.HOST, "target"),
            ),
            edges=(),
        )

        self.assertIsNone(graph.shortest_path("start", "target"))

    def test_rejects_nonpositive_edge_weight(self) -> None:
        with self.assertRaisesRegex(GraphError, "greater than zero"):
            GraphEdge("bad", "a", "b", "transition", 0, "invalid", (evidence(),))


class AStarTests(unittest.TestCase):
    def make_graph(self, links: list[tuple[str, str, float]]) -> AttackGraph:
        names = {"start", "target", *(name for link in links for name in link[:2])}
        return AttackGraph(
            nodes=tuple(
                GraphNode(name, NodeKind.HOST, name) for name in sorted(names)
            ),
            edges=tuple(
                GraphEdge(
                    str(index), source, target, "transition", weight,
                    f"{source} to {target}", (evidence(),),
                )
                for index, (source, target, weight) in enumerate(links)
            ),
        )

    def test_longer_cheaper_route_beats_direct_route_with_cycles_and_dead_ends(self) -> None:
        graph = self.make_graph([
            ("start", "target", 10),
            ("start", "a", 0.5),
            ("a", "b", 0.5),
            ("b", "target", 0.5),
            ("b", "a", 0.1),
            ("start", "dead-end", 0.1),
        ])

        path = graph.shortest_path("start", "target", algorithm="astar")

        self.assertEqual(path.nodes, ("start", "a", "b", "target"))
        self.assertEqual(path.total_weight, 1.5)
        self.assertEqual(path, graph.shortest_path("start", "target"))

    def test_replaces_expensive_discovery_and_preserves_selected_edge_evidence(self) -> None:
        graph = self.make_graph([
            ("start", "a", 8),
            ("start", "a", 4),
            ("start", "b", 1),
            ("b", "a", 1),
            ("a", "target", 3),
        ])

        path = graph.shortest_path("start", "target", algorithm="astar")

        self.assertEqual(path.nodes, ("start", "b", "a", "target"))
        self.assertEqual(path.edges, (graph.edges[2], graph.edges[3], graph.edges[4]))
        self.assertEqual(path.total_weight, 5)

    def test_same_node_returns_zero_cost_without_edges(self) -> None:
        graph = self.make_graph([])

        path = graph.shortest_path("start", "start", algorithm="astar")

        self.assertEqual(path.nodes, ("start",))
        self.assertEqual(path.edges, ())
        self.assertEqual(path.total_weight, 0)

    def test_unreachable_target_and_reverse_only_edges(self) -> None:
        for links in ([], [("target", "start", 1)]):
            with self.subTest(links=links):
                graph = self.make_graph(links)
                self.assertIsNone(
                    graph.shortest_path("start", "target", algorithm="astar")
                )

    def test_rejects_unknown_nodes_and_algorithm(self) -> None:
        graph = self.make_graph([])
        for source, target, message in (
            ("missing", "target", "unknown source"),
            ("start", "missing", "unknown target"),
            ("missing", "missing", "unknown source"),
        ):
            with self.subTest(source=source, target=target):
                with self.assertRaisesRegex(GraphError, message):
                    graph.shortest_path(source, target, algorithm="astar")
        with self.assertRaisesRegex(GraphError, "unknown path algorithm"):
            graph.shortest_path("start", "start", algorithm="greedy")

    def test_built_graph_keeps_cve_evidence_and_json_schema(self) -> None:
        scan, cves = sample_documents()
        graph = build_attack_graph(scan, cves)

        path = graph.shortest_path(
            ENTRY_NODE_ID, "host:2001:db8::10", algorithm="astar"
        )

        self.assertEqual(path.to_dict(), graph.shortest_path(
            ENTRY_NODE_ID, "host:2001:db8::10"
        ).to_dict())
        self.assertEqual(path.edges[-1].metadata["cve_id"], "CVE-2024-6387")
        self.assertIn("CVE-2024-6387", render_path_ascii(graph, path))

    def test_deep_graph_and_fractional_costs(self) -> None:
        path = chain_graph(2500).shortest_path(
            ENTRY_NODE_ID, "host:2499", algorithm="astar"
        )
        self.assertEqual(len(path.nodes), 2501)
        self.assertEqual(path.total_weight, 2500)
        graph = self.make_graph([
            ("start", "a", 0.333333), ("a", "target", 0.333333),
            ("start", "target", 0.6667),
        ])
        path = graph.shortest_path("start", "target", algorithm="astar")
        self.assertEqual(path.nodes, ("start", "a", "target"))
        self.assertEqual(path.total_weight, 0.6667)

    def test_matches_independent_all_pairs_oracle_on_generated_directed_graphs(self) -> None:
        generator = random.Random(42)
        names = ("start", "a", "b", "c", "d", "e", "target")
        for case in range(30):
            links = [
                (source, target, generator.choice((0.125, 0.5, 1, 3, 8)))
                for source in names for target in names
                if generator.random() < 0.25
            ]
            graph = self.make_graph(links)
            costs = {(a, b): 0.0 if a == b else math.inf for a in names for b in names}
            for source, target, weight in links:
                costs[source, target] = min(costs[source, target], weight)
            # Floyd-Warshall is an independent reference, without a search heap.
            for via in names:
                for source in names:
                    for target in names:
                        costs[source, target] = min(
                            costs[source, target],
                            costs[source, via] + costs[via, target],
                        )
            actual_names = {node.node_id for node in graph.nodes}
            for source in sorted(actual_names):
                for target in sorted(actual_names):
                    with self.subTest(case=case, source=source, target=target):
                        path = graph.shortest_path(source, target, algorithm="astar")
                        baseline = graph.shortest_path(source, target)
                        if math.isinf(costs[source, target]):
                            self.assertIsNone(path)
                            self.assertIsNone(baseline)
                        else:
                            self.assertEqual(path.total_weight, costs[source, target])
                            self.assertEqual(path.total_weight, baseline.total_weight)
                            self.assertEqual(path.nodes[0], source)
                            self.assertEqual(path.nodes[-1], target)
                            self.assertEqual(
                                sum(edge.weight for edge in path.edges),
                                costs[source, target],
                            )


class BuilderTests(unittest.TestCase):
    def test_builds_graph_and_selects_best_candidate_path(self) -> None:
        scan, cves = sample_documents()

        graph = build_attack_graph(scan, cves)
        path = graph.shortest_path(ENTRY_NODE_ID, "host:2001:db8::10")

        self.assertEqual(len(graph.nodes), 4)
        self.assertEqual(len(graph.edges), 4)
        self.assertIsNotNone(path)
        self.assertEqual(
            path.nodes,
            (
                ENTRY_NODE_ID,
                "service:[2001:db8::10]:tcp:22",
                "host:2001:db8::10",
            ),
        )
        self.assertEqual(path.total_weight, 4.5)
        self.assertEqual(path.edges[-1].metadata["cve_id"], "CVE-2024-6387")
        self.assertEqual(path.edges[-1].metadata["confidence"], "medium")

    def test_graph_json_round_trip_preserves_shortest_path(self) -> None:
        scan, cves = sample_documents()
        graph = build_attack_graph(scan, cves)

        restored = AttackGraph.from_json(graph.to_json())
        path = restored.shortest_path(ENTRY_NODE_ID, "host:2001:db8::10")

        self.assertEqual(json.loads(restored.to_json()), json.loads(graph.to_json()))
        self.assertEqual(path.total_weight, 4.5)

    def test_builds_evidence_backed_two_host_pivot_path(self) -> None:
        first_scan, cves = sample_documents()
        first_scan["vantage"] = ENTRY_NODE_ID
        observed = evidence("Observed from the first host").to_dict()
        second_service_id = "service:[2001:db8::20]:tcp:443"
        second_scan = {
            "vantage": "host:2001:db8::10",
            "hosts": [
                {
                    "id": "host:2001:db8::20",
                    "address": "2001:db8::20",
                    "hostnames": ["internal.lab"],
                    "evidence": [observed],
                }
            ],
            "services": [
                {
                    "id": second_service_id,
                    "host": "2001:db8::20",
                    "port": 443,
                    "protocol": "tcp",
                    "state": "open",
                    "name": "https",
                    "product": "Internal API",
                    "version": "2.0",
                    "cpes": ["cpe:/a:example:api:2.0"],
                    "evidence": [observed],
                }
            ],
        }
        cves["vulnerabilities"].append(
            {
                "id": "CVE-2026-22222",
                "description": "Example internal service issue.",
                "cvss_score": 8.0,
                "cvss_vector": None,
                "references": [],
            }
        )
        cves["matches"].append(
            {
                "service_id": second_service_id,
                "cve_id": "CVE-2026-22222",
                "confidence": "medium",
                "reason": "Exact CPE candidate; patch status unknown.",
                "evidence": [
                    Evidence(
                        source="nvd",
                        summary="NVD CPE applicability match",
                        level=EvidenceLevel.INFERRED,
                        collected_at=COLLECTED_AT,
                        reference=(
                            "https://nvd.nist.gov/vuln/detail/CVE-2026-22222"
                        ),
                    ).to_dict()
                ],
            }
        )

        graph = build_attack_graph([first_scan, second_scan], cves)
        path = graph.shortest_path(ENTRY_NODE_ID, "host:2001:db8::20")

        self.assertIsNotNone(path)
        self.assertEqual(
            path.nodes,
            (
                ENTRY_NODE_ID,
                "service:[2001:db8::10]:tcp:22",
                "host:2001:db8::10",
                second_service_id,
                "host:2001:db8::20",
            ),
        )
        self.assertEqual(path.total_weight, 10.0)
        rendered = render_path_ascii(graph, path)
        self.assertIn("CVE-2024-6387", rendered)
        self.assertIn("CVE-2026-22222", rendered)

    def test_rejects_unknown_host_scan_vantage(self) -> None:
        scan, cves = sample_documents()
        scan["vantage"] = "host:2001:db8::99"

        with self.assertRaisesRegex(GraphError, "vantage refers to unknown host"):
            build_attack_graph(scan, cves)

    def test_rejects_match_for_unknown_service(self) -> None:
        scan, cves = sample_documents()
        cves["matches"][0]["service_id"] = "service:[2001:db8::99]:tcp:22"

        with self.assertRaisesRegex(GraphError, "unknown service"):
            build_attack_graph(scan, cves)

    def test_ascii_renderers_show_direction_cost_and_cve(self) -> None:
        scan, cves = sample_documents()
        graph = build_attack_graph(scan, cves)
        path = graph.shortest_path(ENTRY_NODE_ID, "host:2001:db8::10")

        graph_image = render_attack_graph_ascii(graph)
        path_image = render_path_ascii(graph, path)

        self.assertIn("[ENTRY]", graph_image)
        self.assertIn("+--", graph_image)
        self.assertIn("-->", graph_image)
        self.assertIn("CVE-2024-6387", graph_image)
        self.assertIn("Total cost: 4.50", path_image)

    def test_custom_entry_id_is_default_source_and_rendered_first(self) -> None:
        scan, cves = sample_documents()
        graph = build_attack_graph(scan, cves, entry_id="zz:operator")
        isolated = GraphNode("host:2001:db8::99", NodeKind.HOST, "isolated")
        graph = AttackGraph(nodes=(*graph.nodes, isolated), edges=graph.edges)

        rendered = render_attack_graph_ascii(graph)

        self.assertEqual(graph.default_source(), "zz:operator")
        self.assertLess(
            rendered.index("<zz:operator>"),
            rendered.index("<host:2001:db8::99>"),
        )

    def test_default_source_requires_an_entry_node(self) -> None:
        graph = AttackGraph(
            nodes=(GraphNode("host:a", NodeKind.HOST, "a"),),
            edges=(),
        )

        with self.assertRaisesRegex(GraphError, "no entry node"):
            graph.default_source()

    def test_ascii_renderer_removes_terminal_control_characters(self) -> None:
        graph = AttackGraph(
            nodes=(GraphNode("entry", NodeKind.ENTRY, "bad\x1b[31m\nlabel"),),
            edges=(),
        )

        rendered = render_attack_graph_ascii(graph)

        self.assertNotIn("\x1b", rendered)
        self.assertIn("bad?[31m?label", rendered)


def chain_graph(length: int, *, loop_back: bool = False) -> AttackGraph:
    """An entry node followed by ``length`` hosts in a single line."""
    nodes = [GraphNode(ENTRY_NODE_ID, NodeKind.ENTRY, "entry")]
    nodes += [GraphNode(f"host:{index}", NodeKind.HOST, "host") for index in range(length)]
    edges = [
        GraphEdge(
            edge_id=f"edge:{index}",
            source=ENTRY_NODE_ID if index == 0 else f"host:{index - 1}",
            target=f"host:{index}",
            relationship="transition",
            weight=1,
            description="step",
            evidence=(evidence(),),
        )
        for index in range(length)
    ]
    if loop_back:
        edges.append(
            GraphEdge(
                edge_id="edge:back",
                source=f"host:{length - 1}",
                target="host:0",
                relationship="transition",
                weight=1,
                description="loop",
                evidence=(evidence(),),
            )
        )
    return AttackGraph(nodes=tuple(nodes), edges=tuple(edges))


class DeepGraphRenderingTests(unittest.TestCase):
    def test_renders_graph_deeper_than_python_recursion_limit(self) -> None:
        graph = chain_graph(5000)

        rendered = render_attack_graph_ascii(graph)

        self.assertTrue(rendered.endswith("Nodes: 5001  Edges: 5000"))
        for index in (0, 2500, 4999):
            self.assertIn(f"<host:{index}>", rendered)

    def test_output_stays_proportional_to_graph_size(self) -> None:
        rendered = render_attack_graph_ascii(chain_graph(5000))

        longest_line = max(len(line) for line in rendered.splitlines())
        self.assertLess(longest_line, 4 * 100 + 200)
        self.assertLess(len(rendered), 5000 * 600)

    def test_depth_limit_continues_branch_as_separate_tree(self) -> None:
        rendered = render_attack_graph_ascii(chain_graph(3), max_depth=2)

        self.assertEqual(
            rendered.splitlines(),
            [
                "HexPath Attack Graph",
                "====================",
                "[ENTRY] entry <entry:scanner>",
                "+-- [transition, cost=1.00] --> [HOST] host <host:0>",
                "    +-- [transition, cost=1.00] --> [HOST] host <host:1>"
                " (continued below: depth limit reached)",
                "",
                "[HOST] host <host:1>",
                "+-- [transition, cost=1.00] --> [HOST] host <host:2>",
                "",
                "Nodes: 4  Edges: 3",
            ],
        )

    def test_cycle_is_still_detected_at_depth(self) -> None:
        rendered = render_attack_graph_ascii(chain_graph(50, loop_back=True))

        self.assertIn("--> [HOST] host <host:0> (cycle)", rendered)

    def test_rejects_invalid_max_depth(self) -> None:
        with self.assertRaisesRegex(GraphError, "max_depth"):
            render_attack_graph_ascii(chain_graph(1), max_depth=0)


if __name__ == "__main__":
    unittest.main()

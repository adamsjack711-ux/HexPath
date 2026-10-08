"""Tests for attack-graph construction and path analysis."""

from __future__ import annotations

from datetime import datetime, timezone
import json
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

    def test_ascii_renderer_removes_terminal_control_characters(self) -> None:
        graph = AttackGraph(
            nodes=(GraphNode("entry", NodeKind.ENTRY, "bad\x1b[31m\nlabel"),),
            edges=(),
        )

        rendered = render_attack_graph_ascii(graph)

        self.assertNotIn("\x1b", rendered)
        self.assertIn("bad?[31m?label", rendered)


if __name__ == "__main__":
    unittest.main()

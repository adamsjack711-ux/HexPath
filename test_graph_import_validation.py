"""Regression tests for rejecting malformed and inconsistent saved attack graphs.

Contribution to HexPath. No network scans are performed by these tests.
Run with: python -m unittest tests/test_graph_import_validation.py -v
"""

import json
import unittest

from hexpath.graph import AttackGraph, GraphError


class GraphImportValidationTests(unittest.TestCase):
    def setUp(self):
        self.valid = {
            "nodes": [
                {"id": "entry:scanner", "kind": "entry", "label": "Scanner"},
                {"id": "host:2001:db8::10", "kind": "host", "label": "Host"},
            ],
            "edges": [],
        }

    def test_rejects_malformed_json(self):
        for payload in ('{', '{"nodes":', 'not json'):
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(GraphError, "invalid graph JSON"):
                    AttackGraph.from_json(payload)

    def test_rejects_non_object_document(self):
        for payload in (None, [], 4, "graph"):
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(GraphError, "graph document must be an object"):
                    AttackGraph.from_dict(payload)

    def test_requires_node_and_edge_lists(self):
        invalid = ({}, {"nodes": [], "edges": None}, {"nodes": {}, "edges": []})
        for payload in invalid:
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(GraphError, "node and edge lists"):
                    AttackGraph.from_dict(payload)

    def test_rejects_duplicate_node_ids(self):
        payload = {"nodes": [self.valid["nodes"][0], self.valid["nodes"][0]], "edges": []}
        with self.assertRaisesRegex(GraphError, "duplicate node identifiers"):
            AttackGraph.from_dict(payload)

    def test_rejects_edges_referencing_unknown_nodes(self):
        edge = {
            "id": "edge:1", "source": "unknown", "target": "host:2001:db8::10",
            "relationship": "transition", "weight": 1,
            "description": "Imported edge", "evidence": [
                {"source": "unit-test", "summary": "Test observation",
                 "level": "observed", "collected_at": "2026-10-22T12:00:00+00:00",
                 "reference": "test-fixture"}
            ],
        }
        payload = {**self.valid, "edges": [edge]}
        with self.assertRaisesRegex(GraphError, "unknown source"):
            AttackGraph.from_dict(payload)

    def test_rejects_missing_edge_evidence(self):
        payload = {**self.valid, "edges": [{
            "id": "edge:1", "source": "entry:scanner", "target": "host:2001:db8::10",
            "relationship": "transition", "weight": 1,
            "description": "Unsubstantiated edge", "evidence": [],
        }]}
        with self.assertRaisesRegex(GraphError, "supporting evidence"):
            AttackGraph.from_dict(payload)

    def test_rejects_invalid_node_metadata(self):
        payload = {"nodes": [{**self.valid["nodes"][0], "metadata": "not an object"}], "edges": []}
        with self.assertRaisesRegex(GraphError, "node metadata must be an object"):
            AttackGraph.from_dict(payload)

    def test_valid_graph_round_trips(self):
        imported = AttackGraph.from_json(json.dumps(self.valid))
        restored = AttackGraph.from_json(imported.to_json())
        self.assertEqual(imported.to_dict(), restored.to_dict())


if __name__ == "__main__":
    unittest.main()

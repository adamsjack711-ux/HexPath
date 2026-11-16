"""Protocol-confirmed MongoDB identities must remain attributable and scoped."""

from __future__ import annotations

from copy import deepcopy
import unittest

from hexpath.scope import Scope
from hexpath.version_evidence import confirm_mongodb_build_info


class MongoVersionEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scope = Scope.from_dict({"name": "lab", "targets": ["2001:db8:1::/64"]})
        self.scan = {
            "hosts": [{"id": "host:2001:db8:1::10", "address": "2001:db8:1::10", "evidence": []}],
            "services": [{
                "id": "service:[2001:db8:1::10]:tcp:27017", "host": "2001:db8:1::10",
                "port": 27017, "protocol": "tcp", "state": "open", "name": "mongodb",
                "product": "MongoDB", "version": "6.1 or later",
                "cpes": ["cpe:/a:mongodb:mongodb"],
                "evidence": [{"source": "nmap", "level": "observed", "summary": "open"}],
            }],
        }
        self.row = {
            "ip": "2001:db8:1::10",
            "data": {"mongodb": {
                "status": "success", "protocol": "mongodb", "port": 27017,
                "timestamp": "2026-11-15T22:06:59Z",
                "result": {"build_info": {"version": "6.0.28"}},
            }},
        }

    def test_confirms_exact_version_without_overwriting_raw_scan(self) -> None:
        merged = confirm_mongodb_build_info(
            self.scope, self.scan, [self.row], reference="mongo.jsonl",
        )
        service = merged["services"][0]
        self.assertEqual(service["version"], "6.0.28")
        self.assertEqual(service["cpes"], ["cpe:/a:mongodb:mongodb:6.0.28"])
        self.assertEqual(service["original_identity"]["version"], "6.1 or later")
        self.assertEqual(service["evidence"][0]["source"], "nmap")
        self.assertEqual(service["evidence"][1]["reference"], "mongo.jsonl#record-1")
        self.assertEqual(self.scan["services"][0]["version"], "6.1 or later")

    def test_rejects_unscoped_or_unmatched_results(self) -> None:
        for change in (
            {"ip": "2001:db8:2::10"},
            {"ip": "2001:db8:1::11"},
            {"data": {"mongodb": {**self.row["data"]["mongodb"], "status": "unknown"}}},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                confirm_mongodb_build_info(
                    self.scope, self.scan, [{**self.row, **change}], reference="mongo.jsonl",
                )

    def test_rejects_conflicting_precise_identity_and_duplicate_probe(self) -> None:
        scan = deepcopy(self.scan)
        scan["services"][0]["cpes"] = ["cpe:/a:mongodb:mongodb:7.0.0"]
        with self.assertRaisesRegex(ValueError, "conflicting precise CPE"):
            confirm_mongodb_build_info(self.scope, scan, [self.row], reference="mongo.jsonl")
        with self.assertRaisesRegex(ValueError, "repeats MongoDB service"):
            confirm_mongodb_build_info(
                self.scope, self.scan, [self.row, self.row], reference="mongo.jsonl",
            )


if __name__ == "__main__":
    unittest.main()

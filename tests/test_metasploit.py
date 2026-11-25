"""Tests for installed Metasploit module metadata lookup."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hexpath.metasploit import find_module_metadata, load_module_index


class MetasploitMetadataTests(unittest.TestCase):
    def test_finds_installed_framework_and_indexes_exact_cve_references(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            metadata = Path(directory) / "db" / "modules_metadata_base.json"
            metadata.parent.mkdir()
            metadata.write_text(json.dumps({
                "exploit/multi/second": {
                    "fullname": "exploit/multi/second", "name": "Second", "type": "exploit",
                    "rank": 300, "references": ["CVE-2024-6387", "CVE-2024-6387"],
                },
                "auxiliary/scanner/first": {
                    "fullname": "auxiliary/scanner/first", "name": "First", "type": "auxiliary",
                    "rank": 500, "references": ["cve-2024-6387", "URL-CVE-2024-9999"],
                },
            }), encoding="utf-8")
            with patch.dict(os.environ, {"MSF_ROOT": directory}):
                selected = find_module_metadata()
            self.assertEqual(selected, metadata)
            self.assertEqual(find_module_metadata(directory), metadata)
            index = load_module_index(metadata)
            self.assertEqual(
                [item["fullname"] for item in index["CVE-2024-6387"]],
                ["auxiliary/scanner/first", "exploit/multi/second"],
            )
            self.assertNotIn("CVE-2024-9999", index)

    def test_explicit_missing_database_reports_error(self) -> None:
        with self.assertRaisesRegex(ValueError, "Metasploit module metadata not found"):
            find_module_metadata("/nonexistent/metasploit/modules_metadata_base.json")

"""Tests for HexPath scope validation."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from hexpath.scope import Scope, ScopeError, TargetOutsideScopeError


class ScopeTests(unittest.TestCase):
    def test_accepts_address_inside_authorized_network(self) -> None:
        scope = Scope.from_dict(
            {"name": "test lab", "targets": ["2001:db8:1::/64"]}
        )

        address = scope.require_authorized("2001:db8:1::42")

        self.assertEqual(str(address), "2001:db8:1::42")

    def test_rejects_address_outside_authorized_network(self) -> None:
        scope = Scope.from_dict(
            {"name": "test lab", "targets": ["2001:db8:1::/64"]}
        )

        with self.assertRaises(TargetOutsideScopeError):
            scope.require_authorized("2001:db8:2::42")

    def test_accepts_ipv4_scope_and_address(self) -> None:
        scope = Scope.from_dict(
            {"name": "test lab", "targets": ["192.0.2.0/24"]}
        )

        address = scope.require_authorized("192.0.2.42")

        self.assertEqual(str(address), "192.0.2.42")

    def test_accepts_mixed_ipv4_and_ipv6_scope(self) -> None:
        scope = Scope.from_dict(
            {
                "name": "dual-stack lab",
                "targets": ["192.0.2.0/24", "2001:db8:1::/64"],
            }
        )

        self.assertEqual(scope.require_authorized("192.0.2.10").version, 4)
        self.assertEqual(scope.require_authorized("2001:db8:1::10").version, 6)
        with self.assertRaises(TargetOutsideScopeError):
            scope.require_authorized("198.51.100.10")

    def test_rejects_network_with_host_bits_set(self) -> None:
        with self.assertRaisesRegex(ScopeError, "host bits set"):
            Scope.from_dict(
                {"name": "test lab", "targets": ["2001:db8:1::1/64"]}
            )

    def test_loads_json_scope_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            scope_path = Path(directory) / "scope.json"
            scope_path.write_text(
                json.dumps({"name": "test lab", "targets": ["fd00:1234::/64"]}),
                encoding="utf-8",
            )

            scope = Scope.from_json_file(scope_path)

        self.assertEqual(scope.name, "test lab")
        self.assertEqual(str(scope.networks[0]), "fd00:1234::/64")

    def test_accepts_target_subnet_contained_by_scope(self) -> None:
        scope = Scope.from_dict(
            {"name": "test lab", "targets": ["2001:db8:1::/64"]}
        )

        network = scope.require_authorized_network("2001:db8:1::/80")

        self.assertEqual(str(network), "2001:db8:1::/80")

    def test_rejects_target_subnet_broader_than_scope(self) -> None:
        scope = Scope.from_dict(
            {"name": "test lab", "targets": ["2001:db8:1::/64"]}
        )

        with self.assertRaises(TargetOutsideScopeError):
            scope.require_authorized_network("2001:db8::/32")

    def test_accepts_ipv4_subnet_contained_by_scope(self) -> None:
        scope = Scope.from_dict(
            {"name": "test lab", "targets": ["192.0.2.0/24"]}
        )

        network = scope.require_authorized_network("192.0.2.128/25")

        self.assertEqual(str(network), "192.0.2.128/25")

    def test_rejects_ipv4_subnet_broader_than_scope(self) -> None:
        scope = Scope.from_dict(
            {"name": "test lab", "targets": ["192.0.2.0/24"]}
        )

        with self.assertRaises(TargetOutsideScopeError):
            scope.require_authorized_network("192.0.0.0/16")


if __name__ == "__main__":
    unittest.main()

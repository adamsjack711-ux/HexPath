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

    def test_rejects_ipv4_scope(self) -> None:
        with self.assertRaisesRegex(ScopeError, "IPv4"):
            Scope.from_dict({"name": "test lab", "targets": ["192.0.2.0/24"]})

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


class ScopeSafetyTests(unittest.TestCase):
    def test_rejects_entire_internet(self) -> None:
        for target in ("::/0", "2000::/3", "2001:db8::/32"):
            with self.subTest(target=target):
                with self.assertRaisesRegex(ScopeError, "too broad"):
                    Scope.from_dict({"name": "oops", "targets": [target]})

    def test_rejects_multicast_range(self) -> None:
        with self.assertRaisesRegex(ScopeError, "multicast"):
            Scope.from_dict({"name": "oops", "targets": ["ff02::1/128"]})

    def test_rejects_loopback_and_unspecified(self) -> None:
        with self.assertRaisesRegex(ScopeError, "loopback"):
            Scope.from_dict({"name": "oops", "targets": ["::1/128"]})
        with self.assertRaisesRegex(ScopeError, "unspecified"):
            Scope.from_dict({"name": "oops", "targets": ["::/128"]})

    def test_rejects_link_local_even_when_narrow(self) -> None:
        with self.assertRaisesRegex(ScopeError, "link-local"):
            Scope.from_dict({"name": "oops", "targets": ["fe80::/64"]})

    def test_rejects_ipv4_mapped_range(self) -> None:
        with self.assertRaisesRegex(ScopeError, "IPv4-mapped"):
            Scope.from_dict({"name": "oops", "targets": ["::ffff:0:0/96"]})

    def test_accepts_a_single_host_and_a_normal_subnet(self) -> None:
        scope = Scope.from_dict(
            {
                "name": "lab vm",
                "targets": ["2001:db8:1::10/128", "fd00:1234:5678::/64"],
            }
        )

        self.assertEqual(len(scope.networks), 2)

    def test_override_allows_a_deliberately_wider_scope(self) -> None:
        scope = Scope.from_dict(
            {"name": "site", "targets": ["2001:db8::/32"]},
            minimum_prefix_length=32,
        )

        self.assertEqual(str(scope.networks[0]), "2001:db8::/32")

    def test_special_use_still_rejected_under_a_loose_override(self) -> None:
        with self.assertRaisesRegex(ScopeError, "multicast"):
            Scope.from_dict(
                {"name": "oops", "targets": ["ff00::/8"]},
                minimum_prefix_length=0,
            )

    def test_rejects_invalid_minimum_prefix_length(self) -> None:
        with self.assertRaisesRegex(ScopeError, "minimum_prefix_length"):
            Scope.from_dict(
                {"name": "lab", "targets": ["2001:db8:1::/64"]},
                minimum_prefix_length=200,
            )


if __name__ == "__main__":
    unittest.main()

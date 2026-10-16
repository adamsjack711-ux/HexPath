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


class ScopeSafetyTests(unittest.TestCase):
    def test_rejects_entire_internet(self) -> None:
        for target in (
            "0.0.0.0/0",
            "10.0.0.0/8",
            "192.0.0.0/16",
            "::/0",
            "2000::/3",
            "2001:db8::/32",
        ):
            with self.subTest(target=target):
                with self.assertRaisesRegex(ScopeError, "too broad"):
                    Scope.from_dict({"name": "oops", "targets": [target]})

    def test_rejects_multicast_range(self) -> None:
        for target in ("224.0.0.0/24", "ff02::1/128"):
            with self.subTest(target=target), self.assertRaisesRegex(
                ScopeError, "multicast"
            ):
                Scope.from_dict({"name": "oops", "targets": [target]})

    def test_rejects_loopback_and_unspecified(self) -> None:
        for target in ("127.0.0.1/32", "::1/128"):
            with self.subTest(target=target), self.assertRaisesRegex(
                ScopeError, "loopback"
            ):
                Scope.from_dict({"name": "oops", "targets": [target]})
        for target in ("0.0.0.0/32", "::/128"):
            with self.subTest(target=target), self.assertRaisesRegex(
                ScopeError, "unspecified"
            ):
                Scope.from_dict({"name": "oops", "targets": [target]})

    def test_rejects_link_local_even_when_narrow(self) -> None:
        for target in ("169.254.1.0/24", "fe80::/64"):
            with self.subTest(target=target), self.assertRaisesRegex(
                ScopeError, "link-local"
            ):
                Scope.from_dict({"name": "oops", "targets": [target]})

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
        ipv6_scope = Scope.from_dict(
            {"name": "site", "targets": ["2001:db8::/32"]},
            minimum_prefix_length=32,
        )
        ipv4_scope = Scope.from_dict(
            {"name": "site", "targets": ["10.20.0.0/16"]},
            minimum_ipv4_prefix_length=16,
        )

        self.assertEqual(str(ipv6_scope.networks[0]), "2001:db8::/32")
        self.assertEqual(str(ipv4_scope.networks[0]), "10.20.0.0/16")

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
        with self.assertRaisesRegex(ScopeError, "minimum_ipv4_prefix_length"):
            Scope.from_dict(
                {"name": "lab", "targets": ["192.0.2.0/24"]},
                minimum_ipv4_prefix_length=40,
            )


if __name__ == "__main__":
    unittest.main()

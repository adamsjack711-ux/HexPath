"""Tests for configured SSH jump-server discovery."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hexpath.jump import JumpProfile, load_jump_profile, scan_through_jump


FIXTURE = (Path(__file__).parent / "fixtures/nmap_ipv6_sample.xml").read_text()


class JumpProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        state_environment = patch.dict(
            os.environ, {"HEXPATH_STATE_DIR": str(self.root)}
        )
        state_environment.start()
        self.addCleanup(state_environment.stop)
        self.identity = self.root / "identity"
        self.known_hosts = self.root / "known_hosts"
        self.identity.write_text("test key", encoding="utf-8")
        self.known_hosts.write_text("test host key", encoding="utf-8")
        self.scan = {
            "vantage": "entry:scanner",
            "hosts": [{"address": "192.0.2.10"}],
            "services": [],
        }

    def write_profile(self, entry_host: str = "192.0.2.10") -> None:
        (self.root / "jump-profile.json").write_text(
            json.dumps({
                "entry_host": entry_host,
                "user": "root",
                "identity_file": str(self.identity),
                "known_hosts_file": str(self.known_hosts),
                "targets": ["2001:db8:1::/120"],
                "ports": "22,80",
                "timeout_seconds": 60,
            }),
            encoding="utf-8",
        )

    def test_loads_only_when_the_latest_scan_contains_the_entry_server(self) -> None:
        self.write_profile()

        profile = load_jump_profile(self.scan)

        self.assertIsNotNone(profile)
        self.assertEqual(profile.entry_host, "192.0.2.10")
        self.assertEqual(profile.targets, ("2001:db8:1::/120",))
        self.write_profile("192.0.2.11")
        self.assertIsNone(load_jump_profile(self.scan))

    @patch("hexpath.jump.subprocess.run")
    def test_internal_scan_is_strict_ssh_and_records_the_jump_vantage(
        self, run_mock
    ) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=FIXTURE, stderr=""
        )
        profile = JumpProfile(
            entry_host="192.0.2.10",
            user="root",
            identity_file=self.identity,
            known_hosts_file=self.known_hosts,
            targets=("2001:db8:1::/125",),
            ports="22,80",
            timeout_seconds=60,
        )

        merged = scan_through_jump(self.scan, profile)

        command = run_mock.call_args.args[0]
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertIn("UserKnownHostsFile=" + str(self.known_hosts), command)
        self.assertIn("root@192.0.2.10", command)
        self.assertIn("-6", command[-1])
        self.assertEqual(merged["jump_scan"]["observed_hosts"], 1)
        self.assertEqual(
            merged["jump_scan"]["scan"]["vantage"], "host:192.0.2.10"
        )
        self.assertEqual(merged["services"], [])


if __name__ == "__main__":
    unittest.main()

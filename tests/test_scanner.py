"""Tests for HexPath's scope-safe Nmap integration."""

from __future__ import annotations

from pathlib import Path
import json
import subprocess
import unittest
from unittest.mock import patch

from hexpath.models import EvidenceLevel, ServiceState
from hexpath.scanner import (
    NmapCommand,
    NmapExecutionError,
    NmapParseError,
    ScanProfile,
    ScannerError,
    build_nmap_command,
    parse_nmap_xml,
    require_authorized_vantage,
    run_nmap,
)
from hexpath.scope import Scope, TargetOutsideScopeError


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "nmap_ipv6_sample.xml"


class NmapCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scope = Scope.from_dict(
            {"name": "test lab", "targets": ["2001:db8:1::/64"]}
        )

    def test_builds_conservative_discovery_command(self) -> None:
        command = build_nmap_command(
            self.scope,
            ["2001:db8:1::10"],
            ScanProfile.DISCOVERY,
        )

        self.assertEqual(
            command.arguments,
            (
                "nmap",
                "-6",
                "-n",
                "--reason",
                "-oX",
                "-",
                "-sn",
                "2001:db8:1::10/128",
            ),
        )

    def test_accepts_subnet_contained_by_scope(self) -> None:
        command = build_nmap_command(
            self.scope,
            ["2001:db8:1:0::/80"],
            ScanProfile.SERVICES,
        )

        self.assertEqual(command.targets, ("2001:db8:1::/80",))
        self.assertIn("--version-light", command.arguments)

    def test_can_skip_host_discovery_for_filtered_targets(self) -> None:
        command = build_nmap_command(
            self.scope,
            ["2001:db8:1::10"],
            ScanProfile.SERVICES,
            skip_discovery=True,
        )

        self.assertIn("-Pn", command.arguments)
        self.assertIn("-sV", command.arguments)

    def test_accepts_nmap_style_service_port_selection(self) -> None:
        command = build_nmap_command(
            self.scope,
            ["2001:db8:1::10"],
            ScanProfile.SERVICES,
            ports="22,80,443,8000-8100",
        )

        port_index = command.arguments.index("-p")
        self.assertEqual(command.arguments[port_index + 1], "22,80,443,8000-8100")

    def test_rejects_invalid_port_selection(self) -> None:
        with self.assertRaisesRegex(ScannerError, "ports"):
            build_nmap_command(
                self.scope,
                ["2001:db8:1::10"],
                ScanProfile.SERVICES,
                ports="--script=unsafe",
            )

    def test_rejects_target_that_is_broader_than_scope(self) -> None:
        with self.assertRaises(TargetOutsideScopeError):
            build_nmap_command(
                self.scope,
                ["2001:db8::/32"],
                ScanProfile.DISCOVERY,
            )

    def test_accepts_authorized_host_as_scan_vantage(self) -> None:
        vantage = require_authorized_vantage(
            self.scope,
            "host:2001:db8:1::10",
        )

        self.assertEqual(vantage, "host:2001:db8:1::10")

    def test_rejects_out_of_scope_scan_vantage(self) -> None:
        with self.assertRaisesRegex(ScannerError, "invalid scan vantage"):
            require_authorized_vantage(self.scope, "host:2001:db8:2::10")


class NmapRunnerTests(unittest.TestCase):
    @patch("hexpath.scanner.shutil.which", return_value="/usr/bin/nmap")
    @patch("hexpath.scanner.subprocess.run")
    def test_executes_argument_tuple_without_shell(
        self,
        run_mock,
        _which_mock,
    ) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            args=("nmap",),
            returncode=0,
            stdout="<nmaprun/>",
            stderr="",
        )
        command = NmapCommand(
            arguments=("nmap", "-6", "-sn", "::1"),
            targets=("::1/128",),
            profile=ScanProfile.DISCOVERY,
        )

        output = run_nmap(command, timeout_seconds=30)

        self.assertEqual(output, "<nmaprun/>")
        run_mock.assert_called_once_with(
            command.arguments,
            capture_output=True,
            check=False,
            text=True,
            timeout=30,
        )

    @patch("hexpath.scanner.shutil.which", return_value="/usr/bin/nmap")
    @patch("hexpath.scanner.subprocess.run")
    def test_reports_nmap_failure(self, run_mock, _which_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            args=("nmap",),
            returncode=1,
            stdout="",
            stderr="bad target",
        )
        command = NmapCommand(
            arguments=("nmap", "-6", "-sn", "::1"),
            targets=("::1/128",),
            profile=ScanProfile.DISCOVERY,
        )

        with self.assertRaisesRegex(NmapExecutionError, "bad target"):
            run_nmap(command)


class NmapXmlParserTests(unittest.TestCase):
    def test_parses_up_ipv6_hosts_and_relevant_services(self) -> None:
        result = parse_nmap_xml(
            FIXTURE_PATH.read_text(encoding="utf-8"),
            reference="fixture.xml",
        )

        self.assertEqual(len(result.hosts), 1)
        self.assertEqual(str(result.hosts[0].address), "2001:db8:1::10")
        self.assertEqual(result.hosts[0].hostnames, ("server.lab",))
        self.assertEqual(result.hosts[0].evidence[0].level, EvidenceLevel.OBSERVED)
        self.assertEqual(len(result.services), 2)
        self.assertEqual(result.services[0].port, 22)
        self.assertEqual(result.services[0].product, "OpenSSH")
        self.assertEqual(result.services[0].version, "9.6")
        self.assertEqual(
            result.services[0].cpes,
            ("cpe:/a:openbsd:openssh:9.6",),
        )
        self.assertEqual(result.services[1].state, ServiceState.OPEN_FILTERED)

        document = json.loads(result.to_json())
        self.assertEqual(document["vantage"], "entry:scanner")
        self.assertEqual(document["hosts"][0]["hostnames"], ["server.lab"])
        self.assertEqual(document["services"][0]["protocol"], "tcp")

    def test_rejects_malformed_xml(self) -> None:
        with self.assertRaisesRegex(NmapParseError, "invalid Nmap XML"):
            parse_nmap_xml("<nmaprun>")

    def test_rejects_non_nmap_document(self) -> None:
        with self.assertRaisesRegex(NmapParseError, "nmaprun"):
            parse_nmap_xml("<report/>")

    def test_preserves_filtered_service_in_complete_topology(self) -> None:
        result = parse_nmap_xml(
            """<nmaprun start="1791509400">
            <host>
              <status state="up" reason="user-set"/>
              <address addr="2001:db8::10" addrtype="ipv6"/>
              <ports>
                <port protocol="tcp" portid="22">
                  <state state="filtered" reason="no-response"/>
                  <service name="ssh"/>
                </port>
              </ports>
            </host>
            </nmaprun>"""
        )

        self.assertEqual(len(result.services), 1)
        self.assertEqual(result.services[0].port, 22)
        self.assertEqual(result.services[0].state, ServiceState.FILTERED)


if __name__ == "__main__":
    unittest.main()

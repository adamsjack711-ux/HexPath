"""Tests for HexPath's scope-safe Nmap integration."""

from __future__ import annotations

from pathlib import Path
import json
import subprocess
import tempfile
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
    resolve_nmap_executable,
    run_nmap,
    scan_levels_document,
    scan_profile_for_level,
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

    def test_os_fingerprint_uses_only_the_best_match_cpes(self) -> None:
        # Nmap lists osmatch candidates highest-accuracy first. Only the best
        # one's CPEs should be kept, not a mix from every lower guess.
        result = parse_nmap_xml(
            """<nmaprun start="1791509400"><host>
              <status state="up" reason="arp-response"/>
              <address addr="192.0.2.23" addrtype="ipv4"/>
              <os>
                <osmatch name="Microsoft Windows 10 1909" accuracy="96">
                  <osclass><cpe>cpe:/o:microsoft:windows_10</cpe></osclass>
                </osmatch>
                <osmatch name="Microsoft Windows Server 2019" accuracy="88">
                  <osclass><cpe>cpe:/o:microsoft:windows_server_2019</cpe></osclass>
                </osmatch>
              </os>
            </host></nmaprun>""",
        )
        host = result.hosts[0]
        self.assertEqual(host.os_name, "Microsoft Windows 10 1909")
        self.assertEqual(host.cpes, ("cpe:/o:microsoft:windows_10",))

    def test_os_detection_flag_appends_capital_o(self) -> None:
        command = build_nmap_command(
            self.scope,
            ["2001:db8:1::10/128"],
            ScanProfile.SERVICES,
            skip_discovery=True,
            os_detection=True,
        )
        self.assertIn("-O", command.arguments)

    def test_os_detection_rejected_for_discovery_profile(self) -> None:
        with self.assertRaisesRegex(ScannerError, "OS detection"):
            build_nmap_command(
                self.scope,
                ["2001:db8:1::10/128"],
                ScanProfile.DISCOVERY,
                os_detection=True,
            )

    def test_can_skip_discovery_for_filtered_targets(self) -> None:
        command = build_nmap_command(
            self.scope,
            ["2001:db8:1::10"],
            ScanProfile.SERVICES,
            skip_discovery=True,
        )

        self.assertIn("-Pn", command.arguments)
        self.assertIn("-sV", command.arguments)

    def test_accepts_numeric_service_port_selection(self) -> None:
        command = build_nmap_command(
            self.scope,
            ["2001:db8:1::10"],
            ScanProfile.SERVICES,
            ports="22,80,443,8000-8100",
        )

        port_index = command.arguments.index("-p")
        self.assertEqual(command.arguments[port_index + 1], "22,80,443,8000-8100")

    def test_rejects_custom_ports_for_fixed_scan_profiles(self) -> None:
        for profile in (
            ScanProfile.DISCOVERY,
            ScanProfile.QUICK,
            ScanProfile.FULL,
            ScanProfile.DEEP,
        ):
            with self.subTest(profile=profile), self.assertRaisesRegex(
                ScannerError,
                "services profile",
            ):
                build_nmap_command(
                    self.scope,
                    ["2001:db8:1::10"],
                    profile,
                    ports="22",
                )

    def test_rejects_invalid_port_selection(self) -> None:
        cases = (
            ("--script=unsafe", "numbers or ranges"),
            ("22-", "invalid port range"),
            ("22--80", "invalid port range"),
            ("22,,80", "empty entries"),
            ("0", "between 1 and 65535"),
            ("65536", "between 1 and 65535"),
            ("443-80", "descending"),
        )
        for ports, message in cases:
            with self.subTest(ports=ports), self.assertRaisesRegex(
                ScannerError,
                message,
            ):
                build_nmap_command(
                    self.scope,
                    ["2001:db8:1::10"],
                    ScanProfile.SERVICES,
                    ports=ports,
                )

    def test_information_levels_map_to_fixed_scan_profiles(self) -> None:
        expected = {
            0: (ScanProfile.DISCOVERY, ("-sn",)),
            1: (ScanProfile.QUICK, ("-sT", "--top-ports", "100")),
            2: (ScanProfile.SERVICES, ("-sT", "-sV", "--version-light")),
            3: (ScanProfile.FULL, ("-sT", "-sV", "--version-light", "-p-")),
            4: (ScanProfile.DEEP, ("-sT", "-sV", "--version-all", "-p-")),
        }

        for level, (profile, profile_arguments) in expected.items():
            with self.subTest(level=level):
                resolved = scan_profile_for_level(level)
                command = build_nmap_command(
                    self.scope,
                    ["2001:db8:1::10"],
                    resolved,
                )
                self.assertEqual(resolved, profile)
                self.assertEqual(
                    command.arguments[6:-1],
                    profile_arguments,
                )

    def test_scan_level_catalog_and_validation(self) -> None:
        document = scan_levels_document()

        self.assertEqual(
            [item["level"] for item in document["levels"]],
            [0, 1, 2, 3, 4],
        )
        self.assertEqual(document["levels"][0]["wait"], "fastest")
        self.assertEqual(document["levels"][-1]["wait"], "longest")
        for invalid in (-1, 5, True, "2"):
            with self.subTest(invalid=invalid), self.assertRaises(ScannerError):
                scan_profile_for_level(invalid)

    def test_builds_ipv4_command_without_ipv6_switch(self) -> None:
        scope = Scope.from_dict(
            {"name": "IPv4 lab", "targets": ["192.0.2.0/24"]}
        )

        command = build_nmap_command(
            scope,
            ["192.0.2.10"],
            ScanProfile.DISCOVERY,
        )

        self.assertEqual(command.targets, ("192.0.2.10/32",))
        self.assertEqual(command.ip_version, 4)
        self.assertNotIn("-6", command.arguments)
        self.assertEqual(command.arguments[-2:], ("-sn", "192.0.2.10/32"))

    def test_rejects_mixed_address_families_in_one_scan(self) -> None:
        scope = Scope.from_dict(
            {
                "name": "dual-stack lab",
                "targets": ["192.0.2.0/24", "2001:db8:1::/64"],
            }
        )

        with self.assertRaisesRegex(ScannerError, "cannot mix IPv4 and IPv6"):
            build_nmap_command(
                scope,
                ["192.0.2.10", "2001:db8:1::10"],
                ScanProfile.DISCOVERY,
            )

    def test_rejects_explicit_address_family_mismatch(self) -> None:
        scope = Scope.from_dict(
            {"name": "IPv4 lab", "targets": ["192.0.2.0/24"]}
        )

        with self.assertRaisesRegex(ScannerError, "requested IPv6"):
            build_nmap_command(
                scope,
                ["192.0.2.10"],
                ScanProfile.DISCOVERY,
                ip_version=6,
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

    def test_accepts_authorized_ipv4_scan_vantage(self) -> None:
        scope = Scope.from_dict(
            {"name": "IPv4 lab", "targets": ["192.0.2.0/24"]}
        )

        vantage = require_authorized_vantage(scope, "host:192.0.2.10")

        self.assertEqual(vantage, "host:192.0.2.10")


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
            ("/usr/bin/nmap", *command.arguments[1:]),
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

    @patch("hexpath.scanner.shutil.which", return_value=None)
    def test_finds_standard_windows_nmap_install(
        self,
        _which_mock,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            program_files = Path(directory) / "Program Files"
            program_files_x86 = Path(directory) / "Program Files (x86)"
            installed_nmap = program_files_x86 / "Nmap" / "nmap.exe"
            installed_nmap.parent.mkdir(parents=True)
            installed_nmap.touch()

            resolved = resolve_nmap_executable(
                platform_name="nt",
                environ={
                    "ProgramFiles": str(program_files),
                    "ProgramFiles(x86)": str(program_files_x86),
                },
            )

        self.assertEqual(resolved, str(installed_nmap))

    @patch("hexpath.scanner.Path.is_file", return_value=False)
    @patch("hexpath.scanner.shutil.which", return_value=None)
    def test_returns_none_when_windows_nmap_is_not_installed(
        self,
        _which_mock,
        _is_file_mock,
    ) -> None:
        self.assertIsNone(
            resolve_nmap_executable(
                platform_name="nt",
                environ={"ProgramFiles": "C:/Program Files"},
            )
        )


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

    def test_parses_ipv4_host_and_service(self) -> None:
        result = parse_nmap_xml(
            """<nmaprun start="1791509400">
            <host>
              <status state="up" reason="syn-ack"/>
              <address addr="192.0.2.10" addrtype="ipv4"/>
              <hostnames><hostname name="web.lab"/></hostnames>
              <ports>
                <port protocol="tcp" portid="443">
                  <state state="open" reason="syn-ack"/>
                  <service name="https" product="nginx" version="1.26"/>
                </port>
              </ports>
            </host>
            </nmaprun>""",
            reference="ipv4-fixture.xml",
        )

        self.assertEqual(result.hosts[0].record_id, "host:192.0.2.10")
        self.assertEqual(result.hosts[0].hostnames, ("web.lab",))
        self.assertEqual(
            result.services[0].record_id,
            "service:[192.0.2.10]:tcp:443",
        )

    def test_parses_os_fingerprint_into_host_cpes(self) -> None:
        result = parse_nmap_xml(
            """<nmaprun start="1791509400">
            <host>
              <status state="up" reason="arp-response"/>
              <address addr="192.0.2.20" addrtype="ipv4"/>
              <ports>
                <port protocol="tcp" portid="445">
                  <state state="open" reason="syn-ack"/>
                  <service name="microsoft-ds"/>
                </port>
              </ports>
              <os>
                <osmatch name="Microsoft Windows XP SP3" accuracy="98">
                  <osclass vendor="Microsoft" osfamily="Windows">
                    <cpe>cpe:/o:microsoft:windows_xp</cpe>
                  </osclass>
                </osmatch>
              </os>
            </host>
            </nmaprun>""",
            reference="os-fixture.xml",
        )

        host = result.hosts[0]
        self.assertEqual(host.os_name, "Microsoft Windows XP SP3")
        self.assertEqual(host.cpes, ("cpe:/o:microsoft:windows_xp",))

    def test_os_parsing_ignores_non_os_cpes_and_absent_block(self) -> None:
        with_hardware = parse_nmap_xml(
            """<nmaprun start="1791509400"><host>
              <status state="up" reason="arp-response"/>
              <address addr="192.0.2.21" addrtype="ipv4"/>
              <os><osmatch name="Some Router" accuracy="90">
                <osclass><cpe>cpe:/h:vendor:router</cpe>
                <cpe>cpe:/o:vendor:router_os</cpe></osclass>
              </osmatch></os>
            </host></nmaprun>""",
        )
        self.assertEqual(with_hardware.hosts[0].cpes, ("cpe:/o:vendor:router_os",))

        without_os = parse_nmap_xml(
            """<nmaprun start="1791509400"><host>
              <status state="up" reason="arp-response"/>
              <address addr="192.0.2.22" addrtype="ipv4"/>
            </host></nmaprun>""",
        )
        self.assertIsNone(without_os.hosts[0].os_name)
        self.assertEqual(without_os.hosts[0].cpes, ())

    def test_rejects_address_family_mislabeled_in_xml(self) -> None:
        with self.assertRaisesRegex(NmapParseError, "marked IPV4 is not IPV4"):
            parse_nmap_xml(
                """<nmaprun><host><status state="up"/>
                <address addr="2001:db8::10" addrtype="ipv4"/>
                </host></nmaprun>"""
            )

    def test_rejects_malformed_xml(self) -> None:
        with self.assertRaisesRegex(NmapParseError, "invalid Nmap XML"):
            parse_nmap_xml("<nmaprun>")

    def test_rejects_non_nmap_document(self) -> None:
        with self.assertRaisesRegex(NmapParseError, "nmaprun"):
            parse_nmap_xml("<report/>")


class ExcludeTargetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scope = Scope.from_dict(
            {"name": "lab", "targets": ["192.168.56.0/24"]}
        )

    def test_exclude_adds_nmap_exclude_argument(self) -> None:
        command = build_nmap_command(
            self.scope, ["192.168.56.0/24"], ScanProfile.SERVICES,
            exclude=("192.168.56.103", "192.168.56.1"),
        )
        self.assertIn("--exclude", command.arguments)
        value = command.arguments[command.arguments.index("--exclude") + 1]
        self.assertEqual(value, "192.168.56.103,192.168.56.1")
        # The exclude list precedes the scan targets.
        self.assertLess(
            command.arguments.index("--exclude"),
            command.arguments.index("192.168.56.0/24"),
        )

    def test_no_exclude_argument_by_default(self) -> None:
        command = build_nmap_command(
            self.scope, ["192.168.56.0/24"], ScanProfile.SERVICES
        )
        self.assertNotIn("--exclude", command.arguments)

    def test_blank_exclude_entries_are_ignored(self) -> None:
        command = build_nmap_command(
            self.scope, ["192.168.56.0/24"], ScanProfile.SERVICES, exclude=("", "  "),
        )
        self.assertNotIn("--exclude", command.arguments)

    def test_invalid_exclude_is_rejected(self) -> None:
        with self.assertRaisesRegex(ScannerError, "invalid exclude target"):
            build_nmap_command(
                self.scope, ["192.168.56.0/24"], ScanProfile.SERVICES,
                exclude=("not-an-ip",),
            )

    def test_cidr_exclude_is_accepted(self) -> None:
        command = build_nmap_command(
            self.scope, ["192.168.56.0/24"], ScanProfile.SERVICES,
            exclude=("192.168.56.100/30",),
        )
        self.assertIn("192.168.56.100/30", command.arguments)


class SmbVulnScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scope = Scope.from_dict(
            {"name": "windows lab", "targets": ["192.168.56.0/24"]}
        )

    def test_vuln_scripts_add_safe_smb_checks(self) -> None:
        command = build_nmap_command(
            self.scope,
            ["192.168.56.101"],
            ScanProfile.SERVICES,
            skip_discovery=True,
            vuln_scripts=True,
        )
        self.assertIn("--script", command.arguments)
        script_argument = command.arguments[command.arguments.index("--script") + 1]
        names = script_argument.split(",")
        self.assertIn("smb-vuln-ms17-010", names)
        self.assertIn("smb-vuln-ms08-067", names)
        self.assertIn("smb-double-pulsar-backdoor", names)

    def test_vuln_scripts_omitted_by_default(self) -> None:
        command = build_nmap_command(
            self.scope, ["192.168.56.101"], ScanProfile.SERVICES
        )
        self.assertNotIn("--script", command.arguments)

    def test_vuln_scripts_rejected_with_discovery(self) -> None:
        with self.assertRaisesRegex(ScannerError, "vulnerability scripts"):
            build_nmap_command(
                self.scope,
                ["192.168.56.101"],
                ScanProfile.DISCOVERY,
                vuln_scripts=True,
            )

    def test_all_vuln_runs_full_set_and_scans_ports(self) -> None:
        command = build_nmap_command(
            self.scope, ["192.168.56.0/24"], ScanProfile.SERVICES,
            skip_discovery=True, all_vuln=True,
        )
        names = command.arguments[command.arguments.index("--script") + 1].split(",")
        self.assertIn("smb-vuln-ms17-010", names)
        self.assertIn("http-vuln-cve2017-12617", names)
        self.assertIn("ftp-vsftpd-backdoor", names)
        # web/ftp ports are scanned so the scripts can reach those services
        ports = command.arguments[command.arguments.index("-p") + 1]
        self.assertIn("8080", ports.split(","))
        self.assertIn("21", ports.split(","))

    def test_parses_confirmed_web_finding(self) -> None:
        xml = """<nmaprun start="1700000000">
          <host><status state="up" reason="syn-ack"/>
            <address addr="192.168.56.107" addrtype="ipv4"/>
            <ports><port protocol="tcp" portid="8080">
              <state state="open" reason="syn-ack"/><service name="http"/>
              <script id="http-vuln-cve2017-12617" output="VULNERABLE: State: VULNERABLE IDs: CVE:CVE-2017-12617">
                <table key="CVE-2017-12617"><elem key="state">VULNERABLE</elem></table>
              </script>
            </port></ports>
          </host></nmaprun>"""
        finding = parse_nmap_xml(xml).script_findings[0]
        self.assertTrue(finding.confirms_vulnerable)
        self.assertEqual(finding.service_id, "service:[192.168.56.107]:tcp:8080")
        self.assertIn("CVE-2017-12617", finding.cve_ids)

    def test_parses_confirmed_ms17_010_finding(self) -> None:
        xml = """<nmaprun start="1700000000">
          <host><status state="up" reason="syn-ack"/>
            <address addr="192.168.56.101" addrtype="ipv4"/>
            <ports><port protocol="tcp" portid="445">
              <state state="open" reason="syn-ack"/>
              <service name="microsoft-ds"/>
              <script id="smb-vuln-ms17-010" output="VULNERABLE: ms17-010 State: VULNERABLE CVE:CVE-2017-0143">
                <table key="CVE-2017-0143">
                  <elem key="title">RCE in Microsoft SMBv1 servers (ms17-010)</elem>
                  <elem key="state">VULNERABLE</elem>
                </table>
              </script>
            </port></ports>
          </host></nmaprun>"""
        result = parse_nmap_xml(xml)
        self.assertEqual(len(result.script_findings), 1)
        finding = result.script_findings[0]
        self.assertTrue(finding.confirms_vulnerable)
        self.assertEqual(finding.script_id, "smb-vuln-ms17-010")
        self.assertIn("CVE-2017-0143", finding.cve_ids)
        self.assertEqual(finding.service_id, "service:[192.168.56.101]:tcp:445")
        self.assertEqual(finding.evidence[0].level, EvidenceLevel.OBSERVED)

    def test_confirmed_finding_without_ids_uses_fallback(self) -> None:
        xml = """<nmaprun start="1700000000">
          <host><status state="up" reason="syn-ack"/>
            <address addr="192.168.56.101" addrtype="ipv4"/>
            <ports><port protocol="tcp" portid="445">
              <state state="open" reason="syn-ack"/>
              <script id="smb-vuln-ms17-010" output="State: VULNERABLE"/>
            </port></ports>
          </host></nmaprun>"""
        finding = parse_nmap_xml(xml).script_findings[0]
        self.assertTrue(finding.confirms_vulnerable)
        self.assertIn("CVE-2017-0144", finding.cve_ids)

    def test_parses_host_level_hostscript_finding(self) -> None:
        # Nmap commonly reports smb-vuln-ms17-010 under <hostscript>, not the port.
        xml = """<nmaprun start="1700000000">
          <host><status state="up" reason="syn-ack"/>
            <address addr="192.168.56.111" addrtype="ipv4"/>
            <ports><port protocol="tcp" portid="445">
              <state state="open" reason="syn-ack"/><service name="microsoft-ds"/>
            </port></ports>
            <hostscript>
              <script id="smb-vuln-ms17-010" output="VULNERABLE: State: VULNERABLE IDs: CVE:CVE-2017-0143">
                <table key="CVE-2017-0143"><elem key="state">VULNERABLE</elem></table>
              </script>
            </hostscript>
          </host></nmaprun>"""
        result = parse_nmap_xml(xml)
        self.assertEqual(len(result.script_findings), 1)
        finding = result.script_findings[0]
        self.assertTrue(finding.confirms_vulnerable)
        self.assertEqual(finding.service_id, "service:[192.168.56.111]:tcp:445")
        self.assertIn("CVE-2017-0143", finding.cve_ids)

    def test_port_and_host_script_are_not_double_counted(self) -> None:
        xml = """<nmaprun start="1700000000">
          <host><status state="up" reason="syn-ack"/>
            <address addr="192.168.56.111" addrtype="ipv4"/>
            <ports><port protocol="tcp" portid="445">
              <state state="open" reason="syn-ack"/>
              <script id="smb-vuln-ms17-010" output="State: VULNERABLE"/>
            </port></ports>
            <hostscript>
              <script id="smb-vuln-ms17-010" output="State: VULNERABLE"/>
            </hostscript>
          </host></nmaprun>"""
        result = parse_nmap_xml(xml)
        self.assertEqual(len(result.script_findings), 1)

    def test_not_vulnerable_finding_is_not_confirmed(self) -> None:
        xml = """<nmaprun start="1700000000">
          <host><status state="up" reason="syn-ack"/>
            <address addr="192.168.56.101" addrtype="ipv4"/>
            <ports><port protocol="tcp" portid="445">
              <state state="open" reason="syn-ack"/>
              <script id="smb-vuln-ms17-010" output="State: NOT VULNERABLE"/>
            </port></ports>
          </host></nmaprun>"""
        finding = parse_nmap_xml(xml).script_findings[0]
        self.assertFalse(finding.confirms_vulnerable)
        self.assertEqual(finding.cve_ids, ())


if __name__ == "__main__":
    unittest.main()

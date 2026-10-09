"""Tests for native HexPath dependency setup."""

from __future__ import annotations

import subprocess
import unittest

from hexpath.setup import SetupError, nmap_install_command, setup_nmap


def completed(
    command: list[str] | tuple[str, ...],
    returncode: int = 0,
    *,
    stdout: str = "",
    stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


class NmapCommandTests(unittest.TestCase):
    def test_uses_homebrew_on_macos(self) -> None:
        command = nmap_install_command(
            system="Darwin",
            which=lambda name: "/opt/homebrew/bin/brew" if name == "brew" else None,
        )
        self.assertEqual(command, ("/opt/homebrew/bin/brew", "install", "nmap"))

    def test_uses_sudo_and_first_available_linux_manager(self) -> None:
        paths = {"apt-get": "/usr/bin/apt-get", "sudo": "/usr/bin/sudo"}
        command = nmap_install_command(
            system="Linux",
            which=paths.get,
            geteuid=lambda: 1000,
        )
        self.assertEqual(
            command,
            ("/usr/bin/sudo", "/usr/bin/apt-get", "install", "-y", "nmap"),
        )

    def test_root_linux_install_does_not_require_sudo(self) -> None:
        command = nmap_install_command(
            system="Linux",
            which=lambda name: "/sbin/apk" if name == "apk" else None,
            geteuid=lambda: 0,
        )
        self.assertEqual(command, ("/sbin/apk", "add", "nmap"))

    def test_windows_explains_npcap_manual_install(self) -> None:
        with self.assertRaisesRegex(SetupError, "Npcap"):
            nmap_install_command(system="Windows", which=lambda _: None)


class NmapSetupTests(unittest.TestCase):
    def test_existing_nmap_is_verified_without_install(self) -> None:
        calls: list[tuple[str, ...]] = []

        def runner(command, **kwargs):
            calls.append(tuple(command))
            return completed(command, stdout="Nmap version 7.99\n")

        result = setup_nmap(
            system="Darwin",
            which=lambda name: "/usr/local/bin/nmap" if name == "nmap" else None,
            runner=runner,
        )

        self.assertFalse(result.installed)
        self.assertEqual(result.version, "Nmap version 7.99")
        self.assertEqual(calls, [("/usr/local/bin/nmap", "--version")])

    def test_missing_nmap_is_installed_then_verified(self) -> None:
        installed = False
        calls: list[tuple[str, ...]] = []

        def which(name: str) -> str | None:
            if name == "brew":
                return "/opt/homebrew/bin/brew"
            if name == "nmap" and installed:
                return "/opt/homebrew/bin/nmap"
            return None

        def runner(command, **kwargs):
            nonlocal installed
            calls.append(tuple(command))
            if tuple(command) == ("/opt/homebrew/bin/brew", "install", "nmap"):
                installed = True
                return completed(command)
            return completed(command, stdout="Nmap version 7.99\n")

        result = setup_nmap(system="Darwin", which=which, runner=runner)

        self.assertTrue(result.installed)
        self.assertEqual(result.path, "/opt/homebrew/bin/nmap")
        self.assertEqual(
            calls,
            [
                ("/opt/homebrew/bin/brew", "install", "nmap"),
                ("/opt/homebrew/bin/nmap", "--version"),
            ],
        )

    def test_failed_install_reports_status_and_command(self) -> None:
        def which(name: str) -> str | None:
            return "/opt/homebrew/bin/brew" if name == "brew" else None

        with self.assertRaisesRegex(SetupError, "status 9"):
            setup_nmap(
                system="Darwin",
                which=which,
                runner=lambda command, **kwargs: completed(command, 9),
            )


if __name__ == "__main__":
    unittest.main()

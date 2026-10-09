"""Install and verify native tools used by HexPath."""

from __future__ import annotations

from dataclasses import dataclass
import os
import platform
import shutil
import subprocess
from collections.abc import Callable


NMAP_DOWNLOAD_URL = "https://nmap.org/download.html"


class SetupError(RuntimeError):
    """Raised when a HexPath runtime dependency cannot be prepared."""


@dataclass(frozen=True, slots=True)
class NmapSetupResult:
    """The verified Nmap executable made available to HexPath."""

    path: str
    version: str
    installed: bool
    install_command: tuple[str, ...] | None = None


Runner = Callable[..., subprocess.CompletedProcess[str]]
Which = Callable[[str], str | None]


def find_nmap(*, which: Which = shutil.which) -> str | None:
    """Return the current Nmap executable, if one is on PATH."""
    return which("nmap")


def verify_nmap(path: str, *, runner: Runner = subprocess.run) -> str:
    """Run Nmap's version command and return its first output line."""
    try:
        process = runner(
            [path, "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as error:
        raise SetupError(f"could not run Nmap at {path!r}: {error}") from error
    if process.returncode != 0:
        detail = process.stderr.strip() or "Nmap returned no error message"
        raise SetupError(f"Nmap verification failed: {detail}")
    version = next(
        (line.strip() for line in process.stdout.splitlines() if line.strip()),
        "",
    )
    if not version:
        raise SetupError("Nmap verification returned no version information")
    return version


def nmap_install_command(
    *,
    system: str | None = None,
    which: Which = shutil.which,
    geteuid: Callable[[], int] | None = getattr(os, "geteuid", None),
) -> tuple[str, ...]:
    """Return the native package-manager command for this computer."""
    current_system = system or platform.system()
    if current_system == "Darwin":
        brew = which("brew")
        if brew:
            return (brew, "install", "nmap")
        raise SetupError(
            "Homebrew is required for automatic Nmap setup on macOS; "
            f"install Nmap manually from {NMAP_DOWNLOAD_URL}"
        )
    if current_system == "Linux":
        managers: tuple[tuple[str, tuple[str, ...]], ...] = (
            ("apt-get", ("apt-get", "install", "-y", "nmap")),
            ("dnf", ("dnf", "install", "-y", "nmap")),
            ("yum", ("yum", "install", "-y", "nmap")),
            ("apk", ("apk", "add", "nmap")),
            ("pacman", ("pacman", "-S", "--needed", "--noconfirm", "nmap")),
        )
        for executable, command in managers:
            resolved = which(executable)
            if not resolved:
                continue
            resolved_command = (resolved, *command[1:])
            if geteuid is not None and geteuid() == 0:
                return resolved_command
            sudo = which("sudo")
            if sudo:
                return (sudo, *resolved_command)
            raise SetupError(
                f"install Nmap as root with {' '.join(resolved_command)!r}, "
                "or install sudo"
            )
        raise SetupError(
            "no supported Linux package manager was found; "
            f"install Nmap manually from {NMAP_DOWNLOAD_URL}"
        )
    if current_system == "Windows":
        raise SetupError(
            "automatic Windows setup is unavailable because Nmap also requires "
            f"the Npcap driver; use the official installer at {NMAP_DOWNLOAD_URL}"
        )
    raise SetupError(
        f"automatic Nmap setup is unavailable on {current_system or 'this platform'}; "
        f"install it manually from {NMAP_DOWNLOAD_URL}"
    )


def setup_nmap(
    *,
    system: str | None = None,
    which: Which = shutil.which,
    runner: Runner = subprocess.run,
    geteuid: Callable[[], int] | None = getattr(os, "geteuid", None),
) -> NmapSetupResult:
    """Install Nmap when missing, then verify the executable and version."""
    existing = find_nmap(which=which)
    if existing:
        return NmapSetupResult(
            path=existing,
            version=verify_nmap(existing, runner=runner),
            installed=False,
        )

    command = nmap_install_command(system=system, which=which, geteuid=geteuid)
    try:
        process = runner(command, check=False)
    except OSError as error:
        raise SetupError(f"could not start {' '.join(command)!r}: {error}") from error
    if process.returncode != 0:
        raise SetupError(
            f"Nmap installation failed with status {process.returncode}: "
            f"{' '.join(command)}"
        )

    installed = find_nmap(which=which)
    if not installed:
        raise SetupError(
            "the package manager completed, but Nmap is still not on PATH; "
            "open a new terminal and run `hexpath setup nmap --check`"
        )
    return NmapSetupResult(
        path=installed,
        version=verify_nmap(installed, runner=runner),
        installed=True,
        install_command=command,
    )

"""Opt-in SSH jump-server discovery for the zero-argument path workflow."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
import json
from pathlib import Path
import re
import shlex
import subprocess
import time
from typing import Any

from hexpath.scanner import ScanProfile, build_nmap_command, parse_nmap_xml
from hexpath.scope import Scope
from hexpath.state import jump_profile_path


_SSH_USER = re.compile(r"[A-Za-z0-9_.-]+")
MAX_JUMP_SCAN_ADDRESSES = 256


@dataclass(frozen=True, slots=True)
class JumpProfile:
    """A pre-authorized internal scan reachable through one SSH server."""

    entry_host: str
    user: str
    identity_file: Path
    known_hosts_file: Path
    targets: tuple[str, ...]
    ports: str | None
    scan_profile: ScanProfile
    timeout_seconds: int


def load_jump_profile(scan: dict[str, Any]) -> JumpProfile | None:
    """Load a matching jump profile, returning null when none is configured."""
    path = jump_profile_path()
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"could not read jump profile: {error}") from error
    if not isinstance(document, dict):
        raise ValueError("jump profile must contain a JSON object")

    entry_host = _text(document.get("entry_host"), "entry_host")
    try:
        entry_host = str(ip_address(entry_host))
    except ValueError as error:
        raise ValueError("jump profile entry_host must be an IP address") from error
    scanned_hosts = {
        item.get("address")
        for item in scan.get("hosts", [])
        if isinstance(item, dict)
    }
    if entry_host not in scanned_hosts:
        return None

    user = _text(document.get("user"), "user")
    if not _SSH_USER.fullmatch(user):
        raise ValueError("jump profile user contains unsupported characters")
    identity_file = _existing_file(document.get("identity_file"), "identity_file")
    known_hosts_file = _existing_file(
        document.get("known_hosts_file"), "known_hosts_file"
    )
    raw_targets = document.get("targets")
    if not isinstance(raw_targets, list) or not raw_targets:
        raise ValueError("jump profile targets must be a non-empty list")
    targets: list[str] = []
    versions: set[int] = set()
    address_count = 0
    for raw_target in raw_targets:
        target = _text(raw_target, "target")
        try:
            network = ip_network(target, strict=True)
        except ValueError as error:
            raise ValueError(f"invalid jump profile target: {target}") from error
        targets.append(str(network))
        versions.add(network.version)
        address_count += network.num_addresses
    if len(versions) != 1:
        raise ValueError("jump profile targets must use one IP family")
    if address_count > MAX_JUMP_SCAN_ADDRESSES:
        raise ValueError(
            "jump profile targets may contain at most "
            f"{MAX_JUMP_SCAN_ADDRESSES} total addresses"
        )

    ports = document.get("ports")
    if ports is not None:
        ports = _text(ports, "ports")
    raw_profile = document.get("profile", ScanProfile.SERVICES.value)
    try:
        scan_profile = ScanProfile(raw_profile)
    except (TypeError, ValueError) as error:
        raise ValueError("jump profile profile must be 'basic' or 'services'") from error
    if scan_profile not in {ScanProfile.BASIC, ScanProfile.SERVICES}:
        raise ValueError("jump profile profile must be 'basic' or 'services'")
    timeout_seconds = document.get("timeout_seconds", 1200)
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or timeout_seconds <= 0
    ):
        raise ValueError("jump profile timeout_seconds must be a positive integer")
    return JumpProfile(
        entry_host=entry_host,
        user=user,
        identity_file=identity_file,
        known_hosts_file=known_hosts_file,
        targets=tuple(targets),
        ports=ports,
        scan_profile=scan_profile,
        timeout_seconds=timeout_seconds,
    )


def scan_through_jump(
    scan: dict[str, Any], profile: JumpProfile
) -> dict[str, Any]:
    """Run the authorized internal scan over SSH and merge normalized evidence."""
    scope = Scope.from_dict({
        "name": "Configured jump targets",
        "targets": list(profile.targets),
    })
    vantage = f"host:{profile.entry_host}"
    internal: dict[str, Any] = {
        "vantage": vantage,
        "hosts": [],
        "services": [],
    }
    deadline = time.monotonic() + profile.timeout_seconds
    for target in _chunk_targets(profile.targets):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError(
                f"jump scan exceeded {profile.timeout_seconds} seconds"
            )
        command = build_nmap_command(
            scope,
            [target],
            profile.scan_profile,
            skip_discovery=True,
            ports=profile.ports,
            ip_version=ip_network(target).version,
        )
        completed = _run_ssh_command(
            profile, shlex.join(command.arguments), remaining
        )
        result = parse_nmap_xml(
            completed.stdout,
            reference=f"ssh-jump:{profile.entry_host}",
            vantage=vantage,
        ).to_dict()
        internal["hosts"].extend(result["hosts"])
        internal["services"].extend(result["services"])
    # Keep the remote result as its own scan document. Flattening it into the
    # entry scan would discard the document-level vantage and could make the
    # graph claim that internal services were reached directly by the scanner.
    updated = deepcopy(scan)
    updated["jump_scan"] = {
        "completed": True,
        "entry_host": profile.entry_host,
        "targets": list(profile.targets),
        "observed_hosts": len(internal["hosts"]),
        "scan": internal,
    }
    updated.pop("cves", None)
    return updated


def _chunk_targets(
    targets: tuple[str, ...], maximum_addresses: int = 8
) -> tuple[str, ...]:
    """Split authorized networks into bounded sequential Nmap host groups."""
    chunks: list[str] = []
    for target in targets:
        network = ip_network(target)
        if network.num_addresses <= maximum_addresses:
            chunks.append(str(network))
            continue
        prefix = network.max_prefixlen - (maximum_addresses.bit_length() - 1)
        chunks.extend(str(item) for item in network.subnets(new_prefix=prefix))
    return tuple(chunks)


def _run_ssh_command(
    profile: JumpProfile, remote_command: str, timeout_seconds: float
) -> subprocess.CompletedProcess[str]:
    ssh_command = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={profile.known_hosts_file}",
        "-o", "ConnectTimeout=10",
        "-i", str(profile.identity_file),
        f"{profile.user}@{profile.entry_host}",
        remote_command,
    ]
    try:
        completed = subprocess.run(
            ssh_command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except FileNotFoundError as error:
        raise ValueError("ssh was not found; install an OpenSSH client") from error
    except subprocess.TimeoutExpired as error:
        raise ValueError(
            f"jump scan exceeded {profile.timeout_seconds} seconds"
        ) from error
    if completed.returncode != 0:
        detail = completed.stderr.strip() or f"ssh exited {completed.returncode}"
        raise ValueError(f"jump scan failed: {detail}")
    return completed


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"jump profile {name} must be a non-empty string")
    return value.strip()


def _existing_file(value: Any, name: str) -> Path:
    path = Path(_text(value, name)).expanduser()
    if not path.is_file():
        raise ValueError(f"jump profile {name} does not exist: {path}")
    return path

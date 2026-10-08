"""Command-line interface for HexPath."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import json
import os
from pathlib import Path
import shlex
import sys

from hexpath.scanner import (
    ScanProfile,
    ScannerError,
    build_nmap_command,
    parse_nmap_xml,
    run_nmap,
)
from hexpath.scope import Scope, ScopeError
from hexpath.vulnerabilities import (
    CpeIdentity,
    NvdClient,
    OsvClient,
    PackageIdentity,
    VulnerabilityError,
    check_cpe,
    check_package,
    check_scan_document,
)


def build_parser() -> argparse.ArgumentParser:
    """Build the HexPath command-line parser."""
    parser = argparse.ArgumentParser(
        prog="hexpath",
        description="Authorized IPv6 discovery and attack-path analysis",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    scope_parser = subcommands.add_parser("scope", help="work with assessment scopes")
    scope_commands = scope_parser.add_subparsers(dest="scope_command", required=True)

    check_parser = scope_commands.add_parser(
        "check",
        help="check whether an IPv6 address is authorized",
    )
    check_parser.add_argument("--scope", required=True, help="path to a scope JSON file")
    check_parser.add_argument("--target", required=True, help="IPv6 address to check")

    scan_parser = subcommands.add_parser("scan", help="plan authorized Nmap scans")
    scan_commands = scan_parser.add_subparsers(dest="scan_command", required=True)
    plan_parser = scan_commands.add_parser(
        "plan",
        help="validate and display an Nmap command without running it",
    )
    plan_parser.add_argument("--scope", required=True, help="path to a scope JSON file")
    plan_parser.add_argument(
        "--profile",
        choices=[profile.value for profile in ScanProfile],
        default=ScanProfile.DISCOVERY.value,
    )
    plan_parser.add_argument("targets", nargs="+", help="authorized IPv6 addresses or CIDRs")

    run_parser = scan_commands.add_parser(
        "run",
        help="run an authorized Nmap scan and print normalized JSON",
    )
    run_parser.add_argument("--scope", required=True, help="path to a scope JSON file")
    run_parser.add_argument(
        "--profile",
        choices=[profile.value for profile in ScanProfile],
        default=ScanProfile.DISCOVERY.value,
    )
    run_parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="maximum Nmap runtime in seconds",
    )
    run_parser.add_argument("targets", nargs="+", help="authorized IPv6 addresses or CIDRs")

    cve_parser = subcommands.add_parser(
        "cve",
        help="check exact software identities for known vulnerabilities",
    )
    cve_commands = cve_parser.add_subparsers(dest="cve_command", required=True)
    package_parser = cve_commands.add_parser(
        "package",
        help="query OSV for an exact package and version",
    )
    package_parser.add_argument(
        "--ecosystem",
        required=True,
        help="OSV ecosystem such as PyPI or npm",
    )
    package_parser.add_argument("--package", required=True, help="package name")
    package_parser.add_argument("--version", required=True, help="exact version")
    package_parser.add_argument(
        "--timeout",
        type=float,
        default=15,
        help="maximum OSV request time in seconds",
    )
    cpe_parser = cve_commands.add_parser(
        "cpe",
        help="query NVD for an exact service CPE",
    )
    cpe_parser.add_argument("--cpe", required=True, help="CPE 2.2 or 2.3 name")
    cpe_parser.add_argument(
        "--timeout",
        type=float,
        default=30,
        help="maximum NVD request time in seconds",
    )
    scan_cve_parser = cve_commands.add_parser(
        "scan",
        help="query NVD for every CPE in a saved HexPath scan",
    )
    scan_cve_parser.add_argument(
        "--input",
        required=True,
        help="scan JSON path, or - to read standard input",
    )
    scan_cve_parser.add_argument(
        "--timeout",
        type=float,
        default=30,
        help="maximum time for each NVD request in seconds",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run HexPath and return a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "scope" and args.scope_command == "check":
            scope = Scope.from_json_file(args.scope)
            address = scope.require_authorized(args.target)
            print(f"authorized: {address} is within {scope.name}")
            return 0
        if args.command == "scan" and args.scan_command == "plan":
            scope = Scope.from_json_file(args.scope)
            command = build_nmap_command(scope, args.targets, args.profile)
            print(shlex.join(command.arguments))
            return 0
        if args.command == "scan" and args.scan_command == "run":
            scope = Scope.from_json_file(args.scope)
            command = build_nmap_command(scope, args.targets, args.profile)
            xml_output = run_nmap(command, timeout_seconds=args.timeout)
            result = parse_nmap_xml(xml_output, reference="live-nmap")
            print(result.to_json())
            return 0
        if args.command == "cve" and args.cve_command == "package":
            package = PackageIdentity(
                ecosystem=args.ecosystem,
                name=args.package,
                version=args.version,
            )
            result = check_package(
                package,
                client=OsvClient(timeout_seconds=args.timeout),
            )
            print(result.to_json())
            return 0 if result.completed else 2
        if args.command == "cve" and args.cve_command == "cpe":
            cpe = CpeIdentity(args.cpe)
            result = check_cpe(
                cpe,
                client=NvdClient(
                    timeout_seconds=args.timeout,
                    api_key=os.environ.get("NVD_API_KEY"),
                ),
            )
            print(result.to_json())
            return 0 if result.completed else 2
        if args.command == "cve" and args.cve_command == "scan":
            try:
                raw_document = (
                    sys.stdin.read()
                    if args.input == "-"
                    else Path(args.input).read_text(encoding="utf-8")
                )
                document = json.loads(raw_document)
            except (OSError, ValueError) as error:
                raise VulnerabilityError(f"could not read scan JSON: {error}") from error
            result = check_scan_document(
                document,
                client=NvdClient(
                    timeout_seconds=args.timeout,
                    api_key=os.environ.get("NVD_API_KEY"),
                ),
            )
            print(result.to_json())
            return 0 if result.completed else 2
    except (ScopeError, ScannerError, VulnerabilityError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    parser.error("unsupported command")
    return 2

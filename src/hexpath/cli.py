"""Command-line interface for HexPath."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
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
    except (ScopeError, ScannerError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    parser.error("unsupported command")
    return 2

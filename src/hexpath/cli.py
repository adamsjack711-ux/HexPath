"""Command-line interface for HexPath."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import sys

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
    except ScopeError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    parser.error("unsupported command")
    return 2

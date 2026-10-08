"""Command-line interface for HexPath."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import json
import os
from pathlib import Path
import shlex
import sys

from hexpath.graph import (
    ENTRY_NODE_ID,
    AttackGraph,
    GraphError,
    build_attack_graph,
    render_attack_graph_ascii,
    render_path_ascii,
)
from hexpath.scanner import (
    ScanProfile,
    ScannerError,
    build_nmap_command,
    parse_nmap_xml,
    require_authorized_vantage,
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
    check_scan_documents,
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
    run_parser.add_argument(
        "--vantage",
        default=ENTRY_NODE_ID,
        help="entry:scanner or the authorized host:<IPv6> running this scan",
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
        action="append",
        help="scan JSON path, or - for standard input; repeat for multiple vantages",
    )
    scan_cve_parser.add_argument(
        "--timeout",
        type=float,
        default=30,
        help="maximum time for each NVD request in seconds",
    )

    graph_parser = subcommands.add_parser(
        "graph",
        help="build and analyze the directed attack graph",
    )
    graph_commands = graph_parser.add_subparsers(dest="graph_command", required=True)
    graph_build_parser = graph_commands.add_parser(
        "build",
        help="build a graph from normalized scan and CVE JSON",
    )
    graph_build_parser.add_argument(
        "--scan",
        required=True,
        action="append",
        help="scan JSON path; repeat for multiple vantages",
    )
    graph_build_parser.add_argument("--cves", required=True, help="CVE JSON path")
    graph_build_parser.add_argument(
        "--entry-id",
        default=ENTRY_NODE_ID,
        help="identifier for the observed scan entry point",
    )
    graph_build_parser.add_argument(
        "--output",
        help="optional path for the reusable graph JSON",
    )
    graph_build_parser.add_argument(
        "--json",
        action="store_true",
        help="print JSON instead of the terminal ASCII graph",
    )
    graph_show_parser = graph_commands.add_parser(
        "show",
        help="render a saved graph as an ASCII diagram",
    )
    graph_show_parser.add_argument("--graph", required=True, help="graph JSON path")
    graph_path_parser = graph_commands.add_parser(
        "path",
        help="find the lowest-cost directed path with Dijkstra's algorithm",
    )
    graph_path_parser.add_argument("--graph", required=True, help="graph JSON path")
    graph_path_parser.add_argument(
        "--source",
        default=ENTRY_NODE_ID,
        help="source node identifier",
    )
    graph_path_parser.add_argument("--target", required=True, help="target node identifier")
    graph_path_parser.add_argument(
        "--json",
        action="store_true",
        help="print machine-readable JSON instead of an ASCII path",
    )

    return parser


def _read_json_document(path: str, document_name: str) -> object:
    try:
        raw_document = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
        return json.loads(raw_document)
    except (OSError, ValueError) as error:
        raise ValueError(f"could not read {document_name} JSON: {error}") from error


def _read_json_documents(paths: Sequence[str], document_name: str) -> list[object]:
    if paths.count("-") > 1:
        raise ValueError("standard input can be used only once")
    return [_read_json_document(path, document_name) for path in paths]


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
            vantage = require_authorized_vantage(scope, args.vantage)
            command = build_nmap_command(scope, args.targets, args.profile)
            xml_output = run_nmap(command, timeout_seconds=args.timeout)
            result = parse_nmap_xml(
                xml_output,
                reference="live-nmap",
                vantage=vantage,
            )
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
                documents = _read_json_documents(args.input, "scan")
            except ValueError as error:
                raise VulnerabilityError(str(error)) from error
            result = check_scan_documents(
                documents,
                client=NvdClient(
                    timeout_seconds=args.timeout,
                    api_key=os.environ.get("NVD_API_KEY"),
                ),
            )
            print(result.to_json())
            return 0 if result.completed else 2
        if args.command == "graph" and args.graph_command == "build":
            scan_documents = _read_json_documents(args.scan, "scan")
            cve_document = _read_json_document(args.cves, "CVE")
            graph = build_attack_graph(
                scan_documents,
                cve_document,
                entry_id=args.entry_id,
            )
            if args.output:
                try:
                    Path(args.output).write_text(graph.to_json() + "\n", encoding="utf-8")
                except OSError as error:
                    raise GraphError(f"could not write graph JSON: {error}") from error
            print(graph.to_json() if args.json else render_attack_graph_ascii(graph))
            return 0
        if args.command == "graph" and args.graph_command == "show":
            graph = AttackGraph.from_dict(_read_json_document(args.graph, "graph"))
            print(render_attack_graph_ascii(graph))
            return 0
        if args.command == "graph" and args.graph_command == "path":
            graph = AttackGraph.from_dict(_read_json_document(args.graph, "graph"))
            path = graph.shortest_path(args.source, args.target)
            if path is None:
                if args.json:
                    print(
                        json.dumps(
                            {
                                "source": args.source,
                                "target": args.target,
                                "path": None,
                            },
                            indent=2,
                            sort_keys=True,
                        )
                    )
                else:
                    print(f"No directed path from {args.source} to {args.target}.")
                return 1
            print(path.to_json() if args.json else render_path_ascii(graph, path))
            return 0
    except (ScopeError, ScannerError, VulnerabilityError, GraphError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    parser.error("unsupported command")
    return 2

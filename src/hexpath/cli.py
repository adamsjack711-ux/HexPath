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
    render_topology_ascii,
)
from hexpath.models import Evidence, EvidenceLevel, Host
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


_COMMANDS = {"assess", "scope", "scan", "cve", "graph"}


def build_parser() -> argparse.ArgumentParser:
    """Build the HexPath command-line parser."""
    parser = argparse.ArgumentParser(
        prog="hexpath",
        description="Authorized IPv6 discovery and attack-path analysis",
        epilog=(
            "quick start:\n"
            "  hexpath scope init 2001:db8:1::/64\n"
            "  hexpath 2001:db8:1::10\n\n"
            "The direct target form runs scanning, CVE checking, and ASCII graph output."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    assess_parser = subcommands.add_parser(
        "assess",
        help="scan targets, check CVEs, and print the ASCII graph",
    )
    assess_parser.add_argument(
        "--scope",
        help="authorized IPv6 CIDR or scope JSON path; defaults to ./scope.json",
    )
    assess_parser.add_argument(
        "-6",
        dest="ipv6",
        action="store_true",
        help="use IPv6 scanning (HexPath always uses IPv6)",
    )
    assess_parser.add_argument(
        "-sV",
        dest="service_scan",
        action="store_true",
        help="enable service/version detection (the default)",
    )
    assess_parser.add_argument(
        "--from",
        dest="vantage",
        help="IPv6 host where this scan is being run",
    )
    assess_parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="maximum Nmap runtime in seconds",
    )
    assess_parser.add_argument(
        "--cve-timeout",
        type=float,
        default=30,
        help="maximum time for each NVD request in seconds",
    )
    assess_parser.add_argument(
        "-oJ",
        "--output-json",
        help="save the scan, CVEs, and graph as one JSON file",
    )
    assess_parser.add_argument(
        "--json",
        action="store_true",
        help="print the combined result as JSON instead of ASCII",
    )
    assess_parser.add_argument("targets", nargs="+", help="authorized IPv6 targets")

    scope_parser = subcommands.add_parser("scope", help="work with assessment scopes")
    scope_commands = scope_parser.add_subparsers(dest="scope_command", required=True)

    init_parser = scope_commands.add_parser(
        "init",
        help="create a scope.json file",
    )
    init_parser.add_argument("targets", nargs="+", help="authorized IPv6 networks")
    init_parser.add_argument(
        "--name",
        default="HexPath assessment",
        help="name stored in the scope file",
    )
    init_parser.add_argument(
        "-o",
        "--output",
        default="scope.json",
        help="scope file to create (default: scope.json)",
    )
    init_parser.add_argument(
        "--force",
        action="store_true",
        help="replace an existing scope file",
    )

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


def _load_quick_scope(requested_scope: str | None) -> Scope:
    raw_scope = requested_scope or os.environ.get("HEXPATH_SCOPE") or "scope.json"
    scope_path = Path(raw_scope)
    if not scope_path.is_file():
        if ":" in raw_scope:
            return Scope.from_dict(
                {"name": "Command-line scope", "targets": [raw_scope]}
            )
        raise ScopeError(
            f"scope file not found: {scope_path}; create one with "
            "'hexpath scope init <authorized-IPv6-network>'"
        )
    return Scope.from_json_file(scope_path)


def _write_json_file(path: str | Path, document: object, document_name: str) -> None:
    try:
        Path(path).write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except OSError as error:
        raise ValueError(f"could not write {document_name} JSON: {error}") from error


def _command_arguments(argv: Sequence[str] | None) -> list[str]:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] not in _COMMANDS and arguments[0] not in {
        "-h",
        "--help",
    }:
        arguments.insert(0, "assess")
    return arguments


def _include_declared_vantage_host(
    scan_document: dict[str, object],
    vantage: str,
) -> None:
    if vantage == ENTRY_NODE_ID:
        return
    hosts = scan_document.get("hosts")
    if not isinstance(hosts, list):
        raise ScannerError("normalized scan is missing its host list")
    if any(isinstance(host, dict) and host.get("id") == vantage for host in hosts):
        return
    address = vantage.removeprefix("host:")
    host = Host(
        address=address,
        evidence=(
            Evidence(
                source="operator",
                summary=f"The operator declared {address} as the scan vantage",
                level=EvidenceLevel.OBSERVED,
                reference="hexpath --from",
            ),
        ),
    )
    hosts.append(host.to_dict())


def main(argv: Sequence[str] | None = None) -> int:
    """Run HexPath and return a process exit code."""
    parser = build_parser()
    args = parser.parse_args(_command_arguments(argv))

    try:
        if args.command == "assess":
            scope = _load_quick_scope(args.scope)
            raw_vantage = args.vantage or ENTRY_NODE_ID
            if raw_vantage != ENTRY_NODE_ID and not raw_vantage.startswith("host:"):
                raw_vantage = f"host:{raw_vantage}"
            vantage = require_authorized_vantage(scope, raw_vantage)
            command = build_nmap_command(scope, args.targets, ScanProfile.SERVICES)
            xml_output = run_nmap(command, timeout_seconds=args.timeout)
            scan_result = parse_nmap_xml(
                xml_output,
                reference="live-nmap",
                vantage=vantage,
            )
            scan_document = scan_result.to_dict()
            _include_declared_vantage_host(scan_document, vantage)
            cve_result = check_scan_documents(
                [scan_document],
                client=NvdClient(
                    timeout_seconds=args.cve_timeout,
                    api_key=os.environ.get("NVD_API_KEY"),
                ),
            )
            cve_document = cve_result.to_dict()
            graph = build_attack_graph(scan_document, cve_document)
            combined_result = {
                "schema_version": 1,
                "scan": scan_document,
                "cves": cve_document,
                "graph": graph.to_dict(),
            }
            if args.output_json:
                _write_json_file(args.output_json, combined_result, "assessment")
            if args.json:
                print(json.dumps(combined_result, indent=2, sort_keys=True))
            else:
                print(render_topology_ascii(scan_document, cve_document))
                coverage = cve_document["coverage"]
                print()
                print(
                    "CVE coverage: "
                    f"{coverage['services_with_cpe']}/{coverage['services']} services "
                    f"with CPE; {len(cve_result.matches)} candidate matches"
                )
                if args.output_json:
                    print(f"Saved JSON: {args.output_json}")
            return 0
        if args.command == "scope" and args.scope_command == "init":
            scope = Scope.from_dict({"name": args.name, "targets": args.targets})
            output_path = Path(args.output)
            if output_path.exists() and not args.force:
                raise ScopeError(
                    f"scope file already exists: {output_path}; use --force to replace it"
                )
            _write_json_file(
                output_path,
                {
                    "name": scope.name,
                    "targets": [str(network) for network in scope.networks],
                },
                "scope",
            )
            print(f"Created {output_path} with {len(scope.networks)} authorized network(s).")
            return 0
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

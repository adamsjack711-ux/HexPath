"""Command-line interface for HexPath."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import json
import os
from pathlib import Path
import shlex
import sys

from hexpath import __version__
from hexpath.graph import (
    ENTRY_NODE_ID,
    AttackGraph,
    GraphError,
    NodeKind,
    build_attack_graph,
    graph_validation_document,
    host_exposure_document,
    path_comparison_document,
    render_attack_graph_ascii,
    render_graph_validation_ascii,
    render_host_targets_ascii,
    render_host_exposure_ascii,
    render_path_ascii,
    render_path_comparison_ascii,
    render_vulnerable_path_ranking_ascii,
    vulnerable_path_ranking_document,
)
from hexpath.scanner import (
    ScanProfile,
    ScannerError,
    build_nmap_command,
    parse_nmap_xml,
    render_scan_levels_ascii,
    require_authorized_vantage,
    run_nmap,
    scan_levels_document,
    scan_profile_for_level,
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
        description="Authorized IPv4 and IPv6 discovery and attack-path analysis",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    scope_parser = subcommands.add_parser(
        "scope",
        aliases=["sc"],
        help="work with assessment scopes",
    )
    scope_parser.set_defaults(command="scope")
    scope_commands = scope_parser.add_subparsers(dest="scope_command", required=True)

    check_parser = scope_commands.add_parser(
        "check",
        aliases=["c"],
        help="check whether an IP address is authorized",
    )
    check_parser.set_defaults(scope_command="check")
    check_parser.add_argument(
        "-s",
        "--scope",
        required=True,
        help="path to a scope JSON file",
    )
    check_parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="IP address to check",
    )

    scan_parser = subcommands.add_parser(
        "scan",
        aliases=["s"],
        help="plan authorized Nmap scans",
    )
    scan_parser.set_defaults(command="scan")
    scan_commands = scan_parser.add_subparsers(dest="scan_command", required=True)
    levels_parser = scan_commands.add_parser(
        "levels",
        aliases=["l"],
        help="show scan information levels and relative wait times",
    )
    levels_parser.set_defaults(scan_command="levels")
    levels_parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="print scan levels as machine-readable JSON",
    )
    plan_parser = scan_commands.add_parser(
        "plan",
        aliases=["p"],
        help="validate and display an Nmap command without running it",
    )
    plan_parser.set_defaults(scan_command="plan")
    plan_parser.add_argument(
        "-s",
        "--scope",
        required=True,
        help="path to a scope JSON file",
    )
    plan_parser.set_defaults(profile=None)
    plan_information = plan_parser.add_mutually_exclusive_group()
    plan_information.add_argument(
        "-p",
        "--profile",
        type=_scan_profile,
        choices=[profile.value for profile in ScanProfile],
        metavar="NAME",
        help="named scan profile",
    )
    plan_information.add_argument(
        "-L",
        "--level",
        dest="profile",
        type=_scan_level,
        metavar="0-4",
        help="information level: 0 fastest through 4 deepest",
    )
    plan_family = plan_parser.add_mutually_exclusive_group()
    plan_family.add_argument(
        "-4",
        dest="ip_version",
        action="store_const",
        const=4,
        help="require IPv4 targets (otherwise inferred)",
    )
    plan_family.add_argument(
        "-6",
        dest="ip_version",
        action="store_const",
        const=6,
        help="require IPv6 targets (otherwise inferred)",
    )
    plan_parser.add_argument("targets", nargs="+", help="authorized IP addresses or CIDRs")

    run_parser = scan_commands.add_parser(
        "run",
        aliases=["r"],
        help="run an authorized Nmap scan and print normalized JSON",
    )
    run_parser.set_defaults(scan_command="run")
    run_parser.add_argument(
        "-s",
        "--scope",
        required=True,
        help="path to a scope JSON file",
    )
    run_parser.set_defaults(profile=None)
    run_information = run_parser.add_mutually_exclusive_group()
    run_information.add_argument(
        "-p",
        "--profile",
        type=_scan_profile,
        choices=[profile.value for profile in ScanProfile],
        metavar="NAME",
        help="named scan profile",
    )
    run_information.add_argument(
        "-L",
        "--level",
        dest="profile",
        type=_scan_level,
        metavar="0-4",
        help="information level: 0 fastest through 4 deepest",
    )
    run_family = run_parser.add_mutually_exclusive_group()
    run_family.add_argument(
        "-4",
        dest="ip_version",
        action="store_const",
        const=4,
        help="require IPv4 targets (otherwise inferred)",
    )
    run_family.add_argument(
        "-6",
        dest="ip_version",
        action="store_const",
        const=6,
        help="require IPv6 targets (otherwise inferred)",
    )
    run_parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=300,
        help="maximum Nmap runtime in seconds",
    )
    run_parser.add_argument(
        "-v",
        "--vantage",
        default=ENTRY_NODE_ID,
        help="entry:scanner or the authorized host:<IP> running this scan",
    )
    run_parser.add_argument("targets", nargs="+", help="authorized IP addresses or CIDRs")

    cve_parser = subcommands.add_parser(
        "cve",
        aliases=["c"],
        help="check exact software identities for known vulnerabilities",
    )
    cve_parser.set_defaults(command="cve")
    cve_commands = cve_parser.add_subparsers(dest="cve_command", required=True)
    package_parser = cve_commands.add_parser(
        "package",
        aliases=["p"],
        help="query OSV for an exact package and version",
    )
    package_parser.set_defaults(cve_command="package")
    package_parser.add_argument(
        "-e",
        "--ecosystem",
        required=True,
        help="OSV ecosystem such as PyPI or npm",
    )
    package_parser.add_argument(
        "-p",
        "--package",
        required=True,
        help="package name",
    )
    package_parser.add_argument(
        "-V",
        "--version",
        required=True,
        help="exact version",
    )
    package_parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=15,
        help="maximum OSV request time in seconds",
    )
    cpe_parser = cve_commands.add_parser(
        "cpe",
        aliases=["c"],
        help="query NVD for an exact service CPE",
    )
    cpe_parser.set_defaults(cve_command="cpe")
    cpe_parser.add_argument(
        "-c",
        "--cpe",
        required=True,
        help="CPE 2.2 or 2.3 name",
    )
    cpe_parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=30,
        help="maximum NVD request time in seconds",
    )
    scan_cve_parser = cve_commands.add_parser(
        "scan",
        aliases=["s"],
        help="query NVD for every CPE in a saved HexPath scan",
    )
    scan_cve_parser.set_defaults(cve_command="scan")
    scan_cve_parser.add_argument(
        "-i",
        "--input",
        required=True,
        action="append",
        help="scan JSON path, or - for standard input; repeat for multiple vantages",
    )
    scan_cve_parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=30,
        help="maximum time for each NVD request in seconds",
    )

    graph_parser = subcommands.add_parser(
        "graph",
        aliases=["g"],
        help="build and analyze the directed attack graph",
    )
    graph_parser.set_defaults(command="graph")
    graph_commands = graph_parser.add_subparsers(dest="graph_command", required=True)
    graph_build_parser = graph_commands.add_parser(
        "build",
        aliases=["b"],
        help="build a graph from normalized scan and CVE JSON",
    )
    graph_build_parser.set_defaults(graph_command="build")
    graph_build_parser.add_argument(
        "-s",
        "--scan",
        required=True,
        action="append",
        help="scan JSON path; repeat for multiple vantages",
    )
    graph_build_parser.add_argument(
        "-c",
        "--cves",
        required=True,
        help="CVE JSON path",
    )
    graph_build_parser.add_argument(
        "-e",
        "--entry-id",
        default=ENTRY_NODE_ID,
        help="identifier for the observed scan entry point",
    )
    graph_build_parser.add_argument(
        "-o",
        "--output",
        help="optional path for the reusable graph JSON",
    )
    graph_build_parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="print JSON instead of the terminal ASCII graph",
    )
    graph_show_parser = graph_commands.add_parser(
        "show",
        aliases=["sh"],
        help="render a saved graph as an ASCII diagram",
    )
    graph_show_parser.set_defaults(graph_command="show")
    graph_show_parser.add_argument(
        "-g",
        "--graph",
        required=True,
        help="graph JSON path",
    )
    graph_validate_parser = graph_commands.add_parser(
        "validate",
        aliases=["v"],
        help="validate and summarize a saved graph",
    )
    graph_validate_parser.set_defaults(graph_command="validate")
    graph_validate_parser.add_argument(
        "-g",
        "--graph",
        required=True,
        help="graph JSON path",
    )
    graph_validate_parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="print the validation summary as machine-readable JSON",
    )
    graph_path_parser = graph_commands.add_parser(
        "path",
        aliases=["p"],
        help="find the lowest-cost directed path with Dijkstra or A*",
    )
    graph_path_parser.set_defaults(graph_command="path")
    graph_path_parser.add_argument(
        "-g",
        "--graph",
        required=True,
        help="graph JSON path",
    )
    graph_path_parser.add_argument(
        "-s",
        "--source",
        help="source node identifier or IP address (default: the graph's entry node)",
    )
    graph_path_parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="target node identifier or IP address",
    )
    graph_path_parser.add_argument(
        "-a",
        "--algorithm",
        type=_path_algorithm,
        choices=("dijkstra", "astar"),
        default="dijkstra",
        metavar="{dijkstra|astar|d|a}",
        help="pathfinding algorithm (default: dijkstra)",
    )
    graph_path_parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="print machine-readable JSON instead of an ASCII path",
    )
    graph_targets_parser = graph_commands.add_parser(
        "targets",
        aliases=["t"],
        help="list host targets and their modeled reachability",
    )
    graph_targets_parser.set_defaults(graph_command="targets")
    graph_targets_parser.add_argument(
        "-g",
        "--graph",
        required=True,
        help="graph JSON path",
    )
    graph_targets_parser.add_argument(
        "-s",
        "--source",
        help="source node identifier or IP address (default: the graph's entry node)",
    )
    graph_targets_parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="print machine-readable JSON instead of a host list",
    )
    graph_paths_parser = graph_commands.add_parser(
        "paths",
        aliases=["r"],
        help="compare the cheapest evidence-backed loop-free routes",
    )
    graph_paths_parser.set_defaults(graph_command="paths")
    graph_paths_parser.add_argument(
        "-g",
        "--graph",
        required=True,
        help="graph JSON path",
    )
    graph_paths_parser.add_argument(
        "-s",
        "--source",
        help="source node identifier or IP address (default: the graph's entry node)",
    )
    graph_paths_parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="target node identifier or IP address",
    )
    graph_paths_parser.add_argument(
        "-n",
        "--limit",
        type=_path_limit,
        default=3,
        help="maximum routes to return (1-20; default: 3)",
    )
    graph_paths_parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="print machine-readable JSON instead of a route comparison",
    )
    graph_score_parser = graph_commands.add_parser(
        "score",
        aliases=["s"],
        help="score network exposure for one selected host",
    )
    graph_score_parser.set_defaults(graph_command="score")
    graph_score_parser.add_argument(
        "-g",
        "--graph",
        required=True,
        help="graph JSON path",
    )
    graph_score_parser.add_argument(
        "-s",
        "--source",
        help="source node identifier or IP address (default: the graph's entry node)",
    )
    graph_score_parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="host node identifier or IP address to score",
    )
    graph_score_parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="print the score and evidence as machine-readable JSON",
    )
    graph_exposure_parser = graph_commands.add_parser(
        "exposure",
        aliases=["x", "vulnerable"],
        help="rank reachable hosts by the transparent network exposure score",
    )
    graph_exposure_parser.set_defaults(graph_command="exposure")
    graph_exposure_parser.add_argument(
        "-g",
        "--graph",
        required=True,
        help="graph JSON path",
    )
    graph_exposure_parser.add_argument(
        "-s",
        "--source",
        help="source node identifier or IP address (default: the graph's entry node)",
    )
    graph_exposure_parser.add_argument(
        "-n",
        "--limit",
        type=_path_limit,
        default=10,
        help="maximum scored host paths to return (1-20; default: 10)",
    )
    graph_exposure_parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="print machine-readable JSON instead of a ranking",
    )

    return parser


def _scan_profile(value: str) -> str:
    return {
        "d": ScanProfile.DISCOVERY.value,
        "s": ScanProfile.SERVICES.value,
    }.get(value, value)


def _scan_level(value: str) -> str:
    try:
        level = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("scan level must be an integer from 0 to 4") from None
    try:
        return scan_profile_for_level(level).value
    except ScannerError as error:
        raise argparse.ArgumentTypeError(str(error)) from None


def _path_algorithm(value: str) -> str:
    return {"d": "dijkstra", "a": "astar"}.get(value, value)


def _path_limit(value: str) -> int:
    try:
        limit = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            "path limit must be an integer between 1 and 20"
        ) from None
    if not 1 <= limit <= 20:
        raise argparse.ArgumentTypeError("path limit must be an integer between 1 and 20")
    return limit


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
        if args.command == "scan" and args.scan_command == "levels":
            if args.json:
                print(json.dumps(scan_levels_document(), indent=2, sort_keys=True))
            else:
                print(render_scan_levels_ascii())
            return 0
        if args.command == "scan" and args.scan_command == "plan":
            scope = Scope.from_json_file(args.scope)
            command = build_nmap_command(
                scope,
                args.targets,
                args.profile or ScanProfile.DISCOVERY.value,
                ip_version=args.ip_version,
            )
            print(shlex.join(command.arguments))
            return 0
        if args.command == "scan" and args.scan_command == "run":
            scope = Scope.from_json_file(args.scope)
            vantage = require_authorized_vantage(scope, args.vantage)
            command = build_nmap_command(
                scope,
                args.targets,
                args.profile or ScanProfile.DISCOVERY.value,
                ip_version=args.ip_version,
            )
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
        if args.command == "graph" and args.graph_command == "validate":
            graph = AttackGraph.from_dict(_read_json_document(args.graph, "graph"))
            if args.json:
                print(
                    json.dumps(
                        graph_validation_document(graph),
                        indent=2,
                        sort_keys=True,
                    )
                )
            else:
                print(render_graph_validation_ascii(graph))
            return 0
        if args.command == "graph" and args.graph_command == "path":
            graph = AttackGraph.from_dict(_read_json_document(args.graph, "graph"))
            source = graph.resolve_node(args.source or graph.default_source())
            target = graph.resolve_node(args.target)
            path = graph.shortest_path(source, target, algorithm=args.algorithm)
            if path is None:
                if args.json:
                    print(
                        json.dumps(
                            {
                                "source": source,
                                "target": target,
                                "path": None,
                            },
                            indent=2,
                            sort_keys=True,
                        )
                    )
                else:
                    print(f"No directed path from {source} to {target}.")
                return 1
            print(path.to_json() if args.json else render_path_ascii(graph, path))
            return 0
        if args.command == "graph" and args.graph_command == "targets":
            graph = AttackGraph.from_dict(_read_json_document(args.graph, "graph"))
            source = graph.resolve_node(args.source or graph.default_source())
            targets = []
            for node in sorted(graph.nodes, key=lambda item: item.node_id):
                if node.kind is not NodeKind.HOST:
                    continue
                path = graph.shortest_path(source, node.node_id)
                targets.append(
                    {
                        "id": node.node_id,
                        "label": node.label,
                        "hostnames": node.metadata.get("hostnames", []),
                        "reachable": path is not None,
                        "cost": path.total_weight if path else None,
                    }
                )
            if args.json:
                print(
                    json.dumps(
                        {"source": source, "targets": targets},
                        indent=2,
                        sort_keys=True,
                    )
                )
            else:
                print(render_host_targets_ascii(source, targets))
            return 0
        if args.command == "graph" and args.graph_command == "paths":
            graph = AttackGraph.from_dict(_read_json_document(args.graph, "graph"))
            source = graph.resolve_node(args.source or graph.default_source())
            target = graph.resolve_node(args.target)
            paths = graph.shortest_paths(source, target, limit=args.limit)
            if args.json:
                print(
                    json.dumps(
                        path_comparison_document(
                            source,
                            target,
                            paths,
                            limit=args.limit,
                        ),
                        indent=2,
                        sort_keys=True,
                    )
                )
            else:
                print(render_path_comparison_ascii(graph, source, target, paths))
            return 0 if paths else 1
        if args.command == "graph" and args.graph_command == "score":
            graph = AttackGraph.from_dict(_read_json_document(args.graph, "graph"))
            source = graph.resolve_node(args.source or graph.default_source())
            target = graph.resolve_node(args.target)
            score = graph.host_exposure(source, target)
            if score is None:
                if args.json:
                    print(
                        json.dumps(
                            {
                                "algorithm": "dijkstra",
                                "source": source,
                                "target": target,
                                "network_score": None,
                                "reason": (
                                    "no evidence-backed directed path from the "
                                    "selected source"
                                ),
                            },
                            indent=2,
                            sort_keys=True,
                        )
                    )
                else:
                    print(f"No directed path from {source} to {target}; score unavailable.")
                return 1
            if args.json:
                print(
                    json.dumps(
                        host_exposure_document(graph, source, score),
                        indent=2,
                        sort_keys=True,
                    )
                )
            else:
                print(render_host_exposure_ascii(graph, source, score))
            return 0
        if args.command == "graph" and args.graph_command in (
            "exposure",
            "vulnerable",
        ):
            graph = AttackGraph.from_dict(_read_json_document(args.graph, "graph"))
            source = graph.resolve_node(args.source or graph.default_source())
            scores = graph.ranked_host_exposures(source)
            if args.json:
                print(
                    json.dumps(
                        vulnerable_path_ranking_document(
                            graph,
                            source,
                            scores,
                            limit=args.limit,
                        ),
                        indent=2,
                        sort_keys=True,
                    )
                )
            else:
                print(
                    render_vulnerable_path_ranking_ascii(
                        graph,
                        source,
                        scores,
                        limit=args.limit,
                    )
                )
            return 0 if scores else 1
    except (ScopeError, ScannerError, VulnerabilityError, GraphError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    parser.error("unsupported command")
    return 2

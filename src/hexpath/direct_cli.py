"""Target-first CLI for service discovery and CVE candidate reporting."""

from __future__ import annotations

import argparse
from dataclasses import replace
from ipaddress import ip_network
import json
import os
from pathlib import Path
import shlex
import socket
import sys

from hexpath.scanner import ScanProfile, ScannerError, build_nmap_command, parse_nmap_xml, run_nmap
from hexpath.scope import Scope, ScopeError
from hexpath.state import save_latest_scan
from hexpath.vulnerabilities import NvdClient, VulnerabilityError, check_scan_documents


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hexpath", description="Scan a target, detect service versions, and look up CVE candidates.",
        epilog=(
            "After a scan, run 'hexpath path' to compile ports and CVEs. "
            "Advanced commands remain available: hexpath scan, scope, cve, graph, assess."
        ),
    )
    parser.add_argument("targets", nargs="+", metavar="TARGET", help="IP, hostname, or scoped CIDR")
    parser.add_argument("-sV", "--services", action="store_true", help="detect service versions")
    parser.add_argument("-O", "--os-detection", action="store_true", help="detect OS (requires Nmap privileges)")
    parser.add_argument(
        "--cves", action=argparse.BooleanOptionalAction, default=True,
        help="look up CVE candidates (default). Use --no-cves to skip lookup, with -sV for version probes",
    )
    parser.add_argument("-p", "--ports", help="ports or ranges, e.g. 22,80,443 or 1-1000; '-' means all TCP ports")
    parser.add_argument(
        "--smb-vuln", dest="smb_vuln", action="store_true",
        help="run Nmap's safe SMB vulnerability checks (ms17-010, ms08-067) for "
        "evidence-backed CVEs on services with no version, such as Windows SMB",
    )
    parser.add_argument("-Pn", dest="skip_discovery", action="store_true", help="skip host discovery")
    family = parser.add_mutually_exclusive_group()
    family.add_argument("-4", dest="ip_version", action="store_const", const=4, help="use IPv4")
    family.add_argument("-6", dest="ip_version", action="store_const", const=6, help="use IPv6")
    parser.add_argument("--scope", help="optional scope JSON to constrain the supplied targets")
    parser.add_argument("--plan", action="store_true", help="preview the command without scanning")
    parser.add_argument("--timeout", type=int, default=300, help="scan timeout in seconds (default: 300)")
    parser.add_argument("--json", action="store_true", help="print machine-readable results")
    parser.add_argument("-o", "--output", help="save results as JSON")
    return parser


def resolve_targets(targets: list[str], version: int | None) -> list[str]:
    """Resolve names once, then pin validation and Nmap to the same addresses."""
    resolved: list[str] = []
    for target in targets:
        try:
            network = ip_network(target, strict=True)
            resolved.append(str(network))
            continue
        except ValueError:
            if "/" in target or ":" in target or target.replace(".", "").isdigit():
                raise ValueError(f"invalid IP address or network: {target}") from None
        family = {4: socket.AF_INET, 6: socket.AF_INET6}.get(version, socket.AF_UNSPEC)
        try:
            answers = socket.getaddrinfo(target, None, family, socket.SOCK_STREAM)
        except OSError as error:
            raise ValueError(f"could not resolve {target}: {error}") from error
        # Like a basic Nmap invocation, select one address per hostname.
        addresses = sorted({item[4][0] for item in answers}, key=lambda item: (":" in item, item))
        if not addresses:
            raise ValueError(f"no usable address for {target}")
        resolved.append(str(ip_network(addresses[0], strict=True)))
    return list(dict.fromkeys(resolved))


def render_result(document: dict) -> str:
    lines = ["HexPath scan results", ""]
    for host in document["hosts"]:
        address = host["address"]
        lines.append(f"Host: {address}")
        if host.get("os_name"):
            lines.append(f"OS estimate: {host['os_name']} (accuracy {host.get('os_accuracy', 'unknown')}%)")
        services = [item for item in document["services"] if item["host"] == address]
        visible = [item for item in services if item["state"] != "closed"]
        if visible:
            lines.append("PORT         STATE           SERVICE / VERSION")
            for service in visible:
                identity = " ".join(str(service[key]) for key in ("name", "product", "version") if service.get(key))
                port = f"{service['port']}/{service['protocol']}"
                lines.append(f"{port:<12} {service['state']:<15} {identity or 'unknown'}")
        else:
            lines.append("No open ports reported among the tested ports.")
        lines.append("")
    if not document["hosts"]:
        lines.append("No hosts reported up. If the target is online, try -Pn.")
    confirmed = [
        finding for finding in document.get("script_findings", [])
        if finding.get("confirms_vulnerable")
    ]
    if confirmed:
        lines.append("Confirmed by Nmap vulnerability scripts (evidence-backed):")
        for finding in confirmed:
            cve_ids = ", ".join(finding.get("cve_ids", [])) or "no CVE id reported"
            lines.append(
                f"  [{finding['host']}] {finding['port']}/{finding['protocol']} "
                f"{finding['script_id']}: {finding['state']} — {cve_ids}"
            )
        lines.append("")
    cves = document.get("cves")
    if cves is None:
        lines.append("CVE lookup skipped (--no-cves).")
    else:
        coverage = cves["coverage"]
        lines.append(f"CVE lookup: {coverage['completed_cpe_checks']}/{coverage['cpe_checks']} software checks completed.")
        for finding in cves["vulnerabilities"]:
            lines.append(f"  {finding['id']}: {finding['description']}")
        if not cves["completed"]:
            lines.append("Coverage incomplete; missing identities or failed lookups are not a clean result.")
        os_candidates = cves.get("os_candidates", [])
        if os_candidates:
            lines.append("")
            lines.append("CVE candidates from the OS fingerprint (based on an OS guess; verify patch level):")
            for candidate in os_candidates:
                score = candidate.get("cvss_score")
                severity = f"CVSS {score}" if score is not None else "no CVSS"
                lines.append(
                    f"  [{candidate['host']}] {candidate['cve_id']} ({severity}): "
                    f"{candidate['description']}"
                )
        lines.append("CVE candidates require applicability checks; they do not prove exploitation.")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    parser = build_parser()
    if not argv:
        parser.print_help()
        return 0
    args = parser.parse_intermixed_args(argv)
    try:
        if args.timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        targets = resolve_targets(args.targets, args.ip_version)
        scope = Scope.from_json_file(args.scope) if args.scope else Scope.from_dict({
            "name": "Explicit command-line targets", "targets": targets,
        })
        profile = ScanProfile.SERVICES if args.services or args.cves else ScanProfile.BASIC
        command = build_nmap_command(
            scope, targets, profile, skip_discovery=args.skip_discovery,
            ports="1-65535" if args.ports == "-" else args.ports, ip_version=args.ip_version,
            vuln_scripts=args.smb_vuln,
        )
        if args.os_detection:
            command = replace(command, arguments=(command.arguments[0], "-O", *command.arguments[1:]))
        if args.plan:
            print(shlex.join(command.arguments))
            if args.cves:
                print("After scanning: NVD lookup for detected software identities.", file=sys.stderr)
            return 0
        print(f"Scanning {', '.join(command.targets)}…", file=sys.stderr, flush=True)
        result = parse_nmap_xml(run_nmap(command, timeout_seconds=args.timeout), reference="live-nmap")
        document = result.to_dict()
        document["scope"] = {"name": scope.name, "targets": [str(item) for item in scope.networks]}
        document["command"] = list(command.arguments)
        if args.cves:
            print("Looking up CVE candidates…", file=sys.stderr, flush=True)
            document["cves"] = check_scan_documents(
                [document], client=NvdClient(api_key=os.environ.get("NVD_API_KEY")),
            ).to_dict()
        save_latest_scan(document)
        serialized = json.dumps(document, indent=2, sort_keys=True)
        if args.output:
            Path(args.output).write_text(serialized + "\n", encoding="utf-8")
        print(serialized if args.json else render_result(document))
        if args.output:
            print(f"Saved results: {args.output}", file=sys.stderr)
        return 2 if args.cves and not document["cves"]["completed"] else 0
    except (ScopeError, ScannerError, VulnerabilityError, ValueError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Scan interrupted.", file=sys.stderr)
        return 130

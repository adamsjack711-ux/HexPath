# HexPath

An IPv6 penetration-testing tool for lab practice and authorized engagements.

HexPath is our school group project to connect IPv6 network discovery, service assessment, CVE enrichment, and attack-path analysis in one workflow. The goal is to turn a long list of findings into a clear, prioritized view of potential paths through a network, so reviewers can understand how findings relate and where to focus their assessment.

## Project status

HexPath currently provides:

- IPv6-only scope validation.
- Scope-checked Nmap discovery and service scans.
- Normalized host, service, CPE, evidence, and vulnerability records.
- NVD CVE lookup for CPEs reported by Nmap.
- OSV package-version lookup based on the checking rules used by pkgxray.
- Explicit coverage reporting that distinguishes a clean result from a failed or incomplete lookup.
- Vantage-aware multi-host reachability modeling.
- Directed attack-graph construction, ASCII terminal rendering, and Dijkstra path analysis.
- Operator-selected targets and ranked comparison of evidence-backed, loop-free routes.
- Full server topology inventory over SSH, including interfaces, listening
  services, libvirt networks and VMs, and Docker networks and containers.

## Workflow

1. **IPv6 discovery** — Identify live IPv6 hosts within the approved assessment scope.
2. **Service assessment** — Use Nmap to identify exposed services and their reported versions.
3. **CVE enrichment** — Add relevant known-vulnerability candidates from NVD and OSV with explicit evidence and coverage status.
4. **Network modeling** — Represent hosts and potential transitions as a weighted, directed graph.
5. **Path analysis** — Use Dijkstra’s algorithm to identify the lowest-cost modeled path between a selected entry point and target, showing the associated findings along the path.

Strict scope controls are applied before a scan command is constructed. HexPath is intended for lab environments and networks the assessment team is authorized to test.

## Install for development

HexPath requires Python 3.11 or newer. Nmap is also required to execute scans.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --editable .
```

## Quick command-line use

HexPath runs entirely in the terminal. Create the authorized IPv6 scope once:

```sh
hexpath scope init 2001:db8:1::/64
```

For a one-off assessment, provide the authorized network directly and skip the
scope file:

```sh
hexpath --scope 2001:db8:1::/64 2001:db8:1::10
```

Then assess a target with one command:

```sh
hexpath 2001:db8:1::10
```

That command automatically:

1. Validates the target against `scope.json`.
2. Runs Nmap IPv6 service and version detection.
3. Checks discovered CPEs against NVD.
4. Builds the directed attack graph.
5. Prints the complete host, service, and CVE topology as ASCII in the terminal.

Familiar Nmap-style flags are also accepted:

```sh
hexpath -6 -sV -Pn -p 22,443 2001:db8:1::10
```

Use `-Pn` when ICMP or another firewall rule prevents Nmap host discovery even
though the target is reachable.
Use `-p` to scan specific ports or ranges when a smaller targeted assessment is
appropriate.

Save the complete scan, CVE, and graph data when needed:

```sh
hexpath -oJ results.json 2001:db8:1::10
```

The terminal keeps the readable topology while `results.json` stores the same
assessment as structured scan, CVE, and graph data:

```text
HexPath Network Topology
========================
               +------------------+
               | SERVER / SCANNER |
               |  entry:scanner   |
               +------------------+
                         |
                 +--------------+
                 |     HOST     |
                 | 2001:db8::10 |
                 |   web.lab    |
                 +--------------+
                         |
           +-------------+-------------+
           |                           |
+---------------------+    +----------------------+
| SERVICE tcp/22 OPEN |    | SERVICE tcp/443 OPEN |
|     OpenSSH 9.6     |    |      nginx 1.26      |
+---------------------+    +----------------------+
           |                           |
 +-------------------+       +-------------------+
 |   CVE-2024-6387   |       | NO CVE CANDIDATES |
 | CVSS 9.0 | MEDIUM |       +-------------------+
 +-------------------+
```

Use a different scope file with `--scope`, or set `HEXPATH_SCOPE` once in the
shell. Record a scan that is actually run from another authorized host with
`--from`:

```sh
hexpath --scope lab.json --from 2001:db8:1::10 2001:db8:1::20
```

Run `hexpath --help` to see the short workflow and `hexpath assess --help` for
all direct-scan options.

Select a host to compare up to three modeled routes after the assessment:

```sh
hexpath --target 2001:db8:1::10 --paths 3 2001:db8:1::10
```

The selected target is scope-checked before scanning. The topology stays visible,
followed by ranked routes showing total cost, the difference from the cheapest
route, candidate CVEs, and confidence. `-oJ` and `--json` include this comparison
under `path_comparison` alongside the scan, CVEs, and graph.

## Full server topology

Show the complete topology of a server that is already available through SSH:

```sh
hexpath inventory aiserver
```

The server is the root of the ASCII diagram. HexPath reads and displays every
host network interface, listening socket, libvirt network, VM, Docker network,
and container reported by the server. Running, stopped, attached, and
unattached resources stay visible.

Keep the terminal diagram and save the same inventory as downloadable JSON:

```sh
hexpath inventory aiserver -oJ full-topology.json
```

Omit `aiserver` to inventory the local computer. The inventory is read-only;
the account running HexPath needs permission to run `virsh`, `docker`, `ip`,
and `ss` on the selected server.

## Advanced commands

The commands below expose each pipeline stage separately for debugging,
research, and multi-file analysis.

### Scope and scanning

Preview a discovery command after validating the target against the scope file:

```sh
hexpath scan plan \
  --scope examples/lab-scope.example.json \
  --profile discovery \
  2001:db8:1::10
```

Run service detection and save the normalized JSON result:

```sh
hexpath scan run \
  --scope examples/lab-scope.example.json \
  --profile services \
  2001:db8:1::10 > scan.json
```

When a scan is actually run from an already reached host, record that host as
the vantage point:

```sh
hexpath scan run \
  --scope examples/lab-scope.example.json \
  --profile services \
  --vantage host:2001:db8:1::10 \
  2001:db8:1::20 > scan-from-host-10.json
```

Use a host vantage only for a scan performed from that host. HexPath validates
that the vantage address is inside the authorized IPv6 scope.

Every target must be fully contained within an allowed IPv6 network. HexPath rejects broader networks and IPv4 targets before starting Nmap.

### CVE checking

Check every unique service CPE across saved scans against NVD:

```sh
hexpath cve scan \
  --input scan.json \
  --input scan-from-host-10.json > cve-results.json
```

Repeated services and CPEs are deduplicated, so the same CPE is queried once.

Check one Nmap CPE directly:

```sh
hexpath cve cpe --cpe cpe:/a:openbsd:openssh:9.6
```

Check an exact package version through OSV using the pkgxray-derived package lookup:

```sh
hexpath cve package --ecosystem PyPI --package Jinja2 --version 2.4.1
```

Set `NVD_API_KEY` in the environment when an NVD API key is available. HexPath sends it through the required request header and does not include it in results.

CPE findings are candidate matches. Nmap identifies the product and version remotely, and NVD identifies applicable CVEs, but a vendor may have backported a patch without changing the reported version. HexPath therefore records these links as inferred, medium-confidence evidence until patch status is validated.

### Attack graph

Build a reusable graph file and display its ASCII representation:

```sh
hexpath graph build \
  --scan scan.json \
  --scan scan-from-host-10.json \
  --cves cve-results.json \
  --output graph.json
```

Display a saved graph again:

```sh
hexpath graph show --graph graph.json
```

Find and display the lowest-cost directed path to a selected host:

```sh
hexpath graph path \
  --graph graph.json \
  --target host:2001:db8:1::10
```

List the available hosts before selecting a target:

```sh
hexpath graph targets --graph graph.json
```

The list includes hosts without a modeled path. Its reachability status describes
the evidence-backed attack graph, rather than whether a host responds to network
traffic. Use `--source` to list reachability from a different entry or host.

Compare several routes to the same host, using an IPv6 address or an exact node ID:

```sh
hexpath graph paths --graph graph.json --target 2001:db8:1::10 --limit 3
hexpath graph paths --graph graph.json --target 2001:db8:1::10 --limit 3 --json
```

Routes are ordered by total cost and never revisit a node. Alternative CVEs on
the same service remain distinct routes. The limit defaults to three and accepts
values from one to twenty; fewer routes are returned when fewer exist. Spur
searches use Dijkstra within Yen's algorithm, without enumerating all possible
routes. Each JSON route retains its nodes, edges, and supporting evidence, with
an added `rank` and `cost_delta`.

`graph paths` returns exit code `0` when a route exists, `1` when the known target
has no directed path, and `2` for invalid input or an unknown target. A comparison
without a route returns an empty JSON `paths` list. The direct assessment uses
these same exit codes when `--target` is supplied. `graph path` keeps its original
single-route JSON format. These commands also accept an IPv6 address for `--source`.

The terminal output uses ASCII branches and arrows. Pass `--json` to `graph build` or `graph path` when another program needs machine-readable output.

Each scan contributes reachability only from its recorded vantage. A path can
therefore continue from the entry point, through a candidate service finding to
one host, and then through services observed by a scan run from that host.

Candidate exploit costs use `11 - CVSS score`, plus a confidence penalty of `0` for high, `1.5` for medium, or `3` for low confidence. A missing CVSS score uses the neutral value `5.0`. Lower costs are prioritized by Dijkstra's algorithm. These costs rank investigation paths; they are not exploit probabilities.

## Tests

```sh
python -m unittest discover --start-directory tests --verbose
```

## Working together

1. Make sure you’ve accepted your GitHub collaborator invitation so you can contribute directly.
2. Use [Issues](https://github.com/adamsjack711-ux/HexPath/issues) to propose ideas, track tasks, and report problems. Add enough context for a teammate to pick up the work.
3. Work on a separate branch and open a pull request into the default branch. Ask a teammate to review it before merging.
4. Keep this README updated as we agree on the scope and how to run the tool.

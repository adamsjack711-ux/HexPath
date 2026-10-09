# HexPath

An IPv4 and IPv6 penetration-testing tool for lab practice and authorized engagements.

HexPath is our school group project to connect IP network discovery, service assessment, CVE enrichment, and attack-path analysis in one workflow. The goal is to turn a long list of findings into a clear, prioritized view of potential paths through a network, so reviewers can understand how findings relate and where to focus their assessment.

## Project status

HexPath currently provides:

- Dual-stack IPv4 and IPv6 scope validation.
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

1. **IP discovery** — Identify live IPv4 or IPv6 hosts within the approved assessment scope.
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

HexPath runs entirely in the terminal. Create the authorized scope once. A scope
can contain IPv4 networks, IPv6 networks, or both:

```sh
hexpath scope init 192.0.2.0/24 2001:db8:1::/64
```

For a one-off assessment, provide the authorized network directly and skip the
scope file:

```sh
hexpath --scope 2001:db8:1::/64 2001:db8:1::10
hexpath --scope 192.0.2.0/24 192.0.2.10
```

Then assess a target with one command:

```sh
hexpath 2001:db8:1::10
```

That command automatically:

1. Validates the target against `scope.json`.
2. Runs Nmap service and version detection for the target's address family.
3. Checks discovered CPEs against NVD.
4. Builds the directed attack graph.
5. Prints the complete host, service, and CVE topology as ASCII in the terminal.

Familiar Nmap-style flags are also accepted:

```sh
hexpath -6 -sV -Pn -p 22,443 2001:db8:1::10
hexpath -4 -sV -Pn -p 22,443 192.0.2.10
```

The `-4` and `-6` flags are optional checks; HexPath normally infers the address
family from the targets. One scan command cannot mix IPv4 and IPv6 targets, so
run one command per family when a scope contains both.

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

To let HexPath select the most vulnerable reachable host, scan one or more
targets with network-wide ranking enabled:

```sh
hexpath --most-vulnerable --rank-limit 10 192.0.2.10 192.0.2.20
```

HexPath runs Dijkstra once from the entry point, finds the least-cost route to
every reachable host, and ranks the results. The complete ranking is included
under `vulnerable_path_ranking` when using `-oJ` or `--json`.

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
that the vantage address is inside the authorized scope.

Every target must be fully contained within an allowed network of the same
address family. HexPath rejects broader and out-of-scope networks before
starting Nmap. A single Nmap command cannot combine IPv4 and IPv6 targets.

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

Find the most vulnerable path without selecting a destination first:

```sh
hexpath graph vulnerable --graph graph.json
hexpath graph vulnerable --graph graph.json --limit 10 --json
```

This runs a single-source Dijkstra search and ranks the least-cost route to
every reachable host. The first result is the modeled most vulnerable route;
the JSON output includes that path, alternatives, candidate CVE evidence, and
hosts that have no evidence-backed route. The command returns `1` when no other
host is reachable from the selected source.

List the available hosts before selecting a target:

```sh
hexpath graph targets --graph graph.json
```

The list includes hosts without a modeled path. Its reachability status describes
the evidence-backed attack graph, rather than whether a host responds to network
traffic. Use `--source` to list reachability from a different entry or host.

Compare several routes to the same host, using an IP address or an exact node ID:

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
single-route JSON format. These commands also accept an IPv4 or IPv6 address
for `--source`.

The terminal output uses ASCII branches and arrows. Pass `--json` to `graph build` or `graph path` when another program needs machine-readable output.

Each scan contributes reachability only from its recorded vantage. A path can
therefore continue from the entry point, through a candidate service finding to
one host, and then through services observed by a scan run from that host.

Candidate exploit costs use `11 - CVSS score`, plus a confidence penalty of `0` for high, `1.5` for medium, or `3` for low confidence. A missing CVSS score uses the neutral value `5.0`. Lower costs are prioritized by Dijkstra's algorithm. These costs rank investigation paths; they are not exploit probabilities.

Network-wide ranking identifies the easiest evidence-backed route in the graph.
It does not account for business importance, data sensitivity, or blast radius;
use `graph path --target` when a specific critical asset is the destination.

## Remaining engineering work

The shortest-path engine, target comparison, IPv4 support, and network-wide
Dijkstra ranking are implemented. The next milestone is a transparent HexPath
Network Exposure Score from `0` to `100`. The score must describe an observed
network route, rather than presenting CVSS as a network-risk score. Dijkstra's
raw additive cost should remain available for path finding and debugging.

### Integrate the current branch stack

Complete the existing work in dependency order before starting overlapping
changes to path ranking:

- [ ] Merge [PR #10](https://github.com/adamsjack711-ux/HexPath/pull/10), the
  port-range validation fix, into `feat/target-path-comparison`.
- [ ] Open and merge `feat/target-path-comparison` into `main`.
- [ ] Retarget or rebase and merge
  [PR #8](https://github.com/adamsjack711-ux/HexPath/pull/8), IPv4 support.
- [ ] Retarget or rebase and merge
  [PR #11](https://github.com/adamsjack711-ux/HexPath/pull/11), network-wide
  Dijkstra ranking.
- [ ] Run the full test suite after the branches are combined.

### Specify the network score

Agree on and document a versioned formula before implementing it. Each result
should expose the final score, the formula version, every component score, and
the raw observations used to calculate it. The first version should consider:

- **Route accessibility:** confirmed-open and uncertain filtered transitions.
- **Path depth:** the number of required host compromises and pivot points.
- **Route redundancy:** independent evidence-backed routes to the target.
- **Blast radius:** the proportion of hosts reachable after the target is
  compromised.
- **Exploit evidence:** CVSS, match confidence, and supporting evidence on the
  selected route. CVSS remains a severity input and is not treated as an
  exploitation probability.

Network-wide quantities must be normalized so the score remains between `0`
and `100` on small and large graphs. Adding unrelated hosts must not change a
route's accessibility or path-depth components. Adding a real alternate route
or downstream host may change redundancy or blast radius because it changes the
network represented by the graph.

Suggested JSON shape:

```json
{
  "network_score": 84,
  "score_version": "hexpath-network-v1",
  "components": {
    "route_accessibility": 31,
    "path_depth": 17,
    "route_redundancy": 12,
    "blast_radius": 16,
    "exploit_evidence": 8
  }
}
```

The example values above illustrate the output shape; they are not an accepted
formula or grading standard.

### Implement and expose the score

- [ ] Add graph analysis for pivot depth, filtered transitions, independent
  routes, chokepoints, and downstream host reachability.
- [ ] Calculate a deterministic score for every reachable host while retaining
  its raw Dijkstra cost and reconstructed route.
- [ ] Rank `graph vulnerable` and `--most-vulnerable` results by network score.
- [ ] Add component explanations to terminal output and JSON output.
- [ ] Keep unreachable hosts explicit and leave their route score unset.
- [ ] Document the formula, assumptions, and limitations next to the command
  examples.

### Verification and scale

- [ ] Test that direct open routes outrank otherwise equivalent filtered or
  multi-pivot routes.
- [ ] Test that independent routes and downstream reach affect only their
  documented components.
- [ ] Test IPv4 and IPv6 graphs, unreachable hosts, cycles, tied scores, and
  missing CVSS values.
- [ ] Assert that every emitted score is deterministic and within `0` to `100`.
- [ ] Add permanent 100-host and 1,000-host fixtures and record runtime and
  memory use for sparse and dense graphs.
- [ ] Run an authorized multi-vantage lab assessment with at least one pivot,
  save its graph, and compare the reported ranking with the expected topology.

### Suggested work split

Claim a task in a GitHub issue before editing, name the expected files, and use
a separate worktree and branch. The graph API should be completed before the
CLI-output task consumes it.

| Work stream | Primary files | Dependency |
| --- | --- | --- |
| Branch integration | Pull requests and CI | None |
| Score specification | `README.md` or a new design document | Team agreement |
| Graph metrics and score API | `src/hexpath/graph.py`, `tests/test_graph.py` | Score specification |
| CLI and JSON presentation | `src/hexpath/cli.py`, `tests/test_cli.py` | Stable graph score API |
| Large fixtures and performance | New files under `tests/fixtures/` plus focused tests | Stable score API |
| Lab validation and examples | `examples/` and documentation | Working end-to-end score |

After the network score is stable, possible follow-up work includes EPSS and
CISA KEV enrichment, explicit network zones and trust boundaries, asset
criticality as a separate impact dimension, vulnerability-response caching,
and a tagged release with reproducible example graphs.

## Tests

```sh
python -m unittest discover --start-directory tests --verbose
```

## Working together

1. Make sure you’ve accepted your GitHub collaborator invitation so you can contribute directly.
2. Use [Issues](https://github.com/adamsjack711-ux/HexPath/issues) to propose ideas, track tasks, and report problems. Add enough context for a teammate to pick up the work.
3. Work on a separate branch and open a pull request into the default branch. Ask a teammate to review it before merging.
4. Keep this README updated as we agree on the scope and how to run the tool.

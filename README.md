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
- Directed attack-graph construction, ASCII terminal rendering, and Dijkstra or A* path analysis.
- Operator-selected targets and ranked comparison of evidence-backed, loop-free routes.
- Versioned 0–100 network exposure scoring with transparent component evidence.

## Workflow

1. **IP discovery** — Identify live IPv4 or IPv6 hosts within the approved assessment scope.
2. **Service assessment** — Use Nmap to identify exposed services and their reported versions.
3. **CVE enrichment** — Add relevant known-vulnerability candidates from NVD and OSV with explicit evidence and coverage status.
4. **Network modeling** — Represent hosts and potential transitions as a weighted, directed graph.
5. **Path analysis** — Use Dijkstra’s algorithm (default) or A* to identify the lowest-cost modeled path between a selected entry point and target, showing the associated findings along the path.

Strict scope controls are applied before a scan command is constructed. HexPath is intended for lab environments and networks the assessment team is authorized to test.

## Install for development

HexPath requires Python 3.11 or newer. Nmap is also required to execute scans.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --editable .
```

## Compact command syntax

The executable remains `hexpath`. Long commands stay available for scripts and
documentation, while common commands and options also have short forms:

| Long form | Short form |
|-----------|------------|
| `scope`, `scan`, `cve`, `graph` | `sc`, `s`, `c`, `g` |
| `graph build`, `show`, `validate`, `path` | `g b`, `g sh`, `g v`, `g p` |
| `graph targets`, `paths`, `score`, `exposure` | `g t`, `g r`, `g s`, `g x` |
| `--graph`, `--source`, `--target`, `--limit` | `-g`, `-s`, `-t`, `-n` |
| `--algorithm`, `--json`, `--output` | `-a`, `-j`, `-o` |

Scan profiles accept `d` for `discovery` and `s` for `services`. Scan information
levels use `-L 0` through `-L 4`. Path algorithms accept `d` for `dijkstra` and
`a` for `astar`. For example:

```sh
hexpath s p -s scope.json -p d 192.0.2.10
hexpath s p -s scope.json -L 2 192.0.2.10
hexpath g p -g graph.json -t 192.0.2.10 -a a
hexpath g s -g graph.json -t 192.0.2.10 -j
hexpath g x -g graph.json -n 10 -j
```

Run `hexpath -V` for the installed version. Command-specific help shows both
forms, such as `hexpath g p -h`.

## Scope and scanning

HexPath offers five information levels so an operator can choose scan depth
without assembling raw Nmap arguments:

| Level | Profile | Relative wait | Information collected |
|-------|---------|---------------|-----------------------|
| 0 | `discovery` | Fastest | Host availability only; no ports or services. |
| 1 | `quick` | Short | Open state for the 100 most common TCP ports. |
| 2 | `services` | Moderate | Top 1,000 TCP ports with light version and CPE probes. |
| 3 | `full` | Long | All 65,535 TCP ports with light version and CPE probes. |
| 4 | `deep` | Longest | All TCP ports with every available version probe. |

List these definitions from the CLI with `hexpath scan levels` or the compact
`hexpath s l`. Add `-j` for JSON. Wait labels are relative: duration depends on
target count, latency, filtering, and the services encountered. Levels control
information breadth and probe depth; they are not Nmap `-T` timing templates.
Level 0 remains the default, and `-L` is mutually exclusive with `-p/--profile`.
`scan run` keeps a five-minute safety timeout unless `-t/--timeout` is supplied;
for example, `-t 1800` permits a selected deeper scan to run for up to 30
minutes without promising that it will finish in that time.

Preview a discovery command after validating the target against the scope file:

```sh
hexpath scan plan \
  --scope examples/lab-scope.example.json \
  --level 0 \
  2001:db8:1::10
```

IPv4 targets use the same workflow. HexPath infers the address family and omits
Nmap's `-6` switch for IPv4:

```sh
hexpath scan plan \
  --scope examples/lab-scope.example.json \
  --profile discovery \
  192.0.2.10
```

Use `-4` or `-6` on `scan plan` and `scan run` when you want HexPath to verify
the intended family explicitly. One scan command cannot mix IPv4 and IPv6
targets; run one command per family when a scope contains both.

Run service detection and save the normalized JSON result:

```sh
hexpath scan run \
  --scope examples/lab-scope.example.json \
  --profile services \
  2001:db8:1::10 > scan.json
```

For a focused service scan, select a validated numeric port list or range with
`--ports`. Custom ports are available only with the `services` profile so they
cannot silently change the fixed definitions of information levels 0–4:

```sh
hexpath scan run \
  --scope examples/lab-scope.example.json \
  --profile services \
  --ports 22,80,443,8000-8100 \
  2001:db8:1::10 > focused-scan.json
```

If an authorized host does not answer discovery probes, add `-Pn` to
`scan plan` or `scan run` to tell Nmap to treat the target as online. Preview
the resulting command with `scan plan` before running it.

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
starting Nmap. By default, IPv4 scope networks must be `/24` or narrower and
IPv6 scope networks must be `/48` or narrower.

The scope file is the main guard against scanning the wrong network, so a
scope target is refused if it is too broad or is a special-use range. By
default IPv4 scope networks must be `/24` or narrower and IPv6 networks must
be `/48` or narrower, so a mistyped prefix cannot silently authorize a huge
range. Multicast, loopback, unspecified, link-local, and IPv4-mapped ranges are
always refused. A deliberately wider scope can be allowed through the Python
API with a lower `minimum_ipv4_prefix_length` or `minimum_prefix_length`, but
the special-use ranges stay refused regardless.

## CVE checking

Check every unique service CPE across saved scans against NVD:

```sh
hexpath cve scan \
  --input scan.json \
  --input scan-from-host-10.json > cve-results.json
```

Repeated services and CPEs are deduplicated, so the same CPE is queried once.
A CPE that cannot be converted for NVD is listed under `invalid_cpes` and the
rest of the scan is still checked; the result is then marked incomplete.

Check one Nmap CPE directly:

```sh
hexpath cve cpe --cpe cpe:/a:openbsd:openssh:9.6
```

Check an exact package version through OSV using the pkgxray-derived package lookup:

```sh
hexpath cve package --ecosystem PyPI --package Jinja2 --version 2.4.1
```

Set `NVD_API_KEY` in the environment when an NVD API key is available. HexPath sends it through the required request header and does not include it in results.

NVD limits how often it can be queried, so HexPath spaces out its requests:
6 seconds apart without an API key, 0.6 seconds with one. A scan with ten
unique CPEs therefore takes about a minute without a key. If NVD still
throttles a request (HTTP 403, 429 or 503), HexPath waits and retries up to
three times, honouring NVD's `Retry-After` header when present, before
recording that CPE as an incomplete lookup. CPEs with more results than fit
in one NVD response are fetched page by page.

CPE findings are candidate matches. Nmap identifies the product and version remotely, and NVD identifies applicable CVEs, but a vendor may have backported a patch without changing the reported version. HexPath therefore records these links as inferred, medium-confidence evidence until patch status is validated.

## Attack graph

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

Validate a saved graph's structure and summarize its node and relationship
counts without running path analysis:

```sh
hexpath graph validate --graph graph.json
hexpath graph validate --graph graph.json --json
```

Find and display the lowest-cost directed path to a selected host. The target
can be an exact node identifier or an IP address:

```sh
hexpath graph path \
  --graph graph.json \
  --target host:2001:db8:1::10
```

List available host targets before choosing one:

```sh
hexpath graph targets --graph graph.json
```

The list includes hosts without a modeled path. Reachability here means that
the saved graph contains an evidence-backed directed route; it does not mean
that the host currently responds to network traffic. Use `--source` to inspect
reachability from a different entry point or host.

Compare several routes to the same host using an IPv4 address, IPv6 address,
or exact node identifier:

```sh
hexpath graph paths \
  --graph graph.json \
  --target 2001:db8:1::10 \
  --limit 3
```

Routes are ordered by total cost and never revisit a node. Parallel transitions,
including alternative CVEs on the same service, remain distinct routes. The
limit defaults to three and accepts values from one to twenty. Add `--json` to
retain each route's nodes, edges, evidence, rank, and cost difference from the
cheapest route in machine-readable output.

`graph paths` exits with status `0` when at least one route exists, `1` when a
known target has no directed path, and `2` for invalid input or an unknown
target. The command uses Yen's algorithm with Dijkstra spur searches and does
not enumerate every possible route.

Score one selected host while keeping its full route and evidence:

```sh
hexpath graph score --graph graph.json --target 2001:db8:1::10
hexpath graph score --graph graph.json --target 2001:db8:1::10 --json
```

`graph score` exits with status `1` and leaves `network_score` unset when the
host is known but unreachable from the selected source.

Rank modeled network exposure without selecting a destination first:

```sh
hexpath graph exposure --graph graph.json
hexpath graph exposure --graph graph.json --limit 10 --json
```

`graph vulnerable` remains available as a compatibility alias for
`graph exposure`.

This runs one single-source Dijkstra search, selects the least-cost route to
every reachable host, and ranks the hosts by HexPath's versioned 0–100 network
exposure score. A higher score means greater modeled exposure. It is not CVSS,
an exploit probability, or proof that exploitation will succeed. JSON output
keeps the raw Dijkstra cost and full evidence-backed path alongside every score
component and its input observations. Hosts without a directed path are listed
explicitly with `network_score: null`. The command exits with status `1` when
no other host is reachable from the selected source.

The current model is `hexpath-network-v1`. Each component is rounded to two
decimal places, then the components are summed and bounded to 0–100:

| Component | Maximum | Calculation |
|-----------|---------|-------------|
| Route accessibility | 30 | Mean state factor for reachability edges on the selected path: `open=1`, `open\|filtered=0.5`, `filtered=0.25`, unknown state `=0`. |
| Path depth | 15 | `15 / host compromises`, counting the target and pivot hosts after the source. |
| Route redundancy | 15 | Five points per independent alternative beyond the first, capped at four routes. Routes must be internally vertex-disjoint; parallel CVE edges between the same nodes count once. |
| Blast radius | 15 | Proportion of other modeled hosts reachable downstream from the target. The selected source and target are excluded from the denominator. |
| Exploit evidence | 25 | Mean of `CVSS factor × confidence factor × strongest evidence factor` for candidate-exploit edges on the selected path. |

For exploit evidence, the CVSS factor is `score / 10`; a missing or invalid
score uses the neutral factor `0.5`. Confidence factors are `high=1`,
`medium=0.75`, `low=0.5`, and unknown `=0.25`. Evidence factors are
`validated=1`, `observed=0.85`, and `inferred=0.65`. A path with no applicable
reachability or exploit edges receives zero for that component. A target with
no other eligible hosts receives zero blast-radius points.

Scores are a transparent prioritization aid. The model does not include asset
value, data sensitivity, compensating controls, exploit availability, patch
status, or real-world impact. Use the component observations and retained path
evidence—not the total alone—when deciding what to investigate.

Try the same saved graph with A* by adding `--algorithm astar`:

```sh
hexpath graph path \
  --graph graph.json \
  --target host:2001:db8:1::10 \
  --algorithm astar
```

Both algorithms return the same minimum cost and preserve the path's evidence
and output format. Equally cheap routes can produce different node sequences.
Dijkstra remains the default; select it explicitly with `--algorithm dijkstra`.
The Python API also supports
`graph.shortest_path(source, target, algorithm="astar")`.

A* prioritizes the cost so far plus an estimate of the remaining cost. HexPath
computes that estimate as the minimum directed hop count to the target times
the smallest edge weight. A reverse breadth-first traversal supplies those hop
counts and excludes nodes that cannot reach the target. This estimate is a
lower bound because every remaining route needs at least that many edges,
each costing at least the minimum weight. IP addresses are not used as spatial
coordinates. See [Boost's A* documentation](https://www.boost.org/doc/libs/1_74_0/libs/graph/doc/astar_search.html)
for the search priority `f = g + h`.

The hop-count pass adds O(V + E) work and memory per query. A* can reduce the
forward search, but a faster total runtime is not guaranteed, especially for
small graphs or graphs whose edge costs vary widely. Compare both algorithms
on your saved lab graph before choosing one.

For an offline comparison without scanning or CVE lookups, run the synthetic
example from the repository root after installing HexPath:

```sh
.venv/bin/hexpath graph path --graph examples/path-comparison.example.json --target host:target --algorithm dijkstra
.venv/bin/hexpath graph path --graph examples/path-comparison.example.json --target host:target --algorithm astar
```

Both should choose `entry:scanner -> host:a -> host:b -> host:target` with a
total cost of `3.00`, rather than the direct edge costing `10.00`.

The terminal output uses ASCII branches and arrows. Branches are drawn at most
100 levels deep; a longer route is marked `(continued below: depth limit
reached)` and its remainder is drawn as a separate tree further down. Pass
`--json` to `graph build`, `graph validate`, `graph path`, `graph paths`,
`graph targets`, `graph score`, or `graph exposure` when another program needs
machine-readable output.

Each scan contributes reachability only from its recorded vantage. A path can
therefore continue from the entry point, through a candidate service finding to
one host, and then through services observed by a scan run from that host.

Candidate exploit costs use `11 - CVSS score`, plus a confidence penalty of `0` for high, `1.5` for medium, or `3` for low confidence. A missing CVSS score uses the neutral value `5.0`. Both algorithms minimize the total cost. These costs rank investigation paths; they are not exploit probabilities.

Network-wide exposure ranking considers modeled accessibility, path depth,
route redundancy, downstream reach, and exploit evidence. It still does not
account for business importance or data sensitivity; use `graph path --target`
when a specific critical asset is the destination.

## Tests

```sh
python -m unittest discover --start-directory tests --verbose
```

## Working together

1. Make sure you’ve accepted your GitHub collaborator invitation so you can contribute directly.
2. Use [Issues](https://github.com/adamsjack711-ux/HexPath/issues) to propose ideas, track tasks, and report problems. Add enough context for a teammate to pick up the work.
3. Work on a separate branch and open a pull request into the default branch. Ask a teammate to review it before merging.
4. Keep this README updated as we agree on the scope and how to run the tool.

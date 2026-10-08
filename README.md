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

## Scope and scanning

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

Find and display the lowest-cost directed path to a selected host:

```sh
hexpath graph path \
  --graph graph.json \
  --target host:2001:db8:1::10
```

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

## Next milestone

Add operator-supplied target selection and clearer path comparison when several
evidence-backed routes reach the same host.

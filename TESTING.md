# HexPath test plan (lab VM)

A shared checklist so everyone tests HexPath the same way against the
authorized lab VM. Run it from the machine that is allowed to reach the lab
network (for the group, the scanning server reached over SSH). Do not run it
against anything other than the VM the team is authorized to test.

> The pass criteria below describe HexPath with the current fix pull requests
> merged (narrow-scope enforcement, NVD request pacing, and reporting an
> unchecked scan as `unknown` rather than `clean`). If a check behaves
> differently, confirm which version of the branch you are testing.

## Prerequisites

- Python 3.11 or newer and Nmap installed on the scanning host.
- HexPath installed for development:
  ```sh
  python3 -m venv .venv
  .venv/bin/python -m pip install --editable .
  ```
- The VM's IPv6 address, confirmed with the person who owns the lab.
- Optional: an NVD API key exported as `NVD_API_KEY` for faster CVE lookups.
  Without one, HexPath spaces NVD requests ~6 seconds apart.

## Scope file

Put only the VM in scope as a single `/128`, so HexPath refuses every other
address. Save this as `lab-vm.scope.json` and share the one copy:

```json
{
  "name": "HexPath lab VM",
  "targets": ["<VM IPv6 address>/128"]
}
```

| # | Check | Command | Pass criteria |
|---|-------|---------|---------------|
| 0 | Scope loads and is narrow | `hexpath scope check --scope lab-vm.scope.json --target <VM IPv6>` | Prints `authorized: <addr> is within HexPath lab VM`. |
| 0b | Scope rejects anything else | `hexpath scope check --scope lab-vm.scope.json --target 2001:db8:9::9` | Exits non-zero with `outside authorized scope`. |

## 1. Discovery

| # | Check | Command | Pass criteria |
|---|-------|---------|---------------|
| 1 | Plan a discovery scan | `hexpath scan plan --scope lab-vm.scope.json --profile discovery <VM IPv6>` | Prints an `nmap -6 ... -sn <VM>/128` command. Nothing runs. |
| 2 | Run discovery | `hexpath scan run --scope lab-vm.scope.json --profile discovery <VM IPv6> > discovery.json` | `discovery.json` lists the VM under `hosts` and has an empty `services` list. |

## 2. Service assessment

| # | Check | Command | Pass criteria |
|---|-------|---------|---------------|
| 3 | Run a service scan | `hexpath scan run --scope lab-vm.scope.json --profile services <VM IPv6> > scan.json` | `scan.json` lists the services you expect on the VM (confirm against what the VM actually runs). |
| 4 | Vantage recorded | add `--vantage host:<VM IPv6>` when scanning from the VM itself | `vantage` in the output is `host:<VM IPv6>`, not `entry:scanner`. |

## 3. CVE enrichment

| # | Check | Command | Pass criteria |
|---|-------|---------|---------------|
| 5 | Check CVEs for the scan | `hexpath cve scan --input scan.json > cves.json` | Finishes without errors. `coverage` shows how many CPEs were checked. |
| 6 | Coverage is honest | inspect `cves.json` | `status` is `vulnerable`, `clean`, or `unknown`. A scan with no services, or one where a lookup failed, is **not** reported as `clean`. |
| 7 | One CVE lookup | `hexpath cve cpe --cpe cpe:/a:openbsd:openssh:9.6` | Prints `completed: true` and a list of CVEs (needs network to NVD). |

## 4. Attack graph and paths

| # | Check | Command | Pass criteria |
|---|-------|---------|---------------|
| 8 | Build the graph | `hexpath graph build --scan scan.json --cves cves.json --output graph.json` | Prints an ASCII graph; `graph.json` is written. |
| 9 | Redisplay a saved graph | `hexpath graph show --graph graph.json` | Same ASCII graph, no error. |
| 10 | Lowest-cost path | `hexpath graph path --graph graph.json --target host:<VM IPv6>` | Prints a path from the entry point to the VM with a total cost, or a clear "no path" message. |

## What the results mean

- **Costs rank which routes to investigate first; they are not exploit
  probabilities.** A lower cost just means a more severe, higher-confidence
  candidate.
- **CVE matches are candidates, not confirmations.** Nmap identifies a product
  and version remotely; NVD lists CVEs for it. A vendor may have backported a
  patch, so HexPath records these as medium-confidence until verified.
- **`unknown` is not `clean`.** `unknown` means a lookup did not complete or
  there was nothing to check; investigate before drawing conclusions.

## Recording results

For each run, note the date, who ran it, the VM address, and whether each
check passed. File anything that fails as a GitHub issue with the command, the
output, and what you expected.

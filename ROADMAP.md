# HexPath group roadmap

Updated 2026-10-13.

## Outcome

Ship one reviewed, dual-stack HexPath release that can discover authorized
hosts, enrich service evidence, compare attack paths, and explain a versioned
0–100 network exposure score. The release should be reproducible in CI and
validated against the group's authorized lab environment.

## Current position

- `main` is stable and its recent CI runs pass on Python 3.11–3.14.
- There are no open GitHub issues, so the work below should be converted into
  claimed issues before implementation starts.
- Six pull requests are open and their checks pass, but none currently has an
  approved review.
- [PR #15](https://github.com/adamsjack711-ux/HexPath/pull/15) is the proposed
  consolidation branch. It includes dual-stack support, target and route
  comparison, A* as an optional algorithm, scan levels, and the first version
  of the network exposure score.
- [PR #8](https://github.com/adamsjack711-ux/HexPath/pull/8),
  [PR #10](https://github.com/adamsjack711-ux/HexPath/pull/10), and
  [PR #11](https://github.com/adamsjack711-ux/HexPath/pull/11) form an older
  dependency stack. Do not merge both implementations of the same feature.
- [PR #17](https://github.com/adamsjack711-ux/HexPath/pull/17) is a small graph
  safety fix. [PR #16](https://github.com/adamsjack711-ux/HexPath/pull/16) adds
  Nmap setup and is still a draft.

The main risk is integration, not a lack of feature code. The group should
first decide what lands, then validate it as one product.

## Recommended merge strategy

Use PR #15 as the consolidation path, subject to the parity and review gates
below. It is based directly on `main` and already covers most of the older
stack. Do not close PRs #8, #10, or #11 until the parity table is complete and
any behavior the group wants to preserve has been carried forward.

Recommended order:

1. Merge PR #17 into `main`.
2. Rebase PR #15 onto the updated `main` and preserve PR #17's edge-weight cap
   and regression tests while resolving `graph.py`.
3. Complete the parity, score-model, CLI, and security reviews for PR #15.
4. Merge PR #15, then run the entire suite from a clean checkout.
5. Close PRs #8 and #11 as superseded. Close PR #10 only if custom port input
   is intentionally removed; otherwise forward-port its validation and tests.
6. Rebase PR #16 onto the new `main`, finish its platform and safety review,
   mark it ready, and merge it separately.

## Four-week delivery plan

The dates are targets, not promises. If the group is smaller, one person may
own more than one lane, but each issue and pull request should still have one
clear owner.

### Week 1 — Integration decision and review setup (October 13–16)

Goal: agree on one integration path and make the large change reviewable.

- [ ] Create one GitHub issue for each workstream in this roadmap and assign an
  owner before code changes begin.
- [ ] Build a feature-parity table comparing `main`, PR #15, and the older
  #8/#10/#11 stack. Explicitly check IPv4/IPv6 scope handling, target
  selection, multiple paths, filtered-host scans, custom ports, server
  inventory/virtualization, vulnerable-host ranking, and JSON compatibility.
- [ ] Record whether custom port selection and server inventory are supported,
  intentionally deferred, or accidental regressions in PR #15.
- [ ] Review the `hexpath-network-v1` formula as a group. Approve the component
  weights, normalization, tie-breaking, missing-CVSS behavior, and the claim
  that the score is exposure evidence rather than exploit probability.
- [ ] Assign separate reviewers for graph/scoring logic and CLI/scanner logic.
- [ ] Merge PR #17 after one approval and green CI.

Exit criteria:

- The parity decision is written in a GitHub issue or PR #15 comment.
- Every PR has an owner and reviewer.
- PR #17 is on `main`.
- The group has agreed which older PRs PR #15 will supersede.

### Week 2 — Consolidate the product (October 19–23)

Goal: land one coherent implementation on `main` without silent regressions.

- [ ] Rebase PR #15 after PR #17 and resolve the graph conflict explicitly.
- [ ] Add or retain a regression test for every parity-table decision.
- [ ] Review graph loading, bounded weights, path reconstruction, cycles,
  deterministic ties, unreachable hosts, and Dijkstra/A* equivalence.
- [ ] Review every CLI alias and long-form command for backward compatibility,
  exit codes, JSON shape, terminal safety, and scope enforcement.
- [ ] Confirm all scan levels use fixed, tool-controlled Nmap arguments and do
  not widen the authorized target scope.
- [ ] Verify that score output always includes the version, components, raw
  observations, selected path, and raw path cost.
- [ ] Run unit tests on Python 3.11, 3.12, 3.13, and 3.14, plus `compileall` and
  `git diff --check`.
- [ ] Merge PR #15 only after both technical reviews approve it.
- [ ] Close superseded PRs with a comment linking to the replacement and any
  follow-up issue.

Exit criteria:

- `main` contains the chosen dual-stack path and exposure-score implementation.
- CI is green on all supported Python versions.
- No accepted feature from the parity table has disappeared without a tracked
  decision.

### Week 3 — Setup, scale, and lab validation (October 26–30)

Goal: prove that the integrated code works outside isolated unit tests.

- [ ] Rebase PR #16, finish its draft checklist, and test `setup nmap --check`
  without system changes.
- [ ] Review Nmap installation behavior for macOS and supported Linux package
  managers. It must explain commands before execution, surface privilege
  requirements, remain idempotent, and fail clearly on unsupported platforms.
- [ ] Add permanent 100-host and 1,000-host sparse and dense graph fixtures.
- [ ] Record runtime and peak memory for graph validation, path ranking, and
  exposure scoring. Set generous regression thresholds in the test plan.
- [ ] Run the shared `TESTING.md` procedure against the authorized lab VM.
- [ ] Add one multi-vantage test with a real pivot and compare the generated
  graph, cheapest path, and exposure ranking with the expected topology.
- [ ] Save sanitized example inputs and outputs that contain no real addresses,
  credentials, API keys, or identifying lab data.

Exit criteria:

- PR #16 is either merged or deferred with a documented reason.
- Scale results are recorded and repeatable.
- The lab checklist passes, or every failure has a filed issue with evidence.

### Week 4 — Release candidate (November 2–6)

Goal: make the result easy for another person to install, run, and evaluate.

- [ ] Update README examples and `TESTING.md` to match the merged CLI exactly.
- [ ] Add a concise changelog for the release and remove stale branch-specific
  instructions from `AGENTS.md`.
- [ ] Confirm the repository has an agreed license and security-reporting
  instructions before publishing a package or release artifact.
- [ ] Build a wheel and source distribution, install each in a clean virtual
  environment, and run CLI smoke tests without an editable checkout.
- [ ] Run the full unit, scale, and authorized lab suites from a release
  candidate commit.
- [ ] Tag the release only after the acceptance checklist below is complete.

Exit criteria:

- A clean user can install HexPath and complete the documented workflow.
- The release notes state the safety model and known limitations.
- The release candidate has an approval from someone other than its author.

## Workstream ownership

| Lane | Primary responsibility | Main surfaces | Can proceed in parallel with |
| --- | --- | --- | --- |
| Integration lead | Parity table, merge order, conflict resolution, closing superseded PRs | GitHub, `AGENTS.md` | Review planning |
| Graph and scoring | Paths, score formula, determinism, overflow, scale | `src/hexpath/graph.py`, `tests/test_graph.py` | Setup work after API agreement |
| CLI and scanning | Commands, aliases, scope safety, scan levels, JSON compatibility | `src/hexpath/cli.py`, `src/hexpath/scanner.py`, related tests | Graph review with agreed interfaces |
| Setup and portability | Nmap detection/install behavior and platform tests | `src/hexpath/setup.py`, setup tests | Graph and score work |
| QA and lab | Fixtures, benchmarks, clean installs, authorized lab checklist | `tests/fixtures/`, `TESTING.md`, `examples/` | All implementation lanes |
| Documentation and release | User workflow, limitations, changelog, release checklist | `README.md`, release metadata | QA after CLI stabilizes |

For a three-person group, combine Integration with Documentation, Graph with
QA, and CLI with Setup. Keep review ownership separate: no one should be the
only approver of their own change.

## Pull-request rules

- Create or claim an issue before editing and list the expected files.
- Use one branch and worktree per issue.
- Keep graph API changes separate from CLI presentation when practical.
- Include tests and user-facing documentation in the same PR as a behavior
  change.
- Require green CI and at least one non-author review.
- Do not mix new enrichment features into the integration release.
- Treat changes to scope enforcement, command execution, graph loading, and
  score interpretation as security-sensitive.

## Release acceptance checklist

- [ ] IPv4 and IPv6 targets are accepted only when explicitly authorized.
- [ ] Discovery, service scanning, CVE enrichment, graph building, path
  comparison, and exposure scoring work through the documented CLI.
- [ ] Dijkstra remains the default, and optional algorithms return equivalent
  optimal costs on admissible inputs.
- [ ] Unreachable hosts remain visible and have no exposure score.
- [ ] Every score is deterministic, bounded from 0 to 100, versioned, and
  explained by components and observations.
- [ ] Malformed or adversarial graph values fail clearly instead of producing
  a false unreachable result.
- [ ] Unit tests pass on Python 3.11–3.14.
- [ ] Sparse and dense scale checks meet the recorded thresholds.
- [ ] The authorized multi-vantage lab run matches the expected topology.
- [ ] Installation and smoke tests pass from built artifacts.
- [ ] Documentation contains no unsupported claims about exploitation,
  vulnerability confirmation, or network authorization.

## After the integration release

Start these only after the release acceptance checklist is complete:

1. Add EPSS and CISA KEV as separately sourced enrichment signals.
2. Model network zones and trust boundaries explicitly.
3. Add asset criticality as an impact dimension separate from exposure.
4. Cache vulnerability responses with provenance and expiry information.
5. Add signed, reproducible release artifacts and a regular dependency review.


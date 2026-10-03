# HexPath

An IPv6 penetration-testing tool for lab practice and authorized engagements.

HexPath is our school group project to connect IPv6 network discovery, service assessment, CVE enrichment, and attack-path analysis in one workflow. The goal is to turn a long list of findings into a clear, prioritized view of potential paths through a network, so reviewers can understand how findings relate and where to focus their assessment.

## Project status

This repository currently contains project documentation only.

The capabilities below describe the planned tool. Implementation, installation instructions, and a working release will follow as development progresses.

## Planned workflow

1. **IPv6 discovery** — Identify live IPv6 hosts within the approved assessment scope, with support planned for local network discovery and larger target sets.
2. **Service assessment** — Use Nmap to identify exposed services and their reported versions.
3. **CVE enrichment** — Add relevant known-vulnerability information from the National Vulnerability Database (NVD) to support review of the findings.
4. **Network modeling** — Represent hosts and potential transitions as a weighted, directed graph.
5. **Path analysis** — Use Dijkstra’s algorithm to identify the lowest-cost modeled path between a selected entry point and target, showing the associated findings along the path.

Strict scope controls and adaptive scan profiles are part of the planned design. HexPath is intended for lab environments and networks the assessment team is authorized to test.

## Planning the tool

Before implementation, we’ll record:

- What problem HexPath solves and who will use it.
- The features we need for our first version.
- The tools and technologies we’ll use.
- Team responsibilities and project deadlines.

## Working together

1. Make sure you’ve accepted your GitHub collaborator invitation so you can contribute directly.
2. Use [Issues](https://github.com/adamsjack711-ux/HexPath/issues) to propose ideas, track tasks, and report problems. Add enough context for a teammate to pick up the work.
3. When development begins, work on a separate branch and open a pull request into the default branch. Ask a teammate to review it before merging.
4. Keep this README updated as we agree on the scope and how to run the tool.

## Next milestone

Agree on the first version’s scope, the lab environment, and the team’s responsibilities.

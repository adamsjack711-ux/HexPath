# HexPath handoff

**Updated:** 17 November 2026

**Checkout:** `hexpath-ipv6-cli`

**Branch:** `fix/assessment-evidence-clarity`

The saved-scan workflow now imports a scoped ZGrab2 MongoDB `buildInfo.version` result with `hexpath scan confirm-mongodb`. It preserves the original Nmap identity and shows any version difference in the target assessment. The importer does not run a network probe. Usage is in `README.md`.

The assessment now returns structured `next_checks` and prints target-specific follow-ups for missing exact versions, incomplete CVE lookups, candidate conditions without observed access effects, and unobserved targets. It also asks for a record of tested IPv6 addresses, ports, protocols, and vantage because service observations do not prove full scan coverage.

On 17 November the remote `feat/os-fingerprint-scoring` branch was fetched. The user narrowed this work to IPv6 information and host grading, so its OS fingerprint collection was adapted into `scan -O` and host summaries. The branch's graph scoring changes were not merged. The host information grade measures exact CPE and completed lookup coverage for open services; OS guesses are displayed separately and do not imply patch status.

The five-host IPv6 lab confirmed MongoDB 6.0.28 where Nmap reported “6.1 or later.” The import changed the MongoDB CPE from broad to exact. A saved 14 November NVD response yielded four candidate CVEs and no observed access-effect evidence or supported path. PostgreSQL's unauthenticated probe supplied no exact server version. The local report and raw evidence are under `/Users/jackadams-lovell/outputs/hexpath/ipv6-followup-20261115/`; they are not part of this repository.

Verification: `PYTHONPATH=src python3 -m unittest discover -s tests` passed 209 tests and `git diff --check` passed. The 17 November CLI replay on the saved five-host IPv6 lab produced a specific next-check section for all five target views without creating a supported path. A bounded live Nmap `-6 -O` probe on two internal lab hosts returned the same Linux 4.19–5.17 guess at Nmap's reported 93% accuracy; the raw XML and grade results are under `/Users/jackadams-lovell/outputs/hexpath/ipv6-host-information-20261117/`. The earlier next-check replay is under `/Users/jackadams-lovell/outputs/hexpath/ipv6-next-steps-20261117/`. A fresh NVD check was incomplete because DNS resolution failed in the test environment.

Next: obtain authorized PostgreSQL version evidence and rerun current NVD lookups when available. Add a scan coverage manifest so HexPath can display the actual tested IPv6 addresses, ports, protocols, and scan origins rather than asking the operator to record them separately.

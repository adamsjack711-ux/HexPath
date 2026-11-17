# HexPath handoff

**Updated:** 17 November 2026

**Checkout:** `hexpath-ipv6-cli`

**Branch:** `fix/assessment-evidence-clarity`

The saved-scan workflow now imports a scoped ZGrab2 MongoDB `buildInfo.version` result with `hexpath scan confirm-mongodb`. It preserves the original Nmap identity and shows any version difference in the target assessment. The importer does not run a network probe. Usage is in `README.md`.

The assessment now returns structured `next_checks` and prints target-specific follow-ups for missing exact versions, incomplete CVE lookups, candidate conditions without observed access effects, and unobserved targets. It also asks for a record of tested IPv6 addresses, ports, protocols, and vantage because service observations do not prove full scan coverage.

The five-host IPv6 lab confirmed MongoDB 6.0.28 where Nmap reported “6.1 or later.” The import changed the MongoDB CPE from broad to exact. A saved 14 November NVD response yielded four candidate CVEs and no observed access-effect evidence or supported path. PostgreSQL's unauthenticated probe supplied no exact server version. The local report and raw evidence are under `/Users/jackadams-lovell/outputs/hexpath/ipv6-followup-20261115/`; they are not part of this repository.

Verification: `PYTHONPATH=src python3 -m unittest discover -s tests` passed 202 tests. The CLI replay on the saved five-host IPv6 lab produced a specific next-check section for all five target views without creating a supported path. The 17 November replay and before/after notes are under `/Users/jackadams-lovell/outputs/hexpath/ipv6-next-steps-20261117/`; this is saved evidence, not a fresh network scan. A fresh NVD check was incomplete because DNS resolution failed in the test environment.

Next: obtain authorized PostgreSQL version evidence and rerun current NVD lookups when available. Add a scan coverage manifest so HexPath can display the actual tested IPv6 addresses, ports, protocols, and scan origins rather than asking the operator to record them separately.

# HexPath handoff

**Updated:** 15 November 2026

**Checkout:** `hexpath-ipv6-cli`

**Branch:** `fix/assessment-evidence-clarity`

The saved-scan workflow now imports a scoped ZGrab2 MongoDB `buildInfo.version` result with `hexpath scan confirm-mongodb`. It preserves the original Nmap identity and shows any version difference in the target assessment. The importer does not run a network probe. Usage is in `README.md`.

The five-host IPv6 lab confirmed MongoDB 6.0.28 where Nmap reported “6.1 or later.” The import changed the MongoDB CPE from broad to exact. A saved 14 November NVD response yielded four candidate CVEs and no observed access-effect evidence or supported path. PostgreSQL's unauthenticated probe supplied no exact server version. The local report and raw evidence are under `/Users/jackadams-lovell/outputs/hexpath/ipv6-followup-20261115/`; they are not part of this repository.

Verification: `PYTHONPATH=src python3 -m unittest discover -s tests` passed 199 tests; `git diff --check` passed. The new CLI command also produced a confirmed scan and an assessment from saved five-host lab evidence. A fresh NVD check was incomplete because DNS resolution failed in the test environment.

Next: obtain authorized PostgreSQL version evidence, rerun current NVD lookups when available, and continue improving how the assessment presents tested IPv6 addresses, ports, and scan origins.

# HexPath handoff

**Updated:** 18 November 2026

**Canonical checkout for the Windows release:** `hexpath-simple-cli`

**Branch:** `feat/simple-cli`

**Released commit:** `6b4fb1842ef628552cd2ae2bc6778e83570feab1`

## Windows executable release

HexPath `v0.1.1` is published at
<https://github.com/adamsjack711-ux/HexPath/releases/tag/v0.1.1>. The release
contains `HexPath-Windows-x64.zip` and a portable SHA-256 checksum file. The ZIP
contains the standalone 64-bit `hexpath.exe` and `WINDOWS.md`; Python is not
required on the destination computer. Nmap remains a separate prerequisite for
live scans. The executable is not code-signed, so Windows SmartScreen may warn.

GitHub Actions run `44352182363` built on native `windows-latest`, ran all 213
unit tests, smoke-tested the packaged executable's version, help, plan mode, and
offline saved-assessment flow, generated the ZIP and checksum, and published
the release. Both build and publication jobs passed. The general test workflow
also runs the full suite on Ubuntu and Windows with Python 3.11 through 3.14.

The published assets were downloaded independently after publication. The
checksum file passed `shasum -a 256 -c`; the ZIP SHA-256 is
`0d1372cda8e969087ded3d9360c85c600ddb9a09c46780c6395c8e17cb905ac3`.
The extracted executable was identified as a PE32+ x86-64 Windows console
executable. No live network scan was used for release verification.

The Windows runtime now locates Nmap through `PATH` and the standard system and
per-user Windows installation directories. The release workflow is tag-driven,
pins PyInstaller 6.16.0, and retains a manually downloadable Actions artifact
for non-tag runs.

## Prior development context (17 November 2026)

The saved-scan workflow now imports a scoped ZGrab2 MongoDB `buildInfo.version` result with `hexpath scan confirm-mongodb`. It preserves the original Nmap identity and shows any version difference in the target assessment. The importer does not run a network probe. Usage is in `README.md`.

The assessment now returns structured `next_checks` and prints target-specific follow-ups for missing exact versions, incomplete CVE lookups, candidate conditions without observed access effects, and unobserved targets. It also asks for a record of tested IPv6 addresses, ports, protocols, and vantage because service observations do not prove full scan coverage.

The five-host IPv6 lab confirmed MongoDB 6.0.28 where Nmap reported “6.1 or later.” The import changed the MongoDB CPE from broad to exact. A saved 14 November NVD response yielded four candidate CVEs and no observed access-effect evidence or supported path. PostgreSQL's unauthenticated probe supplied no exact server version. The local report and raw evidence are under `/Users/jackadams-lovell/outputs/hexpath/ipv6-followup-20261115/`; they are not part of this repository.

Verification: `PYTHONPATH=src python3 -m unittest discover -s tests` passed 202 tests. The CLI replay on the saved five-host IPv6 lab produced a specific next-check section for all five target views without creating a supported path. The 17 November replay and before/after notes are under `/Users/jackadams-lovell/outputs/hexpath/ipv6-next-steps-20261117/`; this is saved evidence, not a fresh network scan. A fresh NVD check was incomplete because DNS resolution failed in the test environment.

Next: obtain authorized PostgreSQL version evidence and rerun current NVD lookups when available. Add a scan coverage manifest so HexPath can display the actual tested IPv6 addresses, ports, protocols, and scan origins rather than asking the operator to record them separately.

# 1,000-rule registry reconciliation — 2026-11-16

Source snapshot: `c54b87b4b6c6a7d82e64d7226f7c5899778d9313`; Git tree `40b041432cacf1800501ff5aa9eacda0cd22a3ed`. Core default registry only; compiled content-pack overlays excluded. All 1,000 constructors have canonical unique IDs R001–R1000, no gaps, and exactly one matching source filename in the complete Git tree. The previous generated catalog (965 entries, commit a740c3df528ba8f5d5323f5ab7797d715390ade0) was reused only for 938 byte-identical source blobs; the 62 changed/new rule descriptors were directly inspected and checked against registration IDs. The refreshed catalog covers 1,000 IDs. This is a static source reconciliation, not a compilation or new detector execution. Catalog digest now hashes the ordered path/Git-blob identities (SHA-256 truncated to 20 hex characters), with generator aligned to compute Git SHA-1 blob identities from local file bytes; clean repository bytes are required for a matching digest. No application code changed.

## Exact accounting

| Scope | Count | Evidence boundary |
|---|---:|---|
| Core registered IDs | 1,000 | Complete source registry/tree join |
| Historical coverage at 965-rule audit | 717 | Historical aggregate, not a current exact-ID set |
| Historical gaps at that audit | 248 | Historical aggregate; not current backlog |
| Current Windows exact-ID inventory records | 27 | 17 historical-pass, 4 authored-unexecuted, 6 missing |
| Reviewed Windows historical pass records | 17 | Exact ID and executed SHA in reviewed manifest; no original TRX bytes admitted |
| Windows IDs not represented in exact-ID inventory | 973 | Not reconciled, not necessarily untested |
| Windows positive/negative executed case totals across all 1,000 | Unknown | Aggregate suite passes do not identify individual case outcomes |
| Portable paired rule IDs | 20 | R586–R605, separate portable scope |
| Portable positive cases | 40 distinct / 80 executions | 20 IDs × 2 formats × 2 platforms; all matched |
| Portable negative cases | 40 distinct / 80 executions | Same matrix; all rejected |
| Portable paired executions total | 160 | 80 distinct cases; Windows and WSL2 Linux at dc43933775cb95a4685ecc860f93fa60b2ad3d1a |
| New executions in this reconciliation | 0 | No transfer of older evidence to current source |
| Independent field-qualified rules | Not established | No inference from synthetic results |

The 17 historical Windows pass records describe positive and negative controls, but no individual test-case counts are asserted; their recorded evidence is not a complete TRX mapping. Portable R586–R605 is disjoint from the 17 Windows manifest IDs. Thus 37 distinct IDs have a reviewed historical Windows-pass record or reported paired portable execution evidence, **not** 37 artifact-admitted Windows rules. The other 963 have not been reconciled to these two specific evidence sets; that is not a count of untested rules. The 717 historical aggregate must not be added to these sets. The 14,361/14,361 Windows regression and 667/667 CLI result are aggregate at 3b54c742; they cannot be counted as 15,028 distinct rules. The benchmark's 19 explicit paired controls is a separate benchmark-defined inventory, not the all-test denominator.

## Per-ID inventory

[registry-reconciliation.csv](registry-reconciliation.csv) lists every registered ID, source path and blob, current exact-ID record status, reviewed execution SHA, and separate portable case execution counts. Blank count means not reconciled, never zero. All R966–R1000 dedicated quality-test files exist; file presence is authored evidence only. Each of the 20 portable IDs has four positive and four negative executions (two formats on two platforms), per the recorded paired reports. The Windows manifest is unchanged; no new execution admission or production promotion.

## Next verification gate

1. Obtain original Windows TRX and benchmark/replay evidence at pinned SHAs; preserve hashes and unique result filenames.
2. Join test case identities to exact rule IDs and polarity using reviewed case mappings (including parameterized cases and shared fixtures); reject missing/ambiguous/duplicate results and distinguish skipped or conditional no-op tests.
3. Record actual positive/negative outcome counts per ID with source SHA, test name and artifact hash. Do not count source tests, suite totals or negative-only producer-gap checks as paired qualification.
4. Execute separately authorized current-SHA verification, then update the exact-ID manifest only after artifact review.

References: [rule catalog](../03-detection-rules/MASTER_RULE_CATALOG.md), [historical resume ledger](../rules/RULE_QUALIFICATION_RESUME_LEDGER.md), [exact-ID inventory](exact-id-qualification.json), [reviewed manifest](reviewed-execution-evidence.json), [development validation ledger](../DEVELOPMENT_VALIDATION_LEDGER.md). No .NET/PowerShell tests, builds, replay, capture or Actions ran during this reconciliation.

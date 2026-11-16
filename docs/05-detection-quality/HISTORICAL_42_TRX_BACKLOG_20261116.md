# Historical Windows 42-TRX source-proof backlog — reconciliation V1 (2026-11-16)

**Disposition: PARTIALLY VERIFIED, provenance recovery continues.** This is a **frozen historical Windows evidence inventory**, **not** a current-HEAD test result or an executed positive/negative rule-accuracy claim.

## Grounded inventory

Source: owner-supplied `source-and-replay-reconciliation-v4.json`, `original-integration-reconciliation-v1.json`, `original-active-sensor-reconciliation-v1.json`, SHA-verified 359-original-artifact recovery manifest, and checked-in `HISTORICAL_WINDOWS_SOURCE_LINKED_TRX_20261116.csv`.

| Immutable historic class | TRX files | Meaning |
| --- | ---: | --- |
| Original recovered TRXs | **42** | Each copy and parsed TRX was verified in the source audit |
| Runner-report-linked | **6** | 3 CLI qualification, 2 integration and 1 active-sensor TRX; original digest plus named runner-source report proof |
| Source-link **not** established | **36** | No runner-execution SHA promotion permitted |
| Of the 36: historical failing TRXs | **7** | Failures may be from earlier fixed regressions or investigations; never label these all-pass |
| Of the 36: pre-test-source-correlated SOC | **1** | 69/69; original `source-sha.txt` binds a pre-test commit, but no persisted final post-test assertion |
| Of the 36: all-pass large regressions (>=5,000 cases) | **11** | Original TRX pass and hash, but lacking same-run full-SHA execution proof |
| Of the 36: remaining targeted/CLI/benchmark runs | **17** | Exact runner-SHA binding still absent |

**The successful new 2026-11-16 SOC 70/70 completion** was generated *after* recovery; it is **outside the frozen 42**, and its completed hash audit does **not** retroactively bind the old 69/69 SOC original.

The additional 80/80 historical PCAP/PCAPNG paired synthetic replay controls for R586–R605 are separately tracked, with 40 positive and 40 negative fixtures at historical SHA `dc43933775cb95a4685ecc860f93fa60b2ad3d1a`. These do not establish field accuracy or qualify the other 980 rules.

## Original byte-level deduplication — 41 unique TRX digests

The uploaded v4 original-TRX audit shows **42 separate recovered TRX file copies, but only 41 distinct SHA-256 file digests**. The following two original copies contain **identical bytes** (SHA-256 `13813608c454d6b4a355b437973358f4830ebcc1e5ad7db52de616c735039b75`; 189/189 passed in each location):

- `originals/root-001/Verification/20261116-113455/carthago-tests.trx`
- `originals/root-002/test-results/carthago-tests.trx`

They are **not two independent demonstrated executions**. The six runner-report-linked files have six distinct TRX hashes. Therefore, in **unique file-digest accounting**, **6 of 41 distinct historical TRX digests are runner-linked and 35 distinct original digests remain unlinked**. In **original file-copy accounting**, the durable legacy metric is still **6 of 42 linked and 36 unlinked file copies**. Neither metric is the count of verified independent test executions: a genuinely separate run could produce identical bytes in theory, and distinct files may also reflect overlapping tests; source/run proof governs execution identity.

The read-only backlog script now emits `distinctOriginalTrxDigests`, `distinctUnlinkedTrxDigests` and the exact duplicate-copy paths. The two 189-result copies are prioritized as **one original digest needing source-run attribution**, not as two separate passed test suites.

## Immediate original-source investigations (actual evidence, no inference)

| Target | Original outcome | Required next proof |
| --- | --- | --- |
| `root-001/DetectionQuality/full-regression-3b54c742-20261116-111805.trx` | 14,361/14,361 passed | Original saved runner source SHA, or authentic completion report/console transcript with TRX digest; **`3b54c742` filename is unverified** |
| `root-001/CLI/cli-regression-3b54c742-20261116-112308.trx` | 667/667 passed | Same requirement; shared short filename hint does **not** establish identical source or runner |
| `root-001/Verification/20261116-113455/diagnostic/crash-.../carthago-tests.trx` | 14,361/14,361 passed | Review original source/runner record and its adjacent multi-MB VSTest diagnostic logs; artifact hash alone does not connect source |
| `root-001/soc-workspace-20261111-131828-20736/soc-workspace-tests.trx` | 69/69 passed | Original final post-run clean-checkout/PASS evidence at SHA `245bcce291abf06dc6b660221f48d3d6dc1962bb`; pre-test SHA file cannot prove final check |
| `root-002/integration/20261113-232405-717596f73498-e6cf3605/cli.trx` | 653/653 passed | Its original verifier log exists but has **no final PASS**; examine authentic run-stage outcome before any source link |
| `root-002/integration/20261113-232136-637f42b1a954-8f7ec341/cli.trx` | 642/652 passed, 10 failed | Diagnose original failures and contemporaneous source, do not upgrade to all-pass |
| `root-001/G1/G1-MainRegression.trx` | 11,007/11,016 passed, 9 failed | Exact failures/commit, compare subsequent corrected run only with separately verified source |
| `root-001/DetectionQuality/r272-isolated.trx` | 11/12 passed, 1 failed | Preserve negative outcome and independently verify later R272 pass if available |
| `root-002/redis-audit-ga-20261103-191600/full-regression.trx` | 10,568/10,569 passed | Pin original source/triage historical failure; later passing artifact is distinct |

Other historical failing TRXs are the two `root-002/investigation-results/redis-mtls-*.trx` (5/9 each) and `root-001/DetectionQuality/full-regression.trx` (14,360/14,361). **Seven distinct failure-containing TRXs**, counted without double-counting their later successful reruns.

The recovery manifest includes original `root-001/Verification/20261116-113455/local-logs/tests.log`, `build-tests.log`, `benchmark.log`, and diagnostic host/data-collector logs. Their existence is **not** a verified executed SHA. Review the source and specific run chronology before any promotion.

## Git commit candidate confirmed, source-run attribution still withheld

GitHub verifies that full commit `3b54c742b5b1d2bfafc2d25840a7dfa34ee46f65` exists (commit timestamp `2026-11-16T10:04:31Z`, message: `test: exercise R272 emission under explicit Research profile [skip ci]`). The first eight characters match the **filename prefix only** of the original 14,361/14,361 Windows and 667/667 CLI TRXs listed above. This narrows the manual provenance investigation but **does not link either TRX to a runner checkout**; no original post-run success/source record, original per-stage source identity or TRX/hash binding was supplied for those two files. Their `sourceSha` fields remain **null** in the strict 42-TRX backlog until that proof is recovered. An earlier owner-reported source label is useful context, not an original-artifact execution proof.

## Read-only reconciliation tools — no tests or artifact edits

Before using the new derived inspectors, run the **offline source-contract tests** (synthetic fixtures only; no original artifacts, tests or captures are executed):

```powershell
python .\scripts\test-wpf-historical-acceptance-contracts.py
```

The test includes a synthetic 42-run/six-link corpus with tampered SHA negative controls and log-proximity checks. It is **authored but not yet executed by the author**; review its actual result before treating a new audit report as established.

Generate a strictly checked 42-run source/backlog report from the existing **derived** JSON files:

```powershell
$bundle = 'C:\Users\afiay\Documents\Carthago-Evidence-20261116-190505'

python .\scripts\reconcile-historical-trx-backlog.py `
  --v4 (Join-Path $bundle 'source-and-replay-reconciliation-v4.json') `
  --integration (Join-Path $bundle 'original-integration-reconciliation-v1.json') `
  --active (Join-Path $bundle 'original-active-sensor-reconciliation-v1.json') `
  --linked-ledger '.\docs\05-detection-quality\HISTORICAL_WINDOWS_SOURCE_LINKED_TRX_20261116.csv' `
  --output (Join-Path $bundle 'historical-trx-backlog-v1.json')
```

The script checks **every one** of the six linked rows against its exact original TRX hash, counters and original report source identity. If an input is missing or mismatched, it **fails closed**. The 36 unlinked runs are assigned investigation priorities with their original reported outcomes and unverified path hints; *none gets a new source attribution*.

Next, scan only original companion log copies (hash/size verified from the original recovery manifest) for **candidate** full SHA tokens without copying raw log content into the derived report:

```powershell
python .\scripts\inspect-historical-original-run-logs.py `
  --bundle $bundle `
  --backlog (Join-Path $bundle 'historical-trx-backlog-v1.json') `
  --output (Join-Path $bundle 'historical-log-source-candidates-v1.json')
```

This second inspector **does not** convert nearby logs, short path hints, or a 40-hex token into an executed-source admission. The scanner restricts inspected logs by SHA-256-verifiable original copy, size and run-directory proximity, records only SHA token candidates and report hashes, and never edits the original evidence.

**Execution status at authoring:** New Python tools are committed as source only. The author has examined the uploaded derived reports and 359-item manifest; the new scripts **have not been executed on the owner's original Windows bundle**. Inspect the generated JSON before changing any reviewed execution ledger, rule classification, SHA-link count or readiness flag.

## Non-negotiable historical evidence rules

A true linkage requires the original TRX hash and exact full 40-hex source SHA from a reliable same-run source declaration, a verifier/runner completion proof and matching timestamps/counters; SHA-like path fragments and the *current* Git HEAD are never enough. Keep original failure rows and chronological follow-up runs distinct. Never call synthetic replay precision or a passing regression actual production field detection accuracy.

Sources in this repository: [Windows evidence recovery](WINDOWS_EVIDENCE_RECOVERY_20261116.md), [six pinned historical TRXs](HISTORICAL_WINDOWS_SOURCE_LINKED_TRX_20261116.csv), [synthetic replay matrix](HISTORICAL_R586_R605_SYNTHETIC_REPLAY_MATRIX_20261116.csv), [SOC verifier closed bug](SOC_VERIFIER_BUG_CLOSURE_20261116.md).

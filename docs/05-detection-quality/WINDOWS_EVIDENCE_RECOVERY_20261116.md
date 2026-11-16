# Windows evidence recovery — static reconciliation (2026-11-16)

Inspection source: `c40b87617267e898088d76fcd9e92e56f9985053`, `feature/carthago-reliability-hardening`. This document records a **read-only GitHub inspection**, not a fresh Windows execution or an accepted baseline. Subsequent commits must not inherit this SHA's evidence.

## What was actually inspected

- `registry-reconciliation.csv`: exactly 1,000 unique canonical IDs R001–R1000; 973 `not-reconciled`, 17 `historical-pass`, 4 `authored-unexecuted`, 6 `missing`. These are **inventory classifications**, not current execution totals.
- `exact-id-qualification.json`: exactly 27 reviewed exact-ID rows, including the same status breakdown.
- `reviewed-execution-evidence.json`: 17 pass declarations with historical executed SHAs; **0 rows contain an original artifact field or SHA-256 TRX digest**. They remain historical reviewed claims, not artifact-admitted results.
- The Git tree at the inspected source contains **no tracked `.trx`, `.pcap`, `.pcapng`, `.binlog` or `.zip`**. The repository's GitHub Actions run list returned zero runs at inspection. Neither fact establishes that a local Windows evidence archive is empty.
- Reported earlier Windows regression (14,361/14,361) and CLI (667/667) checkpoints are historical records, not re-executed or revalidated here. No per-rule positive/negative execution count can be inferred from those aggregate numbers.

**Current artifact-backed Windows exact-ID admissions established by this inspection: 0.** This means none could be independently checked against original bytes in this inspection, **not** that the 17 historical executions never took place. Total actually executed positive/negative cases across R001–R1000: **unknown**.

## Evidence acquisition without running tests

`scripts/inventory-windows-evidence-artifacts.ps1` is a newly authored, **not yet executed** read-only inspector. It hashes original bytes using SHA-256, inventories TRX summaries and per-outcome counts, and flags duplicate content, missing/duplicate test names and conflicting TRX run IDs. It does **not** attest checkout identity, establish case-to-rule mapping or promote evidence. Rejected TRX files and unparsed non-TRX files must remain quarantined for manual review.

Run from an existing Windows checkout in PowerShell, passing **only directories that actually exist**. This is an inspection command, not a test invocation:

```powershell
.\scripts\inventory-windows-evidence-artifacts.ps1 -EvidenceRoot @('.\TestResults', '.\build-verify') -IncludeTestNames |
    Set-Content -LiteralPath '.\windows-evidence-inventory.json' -Encoding UTF8
```

Place the generated inventory outside the original artifact directories and retain the original bytes. If one of these directories is absent, omit it rather than treating its absence as an empty evidence set. The inspector may include large result lists; protect local files according to the source evidence's sensitivity.

For each proposed admission, obtain independently:
1. Preserved original artifact and verified SHA-256. A path, Git blob hash, screenshot or summary is not a substitute.
2. Exact test execution command, project, execution start/finish time, host, selected checkout SHA and provenance of that SHA, plus an explicit source-compatibility decision if the execution SHA differs.
3. Original TRX test names/outcomes and case polarity (positive or negative) from reviewed, unambiguous per-ID mapping. Check with `scripts/verify-qualification-trx.ps1` using its exact expected hash and test names. Confirm full run status, skipped cases, duplicate names, parameterization and missing results separately.
4. Benchmark/replay scope and telemetry provenance: synthetic, packet-integrated, or independently captured Windows field evidence. Do not upgrade synthetic assertions to operational acceptance.
5. Explicit review before adding an `artifact` reference to `reviewed-execution-evidence.json`. A valid TRX alone does not prove the source checkout or real-world precision.

The inspector has no write path into the historical manifest or registered rule source; old artifacts and frozen holdouts must remain unchanged.

## Priority dependencies not satisfied by a test pass

- **R102:** trusted DNS baseline authority and provenance, independent V2 capture/review; frozen V1 and 80% floor preserved.
- **R118:** authenticated device identity and authentication outcome linked to capture; 86% floor preserved.
- **R163:** authenticated application-to-metadata-request ancestry and outcome; 84% floor preserved.
- **R275/R295/R343/R437/R508/R516:** respectively trusted issuer flow/time audit; Kubernetes exec audit; WinRM command/process audit; authenticated Redis configuration outcome; trusted transfer/process context; authenticated connector/session.

## Separate Windows operational acceptance

Current-SHA operational evidence is **not established** by this inspection for SCM lifecycle/recovery, real packet capture and drops, evaluation-to-journal-to-GUI accounting, enrichment correctness, restart retention, GUI responsiveness, or CPU/memory/queue sustained operation. Each requires its own artifact, environment, source SHA and acceptance review.

**No builds, test suites, captures, runtime qualifications or PowerShell inventory execution were performed in this documentation change.** Running the current-SHA suites, service exercises and captures requires explicit authorization under the project's validation policy.

Next step: run the read-only inventory on the Windows evidence archive; preserve immutable source hashes; map each original TRX test identity and polarity to reviewed exact IDs; admit only unambiguous artifacts. Request authorization before new execution and validate the selected isolated worktree SHA separately.


## Located original Windows artifact paths (log-backed, bytes pending)

A previously recorded Windows console transcript from November 16 identifies these on-disk locations; original binary files were **not** transferred through GitHub or attached to this reconciliation:

- `TestResults/Verification/20261116-113455/diagnostic/crash-20261116-113511-666-8def431e/carthago-tests.trx` — log-reported run: 14,361 passed, 0 failed, 0 skipped, at 11:35–11:38 local. An execution SHA was **not** attested by the transcript; it must not be inferred from the current checkout.
- `build-verify/test-results/carthago-tests.trx` — earlier test artifact, copied to a separate `TestResults/Verification/<timestamp>/` directory **before** the subsequent run; preserve both versions rather than overwriting them.
- `build-verify/tuning-benchmark.json`, `build-verify/local-logs/` — paired benchmark and build/test log sources; review run identity and timestamps before relating them to any TRX.
- `TestResults/DetectionQuality/ga09bu-priority.trx` — attempted named output for priority tests, but the saved command output shows compilation errors; file presence and successful execution are **not** established.
- Separate Windows checkout `Carthago-PortableQualification/build-verify/cli-qualification/20261116-112518-dc43933775cb-09617e1b/` — its printed `qualification.json` declares source `dc43933775cb95a4685ecc860f93fa60b2ad3d1a` and 667/667 portable tests; this is a distinct synthetic-portable scope and not an inherited core-Windows verification result. Recover the original `qualification.json`, `portable-tests.trx`, and `cli-paired-*.log` files separately.

The repository now includes `scripts/recover-original-windows-evidence.ps1`, which **has been authored but not executed on Windows**. It copies original bytes to a *new*, externally selected local archive, refuses an existing destination, verifies before/copy/after SHA-256 hashes, and emits a non-admitting manifest. It does not build, test, capture, or modify the source directories. It excludes diagnostic dumps unless explicitly selected.

From the core Windows repository checkout, with the portable qualification checkout alongside it, first pull the updated branch (without discarding local work), then use a **new** destination name and run:

```powershell
$parent = Split-Path (Get-Location).Path -Parent
$portable = Join-Path $parent 'Carthago-PortableQualification'
$roots = @(
    '.\TestResults'
    '.\build-verify'
    (Join-Path $portable 'TestResults')
    (Join-Path $portable 'build-verify')
) | Where-Object { Test-Path -LiteralPath $_ -PathType Container }
if (-not $roots) { throw 'No original evidence roots found' }
$destination = Join-Path $env:USERPROFILE ('Documents\Carthago-Evidence-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
.\scripts\recover-original-windows-evidence.ps1 -EvidenceRoot $roots -Destination $destination
```

After a successful copy, `recovery-manifest.json` contains per-file original/copy SHA-256, source path, size and timestamps, while `executionSha` and `evidenceAdmitted` deliberately remain null/false. Run the existing read-only inventory separately over the new `originals` directory. Review confidential logs or captures before transferring them outside the machine. **No original TRX or evidence files should be committed to the Git repository.**

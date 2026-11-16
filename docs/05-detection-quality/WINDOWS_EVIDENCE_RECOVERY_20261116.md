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


## Recovered-manifest audit and large TRX continuation (2026-11-16)

A user's read-only Windows byte-recovery run reported 359 artifacts / 974,948,690 bytes, 0 admitted results, 0 detector tests executed, on the inspection checkout at `319d058262b4d239d6226a7b8077674e7be9b02b`. Independent analysis of the uploaded JSON manifests showed:

- 357 inventory entries agree on original/recovered SHA-256 and size; two extra copied `.txt` files (`source-sha.txt` and `sdk-version.txt`) were outside the inventory file-type filter. The manifest did not include their text.
- 42 TRX files, with 22 parsed without duplicate names, 8 parsed with an R603 abbreviated-name collision, 12 rejected **solely due to the earlier 16 MiB parser ceiling**. None of the 12 should be described as corrupt or test failures based on size alone.
- For the 30 parsed TRX: 35,665 historical result occurrences (35,646 pass, 19 fail) across files, including a repeated 189-test TRX byte-copy; after collapsing **identical TRX hashes only**, 35,476 occurrences (35,457 pass, 19 fail). These are not distinct tests or current-SHA results.
- 583 canonical R001–R1000 IDs appear in parsed test names; **this is name mention coverage only**, not exact-ID or positive/negative qualification. Other 417 may have unparsed evidence in oversized runs.
- 80 positive/negative pcap/pcapng file-and-log filename pairs exist for R586–R605; the filenames alone do not attest replay success.
- Original Windows qualification result count 14,361, as reported by earlier console output, requires parsing its >16 MiB original TRX before exact per-test reconciliation. No execution SHA was admitted.

To parse large files **from the local, recovered copies**, update the working branch without discarding changes and invoke the existing read-only inventory with explicit higher bounds; defaults remain 16 MiB:

```powershell
$evidenceBundle = 'C:\Users\afiay\Documents\Carthago-Evidence-20261116-190505'
.\scripts\inventory-windows-evidence-artifacts.ps1 `
    -EvidenceRoot (Join-Path $evidenceBundle 'originals') `
    -MaximumTrxBytes 33554432 `
    -MaximumTrxXmlCharacters 67108864 `
    -IncludeTestNames |
    Set-Content -LiteralPath (Join-Path $evidenceBundle 'trx-inventory-expanded.json') -Encoding UTF8
```

This operation hashes and parses local copies. It neither runs the detector/tests nor changes original bytes or admission flags. Review the resulting JSON and upload the expanded inventory only; preserve the original recovery manifest and all TRXs unchanged. The eight R603 collided display names remain ambiguous until the corresponding original test definitions/parameter identities are reviewed, even if their separate test IDs and execution IDs are recorded.


## Source SHA and original replay binding — next local read-only pass

The expanded TRX inventory is **not** sufficient to attest actual execution SHAs. It contains 42 parsed TRX results, a sha256 digest for each, but leaves `executionSha` null and `evidenceAdmitted` false. In particular, a 14,361/14,361 passing TRX without a contemporaneous invocation/pinned-checkout record is still unbound. Commit prefixes in filenames and the SHA of the *later recovery checkout* cannot fix that gap.

The source at commit `dc43933775cb95a4685ecc860f93fa60b2ad3d1a` contains `scripts/verify-cli-qualification.ps1`, which asserts clean checkout HEAD against `-SourceSha` before and after each stage and records `sourceSha`, test-suite counters, per-rule replay `fixtureSha256` / `outputSha256` in its `qualification.json`. This creates a **runner-declared synthetic qualification** provenance route, provided the **original** qualification report, TRX, captures, and logs all match their recovered hashes and stage contracts. It is not independent cryptographic attestation or live-traffic detection validation.

A newly authored read-only tool `scripts/reconcile-recovered-source-and-replays.py` is provided to inspect **original recovered copies on the Windows machine**. It checks the original recovery manifest digest, parses TRX `TestDefinitions` to link test IDs to declaring classes, reads original `qualification.json` source declarations, matches TRX counters and stage codes, and verifies original paired PCAP/PCAPNG and replay log hashes against the report hashes and the observed JSON contract. It reports direct owner-class cases and parameter display collisions without promoting rules. It does not run dotnet, change data, or inspect a capture device. No claim is made that this script has executed on the Windows host.

```powershell
# From the CARTHAGO repository directory, after a safe fast-forward pull:
$bundle = 'C:\Users\afiay\Documents\Carthago-Evidence-20261116-190505'
python .\scripts\reconcile-recovered-source-and-replays.py `
  --bundle $bundle `
  --output (Join-Path $bundle 'source-and-replay-reconciliation.json')
```

The generated JSON distinguishes `sourceShaDeclaredInSameDirectoryReport`, `sourceShaRunnerLinkedToTrx`, and `pathShaHintsUnverified`. Upload only that derived JSON first. To establish unbound Windows 14,361-test run identity, further locate a *contemporaneous* `git rev-parse HEAD` result, clean-working-tree attestation and stage log with exact TRX hash/run ID; without these, the exact source SHA must remain unknown. Do not alter or overwrite recovered original TRXs.

**Code-level example:** `Carthago.Cli.Tests/PortableHttp602605Tests.cs` at the named historical SHA defines 20 explicit `[InlineData]` predicate scenarios: R602 2 positive/4 negative; R603 1/4; R604 2/3; R605 1/3. Their 20 source-defined cases are present as passed in the recovered 667-test portable TRX, but the R603 abbreviated test display names do not faithfully identify every original parameter. Successful synthetic predicate tests alone cannot establish field false-positive / recall performance.


## Original source/report reconciliation v2 — inspected 2026-11-16

A Windows owner-run original-artifact reconciliation output (`source-and-replay-reconciliation-v2.json`) was reviewed as **read-only historical evidence**. The original bundle remains on the owner's machine, not in the repository.

- Original copies: 359 recovered artifacts, 42 parsed TRX, three hashed `qualification.json` reports.
- Three runner-linked original TRX satisfy the local report's matching SHA-256/counter/stage-code gates: `ff35973a0373fb61ccee1a64d836944458d54f88` portable 653/653, same SHA Windows parity 87/87; `dc43933775cb95a4685ecc860f93fa60b2ad3d1a` portable 667/667.
- A fourth TRX (active sensors, 392/392) shares a directory with a hash-verified report declaring `ff35973a0373fb61ccee1a64d836944458d54f88`, but that report has a list-shaped `suites` field. No runner-link admission for this TRX is made by the generic checker.
- The 14,361/14,361 Windows regression TRX is original-hash verified but still lacks a contemporaneous same-run source SHA attestation; do not equate it to a filename prefix or a present-day Git HEAD.
- R586–R605: all 80 original positive/negative PCAP/PCAPNG stages have recorded exit code 0; their capture and log hashes match both original recovery and runner report. The v2 checker called every log `unreadable-log`; that is **not** 80 failed detector controls.
- Windows PowerShell 5.1 redirection commonly emits UTF-16LE files with BOM, whereas the original checker accepted UTF-8 only. The script has been updated to decode BOM-marked UTF-16 or UTF-8 and categorize any remaining parsing/contract errors separately. This diagnosis is plausible but requires a new **read-only** check against local originals to confirm.
- Exact rule positive/negative field qualification, production accuracy, current-source validation, and all artifact admissions remain **unverified**.

After pulling the patched branch, rerun without overwriting prior outputs:

```powershell
$bundle = 'C:\Users\afiay\Documents\Carthago-Evidence-20261116-190505'
python .\scripts\reconcile-recovered-source-and-replays.py `
  --bundle $bundle `
  --output (Join-Path $bundle 'source-and-replay-reconciliation-v3.json')
```

This only reads original recovered copies and writes a new derived JSON report. No original tests, captures, holdouts, or rule manifests are modified.


## V3 verified original PCAP and PCAPNG replay controls — 2026-11-16

The owner uploaded the read-only derived file `source-and-replay-reconciliation-v3.json` (SHA-256: `43be44f8da2d0d48dfeda1ba2e24aa8046c301c44740b65649f085b05bd91b0d`). The report records the **historical** `dc43933775cb95a4685ecc860f93fa60b2ad3d1a` portable Windows run:

- **80/80 synthetic replay controls observed**, with zero blocked: for each R586–R605 exactly one positive and one negative for `pcap`, and one positive and one negative for `pcapng`. Thus 40 positive and 40 negative format-specific controls.
- Each control's original capture and output-log SHA-256 matches both the original recovered copy and the hash recorded in the original `qualification.json`. All 80 runner-stage exit codes are 0. The decoded output satisfies the replay contract: a positive test produced one rule match, a negative test produced none; the parser reported no rejected, truncated, or clock-reset packets and no unexpected suppression.
- R601 uses a three-packet synthetic handshake context for each control; the other 19 rules use a one-packet fixture per control.
- The pinned runner's qualification report declares `sourceSha=dc43933775cb95a4685ecc860f93fa60b2ad3d1a` and `status=SyntheticPortablePassed` (Windows NT 10.0.26300.0), with 667/667 portable tests. Its original report digest in the recovered manifest is `265b8a1bf50258afebcc8488b6432e2c87583496e02b06007922eada4ddfb245`.
- Another runner-linked historical SHA `ff35973a0373fb61ccee1a64d836944458d54f88` records portable 653/653 and Windows parity 87/87. Total runner-linked TRX runs **3 of 42**, with 39 unlinked. A 392/392 active-sensor TRX shares a directory with a source-declaring report, but its `suites` is list-shaped and did not pass the generic runner-link gate.
- The original, recovered 14,361/14,361 Windows full regression is TRX-hash verified but its **execution SHA is still unknown**. A Git SHA prefix in a filename is an unverified clue only.

**Do not conflate these evidence levels.** The 80 controls prove historical *synthetic positive/negative executable replay behavior* for the 20 named rules at the reported source SHA, not their production accuracy, field recall, false-positive rate, physical network readiness, current branch readiness, or formal exact-ID qualification admission. The runner-declared SHA is a contemporaneous report-linked claim corroborated by stage counters and hashes, not external hardware-backed attestation. The v3 checker explicitly records `fieldDetectionQualityEstablished=false`, `artifactsAdmitted=0`, `testsExecutedByAudit=0`. No registry, reviewed-evidence manifest, frozen holdout, or current validation status is promoted as a result.

Further work requires independent source attestation for unbound runs and the separate rule-quality decision rubric, plus explicitly authorized current-SHA and operational testing.


## Original integration report reconciliation — pending local execution

Follow-up inspection of the original 359-file recovery manifest identified **six** \`integration.json\` reports. **Four** of the previously 39 unlinked TRX files have a matching directory-level or nested original integration-report candidate:

- \`originals/root-002/integration/20261113-232136-637f42b1a954-8f7ec341/cli.trx\`
- \`originals/root-002/integration/20261113-232405-717596f73498-e6cf3605/cli.trx\`
- \`originals/root-002/integration/20261113-233654-ff35973a0373-afba12c9/cli.trx\`
- \`originals/root-002/integration/20261113-233654-ff35973a0373-afba12c9/windows-tests/carthago-tests.trx\`

The respective SHA prefixes refer to existing GitHub commits, but this is **not sufficient to attest any of those four runs**. The historical \`scripts/verify-integration.ps1\` at \`ff35973a...\` asserted \`-SourceSha\` and clean, correct branch before and after stages and recorded both CLI and nested Windows result counters; the older \`717596f...\` version did not record nested Windows counters.

The new \`scripts/reconcile-original-integration-evidence.py\` is read-only and **has not run against the original Windows bundle**. Its fail-closed gates are: recovered report/TRX/log SHA-256 and lengths match the original manifest; report declares a canonical 40-character source SHA and \`SyntheticIntegrationPassed\`; zero return codes for \`solution-build\`, \`cli-tests\` and \`windows-verification\`; original verifier log includes the final \`PASS: local build, tests and replay validation.\` line; exact per-suite TRX counters and XML results all pass; test execution timestamps fall inside the report's run period (2-minute allowance); and if an earlier 42-TRX reconciliation is supplied, original TRX digest matches that baseline. No SHA propagates across sibling runs or from filename hints. A source link is runner-report corroboration, not external hardware attestation or field-accuracy qualification.

From the CARTHAGO repository working directory, after safe fast-forward:

\`\`\`powershell
$bundle = 'C:\Users\afiay\Documents\Carthago-Evidence-20261116-190505'
python .\scripts\reconcile-original-integration-evidence.py \`
  --bundle $bundle \`
  --previous (Join-Path $bundle 'source-and-replay-reconciliation-v3.json') \`
  --output (Join-Path $bundle 'original-integration-reconciliation-v1.json')
\`\`\`

This generates a new derived report without executing any tests, builds, captures or modifying the recovered originals. Do not promote formal qualification based on its output alone. The standalone 14,361/14,361 Windows TRX remains unbound unless contemporaneous evidence linking its exact hash/run ID and executed SHA can be independently recovered.

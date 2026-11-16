# Windows evidence recovery — static reconciliation (2026-11-16)

> **Reading guide (2026-11-16):** Early 'pending local execution' sections are preserved historical checkpoints. Later sections document owner-performed original integration and SOC read-only reconciliation. The recovered 14,361/14,361 Windows TRX is hash-verified but **still missing strict same-run execution-SHA linkage**; the separate 14,186-test integration is source-linked. [Current status](../CURRENT_STATUS.md).


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


## Original integration report reconciliation — historical pending checkpoint (superseded below)

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


## Owner-run original integration reconciliation — 2026-11-16 (console summary)

The owner executed `scripts/reconcile-original-integration-evidence.py` on the Windows recovery bundle `C:\Users\afiay\Documents\Carthago-Evidence-20261116-190505`, supplying the existing v3 source/replay reconciliation as `--previous`. The completed PowerShell console output reports:

| Audit measure | Reported result |
| --- | ---: |
| Recovery manifest artifacts | 359 |
| Original `integration.json` reports inspected | 6 |
| Integration TRX files now runner-report linked | 2 |
| Previously linked historical TRX runs | 3 |
| **Additional source links** | **2** |
| **Cumulative runner-report-linked TRX** | **5 of 42** |
| **TRX still lacking a qualifying runner link** | **37 of 42** |
| Detector tests executed in reconciliation | 0 |
| Capture operations | 0 |
| Evidence admissions | 0 |
| Field-accuracy qualification | false |

**Evidence status and review limits:** These counts are transcribed from the owner's completed local console summary, not yet independently cross-checked against the detailed generated `original-integration-reconciliation-v1.json`. In particular, *which* two integration TRXs linked, their exact 40-character source SHAs, which candidates were blocked and why, and whether the complete Windows TRX was one of the two cannot be inferred from the summary and remain pending the detailed report. Do not assign any new source SHA to a specific run based on its folder name, and do not convert these links into formal rule acceptance.

The locally generated report is at:

```text
C:\Users\afiay\Documents\Carthago-Evidence-20261116-190505\original-integration-reconciliation-v1.json
```

After inspecting that report, document the per-run proof chain (report SHA-256, TRX SHA-256, runner-declared source SHA, final verifier PASS, counter/time checks), exact blocked gates, and whether the original 14,361/14,361 regression obtained a valid same-run link. Until then, the 80/80 historical synthetic paired replay controls R586–R605 remain separately established at the historical pinned portable source SHA, and current-SHA/field qualifications remain unadmitted. No tests or captures were initiated in this documentation update.


## Original integration report reconciliation v1 — detailed owner output, 2026-11-16

The owner supplied the complete derived `original-integration-reconciliation-v1.json` produced read-only on recovered originals. Its summary confirms **six reports inspected, two new exact source-run links, cumulative five of 42 source-run links, 37 still without runner link, no tests or captures executed, and zero new formal admissions**.

The only fully successful integration report is:

- Report: `originals/root-002/integration/20261113-233654-ff35973a0373-afba12c9/integration.json`; recovered SHA-256 `7ca38fbaf02b90565112d2b4efafc172474a65b2834ef9a6dddf5f88f6e688e9`
- Runner-declared source SHA: `ff35973a0373fb61ccee1a64d836944458d54f88`
- Original verifier log: SHA-256-verified and contains final `PASS: local build, tests and replay validation.`
- CLI: `originals/root-002/integration/20261113-233654-ff35973a0373-afba12c9/cli.trx`, SHA-256 `732cec57f8ef05faa4a19ffbe773501bf47e37174544ad49e7fc6dcd3414d654`, TRX run ID `8964302d-af93-4bfa-89fc-d540f938b3e7`. **653 executed, 653 passed, zero failed.**
- Windows: `originals/root-002/integration/20261113-233654-ff35973a0373-afba12c9/windows-tests/carthago-tests.trx`, SHA-256 `f51f3aa997d70581dc5702056916ef3c16becd31245ad6046f0bd9c0ab18ac6f`, TRX run ID `16887fab-9bf8-4e22-92a1-d62346378dd9`. **14,186 executed, 14,186 passed, zero failed.**
- For both TRX, original copies are hash verified, report counters match, stage codes indicate success, and timestamps are within runner bounds. Both are linked **historical execution evidence**, not current-HEAD validation or field-accuracy acceptance.

Five integration reports did **not** meet complete report/verifier PASS gates:

| Runner-declared SHA | Original verifier-log status | Final verifier PASS |
| --- | --- | --- |
| `a4c01f86a4aa13b8b4dce9047da8334b51856f07` | missing in recovered manifest | no |
| `390a5801e2e2cb9049f79a26aa5515624925e8a5` | missing in recovered manifest | no |
| `0861e45c832337b5815ae195e0d58812652bfb63` | missing in recovered manifest | no |
| `637f42b1a9547ddb134775d5b88d43afd740787b` | missing in recovered manifest | no |
| `717596f7349804b4d00aea950e28e790cca502fe` | recovered SHA-256 verified | no |

These failures do not establish a test failure or corruption by themselves. The detailed source report intentionally stops at its combined report/verifier gate, so no exact additional failure cause is claimed. Do not attribute the adjacent standalone CLI TRX to these SHAs.

**Important non-inheritance:** The separate recovered **14,361/14,361** Windows TRX remains SHA-256 verified but execution-SHA unlinked; the now-proven **14,186/14,186** Windows integration TRX is a different earlier run at `ff35973a...`. Counting these two together or assigning the later run the earlier SHA would be incorrect.

The 80/80 original synthetic replay controls for R586–R605 remain verified at historical portable SHA `dc43933775cb95a4685ecc860f93fa60b2ad3d1a`. Formal per-rule admissions, real-world precision/recall, and current-source validation remain at **zero newly admitted** in this read-only recovery work. Next candidates are the co-located 392/392 active-sensor report/TRX and any contemporaneous SOC-workspace source record; both need their own strict proof contracts.


## Active-sensor original 392-case qualification: next local read-only check

The original `verify-active-sensors.ps1` at historical commit `ff35973a0373fb61ccee1a64d836944458d54f88` captures branch, clean `git rev-parse HEAD` at start, checks checkout identity again after the TRX, and stores an original `qualification.json` containing `trxSha256`, 28 per-suite count records, source SHA, stage results, and pass status. This schema is **not** the same as the CLI qualification report's dictionary-shaped suites.

A dedicated fail-closed inspector, `scripts/reconcile-original-active-sensor-evidence.py`, is now committed. It checks the original 359-file recovery manifest, original `qualification.json` and `active-sensors.trx` SHA-256 and sizes; 28 exact test-suite identifiers/counts from the historical source (392 total); uniquely mapped TRX tests, successful outcomes and runner stage/status checks; source SHA and branch; exact TRX digest inside the report; and run timestamps. It optionally cross-checks the previous v3 TRX digest. It emits a **new derived JSON only**; no original files, services, captures or tests are touched.

Run on the Windows original evidence directory after safe fast-forward (do not overwrite reports):

```powershell
$bundle = 'C:\Users\afiay\Documents\Carthago-Evidence-20261116-190505'
python .\scripts\reconcile-original-active-sensor-evidence.py `
    --bundle $bundle `
    --previous (Join-Path $bundle 'source-and-replay-reconciliation-v3.json') `
    --output (Join-Path $bundle 'original-active-sensor-reconciliation-v1.json')
```

The report must be reviewed before attributing this **additional** 392/392 historical active-sensor TRX to a pinned source. It is not yet counted among the five runner-linked TRX files, and it can never establish live physical-network accuracy, unattended operation or current-source qualification on its own. No new evidence admission is authorized.


## Original 392/392 active-sensor source link — owner v1 report confirmed, 2026-11-16

The owner uploaded `original-active-sensor-reconciliation-v1.json` (derived report SHA-256 `30485bd516442a6a2ff8130c221996b45faf36ee6043c7b916ca5cfff249ad39`), produced by the previously committed read-only checker on the original Windows evidence bundle. The complete report independently confirms the earlier source-run candidate's local contract:

- Original report: `originals/root-002/active-sensors/20261113-234235-ff35973a0373-a604eff5/qualification.json`; SHA-256 `0f356bfa70bbaae7b306a1c5a8ecc25cd92188f94f48a6247b7f757ab8602011`.
- Original TRX: `originals/root-002/active-sensors/20261113-234235-ff35973a0373-a604eff5/active-sensors.trx`; SHA-256 `5432e008127aae94f18df2f65c55f72604a3814ca759b89c2b04687efa4950d4`; run ID `ad7ee5c9-1578-473a-9696-aea8c5a7e5ef`.
- Runner-declared historical source SHA: `ff35973a0373fb61ccee1a64d836944458d54f88`.
- TRX interval UTC: `2026-11-13T23:43:18.031234Z` to `2026-11-13T23:43:35.854169Z`.
- Counts: **392/392 executed and passed, zero failed**, across **28 original synthetic/loopback active-sensor suites**. Original report/TRX length and SHA-256 verification, exact historical source-suite matrix, report's embedded TRX digest, time enclosure, and full suite outcomes all passed.
- The derived report explicitly states: `historicalActiveTrxRunnerLinked=1`, `newFieldQualifications=0`, `newEvidenceAdmissions=0`, `testsExecutedByAudit=0`, `capturesExecutedByAudit=0`.

**Updated source-attribution status: 6 of 42 historical TRX files linked to runner-declared source SHAs; 36 remain unlinked.** These six are listed by exact original TRX digest and source SHA in `docs/05-detection-quality/HISTORICAL_WINDOWS_SOURCE_LINKED_TRX_20261116.csv`. The ledger counts six distinct TRX files, not distinct detectors or 16,638 unique tests (test-result occurrences are shared/overlapping across historical runs). Two historical source SHAs are represented: `ff35973a...` and `dc439337...`.

The separate 14,361/14,361 Windows regression remains original-hash verified but unlinked to its execution SHA, despite an earlier pinned 14,186/14,186 Windows integration regression now being linked. Active sensor tests here do **not** establish physical/network protocol correctness, unattended SCM or Linux service lifecycle, production precision/recall, or current-HEAD qualification. **No original artifacts, registry rows, holdouts, rule-quality thresholds, or formal evidence admissions were changed.**

The next defensible provenance step is inspecting the original SOC-workspace `source-sha.txt` (the v3 derived inspector found no canonical 40-hex SHA token), any original companion logs, and the matching 69-result `soc-workspace-tests.trx`. Do not infer a 40-character executed SHA from an abbreviated filename, a current checkout or a neighboring run.


## SOC-workspace source-sha UTF-16 recovery — investigation, no new link

The previous v3 derived report found `sourceShaTextArtifacts[0]` at `originals/root-001/soc-workspace-20261111-131828-20736/source-sha.txt` but returned an empty list of canonical 40-character SHA tokens. The original recovery manifest shows the SHA file is **86 bytes**, with a SHA-256-verified original copy, next to a passing **69/69** `soc-workspace-tests.trx`, plus build/restore/test logs.

Historical `scripts/verify-soc-workspace.ps1` writes `git rev-parse HEAD` to `source-sha.txt` via PowerShell `Out-File` after checking the expected branch, clean checkout and local tracking reference. Windows PowerShell 5.1 `Out-File` can write UTF-16LE with a BOM: a 40-character SHA followed by CRLF would occupy exactly **86 bytes**. That is a **plausible explanation**, not yet a verified source identity, because the original file contents were not uploaded.

The read-only `scripts/reconcile-recovered-source-and-replays.py` now detects UTF-16 BOM or UTF-8 text for `source-sha.txt` and emits a canonical `sourceSha40` only if the decoded **entire trimmed file** is a 40-character hex SHA; it marks this as `original-source-file-only-unbound`. No TRX runner link or evidence admission follows automatically. Only after analyzing the original text, exact SOC 69-case TRX, adjacent logs, source verifier contract and run timing may an additional SOC attribution be considered.

Run locally after safe branch update with a fresh output name:

```powershell
$bundle = 'C:\Users\afiay\Documents\Carthago-Evidence-20261116-190505'
python .\scripts\reconcile-recovered-source-and-replays.py `
  --bundle $bundle `
  --output (Join-Path $bundle 'source-and-replay-reconciliation-v4.json')
```

The historical source-run count remains **6/42** until a separate SOC proof-chain review. No tests/builds/captures, original artifact mutations or evidence admissions are performed.


## V4 SOC original source-sha recovered — 2026-11-16

The owner uploaded read-only `source-and-replay-reconciliation-v4.json` (SHA-256 `1916eaafeeec9407481f04764344c8f6c82598091bd5de2c573709f2dd6d5cef`). Unlike v3, v4 decodes the original Windows PowerShell UTF-16LE SHA text correctly.

- File `originals/root-001/soc-workspace-20261111-131828-20736/source-sha.txt`, recovered SHA-256 `8d2bae670ee33c7845d4e55cda783c32a6cd8a4c759fb20cc80ad6f1c86061b3`, 86 bytes. The full trimmed contents are exactly **`245bcce291abf06dc6b660221f48d3d6dc1962bb`**.
- That full SHA exists as a GitHub commit dated 2026-11-11, containing historical `scripts/verify-soc-workspace.ps1`. The script checks the clean branch and `origin` tracking ref, writes `source-sha.txt` before the restore/build/test stages, and checks unchanged checkout after the tests, but the file alone does **not** prove that the post-test assertion executed successfully.
- The original SHA file's recorded last-write timestamp is `2026-11-11T12:18:29.7139782Z`, before the recovered `soc-workspace-tests.trx` last-write `2026-11-11T12:20:00.6365139Z`.
- The corresponding TRX has original SHA-256 `55622ce6b07d89bcd4e2364c5623fba21f9bbacb70102c5196b56c4fe6a213e8` and **69/69 passed**, zero failed, all 69 mapped to original test definitions.
- Three companion recovered logs exist in the manifest: `restore.log` (580 bytes), `build-release.log` (17,400 bytes), `soc-tests.log` (1,030 bytes). Their actual contents and stage completion claims were **not** present in the uploaded v4 file and are not yet verified for source attribution.

**Status:** `source-file-correlated candidate`, *not yet historical runner-report-linked*. The original v4 checker itself records `sourceIdentityLevel=original-source-file-only-unbound` and `sourceShaRunnerLinkedToTrx=null` for the SOC TRX. Accordingly the strict runner-linked count **stays 6/42 (36 unlinked)**. Neither synthetic rule quality nor production detection accuracy is newly admitted. The 80/80 historical paired replays R586–R605 remain unchanged.

Next step: verify the three original stage logs and SOC TRX against the pinned historical verifier contract, while distinguishing a pre-test recorded SHA from a missing persisted final checkout/PASS statement. Never retroactively infer successful post-run Git verification from an earlier SHA file or from the current repository HEAD.


## SOC original stage-log provenance check — historical pending checkpoint (superseded below)

The new read-only `scripts/reconcile-original-soc-workspace-evidence.py` is committed to inspect **all six recovered SOC artifacts** from the same session: `source-sha.txt`, `sdk-version.txt`, `restore.log`, `build-release.log`, `soc-tests.log`, and `soc-workspace-tests.trx`. Each original file is size and SHA-256 checked against `recovery-manifest.json`. The script cross-checks the canonical full SHA against the previous v4 recovery, the original TRX digest against v4, UTC chronology, all 69 uniquely mapped passing cases, and the three source-required groups `NetworkInvestigation`, `IncidentTimeline`, and `IncidentDetectionLinkVm`. The prior expanded TRX inventory records 29, 35 and 5 results respectively (69 total), but original group definitions and stage-log contents must still be read on Windows.

This is a **correlation checker**, not a means to fabricate a post-test SHA attestation. The historical SOC verifier writes the SHA file **before** running restore/build/tests; the final post-test clean-checkout assertion and success message are printed to the host console, not persisted in the six recovery files. Even if all six originals are consistent and the stage logs report success, the checker deliberately returns `strictRunnerLinkEstablished=false` and `sourceShaRunnerLinkedToTrx=null` until an original contemporaneous post-run verifier record is found. The SOC candidate must not increase the strict runner-linked count (currently **6 of 42**). Its distinct evidence level is `original-pretest-source-file-correlated`.

To generate a **new** derived report from the original Windows bundle after pulling the branch:

```powershell
$bundle = 'C:\Users\afiay\Documents\Carthago-Evidence-20261116-190505'
python .\scripts\reconcile-original-soc-workspace-evidence.py `
  --bundle $bundle `
  --previous (Join-Path $bundle 'source-and-replay-reconciliation-v4.json') `
  --output (Join-Path $bundle 'original-soc-workspace-reconciliation-v1.json')
```

The script has **not** run against the owner's original Windows copies in this documentation turn; there is no new test, capture, registry change, or formal admission. Do not share the original stage logs or raw traffic outside the machine when a derived report is sufficient.


## SOC original stage-log correlation — owner execution result (2026-11-16)

The owner ran `scripts/reconcile-original-soc-workspace-evidence.py` with the previously reconciled v4 report and shared the resulting Windows console output (screenshot). The script's local derived report was written to `C:\Users\afiay\Documents\Carthago-Evidence-20261116-190505\original-soc-workspace-reconciliation-v1.json`; its full JSON contents were **not** separately uploaded in this review.

The printed output establishes:

| Original SOC correlation gate | Reported result |
| --- | --- |
| `sourceShaFromOriginalPreTestFile` | `245bcce291abf06dc6b660221f48d3d6dc1962bb` |
| `sourceFileCorrelatedToHistoricalSocTrx` | `true` |
| All six original files SHA-256 verified | `true` |
| Source contents match prior v4 audit | `true` |
| Original SOC TRX digest matches prior v4 audit | `true` |
| All 69 TRX tests and three SOC groups passed | `true` |
| Source file timestamp precedes TRX | `true` |
| Original stage logs readable | `true` |
| Build log reports success | `true` |
| Test log reports success | `true` |
| Persisted post-test source recheck observed | **`false`** |
| `strictRunnerLinkEstablished` | **`false`** |

This verifies a high-confidence **pre-test source-file correlation** to the historical SOC 69/69 run. The original source-file commit exists in GitHub. Crucially, the historical script prints its final clean-checkout verification to the PowerShell console without persisting the outcome to the six recovered artifacts. Do **not** infer its outcome from the passing TRX or stage logs. The console screenshot is the **reconciliation checker output**, not an original November 11 post-run verifier transcript.

**Strict status remains 6/42 runner-report-linked TRX and 36 unlinked**, with SOC separately marked `original-pretest-source-file-correlated`. The 14,361/14,361 standalone full regression remains SHA-unlinked. No historical field qualification, current-SHA qualification or evidence admission changed.

Future remedy (not retroactive): amend `scripts/verify-soc-workspace.ps1` to write a sealed, successful **post-run** completion report only after it checks the checkout SHA, clean state, runner-stage exit codes and the final TRX digest/run identity, then validate that format in a focused test. For the already completed original run, only an authentic contemporaneous final success transcript or report can fill that missing gate.


## Future SOC verifier durable final completion record — authored, pending Windows contract execution

Implemented on `feature/carthago-reliability-hardening`:

- `scripts/SocWorkspaceCompletion.psm1` validates the original bounded TRX, test identity, run GUID, all-passing counters, offset-aware timestamps and required SOC test groups. It validates a success-only completion schema with matching pre/post checkout and tracking SHAs, four stages, SHA-256 hashes and explicit non-admission flags, and atomically publishes `completion.json` without overwrite.
- `scripts/verify-soc-workspace.ps1` now records pre/post clean-source and tracking SHAs, actual stage return codes and SHA-256 for `sdk-version`, `restore`, `build-release`, `soc-tests`, original source-SHA file hash, and original TRX hash/run ID. It writes the completion record **only after** a successful final checkout recheck.
- `scripts/test-soc-completion-contract.ps1` provides offline positive/negative fixture tests, deliberately without invoking dotnet tests, any capture or the real SOC verifier.
- Full schema, immutable-evidence limitations and owner commands are described in `docs/05-detection-quality/SOC_WORKSPACE_COMPLETION_PROVENANCE_V1.md`.

**Execution classification:** The PowerShell contract tests and new end-to-end Windows verifier **have not been executed** in this authoring session. They must be run by the owner against a pinned clean source. The historical November 11 SOC result remains only `original-pretest-source-file-correlated`, and strict source links remain **6/42** pending authentic pre-existing post-run evidence. This new code does not retroactively attest earlier runs or qualify any detection rule.


## 2026-11-16 — New SOC verifier: Windows execution observed, completion blocked by scope gate

Owner executed the new SOC verifier at prior checkout `aec661a6...`. Original `dotnet test --filter FullyQualifiedName~NetworkInvestigation|FullyQualifiedName~IncidentTimeline|FullyQualifiedName~IncidentDetectionLinkVm` produced **70/70 Passed**, zero failed or skipped. Release build succeeded with nine xUnit1026 warnings (R988–R990, R995–R1000). The source-completion module then threw `SOC TRX has an unrelated or overlapping test group` and did **not** write a successful completion report. This is **not** a new detector test failure or source-run admission.

Cause under investigation: the original parser selected SOC ownership from `TestMethod.className` alone, while the actual VSTest filter also matches **method names** in the fully qualified test name (case-insensitive). A narrowly scoped correction now prefers unique class-marker ownership and otherwise requires exactly one method-marker match; it records `methodScopedCases`, verifies total group counts, and continues rejecting ambiguous/extra/failing cases. The offline test adds method-scoped positive and ambiguous/unrelated negative examples. The precise class responsible in the original 70-case TRX is not asserted until local reparse.

**Pending Windows verification:** `scripts/test-soc-completion-contract.ps1`, then read-only `Get-SocWorkspaceTrxEvidence` against `TestResults/soc-workspace-20261116-200338-13980-b214b937/soc-workspace-tests.trx`, then a **new** clean pinned SOC verifier run. The old failed-completion run cannot retroactively acquire a final source SHA attestation. Detailed commands and guardrails: `docs/05-detection-quality/SOC_WORKSPACE_COMPLETION_PROVENANCE_V1.md`.

Historical source-link count remains **6/42**, with 36 unlinked, until distinct original evidence gates pass. This documentation change runs no tests or captures.


## SOC completion post-fix verified by owner console (2026-11-16)

The owner ran the corrected SOC completion flow and shared the terminal record, superseding the previously documented **class-only grouping gate failure** for **new runs**.

| SOC gate | Owner-reported result |
| --- | --- |
| Offline completion contract | **27 assertions PASS** |
| Read-only old-TRX reparse | **70/70 passed**, 29 NetworkInvestigation, 36 IncidentTimeline, 5 IncidentDetectionLinkVm, 5 method-scoped |
| New run restore | PASS |
| New run Release build | PASS, 0 errors; 9 xUnit1026 warnings |
| New SOC unit-test execution | **70/70 passed**, 0 failed/skipped |
| New verifier final source/build/test completion | **PASS printed** |
| New completion report | **Publication path printed**; original JSON content not yet independently inspected |
| Manual WPF / physical network validation | Not assessed |
| Exact rule qualification admissions | 0 new |

The new run is `TestResults/soc-workspace-20261116-201947-13980-fc218b2a/` with `soc-workspace-tests.trx` and `completion.json`. The previous read-only preflight's TRX ID and SHA-256 refer to **the old blocked run**, not to the new successful run. An independent inspection of the *new* report and referenced original artifacts is needed to confirm its exact executed SHA, run ID and hashes. The newly produced run is **not part of the frozen 42 recovered TRX originals**, so the historical cohort count **remains 6/42 runner-linked, 36 unlinked**, including November 11's pre-test-source-correlated SOC TRX.

The subsequent acceptance requirements and original run preservation instructions are maintained in `docs/05-detection-quality/SOC_WORKSPACE_COMPLETION_PROVENANCE_V1.md`. This documentation update does not modify any original evidence, detectors, rule-classification manifests or quality-admission thresholds.


## SOC verifier defect CLOSED — new source-pinned completion evidence reviewed

Subsequent owner-supplied Windows console and `completion.json` close the **SOC test-group classification / final-completion publication defect**. The successful run uses executed source SHA `971892ef4d18e18cbb2d8317c23c0ada64c2dc19`; original fix and production verifier checks were confirmed in that commit.

The new SOC run on 2026-11-16 (20:19:47–20:21:17 UTC) passed **27 offline contract assertions**, restore, Release build (0 errors, nine separate xUnit1026 warnings) and **70/70 SOC tests**. Its runner-generated completion report contains matching five source SHA declarations, all four stages exit code 0, the exact TRX run ID `36333bc5-2f34-472e-9e8c-0afbe7463041`, reported TRX digest `121f68fc32e94d42f4ccc8a424f2a34582cba797cbb904e123b8c8dd4cefe1af`, source-file hash, group partition 29/36/5 with five method-scoped cases, and explicitly false manual-WPF, field-accuracy and evidence-admission flags. The uploaded completion report's SHA-256 is `577edf65e6be209e1908600ea94a9af22b189ea56f8938afaaf84e371d6ac252`.

**Disposition:** Bug **CLOSED**; record and evidence boundaries in `docs/05-detection-quality/SOC_VERIFIER_BUG_CLOSURE_20261116.md`. The read-only sibling-artifact rehash tool `scripts/verify-soc-completion-artifacts.ps1` was added as a **separate, unexecuted** independent integrity check; do not claim its result yet. This **new** SOC TRX remains outside the historical 42 original TRX cohort, still **6/42 strictly source-linked, 36 unlinked**. The original November 11 SOC candidate is still only `original-pretest-source-file-correlated`; no detector/holdout or field quality promotion was performed.


## Final SOC saved-artifact integrity check — Windows PASS (2026-11-16)

The owner ran `scripts/test-soc-completion-contract.ps1` (**27/27 assertions PASS**) and then the read-only `scripts/verify-soc-completion-artifacts.ps1` on the **new**, successfully completed `soc-workspace-20261116-201947-13980-fc218b2a` bundle. The checker emitted `status=all-original-artifact-hashes-matched`, with original run GUID `36333bc5-2f34-472e-9e8c-0afbe7463041`, source SHA `971892ef4d18e18cbb2d8317c23c0ada64c2dc19`, original TRX SHA-256 `121f68fc32e94d42f4ccc8a424f2a34582cba797cbb904e123b8c8dd4cefe1af`, `completionSha256=577edf65e6be209e1908600ea94a9af22b189ea56f8938afaaf84e371d6ac252`, **70/70 original TRX results**, **5 method-scoped**, and four `sha256-matched` stage logs.

**Disposition:** SOC verifier grouping/completion **bug CLOSED**; independent (owner-side) original-artifact rehash follow-up **COMPLETED PASS**. The checker did not run SOC tests, capture traffic or admit quality evidence. No manual WPF approval, production field accuracy, service acceptance or exact-rule admission follows. This new TRX remains **outside** the 42 original recovered historical TRXs, whose source-link ledger remains **6/42 linked, 36 unlinked**. Detailed closure: `docs/05-detection-quality/SOC_VERIFIER_BUG_CLOSURE_20261116.md`.

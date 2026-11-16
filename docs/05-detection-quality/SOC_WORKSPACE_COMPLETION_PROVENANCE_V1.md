# SOC workspace — source-pinned completion evidence v1

**Scope:** Windows PowerShell owner-run, synthetic SOC workspace build/test verification only. This is **not** an admission of detection-rule field quality, UI acceptance or production readiness.

## Problem addressed

The historical 2026-11-11 SOC run retained \`source-sha.txt\`, three stage logs and a 69/69-passing TRX but did **not** persist the verifier's final post-test source/clean-tree check. Its source can only be classified as \`original-pretest-source-file-correlated\`; **do not retroactively reclassify it**. The 2026-11-16 Windows evidence audit remains **6 of 42 runner-report-linked historical TRXs**, with 36 without such a link, unless additional authentic contemporaneous evidence is recovered.

## Implementation

- \`scripts/verify-soc-workspace.ps1\` now creates a unique \`TestResults/soc-workspace-<UTC>-<PID>-<GUID>/\` folder without overwriting prior evidence.
- It refuses a non-Windows host, absent \`git\` / \`dotnet\`, wrong branch, unclean worktree, or a source commit that differs from \`origin/feature/carthago-reliability-hardening\`.
- It records \`source-sha.txt\`, then captures four **actual** stage exit codes and SHA-256 hashes of their saved logs: \`sdk-version\`, \`restore\`, \`build-release\`, and \`soc-tests\`. It keeps \`sdk-version.txt\` for earlier evidence-tool compatibility.
- \`scripts/SocWorkspaceCompletion.psm1\` parses the **original** TRX (bounded to 32 MiB with DTD prohibited and XML resolver disabled), requires a nonempty successful run, all results executed/passed, zero failed, unique test/execution IDs and definitions, and the three groups \`NetworkInvestigation\`, \`IncidentTimeline\` and \`IncidentDetectionLinkVm\`. It captures the TRX run GUID, actual original-file SHA-256, UTC-normalized TRX timestamps, counters and group counts.
- The verifier re-hashes all stage logs and checks the original source SHA file's contents before checking **branch, HEAD, origin tracking SHA and clean worktree a second time**. All source IDs must agree, including with the pre-test values.
- **Only after every gate passes**, \`Publish-SocWorkspaceCompletionRecord\` validates the completion contract and atomically moves a new UTF-8 (no BOM) \`completion.json\` into the run folder. It refuses to overwrite an existing completion file. There is no success completion report if a stage, TRX, post-run checkout or report gate fails.

### Version 1 completion record

\`completion.json\` contains: \`schemaVersion=1\`; \`purpose=soc-workspace-final-provenance-v1\`; \`status=SyntheticSocPassed\`; \`sourceSha\`; \`preRunSha\`; \`postRunSha\`; \`preRunOriginSha\`; \`postRunOriginSha\`; \`branch\`; \`postRunBranch\`; \`sourceShaFileSha256\`; \`startedUtc\`; \`finishedUtc\`; \`trxRunId\`; \`trxSha256\`; \`trxStartedUtc\`; \`trxFinishedUtc\`; \`testResults\` (\`total\`, \`executed\`, \`passed\`, \`failed\`); \`requiredGroups\`; and \`stages\` (four \`exitCode\`, \`logFileName\` and \`logSha256\` records).

Explicit boundaries: \`evidenceAdmitted=false\`, \`fieldAccuracyQualified=false\`, \`manualWpfValidated=false\`.

This is a **runner-generated** source-chain record, strengthened by checkout rechecking and captured hashes; it is not hardware-signed or externally immutable. Retain original report, original TRX, stage logs and the checkout source when auditing.

## Offline contract test (safe; no detector/capture)

On a Windows terminal with PowerShell 5.1 or newer, on the repository branch:

\`\`\`powershell
powershell.exe -NoProfile -File .\scripts\test-soc-completion-contract.ps1
\`\`\`

This exercises synthetic XML/JSON fixtures for the success path, UTC normalization of TRX timestamps with offsets, atomically published JSON, and negative cases for source/branch changes, missing/failed stages, invalid hashes, invalid or failing TRX, missing required groups, skipped results, dangerous XML DTD, attempted overwrite and inflated manual validation. The contract test uses only a temporary directory and cleans it up.

**Execution status:** Authored and committed; no PowerShell runtime or Windows .NET test environment is available in the authoring session. Do **not** claim this contract has passed until the owner runs it.

## Future owner-run SOC verification

After the contract test passes and the repository checkout is clean and current:

\`\`\`powershell
.\scripts\verify-soc-workspace.ps1
\`\`\`

The command runs the pre-existing SOC restore/build/test suite and now publishes \`completion.json\` if, and only if, all checks pass. This **does execute tests**, so do it only during the owner's chosen validation period. No physical network probes or live capture are added. Review the report and original files before a later evidence-admission decision.

**Historical rule impact:** No detector rules, holdouts, benchmarks or existing historical source-run classifications are changed by this code.


## Windows owner execution and SOC TRX class/method filter correction (2026-11-16)

Owner observed on an up-to-date `aec661a6c7646abbf9009dd95dcbd770d317c01c` checkout:

- The initial `scripts/test-soc-completion-contract.ps1` finished: **22 assertions PASS**, no detector tests or capture.
- `scripts/verify-soc-workspace.ps1` restored successfully, **Release build succeeded (0 errors, 9 xUnit1026 warnings)**, and the filtered xUnit TRX contained **70 passed, 0 failed, 0 skipped**.
- Original TRX path: `TestResults/soc-workspace-20261116-200338-13980-b214b937/soc-workspace-tests.trx`.
- `Get-SocWorkspaceTrxEvidence` subsequently rejected at the class-only SOC grouping gate: `SOC TRX has an unrelated or overlapping test group.` As designed, **no `completion.json` was published**, and no post-run SHA attestation was admitted. The failure was in the new **evidence validation layer**, not the tests or the build.

### Correction

The test invocation uses `--filter 'FullyQualifiedName~NetworkInvestigation|FullyQualifiedName~IncidentTimeline|FullyQualifiedName~IncidentDetectionLinkVm'`. VSTest's `FullyQualifiedName` refers to **class plus method**, and contains lookups are case-insensitive. The earlier evidence parser incorrectly permitted only class-name matches. The replacement groups each original `UnitTestResult` by its `TestMethod` definition:

1. Require a `Carthago.Tests.*` owner, nonempty test method, unique TRX test and execution IDs, and a passing result.
2. If the declaring class matches exactly one SOC group, use that group.
3. Otherwise, if the class matches none, permit a **single** matching SOC token in the original method name, counting it as `methodScopedCases` (persisted in `completion.json`).
4. Still reject classes/methods with ambiguous multiple SOC tokens, unrelated tests, failed/incomplete TRX, or group totals not exactly partitioning the executed cases.

This is deliberately aligned with the existing `dotnet test` filter, not a catch-all or a relaxation of result/count/source integrity. The offline contract now includes positive method-only selection and negative unrelated/ambiguous/overlap cases. Microsoft test filtering reference: https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-test-vstest .

The nine distinct `xUnit1026` warnings in R988–R990 and R995–R1000 are unused theory parameter warnings and are **independent** of SOC selection. They should be reviewed in a separate rule-test quality change rather than suppressed as part of the SOC provenance fix. https://xunit.net/xunit.analyzers/rules/xUnit1026

### Owner validation — read-only preflight before an expensive rerun

After updating the existing feature branch, first run the offline contract:

```powershell
.\scripts\test-soc-completion-contract.ps1
```

Then parse the **already generated** 70-case TRX without building or running any tests:

```powershell
Import-Module .\scripts\SocWorkspaceCompletion.psm1 -Force
$oldTrx = '.\TestResults\soc-workspace-20261116-200338-13980-b214b937\soc-workspace-tests.trx'
Get-SocWorkspaceTrxEvidence -Path $oldTrx | ConvertTo-Json -Depth 6
```

The returned `methodScopedCases` and three group counts expose how all cases were classified. **This is only a parser preflight**: do not create a completion report retroactively for the failed old run. Once the preflight passes, execute `.\scripts\verify-soc-workspace.ps1` on a new clean checkout; a successful **new** run will publish its own complete `completion.json`.

**Status:** Correction committed; runtime validation of the corrected parser and final completion record remains **unverified** until owner execution. Historical 2026-11-11 SOC run remains pre-test source-correlated; strict historical source-run count remains 6/42.


## Corrected verifier acceptance — Windows owner execution, 2026-11-16

The owner provided the Windows console transcript from the **new verification pass after the method-scoped grouping correction** on `feature/carthago-reliability-hardening`:

- `scripts/test-soc-completion-contract.ps1`: **PASS (27 offline assertions)**; zero detector tests and captures executed by the contract fixture.
- Reparse of **the older, blocked-completion TRX** `TestResults/soc-workspace-20261116-200338-13980-b214b937/soc-workspace-tests.trx`: original TRX run ID `d29e4dad-46aa-4fe9-be0a-c44707940d29`, original TRX SHA-256 `58eb6dce7cb8aca83eedac60799a922cf3c0713b5827ed4b4c66b65ea8d6a834`; 70 executed, 70 passed, 0 failed. Unique SOC group partition: **NetworkInvestigation 29, IncidentTimeline 36, IncidentDetectionLinkVm 5**, with **5 method-scoped tests**. These figures describe **the older, retrospectively parsed TRX**, not the new run's artifact identity; the old failed completion cannot be reclassified.
- New owner-run `scripts/verify-soc-workspace.ps1`: `sdk-version` reports **9.0.321**; restore succeeded; Release build succeeded **with 0 errors and 9 xUnit1026 warnings**; all **70 SOC tests passed**, with zero failed or skipped.
- **New successful run directory:** `TestResults/soc-workspace-20261116-201947-13980-fc218b2a/`. Original new test-result file `soc-workspace-tests.trx`; run completion is printed as `SOURCE BUILD AND SOC TEST STAGES PASSED`, followed by `SOC source-pinned completion report: .../completion.json`.
- Since the current verifier prints this final message only after `Publish-SocWorkspaceCompletionRecord` returns, the console output supports **successful owner-side publication of a new completion report**. However, the *content of that report*, its exact source SHA and its original TRX/stage-log SHA-256 values were **not uploaded in the transcript**, so no independent second-reader attestation of the contents is asserted.

**Classification:** New Windows SOC synthetic test and local provenance *runner reported PASS*; **external hash/content review pending**. Do **not** copy the older TRX run ID or SHA-256 into the new record. Do **not** count the new TRX among the prior 42 recovered historical files, because the new run was produced **after** the 359-artifact recovery inventory. Within that frozen historical cohort the status remains **6/42 strict source links, 36 unlinked**. The November 11 SOC record remains `original-pretest-source-file-correlated`. All manual WPF acceptance, real capture quality, field precision/recall and rule admissions remain unverified.

For audit of the **new** run without executing another build or test:

```powershell
$dir = '.\TestResults\soc-workspace-20261116-201947-13980-fc218b2a'
Get-Content -LiteralPath (Join-Path $dir 'completion.json') -Raw
Get-FileHash -LiteralPath (Join-Path $dir 'completion.json') -Algorithm SHA256
```

Preserve `completion.json`, the corresponding original `soc-workspace-tests.trx`, `source-sha.txt` and four stage logs together in that run folder. Inspect the completion file and verify its recorded TRX and stage hashes against their original bytes before accepting its source-evidence claim. Uploading `completion.json` is sufficient for the first field-level schema and source SHA review; original artifacts would be needed for an independent hash recheck. No code change or new test execution occurred as part of documenting the supplied console transcript.

**Warning follow-up (separate):** nine xUnit1026 unused-`name`-parameter warnings in R988–R990 and R995–R1000 remain open and should be fixed with rule-test semantics preserved rather than suppressed.

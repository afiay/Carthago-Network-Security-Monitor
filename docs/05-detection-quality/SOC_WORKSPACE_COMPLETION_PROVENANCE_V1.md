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

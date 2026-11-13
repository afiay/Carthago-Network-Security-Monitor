# GA-IQ-01 — pinned solution integration and rule qualification

**SOURCE CANDIDATE — UNVERIFIED.** Base `97014f387ce96118191645efeb8bff92053cbe61`. Existing feature branch only. No builds, application tests, replays, CI or live probes executed by this publication.

## Integration gap and correction

The prior DOTNET.sln explicitly listed only Carthago, Carthago.Tests and Carthago.Benchmarks. Core and Contracts may build transitively; that did not guarantee CLI, CLI tests or Monitor coverage. The solution now explicitly lists all eight projects with Debug/Release Any CPU build configurations. No project reference, target framework, detector, profile or sensor policy changed.

The new owner-run script `scripts/verify-integration.ps1` requires an exact commit SHA, correct branch, clean tracked/untracked checkout and explicit test-time switch. It creates a unique ignored run directory, builds the full solution, runs CLI tests with fresh TRX and nonzero all-passing counters, then invokes the existing Windows verifier in a child shell. It rechecks the checkout between stages and records stage exits and CLI counters. Success means synthetic integration only; it does not certify live capture, deployment or detection accuracy.

## Qualification inventory

The source inventory remains authoritative for candidate associations, not runnable tests. The current registry contains 1,000 contiguous core IDs at the inspected base. Use the existing pinned source inventory rather than inferring test coverage from filenames or batch sizes. Keep the historical 965-rule/12,371-test baseline at c164be6 distinct from the new inventory; 19 paired benchmark controls at that baseline do not represent all xUnit coverage.

Owner commands from a clean Windows checkout:

```powershell
git switch feature/carthago-reliability-hardening
git pull --ff-only origin feature/carthago-reliability-hardening
$sha = (git rev-parse HEAD).Trim()
New-Item -ItemType Directory -Force build-verify | Out-Null
.\scripts\inspect-rule-source-inventory.ps1 -SourceSha $sha |
    Set-Content -Encoding UTF8 "build-verify/rule-source-$sha.json"
.\scripts\verify-integration.ps1 -SourceSha $sha -AuthorizedTestTime
```

The source inventory is read-only against Git blobs; its script/module are from the checked-out revision. Review unresolved declarations, grouped tests and producer dependencies; do not mark missing associations as zero tests. Rebuild the generated catalog separately with `python scripts/build_rule_catalog.py` and the docs index if needed; commit intended generated changes before a clean integration run.

## Qualification acceptance

For each rule record exact SHA, source/descriptor, positive and negative cases (including benign lookalikes), producer path, observed test results, replay evidence and operational disposition. Missing producer or independent labels remain blocked. Preserve R102 frozen V1 and pending V2, Shadow/Disabled semantics, confidence floors, and all historical test results. No new IDs in IQ-01.

Next: review the pinned inventory and resolve source ambiguities; execute the integration gate on Windows, record actual results, then prioritize R966–R1000 and producer-dependent rules. Active sensors have a separate synthetic verifier (`verify-active-sensors.ps1`); live network checks and UI visual acceptance remain separate authorized gates.

## 2026-11-14 — Owner-run build diagnosis and corrective retest

Status: **RED at tested SHA; corrective source candidate UNVERIFIED.** The owner synchronized the existing feature branch (209 fast-forward commits) and used Windows PowerShell 5.1 with .NET SDK 9.0.321. The first integration run at `a4c01f86a4aa13b8b4dce9047da8334b51856f07` stopped at the solution build (exit 1). The diagnostic-only change `390a5801e2e2cb9049f79a26aa5515624925e8a5` now prints a stage start, success or last 80 lines of the failure log and its full path; complete logs remain local. The owner reran at that SHA and reported 12 compiler errors and two warnings; no xUnit or replay stage was reached. Contracts, Core and CLI compiled, but the overall solution did not.

| Observed diagnostic at 390a5801 | Correction in 0861e45c | Status |
| --- | --- | --- |
| 8 CS0122: CLI tests cannot access NativePcapCaptureSource, NativeCaptureDiscovery or IPortableMonitorJournal | Add InternalsVisibleTo for Carthago.Cli.Tests in Carthago.Cli.csproj; keep implementation types internal | Retest pending |
| 4 CS0104: ambiguous JsonSerializer in ActiveEvidenceStore and ActiveSensorProfileStore | Alias System.Text.Json.JsonSerializer explicitly; retain LiteDB storage and existing serialization calls | Retest pending |
| CA1416: platform-neutral ServiceCommands references WindowsServiceControl.ServiceName | Share platform-neutral service-name constant; preserve the public Windows alias and native platform guard | Retest pending |
| CS8620: nullable RuleId finding passed to numeric comparer | Declare IComparer<string?> consistently with existing null-aware CompareIds; preserve numeric ordering | Retest pending |

Corrective commit: [0861e45c832337b5815ae195e0d58812652bfb63](https://github.com/afiay/Carthago-Network-Security-Monitor/commit/0861e45c832337b5815ae195e0d58812652bfb63). No test assertions, rule modes, thresholds, sensor grants, or release gates changed. The existing tests are the regression checks; no new test results or Windows build success are claimed. The supplied owner transcript is evidence of the failed build only; full log and integration.json remain local under build-verify/integration/20261113-231710-390a5801e2e2-72d2353e.

Owner retest from a clean checkout:

```powershell
git pull --ff-only origin feature/carthago-reliability-hardening
$sha = (git rev-parse HEAD).Trim()
.\scripts\verify-integration.ps1 -SourceSha $sha -AuthorizedTestTime
```

Record the actual retest SHA (including any intervening documentation or source commits), build exit, CLI TRX counters, Windows regression counts and replay outcome. On integration success, run the dedicated active-sensor verifier and CLI qualification with Windows parity at the same clean SHA; retain their reports separately. Physical sensors, live capture, field accuracy and production readiness remain unverified. Keep the 1,000 registered core IDs distinct from individually qualified rules and portable CLI capabilities. No Actions dispatch or live probe was performed for these corrections.

## 2026-11-14 — Second corrective build iteration

Owner retest at `0861e45c832337b5815ae195e0d58812652bfb63`: solution build still RED (exit 1), 22 warnings and one error (CS0136 in RuntimeEnrichmentRegressionTests.cs:60). All seven other solution projects produced Release assemblies, including CLI tests, Windows application, Monitor and Benchmarks. The previous twelve errors and two warnings did not recur. No test or replay stage executed. Local run: build-verify/integration/20261113-231840-0861e45c8323-1ac2ef0c.

Correction: rename the inner missing-database lookup result to missingOutcome, preserving all existing GeoIP assertions. Also convert R272's engine-emission test to async Task and await all six detector evaluations, retaining the exact assertions, reset in finally and producer/time/host boundaries. This addresses its six xUnit1031 warnings without changing detector behavior. Remaining warnings in the observed build: four Windows platform analyzer diagnostics in capture reservation tests, three blocking synchronous callback test diagnostics, and nine unused industrial fixture labels. These are nonblocking and intentionally retained for focused follow-up; callback synchronization should not be casually rewritten. No warnings suppressed or tests disabled. New source unverified; pull, pin HEAD and rerun integration. No production readiness or live capture claim.

## 2026-11-14 — Full build GREEN; CLI regression RED

Owner run at `637f42b1a9547ddb134775d5b88d43afd740787b`: all eight solution projects built successfully, CLI xUnit executed 652 tests (642 passed, 10 failed, zero skipped; exit 1). Windows regression and replay benchmark not reached. Local run: build-verify/integration/20261113-232136-637f42b1a954-8f7ec341. The console tail names seven replay tests and one buffered-capture test; two failures are outside the supplied excerpt. Source review also identified the same fixture issue in portable monitor session tests and executable smoke fixtures.

Root cause: distinct synthetic HTTP requests reused the same TCP five-tuple and sequence zero. PortablePacketProcessor.ShouldAcceptSegment correctly rejects fully retransmitted data and fails closed on large overlap/gaps. Therefore later fixture requests never reached HTTP detection as independent requests. Fix the synthetic wire fixtures, not the parser or cooldown policy: advance TCP sequence by payload bytes in classic replay, per-interface PCAPNG sequence, monitor session, buffered capture and PowerShell executable smoke. Retain all existing expected detection counts and add an explicit raw retransmission-vs-new-request replay test (one match, one cooldown suppression, three parsed/evaluated packets). No production code or detection policy changed. New test is authored, unexecuted; CLI retest must establish actual status, including the two previously unseen failures. Subsequent Windows regression, dedicated sensor qualification and physical checks remain pending. No Actions or live probe.

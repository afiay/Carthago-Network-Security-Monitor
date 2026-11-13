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

## 2026-11-14 — CLI GREEN; Windows regression RED

Owner run at `717596f7349804b4d00aea950e28e790cca502fe`: all eight projects built and CLI gate passed (fresh TRX counters enforced by integration; exact count not printed in supplied transcript). The previous 10 CLI failures no longer block the gate. Windows restore/build for tests and benchmarks passed, Windows xUnit exited 1 after 184.5 seconds; exact test counts and names not supplied. Benchmark executed successfully: 165 labeled samples, zero benign critical alerts, 1,000 registered rules matching audit, 19 paired synthetic controls, 933 without explicit replay controls, zero contract issues. Per profile raw recognition was 53/53 expected malicious sample/rule pairs; simulated alerts 1–2/53 (1.9–3.8% recall), zero scored FP; remaining recognized pairs were Shadow/Disabled. These are labeled synthetic benchmark metrics, not independent field accuracy, individual qualification or production alert recall. Do not promote rules based on these numbers.

Local integration evidence: build-verify/integration/20261113-232405-717596f73498-e6cf3605; Windows test log build-verify/local-logs/tests.log and standalone-default TRX build-verify/test-results/carthago-tests.trx. Capture that existing result before another run overwrites the default log. Diagnostic correction: integration now supplies a unique Windows TRX directory and prints the Windows counters and up to 40 failed test names with bounded messages after the nested verifier, retaining the failing exit status. CLI pass counters are printed. Standalone verify-local default path remains compatible. This is a source-only diagnostic change, not a fix for the unidentified Windows failures. Later branch commits are not certified by the historical CLI/build PASS. No active sensor physical qualification, dedicated CLI smoke/parity qualification or Actions execution claimed.

## 2026-11-14 — Windows failure inventory and canonical profile persistence correction

Owner supplied complete test-stage summary for the run at `717596f7349804b4d00aea950e28e790cca502fe`: 14,186 Windows tests, 14,165 passed, 21 failed, 0 skipped. All named failures are active-sensor cases: eight ScheduledSnmpAuthorizationTests, seven ScheduledGatewayTests, one ActiveAuthorizationSurveillanceTests rotation case, two ActiveServiceNegativeStartupTests credential-corruption cases, one ActiveServiceRejectionTests corrupt SNMP case, one HttpHealthSensorTests untrusted HTTPS case and one TlsInspectionSensorTests self-signed loopback case. No detection-rule failure appears in the supplied list. Exact assertion messages were not printed by quiet dotnet output; this is not certification of independent rule accuracy.

Source review identified a shared profile round-trip defect: Gateway/SNMP/TCP use canonical empty HostName; LiteDB's default mapper converts empty strings to null (see https://www.litedb.org/docs/object-mapping/), whereas SavedActiveSensorProfile.TryValidate requires a non-null canonical host. Configure a dedicated BsonMapper for the profile database with EmptyStringToNull=false and TrimWhitespace=false, preserving exact canonical strings, not changing global storage or relaxing validation. Existing SNMP/Gateway configuration tests now also verify the reopened typed row and raw BSON HostName string. Existing grant, rotation, deletion, corruption, scope, persistence and fail-closed assertions retained; no extra test cases or disabled tests. Previously malformed stored rows are not silently migrated or granted authorization; explicit recovery/reapproval may be needed. This is a source-backed candidate for the 19 related failures, not observed resolution. TLS/HTTPS assertion details still needed from the original TRX before any trust or fixture changes. No test executed by publication. Retest the seven affected classes, then full integration at actual HEAD.

## 2026-11-14 — Profile fix verified; two TLS loopback failures remain

Owner focused run after pulling `a125c8382566dc591d9d1d4639a21b153c2db526`: 92 tests, 90 passed, 2 failed, 0 skipped. Original TRX confirms 17 null grant assertions and two empty profile collections; all 19 SNMP/Gateway-related failures now pass, including corruption, rotation, revocation and startup rejection. Both remaining TLS cases still fail quickly: SelfSignedLoopbackHandshakeRetainsEvidenceButRejectsTrust expected CertificateRejected, actual HandshakeFailed; UntrustedHttpsPeerCannotReceiveHttpRequest expected TlsRejected, actual TlsFailed. No successful trust bypass observed. Full Windows rerun remains pending; nine xUnit1026 industrial fixture label warnings remain in focused build.

Source review: both synthetic servers use CreateSelfSigned with RSA.Create and a private key not explicitly imported into a Windows key set; server AuthenticationException/IOException were swallowed. Microsoft documents Schannel's ephemeral-key limitation (https://learn.microsoft.com/dotnet/core/extensions/sslstream-troubleshooting). Candidate correction: shared test-only LoopbackTlsCertificateFixture exports an in-memory PFX, imports with UserKeySet on Windows (no PersistKeySet, dispose temporary key), zeroes PFX bytes, and leaves trust stores untouched. Both loopback tests retain strict rejection, name mismatch, absence of negotiated protocol/HTTP response, and zero received HTTP bytes; additionally assert the observed exact certificate SHA-256 and expose server exception on failure. No production sensor, timeout, trust, grant, detection or assertion threshold relaxed. The supplied old server exception was unavailable, so Schannel cause remains a source-backed hypothesis until retest. No new test cases, no tests executed in publication. Next run both targeted tests, then pinned full integration; physical validation remains separate.

## 2026-11-14 — GA-IQ-01 verified GREEN at ff35973a

Owner-run Windows evidence at exact source SHA [ff35973a0373fb61ccee1a64d836944458d54f88](https://github.com/afiay/Carthago-Network-Security-Monitor/commit/ff35973a0373fb61ccee1a64d836944458d54f88): both corrected TLS/HTTPS loopback tests passed (2/2, zero skipped); subsequent pinned integration run passed solution-build, cli-tests and windows-verification. CLI 653/653 passed, zero failed; Windows 14,186/14,186 passed, zero failed, 14,186 executed. Combined suites 14,839/14,839, excluding the separate focused rerun. The Windows verification gate also completed its benchmark and replay checks. This closes the original 10 CLI and 21 Windows regression failures at this source checkpoint. The earlier 1,000-rule registry and 165-sample metrics are historical measured at 717596f7; do not conflate those metrics with a fresh per-rule field qualification. The Windows fixture correction is verified; the original swallowed server exception is not retrospectively known.

Evidence: owner PowerShell transcript, local directory `build-verify/integration/20261113-233654-ff35973a0373-afba12c9/`: `integration.json`, `solution-build.log`, `cli-tests.log`, `cli.trx`, `windows-verification.log`, `windows-tests/carthago-tests.trx`. The report files themselves remain local and have not been independently opened. Integration status inferred from the successful gate completion and counters is SyntheticIntegrationPassed; field accuracy remains unqualified. Nine xUnit1026 warnings were observed in the focused build; no warning-free claim. No live LAN probes, field accuracy, deployment readiness, physical sensor qualification or dedicated CLI smoke/parity claim. No Actions dispatched.

Next: while still on clean tested SHA ff35973a, run `./verify-active-sensors.ps1` (root script pins current HEAD internally, no parameters), then `./scripts/verify-cli-qualification.ps1 -SourceSha $sha -AuthorizedTestTime -IncludeWindowsParity`. Run sequentially and retain each report. Avoid pulling intervening source changes before these same-SHA gates; if moving to new HEAD, record and requalify the actual new SHA instead. Documentation is published against newer branch HEAD and does not extend the PASS to intervening changes. Continue individual rule evidence qualification and separate authorized physical/release gates after synthetic checks.

## 2026-11-14 — AS-Q01 verified GREEN at ff35973a

Owner completed the next dedicated gate without changing source: AS-Q01 Release build, 28/28 suites and 392/392 tests PASS at `ff35973a0373fb61ccee1a64d836944458d54f88`; all per-suite actual counts match expected. Core families TCP 17, DNS 33, TLS 22, HTTP 38, Gateway 23, SNMP 41; remaining 218 cases cover 22 supporting suites. Local report: `build-verify/active-sensors/20261113-234235-ff35973a0373-a604eff5/qualification.json`. Owner transcript supplied; report not independently opened. Explicit verifier result: live network validation NOT performed. The dedicated cases are already included in the full Windows regression; do not inflate unique integration count. See [ActiveSensors architecture and qualification](../02-architecture/ActiveSensors.md).

Next: stay on clean ff35973a and execute `./scripts/verify-cli-qualification.ps1 -SourceSha $sha -AuthorizedTestTime -IncludeWindowsParity`. Physical/SCM/soak and release qualification remain pending. This documentation-only publication against newer branch HEAD does not qualify intervening executable changes.

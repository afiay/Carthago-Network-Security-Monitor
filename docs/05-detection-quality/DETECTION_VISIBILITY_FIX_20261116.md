# Detection visibility and qualification — 2026-11-16

**Status: SOURCE CANDIDATE — UNVERIFIED.** Source and xUnit tests were authored directly on `feature/carthago-reliability-hardening`. No Windows build, test execution, packet-capture session, independent accuracy holdout or deployment acceptance was performed for these changes. An authored test is not an executed PASS.

## Incident rule-reference integrity

- `IncidentVm.CloneIncident` now retains recorded `PrimaryRuleId`, `RelatedRuleIds` and `RelatedEventIds` (and correlation metadata) when a persisted incident passes through UI view models.
- The Incident Queue and Incidents workspace use one `IncidentQueueProjectionService.GetRecordedRuleIds` projection. It takes only rule references actually stored in a case, its attached detections, or its attached anomalies; it deduplicates case-insensitively and limits displayed references.
- With no recorded rule identifiers, the UI says **No recorded rule IDs**, not that the detection engine necessarily ran and found no applicable rules.
- Exact event navigation still requires separately recorded event IDs and a retained event at the navigation destination; a rule ID alone is not proof of an emitted alert.

## Detection Coverage Center diagnostics

The **Refresh actual status** action now exposes engine record-evaluation count, summed per-rule evaluations, rule matches, rule skips, rule failures, journal failure count, and post-policy **shadowed, suppressed, emitted and persisted** counts. These outcomes can overlap; they must not be summed as mutually exclusive packet counts. The per-rule grid exposes **Skipped** and dominant **No-match reason**, and the detail pane shows its code, category, count and explanation.

**Interpretation:**
1. **Live traffic but engine record evaluations remain zero**: investigate capture-to-enrichment/evaluation routing, session cancellation, and worker health. Packet visibility alone does not establish rule execution.
2. **Engine evaluations rise, but selected rule evaluations are zero**: inspect enabled/Shadow/Disabled policy, candidate selection, and missing telemetry.
3. **Rule evaluations rise and matches remain zero**: inspect rule no-match codes and missing fields; normal benign activity can correctly produce zero matches.
4. **Matches rise but alerts remain empty**: distinguish Shadow and suppression decisions, persisted journal records, and emitted-event/UI delivery. A match is not synonymous with an emitted alert.
5. **Rule IDs present in a persisted incident but linked detection unavailable**: check recorded event IDs and the bounded retained-detection set. Do not infer association from IP proximity, title, or timestamps.

All counters are **process-local** and may reset on restart. Summed per-rule evaluations are not packet counts. This view is not a certified positive/negative test report. The default catalog snapshot currently has no replay-result provider; its `NoCoverage`/no-loaded-replay field must not be interpreted as evidence that no historic tests exist.

## Regression tests authored

- `Carthago.Tests/IncidentRuleVisibilityRegressionTests.cs`: preserved case-level rule and event IDs across a view-model round trip; union of authoritative recorded sources; deduplication/limit; no fabricated match from a high-risk anomaly without rule evidence.
- Existing relevant suites to run alongside it: `IncidentDetectionLinkVmTests`, `RuleHealthDiagnosticsServiceTests`, `RuleTelemetryFieldContractTests`.

### Windows verification (owner-run, pinned checkout)

From the project root:

```powershell
git switch feature/carthago-reliability-hardening
git pull --ff-only origin feature/carthago-reliability-hardening
git rev-parse HEAD

dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release `
  --filter "FullyQualifiedName~IncidentRuleVisibilityRegressionTests|FullyQualifiedName~IncidentDetectionLinkVmTests|FullyQualifiedName~RuleHealthDiagnosticsServiceTests|FullyQualifiedName~RuleTelemetryFieldContractTests" `
  --logger "trx;LogFileName=detection-visibility-regression.trx" `
  --results-directory .\TestResults\DetectionQuality
```

Record the exact checkout SHA, TRX hash, runner identity and success/failure numbers. Then start a controlled live-capture session, record Detection Coverage snapshots at two points in time, and inspect representative rule no-match reasons and any persisted events.

## Explicitly pending qualification

These UI and evidence-preservation changes do **not** qualify R001–R1000. Exact-ID paired positive/negative coverage, independent benign/malicious labels, real producer evidence, R102/R118/R163 dependencies, Windows live-capture verification, and later manual WPF acceptance remain independent gates. No rule threshold, mode, suppressor or trust decision was modified.

References: [Current status](../CURRENT_STATUS.md) · [Registry reconciliation](REGISTRY_RECONCILIATION_20261116.md) · [Exact-ID audit](EXACT_ID_QUALIFICATION_AUDIT.md) · [Holdout V2](holdout/HOLDOUT_V2_PROTOCOL.md).

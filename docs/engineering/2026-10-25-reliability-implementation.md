# Reliability Hardening Implementation Plan

**Goal:** Preserve security findings, make capture delivery visible, and measure accuracy and load before enabling optional external trust integration.

**Architecture:** Extend the existing LiteDB, append-only baseline journal, capture health,
and offline benchmark services. Keep every new policy/metric class deterministic and independent
of WPF so it can be probed on Linux while the Windows-host suite remains authoritative.

**Tech stack:** C# 12, .NET 8, WPF, LiteDB, xUnit.

**Design:** `docs/engineering/2026-10-25-reliability-design.md`

## Global constraints

- Preserve the existing persistence file names and serialized formats.
- No network or local machine changes during unit tests.
- No automatic endpoint containment or trust revocation.
- One changed tracked file per Git commit; use technical commit messages without tool attribution.
- Treat Windows live capture as an operator-side acceptance test.

## Review focus

- Corrupt LiteDB file whose recovery rename fails: original bytes must remain untouched.
- Incident write after store disposal: failure must be observable to its caller.
- Quiet capture versus stale UI: distinct health states without guessing a packet rate.
- Zero-positive or zero-negative labeled replay: finite, explicit quality metrics.
- No GenesisMesh credentials or unavailable authority: capture must continue unchanged.

## Task 1: Safe database recovery

**Files:** `Carthago.Tests/AnalyticsPipelineTests.cs`, `Carthago/Analytics/Services/LocalStore.cs`.

- [ ] Add a regression for an unmovable invalid database whose original bytes must remain.
- [ ] Verify the test exposes the unsafe fallback.
- [ ] Remove the destructive deletion path; fail explicitly if preservation fails.
- [ ] Verify build and portable recovery scenario; commit each file separately.

## Task 2: Incident persistence outcome

**Files:** `Carthago.Tests/AnalyticsPipelineTests.cs`, `Carthago/Analytics/Services/LocalStore.cs`, `Carthago/Analytics/AnalyticsHost.cs`.

- [ ] Add a failing post-disposal incident-write test.
- [ ] Return an explicit success/failure result from incident persistence without changing the serialized schema.
- [ ] Surface failures in analytics health without blocking capture; add regression coverage.
- [ ] Verify existing-data round trip; commit each file separately.

## Task 3: End-to-end capture delivery diagnostics

**Files:** `Carthago.Tests/CaptureFlowHealthTests.cs`, `Carthago/Services/CaptureFlowHealth.cs`, existing capture health wiring if needed.

- [ ] Add a failing test distinguishing overload drops from healthy traffic and stale UI.
- [ ] Introduce deterministic capture-health assessment with counters and reason codes.
- [ ] Expose those reasons to existing diagnostics without duplicating capture state.
- [ ] Verify session restart isolation; commit each file separately.

## Task 4: Detection-quality scores

**Files:** `Carthago.Tests/TuningBenchmarkTests.cs`, `Carthago/Services/Benchmarking/DetectionQualityMetrics.cs`, benchmark report types/formatters.

- [ ] Add failing tests for TP/FP/FN/TN, missing denominators, and labeled negative cases.
- [ ] Calculate precision, recall, specificity, and F1 with explicit undefined metric semantics.
- [ ] Report aggregate results alongside sample counts, without claiming representative real-world rates.
- [ ] Validate deterministic replay fixtures; commit each file separately.

## Task 5: Portable performance benchmark

**Files:** `Carthago.Tests/PerformanceMetricTests.cs`, `Carthago/Services/Benchmarking/PerformanceMetrics.cs`.

- [ ] Add failing tests for finite throughput, bounded queue pressure, and zero-duration handling.
- [ ] Implement a pure summary reducer for elapsed time, events, bytes, and drops.
- [ ] Add an operator-run Windows sustained-load protocol with memory/CPU capture.
- [ ] Commit each file separately.

## Task 6: Optional GenesisMesh evaluation

**Files:** `docs/integrations/genesismesh.md` initially; add implementation only after core reliability verification.

- [ ] Document the mapping from trust evidence to Carthago event enrichment.
- [ ] Document safe API boundaries, authentication, timeouts, retention, and unavailable-service behavior.
- [ ] Keep all enforcement and revocation functions disabled in this phase.
- [ ] Commit the evaluation document separately.

## Verification and integration

- [ ] Cross-build the Windows-targeted solution using .NET 8 with Windows targeting enabled.
- [ ] Run portable cross-platform probes for new deterministic components.
- [ ] Run the complete Windows test suite and live capture/restart acceptance on the Lenovo.
- [ ] Inspect the integration diff; merge once the target `main` history has been reconciled.
- [ ] Remove the single temporary feature branch after successful merge.

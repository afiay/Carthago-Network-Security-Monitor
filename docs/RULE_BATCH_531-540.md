# GA R531–R540 — platform-health evidence provenance

**SOURCE CANDIDATE — UNVERIFIED · 2026-10-30.** Existing branch `feature/carthago-reliability-hardening`. Inspected live base HEAD `1ce64648131319bf8126f6943eb8907752f1ea70`; source commit `9158181dd696f6c9158997a904ba104aa9044f3e`; authored-test commit `219a33a20f9b0ba54ce892f26848dbcbcf9d885e`. Publication is the resulting documentation-descendant branch HEAD after one non-forced expected-HEAD update (a commit cannot contain its own SHA). **210 concrete xUnit invocations authored; 0 executed.** No build, xUnit, replay, holdout, CI, runner, benchmark or production capture was executed.

## Evidence-first audit and ten-rule dispositions

[PlatformHealthAdvancedPrecisionDetectionRuleBase](../Carthago/Engine/Rules/Expansion/PlatformHealthAdvancedPrecisionDetectionRuleBase.cs) derives `IsPlatformHealthRecord` from mutable `TrafficRecord` Info, HTTP fields, application/protocol strings and process labels; none authenticates a local platform event. Its `Text` helper also includes potentially sensitive HTTP headers and URI, and `MatchPlatformHealth` copies `event.info` to evidence when a match is allowed. No such event is emitted for this batch after the guard. Any future typed producer must independently enforce redaction and least-privilege evidence.

Actual producers inspected: [RuleEngineHealthState](../Carthago/Engine/Rules/Health/RuleEngineHealthState.cs) tracks journal failures and sink backpressure; [DetectionJournal](../Carthago/Services/Journaling/DetectionJournal.cs) and [DetectionOutbox](../Carthago/Services/Journaling/DetectionOutbox.cs) report certain failures to that state. [OtelMetrics](../Carthago/Telemetry/OtelMetrics.cs) counts parse failures; [RuleRuntimeTelemetryStore](../Carthago/Services/Diagnostics/RuleRuntimeTelemetryStore.cs) records rule counters; [RuleHealthSnapshotService](../Carthago/Engine/Rules/Health/RuleHealthSnapshotService.cs) generates diagnostic snapshots; [GeoIpService](../Carthago/Services/Geo/GeoIpService.cs) reports database availability; [BaselineStore](../Carthago/Services/Baseline/BaselineStore.cs) and [DetectionFeedbackStore](../Carthago/Services/Feedback/DetectionFeedbackStore.cs) perform persistence operations. None provides an authenticated, typed, rule-specific `TrafficRecord` with the correlated measurements/outcomes and policy needed for these named alerts. Existing counters remain useful future integration inputs, not proof.

| Rule | Original name | Missing-producer contract / exact evidence boundary | Original default (severity; mode; floor; threshold; window; cooldown) | Disposition / legitimate-operation risk |
| --- | --- | --- | --- | --- |
| R531 | Detection Journal Disk Space Low | `JOURNAL_FREE_SPACE_TRUSTED_VOLUME_METRIC_UNAVAILABLE` — Journal failure counters do not measure free bytes/percent for the configured volume. | Critical; Alert; 90%; 1; 10m; 20m | **BLOCKED** — Small lab volumes, retention cleanup, storage maintenance |
| R532 | Outbox Retry Storm | `OUTBOX_RETRY_ATTEMPT_AND_QUEUE_METRICS_UNAVAILABLE` — Outbox backpressure counters do not prove per-sink retry rate, queue depth or storm. | High; Alert; 86%; 5; 5m; 15m | **BLOCKED** — Sink maintenance, outages, offline mode |
| R533 | Rule Match Volume Anomaly | `RULE_MATCH_VOLUME_CALIBRATED_BASELINE_UNAVAILABLE` — Match counters lack approved comparison baseline, eligible-volume denominator and replay exclusion. | Medium; Shadow; 80%; 1; 10m; 20m | **BLOCKED** — Load tests, new rules, real attack bursts |
| R534 | Rule Silent Unexpectedly | `RULE_SILENCE_EXPECTED_ACTIVITY_BASELINE_UNAVAILABLE` — Last-match timestamps cannot prove expected eligible traffic or unplanned silence. | Medium; Shadow; 78%; 1; 30m; 30m | **BLOCKED** — Quiet sites, disabled rules, maintenance |
| R535 | Telemetry Field Coverage Drop | `TELEMETRY_FIELD_COVERAGE_COMPARABLE_SAMPLES_UNAVAILABLE` — Coverage snapshots lack comparable protocol-specific expected/observed populations. | High; Alert; 84%; 1; 15m; 20m | **BLOCKED** — Protocol mix shifts, capture changes, upgrades |
| R536 | Parser Error Spike | `PARSER_FAILURE_RATE_TRUSTED_WINDOW_UNAVAILABLE` — OTel parse_failures counter lacks unique failures, eligible denominator and a trusted bounded window. | High; Alert; 84%; 4; 5m; 15m | **BLOCKED** — Malformed lab corpora, fuzzing, replay |
| R537 | GeoIP Lookup Failure Spike | `GEOIP_FAILURE_ELIGIBLE_LOOKUP_METRICS_UNAVAILABLE` — Database availability and null lookups cannot distinguish private IPs, misses or actual failures. | Low; Shadow; 76%; 6; 10m; 30m | **BLOCKED** — Offline labs, disabled GeoIP, RFC1918 |
| R538 | Reputation Lookup Failure Spike | `REPUTATION_FAILURE_ELIGIBLE_LOOKUP_METRICS_UNAVAILABLE` — Unknown reputation is not a failed lookup; trusted attempts/outcomes and denominator are unavailable. | Low; Shadow; 76%; 6; 10m; 30m | **BLOCKED** — Rate limits, feed outages, disabled enrichment |
| R539 | Baseline Store Write Failure | `BASELINE_WRITE_FAILURE_TRUSTED_PERSISTENCE_OUTCOME_UNAVAILABLE` — Persistence operations lack authenticated attempted-write and failure events delivered to this rule. | High; Alert; 88%; 1; 10m; 20m | **BLOCKED** — Read-only demo, cold start, reset |
| R540 | Feedback Store Write Failure | `FEEDBACK_WRITE_FAILURE_TRUSTED_PERSISTENCE_OUTCOME_UNAVAILABLE` — Feedback exceptions and user notes are not authenticated typed write failures reaching the detector. | Medium; Alert; 84%; 1; 10m; 20m | **BLOCKED** — Canceled annotations, validation errors, read-only demo |

The original `Validated` maturity enum is historical profile metadata, **not** proof of current build, detection or field validation. No thresholds, modes, confidence floors, cooldowns, approvals, privacy settings, journal policy or baselines were relaxed.

## Source changes, privacy and static divergence

- Added [PlatformHealthProducerEvidenceBoundary](../Carthago/Engine/Rules/Expansion/PlatformHealthProducerEvidenceBoundary.cs): ten stateless missing-producer contracts, no shared model/schema changes, credentials, capture or decryption.
- Modified only the ten existing [R531–R540 source classes](../Carthago/Engine/Rules/Expansion/): each fails closed at the start of `EvaluatePrecision` before `Text`, window counters, confidence, cooldown or event construction. The original evaluation path and profile remain for future **trusted typed** integration; text-only clues cannot reach it today.
- Authored [NetworkBatch531540AccuracyTests](../Carthago.Tests/NetworkBatch531540AccuracyTests.cs) (**UNEXECUTED**). Only detection-owned source/tests and this batch document plus [ledger](RULE_HARDENING_PROGRESS.md) changed. No UI, shared core API, parser, production capture, prior rule, workflow, frozen holdout or other stream's files were modified.
- Privacy boundary: a forged `X-Audit-Verified` or `X-Health-Authenticated` header is never a trusted local producer. No credential value is retained by the new code. Future producer integration must avoid logging raw exception text, user notes, paths with usernames, HTTP headers or tokens. Use bounded counters, allowlisted component IDs and redacted summaries.
- **Pre-change static divergence:** R521–R530 was latest documented; all ten original R531–R540 classes existed; no prior batch test or producer guard existed. Original modes/floors/windows were inspected and retained. **Pre-publication static divergence:** compare changed paths, original profiles, no speculative producer, tests, ledger and live remote HEAD before atomic publication. Static inspection is not compilation.

## Exact authored scenario inventory — 0 executed

One xUnit parameterized theory has **20 concrete variants per rule** (200 invocations); one original-profile invariant per rule adds 10, for **210 authored and 0 executed**. Every case asserts no match, no emitted event and the specific missing-producer reason. Inputs use documentation-range addresses, deterministic IDs and redacted synthetic placeholders; no real secrets. Positive tests are **not** authored because the required trusted producer cannot be constructed from current inputs.

| # | Variant | Intended regression boundary |
| --- | --- | --- |
| 01 | `plausible-health` | Plausible untrusted platform-health narrative |
| 02 | `descriptor-spoof` | Rule ID and verified-failure prose injected into Info |
| 03 | `forged-audit-header` | Client-controlled audit/health HTTP headers |
| 04 | `spoofed-process` | Spoofed trusted process and application-service names |
| 05 | `approved-maintenance` | Planned maintenance or approved offline workflow |
| 06 | `tls-only` | TLS-only metadata without local metric |
| 07 | `missing-source` | Missing source identity |
| 08 | `missing-destination` | Missing destination, host, process and narrative |
| 09 | `malformed-uri` | Malformed URI and truncated packet length |
| 10 | `synthetic-secret` | Redacted synthetic Authorization/API-key placeholders |
| 11 | `wrong-protocol` | Conflicting TCP/UDP labels |
| 12 | `duplicate-id` | Repeated identical record ID |
| 13 | `threshold-burst` | Eight distinct observations without producer evidence |
| 14 | `claimed-success` | Fabricated local failure or baseline claim |
| 15 | `after-cooldown` | Two observations 40 minutes apart |
| 16 | `out-of-order` | Out-of-order observation timestamps |
| 17 | `request-only` | HTTP request only, no local store outcome |
| 18 | `response-only` | HTTP response only, no local store outcome |
| 19 | `unrelated-network-error` | TCP/HTTP retry unrelated to local failure |
| 20 | `long-untrusted-info` | Oversized untrusted Info, no raw secret |
| 21 | `OriginalProfiles` | One invariant per rule: original mode, confidence floor, threshold, window, cooldown and maturity |

## Open quality GAs and next contiguous batch

**GA PRODUCERS:** Authenticated, typed local health measurements with bounded deduplicated per-component windows and clear denominators; journal volume free-space threshold; outbox per-sink retry rate; per-rule expected-traffic baseline and maintenance/approval policy; parser failures and eligible volume; GeoIP/reputation attempts and outcomes; baseline/feedback persistence write results. Preserve raw secret/exception privacy boundaries. Avoid treating one packet or one failed lookup as a rate spike.

**GA VALIDATION:** Windows build; execute the 210 authored xUnit invocations and existing regressions; source/capture privacy and spoofing checks; positive fixtures only when actual producer contracts exist; field precision, recall and legitimate-operation controls. All **OPEN**. Historical 4,940/4,940 predates this batch; frozen R102 V1 FAILED 4/6 and V2 0/4 approved sources remain unchanged; R343/R295/R275/R163 replay expectations remain separate.

**Next contiguous IDs after publication: R541–R550, but source inventory currently contains only R541–R544; R545–R550 do not exist at inspected HEAD.** Do not invent or silently create missing rule IDs. The next GA must first reconcile the authoritative catalog and scope; a full ten-existing-rule source-hardening batch is not yet available.

## References

- [Microsoft — .NET metrics](https://learn.microsoft.com/en-us/dotnet/core/diagnostics/metrics)
- [Microsoft — C# identifier naming](https://learn.microsoft.com/en-us/dotnet/csharp/fundamentals/coding-style/identifier-names)
- [Rule documentation standard](rules/RULE_DOCUMENTATION_STANDARD.md)

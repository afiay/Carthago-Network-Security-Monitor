# Rule accuracy batch 11 — R051–R055

**Status: CANDIDATE — UNVERIFIED.** 46 advanced xUnit facts (9 + 9 + 9 + 9 + 10) authored. No builds, xUnit, replay benchmarks, holdout, or Windows runner executed.

| Rule | Candidate precision, state and privacy changes | Facts |
| --- | --- | ---: |
| R051 Packet capture drop surge | Preserve any-positive-delta trigger. Validate fresh UTC health snapshots, report each new drop interval only once, reject repeated/out-of-order snapshots and negative deltas. | 9 |
| R052 Sink queue backpressure | Detect increases in cumulative failure count, not the same historical count on every packet. Treat counter decreases as resets, deduplicate snapshots and reject stale/invalid evidence. | 9 |
| R053 Detection journal write failure | Apply cumulative counter transition handling to mandatory journal failures. Preserve event attribution without exposing journal paths or error strings. | 9 |
| R054 Rule configuration reload failure | Apply cumulative counter transition handling; reject repeated historical failures and handle resets while retaining existing configuration policy. | 9 |
| R055 Threat feed stale | Preserve the strict >24-hour freshness threshold, validate UTC feed timestamps, emit once per stale episode and rearm after a confirmed fresh update. | 10 |

## Evidence and scope

All five rules consume `RuleEngineHealthSnapshot`, not ordinary `TrafficRecord` protocol fields. Tests use typed health snapshots directly and cover genuine operational failures, benign healthy intervals, repeated/stale or contradictory observations, counter resets, out-of-order state, cancellation and feed recovery. Traffic-only JSON replay fixtures would not carry the required health counters and could create misleading labels, so no new replay labels were manufactured for this batch. Existing development replay and frozen holdout are unchanged.

A new `HealthSnapshotTransitions.cs` contains the UTC snapshot-freshness gate and per-rule instance transition helpers. The 60-second snapshot age guard is a **candidate evidence-quality safeguard**, not a production-validated threshold. Cumulative counters are not cleared or reinterpreted in `RuleEngineHealthState`; the helpers only determine whether a fresh counter transition warrants a new alert. No configuration, confidence floor, Shadow/Disabled policy, asset approval, baseline-readiness logic or frozen holdout identity was changed.

## Residual risks and deferred acceptance

- Per-rule instance deduplication does not persist across engine recreation; after restart an already-positive cumulative count may generate one new alert. This is safer than silently losing a real failure but can duplicate incidents.
- A counter reset that occurs between snapshots without a zero or lower value being observed can be mistaken for an increase. Exact once-only incident semantics would require generation IDs or durable event identifiers in the health producer.
- The one-minute freshness gate assumes health snapshots and rule evaluations share a trustworthy UTC clock; clock jumps and replay-time semantics require Windows verification.
- A stalled engine cannot emit these alerts while it remains stalled. The health rules only run when rule evaluation resumes.
- Threat-feed staleness does not establish that a threat feed is enabled or required for a particular deployment; an explicit feed configuration contract would improve future precision.
- These are **uncompiled, unexecuted candidates**. The deferred one-run verifier must establish compilation, full xUnit regression, development replay, frozen holdout, and per-rule advanced test coverage before acceptance.

## Deferred verification

`scripts/verify-all-rule-batches.ps1` remains the sole Windows acceptance entry point. It discovers R051–R055 automatically by filename and is **not executed** until the owner explicitly declares test time.

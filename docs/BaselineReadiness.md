# Baseline readiness and automatic alert eligibility

Baseline-dependent rules remain non-paging until persisted observations establish
an adequate learning window. Readiness is recalculated after each successful
journal append and when the historical baseline is explicitly loaded.

Default readiness requirements:

- At least **100 successfully persisted observations**.
- At least **20 distinct baseline keys** (kind, subject, value).
- At least **24 hours** between the earliest and latest persisted observations.
- A latest observation no older than **48 hours**.
- Valid observation counts and timestamps, without unresolved JSON journal or
  legacy snapshot corruption.
- `BaselineOptions.LearningMode = true` is an explicit override that keeps
  baseline-dependent rules in learning mode.

Unloaded, incomplete, stale, corrupt, and failed-to-persist baseline state is
**not ready**. The original journal/snapshot is retained for investigation;
no automatic deletion, truncation, or backup is performed. A reset returns the
store to learning mode and requires fresh observations.

When readiness is proven, only the explicitly designated baseline promotion
rules **R102 and R103** may become eligible for Alert. Both still need their
rule-specific confidence floors; **R102 also requires at least 80% precision
confidence**. Runtime telemetry, evidence, cooldown, and explicit per-rule
Shadow/Disabled overrides remain authoritative. Maturity is not a reason to
skip any of those safeguards.

Readiness describes the *historical observations stored by Carthago*, not an
independent guarantee that every network segment or DNS client has been
observed. These defaults are conservative starting parameters, not measured
statistical guarantees. Calibrate them with representative long-running
capture and review the baseline coverage before relying on automatic
promotion in production.

The replay benchmark applies rule precision checks after profile tuning.
Its reports are still synthetic sample-level measurements; they are **not**
a substitute for live-capture validation of end-to-end alert delivery.

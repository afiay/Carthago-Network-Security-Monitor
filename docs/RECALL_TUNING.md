# Recall tuning with labeled replays

Carthago's tuning benchmark distinguishes **detector recognition** from **alert eligibility**. A raw rule match, a suppressed event, or a Shadow decision is **not** an alert-level true positive.

## Run the offline benchmark

From the repository root in Windows PowerShell:

```powershell
.\verify-local.ps1 -Details
.\scripts\inspect-recall-gaps.ps1 -Profile Enterprise -Detailed -Top 20
.\scripts\inspect-recall-gaps.ps1 -Profile Research -Detailed -Top 20
```

The benchmark writes:

- `build-verify/tuning-benchmark.json`: machine-readable `recallGaps` records for every missed expected (malicious sample, rule, profile) alert.
- `build-verify/tuning-benchmark.md`: grouped causes and up to 50 representative gaps.

A gap contains the sample and rule ID, profile, detector outcome, effective policy mode, observed confidence/floor when available, and diagnostic evidence.

## How to use the causes

| Cause | What is known | Next investigation |
| --- | --- | --- |
| `MissingTelemetry` | Required fields or a telemetry type were missing | Improve collection or the labeled fixture, not the alert threshold |
| `NoMatch` | The detector did not recognize the expected behavior | Compare rule predicates with corroborated malicious traffic |
| `DetectorFailure` | The rule evaluator failed | Fix the exception, then test its benign and malicious paths |
| `RuleUnavailable` | Expected rule was not available for evaluation | Inspect rule registration and catalog coverage |
| `ProfileShadow` | Default profile policy does not alert on this match | Verify whether the profile is intentionally conservative |
| `PrecisionShadow` | Precision profile is not in Alert mode | Gather evidence to justify a future, separately reviewed promotion |
| `ConfidenceFloor` | A confidence floor prevented an alert | Improve evidence quality; do not lower the floor |
| `ApprovedAsset` | An approved-asset policy contributed to non-alerting | Check scope and ownership, not blanket allowlisting |
| `Disabled` | Rule is disabled for this profile | Verify environment configuration requirements |
| `RuntimeGate` | Runtime policy constrained an otherwise alert-eligible match | Examine the recorded precision/runtime reasons |
| `NoPolicyDecision` | Match exists without a recorded policy decision | Fix benchmark tracing |
| `AlertNotEmitted` | Trace says Alert but no alert ID was emitted | Treat as accounting or emission defect |

Causes are *observed explanations*, not proof that an alert should have been emitted. A rule can have more than one relevant gate; inspect the evidence alongside the category.

## Safety criteria

1. Preserve R118 and R163 in Shadow mode, including their current confidence floors, until independently validated malicious and benign evidence supports a change.
2. Add realistic paired malicious/benign fixtures for the specific missed behavior.
3. Confirm the expected raw match, confidence evidence, and alert-policy decision separately.
4. Require no new benign alert-level false positives across the curated replay profiles.
5. Recompute true positives, false positives, false negatives, precision, recall, and F1 before discussing any rule promotion.
6. Do not generalize the 48-sample replay precision to production prevalence or effectiveness.

Benchmarks use isolated baseline storage and must not reset the live application's baseline journal.

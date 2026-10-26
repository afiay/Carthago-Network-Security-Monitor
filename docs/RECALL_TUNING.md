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

A gap contains the sample and rule ID, profile, detector outcome, effective policy mode, observed confidence/floor when available, and diagnostic evidence. `cause` is the prioritized primary explanation; `blockingFactors` retains every observed independent gate. A raw match can simultaneously face a confidence floor, a missing approved environment, and a Shadow profile.

## How to use the causes

| Cause | What is known | Next investigation |
| --- | --- | --- |
| `MissingTelemetry` | Required fields or a telemetry type were missing | Improve collection or the labeled fixture, not the alert threshold |
| `NoMatch` | The detector did not recognize the expected behavior | Compare rule predicates with corroborated malicious traffic |
| `DetectorFailure` | The rule evaluator failed | Fix the exception, then test its benign and malicious paths |
| `RuleUnavailable` | Expected rule was not available for evaluation | Inspect rule registration and catalog coverage |
| `ProfileShadow` | Default profile policy does not alert on this match | Verify whether the profile is intentionally conservative |
| `PrecisionShadow` | Precision profile is not in Alert mode | Gather evidence to justify a future, separately reviewed promotion |
| `ConfidenceFloor` | The tuning classifier's confidence floor blocked a match | Improve evidence quality; do not lower the floor |
| `PrecisionConfidenceFloor` | An independent runtime precision floor blocked a match even if profile policy was permissive | Corroborate the telemetry; retain the floor (R118 86%, R163 84%, R102 80%) |
| `EnvironmentApprovalRequired` | The runtime precision evaluator requires approved asset, segment, or controller evidence | Validate ownership and scope before requesting a rule change |
| `EnvironmentConfigurationRequired` | A profile's explicit environment configuration requirement is unmet | Configure the approved inventory and re-evaluate without bypassing it |
| `BaselineNotReady` | The runtime evaluator reports inadequate baseline readiness | Collect trusted baseline observations; do not promote prematurely |
| `ApprovedAsset` | An approved-asset policy contributed to non-alerting | Check scope and ownership, not blanket allowlisting |
| `Disabled` | Rule is disabled for this profile | Verify environment configuration requirements |
| `RuntimeGate` | Runtime policy constrained an otherwise alert-eligible match | Examine the recorded precision/runtime reasons |
| `NoPolicyDecision` | Match exists without a recorded policy decision | Fix benchmark tracing |
| `AlertNotEmitted` | Trace says Alert but no alert ID was emitted | Treat as accounting or emission defect |

Causes are *observed explanations*, not proof that an alert should have been emitted. A rule can have several simultaneous blocking factors. Investigate all of them; removing one gate would not necessarily produce an alert, and no gate should be disabled automatically.

## R102 distinct DNS TXT-name corroboration

R102 now records `dns.distinctSuspiciousTxtNames` for structured DNS TXT questions. A new behavioral correlation contributes **0.08** to the candidate confidence only after three different long, high-entropy TXT QNAMEs are observed from the same source to the same root domain within the configured observation window (five minutes by default). Each name must qualify independently. A repeated identical QNAME does not increase the distinct count.

The offline replay set now includes two **paired** fixtures. `r102-distinct-txt-burst-candidate` contains three different synthetic, high-entropy TXT names from one source to one root; `r102-retried-txt-verification-control` repeats the same synthetic TXT name three times. The paired integration test checks R102's actual per-rule confidence, verifies the distinct burst scores higher than identical retries, and requires **both to remain non-alerting** until baseline readiness and production eligibility are established. The candidate has a malicious scenario label for investigative coverage; that label is not proof of exfiltration or a reason to override the baseline policy.

The additional evidence does **not** apply to DNS NULL queries, `_acme-challenge` and other excluded validation names, or known telemetry roots. The rule's **80% confidence floor**, cooldown behavior and requirement for a mature baseline before production alert promotion remain unchanged. Baseline readiness is now an explicit constraint even in the broad Research profile; the benchmark mirrors the live baseline policy instead of assuming an empty baseline is ready. A matched or high-confidence replay candidate is not an alert unless its profile, baseline, runtime precision and suppression gates all permit emission.

Run `dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~R102DistinctTxtCorrelationTests|FullyQualifiedName~R102PairedReplayQualityTests"` to exercise positive/negative controls, source and window isolation, paired replay confidence quality, and preservation of baseline promotion gating. Recompute all replay profile metrics using `.\verify-local.ps1 -Details` after updating. Until local verification passes, treat this change as an unverified candidate. It should not be described as an increase in measured alert-level recall unless new, correctly labeled replay alerts demonstrate one.

## Safety criteria

1. Preserve R118 and R163 in Shadow mode, including their current confidence floors, until independently validated malicious and benign evidence supports a change.
2. Add realistic paired malicious/benign fixtures for the specific missed behavior.
3. Confirm the expected raw match, confidence evidence, and alert-policy decision separately.
4. Require no new benign alert-level false positives across the curated replay profiles.
5. Recompute true positives, false positives, false negatives, precision, recall, and F1 before discussing any rule promotion.
6. Do not generalize the curated replay precision (52 labeled cases at the previous verified baseline; the new paired R102 fixtures bring the candidate set to 54 pending verification) to production prevalence or effectiveness.

Benchmarks use isolated baseline storage and must not reset the live application's baseline journal.

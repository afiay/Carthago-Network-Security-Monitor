# Rule-Owned Precision Detector Migration

Carthago is moving from "central heuristics protected by a safety gate" to "rules that own their own detection contracts, with the central gate kept as defense-in-depth."

## Reference model

- `R094_DGALikeDomainQueryRule` is now the reference implementation style for a migrated rule-owned precision detector.
- `R095-R103` follow the same pattern for the DNS family.
- `ExtendedRuleDetectors` remains the fallback implementation for rules that have not yet been migrated.

## What a migrated rule owns

Each migrated rule should define:

- explicit telemetry family requirements
- explicit field requirements
- positive match conditions
- negative exclusions
- threshold, window, and cooldown behavior when the behavior is temporal
- confidence scoring
- severity selection
- structured evidence
- analyst-facing explanation
- recommended response actions
- false-positive notes
- regression tests

The central precision layer still applies after the rule matches:

- `RuleTelemetryValidator`
- `RuleCandidateSelector`
- `RulePrecisionRuntimeEvaluator`
- `RuleTuningCatalog`
- `RuleExecutionIndex`

That layer is the safety net. It is not the source of truth for the rule's actual detection contract.

## Migration status

### Migrated to rule-owned detectors

- `R094-R103` DNS precision rules

### Still central-gated or legacy-owned

- `R001-R049`
  - Preserved as core rules and intentionally not weakened during this migration.
- `R050-R056`
  - Engine-health rules that still depend on runtime health state rather than traffic-only rule-owned detectors.
- `R057-R093`
  - Still routed through `TelemetryDetectionRuleBase` and `ExtendedRuleDetectors`.
- `R104-R544`
  - Still routed through `TelemetryDetectionRuleBase` and `ExtendedRuleDetectors` unless already implemented as a stronger family-specific rule.

## Maturity guidance

- `Core`
  - Preserved, high-value rules with established semantics and strong production expectations.
- `Validated`
  - Rule-owned detectors with explicit telemetry contracts and dedicated regression tests.
- `Candidate`
  - Rules that are useful but still need stronger field-level evidence, more tuning, or broader replay validation.
- `Experimental`
  - Coverage-oriented rules that should remain `Shadow` or `Disabled` until stronger telemetry and tests exist.
- `Deprecated`
  - Rules kept visible for compatibility or historical reference while being retired safely.

## Runtime mode guidance

- `Alert`
  - Allowed only when the rule has strong field-level telemetry, confidence support, and tests for positive and negative cases.
- `Shadow`
  - Use when telemetry is partial, environmental context is incomplete, or the rule is still being tuned.
- `Disabled`
  - Use when the rule depends on environment configuration that is absent or when the telemetry family is not available.

## Promotion criteria

Promote a rule to reliable `Alert` behavior only when it has:

- structured telemetry evidence instead of `AnyText`
- a real field-level discriminator instead of host-only, protocol-only, category-only, or port-only matching
- threshold/window behavior where the tactic is bursty, repeated, or volumetric
- negative controls for common benign scenarios
- replay-backed regression tests

High or Critical alerting must not come from:

- `AnyText` only
- generic host strings only
- protocol labels only
- category strings only
- port-only evidence
- generic HTTP traffic pretending to be cloud audit
- generic TCP traffic pretending to be OT/ICS
- generic login text pretending to be identity telemetry

## Required tests for a promoted rule

At minimum:

- positive strong-telemetry sample
- negative missing-telemetry sample
- negative `AnyText`-only sample
- negative port-only sample where relevant
- threshold/window test where relevant
- evidence assertion
- severity and confidence assertion

## DNS batch notes

`R094-R103` now:

- require structured DNS telemetry
- stop relying on `Info` text fallback for primary DNS evidence
- keep cooldown/suppression reasons in structured evidence
- expose analyst explanation and recommended actions in structured evidence
- use the central precision runtime only as a final guardrail

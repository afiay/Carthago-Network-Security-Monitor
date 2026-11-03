# Catalog-wide hardening pass: 544 registered rules

This document describes a shared-engine hardening pass and the evidence required before individual rule promotion. It does **not** claim that 544 rules have all been independently validated on real-world traffic.

## Changes that apply across the catalog

1. **Exact confidence enforcement.** The runtime precision gate compares raw finite confidence values to each rule's original minimum confidence, without granting a rounded-up half-percent. Scores that are NaN, infinite, negative, or above 1.0 fail closed. The profile/tuning gate observes the same invalid-score policy and cannot promote an invalid candidate through a baseline exception or the Research profile.
2. **Safer confidence audit values.** Shared confidence calculations normalize non-finite inputs before serialization and use invariant numeric formatting for their explanatory evidence strings. Existing confidence floors are unchanged.
3. **Bounded shared detection state.** Evidence-driven expansion rules share bounded time-window memory: a maximum of 16,384 simultaneous rule/source keys and 512 observations per key. Future-dated observations cannot corroborate an earlier time window. Long-stale keys are reclaimed at capacity; a saturated new key returns no eligible threshold count, rather than an invented detection. Replay isolation now resets the same shared counter state on each fixture.
4. **Complete rule-contract inventory.** Every offline benchmark generates a separate `build-verify/rule-hardening-audit.md` file and a `ruleHardeningAudit` JSON array with **one entry per registered rule**. The audit includes category, severity, maturity, default precision mode, original confidence floor, declared telemetry/evidence contracts, baseline dependency, and available labeled replay cases. The Windows verification script checks catalog count and rejects malformed contracts.
5. **Catalog-wide regression contracts.** Dedicated tests iterate the actual 544-rule registry to check invalid numeric scores, absence of corroborated telemetry, and catalog metadata. The shared window state has independent boundedness and clock-jump tests.

## Evidence status is not production readiness

| Evidence status | What it means |
| --- | --- |
| `NoExplicitReplayControls` | No explicit rule-specific labeled positive or negative replay assertion |
| `PositiveOnly` | At least one expected malicious raw match, but no explicit negative |
| `NegativeOnly` | At least one explicit nonmatch assertion, but no malicious positive |
| `PairedSyntheticControls` | Both kinds of labeled replay assertion exist for the same rule |

A paired synthetic fixture is **not** proof of field precision, a representative adversarial evaluation, or grounds for automatically raising rule maturity. The audit retains missing coverage as visible gaps instead of treating unlabeled benign traffic as universal negative tests. Reported replay alerts remain subject to profile, baseline, environment, confidence, and independent runtime precision gates.

## Run on Windows

From the repository root:

```powershell
git fetch origin feature/carthago-reliability-hardening
git merge --ff-only FETCH_HEAD
.\verify-local.ps1 -Details -LiveOutput
.\scripts\inspect-rule-hardening.ps1 -MissingPaired -Top 25
.\scripts\inspect-rule-hardening.ps1 -OnlyContractIssues
.\scripts\inspect-rule-hardening.ps1 -RuleId R102,R118,R163
```

Inspect the full output at `build-verify/rule-hardening-audit.md`. The machine-readable source is `build-verify/tuning-benchmark.json`. The `RuleHardeningAudit` array records structural readiness; it must be interpreted alongside actual per-rule test results and sample provenance.

## Remaining work

- Obtain genuinely representative benign and malicious telemetry for each protocol/rule family, with sources, permission and provenance documented.
- Add negative, malformed, ambiguous, time-window and environment-specific scenarios for each family; validate privacy-sensitive evidence redaction.
- Measure real precision and recall on held-out labeled traffic separately from policy-eligible emission rates.
- Never auto-promote a rule because a synthetic benchmark passes. Require documented approval and staged deployment with rollback and logging.

This pass hardens the **common execution and verification foundation** of the 544-rule catalog. Specialist rule-by-rule engineering, independent field datasets and production certification remain separate tasks.

# R541–R544 — retrospective source documentation

**Status:** Retrospective source inventory, not an original GA report. **0 tests executed for this documentation reconstruction.** Existing registrations and source profiles were inspected at `949abbf080c4e46c5a04556961b664ec515463c3`; no implementation, policy, test fixture or historical result was changed.

These four existing PlatformHealthAdvanced rules had no dedicated batch page. This page records the current source predicates and proposed verification cases without inventing historical execution results. The [historical expansion overview](../guides/R273_R544_SelectedRules.md) and [development validation ledger](../../DEVELOPMENT_VALIDATION_LEDGER.md) remain authoritative for their own scope.

| Rule | Source predicate | Declared profile | Negative controls / limitations |
| --- | --- | --- | --- |
| [R541 Content Pack Validation Failure](../../../Carthago/Engine/Rules/Expansion/R541_ContentPackValidationFailureRule.cs) | Platform-health record with content/rule pack context and validation failure semantics (schema, duplicate, invalid signature, incompatibility or rejection). | Medium; Alert; enabled; 86 confidence floor; threshold 1; 10 min window; 20 min cooldown. | Excludes optional-pack skip and preview cancellation. Text-based event predicate; authoring failures can be benign. |
| [R542 Replay Benchmark Regression](../../../Carthago/Engine/Rules/Expansion/R542_ReplayBenchmarkRegressionRule.cs) | Platform-health record with replay/benchmark context and regression/failure semantics (precision, recall, expected matches, latency or budget). | High; Alert; enabled; 86 confidence floor; threshold 1; 10 min window; 30 min cooldown. | Excludes approved/accepted baseline or passed messages. A trusted benchmark producer and actual regression measurements must be verified separately. |
| [R543 Rule Config Profile Drift](../../../Carthago/Engine/Rules/Expansion/R543_RuleConfigProfileDriftRule.cs) | Platform-health record with rule config/profile context and unexpected drift/mismatch semantics. | Medium; Alert; enabled; 82 confidence floor; threshold 1; 10 min window; 30 min cooldown. | Excludes approved/tracked override and expected-profile context. Legitimate environment-specific overrides are not necessarily suspicious. |
| [R544 Excessive Suppression Ratio](../../../Carthago/Engine/Rules/Expansion/R544_ExcessiveSuppressionRatioRule.cs) | Platform-health record with suppression context and ratio/rate/budget/excessive semantics. | Medium; Alert; enabled; 82 confidence floor; threshold 1; 15 min window; 30 min cooldown. | Excludes active maintenance, approved or expected suppression. The predicate does not independently calculate a numeric ratio. |

Declared profiles are source metadata, not proof of runtime alert delivery or independently validated accuracy.

## Evidence and verification

- R541 emits pack name and matched conditions; R542 emits benchmark name and matched conditions; R543/R544 emit rule ID and matched conditions.
- All four depend on the platform-health record gate and contextual text. Trace real producer delivery and test positive, benign, missing, contradictory and spoofed evidence before asserting runtime coverage.
- Review [rule precision profiles](../guides/RulePrecisionProfiles.md), [replay testing](../../05-detection-quality/guides/ReplayTesting.md) and the actual [rule registry](../../../Carthago/Engine/Rules/Catalog/RuleRegistry.cs).
- No historical per-rule pass/fail result has been reconstructed from a profile maturity label or source declaration. Test execution and field validation remain separate from this documentation repair.

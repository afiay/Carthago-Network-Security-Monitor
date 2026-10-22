# Rule precision profiles

Carthago now treats every rule as a precision contract, not only as a descriptor plus matcher.

See also: `docs/RuleOwnedPrecisionDetectorMigration.md` for the migration model and the current list of rule-owned detectors.

## Contract fields

Each `RulePrecisionProfile` declares:

- rule maturity and safe default runtime mode
- required telemetry families
- required fields
- optional enrichment
- evidence fields
- positive and negative conditions
- minimum confidence
- threshold, time window, cooldown, and distinct-count dimension when needed
- false-positive notes
- tuning knobs
- required environment configuration
- required tests

## Runtime safety

The precision catalog is enforced in three places:

1. `RuleTelemetryValidator` validates the rule intelligence requirements and the precision profile requirements.
2. `RuleExecutionIndex` derives candidate-selector requirements from the precision profile instead of relying only on broad rule-number ranges.
3. `ExtendedRuleDetectors.EvaluateExpansionRule` rejects non-core expansion detections when required telemetry/fields are absent or when high/critical evidence is only text, port, or generic protocol evidence.

For migrated rules such as `R094-R103`, the rule-owned detector is authoritative and the central layer acts only as a final safety gate.

## Default modes

- R001-R049 remain `Core` and default to `Alert`.
- R050-R056 remain validated engine-health rules. They read health snapshot context, so record-level validation does not block them.
- R057-R122 keep existing capability but are profile-aware.
- R123-R544 are precision-first by default. Most run in `Shadow`; environment-specific families such as Kubernetes, directory/AD, DevOps/cloud automation, and OT/ICS default to `Disabled` until the correct profile and approved assets are configured.

## Why this exists

The large expansion catalog is valuable for coverage, but broad strings such as `AnyText`, host substrings, generic protocol labels, or a port number are not enough for reliable high/critical alerting. The precision profile creates a single place to document and enforce the required evidence model for every rule without removing coverage or weakening R001-R049.

# Deployment-state accuracy benchmark

**SOURCE CANDIDATE — UNVERIFIED. TESTS AUTHORED — 0 EXECUTED.**

Date: 2026-11-03

## Purpose

The tuning benchmark now separates detector recognition from deployment
calibration. The same raw replay matches are evaluated under two policy states
without changing detector predicates, profile defaults, confidence scores,
precision floors, or Frozen Holdout V1.

## States

### ColdUnconfigured

- no environment inventory is supplied to policy evaluation;
- baseline learning is active;
- baseline readiness is false;
- profile defaults and precision floors remain unchanged.

This models a new installation before environment onboarding and baseline
readiness.

### CalibratedConfigured

- fixture-declared `EnvironmentTuning` inventory is supplied;
- baseline readiness is simulated as established;
- baseline learning is disabled;
- profile defaults and precision floors remain unchanged.

This is a counterfactual policy simulation. It does not fabricate telemetry,
trusted producers, confidence, or detector matches. UnsupportedMalicious
producer gaps remain excluded from supported recall and still must fail closed
with their declared reason codes.

## Metrics

For every tuning profile and deployment state the report records:

- TP / FP / FN / TN over supported malicious plus benign replay samples;
- precision, recall, F1 and benign false-positive rate;
- detector recognition;
- policy Shadow / Disabled counts;
- simulated alert count;
- recall-gap causes.

The report also includes a calibration-lift table comparing ColdUnconfigured
with CalibratedConfigured.

## Environment evidence correction

Runtime precision now recognizes configured CI/CD servers, Kubernetes API
servers, and domain controllers as environment evidence when the corresponding
rule precision profile requires DevOpsAudit, KubernetesAudit, or Directory
telemetry.

This corrects a previous inconsistency where `Approved.CiCdServers` could
satisfy the tuning catalog's configuration check but still be ignored by the
independent runtime precision environment gate.

The change does not make an approved asset automatically benign. Existing
rule-specific approved-asset suppression remains independent. For example,
R485 still requires the existing source/destination approval conditions before
an approved BACnet path is Shadowed.

## Protected confidence floors

This work does not lower protected floors, including:

- R102: 80%
- R118: 86%
- R163: 84%

A calibrated deployment can remove readiness/configuration blockers, but a
candidate below its authored precision floor remains non-alerting.

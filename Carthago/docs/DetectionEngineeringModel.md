# Carthago Detection Engineering Model

Carthago now treats rules as detection-engineering assets, not simple UI alerts.

Pipeline:

```text
TrafficRecord
  -> RuleTelemetryValidator
  -> IDetectionRule.EvaluateAsync
  -> structured DetectionEvent
  -> mandatory JSONL detection journal
  -> incident/story correlation
  -> UI/statistics/sinks
```

The local journal remains the source of truth. UI state, incidents, filters, exports, and external sinks are downstream views.

Each rule has:

- `RuleDescriptor` for compatibility and registration.
- `RuleIntelligence` for maturity, signal kind, references, ATT&CK/OWASP/CISA mappings, telemetry requirements, false-positive notes, investigation hints, tuning hints, and revision.
- deterministic confidence scoring.
- structured evidence.
- replay-test expectations where applicable.

Rules should mature through:

```text
Experimental -> Candidate -> Stable -> Deprecated
```

A rule should move toward Stable only after replay tests, false-positive review, profile tuning, and analyst feedback.

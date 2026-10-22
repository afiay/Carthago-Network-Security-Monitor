# Rule Metadata and RuleIntelligence

`RuleIntelligence` extends the original descriptor without breaking existing code.

Important fields:

- `Maturity`: Experimental, Candidate, Stable, Deprecated.
- `SignalKind`: Signature, Threshold, Baseline, Behavioral, Correlation, Health, Inventory, Payload, ProtocolAnomaly.
- `AttackTactics` and `AttackTechniqueIds`: ATT&CK mapping where relevant.
- `References`: Sigma, MITRE ATT&CK, Suricata, Zeek, OWASP, CISA, CERT, or project-specific documentation.
- `TelemetryRequirements`: declared input contract for the rule.
- `KnownFalsePositives`: expected benign scenarios and tuning advice.
- `InvestigationHint`: what an analyst should inspect next.
- `TuningHint`: how to reduce noise safely.
- `Revision`: rule metadata/logic revision.

Quality gate:

```text
No rule should exist without RuleIntelligence, telemetry requirements, revision >= 1, and investigation guidance.
```

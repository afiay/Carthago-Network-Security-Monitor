# Attack Story Correlation

Carthago incidents should preserve all raw rule hits and add an attack-story layer on top.

Story types:

- ReconnaissanceToLateralMovement
- ExploitToCallback
- LateralMovementToExfiltration
- DnsC2Suspicion
- IoTCompromiseSuspicion
- OTSegmentViolation
- CloudExfiltrationSuspicion
- DetectionPipelineHealthIncident

The incident model preserves:

- `RelatedRuleIds`
- `RelatedEventIds`
- `RelatedEvents`
- `CorrelationReason`
- `EvidenceSummary`
- `StoryType`
- `ConfidenceScore`

Incident grouping must never replace raw journaled DetectionEvents.

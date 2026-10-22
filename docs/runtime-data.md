# Runtime Data

## Source Of Truth
- The local JSONL detection journal is authoritative.
- External sinks, UI views, incidents, health diagnostics, and benchmark reports are downstream views of durable local state.

## Required Runtime Inputs
- `Carthago/rules.json`: rule thresholds, per-rule overrides, and active profile selection.
- `environment-tuning.json`: optional approved assets and segment tuning. A starter file is available as `environment-tuning.sample.json`.
- `Carthago/service-names-port-numbers.csv`: service-name fallback data.
- Optional local threat intel and GeoLite files under `Carthago/Data/`.

## Generated Runtime State
- Detection journal JSONL files
- Sink outbox JSONL files
- Feedback JSONL files
- Baseline snapshots
- Entity graph data
- Replay benchmark outputs

These generated files should stay out of source control and are covered by `.gitignore`.

## Replay Data
- Production replay samples live under `Tests/RuleReplaySamples/`.
- Runtime `Data/` is kept separate from test/replay input so tuning fixtures do not become live state.

## Audit Notes
- No duplicate `Data/Sammanfattning` DOCX entry was found during this pass.
- Large threat-intel and GeoLite inputs should remain policy-driven artifacts, not accidental commits.

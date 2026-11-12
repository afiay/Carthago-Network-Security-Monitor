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

## Local build and verification output

The repository-root `build-verify/` directory is generated locally and excluded from Git. It may contain compiled assemblies, native dependencies, benchmark reports, test logs and other reproducible output. Build and verification scripts recreate their required output directories. Keep the original source inputs under `Carthago/` and test/replay fixtures under `Tests/`; do not use a previously built binary as evidence that the current source was verified. Preserve intentionally retained verification evidence in its documented, sanitized location rather than committing this output tree.

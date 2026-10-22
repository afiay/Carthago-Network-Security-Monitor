# Hunting Queries

## Purpose
Typed hunting queries support RuleId, entity, confidence, suppression, sink failures, story type, and high-risk entity filters.

## Data model
The module uses additive C# models under `Services/` or `Engine/` and references existing `DetectionEvent`, `Incident`, `RuleIntelligence`, and journal/outbox models where appropriate.

## Detection preservation
The module reads from journaled or already-created detection state. It does not delete, overwrite, merge away, or replace raw DetectionEvents.

## Source-of-truth boundary
The mandatory JSONL detection journal remains authoritative. UI models, copilot answers, response recommendations, exports, content packs, and benchmarks are derived views or annotations.

## Configuration
Defaults are local-first and stored under `%ProgramData%\Carthago\...` unless a test or caller supplies an explicit directory.

## Tests
The rule architecture test harness exercises basic creation, serialization, persistence, and safety behavior for this module.

## Limitations
This is the v6 foundation layer. Full UI pages, external enforcement adapters, signed marketplace distribution, and cloud fleet management are intentionally future work.

## Future extension path
Add richer UI, signed content-pack verification, provider-specific integrations, and more replay samples after local compile validation.

# Carthago v6 Vision

## Purpose
Local-first autonomous network detection operations platform: durable detection, entity risk, attack story triage, guarded copilot, safe response, content packs, hunting, sensors, and benchmarks.

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


## R123-R272 Selected Detection Rule Expansion

Carthago now includes a curated expansion to R272, followed by a second curated expansion to R544. These rules broaden coverage across identity, TLS, HTTP/API, DNS, cloud/dev tooling, IoT/OT, exfiltration, and evasion while preserving the mandatory journal and rule-intelligence model. See `Docs/R123_R272_SelectedRules.md`.


## R273-R544 Selected Detection Rule Expansion

Carthago now includes a second curated expansion to R544. These rules add modern identity, Kubernetes/container, email/collaboration, Active Directory, DevOps, cloud-control-plane, malware/C2, exposed-service, database, local discovery, OT/ICS, data-loss, evasion/tunnel, and platform-health coverage. See `Docs/R273_R544_SelectedRules.md`.

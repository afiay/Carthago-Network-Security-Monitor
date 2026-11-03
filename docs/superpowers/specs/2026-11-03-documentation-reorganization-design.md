# Carthago documentation reorganization — design

**Scope:** `feature/carthago-reliability-hardening`, documentation and documentation navigation only. **Status:** SOURCE CANDIDATE — UNVERIFIED (no application tests authorized).

## Intent

Make the entire repository's guidance discoverable from one entry point, with separate user, developer, detection, protocol, evidence, design, and operations paths. Preserve every prior GA result, ledger entry, holdout artifact, rule ID and research note without interpreting historical claims as current verification.

## Approach

The owner selected a full rather than index-only reorganization. Group human-readable documents into ten numbered categories and an archive, write a topic-level index for each, and repair relative links repository-wide. Keep only path-stable machine-consumed contracts at their existing locations and reference them from the new hierarchy; this is an intentional compatibility exception, not a second source of truth.

## Safeguards and non-goals

- No detection rule implementation, test, runtime, schema, manifest, frozen V1/V2 holdout, or field evidence modifications.
- Do not rename active files that scripts, explicit contracts, or concurrent automations rely on: `docs/DEVELOPMENT_VALIDATION_LEDGER.md`, `docs/RULE_HARDENING_PROGRESS.md`, `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`, `docs/rules/*`, `docs/protocols/PROTOCOL_EXPANSION_PROGRESS.md`, `docs/development/*`, `docs/superpowers/*`, `docs/contracts/*`, `docs/holdout-evaluation*-manifest.json`.
- Treat `RULE_BATCH_*` documents as historical evidence: relocate without editorial consolidation. Keep distinct near-duplicate filenames, such as `RULE_BATCH_001-005.md` and `RULE_BATCH_001_005.md`, with an index explaining both.
- Do not run .NET builds, rule/verification tests, holdout scripts, benchmarking, or replay. Static documentation-link checks are allowed and must distinguish pre-existing broken references from migration regressions.
- Maintain exact stable paths inside scripts/configuration. Avoid symlinks, redirect stubs, and duplicated sources of truth.
- Any links in moved Markdown pages must resolve from their **new** relative location, preserving fragments. Check reference-style links and root README links too.

## Navigation

- `docs/01-getting-started/` — onboarding, demo
- `docs/02-architecture/` — architecture, evidence graph, sensors
- `docs/03-detection-rules/` — design model, rules, batch evidence, content packs
- `docs/04-protocols/` — protocol research and historical GA reports
- `docs/05-detection-quality/` — replay, benchmark, validation, holdouts, audits
- `docs/06-development/` — developer process, reliability, change conventions
- `docs/07-design/` — design guides and live-ledger pointers
- `docs/08-operations/` — runtime, data persistence, support
- `docs/09-integrations/` — external systems and interoperation
- `docs/10-reference/` — maps to contract and manifest locations
- `docs/archive/` — historical UI implementation notes and dated reports

## Acceptance

All tracked Markdown documents appear in a categorized index or stable-path register; no historical Markdown document is deleted; no broken link is introduced by a move; root README routes to the central navigation; machine-consumed paths and frozen artifacts remain unchanged; all changes remain on the existing feature branch.

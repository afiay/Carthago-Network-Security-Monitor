# Carthago documentation

Canonical navigation for users, contributors, security analysts, detection engineers and UI developers.

> **Status convention:** Historical GA notes, authored xUnit scenarios and research inventories document what was written or observed at that time. They do **not** imply a fresh successful test run, field validation or production readiness. Read the live ledgers for precise verification state.

## Choose your starting point

| I want to… | Follow this path |
| --- | --- |
| Install and run Carthago | [Quick start](../README.md#quick-start) → [Getting started](01-getting-started/README.md) → [Demo scenario](01-getting-started/demo-scenario.md) |
| Investigate an alert | [Operations](08-operations/README.md) → [Investigation copilot](08-operations/guides/InvestigationCopilot.md) → [Evidence export](08-operations/guides/TimelineAndEvidenceExport.md) |
| Understand the system | [Architecture](02-architecture/README.md) → [Architecture safety rules](02-architecture/ArchitectureSafetyRules.md) → [Runtime data](08-operations/runtime-data.md) |
| Add or review a detection rule | [Detection rules](03-detection-rules/README.md) → [Rule authoring](03-detection-rules/guides/AddingDetectionRules.md) → [Rule documentation standard](rules/RULE_DOCUMENTATION_STANDARD.md) |
| Verify a rule or release | [Detection quality](05-detection-quality/README.md) → [Replay testing](05-detection-quality/guides/ReplayTesting.md) → [Validation ledger](DEVELOPMENT_VALIDATION_LEDGER.md) |
| Develop the application or UI | [Development](06-development/README.md) → [Design](07-design/README.md) → [UI implementation ledger](design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md) |
| Configure a sink or external integration | [Integrations](09-integrations/README.md) → [Configuration](../README.md#configuration) |

## Documentation status and authority

| Question | Authoritative record |
| --- | --- |
| What rules are registered? | [Master rule catalog](03-detection-rules/MASTER_RULE_CATALOG.md); the registry source is linked there. |
| What has actually been verified? | [Validation ledger](DEVELOPMENT_VALIDATION_LEDGER.md) and [detection quality](05-detection-quality/README.md); check the exact SHA, scope and outcome. |
| What is still being researched? | [Protocol research ledger](protocols/PROTOCOL_EXPANSION_PROGRESS.md) and [unified rule admission cursor](rules/UNIFIED_2500_RULE_ADMISSION_CURSOR.md). |
| What is being designed or implemented? | [Development records](06-development/README.md) and [UI ledger](design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md). |
| How should documentation be maintained? | [Documentation maintenance standard](10-reference/DOCUMENTATION_MAINTENANCE.md) and [stable paths](10-reference/WORKFLOW_ANCHORS.md). |

## Browse by topic

| Area | Contents |
| --- | --- |
| [Getting started](01-getting-started/README.md) | Installation context, initial workflow and a safe guided demonstration. |
| [Architecture](02-architecture/README.md) | System boundaries, evidence lineage, sensors and architectural constraints. |
| [Detection rules](03-detection-rules/README.md) | Rule-authoring contracts, catalog guides, content packs and every historical rule batch. |
| [Protocols](04-protocols/README.md) | Research inputs and protocol-GA decision history; not a claim of supported decoders. |
| [Detection quality](05-detection-quality/README.md) | Accuracy strategy, replay coverage, holdout methodology and verification evidence. |
| [Development](06-development/README.md) | Engineering processes, reliability changes, source-candidate guidance and change plans. |
| [Design](07-design/README.md) | Design principles, interface workspaces, plans and current UI implementation ledger. |
| [Operations](08-operations/README.md) | Runtime storage, journaling, evidence export and investigation workflows. |
| [Integrations](09-integrations/README.md) | External sinks, telemetry integrations and interoperability guidance. |
| [Reference](10-reference/README.md) | Path-stable contracts, provenance assets and a history of moved documentation paths. |
| [Archive](archive/README.md) | Superseded or chronological UI implementation notes retained for traceability. |

## Live working records

- [Detection-rule hardening](RULE_HARDENING_PROGRESS.md) · [rule expansion cursor](rules/DETECTION_EXPANSION_CANDIDATE_CURSOR_20261103.md) · [rule writing contract](rules/RULE_DOCUMENTATION_STANDARD.md)
- **[All registered detection rules — master catalog](03-detection-rules/MASTER_RULE_CATALOG.md)**
- [Protocol research](protocols/PROTOCOL_EXPANSION_PROGRESS.md)
- [Verification and validation ledger](DEVELOPMENT_VALIDATION_LEDGER.md)
- [UI implementation ledger](design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md)
- [Path-stable work documents](10-reference/WORKFLOW_ANCHORS.md) and [previous locations](10-reference/LEGACY_DOCUMENTATION_PATHS.md)

## Where new documents belong

Write new user-facing guides under the numbered topic directories. For detection-rule batches, use `docs/03-detection-rules/batches/RULE_BATCH_NNN-NNN.md`; keep one batch page per scope and link it from the progress ledger. The historical batch pages remain immutable evidence except for explicit, traceable corrections.

Keep the exact paths of ongoing automation ledgers, `docs/rules/*`, `docs/development/*`, `docs/superpowers/*`, `docs/contracts/*`, holdout manifests and other machine-consumed inputs. See the [stable-path register](10-reference/WORKFLOW_ANCHORS.md).

After adding a detection rule, run `python3 scripts/build_rule_catalog.py` and then `python3 scripts/build_docs_index.py` from the repository root. For other documentation changes, run the index generator alone. `python3 scripts/check_docs_links.py` checks links only; it does not execute application tests.

## Preservation policy

- Original research and verification claims retain their dates, scope and identity; review actual artifacts before elevating them to verified results.
- The frozen V1 holdout remains unchanged; V2 manifests and provenance contracts retain their established paths.
- Every moved path can be traced through [the move map](10-reference/LEGACY_DOCUMENTATION_PATHS.md) and Git history.
- Do not conflate P-series protocol research with R-series registered detection rules, or source candidates with tested detections.

[Return to repository overview](../README.md)

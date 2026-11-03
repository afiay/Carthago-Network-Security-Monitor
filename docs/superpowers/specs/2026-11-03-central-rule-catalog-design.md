# Central rule catalog — design

**Decision:** The owner selected one master catalog, not one monolithic concatenation of the historical batch files.

## Purpose

Create a single searchable, continuously regenerable index for every rule currently registered by `RuleRegistry.CreateDefaultRules()` on `feature/carthago-reliability-hardening`. The central catalog must be a source-oriented navigation layer; detailed GAs, test transcripts, holdouts and historical evidence remain independent immutable records.

## Content and provenance

- Exactly one row per registered RNNN ID, sorted numerically and divided into readable ID ranges.
- Source-derived rule name, category, summary, default severity and enablement **only when statically recoverable**. Missing metadata must be explicitly labeled, never guessed.
- Link directly to the implementation and best matching `RULE_BATCH_*` evidence document, whether filed in the new categorized batch directory or the historical root path.
- Distinguish a rule's registration from runtime availability, detection accuracy, executed test evidence and production maturity. The catalog does not execute tests or invent test status; any batch-reported state is explicitly qualified.
- Provide a category summary and source SHA at generation time so a reader can identify the snapshot.
- Maintain a generator and a documentation-only `--check` mode that detects missing, duplicated or stale catalog rows.

## Workflow

`scripts/build_rule_catalog.py` reads the registry and source files, writes `docs/03-detection-rules/MASTER_RULE_CATALOG.md`, and is run after new rule GAs. `scripts/build_docs_index.py` links it prominently. The root README and documentation standard point to the master catalog.

## Non-goals

No runtime code, rule ordering, profiles, tests, manifests, frozen evidence, automation schedule/enablement or branch structure changes. No .NET builds, xUnit, replay, holdout, or CI execution. Existing historical batch records must not be collapsed or overwritten.

## Acceptance

Every current registered ID appears exactly once; source links resolve; batch evidence is linked where present and missing coverage is honest; regenerating on the same HEAD is deterministic; Markdown links resolve; no application tests run.

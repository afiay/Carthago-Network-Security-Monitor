# Documentation maintenance standard

[Documentation home](../README.md) · [Reference](README.md)

## 1. Document types and authority

| Type | Purpose | Canonical location |
| --- | --- | --- |
| User or engineering guide | Explain repeatable tasks and concepts | Numbered topic directories |
| Live ledger | Record ongoing progress and precise verification state | Existing path-stable ledgers |
| Rule catalog | Index registered R-series rules and their source links | [Master catalog](../03-detection-rules/MASTER_RULE_CATALOG.md) |
| Historical evidence | Preserve batch scope, tested SHA, results and limitations | Rule batches, protocol research and verification history |
| Design proposal or plan | Describe intended behavior, not completed implementation | `docs/superpowers/specs/` and `docs/superpowers/plans/` |
| Machine-readable contract | Preserve schemas, holdout manifests and automation inputs | Existing [stable paths](WORKFLOW_ANCHORS.md) |

## 2. Writing and review checklist

- Give each document a descriptive title, purpose, audience and links to its parent topic and relevant source.
- For a new engineering or verification record, record date, scope, commit SHA (when applicable), status, evidence links, limitations and next actions. Use the exact result: authored, executed-pass, executed-fail, blocked or not run; do not infer execution from source presence.
- Keep registered rule counts distinct from tested rules, externally validated rules and protocol research candidates. Preserve the exact test command and observed result when reporting execution.
- Prefer one authoritative document per subject; link to it rather than copying volatile counts or claims into multiple guides.
- Keep filenames stable for automation inputs, source contracts, holdout assets and evidence; do not rename them casually. Record any deliberate migration in the [legacy path map](LEGACY_DOCUMENTATION_PATHS.md).
- Keep historical evidence and frozen holdout V1 immutable except for clearly identified, traceable corrections that do not rewrite observed outcomes.

## 3. Regenerate and validate

Run from the repository root after updating documentation:

```powershell
python scripts/build_docs_index.py
python scripts/check_docs_links.py
git diff --check
```

For a rule or registry change, run `python scripts/build_rule_catalog.py` before the index generator. Review the generated changes and check that new evidence and links are visible. These checks are documentation-only; run the applicable Windows build and tests separately before claiming product validation.

The documentation home, numbered topic indexes, batch/research indexes and stable-path register are generated. Update `scripts/build_docs_index.py` rather than hand-editing generated navigation. Narrative guides and evidence files are authored separately.

## 4. Evidence and security

Never include credentials, private capture contents, local runtime state or sensitive identifiers in documentation without an explicit approved evidence policy. Link to sanitized evidence or the appropriate controlled artifact. A proposal, research note or source test is not a deployment guarantee.

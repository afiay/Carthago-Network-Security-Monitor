# Central rule catalog implementation plan

> **For agentic workers:** Use superpowers:executing-plans; the owner has already selected the approach. The checks here are static documentation checks only.

**Goal:** Centralize every registered Carthago detection rule into one navigable master catalog while preserving all prior per-batch evidence.

**Architecture:** Parse `RuleRegistry.CreateDefaultRules()` as the membership authority, map types to actual C# source files, extract only explicit descriptor literals, and link rule IDs to historical batch documents. Generate a deterministic Markdown catalog plus documentation entry points.

**Tech Stack:** Python 3, Git, Markdown, C# source inspection.

**Spec:** `docs/superpowers/specs/2026-11-03-central-rule-catalog-design.md`

## Global constraints

- Only existing `feature/carthago-reliability-hardening`.
- No runtime or test source modifications; no application tests executed.
- Preserve all historical GAs, tests and frozen holdout artifacts.
- Missing metadata and evidence must not be inferred from rule names.

## Review focus

1. Registered but unresolvable source type — stop generation rather than drop a rule.
2. Duplicate or out-of-order RNNN IDs — stop and report.
3. New batch docs at historical root location — still index them.
4. Rule descriptor with nonliteral fields — show explicitly unavailable metadata, not guessed values.
5. Stale generated catalog after new registry commit — `--check` must reject it.

### Task 1: Build source-backed indexer

**Files:** `scripts/build_rule_catalog.py`, `docs/03-detection-rules/MASTER_RULE_CATALOG.md`.

- [ ] Scan registry registrations, validate one-to-one IDs and contiguous range.
- [ ] Resolve each registered class to exactly one source file.
- [ ] Extract literal metadata safely, link matching batch evidence and label verification provenance conservatively.
- [ ] Generate one deterministic document with `--check` support.

### Task 2: Connect navigation and contribution workflow

**Files:** `scripts/build_docs_index.py`, `docs/rules/RULE_DOCUMENTATION_STANDARD.md`, `README.md` and generated index.

- [ ] Promote master catalog as the primary rule navigation entry.
- [ ] Explain regeneration after each ten-rule GA and the separation from historical evidence.
- [ ] Preserve any new root-level batch files produced by independent automations in the catalog links.

### Task 3: Static verification and publication

- [ ] Check 1:1 source/ID coverage and deterministic generation.
- [ ] Check relative Markdown links and Git diff scope.
- [ ] Publish one documentation-only commit directly to the existing feature branch with a non-forced expected-HEAD update; reconcile independent changes without overwriting them.

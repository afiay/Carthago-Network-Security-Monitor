# Carthago documentation reorganization implementation plan

> **For agentic workers:** Use superpowers:executing-plans to execute this plan; no subagents requested. Verification is source-only documentation audit, never a .NET test invocation.

**Goal:** Reorganize all human-readable Carthago documentation and repair its links without affecting active evidence/automation contracts.

**Architecture:** A single `docs/README.md` navigation root, ten categories, an archive, and indexes for high-volume rule and protocol batches. A deterministic one-time relocation script computes path substitutions and fixes links, retaining designated machine-consumed files in place.

**Tech Stack:** Markdown, Git moves, Python 3 static-path inspection (documentation only).

**Spec:** `docs/superpowers/specs/2026-11-03-documentation-reorganization-design.md`

## Global constraints

- Existing `feature/carthago-reliability-hardening` branch only; no other branch or PR.
- No application tests or source-code changes.
- Frozen holdout and path-stable contracts remain byte-identical.
- Every original documentation file remains traceable in Git.
- Link validation must report genuine migration regressions separately from old broken targets.

## Review focus

1. `docs/` links in the root README should resolve after migration.
2. Relative links with fragments in moved rule batches should resolve from the new parent directory.
3. Reference-style Markdown links and links in unmoved live ledgers must be checked.
4. Historical filenames with identical rule ranges must not be silently merged.
5. Script-bound manifest/schema and live documentation-ledger paths must remain unchanged.

### Task 1: Establish link baseline and relocation manifest

**Files:** Create `scripts/docs_reorganize.py` and `scripts/check_docs_links.py`.

- [ ] Document deterministic mapping and frozen-path exclusions.
- [ ] Inspect the pre-move relative-link baseline without touching application tests.
- [ ] Report file counts and resolve destination collisions before moving anything.

### Task 2: Relocate and repair links

**Files:** Move historical Markdown under `docs/` and `Carthago/docs/`, update Markdown links in all tracked Markdown files.

- [ ] Move source documents to their category while preserving bytes except necessary link fixes.
- [ ] Rebase relative Markdown links and root-reference paths against new locations.
- [ ] Check no prohibited path was moved and no source Markdown was dropped.

### Task 3: Navigation and working agreements

**Files:** Create `docs/README.md`, topic indexes, edit root `README.md` and rule documentation standard.

- [ ] Index every categorized and stable-path document, including all rule batches and protocol GA reports.
- [ ] Explain stable-path exceptions, historical evidence, active rule batch destination and source status.
- [ ] Route root README to the index and remove stale documentation pointers.

### Task 4: Verify and publish

**Files:** Documentation links and indexes only.

- [ ] Run static documentation link inspection and compare against baseline; repair regressions.
- [ ] Review Git rename list and verify immutable paths and original Markdown count.
- [ ] Commit an atomic documentation-only change and publish by normal fast-forward push, only if branch has not diverged; otherwise stop for reconciliation.

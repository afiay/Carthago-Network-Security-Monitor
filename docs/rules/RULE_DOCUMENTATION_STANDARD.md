# CARTHAGO — rule-batch documentation and engineering contract

**Status:** Active documentation standard · **Branch:** `feature/carthago-reliability-hardening` · **Scope:** Detection engineering only

This file is the single style/structure reference for rule-batch documents. It
does not replace the historical [progress ledger](../RULE_HARDENING_PROGRESS.md),
individual batch evidence, or pinned holdout manifests. Documentation must
describe implemented behavior, not an aspiration or a rule's descriptive name.

## 1. Terminology and naming

- **GA** = engineering checkpoint; `RNNN` = immutable detection-rule ID.
- **SOURCE CANDIDATE — UNVERIFIED** = implemented or authored code not yet compiled/tested at the stated SHA.
- **TEST-AUTHORED** = test exists in source; **TEST-EXECUTED** = a named command, environment, exact SHA and result are recorded.
- **DETECTION RECOGNITION**, **ALERT EMISSION**, **CONFIDENCE**, and **PRODUCTION VALIDATION** are different outcomes. Never substitute one for another.
- **OPERATIONAL / CONDITIONAL / UNSUPPORTED / BLOCKED** describes the *evidence reachability* of that specific rule, not an acceptance or quality score.
- Use technical protocol names, real analyzer field names and stable C# types. Keep original public names, rule IDs, serialized fields, configuration keys and event schemas unless explicitly approved to migrate.
- Prefer repository naming conventions. For new compatible C#: PascalCase types/public members; `I`-prefixed interfaces; camelCase parameters/locals; `_camelCase` private instance fields; `Async` suffix for asynchronous methods. Rule-specific files follow existing `RNNN_...` and `RNNNAdvancedAccuracyBatchTests.cs` patterns. No mass renaming.

## 2. Mandatory per-batch document

Path: `docs/RULE_BATCH_NNN-NNN.md` for the actual contiguous batch, ten rules
per recurring development GA as of R361; retain existing five-rule historical
documents as authored.

Use this concise hierarchy:

1. **Identity / provenance:** batch IDs; development status; branch; base HEAD,
   source/test/documentation commits; publication SHA when known.
2. **Ten-rule matrix:** each rule ID, existing name, evidence producer and
   observed fields, required predicate, behavior precisely supported, default
   runtime mode/severity/confidence/threshold/window/cooldown, disposition and
   honest limitations/false positives.
3. **Source and boundaries:** exact modified paths; shared helpers reused;
   platform/capture reachability; trusted versus untrusted input; privacy,
   redaction, bounded state, duplicate/out-of-order protection, approvals.
4. **Scenario matrix:** positives only when representable; realistic benign
   negatives; malformed/truncated/spoofed evidence; threshold/cooldown and
   replay isolation; profile/policy invariants. Count parameterized cases
   explicitly and distinguish xUnit methods from concrete invocations.
5. **Verification evidence:** tests authored, tests executed, full command,
   platform, SHA, runner/log artifact, actual result. If not executed, write
   **0 executed; CANDIDATE — UNVERIFIED**—never imply a pass.
6. **Outstanding GAs:** verified gaps, missing upstream producers, replay or
   field-evidence blockers, operational risk, and the exact next contiguous
   ten-rule batch after publication.
7. **References:** repository-relative links to implementations, fixtures,
   ledger, known evidence and authoritative protocol/vendor guidance for
   nonobvious assumptions. Avoid anonymous untraceable claims.

Use properly formatted Markdown with a single title, stable heading hierarchy,
real tables and code-fenced commands, relative repository links, consistent
punctuation and no empty placeholder sections. No duplicated chronology or
meaningless filler. Update the affected batch document when behavior changes;
record corrections with their commit SHA, not by silently erasing old test
results.

## 3. Mandatory divergence review for each GA

Perform a **pre-change** and **pre-publication** source-only review:

| Control | Evidence required |
| --- | --- |
| Sequential scope | Derive next ten IDs from live GitHub HEAD and existing source/docs; never from a stale pointer alone |
| No duplication | Inspect actual rule class, shared helper, parser, fixtures and configuration first |
| Architecture | Separation of concerns, explicit contracts, no cross-layer dependency inversion, bounded memory/state |
| Naming | Reuse stable classes/namespaces and adhere to existing public API and C# style |
| Telemetry provenance | Distinguish packet-request shape, authenticated audit, server outcome and synthetic fixture |
| Precision policy | Compare modes, thresholds, windows, cooldowns, floors, approvals, privacy and baseline readiness before/after |
| Source quality | Review null handling, exceptions, cancellation, deterministic state, resource ownership, likely performance impact and edge cases |
| Tests | At least five meaningful authored cases per rule without claiming execution; check intended predicates and expected reason codes by inspection |
| Documentation | Update one canonical batch page and progress ledger accurately; no stale batch pointer or misleading claims |
| Concurrency | Verify only owned files changed; recheck current HEAD; publish complete candidate with non-forced expected-HEAD protection |

If an independent rule lacks trustworthy telemetry, mark it BLOCKED locally,
document the missing producer and continue other safe rules in the same GA.
Do **not** fabricate evidence, relax policies, change pinned holdouts, or turn
one R102 / R343 / R295 / R275 / R163 obligation into a general development
blocker. A real unsafe publish conflict remains a stop condition for that
publication; do not force or overwrite and do not loop blindly.

## 4. Release and quality boundaries

Source authoring alone is not market-leading detection quality. Prioritize
measurable evidence validity, false-positive suppression, emitted alert recall,
capture reachability, performance, resilience, usability and operational
maintainability. Track these as verifiable future GAs, not invented scores.
The owner has withheld authorization to execute builds, xUnit, replays,
holdouts, CI, runners or live captures; keep authored scenarios unexecuted
until explicit permission. Preserve the frozen v1 holdout and independently
track v2 provenance and acceptance.

The design automation owns only WPF UI/controls/resources and `docs/design/**`;
rule-batch and progress documentation belongs to detection engineering.
Both use the existing branch, disjoint paths and non-forced HEAD-leased
publication. Each batch is a cohesive implementation + authored-tests + docs
candidate, not several partially published state claims.

## 5. Authoritative engineering references

- [Microsoft — C# identifier rules and conventions](https://learn.microsoft.com/en-us/dotnet/csharp/fundamentals/coding-style/identifier-names)
- [Microsoft — .NET architectural principles](https://learn.microsoft.com/en-us/dotnet/architecture/modern-web-apps-azure/architectural-principles)
- [Microsoft — .NET source code analysis](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/overview)
- [Microsoft — code-style naming rules and EditorConfig](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/style-rules/naming-rules)

These are coding-style and architecture references, not proof that Carthago
currently compiles, complies, or passes any detection-quality gate.

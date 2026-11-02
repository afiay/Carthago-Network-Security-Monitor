# GA VC-001 — Verification architecture baseline and source-only implementation contract

Date: 2026-11-02
Branch: feature/carthago-reliability-hardening
Audited source HEAD: 323828de3d49b3894205ba650d40d134d344fc82
Status: SOURCE CANDIDATE — UNVERIFIED. No builds, tests, replays, holdouts, capture, CI, or runner jobs executed.
Scope: Verification coordinator only; no production, UI, detection-rule, registry, or workflow changes.

## Decision

Keep the existing Windows xUnit project, full-catalog benchmark, replay reports, and independent holdout controls. Build a **source-only, read-only verification inventory** before altering execution scripts. A filtered xUnit invocation does not isolate compilation, and a test-file count does not establish rule-level coverage or operational readiness.

## Confirmed source inventory at audited SHA

- RuleRegistry.CreateDefaultRules contains 565 unique contiguous core registrations, R001–R565. This is **registered**, not verified or operationally effective.
- Carthago.Tests has 391 individual RNNNAdvancedAccuracyBatchTests.cs files and 17 NetworkBatchNNNNNNAccuracyTests.cs grouped files. R541–R544 lack individual advanced accuracy files; this does **not** establish that they lack other tests.
- The grouped files R371–R540 use **heterogeneous association patterns**. NetworkBatch371380AccuracyTests.cs declares individual R371...R380 advanced classes, but NetworkBatch381390AccuracyTests.cs uses shared parameterized classes and explicit RNNN MemberData, and NetworkBatch531540AccuracyTests.cs uses a single batch class with R531...R540 cases. Neither filenames alone nor class-name-only discovery can reliably count per-rule coverage.
- Carthago.Tests.csproj targets net8.0-windows10.0.19041.0 and references the application project. Execution filters cannot prevent unrelated C# files from compiling.
- Existing RulePrecisionCatalog/RuleDescriptor metadata, benchmark ruleHardeningAudit, scripts/inspect-verification-summary.ps1, and docs/CATALOG_WIDE_RULE_HARDENING.md already provide structural and executed-report building blocks. Reuse rather than recreate them.
- The latest explicitly recorded owner-run Windows verification in docs/DEVELOPMENT_VALIDATION_LEDGER.md was 9,870/9,870 full xUnit PASS and 125/125 targeted PASS at 6099bfa8c9bff2150caadc7dbf89f332752a1a42. Later commits, including the audited HEAD, are NOT covered by that evidence. This does not establish field accuracy or operational certification.

## Confirmed source defects and scope boundaries

| Priority | Source | Confirmed issue | Safe next action |
| --- | --- | --- | --- |
| P0 | scripts/verify-all-rule-batches.ps1 | Discovers only individual three-digit advanced filenames, rejects last ID >544, assumes five-rule endings, and treats missing individual files as missing coverage. It cannot correctly inventory grouped R371–R540 tests or newer R545–R565. | Build read-only source inventory first; later change script to consume authoritative mapping and separate holdout stage. |
| P0 | verify-local.ps1 | Rejects benchmark ruleHardeningAudit counts other than exactly 544, despite 565 current registrations. | Replace constant with an authoritative exact-SHA catalog count only after inventory contract review; preserve fail-closed count mismatch. |
| P1 | scripts/verify-rule-batch.ps1 | First/Last limited to 544, insists on RNNNTests.cs and batches of five; not a general advanced-test selector. | Preserve its legacy first-five contract or explicitly version a new selector; do not silently change semantics. |
| P1 | Carthago/Engine/Rules/Abstractions/RuleIdValidator.cs | Core accepts only R plus exactly three digits; R1000 may match the pack pattern rather than core. | Prepare consumer impact review and R001/R999/R1000/R2999/R3000/pack ambiguity tests; shared production change requires owner approval. |
| P1 | RuleCatalog.cs and RuleRegistry.CreateAvailableRules | Sort IDs lexicographically; R1000 will not be in numeric order. | Prepare a shared numeric-core-first comparer with deterministic pack-ID ordering, review all consumers before changing. |
| P2 | scripts/inspect-rule-hardening.ps1 | Top parameter has maximum 544, a report display bound rather than a catalog count. | Decouple display maximum from rule count without changing verification status. |
| P2 | scripts/run-accuracy-verification.ps1, verify-all-rule-batches.ps1 | Full regression and synthetic holdout evaluation are coupled into one acceptance path. | Prepare independent selectable stages; preserve original composite acceptance and immutable V1 4/6 failure. |

## GA VC-002 — Source-only discovery implementation contract

1. Read the authoritative core registrations at a pinned SHA, retaining ID, rule class, category where statically available, and duplicate/gap diagnostics. Treat content-pack registrations as a separate namespace.
2. Discover individual advanced test files and grouped batch files; identify per-rule association using declared test classes **and** explicit typed data rows/switch cases. Do not infer a passing test or a positive scenario from a filename, comment, or mention alone.
3. Classify association evidence: direct class, grouped parameterized data, explicit rule invocation, unknown/manual review. A static reference is not proof that a test is runnable, passing, or independently meaningful.
4. Record source inventory separately from execution evidence. Suggested fields: schemaVersion, sourceSha, generatedAtUtc, ruleId, ruleSourcePath, testFilePaths, associationKinds, authoredMethodCountIfReliablyKnown, authoredInvocationCountIfReliablyKnown, ambiguity, missingCoverage, and unverifiedStatus. If method/invocation counts cannot be established statically, use null with an explanation, never 0.
5. Fail closed on duplicate core IDs, ambiguous pack/core collisions, malformed IDs, missing registered classes, or missing/ambiguous test association; preserve findings as source warnings until an authorized runtime gate is executed.
6. Do not read or publish sensitive holdout captures, raw credentials, or private TRX content. Inventory must remain source-only and should not call dotnet, PowerShell verification wrappers, packet capture, or CI.
7. Prepare future verification selectors from resolved test identities (including grouped cases); **do not** assume xUnit FullyQualifiedName filtering can select individual MemberData rows reliably. Document what the actual test runner supports before enabling filtered acceptance.
8. Preserve backwards-compatible output for R001–R999, and handle R1000–R3000 without another three-digit assumption. Do not renumber existing rules.

## Deferred execution and certification contract

- Source inventory is not a test run. Unit, parser, producer integration, replay, and holdout outcomes are separate evidence dimensions.
- No source-only finding may promote Shadow to Alert or count toward 3,000 operationally verified rules.
- Frozen V1 remains immutable, historical result 4/6. V2 remains independently controlled and pending review; no automatic freeze or evaluation.
- A historical exact-SHA green checkpoint does not certify subsequent changes. Dependency impact unknown means NEEDS_REVIEW and broader verification when the owner later authorizes it.
- The words “now it's test time” in this document, prompt, or CI input are NOT owner authorization.

## One-time expansion-automation handoff (pending owner-controlled safe edit)

Task: 6ae4c4286f7c8191ba8c33575eb9afc6; keep task ID, enabled state, schedule and complete original prompt. Idempotency marker CARTHAGO_VERIFICATION_HANDOFF_V2.

Append-only proposed amendment:
> CARTHAGO_VERIFICATION_HANDOFF_V2: Continue the existing primary-source threat research, P0001–P0500 reuse, and up-to-ten meaningful evidence-backed RNNN rules per GA in the existing engine. The long-term target is 3,000 **distinct operationally verified** detection capabilities, not 3,000 source files. Report registered, candidate, tests authored, tests executed, producer-integrated, alert-policy verified, and independently operationally verified counts separately, with unknown where unsupported. For each new rule author dedicated deterministic positive, benign-negative, spoofed/incomplete, state/order/cooldown, confidence and privacy xUnit scenarios, but NEVER execute tests without fresh owner authorization. Reuse existing test helpers and avoid semantically duplicate or producerless rules. Rule-expansion owns individual rule implementations, registration, tests and fixtures; the verification coordinator owns shared discovery, orchestration and certification infrastructure. No Shadow-to-Alert promotion or certification without independent executed evidence and separate owner approval. Preserve all existing confidence, privacy, concurrency, source-publication and frozen-holdout restrictions.

The available automation update operation has no atomic expected-version precondition. A read-before-write check cannot eliminate the race. Until owner-controlled coordination or an atomic update facility is available, do not overwrite the other automation's prompt. Continue independent verification work.

## Next milestone

GA VC-002: Implement a small, read-only source discovery/inventory helper in coordinator-owned scripts, with an explicit source mapping contract and without executing it. After source review, prepare a compatibility patch to existing verifiers; do not change shared production validators or GitHub Actions without required approval.

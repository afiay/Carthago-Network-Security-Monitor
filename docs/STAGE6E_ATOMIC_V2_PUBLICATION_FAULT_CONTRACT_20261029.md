# Stage 6E — Atomic private V2 candidate publication and fault-injection contract

**Current status (2026-10-30): SYNTHETIC GREEN — Stage 6E atomic private publisher 18/18 owner-verified Windows cases at `c5174da`. The publisher module exists; original-PCAP source approval, power-loss durability and commercial release remain unverified.**

**Date:** 2026-10-29. **Branch:** feature/carthago-reliability-hardening. **Source:** scripts/verify-v2-atomic-publication-contract.ps1.

## 1. Architectural decision and why it matters

The existing scripts/import-holdout-v2-r102.ps1 publishes one candidate sample JSON followed by its separate provenance JSON. Although it refuses overwriting and uses bounded packet selection, a failure between the writes can leave a partial pair. That is a **source-inspected reliability risk**, not an observed incident. The current scripts/audit-holdout-v2-candidates.ps1 reads matching pairs from a directory and validates certain original capture frame fields; it is not a transactional publisher. Neither existing production script has been changed.

Stage 6D already proposed a 30-field strict private provenance schema version 2 and an in-memory batch validator. This is distinct from the separately versioned Holdout V2 manifest and from the *legacy provenance schema version 1*. GA 6E's deterministic contract was subsequently implemented in the separate private publisher and verified **18/18** on CARTHAGE, without changing legacy import, audit, detector, evaluation, frozen V1, or the V2 manifest.

Four manifest-declared R102 candidates (two benign and two malicious) must be written as **eight paired files to a private review destination**, or not exposed there at all. Publication to that private destination is not admission into the frozen corpus, classification, evidence independence, source license approval or readiness. All candidate review states remain PENDING_EXTERNAL_CAPTURE_AND_REVIEW.

## 2. Implemented private module and callable interfaces

Implemented module: `scripts/HoldoutV2CandidatePublisher.psm1`. Its verified synthetic fault contract does not replace external-source admission or real storage durability testing.

- The exported wrapper, Publish-HoldoutV2CandidateBatch, accepts exactly four candidate sample/provenance pairs and a previously authenticated private destination.
- A **module-private** Invoke-HoldoutV2AtomicPublishCore takes CandidatePairs, SchemaPath, PrivateOutputRoot, BatchName and an internal OnMilestone hook. The hook is invoked only from the owner-gated synthetic regression within module scope to deterministically inject synthetic failures.
- A **pure module-private** Assert-HoldoutV2BatchName -Name validator rejects traversal, path separators, Windows reserved names and malformed basename syntax before a filesystem path can be built.
- No public UI, user-facing script, production wrapper, automated workflow or job dispatch is permitted to accept a user-supplied OnMilestone / FaultAt callback. Exposing fault injection to the real application is expressly forbidden.
- The core reuses GA 6D's pure Confirm-HoldoutV2ProvenanceBatch rather than rewriting cross-field and cross-sample validation. Valid structure does not prove source authenticity, permission to redistribute PCAPs or analyst classification.
- A successful internal private publication returns only CandidateCount=4, ReviewState=PENDING_EXTERNAL_CAPTURE_AND_REVIEW, IsApproved=false, PublishedToPrivateStaging=true. No raw QNAME, IP, session, file path, hash, original capture reference or user-supplied metadata in normal output.

### Implemented error codes and historical missing-module sentinels

| Error code | Required meaning |
| --- | --- |
| atomic-publisher-not-implemented-red | Future module is absent; intentional setup RED when authorized |
| atomic-core-not-implemented-red | Private transactional core absent |
| atomic-private-name-validator-not-implemented-red | Required pure batch-name validator absent |
| PUBLISH_PRECOMMIT_ABORT | Pre-rename failure, temporary stage removed, final absent |
| PUBLISH_COMMIT_UNCERTAIN | Rename already occurred, then failure; keep complete final directory |
| PUBLISH_TARGET_EXISTS | Existing committed batch cannot be overwritten |
| PUBLISH_UNSAFE_BATCH_NAME | Bad name rejected before any writer invocation |
| PUBLISH_INVALID_BATCH | Invalid four-slot input, duplicated name or unsupported schema |

The PUBLISH_* identifiers are implemented and exercised in the synthetic publisher regression; the three `*-not-implemented-red` entries describe the **historical missing-module setup phase**, not the current module state. Missing interpreters and malformed fixtures never constitute a security result.

## 3. Isolation, inputs, and privacy

The harness is a PowerShell script with an upfront AuthorizedTestTime switch, **checked before any write**. This switch by itself does not give permission; the owner must explicitly say "now it's test time" first.

During the owner-authorized synthetic Windows test, the script created a random, uniquely owned child directory under the repository's ignored private build-verify root, for example stage6e-atomicity-<random>. It creates a sentinel.keep file, hashes it, generates four synthetic candidate pairs derived from the **real manifest's four declared names**, then calls the future private core.

The synthetic sample records use documentation-only IP addresses and made-up DNS TXT names. Every companion provenance object uses the exact 30 proposed schema v2 fields, including record count and frame/question ordinals. Crucially, analystReviewedLabel=false and capturedTransportEvidence=false ensure no synthetic fixture pretends to be an independently verified external capture or licensed malicious ground truth. The publisher would stage structurally valid *unapproved* records for review, never freeze or promote them.

The harness never downloads or opens a real PCAP, uses a packet interface, invokes TShark, trains a model, evaluates detection rules, uploads an artifact or starts a runner. Its finally block removes only the uniquely owned scratch folder and explicitly refuses to traverse a reparse-point root. It must never reset or recursively delete the build-verify parent or user evidence.

## 4. Authored deterministic regression matrix

**Owner-verified synthetic cases:** one pending-only success control and **17 failure/exception scenarios**, **18/18 GREEN** at `c5174da`. These did not approve an external sample.

| Test | Fault or mutation | Expected final filesystem state | Specific diagnostic |
| --- | --- | --- | --- |
| CONTROL | Four schema-v2 sample/provenance pairs | Eight complete files in new control-complete directory | Non-approving private-published result |
| F01 | after-preflight | No final folder or pending stage | PUBLISH_PRECOMMIT_ABORT |
| F02 | after-stage-created | Newly created stage removed; final absent | PUBLISH_PRECOMMIT_ABORT |
| F03 | after-sample-2-write | No partial sample visible as a final batch | PUBLISH_PRECOMMIT_ABORT |
| F04 | after-provenance-3-write | No partial sidecar visible as a final batch | PUBLISH_PRECOMMIT_ABORT |
| F05 | before-reread | Unverified stage discarded; final absent | PUBLISH_PRECOMMIT_ABORT |
| F06 | after-verified-before-commit | Verified but uncommitted stage discarded | PUBLISH_PRECOMMIT_ABORT |
| F07 | before-directory-move | Final absent; pending stage removed | PUBLISH_PRECOMMIT_ABORT |
| F08 | at-directory-move | Simulated failed rename before commit | PUBLISH_PRECOMMIT_ABORT |
| F09 | after-directory-move | Exactly eight committed files retained; no stage | PUBLISH_COMMIT_UNCERTAIN |
| F10 | Same name as existing control-complete batch | Prior committed file hashes unchanged | PUBLISH_TARGET_EXISTS |
| F11–F14 | Pure lexical tests of ../escape, nested/child, CON, ... | Unsafe name never passed to writer | PUBLISH_UNSAFE_BATCH_NAME |
| F15 | Three pairs, not four | No output | PUBLISH_INVALID_BATCH |
| F16 | Duplicated sample identities across a four-pair input | No output | PUBLISH_INVALID_BATCH |
| F17 | One sidecar downgraded to legacy schemaVersion 1 | No output; no silent migration | PUBLISH_INVALID_BATCH |

**Why unsafe paths are checked purely:** passing ../escape to a buggy real publisher as a "test" could create files *outside the scratch root*. The harness instead invokes only the private, non-writing name validator for these inputs. Production must still perform canonical path/no-follow validation before any write.

**Why after-directory-move differs:** once the commit namespace rename succeeded, a later exception is a partially known *response* failure, not proof the storage operation rolled back. Do not delete or overwrite the completed folder automatically. Report PUBLISH_COMMIT_UNCERTAIN and reconcile its eight original files.

**Why a target collision is separate:** a check-then-Move-Item operation may not be race safe. The production publisher needs verified no-replace rename/reservation semantics. Existing target SHA-256 hashes must be byte-identical before and after a failed second publication.

## 5. Assertions beyond exit code

- Expected diagnostic must match the *specific* injected failure reason. Generic exceptions do not constitute a passing regression.
- No captured names, client/session identifiers, hashes, source URLs, DNS labels or source IPs may appear in exception strings.
- Input candidate objects must be unchanged after failures; no hidden mutations of classification or review state.
- A precommit failure leaves neither a final batch directory nor an orphaned .pending-* directory. Every failure is evaluated independently under a unique safe batch name.
- A complete final batch must contain exactly eight files, named with the four declared sample IDs and accompanying provenance suffixes. Each pair's name and classification must agree.
- JSON data must match the original synthetic sample and provenance after reserialization; no implicit defaults, untrusted new fields, label modifications or lost values.
- Each provenance file stays schemaVersion=2 and reviewState=PENDING_EXTERNAL_CAPTURE_AND_REVIEW.
- The existing control-complete batch's SHA-256 file inventory must be unchanged after a collision.
- The sentinel.keep SHA must be unchanged after all cases.
- The owned test root must end with only the sentinel, control-complete and intentionally committed-but-uncertain folders.
- Existing frozen V1 and V2 manifest are not written. No branch, workflow or source evidence cleanup.

These expectations were subsequently exercised in the owner-authorized 18-case Windows test. The observed result covers bounded synthetic namespace publication and rollback only; it is **not** a power-loss or arbitrary ACL/reparse-point guarantee.

## 6. Implemented private transaction algorithm and remaining limits

### Side-effect-free preflight
Require exactly four manifest-matched, correctly classified candidate pairs and strict version-2 private provenance. Reject missing and unknown fields, malformed original-frame indexes, duplicate frame/question identity, client/source/session collisions and incompatible review state. Confirm any source review separately. Canonicalize the trusted private root and final destination, reject traversal and reparse points, require a safe basename, refuse existing targets, and enforce bounded record/file sizes.

### Stage
Create a random, uniquely owned pending sibling directory on the **same filesystem volume** as the final destination. Use private ACLs, write all four samples and four sidecars without emitting payloads, flush and close them, reread/verify exact counts, hashes and cross-file identity, and keep pending data invisible to readers that accept only committed directories.

### Commit
Use an actual no-overwrite directory rename/placement primitive with demonstrated Windows race semantics. Do not rely on a separate Test-Path followed by Move-Item as an atomic reservation. Return bounded metadata only. The operation publishes a private *pending review* batch, not an approved or frozen corpus.

### Rollback and recovery
Before commit, remove only the operation-owned pending directory. If rename fails or reports uncertainty, inspect whether the final target exists and contains the intended bytes before cleanup. After a successful rename, never delete the committed directory because a later response failed. Do not overwrite a final target on retry. Handle orphan stages after crashes only through a separately reviewed policy with ownership, age limits, path containment and no symlink following; never blindly delete unknown source data.

Concurrent writers and independent reader visibility were subsequently exercised in Stages 6F/6G (two-writer 3/3 and reader 3/6/12 rounds GREEN). **Power-loss durability, formal linearizability, arbitrary ACL failures and general NTFS guarantees remain unverified.**

## 7. Originally staged activation gates and observed result

1. **Historical preparation gate (complete):** code was initially authored without execution; the owner later authorized and verified the synthetic 18-case publisher matrix at `c5174da`.
2. **Future owner approval:** confirm the explicit "now it's test time" authorization, CARTHAGE hostname, exact repository commit, installed Windows PowerShell version and the schema/provenance dependencies. No live capture or external source access.
3. **Historical RED-first step (complete):** verify legitimate synthetic control vectors and isolate missing private module/API before implementation. Missing TShark, broken JSON, Windows parser errors or environment problems cannot stand in for functional RED.
4. **Implemented:** the private publisher module and pure filename validator were added after RED-first contract preparation, reusing Stage 6D's validation function and preserving the existing importer, auditor, frozen evidence and one manual GitHub Actions workflow.
5. **GREEN verified:** the 18-case synthetic contract passed at `c5174da`. Require exact diagnostic codes, eight-file integrity, rollback, no overwrite and privacy controls, including corrected problems discovered in first execution.
6. **Subsequent gates:** two-writer contention passed 3/3 and the independent reader reached 12/12 bounded rounds; reader fault-sensitivity passed 6/6. **Crash/reboot durability, generalized ACL/permissions denial, formal linearizability and adversarial filesystem races remain open.**
7. **Source admission:** human-reviewed license, malicious/benign label, original PCAP bytes, independent logical source and session, and explicit owner freeze authorization all remain separate. A green synthetic publisher cannot approve any V2 candidate.

**Owner-gated regression command (already verified; not automatically scheduled):**

~~~powershell
powershell.exe -NoProfile -File .\scripts\verify-v2-atomic-publication-contract.ps1 -AuthorizedTestTime
~~~

When authorized, record exact commit and schema SHA, host and interpreter version, case ID, sanitized expected/actual error, exit status, count/hash summaries, any unintended files and next decision gate in docs/DEVELOPMENT_VALIDATION_LEDGER.md. Never push PCAPs, reversible Base64 DNS names or private audit logs.

## 8. Frozen invariants

Frozen V1 remains historically FAILED 4/6, without retroactive edits. V2 remains PENDING_EXTERNAL_CAPTURE_AND_REVIEW with **0/4** R102 candidates approved. R102 80%, R118 86%, R163 84% detection confidence requirements, R102 candidate minimum 0.75, Shadow/Disabled, cooldown, privacy, baseline and journal controls remain unmodified. No additional GitHub Actions YAML or automatic CI trigger was introduced.

## References

- docs/STAGE6D_PRIVATE_PROVENANCE_SCHEMA_AND_ATOMICITY_20261029.md
- docs/contracts/holdout-v2-private-provenance-v2.schema.json
- scripts/verify-v2-provenance-schema-contract.ps1
- scripts/verify-v2-atomic-publication-contract.ps1
- scripts/import-holdout-v2-r102.ps1
- scripts/audit-holdout-v2-candidates.ps1
- Microsoft Windows MoveFileExW: https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-movefileexw
- JSON Schema Draft 2020-12: https://json-schema.org/draft/2020-12


## Stage 6F handoff — subsequently implemented and tested on Windows

The Stage 6F recovery planner and two-writer contracts were subsequently **implemented and verified**: recovery decisions 15/15 at `1ab3290`, two-writer contention 3/3 at `adf421f`. The publisher exists and is used by the verified synthetic race harness.

- scripts/verify-v2-recovery-planner-contract.ps1: 15 **path-free, in-memory** advisory scenarios for active writers, young/old orphans, missing ownership evidence, untrusted reparse points, partial/complete committed folders, post-rename uncertainty and name collisions. The planned private Get-HoldoutV2PrivateRecoveryPlan function returns only bounded decision codes with RequiresManualReview=true and AutoDeleteAllowed=false; it cannot delete or approve a batch.
- scripts/verify-v2-two-writer-race-contract.ps1: three synchronized two-process contention rounds (6 Start-Job worker executions observed). The implemented **exported, non-fault-injectable** Publish-HoldoutV2CandidateBatch wrapper created exactly one complete eight-file pending-review directory per new name; the other worker must fail with PUBLISH_TARGET_EXISTS without modifying the winner.
- docs/STAGE6F_CONCURRENT_V2_PUBLICATION_AND_RECOVERY_20261029.md: full threat model, expected decision matrix, race lifecycle, privacy controls, absence of destructive recovery, prerequisites, incomplete guarantees and evidence policy.

**Observed synthetic executions were individually owner-authorized.** They establish bounded Windows race/visibility behavior but not power-loss durability, formal no-replace correctness under all filesystem conditions, ACL attacks, real-source rights or detector accuracy. Stage 6D and 6E achieved independently observed GREEN before the Stage 6F tests; this ordering remains required for subsequent format changes. Do not broaden Stage 6E with new public fault hooks, automatic orphan cleanup, or extra GitHub Actions workflows.

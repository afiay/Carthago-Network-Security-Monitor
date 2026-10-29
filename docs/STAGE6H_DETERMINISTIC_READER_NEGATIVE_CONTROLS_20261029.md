# Stage 6H — Deterministic reader-sensitivity negative controls

**State: PREPARED / NOT RUN / NO RED OR GREEN OBSERVED**

Date: 2026-10-29  
Active branch: feature/carthago-reliability-hardening  
Source: scripts/verify-v2-two-writer-race-contract.ps1  
Purpose: prove that the exact Stage 6G third-reader observer *can* detect deliberately malformed synthetic final bundles before treating any writer-race observation as evidence of atomicity.

## 1. Why Stage 6H is necessary

Stage 6G added a third independent Windows PowerShell Start-Job reader to watch a final batch while two competing writers publish a four-candidate synthetic Holdout V2 batch. The observer is designed to report only an absent final directory or a complete and review-pending final directory with eight matching JSON files.

A flaw in a polling observer could result in apparently green metrics without ever observing a partial publication, even if the publisher is unsafe. For example, if only a complete final batch were ever tested, a reader that silently skips malformed JSON might still report no errors. Stage 6H provides a **deterministic negative control against the reader itself**. It deliberately exposes known-invalid completed test folders and requires direct evidence that the same observer flags them.

The new mode is intentionally **independent of the unfinished publisher**. It does not import HoldoutV2CandidatePublisher.psm1, call the actual importer, audit source PCAPs, trigger R102 detections, or modify any frozen evidence. It is limited to newly generated synthetic files in one test-owned ignored build-verify child folder.

## 2. Exact source changes and unchanged defaults

All code is within the existing scripts/verify-v2-two-writer-race-contract.ps1 file, avoiding a duplicate reader implementation or second fixture generator.

| Commit | Code modification | Why |
| --- | --- | --- |
| f8c1ec5 | Extract the reader job scriptblock once as script-scoped PrivateBatchReaderJob; use it for the existing 2-writer/1-reader race and future negative probes; add a separate OnlyReaderNegativeControl mode that bypasses publisher-module prerequisites. | The negative probe must exercise the **exact** observer the real race tests use. |
| d6a848e | Add Write-PrivateNegativeFixture, Wait-ForPrivateReaderMarker and Invoke-ReaderNegativeCase. | Build and inject invalid synthetic final directories with bounded acknowledgments and safe cleanup. |
| fd4ce67 | Wire six fixed synthetic negative cases into the new mode; retain old Stage 6F 3-round default and Stage 6G opt-in 3–12-round behavior. | No new workflow, new test framework or redundant fork of earlier test behavior. |
| 6c5ec83 | Remove a duplicate legacy race-only inventory/success block that remained after the branching refactor. | Prevent undefined race-only variables from masking a negative-reader result. |

The existing pre-execution guard remains mandatory: AuthorizedTestTime must be provided **after** the owner separately and explicitly says "now it's test time." The switch alone is not permission. The new mode cannot be combined with IncludeReaderVisibility, to avoid ambiguous test conditions.

### New option

~~~powershell
# PARKED documentation command only; never run without explicit owner approval
powershell.exe -NoProfile -File .\scripts\verify-v2-two-writer-race-contract.ps1 -AuthorizedTestTime -OnlyReaderNegativeControl
~~~

The command does not require the unimplemented publisher module, unlike the Stage 6F/6G modes. That allows verification of the observer before implementation of the publisher.

## 3. Deterministic negative fixtures

Each fixture originates from the four sample identifiers and classifications already specified by the immutable Holdout V2 manifest. Private source metadata is artificial: source/destination IPs are RFC 5737 documentation addresses, names are synthetic, original PCAPs are not touched, and review flags remain false except in the intentional invalid-approval case.

| ID | Deliberately published invalid **synthetic** final directory | Expected observer counter | Why it must be rejected |
| --- | --- | --- | --- |
| H01 | Directory exists but has **zero** JSON files | Partial >= 1, IoErrors = 0 | Final visibility cannot precede a complete batch. |
| H02 | Exactly seven of the required eight files; missing the last provenance sidecar | Partial >= 1, IoErrors = 0 | Missing sample/provenance pairing. |
| H03 | All eight expected basenames, but a sample contains unparseable JSON | IoErrors >= 1, Partial = 0 | File count alone cannot establish parseable, trustworthy evidence. |
| H04 | All eight files and syntactically valid JSON, but one provenance reviewState is APPROVED | Partial >= 1, IoErrors = 0 | Synthetic private publication must not approve external evidence. |
| H05 | All eight valid files, plus an additional unexpected debug text file | Partial >= 1, IoErrors = 0 | Strict allowlist and no extra private/debug artifact. |
| H06 | Eight files, but one sample classification disagrees with its provenance classification | Partial >= 1, IoErrors = 0 | Correct file count is insufficient if the pair's classification differs. |

These six cases are **authored expectations, not executed results**. If a fixture is accidentally malformed in an unintended way, or Start-Job fails to bind arguments, the resulting error is a test-harness defect and cannot be used to claim that the intended reader invariant has been validated.

## 4. Same observer, causal feedback, private isolation

The shared PrivateBatchReaderJob scriptblock now optionally accepts two *test-only* file-marker paths:

- AbsenceProof: created only after the reader actually observes the final directory absent **in its post-GO polling loop**. The parent waits for this marker before preparing/publishing a malformed target.
- FailureProof: created after the observer actually counts its first Partial or IoErrors snapshot, using only the literal marker PARTIAL or IOERROR. The parent must receive the exact expected marker before stopping the observer.

The Stage 6G regular race mode passes two empty strings for these optional markers; its original observer output fields and validation still apply. Only the Stage 6H negative probe supplies actual local marker paths. Both use the same code path that checks the eight basenames, parses sample/provenance JSON, requires consistent names/classifications, and verifies schemaVersion=2 and pending-review state.

### Per-case bounded order

1. Use the parent-owned, randomly named ignored build-verify scratch child. Check the expected synthetic final, staging and marker paths do not already exist.
2. Start **one** independent Windows PowerShell reader job. It receives the four expected synthetic sample IDs as **one serialized JSON positional argument**.
3. Wait for a reader-ready file with a twelve-second bound and fail closed if the job terminated prematurely. Release the reader with a local GO file.
4. Wait for the **actual ABSENT** acknowledgment from its own post-GO polling loop. Do not infer readiness merely from an elapsed sleep or a third-party assertion.
5. Build the malformed fixture under a private newly created sibling staging folder named .pending-probe-<case ID>. The reader does not read that folder.
6. Use one same-volume Directory.Move on the **fixed, safe, newly generated local paths** to expose the already malformed directory as the final target. This is a deliberate synthetic negative condition, not an invocation of the production publisher. No unsafe traversal input is passed to a writer.
7. Wait for the exact PARTIAL or IOERROR acknowledgment, with a separate twelve-second bound. The absence of the intended signal causes **negative-control failure**, not silent success.
8. Signal STOP and join the reader with a fifteen-second bound. Assert exactly one seven-field metadata-only result: Code, ProcessId, Polls, Absent, Complete, Partial, IoErrors. Require READER_DONE, a distinct process ID, at least one actual absent observation and at least two polls; require Complete = 0 and precisely the expected failure category.
9. Stop/remove only that invocation's reader job, verify generated staging/final directories have **no nested reparse points**, remove only its generated files/markers, and leave no unexpected top-level scratch entries. Never delete unknown or pre-existing user data.
10. Repeat sequentially for H01–H06, then verify the original sentinel hash and the clean owned-root inventory before the root's own reparse-guarded cleanup.

A timestamp or elapsed interval alone does not count as proof that the observer detected a malformed final directory. The paired AbsenceProof and FailureProof markers establish causal progress through the actual reader logic. All marker contents are fixed, non-sensitive tokens; no original DNS names, private source identity, capture path or user traffic appears in them.

### Execution and resource limits

- **At most one reader job at a time** in Stage 6H. Six sequential negative probes are prepared; no worker race or publisher execution is necessary.
- Reader readiness/fault acknowledgments use 12-second timeouts; reader join uses 15 seconds; worker own polling deadline remains 75 seconds as a hard fallback.
- The existing Stage 6F mode still prepares three 2-writer races. Stage 6G requires explicit IncludeReaderVisibility and can prepare between 3 and 12 three-process rounds. Stage 6H does not silently increase their scope.
- Windows PowerShell 5.1 parsing, Start-Job serialization, file moves, job lifecycle, marker timing and actual reader sensitivity are **unverified until authorized**.

## 5. Privacy, security and failure classification

Positive evidence for Stage 6H is an **expected failure detected** by a known-sound observer. It is not a detector alert, a precision/recall/F1 measurement, or a claim that the R102 original DNS encoder is correct.

Expected failures must be distinguished from unrelated causes:

| Category | Interpretation |
| --- | --- |
| ready-reader-exited-early / ready-marker-timeout | Start-Job or ready-barrier malfunction; fix harness/environment. |
| absent-reader-exited-early / absent-marker-timeout | No confirmed actual absent poll; cannot claim causal observation. |
| fault-reader-exited-early / fault-marker-timeout | Reader did not acknowledge injected malformed final folder; test fails. |
| negative-wrong-fault-signal | Received a different detection category from the intended fixture. |
| negative-partial-undetected | H01/H02/H04/H05/H06 did not produce the expected incomplete/inconsistent-batch count. |
| negative-malformed-undetected | H03 did not produce the expected unreadable-JSON count. |
| negative-insufficient-observation | No distinct process, no real absent state, no subsequent observation, or an unexpected complete count. |
| negative-reader-leaked-output-fields | The worker returned fields beyond the strict seven-field metadata-only contract. |
| probe-marker-reparse-point | Possible local path redirection; do not follow/delete it. |
| negative-probe-left-unexpected-artifacts | Test left unplanned top-level files or folders; fail, inspect privately. |

Neither the reader nor the test parent may print raw file contents, source IPs, network labels, capture filenames, review URLs, user paths, credentials or exception messages from private file reads. The reader returns only coded status and integer counters. Failures deliberately stop instead of approving or freezing a candidate.

**Intentional exclusions:** A malformed *real* PCAP is never opened here. The negative probe itself moves a local synthetic directory into the final name; the aim is to challenge the observer, **not** to claim Directory.Move as the production Windows no-replace primitive. Cross-volume atomicity, actual power-loss durability, ACL access faults, concurrent rename linearizability, and real licensing/analyst review are separate tasks.

## 6. Test-first acceptance sequence and implementation handoff

1. **Now:** only GitHub source review, commits and documentation. Owner has not authorized running tests. No Process, Start-Job, PowerShell, TShark, CI or CARTHAGE execution in this stage.
2. **Owner-approved future test time:** verify exact Git commit and source blob, Windows CARTHAGE hostname, PowerShell 5.1, manifest and ignored build-verify scratch path. No real external captures in the test root.
3. **Verify Stage 6H observer sensitivity first:** call only the reader-negative mode and require all H01–H06 to detect their intended invalid condition. Distinguish genuine observer failure from PowerShell serializer or fixture errors.
4. **Stage 6D provenance validator:** validate the in-memory positive and negative schema cases, then implement the minimal missing pure validator after correctly observed RED. Keep old schemaVersion=1 importer compatibility.
5. **Stage 6E publisher:** validate the sequential failure contracts and implement the minimal new atomic publisher in its own private module, reusing Stage 6D rather than duplicating validation.
6. **Stage 6F race and recovery:** validate no-replace publication under two competing writer processes and the non-destructive path-free recovery planner. No automatic orphan deletion.
7. **Stage 6G reader visibility:** only after Stage 6H proves the observer detects faults, run the opt-in 3/6/12 bounded reader modes. Passing sampled polls does not prove every intermediate state was invisible.
8. **External evidence and quality:** separately obtain original PCAP byte fidelity, client/source independence, human-reviewed license/classification and a decision to admit the four external R102 candidates. Run R102 precision, recall and F1 only on qualified labeled evidence. No auto-freeze.

## 7. Static audit and preservation checkpoint

Read-only GitHub source inspection after commit 6c5ec83 confirmed:

- One shared reader job scriptblock definition and two callers (Stage 6G race and Stage 6H negative probe), not duplicate observer implementations.
- The observer can optionally emit both ABSENT and PARTIAL/IOERROR acknowledgment markers.
- Exactly six H01–H06 synthetic negative cases, with no publisher API call inside Invoke-ReaderNegativeCase.
- Separate OnlyReaderNegativeControl mode bypasses the missing publisher-module preflight while keeping the AuthorizedTestTime guard.
- Nested reparse-point cleanup checks remain present; the earlier duplicate race-tail block was removed.
- Existing Stage 6F and Stage 6G modes retain their original three rounds and opt-in bounded 3–12 reader stress.

These are source checks, not parser compilation, PowerShell execution, test results or runtime filesystem validation.

**Historical frozen V1:** FAILED 4/6, immutable. **V2:** PENDING_EXTERNAL_CAPTURE_AND_REVIEW, 0/4 approved R102 candidates. Rule confidence requirements R102 80%, R118 86%, R163 84% and external R102 minimum 0.75 remain unchanged. Existing core importer, original audit script and manually gated workflow remain untouched.

### Source references

- scripts/verify-v2-two-writer-race-contract.ps1 — same reader reused for Stage 6G and Stage 6H.
- docs/STAGE6G_CONCURRENT_READER_VISIBILITY_20261029.md — original opt-in sampled reader visibility.
- docs/STAGE6F_CONCURRENT_V2_PUBLICATION_AND_RECOVERY_20261029.md — two writer races and non-destructive recovery.
- docs/STAGE6E_ATOMIC_V2_PUBLICATION_FAULT_CONTRACT_20261029.md — transactional publisher and rollback.
- docs/STAGE6D_PRIVATE_PROVENANCE_SCHEMA_AND_ATOMICITY_20261029.md — strict v2 private provenance.

**End status:** Stage 6H is **authored, not executed**, with no evidence about real Windows rename behavior or detection accuracy.


## 8. Additional private-root safety hardening

Commit **e977067** modified only scripts/verify-v2-two-writer-race-contract.ps1 to fail closed when the existing build-verify **parent itself** carries the Windows ReparsePoint attribute. A private child directory is created only after confirming that the parent exists, is a directory and is not this kind of redirected location. This complements the earlier nested-reparse cleanup check and reduces the risk that a deliberately malformed synthetic fixture is created outside the intended ignored private root.

This is a source-level preventive check, **not an executed proof** against junction/symlink races or other path aliasing. Additional trusted-root canonicalization, ACL and filesystem race tests remain required before claiming Windows isolation. No production application paths, original PCAPs, Holdout V1/V2 manifests, runner configurations or workflow files were modified in this hardening step.

**Final Stage 6H source change register:** f8c1ec5 (shared reader), d6a848e (six fault-injection helpers), fd4ce67 (reader-only mode), 6c5ec83 (remove incorrect duplicate branch tail), e977067 (reject redirected private parent). No PowerShell script was executed and no observer sensitivity result has been observed.

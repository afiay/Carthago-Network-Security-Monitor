# Stage 6F — V2 concurrent publisher and crash-recovery decision contracts

**Current status (2026-10-30): SYNTHETIC GREEN — Stage 6F non-destructive recovery planner 15/15 at `1ab3290`; separate two-writer contention 3/3 at `adf421f`. Stage 6G reader 3/6/12 and Stage 6H reader-sensitivity 6/6 were also separately verified. Power-loss durability and field evidence remain unverified.**  
Date: 2026-10-29  
Branch: feature/carthago-reliability-hardening  
Predecessors: Stage 6D (strict private provenance, pure validator); Stage 6E (single-writer transactional publication).

## 1. Executive decision and limits

Stage 6E defines a full private batch transaction for exactly four external R102 candidates and their four provenance sidecars, with all files staged and committed as one new directory name. It has a deterministic sequential fault-injection contract, but cannot establish safety under concurrent competing writers or diagnose what should happen after interruption, orphaned pending directories and ambiguous commit responses.

Stage 6F adds two **separate and opt-in** regression contracts:

- scripts/verify-v2-recovery-planner-contract.ps1 — 15 owner-verified synthetic, path-free, in-memory recovery classifications. The implemented planner cannot delete, rename, approve, freeze, overwrite or accept a target filesystem path. Human review remains mandatory.
- scripts/verify-v2-two-writer-race-contract.ps1 — 3 verified synchronized race rounds using two separate Windows PowerShell Start-Job processes per round (6 synthetic worker-process executions). The publisher must return exactly one safe winner and one target-exists failure per fresh directory name. Both workers use only synthetic candidates under a unique private scratch root.

The contracts were originally prepared before the publisher existed. `scripts/HoldoutV2CandidatePublisher.psm1`, its private recovery planner and exported publisher wrapper are now implemented; their bounded synthetic recovery/contended-publication behavior has been verified on CARTHAGE. The original capture/importer/auditor remain unchanged.

The work does **not** claim that source labels are correct, captures are authentic, licensed redistribution is permitted, clients are independent, packet content is safe, the original frozen V1 is passing, or that Holdout V2 may be frozen.

## 2. Verified starting point in the repository

Read-only source inspection of the feature branch confirms:

- scripts/import-holdout-v2-r102.ps1 currently writes a sample and a provenance sidecar separately; the existing importer produces provenance schemaVersion 1 and retains bounded selected frames. Its independent writes present a potential partial-pair risk if interrupted.
- scripts/audit-holdout-v2-candidates.ps1 consumes the four manifest-named candidate pairs and original PCAP frames but lacks strict versioned provenance and authenticated logical-client independence.
- docs/contracts/holdout-v2-private-provenance-v2.schema.json specifies 30 required private metadata properties; `scripts/HoldoutV2Provenance.psm1` now implements runtime validation, owner-verified 26/26 under Stage 6D.
- scripts/verify-v2-atomic-publication-contract.ps1 contains the prior Stage 6E sequential fault matrix. Stage 6F does not rewrite it or alter its future API surface.
- docs/holdout-evaluation-v2-manifest.json remains PENDING_EXTERNAL_CAPTURE_AND_REVIEW, with 8 pinned V1-derived non-R102 references and four still unapproved R102 slots.
- The centralized GitHub workflow is manually gated. Stage 6F creates no new workflow, schedule, trigger, artifact, runner job or public fault API.

## 3. Stage 6F-A: pure orphan / recovery decision planning

Implemented internal API, private to HoldoutV2CandidatePublisher.psm1:

~~~
Get-HoldoutV2PrivateRecoveryPlan -Entries <synthetic inventory metadata>
~~~

The input is a list of metadata **without paths or packet bytes**. Each artificial entry contains: a test key, lifecycle Kind, OwnedByInvocation, HasOwnershipMarker, IsReparsePoint, WriterActive, AgeMinutes, PairCount, HashesVerified, ProvenanceSchemaVersion, CommitOutcome, DestinationExists, and NameCollision. This is explicitly not a directory scanner and cannot assert that an actual Windows ACL, ownership marker, reparse point, PID liveness or hash is genuine. Those must be independently verified by an authorized inventory collector later.

Required output is one bounded metadata object:

| Field | Type and requirement |
| --- | --- |
| EntryCount | Exact count of input inventory items |
| RequiresManualReview | True, even if a committed directory appears complete |
| AutoDeleteAllowed | False for every path-free decision |
| Decisions | For each entry, exactly Key, Disposition and Reason |

No raw path, capture filename, client name, source IP, session ID, QNAME, license URL, reversible label or hash may be returned. In particular, a decision called QUARANTINE_REVIEW is **advisory**, not permission to automatically move anything into a quarantine directory. Runtime cleanup and actual quarantine need independent ownership, path, permission and audit safeguards.

### In-memory recovery matrix (15/15 owner-verified scenarios)

| ID | Synthetic inventory condition | Expected disposition | Expected reason |
| --- | --- | --- | --- |
| R01 | Owning writer still active | LEAVE_UNTOUCHED | RECOVERY_ACTIVE_WRITER |
| R02 | Recent stage not committed | REVIEW_PENDING | RECOVERY_UNCOMMITTED_STAGE |
| R03 | Old pending, four pairs, hashes verified | QUARANTINE_REVIEW | RECOVERY_ORPHAN_COMPLETE |
| R04 | Old pending, only two pairs | QUARANTINE_REVIEW | RECOVERY_ORPHAN_PARTIAL |
| R05 | Pending entry not owned by current invocation | LEAVE_UNTOUCHED | RECOVERY_UNOWNED_ENTRY |
| R06 | Ownership marker absent | BLOCK_REVIEW | RECOVERY_OWNER_UNVERIFIED |
| R07 | Reparse-point/symlink flag | BLOCK_REVIEW | RECOVERY_REPARSE_POINT |
| R08 | Four-pair committed and hash-verified, review still pending | RETAIN_COMMITTED | RECOVERY_COMMITTED_PENDING_REVIEW |
| R09 | Final directory exists with two pairs only | QUARANTINE_REVIEW | RECOVERY_PARTIAL_FINAL |
| R10 | Final exists with four pairs but integrity not verified | QUARANTINE_REVIEW | RECOVERY_UNVERIFIED_FINAL |
| R11 | Post-move response lost, final exists with four verified pairs | RECONCILE_COMMITTED | RECOVERY_COMMIT_UNCERTAIN_FINAL_PRESENT |
| R12 | Commit uncertain and final absent | BLOCK_REVIEW | RECOVERY_COMMIT_UNCERTAIN_FINAL_ABSENT |
| R13 | Old/unsupported provenance version in pending stage | QUARANTINE_REVIEW | RECOVERY_SCHEMA_UNSUPPORTED |
| R14 | Competing destination name collision | BLOCK_REVIEW | RECOVERY_TARGET_COLLISION |
| R15 | Unknown lifecycle kind | BLOCK_REVIEW | RECOVERY_UNKNOWN_KIND |

The contract creates each independent case from a path-free reference, invokes the **private module function through module scope**, asserts the exact expected constant reason and disposition, confirms only the four result fields are exposed, checks that no input was mutated, and rejects any result that appears to authorize deletion, approval, promotion or freeze.

The initial missing-module assertions belonged to historical RED-first preparation. The recovery planner is now present; its fifteen path-free cases were owner-verified **15/15** at `1ab3290`. No result authorizes automatic deletion, promotion or source approval.

### Recovery policy that must *not* be implemented automatically

Never classify a pending directory as safe for deletion based solely on age, a filename prefix, a positive caller-owned boolean, or an inactive PID. The real filesystem may contain untrusted reparse points, inherited ACLs, stale locks, hard links, or an interrupted previous user's data. A stage might already have been renamed, with a subsequent response failure. The eventual authorized recovery workflow should be read-only discovery and signed/recorded manual reconciliation first. If a cleanup command is later approved, its ownership proof, scope, target hash, race controls and undo/recovery process need an independent destructive-operation review.

## 4. Stage 6F-B: separate-process same-name race contract

Implemented exported private-batch publisher API exercised by the synthetic harness:

~~~
Publish-HoldoutV2CandidateBatch -CandidatePairs <four private synthetic pairs>
  -SchemaPath <versioned private schema>
  -PrivateOutputRoot <newly owned ignored scratch directory>
  -BatchName <safe fixed name>
~~~

There is intentionally **no public OnMilestone, FaultAt, or arbitrary code callback** in the production wrapper. The race harness uses the normal public interface, rather than the Stage 6E module-private fault hook.

### Fixture, process and isolation construction

1. Read the actual Holdout V2 manifest for the four fixed R102 names, classifications and pending approval state.
2. Generate four pairs with schema version 2, 30 private provenance properties, three synthetic DNS TXT records per sample and RFC 5737 documentation-only IPs; analystReviewedLabel=false and capturedTransportEvidence=false.
3. Require the implemented module and exported publisher wrapper to exist before creating test files.
4. Create a fresh random test-owned directory under the repository's ignored build-verify root. Write one local sentinel and record its SHA-256.
5. For each of three fixed safe batch names (race-01, race-02, race-03), start **two distinct Start-Job worker processes**. Each imports the same publisher module, writes a local ready marker, then waits for one private go-signal file.
6. The parent waits for both ready markers with a bounded timeout before emitting the signal, to increase overlap. The workers have their own signal timeout. No packet interface, download or network request occurs.
7. Both workers attempt the same private batch name with the same four synthetic pairs. They return only a sanitized status code (WIN, TARGET_EXISTS, BAD_SUCCESS_SHAPE, BARRIER_TIMEOUT or UNEXPECTED_ERROR) and numerical process ID. Raw exception messages and private samples are not forwarded to the console.
8. Require exactly one WIN and exactly one TARGET_EXISTS, with two distinct process IDs, **per round**. Validate exactly eight paired files in the final directory, unchanged JSON content, unchanged pending review state, and no .pending-* orphan.
9. Stop/remove any remaining jobs in a finally block, remove only locally owned barrier files, and check that the root ultimately contains precisely the three committed directories and the sentinel.
10. Verify the sentinel SHA and then delete only the uniquely owned scratch root (after a reparse-point guard). No other directories, real source data, or manifests may be deleted.

A synchronized barrier does **not guarantee the two writers execute the rename simultaneously**. It creates a reproducible contention window whose strength must be measured at authorized test time. Three rounds are a first regression, not a statistical proof of race freedom. More rounds, controlled injected delays and a Windows no-replace primitive review are separate follow-on work.

### Success and failure checks

| Scenario | Number of process workers | Required result | What remains unproven |
| --- | --- | --- | --- |
| race-01 | 2 | One complete private batch; exactly one WIN and one TARGET_EXISTS | Actual Windows no-replace primitive choice |
| race-02 | 2 | Same, with a newly named destination | Stress coverage beyond one competition |
| race-03 | 2 | Same, with a newly named destination | Statistical guarantees, crash durability |
| cleanup/inventory | 0 additional processes | No pending stage, unrelated sentinel intact | Actual power-loss, ACL and reparse-point attacks |

If the parent cannot observe two ready markers, it must fail as **harness/environment error**, not claim a successful security rejection. If a publisher raises an unexpected error, the worker returns only UNEXPECTED_ERROR and the test fails. If both writers claim success, or both are rejected, the test fails. File existence alone does not constitute correctness; the test checks all eight files' synthetic content and their pending review state.

**Third-reader gap subsequently addressed within a bounded synthetic scope:** GA 6G ran the same private publisher with a third independent reader at 3/6/12 rounds and saw only absent/complete pending-review final folders. These are sampled snapshots, not continuous formal linearizability. **Still pending:** adversarial ACL-denial, handle locking, and power-failure/durability tests.

## 5. Windows semantics and operational constraints

- All test files are private synthetic data under a newly generated ignored build-verify child. The production output-root validator must accept only a trusted root, canonicalize it and reject redirects/reparse points before writing.
- Do not implement a naive Test-Path then Move-Item overwrite-prone sequence; the commit must use verified same-volume **no-replace** semantics. Windows directory moves and filesystem sharing/ACL nuances must be reviewed and observed on CARTHAGE during authorized validation.
- Post-rename failure does not prove rollback. Preserve complete committed directories and report an uncertain result until reconciled.
- A same-volume namespace rename is not proof of power-loss persistence. Explicit file flush, storage write ordering and recovery after crash require independent environmental testing.
- The owner-verified CARTHAGE 3/3 race confirms separate Start-Job workers, distinct process IDs, four-candidate serialization, ready/go barriers, module import and sanitized results within its bounded synthetic environment. Broader scheduling, OS versions, ACL and hostile filesystem conditions remain separately unverified.
- No machine-wide service changes, firewall adjustments, listener, private capture, VPN, Internet transaction, OS reboot, automatic branch cleanup, CI trigger or overnight execution are part of Stage 6F.

## 6. Completed synthetic gates and remaining acceptance boundaries

1. Owner must explicitly say "now it's test time" before any tests. An AuthorizedTestTime parameter is a safety gate, not permission by itself.
2. Confirm Windows CARTHAGE, current Git SHA, interpreter version, intended private volume, no production data in the scratch root, and the module/API availability. Verify the synthetic fixture generator and Stage 6D schema assumptions.
3. Stage 6D provenance 26/26 and Stage 6E single-writer 18/18 were separately verified before Stage 6F; retain this gate dependency for future schema changes.
4. **Completed 15/15:** the Stage 6F-A path-free recovery decision scenarios returned the expected review-only results; fix any test-harness failures before claiming a meaningful implementation regression.
5. **Completed 3/3:** the Stage 6F-B two-writer contention rounds ran under explicit owner authorization, with synthetic private scratch and no real capture. Require one winner/one loser per round and complete unchanged content. Record failures as exact sanitized categories.
6. **Completed separately:** Stage 6H six reader-negative controls and Stage 6G reader visibility at 3/6/12 rounds. **Still open:** ACL fault injection, crash/reboot recovery and power-loss durability; they do not follow from sampled reader polls.
7. Keep human-reviewed capture rights, original source-byte fidelity, client independence and malicious classification separate from publishing. No V2 candidate is admitted or frozen from these tests.

### Owner-gated regression commands (previously executed; do not rerun automatically)

~~~powershell
powershell.exe -NoProfile -File .\scripts\verify-v2-recovery-planner-contract.ps1 -AuthorizedTestTime
powershell.exe -NoProfile -File .\scripts\verify-v2-two-writer-race-contract.ps1 -AuthorizedTestTime
~~~

Never dispatch these commands automatically. The single centralized GitHub Actions workflow remains manually gated; this development step does not add profiles or invoke the self-hosted runner.

## 7. Documentation and evidence standard

The completed tests are documented in docs/DEVELOPMENT_VALIDATION_LEDGER.md. For any further authorized work, append: exact commit SHA, host, PowerShell and OS versions, intended private root, fixture/schema hashes, case IDs and timestamps, expected vs observed **sanitized** code, process-count and PID uniqueness, file-count/hash summary, pending-orphan count, non-sensitive warnings, and next gate.

Do **not** publish original PCAPs, individual DNS QNAMEs, reversible labels, client addresses, review notes, source/license URLs, or raw worker logs. Avoid declaring RED/GREEN for a case that merely failed because a prerequisite module, serializer or Windows feature is unavailable.

## 8. Preserved project invariants

Frozen V1 R102 evidence remains historically FAILED 4/6. V2 remains PENDING_EXTERNAL_CAPTURE_AND_REVIEW with **0/4** approved R102 candidates. The R102 confidence requirement remains 80%, R118 86%, R163 84%, candidate confidence floor 0.75; Shadow/Disabled, baseline, cooldown, journal integrity, privacy and governance controls remain untouched. No merge, branch deletion, production code rewrite, dataset replacement or network activity was undertaken.

**Current Stage 6F outcome: synthetic Windows recovery GREEN 15/15 and two-writer contention GREEN 3/3.** No crash durability, real-source approval, or broad filesystem guarantee is asserted.

## References

- docs/STAGE6E_ATOMIC_V2_PUBLICATION_FAULT_CONTRACT_20261029.md — sequential fault injection, postcommit uncertainty, old branch state.
- docs/STAGE6D_PRIVATE_PROVENANCE_SCHEMA_AND_ATOMICITY_20261029.md — strict private provenance and validation boundary.
- scripts/verify-v2-atomic-publication-contract.ps1 — verified synthetic sequential publisher contract (18/18).
- scripts/verify-v2-recovery-planner-contract.ps1 — verified synthetic recovery planner contract (15/15).
- scripts/verify-v2-two-writer-race-contract.ps1 — verified synthetic writer contention (3/3) and later reader visibility (3/6/12).
- Microsoft PowerShell Start-Job documentation: https://learn.microsoft.com/powershell/module/microsoft.powershell.core/start-job
- Windows MoveFileExW documentation: https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-movefileexw


## 9. Static hardening and verification checkpoint

The authored test suite was updated in an additional static hardening commit **bf1045e**: its final cleanup now uses Assert-NoReparseInOwnedTree. Rather than checking only the top-level scratch folder and then recursively deleting everything, it walks directories **one level at a time**, inspects each item for the Windows ReparsePoint attribute *before entering it*, and refuses recursive cleanup if any nested link/reparse point is present. This prevents a malicious or faulty future publisher from causing the *test harness* to follow a nested redirection outside its uniquely owned scratch tree. The routine does **not** prove that the underlying Windows filesystem resolves paths without races; actual link/ACL attacks and cleanup atomicity remain separate authorization-gated tests.

The race worker also stages its four synthetic candidates as **one positional array argument**, instead of allowing PowerShell's argument binder to flatten the array into several unrelated parameters. Each worker suppresses warning/information/verbose output and returns only a bounded status and numeric process ID; on unexpected publisher error it returns UNEXPECTED_ERROR without printing the exception. Whether Start-Job serializes the candidate-array shape as intended must still be verified on CARTHAGE at authorized test time. These are **source-level precautions, not observed test results**.

### Final Stage 6F change register

| Commit | File | Purpose |
| --- | --- | --- |
| bf4a27e | scripts/verify-v2-recovery-planner-contract.ps1 | Fifteen path-free advisory recovery decisions, always requiring review |
| 7743740 | scripts/verify-v2-recovery-planner-contract.ps1 | Private module-scope invocation and corrected forbidden-output pattern |
| e8cf7f3 | scripts/verify-v2-two-writer-race-contract.ps1 | Three two-process contention rounds with fresh private batch names |
| fd8a992 | scripts/verify-v2-two-writer-race-contract.ps1 | Preserve candidate argument array and suppress child output streams |
| 7974219 | docs/STAGE6F_CONCURRENT_V2_PUBLICATION_AND_RECOVERY_20261029.md | In-depth design and acceptance matrix |
| dfc75c1 | docs/STAGE6E_ATOMIC_V2_PUBLICATION_FAULT_CONTRACT_20261029.md | Stage 6E dependency and handoff reference |
| bf1045e | scripts/verify-v2-two-writer-race-contract.ps1 | Block recursive scratch cleanup through nested reparse points |

**Historical authoring checkpoint:** no test ran during the source-only commit. **Subsequent owner verification:** recovery 15/15 at `1ab3290`, writer contention 3/3 at `adf421f`; source-level precautions are now accompanied by bounded runtime evidence.


## 10. Stage 6G concurrent reader handoff — subsequently verified

The third-reader visibility gap identified in Stage 6F is now addressed **at the regression-source level only** by extending the **same** scripts/verify-v2-two-writer-race-contract.ps1. Commits bb8a458, 2dccb79 and 6af2424 added an opt-in IncludeReaderVisibility switch, single-string JSON binding for the four expected synthetic names, separate Partial versus read/parse error counters, and a bounded ReaderStressRounds range of 3–12 (six default when opted in). The existing Stage 6F invocation **without** IncludeReaderVisibility still prepares three rounds with exactly two writer jobs each; no new script, workflow, public production hook or sample corpus was created.

In the owner-authorized bounded synthetic runs, the opt-in third reader job waited behind the same local GO barrier as the two writer processes and repeatedly poll only the safe final directory. A legitimate observation is either **absent** or **exactly eight complete, readable, paired JSON files** with schemaVersion=2 and PENDING_EXTERNAL_CAPTURE_AND_REVIEW. The reader returns metadata-only Polls, Absent, Complete, Partial and IoErrors counters; the parent requires at least one absent and one complete observation, zero partial/unreadable snapshots and an independent reader process ID. All jobs remain bounded and scratch-owned.

The full threat model, invocation examples, exact diagnostics, safety boundaries, acceptance sequence and preserved invariants are in **docs/STAGE6G_CONCURRENT_READER_VISIBILITY_20261029.md** (commit 815a064). This remains a **sampled visibility regression**, not proof that partial visibility never happened between polls. Stage 6H subsequently supplied the exact shared-reader synthetic negative control, owner-verified 6/6 at `8882f1c`, before Stage 6G was closed GREEN on bounded 3/6/12 rounds. These checks never wrote outside the owned synthetic scratch directory. Continuous reader visibility, actual Windows no-replace API semantics, NTFS crash durability, ACL errors, and real source/license/label review remain unverified and separately gated.

**Historical authoring record:** no tests were executed during this original documentation step. **Current validation:** owner-observed Stage 6F recovery and writer contention, Stage 6G bounded reader visibility, and Stage 6H reader sensitivity GREEN as summarized above. No live capture or CI was dispatched as part of the documentation refresh. Frozen V1 and pending V2 approval state remain untouched.

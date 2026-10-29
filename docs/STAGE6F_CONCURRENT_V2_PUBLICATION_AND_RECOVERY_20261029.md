# Stage 6F — V2 concurrent publisher and crash-recovery decision contracts

**Status: PARKED / TEST SOURCE AUTHORED / ZERO EXECUTIONS**  
Date: 2026-10-29  
Branch: feature/carthago-reliability-hardening  
Predecessors: Stage 6D (strict private provenance, pure validator); Stage 6E (single-writer transactional publication).

## 1. Executive decision and limits

Stage 6E defines a full private batch transaction for exactly four external R102 candidates and their four provenance sidecars, with all files staged and committed as one new directory name. It has a deterministic sequential fault-injection contract, but cannot establish safety under concurrent competing writers or diagnose what should happen after interruption, orphaned pending directories and ambiguous commit responses.

Stage 6F adds two **separate and opt-in** regression contracts:

- scripts/verify-v2-recovery-planner-contract.ps1 — 15 synthetic, path-free, in-memory recovery classifications. The eventual planner must never delete, rename, approve, freeze, overwrite or even accept a target filesystem path. Human review remains mandatory.
- scripts/verify-v2-two-writer-race-contract.ps1 — 3 planned synchronized race rounds using two separate Windows PowerShell Start-Job processes per round (6 worker-process executions when testing is eventually authorized). The publisher must return exactly one safe winner and one target-exists failure per fresh directory name. Both workers use only synthetic candidates under a unique private scratch root.

These are preparation for future code and tests; the corresponding module scripts/HoldoutV2CandidatePublisher.psm1, private recovery planner, and public publisher wrapper do **not yet exist**. No result is observed and no production code was changed.

The work does **not** claim that source labels are correct, captures are authentic, licensed redistribution is permitted, clients are independent, packet content is safe, the original frozen V1 is passing, or that Holdout V2 may be frozen.

## 2. Verified starting point in the repository

Read-only source inspection of the feature branch confirms:

- scripts/import-holdout-v2-r102.ps1 currently writes a sample and a provenance sidecar separately; the existing importer produces provenance schemaVersion 1 and retains bounded selected frames. Its independent writes present a potential partial-pair risk if interrupted.
- scripts/audit-holdout-v2-candidates.ps1 consumes the four manifest-named candidate pairs and original PCAP frames but lacks strict versioned provenance and authenticated logical-client independence.
- docs/contracts/holdout-v2-private-provenance-v2.schema.json proposes exactly 30 required private metadata properties and pending review; it is not an implemented validator.
- scripts/verify-v2-atomic-publication-contract.ps1 contains the prior Stage 6E sequential fault matrix. Stage 6F does not rewrite it or alter its future API surface.
- docs/holdout-evaluation-v2-manifest.json remains PENDING_EXTERNAL_CAPTURE_AND_REVIEW, with 8 pinned V1-derived non-R102 references and four still unapproved R102 slots.
- The centralized GitHub workflow is manually gated. Stage 6F creates no new workflow, schedule, trigger, artifact, runner job or public fault API.

## 3. Stage 6F-A: pure orphan / recovery decision planning

Future internal API, private to HoldoutV2CandidatePublisher.psm1:

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

### In-memory recovery matrix (15 authored scenarios)

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

The module is missing by design; a future authorized initial run will encounter recovery-module-not-implemented-red or recovery-planner-not-implemented-red until the minimal implementation exists. That is an **unimplemented API observation**, not a valid security RED until fixture/output assumptions have been independently verified.

### Recovery policy that must *not* be implemented automatically

Never classify a pending directory as safe for deletion based solely on age, a filename prefix, a positive caller-owned boolean, or an inactive PID. The real filesystem may contain untrusted reparse points, inherited ACLs, stale locks, hard links, or an interrupted previous user's data. A stage might already have been renamed, with a subsequent response failure. The eventual authorized recovery workflow should be read-only discovery and signed/recorded manual reconciliation first. If a cleanup command is later approved, its ownership proof, scope, target hash, race controls and undo/recovery process need an independent destructive-operation review.

## 4. Stage 6F-B: separate-process same-name race contract

Future public production API assumed by the parked harness:

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
3. Require the future module and public wrapper to exist before creating test files.
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

**Critical gap to test later:** a third independent reader polling during the rename should never observe fewer than eight files in a final directory. The present harness verifies after both workers terminate, not continuous reader visibility. Separate reader-observer, ACL-denial, handle locking and power-failure tests remain pending.

## 5. Windows semantics and operational constraints

- All test files are private synthetic data under a newly generated ignored build-verify child. The production output-root validator must accept only a trusted root, canonicalize it and reject redirects/reparse points before writing.
- Do not implement a naive Test-Path then Move-Item overwrite-prone sequence; the commit must use verified same-volume **no-replace** semantics. Windows directory moves and filesystem sharing/ACL nuances must be reviewed and observed on CARTHAGE during authorized validation.
- Post-rename failure does not prove rollback. Preserve complete committed directories and report an uncertain result until reconciled.
- A same-volume namespace rename is not proof of power-loss persistence. Explicit file flush, storage write ordering and recovery after crash require independent environmental testing.
- PowerShell Start-Job on the planned Windows host should be validated as separate worker processes with distinct process IDs. Start-Job serialization of the four-candidate array, local barrier handling, module import, timing and sanitized output are **unverified** at present.
- No machine-wide service changes, firewall adjustments, listener, private capture, VPN, Internet transaction, OS reboot, automatic branch cleanup, CI trigger or overnight execution are part of Stage 6F.

## 6. Test-first ordering and acceptance criteria

1. Owner must explicitly say "now it's test time" before any tests. An AuthorizedTestTime parameter is a safety gate, not permission by itself.
2. Confirm Windows CARTHAGE, current Git SHA, interpreter version, intended private volume, no production data in the scratch root, and the module/API availability. Verify the synthetic fixture generator and Stage 6D schema assumptions.
3. Observe Stage 6D pure provenance validator RED/GREEN first; then Stage 6E single-writer publisher RED/GREEN, so each Stage 6F regression has a known-good baseline.
4. Run the 15 Stage 6F-A in-memory decision scenarios and verify stable safe results without disk I/O; fix any test-harness failures before claiming a meaningful implementation regression.
5. Run the three Stage 6F-B races only under renewed explicit authorization, with a safe output root and no real capture. Require one winner/one loser per round and complete unchanged content. Record failures as exact sanitized categories.
6. Follow with owner-approved third-reader visibility, concurrent stress, ACL injection and crash/reboot recovery tests as separate later gates. Do **not** assume they passed from this test preparation.
7. Keep human-reviewed capture rights, original source-byte fidelity, client independence and malicious classification separate from publishing. No V2 candidate is admitted or frozen from these tests.

### Parked commands (not permission)

~~~powershell
powershell.exe -NoProfile -File .\scripts\verify-v2-recovery-planner-contract.ps1 -AuthorizedTestTime
powershell.exe -NoProfile -File .\scripts\verify-v2-two-writer-race-contract.ps1 -AuthorizedTestTime
~~~

Never dispatch these commands automatically. The single centralized GitHub Actions workflow remains manually gated; this development step does not add profiles or invoke the self-hosted runner.

## 7. Documentation and evidence standard

When tests are eventually approved, append to docs/DEVELOPMENT_VALIDATION_LEDGER.md: exact commit SHA, host, PowerShell and OS versions, intended private root, fixture/schema hashes, case IDs and timestamps, expected vs observed **sanitized** code, process-count and PID uniqueness, file-count/hash summary, pending-orphan count, non-sensitive warnings, and next gate.

Do **not** publish original PCAPs, individual DNS QNAMEs, reversible labels, client addresses, review notes, source/license URLs, or raw worker logs. Avoid declaring RED/GREEN for a case that merely failed because a prerequisite module, serializer or Windows feature is unavailable.

## 8. Preserved project invariants

Frozen V1 R102 evidence remains historically FAILED 4/6. V2 remains PENDING_EXTERNAL_CAPTURE_AND_REVIEW with **0/4** approved R102 candidates. The R102 confidence requirement remains 80%, R118 86%, R163 84%, candidate confidence floor 0.75; Shadow/Disabled, baseline, cooldown, journal integrity, privacy and governance controls remain untouched. No merge, branch deletion, production code rewrite, dataset replacement or network activity was undertaken.

**Stage 6F outcome: source contracts prepared, with ZERO executions and ZERO validated filesystem or recovery claims.**

## References

- docs/STAGE6E_ATOMIC_V2_PUBLICATION_FAULT_CONTRACT_20261029.md — sequential fault injection, postcommit uncertainty, old branch state.
- docs/STAGE6D_PRIVATE_PROVENANCE_SCHEMA_AND_ATOMICITY_20261029.md — strict private provenance and validation boundary.
- scripts/verify-v2-atomic-publication-contract.ps1 — parked sequential publisher contract.
- scripts/verify-v2-recovery-planner-contract.ps1 — parked pure recovery planner contract.
- scripts/verify-v2-two-writer-race-contract.ps1 — parked separate-process race harness.
- Microsoft PowerShell Start-Job documentation: https://learn.microsoft.com/powershell/module/microsoft.powershell.core/start-job
- Windows MoveFileExW documentation: https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-movefileexw

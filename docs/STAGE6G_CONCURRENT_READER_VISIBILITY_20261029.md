# Stage 6G — Concurrent reader visibility and bounded three-process stress

**Current status (2026-10-30): SYNTHETIC GREEN — independent reader visibility 3/3, 6/6 and 12/12 bounded rounds (maximum at `566f746`), with one WIN/one TARGET_EXISTS and absent/complete snapshots only. Stage 6H shared-reader negative sensitivity 6/6 independently GREEN at `8882f1c`.**  
**Date:** 2026-10-29  
**Active branch:** feature/carthago-reliability-hardening  
**Existing test harness extended:** scripts/verify-v2-two-writer-race-contract.ps1  
**No new production module, workflow, source capture, dataset, or branch.**

## 1. Engineering objective and measured boundary

Stage 6F introduced three two-writer race contracts that verify the final private candidate batch **after** both publishers complete. Those tests cannot establish what a third independent process observes **while** the rename/commit occurs. A broken publisher that creates the final directory first, then adds its eight JSON files one by one, might still pass a final-state check. A reader could mistake an incomplete candidate for a usable private bundle.

Stage 6G makes the third-reader observer an explicit **opt-in extension** of the existing two-writer synthetic harness. It reuses the same manifest-derived four candidate pairs, schema, safe writer interface, unique scratch root, workers, content assertions and cleanup. Stage 6F's three-round behavior is unchanged when the new switch is omitted. The owner subsequently authorized and ran the bounded 3-, 6- and 12-round Windows contracts. Their synthetic results are recorded in `docs/DEVELOPMENT_VALIDATION_LEDGER.md`; no real source was involved.

**Correctness property under test:** Every successful reader snapshot of a final batch name must be either:

- **ABSENT** — the final directory has not become visible, or
- **COMPLETE_PENDING_REVIEW** — the final directory contains **exactly eight valid sample/provenance JSON files** with the four expected manifest names, matching classifications, provenance schema version 2, and PENDING_EXTERNAL_CAPTURE_AND_REVIEW state.

**Forbidden observations:** final directory visible with 0–7 files; extra or misplaced files; malformed, truncated or unreadable JSON; wrong sample/provenance names; inconsistent classifications; legacy provenance version; or a source approval/frozen state. Directory-read errors are tracked separately from a clean absence and also fail the contract.

This is a *sampled concurrency invariant*: a fast transient partial state between polls may be missed. Absence of a detected partial snapshot cannot prove linearizability or Windows power-loss durability. The bounded synthetic reader behavior has been observed on Windows, but it cannot establish formal linearizability or power-loss durability.

## 2. Why the existing harness was extended instead of copied

Stage 6F already prepares:

1. Four manifest-matched synthetic sample/provenance pairs, with two benign and two malicious R102 placeholder names; three dummy TXT records per pair; RFC 5737 documentation-only addresses.
2. A newly generated ignored build-verify test root, unique sentinel file and SHA-256.
3. Two independent Windows PowerShell Start-Job workers that wait on a local ready/go barrier and invoke the **normal public publisher wrapper**.
4. One writer WIN, one writer TARGET_EXISTS, complete eight-file output, unchanged content and no leftover pending stages.
5. Cleanup restricted to the newly owned scratch root with a nested ReparsePoint check.

Duplicating those fixtures in a separate Stage 6G script would introduce opportunities for different serialization assumptions, different private roots and divergent test rules. The new opt-in reader is therefore implemented in **the existing source file**, with no new GitHub workflow or production implementation.

## 3. New, explicitly gated invocation parameters

| Parameter | Default | Effect |
| --- | --- | --- |
| AuthorizedTestTime | false | Existing explicit gate. Its presence is not user authorization; owner must first say "now it's test time". |
| IncludeReaderVisibility | false | Adds one third, independent Start-Job observer per writer race. Stage 6F default remains two writer jobs and three rounds. |
| ReaderStressRounds | 6 | Only used when IncludeReaderVisibility is supplied; bounded to 3–12 rounds by ValidateRange. Original no-reader run remains exactly three rounds. |

**Owner-gated regression commands (already executed with bounded synthetic cases; not automatic):**

~~~powershell
# Stage 6F original three-round behavior:
powershell.exe -NoProfile -File .\scripts\verify-v2-two-writer-race-contract.ps1 -AuthorizedTestTime

# Stage 6G default: six 2-writer + 1-reader rounds:
powershell.exe -NoProfile -File .\scripts\verify-v2-two-writer-race-contract.ps1 -AuthorizedTestTime -IncludeReaderVisibility

# Stage 6G bounded repeat: twelve independent three-process rounds:
powershell.exe -NoProfile -File .\scripts\verify-v2-two-writer-race-contract.ps1 -AuthorizedTestTime -IncludeReaderVisibility -ReaderStressRounds 12
~~~

These commands are documentation, **not permission to run**. Stage 6D pure validation and Stage 6E transactional publisher RED/GREEN must be completed under explicit authorization before interpreting Stage 6G outcomes.

## 4. Three-process life cycle, independently verifiable milestones

For each safe, unique batch name (race-01 through race-N):

| Step | Writer 1 | Writer 2 | Reader 3 | Parent contract |
| --- | --- | --- | --- | --- |
| 0 | No work yet | No work yet | Asserts final target initially absent | Uses only newly owned scratch |
| 1 | Imports module, creates ready marker | Same | Creates reader-ready marker | Requires **all three** readiness markers |
| 2 | Waits for local go signal | Waits | Waits | Releases all participants with one local signal |
| 3 | Attempts exact new batch name | Competes for same name | Repeatedly samples final directory state | Never reads a .pending-* directory |
| 4 | Reports sanitized WIN or TARGET_EXISTS | Reports sanitized WIN or TARGET_EXISTS | Tracks Absent / Complete / Partial / IoErrors counters | Requires exactly one WIN and one TARGET_EXISTS |
| 5 | Terminates | Terminates | Stays alive briefly after writer join | Parent independently validates eight final files and content |
| 6 | No further work | No further work | Receives private stop signal; returns bounded metadata | Requires reader to report completed, with zero Partial and IoErrors |
| 7 | Joined/removed | Joined/removed | Joined/removed | Removes only owned barrier files, verifies pending-stage absence |
| 8 | — | — | — | Tests sentinel SHA, expected directory inventory and nested reparse-point safety before cleanup |

A third observer is a **distinct Windows PowerShell job process**, not an asynchronous scriptblock in the publisher itself. The parent checks its ProcessId differs from both writer IDs.

Reader polling is bounded by a 75-second observation deadline and a 4-millisecond sleep between samples. The start barrier is bounded by 30 seconds for each reader. The parent bounds readiness and job joins; worker completion should never be treated as success if the observer failed to join.

Before observing, the reader receives the four *expected synthetic sample names* as one JSON string, decoded in its own process. This avoids array flattening in PowerShell job argument binding. No real client/source metadata or original DNS wire-label bytes are passed.

### Reader snapshot algorithm (implemented and exercised)

1. Check the final directory is absent before signalling READY. If it already exists, return EARLY_VISIBLE.
2. Wait for GO; maintain integer counters Polls, Absent, Complete, Partial and IoErrors.
3. If the final directory is absent, increment Absent.
4. If it exists, enumerate top-level files and require exactly the eight expected sample/provenance basenames; extra files or missing files count as Partial.
5. If the names match, read and parse each of the four sample JSON and four provenance JSON files; require names, classifications, schemaVersion=2 and pending review state. Mismatch counts as Partial.
6. An exception opening, reading, enumerating or parsing is recorded as IoErrors. The exception message is never published or returned, because it may contain source paths or private payload.
7. After both writers terminate, the parent allows a brief final observation window, signals reader STOP and requires one bounded result with code READER_DONE. It then requires **at least one complete snapshot**, at least one absent observation and **zero partial/unreadable snapshots**.

The final detailed byte and semantic-content comparisons still run through the preexisting Assert-CompletePendingBatch check after the writer race. The observer does not claim to parse or validate original PCAP capture frames, rights, malicious labels, or independent source/client evidence.

## 5. Expected diagnostics (stable and privacy-safe)

| Failure ID / category | Meaning | Classification |
| --- | --- | --- |
| workers-did-not-reach-barrier | At least one required participant failed readiness | Harness/environment, NOT observed atomicity RED |
| READER_NAMES_INVALID | Reader did not receive four expected sample IDs | Harness serialization error |
| EARLY_VISIBLE | Final target existed before the writers were released | Isolation or unsafe publication |
| READER_BARRIER_TIMEOUT | No GO signal within bounded wait | Harness/barrier issue |
| READER_DEADLINE | Observer did not stop before its deadline | Scheduler/runtime issue |
| READER_UNEXPECTED | Reader failed before bounded normal result | Harness/runtime issue |
| reader-did-not-stop | Reader worker did not return within bounded join | Harness/runtime issue |
| reader-invalid-output-shape | Worker returned wrong number/type of results | Harness/output issue |
| observer-not-independent-process | Reader PID equal to writer PID | Invalid process-independence evidence |
| reader-did-not-observe-both-states | Observer never saw at least one legitimate full final view | Insufficient observation, NOT proof of safe commit |
| reader-observed-partial-visible-batch | Observed final directory with missing/extra/inconsistent JSON | Candidate atomic-visibility violation, once controls are sound |
| reader-view-unreadable-or-io-error | JSON parse or filesystem read failed while final directory appeared | Strict failure; distinguish harness/IO issue before calling a product bug |
| race-did-not-have-exactly-one-winner | Both writers claimed success or neither produced proper target-exists | No-replace concurrency regression |
| race-produced-incomplete-final | Post-race final folder does not contain eight expected files | Final integrity regression |
| cleanup-nested-reparse-point | Scratch tree contains untrusted nested link/reparse point | Safety stop, no recursive deletion |

No diagnostic may print packet names, reversible DNS data, captured IPs, client/session IDs, source URLs, private file paths or serialized request contents. Only safe synthetic batch markers and metadata counters are permitted.

## 6. Coverage matrix and deliberate exclusions

| Scenario | Stage 6G status | Assurance boundary |
| --- | --- | --- |
| Three-process absent-to-complete observation for each fresh batch | **GREEN**, owner-confirmed 3/6/12 rounds | Detects a partial final directory when sampled |
| Six rounds by opt-in default | **GREEN 6/6** | Bounded, repeatable stress; no statistical guarantee |
| Up to twelve rounds by explicit parameter | **GREEN 12/12** at `566f746` | Additional opportunities to expose contention |
| One winner and one target-exists loser | **Observed** one WIN and one TARGET_EXISTS per round | Tests no-replace contention |
| Reader parses eight expected records | **GREEN in bounded synthetic sampled snapshots** | Visible JSON and matching metadata, not byte-accurate source PCAP |
| Separate no-replace rename primitive review | **Bounded Windows contention/visibility tested**; no formal guarantee | Atomicity depends on actual Windows behavior |
| Deliberately incomplete/malformed synthetic final folders | **GREEN 6/6 reader negative sensitivity, Stage 6H** | Observer-sensitivity negative control required |
| Continuous formal linearizability proof | Not feasible from sampled polling | A sub-poll interval partial view may be missed |
| Reader under share-violation and ACL denial | Deferred | Real Windows filesystem and permissions behavior |
| Writer crash/reboot while renaming | Deferred | No destructive crash injection authorized |
| Full NTFS durability/power-loss guarantee | Deferred | Requires storage-specific recovery evidence |
| Real malicious-source or license approval | Outside scope | Manual human review required |

The deterministic shared-reader negative control was separately implemented and **verified 6/6** in Stage 6H before Stage 6G was closed GREEN. It detected deliberately incomplete/malformed **synthetic final directories** in its owned scratch folder. Never create a deliberately unsafe path or write into a real candidate directory to generate that negative control.

The parent must refuse any unexpected top-level scratch entries. Even when all tests eventually pass, a reader might miss very brief partial states because polling is sampled. A future true no-replace commit primitive audit, continuous watcher or deterministic fault hook must complement this regression.

## 7. Dependency and authorization ordering

1. Preserve Stage 6D's private provenance schema (all 30 required fields), Stage 6E's atomic publisher and Stage 6F's prior race/recovery contracts. No code duplication or additional production modules from Stage 6G.
2. Obtain explicit owner test-time authorization. Simply passing AuthorizedTestTime is **not** sufficient.
3. Verify CARTHAGE, Windows PowerShell version, exact checkout SHA, private filesystem roots and absence of real source data in scratch.
4. Use the already confirmed Stage 6D 26/26, Stage 6E 18/18 and Stage 6F recovery 15/15 plus writer 3/3 as prerequisites for any future versioned reruns. Treat missing-module errors and malformed synthetic fixtures as setup defects, not as demonstrated security RED.
5. Stage 6G's opt-in reader tests were subsequently run at three, then six, then twelve rounds, all GREEN; future code changes should repeat the incremental ordering only if separately authorized. If a reader misses complete view or sees IO errors, distinguish test scheduling/serialization from genuine product regression.
6. Capture metadata-only evidence for every attempt: exact commit SHA and schema blob, OS/PowerShell versions, round count, writer PIDs unique (numeric only), reader PID uniqueness, WIN/TARGET_EXISTS codes, per-round Absent/Complete/Partial/IoErrors counts, final eight-file integrity, sentinel SHA outcome and orphan count.
7. The shared-reader Stage 6H deterministic sensitivity check was completed 6/6 before closing Stage 6G GREEN.
8. Do not run packet capture, TShark, detector replay, R102 accuracy, dataset mutation, model training or any GitHub Actions job without separately authorized gates.
9. Do not freeze V2, modify failed V1, change rule confidence or auto-approve source rights, labels or provenance.

## 8. Source-level change and audit trail

| Commit | Single changed file | Change |
| --- | --- | --- |
| bb8a458 | scripts/verify-v2-two-writer-race-contract.ps1 | Add third independent reader job behind new IncludeReaderVisibility switch; verify absent vs eight-file complete snapshots during publication |
| 2dccb79 | scripts/verify-v2-two-writer-race-contract.ps1 | Pass four expected names through one JSON positional argument; split visible-incomplete errors from read/parse errors |
| 6af2424 | scripts/verify-v2-two-writer-race-contract.ps1 | Add bounded 3–12 reader stress rounds (default six when opted in), retaining original three-round Stage 6F behavior when omitted |

**No runtime evidence** is available for these commits. GitHub publication and static source inspection are not PowerShell parser proof, race reliability proof, a Windows filesystem performance result or a field accuracy measurement.

## 9. Preserved invariants

Frozen V1 remains FAILED 4/6 (historical R102 missing transport attribution) with immutable references. V2 manifest remains PENDING_EXTERNAL_CAPTURE_AND_REVIEW with **0/4 approved** external R102 candidates. R102 confidence 80%, R118 86%, R163 84%, R102 holdout minimum 0.75, Shadow/Disabled, cooldown, baseline, journal and private data controls remain untouched. No branch merge/cleanup, runner execution, auto workflow, new capture, foreign source rights claim or real production implementation is part of this change.

**Stage 6G status: regression source prepared; RED/GREEN NOT OBSERVED; tests executed = zero.**

## References

- scripts/verify-v2-two-writer-race-contract.ps1 — existing Stage 6F harness with opt-in Stage 6G observer.
- docs/STAGE6F_CONCURRENT_V2_PUBLICATION_AND_RECOVERY_20261029.md — two-writer race and read-only recovery planner.
- docs/STAGE6E_ATOMIC_V2_PUBLICATION_FAULT_CONTRACT_20261029.md — eight-file publisher transaction and fault matrix.
- docs/STAGE6D_PRIVATE_PROVENANCE_SCHEMA_AND_ATOMICITY_20261029.md — strict provenance v2.
- Microsoft PowerShell Start-Job documentation: https://learn.microsoft.com/powershell/module/microsoft.powershell.core/start-job
- Microsoft MoveFileExW documentation: https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-movefileexw


## 10. Stage 6H negative-control completion at source level — 2026-10-29

The deterministic sensitivity probe required by Stage 6G was implemented and subsequently **owner-verified GREEN 6/6 at `8882f1c`**. Rather than writing a duplicate observer, the existing scripts/verify-v2-two-writer-race-contract.ps1 now holds **one** shared PrivateBatchReaderJob scriptblock reused by (a) the Stage 6G concurrent reader and (b) an independent Stage 6H synthetic negative-control mode.

The OnlyReaderNegativeControl mode does **not** import or call the publisher module and does **not** start two competing writer jobs. It sequentially creates six deliberately malformed synthetic final folders under one unique ignored scratch root: H01 zero-file directory; H02 missing sidecar; H03 malformed JSON in otherwise complete eight-file names; H04 false APPROVED review state; H05 unexpected extra file; H06 conflicting sample/provenance classification. All sources/identifiers are artificial, never real PCAP content.

Both test modes execute exactly the same reader code. The Stage 6H parent requires a **real post-GO absence acknowledgment** before revealing each invalid synthetic folder via a same-volume move, and a **reader-generated PARTIAL or IOERROR acknowledgment** afterward. Each check has bounded waits, a strict seven-field metadata-only result, and no raw-content logging. The old Stage 6F three-round behavior and opt-in Stage 6G 3–12-round behavior are preserved.

Detailed test mechanics, executed counters, failure categories, path controls and owner-gated commands are in docs/STAGE6H_DETERMINISTIC_READER_NEGATIVE_CONTROLS_20261029.md, commits **402003f** and **b791d5d**. Source updates: **f8c1ec5, d6a848e, fd4ce67, 6c5ec83, e977067**. The last one guards against a redirected build-verify parent before scratch creation.

**Acceptance order followed:** the owner verified H01–H06 sensitivity in reader-only mode before interpreting the successful Stage 6G writer/reader races. The later Stage 6G 3/6/12 matrix is GREEN within sampled synthetic scope. This is still sampled observation; even after a successful negative control, it does not prove formal linearizability, crash durability or original-source correctness.

**Historical authoring truth:** Stage 6H was not executed during its original source-only authoring step. **Current state:** Windows owner-observed Stage 6H 6/6 and Stage 6G bounded reader 3/6/12 tests have since executed; no live PCAP or CI was involved. Existing importer and auditor remain unchanged; V1 frozen outcome and V2 PENDING_EXTERNAL_CAPTURE_AND_REVIEW, 0/4 approval state, are preserved.

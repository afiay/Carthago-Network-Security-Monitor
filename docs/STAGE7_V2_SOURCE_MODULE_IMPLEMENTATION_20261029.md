# Carthago — GA 7: V2 source modules and verified synthetic contracts

**Date:** 2026-10-29  
**Branch:** feature/carthago-reliability-hardening  
**Current status (2026-10-30): IMPLEMENTED; TARGETED SYNTHETIC VALIDATION GREEN.** Owner-verified Windows results include GA 6D provenance **26/26** (`3ae94ba`), GA 6E atomic publication **18/18** (`c5174da`), GA 6F recovery **15/15** (`1ab3290`) and two-writer contention **3/3** (`adf421f`), GA 6H reader sensitivity **6/6** (`8882f1c`), GA 6G sampled reader visibility **3/6/12 rounds** (`566f746`), and original binary DNS/TShark plus optional V2 source-binding verification at **`e412c2a`**. The read-only GA 8 wire-to-legacy bridge separately passed at **`9f709d0`**. These are synthetic contracts, **not** full xUnit/replay/performance certification, real capture approval, NTFS power-loss durability or production acceptance. V2 remains `PENDING_EXTERNAL_CAPTURE_AND_REVIEW` with **0/4 external R102 sources approved**.

## Executive implementation result

Three missing private modules were implemented without changing the legacy R102 importer, existing V2 auditor, detection thresholds, frozen V1 evidence, V2 manifest, self-hosted runner configuration, or centralized manual-only GitHub Actions workflow.

| Module | Public API | Private implementation | Intended result |
| --- | --- | --- | --- |
| scripts/DnsWirePcap.psm1 | Read-DnsWireQuestion, Confirm-DnsWireCandidateBinding, Measure-DnsWireMaliciousSourceIndependence | RFC 1035 compressed-name/question decoder; selected-frame TShark raw-byte binding; canonical RFC 4648 Base64; ASCII-only logical-source overlap review | Source bytes/transport and suspicious client-reuse signals, never automated independence approval |
| scripts/HoldoutV2Provenance.psm1 | Confirm-HoldoutV2ProvenanceBatch | Strict 30-field schema v2 typed/allowlist checks, four manifest slots, frame/question cardinality and global tuple uniqueness | One five-field private pending-review metadata object; no disk writes or external capture |
| scripts/HoldoutV2CandidatePublisher.psm1 | Publish-HoldoutV2CandidateBatch | Private name/path checks; pure validator reuse; exactly eight staged sample/sidecar JSON files; close/flush/re-read; same-volume no-replace Directory.Move; guarded rollback; private fault hook | One four-field private-published/pending result. Does not freeze or approve a candidate. |

The publisher module also implements a *non-exported*, path-free Get-HoldoutV2PrivateRecoveryPlan to satisfy GA 6F's 15-case advisory recovery contract. It returns manual-review decisions only; it cannot remove, rename, scan or approve filesystem entries. The module keeps Assert-HoldoutV2BatchName and Invoke-HoldoutV2AtomicPublishCore **private**, so fault injection is not exposed to applications or end users.

### Commits recorded during implementation

| Commit | Change |
| --- | --- |
| a7bc0dc | Add strict provenance v2 validator |
| 15d3ea1 | Ensure wrong schema version reports PROV_SCHEMA_VERSION |
| 18f69b4 | Add private atomic batch publisher |
| 2e9a447 | Add DNS original-label decoder, binding API and source independence reviewer |
| 85e4cbf | Correct multi-question DNS array emission |
| 5d199c8 | Add private, non-destructive recovery planner |
| abbe6b0 | Repair source-edit replacement corruption in recovery function |
| f527538 | Use non-disclosing stable DNS/TShark errors |

**Version boundary:** The existing import-holdout-v2-r102.ps1 still emits **provenance schemaVersion=1**. The new module accepts **private provenance schemaVersion=2**, a separate version from the Holdout V2 **manifest schemaVersion=2**. The implementation is an opt-in library, NOT a silent upgrade, replacement of the legacy importer, or a license to reinterpret its existing 11-field printable QNAME records as binary-label evidence.

## 1. DNS original-byte reader and binding

### Read-DnsWireQuestion

Inputs: CapturePath, FrameNumber (>=1), zero-based QuestionIndex, TsharkPath.

1. Require a locally existing original capture file, reject reparse-point source and derive its SHA-256.
2. Select exactly the requested frame with TShark (-T jsonraw) and independently select its captured original IP and UDP/TCP ports with bounded (-T fields). No network capture or download is requested. The code never uses dns.qry.name presentation text to establish label bytes.
3. Decode the raw DNS question section beginning at the 12-byte header; enforce QDCOUNT 1..64, DNS question classification IN, strictly bounded labels 1..63 bytes, <=255 bytes expanded name, uncompressed termination, valid compressed backward pointers, no forward pointers, truncated labels, pointer loops or invalid offsets.
4. Select exactly the requested zero-based question ordinal, including more than one question in a single DNS frame. Extract source/destination IP, transport and ports; validate destination port 53 and source port range.
5. Return only **private** selected-frame metadata, including DnsWireLabelsBase64 (a reversible representation of original binary label octets). Callers must not print/upload that object or put it in public telemetry. Error paths must emit constant metadata-only identifiers.

**Observed on CARTHAGE:** synthetic TShark 4.6.9 `-T jsonraw` descriptor parsing, strict DNS-over-TCP two-byte framing, four source-bound questions and five invalid selections passed, followed by the optional V2 two-record/19-negative binding and seven logical-source risk scenarios at `e412c2a`. **Remaining gaps:** independent real-source review, generalized IPv6/TCP reassembly coverage, arbitrary capture formats, field precision/recall and non-synthetic provenance. The decoder remains deliberately fail-closed.

### Confirm-DnsWireCandidateBinding

The binding routine consumes the **original PCAP path**, claimed capture hash, frame and question ordinal vectors, and a strict private record list. It requires consistent cardinality and unique frame/question references, canonical RFC 4648 Base64 for each label, exact label-byte equality with its selected original DNS question, and equality for QTYPE, captured source/destination address, IP version, source/destination port and UDP/TCP attribution.

Result fields are limited to MatchedQuestionCount and CaptureSha256. It does not approve classification, rights, analyst review, source independence, rule promotion or field-wide accuracy.

### Measure-DnsWireMaliciousSourceIndependence

For exactly two candidate source sets, computes **review-risk indicators**: full name-set overlap ignoring order, partial overlap distinct count, repeated original frame/ordinal, equal collection session, and equal originating client. It folds DNS **ASCII A-Z only on decoded original octets**, never UTF-8/Unicode normalization and never raw Base64 string casing. It always returns RequiresAnalystReview=true and IndependenceApproved=false.

A lack of overlap or different IP addresses is **not proof of independent clients**. Real collector identity, session origin, provenance and human label verification remain separate approval requirements.

## 2. Strict private provenance v2 validator

The validator reads the trusted docs/contracts/holdout-v2-private-provenance-v2.schema.json and rejects a different/untrusted schema path, unexpected required-field set, schema extra properties, missing fields, wrong JSON types, forbidden values, unsupported provenance version, invalid source IP syntax and invalid timestamps. It validates the declared two benign/two malicious external R102 manifest slots, exact source/class labels, private capture frame number/question ordinal counts, per-sample and globally unique (SHA256, frame, ordinal) references, and distinct malicious source IP/session/origin identifiers.

Expected negative diagnostics are specific, including PROV_SCHEMA_VERSION, PROV_SCHEMA_EXTRA_FIELD, PROV_SCHEMA_REQUIRED_FIELD, PROV_SCHEMA_TYPE, PROV_SCHEMA_FRAME_INDEX, PROV_SCHEMA_QUESTION_INDEX, PROV_SCHEMA_CARDINALITY, PROV_SCHEMA_DUPLICATE_QUESTION, PROV_BATCH_DUPLICATE_QUESTION, PROV_BATCH_IP_COLLISION, PROV_BATCH_ORIGIN_COLLISION, PROV_BATCH_SESSION_COLLISION, PROV_SCHEMA_ROOT, PROV_SCHEMA_URI, PROV_SCHEMA_LICENSE, PROV_SCHEMA_VANTAGE, PROV_SCHEMA_METHOD, PROV_SCHEMA_ENCODING and PROV_SCHEMA_REVIEW_STATE.

The public result has only CandidateCount=4, SchemaValid=true, RequiresHumanReview=true, IsApproved=false and ApprovalState=PENDING_EXTERNAL_CAPTURE_AND_REVIEW. **It validates asserted structured metadata, not whether the assertion is true.** A well-typed license URI does not prove ownership or redistribution rights; a claimed client label does not prove an independent client; a true analyst flag is not independently authenticated review. The original capture hash/transport/wire content must be separately checked using the DNS source binder and manual review. The validator does no writes, replays, packet reads or network operations.

## 3. Atomic private publisher and recovery

### Public wrapper

Publish-HoldoutV2CandidateBatch receives CandidatePairs, SchemaPath, PrivateOutputRoot and safe BatchName. The private root must be an **already existing child** of the ignored repository build-verify directory. Unsafe basenames, reparse-point roots and paths outside that trust boundary are rejected. Batch names use a narrow basename allowlist rather than accepting arbitrary paths.

A complete publication:

1. **Before writing:** call Confirm-HoldoutV2ProvenanceBatch; match the four sample/provenance names and classifications; require strict six-field sample schema, the existing eleven captured DNS record fields, correct expected R102/negative controls, matching counts, and only pending-review states.
2. **Prepare:** allocate a unique random .pending-* sibling under the same private root. Use CreateNew file operations, four samples and four sidecars, flush each file, and close handles.
3. **Verify:** reread all eight files, require exact original serialized text equality, parse every file and confirm consistent names, classifications, schemaVersion=2 and pending review state. Never place an unverified partial folder at the final name.
4. **Commit:** Directory.Move the **entire private staging directory** into a fresh final basename on the same filesystem. No file-by-file copying to a visible target. A second concurrent publisher must lose with PUBLISH_TARGET_EXISTS rather than overwrite.
5. **Return:** CandidateCount=4, ReviewState=PENDING_EXTERNAL_CAPTURE_AND_REVIEW, IsApproved=false, PublishedToPrivateStaging=true. The result proves only that a private folder was published by the code path if later verification passes.

The private Invoke-HoldoutV2AtomicPublishCore exposes **no public fault-injection hook**. The earlier GA 6E harness can enter module scope for synthetic GA testing; the production wrapper cannot accept OnMilestone or FaultAt arguments.

On precommit failure, clean up only the random operation-owned .pending-* folder after inspecting nested reparse points. If a final target exists because another process won, do not modify it. If an error occurs **after** a successful directory move, return PUBLISH_COMMIT_UNCERTAIN and retain the complete folder for manual reconciliation. No output path, source IP, reversible original name, capture file hash, license URL or client identity is added to public result fields.

**Windows evidence boundary:** controlled CARTHAGE synthetic tests for GA 6E/6F/6G observed rollback, one-winner/one-target-exists contention and reader absent/complete snapshots. These **do not** establish power-loss durability, universal no-replace linearizability, adverse ACL/reparse-point race safety or production filesystem assurance.

### Private recovery planner

Get-HoldoutV2PrivateRecoveryPlan accepts metadata-only entries, including claimed ownership-marker status, writer liveness, age, pair count, hash verification, provenance version and final-state status. It returns at most EntryCount, RequiresManualReview=true, AutoDeleteAllowed=false and per-entry Key, Disposition, Reason.

Supported decisions distinguish active writers, unowned/missing-marker entries, nested-reparse risks, young/old pending stages, complete/partial/unverified final folders, post-move uncertainty, unsupported schemas and name collisions. A QUARANTINE_REVIEW result is **advisory**, not permission to move anything. The function has no path arguments, does not scan disks and never deletes data.

## 4. Compatibility and documented non-goals

This change does NOT:
- modify, migrate or silently bypass the existing schemaVersion=1 importer or 11-field legacy auditor;
- mark four external V2 candidate sources approved (still **0/4**);
- certify source licensing, analyst labels, original malicious ground truth or independently authenticated client sessions;
- raise R102 confidence thresholds or promote a rule;
- interpret or edit immutable historical V1 evidence (historical FAIL 4/6);
- dispatch unsanctioned CARTHAGE jobs or change workflow profiles; previously owner-authorized synthetic PowerShell/TShark tests were executed and are recorded in the ledger;
- claim production performance or field quality metrics, crash durability or universal filesystem correctness from the bounded synthetic tests.

Integration of the new **private** V2 schema and DNS wire-byte fields into the existing importer/auditor needs its own backward-compatible, opt-in cutover and observed RED/GREEN, rather than a speculative replacement of production behavior. In particular, the existing legacy source audit checks printable QNAMEs and frame-number-only attribution; it must not be treated as the new byte-accurate source contract.

## 5. Current GA verification and remaining acceptance work

The owner has already authorized and completed the **targeted synthetic** checks below; do not describe them as parked or request reflexive reruns without a relevant source change. Full transcripts and exact tested revisions are preserved in `docs/DEVELOPMENT_VALIDATION_LEDGER.md`.

| GA | Verified local Windows result | Tested revision | Scope |
| --- | --- | --- | --- |
| GA 6D | GREEN — 2 pending-only controls + 24 negative provenance cases | `3ae94ba` | Structured metadata; **not** source rights |
| GA 6E | GREEN — 18/18 atomic private-publisher controls | `c5174da` | Synthetic commit/rollback; **not** power-loss durability |
| GA 6F | GREEN — 15/15 recovery decisions, 3/3 writer contention | `1ab3290`, `adf421f` | Review-only recovery and competing writers |
| GA 6H | GREEN — 6/6 invalid final-batch reader sensitivity | `8882f1c` | Invalid synthetic folder detection |
| GA 6G | GREEN — 3/6/12 bounded three-process reader rounds | `566f746` (12-round maximum) | Sampled absent/complete visibility; not linearizability |
| GA 7 DNS source verification | GREEN — TCP/UDP/JSON raw, four bound questions + five negatives; optional two V2 records + nineteen negatives and seven source-risk cases | `e412c2a` | Original-wire **synthetic** PCAP; no approval |
| GA 8 compatibility | GREEN — two printable names, ten non-lossless rejections; three original bound frames and eleven negative cases | `9f709d0` | Read-only metadata; no sample publication |

**Still pending:** The legacy importer/auditor enforcement contract has no independently confirmed Windows PASS in this recorded set, and the existing importer/auditor/publisher format migration is not implemented. The four independent licensed/labeled external R102 captures remain **0/4 approved**; frozen V1 is **FAILED 4/6**. R102 field precision/recall, full integrated xUnit/replay/performance, power-loss durability and adversarial filesystem conditions require independent evidence.

### Current test policy

Tests remain manual and owner-authorized. A prior successful run does not authorize future execution or CI dispatch. A synthetic PASS covers the stated contract at its tested SHA only.

**Historical implementation note:** no test ran during the original module-authoring step. Later Windows test outcomes changed the **current** verification status, not the validity of that historical note.

## 6. Sources within the repository

- docs/STAGE6D_PRIVATE_PROVENANCE_SCHEMA_AND_ATOMICITY_20261029.md
- docs/STAGE6E_ATOMIC_V2_PUBLICATION_FAULT_CONTRACT_20261029.md
- docs/STAGE6F_CONCURRENT_V2_PUBLICATION_AND_RECOVERY_20261029.md
- docs/STAGE6G_CONCURRENT_READER_VISIBILITY_20261029.md
- docs/STAGE6H_DETERMINISTIC_READER_NEGATIVE_CONTROLS_20261029.md
- docs/DEVELOPMENT_VALIDATION_LEDGER.md

**Current status:** targeted synthetic module contracts verified as listed above. **Still unapproved:** all external R102 source admissions (0/4). The legacy importer/auditor remain unchanged.

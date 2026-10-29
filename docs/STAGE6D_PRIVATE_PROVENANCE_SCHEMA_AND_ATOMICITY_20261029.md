# Stage 6D — Private Holdout V2 provenance schema and transactional admission contract

**Current status (2026-10-30): SYNTHETIC GREEN — private provenance validator 2 pending-only positives + 24 negatives (26/26) verified on CARTHAGE at `3ae94ba`. The downstream atomic publisher (Stage 6E) is independently GREEN 18/18 at `c5174da`; Holdout V2 source approval remains PENDING, 0/4.**

**Date:** 2026-10-29  
**Branch:** `feature/carthago-reliability-hardening`  
**Created schema:** `docs/contracts/holdout-v2-private-provenance-v2.schema.json` (commit `163a11b`)  
**Prepared synthetic test:** `scripts/verify-v2-provenance-schema-contract.ps1` (commits `9e29ab7`, `fbab77d`)  
**Production code status:** `scripts/HoldoutV2Provenance.psm1` exists and its synthetic schema/collision validation is verified; `scripts/HoldoutV2CandidatePublisher.psm1` also exists, with separate fault/concurrency checks. The legacy importer and auditor still use their older provenance format and remain unchanged.

## 1. Why this stage exists

Carthago's **Holdout V2 manifest schemaVersion=2** is a separate versioning surface from the current private candidate **provenance schemaVersion=1** written by `scripts/import-holdout-v2-r102.ps1`. Conflating them could let unreviewed data acquire apparent legitimacy or produce ambiguous parsing. The current importer writes one `<sample>.json` and one `<sample>.provenance.json` separately. Its source selection is bounded and it refuses to overwrite existing files; nevertheless, a failure during the second write can leave a partial pair. No production change or failure is claimed from the new contracts.

GA 6D established a **private provenance schema v2** with complete allowlisting, bounded typed fields, and explicit pending review. The separate all-or-nothing four-candidate private publisher was subsequently implemented and validated under GA 6E. It does **not** authorize V2 freeze, relabeling, promotion, capture redistribution, or rule accuracy claims.

The existing v1 importer remains a legacy input path. New features must be opt-in and use the existing original-PCAP provenance work, not rewrite or silently convert old data.

## 2. Source-informed baseline and compatibility boundary

Read-only GitHub inspection identified these actual legacy inputs and protections:

- `scripts/import-holdout-v2-r102.ps1` writes provenance `schemaVersion=1` and the existing eleven-field printable record model, including TShark frame indexes and an SHA-256 of the original PCAP. It writes sample and provenance files individually.
- `scripts/audit-holdout-v2-candidates.ps1` currently checks selected source frames, textual `dns.qry.name` / QTYPE / transport and source addresses against a matching original capture. It can reject a reused capture hash/frame pair and forbidden *record* fields, but it does not enforce a strict, versioned provenance-object allowlist or distinguish independently authenticated logical clients solely from different IPs.
- `docs/holdout-evaluation-v2-manifest.json` keeps eight historical R118/R163 records by immutable reference and declares four external R102 placeholders (two benign, two malicious). Those slots are **not** approved and their manifest hashes remain null.
- Current private importer record output and the failure evidence for frozen V1 remain unchanged by Stage 6D.

**Migration rule:** Never interpret a missing `schemaVersion`, legacy `schemaVersion=1` or a printable `dnsQname` as proof of `labels-base64-v1`. New schema v2 requires exact original PCAP hash and frame/question ordinal binding through the separately validated wire decoder. Legacy fixtures must continue through the legacy path until an explicit, auditable migration is designed, tested and approved.

## 3. Exact proposed provenance v2 allowlist

The JSON Schema uses Draft 2020-12, `type: object`, `additionalProperties: false`, and all 30 fields are required. The following table is generated from the committed proposed schema, not from invented production behavior.

| Field | Type / allowed value | Meaning and limit |
| --- | --- | --- |
| `schemaVersion` | integer (const 2) | Mandatory; see JSON Schema. |
| `sample` | string | Pattern-restricted; see JSON Schema. |
| `classification` | string (enum Benign, Malicious) | Mandatory; see JSON Schema. |
| `sourceKind` | string (const external-pcap-reviewed) | Legacy sourceKind token maintained for manifest compatibility; NOT proof of approval. |
| `sourceUri` | string | Syntactic HTTPS only. Never establishes license rights, source ownership, reviewer identity or independence. |
| `sourceLicense` | string (enum Apache-2.0, CC-BY-4.0, CC0-1.0) | Mandatory; see JSON Schema. |
| `sourceLicenseEvidenceUri` | string | Syntactic HTTPS only. Never establishes license rights, source ownership, reviewer identity or independence. |
| `independentLabelBasis` | string | Untrusted assertion pending independent human verification. |
| `analystReviewedLabel` | boolean | Typed declaration only; true is NOT proof that review happened. |
| `capturedTransportEvidence` | boolean | Must be verified against original source frames; cannot be trusted as a claim. |
| `privacyReviewRequired` | boolean (const true) | Mandatory; see JSON Schema. |
| `captureFileName` | string | Pattern-restricted; see JSON Schema. |
| `captureSha256` | string | Pattern-restricted; see JSON Schema. |
| `frameNumbers` | array | Repeated frame numbers allowed only when questionIndices differ; composite uniqueness checked by runtime. |
| `questionIndices` | array | Zero-based DNS question ordinal. Runtime must check exact count, per-frame bounds and uniqueness of each frame/ordinal pair. |
| `selectedRecordCount` | integer | Mandatory; see JSON Schema. |
| `sourceAddress` | string | Structural shape only; runtime must parse using System.Net.IPAddress and check actual captured source. |
| `queryRoot` | string | Legacy printable grouping root; never a lossless DNS wire-label oracle. |
| `originatingClientLabel` | string | Opaque local private identity, not independently verified by syntax. |
| `collectionSessionId` | string | Opaque local private identity, not independently verified by syntax. |
| `collectionVantage` | string (enum client, endpoint, sensor) | A sensor vantage does not establish independent clients. |
| `independentClientEvidenceUri` | string | Syntactic HTTPS only. Never establishes license rights, source ownership, reviewer identity or independence. |
| `dnsWireNameEncoding` | string (const labels-base64-v1) | Private byte-accurate decoding required, but reversible wire labels are intentionally excluded from default JSON provenance and telemetry. |
| `extractor` | string (const tshark) | Mandatory; see JSON Schema. |
| `extractorVersion` | string | Bounded to 160 characters. |
| `maximumPacketsToScan` | integer | Mandatory; see JSON Schema. |
| `selectionMethod` | string (const selected-source-frame-question-tuples-v2) | Mandatory; see JSON Schema. |
| `transformations` | string (const None: original DNS label octets preserved; ASCII-only identity comparison) | Mandatory; see JSON Schema. |
| `preparedAtUtc` | string | Bounded to 40 characters. |
| `reviewState` | string (const PENDING_EXTERNAL_CAPTURE_AND_REVIEW) | This file cannot approve source license, classification, independent client or V2 freeze. |

**Interpretation:** `sourceKind='external-pcap-reviewed'` is retained only as the historical manifest discriminator; it is not a reviewer signature. `analystReviewedLabel=true` is a syntactically valid boolean declaration but **never standalone verification**. The proposed `reviewState` is permanently `PENDING_EXTERNAL_CAPTURE_AND_REVIEW` in unapproved private candidate documents; approvals require a separately controlled review artifact and explicit owner decision.

The HTTPS patterns restrict URL syntax but do **not** verify DNS, ownership, reachable source pages or actual redistribution rights. The `sourceAddress` field uses a bounded character pattern and additionally **requires runtime `System.Net.IPAddress` parsing**. The root is an ASCII grouping value, not an oracle for binary wire labels.

### Privacy and binary wire boundary

Reversible per-label Base64 DNS bytes must not be emitted into default telemetry or public candidate summaries. A private source decoder may reconstruct original labels on demand from the pinned capture SHA + frame number + zero-based question index; only authorized local analysis should hold those bytes in memory. The schema records the encoding contract, but does **not** serialize those original names. Original-byte entropy and 50-octet label thresholds must be computed on decoded DNS label bytes, never the longer Base64 representation.

`frameNumbers` may contain the same frame more than once **only when each `questionIndices` reference is distinct** and the PCAP message actually has that many questions. `uniqueItems: true` on the frame array would reject valid multi-question DNS messages. Structural JSON Schema alone cannot prove original-frame or question-ordinal authenticity.

## 4. Cross-field and cross-candidate requirements outside JSON Schema

The implemented `Confirm-HoldoutV2ProvenanceBatch -Candidates -SchemaPath` helper is intentionally **pure**: it takes four private candidate objects and schema location, makes no writes or network calls, and returns only `CandidateCount`, `SchemaValid`, `RequiresHumanReview`, `IsApproved`, and `ApprovalState`.

Required independent validation after schema typing:

1. Compare `frameNumbers.Count == questionIndices.Count == selectedRecordCount == candidate.records.Count`. Use strict JSON types; never silently cast numeric strings to integers or truthy strings to booleans.
2. Check unique `(captureSha256, frameNumber, questionIndex)` references both within one sample and across the entire four-slot batch; independently verify the actual source message and DNS question ordinal once the original PCAP decoder is available.
3. Verify all four candidate `sample` names/classifications correspond to **exactly** the four expected manifest slots: two benign, two malicious. No name or classification changes may silently substitute samples.
4. Require corroborated logical-client IDs, collection sessions, vantage information, and separate human review for malicious-source independence. Different `sourceAddress` strings alone cannot establish independence. Flag complete or partial original-name overlap across source groups for manual review.
5. Validate `captureSha256` against the exact original locally retained PCAP, not against the candidate's own string. Compare decoded original label bytes, QTYPE, source/destination IPs, transport and ports against the corresponding private records.
6. Require the same frozen V1 and pending V2 manifest states as before. Do not mutate or freeze the manifest as a side effect of parsing.
7. Require a human-verifiable source license, privacy review, classification review and authentic client/session evidence separately. A typed field, known license token or HTTPS reference is only metadata, not proof of rights.
8. Fail closed on unknown additional fields in private provenance, missing required fields, unsupported schema versions, unexpected discriminators, malformed timestamps, unsafe filenames, overlong values, or inconsistent batch cardinality.
9. Avoid reading or publishing unbounded untrusted packet data. Enforce the existing bounded record/packet caps, selected frame scans and local private storage.
10. Never print DNS QNAMEs, reversible Base64 strings, source IPs, capture paths, URLs, credentials or session/client labels into ordinary console logs, CI summaries or shared artifacts.

## 5. Synthetic provenance regression contract — verified

The companion script defines a syntactically valid **four-candidate** reference fixture from the actual manifest names, with only RFC 5737 documentation IPs and `example.org` marker URLs. It is not external ground truth and uses `analystReviewedLabel=false` and `capturedTransportEvidence=false`, deliberately demonstrating that **schema-valid can remain wholly unapproved**.

Two valid-structure, review-pending controls were executed and verified: (i) four well-formed candidate sidecars, and (ii) a repeated frame with a distinct question index within the same capture. Both must return exactly one five-property, non-approving metadata object and leave the input unchanged.

**Negative cases, with stable diagnostic identifiers to distinguish real schema failures from unrelated interpreter errors:**

| # | Mutation | Required diagnostic | Expected boundary |
| --- | --- | --- | --- |
| 1 | `wrong-version` | `PROV_SCHEMA_VERSION` | Structural or cross-candidate rejection, not source approval |
| 2 | `unknown-field` | `PROV_SCHEMA_EXTRA_FIELD` | Structural or cross-candidate rejection, not source approval |
| 3 | `missing-required` | `PROV_SCHEMA_REQUIRED_FIELD` | Structural or cross-candidate rejection, not source approval |
| 4 | `review-bool-string` | `PROV_SCHEMA_TYPE` | Structural or cross-candidate rejection, not source approval |
| 5 | `sha-uppercase` | `PROV_SCHEMA_CAPTURE_HASH` | Structural or cross-candidate rejection, not source approval |
| 6 | `negative-frame` | `PROV_SCHEMA_FRAME_INDEX` | Structural or cross-candidate rejection, not source approval |
| 7 | `negative-ordinal` | `PROV_SCHEMA_QUESTION_INDEX` | Structural or cross-candidate rejection, not source approval |
| 8 | `array-misaligned` | `PROV_SCHEMA_CARDINALITY` | Structural or cross-candidate rejection, not source approval |
| 9 | `count-mismatch` | `PROV_SCHEMA_CARDINALITY` | Structural or cross-candidate rejection, not source approval |
| 10 | `duplicate-same-frame-question` | `PROV_SCHEMA_DUPLICATE_QUESTION` | Structural or cross-candidate rejection, not source approval |
| 11 | `duplicate-across-samples` | `PROV_BATCH_DUPLICATE_QUESTION` | Structural or cross-candidate rejection, not source approval |
| 12 | `duplicate-sample` | `PROV_BATCH_DUPLICATE_SAMPLE` | Structural or cross-candidate rejection, not source approval |
| 13 | `same-malicious-source` | `PROV_BATCH_IP_COLLISION` | Structural or cross-candidate rejection, not source approval |
| 14 | `same-malicious-session` | `PROV_BATCH_SESSION_COLLISION` | Structural or cross-candidate rejection, not source approval |
| 15 | `same-malicious-origin` | `PROV_BATCH_ORIGIN_COLLISION` | Structural or cross-candidate rejection, not source approval |
| 16 | `invalid-vantage` | `PROV_SCHEMA_VANTAGE` | Structural or cross-candidate rejection, not source approval |
| 17 | `http-source` | `PROV_SCHEMA_URI` | Structural or cross-candidate rejection, not source approval |
| 18 | `wrong-license` | `PROV_SCHEMA_LICENSE` | Structural or cross-candidate rejection, not source approval |
| 19 | `wrong-encoding` | `PROV_SCHEMA_ENCODING` | Structural or cross-candidate rejection, not source approval |
| 20 | `false-approval` | `PROV_SCHEMA_REVIEW_STATE` | Structural or cross-candidate rejection, not source approval |
| 21 | `invalid-root` | `PROV_SCHEMA_ROOT` | Structural or cross-candidate rejection, not source approval |
| 22 | `unexpected-method` | `PROV_SCHEMA_METHOD` | Structural or cross-candidate rejection, not source approval |
| 23 | `wrong-count-type` | `PROV_SCHEMA_TYPE` | Structural or cross-candidate rejection, not source approval |
| 24 | `not-four-candidates` | `PROV_BATCH_SHAPE` | Structural or cross-candidate rejection, not source approval |

All **24 negative rejection cases were owner-verified** on CARTHAGE (in addition to two pending-only positive controls). The validator distinguishes missing fields from wrong types, malformed schema fields from inconsistent cross-candidate collections, and invalid repeat packet/question pairs from valid multi-question frames.

The test originally targeted a deliberately missing helper as a RED-first design. The helper was subsequently implemented, and the exact synthetic validator matrix reached GREEN at `3ae94ba`. The `-AuthorizedTestTime` flag remains a required guard for any later rerun; missing-implementation diagnostics describe the historical design phase, not the current code.

### Expected safe error behavior

All negative failures should use bounded constant error codes such as `PROV_SCHEMA_VERSION` or `PROV_BATCH_SESSION_COLLISION`, with **no appended private values**. The test's error-path scanner looks for private source IPs, client/session markers, capture filenames, hashes and source URLs, and rejects accidental leakage. The positive response must have exactly five harmless metadata fields. Neither positive nor negative result should claim evidence approval.

## 6. Atomic candidate publication — implemented and synthetically verified in Stage 6E

**The existing importer remains unchanged. The separate V2 private publisher has since been implemented and verified on synthetic pending-only batches. The following is its original acceptance contract; see Stage 6E/6F/6G for observed tests and limits.**

Recommended API boundary: `Publish-HoldoutV2CandidateBatch -ValidatedCandidates -PrivateOutputDirectory` with a distinct protected root under `build-verify`. Never accept an arbitrary absolute or redirected path outside that root.

A proper publication transaction is:

1. **Preflight, no writes:** canonicalize the private root and target; reject traversal, unexpected reparse points/symlinks, path collisions and existing destination batches. Check the four slots and complete schema; validate source identity and reviewed-attestation requirements appropriate to the stage. Compute source hashes without modifying PCAPs.
2. **Prepare an isolated sibling directory** on the same filesystem with a random, unguessable `.pending-<id>` name under the private output root. Never replace or delete an existing batch or old evidence.
3. **Write all four sample JSON and four provenance sidecars to the pending directory**, without printing reversible data. Ensure the correct private file permissions and no other process can treat `.pending-*` as ready.
4. **Flush, close and reread** all eight files; verify shape, byte hashes, count, candidate names and complete cross-file correspondence. A sidecar without its matching sample must fail. Preserve per-capture hash references rather than duplicating PCAP content.
5. **Commit by one same-filesystem directory rename/move** to a previously nonexistent final batch folder. The auditor must consume only a complete named directory, never the pending scratch path. Same-volume directory renames are intended to avoid exposing individual half-written files; verify actual Windows filesystem behavior during authorized testing. Do not promise crash durability purely from atomic metadata rename.
6. **Rollback on any pre-commit failure:** remove only this invocation's uniquely owned pending folder. Do not delete source PCAPs, preexisting batches, frozen manifests, or unrelated local files. On uncertain post-commit failure, quarantine/report instead of assuming publication succeeded or destructively retrying.
7. **Idempotent retries:** refuse to overwrite a final folder. A retry must use a new unique stage and must not reuse an old audit success as a new approval.
8. **Admission separated from publication:** even a complete private batch remains `PENDING_EXTERNAL_CAPTURE_AND_REVIEW` unless a separately authenticated human review and explicit freeze decision are recorded.

The current flat-path auditor already accepts a `-CandidateDirectory` argument; a future integration may point it at the committed batch folder without changing the frozen manifest. Do not silently alter its current behavior to accept pending directories.

### Atomic publisher fault-injection contract — executed (18/18)

Prepare a separate transaction harness (after schema RED/GREEN) that simulates failure at: preflight; writing sample 2/4; writing provenance 3/4; flush/reread mismatch; permission denial; target-already-exists; directory rename failure; and post-move status uncertainty. For every **pre-commit** failure, require that the destination batch is absent and no unrelated file changed. For post-commit uncertainty, require manual reconciliation and no destructive overwrite. Also verify two concurrent writers cannot both claim the same target.

Fault injection may only modify synthetic private temporary files on explicitly approved CARTHAGE test time. It must not read real external PCAP, run detectors or mutate the V1/V2 manifests.

## 7. Execution record and originally planned RED/GREEN gates

- **Observed gate:** the owner explicitly ran the private synthetic provenance matrix on CARTHAGE; 2 pending-only controls and 24 negatives passed at `3ae94ba`. CI, real PCAPs, external admissions and automatic promotion were not authorized.
- **First authorized gate:** verify the exact code SHA, PowerShell 5.1, the 2020-12 schema parser, the four-slot manifest, and original V1 constraints. Check that every static test vector conforms to its intended positive/negative class; failures in the harness or schema engine are **not** security RED.
- **Historical RED-first plan (completed for the validated synthetic scope):** run the private schema contract; observe missing module/API and then genuine independent validation failures. Do not report a successful suite until the implementation meets all type/collision/privacy expectations.
- **GREEN phase:** implement minimal pure validator without changing the legacy importer or frozen evidence, run focused regression with exact error identifiers and verify no input mutation, auto-approval or privacy leakage.
- **Transaction GA (completed within synthetic scope):** GA 6E's 18 publisher cases and GA 6F's 3 writer-contending rounds were independently owner-verified. Actual crash durability and adversarial permissions remain open.
- **Production admission:** source licensing, malicious classification, original client provenance and Holdout V2 freeze require separate human authority. No algorithmic syntactic validation implies permission.
- **Evidence ledger format:** date, code SHA, schema SHA, host, interpreter version, test case ID, expected vs observed error, sanitized exit status, count/hash summary, privacy review and next approval gate.

### Owner-gated regression command (already verified; no need to rerun without code changes)

```powershell
powershell.exe -NoProfile -File .\scripts\verify-v2-provenance-schema-contract.ps1 -AuthorizedTestTime
```

**Historical authoring precaution:** execution requires explicit owner authorization; prior successful runs do not grant standing permission for future tests.

## 8. Non-negotiable safety and compatibility constraints

- Preserve R102 80% confidence, R118 86%, R163 84%, V2 R102 acceptance minimum 0.75 and all Shadow/Disabled, cooldown, baseline, privacy and journal controls.
- Preserve frozen V1 and its documented R102 missing transport-attribution cases; never rewrite V1 evidence to appear passing.
- Preserve the eight V1-derived R118/R163 V2 slots by exact immutable blob, with four R102 placeholders unapproved (0/4).
- No new automatic GitHub Actions or parallel workflow definitions.
- No irreversible branch deletion or merging as part of this stage.
- Keep all private PCAPs and reversible DNS names out of Git, public telemetry, default serialization and ordinary logs.

**Historical status at initial commit:** schema and tests were authored before the modules existed. **Current verified status:** Stage 6D 26/26 and Stage 6E 18/18 synthetic checks GREEN; real source approval remains pending.

## References

- JSON Schema Draft 2020-12: https://json-schema.org/draft/2020-12
- RFC 1035 DNS wire format: https://www.rfc-editor.org/rfc/rfc1035
- RFC 4343 DNS case-insensitive identity: https://www.rfc-editor.org/rfc/rfc4343
- RFC 4648 canonical Base64: https://www.rfc-editor.org/rfc/rfc4648
- Local auditor and importer: `scripts/audit-holdout-v2-candidates.ps1`, `scripts/import-holdout-v2-r102.ps1`.


## GA 6E handoff — source implemented and synthetic 18/18 verified

The Stage 6E handoff was subsequently implemented and verified **18/18** under owner-authorized Windows synthetic tests at `c5174da`; the original design script is `scripts/verify-v2-atomic-publication-contract.ps1`. Details and boundaries are in `docs/STAGE6E_ATOMIC_V2_PUBLICATION_FAULT_CONTRACT_20261029.md`.

The implemented test exercises a **module-private** fault-injectable publisher core and pure non-writing batch-name validator; both now exist in `scripts/HoldoutV2CandidatePublisher.psm1`. Stage 6E defines one private unpublished-to-holdout control and 17 failure/exception cases covering eight precommit faults, postcommit uncertainty, existing-target protection, four pure unsafe filename tests and three invalid batch forms. It checks exact eight-file sample/provenance contents and denies any automatic approval. No existing importer/auditor, V1/V2 manifest, workflow or threshold has been changed.

Stage 6D's private schema checks were independently confirmed GREEN before interpreting Stage 6E's later publisher result. The dependency remains mandatory for any future versioned schema change. Neither a file committed to GitHub nor an authored failure callback is proof of a real Windows filesystem result. Bounded two-writer contention **3/3** and sampled-reader visibility **3/6/12** are now verified on synthetic Windows tests; crash/power-loss durability, arbitrary ACL denial, and symlink/reparse-point race attacks remain separate unverified acceptance work. These synthetic suites were later executed by the owner and recorded in `docs/DEVELOPMENT_VALIDATION_LEDGER.md`; no tests were run merely to refresh this document.

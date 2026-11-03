# GA 6 — Legacy V2 importer/auditor enforcement contract (not yet verified)

**Current status (2026-10-30): PENDING — separate legacy auditor enforcement harness has NO independently recorded Windows PASS.** The successfully completed GA 7 binary DNS/TShark and V2 frame/question tests (`e412c2a`) verify the **new private source binder**, not this legacy `dns.qry.name` importer/auditor implementation. GA 8 compatibility is independently GREEN (`9f709d0`), but it does **not** migrate or certify the old auditor. This distinction is intentional: retain this contract as an open test until the owner runs and verifies this exact harness.

Date: 2026-10-29  
Branch: feature/carthago-reliability-hardening  
Execution: separately owner-gated; the legacy auditor contract has not been verified. The sections below retain the historical RED-first design, not a synthetic PASS.

## Verified existing behavior
Read-only inspection of scripts/audit-holdout-v2-candidates.ps1 shows that the auditor:
- Requires four external slots, two benign and two malicious, and preserves R102 confidence floor 0.75.
- Checks selected frame numbers, original PCAP SHA-256, a strict eleven-field legacy record schema and selected TShark text output.
- Rejects duplicate capture SHA/frame keys across candidates.
- Checks distinct source IPs for malicious samples, but does not prove distinct originating clients or sessions.
- Compares dns.qry.name text, not exact binary label octets; it does not bind a question ordinal.
- Checks analystReviewedLabel as truthy, and HTTPS licensing references, but neither proves actual analyst decision nor source rights.
- Prints certain capture filenames, source names and TShark errors; review for privacy before production use.

## RED-first behavior-level regression matrix
All fixtures synthetic, generated in an isolated temporary directory, removed in finally. No real capture, no live traffic, no uploads.
A valid four-slot control fixture must pass packet attribution without approving labels, licensing, independence or V2 freeze.
Mutation cases, each run independently against the actual auditor entry point:
A01 mirrored complete QNAME sets across different IPs => reject as independent malicious clients.
A02 same collectionSessionId across malicious candidates => reject.
A03 same originatingClientLabel across malicious candidates => reject.
A04 same capture SHA and frame/question reference across slots => reject.
A05 same capture frame but different question ordinal => only accept if explicitly bound and distinct, with independent source review still pending.
A06 changed canonical Base64 label bytes => reject against original frame.
A07 invalid or noncanonical Base64 => reject.
A08 wrong question ordinal, QTYPE, UDP/TCP attribution or ports => reject.
A09 absent original capture or altered SHA => reject.
A10 missing/unknown collection vantage or unreviewed source attribution => reject.
A11 missing source license or label decision => reject; HTTPS URL alone cannot establish approval.
A12 unexpected private fields in sample or provenance => reject.
A13 distinct name sets and sessions => still NOT auto-approve independence.
A14 benign candidate mislabeled malicious or altered expected matches => reject.
A15 log/output privacy: no raw QNAME, reversible Base64, source IP or unredacted TShark diagnostics.
A16 exact 2 benign + 2 malicious and minimum 3 distinct >=50-octet TXT labels per malicious case, measured from decoded bytes, not Base64 length.

## Implementation boundary
Keep frozen V1 and existing fixture hashes unchanged. Do not edit R102 threshold or promote V2.
Prefer reusing Read-DnsWireQuestion and Confirm-DnsWireCandidateBinding from the approved private decoder module, and Measure-DnsWireMaliciousSourceIndependence for advisory risk flags.
Extend the actual auditor/importer so these decisions are enforced, not merely reported by a helper.
Preserve legacy ASCII compatibility; version new binary records explicitly and reject conflicting representations.
Fail closed on missing provenance, malformed packet, ambiguous question or unsupported schema.
Never treat synthetically generated provenance as independent malicious ground truth.

## Parked validation
1. Stage 1–5 RED/GREEN must be completed sequentially under explicit owner test-time authorization.
2. Build a synthetic four-slot harness that invokes the actual audit script and checks each A01–A16 exit code and sanitized output.
3. Observe RED before modifying auditor/importer; record exact SHA, Windows hostname, TShark version, failures, hashes.
4. Implement minimal enforcement, observe GREEN, then perform focused V2 contract checks.
5. Only after owner approval evaluate full regression and separately review source rights, malicious labels, logical-client independence and freeze readiness.

## Evidence reporting template
Commit SHA | file | scenario | expected | observed | exit code | evidence hash | privacy review | status (PARKED/RED/GREEN/FAILED).
No test has been executed for this document.

References:
https://www.rfc-editor.org/rfc/rfc1035
https://www.rfc-editor.org/rfc/rfc2181
https://www.rfc-editor.org/rfc/rfc4343
https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow


## Implemented preparation — 2026-10-29, commit 6aa9f01

File: `scripts/verify-v2-auditor-enforcement.ps1`. This is a **parked executable regression harness**, not an executed or certified test. It is not wired to a CI trigger, and has an explicit `-AuthorizedTestTime` switch. The owner's separate conversational approval remains mandatory.

### Actual entry point and fixture layout
The harness calls `scripts/audit-holdout-v2-candidates.ps1` as a child PowerShell process, supplying `-CaptureDirectory`, `-CandidateDirectory` and `-TsharkPath`. It reads the actual V2 manifest to obtain the four fixed names and classifications rather than guessing the entry order. It writes four raw-linktype IPv4/UDP DNS PCAPs, each containing three TXT questions, and corresponding `.json` and `.provenance.json` files in a random OS temporary directory. No network interface is opened, no PCAP is downloaded, no real client IP is used, and no private evidence is committed.

All filenames are generated by the harness. Each name, destination and source address is synthetic, with RFC 5737 documentation networks. The malicious fixture labels contain 56 ASCII octets before the suffix, satisfying the current **text-based** minimum length, but **not proving malicious truth**. Provenance fields deliberately carry `synthetic-only` review markers: they are sufficient only to exercise current packet-attribution syntax. Neither an HTTPS example URL nor a self-declared reviewed flag constitutes real licensing or classification evidence.

### Executable subset and expected behavior
| Case | Mutation | Expected | Current predicted outcome / caveat |
| --- | --- | --- | --- |
| BASELINE | Four internally consistent synthetic candidates | Auditor exits zero (attribution-only) | Not observed; synthetic metadata must never be taken as real approval |
| A01 | Mirror the complete three-name malicious QNAME set, with distinct IPs and source captures | Reject independence | Known risk: legacy auditor only checks distinct malicious IPs |
| A02 | Duplicate malicious collection session IDs | Reject independence | Known risk: existing auditor does not check session ID |
| A03 | Duplicate malicious originating-client labels | Reject independence | Known risk: existing auditor does not check origin ID |
| A06 | Change one serialized TXT QNAME without altering original packet | Reject | Existing auditor should detect byte/text disagreement for ASCII names |
| A09 | Replace the declared SHA-256 | Reject | Existing capture-hash check should detect this |
| A11 | Clear analyst-reviewed flag | Reject | Existing metadata check should reject |
| A12 | Add one forbidden private record field | Reject | Existing eleven-field allowlist should reject |
| A14 | Change malicious expected match to R118 | Reject | Existing expected-rule check should reject |

**Important RED criterion:** First establish that the control fixture passes the unmodified auditor and TShark produces expected fields. If baseline fails due to fixture construction, TShark format, PowerShell parsing, script-interface drift, or environmental dependency, that is a *harness defect*, **not an observed security RED**. Only then count A01/A02/A03 correctly reported failures as behavior-level RED. The harness deliberately uses hard failure if the observed exit category differs from the expected outcome. Execution has not occurred.

### Deferred coverage, not falsely marked complete
The initial executable subset does not implement A04/A05/A07/A08/A10/A13/A15/A16 fully. In particular, same-frame/different-question semantics, canonical Base64, binary label length, privacy-output capture inspection, and unreviewed licensing cannot be validated through the current legacy eleven-field ASCII schema alone. Those require Stage 1–5 codec/provenance APIs and an explicit versioned V2 schema. Add them to this same harness after those dependencies are verified; do not claim the entire 16-case matrix passes.

### Privacy and machine safety
The child auditor's stdout/stderr is redirected to a temporary private log and never printed on a normal run. The random directory and logs are deleted in `finally`, including after failures. This means failing logs are intentionally ephemeral; record metadata-only failure codes in the ledger, never upload raw PCAP or DNS names. No GitHub Actions workflow is dispatched; the centralized workflow remains unchanged. PowerShell 5.1 and TShark compatibility, synthetic IPv4 checksum and parser behavior remain **unverified** because tests are parked.

### Sequential validation gate, only once authorized
1. Verify CARTHAGE, TShark version, current repository commit, manifest/fixture hashes and no live capture.
2. Run `powershell.exe -NoProfile -File .\scripts\verify-v2-auditor-enforcement.ps1 -TsharkPath 'C:\Program Files\Wireshark\tshark.exe' -AuthorizedTestTime` only after explicit test-time approval.
3. Record baseline outcome, then A01/A02/A03 expected RED and legacy negative control outcomes separately.
4. Implement minimal auditor enforcement only after RED is captured, using source-bound frame/question bytes, session and logical origin review.
5. Repeat the focused harness for GREEN; only then add remaining A04–A16 and integrated V2 readiness validation. Keep V1 frozen and V2 at 0/4 approvals throughout.

### Known implementation hazards to review at test time
- Confirm PowerShell JSON serialization of empty `expectedMatches` arrays and numerical types matches the auditor's strict checks.
- Synthetic PCAP has no link-layer Ethernet header (DLT_RAW=101); independently confirm TShark decodes IPv4/UDP/DNS and returns exactly the selected fields.
- Confirm string source addresses and DNS names are compared without unintended whitespace/case changes.
- The current auditor has no output-privacy guarantee for unexpected TShark failures; never publish its unfiltered output.
- The harness uses a real child process for the actual auditor, but that does *not* mean the missing binary provenance/importer behavior is implemented.

Execution status: **PARKED — NOT RUN**. No RED/GREEN, precision, recall, F1, source license, classification approval or freeze claim.


## Stage 6B — reason-specific enforcement and privacy hardening (2026-10-29)

**Code commits:** `d4cbdca` (expanded scenarios and strong assertions) and `05e5dda` (explicitly typed empty benign expectation arrays). The code change extends `scripts/verify-v2-auditor-enforcement.ps1` exclusively; no production rules, real samples, manifest, source capture, CI workflow or audit implementation was changed.

**Execution:** PARKED / NOT RUN. The following describes expected, *not observed*, results. GitHub accepting a commit is not evidence that PowerShell parses, TShark decodes the synthetic captures, or the checks pass.

### Why the previous exit-code-only harness needed hardening

Previously, each negative case required only a nonzero child process exit. Any unrelated failure (missing TShark, malformed synthetic PCAP, broken JSON cardinality, an incidental interpreter error, or the same wrong upstream validation failing first) could accidentally satisfy the expectation. That would produce a **false GREEN** for a security safeguard that had not actually been exercised.

The new `Get-ExpectedReason` mapping requires a privacy-safe failure reason that corresponds to the intended invariant. `InvokeAudit` checks BOTH the exit category and the reason from an ephemeral private log. An expected reject with the wrong reason now fails the harness. The success control requires the auditor's `SOURCE AUDIT COMPLETE:` marker and explicitly rejects text claiming approval, promotion, freezing, or verified independence. This does not make the current auditor secure; it makes the future test outcome more interpretable.

### Expanded scenario-by-scenario execution matrix

The explicit current invocation sequence contains **two attribution-only success controls** and **15 rejecting mutations**. Each mutation regenerates all four files/sources in an isolated directory, invokes the *real* auditor with its unmodified entry point, and compares the child process outcome with the expected result.

| Case | Synthetic mutation and attack/failure boundary | Required private-safe diagnostic | Expected result |
| --- | --- | --- | --- |
| BASELINE | Two benign and two malicious fixed manifest names; three selected UDP/TXT frame records per slot; valid original capture hash | `SOURCE AUDIT COMPLETE:` | Accept **packet attribution only** |
| A13 | Separate synthetic source/session/name sets, same valid control as BASELINE | `SOURCE AUDIT COMPLETE:` | Accept **packet attribution only**, not independence |
| A01 | Mirrored full malicious TXT QNAME set in two different synthetic source IPs and captures | `SOURCE_INDEPENDENCE_MIRROR` | Reject; missing in legacy auditor |
| A02 | Distinct malicious source IPs but repeated `collectionSessionId` | `SOURCE_SESSION_COLLISION` | Reject; missing in legacy auditor |
| A03 | Distinct malicious source IPs but repeated `originatingClientLabel` | `SOURCE_ORIGIN_COLLISION` | Reject; missing in legacy auditor |
| A04 | Copy benign slot 0 PCAP bytes and record contents to benign slot 1 while preserving each slot's unique filename/sample identifier | `same original PCAP packet frame reused` | Reject based on global SHA/frame reuse, **not** malicious source IP |
| A06 (legacy) | Change one text `dnsQname` without changing captured packet | `serialized record differs from decoded PCAP` | Reject byte/text mismatch for **legacy printable** name only |
| A08-qtype | Alter one TXT record's reported DNS type to A | `serialized record differs from decoded PCAP` | Reject |
| A08-port | Alter one selected frame's source port in the JSON record | `serialized record differs from decoded PCAP` | Reject |
| A09 | Replace declared original PCAP SHA-256 with all zeroes | `original PCAP SHA-256 mismatch` | Reject |
| A09-missing | Remove one local synthetic PCAP after writing its provenance | `original capture missing` | Reject; never trust JSON alone |
| A10 | Use an unrecognized `collectionVantage` while keeping other metadata consistent | `SOURCE_VANTAGE_UNREVIEWED` | Reject; missing in legacy auditor |
| A11 | Clear the boolean analyst review flag | `incomplete external attribution or label review` | Reject syntactically; does not verify real human review |
| A11-license | Set the source license token to `Unlicensed` | `incomplete external attribution or label review` | Reject syntactically; does not verify rights to an apparently valid license |
| A12 | Add an unreviewed private field to a serialized packet record | `DNS packet record has missing, extra or invalid typed fields` | Reject via existing legacy allowlist |
| A14 | Replace expected malicious match `R102` with `R118` | `R102 malicious expected rule/confidence was altered` | Reject |
| A16-distinct | In malicious slot 2, place the *same* valid long TXT name in frames 2 and 3 while keeping their PCAP bytes and JSON records aligned | `R102 malicious encoded-TXT requires three distinct captured TXT` | Reject: only two distinct names, no fabricated record/PCAP mismatch |

The A04 benign-to-benign mutation is deliberate. If both malicious candidates reused one capture, the auditor's older distinct-source-IP check could reject the fixture **before** the global frame-reuse safeguard was reached; that would hide which invariant actually triggered. This regression isolates global frame reuse from the separate malicious-source requirement.

The A16 mutation is also deliberate: the repeated name is written into the **PCAP and its serialized record**, not just the JSON. A negative result should therefore be caused by distinct-name cardinality, not a generic packet mismatch.

### Semantic output and privacy assertions

For *every* child invocation, `Assert-PrivateAuditOutput` reads the temporary log, extracts the synthetic candidate QNAMEs and source addresses from the corresponding private fixture files, and fails if any of those values, or the synthetic destination address, appear verbatim in output. Comparisons use ordinal case-insensitive substring checks so case changes cannot bypass the assertion.

Only metadata-only progress and failure categories can be printed to the ordinary console. The underlying child process output is neither uploaded as a workflow artifact nor emitted in an exception. The randomly named scratch directory is removed under `finally`, including on failure. The checker does **not yet** prove that all other sensitive material (for example a raw hex dump, unfamiliar TShark diagnostic syntax, real future client identifiers or credentials) is redacted; that requires a separately authorized and expanded A15 review after decoder integration.

**Stable future failure codes:** The four new unimplemented enforcement gates A01, A02, A03 and A10 each require an explicit constant diagnostic identifier. These codes must carry no origin labels, source IPs, session IDs, DNS QNAMEs, Base64 names or PCAP paths. If implementation chooses a different code, change the contract with a documented reason rather than broadening it to accept any nonzero exit.

### Static correctness refinement — PowerShell JSON empty arrays

The prior fixture used pipeline subexpressions like `expectedMatches=$(if (...) { ... } else { @() })`. A PowerShell empty pipeline can collapse to `$null`, accidentally yielding JSON `null` rather than `[]`, and could cause a false baseline failure. Commit `05e5dda` now assigns explicitly typed `[string[]]` expectation arrays before JSON serialization. Their runtime representation and compatibility with Windows PowerShell 5.1 remain unverified until the first authorized run.

### Dependencies and deferred evidence — do not report as completed

- **A05:** Multiple QNAMEs in one captured frame with distinct *question ordinals* requires the lossless decoder/explicit `questionIndices`. The current auditor only tracks frame numbers and first textual QTYPE.
- **A06 binary variant / A07:** Noncanonical and conflicting per-label Base64 requires the new versioned binary-wire schema and decoder; the legacy A06 text mutation is only a partial safeguard.
- **A08 full:** The current addition checks legacy QTYPE and port, not an independently bound question ordinal or actual TCP reassembly.
- **A10 full:** The new vantage token rejection is a syntactic requirement, not independently corroborated capture-vantage identity.
- **A11 full:** A valid-looking HTTPS evidence URL or allowable license string is not evidence that a human actually reviewed source rights and classification. Keep external review separate.
- **A12 full:** The current check covers the packet record allowlist, not a complete versioned provenance allowlist.
- **A15 full:** Output assertions cover known synthetic QNAMEs/addresses and forbidden approval wording; unknown secrets and all error paths remain to be analyzed privately.
- **A16 binary variant:** A label of 50+ Base64 *characters* is not necessarily 50+ original DNS octets. Byte-length eligibility and entropy must be calculated from canonical decoded wire bytes when the codec is implemented.
- **Cross-client malicious truth:** Identical or disjoint QNAME sets alone cannot prove that two sources are independent clients; human evidence must remain mandatory, with V2 candidate approvals still 0/4.

### Exact future acceptance order (NOT authorization to run)

1. Verify the explicitly approved test window, CARTHAGE hostname, checkout SHA, Windows PowerShell 5.1 and installed TShark version. Ensure no live capture or external traffic, and use only synthetic local files.
2. Run the two controls first. If either fails, classify as a **harness/environment defect**, preserve a sanitized failure code and fix the fixture. Do not use that failure as an observed RED for R102/provenance.
3. Run legacy expected rejects A04/A06/A08/A09/A11/A12/A14/A16. Each must fail for its **specific** reason, not any incidental error.
4. Observe A01/A02/A03/A10 expected RED against the legacy auditor, after the controls and existing checks are sound. Record each outcome, exact code and commit.
5. Only then implement narrow production importer/auditor enforcement, preferably using shared original-frame binding and a review-only source-independence classifier; preserve frozen V1.
6. Re-run the same focused harness for GREEN, and prepare the remaining binary-only scenarios. Separate aggregate precision/recall/F1 and V2 admission from source syntax validation.
7. Update this document and the central ledger with version, results and exceptions. Do not freeze/promote a candidate without a new explicit decision.

**Next implementation priority:** audit hardening for human-reviewed logical origin, collection session and capture vantage, *after* a valid RED has been observed. The test-first dependency still applies; no production enforcement was written in this step.

**Current verification truth:** GitHub commits successfully published the code. No build, PowerShell execution, TShark processing, replay, GitHub Actions dispatch, source capture, malicious-label review or V2 promotion was performed. All newly added scenarios are **PARKED / UNOBSERVED**.


## Stage 6C — multi-source spoofing, type confusion and provenance schema (2026-10-29)

**Code commits:** `365db90` added five further synthetic mutations to the same existing auditor harness; `b20fd83` ensured the untrusted provenance key is inserted explicitly into the PowerShell ordered dictionary. No new workflow, live source, networking logic, R102 rule or existing holdout fixture was modified.

**Execution:** PARKED. This update records authored source and expectations only. No Windows PowerShell interpreter, TShark process, packet replay, compilation, live traffic, CI or holdout was executed. Test results, passing counts and security efficacy are **not** inferred from a GitHub commit.

### Threat model and reasons for extending the matrix

The legacy V2 auditor currently compares TXT names as normalized text and requires only different observed malicious source IP addresses. Because DNS identity is ASCII-case-insensitive (RFC 4343), a malicious-source mirror can appear different in captured byte capitalization and question order yet still comprise the same logical query set. An automated import must flag this, rather than treating differing IPs, casing, frame order or collection metadata as independently authenticated malicious clients.

Other risks lie in **asserted** provenance fields. A candidate might supply a blank originating-client label, an empty collection-session identifier, a truthy but non-boolean `analystReviewedLabel`, or an additional unreviewed JSON property. The current auditor can reject a known packet-record extra field but does not yet enforce a complete versioned provenance schema. A self-asserted HTTPS reference does not turn any such value into reviewed evidence.

### New executable synthetic cases

| Case | Exact synthetic input | Required reason | Why this is independently valuable |
| --- | --- | --- | --- |
| A01-case | Candidate slot 3 uses the same three distinct long TXT names as malicious slot 2, permutes frame order, writes upper-case labels and suffix bytes **only in the PCAP**, and retains lower-case canonical textual sample names. Source IP, capture hash and collection identifiers remain different. | `SOURCE_INDEPENDENCE_MIRROR` | Tests ASCII-only DNS identity and order-independent name-set overlap, not a superficial exact-string or same-packet equality check. The legacy auditor's existing lowercase textual comparison should permit frame-to-record agreement. |
| A10-origin | Empty `originatingClientLabel` on malicious slot 2, with the PCAP and all packet fields unchanged. | `SOURCE_ORIGIN_MISSING` | Explicit negative coverage of a missing logical-origin attribution, independent of differing source IPs. |
| A10-session | Empty `collectionSessionId` on malicious slot 2, without changing observed packet bytes. | `SOURCE_SESSION_MISSING` | A collection-session identifier cannot be replaced by packet source addresses or synthetic session assumptions. |
| A11-review-type | Use the nonempty JSON string `"yes"` instead of the boolean `true` for `analystReviewedLabel`. | `SOURCE_REVIEW_FIELD_INVALID` | Defends against truthiness coercion (`-not` on a nonempty string), without pretending any syntactically valid boolean constitutes real human approval. |
| A12-provenance | Add `unreviewedImportedDebug` to the provenance object on malicious slot 2; preserve otherwise complete four-slot fixture. | `SOURCE_PROVENANCE_SCHEMA_REJECTED` | Detects unexpected provenance fields separately from the existing eleven-field packet-record allowlist. Insertion uses `$p['unreviewedImportedDebug']` so a new ordered dictionary key is unambiguously persisted. |

The complete prepared inventory is now **two attribution-only success controls** (`BASELINE`, `A13`) and **20 mutation invocations**: fifteen from Stage 6B plus five new ones. This is **22 planned child-auditor invocations**, not 22 passing tests. The existing Stage 6A/B cases remain unchanged and still require exact reason-specific rejection.

### Boundaries of what these tests prove

1. **Mirroring detection, not malicious truth.** Even if the mirror flag is absent for disjoint names, no candidate gains independent-client approval; manual source/session evidence must still be reviewed.
2. **ASCII case folding, not Unicode normalization.** Only DNS ASCII A–Z map to a–z; non-ASCII original octets remain byte-distinct. The binary-octet variant stays in `verify-dns-wire-source-contract.ps1` and cannot be claimed GREEN until the independent decoder is implemented and validated.
3. **Reported provenance, not authenticated origin.** A nonempty client/session field is necessary but insufficient. The future enforcement must correlate independently reviewed collector/session evidence and may need the source-capture root, vantage and timestamp. No automatic approval from syntactic completeness is allowed.
4. **Typed review fields, not authorization.** Reject a string masquerading as a boolean, then separately assess licensing and analyst identity through a controlled human review workflow. A stored `true` cannot prove the review happened.
5. **Fail-closed schema discipline.** The envisioned strict provenance schema must list required and permitted fields, input versions, data types, cardinalities and allowed values; it should reject extras rather than silently ignore attacker-controlled metadata. The old legacy JSON format remains protected by an explicit version/compatibility boundary, not silent auto-upconversion.
6. **No accidental RED from malformed fixtures.** Before any authorized run, the BASELINE control and A13 must complete with expected packet attribution. If either fails due to TShark output, PowerShell 5.1 serialization, packet construction or other environmental causes, do not credit subsequent negative outcomes as a security regression.
7. **No information leaks.** The harness continues to scan the temporary child stdout/stderr for synthetic DNS QNAME and client/destination IP strings. This is partial privacy coverage, not a complete guarantee for unknown labels or binaries. Keep raw logs local and ephemeral.

### Required diagnostic contract after production implementation

The target auditor should produce one stable code without user-provided contents for each missing safeguard: `SOURCE_INDEPENDENCE_MIRROR`, `SOURCE_ORIGIN_MISSING`, `SOURCE_SESSION_MISSING`, `SOURCE_REVIEW_FIELD_INVALID`, and `SOURCE_PROVENANCE_SCHEMA_REJECTED`. Existing Stage 6B codes `SOURCE_SESSION_COLLISION`, `SOURCE_ORIGIN_COLLISION` and `SOURCE_VANTAGE_UNREVIEWED` remain.

A future helper must not use observed IP inequality as its sole evidence of independent clients. It must not output reversible labels, per-client identifiers, session IDs, PCAP paths, debug payloads or source URLs. A clean audit verifies packet attribution and structural controls only; it never promotes V2.

### Deferred implementation and test-time procedure

- Obtain a **separate explicit user approval** before any execution. The `-AuthorizedTestTime` switch is procedural and not permission on its own.
- First confirm the baseline synthetic fixture and TShark environment, then check the legacy rejection reasons A04/A06/A08/A09/A11/A12/A14/A16.
- Record each new Stage 6C expected RED from the actual legacy auditor in the private CARTHAGE evidence ledger. If a case unexpectedly rejects for another reason, count it as *harness/contract failure* rather than security RED.
- Only after valid RED may the source-auditor enforcement be implemented; keep human-reviewed independence and source/license proof as separate, explicit approvals. Observe GREEN on the same frozen synthetic vectors, then extend binary wire tests.
- Record exact Git commit, Windows hostname, TShark version, SHA-256, permitted aggregate counts, exit codes and sanitized error identifiers. Preserve failed V1 and V2 `PENDING_EXTERNAL_CAPTURE_AND_REVIEW` with **0/4** approved R102 candidates.

**Completion status: authored only.** The next highest-value non-executing preparation is to specify the exact versioned V2 provenance allowlist and the importer/auditor rollback guarantees without editing the production path before RED.

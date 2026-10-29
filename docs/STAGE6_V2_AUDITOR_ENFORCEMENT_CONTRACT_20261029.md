# Stage 6 — V2 importer/auditor enforcement contract (PARKED)
Date: 2026-10-29
Branch: feature/carthago-reliability-hardening
Execution: NOT AUTHORIZED. This document is a specification, not a passing test.

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

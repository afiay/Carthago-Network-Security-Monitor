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

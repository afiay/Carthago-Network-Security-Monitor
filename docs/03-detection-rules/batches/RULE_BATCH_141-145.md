# R141-R145 typed TLS handshake and certificate precision

**CANDIDATE - UNVERIFIED (2026-10-27).** Six source files and six test
files authored, including five rule implementations, one shared evidence/window
contract, five advanced xUnit classes (eight cases each), and an isolated
fixture. **40 tests authored; zero executed.** No build, benchmark, frozen
holdout, GitHub Actions or Windows runner was invoked.

| Rule | Candidate production refinement | Advanced cases authored |
| --- | --- | --- |
| R141 | Require typed TCP/TLS, a handshake-sourced SNI, a bounded observed JA3/JA4 fingerprint, externally attributed socket and three independently observed records from the same source+SNI+fingerprint. Bounded instance-owned replay window resists duplicate packet IDs. This remains a repeat candidate, NOT proven rarity or first seen. | Three positives; duplicate ID; source isolation; SNI isolation; contradictory UDP; packet-Info fingerprint decoy; conflicting SNI fields; browser traffic. |
| R142 | Require typed TCP/TLS, explicit consistent SNI, an external observed socket and bounded certificate subject before applying the existing conservative subject/SNI root mismatch heuristic. Redact certificate DN from event evidence and hash cooldown identity. Subject mismatch does NOT prove failed SAN validation. | Positive different-root CN; benign same-root; covering wildcard; internal socket; HTTP-host-only; conflicting SNI; UDP; DN privacy and Shadow floor. |
| R143 | Require typed TCP/TLS and certificate subject, not a sensitive port or packet description alone, before inspecting wildcard subjects on sensitive management/auth/database ports. Redact certificate subject and hash cooldown identity. | Positive wildcard on 5986; ordinary HTTPS; ordinary CN; missing TCP; Info-only wildcard; QUIC; SYN-only; privacy/Shadow floor. |
| R144 | Require typed TCP/TLS, external socket and ordered bounded certificate dates. Preserve the existing >=825-day validity threshold; reject missing, reversed and unreasonable date intervals. Hash cooldown identity. | Ten-year positive; ordinary lifetime; missing dates; reversed dates; internal socket; UDP; plain TCP decoy; numeric evidence/Shadow floor. |
| R145 | Require typed TCP/TLS, explicit SNI, observed fingerprint, external socket and <=30-day certificate interval. Count only three independent observations from the same source, fingerprint, SNI AND certificate validity interval. Candidate does not establish SNI novelty. | Three positives; duplicate ID; source isolation; changed certificate interval; 90-day cert; browser; missing dates; UDP/SNI contradiction plus Shadow floor. |

## Source integrity, state and privacy

- The shared `NetworkBatch141145Evidence.TlsSession` composes the existing
  strict R136-R140 transport contract with source/destination IP family,
  bounded service port, UTC timestamp and mutual SNI consistency checks.
  UDP, QUIC, HTTP-only, DNS-only, SYN/FIN/RST-only and packet-Info guesses
  must not manufacture TLS handshakes.
- The shared `NetworkBatch141145Window` is instance-owned, bounded to
  1,024 keys and 256 packet identities per key, window-scoped and
  duplicate-ID resistant. Out-of-order observations cannot advance counters.
  This still needs later Windows concurrency and expiry validation.
- R141/R145 use source-scoped keys rather than the original shared global
  timestamp map; a second host or client does not help an unrelated session
  reach the threshold.
- R142/R143 emit `tls.certSubject=[REDACTED]` rather than a raw DN.
  Cooldown keys hash the relevant identity. SNI/JA4 fields still appear in
  the existing shared TLS evidence builder; broader privacy policy and
  telemetry access control remain separate concerns.
- No precision floors, runtime mode defaults, per-rule thresholds, baseline
  or asset approvals, frozen holdout blobs/labels, or policy gates changed.
  R141/R145 remain Candidate/Shadow. R142-R144 remain Shadow by default.

## Deferred acceptance and limitations

The original `Carthago.Tests/TlsPkiPrecisionRuleTests.cs` legacy positive/
negative expectations were retained. New files
`R141AdvancedAccuracyBatchTests.cs` through
`R145AdvancedAccuracyBatchTests.cs` are discoverable by the existing
single deferred verifier `scripts/verify-all-rule-batches.ps1`.

No test has been run for this batch. Inspect actual capture-adapter support
for `IsTcp`, `Sni/TlsSni`, parsed fingerprint fields and certificate
subject/date pairs during the next user-authorized validation. Missing
telemetry can produce false negatives; R142's CN comparison cannot
independently decide SAN coverage. Stable JA3/JA4 and short-lived
certificates are common in authorized applications. Candidate logic must
not be promoted based on crafted test fixtures alone.

Frozen V1 synthetic holdout remains FAILED at **4/6** due to R102
transport attribution. V2 remains pending independent licensed captures,
labels and approval. No change to either holdout.

**Next contiguous five-rule batch: R146-R150.**

## Static fixture correction after code review

`TrafficRecord.Sni` and `TrafficRecord.TlsSni` share the same
backing property; setting them to different values in one record cannot
represent independently conflicting parser fields. The affected
R141/R142/R145 tests were corrected to assert *real* contradictory
HTTP metadata on an attributed TLS record. This does not adjust any
detector, precision threshold or runtime policy. Tests remain **UNEXECUTED**.

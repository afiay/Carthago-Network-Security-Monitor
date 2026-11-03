# R136-R140 HTTP session/recovery and TLS certificate precision

**CANDIDATE - UNVERIFIED (2026-10-27).** Source and 40 xUnit facts authored,
zero executed. The current deferred Windows entry point remains
`scripts/verify-all-rule-batches.ps1` (unchanged). No CI, Windows runner,
benchmark, holdout or local build was invoked.

| Rule | Production changes | Eight advanced cases authored |
| --- | --- | --- |
| R136 | Requires attributed TCP cleartext HTTP and an actual request Cookie header with a known session name and plausible opaque value. Ignores Set-Cookie in request metadata and raw Info. Redacts request paths and cookie values. | Valid session, HTTPS, UDP/missing TCP, analytics/Info-only, placeholders, Set-Cookie-only, spoofed header name, privacy/Alert floor. |
| R137 | Requires POST/PUT/PATCH to a bounded set of recovery/enrollment action paths. Counts unique packet IDs in an instance-owned bounded time window keyed by source, host and hashed route; redacts route and query. | Eight independent submissions, GET-only, unrelated POSTs, duplicate ID, host isolation, expiry, transport contradiction, enrollment privacy/Shadow floor. |
| R138 | Requires typed TLS/TCP, an actual external destination IP and exact issuer/subject DN equality; does not equate shared CNs with identical DNs. Suppresses raw DN evidence. | Self-issued indicator, trusted CA, internal IP, spoofed external SNI, UDP/missing TCP, Info-only, different organizations, privacy/Shadow floor. |
| R139 | Requires typed TLS/TCP and exact weak-version values in the parsed TlsVersion field, not offered-version text or port/Info guesses. Emits normalized version evidence. | TLS1.0, TLS1.1/SSLv3, modern versions, offered-only text, Info/port-only, UDP/QUIC/missing TCP, HTTP contradiction, Alert floor. |
| R140 | Requires typed TLS/TCP and an exact suspicious issuer CN from the parsed certificate issuer DN. Does not match arbitrary issuer substrings or OU labels; redacts DN. | Mitmproxy CN, public CA, partial substring, suspicious OU only, Info-only, transport contradiction, HTTP contradiction, privacy/Shadow floor. |

## Evidence and safety boundaries

- R136 does **not** persist raw cookie values. A request Cookie header
  demonstrates session material in HTTP traffic; it does not prove a stolen
  or replayed session. The capture adapter must actually populate
  `HttpRequestHeaders`; `Info` text is not accepted as a substitute.
- R137 counts observed submissions, not confirmed password resets, MFA
  enrollment successes or unique affected identities. Real helpdesk waves
  and replay semantics require operational review. Its bounded state is
  per rule instance and packet-ID deduplicated, including out-of-order
  telemetry rejection.
- R138's matching issuer/subject names indicate a **self-issued**
  certificate, not cryptographic proof of self-signing or lack of trust.
  The destination boundary is based on the observed IP, not an unverified
  SNI string. Actual certificate validation remains out of scope.
- R139 assumes `TlsVersion` is the negotiated TLS version from the
  parser. TLS record-layer legacy_version or client-supported_versions
  must **not** be mapped to this field as negotiated version. TLS 1.3
  compatibility bytes are not evidence of TLS 1.2 or TLS 1.0 negotiation.
- R140's issuer names are weak anomaly heuristics, not a proof of MITM.
  Sanctioned QA/interception infrastructure may match. No raw DN is
  emitted in rule-owned evidence.
- R138-R140 TLS classification requires explicit TCP and coherent TLS
  protocol labels. QUIC, UDP, HTTP request metadata and contradictory
  labels are rejected; packet descriptions and ports alone cannot qualify.
- Shared event building excludes R136/R137 raw HTTP paths; cooldown
  keys use route or issuer fingerprints. Existing confidence floors,
  default modes, threshold settings, approval gates, baseline-readiness
  checks and frozen holdout content were not modified.

## Deferred acceptance and known risks

The five new classes
`Carthago.Tests/R136AdvancedAccuracyBatchTests.cs` through
`R140AdvancedAccuracyBatchTests.cs` are included automatically in the
existing contiguous per-rule discovery contract. They require the owner's
later single consolidated Windows verification. Do not run them before
explicit authorization.

Primary risks: HTTP capture adapters may omit Cookie or method/path
metadata; TLS adapters may expose certificate fields without verified
handshake direction or label `TlsVersion` from an offer rather than the
negotiated session. Strict attribution may reduce recall on incomplete
telemetry. Time-window concurrency and out-of-order delivery need runtime
verification. Evidence redaction must be checked against all downstream
event serialization paths.

Frozen V1 holdout remains FAILED (R102 4/6). V2 is pending independent
capture and label review; no holdout fixtures, labels, confidence floors
(R102 80%, R118 86%, R163 84%) or approval policy were changed.

**Next batch: R141-R145.**

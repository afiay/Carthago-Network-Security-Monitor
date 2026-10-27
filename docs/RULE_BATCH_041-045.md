# Rule accuracy batch 09 — R041–R045

**Status: CANDIDATE — UNVERIFIED.** 35 advanced xUnit facts (7 + 6 + 7 + 7 + 8) and five explicitly benign development replay controls authored. No build, xUnit, replay benchmark, holdout or Windows runner executed.

| Rule | Candidate precision / state / privacy changes | Facts |
| --- | --- | ---: |
| R041 JA4 fan-out | Preserve eight distinct SNI/60 s; require actual TLS/QUIC, attributable private-to-public traffic, valid JA4 and SNI, per-source/fingerprint windows, duplicate and out-of-order guards, clear completed windows, redact fingerprint and hostname. | 7 |
| R042 Uncommon QUIC ALPN | Preserve first-three rarity heuristic; require actual QUIC and valid bounded ALPN token, exclude common HTTP/3, global six-hour rarity with per-flow timestamp deduplication and bounded state, redact ALPN. | 6 |
| R043 SNI/Host mismatch | Preserve two-minute correlation; bind TLS and HTTP evidence to same four-tuple, reject stale/out-of-order, contradictory Host headers, CONNECT tunnels and prose-only claims, redact SNI and Host. | 7 |
| R044 Unusual HTTP method | Preserve existing suspicious method set and CONNECT proxy-port exceptions; require structured HTTP request, valid private-to-public attribution, reject Info-only text and conflicting application service. | 7 |
| R045 Sparse POST | Preserve missing UA/Content-Type heuristic; require complete captured HTTP header block with a unique validated Host, reject incomplete/contradictory header evidence, sanitize description. | 8 |

**Benign development replay controls:** R041 TCP/443 with JA4/SNI but no TLS, R042 HTTP with ALPN field but no QUIC, R043 HTTP Host without correlated TLS, R044 TRACE in Info prose without observed method, R045 incomplete POST headers. These controls use explicit `expectedNonMatches`; they are not independently labeled field traffic.

## Residual risks / acceptance focus

- R041 legitimate browsers and automation can contact eight distinct hosts with one JA4. Source aggregation across NAT may exaggerate fan-out; a malformed or unavailable SNI creates false negatives.
- R042 ALPN novelty is not proof of compromise; global rarity can be biased by traffic volume and per-flow coarse timestamps. Only first three observations in a six-hour epoch are candidates.
- R043 capture must expose source port and both decrypted HTTP and TLS metadata for the same transport tuple. Hostnames sharing a registrable root are intentionally treated as non-mismatches; the legacy naive root-domain helper is not a public-suffix-list implementation and can miss `.co.uk` mismatches.
- R044 WebDAV, TRACE and CONNECT may be authorized. The rule does not authenticate user authorization; a proxy on a nonstandard port can still match.
- R045 header-completeness evidence is required to avoid false positives from truncated captures, which can reduce recall when the parser drops the terminating blank line. Some legitimate clients omit User-Agent or Content-Type.
- Each state map is bounded best-effort and cleared by replay reset. Regressions in shared runtime state, event policy, parser header normalization and operational recall remain unverified.

## Deferred acceptance

`scripts/verify-all-rule-batches.ps1` remains the sole local Windows entry point. It discovers the five new test classes by filename and runs one full xUnit suite, one development replay and one frozen holdout when the owner explicitly authorizes test time. No confidence floors (R102 80%, R118 86%, R163 84%), Shadow/Disabled mode, baseline-readiness or asset approvals, frozen holdout fixtures, thresholds or enablement settings were modified.

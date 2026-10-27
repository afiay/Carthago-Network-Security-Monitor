# Rule accuracy batch 05 — R021–R025

**Status: CANDIDATE — UNVERIFIED.** Source, xUnit and labeled benign replay fixture authoring only. No build, xUnit, development replay, frozen holdout or Windows verification was executed. These are authored assertions, not passing test evidence.

| Rule | Detection boundary and candidate changes | Advanced xUnit facts |
| --- | --- | ---: |
| R021 — ICMP tunneling suspicion | Validate attributed IP endpoints and positive packet size; exclude explicit ICMP non-echo errors; isolate echo volume by source/destination; discard future/stale samples, use 64-bit volume totals and bounded state; clear triggered windows on cooldown. Preserve 20 packets/60 s and 100,000 bytes. | 6 |
| R022 — DNS NXDOMAIN spike | Require an observed DNS response and NXDOMAIN result; explicit RCODE overrides contradictory free text; attribute response traffic to client, isolate by client/resolver; deduplicate same-timestamp observations, bound state and clear on cooldown. Preserve 30 responses/60 s. | 6 |
| R023 — TLS to public IP without SNI | Require TLS evidence rather than TCP/443 alone; validate publicly routable destination and source attribution; exclude QUIC, hostname SNI and malformed ports; isolate by source/destination/port and count distinct timestamps in five minutes. Preserve three-observation threshold. | 7 |
| R024 — Rare TLS fingerprint | Require attributable TLS observation, bounded structured JA3/JA4 token, nonempty payload and valid IPs; exclude QUIC and untrusted text; keep fingerprint values out of alerts. Preserve novelty <=3 and existing severity. | 6 |
| R025 — TLS certificate expiry | Require structured certificate validity and TLS evidence; reject impossible validity ranges, malformed endpoints, QUIC and empty packets; use UTC comparison, clamp count to prevent integer overflow; preserve expired/within-seven-day severity and cooldown. | 6 |

**Total: 31 authored advanced xUnit facts**, plus five explicitly benign replay controls. The controls are negative examples, not independently labeled malicious incidents or proof of field accuracy.

## Replay controls
- r021-icmp-error-not-tunnel.json — ICMP destination-unreachable traffic cannot create echo tunnel evidence.
- r022-dns-query-nxdomain-prose.json — NXDOMAIN prose on a query is not an observed negative DNS response.
- r023-tcp443-no-tls.json — a TCP/443 observation without TLS handshake evidence cannot prove missing SNI.
- r024-http-ja4-metadata.json — an unrelated HTTP record carrying a JA4 field cannot create TLS novelty.
- r025-tcp443-cert-field-no-tls.json — an uncorroborated certificate date on TCP/443 cannot prove observed TLS expiry.

## Residual limitations
- ICMP echo volume is a heuristic; diagnostics, MTU testing and authorized probes can resemble tunneling. Headerless legacy ICMP remains eligible; no payload-content entropy or tunnel decoding is claimed.
- DNS NXDOMAIN responses may be legitimate from search-suffix expansion, browser prefetch or misconfiguration. Same-timestamp deduplication trades sensitivity for protection from duplicated capture records. DNS transaction IDs are not available in the current record model.
- TLS without SNI is legitimate for some clients. Repeated observations are not guaranteed to represent distinct connections without flow/session identifiers.
- JA3/JA4 novelty is a rarity observation, not a maliciousness label. The fingerprint counter is process-global and can drift with memory eviction.
- Expired certificates indicate a hygiene problem, not attacker intent; TLS certificate data may be missing from passive capture. A future NotBefore on an otherwise unexpired certificate is not covered by this rule.
- Existing rule descriptors, config thresholds, R102 >=80%, R118 >=86%, R163 >=84%, Shadow/Disabled policy, baseline readiness, asset approvals, privacy and frozen holdout fixtures are untouched.
- The consolidated Windows verifier auto-discovers R021–R025 advanced test files. Only the owner's explicit "now it's test time" instruction authorizes running it.

## Deferred acceptance
Freeze the exact branch SHA, then run the single Windows verification entry point, inspect TRX, development replay, frozen holdout and complete TXT evidence, and correct actual failures without lowering production thresholds. No real-world precision, recall, F1 or alert-promotion claim is made.

# Rule accuracy batch 10 — R046–R050

**Status: CANDIDATE — UNVERIFIED.** 36 advanced xUnit facts (7 + 7 + 7 + 7 + 8) and five explicitly benign development replay controls authored. No builds, xUnit, replay benchmarks, holdout or Windows runner executed.

| Rule | Candidate precision / state / privacy changes | Facts |
| --- | --- | ---: |
| R046 Unauthorized VPN protocol egress | Retain legacy UDP port set and first-three-per-minute candidate budget. Require attributable private-to-public UDP and explicit VPN protocol classification rather than port-only claims; respect negative classification, isolate rate state by source/destination/port, reject duplicate/out-of-order observations. | 7 |
| R047 HTTP Basic Auth to IP literal | Require a structured HTTP request, captured Basic Authorization header, validated destination-IP Host authority, unique credential evidence and public egress. Never decode, persist or log credential material. Reject Info prose, Bearer authentication and conflicting authorities. | 7 |
| R048 Alternate DoH patterns | Require structured GET/POST on 443, canonical exact DNS provider host, attributable endpoints, observed URI and DNS query/JSON evidence; reject provider substrings, duplicate Host fields and prose-only claims. Bound and deduplicate per-source observations; redact URI and host. | 7 |
| R049 Suspicious SNI shape | Preserve existing 40-character, entropy 3.7, hyphen and single-label heuristics; require actual TLS handshake classification and attributable public egress. Validate hostname syntax and redact SNI from alert descriptions. | 7 |
| R050 Rule execution gap | Preserve >10-second threshold; reject absent, future, non-UTC or internally contradictory health snapshots. Keep cancellation semantics and health-event attribution. | 8 |

**Benign development replay controls:** R046 QUIC UDP/443 without VPN classification; R047 IP-literal Bearer authorization; R048 provider-name substring spoof; R049 TCP/443 with uncorroborated SNI; R050 consecutive routine observations. These are development-only synthetic negatives, not independently labeled production traffic.

## Residual risks and deferred acceptance

- R046 cannot prove authorization from packet telemetry; even positively identified VPN protocols may be approved. Missing enrichment can suppress valid detections, particularly IPsec and WireGuard flows.
- R047 Basic authentication may be used legitimately on IP-literal hosts. Parser normalization, IPv6 Host authority and incomplete header captures require additional real capture validation. No credential contents are included in alert descriptions.
- R048 only recognizes selected provider hostnames and structured HTTP metadata; encrypted DoH without decrypted HTTP or alternate provider patterns will be missed. Application/dns-json is a heuristic and not definitive proof of DNS exchange.
- R049 long/high-entropy hostnames are common in CDNs and generated service names. The single-label heuristic remains noisy and should not be promoted on synthetic recognition alone.
- R050 depends on the rule engine resuming evaluation to observe a gap. It is not an independent watchdog and cannot report an indefinitely stalled engine without a subsequent evaluation. HealthSnapshot fields are not proof of wall-clock correctness.
- All source changes are uncompiled and unexecuted candidates. Changes to shared state, policy enforcement, selector telemetry, replay fixture interpretation and operational recall remain unverified.

## Deferred consolidated Windows acceptance

The sole acceptance entry point remains `scripts/verify-all-rule-batches.ps1`, which discovers advanced classes R001–R050 and runs one full xUnit regression, one development replay and one frozen holdout when explicitly authorized. No configured thresholds, R102/R118/R163 confidence floors, Shadow/Disabled policy, baseline readiness, asset approval safeguards, rule enablement or frozen holdout fixtures were changed.

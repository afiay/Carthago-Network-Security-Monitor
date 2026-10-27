# Rule accuracy batch 08 — R036–R040

**Status: CANDIDATE — UNVERIFIED.** Authored 38 advanced xUnit facts (8 + 7 + 8 + 7 + 8) and five explicit benign development replay controls. No builds, xUnit, replay benchmark, frozen holdout or Windows runner executed.

| Rule | Candidate precision / state / privacy changes | Advanced facts |
| --- | --- | ---: |
| R036 Heavy egress to one host | Preserve 20 MB/120 s; private-to-public IP validation, long byte accounting, pair isolation, coarse-timestamp duplicate handling, bounded state and completed-window clearing. Do not call `AllowListLearner.MarkBad` based on traffic volume alone. | 8 |
| R037 JA4 drift per SNI | Preserve 3 distinct JA4s/5 observations/1 h and low-volume guard. Require actual TLS/QUIC classification, valid SNI and JA4 evidence; count time-window observations rather than all-time fingerprint counts; bound per-SNI state, exclude repeated timestamp/fingerprint pairs, sanitize alert text. | 7 |
| R038 Encrypted DNS bootstrap | Preserve 10 structured DoH requests + 3 high-entropy QUIC observations/300 s. Require explicit HTTP method, URI and GET query or POST content type; reject Info-only text and malformed transport/endpoint evidence; dedupe coarse timestamps, isolate source, clear suppressed completed windows. | 8 |
| R039 Sensitive-network ASN novelty | Require explicitly sensitive source classification and attributable private-to-public flow. Parse canonical AS number within UInt32 range; scope first observation to each sensitive source, expire old keys, reject future/out-of-order contamination and remove organization prose from descriptions. | 7 |
| R040 Long-lived encrypted low-throughput | Preserve 15 min/12 observations/300 KB; require encrypted protocol evidence and public destination, reject duplicate/out-of-order records, reset on >5 min idle gap or excessive bytes, bound state and clear completed flows. | 8 |

**Development replay negatives:** R036 below-threshold authorized transfer; R037 TCP/443 with JA4 field but no TLS evidence; R038 prose-only DoH text; R039 office-classified ASN enrichment; R040 TCP/443 with no encrypted protocol classification. Each fixture has an explicit `expectedNonMatches` rule ID. Synthetic labels are not independent field precision.

## Residual risks and verification focus

- R036 counts observed `TrafficRecord.Length` rather than confirmed application payload bytes. Distinct same-timestamp packets of the same length are conservatively deduplicated. A large authorized backup can still exceed the unchanged threshold; service reputation is no longer penalized solely by this volume hypothesis.
- R037 one legitimate SNI can serve diverse clients and JA4s. The detector has no external popularity baseline; its 50-observation rarity cap is a heuristic. Source isolation is intentionally **per SNI**, not per client.
- R038 structured HTTP evidence may be unavailable on encrypted captures. DoH and high-entropy QUIC are not proof of compromise, and a shared source could represent a NAT or proxy. Alternative DoH paths, HTTP/3 and other encrypted DNS transports may be missed.
- R039 `WhoisASN` enrichment is treated as destination metadata, but the record does not carry an enrichment provenance token. `NetworkType` is a coarse classification, not an authenticated VLAN ID. ASN novelty does not establish malicious intent.
- R040 a long-lived, sparse TLS/QUIC flow may be a legitimate push notification or heartbeat. Idle-gap reset protects against combining unrelated sessions, but the capture has no guaranteed session ID. `Length` is not necessarily payload length.
- All changes are candidate code. Verify compile, xUnit, replay labels, policy decisions, replay holdout and operational false negatives together before acceptance. Do not promote on synthetic accuracy alone.

## Deferred consolidated acceptance

`scripts/verify-all-rule-batches.ps1` remains the single Windows verification entry point. It discovers R036–R040 through the existing filename contract and enforces at least five passing advanced cases per rule in one complete suite run, followed by one development replay and one frozen holdout. Do **not** execute until the owner explicitly says **now it's test time**.

No confidence floors (R102 80%, R118 86%, R163 84%), baseline-readiness or asset approvals, Shadow/Disabled policies, frozen holdout fixtures or existing rule enablement were changed.

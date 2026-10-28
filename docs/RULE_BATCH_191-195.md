# R191-R195 — Typed DNS novelty and encrypted-resolver request evidence

**CANDIDATE / UNVERIFIED — 51 new advanced xUnit facts authored, zero executed.**

| Rule | Precision, state and privacy changes | Facts |
|---|---|---:|
| R191 | Wire-attributed consonant-heavy DGA-like DNS query, replay guard, no raw qname in new evidence | 10 |
| R192 | Valid IDNA punycode in registrable label, first-seen candidate, duplicate guard and label redaction | 10 |
| R193 | Exact registrable cloud-brand lookalike label, first-seen candidate, replay guard and identifier redaction | 10 |
| R194 | Strict HTTP authority and external IP; DoH-shaped GET with complete decoded DNS question or POST MIME/length; approved-host suppression, replay guard, redacted path/host | 11 |
| R195 | External TCP/853 TLS handshake with SNI and parsed TLS version, approved-host suppression, browser exclusion, replay guard and SNI redaction | 10 |

**Source:** `Carthago/Engine/Rules/Expansion/R191_*.cs` through `R195_*.cs`, `NetworkBatch191195Evidence.cs`, scoped redaction in `HttpApiPrecisionDetectionRuleBase.cs` and `TlsPkiPrecisionDetectionRuleBase.cs`. **Tests:** `Carthago.Tests/R191AdvancedAccuracyBatchTests.cs` through `R195AdvancedAccuracyBatchTests.cs`, shared `NetworkBatch186195Context.cs`. Existing `scripts/verify-all-rule-batches.ps1` remains the single deferred Windows verifier.

**Candidate source:** `064dc0a45b70cb786d6b040e251e6b80becacd44`. **Tests:** `1d7ec5d3495c4f43244eca1e71bbab92649c9ee6`. **Static precision follow-ups:** `a2039b6a5ca68aad4b43a44d192b3c6ec991ef2c` (external IP boundary) and `c2ea55c3d911aa23611415bb53eb300aaff1fd04` (complete DoH GET DNS wire question, additional negative test).

## Limitations

R191 remains a heuristic, not proof of malware or DGA. R192 punycode is not proof of a visual homograph; R193 exact brand-lookalike labels may occur in approved training. Novelty uses the existing baseline store/fallback and is **not** equivalent to a readiness-certified baseline; configured Shadow policy is unchanged.

R194 can validate a GET DNS wire question from the observable URL but cannot verify an encrypted response or an unseen POST body. A POST with `application/dns-message` and a plausible Content-Length remains **request-shape evidence only**. R195 sees TLS/SNI/port metadata, not decrypted DoT DNS payload or independently verified resolver approval. TLS without SNI is intentionally not promoted as unapproved DoT. The static approved-host lists are not a substitute for enterprise policy inventory.

R190's TTL adapter gap from the preceding batch persists: inspected `PacketHandler` paths do not populate `DnsTtl`, so the R190 candidate contract is not evidence of live detection reachability.

**R186-R195 combined:** 10 consecutive rules, **101 authored advanced xUnit facts, zero executed**. All CANDIDATE / UNVERIFIED. No builds, xUnit, development replay, benchmark, V1/V2 holdout, CI or Windows runner invoked. Existing confidence floors, thresholds, Shadow/Disabled/Alert modes, approval/baseline gates and frozen holdout data unchanged. Frozen V1 R102 remains FAILED at 4/6; V2 requires independently sourced licensed PCAP and analyst approval.

**Next consecutive five-rule batch: R196-R200, then R201-R205.**

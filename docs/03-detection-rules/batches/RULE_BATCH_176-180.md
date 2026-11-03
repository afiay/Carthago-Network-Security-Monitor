# R176-R180 — Candidate precision and privacy hardening

**Status: CANDIDATE / UNVERIFIED. No tests, builds, replay, holdout, CI or runner executed.**

| Rule | Evidence and false-positive boundary | Advanced xUnit facts |
|---|---|---:|
| R176 | Wire-attributed Host and X-Forwarded-Host; reject conflicting Host, same-boundary forwarding, Info-only claims; fixed-category rewrite evidence. | 9 |
| R177 | Typed multipart or PUT upload and observed filename; reject benign media, GET downloads and Info-only filename; fingerprint filenames. | 9 |
| R178 | Valid DNS questions to exact mining pool roots with stratum/pool labels; reject brand-only, spoofed protocol and replay; redact qname. | 9 |
| R179 | Exact onion/gateway suffix; reject lookalikes, contradictory transports, response traffic and replay; redact identifiers. | 9 |
| R180 | Existing first-seen/entropy thresholds retained; require typed DNS query, reject response/HTTP contradictions and replay; redact qname. | 9 |

**Changed source:** `Carthago/Engine/Rules/Expansion/R176_*.cs` through `R180_*.cs`, `NetworkBatch176180Evidence.cs`, `HttpApiPrecisionDetectionRuleBase.cs`, `Carthago/Engine/Rules/Dns/DnsPrecisionDetectionRuleBase.cs`. **Tests:** `Carthago.Tests/R176AdvancedAccuracyBatchTests.cs` through `R180AdvancedAccuracyBatchTests.cs` and `NetworkBatch176185Context.cs`. **Coverage:** 45 authored facts, 0 executed.

**Limitations:** HTTP capture adapters may not surface multipart Content-Disposition; no body inference from Info. DNS qname is not evidence of connection or malicious intent. The existing R180 baseline fallback remains unverified. Per-rule-instance replay guards are bounded but need later Windows concurrency and clock-skew verification. DNS qnames and upload filenames are redacted in new event evidence; root-domain and generic rule summaries remain category-only.

Default modes, floors, thresholds, approval and baseline-readiness policy, frozen V1 (R102 FAILED 4/6), and V2 independent-PCAP requirements are unchanged. The consolidated `scripts/verify-all-rule-batches.ps1` remains the sole deferred verification entry point and discovers the new tests automatically. **Next: R181-R185.**
Static follow-up: R178 requires a pool/stratum service subdomain rather than the mining-provider brand apex; candidate correction `806a6244cd549c2606f9a23ba535b51a2bef0744`. The R178 apex benign negative remains unexecuted. No test or build was run.


Static refinement: R178 requires an anchored pool/stratum/rig service label, rejecting provider website `www.2miners.com` as a close benign negative. One additional advanced fact authored, zero executed. R176–R180 now **46 facts**, and R176–R185 now **86 facts**, all CANDIDATE / UNVERIFIED.

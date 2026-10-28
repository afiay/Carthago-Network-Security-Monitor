# R186-R190 — Typed DNS service evidence and bounded-state hardening

**CANDIDATE / UNVERIFIED — 50 new advanced xUnit facts authored (10 per rule), zero executed.**

| Rule | Production changes | Authored facts |
|---|---|---:|
| R186 | Strict wire-attributed CAA queries, source/resolver-scoped distinct-root counting, duplicate-ID and out-of-order resistance | 10 |
| R187 | Typed NULL query only, benign validation exclusions, instance-owned replay protection, privacy-safe evidence | 10 |
| R188 | Typed AD SRV service-label validation (including underscore service labels), distinct per-zone/source/resolver windows | 10 |
| R189 | Internal-source AD SRV leakage to an external IP resolver, strict SRV qtype and replay guard; no public SRV promotion | 10 |
| R190 | Typed DNS response with explicit parsed nonnegative TTL and response direction, bounded client/resolver/root counts | 10 |

## Files and publication

Production: `Carthago/Engine/Rules/Expansion/R186_*.cs` through `R190_*.cs`, `NetworkBatch186190Evidence.cs`, and scoped DNS evidence redaction in `Carthago/Engine/Rules/Dns/DnsPrecisionDetectionRuleBase.cs`. Tests: `Carthago.Tests/R186AdvancedAccuracyBatchTests.cs` through `R190AdvancedAccuracyBatchTests.cs`, with `NetworkBatch186195Context.cs`. The unchanged `scripts/verify-all-rule-batches.ps1` is the sole deferred Windows verification entry point.

Source commit `ef92684391f13953128933df811cf310a461027f`; authored tests `b4f5b597844f688573460b4c3a40312dd9306469`; static follow-up `b4bc16137e343dc51fa991b1b732586582a70bc6`. All 50 xUnit facts remain unexecuted.

## Evidence limitations and operational risks

The existing `PacketHandler` currently populates DNS qname/qtype/rcode/response status but does **not** populate `DnsTtl` or answer values in its observed DNS parsing paths. Therefore R190's short-TTL response classification is **not presently proven reachable in live capture** without an independently validated TTL-bearing adapter. The synthetic tests explicitly populate `DnsTtl`; they are *contract tests*, not capture-adapter or detection-recall evidence. Do not infer a positive live TTL signal from `Info`.

AD SRV service labels are legal underscore-prefixed DNS names; the previous generic hostname validator rejected them. R188/R189 now use a narrow typed AD SRV validator. DNS packet parsing of actual SRV qtypes, the fidelity of resolver attribution, out-of-order concurrency, and operational false positives remain unverified. High-volume CAA and SRV traffic may be legitimate PKI/AD administration.

**Safety and certification:** No builds, xUnit, replay, benchmarks, frozen holdouts, GitHub Actions or Windows runners executed. No confidence floors, thresholds, runtime policies, baseline/asset approvals or frozen samples changed. Frozen V1 R102 remains **FAILED 4/6**; V2 requires independent licensed captures and analyst review. Candidate test assertions do not establish field accuracy.

**Next consecutive batch: R191-R195.**

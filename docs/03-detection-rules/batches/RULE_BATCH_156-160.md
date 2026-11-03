# R156-R160 HTTP/JWT precision candidate — 2026-10-27

**CANDIDATE / UNVERIFIED.** No compilation, xUnit, replay, benchmark, frozen holdout, GitHub Actions or Windows runner execution occurred.

| Rule | Implementation | Advanced tests authored (not run) |
| --- | --- | ---: |
| R156 | Typed HTTP JWT header/query attribution; JSON-decoded `alg=none` and empty signature; no Info-derived JWT | 8 |
| R157 | Signed-shaped JWT in allowlisted query keys only; excludes fragments, state and bearer-header-only traffic | 9 |
| R158 | Exact Swagger/OpenAPI path segments, trusted HTTP request provenance, inbound boundary, documented public host suppression | 8 |
| R159 | Sensitive Actuator segment matching; health/info and substring lookalikes excluded; inbound boundary | 8 |
| R160 | Kubernetes API path and port/anchored host corroboration; generic HTTPS 443 no longer sufficient | 8 |
| **Total** | | **41** |

Files: `Carthago/Engine/Rules/Expansion/R156_*Rule.cs` through `R160_*Rule.cs`, `NetworkBatch156165Evidence.cs`, `HttpApiPrecisionDetectionRuleBase.cs`, `Carthago.Tests/R156AdvancedAccuracyBatchTests.cs` through `R160AdvancedAccuracyBatchTests.cs`, and `Carthago.Tests/NetworkBatch156165Context.cs`.

The shared evidence builder redacts raw HTTP paths for R156-R165; rule-specific evidence uses fixed route categories for R158-R160 and fixed JWT source categories for R156. Each rule has a bounded, instance-owned, source+target replay guard rejecting repeated packet IDs and older observations. These are request/probe indicators, **not proof of successful exploitation or of an exposed service**. Configured confidence floors and runtime modes are preserved (R156 80% Alert, R157 74% Shadow, R158 72% Shadow, R159 78% Alert, R160 78% Alert).

**Limitations:** real HTTP parser attribution and service identity require capture validation; syntactically decoded JWTs are not cryptographically verified; malicious query values remain in the input TrafficRecord (not the new structured evidence). Strict URI and transport gates may reduce recall. Replay guards are local to detector instances, not a distributed state store. The tests are source-authored only.

Single deferred verification entry point: `scripts/verify-all-rule-batches.ps1` (unchanged). Frozen V1 R102 remains FAILED 4/6, V2 remains pending independently licensed PCAP evidence and analyst approval. No thresholds, frozen samples, replay labels or promotion gates changed.

**Next consecutive batch: R161-R165.**

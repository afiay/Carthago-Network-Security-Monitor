# R161-R165 service-probe precision candidate — 2026-10-27

**CANDIDATE / UNVERIFIED.** No build, xUnit, replay, benchmark, frozen holdout, CI or Windows runner execution.

| Rule | Narrow candidate changes | Advanced tests authored (unexecuted) |
| --- | --- | ---: |
| R161 | Typed HTTP; Docker port/anchored host plus exact daemon API segment; inbound boundary | 8 |
| R162 | Typed HTTP; Redis/Memcached port or anchored service host plus explicit admin path, not packet Info | 8 |
| R163 | Retains existing independent socket/Host/provider/path credential contract and 84% floor; rejects contradictory UDP/QUIC/DNS; fixed route evidence; replay guard | 8 |
| R164 | Typed HTTP and consistent authority; retains existing suspicious-target/OIDC exceptions; redacts redirect target and query secrets | 8 |
| R165 | Typed HTTP, inbound boundary, exact phpinfo route; unrelated query flags no longer qualify | 8 |
| **Total** | | **40** |

Production: `Carthago/Engine/Rules/Expansion/R161_*Rule.cs` through `R165_*Rule.cs`, and `NetworkBatch156165Evidence.cs`. Tests: `Carthago.Tests/R161AdvancedAccuracyBatchTests.cs` through `R165AdvancedAccuracyBatchTests.cs`, sharing `NetworkBatch156165Context.cs`.

The shared HTTP guard rejects contradictory observed Host fields, while the R163-specific metadata authority contract remains independent to support documented provider aliases and IPv6 metadata. Per-rule-instance, bounded source/target replay guards prevent duplicate record IDs and older observations from qualifying as new detections. All R156-R165 HTTP paths are redacted by the shared event builder; R161-R165 use fixed route categories or fixed redirect target category. No raw credential, JWT, or redirect URL is intentionally copied to new structured evidence.

Existing modes/floors retained: R161 Alert/78%, R162 Shadow/72%, R163 Alert/84%, R164 Shadow/74%, R165 Shadow/70%. **R163 is a metadata credential request candidate, not independently established SSRF.** Other detections are requests/probes, not confirmed service exposure.

**Risks:** parser-specific HTTP attribution, proxy/Host header handling, cloud metadata IPv6 aliases and legitimate cache/container administration must be reviewed against real traffic. Replay guard state is per rule instance and bounded; no distributed correlation. Strict route/authority gates may reduce recall. Unexecuted tests provide no measured precision or alert recall.

Single deferred Windows verification command remains `scripts/verify-all-rule-batches.ps1`, unchanged. Frozen V1 R102 holdout still FAILED 4/6; V2 requires independent licensed PCAP capture and separate analyst approval. No frozen labels, confidence floors, thresholds, approval gates, Shadow/Disabled policy or existing replay classifications changed.

**Next consecutive batch: R166-R170.**

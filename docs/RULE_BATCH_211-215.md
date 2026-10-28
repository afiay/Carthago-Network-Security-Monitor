# R211-R215 — Typed script retrieval and cloud-storage request evidence

**CANDIDATE / UNVERIFIED — 62 advanced xUnit facts authored, zero executed.**

| Rule | Narrow candidate production change | Advanced facts |
| --- | --- | ---: |
| R211 | Require typed GET for a PowerShell-client .ps1 request to a non-gallery external host; bounded duplicate/out-of-order guard. | 12 |
| R212 | Require typed curl/wget raw-script GET alongside the legacy shell-pipe summary hint; explicitly mark execution unverified and retain original Critical/Alert floor. | 12 |
| R213 | Require provider-specific AWS/GCS/Azure signed-query shape on typed GET/HEAD; count distinct **object paths** by SHA256 fingerprint in a bounded instance-owned source/provider window, never raw signed URLs. | 14 |
| R214 | Require typed GET to S3 endpoint with bucket-root listing query; reject object paths with misleading list-type; bounded replay guard. | 12 |
| R215 | Require typed GET to Azure Blob container path with exact comp=list/restype=container query; reject blob-object paths; bounded replay guard. | 12 |
| **Total** | **Five consecutive candidate rules** | **62** |

**Production files:** `Carthago/Engine/Rules/Expansion/R211_PowershellGalleryExternalScriptPullRule.cs` through `R215_AzureBlobContainerEnumerationRule.cs`; extended `NetworkBatch206215Evidence.cs`; scoped host/path redaction in `HttpApiPrecisionDetectionRuleBase.cs`. Reused `NetworkBatch201205Window` with instance-owned bounded state. The R213 signed URL itself is not retained as a distinct key; an object-path fingerprint is used instead.

**Advanced tests:** `Carthago.Tests/R211AdvancedAccuracyBatchTests.cs` through `R215AdvancedAccuracyBatchTests.cs` and `NetworkBatch211215Context.cs`. Per-rule scenarios cover typed positive, close benign, packet-Info spoof, contradictory Host and UDP, method/path boundaries, duplicate packet IDs, out-of-order events, independent sources, query-secret redaction and unchanged confidence/default modes. R213 adds seven-versus-eight threshold, signed-query completeness, same-object changing signatures, per-source separation and no raw signed URL persistence. **All authored; none executed.**

**Candidate commits:** source `fa699244fe601ec4f6d4693b71d957a19084593a`; advanced tests `9a5b0f9ca2fa5142f45f005af1befbbffbcef701`.

## Evidence and verification limitations

The inspected `TrafficRecord` exposes no trusted process command-line field. **R212's packet Info shell-pipe hint is not proof of execution**; the additional typed HTTP evidence only confirms a raw script request. The Critical default remains unchanged pending independent execution telemetry. R211 confirms a request, not script execution. R213 counts observed signed-URL requests for distinct object paths, **not downloads or successful credential use**; changing signatures on one object does not inflate the count. R214/R215 listing requests do not establish successful enumeration or authorization failure. Cloud storage HTTP request metadata may be unavailable in live encrypted traffic because the inspected `PacketHandler` parses cleartext HTTP only. Synthetic typed HTTPS fixtures remain contract-only.

No builds, xUnit, replay, benchmark, frozen holdout, CI or Windows runner executed. The deferred single verifier `scripts/verify-all-rule-batches.ps1` remains unchanged. Existing R102 80%, R118 86%, R163 84% floors, other thresholds, Shadow/Disabled/Alert policies, baseline readiness, asset approvals and frozen evidence preserved. Frozen R102 V1 remains FAILED 4/6; V2 awaits independently licensed PCAP and analyst review.

**R206-R215 combined: ten consecutive rules, 117 advanced xUnit facts authored, zero executed, CANDIDATE / UNVERIFIED. Next R216-R220 then R221-R225.**

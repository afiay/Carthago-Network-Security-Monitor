# R221–R225 — Remote-support egress and industrial protocol attribution

**CANDIDATE / UNVERIFIED — 78 advanced xUnit facts authored, ZERO executed.**

| Rule | Narrow candidate production change | Advanced facts |
| --- | --- | ---: |
| R221 | Corroborate exact remote-support process and vendor endpoint (AnyDesk, TeamViewer, RustDesk, Splashtop, ScreenConnect); first-seen baseline and bounded distinct-flow window; redact host/Info. | 17 |
| R222 | Require overlay process with exact vendor host or WireGuard UDP service port; reject bare ports, browsing, Info and mismatched SNI/HTTP authority; distinct-flow window and baseline. | 16 |
| R223 | Require parser-attributed industrial L7 protocol with coherent transport and service port before internal-to-external classification; reject Info and guessed ApplicationService. | 15 |
| R224 | Require typed DNP3/TCP/20000 before external or cross-/24 boundary classification; replay guard and privacy; /24 is a heuristic, not approval evidence. | 15 |
| R225 | Require typed S7comm/TCP/102 before external or cross-/24 boundary classification; replay guard and privacy; /24 is a heuristic, not approval evidence. | 15 |
| **Total** | **Five consecutive rules** | **78** |

**Production paths:** `Carthago/Engine/Rules/Expansion/R221_RemoteDesktopSaasToolBeaconRule.cs` through `R225_S7CommTrafficOutsideApprovedSegmentRule.cs`; new `NetworkBatch221225Evidence.cs`; scoped host/path redaction in `CloudDevPrecisionDetectionRuleBase.cs` and OT host/Info redaction in `Carthago/Engine/Rules/IotOt/IotOtPrecisionDetectionRuleBase.cs`. Existing `NetworkBatch201205Window` and `NetworkBatch156165ReplayGuard` provide per-detector bounded duplicate/out-of-order state. Original first-seen baseline and fallback behavior is retained; no baseline or asset approval bypass added.

**Advanced tests:** `Carthago.Tests/R221AdvancedAccuracyBatchTests.cs` through `R225AdvancedAccuracyBatchTests.cs` plus `NetworkBatch221225Context.cs`. R221/R222 cases cover repeated typed positives, browser/vendor negatives, packet Info spoofing, contradictory transport, private destination, process/host mismatch, duplicate packet ID, out-of-order, independent source, expiry, vendor-subdomain redaction, unchanged confidence/default mode and vendor-specific alternatives. R223–R225 cover typed positives, port-only, guessed ApplicationService, Info-only claims, UDP contradiction, wrong port/protocol, replay, out-of-order, source separation, secret redaction, profile floors and boundary/same-/24 controls. All **78 authored and unexecuted**. No replay fixture was added because current capture does not establish the required OT L7 identity.

**Candidate commits:** source `e06e157af4bf2ab4d45f27657ea08ca52ecb305a`, tests `325a0b59099da484b9a3a7d5345cff2a6d89c6ad`, static source/test correction `2a0a0caeb5c867d388cb2db9e7043c95611566e0`. The initial test commit message uses an outdated 75 count; 78 [Fact] methods are present after correction.

## Telemetry and operational limitations

**Important:** inspected `PacketHandler` does not currently decode DNP3, S7comm, or other industrial L7 protocols into `TrafficRecord.ApplicationProtocol`; it only populates port-guessed `ApplicationService` for these flows. Thus R223–R225 typed positive test records exercise an **unreachable live capture contract at present**. These are not field detections, and no synthetic holdout or success claim is made. A future separately reviewed OT parser/adapter implementation is needed before live recall can be assessed. R221/R222 also depend on trustworthy endpoint process attribution and SNI/host visibility, which are not guaranteed by passive capture. Requiring process-plus-endpoint corroboration can reduce recall for unknown clients; this is an explicit precision tradeoff. Approved remote support, mesh VPNs, routed SCADA and PLC engineering paths remain realistic benign equivalents. Different /24 networks do not prove a disallowed segment; an asset inventory and policy source must make that decision.

No build, xUnit, replay, benchmark, frozen holdout, CI, GitHub Actions or Windows runner was executed. The single deferred verifier `scripts/verify-all-rule-batches.ps1` remains unchanged. Frozen R102 V1 **FAILED 4/6**, immutable; V2 independent licensed PCAP and analyst review pending. Confidence floors R102 80%, R118 86%, R163 84% and all other floors, thresholds, default Shadow/Disabled/Alert modes, asset approvals, baseline readiness and evidence privacy remain unchanged.

**R216–R225 combined: ten consecutive candidate rules, 159 advanced xUnit facts authored, ZERO executed. Next R226–R230, then R231–R235.**

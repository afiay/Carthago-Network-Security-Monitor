# R301–R305 — Kubelet and container registry provenance

**CANDIDATE / UNVERIFIED.** 70 advanced xUnit facts authored (14 per rule), **ZERO executed**. Static source inspection only; no build, test, replay, benchmark, holdout, CI, GitHub Actions or runner. The five rules deliberately fail closed with `NoMatch/InsufficientEvidence` until a trusted service-identity and operation-outcome producer is connected.

Source paths: `Carthago/Engine/Rules/Expansion/R301_KubeletReadonlyPortProbeRule.cs`, `R302_KubeletRunOrExecProbeRule.cs`, `R303_ContainerRegistryManifestEnumerationRule.cs`, `R304_ContainerRegistryAnonymousPullBurstRule.cs`, `R305_ImageRegistryPushFromWorkstationRule.cs` (same directory). Tests: `Carthago.Tests/NetworkBatch301305Context.cs` and `Carthago.Tests/R301AdvancedAccuracyBatchTests.cs` through `R305AdvancedAccuracyBatchTests.cs`.

**R301 (14 unexecuted facts):** `KUBELET_READONLY_ENDPOINT_IDENTITY_UNAVAILABLE`. Kubelet read-only port 10255, `GET /pods`, `/runningpods/` and `/metrics` can be observed as cleartext HTTP requests but do not prove that the destination is Kubelet, that read-only access is exposed, or that sensitive pod data was returned. A trusted endpoint inventory and response validation are missing. No positive invented.

**R302 (14 unexecuted facts):** `KUBELET_EXEC_REQUEST_PROVENANCE_UNAVAILABLE`. `POST /run/...` or `/exec/...` on 10250 does not establish authenticated Kubelet identity, command execution, or result. HTTPS is not decrypted; no authenticated Kubelet audit producer is available. No positive invented.

**R303 (14 unexecuted facts):** `REGISTRY_MANIFEST_ENUMERATION_AUDIT_UNAVAILABLE`. `/v2/<name>/manifests/<ref>` and `/tags/list` requests alone cannot establish successful enumeration or distinct responses from an authenticated registry. A trusted registry identity, result stream, and approval context are absent. No positive invented.

**R304 (14 unexecuted facts):** `REGISTRY_ANONYMOUS_PULL_AUDIT_UNAVAILABLE`. Missing Authorization in bounded request headers is not proof of anonymous access; a `GET /blobs/...` request does not establish successful blob delivery or a deduplicated pull burst. Require authenticated registry response/audit and unique operation IDs. No positive invented.

**R305 (14 unexecuted facts):** `REGISTRY_PUSH_ASSET_AND_RESULT_UNAVAILABLE`. `PUT`, `PATCH` and `POST` to blob-upload or manifest routes do not establish successful image push or unapproved workstation origin. Current packet records lack approved workstation/CI role and authenticated registry write outcome. No positive invented.

Each rule has six behavior-specific negative cases plus descriptor spoof, duplicate, out-of-order, independent source, missing source, contradictory UDP/HTTP, privacy non-emission and original profile assertions. **All 70 tests are authored but not executed.** They are not evidence of passing behavior or field precision.

PacketHandler does not decrypt HTTPS or fully reassemble TCP. `Info` is not an authenticated audit channel; URL and port matching alone must not produce attack verdicts. Keep original confidence floors, thresholds, modes, asset approvals, baseline readiness, privacy and architecture. Frozen R102 V1 **FAILED 4/6**, immutable; V2 pending independently reviewed licensed PCAP and analyst approval. Deferred verifier `scripts/verify-all-rule-batches.ps1` unchanged.

**Next R306–R310, then R311–R315.**

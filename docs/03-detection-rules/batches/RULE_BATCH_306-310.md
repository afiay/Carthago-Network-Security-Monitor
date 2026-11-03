# R306–R310 — Docker build, Kubernetes Dashboard and service mesh provenance

**CANDIDATE / UNVERIFIED.** 70 advanced xUnit facts authored (14 per rule), **ZERO executed**. Static source inspection only; no build, test, replay, benchmark, holdout, CI, GitHub Actions or runner. All five rules fail closed with `NoMatch/InsufficientEvidence` until authenticated service identity, operation outcome and approved asset/mesh context become available.

Source paths: `Carthago/Engine/Rules/Expansion/R306_DockerBuildContextArchiveUploadRule.cs`, `R307_KubernetesDashboardExposureProbeRule.cs`, `R308_HelmTillerLegacyPortExposureRule.cs`, `R309_IstioEnvoyAdminEndpointProbeRule.cs`, `R310_ServiceMeshSidecarBypassPatternRule.cs` (same directory). Tests: `Carthago.Tests/NetworkBatch306310Context.cs` and `Carthago.Tests/R306AdvancedAccuracyBatchTests.cs` through `R310AdvancedAccuracyBatchTests.cs`.

**R306 (14 unexecuted facts):** `DOCKER_BUILD_CONTEXT_UPLOAD_AUDIT_UNAVAILABLE`. A POST to `/build`, `/build/context.tar.gz` or an archive filename does not prove a Docker build endpoint, the archive contents or a completed build-context transfer. HTTPS is not decrypted; no trusted build API audit is connected. No positive invented.

**R307 (14 unexecuted facts):** `K8S_DASHBOARD_EXPOSURE_IDENTITY_UNAVAILABLE`. `/api/v1/login`, `/kubernetes-dashboard`, ports 443/8443/9090 and dashboard labels do not prove the target is a Dashboard or that unauthorized access succeeded. Require validated endpoint inventory, authentication and response audit. No positive invented.

**R308 (14 unexecuted facts):** `HELM_TILLER_ENDPOINT_AUDIT_UNAVAILABLE`. TCP/44134, `grpc` labels, process names or `Info` do not prove Helm Tiller identity, approved network segmentation or remote access outcome. A different /24 is not a trusted boundary. No positive invented.

**R309 (14 unexecuted facts):** `ENVOY_ADMIN_ENDPOINT_IDENTITY_UNAVAILABLE`. `/config_dump`, `/stats`, `/clusters` and port 15000 do not establish a validated Envoy admin listener, successful response or unauthorized exposure. Sidecar ports 15001/15090 may carry non-admin traffic. No positive invented.

**R310 (14 unexecuted facts):** `MESH_SIDECAR_BYPASS_TELEMETRY_UNAVAILABLE`. Direct pod-IP contact or ports 15001/15006/15008 cannot prove bypass of enforced sidecar routing or mTLS policy. Require a trusted mesh policy inventory, route/identity context and observed bypass outcome. No positive invented.

Each rule has six behavior-specific negative cases plus descriptor Info spoof, duplicate, out-of-order, independent source, missing source, contradictory UDP/HTTP, privacy non-emission and original profile assertions. **All 70 facts are authored, ZERO executed.** No field recall, passing regression or production detection is claimed.

PacketHandler does not decrypt HTTPS or fully reassemble TCP. `Info`, HTTP path, port, host and process labels are not authenticated audit events. Preserve original confidence floors, thresholds, modes, asset approvals, baseline readiness, privacy and architecture. Frozen R102 V1 **FAILED 4/6**, immutable; V2 pending independently reviewed licensed PCAP and analyst approval. Deferred verifier `scripts/verify-all-rule-batches.ps1` unchanged.

**R301–R310 combined 140 advanced xUnit facts authored, ZERO executed. Next R311–R315 then R316–R320.**

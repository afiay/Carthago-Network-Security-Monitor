# R261–R265 — typed network path and conservative proxy/Tor/VPN attribution

**CANDIDATE — UNVERIFIED.** Authored 2026-10-28 on the existing `feature/carthago-reliability-hardening` branch. **47 advanced xUnit facts authored (R261=9, R262=10, R263=9, R264=9, R265=10); ZERO executed.** No builds, xUnit, replay, benchmarks, holdouts, CI, GitHub Actions or Windows runner were run.

## Commits and changed paths

Source commit: `e0c94719367a281d156b369b888591343281968f`.
Tests commit: `e7d75dc9f1ed3ec1aaf8fac7a15e17565d739459`.

Production: `Carthago/Engine/Rules/Expansion/NetworkBatch261265Evidence.cs`, `R261_TtlAnomalyToSameServiceRule.cs`, `R262_SuspiciousPacketFragmentationRule.cs`, `R263_UserSpaceProxyProcessEgressRule.cs`, `R264_TorDirectoryOrGuardConnectionRule.cs`, `R265_PublicVpnProxyDomainContactRule.cs`, `EvasionInfraPrecisionDetectionRuleBase.cs`, `Carthago/Models/TrafficRecord.cs`.

Tests: `Carthago.Tests/NetworkBatch261265Context.cs`, `R261AdvancedAccuracyBatchTests.cs` through `R265AdvancedAccuracyBatchTests.cs`. Each class preserves the existing minimum-confidence, threshold and default-mode contract. No new replay labels or frozen holdout changes.

## Per-rule observable contracts and advanced test coverage

- **R261 (9):** Three distinct packet IDs with numeric IP TTL/hop-limit observations to the same source/destination/service in a 15-minute detector-instance window; require a spread of at least 16. Tests cover positive path spread, stable TTL, Info spoof, invalid TTL, replay and out-of-order, destination isolation, window expiry, evidence privacy and profile policy. This is a path-change heuristic, not a claim of spoofing, maliciousness, or an approved route baseline. PacketHandler populates `TrafficRecord.TTL`, but live detection is unverified.
- **R262 (10):** Typed IPv4 noninitial fragment offset, More Fragments bit, and tiny payload length in a bounded two-packet window. Tests cover positive *synthetic contract*, missing fields, Info spoof, ordinary payload size, unsupported IPv6 contract, contradictory L7, replay/out-of-order, source isolation, evidence privacy and profile policy. **PacketHandler currently drops fragmented IPv4 and non-atomic IPv6 frames; it does not populate the new fragment fields. This rule has NO proven live-capture reachability.** No overlap or successful evasion claim.
- **R263 (9):** Exact allowlisted proxy/tunnel process basename co-observed with internal-to-external typed TCP flow. Tests cover positive, process-substring spoof, Info spoof, internal destination, UDP contradiction, missing process, Windows basename normalization, path/Info redaction and policy. Live process enrichment and actual policy-bypass attribution remain unverified.
- **R264 (9):** Exact `tor.exe`, `tor` or `arti.exe` basename co-observed with external typed TCP flow. Tests cover positive, port-only and website-only benign controls, Info spoof, process-substring spoof, internal destination, UDP contradiction, redaction and policy. **Tor guard/directory role and circuit establishment are NOT established** by process or port alone; trusted relay inventory correlation is still absent.
- **R265 (10):** External typed TCP/TLS with syntactically valid SNI matching an exact known provider domain or dot-delimited suffix. Tests cover positive, Info spoof, suffix impersonation, missing TLS, DNS-query-only, internal destination, UDP contradiction, unknown provider, redaction and policy. **SNI contact is not proof of VPN or proxy tunnel establishment** and HTTPS is not decrypted.

## State, privacy and compatibility

R261 and R262 use detector-instance-owned, bounded, replay/out-of-order rejecting observation windows; R263–R265 retain the existing rule cooldown and runtime policy. Untrusted packet Info and raw process paths are excluded from R261–R265 event evidence; only normalized process basenames and provider categories are added where relevant. The original confidence floors, severities, thresholds, default Alert/Shadow/Disabled policies, asset approvals, baseline readiness and approved architecture were not changed.

The `TrafficRecord` fragment properties are **typed contract placeholders only**; adding them does not alter PacketHandler's intentional no-reassembly/drop policy. Do not promote R262 based on these synthetic facts. R264 does not claim directory/guard identification, R265 does not claim a successful VPN connection. No field precision, recall, F1, emitted-alert recall or deployment readiness is established.

Frozen R102 V1 remains **FAILED 4/6**, immutable. V2 remains pending independent licensed PCAP evidence and analyst review/approval. The sole deferred Windows verifier `scripts/verify-all-rule-batches.ps1` is unchanged and unexecuted.

**Next consecutive rules: R266–R270, then R271–R275, unless the live branch has advanced.**

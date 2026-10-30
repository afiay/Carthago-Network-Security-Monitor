# GA R521–R530 — evasion behavior and sensor-health provenance boundaries

**SOURCE CANDIDATE — UNVERIFIED · 2026-10-30.** Existing branch `feature/carthago-reliability-hardening`. Live inspected base HEAD `3eefe8873fcfb2156ea8badbf4a8676b7cdbba02` (UI-17 and R511–R520 present); source commit `944c7b6e406bac0ae951a21386421968bd5d98c1`; authored-test commit `da51479aeb6d4e3bfa62846982483cb91456a929`. **270 concrete xUnit invocations AUTHORED; 0 EXECUTED.** No builds, xUnit, replays, holdouts, CI, Windows runners, benchmarks or production captures executed. The atomic publication SHA is the resulting documentation-descendant branch HEAD; a commit cannot embed its own SHA.

## Evidence-first review and ten-rule dispositions

[TrafficRecord](../Carthago/Models/TrafficRecord.cs) exposes bounded HTTP method/host/User-Agent, TLS SNI, packet sizes and QUIC version/optional ALPN/CID hash. [PacketHandler](../Carthago/Services/PacketHandler.cs) decodes some cleartext HTTP and QUIC headers; [MsQuicEtwListener](../Carthago/Services/Etw/MsQuicEtwListener.cs) emits isolated ETW connection records with an optional hashed CID. None of these producers authenticates proxy policy, WebSocket tunnel establishment, correlated encrypted HTTP authority, ECH provider approval, session-linked CID rotation, calibrated beacon/UA anomaly baselines, or a site-health metric. [RuleHealthSnapshotService](../Carthago/Engine/Rules/Health/RuleHealthSnapshotService.cs) produces diagnostic snapshots, not authenticated sensor heartbeat or clock-offset `TrafficRecord` events. The original [platform-health base](../Carthago/Engine/Rules/Expansion/PlatformHealthAdvancedPrecisionDetectionRuleBase.cs) accepts mutable text, application labels and process names as health anchors; those are not an authenticated sensor provenance contract.

All ten named behaviors are **BLOCKED** until their independent evidence producers and policies exist. Existing generic hints may support investigation but cannot substantiate these named alerts. This is not an executed recall or precision measurement.

| Rule | Existing name | Required independent predicate / missing-producer reason | Original default (severity; mode; floor; threshold; window; cooldown) | Disposition / legitimate-traffic risk |
| --- | --- | --- | --- | --- |
| R521 | HTTP CONNECT To Non Proxy Port | `HTTP_CONNECT_PROXY_PORT_POLICY_AND_SESSION_UNAVAILABLE` | Medium; Alert; 84%; 1; 20m; 35m | **BLOCKED** — approved CONNECT proxies, developer tunnels and secure gateways |
| R522 | WebSocket Tunnel To IP Literal | `WEBSOCKET_UPGRADE_TUNNEL_SESSION_PROVENANCE_UNAVAILABLE` | High; Alert; 84%; 1; 20m; 35m | **BLOCKED** — approved IP-literal WebSocket endpoints and test services |
| R523 | Domain Fronting Host SNI Mismatch | `DOMAIN_FRONTING_SNI_HTTP_AUTHORITY_CORRELATION_UNAVAILABLE` | High; Alert; 84%; 1; 20m; 35m | **BLOCKED** — CDNs, reverse proxies and unrelated HTTP/TLS observations |
| R524 | ECH To Unapproved Provider | `ECH_PROVIDER_APPROVAL_AND_HANDSHAKE_PROVENANCE_UNAVAILABLE` | Medium; Alert; 84%; 1; 20m; 35m | **BLOCKED** — legitimate ECH privacy providers and managed browsers |
| R525 | QUIC Connection ID Rotation Burst | `QUIC_CID_ROTATION_SESSION_BASELINE_UNAVAILABLE` | Medium; Alert; 84%; 4; 10m; 35m | **BLOCKED** — normal QUIC migration, NAT rebinding and CID privacy rotation |
| R526 | Packet Size Mimicry Beacon | `PACKET_SIZE_MIMICRY_CALIBRATED_BASELINE_UNAVAILABLE` | Medium; Alert; 84%; 3; 120m; 35m | **BLOCKED** — legitimate keepalives, fixed-size application messages and backups |
| R527 | Sleepy Beacon Long Gap Pattern | `SLEEPY_BEACON_LONG_GAP_BASELINE_UNAVAILABLE` | Medium; Alert; 84%; 3; 120m; 35m | **BLOCKED** — idle clients, scheduled jobs, power saving and capture gaps |
| R528 | User Agent Randomization Burst | `USER_AGENT_DISTINCT_REQUEST_BASELINE_UNAVAILABLE` | Medium; Alert; 84%; 4; 10m; 35m | **BLOCKED** — browser upgrades, shared proxies, QA automation and privacy tools |
| R529 | Sensor Heartbeat Missing For Site | `SENSOR_HEARTBEAT_TRUSTED_HEALTH_PRODUCER_UNAVAILABLE` | High; Alert; 86%; 1; 10m; 20m | **BLOCKED** — maintenance windows, planned shutdowns and disabled sensors |
| R530 | Sensor Clock Skew Increasing | `SENSOR_CLOCK_SKEW_TRUSTED_METRIC_PRODUCER_UNAVAILABLE` | Medium; Alert; 82%; 1; 10m; 30m | **BLOCKED** — VM sleep/resume, NTP convergence and clock-source transitions |

**Evidence boundaries:** R521 needs a decoded CONNECT plus an authoritative approved-proxy-port policy and correlated tunnel/session outcome; R522 needs accepted WebSocket upgrade, IP-literal endpoint and actual tunnel-session classification; R523 needs same-session TLS SNI and HTTP authority (not arbitrary `HttpHost` + `Sni` fields); R524 needs decoded ECH handshake semantics and trusted provider approval; R525 needs session-linked CID transitions and normal migration baseline; R526–R527 need complete, deduplicated timing/size windows and calibrated benign controls; R528 needs distinct request-level User-Agent series with stable source identity and approved baseline; R529 needs authenticated site/sensor heartbeat cadence and maintenance policy; R530 needs authenticated numeric offset samples, trend and threshold. No request shape, packet count, hostname, Info text or spoofed audit header substitutes for those contracts.

## Source scope, contract preservation and static divergence

- Added [EvasionAndSensorEvidenceBoundary](../Carthago/Engine/Rules/Expansion/EvasionAndSensorEvidenceBoundary.cs), a stateless ten-rule missing-producer map with no new shared API, telemetry model, credentials or capture behavior.
- Updated [EvidenceDrivenPrecisionRuleBase](../Carthago/Engine/Rules/Expansion/EvidenceDrivenPrecisionRuleBase.cs) to fail closed for **R521–R528 after core-telemetry validation but before HTTP applicability, generic scoring, threshold windows, cooldown or alert construction**. Existing prior-batch guards and all other rule IDs are unchanged.
- Updated [R529](../Carthago/Engine/Rules/Expansion/R529_SensorHeartbeatMissingForSiteRule.cs) and [R530](../Carthago/Engine/Rules/Expansion/R530_SensorClockSkewIncreasingRule.cs) to reject untrusted text-based health narratives before their legacy heuristic match path. This intentionally suppresses previously possible unauthenticated text matches; the old matching logic remains for a future typed integration. No actual connected trusted health producer was identified. The original `Validated` maturity metadata is preserved as historical profile metadata, **not** a claim of operational validation.
- Authored [NetworkBatch521530AccuracyTests](../Carthago.Tests/NetworkBatch521530AccuracyTests.cs) (**UNEXECUTED**). Updated only this batch page and [progress ledger](RULE_HARDENING_PROGRESS.md) in documentation. No UI, capture, service, model, workflow, runner, previous-rule profile, approval, privacy, baseline or frozen holdout file changed.
- All original modes remain **Alert**, original severity/floor/threshold/window/cooldown unchanged. R521–R528 retain 84% floors and 35m cooldown; R525/R528 4 observations/10m, R526/R527 3 observations/120m, others 1/20m. R529 retains High/86%/1/10m/20m and R530 Medium/82%/1/10m/30m. Original `Validated` maturity enum is not evidence of tests or producer reachability.
- **Pre-change review:** R511–R520 was the latest documented batch; all ten R521–R530 original classes existed; no prior R521–R530 missing-producer guard or batch xUnit file existed. UI-17 changed UI/design paths only. **Pre-publication review:** compare exact changed paths, original profiles, evidence contracts and remote HEAD, then use one non-forced expected-HEAD update. Static review is not compilation.

## Exact authored scenario inventory — 0 executed

A parameterized xUnit theory declares **26 variants for each of ten rules** (260 concrete invocations) plus **one original-profile invariant for each rule** (10 invocations), total **270 authored, 0 executed**. All cases use documentation-range addresses, deterministic GUIDs and synthetic redacted placeholders. For R521–R528, missing-core cases expect `MISSING_CORE_TELEMETRY`; R529–R530 always return their rule-specific producer reason because no authenticated sensor health producer is connected. Other variants assert no match, no event and the exact rule-specific missing-producer code. Authored assertions are not pass results.

| # | Variant | Intended regression boundary |
| --- | --- | --- |
| 01 | `plausible` | Realistic request/flow or claimed health event without independently verified producer |
| 02 | `descriptor-spoof` | Rule ID and claimed validated success injected into mutable Info |
| 03 | `approved-admin` | Legitimate administrative or maintenance workflow |
| 04 | `forged-audit` | Client-controlled X-Audit/X-Sensor/X-Proxy headers |
| 05 | `tls-only` | Encrypted transport with no decoded HTTP request |
| 06 | `missing-source` | Absent source identity; R521-R528 must reject core telemetry |
| 07 | `missing-destination` | Absent destination, host, process and Info fallback; R521-R528 reject core telemetry |
| 08 | `malformed-target` | Invalid percent escape and truncated packet measurements |
| 09 | `synthetic-secret` | Redacted synthetic Authorization/header/URI placeholders |
| 10 | `inbound` | Opposite network direction |
| 11 | `wrong-protocol` | TCP/UDP flag inconsistency |
| 12 | `threshold-burst` | Six distinct events still cannot invent producer evidence |
| 13 | `claimed-success` | Fabricated ECH/WebSocket/heartbeat success text |
| 14 | `duplicate-id` | Repeated identical record ID |
| 15 | `spoofed-process` | Untrusted process and application service names |
| 16 | `quic-cid-only` | QUIC version and isolated hashed CID without rotation correlation |
| 17 | `ech-claim-only` | ECH ClientHelloOuter text without accepted handshake or policy |
| 18 | `after-cooldown` | Two events separated by 40 minutes, no evidence producer |
| 19 | `provider-lookalike` | Lookalike trusted proxy/provider hostname |
| 20 | `request-only` | CONNECT request without correlated proxy outcome |
| 21 | `response-only` | Unpaired HTTP 200 response label |
| 22 | `host-sni-mismatch-unpaired` | Two uncorrelated authority/SNI values |
| 23 | `out-of-order` | Out-of-order event times, no proof |
| 24 | `useragent-rotation` | Five distinct client-controlled User-Agent values without trusted grouping/baseline |
| 25 | `heartbeat-prose` | Untrusted sensor-heartbeat-missing narrative |
| 26 | `clock-drift-prose` | Untrusted clock-skew-increasing narrative |
| 27 | `OriginalProfiles` | One invariant per rule: original Alert mode, confidence floor, threshold, window, cooldown and maturity |

## Open quality GAs and next contiguous batch

**GA PRODUCERS:** Correlated HTTP CONNECT/WebSocket outcomes and trusted proxy policy; same-session SNI/authority observation; ECH provider approval; QUIC CID session mapping with privacy-safe bounded state; calibrated packet-timing and User-Agent anomaly baselines; authenticated site/sensor heartbeat and numeric clock-offset sources. Treat network clues as investigatory only until validated.

**GA VALIDATION:** Windows build; execute the 270 authored xUnit invocations and existing regressions; adversarial spoofing, privacy and capture-loss checks; positive fixtures only after real producer integration; field precision/recall and legitimate-traffic controls. All **OPEN**; no positive validated detections. Historical 4,940/4,940 checkpoint predates these candidates; frozen R102 V1 FAILED 4/6 and V2 0/4 approved external sources remain unchanged; R343/R295/R275/R163 replay expectations remain separate.

**Next independent contiguous batch after safe publication: R531–R540**, subject to fresh live branch and source inspection. Do not treat an external R102 evidence dependency as a blocker for unrelated rule development.

## References

- [RFC 9110 — HTTP semantics / CONNECT](https://www.rfc-editor.org/rfc/rfc9110.html)
- [RFC 6455 — WebSocket protocol](https://www.rfc-editor.org/rfc/rfc6455.html)
- [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [RFC 9000 — QUIC connection IDs and migration](https://www.rfc-editor.org/rfc/rfc9000.html)
- [Rule documentation standard](rules/RULE_DOCUMENTATION_STANDARD.md)

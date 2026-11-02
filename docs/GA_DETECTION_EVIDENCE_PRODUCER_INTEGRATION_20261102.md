# GA Detection Evidence Integration — R437, R485, R508, R516

**Branch:** `feature/carthago-reliability-hardening` (existing branch only)  
**Baseline verification:** Owner Windows Release build with zero warnings and xUnit 9,762/9,762 GREEN at `e73650fc594179d6c7c1db5d5b933a8eff4bd082`.  
**This GA:** **SOURCE CANDIDATE — UNVERIFIED** until an owner-authorized exact-SHA test. No detection recall, new alert, or external capture claim is made here.

## Aim and immovable constraints

Improve the **existing** Carthago rule engine's positive-detection *evidence*, not create a separate protocol/rule system. First trace each named rule backwards from `RuleRegistry` to `EvaluatePrecision`, its `EvidenceBoundary`, the `TrafficRecord` producer, the native parser, and the actual live capture path. A parser accepting bytes is not proof of a real observed session, trusted endpoint identity, command execution, successful change, approved/unapproved status, or exfiltration.

Preserve malicious replay `ExpectedMatches` and `MissingExpectedMatches` truthfully. Do not turn an unverified request into a positive security detection, lower confidence floors, promote Shadow candidates, skip detection-quality gates, alter frozen V1 or publish/approve V2 source evidence.

## Gap audit

| Existing rule | Available components found | What prevents an authenticated positive | Status after this GA |
| --- | --- | --- | --- |
| **R437 — Redis CONFIG SET Indicator** | `Resp2CommandInspector` already parses bounded RESP2 arrays of bulk strings, `PacketHandler` captures early TCP bytes, and `TrafficRecord` carries capture-derived properties | Before this GA the RESP2 inspector was isolated. Even a decoded request does **not** establish a trusted Redis server response, authorization/asset policy or completed change | **First-payload request-shape wiring implemented; detector still fail-closed** |
| **R485 — BACnet WriteProperty Request** | `OtProtocolLight` recognizes BACnet BVLC/NPDU framing; `BacnetBvlcControlInspector` parses selected control-plane BVLC envelopes but is not connected to live capture | No bounded, verified **WriteProperty APDU** service/invoke-ID/property decoder, request/reply correlation or trusted engineering-host policy; `Info` is untrusted | **Open; no detection promotion** |
| **R508 — Rclone UserAgent Egress** | `WindowsProcessResolver` best-effort process-table enrichment; HTTP parser recognizes request metadata; network flows are captured | Client-supplied UA plus process-name enrichment cannot prove verified rclone executable identity or distinct completed file transfer; no joined local process/file/egress/server-outcome provenance | **Open; no detection promotion** |
| **R516 — Cloudflared Tunnel Handshake** | TCP/TLS/QUIC/SNI and process-name enrichment available | Generic tunnel endpoints/process labels cannot establish an authenticated Cloudflare connector ID or actual tunnel-session establishment; no trusted connector session source | **Open; no detection promotion** |

### R437: first integrated evidence producer

Files changed:

- `Carthago/Services/ProtocolIntelligence/Resp2CommandInspector.cs`: reuse the existing strict bounded RESP2 framing. Distinguish case-insensitive `CONFIG SET` only when an entire array of bulk strings has valid lengths and contains one or more full parameter/value pairs (`CONFIG`, `SET`, parameter, value, etc.). Observation carries a fixed boolean; do **not** retain any parameter name, value, credential, command bytes or server reply.
- `Carthago/Services/PacketHandler.cs`: admit a complete command only from the **first client TCP payload** immediately following an observed SYN, on the expected contiguous TCP sequence and destination port 6379, without a known TLS stream. The existing `ShouldAcceptSegment` early-data limit and bounded flow-state store remain; this is **not** general TCP stream reassembly. A capture starting midstream, missing bytes, encrypted payload, wrong direction or incorrect port does not produce trusted request-shape evidence.
- `Carthago/Models/TrafficRecord.cs`: `RedisRespConfigSetRequestObserved` (public getter, internal setter) is set by the packet parser only; untrusted JSON cannot ordinarily set it. A validated RESP2 command is tagged `ApplicationProtocol = "redis.resp2"`. This flag asserts *request shape only*, not command execution or abuse.
- `Carthago/Engine/Rules/Expansion/ServiceExposureEvidenceBoundary.cs`: keep the original R437 missing-producer reason `REDIS_RESP_CONFIG_SET_UNAVAILABLE`, with updated detail distinguishing available request-shape evidence from absent independently trusted Redis response/authorization context. **Do not bypass `EvidenceDrivenPrecisionRuleBase.EvaluateSpec` or alter `R437_RedisCONFIGSETIndicatorRule` in this GA.**
- Tests: extend the existing `Resp2CommandInspectorTests` with fixed-shape, multiple-pair, negative, truncation and no-secret-retention cases; add `RedisRespCaptureIntegrationTests` with raw synthetic IPv4/TCP SYN + first-payload frames, wrong direction/port, missing SYN, gap/out-of-order sequence, coalesced commands, JSON import forgery and confirmed R437 NoMatch. The new xUnit cases are **authored, NOT RUN**.

**What this deliberately does not detect:** Observing an attempted `CONFIG SET` on a TCP connection is not equivalent to the server applying the operation. This GA does not classify the attempt as an unauthorized configuration change or a true-positive intrusion. Valid private maintenance and synthetic attack traffic remain indistinguishable without an independently trusted outcome and asset policy.

## Next integration gates (no code duplication)

1. **R437 reply and policy (next source GA):** Design a separately bounded, privacy-preserving Redis client/server request/reply correlator with strict sequence coverage, client/server direction, transaction identity, and explicit error/OK reply distinction; consume a trusted server/asset inventory and approved management-source policy. Preserve the existing `Resp2CommandInspector` and `PacketHandler` infrastructure. Keep request-only observations diagnostic/Shadow or NoMatch until the owner approves policy and quality gates; **never infer authenticated server outcome from packet `Info` or Redis port**. Include positive *confirmed command* and benign administrator/false-positive pairs, fragmentation, retransmissions, protocol downgrade/TLS and spoofed/replayed labels.
2. **R485 BACnet APDU:** Add bounded BVLC/NPDU/APDU request parsing and independent invoke-ID/property association using the existing OT packet capture path. Recognizing BVLC or WHO-IS/IA-M is not decoding WriteProperty. Validate boundaries and engineering-source approval, distinct benign ReadProperty and rejected service outcomes, before rule promotion.
3. **R508 process/egress:** Extend existing Windows process/flow enrichment with independently attributed process identity (PID + start time + executable provenance), time-bounded local file/byte correlation and corroborated external transfer responses without retaining file content/secrets. Separate suspected transfer from completed exfiltration.
4. **R516 connector/session:** Integrate authenticated local Cloudflare connector/session audit or service data with stable connector identifiers and strict flow correlation; SNI, QUIC/7844 and process name must never establish an authenticated tunnel alone.

## Independent verification and release constraints

- **Source candidate:** no test was run by the assistant. Owner must explicitly authorize test time, fast-forward, record exact branch SHA, run `dotnet build -c Release`, the targeted `Resp2CommandInspectorTests|RedisRespCaptureIntegrationTests|NetworkBatch431440AccuracyTests|TuningBenchmarkTests` filter, and the complete `Carthago.Tests` regression suite with TRX. A green xUnit run does not approve detection quality.
- **Quality gate:** replay `rclone-exfil` R508, `redis-config-set` R437, `bacnet-write-property` R485, and `cloudflared-tunnel` R516 retain original malicious labels and visible missed positives. Compare matched/missed, FP/TP, evidence-producer coverage and policy before and after each implementation. No relabeling, synthetic evidence promotion or tuning threshold reductions to gain green results.
- **Provenance:** authored synthetic RESP2 tests do not establish external source-capture rights, real endpoint identity, source attestations or approved holdouts. Do not touch frozen Holdout V1 (historical FAILED 4/6), and keep V2 `PENDING_EXTERNAL_CAPTURE_AND_REVIEW` with 0 approved. Confidence floors stay R102 80%, R118 86%, R163 84%.
- **Concurrent work:** all source changes go to the same existing feature branch; later automated rule/UI commits are separately **CANDIDATE — UNVERIFIED** until their own exact-SHA test evidence.

## Protocol reference

- Redis protocol RESP: https://redis.io/docs/latest/develop/reference/protocol-spec/
- Redis CONFIG SET command and multi-parameter syntax: https://redis.io/docs/latest/commands/config-set/

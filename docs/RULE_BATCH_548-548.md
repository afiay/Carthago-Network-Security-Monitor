# CARTHAGO — GA R548: External Modbus write-request target fanout

**Status:** SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; **0 EXECUTED**.  
**Branch:** `feature/carthago-reliability-hardening` only.  
**2026-11-01 source base HEAD:** `dc51ac8486607462b59e66bfa2fbfa52aa8198c6` (UI-71 documentation, disjoint from detection-owned paths).  
**Source/test commit:** `732fea8e0ff16f27b2628b2e77719aac18d6f0a8`; test source blob `b386482b51f0afa9cc64c94c9f7367e5443b17b1`. The documentation commit is the final expected-HEAD-protected publication commit; inspect the branch/commit URL for its exact SHA after publication.  
**Research:** original P0038 Modbus and P0039 Modbus/TCP (one protocol family, not two new parsers); immutable 500-entry inventory and [protocol ledger](protocols/PROTOCOL_EXPANSION_PROGRESS.md). This GA adds one RNNN rule, not another P ID or isolated inspector.

## Rule and deduplication decision

| Rule | Producer and exact predicate | Policy and reachability | Existing overlap / false positives |
| --- | --- | --- | --- |
| **R548 — External Modbus Write Target Fanout** | `PacketHandler.ParseFrame` → `OtProtocolLight.TryIdentifyTcp` (MBAP length, protocol ID and client-side write function 05/06/15/16) → typed `TrafficRecord.ApplicationProtocol="modbus.write"`, `IsTcp`, `Protocol="TCP"`, `IpVersion=4`, `L4Len=12..260`, `SourcePort!=502`, `DestinationPort=502`, distinct `Id`, source/destination. One public IPv4 source addresses **three distinct RFC1918 IPv4 destinations** within five minutes. | **CONDITIONAL** on visible TCP payloads and the existing bounded producer; **Critical / Candidate / Shadow / 90% floor / 3 distinct targets / 5m / 10m cooldown**. No new capture integration. | R240 detects individual parsed Modbus write requests, R476 describes coil-write bursts with deeper telemetry gates, R223 covers internal-to-external OT traffic. R548 alone correlates **one external source across multiple private Modbus write targets**. Legitimate NAT/VPN, remote engineering, maintenance and multi-PLC commissioning may look similar. |

The typed `ApplicationProtocol` is set by the bounded packet parser on the live capture path, but it is **publicly mutable in `TrafficRecord`**. An imported or synthetic record must not be treated as authenticated wire provenance. The rule checks coherent typed TCP/IPv4, source/destination, non-QUIC, unencrypted transport and bounded length, and rejects contradictory HTTP/DNS/TLS fields, but it does not authenticate a source host, an operator, or a PLC. The current parser inspects early TCP bytes without complete stream reassembly. Fragments, TLS-wrapped Modbus, NAT vantage-point ambiguity and missing capture privileges reduce reachability. An observed request does not establish device response, register change, process impact, malicious intent or a CVE.

## Security rationale and dated sources

- [Modbus Organization, Application Protocol V1.1b3 (2012-04-26)](https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf): function codes 05/06/15/16 are write requests. [Current specifications index](https://www.modbus.org/modbus-specifications) distinguishes plain Modbus/TCP from Modbus Security (TLS/802).
- [MITRE ATT&CK ICS T0836, Modify Parameter](https://attack.mitre.org/techniques/T0836/), **last modified 2026-10-13**: protocol writes may be part of process manipulation, but [DET0776](https://attack.mitre.org/detectionstrategies/DET0776/) requires authorized engineering/asset roles, maintenance/change-control context and preferably downstream process-state corroboration before alert promotion.
- [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog): attempted live JSON retrieval on 2026-11-01 returned HTTP 403. **No R548-specific confirmed exploitation evidence** is asserted. [FIRST EPSS](https://www.first.org/epss/) estimates CVE exploitation likelihood, not whether this traffic represents exploitation; no CVE-specific score is applicable or invented.
- Threat classification for this **generic request pattern**: `UNVERIFIED` (not `CONFIRMED_EXPLOITED_ZERO_DAY`). Modbus writes and MITRE case studies do not prove any particular request is malicious.

## Evidence lifecycle, privacy and safety

- [R548 rule](../Carthago/Engine/Rules/Expansion/R548_ExternalModbusWriteTargetFanoutRule.cs) is an ordinary `IotOtAdvancedPrecisionDetectionRuleBase` registered once in [RuleRegistry](../Carthago/Engine/Rules/Catalog/RuleRegistry.cs), with `Rules.R548.Enabled`. Existing RuleEngine and JSONL journal-first handling remain unchanged; no direct alerts, UI updates, outbound sinks or fabricated audit events.
- Reuses `NetworkBatch236240Evidence.ModbusWrite` and `NetworkBatch226230Evidence.Window`: 4096 source buckets, at most 512 packet IDs/targets per bucket, monotonic timestamps, deduplicated IDs and bounded cooldown map. Saturation fails closed; no unbounded payload accumulation or replay bypass.
- Emitted evidence contains only `modbus.operation`, `matched_conditions`, aggregate `count`, `window_seconds` and destination port. Never copy `Info`, register values, command contents, credentials or raw payload into structured evidence. Packet endpoints remain ordinary existing `DetectionEvent` metadata.
- Default Shadow mode is deliberate: no approved OT asset inventory, gateway allowlist, change-control feed, authenticated device outcome or independent precision measurements are available. Do not promote to Alert based on this source candidate. Preserve all pre-existing R102/R118/R163 floors, frozen R102 V1 and pending V2 unchanged.

## Authored advanced scenarios — NOT EXECUTED

[R548AdvancedAccuracyBatchTests.cs](../Carthago.Tests/R548AdvancedAccuracyBatchTests.cs) contains **19 xUnit methods / 25 concrete invocations** (17 Facts and 2 Theories with 3 and 5 InlineData cases):

1. Positive wire-classified MBAP write request and three-distinct-private-target correlation, Critical severity, count and window.
2. Legitimate read, server response, internal engineering and repeated single-target negatives; guessed text/port-only evidence rejected.
3. Truncation, declared-length spoofing, public/nonpublic/multicast addressing, wrong transport/port, missing/overlong payload and contradictory HTTP/DNS/TLS metadata fail closed.
4. Duplicate packet IDs, out-of-order timestamps, distinct-source isolation, window expiry, cooldown suppression and concurrent arrivals.
5. Raw `Info` and register-value markers excluded from evidence; unique registry ID, Candidate/Shadow policy, 90% floor and catalog telemetry validation.

**Tests executed:** 0. **Builds/restores:** 0. **Replays/holdouts/CI/Actions/runners/benchmarks/scans/captures:** 0. No compilation success, field precision, recall, F1, exploit detection or production outcome is claimed. Owner authorization remains required: **“now it's test time.”**

## Scope, divergence review and next GA

The only changed paths are:

- `Carthago/Engine/Rules/Expansion/R548_ExternalModbusWriteTargetFanoutRule.cs`
- `Carthago.Tests/R548AdvancedAccuracyBatchTests.cs`
- `Carthago/Engine/Rules/Catalog/RuleRegistry.cs`
- `docs/RULE_BATCH_548-548.md`
- `docs/rules/PROTOCOL_INFORMED_THREAT_BACKLOG.md`

No UI files, design ledger, historical protocol research, shared capture/traffic model, journals, profiles, workflows, runner configuration, frozen holdouts or prior rules were modified. The paused legacy detection automation is not a concurrent writer; the active UI automation has disjoint ownership. Pre-publication must recheck live HEAD and reject overlapping detection changes or a stale atomic lease. **Next proposed GA: R549** only after another live registry/producer and threat-overlap audit. Prefer a new DNS or edge behavior with trustworthy typed evidence over another generic port or fanout heuristic.

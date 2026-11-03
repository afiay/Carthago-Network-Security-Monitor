# R226–R230 — typed OT/MQTT precision candidate

**CANDIDATE — UNVERIFIED.** Authored 2026-10-28 on `feature/carthago-reliability-hardening`. No build, xUnit, replay, holdout, CI, or runner was executed. This is an authored source/test contract, **not** accepted field accuracy.

## Scope and actual paths

Production: `Carthago/Engine/Rules/Expansion/R226_EthernetipCipDiscoveryBurstRule.cs`, `R227_ProfinetDcpDiscoverySuspiciousRule.cs`, `R228_OpcUaInternetEgressRule.cs`, `R229_MqttRetainedTopicAbuseRule.cs`, `R230_MqttLastWillSuspiciousRule.cs` and `NetworkBatch226230Evidence.cs`; `Carthago/Services/NetworkBatch226230Wire.cs`, `PacketHandler.cs`; `Carthago/Models/TrafficRecord.cs`; `Carthago/Engine/Rules/IotOt/IotOtPrecisionDetectionRuleBase.cs`.

Tests: `Carthago.Tests/NetworkBatch226230Context.cs`, `R226AdvancedAccuracyBatchTests.cs` through `R230AdvancedAccuracyBatchTests.cs` (9 authored xUnit facts each, **45 unexecuted**) and `NetworkBatch226230WireTests.cs` (**7 unexecuted parser facts**). Total **52 authored, zero executed**. No development replay fixtures added: typed L2 and OPC UA capture is not yet independently observable in the inspected adapter.

## Precision and state decisions

- **R226:** Require explicit wire-attributed EtherNet/IP ListIdentity operation on port 44818 and coherent TCP/UDP transport; eight distinct destinations within the original two-minute window. Added bounded first-frame EtherNet/IP ListIdentity recognizer in the TCP capture path. Port, Info and generic CIP alone do not qualify. Nine scenarios include positive burst, isolated inventory, spoofed Info, generic CIP, contradictory flags, duplicate IDs, source isolation, out-of-order frames and default Shadow/76 floor.
- **R227:** Profinet DCP Identify is **Ethernet L2**, not UDP/34964. Require an explicitly decoded `PROFINET-DCP` L2 record with valid MAC addresses and eight unique frames. The current IP-only `PacketHandler` **cannot produce these records**: the positive is an injected contract-only case, not live reachability. Nine scenarios cover L2 contract burst, UDP port-only, Info spoof, invalid MAC, generic Profinet, duplicate, source isolation, out-of-order and Shadow/76.
- **R228:** Require typed `opcua` ApplicationProtocol, coherent TCP/4840 and private-to-public IP egress. Port, service guess and Info cannot substitute for parsing. The current capture parser does **not** decode OPC UA, so the positive is contract-only. Nine scenarios cover typed positive, internal historian, port-only, contradictory UDP, service guess, replay, external source, evidence privacy and Alert/84.
- **R229:** Require parsed cleartext MQTT PUBLISH with retain flag, a parser-derived topic-present/control-topic category, and either a control-topic category or external broker. Exact topic bytes are **never retained** in TrafficRecord or detection evidence. Nine scenarios cover positive, internal status, Info spoof, near-match topic, external broker, TLS contradiction, duplicate, privacy and Shadow/74.
- **R230:** Require parsed MQTT 3.1.1 CONNECT with Will flag and parser-derived will-topic category; no Info-only will claims. Nine scenarios cover positive, routine availability, Info spoof, PUBLISH contradiction, external broker, TLS contradiction, duplicate, privacy and Shadow/74.

The new per-instance window limits keys to 4,096 and observations to 512 per source, rejects repeated packet GUIDs and backwards timestamps, and fails closed when saturated. Existing configured thresholds, cooldown profiles, confidence floors and default modes are unchanged. Shared IoT event building now omits raw Info and redacts host evidence for R226–R235; scoped source evidence uses fixed categories.

## Known limitations / deferred verification

- MQTT parser is a bounded **first-packet** MQTT 3.1.1 subset, not a stream reassembler, MQTT 5 decoder, TLS decryptor, or proof that retained data reached subscribers. Split packets, v5 CONNECT and MQTT over TLS are not classified.
- EtherNet/IP recognizer covers an exact TCP ListIdentity encapsulation header only. UDP ListIdentity and segmented traffic remain unverified.
- R227 requires a separately designed Ethernet-frame adapter; the current PacketHandler drops non-IP Profinet DCP frames.
- R228 requires independently parser-attributed OPC UA, which PacketHandler does not yet provide. These two rules' injected positives must not be counted as live detection evidence.
- Default Alert/Shadow behavior, confidence floors, asset approvals and baseline-readiness gates must be evaluated later through the existing consolidated Windows verifier `scripts/verify-all-rule-batches.ps1` **only after the owner explicitly authorizes testing**. The script was not run or modified.
- Frozen V1 R102 holdout remains **FAILED 4/6**, immutable. V2 is **PENDING** independent licensed PCAP and separate analyst review; R102 80%, R118 86%, R163 84% floors are unchanged.

**Next: R231–R235, then R236–R240.** This document does not certify the candidate.

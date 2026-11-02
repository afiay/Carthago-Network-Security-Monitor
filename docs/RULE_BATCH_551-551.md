# CARTHAGO — GA R551: External BACnet Discovery Followed by Modbus Write Requests

**Status:** SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED  
**Branch:** `feature/carthago-reliability-hardening`  
**Live source base SHA:** `6d9b7f8578f996926fb599523cb03a5e94180312` (2026-11-02)  
**Source, registry and authored-test commit SHA:** `19aca99dca435d51b02ce9edeb53aab20a06bce6` (unpublished until the cohesive documentation commit is atomically promoted).  
**Publication/documentation SHA:** the Git commit containing this document is the authoritative publication SHA; it is recorded in the publication result rather than embedded as an impossible self-referential Git hash.  
**Next proposed cursor:** R552, subject to a new live source/registry/producer and concurrency audit.

## Rule matrix and research mapping

| Rule | Historical P research | Producer and observable typed predicate | Mode / severity / confidence | Threshold / time / cooldown | Disposition |
| --- | --- | --- | --- | --- | --- |
| **R551** External BACnet Discovery Followed by Modbus Write Requests | **P0046 BACnet**, **P0382 BVLC** (related framing), **P0038 Modbus**, **P0039 Modbus/TCP** (same Modbus family) | `PacketHandler` → `OtProtocolLight` → `TrafficRecord.ApplicationProtocol` = `bacnet.whois` on IPv4 UDP/47808, then `modbus.write` on IPv4 TCP/502; identical public IPv4 source and RFC1918 target for each pair, two distinct targets | Candidate / **Shadow** / High / minimum **90%** | **2** completed targets / 5 min; max 120 s discovery-to-write; 10 min cooldown | **CONDITIONAL source-defined rule**, registered in the ordinary engine; no new parser, sensor or production validation |

**Novelty / overlap:** R241 covers BACnet discovery bursts; R545 and R547 cover one-direction public/private BACnet announcements and fanout; R550 correlates BACnet Who-Is with reverse I-Am shapes; R240 and R476 cover individual or repeated Modbus writes; R548 correlates Modbus write requests to three targets. **R551 instead requires two distinct ordered cross-protocol discovery-to-write pairs**, each with the same public source and private destination. One protocol, one target, one-way traffic, port-only records, or writes before discovery do not meet the predicate. The rule does not claim authorization, a write response, process modification, device compromise, or exploitation.

## Source-first reachability, evidence and privacy

- Existing producer: [PacketHandler](../Carthago/Services/PacketHandler.cs) calls [OtProtocolLight](../Carthago/Services/OtProtocolLight.cs) on visible early TCP payload and UDP datagrams; the OT classifier validates bounded BACnet BVLC length / Who-Is shape and Modbus MBAP length / write-function request direction. [NetworkBatch241245Evidence](../Carthago/Engine/Rules/Expansion/NetworkBatch241245Evidence.cs) and [NetworkBatch236240Evidence](../Carthago/Engine/Rules/Expansion/NetworkBatch236240Evidence.cs) supply conservative existing predicates. `ApplicationService` port guesses, `Info` and user-supplied headers are **not** used.
- Required typed fields: `TrafficRecord.Id`, `Source`, `Destination`, `IpVersion`, `IsTcp`, `IsUdp`, `IsQuic`, `Protocol`, `SourcePort`, `DestinationPort`, `ApplicationProtocol`, `L4Len`, and canonical `RuleEvaluationContext.TimestampUtc`. Reject contradictory TLS/HTTP/DNS fields. Exact public source/private target pairing is normalized via IPv4 parsing. No application credentials, register values or BACnet device identifiers are retained.
- **Conditional reachability:** the capture point must see *both* public-to-private operations, including early cleartext TCP/502 bytes. TLS-wrapped Modbus, encrypted BACnet/SC, NAT ambiguity, missing segments, port translation and single-sided capture are not observable through this predicate. The BACnet classifier validates a request *shape*, not a full authenticated application transaction. The Modbus classifier identifies write function codes but does not verify register semantics, server acknowledgement or safe operating ranges.
- **Trust boundary:** `TrafficRecord.ApplicationProtocol` is publicly settable; imported/synthetic records are not cryptographically attested. The authored tests demonstrate the real packet producer and reject Info-only/contradictory evidence, but cannot establish an unforgeable sensor origin. Retain **Shadow** until provenance/asset-role and replay evidence exists. No shared telemetry/schema changes are authorized.
- **False positives:** legitimate BACnet/Modbus gateways, multi-protocol commissioning, authorized remote engineering, maintenance and asset inventory. Approved gateway, source-role, destination asset and maintenance-window controls are **recommended future tuning**, not claimed as implemented allowlists.
- **State bounds:** per-rule lock, at most 1,024 source buckets, 32 private targets and 128 packet IDs per source; five-minute pruning; monotonic timestamps and unique IDs; saturation fails closed; duplicate and repeated completed-target writes cannot inflate pair counts. Repeated completed pairs during ten-minute cooldown return `SuppressedMatch`, preserving suppression accounting.
- **Event lifecycle:** R551 returns a normal `RuleEvaluationResult.Match` and fixed non-secret `DetectionEvidenceItem` values. The existing engine owns JSONL journal-first persistence and downstream delivery. No direct UI, incident, external sink or false audit write. No changes to existing confidence floors, rule modes, approvals, suppression semantics, pinned holdouts or RNNN IDs.

## Threat research — primary references and classification

| Source / date | Relevance | Exploitation classification |
| --- | --- | --- |
| [ASHRAE BACnet Standard 135-2020 Addendum bx](https://bacnet.org/wp-content/uploads/sites/4/2024/10/135_2020_bx_20240930.pdf), approved **2024-09-30** | Who-Is discovery and legitimate router/proxy behavior; no guarantee of target device identity | **UNVERIFIED** for this sequence |
| [Modbus Organization, Modbus Application Protocol V1.1b3](https://www.modbus.org/modbus-specifications), **2012-04-26** | Function 05/06/15/16 write requests; function 06 is a single holding-register write request | Protocol behavior, not exploitation evidence |
| [MITRE ATT&CK ICS T0846](https://attack.mitre.org/techniques/T0846/) and [T0836](https://attack.mitre.org/techniques/T0836/), last modified **2026-10-13** | Discovery and attempted parameter modification are distinct; DET0739/DET0776 recommend authorized source, baseline and outcomes for operational fidelity | Generic technique context, not a CVE or IOC |
| [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), consulted **2026-11-02** | Web catalog returned HTTP 403 during this review; no candidate-specific exploited CVE verified | **UNVERIFIED** |
| [FIRST EPSS](https://www.first.org/epss/), consulted **2026-11-02** | Predictive 30-day exploitation likelihood for individual CVEs; R551 has no CVE-specific claim and no assigned EPSS score | Not exploitation proof |

No affected product versions, confirmed zero-day IOCs, or vendor-confirmed exploitation can be inferred from the two packet-request shapes. No vulnerability signature is asserted.

## Source changes and authored scenarios

- [R551 rule](../Carthago/Engine/Rules/Expansion/R551_ExternalBacnetDiscoveryThenModbusWriteRule.cs) — one normal `IotOtAdvancedPrecisionDetectionRuleBase` rule.
- [R551 advanced tests](../Carthago.Tests/R551AdvancedAccuracyBatchTests.cs) — **22 xUnit methods: 20 Facts + 2 Theories with 8 InlineData cases = 28 concrete invocations**.
- [RuleRegistry](../Carthago/Engine/Rules/Catalog/RuleRegistry.cs) — exactly one explicit `R551` registration and `Rules.R551.Enabled` descriptor.
- This GA document, plus the [detection-owned protocol-informed backlog](rules/PROTOCOL_INFORMED_THREAT_BACKLOG.md).

The authored tests cover: actual IPv4 UDP/TCP `PacketHandler.ParseFrame` production; two-pair positive; Modbus read/I-Am/port-only/Info-only and legitimate negatives; malformed BVLC/MBAP, TLS/DNS/HTTP contradictions and nonpublic sources; source/target isolation; duplicate packet IDs; reverse-order and stale windows; exactly 120-second boundary; concurrency; cooldown suppression; bounded-state fail-closed; privacy; Shadow/Candidate/90% policy and registry uniqueness. Fixtures are synthetic, non-secret and do not simulate real device outcomes.

**Tests executed: 0; builds/restores: 0; replays/holdouts/CI/Actions/runners/benchmarks/scans/captures: 0.** No compile success, precision, recall, F1, operational detection or exploit-detection claim. The 2026-10-31 historical user-run results are not evidence for this GA.

## Pre-publication divergence and next decision

Only detection-owned source, its tests, the registry, this report and the detection-owned backlog are in scope. No UI paths, `docs/design/**`, historical protocol research, shared capture/telemetry, journal, workflows, runners or holdouts may change. The independent UI automation is enabled; overlapping older detection automations were paused at source review. This GA is published only by one non-forced expected-HEAD-protected atomic update after comparing live branch HEAD and the exact changed paths. If the HEAD moves incompatibly, stop publication.

**Next proposed R552:** re-audit the live registry and deduplicated backlog; do not assume the next ID or register speculative MQTT/DTLS/HTTP/Windows outcomes without trustworthy producers. Candidate priority: a distinct, evidence-reachable, high-impact behavioral sequence rather than another protocol/port label.

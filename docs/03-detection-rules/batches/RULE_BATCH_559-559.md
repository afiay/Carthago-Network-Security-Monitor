# CARTHAGO — GA R559: internal cross-subnet BACnet discovery followed by Modbus write requests

**Branch:** `feature/carthago-reliability-hardening`  
**Source audit base HEAD:** `e275ab0eb9b65c96c714c3e8bf9bfa0ad1dec086` (2026-11-02).  
**Status:** **SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED.** No restore, build, xUnit, replay, holdout, CI, runner, capture, benchmark or packet scan executed.

## Research, novelty and observable malicious predicate

**R559 — Internal Cross-Subnet BACnet Discovery Followed by Modbus Write Requests** maps to **P0046 BACnet / P0382 BVLC** and **P0038 Modbus / P0039 Modbus-TCP** (one Modbus family). The owner CSV and corrected audit classify both wire producers as **PARTIAL**, not complete supported protocol decoders. R551 correlates two public-source BACnet→Modbus target pairs; R547/R550 cover BACnet discovery, R240/R548/R557 cover Modbus write requests/fanout. **R559 requires one RFC1918 source to complete ordered BACnet Who-Is→Modbus write-request pairs to targets in two distinct remote RFC1918 /24 networks, excluding the source's own /24.** It is not simple port fanout or a new protocol runtime.

**Threat hypothesis:** a compromised internal gateway/engineering host could discover devices across routed OT segments then attempt Modbus write operations. Legitimate multi-protocol gateways, SCADA maintenance and cross-segment commissioning can produce identical traffic. No source authentication, server acceptance, register value, device effect, compromise or CVE exploitation is established.

**Policy:** High / Candidate / **Shadow / minimum confidence 90%**; two remote /24s, same exact source/target in each pair, discovery before write within 120 seconds, all completed in 300 seconds; 600-second cooldown. Reject same-source-/24 traffic, two hosts in one remote /24, reads, responses, BACnet I-Am, port/Info guesses, missing/inconsistent protocol fields, duplicate IDs and stale/out-of-order observations.

## Producer, provenance, state and privacy

- **Actual existing producer:** `PacketHandler.ParseFrame` → `OtProtocolLight.TryIdentifyUdp` for bounded BACnet BVLC Who-Is and `OtProtocolLight.TryIdentifyTcp` for Modbus MBAP function 5/6/15/16 write request shapes. `NetworkBatch241245Evidence.Bacnet` and `NetworkBatch236240Evidence.ModbusWrite` verify typed direction/port/label. Required `TrafficRecord` fields: `Id`, `Source`, `Destination`, `IpVersion`, `IsUdp`, `IsTcp`, `Protocol`, `SourcePort`, `DestinationPort`, `ApplicationProtocol`, `L4Len`, plus evaluation timestamp. Both protocol packets must be visible from the same source at the capture point.
- **Provenance limit:** `ApplicationProtocol` remains publicly settable on imported records; a forged label cannot be cryptographically excluded by this rule. UDP source spoofing, NAT, missing TCP segments and one-sided capture affect attribution. Keep Shadow; require approved capture-origin attestation and maintenance/asset allowlists before Alert promotion.
- **Bounded state:** 1024 source buckets, 32 targets/source, 128 packet IDs/source; monotonic time, 5m expiry, 2m pair expiry, deduplication, 10m cooldown and fail-closed saturation. Completed distinct destination /24s are counted, not packets or same-/24 hosts.
- **Privacy/journal:** fixed operation names, aggregate count, timing and rule-owned condition tags only; no raw `Info`, packet bytes, credentials, device identifiers or register values. Existing `RuleEngine` journal-first lifecycle, suppression, Shadow/Disabled and all existing rule floors/holdouts remain unchanged.

## Authored xUnit — not executed

**25 methods (23 Fact, 2 Theory); 33 concrete invocations (23 Fact + 10 InlineData); 0 executed.** Scenarios cover real `PacketHandler` BACnet/Modbus parsing, positive two-network sequence, benign commissioning and same-subnet negatives, public/reserved addresses, spoofed/port/Info-only evidence, malformed BVLC/MBAP, reads/responses, source/target mismatch, duplicate IDs, timing boundaries, out-of-order, expired window, concurrency, cooldown, bounded saturation, privacy and registry/Shadow/confidence invariants. No build, tests, replay, holdout, CI or capture performed; no measured precision/recall claim.

## Dated primary threat research (2026-11-02)

- [FBI/EPA warning, 2026-07-30](https://www.fbi.gov/investigate/cyber/alerts/2026/malicious-cyber-actors-targeting-water-and-wastewater-sector-internet--facing-programmable-logic-controllers-causing-operational-disruptions): observed Rockwell MicroLogix PLC incidents and configuration tampering. **Different product/protocol context, not an R559 exploitation signature.**
- [MITRE ICS T0846](https://attack.mitre.org/techniques/T0846/) / [DET0739](https://attack.mitre.org/detectionstrategies/DET0739/) and [T0836](https://attack.mitre.org/techniques/T0836/) / [DET0776](https://attack.mitre.org/detectionstrategies/DET0776/), last modified **2026-10-13**: discovery and parameter modification detection require authorized asset roles, maintenance windows and, for outcomes, historian/controller corroboration.
- [Modbus V1.1b3 specification](https://www.modbus.org/modbus-specifications) (2012-04-26); [BACnet Committee standards/addenda](https://bacnet.org/addenda/) (updated 2025-07-01).
- [FIRST EPSS](https://www.first.org/epss/) forecasts CVE exploitation likelihood; no behavioral R559 score applies. No candidate-specific CISA KEV entry or confirmed exploitation is claimed.

## Changed paths and next checkpoint

Only five detection-owned files: the R559 class, advanced xUnit tests, `RuleRegistry.cs`, this GA report, and the detection-owned threat backlog. No UI, shared capture, protocol research, workflows, runners, or frozen holdouts touched. **Next proposed R560** only after fresh source/registry audit; reject pure mirrored fanout additions, favor independently observable new predicates. Authenticated OT asset roles and process outcomes remain **BLOCKED** pending owner-approved integration. **SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED.**

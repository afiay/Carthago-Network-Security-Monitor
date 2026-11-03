# CARTHAGO — GA R560: external BACnet reply followed by Modbus write request

**Branch:** `feature/carthago-reliability-hardening`  
**Source audit HEAD:** `11fa81f6d52f50ee752d42590151c8f4ce44f0f2` (2026-11-02).  
**Status:** **SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED.** No restore, build, xUnit, replay, holdout, CI, runner, capture, benchmark or packet scan executed in this GA.

## Novelty, protocol mapping and threat hypothesis

**R560 — External BACnet Reply Followed by Modbus Write Request** maps to **P0046 BACnet**, related **P0382 BVLC**, and **P0038 Modbus / P0039 Modbus-TCP**. These are historical research rows, not four fully validated decoders. The rule observes **one public IPv4 peer** send a BACnet Who-Is-shaped datagram to an exact RFC1918 endpoint, receive a reverse-direction I-Am-shaped datagram from that endpoint within **60 seconds**, then send a Modbus/TCP write-request shape to the **same endpoint** within **120 seconds** of the reply. All three distinct packet IDs must occur in order within **300 seconds**.

**Distinct coverage:** R550 requires two targets with Who-Is→I-Am-shaped pairs but no control request. R551 requires two targets with Who-Is→Modbus-write pairs but no reverse observation. R559 is internal-origin and two remote subnets. **R560 instead requires three directional stages at one exact target**, enabling targeted one-device reconnaissance-to-write *request* correlation, not another subnet-fanout mirror. This does not prove causal BACnet reply association or Modbus write success. It is a higher-specificity candidate, not an independent exploit signature.

**Benign lookalikes:** authorized building-management gateways, BACnet BBMD/device proxies, maintenance tools and commissioning often combine discovery with multi-protocol engineering. UDP spoofing, NAT, missing TCP first segments, capture placement and I-Am proxies can distort identity or correlation.

## Producer, policy, state, privacy and limitations

- **Existing producer only:** `PacketHandler.ParseFrame` → `OtProtocolLight.TryIdentifyUdp` for bounded `bacnet.whois`/`bacnet.iam` labels, and `OtProtocolLight.TryIdentifyTcp` for bounded `modbus.write` request shapes. Existing `NetworkBatch241245Evidence.Bacnet` and `NetworkBatch236240Evidence.ModbusWrite` provide typed transport and direction gates. Fields: `Id`, `Source`, `Destination`, `IpVersion`, `Protocol`, `IsUdp`, `IsTcp`, `SourcePort`, `DestinationPort`, `ApplicationProtocol`, `L4Len` and canonical UTC timestamp. Both directions and Modbus TCP first-segment payload must be visible.
- **Policy:** High / Candidate / **Shadow** / minimum confidence **90%** / threshold **one completed triple** / 300s total / 60s reply / 120s write / 600s cooldown. No operational Alert promotion without source attestation and approved engineering-host/asset-role/maintenance controls.
- **State:** lock-protected, 512 public-source buckets, 16 private targets per source, 96 packet IDs per source, monotonic timestamps, expiry, unique-ID suppression and fail-closed saturation. Cooldown suppression returns `SuppressedMatch`, not a second event.
- **Privacy:** only fixed operation names and aggregate condition tags in structured evidence; never `Info`, credentials, raw packet content, BACnet device IDs or Modbus register addresses/values. Normal `RuleEngine` journal-first event lifecycle is preserved.
- **Provenance limitation:** `TrafficRecord.ApplicationProtocol` is publicly settable, so imported record labels cannot be cryptographically authenticated by this rule. The positive path is demonstrable through the existing real packet classifier, but **not** proof of trusted sensor origin. No authenticated asset identity, server outcome, controller change, exploit or CVE is claimed. Keep Shadow until provenance and maintenance exclusions are validated.

## Authored xUnit, unexecuted

**21 test methods: 20 Facts + 1 Theory with 6 InlineData cases = 26 concrete invocations; 0 executed.** Covers actual `PacketHandler` classification of all three packet shapes, one-target positive, missing/unrelated replies, legitimate/nonpublic peers, Modbus reads, malformed BVLC/MBAP, Info-only and contradictory evidence, duplicate IDs, out-of-order timestamps, 60/120/300-second boundaries, cooldown suppression, concurrent writes, bounded target saturation, redaction and registry/Shadow/confidence invariants. No pass/fail or detection-quality claim is made.

## Dated primary references and evidence strength

- [BACnet Committee Addendum 135-2020bx](https://bacnet.org/wp-content/uploads/sites/4/2024/10/135_2020_bx_20240930.pdf), approved **2024-09-30**, describes device-address proxies and legitimate Who-Is/I-Am behavior.
- [Modbus Organization V1.1b3 specification](https://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf), dated **2012-04-26**, defines write functions and distinguishes requests from outcomes.
- [MITRE ATT&CK ICS T0846](https://attack.mitre.org/techniques/T0846/) and [DET0739](https://attack.mitre.org/detectionstrategies/DET0739/), last modified **2026-10-13**, emphasize authorized source roles and operational baselines; [T0836](https://attack.mitre.org/techniques/T0836/) last modified **2026-10-13** describes parameter modification but R560 sees only requests.
- [FIRST EPSS](https://www.first.org/epss/) is a CVE likelihood model, not evidence of this behavioral predicate. No R560-specific CISA KEV exploitation evidence, affected-product version, vendor-confirmed exploit or EPSS score established.

## Change scope and next cursor

Exactly five detection-owned paths: `Carthago/Engine/Rules/Expansion/R560_ExternalBacnetReplyThenModbusWriteRule.cs`, `Carthago.Tests/R560AdvancedAccuracyBatchTests.cs`, `Carthago/Engine/Rules/Catalog/RuleRegistry.cs`, this report and `docs/rules/PROTOCOL_INFORMED_THREAT_BACKLOG.md`. No UI, historical protocol ledger, shared capture/telemetry, runners, workflows, config, holdouts or unrelated tests changed. **Next proposed cursor R561** only after live source/registry audit; prefer independently observed behaviors, not more fanout mirrors. Stronger authenticated OT control-outcome detection remains **BLOCKED** pending owner-approved trusted sensor/asset evidence.

**SOURCE CANDIDATE — UNVERIFIED. TESTS AUTHORED; 0 EXECUTED.**

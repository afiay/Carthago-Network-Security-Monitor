# GA R545 — external BACnet I-Am announcement detection

**Branch:** feature/carthago-reliability-hardening  
**Status:** SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; **0 EXECUTED**  
**Source base HEAD:** 3bfb8562a7b63307277e82b59cfe49ff14a43e8b (2026-11-01)  
**Publication:** atomic branch commit containing this report (exact SHA is recorded in the run report; a commit cannot contain its own hash).  
**Scope:** One justified new rule, not a ten-rule quota. Next unallocated rule ID after this GA: **R546** (recheck live registry before reuse).

## Identity and evidence matrix

| Rule | Research inputs | Predicate and real producer | Policy | Limitation |
| --- | --- | --- | --- | --- |
| R545 External BACnet I-Am Announcement | P0046 BACnet NPDU; P0382 BVLC is a related layer, not an independent new detection | Two distinct \`bacnet.iam\` UDP datagrams from globally routable IPv4 source to RFC1918 destination within 5m; both ports 47808. \`PacketHandler\` calls \`OtProtocolLight.TryIdentifyUdp\` and sets \`TrafficRecord.ApplicationProtocol\`; \`NetworkBatch241245Evidence.Bacnet\` enforces typed operation/transport. | Candidate; High severity; **Shadow**; minimum confidence 80%; threshold 2; 5m observation window; 10m cooldown; source+destination state; enabled but non-paging. | I-Am is unauthenticated discovery, not device identity, authorization, exploitation, process manipulation or server acceptance. Requires visible BACnet/IP UDP and private-address target. IPv6, encrypted BACnet/SC, non-IP MS/TP, unobserved or fragmented messages not supported. |

**Distinct from existing rules:** R121 focuses on non-admin discovery; R241 requires a generic 15-message Who-Is/I-Am burst and does not require an external-to-private I-Am direction. R485/R486 are separate BACnet control/write hypotheses, not I-Am announcements. R223 is outbound ICS-to-Internet traffic. R545 is a narrower *external-origin device-announcement* signal; it does not duplicate R241's generic rate predicate.

**Security interpretation:** This is a suspicious cross-boundary device advertisement and possible exposure/misrouting, not a validated intrusion. MITRE ICS T0846 (Remote System Discovery) explicitly warns to incorporate authorized roles and operational baselines before alerting. Approved BACnet BBMDs, foreign-device registration, VPNs, NAT and commissioning are realistic benign lookalikes. No authenticated BBMD or asset-role inventory is presently joined to this record, so **Shadow must remain the default**. No CVE or zero-day exploitation is claimed. CISA KEV and FIRST EPSS were consulted as research sources, but no candidate-specific exploited CVE or EPSS value is asserted.

## Source, contracts and privacy

- New ordinary registered rule: [R545_ExternalBacnetIAmAnnouncementRule.cs](../Carthago/Engine/Rules/Expansion/R545_ExternalBacnetIAmAnnouncementRule.cs).
- Explicit registration: [RuleRegistry.cs](../Carthago/Engine/Rules/Catalog/RuleRegistry.cs); unchanged public rule/telemetry schemas and config conventions.
- Existing trusted packet route: [PacketHandler.cs](../Carthago/Services/PacketHandler.cs) → [OtProtocolLight.cs](../Carthago/Services/OtProtocolLight.cs) → [TrafficRecord.cs](../Carthago/Models/TrafficRecord.cs).
- Existing operation guard and bounded deduplicated window: [NetworkBatch241245Evidence.cs](../Carthago/Engine/Rules/Expansion/NetworkBatch241245Evidence.cs), [NetworkBatch226230Evidence.cs](../Carthago/Engine/Rules/Expansion/NetworkBatch226230Evidence.cs).
- No packet payload, BACnet device ID, raw \`Info\`, token or device identity is placed in either legacy or structured evidence. Only endpoints, operation label, count, time window and matched-condition codes are retained.
- Rule returns \`RuleEvaluationResult.Match\` or \`SuppressedMatch\`; it does not call UI, sinks, incidents or journals directly. The normal engine owns journal-first emission and mode enforcement.
- Only one rule-owned bounded 4,096-key cooldown map and the existing bounded 4,096-bucket/512-packet observation helper are used. Missing, malformed, contradictory, replayed, out-of-order or over-capacity inputs fail closed.
- The current producer inspects only the first bounded TCP/UDP message region; it does not reconstruct full BACnet sessions or verify the I-Am device identity. Its \`bacnet.iam\` classification is a frame-prefix observation, not a full APDU semantic validation. **Production validation pending.**

## Authored source-only scenario matrix

[R545AdvancedAccuracyBatchTests.cs](../Carthago.Tests/R545AdvancedAccuracyBatchTests.cs) includes 16 xUnit methods and 22 concrete invocations (14 \`Fact\` methods + two \`Theory\` methods with 5 and 3 cases). Scenario classes: valid wire classification and two-observation positive; internal/nonroutable and Who-Is negatives; truncated or inconsistent BVLC and text-only spoofing; transport/port contradiction; duplicate packet, out-of-order, destination isolation and expiry; cooldown suppression; raw-Info privacy; unique registration, confidence and Shadow mode. Counts refer to authored source, not executed tests.

**Tests authored:** 16 methods / 22 invocations. **Tests executed:** 0. **Builds/replays/CI/runners/captures:** 0. **Acceptance:** unverified until the owner explicitly authorizes testing.

## Outstanding obligations and next GA

1. Independent Windows compile/test, journal-first replay and representative BACnet/IP captures only after explicit test authorization. No measured precision, recall, F1 or production alert claim.
2. If production Alert is later considered, obtain authenticated BBMD/foreign-device, asset-role, gateway and maintenance-approval evidence via an owner-approved versioned integration proposal; do not infer approval from packet text.
3. Next GA: evaluate the next deduplicated [threat backlog](rules/PROTOCOL_INFORMED_THREAT_BACKLOG.md) candidate; **R546** is only a proposed next cursor, never a lease. The historical P inventory remains complete and unchanged.

## External references

- BACnet specification steward: https://bacnet.org/
- ASHRAE BACnet foreign-device/BBMD interpretation (2025): https://www.ashrae.org/file%20library/technical%20resources/standards%20and%20guidelines/standards%20intepretations/ic-135-2024-8.pdf
- MITRE ATT&CK ICS T0846 (last modified 2026-10-13): https://attack.mitre.org/techniques/T0846/
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- FIRST EPSS: https://www.first.org/epss/

# GA R481–R490 — industrial application-operation evidence boundaries

**SOURCE CANDIDATE — UNVERIFIED · 2026-10-30.** Existing branch: `feature/carthago-reliability-hardening`. Inspected live base HEAD `360485f90804f13ae922ef255afcd9561e383939`; source commit `29d0777c900026301177843e477cb95dff01af20`; authored-test commit `177b19e8da94d78de0b4650ebf37af700de4e3b5`. The documentation-descendant commit is the atomic publication target; its own SHA cannot be embedded in its tracked contents. **210 concrete xUnit invocations AUTHORED; 0 EXECUTED.** No build, test, replay, holdout, CI, runner, benchmark or production capture.

## Evidence-first review and ten dispositions

[TrafficRecord](../Carthago/Models/TrafficRecord.cs) retains source/destination, ports, application labels, bounded HTTP/TLS and packet metadata, **not** decoded industrial application services, authenticated control sessions, authorization outcomes, or trustworthy request-response provenance. [OtProtocolLight](../Carthago/Services/OtProtocolLight.cs) identifies some Modbus/S7/DNP3 framing and BACnet BVLC/NPDU; its DNP3 CRC check is link-layer only and BACnet identification only distinguishes some discovery labels. [PacketHandler](../Carthago/Services/PacketHandler.cs) does not provide the missing decoded operations to these rule predicates. ApplicationProtocol, Info, process names, ports, HTTP methods, or forged headers cannot be promoted into command evidence. No HTTPS decryption is assumed.

| Rule and original name | Decisive missing evidence | Original profile: mode; severity; floor; threshold; window; cooldown | Disposition and legitimate-traffic false-positive boundary |
| --- | --- | --- | --- |
| R481 DNP3 Freeze Counter Command | Application-layer freeze function, counter objects, client direction and approved master | Alert; High; 86%; 1; 10m; 45m | **BLOCKED** · `DNP3_FREEZE_COUNTER_APPLICATION_OPERATION_UNAVAILABLE`; approved counter freezes, substation maintenance |
| R482 IEC104 Control Command External | IEC 104 ASDU control type/cause, request direction and trusted external master policy | Alert; Critical; 86%; 1; 10m; 45m | **BLOCKED** · `IEC104_CONTROL_ASDU_AND_EXTERNAL_POLICY_UNAVAILABLE`; authorized remote control and operator tests |
| R483 OPC UA Browse Node Burst | Decoded Browse service requests, distinct nodes, session identity and calibrated rate baseline | Alert; Medium; 86%; 4; 10m; 45m | **BLOCKED** · `OPCUA_BROWSE_REQUEST_SERIES_UNAVAILABLE`; HMI browsing, discovery, historian enumeration |
| R484 OPC UA Write Request Indicator | Decoded Write service request and node, session authorization and response distinction | Alert; Critical; 86%; 1; 10m; 45m | **BLOCKED** · `OPCUA_WRITE_SERVICE_REQUEST_UNAVAILABLE`; legitimate HMI writes and process setpoint changes |
| R485 BACnet WriteProperty Request | Confirmed WriteProperty APDU/invoke ID, target, request direction and policy | Alert; Critical; 86%; 1; 10m; 45m | **BLOCKED** · `BACNET_WRITEPROPERTY_CONFIRMED_REQUEST_UNAVAILABLE`; BMS scheduling, commissioned building control |
| R486 BACnet DeviceCommunicationControl | Decoded DCC service, target, invoke ID and approved maintenance | Alert; Critical; 86%; 1; 10m; 45m | **BLOCKED** · `BACNET_DEVICE_COMMUNICATION_CONTROL_REQUEST_UNAVAILABLE`; planned device maintenance and BMS commissioning |
| R487 Profinet DCP Set Name Request | Validated L2 DCP Set Name frame, station identity and authorized engineering source | Alert; High; 86%; 1; 10m; 45m | **BLOCKED** · `PROFINET_DCP_SET_NAME_FRAME_UNAVAILABLE`; legitimate plant commissioning and device replacement |
| R488 EtherNetIP ListIdentity Burst | Decoded encapsulation ListIdentity transactions, distinct targets and discovery baseline | Alert; Medium; 86%; 4; 10m; 45m | **BLOCKED** · `ETHERNETIP_LISTIDENTITY_DISTINCT_BURST_UNAVAILABLE`; routine PLC inventory and engineering discovery |
| R489 EtherNetIP ForwardOpen External | Decoded CIP Forward_Open request/connection path, direction and trusted boundary policy | Alert; Critical; 86%; 1; 10m; 45m | **BLOCKED** · `ETHERNETIP_CIP_FORWARDOPEN_AND_BOUNDARY_UNAVAILABLE`; approved remote maintenance and controller connections |
| R490 IEC61850 MMS Write Indicator | Decoded MMS Write request/object, authenticated association and outcome distinction | Alert; Critical; 86%; 1; 10m; 45m | **BLOCKED** · `IEC61850_MMS_WRITE_OPERATION_UNAVAILABLE`; substation configuration and authorized setpoint writes |

All ten **BLOCKED**: no operational positive is representable with current trustworthy producers. This source-only guard prevents unsupported alerts; it **does not** establish detection recall or measured accuracy. The [shared evaluator](../Carthago/Engine/Rules/Expansion/EvidenceDrivenPrecisionRuleBase.cs) checks core telemetry, then [OtDeepOperationEvidenceBoundary](../Carthago/Engine/Rules/Expansion/OtDeepOperationEvidenceBoundary.cs) returns explicit `InsufficientEvidence` before RequireHttp, generic signal scoring, thresholds, state mutation, cooldown or event construction. Missing core telemetry returns `MISSING_CORE_TELEMETRY` where the shared evaluator is reached.

## Static divergence and integration findings

- Only detection-owned files changed: `Carthago/Engine/Rules/Expansion/EvidenceDrivenPrecisionRuleBase.cs`, new `Carthago/Engine/Rules/Expansion/OtDeepOperationEvidenceBoundary.cs`, new `Carthago.Tests/NetworkBatch481490AccuracyTests.cs`, this document and `docs/RULE_HARDENING_PROGRESS.md`. No UI, models, capture services, parser, workflows, runners or automation settings.
- Existing ten rule classes, IDs, configuration keys, Alert modes, severities, confidence floors, observation thresholds, 10-minute windows and 45-minute cooldowns remain unchanged. R483 and R488 retain threshold **4**; all others retain **1**. No baseline, approval, shadow/disabled, privacy, journal, or frozen R102 controls changed.
- R481: existing DNP3 recognition checks link CRC, not application freeze. R482: IEC104 ASDU control decoding is absent. R483–R484: OPC UA service decoding/session identity is absent; HTTP method indicators are not OPC UA service evidence.
- R485 has a **pre-existing untrusted `Info`-string WriteProperty prefilter** before `EvaluateSpec`; when that prefilter fails it returns `BACNET_WRITE_PROPERTY_NOT_OBSERVED` rather than the new evidence-gap code. When it passes, the new guard blocks. This ordering is preserved for compatibility; the string is **not** proof of a BACnet command. The existing BACnet parser recognizes framing/discovery only.
- R487 PROFINET DCP Set Name is link-layer discovery/configuration; original port indicators `34964, 49152` and HTTP methods do not prove DCP Set Name. R488–R489 retain empty original port/protocol indicators and HTTP method vocabulary; neither can prove an EtherNet/IP encapsulation/CIP operation. R490 shares TCP/102 with other ISO-on-TCP traffic, which is not MMS Write proof.
- Future integrations must first define typed, bounded, wire-validated request metadata with source/destination and direction, duplicate/out-of-order handling, redaction, authorized-asset policy and response/outcome distinction. Do **not** persist sensitive command values, credentials or arbitrary payloads. A decoded request may prove an *attempt* but not a successful control action.
- Static pre-change review used live HEAD `360485f` and preceding R471–R480 implementation/tests/docs. Source change is an early shared evaluator gate plus one small rule-specific boundary map; no duplicate protocol parser. Pre-publication review must confirm five owned paths, source/test/docs parent chain, latest live remote ref and unchanged unrelated UI blobs. No compilation or behavioral validation is claimed.

## Authored xUnit scenario inventory — UNEXECUTED

[NetworkBatch481490AccuracyTests](../Carthago.Tests/NetworkBatch481490AccuracyTests.cs) uses **20 named adversarial/boundary variations × 10 rules = 200 concrete invocations**, plus **10 original-profile invariant invocations**, totaling **210 authored, 0 executed**. The 20 variations for each rule are:

1. `plausible` — port and protocol-label clues only.
2. `wire-label-only` — framing label without decoded operation.
3. `descriptor-spoof` — operation name and fabricated success text.
4. `approved-engineering` — legitimate maintenance process and context.
5. `forged-audit` — attacker-controlled HTTP verification headers.
6. `tls-only` — encrypted traffic without decrypted service.
7. `missing-source` — absent source attribution.
8. `missing-destination` — absent destination/host and behavior text; R485's pre-existing prefilter is asserted separately.
9. `malformed-command` — truncated payload and invalid claimed APDU.
10. `secret-placeholder` — synthetic token-looking URI/header; no real secret.
11. `wrong-direction` — reversed client/server direction.
12. `wrong-protocol` — mismatched transport.
13. `threshold-burst` — six repeated unsupported observations cannot fill a validated window.
14. `claimed-success` — fabricated ACK/Write/Forward_Open outcome text.
15. `duplicate-id` — repeated observation identity.
16. `spoofed-process` — attacker-controlled process/service names.
17. `fragmentary-native` — truncated native traffic with protocol label.
18. `after-cooldown` — unsupported evidence remains blocked across 46-minute intervals.
19. `cross-boundary` — public documentation-address destination does not prove a control operation.
20. `spoofed-authority` — fabricated industrial-PDU and asset-inventory headers.

Profile invariants independently assert original `Alert` mode, confidence **86**, thresholds, windows and cooldowns for all ten rules. The synthetic fixtures **do not represent valid positive decoded commands**, and no test is described as passed. Source inspection is not compilation.

## Outstanding quality GAs and next batch

- Run deferred Windows compilation, all authored xUnit scenarios, privacy regressions, controlled native-protocol replay and field precision/recall measurement **only when the owner explicitly authorizes testing**.
- Obtain independently validated IEC104, OPC UA, BACnet, PROFINET DCP, EtherNet/IP/CIP and IEC61850 MMS application-layer producers; correlate authenticated source/asset policy and server responses. Avoid unsafe production control traffic.
- The historical **4,940/4,940** full regression checkpoint predates these batches. Frozen R102 V1 **FAILED 4/6** and V2 **0/4 approved sources** remain unchanged; independent R343/R295/R275/R163 replay expectations remain outstanding. Confidence floors R102 80%, R118 86%, R163 84%, external R102 0.75 remain unchanged.
- Next independent sequential development GA, after atomic publication and fresh inspection: **R491–R500**.

## References

- [Rule documentation standard](rules/RULE_DOCUMENTATION_STANDARD.md), [progress ledger](RULE_HARDENING_PROGRESS.md), [prior GA R471–R480](RULE_BATCH_471-480.md).
- [OPC Foundation UA Part 4 Services](https://reference.opcfoundation.org/specs/OPC-10000-4/full) and [Write service semantics](https://reference.opcfoundation.org/specs/OPC-10000-4/5.11.4) (a service-level request and server result are not inferred from TCP/4840).
- [BACnet Committee standard overview](https://bacnet.org/about-bacnet-standard/) (building-automation protocol and service semantics).
- [ODVA EtherNet/IP and CIP standards](https://www.odva.org/) (distinct encapsulation and CIP services; no port-only attribution).

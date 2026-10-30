# GA R471–R480 — remote-session and industrial-control operation evidence boundaries

**SOURCE CANDIDATE — UNVERIFIED · 2026-10-30.** Branch: `feature/carthago-reliability-hardening`. Inspected live base HEAD `69c92a8065c3d280129190615f697a0a6c753e34`; source commit `5962ae38b132b37f5f47a99fb075eaac21aaa23b`; authored-test commit `934223deb5a4d4c004165146e7fccf293592b092`. The documentation-descendant commit is the atomic publication target; its SHA cannot be embedded in itself. **200 concrete xUnit invocations AUTHORED; 0 EXECUTED.** No build, tests, replay, holdout, CI, Windows runner, benchmark or production capture.

## Evidence-first review and ten dispositions

[TrafficRecord](../Carthago/Models/TrafficRecord.cs) contains source/destination, ports, application labels, process name and bounded HTTP/TLS fields, **not** RDP clipboard virtual-channel contents, authenticated remote-support session authorization, or decoded OT application commands. [PacketHandler](../Carthago/Services/PacketHandler.cs) calls [OtProtocolLight](../Carthago/Services/OtProtocolLight.cs): its bounded TCP parser identifies Modbus framing and some write-function families, S7comm framing, and DNP3 link-layer CRC. It **does not** produce function-43 MEI-14, diagnostics subfunction, coil-specific write series, S7 CPU/block/identification operations, or DNP3 application-layer CROB. A protocol label is not a command or server outcome. Encrypted RDP content is not decrypted. No authenticated remote-support inventory or OT master/engineering authorization producer reaches these predicates.

| Rule and original name | Decisive missing producer/predicate | Original profile: mode; severity; floor; threshold; window; cooldown | Disposition; false-positive risk |
| --- | --- | --- | --- |
| R471 RDP Clipboard File Transfer Indicator | RDP clipboard virtual-channel file payload/direction and session policy | Alert; Medium; 76%; 1; 5m; 20m | **BLOCKED** · `RDP_CLIPBOARD_FILE_CHANNEL_PROVENANCE_UNAVAILABLE`; Authorized file copy, remote work and support sessions |
| R472 Remote Support Tool Unexpected Use | Authenticated remote-support session, trusted tool/asset inventory and unexpected-use policy | Alert; Medium; 76%; 1; 5m; 20m | **BLOCKED** · `REMOTE_SUPPORT_SESSION_AND_ASSET_POLICY_UNAVAILABLE`; Approved remote helpdesk and maintenance |
| R473 Modbus Function43 DeviceId Enumeration | Modbus function 43 / MEI 14 decoded request series and enumeration baseline | Alert; Medium; 86%; 4; 10m; 45m | **BLOCKED** · `MODBUS_DEVICE_ID_REQUEST_SERIES_UNAVAILABLE`; Commissioning and PLC inventory |
| R474 Modbus Force Listen Only Mode Attempt | Modbus function 08 / subfunction 0004 decoded client request | Alert; Critical; 86%; 1; 10m; 45m | **BLOCKED** · `MODBUS_LISTEN_ONLY_SUBFUNCTION_UNAVAILABLE`; Authorized diagnostics, controlled maintenance |
| R475 Modbus Diagnostics Function Abuse | Decoded function 08 subfunction, approved source and policy | Alert; High; 86%; 1; 10m; 45m | **BLOCKED** · `MODBUS_DIAGNOSTICS_SUBFUNCTION_AND_POLICY_UNAVAILABLE`; Engineering diagnostics and troubleshooting |
| R476 Modbus Coil Write Burst | Distinct Modbus function 05/15 client requests, rate baseline and approved sources | Alert; Critical; 86%; 4; 10m; 45m | **BLOCKED** · `MODBUS_COIL_WRITE_DISTINCT_BURST_UNAVAILABLE`; Approved coil writes, commissioning |
| R477 S7 Start Stop CPU Command Indicator | S7comm CPU control command decoded with direction and engineering-session policy | Alert; Critical; 86%; 1; 10m; 45m | **BLOCKED** · `S7_CPU_CONTROL_COMMAND_UNAVAILABLE`; Authorized CPU maintenance and commissioning |
| R478 S7 Upload Download Block Transfer | S7comm block transfer operation with request/response and outcome | Alert; Critical; 86%; 1; 10m; 45m | **BLOCKED** · `S7_BLOCK_TRANSFER_OPERATION_UNAVAILABLE`; PLC programming, firmware and backups |
| R479 S7 PLC Identification Probe | S7comm PLC identification request and source-attributed probe context | Alert; Medium; 86%; 1; 10m; 45m | **BLOCKED** · `S7_PLC_IDENTIFICATION_REQUEST_UNAVAILABLE`; Asset inventory and engineering tools |
| R480 DNP3 Control Relay Output Block | DNP3 application function and group-12 CROB operation with authorized master context | Alert; Critical; 86%; 1; 10m; 45m | **BLOCKED** · `DNP3_CROB_CONTROL_OPERATION_UNAVAILABLE`; Authorized substation controls and relay testing |

The [shared evaluator](../Carthago/Engine/Rules/Expansion/EvidenceDrivenPrecisionRuleBase.cs) first validates core telemetry. [LocalDiscoveryEvidenceBoundary](../Carthago/Engine/Rules/Expansion/LocalDiscoveryEvidenceBoundary.cs) now rejects R471–R472. The new [OtCommandEvidenceBoundary](../Carthago/Engine/Rules/Expansion/OtCommandEvidenceBoundary.cs) rejects R473–R480 before HTTP applicability, cross-boundary checks, generic signals, burst state, confidence, cooldown and event construction. Missing source/destination returns `MISSING_CORE_TELEMETRY`; otherwise the rule-specific code above is returned as `InsufficientEvidence`. These are **source-only contracts, not observed execution**.

**All ten BLOCKED.** This is an honest evidence limitation, not a validated negative/positive accuracy score. Their alerts cannot currently fire. An RDP port 3389 connection, an alleged remote-support process name, Modbus port 502, S7comm port 102 or DNP3 port 20000 is insufficient to prove a named operation. The legitimate-traffic risks above require trusted asset inventory and calibrated baseline policies before future operational enablement.

## Original contract preservation and static divergence review

- Source scope: modified only `Carthago/Engine/Rules/Expansion/LocalDiscoveryEvidenceBoundary.cs` and `Carthago/Engine/Rules/Expansion/EvidenceDrivenPrecisionRuleBase.cs`; added `Carthago/Engine/Rules/Expansion/OtCommandEvidenceBoundary.cs` and `Carthago.Tests/NetworkBatch471480AccuracyTests.cs`, plus this document and `docs/RULE_HARDENING_PROGRESS.md`. No shared models, capture service, UI, runner, workflow or original rule classes changed.
- R471–R472 retain **Alert**, Medium, **76%**, threshold **1**, **5-minute** window and **20-minute** cooldown. R473–R480 retain **Alert**, **86%**, **10-minute** window and **45-minute** cooldown; **R473/R476 threshold 4**, others 1. Original severity and enabled-by-default settings are unchanged. All approvals, baseline readiness, confidence floors, shadow/disabled modes, privacy and frozen evidence restrictions are preserved.
- **Known contract mismatch:** R478 retains `RequireHttp=true` although its named operation is native S7comm. R473 and R479 also carry HTTP GET/POST method indicators without an HTTP operation requirement. No silent migration was made; a separate approved integration GA must reconcile those contracts with trusted native-command producers.
- `OtProtocolLight` labels `modbus.write` for several write functions, not exclusively coils. DNP3 link-layer CRC validation is not application-layer operation confirmation. S7comm framing cannot establish command success. No guessed authenticated flag, new capture field, parser duplication, new state allocation or fabricated score was added.
- Existing HTTP retained headers/request-targets and OT asset authorization remain separate privacy/integration audits. Test inputs use only synthetic credential placeholders. No credentials or payloads are retained by the new guard.
- Start/end static review: compare live branch and prior R461–R470 candidate, exact rule IDs, original specs, evidence producers, guard order, no public API migration, UI-owned paths and documentation. The source-only diff and expected-HEAD publication must be rechecked immediately before publishing; no build/compile claim is supported.

## Authored xUnit scenario inventory — 0 executed

[Carthago.Tests/NetworkBatch471480AccuracyTests.cs](../Carthago.Tests/NetworkBatch471480AccuracyTests.cs) contains two parameterized xUnit methods. The first enumerates **19 distinct adversarial/benign/boundary cases per rule**; the second checks the original profile for each rule. **19 × 10 + 10 = 200 concrete authored invocations; 0 executed.**

| Scenario IDs (applied to each R471–R480) | Contract |
| --- | --- |
| `plausible`, `wire-framing` | A plausible port/application label and even recognized framing cannot assert a decoded operation |
| `descriptor-spoof`, `spoofed-process`, `forged-audit` | Rule names, process/service strings and untrusted HTTP headers cannot become authenticated provenance |
| `approved-engineering`, `cross-boundary`, `wrong-direction` | Legitimate maintenance and traffic direction alone are not a malicious command |
| `tls-only`, `fragmentary-native`, `malformed-command`, `wrong-protocol` | Encrypted, incomplete, malformed or protocol-mismatched observations fail closed |
| `missing-source`, `missing-destination` | Core telemetry omissions must report `MISSING_CORE_TELEMETRY` |
| `secret-placeholder`, `claimed-success` | Synthetic credential strings and asserted success cannot prove an outcome or leak credentials |
| `threshold-burst`, `duplicate-id`, `after-cooldown` | Repeated/duplicate/time-separated untrusted observations never satisfy trusted evidence |
| Profile invariant (per rule) | Original Alert mode, threshold, confidence floor, window and cooldown remain unchanged |

There is **no supportable positive operational test** until authenticated session or decoded operation producers exist. The authored scenarios are contract assertions, not a measurement of precision, recall, successful compilation or production behavior.

## Outstanding quality GAs and next batch

Windows compilation and execution of all 200 authored scenarios; trusted RDP virtual-channel/file-transfer events; authenticated remote-support inventory; Modbus function/subfunction parsing and distinct-command baselines; S7 CPU/block/identification request parsing; DNP3 CROB application-object and response correlation; trusted engineering/SCADA policy; privacy review; field false-positive/recall measurement remain open. The historical **4,940/4,940** regression checkpoint predates these source candidates. Frozen R102 V1 **FAILED 4/6**, V2 **0/4 approved external sources**, and R343/R295/R275/R163 replay obligations are separate GAs and do not block independent rule development.

**Next consecutive GA after safe publication: R481–R490**, subject to live HEAD inspection. Do not start it until this entire candidate is published.

## References

- [Modbus Organization — official application and TCP specifications](https://www.modbus.org/modbus-specifications) (function codes require decoded requests and subfunctions).
- [Microsoft — RDP clipboard file redirection behavior](https://github.com/MicrosoftDocs/SupportArticles-docs/blob/main/support/windows-server/virtualization/copy-paste-not-work-hyper-v-vmconnect-enhanced-session-mode.md) (clipboard policy and file copy are session features, not packet-port attribution).
- [ABB — DNP3 Control Relay Output Block](https://techdoc.relays.protection-control.abb/r/REC615-and-RER615-DNP3-Communication-Protocol-Manual/2.0/en-US/Binary-outputs-and-control-relay-output-block) (application-layer control objects and device-specific semantics).
- [Rule documentation standard](rules/RULE_DOCUMENTATION_STANDARD.md) · [Progress ledger](RULE_HARDENING_PROGRESS.md) · [Prior R461–R470 GA](RULE_BATCH_461-470.md).

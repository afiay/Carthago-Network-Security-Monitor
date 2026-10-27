# R116–R120 IoT/OT precision and evidence hardening

**CANDIDATE — UNVERIFIED.** 35 new advanced xUnit facts, seven per rule.
No build, xUnit, development replay, holdout or runner job was executed.

| Rule | Candidate implementation | Advanced test coverage (7 each) |
| --- | --- | --- |
| R116 | Require UDP SSDP/UPnP parser attribution and explicit M-SEARCH/discover action, not port/Info alone; per-detector bounded duplicate-resistant 60s source windows; raw discovery Info excluded from alerts. | External positive; 25-event local positive; single multicast benign; unclassified Info negative; TCP/HTTP contradictions; repeated record-ID negative; secret redaction. |
| R117 | Require TCP port 23, Telnet parser attribution and bounded login/username/password prompt syntax; reject HTTP/UDP and unrelated ports; omit raw login transcripts from evidence. | Classified positive; bare session benign; prose-only username benign; wrong-port and unclassified negative; contradictory transports; independent targets; password privacy. |
| R118 | Preserve the existing default-credential authentication matcher and **86% confidence floor**; fail closed on contradictory UDP/Telnet transport and conflicting HTTP Host/SNI. Existing duplicate Authorization and parser-redaction safeguards remain authoritative. | HTTP Basic positive; duplicate Authorization negative; missing host; UDP/SNI contradictions; genuine Telnet default pair; UDP Telnet negative; no credential export. |
| R119 | Require device-source process identity or parser-classified RTSP/ONVIF, not Info-only camera claims; direct RTSP needs explicit protocol classification, not port 554 alone; per-detector bounded duplicate-resistant 15-minute source/destination windows; no raw camera Info export. | Five-observation positive; four-observation negative; Info-only browser negative; port-only RTSP negative; classified RTSP positive; duplicate ID negative; cloud-token privacy. |
| R120 | Require coherent Modbus/TCP classification and destination port 502; distinguish actual write functions (5/6/15/16 or write coil/register) from generic register/read text; preserve external-boundary detection and existing same-/24 negative; no raw Modbus Info export. | Cross-segment write positive; same-segment read benign; cross-segment read benign; Info-only spoof negative; UDP/HTTP contradictions; external boundary positive; payload privacy. |

Source files: `Carthago/Engine/Rules/IotOt/R116_*.cs` through
`R120_*.cs`, `Carthago/Engine/Rules/IotOt/IotOtPrecisionDetectionRuleBase.cs`,
and `Carthago/Engine/Rules/Abstractions/NetworkBatch116120Evidence.cs`.
Test files: `Carthago.Tests/R116AdvancedAccuracyBatchTests.cs` through
`R120AdvancedAccuracyBatchTests.cs` and
`Carthago.Tests/NetworkBatch116120Context.cs`.

**Preserved:** R116 threshold 25/60s, R119 threshold 5/900s,
R117/R118/R120 existing one-event gates, cooldowns, runtime modes and
confidence floors (R118=86%, R102=80%, R163=84%). Existing baseline-readiness,
asset approvals, approved broker/OT segments, Shadow/Disabled policy and
frozen v1 holdout inputs remain unchanged. No synthetic replay fixture or
independent field label was fabricated.

**Open risks:** `TrafficRecord` has no dedicated typed SSDP action,
Telnet prompt or Modbus function-code fields; bounded `Info` is accepted
only after parser-attributed protocol and transport validation. Confirm
actual capture adapter maps ApplicationProtocol/ApplicationService consistently.
Camera process names are contextual, not authenticated device inventory.
The bounded per-detector window is not durable across restarts; out-of-order
and high-cardinality pressure need measured operational evaluation.
Existing approved OT controller and segment configuration must still be
honored by the runtime policy layer. Synthetic direct-rule tests do not
establish final alert delivery or operational precision. V1 holdout remains
FAILED for unrelated R102 telemetry omissions; v2 remains pending.

The single deferred Windows verification entry point is
`scripts/verify-all-rule-batches.ps1`; it discovers these five test
files automatically and requires five passing advanced cases per rule.
Do **not** invoke it until the owner explicitly says **now it's test time**.

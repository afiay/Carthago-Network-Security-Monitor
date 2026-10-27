# R121–R125 BACnet, gateway, VPN, RDP and WinRM hardening

**CANDIDATE — UNVERIFIED.** 35 new advanced xUnit facts, seven per rule.
No build, xUnit, replay, holdout or runner job was executed.

| Rule | Narrow implementation | Seven advanced cases |
| --- | --- | --- |
| R121 | Require UDP BACnet parser attribution, port 47808 and bounded Who-Is semantics. Do not treat multicast or I-Am as discovery; admin-process suppression no longer trusts packet Info. Redact raw OT Info. | Classified positive, I-Am benign, multicast-only benign, unclassified port, TCP/HTTP contradiction, admin process, privacy. |
| R122 | Require attributed UDP CoAP or separately attributed Zigbee gateway HTTPS process; count only validated, distinct packet identities in bounded instance-owned windows; suppress raw Info. Existing threshold remains three. | CoAP positive, internal benign, unclassified port, three-event gateway, duplicate replay, spoofed gateway text, contradiction/privacy. |
| R123 | Require coherent TCP HTTP telemetry, real HTTP method and VPN login route, with Host/SNI consistency. Persist only a fixed route category rather than authentication-bearing URI path. | VPN positive, generic IdP benign, missing method, UDP/SNI contradictions, static docs, internal portal, path privacy. |
| R124 | Require TCP and RDP port or parser classification, no HTTP/DNS/UDP contradictions; source-port-only traffic and unrelated HTTPS cannot qualify. | Outbound/inbound positives, internal benign, source-port negative, HTTP contradiction, UDP/DNS contradiction, privacy. |
| R125 | Require TCP and WinRM/WSMAN destination port or parser classification, no HTTP/DNS/UDP/QUIC contradictions. | Outbound/inbound positives, internal benign, wrong-port HTTPS, port-only HTTP GET, UDP/QUIC contradiction, privacy. |

Candidate source: five rule files plus
`Carthago/Engine/Rules/Abstractions/NetworkBatch121125Evidence.cs`,
the existing IoT/OT and IdentityAccess evidence bases.
Tests: `Carthago.Tests/R121AdvancedAccuracyBatchTests.cs` through
`R125AdvancedAccuracyBatchTests.cs`, and
`Carthago.Tests/NetworkBatch121125Context.cs`.

**Preserved:** Existing rule thresholds, windows, cooldowns, severities,
confidence floors (R102 80%, R118 86%, R163 84%), default Shadow/Disabled
policy, baseline/asset approval, replay labels and frozen holdout.
The single deferred Windows entry point remains
`scripts/verify-all-rule-batches.ps1`, which discovers these five
advanced files automatically; it was not executed or changed.

**Open risks:** BACnet Who-Is still comes from bounded decoded Info after
protocol attribution because TrafficRecord lacks typed BACnet action.
Zigbee gateway process attribution is contextual, not signed inventory.
R123 path suppression deliberately reduces forensic path detail to protect
authentication tokens. Port-based RDP/WinRM classification requires live
adapter confirmation; protocol-specific capture telemetry may differ.
State windows are per-instance and reset on restart. Real-world false
positives, out-of-order delivery and confidence/policy interactions remain
unverified. Frozen v1 R102 holdout remains FAILED (4/6), and v2 awaits
independent approved packet evidence.

**Next batch: R126–R130**, only after publication of this candidate.

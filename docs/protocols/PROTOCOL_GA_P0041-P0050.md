# Carthago protocol intelligence — GA P0041–P0050

**Status:** SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; **0 EXECUTED**.  
**Branch:** `feature/carthago-reliability-hardening` ONLY.  
**Live source base:** `691717f8a3302f58454dfcb9e6da45993b17a442` (2026-10-30; rechecked immediately before publication).  
**Publication/test source SHA:** the single atomic Git commit containing all eight owned paths; its SHA is available from branch history (cannot self-reference its own hash).  
**Inventory:** owner's immutable Library CSV P0041–P0050; these are research identifiers, never RNNN rules.  
**Next GA:** **P0051–P0060**.  
**Previous:** [GA P0031–P0040](PROTOCOL_GA_P0031-P0040.md).

## Ten-entry decision matrix (all original P IDs retained)

| P ID / original label | Disposition | Initial / candidate reachability | Falsifiable value and benign alternatives |
| --- | --- | --- | --- |
| P0041 `s7comm` S7 | **PARTIAL** | Existing [OtProtocolLight](../../Carthago/Services/OtProtocolLight.cs) bounded TPKT/COTP/S7 identification; not full S7 operation decoding. | An attested PLC, engineer role, authorized change window and S7 function/result are needed for a control-change claim. Normal HMI/engineering polling can look similar. Reuse existing producer, do not duplicate. |
| P0042 `opcua` OPC UA Binary | **IMPLEMENTED_ISOLATED** (connection layer only) | New [OpcUaConnectionInspector](../../Carthago/Services/ProtocolIntelligence/OpcUaConnectionInspector.cs) recognizes bounded complete plaintext HEL/ACK/ERR connection messages, no SecureChannel, service method, node, endpoint or auth decoding; **no registered live producer**. | Unexpected OPC UA exposure or repeated failed negotiation would require attested TCP reassembly, host/asset identity and server logs. Normal reconnects, commissioning and proxy handshakes are benign. Existing R483/R484 rule descriptions are **not** proof of typed Browse/Write telemetry. |
| P0043 `goose` GOOSE | **BLOCKED — SHARED L2 INTEGRATION** | Non-IP EtherType 0x88b8 is not reachable through inspected IP-only PacketHandler path. | Switch-port, IEC 61850 asset-role and signed change context required to evaluate unexpected GOOSE state; routine protection events can be legitimate. |
| P0044 `mms` MMS | **DEFERRED** | No validated MMS session/presentation association or bounded confirmed message producer in reviewed packet path. | MMS operation/association monitoring needs a trusted session parser and substation context; generic TCP 102 cannot prove IEC 61850 operations. |
| P0045 `iec60870_104` IEC 60870-5-104 | **IMPLEMENTED_ISOLATED** (APCI only) | New [Iec104ApduInspector](../../Carthago/Services/ProtocolIntelligence/Iec104ApduInspector.cs) validates complete APCI I/S/U envelopes and exposes only ASDU type on I-frames; **no live producer**. | Command intent requires decoded ASDU cause/IOA, station role, source authorization and trusted outcome. I-frame or type alone is not a command-success verdict. Maintenance and SCADA polling are benign. |
| P0046 `bacnet` BACnet NPDU | **PARTIAL** | Existing [OtProtocolLight](../../Carthago/Services/OtProtocolLight.cs) BACnet/IP BVLC and limited Who-Is/I-Am recognition. No complete NPDU/APDU decode. | Device inventory or unauthorized write needs asset role, confirmed APDU service and change window; normal discovery/failover can mimic anomalies. Reuse existing parser. |
| P0047 `pn_dcp` PROFINET DCP | **BLOCKED — SHARED L2 INTEGRATION** | Non-IP Ethernet 0x8892 requires explicit frame adapter; port-based inference is invalid. | Device name/IP changes require trusted switch and engineering workstation provenance; commissioning is benign. |
| P0048 `pn_io` PROFINET IO | **BLOCKED — SHARED L2 INTEGRATION** | Non-IP real-time EtherType 0x8892 and FrameID require an approved L2 capture bridge; no typed producer. | Cycle anomalies require time-synchronized topology and process baselines; jitter and maintenance are benign. |
| P0049 `ethercat` EtherCAT | **BLOCKED — SHARED L2 INTEGRATION** | EtherType 0x88a4 dropped by inspected IP-only fast path; no adapter. | Unexpected control writes require device roles, state and controller evidence; normal cyclic frames are benign. |
| P0050 `bgp` BGP-4 | **IMPLEMENTED_ISOLATED** (message envelope only) | New [BgpMessageInspector](../../Carthago/Services/ProtocolIntelligence/BgpMessageInspector.cs) validates complete OPEN/UPDATE/NOTIFICATION/KEEPALIVE/ROUTE_REFRESH envelopes, without parsing routes or peer auth; **no live producer**. | Route hijack or session abuse requires trusted router RIB/BMP/syslog/neighbor state and path-policy comparison. Normal convergence, refresh and resets are benign. |

**Totals:** 3 IMPLEMENTED_ISOLATED; 2 PARTIAL/reuse; 1 DEFERRED; 4 BLOCKED shared L2; 0 EXISTING full; 0 live integrations; 0 rejected. No claim of three new *operational* protocols.

## Source-first reachability and implementation boundaries

Inspected at base SHA: [PacketHandler](../../Carthago/Services/PacketHandler.cs), [TrafficCaptureService](../../Carthago/Services/TrafficCaptureService.cs), [TrafficRecord](../../Carthago/Models/TrafficRecord.cs), [OtProtocolLight](../../Carthago/Services/OtProtocolLight.cs), [PortServiceResolver](../../Carthago/Services/PortServiceResolver.cs), NetworkBatch226230Wire, NetworkBatch231235Wire, NetworkBatch246250Wire, ETW/Cisco adapter inventory and existing OT rules R482–R484. Existing rule names/text are not a trusted protocol field producer. TCP early-byte inspection is not a verified complete application message boundary. Current non-IP Ethernet fast path does not supply L2 frames to these inspectors.

All three new inspectors are stateless, allocation-free on successful parse, use bounded `ReadOnlySpan<byte>` and exact declared length checks, do not allocate strings or retain sensitive contents, and return only unauthenticated metadata. OPC UA UACP connection messages are **not** secure-channel operations; IEC104 ASDU type is not an authorized command; BGP UPDATE shape is not a validated route announcement. No parsers are called by live capture, registered as RNNN rules, or allowed to emit DetectionEvents, alerts, UI messages or sinks.

## Security advisories, evidence classification and dated provenance

**Threat refresh performed 2026-10-30.** Checked CISA KEV and CISA ICS advisory search, vendor/standards protocol sources and FIRST EPSS guidance. No verified protocol-specific, affected-version, dated exploited CVE/IOC chain for these ten items was established during this GA; therefore the classification for P0041–P0050 is **UNVERIFIED** for CVE exploitation. No `CONFIRMED_EXPLOITED_ZERO_DAY`, `CONFIRMED_EXPLOITED_KNOWN_VULNERABILITY` or `VENDOR_ADVISORY_NO_EXPLOIT_EVIDENCE` is asserted without an actual matching advisory. FIRST EPSS is a probability model, not an observed compromise. Reassess when vendor/product versions and exposure are available.

- OPC Foundation Part 6 §7.1.2, UACP HEL/ACK/ERR message header and bounded URL: https://reference.opcfoundation.org/specs/OPC-10000-6/7 (accessed 2026-10-30).
- Beckhoff IEC 60870-5-104 APCI telegram structures and I/S/U control formats: https://infosys.beckhoff.com/content/1033/ts650x_tcplc_iec60870-5-10x/11728916875.html (accessed 2026-10-30).
- IETF RFC 4271 §4 BGP-4 message formats, January 2006: https://datatracker.ietf.org/doc/html/rfc4271 (accessed 2026-10-30).
- IETF RFC 2918 route refresh, September 2000: https://datatracker.ietf.org/doc/html/rfc2918 (accessed 2026-10-30).
- CISA KEV catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog (checked 2026-10-30; no item-specific exploit attribution asserted).
- CISA ICS advisories: https://www.cisa.gov/news-events/ics-advisories (checked 2026-10-30; no item-specific claim asserted).
- FIRST EPSS: https://www.first.org/epss/ (risk estimate only; no numeric EPSS value inferred).

## Authored-only regression evidence (NOT executed)

| Inspector / source blob | Authored xUnit test source blob | xUnit methods | Concrete invocations | Five mandatory independent scenario families |
| --- | --- | ---: | ---: | --- |
| OPC UA `d9aaaabc6e75` | [OpcUaConnectionInspectorTests](../../Carthago.Tests/ProtocolIntelligence/OpcUaConnectionInspectorTests.cs) `642f4c8474ce` | 13 | 16 | HEL/ACK/ERR positive; OPN/MSG/CLO/RHE negative; wrong length, truncated and oversized; repeat deterministic; URL/status redaction and unattested boundary |
| IEC104 `0359a247f841` | [Iec104ApduInspectorTests](../../Carthago.Tests/ProtocolIntelligence/Iec104ApduInspectorTests.cs) `bc6bd9da7e11` | 12 | 17 | I/S/U positive; DNP3 negative; truncated/overlong/reserved-bit; deterministic repeat; no station address retention and boundary required |
| BGP `bb48be534ba5` | [BgpMessageInspectorTests](../../Carthago.Tests/ProtocolIntelligence/BgpMessageInspectorTests.cs) `0d7cdb0c240f` | 17 | 17 | OPEN/UPDATE/NOTIFICATION/KEEPALIVE/refresh positive; cross-protocol marker negative; length/type/hold/attribute adversarial; repeat; no ASN/prefix retention and boundary required |

**Total authored: 42 xUnit methods / 50 concrete invocations. Executed: 0. Builds: 0. Replays: 0. CI/runner: 0.** These are synthetic spec-derived fixtures, not independent TShark corroboration or executed evidence. Compile correctness, behavioral accuracy, throughput, false-positive rates and production reachability are **unverified**.

## Shared integration proposal — coordination required, NOT applied

Only after explicit owner approval and a new live-HEAD cross-stream audit: introduce a narrowly typed, source-attributed `CompleteProtocolMessage` adapter with TCP stream reassembly limits (per-flow bytes, TTL, fragmentation, reset and duplicate/out-of-order handling), source sensor, endpoint role, timestamp and encryption state. Route verified OPC UA UACP/IEC104/BGP messages into the isolated inspectors, never port-only guesses. Keep observations separate from `TrafficRecord` until schema/consumer compatibility is reviewed. Test valid/malformed streams, half-open sessions, interleaving, encryption, privacy and journal ordering. Rollback by removing the optional adapter and leaving isolated inspectors dormant; preserve existing DetectionEvents and holdouts.

For GOOSE/PROFINET/EtherCAT, a **separate** owner-approved L2 Ethernet adapter must preserve EtherType, VLAN, frame boundaries, MAC/switch-port provenance and privacy; no packet-core modification is authorized in this GA. MMS needs a separate bounded ISO session/presentation contract. S7/BACnet improvements should extend existing helpers only after shared ownership approval.

## Divergence and publication review

The owner-owned paths in this GA are only `Carthago/Services/ProtocolIntelligence/**`, `Carthago.Tests/ProtocolIntelligence/**`, and `docs/protocols/**`. Neither detection-owned `Engine/Rules/**`, frozen R102 holdouts, detection ledger, UI paths/design ledger, shared PacketHandler/TrafficRecord/TrafficCaptureService/Carthago.csproj, nor journal/security/privacy configuration are modified. Preserve R102/R118/R163 confidence floors, Shadow/Disabled, cooldowns, baseline readiness, raw immutable DetectionEvents and journal-first ordering.

Publication requires one atomic non-forced expected-HEAD update of all eight paths, with a recheck immediately before the update. If the branch moves or ownership overlaps, stop and reconcile; never overwrite. The published commit SHA is the branch HEAD after the update. **Next GA P0051–P0060**, no skipped or repeated P IDs.

# Carthago protocol intelligence — GA P0121–P0130

**Status:** SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; **0 EXECUTED**.  
**Branch:** feature/carthago-reliability-hardening ONLY.  
**Live source base:** 7c33d95aa8f9f8a88e8247b85744f8b90dd6af28 (2026-10-31).  
**Isolated source commit:** 8d9ba4b9dc89374bcfae3a70492d166533fe5f47. **Authored-test commit:** 152f157d0e217f5d41682cfa8e0a4fde92bc5df9.  
**Publication SHA:** the documentation-descendant commit targeted by one non-forced expected-HEAD atomic update (cannot embed its own SHA).  
**Authoritative inventory:** owner's immutable 2026-10-30 Library CSV, exactly P0121–P0130. P IDs are not detection rules.  
**Previous:** [P0111–P0120](PROTOCOL_GA_P0111-P0120.md). **Next:** **P0131–P0140**.

## Exactly ten original P-ID decisions

| P ID and original dissector key | Disposition | Actual reachability and producer | Security hypothesis, required evidence and benign alternative |
| --- | --- | --- | --- |
| P0121 pn_mrrt | **BLOCKED — L2 INPUT** | PROFINET redundancy component; non-IP frame dropped; no ring/switch producer. | Unexpected ring role needs switch-port and topology logs; legitimate failover is benign. |
| P0122 pn_ptcp | **BLOCKED — L2 INPUT** | No PROFINET non-IP or hardware clock source; no PTCP PDU producer. | Clock attack requires time-source role and authenticated controller evidence; jitter/maintenance benign. |
| P0123 pn_rsi | **BLOCKED — L2 INPUT / DISTINCTNESS UNVERIFIED** | Wireshark one-field dissector label is not proof of a distinct protocol; no L2 producer. | Redundancy interface changes require device role and switch logs; planned failover benign. |
| P0124 ecat | **REJECTED_DUPLICATE_OR_NOT_A_PROTOCOL** | EtherCAT datagrams are a component of P0049 EtherCAT; EtherType 0x88a4 not delivered. | Unauthorized writes need addressed slave, command, WKC and outcome; cyclic I/O benign. |
| P0125 ecat_mailbox | **REJECTED_DUPLICATE_OR_NOT_A_PROTOCOL** | Mailbox is an EtherCAT subprotocol, not a new transport; parent L2 blocked. | Firmware/parameter access needs mailbox command and controller audit; commissioning benign. |
| P0126 ecatf | **REJECTED_DUPLICATE_OR_NOT_A_PROTOCOL** | EtherCAT frame header is a dissector surface of P0049, not an independent protocol. | Malformed frame evidence needs actual EtherCAT L2 producer and receiver errors; noise benign. |
| P0127 mstp | **BLOCKED — SERIAL INPUT** | BACnet MS/TP needs RS-485 serial capture, CRC, token ring; BACnet/IP partial helper is not MS/TP. | Rogue master/token anomaly requires serial port, node and building-controller audit; token passing benign. |
| P0128 104apci | **REJECTED_DUPLICATE_OR_NOT_A_PROTOCOL** | Existing isolated Iec104ApduInspector from P0045 covers APCI; no runtime producer. | Unexpected IEC104 control sequence needs trusted TCP reassembly and station logs; reconnect benign. |
| P0129 104asdu | **REJECTED_DUPLICATE_OR_NOT_A_PROTOCOL** | ASDU is IEC101/104 application component, not separate protocol; existing IEC104 exposes only ASDU type (PARTIAL family). | Control intent requires cause, IOA, authorized station and controller outcome; SCADA polling benign. |
| P0130 iec60870_101 | **IMPLEMENTED_ISOLATED** | New bounded FT1.2 fixed/variable/ACK inspector; complete trusted plaintext serial frame and configured 1/2-byte address required; NO SERIAL PRODUCER. | Link anomalies require attested serial source, device role, ASDU semantics and device logs; polling/retries benign. |

**Totals:** 1 IMPLEMENTED_ISOLATED (one genuinely new distinct serial-family parser, **zero operational**); 4 BLOCKED input; 5 REJECTED duplicate/subdissector; 0 EXISTING as new independent operational protocols; 0 PARTIAL as roster outcome (IEC104 ASDU family remains partial); 0 DEFERRED; 0 INTEGRATED_UNVERIFIED. No skipped IDs.

## Source-first divergence and hard boundaries

At 7c33d95aa8f9f8a88e8247b85744f8b90dd6af28, inspected [PacketHandler](../../Carthago/Services/PacketHandler.cs), [TrafficCaptureService](../../Carthago/Services/TrafficCaptureService.cs), [TrafficRecord](../../Carthago/Models/TrafficRecord.cs), [OtProtocolLight](../../Carthago/Services/OtProtocolLight.cs), [NetworkBatch226230Wire](../../Carthago/Services/NetworkBatch226230Wire.cs), [NetworkBatch231235Wire](../../Carthago/Services/NetworkBatch231235Wire.cs), [NetworkBatch246250Wire](../../Carthago/Services/NetworkBatch246250Wire.cs), [PortServiceResolver](../../Carthago/Services/PortServiceResolver.cs), [IEC104 inspector](../../Carthago/Services/ProtocolIntelligence/Iec104ApduInspector.cs), project files, canonical engineering conduct, rule and UI ledgers read-only. Existing ETW/Windows audit and Cisco SNMP/Syslog adapters do not attest L2 or serial frames. PacketHandler handles Ethernet/VLAN but returns null for non-IP EtherTypes; early TCP bytes are not reassembled serial or full TCP messages.

New [Iec101Ft12Inspector](../../Carthago/Services/ProtocolIntelligence/Iec101Ft12Inspector.cs) is stateless, allocation-free on success, uses ReadOnlySpan<byte>, validates <=261 bytes, repeated length, 1/2-octet configured address width, exact frame end, modulo-256 checksum and reserved controls. It returns only link-frame kind, byte length, link function code and optional ASDU type. It retains no station address, ASDU body, raw bytes or sensitive fields. No direct alert, journal, UI, sink, registration, shared-core change or exploit claim. Caller-provided completeness boolean alone is NOT trusted provenance; a future approved adapter must attest serial frame boundaries, media, direction, station mapping and loss. Encrypted payload and IEC104-over-TCP are NOT OBSERVABLE through this inspector.

## Threat refresh and original sources — 2026-10-31

Reviewed [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [CISA 2026-10-20 ICS advisory release](https://content.govdelivery.com/accounts/USDHSCISA/bulletins/42fd2a7), [Hitachi Energy PSIRT](https://www.hitachienergy.com/products-and-solutions/cybersecurity/psirt), [FIRST EPSS](https://www.first.org/epss/) and [Beckhoff FT1.2 frame specification](https://infosys.beckhoff.com/content/1031/ts650x_tcplc_iec60870-5-10x/11700014987.html). Hitachi advisory 8DBD000259 (updated 2026-09-29) concerns RTU500 firmware including CVE-2026-17539 in adjacent **IEC60870-5-104** communications; CISA published ICSA-26-293-05 on 2026-10-20. For that **adjacent vendor advisory only**, classify **VENDOR_ADVISORY_NO_EXPLOIT_EVIDENCE**. For all ten P entries, **protocol-specific exploitation UNVERIFIED**: no evidence of confirmed exploited zero-day or an IEC101 signature, and no verified device version, prerequisites, IOCs, or reliable EPSS numeric estimate. FIRST EPSS is probability, not exploitation proof. No packet shape proves vulnerable firmware or successful unauthorized control.

## Authored tests, not executed

[Isolated xUnit source](../../Carthago.Tests/ProtocolIntelligence/Iec101Ft12InspectorTests.cs): **14 test methods / 17 concrete invocations; 0 executed**. Five substantive groups: positive fixed/variable/ACK; legitimate negative and IEC104 cross-protocol; truncated/malformed/repeated length/checksum/overlong; retransmission/out-of-order/concurrency; provenance, privacy, encrypted/opaque boundary and fail-closed default. Synthetic non-secret fixtures are not independent captures. No build, dotnet test, xUnit, replay, holdout, CI, Windows runner, benchmark, active scan or traffic capture was performed.

## Exact shared integration proposal — NOT AUTHORIZED

1. Separate opt-in **serial** adapter for P0130/P0127 with verified RS-485 link/frame boundary, configured baud/parity/address width, CRC or FT1.2 checksum, direction, monotonic time, source ID, asset role, bounded queues, TTL, cancellation, loss accounting and redaction. Separate **Ethernet L2** bridge for P0121–P0126 with original EtherType, VLAN, MAC, switch port, time and full frame; never map L2 to invented IP ports.
2. Only after owner approval, propose minimal additive typed producer/consumer contract and compatibility migration against TrafficRecord, all rules, journal-first immutable raw DetectionEvents, privacy, serialized evidence and UI consumers. No code in PacketHandler, TrafficCaptureService, TrafficRecord, csproj or rules is authorized now.
3. Authored future integration scenarios: serial split/concat, duplicate/reorder, missing source, wrong address width, clock drift, loss, spoofing, encrypted content, EtherCAT/PROFINET L2, false positives and journal serialization. **Execute 0** until the owner says **now it's test time**.
4. Roll back optional adapter/registration only, never original RNNN definitions, pinned holdouts, confidence floors (R102/R118/R163), modes, cooldowns, suppression, raw DetectionEvents, or UI. **BLOCKED — SHARED INTEGRATION**.

## Cross-stream and publication

Only protocol-owned paths changed: Carthago/Services/ProtocolIntelligence/Iec101Ft12Inspector.cs, Carthago.Tests/ProtocolIntelligence/Iec101Ft12InspectorTests.cs, docs/protocols/PROTOCOL_GA_P0121-P0130.md, docs/protocols/PROTOCOL_EXPANSION_PROGRESS.md. SDK-style project auto-compiles new source/test files; no csproj edit. Detection and UI streams, ledgers, R102 frozen holdouts and security/privacy controls unchanged. All authored source remains **UNVERIFIED**. Pre-publication must recheck live HEAD; update only via expected-HEAD-protected atomic non-force update_ref. **Next GA P0131–P0140.**

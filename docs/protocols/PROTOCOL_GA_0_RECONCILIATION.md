# Carthago protocol intelligence — GA 0 source reconciliation

**Status:** SOURCE-ONLY RECONCILIATION — NOT RUNTIME VERIFIED  
**Branch:** `feature/carthago-reliability-hardening`  
**Historical inventory source:** `Carthago_500_Protocol_Source_Audit_2026-10-30.csv` (ChatGPT Library `/Carthago Protocol Expansion`), snapshot `3eefe8873fcfb2156ea8badbf4a8676b7cdbba02`.  
**Reconciled branch HEAD:** `7aa356429b674fab1975127f40f4fea6b312450b` (2026-10-30); later publication is a descendant, not evidence of runtime testing.  
**Scope:** Original P0001–P0500 retained as immutable research row identifiers; no detection-rule IDs assigned.

## Reconciliation method and source divergence

The 500-row source CSV was read, not reconstructed from protocol names. It contains **500 unique P IDs** and **500 unique Wireshark filter keys**, which is **not evidence of 500 distinct protocol specifications**. The historical audit inspected the capture entry point and selected wire helpers, not every rule and optional adapter. Comparing historical audit SHA `3eefe887...` with `7aa356429b674fab1975127f40f4fea6b312450b` showed three commits and seven changed paths, confined to R521–R530 detection-rule sources, authored tests and detection documentation. **None changed** `PacketHandler.cs`, `TrafficCaptureService.cs`, `TrafficRecord.cs`, `PortServiceResolver.cs`, `OtProtocolLight.cs`, or the four inspected wire-helper paths. Re-read these at the new HEAD before deriving the conclusions below.

| Source inventory classification | Rows | Interpretation |
| --- | ---: | --- |
| `CANDIDATE_UNVERIFIED` | 373 | Not found in selected packet decoders; distinctness and reachability still unproven |
| `NEW_INGESTION_REQUIRED` | 31 | Requires explicit non-IP source/producer and trusted provenance |
| `MEDIA_DEPENDENT` | 32 | Requires link-layer/radio/media capture capability not present in inspected path |
| `EXTEND_NOT_NEW` | 18 | Reuse existing partial parser/metadata rather than claim wholly new protocol |
| `REUSE_OR_EXTEND` | 5 | Existing client, listener or related implementation |
| `SUBPROTOCOL_OR_VARIANT_NOT_DISTINCT` | 25 | Not counted as independent protocol without specification and sensor justification |
| `REJECT_AS_500_DISTINCT_WIRE_PROTOCOL` | 16 | Product, dissector surface or non-wire-protocol inventory entry |
| **Total** | **500** | **Historical P IDs retained without padding or substitution** |

**Distinct-protocol eligibility:** The source audit establishes **436 unverified research candidates** (373 + 31 + 32), **23 reuse/extension entries**, and **41 variants/rejections**. It does **not** establish a truthful final count of distinct, feasible, useful *new* protocols: the **verified eligible distinct-protocol count is not yet determined**, rather than falsely claiming 436 or 500. Each GA will substantiate or reject ten contiguous IDs. The number of *individually verified new, live-capture-integrated* protocols at this reconciliation is **0**. Evidence-based replacement proposals, if any, must be separately approved and must never renumber or pad P IDs.

## Live source boundaries

- [PacketHandler](../../Carthago/Services/PacketHandler.cs) accepts Ethernet, raw IP, Linux cooked captures and limited VLAN; it drops non-IP EtherTypes at the fast-path branch, then handles IPv4/IPv6 and TCP/UDP/ICMP. It does not invoke the new protocol inspectors.
- [TrafficCaptureService](../../Carthago/Services/TrafficCaptureService.cs) routes SharpPcap packet parsing and ETW record producers; those are not interchangeable trusted payload sources.
- [TrafficRecord](../../Carthago/Models/TrafficRecord.cs) has transport, HTTP, TLS/ALPN and QUIC fields but no authoritative HTTP/2 frame, DTLS record, proxy request outcome, NetScaler version or appliance configuration fields.
- [PortServiceResolver](../../Carthago/Services/PortServiceResolver.cs) offers port/ALPN inference only; inference is not a frame decoder.
- [SMB2 write](../../Carthago/Services/NetworkBatch246250Wire.cs), [OT](../../Carthago/Services/OtProtocolLight.cs), [MQTT/CIP](../../Carthago/Services/NetworkBatch226230Wire.cs), and [CoAP/RTSP](../../Carthago/Services/NetworkBatch231235Wire.cs) provide bounded partial recognition. Do not duplicate them.
- Optional [MsQuic ETW](../../Carthago/Services/Etw/MsQuicEtwListener.cs), [Cisco Syslog](../../Carthago/Services/Cisco/CiscoSyslogListener.cs), [SNMP client](../../Carthago/Services/Cisco/SharpSnmpClientAdapter.cs) and [Windows Security audit](../../Carthago/Services/TrustedAudit/WinRmLocalSecurityAuditReader.cs) require their own provenance/coverage evaluation before being used as trusted evidence.
- [Carthago.csproj](../../Carthago/Carthago.csproj) uses SDK default compile inclusion (except explicitly excluded test paths). [Carthago.Tests.csproj](../../Carthago.Tests/Carthago.Tests.csproj) is a separate xUnit project with default compile inclusion. No project-file changes are needed for isolated source/test folders.

## Priorities and limitations

Prioritize genuine exploitable exposure only when the specific sensor can observe the required fields. CISA's 2026-09-27 notice identifies CVE-2026-88772 as exploited; Citrix requires DTLS-enabled NetScaler and affected software. DTLS records alone cannot establish device type, version, exploit attempt or successful compromise. HTTP/2 frame metadata alone cannot establish HTTP request smuggling or application compromise. HTTP/3 payloads remain encrypted behind QUIC. Native wireless and non-IP traffic cannot be made reachable by naming a port.

**Evidence:** [CISA 2026-09-27](https://content.govdelivery.com/accounts/USDHSCISA/bulletins/42cc465); [Citrix CTX697096](https://support.citrix.com/external/article/CTX697096/citrix-netscaler-adc-and-citrix-netscaler-gateway-security-bulletin.html); [RFC 9113 HTTP/2](https://www.rfc-editor.org/rfc/rfc9113); [RFC 6347 DTLS 1.2](https://www.rfc-editor.org/rfc/rfc6347); [RFC 9147 DTLS 1.3](https://www.rfc-editor.org/rfc/rfc9147).

**Next GA after this reconciliation:** [P0001–P0010](PROTOCOL_GA_P0001-P0010.md). No builds, tests, replay, captures or runtime integration were executed.

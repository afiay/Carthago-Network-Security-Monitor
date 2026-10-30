# Carthago protocol intelligence — GA P0051–P0060

**Status:** SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; **0 EXECUTED**.  
**Branch:** `feature/carthago-reliability-hardening` ONLY.  
**Live source base SHA:** `121ebc81a09e49d4543697ee2216b29259844c38` (2026-10-30).  
**Publication/test SHA:** the single source-only commit produced by the protected atomic ref update; use branch history (a commit cannot embed its own SHA).  
**Inventory:** owner's immutable ChatGPT Library CSV P0051–P0060, not detection-rule IDs.  
**Previous:** [GA P0041–P0050](PROTOCOL_GA_P0041-P0050.md). **Next:** **GA P0061–P0070**.

## Ten-entry source-grounded decision matrix

| P ID and original label | Disposition | Verified starting surface / candidate reachability | Falsifiable security value and benign alternative |
| --- | --- | --- | --- |
| P0051 `ntp` NTP | **PARTIAL** | Existing [OtProtocolLight](../../Carthago/Services/OtProtocolLight.cs) recognizes bounded NTP mode-7 monlist request; [PortServiceResolver](../../Carthago/Services/PortServiceResolver.cs) has service metadata. Not full NTPv4 time-sync, control, mode, KoD or authentication parsing. | Time manipulation requires trusted server identity, clock offset, host synchronization events and corroboration; legitimate drift and failover can resemble anomalies. Reuse existing parser rather than duplicate. |
| P0052 `pop` POP3 | **DEFERRED** | No trusted reassembled, plaintext POP3 command/response producer established; port 110 metadata is not a decoder. | Mailbox abuse needs authenticated server logs and command/outcome, not port observation; normal client polling is benign. TLS encrypted content NOT OBSERVABLE from packets. |
| P0053 `telnet` Telnet | **IMPLEMENTED_ISOLATED** | New [TelnetControlInspector](../../Carthago/Services/ProtocolIntelligence/TelnetControlInspector.cs) recognizes RFC 854 complete, caller-attested IAC WILL/WONT/DO/DONT and bounded SB/SE control tokens. No live TCP reassembly or registration. | Legacy remote access exposure or option-negotiation patterns require trusted endpoint, policy and session evidence. Admin console access and equipment maintenance are benign. Control tokens do not prove login, plaintext credentials or compromise. |
| P0054 `rsync` rsync | **DEFERRED** | No trusted rsync daemon handshake/stream boundary or host transfer logs established. | Unexpected transfer needs authorized endpoint identity, transferred byte counts and host/proxy logs; backups are benign. SSH transport hides payload. |
| P0055 `rlogin` rlogin | **DEFERRED** | No attested rlogin session framing, login/audit source or cleartext stream producer. | Legacy access needs host login outcomes and asset role; authorized maintenance is benign. Avoid retaining usernames. |
| P0056 `wbxml` WAP Binary XML | **REJECTED_DUPLICATE_OR_NOT_A_PROTOCOL** | WBXML is an application content encoding, not an independent network transport; requires an identified carrying application before decoding. | No standalone security claim from a Wireshark label; review a concrete carrier and application need separately, not as a new protocol. |
| P0057 `wlan_rsna_eapol` IEEE 802.11 RSNA EAPOL key | **BLOCKED — MEDIA/L2 INTEGRATION** | Native 802.11/radiotap and non-IP EAPOL frames lack a trusted producer through inspected IP-only capture path. | Rogue AP/key negotiation claims need authorized Wi-Fi capture, BSSID/STA and AP controller logs; roaming and rekeying are benign. |
| P0058 `wps` Wi-Fi Protected Setup | **BLOCKED — MEDIA/L2 INTEGRATION** | WPS association/management frames require a supported wireless capture adapter and trustworthy provenance; no packet-port inference. | WPS PIN abuse needs AP configuration, pairing outcomes and controller events; routine enrollment is benign. |
| P0059 `syslog` Syslog Message | **EXISTING** (limited) | Existing [CiscoSyslogListener](../../Carthago/Services/Cisco/CiscoSyslogListener.cs) is a UDP listener and derives PRI/severity. Does not establish full RFC 5424 parsing, TLS provenance or sender authenticity. | Log changes and administrative events need trusted source configuration, structured event IDs and audit chain; legitimate device reboots create similar messages. Reuse listener; RFC 5424 extension needs separate coordinated integration. |
| P0060 `ospf` OSPF | **IMPLEMENTED_ISOLATED** (v2 envelope only) | New [OspfV2PacketInspector](../../Carthago/Services/ProtocolIntelligence/OspfV2PacketInspector.cs) validates complete caller-attested IP protocol 89 OSPFv2 envelopes, type-specific minimum shapes and checksum for AuType 0 only. No OSPFv3, LSA validation, auth or live producer. | Adjacency manipulation or route injection needs trusted router neighbor/RIB/syslog, authentication and topology; legitimate convergence/failover is benign. Packet type does not prove adjacency or hijack. |

**Totals:** 2 IMPLEMENTED_ISOLATED, 1 PARTIAL, 1 EXISTING limited, 3 DEFERRED, 2 BLOCKED, 1 REJECTED; 0 live integrations. All ten IDs retained; no 500-decoder claim.

## Source-first divergence and trust boundary

Reviewed current [PacketHandler](../../Carthago/Services/PacketHandler.cs), [TrafficCaptureService](../../Carthago/Services/TrafficCaptureService.cs), [TrafficRecord](../../Carthago/Models/TrafficRecord.cs), [OtProtocolLight](../../Carthago/Services/OtProtocolLight.cs), [PortServiceResolver](../../Carthago/Services/PortServiceResolver.cs), NetworkBatch226230Wire/231235Wire/246250Wire, [CiscoSyslogListener](../../Carthago/Services/Cisco/CiscoSyslogListener.cs), architecture/precision documentation, detection and UI ledgers, existing protocol inspectors and xUnit style. The SDK-style .NET 8 project includes new C# files by default; no project edit required.

Neither new inspector is called by PacketHandler, receives a trusted complete TCP control boundary or attested IP protocol-89 payload, emits alerts, writes DetectionEvents or registers an RNNN rule. They are isolated, stateless, allocation-free on successful parse, bounded (Telnet 512 bytes, OSPFv2 65,535 bytes) and never retain Telnet terminal data, OSPF Router IDs, areas, LSAs or authentication bytes. OSPFv2 authenticated packets are deliberately rejected: neither checksum nor frame presence authenticates the peer. OSPFv2 packet envelope checks do **not** parse individual LSAs or validate route semantics. Telnet subnegotiation bytes are skipped and never stored. A complete application control token must be attested by a future source adapter, not guessed from TCP segments. L2/Wi-Fi frames require a separate authorized adapter.

## Threat refresh and evidence classification (2026-10-30)

Official references checked for protocol format, plus current CISA KEV and FIRST EPSS. **All ten entries remain UNVERIFIED for item-specific active exploitation**: no matching vendor/device version, advisory date, exploit prerequisites, verified IOC and trusted observable sensor chain was established in this GA. This does **not** assert absence of vulnerabilities. No invented zero-day or numerical EPSS claim; a parser hit is never a CVE exploit verdict.

- Telnet RFC 854, May 1983, commands and IAC escaping: https://www.rfc-editor.org/rfc/rfc854.html
- OSPFv2 RFC 2328, April 1998, Appendix A.3 and authentication/checksum: https://www.rfc-editor.org/rfc/rfc2328.html
- Syslog RFC 5424, March 2009, structured header: https://www.rfc-editor.org/rfc/rfc5424.html
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog (checked 2026-10-30, no item-specific exploit attribution asserted)
- FIRST EPSS: https://www.first.org/epss/ (probability estimate only; no score inferred)
- Wireshark reference catalog: https://www.wireshark.org/docs/dfref/ (naming reference only)

## Authored-only regression scenarios — NOT EXECUTED

| Inspector | Source Git blob | xUnit test source Git blob | Methods | Concrete invocations | Independent scenario classes |
| --- | --- | --- | ---: | ---: | --- |
| Telnet IAC control | `ca8ef36925f4` | [TelnetControlInspectorTests](../../Carthago.Tests/ProtocolIntelligence/TelnetControlInspectorTests.cs) `72ad0a3cc88c` | 13 | 16 | Four command positives and SB/SE; legitimate terminal/TLS negative; malformed/truncated/overlong/nested escape; deterministic replay and no session state; no credential retention and unattested-boundary rejection |
| OSPFv2 envelope | `853867bbbf6d` | [OspfV2PacketInspectorTests](../../Carthago.Tests/ProtocolIntelligence/OspfV2PacketInspectorTests.cs) `89ab3c6e16cd` | 14 | 18 | Five packet-type envelopes; wrong IP protocol and OSPFv3 negative; malformed length, type, checksum, LSA count; repeated stateless observations; rejected auth modes, privacy and unattested IP payload |

**Authored 27 xUnit methods / 34 concrete invocations. Executed 0; builds 0; replay 0; CI/runner 0.** Fixtures are synthetic RFC-derived packet shapes, not independent capture or TShark evidence. No compile, behavior, accuracy, precision or production reachability is verified.

## Shared integration proposal — NOT APPLIED

Requires separate explicit owner approval and cross-stream lease: a source-attributed TCP control-token adapter with bounded per-flow state, reassembly, retransmission/out-of-order protection, timeout, verified token alignment, endpoint identity and privacy for Telnet; and a complete IP protocol 89 payload adapter preserving IP source/interface, fragmentation and capture provenance for OSPFv2. Route to isolated inspectors as observations only, not automatic DetectionEvents. Test malformed/cross-protocol/encrypted input, source attribution, privacy, journal-first ordering, existing rule regression and rollback by disabling the optional adapter. Never change [PacketHandler](../../Carthago/Services/PacketHandler.cs), [TrafficRecord](../../Carthago/Models/TrafficRecord.cs), capture or journal in this GA. Wi-Fi requires a separate driver/media GA. NTP/Syslog extensions require coordination with existing owners.

## Divergence and publication

Owned paths: `Carthago/Services/ProtocolIntelligence/**`, `Carthago.Tests/ProtocolIntelligence/**`, `docs/protocols/**` only. Detection/UI ledgers, RNNN rules, frozen R102 V1 (FAILED 4/6), R102/R118/R163 floors, Shadow/Disabled, cooldowns, privacy, journal-first raw immutable DetectionEvents and shared project/capture/security pipelines remain untouched. Before publication recheck live HEAD and other streams' changed paths. Publish all six files via one non-forced, expected-HEAD-protected update; on overlap or stale lease stop rather than overwrite. **Next GA P0061–P0070**.

# Protocol Intelligence — GA P0261–P0270

**Branch:** `feature/carthago-reliability-hardening`  
**Base HEAD (before this GA):** `5c87b8489f4821eda1c815f7880e46a3ddaa911a`  
**Source blob:** `8a3213f92bc9642fbe67361257623cf1b8a1e3d6` · **Authored-test blob:** `f5729fb23f1ee62e8ec4e0fdf58b0265259312e0`  
**Publication commit:** the commit containing this document (a commit cannot contain its own SHA).  
**Status:** SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; **0 EXECUTED**. No live integration.

## Ten consecutive research decisions

Authoritative immutable P IDs and filter keys: owner Library CSV `Carthago_500_Protocol_Source_Audit_2026-10-30.csv` (2026-10-30); the 500 entries are research rows, not 500 proven independent protocol gaps.

| ID | Original key / protocol | Disposition | Source and reachability / security evidence |
| --- | --- | --- | --- |
| P0261 | `mrcpv2` / MRCPv2 | DEFERRED | [RFC 6787](https://www.rfc-editor.org/rfc/rfc6787); voice-resource control over SIP-negotiated sessions needs asset demand, trusted message boundaries and server audit. Encrypted media/application content is not available to passive packet inference. |
| P0262 | `netperfmeter` / NetPerfMeter | DEFERRED | Wireshark research label; benchmark traffic may resemble flooding but legitimate testing is common. Need documented deployment, authoritative framing and provenance before a parser or alert. |
| P0263 | `npmp` / NetPerfMeter | REJECTED_DUPLICATE_OR_NOT_A_PROTOCOL | Same original protocol label as P0262; retain row for provenance, do not count a second independent NetPerfMeter protocol. |
| P0264 | `ocp1` / OCP.1 (AES70) | DEFERRED | AES70 networked audio control; need AES70 specification, verified audio/control assets and trusted control-action outcomes. No claim of unsafe device configuration from a port label. |
| P0265 | `osinlcp` / PPP OSI NCP | BLOCKED | [RFC 1377](https://www.rfc-editor.org/rfc/rfc1377) PPP link control; no trusted PPP native frame producer in current Windows capture fast path. Requires separate capture-adapter GA. |
| P0266 | `osmo_trxc` / OsmoTRX control/clock | DEFERRED | Specialized Osmocom base-station transport; requires deployment evidence, vendor specification and trusted radio-control logs. No general Windows endpoint relevance established. |
| P0267 | `pfcp` / PFCP | DEFERRED | [ETSI TS 129 244](https://www.etsi.org/deliver/etsi_ts/129200_129299/129244/16.05.00_60/ts_129244v160500p.pdf) over UDP/8805; mobile control/user-plane session changes need operator topology and authenticated SMF/UPF logs. A packet alone does not establish an authorized or successful change. |
| P0268 | `pn_rt` / PROFINET RT | BLOCKED | Non-IP PROFINET RT EtherType frames are discarded by current IP-only fast path. A native L2 producer and asset-role attestation require a separately approved integration GA. |
| P0269 | `portcontrol` / Port Control Protocol | IMPLEMENTED_ISOLATED | [RFC 6887](https://www.rfc-editor.org/rfc/rfc6887) PCP v2 MAP request/response envelope, complete UDP payload only. [Source](../../../Carthago/Services/ProtocolIntelligence/PcpMapInspector.cs) and [authored tests](../../../Carthago.Tests/ProtocolIntelligence/PcpMapInspectorTests.cs). No trusted live producer, NAT/firewall state or authentication outcome. |
| P0270 | `pppmuxcp` / PPPMux Control Protocol | BLOCKED | [RFC 3153](https://www.rfc-editor.org/rfc/rfc3153); native PPP frame input absent. Multiplexing control is not independently observable from ordinary IP packets. |

**Totals:** 1 IMPLEMENTED_ISOLATED, 5 DEFERRED, 3 BLOCKED, 1 REJECTED; 0 EXISTING, 0 PARTIAL, 0 INTEGRATED_UNVERIFIED. One genuinely new narrow inspector; zero reused operational decoders; zero live registrations.

## Source-first divergence and exact integration boundary

Read at the exact base SHA: [conduct](../../rules/RULE_DOCUMENTATION_STANDARD.md), [architecture](../../02-architecture/ArchitectureSafetyRules.md), [rule authoring](../../03-detection-rules/guides/AddingDetectionRules.md), [precision migration](../../03-detection-rules/guides/RuleOwnedPrecisionDetectorMigration.md), [detection model](../../03-detection-rules/guides/DetectionEngineeringModel.md), [PacketHandler](../../../Carthago/Services/PacketHandler.cs), [TrafficCaptureService](../../../Carthago/Services/TrafficCaptureService.cs), [TrafficRecord](../../../Carthago/Models/TrafficRecord.cs), [OT classifier](../../../Carthago/Services/OtProtocolLight.cs), [wire helpers 226–230](../../../Carthago/Services/NetworkBatch226230Wire.cs), [231–235](../../../Carthago/Services/NetworkBatch231235Wire.cs), [246–250](../../../Carthago/Services/NetworkBatch246250Wire.cs), [port resolver](../../../Carthago/Services/PortServiceResolver.cs), [app project](../../../Carthago/Carthago.csproj), [test project](../../../Carthago.Tests/Carthago.Tests.csproj), [Cisco Syslog](../../../Carthago/Services/Cisco/CiscoSyslogListener.cs), [SNMP](../../../Carthago/Services/Cisco/SharpSnmpClientAdapter.cs), [Windows audit](../../../Carthago/Services/TrustedAudit/WinRmLocalSecurityAuditReader.cs), [detection ledger](../../RULE_HARDENING_PROGRESS.md) and [UI ledger](../../design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md) (read-only).

SDK-style C# projects include new source/test files without project edits. The packet fast path accepts IPv4/IPv6 TCP/UDP/ICMP, discards non-IP frames and has no protocol-owned PCP message producer or trusted NAT/firewall mapping-outcome event. Port-service metadata is only a hint. No shared files or rule definitions are edited. No separate PPP, radio, telecom or PROFINET adapter has been established.

## P0269 scope, falsifiable value, false positives and privacy

The [inspector](../../../Carthago/Services/ProtocolIntelligence/PcpMapInspector.cs) requires **four explicit caller attestations**: complete UDP datagram, unfragmented IP, independently identified PCP endpoint (typically UDP/5351), and plaintext/source provenance. These are caller-supplied preconditions, **not validated by a registered capture adapter**. Only RFC 6887 version 2 opcode MAP is recognized. It checks 60-byte MAP envelopes, 1100-byte RFC datagram ceiling, 4-byte alignment, bounded 32-option walk, option length/padding, singleton THIRD_PARTY and PREFER_FAILURE, FILTER shape, and optional unknown TLVs. Unknown mandatory options fail closed; legal >32 options are conservatively rejected. Reserved fields are ignored on reception as specified. PEER, ANNOUNCE, NAT-PMP and future versions are out of scope. Strict option checks may reject valid future extensions.

Returned fields are **unverified wire claims**: request/response flag, result code, lifetime, transport number, internal/external port and booleans for THIRD_PARTY/FILTER/PREFER_FAILURE, plus option count. No nonce, client/external/third-party IP, raw option bytes, payload, credentials or endpoint identifiers are retained. The parser is stateless, deterministic, allocation-free in the inspect path, has no timers or mutable state and does not emit alerts, journal events, UI updates or external sinks. It cannot infer that a NAT/firewall rule was installed or that a requester was authorized.

Potential future value: correlate PCP MAP requests to expose unexpected inbound-port mapping attempts, deletion bursts or THIRD_PARTY mapping requests. Required trusted evidence: capture-interface/5-tuple/UDP provenance, authenticated gateway PCP audit, asset ownership and mapping success/failure, policy exceptions, baseline and time correlation. Benign P2P, gaming, telephony, cameras, normal NAT recovery, retransmissions and authorized mapping maintenance can look similar. No packet alone is proof of compromise.

**Proposed shared integration — NOT IMPLEMENTED:** after explicit owner approval and fresh cross-stream review, add an additive PCP UDP/5351 adapter at the existing validated UDP payload boundary in `PacketHandler.cs` with capture source/5-tuple/time/fragmentation attestations. Publish a versioned, privacy-safe typed observation to a separately reviewed consumer; preserve existing `TrafficRecord` serialization, journal-first raw DetectionEvents and all RNNN rules. Compatibility tests must check port-only negatives, NAT-PMP version zero, malformed UDP/IPv6 fragments, no false authenticated outcomes, backpressure and journal invariants. Rollback removes the additive adapter/producer registration only. Shared files are untouched in this GA; dependency **BLOCKED — SHARED INTEGRATION**.

## Authored source-only scenarios and verification

[Authored xUnit file](../../../Carthago.Tests/ProtocolIntelligence/PcpMapInspectorTests.cs): **28 [Fact] methods / 28 concrete invocations**. Scenario classes: valid MAP request and response shapes; benign NAT-PMP, PEER/ANNOUNCE and cross-protocol negatives; malformed/truncated/overlong, padding and unknown mandatory TLVs; bounded option count, duplicates, reordered requests and concurrent deterministic calls; four independent source attestations, privacy redaction and fail-closed defaults. Synthetic RFC-derived fixtures only. **0 builds; 0 tests executed; 0 CI/Actions; 0 runner; 0 replay/holdout; 0 live capture/scan.** No measured precision, no runtime support claim.

## Threat refresh — 2026-10-31

Checked [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [CISA JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json): direct retrieval returned **HTTP 403**, so exhaustive KEV status is unavailable. Reviewed original [RFC 6887](https://www.rfc-editor.org/rfc/rfc6887), [ETSI PFCP](https://www.etsi.org/deliver/etsi_ts/129200_129299/129244/16.05.00_60/ts_129244v160500p.pdf), [Siemens ProductCERT](https://cert-portal.siemens.com/) (October 28, 2026 feature concerns Brotli decoder, not proven PROFINET RT exploitation), and [FIRST EPSS](https://www.first.org/epss/). No dated first-party advisory was verified establishing a specific exploited zero-day in these ten wire protocols. **Classification: UNVERIFIED** for protocol-specific exploitation, not a claim of no vulnerabilities. No affected version, IOC or EPSS number was invented. EPSS estimates CVE exploitation probability, not proof of an attack or proof that a protocol is compromised.

**Next exact GA:** P0271–P0280. Recover new live HEAD; never repeat this GA.

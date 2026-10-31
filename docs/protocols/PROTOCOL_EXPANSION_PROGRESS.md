# Carthago protocol intelligence — dedicated progress ledger

**Branch:** `feature/carthago-reliability-hardening`  
**Status:** SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; **0 EXECUTED**  
**Original inventory:** P0001–P0500, immutable research row identifiers from the owner's 2026-10-30 CSV (ChatGPT Library `/Carthago Protocol Expansion`). They are not detection-rule IDs.

## Completed source-only checkpoints

| GA | Base source SHA | Research IDs | Outcomes | Authored xUnit methods / invocations | Executed | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| [GA 0](PROTOCOL_GA_0_RECONCILIATION.md) | `7aa356429b674fab1975127f40f4fea6b312450b` | Inventory P0001–P0500, source reconciliation only | 436 provisional unverified research candidates, 23 reuse/extend, 41 variants/rejects; true distinct eligible count not yet established | 0 / 0 | 0 | Historical audit vs live HEAD, three detection-only commits; no changed packet producers |
| [GA P0001–P0010](PROTOCOL_GA_P0001-P0010.md) | `7aa356429b674fab1975127f40f4fea6b312450b` | P0001–P0010 | 2 IMPLEMENTED_ISOLATED, 2 PARTIAL, 4 DEFERRED, 2 REJECTED; 0 live integrated | 17 / 20 | 0 | HTTP/2 and DTLS bounded source inspectors and isolated xUnit scenarios |

| [GA P0011–P0020](PROTOCOL_GA_P0011-P0020.md) | 568a297281022f66c21bc6c92b28af6277571090 | P0011–P0020 | 2 IMPLEMENTED_ISOLATED (LDAP, DCE/RPC), 1 PARTIAL (SMTP), 1 EXISTING (active SNMP), 4 DEFERRED, 2 REJECTED; 0 integrated | 23 / 25 | 0 | Source-only bounded LDAP BER and DCE/RPC v5 header inspectors; attested message/PDU boundary required |

| [GA P0021–P0030](PROTOCOL_GA_P0021-P0030.md) | d0cf9e925b65038bd9dfe74b4238533e12f71b1b | P0021–P0030 | 3 IMPLEMENTED_ISOLATED (PostgreSQL startup, RESP2, AMQP preface), 2 PARTIAL (DHCPv4, NBNS metadata), 5 DEFERRED; 0 integrated | 38 / 43 | 0 | Source-only bounded protocol observers; trusted plaintext message boundary required; no shared integration |

| [GA P0031–P0040](PROTOCOL_GA_P0031-P0040.md) | f9fcc016081620c20bf9130ea33194d225c0f263 | P0031–P0040 | 2 IMPLEMENTED_ISOLATED (WireGuard, IKEv2-only), 3 PARTIAL (Modbus, Modbus/TCP, DNP3), 1 DEFERRED (ESP), 4 BLOCKED L2 (EAPOL, ARP, LLDP, STP); 0 integrated | 29 / 38 | 0 | Complete caller-attested UDP envelopes only; no runtime producer, authentication, decryption or exploit claims |

**Last completed research GA:** P0141–P0150 (source-only, unverified). **Next exact ten IDs:** **P0151–P0160**. Do not skip blocked candidates, invent new P IDs, rewrite historical outcomes, or treat authored tests as executed. Recover live HEAD and compare concurrent detection/UI stream paths before publication.

| [GA P0041–P0050](PROTOCOL_GA_P0041-P0050.md) | 691717f8a3302f58454dfcb9e6da45993b17a442 | P0041–P0050 | 3 IMPLEMENTED_ISOLATED (OPC UA UACP, IEC104 APCI, BGP-4 envelope), 2 PARTIAL (S7, BACnet), 1 DEFERRED (MMS), 4 BLOCKED L2 (GOOSE, PROFINET DCP/IO, EtherCAT); 0 integrated | 42 / 50 | 0 | Source-only bounded inspectors, synthetic authored xUnit scenarios, no trusted TCP reassembly or L2 producer |

| [GA P0051–P0060](PROTOCOL_GA_P0051-P0060.md) | 121ebc81a09e49d4543697ee2216b29259844c38 | P0051–P0060 | 2 IMPLEMENTED_ISOLATED (Telnet IAC, OSPFv2 envelope), 1 PARTIAL (NTP), 1 EXISTING limited (Syslog), 3 DEFERRED (POP3, rsync, rlogin), 2 BLOCKED Wi-Fi/L2 (RSNA EAPOL, WPS), 1 REJECTED (WBXML encoding); 0 integrated | 27 / 34 | 0 | Bounded isolated RFC 854 and RFC 2328 source inspectors; no TCP/IP trusted producer, no auth/LSA/credential claims |\n\n| [GA P0061–P0070](PROTOCOL_GA_P0061-P0070.md) | 8b12fdbb335a58ffb98a80fd3f2064415bdd22d5 | P0061–P0070 | 2 IMPLEMENTED_ISOLATED (GRE, VXLAN), 7 DEFERRED (EIGRP, IGMP, PIM, L2TP, PPTP, SSTP, IPsec AH), 1 BLOCKED L2/LLC (IS-IS); 0 integrated | 33 / 40 | 0 | Bounded strict RFC 2784/2890/7348 source-only inspectors, synthetic tests, Arista CVE-2026-7473 vendor threat context, no shared producer |

## Unresolved independent obligations

- Owner approval and cross-stream review for any shared capture/telemetry/record schema integration; source-only isolated work may continue meanwhile.
- First actual build/xUnit/Windows replay awaits explicit owner command **“now it’s test time.”**
- Live sensor provenance, TCP stream boundaries, DTLS 1.3 encrypted records, endpoint/proxy logs and NetScaler asset/config/IOC correlation are not established by these isolated inspectors.
- Continue source-only with P0151–P0160; preserve detection and UI ledgers, frozen holdouts, journal-first raw DetectionEvents, privacy, cooldowns, thresholds and rule IDs.

| [GA P0071–P0080](PROTOCOL_GA_P0071-P0080.md) | 984c9bbea00f68d7dc2f6b8b5f0d163880ddcba4 | P0071–P0080 | 2 IMPLEMENTED_ISOLATED (Geneve, HSRP v1), 1 EXISTING (VLAN), 1 DEFERRED (GTP), 5 BLOCKED input/L2 (PPP, PPPoE, MPLS, CDP, UDLD), 1 REJECTED as separately counted variant (GTPv2-C); 0 integrated | 33 / 41 | 0 | Source-only bounded Geneve and HSRP v1 inspectors; no trusted live UDP envelope, HSRP authentication or runtime registration |

| [GA P0081–P0090](PROTOCOL_GA_P0081-P0090.md) | 59cbc728164559c05659edfdccc04d7ab2d54707 | P0081–P0090 | 2 IMPLEMENTED_ISOLATED (STUN Binding, RADIUS UDP), 4 DEFERRED (VRRP, GLBP, TACACS, TACACS+), 2 BLOCKED (B.A.T.M.A.N. L2, EAP L2/AAA), 2 REJECTED distinctness (DCE/RPC Kerberos subdissector, bHTTP representation); 0 integrated | 39 / 47 | 0 | RFC 8489 and RFC 2865/2866 bounded source inspectors; Cisco ISE and Siemens RADIUS vendor advisories; no trusted live producer or authentication claims |

| [GA P0091–P0100](PROTOCOL_GA_P0091-P0100.md) | fecc45af2eaa7870d1c3fa33b5aad662d9cc7b83 | P0091–P0100 | 1 IMPLEMENTED_ISOLATED (TFTP RRQ/WRQ), 7 DEFERRED (NBSS, NBDGM, DHCP failover, SFTP, Git, BitTorrent, IPP), 1 BLOCKED L2 (LLTD), 1 REJECTED independent protocol (DNS server role); 0 integrated | 23 / 29 | 0 | RFC 1350/2347 bounded source-only TFTP inspector; CISA 2026-07-13 router/TFTP threat context; no trusted runtime producer |

| [GA P0101–P0110](PROTOCOL_GA_P0101-P0110.md) | 0871d7a795e3f9cd7d6ce780cb02152309fbc72a | P0101–P0110 | 2 IMPLEMENTED_ISOLATED (LPD top-level command, RFB version), 1 DEFERRED (IPMI), 1 BLOCKED USB (IPPUSB), 6 REJECTED independently counted RDP channel/transport variants; 0 integrated | 33 / 40 | 0 | RFC 1179/6143 bounded source-only inspectors; AMI BMC advisory context not packet exploit evidence; no trusted producer |

| [GA P0111–P0120](PROTOCOL_GA_P0111-P0120.md) | 11a2a9d68f885b4fef01b7985d35bf84327a6126 | P0111–P0120 | 1 IMPLEMENTED_ISOLATED (CIP encapsulation extension), 1 PARTIAL (SMB pipes), 4 DEFERRED (CIP objects/safety/PCCC), 1 BLOCKED L2 (MRP), 3 REJECTED as independently counted (RDP audio, NetBIOS umbrella, CIP Safety Validator); 0 integrated | 20 / 21 | 0 | Strict bounded EtherNet/IP session/CPF observer; no runtime producer or CIP object/safety claim; no shared-core edits |

| [GA P0121–P0130](PROTOCOL_GA_P0121-P0130.md) | 7c33d95aa8f9f8a88e8247b85744f8b90dd6af28 | P0121–P0130 | 1 IMPLEMENTED_ISOLATED (IEC101 FT1.2 serial), 4 BLOCKED input (PROFINET MRRT/PTCP/RSI L2; BACnet MS/TP serial), 5 REJECTED separately counted EtherCAT/IEC104 components; 0 live integrated | 14 / 17 | 0 | Strict serial framing, no trusted producer, source-only and no shared edits |

| [GA P0131–P0140](PROTOCOL_GA_P0131-P0140.md) | 187823c5e5d291791ac567c8da1766dbf9a0e6a5 | P0131–P0140 | 3 IMPLEMENTED_ISOLATED (MQTT-SN, RTP, RTCP), 3 DEFERRED (IEC103, Thrift, SIP), 2 BLOCKED L2 (HSR, HSR/PRP supervision), 2 REJECTED subcomponents (IEC ASDU, SIPfrag); 0 integrated | 47 / 49 | 0 | Bounded source-only UDP inspectors, Cisco HTTP-on-SIP-phone vendor advisory distinguished from SIP exploitation, no shared capture/telemetry edits |

| [GA P0141–P0150](PROTOCOL_GA_P0141-P0150.md) | ad1cd1b2e9425c215fd906d0babb697e19c8f7e2 | P0141–P0150 | 1 IMPLEMENTED_ISOLATED (Diameter base envelope), 1 PARTIAL (gQUIC metadata), 4 DEFERRED (H.323, MGCP, MEGACO, AFS Rx), 3 BLOCKED L4/SIGTRAN (SS7 SCCP, DCCP, SCTP), 1 REJECTED independent protocol (NFSACL); 0 integrated | 22 / 25 | 0 | RFC 6733 bounded AVP/header inspector; no SCTP/TCP trusted producer, auth outcomes or shared integration |

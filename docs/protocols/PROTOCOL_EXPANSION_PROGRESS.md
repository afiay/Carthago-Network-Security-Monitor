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

**Last completed research GA:** P0051–P0060 (source-only, unverified). **Next exact ten IDs:** **P0061–P0070**. Do not skip blocked candidates, invent new P IDs, rewrite historical outcomes, or treat authored tests as executed. Recover live HEAD and compare concurrent detection/UI stream paths before publication.

| [GA P0041–P0050](PROTOCOL_GA_P0041-P0050.md) | 691717f8a3302f58454dfcb9e6da45993b17a442 | P0041–P0050 | 3 IMPLEMENTED_ISOLATED (OPC UA UACP, IEC104 APCI, BGP-4 envelope), 2 PARTIAL (S7, BACnet), 1 DEFERRED (MMS), 4 BLOCKED L2 (GOOSE, PROFINET DCP/IO, EtherCAT); 0 integrated | 42 / 50 | 0 | Source-only bounded inspectors, synthetic authored xUnit scenarios, no trusted TCP reassembly or L2 producer |

| [GA P0051–P0060](PROTOCOL_GA_P0051-P0060.md) | 121ebc81a09e49d4543697ee2216b29259844c38 | P0051–P0060 | 2 IMPLEMENTED_ISOLATED (Telnet IAC, OSPFv2 envelope), 1 PARTIAL (NTP), 1 EXISTING limited (Syslog), 3 DEFERRED (POP3, rsync, rlogin), 2 BLOCKED Wi-Fi/L2 (RSNA EAPOL, WPS), 1 REJECTED (WBXML encoding); 0 integrated | 27 / 34 | 0 | Bounded isolated RFC 854 and RFC 2328 source inspectors; no TCP/IP trusted producer, no auth/LSA/credential claims |\n\n## Unresolved independent obligations

- Owner approval and cross-stream review for any shared capture/telemetry/record schema integration; source-only isolated work may continue meanwhile.
- First actual build/xUnit/Windows replay awaits explicit owner command **“now it’s test time.”**
- Live sensor provenance, TCP stream boundaries, DTLS 1.3 encrypted records, endpoint/proxy logs and NetScaler asset/config/IOC correlation are not established by these isolated inspectors.
- Continue source-only with P0061–P0070; preserve detection and UI ledgers, frozen holdouts, journal-first raw DetectionEvents, privacy, cooldowns, thresholds and rule IDs.

# Carthago protocol intelligence — GA P0021–P0030

**Status:** SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; **0 EXECUTED**  
**Branch:** feature/carthago-reliability-hardening ONLY  
**Source base SHA:** d0cf9e925b65038bd9dfe74b4238533e12f71b1b (live remote HEAD inspected 2026-10-30).  
**Source/authored-test/documentation:** one cohesive candidate tree/commit; **publication SHA:** resulting protected branch update (cannot be embedded in its own commit).  
**Research inventory:** immutable P0021–P0030 IDs from owner's 2026-10-30 Library CSV, not RNNN rules.  
**Previous:** [GA P0011–P0020](PROTOCOL_GA_P0011-P0020.md). **Next:** **P0031–P0040**.

## Ten-entry source and decision matrix

| ID | Original key | Disposition | Live baseline / isolated source | Falsifiable security value and benign alternative |
| --- | --- | --- | --- | --- |
| P0021 | pgsql | **IMPLEMENTED_ISOLATED** | [PostgresStartupInspector](../../Carthago/Services/ProtocolIntelligence/PostgresStartupInspector.cs) reads caller-attested plaintext PostgreSQL v3.0 startup, SSLRequest and GSSENCRequest envelopes; no live trusted boundary. | SSL/GSS negotiation presence and parameter-name flags can contextualize database connections; normal clients negotiate identically. Version, server settings, session identity and login outcome require trusted server/asset logs. |
| P0022 | mysql | **DEFERRED** | [PortServiceResolver](../../Carthago/Services/PortServiceResolver.cs) maps TCP 3306 to MySQL as metadata; [PacketHandler](../../Carthago/Services/PacketHandler.cs) has no verified MySQL handshake/packet-sequence or TLS producer. | Suspicious connection/auth needs server authentication/audit outcomes, phase and account; backups and application pools are benign. MySQL TLS opaque. |
| P0023 | mongo | **DEFERRED** | No verified OP_MSG/OP_COMPRESSED framing or trusted MongoDB command producer in reviewed capture path. | Unauthorized reads/exports require authenticated server command audit and deployment context; application reads/backups resemble exfiltration. TLS/compressed bodies not decoded. |
| P0024 | resp | **IMPLEMENTED_ISOLATED** | [Resp2CommandInspector](../../Carthago/Services/ProtocolIntelligence/Resp2CommandInspector.cs) parses bounded RESP2 array-of-bulk-strings subset at attested plaintext client-command boundary; returns only fixed command kind, argument count and consumed bytes. No live producer. | AUTH, CONFIG, RESTORE, EVAL and FLUSHALL command attempt shapes could guide investigation; admin maintenance uses them legitimately. Execution, success, ACL permissions and exploit unproven. TLS opaque. |
| P0025 | kafka | **DEFERRED** | [Carthago.csproj](../../Carthago/Carthago.csproj) references Confluent.Kafka for application integration, **not** a passive Kafka decoder or trusted broker audit source. No validated request-correlation producer. | Topic access/authorization needs Kafka broker audit, principal, ACL, topic and correlation ID. Normal clients generate similar traffic; SASL/TLS opaque. |
| P0026 | amqp | **IMPLEMENTED_ISOLATED** | [AmqpConnectionHeaderInspector](../../Carthago/Services/ProtocolIntelligence/AmqpConnectionHeaderInspector.cs) recognizes exact AMQP 0-9-1, 1.0 and 1.0 SASL prefaces at attested plaintext connection start. 0-9-1 and 1.0 are distinct wire protocols, not one frame parser. | Broker protocol exposure/version inventory can aid hardening; normal broker clients send these. Auth, publish, consume, routing and delivery outcomes need broker logs. |
| P0027 | dhcp | **PARTIAL** | [PortServiceResolver](../../Carthago/Services/PortServiceResolver.cs) has 67/68 DHCP/BOOTP hints, not verified DHCPv4 header, option 53, transaction ID or lease producer. | Rogue DHCP/lease anomalies require server identity, trusted option parsing, lease ACK and segment context; normal failover/renewals confound. |
| P0028 | dhcpv6 | **DEFERRED** | IPv6/UDP transport is not a DHCPv6 option/transaction decoder; no trusted DUID, relay chain, message type or lease producer. | Rogue DHCPv6/relay behavior needs attested link/relay context, server identity and lease events; ordinary renumbering benign. |
| P0029 | nbns | **PARTIAL** | [PortServiceResolver](../../Carthago/Services/PortServiceResolver.cs) maps UDP 137 to NetBIOS name service; this is **not** NBNS query/response decoding. DNS semantics must not be blindly reused. | Poisoning needs actual NBNS questions/responses, transaction IDs and host/segment attribution; legacy Windows name resolution benign. |
| P0030 | openvpn | **DEFERRED** | No verified OpenVPN control-channel opcode/session/certificate producer in inspected capture path; port alone insufficient. | Abnormal VPN access needs trusted server session/authentication and certificate/device evidence; legitimate reconnects/key renegotiation confound. TLS/encrypted content opaque. |

**Totals:** 3 IMPLEMENTED_ISOLATED, 2 PARTIAL, 5 DEFERRED, 0 EXISTING, 0 REJECTED, **0 INTEGRATED**, **0 new RNNN detection rules**. Ten historical research rows resolved, not ten new decoders.

## Parser contracts, bounds, privacy and observability

- **PostgreSQL:** caller attests plaintext connection start. Big-endian length 8–8192, v3.0 startup plus exact 8-byte SSL/GSS requests; maximum 32 key/value pairs, 64-byte ASCII keys and 2048-byte values. User key must be present; no key/value payloads, credentials, query text or backend PID returned. PostgreSQL 18 protocol 3.2, CancelRequest and later messages outside subset. Coalesced bytes yield only first message. SSL/GSS request is not proof of negotiated encryption.
- **RESP2:** caller attests plaintext client-command direction and first command boundary. Maximum 8192 input bytes and 16 bulk-string elements, strict decimal length/CRLF framing, fixed case-insensitive command allowlist. Binary argument bytes skipped, never returned. Unknown commands, RESP3 aggregates, streamed/large values and server replies deliberately excluded. Command arity/execution not validated; coalesced commands yield first only.
- **AMQP:** caller attests plaintext connection start. Exact 8-byte 0-9-1, 1.0 and 1.0 SASL prefaces only; maximum 4096 input bytes. No AMQP frames, message headers, broker response, TLS/SASL outcome, credentials or payloads. Preface is not proof of successful negotiation.
- All three inspectors are deterministic, stateless, allocation-free on success, with no cache, regex, logging, alerts, UI, sinks, network calls or journal writes. Strict subsets can reject legitimate unsupported versions/frames. Forged bytes may match a shape; observations are untrusted, not detections.
- [PacketHandler](../../Carthago/Services/PacketHandler.cs) performs bounded early TCP inspection (4096 bytes per direction), not reliable application reassembly or trusted plaintext attestation. [TrafficRecord](../../Carthago/Models/TrafficRecord.cs) lacks typed PostgreSQL/RESP/AMQP producers. [TrafficCaptureService](../../Carthago/Services/TrafficCaptureService.cs) does not register inspectors. Non-IP Ethernet drop unchanged. **ISOLATED — NOT LIVE-CAPTURE INTEGRATED.**

## Threat refresh — original first-party sources, 2026-10-30

- **P0021 PostgreSQL CVE-2026-6479 — VENDOR_ADVISORY_NO_EXPLOIT_EVIDENCE.** PostgreSQL advisory describes uncontrolled recursion during SSL/GSS initialization, fixed **2026-05-14** in 18.4, 17.10, 16.14, 15.18, 14.23. Prerequisites: attacker can connect to AF_UNIX socket, or TCP with both SSL and GSS disabled. No actual asset version/configuration, repetition, exploit IOC or observed exploitation established here. Isolated SSL/GSS request cannot detect this CVE. [Vendor advisory](https://www.postgresql.org/support/security/CVE-2026-6479/); [protocol formats](https://www.postgresql.org/docs/current/protocol-message-formats.html).
- **P0024 Redis CVE-2026-81934 — VENDOR_ADVISORY_NO_EXPLOIT_EVIDENCE.** Redis advisory published **2026-08-28**, updated **2026-09-01**, describes TLS pending-data use-after-free requiring authenticated access and specific conditions; Redis stated no known active customer exploitation as of **2026-08-27**. Fixed OSS versions include 8.10.1, 8.8.2, 8.6.6, 8.4.6, 8.2.9, 7.4.11, 7.2.16 and 6.2.24. [Vendor advisory](https://redis.io/blog/security-advisory-cve-2026-81934/). Debian [DSA-6538-1, 2026-10-02](https://lists.debian.org/debian-security-announce/2026/msg00451.html) covers multiple Redis issues including this CVE. RESP plaintext commands cannot inspect TLS internals or establish this exploit.
- **P0022–P0023, P0025–P0030 — UNVERIFIED** for candidate-specific exploited-CVE claims. No authenticated exploit event, affected asset, IOC, vendor-verified signature or confirmed exploitation established in this GA. Not a claim that protocols are vulnerability-free. [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) is an exploitation catalog; [FIRST EPSS](https://www.first.org/epss/) is a probabilistic CVE-level forecast, not exploitation proof. No EPSS number or absence-from-KEV claim invented.
- Protocol specifications: [Redis RESP](https://redis.io/docs/latest/develop/reference/protocol-spec/), [RabbitMQ AMQP](https://www.rabbitmq.com/docs/specification), [OASIS AMQP 1.0](https://docs.oasis-open.org/amqp/core/v1.0/cs01/amqp-core-transport-v1.0-cs01.html), [PostgreSQL protocol](https://www.postgresql.org/docs/current/protocol-overview.html). No third-party decoder code copied.

## Authored xUnit scenarios — zero executed

| Inspector / test source | Methods | Concrete invocations | Independent scenario classes |
| --- | ---: | ---: | --- |
| [PostgreSQL](../../Carthago.Tests/ProtocolIntelligence/PostgresStartupInspectorTests.cs) | 14 | 15 | Valid v3.0 startup; SSL/GSS negotiation; HTTP negative; TLS/untrusted boundary; truncation/forged lengths; missing user; malformed pairs; unsupported 3.2; bounded parameter count/input; coalescence; repeated observation; privacy/no login inference. |
| [RESP2](../../Carthago.Tests/ProtocolIntelligence/Resp2CommandInspectorTests.cs) | 14 | 16 | AUTH/RESTORE/CONFIG; mixed-case command; HTTP negative; untrusted/TLS; truncated/wrong CRLF; null/nested RESP; forged lengths; nonminimal/negative decimals; bounded elements/input; coalescence; repeat neutrality; unknown command; credential redaction. |
| [AMQP](../../Carthago.Tests/ProtocolIntelligence/AmqpConnectionHeaderInspectorTests.cs) | 10 | 12 | Three exact versions; HTTP negative; untrusted/TLS; truncation; forged magic; unsupported version; size cap; coalescence; repeated observation; SASL is not authentication proof. |
| **Total** | **38** | **43** | **0 executed** |

Fixtures are synthetic, public-format-inspired and non-secret; no independently corroborated vendor packet capture replayed. **No dotnet build, xUnit, replay, holdout, CI, Windows runner, benchmark, packet capture or active scan executed.** All are source candidates, possibly requiring correction after owner-authorized exact-SHA Windows compilation.

## Shared integration proposal — NOT AUTHORIZED OR IMPLEMENTED

**BLOCKED — SHARED INTEGRATION** for all three inspectors. A separate owner-approved GA would:
1. Add an opt-in, bounded, direction-aware trusted plaintext message-boundary producer after verified TCP reassembly or trusted application/proxy/server logs; attest source ID, capture time, plaintext provenance, connection identity, frame length, fragment/retransmission policy and privacy consent. Never pass arbitrary early bytes as verified boundary.
2. Define reviewed optional typed protocol-observation fields/sidecar with stable serialization, source trust, authenticated-versus-untrusted distinction and redacted metadata. Preserve existing TrafficRecord, JSONL DetectionEvents and rule contracts.
3. Register inspectors only in approved adapter, not direct alerts. Never promote Alert from port/name/command attempt. Preserve Shadow/Disabled, cooldowns, baselines, R102/R118/R163 floors and frozen R102 holdouts.
4. Author compatibility/rollback scenarios: Npcap/ETW parity, split/coalesced/reordered TCP, TLS opacity, forged framing, provenance, throughput/memory bounds, disabled adapter, journal-first invariants and existing UI/rule consumers. Rollback disables adapter and reverts shared wiring, retaining isolated inspectors and historical docs.

No shared capture, model, project, detection, UI, privacy or journal file edited.

## Source-only divergence and publication review

- Live base: d0cf9e925b65038bd9dfe74b4238533e12f71b1b. Prior protocol publication: 21cfd475d84b31aa17a21221f404ab00b77498fc. GitHub compare found two intervening UI-only commits touching Carthago/Views/MainWindow.Dashboard.cs, Carthago/Views/MainWindow.xaml and docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md; no protocol overlap at inspection.
- Inspected rule standard, safety contracts, dedicated protocol ledger, detection/UI ledgers read-only, PacketHandler, TrafficCaptureService, TrafficRecord, PortServiceResolver, OT/wire helpers, Cisco SNMP/Syslog, Windows Security reader, project and existing protocol inspectors/tests. No new dependency or shared registration; SDK compilation automatically includes new source/test files.
- Owned changed paths only Carthago/Services/ProtocolIntelligence/**, Carthago.Tests/ProtocolIntelligence/**, docs/protocols/**. No change to RNNN rules, JSONL journal, confidence floors, privacy, UI or frozen holdouts.
- Recheck live HEAD immediately before publication. Use one non-forced expected-HEAD-protected atomic branch update; reconcile disjoint concurrent commits, stop on overlap. Never force-push.

**Next GA: P0031–P0040**, recovered from immutable inventory and live branch ledger.

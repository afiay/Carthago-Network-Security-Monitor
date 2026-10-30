# Carthago protocol intelligence — GA P0031–P0040

**Status:** SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; **0 EXECUTED**.  
**Branch:** `feature/carthago-reliability-hardening` ONLY.  
**Source base:** `f9fcc016081620c20bf9130ea33194d225c0f263` (live branch HEAD inspected 2026-10-30).  
**Research source:** owner's immutable 2026-10-30 Library CSV, P0031–P0040. P IDs are research IDs, never RNNN rules.  
**Publication:** source, authored tests, this GA document and dedicated protocol ledger must be one protected atomic branch update; publication SHA is the resulting commit (cannot be self-referenced).  
**Previous:** [GA P0021–P0030](PROTOCOL_GA_P0021-P0030.md). **Next:** **P0041–P0050**.

## Ten-entry source-grounded decision matrix

| ID / original key | Disposition | Baseline / candidate reachability | Falsifiable security use, prerequisites and benign alternatives |
| --- | --- | --- | --- |
| P0031 `wg` — WireGuard | **IMPLEMENTED_ISOLATED** | New [WireGuardDatagramInspector](../../Carthago/Services/ProtocolIntelligence/WireGuardDatagramInspector.cs): complete, caller-attested UDP payload, exact type 1/2/3 lengths, bounded type 4 shape, reserved-zero checks; **no live producer/registration**. | A trusted sensor could count message *shapes* or contextualize unexpected VPN exposure. Ordinary VPN handshakes/rekeys/roaming are benign. No peer authentication, counter-replay verdict, key/ciphertext disclosure, or compromise claim. |
| P0032 `isakmp` — IKE/ISAKMP | **IMPLEMENTED_ISOLATED (IKEv2 only)** | New [IkeV2DatagramInspector](../../Carthago/Services/ProtocolIntelligence/IkeV2DatagramInspector.cs): caller-attested UDP 500/4500, optional non-ESP marker, IKEv2 header and bounded outer generic-payload lengths; **not IKEv1/entire ISAKMP**, no live producer. | Exposed IKE negotiation shape may guide device-specific investigation, but successful authentication, exploit CERT contents, peer identity and service crash require trusted Firebox/VPN logs and asset/version/config evidence. Normal rekey/retries are benign. |
| P0033 `esp` — IPsec ESP | **DEFERRED** | Encrypted ESP payload and native IP protocol 50 have no verified typed producer in reviewed fast path. | ESP SPI/sequence may contextualize traffic only after an explicit IP-protocol-50 adapter and endpoint attribution; encrypted contents, replay decisions and VPN success cannot be inferred. |
| P0034 `eapol` — IEEE 802.1X/EAPOL | **BLOCKED — SHARED L2 INTEGRATION** | Non-IP EtherType 0x888e rejected by inspected packet fast path; no approved L2 adapter. | Auth failures require supplicant/authenticator/RADIUS logs and switch-port identity. Normal reconnect/roaming resembles abuse. |
| P0035 `arp` — ARP | **BLOCKED — SHARED L2 INTEGRATION** | EtherType 0x0806 not passed to current IP-only decoder; no approved L2 adapter. | Poisoning inference requires validated MAC/IP/segment/host-role history and switch context; gratuitous ARP and failover are benign. |
| P0036 `lldp` — LLDP | **BLOCKED — SHARED L2 INTEGRATION** | EtherType 0x88cc not passed to current IP-only decoder; no approved L2 adapter. | Spoofed topology needs switch port, authenticated inventory and TLV provenance; normal switch moves are benign. |
| P0037 `stp` — STP/BPDU | **BLOCKED — SHARED L2 INTEGRATION** | IEEE 802.3/LLC BPDU input path not established; **not** an IP port protocol. | Root-bridge changes require trusted switch telemetry and VLAN topology; maintenance/failover can look similar. |
| P0038 `modbus` — Modbus | **PARTIAL** | Existing [OtProtocolLight](../../Carthago/Services/OtProtocolLight.cs) recognizes bounded Modbus/TCP framing; no full authorization or asset role. | OT write-attempt patterns need PLC role, approved change window and transaction outcome; normal HMI writes are benign. Reuse existing helper. |
| P0039 `mbtcp` — Modbus/TCP | **PARTIAL** | Same existing Modbus/TCP producer as P0038; not a second independent parser. | See P0038; avoid duplicate capability and inflated coverage counts. |
| P0040 `dnp3` — DNP3 | **PARTIAL** | Existing [OtProtocolLight](../../Carthago/Services/OtProtocolLight.cs) recognizes bounded DNP3 frame/CRC, not complete application-function semantics. | Control-function claims require validated application frames, station roles, authorized operations and process logs; maintenance traffic benign. |

**Totals:** 2 IMPLEMENTED_ISOLATED (not live), 3 PARTIAL, 1 DEFERRED, 4 BLOCKED; 0 INTEGRATED_UNVERIFIED, 0 new RNNN rules, 0 runtime capture integrations, 0 duplicate decoders of Modbus/DNP3.

## Boundaries, source divergence and integration

- Live entry [PacketHandler](../../Carthago/Services/PacketHandler.cs) inspects IP/TCP/UDP and bounded early bytes, not arbitrary decrypted VPN streams or non-IP L2 frames. [TrafficCaptureService](../../Carthago/Services/TrafficCaptureService.cs) and [TrafficRecord](../../Carthago/Models/TrafficRecord.cs) are coordination-required. No code here edits those producers or their consumers.
- The new inspectors live solely under `Carthago/Services/ProtocolIntelligence/**` and corresponding `Carthago.Tests/ProtocolIntelligence/**`. Existing SDK-style `Carthago.csproj` and xUnit project include these source files automatically. No dependency additions, settings, alert outputs, journaling, state, I/O, active capture or decryption.
- WireGuard inspector: accepts only caller-attested full UDP payloads up to 65,535 bytes, reserved-zero bytes, fixed handshake lengths (148, 92, 64), transport length >=32 divisible by 16. Returns type, length and opaque flag only; deliberately omits peer indices, counters, keys, ciphertext and replay decisions. A forged same-shape datagram remains indistinguishable.
- IKEv2 inspector: caller-attested complete UDP payload on 500/4500, NAT-T non-ESP marker on 4500, nonzero initiator SPI, major version 2, known exchange 34–37, reserved-flag check, exact network-byte-order message length, <=24 outer generic payload envelopes. SK/SKF contents remain opaque and terminal; no certificate, inner payload, endpoint identity or exploit inference. Valid extensions outside the bounded subset may be rejected.
- **Shared integration proposal (NOT authorized or applied):** introduce an explicitly trusted, versioned datagram observation adapter between capture and these inspectors, carrying capture backend, link type, original wire-length/truncation flag, direction, ports, timestamp, source/asset identity and privacy classification. Only invoke on complete non-truncated UDP payloads, never on arbitrary TCP fragments or encrypted TLS/QUIC. Publish as additive typed telemetry only after explicit owner approval and compatibility checks of TrafficRecord, journaling, capture backends, consumer filters and false positives. For L2, separately propose an opt-in EtherType/LLC adapter with VLAN/port provenance and bounded parsing. Rollback: disable new adapter, leave existing TrafficRecord/DetectionEvents and rules untouched. No such adapter exists in this GA.
- Pre-change divergence: reviewed live branch SHA, detection ledger (read-only), UI ledger (read-only), architecture/rule standards, packet/OT wire helpers, capture/record contracts and existing isolated protocol sources. Concurrent UI changes since prior protocol GA affect only `Carthago/Views/**` and `docs/design/**`; they are not modified here.
- Preserve mandatory JSONL journal, immutable raw DetectionEvents, Shadow/Disabled, cooldowns, R102/R118/R163 floors, baseline readiness, suppression reasons, approvals, privacy and pinned holdouts. No detection-rule registration, false alert emission or production evidence.

## Threat advisory refresh — 2026-10-30

These are **risk context**, not signatures. Neither inspector can determine whether a vulnerable appliance is deployed or an exploit succeeded.

| Advisory and original source | Dated evidence and classification | Required asset evidence and observability |
| --- | --- | --- |
| [WatchGuard CVE-2025-14733](https://psirt.watchguard.com/CVE-2025-14733/) | Published **2025-12-19**, updated **2026-08-10**. **CONFIRMED_EXPLOITED_KNOWN_VULNERABILITY**: WatchGuard reports in-the-wild attempts; [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-14733) confirms CISA KEV addition **2025-12-19**. | Fireware vulnerable releases and IKEv2 dynamic peer/mobile VPN configuration, including historical configuration, must be verified. Vendor IOCs include named attacker IPs, oversized IKE_AUTH CERT payloads (>2000 bytes), peer certificate-chain errors, and iked hang/crash; **this inspector sees none of the certificate contents or outcomes**. Trust Firebox logs, device inventory/config and incident response evidence, not UDP presence. |
| [WatchGuard CVE-2026-13368](https://psirt.watchguard.com/CVE-2026-13368/) | Published **2026-07-02**, updated **2026-08-27**. **VENDOR_ADVISORY_NO_EXPLOIT_EVIDENCE**: vendor not aware of exploitation. | Requires affected Fireware and mobile VPN with IKEv2 external LDAP authentication. LDAP backend logs and vendor asset configuration are needed; IKE envelope shape cannot prove the race condition. |
| [WatchGuard CVE-2026-86133](https://psirt.watchguard.com/CVE-2026-86133/) | Published **2026-09-29**. **VENDOR_ADVISORY_NO_EXPLOIT_EVIDENCE**: vendor not aware of exploitation. | Requires affected Fireware, IKEv2 configuration and an established initial handshake; encrypted crafted message and daemon crash are **not observable** in this source-only inspector. |
| WireGuard protocol | **UNVERIFIED** for any CVE-specific exploitation claim in this GA. | WireGuard datagram shapes do not reveal authenticated peer, key state, exfiltration, or tunnel success. |

[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) provides exploited-vulnerability evidence; [FIRST EPSS](https://www.first.org/epss/) estimates 30-day exploitation probability, not exploitation proof. No contemporaneous per-CVE EPSS numeric value was retrieved; none is asserted.

## Authored-only scenarios and quality boundary

- [WireGuard tests](../../Carthago.Tests/ProtocolIntelligence/WireGuardDatagramInspectorTests.cs): **12 xUnit methods / 19 concrete invocations**. Covers four legitimate wire shapes, benign DNS/IKE negatives, reserved/type spoofing, truncated/overlong fixed lengths, transport tag/alignment and minimum length, oversized input, trusted producer boundary, deterministic duplicates and redacted observations.
- [IKEv2 tests](../../Carthago.Tests/ProtocolIntelligence/IkeV2DatagramInspectorTests.cs): **17 xUnit methods / 19 concrete invocations**. Covers SA_INIT, NAT-T marker, benign DNS/unknown port, spoofed marker/flags/version/SPI, declared and generic length failures, truncation, bounded payload count, encrypted SK/SKF privacy, deterministic duplicates and redaction.
- **Combined:** **29 xUnit methods, 38 authored concrete invocations, 0 executed**. No build, xUnit, replay, CI, Windows runner, benchmark, scan, active capture or packet validation occurred. SOURCE CANDIDATE — UNVERIFIED; no accuracy, performance, production integration or CVE detection claims.

## Remaining quality GAs and exact continuation

1. Owner-authorized source/compile/xUnit validation on a pinned SHA, benign/malicious paired fixtures, parser differential corroboration, and Windows sensor/packet-boundary proof.
2. Separate owner-approved shared integration for UDP producer and for non-IP L2 frames; cross-stream source compatibility and rollback evidence before wiring.
3. Next exactly ten research IDs **P0041–P0050** after protected publication; do not revisit P0031–P0040 unless a specific defect is evidenced.

**Specifications:** [WireGuard protocol](https://www.wireguard.com/protocol/); [IKEv2 RFC 7296](https://datatracker.ietf.org/doc/html/rfc7296); [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog); [FIRST EPSS](https://www.first.org/epss/).

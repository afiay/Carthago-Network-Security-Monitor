# Carthago protocol-informed threat detection backlog

**Branch:** feature/carthago-reliability-hardening  
**Audit base:** 3bfb8562a7b63307277e82b59cfe49ff14a43e8b, 2026-11-01  
**Status:** SOURCE CANDIDATE — UNVERIFIED; no builds/tests/captures executed.  
**Input:** completed immutable P0001–P0500 source research (50 GAs, not 500 verified protocols); original owner CSV of 2026-10-30; [protocol ledger](../protocols/PROTOCOL_EXPANSION_PROGRESS.md); the complete 544-rule registered catalog at the source base. This is a **prioritized threat crosswalk**, not a claim that all 500 labels represent distinct wire protocols or that every R rule has been validated. R IDs are detection rules; P IDs are research row IDs.

## Reconciliation and first rule

The live [registry](../../Carthago/Engine/Rules/Catalog/RuleRegistry.cs) contained **544 unique R001–R544 registrations**, and the source tree had no R545 class at the audit base. The previous detection continuation was paused; the independent UI stream owns disjoint UI paths. This GA adds **R545** to the existing rule engine, not a new protocol runtime.

| Priority | P research and existing R overlap | Novel falsifiable predicate / sensor | Decision |
| --- | --- | --- | --- |
| 1 | **P0046 BACnet**, related **P0382 BVLC**; R121, R241, R223, R485–R486 | Two bounded \`bacnet.iam\` packets from public IPv4 source to RFC1918 target in 5m, trusted PacketHandler/OT classifier; 10m cooldown; High/Shadow/80%; no device ID or control claim | **R545 authored**, ordinary rule + registry + advanced tests; source candidate |
| 2 | **P0005 DTLS**; R012, R029, R046, R290, R413 | DTLS VPN handshake anomalies correlated with verified NetScaler appliance version, DTLS setting and affected-session logs. Wire DTLS inspector exists only isolated, no trusted runtime producer or appliance outcomes | **BLOCKED** — shared UDP/DTLS integration and authenticated appliance evidence; no exploit signature |
| 3 | **P0001 HTTP/2**, **P0002 HTTP/3**, **P0003 WebSocket**, **P0004 gRPC**; R151, R153–R177, R521–R523 | Edge/proxy-confirmed cross-request routing, abuse and server response outcomes, not ALPN or ciphertext. Existing HTTP/2 inspector is isolated; HTTP/3 encrypted | **BLOCKED** — trusted proxy request/response correlation and approval for shared ingest |
| 4 | **P0006 SMB**, **P0010 Kerberos**, **P0011 LDAP**, **P0113 SMB pipe**; R073–R082, R286–R288, R333–R350 | Remote-service creation followed by authenticated Windows outcome or abnormal service-account access, joined to source identity and target host | **BLOCKED** — source/target authenticated outcomes not established by SMB2/RPC prefix alone; do not duplicate lateral rules |
| 5 | **P0038/P0039 Modbus**, **P0041 S7**, **P0046 BACnet**; R120, R240, R473–R486 | Unexpected write/control operation with verified asset role, maintenance window and process outcome | **PARTIAL / OVERLAP** — existing Modbus write and BACnet discovery signals; control outcomes and asset approvals absent; no duplicate R |
| 6 | **P0018 SNMP**, **P0059 Syslog**; R? existing network-device/engine-health family | Authenticated device config change or newly enabled remote management access from signed vendor/syslog records | **BLOCKED** — active SNMP query and UDP syslog text are not authenticated change outcomes |
| 7 | **P0024 RESP**, **P0021 PostgreSQL**; R433–R445 | Server-verified Redis CONFIG/replication or database export outcome with session identity | **BLOCKED** — isolated startup/RESP inspector does not deliver authenticated server audit; existing R437/R438 already claim related behaviors |
| 8 | **P0042 OPC UA**, **P0046 BACnet**, **P0135 MQTT-SN**; R228–R230, R451, R483–R486 | Authenticated broker/OT control-topic or service operation crossing an unapproved trust boundary | **DEFER** — MQTT-SN is not MQTT 3.1.1; existing MQTT packet PUBLISH flags do not prove broker authorization or command execution |
| 9 | **P0053 Telnet**, **P0097 TFTP**, **P0472 rexec**, **P0493 rsh**; R014, R117, R277 | Cleartext remote-execution attempt with host-verified command start, not a plaintext request prefix | **BLOCKED** — isolated inspectors and packet headers cannot prove execution; privacy-sensitive credentials |
| 10 | **P0034–P0037 L2** and **P0451–P0460 wireless**; R015, R067–R069, R491 | Unapproved L2 identity/control changes with trusted native link-layer producer | **BLOCKED** — existing IP-only fast path drops non-IP EtherTypes; no fabricated port-based matches |

**Existing-rule deduplication:** The registry was read through R544; current rule families already include HTTP/edge probes, DNS tunneling, identity and Windows lateral movement, OT writes, cloud/API exfiltration, MQTT retained/will, and platform health. A new rule requires a *new positive predicate* and a *real producer*, not another protocol label or combination of names. Priorities above reflect reachable data, not hypothetical CVE exploitation.

**First GA:** [R545 source-only batch](../RULE_BATCH_545-545.md). Next proposed cursor **R546** after a new live audit. No P0501 and no new protocol GA. This backlog is independently owned by detection engineering; do not modify historical protocol or UI ledgers.

## Risk, policy and provenance boundaries

- **Confirmed exploitation** must come from CISA KEV or a dated vendor statement. A CVE, protocol or port alone cannot identify a successful exploit. CISA NetScaler advisory for CVE-2026-88772 is a research priority, not a DTLS packet signature: https://content.govdelivery.com/accounts/USDHSCISA/bulletins/42cc465 .
- **MITRE ATT&CK ICS T0846**, modified 2026-10-13, calls for source-role and operational-baseline checks rather than paging on novelty/discovery alone: https://attack.mitre.org/techniques/T0846/ .
- **ASHRAE BACnet interpretation**, 2025, describes BBMD/foreign-device routing that can be legitimate: https://www.ashrae.org/file%20library/technical%20resources/standards%20and%20guidelines/standards%20intepretations/ic-135-2024-8.pdf .
- **FIRST EPSS** estimates future exploitation probability, not observed compromise. No invented score is assigned: https://www.first.org/epss/ .
- Preserve R102/R118/R163 floors 80/86/84%, frozen R102 V1 4/6, pending V2 provenance, original config and journal-first semantics. No shared sensor/telemetry edits, tests, CI, runners, or live capture without explicit owner approval.

## GA R546 — newly resolved reachable threat predicate

| Priority | Research and overlap | Source-backed decision | Evidence / policy |
| --- | --- | --- | --- |
| Completed | **P0051 NTP**, existing **R242** monlist request burst; R001/R017 generic scans | **R546 authored**: three **distinct public NTP endpoints** probed by one RFC1918 host using bounded, packet-classified mode-7 monlist requests within five minutes; R242 counts repeated requests per same pair, not fanout | Existing PacketHandler → OtProtocolLight → typed ApplicationProtocol, IpVersion, L4Len, UDP ports and addresses; Medium/Shadow/80%, ten-minute cooldown; no response, amplification, vulnerability or authenticated-source claim. [GA R546](../RULE_BATCH_546-546.md). |

Next proposed rule cursor **R547**, subject to fresh live registry audit. Do not repeat completed protocol GAs or add isolated protocol inspectors. Historical P inventory remains unchanged.

## GA R547 — public-to-private BACnet Who-Is target fanout

| Priority | P research / prior rule overlap | New producer-backed disposition | Limits / policy |
| --- | --- | --- | --- |
| Completed | **P0046 BACnet**, related **P0382 BVLC**; R241 Who-Is/I-Am packet burst, R545 I-Am external pair, R223 generic ICS internet | **R547 authored:** three distinct RFC1918 destinations targeted within 5m by one public IPv4 source using wire-classified BACnet Who-Is requests on UDP/47808; packet ID deduplication and source-keyed bounded state; [GA R547](../RULE_BATCH_547-547.md). | High / Shadow / 80%, 10m cooldown; **SOURCE CANDIDATE — UNVERIFIED**, 19 xUnit methods / 25 invocations authored, 0 executed; requires visible IPv4 UDP producer. No authenticated identity, server reply, vulnerable asset or exploit claim. |

**Threat research:** MITRE ATT&CK ICS [T0846](https://attack.mitre.org/techniques/T0846/) and [DET0739](https://attack.mitre.org/detectionstrategies/DET0739/) updated 2026-10-13 emphasize operational-fidelity and approved-asset context. CISA KEV retrieval returned HTTP 403; no candidate-specific exploitation or EPSS score asserted. Cross-boundary Who-Is can be legitimate BBMD/foreign-device routing, commissioning or inventory. **Next proposed cursor R548** subject to live registry/producer review. Historical P inventory and protocol ledger remain immutable.

## GA R548 — public-to-private Modbus write-request fanout

| P research / overlap | Evidence-backed disposition | Caveats / policy |
| --- | --- | --- |
| **P0038 Modbus**, **P0039 Modbus/TCP** (same protocol family); R240 single write request, R476 coil-write burst, R223 internal-to-external OT | **R548 authored:** one public IPv4 source sends bounded parser-classified `modbus.write` TCP/502 requests to **three distinct RFC1918 destinations** within 5m; source-keyed, unique-ID, monotonic bounded window. [GA R548](../RULE_BATCH_548-548.md). | Critical / Candidate / **Shadow / 90%**; 10m cooldown; **19 xUnit methods / 25 invocations authored, 0 executed**. Conditional on real PacketHandler TCP payload capture; no authentication, PLC write result, register values, approved asset role or CVE inference. |

**Threat research (2026-11-01):** Modbus Organization [V1.1b3, 2012-04-26](https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf); MITRE ICS [T0836](https://attack.mitre.org/techniques/T0836/) and [DET0776](https://attack.mitre.org/detectionstrategies/DET0776/) last modified 2026-10-13 require authorized source and operational change evidence before alerting. CISA KEV JSON retrieval HTTP 403; no R548-specific exploitation evidence or FIRST EPSS score asserted. No change to protocol research or UI ledgers. **Next proposed R549**, subject to live source and registry reconciliation.

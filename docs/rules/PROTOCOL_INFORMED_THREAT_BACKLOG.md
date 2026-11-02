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


## GA R549 — known-default HTTP Basic attempts across private subnets

| Research mapping and overlap | New source-backed disposition | Limits and policy |
| --- | --- | --- |
| **P0001/P0002/P0003** are adjacent *web-edge visibility* research, **not HTTP/1.1 decoder IDs**; original inventory has no distinct HTTP/1.1 row. R118 default IoT credential, R133 cleartext Basic, R237 IoT admin route, R130/R169 login bursts | **R549 authored:** three *different RFC1918 /24 destination networks* receive complete, parser-confirmed known-default Basic GET/POST requests to anchored admin routes from one RFC1918 source within 5m. Existing PacketHandler/HttpLight `HttpBasicDefaultCredentialObserved` internal-set flag; no independent inspector. [GA R549](../RULE_BATCH_549-549.md). | **High / Candidate / Shadow / 88% / 5m / 10m**; **20 xUnit methods / 26 invocations authored, 0 executed**. Requires visible early cleartext HTTP headers and coherent packet fields; no authenticated login or device outcome. Authorized provisioning/scanners and NAT can look similar. |

**Threat research (2026-11-02):** MITRE [T1078.001](https://attack.mitre.org/techniques/T1078/001/) and [DET0465](https://attack.mitre.org/detectionstrategies/DET0465/) modified 2026-05-12; [CISA Secure by Demand OT guidance](https://www.cisa.gov/sites/default/files/2025-01/joint-guide-secure-by-demand-priority-considerations-for-ot-owners-and-operators-508c.pdf) dated 2025-01-13. CISA KEV fetch returned 403; no CVE-specific exploitation or EPSS score is claimed. Historical P inventory and protocol ledger unchanged. **Next proposed cursor R550** subject to live audit.

## GA R550 — cross-boundary BACnet Who-Is / reverse I-Am-shaped correlation

| Research mapping / overlap | New evidence-backed decision | Limits / policy |
| --- | --- | --- |
| **P0046 BACnet**, related **P0382 BVLC**; R241 discovery bursts, R545 inbound I-Am, R547 inbound Who-Is fanout | **R550 authored**: the existing bounded UDP producer must classify a public-to-private Who-Is-shaped datagram followed within 60s by a private-to-same-public I-Am-shaped datagram, for **two distinct private targets within 5m**. This is a two-direction pair correlation rather than another one-way fanout. [GA R550](../RULE_BATCH_550-550.md). | High / Candidate / **Shadow / 86%**; 10m cooldown; **20 xUnit methods / 28 invocations authored, 0 executed**. Requires both capture directions, strict IPv4/UDP/47808 and unique packet IDs. Classifier does not validate full I-Am parameters, authenticated identity, authorization or exploit outcomes. Legitimate BBMD, foreign-device and commissioning flows are lookalikes. |

**Threat refresh (2026-11-02):** [ASHRAE BACnet Who-Is/I-Am Addendum bx, 2024-09-30](https://bacnet.org/wp-content/uploads/sites/4/2024/10/135_2020_bx_20240930.pdf); [MITRE ICS T0846](https://attack.mitre.org/techniques/T0846/) modified **2026-10-13**; [Siemens SSA-781903](https://cert-portal.siemens.com/productcert/html/ssa-781903.html) published **2026-08-11**, a malformed-packet DoS advisory **not detectable by R550**. No R550-specific confirmed exploitation or FIRST EPSS score asserted.

**Rejected for this GA:** An MQTT retained-control multi-broker correlation is **BLOCKED** pending an attested capture-origin flag or equivalent trusted producer boundary: existing `MqttPublishTopicObserved`, `MqttRetain` and `MqttControlTopicObserved` are publicly settable on `TrafficRecord` and imported records can impersonate parsed MQTT semantics. The original P0135 is **MQTT-SN**, not MQTT 3.1.1, and must not be misused as a mapping. DTLS appliance exploitation, encrypted HTTP/2/HTTP/3 outcomes and authenticated Windows lateral movement remain separately blocked by their missing sensors.

**Next proposed cursor: R551** only after a fresh live audit; historical protocol GAs and UI ledger remain unchanged. **SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED.**

## GA R551 — external BACnet discovery followed by Modbus write-request pairs

| P research and overlap | Source-defined decision | Evidence limits / policy |
| --- | --- | --- |
| **P0046 BACnet / P0382 BVLC**, **P0038 Modbus / P0039 Modbus-TCP**; R241/R545/R547/R550 BACnet discovery and R240/R476/R548 Modbus write | **R551 authored:** same public IPv4 source sends bounded BACnet Who-Is request and then, within **120 s**, a bounded Modbus write request to the **same RFC1918 target**; **two distinct targets** complete within **5 min**. Cross-protocol ordered pairs are not covered by either individual protocol fanout. [GA R551](../RULE_BATCH_551-551.md). | High / Candidate / **Shadow / 90%**; 10m cooldown, bounded per-source target/packet state, unique IDs and monotonic time. **22 xUnit methods / 28 invocations authored; 0 executed**. Requires two visible cleartext protocol producer paths; does not establish authenticated source, accepted write, device state or CVE exploitation. Legitimate multi-protocol gateways/commissioning and NAT are lookalikes. |

**Threat research (2026-11-02):** [ASHRAE BACnet Addendum bx, 2024-09-30](https://bacnet.org/wp-content/uploads/sites/4/2024/10/135_2020_bx_20240930.pdf), [Modbus application protocol V1.1b3, 2012-04-26](https://www.modbus.org/modbus-specifications), [MITRE ICS T0846](https://attack.mitre.org/techniques/T0846/) and [T0836](https://attack.mitre.org/techniques/T0836/) last modified 2026-10-13. CISA KEV web access returned 403, and no candidate-specific exploited CVE or EPSS score was established; **UNVERIFIED**. The packet classifier is shallow and `TrafficRecord.ApplicationProtocol` is publicly settable; a trusted capture-origin/asset-role gate is still required before operational alert promotion. The historical 500-entry research and protocol ledger are unchanged.

**Next proposed cursor: R552**, only after live registry and producer reconciliation. **SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED.**

## GA R552 — public-to-private NTP mode-7 monlist scanning across private subnets

| P research / existing coverage | New source-defined decision | Limits / policy |
| --- | --- | --- |
| **P0051 NTP** (partial existing bounded classifier); R242 same-pair monlist bursts, R546 private-to-public monlist target fanout | **R552 authored:** a single **public unicast IPv4 source** sends parser-classified mode-7 MON_GETLIST_1-shaped UDP/123 requests to **three distinct RFC1918 destination /24s** within five minutes; unique packet IDs, coherent IPv4/UDP, source port >=1024, bounded payload, monotonic window. [GA R552](../RULE_BATCH_552-552.md). | Medium / Candidate / **Shadow / 84%** / 5m / 10m; **21 xUnit methods / 28 invocations authored, 0 executed**. Conditional on actual inbound IPv4 UDP packet capture; source addresses may be spoofed, NAT may obscure topology, and no response, affected version, authorization or amplification is established. Legitimate scanners and managed-service probes can look similar. |

**Threat refresh (2026-11-02):** [NTP Project BUG 1532](https://www.ntp.org/support/securitynotice/ntpbug1532/) updated **2026-09-03** documents **historical 2013 exploitation** of CVE-2013-5211 against vulnerable pre-4.2.7p26 `ntpd`, not evidence of a current R552-detectable exploit. [Cisco advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-CVE-2013-5211) first published **2014-01-09**; [MITRE T1595](https://attack.mitre.org/techniques/T1595/) last modified **2025-10-24**. No candidate-specific current CISA KEV evidence or FIRST EPSS score claimed. The packet parser provides only a mode-7 request shape; `TrafficRecord.ApplicationProtocol` and UDP source are not cryptographically authenticated. Preserve Shadow until trusted sensor origin and environment-specific exclusions are independently validated.

**Next proposed cursor R553**, subject to live registry and producer audit; do not add P0501 or new isolated protocol inspectors. **SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED.**

## GA R553 — internal cross-subnet SMB2 WRITE request fanout

| P research / existing overlap | New source-defined decision | Reachability, false positives and policy |
| --- | --- | --- |
| **P0006 SMB** (source audit: partial SMB2 WRITE framing, not full session parsing); **P0113 SMB named pipes excluded** because pipe identity is not parsed. R076/R078 generic SMB admin/lateral indicators; R249 external SMB2 WRITE; R333/R334 SMB enumeration | **R553 authored:** one RFC1918 IPv4 source sends PacketHandler-classified **SMB2 WRITE request shapes** on TCP/445 to **three different remote RFC1918 /24s** within five minutes; packet IDs unique, coherent first-segment metadata, monotonic window. [GA R553](../RULE_BATCH_553-553.md). | **High / Candidate / Shadow / 88% / 5m / 10m**, **20 xUnit methods / 27 concrete invocations authored, 0 executed**. Requires visible, unencrypted first-segment SMB2 WRITE framing. Approved backups, software distribution, roaming profiles and replication are lookalikes. No ADMIN$/C$ path, authenticated account, successful write, file content, remote execution, ransomware or CVE exploitation is inferred. |

**Threat research (2026-11-02):** MITRE [T1021.002](https://attack.mitre.org/techniques/T1021/002/) and [DET0530](https://attack.mitre.org/detectionstrategies/DET0530/) last modified **2026-05-12**; DET0530 explicitly needs share/logon/process outcomes that this packet-only rule does **not** provide. Microsoft [SMB signing and encryption guidance](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview) confirms encrypted SMB payloads are not available to a passive parser. Microsoft [event 5145 documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5145) describes an optional future host-side access evidence source, not a current R553 producer. [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) access returned HTTP 403 and no R553-specific exploitation evidence was established; [FIRST EPSS](https://www.first.org/epss/) is a CVE risk estimate and no score is assigned to this behavioral predicate. Threat classification **UNVERIFIED**, not a zero-day exploit detector.

**Next proposed cursor R554**, subject to live registry, overlap and producer review. Do not add a speculative SMB named-pipe or authenticated admin-share outcome rule without a trusted producer. Historical protocol GAs and UI ledger remain unchanged. **SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED.**


## GA R554 — internal SMB2 WRITE request fanout followed by public FTP upload command

| P research / existing rule overlap | Source-defined decision | Evidence reachability and caveats |
| --- | --- | --- |
| **P0006 SMB** partial bounded SMB2 WRITE framing; FTP STOR/APPE is an existing PacketHandler/R248 producer (no invented FTP P ID). R553 counts three private SMB target subnets; R248 sees a single external FTP upload command; R256 internal HTTP staging and R257 credential-process HTTP upload do not express this ordered chain. | **R554 authored:** one RFC1918 source emits two SMB2 WRITE request shapes to distinct other RFC1918 /24s and then a parser-classified FTP STOR/APPE control request to public IPv4 within 120 seconds of both, all within five minutes. [GA R554](../RULE_BATCH_554-554.md). | **High / Candidate / Shadow / 88% / 2 subnets / 5m / 120s sequence / 10m cooldown**; 23 xUnit methods / 29 concrete invocations authored, **0 executed**. CONDITIONAL on visible first TCP segments; no authenticated share, file staging, successful FTP transfer, data exfiltration or exploit claim. Authorized backup/patch/legacy FTP can look similar. |

**Threat refresh (2026-11-02):** [RFC 959](https://www.rfc-editor.org/info/rfc959/) (1985-10) defines STOR/APPE request semantics; [MITRE T1048.003](https://attack.mitre.org/techniques/T1048/003/) last modified **2026-09-03** describes FTP exfiltration as a possible behavior but requires corroboration beyond packet requests. [MITRE T1021.002](https://attack.mitre.org/techniques/T1021/002/) last modified **2026-05-12** does not justify claiming admin-share access. No candidate-specific CISA KEV exploitation or FIRST EPSS score established; classification **UNVERIFIED**. All evidence is redacted, state bounded and duplicate-resistant. R102/R118/R163 floors, frozen holdouts, shared telemetry, UI and historical protocol ledger unchanged. **Next proposed cursor R555** after live audit. **SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED.**

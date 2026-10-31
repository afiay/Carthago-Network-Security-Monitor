# Carthago protocol intelligence — GA P0071–P0080

**Status:** SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; **0 EXECUTED**.  
**Branch:** `feature/carthago-reliability-hardening` only.  
**Source base (live HEAD at reconciliation):** `984c9bbea00f68d7dc2f6b8b5f0d163880ddcba4` (2026-10-31).  
**Publication:** atomic expected-HEAD-protected branch update; obtain publication commit SHA from branch history (a commit cannot embed its own hash).  
**Research inventory:** owner's immutable 2026-10-30 CSV, original P0071–P0080 IDs. No P ID is an RNNN detection rule.  
**Previous:** [GA P0061–P0070](PROTOCOL_GA_P0061-P0070.md). **Next:** **GA P0081–P0090**.

## Exactly ten inventory dispositions

| P ID / original label | Disposition | Producer and reachability | Falsifiable value, evidence and benign alternative |
| --- | --- | --- | --- |
| P0071 `geneve` — Generic Network Virtualization Encapsulation | **IMPLEMENTED_ISOLATED** | New [GeneveDatagramInspector](../../Carthago/Services/ProtocolIntelligence/GeneveDatagramInspector.cs) handles caller-attested complete UDP/6081 data envelopes, Ethernet payload and noncritical options only; no live capture registration. | VNI and option count could support an overlay-policy review only with authenticated hypervisor/VTEP inventory, expected VNI, tunnel endpoint identity and forwarding outcomes. Authorized tenant migration and virtualization overlays are benign. |
| P0072 `gtp` — GPRS Tunneling Protocol | **DEFERRED** | No verified GTP-U/GTP-C versioned boundary, mobile-core sensor or trusted subscriber/session producer. | Unauthorized tunnel/session activity requires authenticated core-plane TEID/session, peer and GTP version; roaming and handover are benign. Port 2152 alone is not evidence. |
| P0073 `gtpv2` — GPRS Tunneling Protocol V2 | **REJECTED_DUPLICATE_OR_NOT_A_PROTOCOL** for *separate backlog distinct-protocol count* | Genuine version-specific GTPv2-C wire format, but same GTP family already counted at P0072; no parser is claimed. | Keep version-specific message/framing requirements in GTP parent research; do not erase its distinct wire format or silently inflate protocol count. |
| P0074 `ppp` — Point-to-Point Protocol | **BLOCKED — INPUT ADAPTER** | PPP framing and link-type/PPP-over-tunnel boundaries are not established by the current IP Ethernet fast path. | LCP/PAP/CHAP abuse needs authenticated access server, negotiated protocol and AAA outcome; authorized remote access is benign. |
| P0075 `pppoe` — PPP over Ethernet | **BLOCKED — SHARED L2 INTEGRATION** | EtherTypes 0x8863/0x8864 dropped before IP parsing. | Rogue access concentrator requires trusted Ethernet capture, AC/session context and AAA evidence; subscriber reconnect is benign. |
| P0076 `vlan` — IEEE 802.1Q | **EXISTING** | [PacketHandler](../../Carthago/Services/PacketHandler.cs) already recognizes and strips bounded 802.1Q/802.1ad tags, depth ≤8, before L3. No new decoder. | VLAN-hopping hypothesis needs original tagged frame provenance, switch port policy and MAC table evidence; legitimate trunk tagging is benign. |
| P0077 `mpls` — MPLS label stack | **BLOCKED — SHARED L2 INTEGRATION** | No approved EtherType 0x8847/0x8848 or link-layer MPLS input adapter, label-stack evidence or trustworthy IP payload handoff. | Unauthorized label switching needs provider router control plane, expected labels, ingress interface and forwarding outcome; label changes are often normal. |
| P0078 `cdp` — Cisco Discovery Protocol | **BLOCKED — SHARED L2/LLC INTEGRATION** | No SNAP/LLC adapter to deliver CDP frames with physical interface provenance. | Rogue neighbor or topology drift needs trusted interface identity, authenticated switch inventory and neighbor history; legitimate device replacement is benign. |
| P0079 `udld` — Unidirectional Link Detection | **BLOCKED — SHARED L2/LLC INTEGRATION** | No LLC/SNAP UDLD producer or reliable link-state correlation. | Link manipulation requires interface/link state and authenticated device logs; cable faults are benign. |
| P0080 `hsrp` — Cisco Hot Standby Router Protocol | **IMPLEMENTED_ISOLATED** | New [HsrpV1MessageInspector](../../Carthago/Services/ProtocolIntelligence/HsrpV1MessageInspector.cs) recognizes only RFC 2281 version-0 20-byte UDP/1985 envelopes with caller-attested IPv4 TTL=1 multicast 224.0.0.2; no live producer. | Unexpected group/state/priority could support rogue-gateway triage with trusted router inventory, authenticated neighbor/AAA logs and actual forwarding state; maintenance/failover are benign. |

**Totals:** 2 IMPLEMENTED_ISOLATED; 1 EXISTING; 0 PARTIAL; 1 DEFERRED; 5 BLOCKED; 1 REJECTED; **0 live integrated**.

## Source-first divergence and limits

The live source base was checked against the previous protocol publication `98a680fd304af2e093c209b3c7eae3f726aa57bb`: two intervening commits changed only `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. The detection ledger was read-only. Existing `ProtocolIntelligence/**` includes GRE and VXLAN but not Geneve or HSRP. The .NET 8 SDK-style project auto-includes owned C# files; no project, package, shared capture, record, UI, rule or journal changes are needed for isolated compilation.

Reviewed [PacketHandler](../../Carthago/Services/PacketHandler.cs), [TrafficCaptureService](../../Carthago/Services/TrafficCaptureService.cs), [TrafficRecord](../../Carthago/Models/TrafficRecord.cs), [PortServiceResolver](../../Carthago/Services/PortServiceResolver.cs), `OtProtocolLight.cs`, `NetworkBatch226230Wire.cs`, `NetworkBatch231235Wire.cs`, `NetworkBatch246250Wire.cs`, optional Windows/ETW/Cisco sources, rule contracts, and prior protocol inspectors. Current Ethernet non-IP frames are discarded; UDP bytes lack an explicit trusted complete-payload/outer-envelope contract for these new inspectors. Port/service labels cannot substitute for parsing. No new source class is called by the production pipeline. Both are **ISOLATED — NOT LIVE-CAPTURE INTEGRATED**.

**Geneve bounds:** caller-attested UDP destination 6081, 42–65,535-byte complete datagram, version 0, 0–252 option bytes, 4-byte aligned options with bounded deterministic walk, noncritical options only, data (not OAM) packets, protocol type 0x6558 (transparent Ethernet), single optional VLAN, IPv4/IPv6/ARP envelope shape. Unknown critical options and C/O flags fail closed because no option registry or control-plane producer is trusted. No decapsulation, checksum/outer IPv6 zero-checksum validation, tunnel authorization, tenant identity assertion, inner IP/MAC retention, fragmentation state or retransmission inference. Unknown extensions and nested VLAN are unsupported.

**HSRP bounds:** exactly 20 bytes, version field 0 (RFC 2281 HSRP v1), opcode Hello/Coup/Resign, six defined state values, reserved byte zero, Hello holdtime strictly greater than hellotime. Caller must independently attest complete UDP payload, destination port 1985, IPv4 multicast 224.0.0.2 and TTL=1. No parsing of HSRPv2, no authentication check (RFC 2281's eight cleartext authentication bytes), no virtual-IP retention, no peer/session/election state and no claim of router compromise. No sensitive bytes are returned by either inspector. Both are stateless and allocate no unbounded memory.

## Threat refresh — source-grounded, not protocol-presence CVE detection

- **CONFIRMED_EXPLOITED_KNOWN_VULNERABILITY (related tunnel environment, not a Geneve or HSRP exploit):** Arista EOS CVE-2026-7473, [Security Advisory 0137](https://www.arista.com/en/support/advisories-notices/security-advisory/24005-security-advisory-0137), originally 2026-05-05, revision 2026-08-10. The vendor reports exploitation and describes unexpected GRE/VXLAN/GUE/IP-in-IP decapsulation on specifically configured affected EOS platforms; requires configured decapsulation IP and affected device family/version. CISA [KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) added it 2026-06-09. **Neither new inspector detects this CVE**. Its tunnel-type conditions are not interchangeable with Geneve. Relevant IOCs are anomalous internal forwarding and authenticated ACL counters, not an isolated UDP signature.
- **UNVERIFIED for P0071/P0080 exploitation:** No direct, version-specific, primary-source exploited zero-day advisory established for Geneve or HSRP in this refresh. Cisco's [2026-09-30 SD-WAN Manager API advisory CVE-2026-76504](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-webauth-xr8beuuU.html) concerns HTTP API session authorization, **not HSRP**. Do not cross-label.
- [FIRST EPSS](https://www.first.org/epss/) is a probabilistic risk forecast, not evidence of exploitation. Its live API numeric value could not be independently retrieved in this run; no score or percentile is asserted.
- No vendor-device version, affected configuration, endpoint/ACL outcome or forensic IOC is observable from these isolated parsers. All network-only vulnerability assertions remain **NOT OBSERVABLE**.

## Authored source and scenarios — none executed

| File | Source Git blob SHA | Authored xUnit methods | Concrete invocations |
| --- | --- | ---: | ---: |
| [Geneve inspector](../../Carthago/Services/ProtocolIntelligence/GeneveDatagramInspector.cs) | `27fedb6db0729ad13227308a9c7a8e509151fab7` | — | — |
| [HSRP inspector](../../Carthago/Services/ProtocolIntelligence/HsrpV1MessageInspector.cs) | `615acf177918cf3446b189ffff80bc08e9e0d063` | — | — |
| [Geneve tests](../../Carthago.Tests/ProtocolIntelligence/GeneveDatagramInspectorTests.cs) | `e8545b893e91fe9af48774f19f551793fc77b8c3` | 18 | 20 |
| [HSRP tests](../../Carthago.Tests/ProtocolIntelligence/HsrpV1MessageInspectorTests.cs) | `d1f424eb74294fe934faf2ee1fd0fab7d1e47464` | 15 | 21 |
| **Total authored** | | **33** | **41** |

Geneve scenarios: three VNIs, noncritical option, VLAN, cross-port and untrusted-boundary negatives, unknown versions, control/critical options, option overrun, malformed/truncated/oversized, inner-protocol and length discrimination, nested VLAN rejection, repeated/out-of-order/concurrent statelessness, sensitive-field omission. HSRP scenarios: six valid states, Coup/Resign, cross-port and untrusted envelope negatives, HSRPv2 exclusion, invalid opcode/state/reserved, timer invariants, truncation/overlength, reordered and concurrent calls, cleartext-authentication and virtual-IP redaction.

**Builds: 0. Tests executed: 0. CI/replay/holdout/runner: 0.** Authored assertions are not pass evidence. All candidates are unverified.

## Coordination-only integration proposal and rollback

Do **not** publish this proposal as runtime code without explicit owner approval. Minimal future shared patch: add a trusted, opt-in UDP payload-envelope producer at `Carthago/Services/PacketHandler.cs` / `TrafficCaptureService.cs` that proves complete UDP length, IP fragmentation status, destination port and, for HSRP, IPv4 TTL and multicast destination. Publish only privacy-safe typed observations through an explicitly reviewed additive `TrafficRecord` compatibility extension or isolated journal-independent consumer. Verify producer authenticity, duplicate/reordering, IPv4/IPv6 checksum and capture truncation behavior, source-of-truth journaling, existing RNNN contracts, false positives and rollback. For PPP/PPPoE/MPLS/CDP/UDLD, design a separate explicit L2/LLC input adapter with interface/link-type provenance; no port-based substitute.

**Rollback:** remove only new protocol-owned parser/test registration and any approved additive observation fields in a separately reviewed integration GA, leaving existing capture, journal, detection and UI untouched. Existing R102/R118/R163 floors, Shadow/Disabled, cooldowns, privacy, baseline readiness and frozen holdouts are unchanged.

**Next exact ten:** **P0081–P0090**, only after publication confirmation and fresh live-HEAD recovery.

## Specifications

- [RFC 8926 — Geneve](https://www.rfc-editor.org/rfc/rfc8926.html), November 2020.
- [RFC 2281 — HSRP](https://www.rfc-editor.org/rfc/rfc2281.html), March 1998 (informational; describes version field 0).
- [IANA port registry](https://www.iana.org/assignments/service-names-port-numbers/).
- [Arista Security Advisory 0137](https://www.arista.com/en/support/advisories-notices/security-advisory/24005-security-advisory-0137).

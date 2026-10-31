# Carthago protocol intelligence — GA P0081–P0090

**Status:** SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; **0 EXECUTED**.  
**Branch:** `feature/carthago-reliability-hardening` only.  
**Live source base:** `59cbc728164559c05659edfdccc04d7ab2d54707` (2026-10-31).  
**Publication:** one expected-HEAD-protected atomic branch update; publication commit cannot self-reference its SHA.  
**Inventory:** immutable owner's 2026-10-30 Library CSV, original P0081–P0090; P IDs are research row IDs, not RNNN rules.  
**Previous:** [GA P0071–P0080](PROTOCOL_GA_P0071-P0080.md). **Next:** **GA P0091–P0100**.

## Exactly ten inventory decisions

| ID / original Wireshark key | Disposition | Existing source reachability and trusted fields | Falsifiable security value, benign alternative and limitation |
| --- | --- | --- | --- |
| P0081 `vrrp` — Virtual Router Redundancy Protocol | **DEFERRED** | VRRPv3 IPv4/IPv6 uses IP protocol 112, TTL/hop limit 255 and link-local multicast; current [PacketHandler](../../Carthago/Services/PacketHandler.cs) has no trusted protocol-112 payload producer. No new parser. | Unexpected VRID/priority advertisements could suggest gateway impersonation only with authenticated router/interface inventory, complete IP112 payload and routing outcome; routine failover is benign. |
| P0082 `glbp` — Gateway Load Balancing Protocol | **DEFERRED** | No GLBP-specific complete UDP framing or authenticated Cisco router/forwarding source established; port names alone do not decode it. | Gateway membership changes need device configuration, peer identities and forwarding-state outcomes; maintenance is benign. |
| P0083 `batadv` — B.A.T.M.A.N. Advanced | **BLOCKED — SHARED L2 INPUT** | Native Ethernet mesh frames lack a trusted non-IP EtherType/ingress-interface adapter; current fast path discards non-IP EtherTypes. | Mesh topology manipulation needs L2 interface/neighbor and bridge evidence; mobility is benign. |
| P0084 `stun` — STUN | **IMPLEMENTED_ISOLATED** | New [StunBindingMessageInspector](../../Carthago/Services/ProtocolIntelligence/StunBindingMessageInspector.cs) recognizes bounded RFC 8489 Binding UDP envelopes, caller-attested complete payload, method/class and TLV shape; no live registration. | Unexpected STUN destinations or repeated Binding requests require trusted endpoint/app identity, ICE policy and connection outcomes; legitimate WebRTC/VoIP is common. No NAT, auth, fingerprint or session validation. |
| P0085 `radius` — RADIUS | **IMPLEMENTED_ISOLATED** | New [RadiusPacketInspector](../../Carthago/Services/ProtocolIntelligence/RadiusPacketInspector.cs) recognizes strict complete UDP/1812 authentication and UDP/1813 accounting envelopes, bounded attribute TLVs and Message-Authenticator attribute *presence*; no live registration. | Anomalous Access-Accept/Reject patterns require authenticated AAA logs, verified response authenticators, NAS identity, configuration and actual access outcomes; authorized reauthentication is benign. Code presence is not authentication or CVE proof. |
| P0086 `tacacs` — legacy TACACS | **DEFERRED** | No authenticated legacy TACACS deployment, wire-version boundary or capture source established. Do not conflate legacy TACACS with TACACS+. | Privileged access anomalies need verified AAA outcomes; normal admin sessions are benign. |
| P0087 `tacplus` — TACACS+ | **DEFERRED** | RFC 8907 TCP/49 requires complete 12-byte header and body boundaries plus endpoint authentication; current TCP early bytes are not trusted message reassembly. No deobfuscation or parser claim. | Unauthorized command authorization needs trusted TACACS+ server logs, user/device and outcome; normal administration is benign. |
| P0088 `krb5rpc` — DCE/RPC Kerberos V | **REJECTED_DUPLICATE_OR_NOT_A_PROTOCOL** for separate protocol count | DCE/RPC authentication subdissector/variant, not a new independent transport protocol; existing isolated [DCE/RPC v5 inspector](../../Carthago/Services/ProtocolIntelligence/DceRpcPduInspector.cs) must not be equated with authenticated Kerberos decoding. | Kerberos-authenticated RPC misuse requires endpoint/Windows event provenance and verified security context, not RPC header presence. |
| P0089 `eap` — Extensible Authentication Protocol | **BLOCKED — SHARED INPUT/AAA INTEGRATION** | EAPOL L2 frames are dropped; RADIUS EAP-Message attribute encapsulation has no trusted producer or reassembly. No standalone EAP authentication-result inference. | Unauthorized EAP success requires 802.1X supplicant/authenticator, AAA logs, EAP method and verified outcome; routine roaming is benign. |
| P0090 `bhttp` — Binary HTTP Message Representation | **REJECTED_DUPLICATE_OR_NOT_A_PROTOCOL** for separate wire-protocol count | RFC 9292 defines an HTTP message representation, not a separately reachable network transport; no trusted plaintext application boundary. | Abuse is application/proxy-context dependent; encrypted HTTP contents are NOT OBSERVABLE in passive ciphertext. |

**Totals:** 2 IMPLEMENTED_ISOLATED; 0 EXISTING; 0 PARTIAL; 4 DEFERRED; 2 BLOCKED; 2 REJECTED; **0 live integrated**.

## Source-first divergence and security invariants

At source base `59cbc728164559c05659edfdccc04d7ab2d54707`, reviewed [PacketHandler](../../Carthago/Services/PacketHandler.cs), [TrafficCaptureService](../../Carthago/Services/TrafficCaptureService.cs), [TrafficRecord](../../Carthago/Models/TrafficRecord.cs), [OtProtocolLight](../../Carthago/Services/OtProtocolLight.cs), NetworkBatch226230Wire/231235Wire/246250Wire, [PortServiceResolver](../../Carthago/Services/PortServiceResolver.cs), optional ETW/Windows/Cisco Syslog/SNMP adapters, [rule documentation standard](../rules/RULE_DOCUMENTATION_STANDARD.md), detection ledger and UI ledger (read-only), prior protocol GA and inspectors. SDK-style .NET 8 projects auto-include new C# source in protocol-owned folders. Existing L2 non-IP frames and IP protocol 112 are not passed to an attested protocol inspector; UDP payload bytes exist but no complete-payload provenance contract is registered for these new inspectors. TCP inspection is an early bounded window, not general reassembly. No new parser is called by the runtime.

**STUN bounds:** complete caller-attested UDP message, 20–2048 bytes, Binding method only, 0x2112A442 magic cookie, exact aligned attribute length, at most 64 TLVs, strict known integrity/fingerprint attribute sizes, fingerprint must be final. UDP port intentionally not a discriminator because ICE can use negotiated ports. Does not verify HMAC, CRC, transaction matching, NAT mapping, TURN, ICE consent, credential or address. Unknown methods/extensions, concatenated frames and oversized messages are unsupported; valid non-Binding STUN is not classified. Sensitive TLV values and 96-bit transaction IDs never leave the inspector.

**RADIUS bounds:** complete caller-attested UDP/1812 or /1813 datagram, 20–4096 bytes, codes 1/2/3/11 (auth) and 4/5 (accounting), exact declared length, at most 128 TLVs, reject malformed or duplicated type-80 Message-Authenticator. This intentionally excludes RFC-permitted trailing UDP padding, legacy ports, RADIUS over TLS/DTLS, CoA and unknown codes. No shared secret, Response Authenticator, HMAC, credential, authorization outcome, NAS or user identity verification; raw authenticators and attribute values never leave the inspector. Attribute presence cannot establish BlastRADIUS mitigation or actual login.

Neither class has state, I/O, alerts, journals, UI writes, direct sinks or network actions. No RNNN definitions, confidence floors (R102/R118/R163), Shadow/Disabled, cooldowns, baseline readiness, suppression, privacy or frozen holdouts changed. Both remain **ISOLATED — NOT LIVE-CAPTURE INTEGRATED**.

## Threat refresh — first-party evidence, 2026-10-31

- **VENDOR_ADVISORY_NO_EXPLOIT_EVIDENCE:** Cisco ISE RADIUS DoS **CVE-2026-20352**, [Cisco advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-RADIUS-dos-wR3hYPMw), first published **2026-09-16**. Cisco reports *no known public malicious use*. Requires an affected Cisco ISE Policy Service Node with RADIUS service enabled (enabled by default); affected ISE 3.2/3.3/3.4/3.5 release trains, fixed in 3.2 Patch 11, 3.3 Patch 12, 3.4 Patch 7, 3.5 Patch 4 respectively; 3.1 and earlier listed not vulnerable. A crafted RADIUS request may cause service unavailability. The vendor supplies no universal packet IOC. Our inspector cannot infer device version, exploit payload, service availability or successful DoS.
- **VENDOR_ADVISORY_NO_EXPLOIT_EVIDENCE:** RADIUS protocol forgery **CVE-2024-3596** (BlastRADIUS), [Siemens ProductCERT SSA-723487](https://cert-portal.siemens.com/productcert/html/ssa-723487.html) published **2024-07-09**, updated **2026-06-09**, and [SSA-794185](https://cert-portal.siemens.com/productcert/html/ssa-794185.html) updated **2026-10-13**. On-path attacker and affected RADIUS client/server configurations are prerequisites; affected device families and fixed releases depend on the vendor product advisory. Lack of a valid Message-Authenticator and vulnerable MD5 response authentication are relevant but **cannot be confirmed from a passive presence-only attribute inspector**. No wild exploitation claim is established by these advisories.
- **UNVERIFIED** for STUN Binding, VRRP, GLBP, legacy TACACS, TACACS+, EAP, B.A.T.M.A.N. and bHTTP: no item-specific, current, first-party exploited-zero-day evidence established in this refresh; this is not proof that vulnerabilities do not exist.
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) was considered for exploitation corroboration, and [FIRST EPSS](https://www.first.org/epss/) as a probabilistic risk model. No verified live EPSS numerical score is available; none is invented. A port, packet code or protocol presence never proves exploitation.

## Authored tests and exact Git object provenance

| Artifact | Source Git blob SHA | xUnit methods | Concrete invocations |
| --- | --- | ---: | ---: |
| [STUN inspector](../../Carthago/Services/ProtocolIntelligence/StunBindingMessageInspector.cs) | `b1e7538404779738374911d3ea78f8e28124f52b` | — | — |
| [RADIUS inspector](../../Carthago/Services/ProtocolIntelligence/RadiusPacketInspector.cs) | `d5d9b1be7aabe04e3d4f89aa439ecae2c6865a8a` | — | — |
| [STUN tests](../../Carthago.Tests/ProtocolIntelligence/StunBindingMessageInspectorTests.cs) | `117e8c9cad2707b77493bf78b98e6757d9a0548c` | 19 | 22 |
| [RADIUS tests](../../Carthago.Tests/ProtocolIntelligence/RadiusPacketInspectorTests.cs) | `8803ba1e9d38d566f625a51c44f8c57dcc7bb6c1` | 20 | 25 |
| **Total authored** | | **39** | **47** |

Five independent scenario classes per inspector: (1) valid message classes/codes and TLVs, (2) cross-protocol/transport and untrusted-boundary negatives, (3) truncated/overlong/malformed, length and attribute-count bounds, (4) deterministic out-of-order and concurrent stateless calls, (5) credential/transaction/authenticator redaction and fail-closed integrity/provenance boundaries. Synthetic fixtures are source-labelled and not real captures or exploits. **Builds 0; xUnit executed 0; replay 0; CI 0; runner 0; active scan 0.** Authored assertions are not passing evidence.

## Shared integration proposal — coordination required, NOT APPLIED

Under separate explicit owner approval and fresh cross-stream review, add a narrow, opt-in producer to [PacketHandler](../../Carthago/Services/PacketHandler.cs) / [TrafficCaptureService](../../Carthago/Services/TrafficCaptureService.cs) that attests complete unfragmented UDP payload and link-type provenance, then passes a bounded copy-free span to the STUN Binding and RADIUS inspectors. Preserve STUN dynamic-port classification only after full cookie/framing validation; RADIUS ports must be verified from the outer UDP header. Add a privacy-reviewed typed observation consumer only after schema compatibility review of [TrafficRecord](../../Carthago/Models/TrafficRecord.cs), never direct alerts or false journal events. For AAA outcomes require authenticated server/NAS logs and cryptographic verification; for EAP/mesh add separately approved L2/AAA input adapters; for VRRP add verified IP-112 input. Do not modify shared paths in this GA.

**Compatibility plan when testing is authorized:** Windows x64/ARM64 compilation, all 47 authored invocations, synthetic cross-protocol negatives, full/truncated/fragmented IPv4/IPv6 UDP captures, RADIUS padding and response-authentication boundaries, STUN ICE dynamic ports, benign load and out-of-order behavior, JSONL-first raw event immutability, existing RNNN policy and UI invariants. **Rollback:** remove only approved additive runtime wiring and observation registration, leaving protocol-owned isolated source and original journal/rules/UI intact.

**Next exact ten IDs:** **P0091–P0100**. Do not skip blocked entries or re-run completed GAs.

## Specifications

- [RFC 8489 — STUN](https://www.rfc-editor.org/rfc/rfc8489.html), February 2020.
- [RFC 2865 — RADIUS](https://www.rfc-editor.org/rfc/rfc2865.html), June 2000.
- [RFC 2866 — RADIUS Accounting](https://www.rfc-editor.org/rfc/rfc2866.html), June 2000.
- [RFC 3579 — RADIUS and EAP](https://www.rfc-editor.org/rfc/rfc3579.html), September 2003.
- [RFC 5798 — VRRPv3](https://www.rfc-editor.org/rfc/rfc5798.html), March 2010.
- [RFC 8907 — TACACS+](https://www.rfc-editor.org/rfc/rfc8907.html), September 2020.
- [RFC 9292 — Binary HTTP](https://www.rfc-editor.org/rfc/rfc9292.html), August 2022.
- [Cisco ISE CVE-2026-20352](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-RADIUS-dos-wR3hYPMw).
- [Siemens BlastRADIUS advisory](https://cert-portal.siemens.com/productcert/html/ssa-723487.html).

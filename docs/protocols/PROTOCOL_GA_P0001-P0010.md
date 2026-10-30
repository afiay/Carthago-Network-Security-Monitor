# Carthago protocol intelligence — GA P0001–P0010

**Status:** SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; **0 EXECUTED**  
**Branch:** `feature/carthago-reliability-hardening`  
**Source base SHA:** `7aa356429b674fab1975127f40f4fea6b312450b`; **source/test/documentation commit:** this cohesive commit; **publication SHA:** the branch ref after its single expected-HEAD update (a commit cannot contain its own SHA).  
**Inventory:** original P0001–P0010 rows of the owner-provided 2026-10-30 CSV; no substitution or rule registration.  
**GA 0:** [reconciliation](PROTOCOL_GA_0_RECONCILIATION.md).

## Ten-ID decision matrix

| P ID | Original key | Disposition | Observed baseline and exact gap | Trust, reachability and falsifiable security value |
| --- | --- | --- | --- | --- |
| P0001 | `http2` | **IMPLEMENTED_ISOLATED** | Existing ALPN `h2` is only a hint; added bounded one-frame inspector. | Only verified plaintext HTTP/2 frame boundary, not encrypted TLS or HPACK. Stream ID, type, flags and frame length may inform future proxy-abuse analytics; cannot prove request smuggling. No runtime producer. |
| P0002 | `http3` | **PARTIAL** | MsQuic ETW/QUIC ALPN metadata, not HTTP/3 frame or QPACK decoding. | Trusted proxy/endpoint HTTP/3 request and response logs required for method, status and routing. QUIC packet alone cannot establish application outcomes. No new decoder. |
| P0003 | `websocket` | **DEFERRED** | No verified WebSocket frame producer in reviewed packet path. | Require observed HTTP Upgrade/101 handshake or authenticated proxy evidence plus TCP stream reassembly; TLS ciphertext opaque. An isolated frame matcher without handshake would invite false positives. |
| P0004 | `grpc` | **DEFERRED** | No authenticated gRPC message producer; HTTP/2 metadata alone is insufficient. | Require verified HTTP/2 content-type and stream lifecycle or trusted service logs; do not infer RPC method/success from generic TCP. |
| P0005 | `dtls` | **IMPLEMENTED_ISOLATED** | Added bounded DTLS 1.0/1.2 record inspector; DTLS 1.3 compact ciphertext not decoded. | UDP datagram record header, epoch, sequence, count and first unencrypted handshake type only. Requires trusted Citrix asset/version/configuration and appliance logs for CVE-2026-88772 exposure or exploitation. No runtime producer. |
| P0006 | `smb` | **PARTIAL** | Existing `NetworkBatch246250Wire.Smb2Write` validates one bounded SMB2 write request. | Do not duplicate parser. Server-side write success, identity, dialect and share access need trusted SMB/Windows audit and state. |
| P0007 | `smb_direct` | **REJECTED_DUPLICATE_OR_NOT_A_PROTOCOL** | SMB Direct is SMB over RDMA transport, not a new independent SMB application decoder. | RDMA visibility requires a separate capture/source contract; no TCP port-only substitution. |
| P0008 | `smb_netlogon` | **REJECTED_DUPLICATE_OR_NOT_A_PROTOCOL** | Netlogon is an RPC service/protocol-family surface, not an independent SMB wire decoder to count here. | Authenticated DC/RPC audit and operation outcomes required; generic SMB traffic is not a Netlogon event. |
| P0009 | `ntlmssp` | **DEFERRED** | Authentication token format may appear inside SMB/HTTP/RPC; not a standalone SMB decoder. | Trusted protocol-specific auth context and Windows logon outcomes needed; avoid logging NTLM challenge/response secrets. |
| P0010 | `kerberos` | **DEFERRED** | No bounded Kerberos wire decoder in reviewed fast path; Windows Security reader is not equivalent. | DC event evidence (e.g. AS/TGS requests and actual outcomes) or trusted UDP/TCP 88 frame source required; never equate port 88 with a successful authentication. |

**Counts:** 2 implemented isolated, 2 partial/reused, 4 deferred, 2 rejected; **0 integrated**, **0 verified runtime**. No P IDs were registered as `RNNN` detection rules. No changes to detection or UI paths.

## Implementation and sensor boundaries

- [Http2FrameInspector](../../Carthago/Services/ProtocolIntelligence/Http2FrameInspector.cs): verifies the optional 24-byte client connection preface and the first complete nine-byte HTTP/2 frame header at a **caller-confirmed plaintext boundary**. Validates known frame types, stream IDs, SETTINGS/ACK, PING and size rules. Caps inspected frame payload at 16,384 bytes; larger valid negotiated frames are intentionally not classified. No HPACK, request headers, stream correlation or body parsing. A single frame observation cannot establish an attack.
- [DtlsRecordInspector](../../Carthago/Services/ProtocolIntelligence/DtlsRecordInspector.cs): bounded DTLS 1.0/1.2 datagram record framing, maximum 16 records and 18,432 bytes per record. Checks declared lengths and first unencrypted handshake fragment bounds. Only first record's sequence is returned, with no state or replay verdict. DTLS 1.3 compact encrypted record headers are **not supported**; epoch >0 and application data remain opaque.
- Both are deterministic, allocation-free on the success path, require no new dependencies, do not log sensitive bytes and never emit alerts, journal records or UI updates. They are **not wired** to `PacketHandler` or `TrafficRecord`, so they provide **no current live-capture coverage**.
- Shared integration is **BLOCKED — SHARED INTEGRATION** pending owner approval. Proposed minimal adapter: a provenance-tagged, bounded TCP plaintext frame-boundary source for HTTP/2 (prefer a trusted proxy endpoint; never treat TLS ALPN as plaintext); a datagram-boundary-preserving UDP source for DTLS with explicit source/asset context; typed optional observations with provenance and redaction, then dedicated compatibility/replay tests. Keep `PacketHandler.cs`, `TrafficRecord.cs`, `TrafficCaptureService.cs`, `Carthago.csproj` and journal unchanged until a separate approved integration GA. Rollback: remove adapter wiring and optional fields; retain isolated inspectors without affecting existing rule contracts.
- Potential false positives: accidental byte-shape collisions, HTTP/2 frame fragments/coalescence, DTLS replays, middlebox transforms and spoofed UDP. A parser-positive is **only a record/frame-shape observation**, never proof of a trusted server, successful login, exploit or malicious intent. A false negative is possible for fragmented HTTP/2 frames, negotiated larger frames, DTLS 1.3, malformed traffic and unobserved encrypted endpoints.

## Threat evidence and classification

**P0005 CVE-2026-88772 — CONFIRMED_EXPLOITED_ZERO_DAY:** CISA bulletin dated **2026-09-27** states the Citrix NetScaler CVE was exploited globally and added to KEV. Citrix CTX697096 confirms memory overflow/RCE or DoS, requiring DTLS enabled (default for VPN vServers), and fixed releases 14.1-73.37, 13.1-64.23, FIPS 14.1-73.37, FIPS/NDcPP 13.1.37.279 or later. Actual affected version, configuration, device identity, appliance errors and IOCs require trusted asset inventory and NetScaler Console/syslog; **no DTLS wire signature here detects the CVE**. A later vendor advisory may supersede a fixed build for a *different* CVE; always consult current Citrix advisories. [CISA](https://content.govdelivery.com/accounts/USDHSCISA/bulletins/42cc465) · [Citrix](https://support.citrix.com/external/article/CTX697096/citrix-netscaler-adc-and-citrix-netscaler-gateway-security-bulletin.html) · [KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

**P0001–P0004 and P0006–P0010 — UNVERIFIED for any candidate-specific exploited zero-day:** The examined sources do not substantiate an exploit signature from protocol presence. Citrix CVE-2026-88773 concerns an HTTP-enabled appliance configuration, not generic proof from an HTTP/2 frame. FIRST EPSS is a statistical risk estimate, not proof of exploitation; no numeric EPSS value was assumed. [Citrix](https://support.citrix.com/external/article/CTX697096/citrix-netscaler-adc-and-citrix-netscaler-gateway-security-bulletin.html) · [FIRST EPSS](https://www.first.org/epss/).

Protocol framing references: [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113) (HTTP/2), [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455) (WebSocket), [RFC 6347](https://www.rfc-editor.org/rfc/rfc6347) (DTLS 1.2), [RFC 9147](https://www.rfc-editor.org/rfc/rfc9147) (DTLS 1.3). No Wireshark source was copied.

## Authored, not executed, scenario evidence

| Inspector | Authored xUnit methods | Concrete authored invocations | Independent scenario coverage |
| --- | ---: | ---: | --- |
| [HTTP/2](../../Carthago.Tests/ProtocolIntelligence/Http2FrameInspectorTests.cs) | 8 | 10 | Positive preface/SETTINGS; benign HTTP/1 negative; truncated frame; overlong payload; missing trusted plaintext context and TLS-like bytes; coalesced first-frame accounting; invalid control-frame shape (3 inputs); reserved stream bit. |
| [DTLS](../../Carthago.Tests/ProtocolIntelligence/DtlsRecordInspectorTests.cs) | 9 | 10 | Positive DTLS 1.2 handshake header; benign DNS negative; truncation; forged length; encrypted epoch opacity; coalesced same-sequence records with no replay inference; 17-record resource bound; forged handshake fragment offset; unsupported versions (2 inputs). |
| **Total** | **17** | **20** | **0 executed**; no xUnit, build, CI, runner, capture or replay was run. |

Tests are source-authored, not a verified acceptance result. Fixtures contain no credentials or captured private traffic. The handshake-positive is a minimal framing fixture, not a full semantically valid ClientHello. A future Windows verification GA must compile, run and add realistic protocol fixtures, fragmented/retransmitted TCP cases, independent dissector corroboration, and source-attributed proxy/NetScaler log comparisons. These source candidates must not be promoted to operational detection claims before that evidence exists.

## Pre-publication safety review and next GA

Owned changes are restricted to `Carthago/Services/ProtocolIntelligence/**`, `Carthago.Tests/ProtocolIntelligence/**` and `docs/protocols/**`. No `RNNN`, `UI-NN`, `docs/RULE_HARDENING_PROGRESS.md`, `docs/design/**`, profile, privacy, journal or shared capture file was changed. Preserve R102/R118/R163 confidence floors, frozen R102 V1 4/6 failure, shadow/disabled and cooldown/baseline policies. All source-only evidence is unverified.

**Next contiguous GA:** **P0011–P0020**. Recover live HEAD and the dedicated ledger first; do not reprocess P0001–P0010 or let blocked integration stop independent work.

# R986 — EtherNet/IP RegisterSession with public client
**SOURCE CANDIDATE — UNVERIFIED.** Candidate/Shadow; tests authored, zero executed.

Owner workbook R2782 / AN2253 T0883: https://attack.mitre.org/detectionstrategies/DET0796#AN2253
Original workbook explicitly includes EtherNet/IP and requires asset role/approved communication policy. This candidate observes native protocol session registration only.

Exact first complete IPv4 TCP/44818 client/server PSH/ACK payloads, observed SYN and matching SYN-ACK, 28-byte encapsulation RegisterSession command 0065 LE, payload length 4, request handle zero, response handle nonzero, status/options zero, protocol version 1, option flags zero, matching opaque eight-byte sender context. Same flow, sequence/opposite ACK and <=30s. No session handle or context emitted; pending context/time only, cleared on reset/TLS/gap/replay/extra payload/response. Reuses R983 handshake gate extended to TCP/44818; other TCP detectors unchanged. No authentication, CIP operation, device role, unauthorized access or policy violation inferred. Approved engineering can match. No fragmented/coalesced messages or general reassembly.

Dedup: R488 ListIdentity discovery, R489 ForwardOpen, R983 FINS negotiation and R973 OPC UA handshake distinct. Existing broad predicates can overlap; no independent incident claim. Independent captures and approved communication policy required for promotion.

40 authored xUnit cases: three positive, 19 malformed/other operations, 14 session controls, four facts for timeout, scope/forgery, cooldown and registry. Windows compilation and execution pending.

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~R986EtherNetIpRegisterSessionQualityTests|FullyQualifiedName~R983FinsNodeNegotiationQualityTests"
```
Next R987 subject to live registry.

# R973 — OPC UA HEL/ACK with public client
**SOURCE CANDIDATE — UNVERIFIED.** Candidate/Shadow; source and tests authored only.

Owner workbook R2782 / AN2253: https://attack.mitre.org/detectionstrategies/DET0796#AN2253
Protocol: OPC UA Part 6, UA TCP message protocol https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.2

Exact complete IPv4 TCP/4840, observed SYN/SYN-ACK, first client HELF and first server ACKF, TCP sequence/ACK contiguous and same flow, <=30 seconds. Version zero, bounded buffers 8192–16777216, server receive <= client send and server send <= client receive. HEL exact endpoint length 11–2048, bounded printable ASCII opc.tcp:// shape; no claim of valid DNS/URL identity. ACK exact 28 bytes. No endpoint URL retained; only pending buffer sizes/time in existing bounded flow. Reset on reuse, FIN/RST, TLS, gaps, retransmits, invalid/other first payload, expiry. Narrow PSH/ACK, single-packet messages; no general reassembly, encrypted transport, authentication, SecureChannel or Session claims. Authorized remotely routed OPC UA clients can match.

Dedup: R684 observes TCP SYN/SYN-ACK on 4840 and is not changed; R973 confirms OPC UA transport acknowledgement. R228 OPC UA egress and R483/R484 operation shapes are distinct. R684/R973 may overlap a connection; not independent incidents. No asset inventory/approval inferred.

36 authored xUnit cases: three raw positive buffer boundaries, 17 malformed/near-miss frames, 12 session mismatches, exact timeout/one-shot, scope/forgery/contradictions, cooldown/isolation and registry. Synthetic only; Windows execution and independent captures pending.

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~R973OpcUaHelloAckQualityTests|FullyQualifiedName~R970Iec104StartupOffQualityTests|FullyQualifiedName~R972SnmpSystemFingerprintQualityTests"
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release
```

Next R974 subject to live registry. Existing qualification obligations unchanged.

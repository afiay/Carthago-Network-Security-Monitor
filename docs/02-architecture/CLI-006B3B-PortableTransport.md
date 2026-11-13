# CLI-006B.3B — Portable transport decoding

**SOURCE CANDIDATE — UNVERIFIED.** 17 portable and two Windows integration cases authored; zero executed in this session.

Core now owns TCP/UDP/ICMP header parsing. Existing PacketHandler delegates to PortableTransportHeaders, retaining record construction, flow state, protocol intelligence, service resolution and capture adapters. Transport payload offsets/counts refer to the input span; no new copying or payload retention. Existing TCP flags including NS, sequence/ack, data offset, UDP declared length, ICMP summary and incomplete capture behavior preserved. An explicit guard rejects inconsistent IP header bounds. ICMP preserves empty application payload with transport length separately. UDP shorter than IP payload remains accepted for header summary; existing complete-datagram evidence gates remain in PacketHandler.

Qualification:
```powershell
dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release --filter "FullyQualifiedName~PortableTransportHeaderTests|FullyQualifiedName~PortableFrameHeaderTests"
dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~PortableTransportIntegrationTests|FullyQualifiedName~PortableFrameHeaderIntegrationTests"
dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release
```

Repeat portable tests on Linux/macOS. No native capture or rule execution port claimed. Next CLI-006B.3C: extract application parsing and flow dependencies in bounded slices. No Actions execution requested.

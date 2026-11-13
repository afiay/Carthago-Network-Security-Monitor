# CLI-006B.3A — Portable link and IP framing

**SOURCE CANDIDATE — UNVERIFIED.** 11 portable and four Windows xUnit cases authored; zero executed in this session.

Extract existing PacketHandler link-layer, stacked VLAN, IPv4/IPv6 header and extension traversal into Core's internal PortableFrameHeaders. The existing Windows handler delegates to it and retains transport/application processing, ARP, flow state, service resolution and capture adapter. Numeric link type replaces PacketDotNet enum inside Core. No native capture dependency added. The original acceptance rules (including incomplete IP header vs incomplete packet distinction, atomic IPv6 fragments, bounded VLAN/extensions and raw link-type handling) are preserved; no new protocol or live platform support claimed.

Tests cover Ethernet, BSD null, raw IP, SLL/SLL2, VLAN depth, truncation, IPv4 fragments, IPv6 extensions and atomic fragments; Windows integration uses the existing PacketHandler. Run:

```powershell
dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release --filter "FullyQualifiedName~PortableFrameHeaderTests"
dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~PortableFrameHeaderIntegrationTests|FullyQualifiedName~Dns|FullyQualifiedName~R981"
dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release
```

Repeat portable tests on Linux/macOS. Existing capture/replay regression remains mandatory. Next CLI-006B.3B: transport header extraction and raw frame pipeline adapter separation, then protocol/flow dependencies. No Actions execution requested.

# CLI-006B.3C4 — Portable raw-frame processor

**SOURCE CANDIDATE — UNVERIFIED.** Eight portable and one Windows xUnit cases authored; zero executed in this session.

The existing PacketHandler raw-frame implementation is relocated into Core's internal PortablePacketProcessor. Windows PacketHandler retains its public capture API, raw-frame test entry point and Redis window helper. Numeric link-layer identifiers replace PacketDotNet types in Core. Existing Windows service lookup, JA4X fingerprint function, display wall clock and legacy shared flow-state behavior are passed explicitly. Portable sessions default to independent flow state, injected capture clock, Unknown service names and no JA4X output unless supplied. The recent EtherNetIpIdentityResetInspector moves with its caller. IpUtils remains in Windows for public compatibility.

Existing protocol validation, record construction, correlation and TCP state logic remain in one canonical implementation. This is not general TCP reassembly or portable detection execution. Certificate identity enrichment still uses wall-clock validity; JA4X platform parity is deferred. Windows display time remains local wall clock; portable display time uses the supplied clock. No CLI command or PCAP reader is added yet. Existing Windows integration and full regression are required before claiming parity.

```powershell
dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release --filter "FullyQualifiedName~PortablePacketProcessorTests"
dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~PortablePacketAdapterTests|FullyQualifiedName~Capture|FullyQualifiedName~Dns|FullyQualifiedName~EtherNetIp|FullyQualifiedName~Tls"
dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release
dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release
```

Repeat portable tests on Linux/macOS. Next: portable PCAP intake and replay command or detection dependency extraction, followed by full rule execution. No Actions execution requested.

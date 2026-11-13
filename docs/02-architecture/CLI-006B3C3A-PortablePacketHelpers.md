# CLI-006B.3C3A — Remaining portable packet helpers

**SOURCE CANDIDATE — UNVERIFIED.** 15 portable xUnit cases authored; zero executed in this session.

Core compiles ten existing internal helper sources: NetworkBatch226230Wire, NetworkBatch231235Wire, NetworkBatch246250Wire, OtProtocolLight, DnsAObservationInspector, EtherNetIpRegisterSessionInspector, FinsControllerStopInspector, FinsDataMemoryClearInspector, FinsNodeNegotiationInspector and TlsIdentityEnrichment. Windows excludes their canonical source paths. No source algorithms or namespaces changed; no public type relocation in this batch. The TLS identity helper already parses DER SANs using System.Formats.Asn1; platform-local certificate validity conversion remains unchanged. X509Ja4X is deferred because its formatted SAN count requires parity review. PortServiceResolver remains host-owned (file/cache/network lifecycle); future portable processing should inject service resolution. FlowKey, HandshakeBuffer and LatencyTracker remain for next milestone. PacketHandler's native capture adapter and orchestration remain in Windows.

Publication rebased onto 987f77ad7a213bf4dc19c1e8d401182cf1452e5b to preserve concurrent dashboard UI changes; changed paths were disjoint.

Tests exercise representative positive/negative wire shapes, DTD rejection, direction, exact DNS answer bounds, FINS/EtherNetIP correlation windows, TLS negotiation and DER SAN matching. Existing Windows protocol and capture provenance regressions remain required.

```powershell
dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release --filter "FullyQualifiedName~PortablePacketHelperTests"
dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~Dns|FullyQualifiedName~TlsIdentityEnrichmentTests|FullyQualifiedName~Fins|FullyQualifiedName~EtherNetIp|FullyQualifiedName~NetworkBatch"
dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release
dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release
```

Repeat portable tests on Linux/macOS. Next CLI-006B.3C3B: flow key, handshake buffering, latency and state lifetime. No Actions execution requested.

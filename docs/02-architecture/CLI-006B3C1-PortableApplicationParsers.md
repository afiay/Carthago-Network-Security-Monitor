# CLI-006B.3C1 — Portable application parsers

**SOURCE CANDIDATE — UNVERIFIED.** 17 portable xUnit cases authored; zero executed in this session.

## Implementation
Move the four existing internal lightweight parser types (HttpLight, TlsLight, DnsLight, QuicLight) out of PacketHandler.cs into Core's PortableApplicationParsers.cs, preserving namespace and class bodies. Compile the existing SensitiveTelemetryContracts source only in Core, since HTTP uses its default credential byte classifier. It depends only on BCL and the already shared TrafficRecord. Existing Windows callers use the Core friend access; no rule logic, thresholds, redaction policy or parser behavior is intentionally changed. IpUtils stays in Windows. No new package or platform dependency.

The lightweight parsers are metadata recognizers, not comprehensive protocol validators; QUIC header recognition does not prove a handshake, DNS presentation does not replace the strict binary codec, and TLS summaries do not establish authenticated peer identity. HTTP preserves complete-header and singleton credential gates. Full capture provenance and application flow state remain in PacketHandler.

## Qualification
```powershell
dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release --filter "FullyQualifiedName~PortableApplicationParserTests"
dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release
dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~HttpLightPrivacyTests|FullyQualifiedName~SensitiveTelemetryContractTests|FullyQualifiedName~DevOpsHttpParserProvenanceTests|FullyQualifiedName~TlsIdentityEnrichmentTests|FullyQualifiedName~Dns"
dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release
```

Repeat portable tests on Linux/macOS; existing Windows protocol/replay qualification is required. No Actions execution requested. Next CLI-006B.3C2: inventory and extract remaining protocol inspectors and fingerprints.

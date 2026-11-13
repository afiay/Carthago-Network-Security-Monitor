# CLI-006C.1 — Classic PCAP inspection

**SOURCE CANDIDATE — UNVERIFIED.** 20 portable xUnit cases authored; zero executed in this session.

```sh
carthago pcap inspect capture.pcap --limit 50 --json
```

Read-only classic PCAP v2.4, both byte orders and timestamp resolutions. Supported numeric link types 0,1,12,101,113,228,229,276. Reject unsupported format/version/link flags, invalid fractions/lengths and partial records. Limits: 512 MiB, 1,000,000 records, 1 MiB frame/snaplen, 1–100 output rows (default 50); full scan within limits, no partial success for malformed files. Capture-truncated records skipped; parsed/rejected/truncated counts are mutually exclusive. Big-endian DLT_NULL family bytes are normalized to the existing Core decoder. Original nanosecond fraction retained; .NET clock uses 100 ns ticks. Backward timestamp resets session state; count reported. No sorting or network access. Output restricted to endpoint/port/protocol/length/time; no raw packet, header, credential or full TrafficRecord serialization. Untrusted capture, detection not assessed. No PCAPNG, rule execution, JA4X or service database lookup. Existing Windows adapter preserves log routing; portable processor defaults to no console diagnostic output.

```powershell
dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release --filter "FullyQualifiedName~PortablePcapInspectionTests|FullyQualifiedName~PortablePacketProcessorTests"
dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release
dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~PortablePacketAdapterTests|FullyQualifiedName~Capture"
dotnet run --project Carthago.Cli -- pcap inspect capture.pcap --json
```

Publication rebased onto fe1ab351b89566ce5c611df7d86e3a61a5891615 to preserve concurrent active-sensor and GeoIP changes; modified paths were disjoint.

Repeat on Linux/macOS; next PCAPNG and/or portable detection execution. No Actions execution requested.

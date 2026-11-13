# CLI-006C.2 — PCAPNG inspection

**SOURCE CANDIDATE — UNVERIFIED.** Ten portable cases authored; zero executed.

`carthago pcap inspect capture.pcapng --limit 50 --json`

Supports PCAPNG 1.0 SHB/IDB/EPB, mixed section byte orders, interface link types, decimal (0–19) and binary (0–63) timestamp exponents, signed seconds offsets, section length checks and block trailers. Unknown metadata blocks are skipped by validated envelope; Simple Packet and obsolete Packet Blocks fail explicitly (no silent packet loss). Maximum 8 interfaces per section, 64 sections, 2 million blocks; existing 512 MiB/1 million packet/1 MiB frame limits apply. PCAPNG snaplen zero means unlimited subject to local frame limit. Interface state resets at section change and on backwards raw timestamp; different interfaces never share packet state. Timestamp fraction rounded down to nanoseconds and .NET ticks. JSON adds format, section/interface counts and row section/interface/link IDs; classic existing fields retained. PCAPNG top-level link type null, timestamp resolution per_interface. No raw bytes, options, comments or secrets exported. Imported data is untrusted, no rules executed.

Format reference: https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/06/ (Internet-Draft, September 2026).

```powershell
dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release --filter "FullyQualifiedName~PortablePcapNgTests|FullyQualifiedName~PortablePcapInspectionTests"
dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release
```

Publication rebased onto ac9f2c0372523287d0d7de9a7315923622b494af to preserve concurrent GeoIP and rule-qualification changes; modified paths were disjoint.

Next: portable detection execution and replay qualification. No Actions execution requested.

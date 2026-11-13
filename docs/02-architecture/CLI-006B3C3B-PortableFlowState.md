# CLI-006B.3C3B — Portable flow state

**SOURCE CANDIDATE — UNVERIFIED.** Seven portable and one Windows xUnit facts authored; zero executed in this session.

Core owns FlowKey, HandshakeBuffer and LatencyTracker; Windows forwards the public types. HandshakeBufferState preserves existing TLS reconstruction, memory limits, counters and removal behavior, but supports instance ownership and an injected UTC clock. Legacy static facade retains one wall-clock shared instance. LatencyTrackerState preserves existing latency bins and first-data semantics, adds synchronized access and a 16,384-flow FIFO insertion cap (oldest insertion evicted at capacity). No idle expiration added to latency state; future session lifecycle and flow cleanup still required. Legacy static latency facade uses the bounded state. Existing PacketHandler constructors preserve shared facade behavior; a new internal constructor permits explicit independent states. No existing replay caller is migrated in this batch; isolated replay requires selecting that constructor and a capture-time clock.

Publication rebased onto fa7f39a565592e305bb1bac61887b0fd03a22e8e to preserve concurrent active-evidence changes; changed paths were disjoint.

Qualification:
```powershell
dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release --filter "FullyQualifiedName~PortableFlowStateTests"
dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~PortableFlowCompatibilityTests|FullyQualifiedName~Tls|FullyQualifiedName~Capture"
dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release
dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release
```
Repeat portable tests on Linux/macOS. Next: portable PacketHandler boundary, host service resolution injection and certificate fingerprint parity. No Actions execution requested.

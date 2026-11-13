# CLI-006D.3 — First portable detector (R589)

**SOURCE CANDIDATE — UNVERIFIED.** Eleven portable and four Windows parity cases authored; zero executed.

R589 WebLogic keystore script request now delegates to a single Core detector using the original HTTP evidence hygiene, exact path/suffix predicate and instance-owned ten-minute cooldown. The shared WebSignatureRequestEvidence and WebSignatureCooldown source compiles once in Core; existing namespaces and semantics remain unchanged. GET and POST behavior is preserved, not broadened. Windows retains descriptor, evidence creation, confidence, Shadow profile and runtime policy.

Portable results are request observations (none/match/suppressed), not persisted alerts, successful exploitation or host authorization. The internal detector does not execute trusted host capabilities. No public PCAP detect command or full rule catalog execution exists yet. Existing HTTP parser limitations and cooldown behavior are unchanged. Tests cover synthetic raw TCP parsing, signature/near misses, contradictory fields, cooldown and host parity.

Owner-run gates:
```powershell
dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release --filter "FullyQualifiedName~PortableR589Tests"
dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~PortableR589ParityTests"
dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release
dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release
```

Next: bounded offline replay dispatcher, explicit unsupported-rule outcomes, and PCAP/PCAPNG detection integration with isolated state. No Actions run requested.

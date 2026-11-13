# CLI-006D.2 — Portable packet evaluation context

**SOURCE CANDIDATE — UNVERIFIED.** Five portable and three Windows test cases authored; zero executed.

Introduces PacketEvaluationContext in net8.0 Carthago.Core, with the exact caller-owned TrafficRecord, Sensitivity and explicit UTC timestamp. Non-UTC inputs are rejected to avoid timezone-dependent replay. The Windows RuleEvaluationContext composes this type and retains its historical normalization for local/unspecified timestamps, existing public property signatures, host health snapshot and exact R275 capability/promotion binding checks. Existing R272 correlation state remains host-only and unchanged.

The packet context is not immutable evidence: its TrafficRecord is mutable. No record provenance or authorization is inferred, and it cannot accept trusted capability objects. No detector is migrated or executed by this increment. No PCAP detection command is added; the next increment must choose an existing packet-only detector, extract its canonical predicate without duplicating it, and verify positive/negative/boundary parity and unsupported producers.

Owner-run gates:
```powershell
dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release --filter "FullyQualifiedName~PortableEvaluationContextTests|FullyQualifiedName~PortableDetectionModelTests"
dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~PacketEvaluationContextHostTests|FullyQualifiedName~R275TrustedCapabilityContextTests|FullyQualifiedName~R275PromotionPolicyTests|FullyQualifiedName~R272AdvancedAccuracyBatchTests"
dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release
dotnet build Carthago.Monitor/Carthago.Monitor.csproj -c Release
```
Run portable tests on Windows and Linux. No Actions run requested. Publication is not build or field validation.

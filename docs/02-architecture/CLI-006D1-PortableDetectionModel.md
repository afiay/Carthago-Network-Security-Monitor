# CLI-006D.1 — Portable detection data model

**SOURCE CANDIDATE — UNVERIFIED.** Four tests authored; zero executed.

Continues CLI-006C.2. DetectionEvent, Sensitivity, RuleDescriptor, RuleEvaluationResult, RuleNoMatchReason and RuleMode now compile once in net8.0 Carthago.Core. Canonical source paths and namespaces remain unchanged; the Windows project excludes these sources and consumes Core. No detector logic, serialization properties, severity values, delivery or suppression semantics changed.

RuleEvaluationContext and IDetectionRule still depend on host-only trusted-audit and intelligence services; those boundaries are not moved. Imported captures remain untrusted and no rules are executed by this increment. Existing NoMatchReason clock behavior remains unchanged; deterministic replay requires explicit timestamps.

Owner-run gates:
```powershell
dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release --filter "FullyQualifiedName~PortableDetectionModelTests|FullyQualifiedName~PortableCoreArchitectureTests"
dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release
dotnet build Carthago/Carthago.csproj -c Release
dotnet build Carthago.Monitor/Carthago.Monitor.csproj -c Release
dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release
```
Run portable tests on Windows and Linux. No Actions run requested. Next: isolate packet-only evaluation context while preserving trusted R275 capability boundaries, then qualify an existing detector through deterministic replay.

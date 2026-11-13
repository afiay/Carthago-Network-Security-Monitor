# CLI-006B.2 — Shared traffic model

**SOURCE CANDIDATE — UNVERIFIED.** Six portable and one Windows xUnit facts authored; zero executed in this session.

## Implementation
`TrafficRecord` is compiled once by portable net8.0 Core. The canonical source file and namespace remain unchanged; Windows excludes its own compile and forwards the former CLR type to Core. The existing DNS observation dependency already lives in Core. No fields, notification semantics, JSON attributes or evidence accessors changed. Core's existing friend declarations preserve Windows producer/test access; capture-only setters remain internal and ordinary System.Text.Json imports cannot set them.

## Compatibility audit
At base commit 11f5df80d37d61b0612243a249468e0b46ebaa1a, the recursive repository tree listed all project files and XAML views. Inspection found no direct TrafficRecord reference in XAML, and no other project links the model source. The Cisco tools view declares a Carthago.Models namespace for other models; do not change it. The model uses System, System.ComponentModel and Core's internal DNS observation. The Windows type forwarder supports former CLR assembly-qualified lookup; it does not certify arbitrary third-party binaries, serializers, or WPF markup. Full rebuild and runtime smoke remain required.

The branch advanced to c06cc3e9cda6ed3ca27ca6356e02a6aaf8ea4d5f before publication; the new R981 DNP3 capture-only flag was inspected, preserved and added to the import-forgery regression. No concurrent files were overwritten.

## Qualification
```powershell
dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release --filter "FullyQualifiedName~PortableTrafficRecordTests|FullyQualifiedName~PortableProtocolCoreTests|FullyQualifiedName~PortableCoreArchitectureTests"
dotnet build Carthago/Carthago.csproj -c Release
dotnet build Carthago.Monitor/Carthago.Monitor.csproj -c Release
dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~TrafficRecordAssemblyCompatibilityTests|FullyQualifiedName~Dns|FullyQualifiedName~R979BacnetEventDisableQualityTests"
dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release
```

Repeat portable tests on Linux/macOS; inspect live traffic grid, filtering and evidence on Windows. Tests verify single assembly identity, property aliases and notifications, public JSON round-trip, capture-only forgery rejection, internal DNS privacy and legacy type forwarding. No GitHub Actions execution requested.

Next: CLI-006B.3 — extract frame parsing dependencies incrementally, preserving native capture adapters and replay time. This milestone does not provide a portable live capture or full detection engine.

# CLI-006B.1 — Portable protocol parsing

**SOURCE CANDIDATE — UNVERIFIED.** Seven xUnit facts authored; zero executed in this session.

## Implementation
Core now compiles the existing DNS wire-name codec, DNS address observation inspector and BACnet Event_Enable disable inspector. Windows excludes those three canonical files from its own compile and references Core. Namespaces, source paths, visibility, parser bodies and call sites are unchanged. No new package dependency; no new capture or detection capability is claimed. The DNS inspector remains enrichment-only and the BACnet inspector remains request-only; neither is evidence of authorization or server outcome.

## Dependency inventory
- DNS codec: System, collections, LINQ, text. No host dependencies.
- DNS address inspector: codec, binary primitives, IPAddress. No capture dependencies.
- BACnet inspector: binary primitives only.
- TrafficRecord: INotifyPropertyChanged and nested DNS observation type. Moving this public model requires checking WPF XAML namespace/type resolution, reflection, linked compile consumers and capture-only internal setters; deferred.
- PacketHandler: SharpPcap, PacketDotNet, flow/fingerprint/protocol helpers, mutable per-flow state. Separate frame parser from capture adapters, preserving existing replay clock injection.
- RuleEngine: registry, content packs, selector, trusted audit, configuration, tuning, diagnostics and correlation. Extract contract/state dependencies before execution.

## Qualification
```powershell
dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release --filter "FullyQualifiedName~PortableProtocolCoreTests|FullyQualifiedName~PortableCoreArchitectureTests"
dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release
dotnet build Carthago/Carthago.csproj -c Release
dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~Dns|FullyQualifiedName~R979BacnetEventDisableQualityTests"
dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release
```

Repeat portable tests on Linux/macOS. These synthetic fixtures verify assembly identity, binary label round-trip, compression rejection, DNS answer extraction, all truncated prefixes, and exact BACnet request classification. Existing Windows replay tests remain necessary; no capture parity or field accuracy has been established. Rebuild consumers after assembly identity changes.

Next: CLI-006B.2 — inventory and extract shared TrafficRecord and further packet parser dependencies; retain evidence provenance and Windows UI compatibility. No GitHub Actions requested.

# CLI-006A — Portable Core: session archive extraction

**SOURCE CANDIDATE — UNVERIFIED.** Four xUnit facts authored; zero executed in this change session. No Linux/macOS live capture or Windows deployment certification.

## Scope

The portable net8.0 CLI and Windows WPF application previously compiled separate copies of the same CSA v1 snapshot and archive implementation. `Carthago.Core` now owns those two types in one net8.0 assembly with no project/package references. Both hosts reference Core; the Windows monitor inherits that reference through the application. Source paths and namespaces remain stable; only compile ownership changes. Existing internal access is retained temporarily through friend assemblies. No CSA format, serialization, redaction, integrity-check or command behavior changes are intended. Existing Contracts remain independent.

## Qualification

Run from the repository root with .NET 8 SDK:

```powershell
dotnet build Carthago.Core/Carthago.Core.csproj -c Release
dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release
dotnet build Carthago/Carthago.csproj -c Release
dotnet build Carthago.Monitor/Carthago.Monitor.csproj -c Release
dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release
```

First two commands are portable; repeat on Linux and macOS. Last three require Windows for full qualification. Tests cover single assembly ownership, redaction/CLI inspection, tampering and cancelled replacement. Existing binaries compiled against the old type assembly must be rebuilt; no binary compatibility guarantee is made. No GitHub Actions execution requested.

## Next gates

- CLI-006B: dependency inventory of packet parsing, traffic/evidence models and rule evaluation; isolate Windows APIs before moving behavior. Use replay parity checks.
- CLI-006C: portable capture provider contract and offline replay; separate live libpcap availability/permission failures from detection outcomes.
- CLI-006D: platform host, IPC and lifecycle adapters with explicit capability reporting, then Linux/macOS deployment qualification.

The full detection engine remains in the Windows project; this is the first shared-library extraction, not a portable monitoring release.

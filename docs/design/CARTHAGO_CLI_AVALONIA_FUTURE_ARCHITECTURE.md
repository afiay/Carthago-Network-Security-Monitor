# Carthago CLI and Avalonia desktop — future architecture specification

**GA UI-06 · 2026-10-30 · DESIGN ONLY — NOT IMPLEMENTED / UNVERIFIED.**
This document proposes a future Windows/Linux CLI and Avalonia desktop GUI.
It does not authorize project creation, engine migration, platform adapters,
command execution, testing, or claims of cross-platform runtime support.

## Current repository contract (source audit)

- [WPF application](../../Carthago/Carthago.csproj) uses `OutputType=WinExe`,
  `TargetFramework=net8.0-windows10.0.19041.0`, `UseWPF=true`,
  and Windows runtime identifiers. Its entrypoint is the Windows application
  startup, not a general-purpose `carthago` terminal executable.
- [MainWindow.xaml](../../Carthago/Views/MainWindow.xaml) and its partials
  bind existing local capture, incident, detection and navigation state.
  `DashboardCliCompanionPanel` is a **static unavailable placeholder**.
- [Carthago/Tests/Program.cs](../../Carthago/Tests/Program.cs) is a test
  harness; `Carthago.Benchmarks/Program.cs` is benchmarking;
  `scripts/*.ps1` are development/verification scripts. None is an
  authenticated production CLI or an embeddable terminal command provider.
- Existing capture and trust/provenance components must be audited before
  extraction. Do not assume ETW, WPF, Windows security auditing, Cisco
  integrations, ScottPlot.WPF or WebView2 work on Linux.

## Proposed boundaries (no code added)

| Proposed component | Responsibility | Explicit non-goals and evidence boundary |
| --- | --- | --- |
| `Carthago.Contracts` (future) | Versioned, platform-neutral **read-only** status, incident and event DTOs with source provenance, event time semantics, rule ID, bounded counts, missing/unsupported states | No raw packet body, credentials, secrets, implicit audit authentication, or reuse of Windows-only serialized models without review |
| `Carthago.Application` (future) | Shared query and authorization use cases only after isolating genuinely portable behavior and auditing all consumers | No direct WPF types, `Dispatcher`, capture handles, or implicit platform equivalence |
| `Carthago.Cli` (future) | Dedicated .NET console executable for Windows/Linux; proposed **read-only** commands: `status`, `events`, `incidents`, `rules`, `capabilities`; structured JSON plus human-readable output | Commands are proposals, not working syntax. No arbitrary shell execution, configuration mutation or capture start/stop without separately approved contracts |
| `Carthago.Desktop.Avalonia` (future) | Independent Avalonia desktop frontend sharing versioned read-only DTOs; reproduces approved layout with native responsive and accessibility behavior | Do not replace current WPF or claim that existing XAML/controls are directly portable |
| Platform capability providers (future) | Explicit Windows and Linux implementations for OS-specific capture/audit capabilities; unsupported modes return structured `Unavailable` with reason | No fabricated ETW/Linux audit equivalence, packet decryption, trusted cloud events or silent fallback to weaker evidence |
| Local session transport (future) | Authenticated local IPC, opt-in listener, bounded streaming with backpressure and disconnect/reconnect semantics | No unauthenticated TCP port, remote exposure, raw-secret forwarding or implicit CLI-to-engine privilege escalation |

## Candidate contract and trust model

- **Capabilities first:** each provider advertises availability, OS/version,
  privilege requirements, capture limitations, producer identity and whether
  its evidence is authenticated. A disabled/unavailable capability is
  distinguishable from a zero count.
- **Data provenance:** every projected event carries its origin and observed
  timestamp, explicit timezone/clock convention, trust boundary and retention
  window. Detection counts, incidents, delivery state, evidence counts and
  detection coverage remain separate concepts. Missing denominators show
  `Unavailable`, never fabricated percentages.
- **Privacy by default:** read-only DTOs omit secrets, tokens, HTTP
  authorization headers, raw evidence and packet payload. Any future evidence
  retrieval requires explicit authorization, redaction, bounded pagination,
  auditing and separate owner approval.
- **Local IPC security:** prefer OS-local named pipes on Windows and Unix-domain
  sockets on Linux *after feasibility review*, with per-user permissions and
  explicit peer identity checks. Treat transport identity as separate from
  event provenance. A UI or CLI must not infer authenticated audit evidence
  from an untrusted network field.
- **Concurrency:** bounded event buffers, cancellation, backpressure and
  deterministic disconnect states. Never block packet processing on UI/CLI
  rendering; do not mutate rule thresholds, suppression, confidence floors,
  journal or approval state through the proposed read-only interface.
- **Deployment:** independent packaging and signing decisions per OS, no
  assumption that WPF-specific runtime components can be bundled on Linux.
  Verify target distributions, capture permissions, CPU/memory footprint,
  offline operation and upgrade/rollback behavior before product claims.

## Future GAs, dependent on separate owner authorization

1. **GA CLI-A (contract review):** inventory exact engine dependencies,
   event provenance, privacy rules and OS-specific capabilities. Specify
   versioned DTO schema and unsupported states without changing production
   code.
2. **GA CLI-B (security/design approval):** review local IPC threat model,
   command permission boundaries, transport authentication, secret redaction,
   packaging and compatibility. No implementation before approval.
3. **GA CLI-C (isolated prototype):** only after explicit authorization,
   implement a separate read-only CLI against approved contracts; do not
   launch commands inside the WPF visual placeholder.
4. **GA GUI-A (separate frontend):** only after explicit authorization,
   prototype Avalonia UI with truthful data projections, platform support
   checks and screenshot fidelity. Keep WPF operational until a migration
   decision is explicitly approved.
5. **GA validation (owner-authorized):** pinned-SHA Windows/Linux builds,
   supported-distribution matrix, CLI exit codes/JSON contracts, negative
   privacy and spoofing tests, capture/permission failure modes, throughput,
   memory, accessibility, keyboard focus, layout and rollback.

## Authoritative references

- [Avalonia cross-platform architecture](https://docs.avaloniaui.net/docs/fundamentals/cross-platform-architecture) —
  separate shared UI contracts from OS-specific integration.
- [Avalonia supported platforms](https://docs.avaloniaui.net/docs/supported-platforms) —
  check release-specific Windows and Linux support before committing to an OS.
- [Avalonia Linux platform guide](https://docs.avaloniaui.net/docs/platform-specific-guides/linux) —
  display backends and deployment assumptions require verification.
- [Microsoft System.CommandLine overview](https://learn.microsoft.com/en-us/dotnet/standard/commandline/) —
  potential future command parsing; not an installed dependency or current CLI.
- [Microsoft C# naming conventions](https://learn.microsoft.com/en-us/dotnet/csharp/fundamentals/coding-style/identifier-names) —
  preserve existing public contracts and compatible naming.

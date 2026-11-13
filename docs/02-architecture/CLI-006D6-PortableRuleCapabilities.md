# CLI-006D.6 — Portable rule capability catalog

**SOURCE CANDIDATE — UNVERIFIED.** Parent `f39e4b877d5b12bc92542cec77b11d0e8c13f1d2`.

Commands:
```
carthago rules capabilities --json
carthago rules capabilities --portable --json
carthago rules capabilities R590 --json
carthago rules capabilities R1000 --json
```

The default and --portable list the five compiled portable registrations (R586–R590); they do not enumerate the Windows rule catalog. Numeric lookup reports supported or unsupported_detector; unsupported does not assert that a rule exists in the live registry. Catalog metadata and fresh evaluator factories share one registration source; dispatcher support and execution derive from it. State remains per detector per replay epoch. Metadata describes PCAP/PCAPNG, required coherent cleartext TCP/HTTP evidence, supported HTTP methods, 600-second cooldown, and qualification/registration not assessed. No Windows policy execution, live capture or alert publication. No automatic all-rules selection yet.

Nine synthetic cases authored; zero executed. Owner gate: `dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release --filter "FullyQualifiedName~PortableRuleCapabilityTests|FullyQualifiedName~PortableReplayTests|FullyQualifiedName~CliApplicationTests|FullyQualifiedName~PortableHttpBatchTests"`. Next: CLI-006E pinned integration and parity qualification.

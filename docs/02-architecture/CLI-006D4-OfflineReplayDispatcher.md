# CLI-006D.4 — Offline replay dispatcher

**SOURCE CANDIDATE — UNVERIFIED.** Parent `a894a36f036fccad864d6c4c7ebf4172a12411e3`. No builds, tests, live capture or Actions executed.

`carthago pcap detect capture.pcapng --rules R589,R1000 --limit 50 --json`

- Reuse the existing bounded classic PCAP/PCAPNG inspection loop with a decoded-packet observer. The normal inspect command still does not execute rules.
- Core dispatches only R589; canonical numeric IDs without a portable detector report `unsupported_detector`, not a negative result. A successful command means the capture was processed, not that every requested rule is supported. No claims about registration of unsupported IDs.
- Isolate the detector by capture invocation, PCAPNG section/interface and parser clock-reset epoch. Preserve existing R589 predicate and cooldown; no Windows runtime policy, alerts, external providers or active actions.
- Keep complete counters and at most 100 findings. Findings contain rule ID, packet ordinal, timestamp/nanoseconds, section/interface and validated HTTP method, not raw payload or URL. No partial success JSON for malformed capture or cancellation. Existing parser/reader limits remain in force.
- R589 observations are not successful exploitation, authenticated telemetry or detection validation. No full TCP reassembly, encrypted HTTP decryption, or cross-interface correlation promised. A zero parsed-packet result has zero evaluations.

Owner validation: `dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release --filter "FullyQualifiedName~PortableReplayTests|FullyQualifiedName~PortablePcap|FullyQualifiedName~PortableR589Tests"`. Windows parity: `dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~PortableR589ParityTests"`. Then pinned integration gate.

Next: qualify this baseline, generalize dispatcher counters for additional rules, and migrate eligible detectors with positive/negative and parity coverage.

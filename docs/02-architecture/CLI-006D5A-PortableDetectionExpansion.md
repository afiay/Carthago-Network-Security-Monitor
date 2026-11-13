# CLI-006D.5A — Two portable detectors and independent accounting

**SOURCE CANDIDATE — UNVERIFIED.** Parent `d9ade6dba94bc9fd7e802bdcefdc6f52c36326eb`. R587 and R589 supported; all other canonical numeric IDs explicit unsupported. Extract R587 predicate and cooldown into Core, preserving Windows descriptor, Shadow mode, confidence, evidence and exact GET/path predicate. Independent per-rule counters and state; global match/suppression totals sum observations, not unique packets. Findings preserve capture order then requested rule order. Nine portable synthetic cases (seven R587, two replay), four Windows parity cases authored; zero executed. Correct stale available-capabilities assertion (session.inspect, pcap.inspect, pcap.detect).

Owner gates: `dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release --filter "FullyQualifiedName~PortableR587Tests|FullyQualifiedName~PortableReplayTests|FullyQualifiedName~CliApplicationTests"` and `dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~PortableR587ParityTests|FullyQualifiedName~PortableR589ParityTests"`.

No live alerts, rule promotion, capture or Actions. No additional evidence coverage or exploit outcome claimed. Next: qualify and add a small batch of existing HTTP rules, then capability manifest and producer eligibility.

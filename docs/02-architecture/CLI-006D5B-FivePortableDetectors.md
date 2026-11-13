# CLI-006D.5B — Five portable detectors

**SOURCE CANDIDATE — UNVERIFIED.** Parent `24d976c296c89e635de3a891b78d5c551685b371`.

R586 (WordPress wp2shell), R588 (SolarWinds SUPERNOVA handler), R590 (Rejetto HFS search) now delegate to shared Core detectors, alongside R587/R589. Preserve literal predicates, evidence hygiene, per-rule cooldown, Windows descriptors, Shadow policy, confidence and event evidence. Existing signatures are not broadened or independently certified. R588's substring marker and R590's literal search marker are unchanged. These are request observations, not exploitation outcomes.

`carthago pcap detect capture.pcapng --rules R586,R587,R588,R589,R590 --json`

19 portable cases (15 signature, three evidence/cooldown, one capture replay) and 15 Windows parity cases authored; zero executed. All other numeric IDs remain explicitly unsupported. No live capture or Actions.

Owner gates: `dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release --filter "FullyQualifiedName~PortableHttpBatchTests|FullyQualifiedName~PortableReplayTests|FullyQualifiedName~PortableR587Tests|FullyQualifiedName~PortableR589Tests"`; `dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~PortableHttpBatchParityTests|FullyQualifiedName~PortableR587ParityTests|FullyQualifiedName~PortableR589ParityTests"`.

Next: CLI-006D.6 capability catalog and required evidence, then pinned qualification.

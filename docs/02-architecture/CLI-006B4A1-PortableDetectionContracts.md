# CLI-006B.4A1 — Portable detection contracts and metadata

**SOURCE CANDIDATE — UNVERIFIED.** 23 portable and one Windows xUnit cases authored; zero executed.

Building on concurrent CLI-006D.1, which already moved six of the twelve canonical files, Core now compiles twelve canonical source files covering DetectionEvent, Sensitivity, rule descriptors/modes/results/reasons/traces, RuleIntelligence, RulePrecisionProfile/catalog, confidence/evidence builders and rule ID validation. Windows excludes those files and forwards all 32 public types. Source bodies, namespaces, confidence thresholds, rule maturity/default modes and existing validation heuristics are unchanged. The precision catalog's process-wide override dictionary remains shared; no isolated rule execution is claimed. EvidenceBuilder is not a privacy sanitizer; sensitive markers do not authorize export. RuleEvaluationResult failure strings and reason default timestamps retain existing behavior. Public RuleEvaluationContext and IDetectionRule remain in Windows pending the R275 trusted audit capability and promotion authorization dependency review. RuleEngineHealthState remains in Windows; snapshot split is next. No change to live rule registry or execution. Publication integrates concurrent R988–R1000 and CLI-006D.1 changes at 36093b7a6b1449991123f768e32ece75c1a7405a; six already-linked files were not duplicated, current RuleIdValidator (R1000+) and RulePrecisionProfile bodies preserved, README merged. RuleEvaluationContext now also references engine-owned R272 signals; retain that boundary in next milestone.

Qualification:
```powershell
dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release --filter "FullyQualifiedName~PortableDetectionContractTests"
dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~PortableDetectionContractCompatibilityTests|FullyQualifiedName~Precision|FullyQualifiedName~Confidence|FullyQualifiedName~Evidence"
dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release
dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release
```

Next: CLI-006B.4A2 — health snapshot, trusted audit dependency boundary and evaluation context/interface. No Actions execution requested.

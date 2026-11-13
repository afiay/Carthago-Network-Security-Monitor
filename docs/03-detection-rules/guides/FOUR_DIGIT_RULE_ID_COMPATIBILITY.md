# Four-digit rule identity compatibility

**SOURCE CANDIDATE — UNVERIFIED.** Rule IDs remain stable. R001–R999 are not renamed; R1000, R1001 and R3085 use their natural decimal form. The core ID contract is a positive Int32 with at least three digits, padded only when necessary, uppercase R and ASCII decimal digits. R000, R01000, R2147483648 and numeric R-series aliases are invalid, never content-pack IDs. Content-pack IDs retain their separate prefix contract.

The Core RuleIdValidator exposes one canonical parser and a numeric comparer. Core/available catalogs, runtime ordering with active packs, session exports, tuning snapshots, telemetry coverage, health diagnostics, no-match reports and replay rule lists use the same comparer. Pack groups retain their existing lexical placement. No detection predicates, confidence thresholds, runtime modes or persistent IDs are migrated. CLI archive and ledger readers require exact canonical core ID text and fail closed on aliases, malformed IDs and duplicates.

The focused verification script accepts canonical rule numbers beyond 544, discovers exactly one supported dedicated test filename (RnnnTests.cs or RnnnOperationQualityTests.cs), applies an exact class-boundary filter, deletes stale TRX and rejects absent/empty/nonpassing/unrelated results. It intentionally fails on missing or ambiguous dedicated tests; grouped test associations are handled by the existing source inventory. The historical advanced R001–R544 acceptance gate remains historical, and its full suite runs the later tests without claiming per-rule advanced coverage.

## Verification (owner)

```powershell
git pull --ff-only origin feature/carthago-reliability-hardening
dotnet test .\Carthago.Cli.Tests\Carthago.Cli.Tests.csproj -c Release --filter "FullyQualifiedName~OfflineRuleQueriesTests"
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~IndustrialBatchRegistryQualityTests|FullyQualifiedName~ContentPackCatalogTests|FullyQualifiedName~RuleTuningCatalogTests"
.\scripts\verify-rule-batch.ps1 -First 999 -Last 1000
python scripts/test_rule_catalog_ids.py
python scripts/build_rule_catalog.py
python scripts/build_docs_index.py
```

The new CLI regression cases exercise the numeric boundary, future IDs, Int32 overflow, zero, leading-zero aliases, non-ASCII digits, pack separation, archive lookup, paging and ledger parsing. Existing Windows registry/content-pack tests cover the R1000 boundary. No .NET or PowerShell execution was performed in the editing environment; the generated catalog must be refreshed from a complete checkout. Do not infer detector accuracy from ID compatibility.

The full Windows verifier (`verify-local.ps1`) now reads three-or-more ASCII digits and rejects invalid registry aliases. This removes the false catalog-inventory mismatch where the benchmark included R1000 but the source-side regex excluded it. Its original minimum-preservation floor and benchmark quality gates remain unchanged.

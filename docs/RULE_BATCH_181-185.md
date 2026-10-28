# R181–R185 — DNS provenance and bounded-state hardening

**CANDIDATE / UNVERIFIED — 40 new advanced xUnit facts authored, zero executed.**

| Rule | Scope | Facts |
|---|---|---:|
| R181 | Source+resolver scoped bounded DNS ANY burst, duplicate ID and out-of-order rejection | 8 |
| R182 | Attributed AXFR/IXFR, TCP transport, external boundary; reject internal secondary and Info-only | 8 |
| R183 | Distinct high-entropy DNSSEC subdomains per source/resolver/root, bounded and duplicate-resistant | 8 |
| R184 | External resolver, typed PTR reverse names, distinct-name enumeration and source isolation | 8 |
| R185 | Exact OAST/canary/metadata DNS root, no packet-Info promotion, duplicate rejection and redaction | 8 |

**Source:** `Carthago/Engine/Rules/Expansion/R181_*.cs` through `R185_*.cs`, `NetworkBatch181185Window.cs`, and correction to `NetworkBatch176180Evidence.cs` for case-insensitive DNS application protocol and IP version validation. **Tests:** `Carthago.Tests/R181AdvancedAccuracyBatchTests.cs` through `R185AdvancedAccuracyBatchTests.cs`. A separate earlier correction commit `9c93dfe6849763f55f44c1fc7e899e4c239f9e07` fixed C# quote escaping in the unexecuted R177 multipart fixture.

**R176–R185 total: 10 rules, 85 new advanced facts authored, zero executed.** Tests remain discoverable by the unchanged single `scripts/verify-all-rule-batches.ps1` deferred Windows entry point. No build, xUnit, replay, benchmark, frozen holdout, GitHub Actions or Windows runner was invoked. Confidence floors, thresholds, runtime policies, approval/baseline gates and frozen holdout unchanged. Frozen R102 V1 remains FAILED 4/6; V2 awaits independently sourced and reviewed PCAP. DNS telemetry cannot prove attack success. Operational capture, false-positive, out-of-order and concurrency behavior remains unverified. **Next R186–R190, then R191–R195.**

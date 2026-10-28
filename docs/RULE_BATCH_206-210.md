# R206-R210 — Git and package-client HTTP evidence

**CANDIDATE / UNVERIFIED — 55 advanced xUnit facts authored, zero executed.**

| Rule | Narrow candidate change | Authored facts |
| --- | --- | ---: |
| R206 | Require typed Git smart-HTTP upload-pack GET/POST, Git client, external unofficial host, bounded per-source replay/out-of-order guard; accept remotes without .git suffix. | 11 |
| R207 | Require typed receive-pack discovery/POST with Git client, external unofficial host, bounded replay/out-of-order guard. | 11 |
| R208 | Require typed GET/HEAD to a recognized npm/PyPI/NuGet registry request shape with matching client and unofficial host; bounded replay guard. | 11 |
| R209 | Require observed npm/node HTTP request to a /beacon path with explicit install-hook event/phase query rather than packet Info claims. | 11 |
| R210 | Require typed pip/poetry GET/HEAD to a Python package index/artifact path at an unofficial external host. | 11 |
| **Total** | **Five consecutive candidate rules** | **55** |

**Production files:** `Carthago/Engine/Rules/Expansion/R206_GitCloneFromUnknownExternalHostRule.cs` through `R210_PypiPackageDownloadFromRareDomainRule.cs`, `NetworkBatch206215Evidence.cs`, and scoped host/path redaction in `HttpApiPrecisionDetectionRuleBase.cs`. Reused existing instance-owned `NetworkBatch201205Window`; no new unbounded static state.

**Advanced tests:** `Carthago.Tests/R206AdvancedAccuracyBatchTests.cs` through `R210AdvancedAccuracyBatchTests.cs` and `NetworkBatch206210Context.cs`. Eleven independent facts per rule cover typed positive, official provider, packet-Info spoofing, contradictory Host, contradictory UDP, wrong method, duplicate packet ID, out-of-order source observation, independent source, query-secret evidence redaction and exact confidence/default-mode contract. **All are authored, not executed.**

**Candidate commits:** source `15ae3a5aeda96e8c3ad7e428ed0ac725d4809e63`; valid Git remote path correction `335bfd1cb7c0f104bb51c77f6fd55c7fdf105fe3`; tests `e1a60edaaa1fbe9e45e1094760bf4573b1bcb5b5`.

## Boundaries and risks

Packet Info cannot prove Git operations, install-hook execution, package trust, download completion, or exfiltration. R209's query event is an observable HTTP label, not proof of npm lifecycle execution. Git and package client process metadata may not be available from the live packet adapter. The existing `PacketHandler` parses cleartext HTTP, not decrypted HTTPS; HTTPS-labeled synthetic records are **contract-only**, not evidence of live visibility. The legacy baseline first-seen fallback remains in place; first-seen is **not asset approval** and the existing readiness/approval gates remain authoritative. Static rule-owned cooldowns are unchanged; new observation state bounds duplicate/out-of-order inputs.

No builds, xUnit, development replay, benchmark, holdout, CI or Windows runner were executed. The single deferred verifier `scripts/verify-all-rule-batches.ps1` remains unchanged. R102 frozen V1 FAILED at 4/6; V2 requires independent licensed PCAP and analyst review. R102 80%, R118 86%, R163 84% floors, configured thresholds, default Shadow/Disabled/Alert modes, asset approvals, baseline readiness and frozen evidence unchanged.

**Next contiguous subbatch: R211-R215; next ten after completion: R216-R225.**

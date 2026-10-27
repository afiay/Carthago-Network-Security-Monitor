# R171-R175 HTTP precision candidate — 2026-10-28

**CANDIDATE / UNVERIFIED.** No builds or tests executed.

| Rule | Scope | Advanced cases authored, unexecuted |
| --- | --- | ---: |
| R171 | Attributed SOAP request, exact action tokens, redacted action | 9 |
| R172 | Scanner/browser User-Agent token boundaries, contradictory header rejection, privacy | 9 |
| R173 | Cross-origin management API preflight, requested method and sensitive header names | 9 |
| R174 | Typed WebDAV methods, explicit deep discovery or management-path context | 9 |
| R175 | Structured Content-Length and Transfer-Encoding consistency checks | 10 |
| **Total** | | **46** |

Source: `Carthago/Engine/Rules/Expansion/R171_*Rule.cs` through `R175_*Rule.cs`, `NetworkBatch171175Evidence.cs` and scoped event-builder path redaction. Tests: `Carthago.Tests/R171AdvancedAccuracyBatchTests.cs` through `R175AdvancedAccuracyBatchTests.cs`, using `NetworkBatch166175Context.cs`. Tests cover positive and benign equivalents, contradictory or partial metadata, duplicate records, confidentiality and unchanged policy.

New evidence avoids persisting raw SOAPAction, User-Agent, sensitive paths and query values. Duplicate and out-of-order observations are rejected by bounded per-rule-instance state. These changes preserve configured confidence floors and default modes: R171 Shadow/74%, R172 Shadow/68%, R173 Shadow/74%, R174 Shadow/74%, R175 Alert/82%.

Known limitations: SOAP action names, User-Agent claims and CORS preflights do not prove exploitation. WebDAV operations may be legitimate. HTTP framing conflicts do not establish successful desynchronization. Capture-adapter provenance and real-world false positives remain unverified; strict gates may reduce recall.

Single deferred Windows verification entry point: `scripts/verify-all-rule-batches.ps1`, unchanged. No xUnit, builds, replay, benchmark, holdout, runner or CI executed. No baseline readiness, approvals, thresholds, runtime policy or frozen data changed. Frozen V1 R102 still FAILED at 4/6; V2 pending independent reviewed licensed PCAP evidence.

**R166-R175 total: 91 authored advanced test facts, zero executed.**

**Next batches: R176-R180 and R181-R185.**

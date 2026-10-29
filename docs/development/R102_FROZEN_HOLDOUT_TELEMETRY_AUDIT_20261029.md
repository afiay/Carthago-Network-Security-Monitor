# R102 frozen synthetic holdout - telemetry provenance audit

## Status (October 29, 2026)

**Holdout result: FAILED (not certified).** The operator executed `scripts/evaluate-holdout.ps1 -NoBuild` on CARTHAGE after the full local xUnit run (4,940/4,940 passed). The frozen holdout evaluated 12 samples (6 malicious, 6 benign). Four of six malicious expectations were recognized, two R102 DNS TXT scenarios were not recognized, and no benign alerts were observed. All six runtime profiles generated 0 of 6 expected malicious **alerts**. The holdout ended with three reported issues (two unmatched R102 sample expectations plus the aggregate 4/6 recognition gate). No confidence/alert promotion is authorized by this result.

## Read-only source inspection

Frozen manifest: `docs/holdout-evaluation-manifest.json` (schema v1, frozen 2026-10-26). The two missed files are:

- `Tests/RuleReplayHoldout/malicious/holdout-r102-multistage-encoded-txt.json`
- `Tests/RuleReplayHoldout/malicious/holdout-r102-second-client-encoded-txt.json`

Each has three long, distinct, high-entropy DNS TXT QNAMEs and `protocol: DNS`, `applicationProtocol: DNS`, destination port 53, and an IP source/resolver. **None declares either `isUdp: true` or `isTcp: true`.** Those boolean properties therefore remain false on deserialization of a default `TrafficRecord`.

`NetworkBatch096100Evidence.Dns` is R102's mandatory telemetry gate: it requires syntactically valid DNS fields **and a coherent transport** (`IsUdp && !IsTcp` or `IsTcp && !IsUdp`, with appropriate protocol/flags). It returns false when neither transport bit is set. R102's `EvaluatePrecision` returns `NoMatch` immediately when that guard fails, before applying long-label/entropy/correlation thresholds. The benchmark does not infer or synthesize transport flags from `protocol: DNS` or port 53.

Development replay controls such as `Tests/RuleReplaySamples/malicious/r102-distinct-txt-burst-candidate.json` explicitly provide `isUdp: true`, a source port and IPv4 metadata; existing unit tests use a DNS record builder that also sets `IsUdp = true`. These are **different, non-holdout samples** and support the transport-gate diagnosis. No assertion is made that merely adding UDP would prove the holdout's traffic was UDP, that R102 would necessarily emit an alert, or that the entire holdout would then pass.

## Safety and data-separation decision

1. **Do not mutate the frozen twelve v1 holdout files, labels, hashes or manifest.** The hash pinning detects exactly that kind of post-result replacement. The v1 failure remains recorded.
2. **Do not infer protocol attribution** from destination port, DNS strings, qtype, or synthetic analyst labels. That would undermine real detector precision and might raise benign false positives.
3. **Do not lower thresholds or override R102 precision policy** in order to turn a detector no-match or an alert-shadowed result into a pass.
4. A clean next independent evaluation should use a newly versioned, externally grounded fixture set with an explicit metadata provenance contract: verified transport, query/response direction, capture timestamp, parser attribution, stable record IDs, negative controls, and a separately pinned manifest. Design and freeze it **before** running it; do not edit v1 to score green.
5. Future replay output can report structured missing telemetry diagnostics. Such reporting may improve triage but must never change detection behavior or gate criteria.

## Guarded test added

`Carthago.Tests/R102AdvancedAccuracyBatchTests.cs` now has `Structured_Txt_Without_Transport_Identity_Fails_Closed`: a fresh synthetic high-entropy TXT name without either UDP or TCP attribution must not match; a separately created coherent UDP record remains eligible for an unsigned R102 candidate. No frozen holdout data is copied or tuned. **Focused test verified on CARTHAGE at commit `a06a848` (October 29, 2026):** `dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~R102AdvancedAccuracyBatchTests"` completed **8/8 passing, zero failures, zero skips**. Release build succeeded with **8 warning occurrences** (seven nullable source warnings and one existing xUnit analyzer warning, outside the modified R102 test). The run checks the source-level guard but does not re-run or pass frozen holdout v1.

## Relationship to other certification gates

- Full xUnit suite: **4,940/4,940 passed** at previously checked-out commit `498b8b0` (before this additional regression test).
- Development replay: 146 fixtures processed; **four blockers** remain R343, R295, R275, R163.
- Frozen v1 holdout: **FAILED** on R102 telemetry completeness; zero benign alerts but zero alert-level recall. The metric is from synthetic, not independently sampled field data.
- Windows producer/IPC work: separately tested in isolation, without OS transport authentication. This holdout diagnosis does not authorize service deployment, command-line logging or receipt promotion.

## Diagnostic-only replay improvements and v2 source controls (2026-10-29)

New `DnsReplayTelemetryDiagnostics` provides bounded, field-name-only error codes for a structured DNS replay record. It never mutates the packet, infers transport or creates signed/alert evidence. Codes include `DNS_TRANSPORT_UNATTRIBUTED`, `DNS_TRANSPORT_CONFLICT`, `DNS_TRANSPORT_FLAGS_CONFLICT`, `DNS_PORT_53_MISSING`, `DNS_QNAME_MISSING`, `DNS_QTYPE_MISSING` and `DNS_IP_INVALID`. The benchmark records `inputRecordsInspected`, `inputRecordsWithIssues` and sorted `inputTelemetryIssueCodes` for expected DNS rules. When all evaluated records for a missed expected DNS rule contain input errors, the report calls the outcome `InvalidInputTelemetry`; if at least one properly formed DNS record is present, a non-match remains `NoMatch`. No other rule-evaluation, confidence or alert semantics are altered.

Both holdout evaluators call `scripts/inspect-replay-input-telemetry.ps1` to show stable codes and counts; the normal benchmark Markdown also has a separate structured-DNS-input section. The original v1 frozen JSON files and Git hash manifest remain unchanged and the **v1 result is still FAILED**. The new reporting is not a holdout fix and cannot be presented as improved detection recall.

The existing independent **v2** holdout workflow predates this increment and already requires PCAP/TShark-verified UDP/TCP, query name/type and packet frame attribution. This increment strengthens its source audit to reject unexpected fixture fields, invalid typed transport flags, misleading expected labels and changed confidence expectations. A new read-only readiness script checks the pending four external R102 source slots and verifies all eight retained v1 blob hashes. It cannot assert that reviewed PCAPs exist, that malicious labels are independently validated, or that privacy/license approval has been granted. V2 remains `PENDING_EXTERNAL_CAPTURE_AND_REVIEW` until those independent source conditions are actually met.

**Verification status:** C# changes, diagnostic tests, PowerShell script changes and the added v2 contract tests are committed but **not yet built or executed on CARTHAGE**. The last confirmed focused R102 run is 8/8 at earlier commit `a06a848`. The last confirmed full-suite run is 4,940/4,940 at earlier commit `498b8b0`. The replay and frozen v1 holdout failures remain recorded. Do not silently freeze or rerun holdout v2 with synthetic guesses.

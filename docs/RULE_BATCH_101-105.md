# Rule hardening batch 21 — R101–R105

**Status: CANDIDATE — UNVERIFIED.** Five existing precision detectors updated, one shared typed-evidence helper added, one test-context factory and **35 advanced xUnit facts** (seven per rule). No build, xUnit, replay, benchmark, holdout, Windows runner or other automated test was executed.

| Rule | Previously observed risk | Candidate hardening | Advanced facts |
| --- | --- | --- | ---: |
| **R101 — DNS CNAME Chain Abuse** | The previous implementation counted every occurrence of the word `CNAME` in a response, including disconnected records, without confirming DNS transport consistency. | Require a coherent DNS response and calculate **longest connected alias path** from bounded answer tokens; reject cycles, conflicting edges, excessively long answer text and missing answer context. Retain existing threshold, provider-aware suppression, severity and confidence. | 7 |
| **R102 — DNS Tunneling via Long Labels** | A qname grafted onto an unrelated protocol could count as a DNS question; repeated delivery of the same record ID could increment suspicious-query windows and strengthen confidence. | Validate attributable DNS question transport before evaluation and deduplicate packet IDs per detector instance before mutating existing suspicious-query state. Preserve monolithic-TXT support, entropy/length/repeat thresholds, existing R102 **80%** confidence floor, cooldown and existing labeled replay files. | 7 |
| **R103 — DNS Beaconing With Stable Interval** | Replaying a single record ID could fabricate a stable cadence. Contradictory DNS/HTTP fields were not rejected before window mutation. | Require coherent DNS question and distinct packet IDs before adding timestamps; preserve sample-count, interval, jitter, distinct-query and cooldown policies. | 7 |
| **R104 — First-Time Cloud Storage Upload** | An in-memory first-seen fallback treated baseline storage failures as proof of novel provider use. Untrusted packet `Info` could supply upload metadata, and raw URI evidence could expose query tokens. | Require typed outbound HTTP upload shape and host/transport consistency, use parser-attributed upload metadata only, fail closed when persistent baseline is unavailable, and omit raw HTTP URI from R104 event evidence. Preserve first-seen semantics, thresholds, learning/readiness and asset-approval policy. | 7 |
| **R105 — Large Upload to Personal Cloud Provider** | Transfer size alone could qualify a download; duplicate packet delivery could inflate windowed upload bytes; free-form `Info` could act as upload metadata and raw URI evidence could expose secrets. | Require a structured outbound HTTP POST/PUT/PATCH request, deduplicate packet IDs before counting volume, use typed upload metadata for enterprise-provider qualification and omit raw URI evidence. Preserve single/window byte thresholds, provider classification and severity/confidence. | 7 |

## Scope and test matrix

`NetworkBatch101105Evidence.cs` supplies bounded CNAME chain parsing and HTTP-upload provenance checks. `CloudSaasPrecisionDetectionRuleBase.MatchCloud` gained an **optional, default-false** `redactHttpUri` parameter; only R104/R105 opt in. Other cloud rules retain their existing event schema and behavior. No generic detector, rule registry, configuration value or global confidence calculation was changed.

Five `Carthago.Tests/RNNNAdvancedAccuracyBatchTests.cs` files and `NetworkBatch101105Context.cs` add genuine positive examples, close benign negatives, malformed/disconnected CNAME aliases, DNS TXT and beacon behavior, contradictory transport, duplicated packet IDs, source/provider isolation, stateful window accumulation, failed baseline persistence, cancellation and sensitive-query suppression. The DNS replay samples already in `Tests/RuleReplaySamples/` were **inspected but not edited**: no new replay labels were manufactured and no frozen holdout was changed.

`scripts/verify-all-rule-batches.ps1` remains the sole deferred Windows verification entry point. It discovers these five test classes automatically. No separate runner or CI execution was started.

## Explicit limitations and acceptance risks

- **R101:** CNAME chains are inferred from bounded textual DNS-answer tokens, not a complete typed RR graph with transaction-level query anchoring. A connected sequence inside an unrelated answer set could still be counted. Capture adapter parsing and actual response formats must be inspected during later acceptance.
- **R102/R103:** Per-instance record-ID deduplication is bounded to the existing 10-minute helper; shared static windows can survive detector-instance recreation. Replay-loader normalization of DNS transport fields is not yet verified. The already-labeled R102 replay samples lack some explicit packet fields in their JSON, so replay ingestion must be checked before treating any failure as detector regression.
- **R104:** A baseline-store I/O failure now prevents first-seen matches instead of using the former in-memory fallback. Older tests using the default baseline directory may require isolated test stores; no default storage, readiness or promotion policy was weakened.
- **R105:** HTTP request length/L4 length is used as a proxy for uploaded bytes. It is **not** a verified application-level transferred-byte counter and may overstate outbound payload. Parser direction, TCP reassembly, duplicate delivery across rule instances and long-running memory behavior remain acceptance requirements.
- **Cloud privacy:** Raw HTTP request URI evidence is omitted for R104/R105, but host/provider and process identity remain visible; this is **not** full privacy anonymization. Other CloudSaas rules still use their existing URI-evidence behavior. The source/host/SNI consistency gate may reject some legitimate proxy and TLS-decrypted captures.
- **DNS privacy:** R101–R103 continue to include observed DNS qnames in the established DNS precision event pipeline. Retention and privacy review remains separate.

The exact configured confidence floors **R102=80%, R118=86%, R163=84%**, existing rule thresholds, Shadow/Disabled policy, baseline-readiness/asset-approval safeguards, frozen holdout and unrelated rule behavior were not intentionally modified. No accuracy, recall, F1, acceptance or promotion claims can be made from unexecuted tests.

**Status: CANDIDATE — UNVERIFIED until the user explicitly says “now it's test time.”**

**Next batch to author: R106–R110.**

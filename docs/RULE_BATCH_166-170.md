# R166-R170 HTTP secret and XML precision candidate — 2026-10-28

**CANDIDATE / UNVERIFIED.** No builds, xUnit, replay, benchmark, frozen holdout, CI or Windows runner executed.

| Rule | Narrowly scoped source change | Advanced xUnit facts authored / unexecuted |
| --- | --- | ---: |
| R166 | Parser-attributed inbound HTTP, exact secret-file allowlist, fixed redacted path evidence, duplicate/late-record rejection | 9 |
| R167 | Anchored Git internals, excludes .github/.gitignore, typed inbound transport and source-scoped replay guard | 9 |
| R168 | Backup/dump/database token boundaries plus archive suffix; avoids incidental 'db' substrings and ordinary reports | 9 |
| R169 | POST login failure with typed HTTP, anchored admin login route, bounded per-instance source/target/path event counts and duplicate-ID rejection | 9 |
| R170 | XML content type plus **observable query-encoded** DOCTYPE+ENTITY+SYSTEM and external reference; no Info-only body inference | 9 |
| **Total** | **Five consecutive rules** | **45** |

Production changes: `Carthago/Engine/Rules/Expansion/R166_*Rule.cs` through `R170_*Rule.cs`, new `NetworkBatch166170Evidence.cs`, scoped event redaction in `HttpApiPrecisionDetectionRuleBase.cs`. Tests: `Carthago.Tests/R166AdvancedAccuracyBatchTests.cs` through `R170AdvancedAccuracyBatchTests.cs`, shared `NetworkBatch166175Context.cs`, and a targeted legacy R170 fixture correction in `HttpApiPrecisionRuleTests.cs` to encode the XML in observable URI metadata instead of pretending that Info is the HTTP body.

Evidence boundaries: HTTP requires attributed TCP, application protocol, coherent HTTP authority and valid endpoints. Cross-boundary R166-R169 require inbound requests to protected address space. R169 uses a bounded per-rule-instance window, rejects duplicate and late record IDs and never persists a credential or username in new evidence. The available authentication-failure indicator is still a bounded parser summary (Info), **not** a trusted HTTP response-status field; confirm adapter provenance before promotion. R170 cannot inspect XML request bodies because TrafficRecord has no body field. It now matches only explicit XML in the observed request target; this is intentionally low-recall but avoids fabricating payload proof.

Privacy: R166-R170 use fixed `http.path=[REDACTED]` in both rule-owned and shared structured evidence, and hashed path keys for cooldown. Raw query secrets, Git branch names and backup filenames are not intentionally retained by these new rule-owned fields. The existing common event pipeline should be audited for any unrelated raw packet metadata before field use.

**Deferred single Windows verification:** `scripts/verify-all-rule-batches.ps1`, unchanged; 45 authored cases, **zero executed**. These cases cover positive detections, close benign traffic, protocol and Host contradictions, duplicate/out-of-order observations, source isolation, privacy and unchanged confidence/mode policy. No new replay positives were manufactured because the current replay schema cannot attest an XML body.

Existing floors and modes retained: R166 Alert/78%, R167 Alert/80%, R168 Shadow/72%, R169 Shadow/74%, R170 Alert/80%. No thresholds, asset approvals, baseline-readiness or frozen holdout changed. Frozen V1 R102 remains FAILED 4/6; V2 awaits independent licensed PCAP capture, analyst review and approval. All new cases remain **CANDIDATE / UNVERIFIED**.

**Next consecutive batch: R171-R175.**

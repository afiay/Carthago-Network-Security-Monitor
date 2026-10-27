# Rule hardening batch 18 — R086–R090

**CANDIDATE — UNVERIFIED.** Five rule adapters, one shared evidence component, and **35 authored advanced xUnit facts** (seven per rule). No builds, xUnit, replay, holdout, Windows runner or any automated project verification executed.

| Rule | Audited issue in legacy detector | Candidate evidence requirement | Facts |
| --- | --- | --- | ---: |
| **R086 — Path Traversal / LFI Pattern** | Generic packet payload/text inspection flagged `../` or filenames without a meaningful exploit path and could copy sensitive original text into evidence. | Valid structured HTTP request, bounded at-most-twice-decoded URI and **both** an upward-path component and a sensitive target (`etc/passwd`, `etc/shadow`, `windows/win.ini`, `WEB-INF/web.xml`). | 7 |
| **R087 — Webshell Upload Pattern** | `filename=`, `.php`, `upload`, `shell` or `cmd` in mixed descriptive text could generate a critical alert, with raw excerpts. | Structured HTTP POST/PUT/PATCH with a complete, valid multipart Content-Type header and independently parsed `HTTP/SCRIPT_UPLOAD_OBSERVED` classification. This is a suspicious *script-upload request*, not proof a webshell was installed or executed. | 7 |
| **R088 — Suspicious Deserialization Payload** | Standalone `rO0AB`, `serialized` and technology terms in broad packet Info led to unproven deserialization claims. | Valid structured HTTP request, parser classification `HTTP/DESERIALIZATION_PAYLOAD_OBSERVED` and recognizable language-specific serialized-payload marker in the observed request target. | 7 |
| **R089 — Command Injection Pattern** | Generic `&&`, pipes, shell keywords or process/Info text caused claims and could expose payloads. | Valid structured HTTP request target containing an actual command separator or substitution boundary *plus* a recognized shell command, with up to two bounded URI-decode passes. | 7 |
| **R090 — Reverse Shell Payload Indicator** | Generic terms (`reverse shell`, `powershell -enc`, `meterpreter`) and unstructured Info could generate critical claims. | Valid structured HTTP request target containing a concrete reverse-connection execution expression (such as `bash -i ... /dev/tcp/host/port` or `nc -e /bin/sh host port`). A successful connection or executed shell is **not** established. | 7 |

## Shared implementation and evidence privacy

`NetworkBatch086090Evidence.cs` calls the already-established `NetworkBatch081085Evidence.HttpRequest` gate, validates the bounded request target, refuses invalid URI encoding and expansions exceeding 4096 characters, and limits regex matching to 50 milliseconds with culture-invariant semantics. It never copies raw `Info`, request URIs, query strings, payloads, cookies, passwords or headers into DetectionEvent summaries, descriptions or evidence. It reuses existing confidence/intelligence evaluation and per-instance `NetworkBatch081085Dedup` record-identity suppression. No new dependencies were added.

Seven separate `[Fact]` xUnit cases per rule cover genuine positives, encoded/evasive variants, convincing benign negatives, free-text-only false positives, missing/contradictory protocol and HTTP attributes, replayed record identities and repeated observations, cancellation, excessive inputs, and private-content redaction. No test command was invoked.

## Limitations and acceptance risks

**Capture compatibility must be verified before promotion.** Some packet-capture paths may omit `HttpUri`, complete headers, or `ApplicationService` classifications. In particular, `SCRIPT_UPLOAD_OBSERVED` and `DESERIALIZATION_PAYLOAD_OBSERVED` are *proposed parser contracts*, not verified outputs of any current capture provider; both corresponding rules intentionally fail closed when these fields are absent. The current `TrafficRecord` does not contain upload-body content or an independently attested execution outcome, so R087/R088 cannot claim actual payload upload/execution from a real packet without parser integration.

The deliberately narrow request-target patterns sacrifice recall: payloads confined to bodies, encrypted HTTPS without inspection, HTTP/2, unsurfaced headers, alternative encoding chains and uncommon shell/SQL grammar may not match. R086 sensitive paths can appear in legitimate security scans and tutorials. R087 multipart/form classification alone does not imply harm and requires trustworthy external parsing. R088's recognized markers are heuristics, not confirmed exploit gadgets. R089/R090 patterns indicate suspicious text in an observed request, not remote execution.

The deduplication state is bounded, local to each rule instance and lost on process restart. Timestamp and URI consistency depend on trusted capture timestamps. Per-rule runtime mode, suppression and confidence policies continue to be resolved in the existing execution pipeline.

## Preserved governance

Rule IDs, categories, severities, config keys and enabled defaults are unchanged. No rules.json, confidence floors **R102=80%, R118=86%, R163=84%**, Shadow/Disabled policy, asset approval, baseline readiness, frozen holdout, or unrelated detector implementation was changed. No malicious fixtures were relabeled and no synthetic accuracy score is claimed.

`scripts/verify-all-rule-batches.ps1` remains the **sole** Windows verification entry point for later explicit approval, automatically discovering all five `RNNNAdvancedAccuracyBatchTests.cs` files. Do not run it until the owner says **"now it's test time"**.

**Next sequential batch to author: R091–R095.**

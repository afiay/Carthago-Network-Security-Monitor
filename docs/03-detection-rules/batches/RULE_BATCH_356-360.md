# R356–R360 — DevOps HTTP provenance and token-shaped observations

**CANDIDATE — UNVERIFIED** · Authored 2026-10-28 · Existing branch feature/carthago-reliability-hardening.
No builds, xUnit tests, replays, benchmarks, holdouts, CI, runners or production capture were executed.
**63 rule xUnit scenario invocations + 15 parser/privacy scenario invocations = 78 authored, ZERO executed.**
Synthetic positives and synthetic parser flags do not establish field accuracy.

## Five-rule dispositions and evidence boundary

| Rule | Development disposition | Narrow eligible behavior | Missing provenance / material risk |
| --- | --- | --- | --- |
| **R356 Jenkins crumb issuer** | **OPERATIONAL request shape; BLOCKED enumeration intent** | Parsed TCP/HTTP GET to a terminal /crumbIssuer/api/json or /xml, including Jenkins context prefix. Reject ambiguous origin targets, other methods and lookalike paths. | Normal Jenkins clients fetch CSRF crumbs. A single request is **not** enumeration or malicious activity. Host identity, authorization and intent are not verified. Existing Medium/Alert/74/threshold-1 profile unchanged. |
| **R357 TeamCity auth bypass** | **CONDITIONAL suspicious request shape; BLOCKED bypass outcome** | Parsed inbound-external GET/POST to TeamCity REST/admin paths **with** ..; or a specific jsp= path-override shape. Normal /app/rest requests and Info-only CVE text fail closed. | No authenticated TeamCity identity, HTTP response or authorization audit. Request-shape observation does **not** prove successful bypass or a particular CVE. Existing High/Alert/78/threshold-1 and boundary requirement unchanged. |
| **R358 Bamboo artifact bulk** | **CONDITIONAL HTTP burst; BLOCKED successful downloads** | Parsed GET to an /artifact/<nonempty> path; existing five-observation/20-minute rule window remains mandatory. | The existing counter counts **requests**, not distinct successful responses, artifact bytes, or exfiltration. Client retries and CI jobs can cause bursts; no trusted response/outcome producer. Existing Medium/Alert/74/threshold-5 unchanged. |
| **R359 Azure DevOps PAT in URL** | **CONDITIONAL cleartext parser observation; HTTPS unsupported** | Parser-derived HttpAzureDevOpsPatUrlObserved for a 52+-character token-shaped named query parameter, plus bounded origin-form HTTP and dev.azure.com or *.visualstudio.com HTTP Host. | Pattern is **not** credential validity; Host is client supplied. TLS/SNI, Info and imported JSON cannot assert the flag. Matching query values are sanitized from retained HttpUri before record construction; rule event http.path is redacted. |
| **R360 CircleCI API token exposure** | **CONDITIONAL cleartext parser observation; HTTPS unsupported** | Parser-derived HttpCircleCiTokenPatternObserved for exactly one complete Circle-Token HTTP header with a 40-hex token-shaped value, plus bounded origin-form HTTP and CircleCI HTTP Host. | Generic Authorization, Info and provider words cannot assert the flag. Duplicated, truncated or malformed header sections fail closed. Value is redacted before header retention; no token validity, use or exfiltration proof. |

## Capture provenance and privacy

- PacketHandler.HttpLight performs bounded, best-effort inspection of early TCP payload bytes; it is **not** general HTTP stream reassembly or authenticated server telemetry. New token flags are set only for client-to-server (c2s) parser results and have internal setters.
- R359's parser classifies a named query token shape before redacting it from the retained HTTP path. R360's Circle-Token value is redacted before storing header diagnostics. Both flags reject incomplete header blocks; R360 rejects duplicate Circle-Token headers.
- Event evidence http.path is redacted for **all R356–R360**. This does not imply all possible sensitive query values are removed from TrafficRecord.HttpUri for every rule; broader capture-wide URI sanitization remains a separate privacy task. Do not log or export raw synthetic token strings from unit fixtures.
- DevOpsHttpEvidence rejects absolute-form, authority-relative, encoded-path, traversal and control-character request targets before narrow path matching. HTTP Host remains untrusted and is never treated as cryptographically authenticated identity.
- R357's bypass-shape check is a **probe heuristic**, not a TeamCity exploit validator. R356 and R358 are potentially noisy under normal CI use; production promotion requires approved asset/identity context, verified benign/malicious holdouts and review. No new alert authorization is granted.

## Authored, not executed: scenario inventory

- **R356 — 15**: JSON/XML crumb API positives; five endpoint lookalikes; POST negative; TLS-only and missing-method negatives; three ambiguous request targets; event query redaction; unchanged profile.
- **R357 — 13**: two specific bypass-shaped inbound request positives; four normal/unrelated admin negatives; DELETE, internal-only, TLS-only, absolute target and Info-only negatives; event query redaction; unchanged profile.
- **R358 — 11**: fifth request matches only after four below-threshold observations; independent four-request negative; four invalid artifact paths; POST, TLS-only and absolute target negatives; event redaction; unchanged five-observation threshold.
- **R359 — 12**: synthetic parser-flag positives for provider host/subdomain; Info-only and raw URI without flag negatives; three spoofed-host negatives; TLS, absolute target, contradictory UDP negatives; event query redaction; unchanged profile.
- **R360 — 12**: synthetic parser-flag positives for CircleCI host/subdomain; spoofed-host negatives; Info-only and redacted-header-only negatives; TLS, UDP, absolute target and missing-method negatives; event redaction; unchanged profile.
- **HTTP parser/privacy — 15**: four Azure query-key variants, three invalid/short queries, incomplete Azure header section, valid Circle-Token and redaction, two invalid lengths, duplicate and incomplete Circle-Token sections, generic Authorization negative, JSON import cannot set flags.

Source: Carthago/Engine/Rules/Expansion/R356_*.cs through R360_*.cs; shared DevOpsHttpEvidence.cs, EvidenceDrivenPrecisionRuleBase.cs, CloudDevPrecisionDetectionRuleBase.cs, Carthago/Models/TrafficRecord.cs and Carthago/Services/PacketHandler.cs.
Tests: Carthago.Tests/NetworkBatch356360Context.cs, R356AdvancedAccuracyBatchTests.cs through R360AdvancedAccuracyBatchTests.cs, and DevOpsHttpParserProvenanceTests.cs.

## Frozen evidence and verification

Preserved without modification: R102 **80%**, R118 **86%**, R163 **84%** confidence floors; all runtime modes, approvals, baseline and privacy gates.
R102 frozen V1 **FAILED 4/6**, V2 **PENDING_EXTERNAL_CAPTURE_AND_REVIEW**.
Four replay expectation blockers (R343/R295/R275 trusted audit and R163 confidence) remain unresolved.
Earlier xUnit/replay results do **not** verify this batch.

Source commit: 3d3126d92bee347598d3e2a44c354b8e3b31e1df.
Tests commit: 31205081dea8e30eac04f110b8c48bbb3d03f7fe.
Docs/ledger commit: the commit containing this document.

Publication requires a single non-forced update_ref using the freshly rechecked remote HEAD as expected_sha; never publish partially, force-push, create another branch or trigger CI/tests.
**Next sequential unfinished batch: R361–R365**, only after safe publication.

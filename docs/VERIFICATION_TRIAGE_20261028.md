# Local verification triage — 2026-10-28

**Branch:** `feature/carthago-reliability-hardening`  
**Status:** 4,797/4,797 xUnit VERIFIED on CARTHAGE; replay-expectations FAILED (4); no certification or ledger promotion.

## Observed local evidence

The user-supplied local verification at `12ce0d2` (before the repairs below) completed 4,733 xUnit cases: **4,675 passed, 58 failed, 0 skipped**. The benchmark stage ran, but `verify-local.ps1` failed the `tests` and `replay-expectations` stages. All figures below belong to that pre-repair run; **no post-repair tests have been executed or verified**.

Failure triage, by primary symptom (58 total):

| Failure group | Count | Engineering disposition |
| --- | ---: | --- |
| Sensitive host, DNS and transfer-destination evidence | 28 | Shared event-boundary redaction implemented; needs runtime confirmation |
| Legacy positives, negative behavior, HTTP/DNS provenance, or other behavioral assertions | 20 | Typed test fixtures improved; other mismatches require individual analysis |
| Replay/paired benchmark expectations | 5 | Blocked pending capability-grounded fixtures and trusted producers |
| GitHub/GitLab Info-token test expectations | 2 | Tests now reject untrusted descriptive token strings |
| R178 default mode expectation | 1 | Aligned test with existing Alert-mode contract |
| Content-pack evidence assertion | 1 | Still open; investigate generated pack output |
| R164 evidence key | 1 | Restored safe `redirect.target` key; never store raw redirect URL |

## Fixes and scope

- `PrecisionTelemetryDetectionRuleBase`: apply rule-scoped host and destination redaction to the initial event projection and forwarded structured evidence, while preserving original capture records and detection inputs.
- `R164`: avoid classifying exact same-host internal returns as malicious; retain cross-host internal and lookalike redirects. Restore a privacy-safe static `redirect.target` evidence value.
- DNS, HTTP/API, CloudDev and IdentityAccess legacy tests: provide properly attributed packet identity and transport metadata; use valid DoH and DoT observations in positive fixtures.
- R275/R343 legacy tests: assert fail-closed when only ordinary device-code HTTP or WinRM Info text is available.
- Added cross-projection evidence privacy regressions for R179, R204 and R248.

These changes do **not** lower confidence floors, bypass environment approvals, turn Shadow into Alert or enable rules from unauthenticated Info text.

## Replay caveat and next validation

Five replay expectations are still known to disagree with the actual capability contract:
- **R343** requires trusted WinRM command audit, not an Info string.
- **R295** requires Kubernetes API-server/exec audit, not a path alone.
- **R240** requires parser-derived Modbus write-function attribution, not an Info description.
- **R275** requires independently corroborated device-code abuse, not simple device-code initiation.
- **R163** replay expects confidence 0.65 while the observed confidence was 0.62, below the protected 0.84 precision floor.

The benchmark previously identified **44/48 raw malicious matches** but only **4/48 Enterprise alerts**; 40 were routed to Shadow. These figures do not measure independent production recall. Keep the original fixture labels and policy baselines, and distinguish `NoMatch` from Shadow/Disabled rather than manipulating scores for a green result.

**Next local verification:** fast-forward the existing branch, pin the exact HEAD, run `verify-local.ps1 -Details -LiveOutput` once and capture the TRX plus replay JSON. Audit the remaining mismatch messages. Do not certify R351–R355 or advance the hardening ledger before all required gates pass.


## Follow-up CARTHAGE verification: 4,718 / 4,735 passing

The subsequent user-supplied local run completed with **4,718 passed, 17 failed, 0 skipped** (4,735 total). This is **41 fewer failures** than the preceding 58-failure result, but **not certification**.

Remaining failing groups from the reported test names:

- 4 HTTP/API legacy positives (R156, R157, R176, R177).
- 6 CloudDev legacy positives (R217–R222).
- 1 identity-access fixture (R128).
- 1 content-pack alias assertion (AD041 delegates to unobservable R343).
- 1 paired replay contract (R275/R343).
- 4 tuning benchmark tests related to stale replay expectations.

**Subsequent commits are unverified until the next local run.** They correct synthetic JWT signatures, invalid IPv4 octets, provider process/host attribution, valid webhook token and multipart/Content-Length request shapes, TCP/TLS flow attribution, and content-pack wrapper tests. Benchmark test expectations now reconcile and report the missing positives explicitly rather than demanding fictitious matches. The replay fixtures and the production **replay-expectations gate have not been weakened or removed**: unsupported R343, R295, R275 and description-only R240 scenarios and the R163 confidence discrepancy remain explicit blockers.

No detection thresholds, confidence floors, required audits or runtime mode defaults were relaxed as part of this follow-up. The new R351–R355 test additions from the concurrent engineering stream must also pass the next actual verification before this status can change.

## 2026-10-28 23:16 CARTHAGE verification

The uploaded TRX confirms **4,791 passed, 0 failed, 0 skipped**. Full verification still fails `replay-expectations` on five labeled cases. Alert-level Enterprise recall remains 4/48 with zero benign alert false positives (offline fixtures only).

The current *unverified* candidate routes synthetic Modbus TCP bytes through the same bounded parser used by capture, adds positive/negative replay coverage, and restores the expected R240 detection assertion. No detector or policy thresholds were changed. The other replay gaps are not waived, and a clean xUnit result alone is not release certification.

## CARTHAGE verification 2026-10-28 23:27–23:28 local

The supplied TRX verifies **4,796 passed, 1 failed, 0 skipped** (4,797 total). The six new R240 parser-backed tests ran; five passed and the single `Port_502_And_Info_Without_Payload_Do_Not_Prove_Modbus_Write` test failed because the source fixture's newline-sensitive string replacement did not remove the raw OT bytes on Windows. The observed unexpected R240 match was therefore not proof that the rule trusted packet Info.

The separate replay-expectations stage improved from **five to four** invalid fixtures: R240 passed genuine MBAP/PDU-based recognition. Still open: R343 (WinRM audit), R295 (Kubernetes exec audit), R275 (IdP corroboration), R163 (0.62 vs expected minimum 0.65; production confidence floor remains 0.84).

The negative test now removes the `rawOtTcpPayloadsByRecordIndex` property via `JsonNode`, asserts removal, and keeps the explicit R240 non-match expectation. These corrections are **PUBLISHED BUT NOT YET TESTED**; do not mark the branch or full verification as green based on the previous run. Do not lower confidence floors or waive the four replay blockers.


## CARTHAGE verified 23:33–23:34 local — 4,797/4,797 passing

The full TRX supplied after the CRLF-safe R240 regression fix contains **4,797 Passed, zero Failed, zero Skipped** at 2026-10-28 23:33–23:34 (+01:00). The full local verifier successfully completed the benchmark stage but **failed `replay-expectations`** for exactly four fixtures. R240's parser-backed request now passes both positive and fail-closed negative checks.

**Outstanding and *not waived*:**

| Fixture | Rule | Observed | Required engineering evidence |
| --- | --- | --- | --- |
| `ad-psremoting-encoded-command` | R343 | No match; 0.00 confidence | Authenticated WinRM/PowerShell operation and process-command audit, bound to a specific host/session/actor |
| `kubernetes-pod-exec` | R295 | No match; 0.00 confidence | Verified Kubernetes API-server exec authorization/session audit with actor, resource and outcome |
| `oauth-device-code-phishing` | R275 | No match; 0.00 confidence | Trusted identity-provider device-flow abuse audit **and independent** phishing corroboration |
| `ssrf-imds` | R163 | Direct metadata credential-path observation at 0.62; fixture expects at least 0.65 | Independently attributable causal link between inbound request and outbound metadata access, not simply a shared timestamp or URL mention |

R163's existing **production precision floor of 0.84** is preserved. Its current replay has an inbound `/fetch?url=...` record and a separate metadata request but **no authenticated trace or causality evidence**. Adding confidence solely for an IMDSv2 header, a query string, or spatial/temporal coincidence would be incorrect.

The 146-fixture replay reports 48 malicious and 98 benign. Enterprise: **45/48 raw recognized; 4/48 alerted; 0/98 benign alerted**. The gap primarily reflects Shadow/approval policies and missing trusted outcomes; neither figure estimates field accuracy. Catalog audit: 544 rules, 10 with paired synthetic controls, 489 without explicit replay controls, zero contract issues.

The `verify-local.ps1` diagnostic printer was improved after this run to surface the missing-evidence outcome and reason codes. This output-only change has **not been retested**. It must not affect gate outcomes.

**Next engineering milestone:** introduce reviewed, authenticated telemetry provenance through existing extension points; attach scenario-specific positive/negative evidence and adversarial spoofing controls for R343/R295/R275; implement independent SSRF causality for R163. Keep all four original malicious labels and minimum-confidence fixtures unchanged until genuinely supported. Do not treat successful xUnit tests alone as release certification.

# Local verification triage — 2026-10-28

**Branch:** `feature/carthago-reliability-hardening`  
**Status:** CANDIDATE — UNVERIFIED; no certification or ledger promotion.

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

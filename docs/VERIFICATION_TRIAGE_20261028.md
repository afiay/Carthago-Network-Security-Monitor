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

## Next engineering increment — signed audit verifier foundation (unverified)

Added an operator-pinned RSA-PSS/SHA-256 audit receipt verifier, an immutable verified-receipt capability, and 15 new xUnit invocations for signature tampering, wrong/unknown keys, wrong rule/operation scope, replay, time skew, invalid IDs/hashes, duplicate JSON properties, domain separation and fail-closed behavior. All receipts require actor/resource/session trace hashes. See `docs/development/TRUSTED_AUDIT_PROVENANCE_CONTRACT_20261028.md`.

**No producer, RuleEvaluationContext bridge, or rule-match path was connected.** The four remaining replay failures are deliberately unchanged, and the new foundation is **NOT TESTED** on CARTHAGE. Synthetic ephemeral test key material is neither deployed nor shipped as trust anchors. Existing 4,797/4,797 results apply only to the preceding checkpoint.


## 2026-10-28 audit-trust progress — source candidate, not yet tested

The newly uploaded CARTHAGE `verify-local.ps1` console log confirms **benchmark PASS** and **`replay-expectations` FAIL**, with the same four mandatory blockers: `R343` / `WINRM_COMMAND_AUDIT_UNAVAILABLE`, `R295` / `K8S_POD_EXEC_AUDIT_UNAVAILABLE`, `R275` / `TRUSTED_DEVICE_CODE_ABUSE_EVENT_UNAVAILABLE`, and `R163` 0.62 confidence vs 0.65 fixture minimum. No new test counts are visible in the provided benchmark-only excerpt; do **not** call the newer trusted-audit tests green.

Offline detection funnel: 45/48 malicious fixtures recognized, 4/48 Enterprise alerts and 0/98 benign alerts. This **does not establish field accuracy** or support disabling Shadow/approval gates.

**Source-level work since last CARTHAGE green xUnit checkpoint:** the signed audit verifier now rejects alias issuer IDs sharing a canonical RSA public key and binds its immutable receipts to the verifier instance; a new `TrustedAuditReceiptCorrelation` component implements fail-closed, same-registry/same-subject association only. A separate xUnit suite covers cross-registry mixing, self-corroboration, repeated IDs, differing trace/actor/resource and temporal skew. **No production producer or alert path is connected**, and the four replay fixtures are unchanged. Different keys are not proof of independent producer control. Full compile/test, signed audit producer integration and actual event semantics remain pending.

Focused next check on CARTHAGE:
```powershell
git pull --ff-only
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~TrustedAuditReceipt"
```
If focused tests pass, execute `.\verify-local.ps1 -Details -LiveOutput` once on a recorded HEAD. Do not promote certification while the four replay expectations fail.


## CARTHAGE verified 2026-10-29 00:01–00:02 (+01:00)

**Git checkpoint tested:** `42ad48a40674ff116a9d01011e15faab7472554f` (from the local checkout report immediately preceding this uploaded TRX).

The complete uploaded `carthago-tests.trx` reports:

- **4,825 / 4,825 xUnit tests Passed**, 0 Failed, 0 Skipped, 0 inconclusive, 0 errors.
- TRX run start `2026-10-29 00:01:18+01:00`; finish `2026-10-29 00:02:29+01:00`.
- **28/28 `TrustedAuditReceipt*` test cases Passed**, including signer key alias rejection, verifier-registry isolation, signed trace/actor/resource mismatch, replay/expiry protections, domain separation, and unchanged rule fail-closed behavior.
- The immediately preceding read-only benchmark summary on the same local checkout reported 146 replay samples (48 malicious; 98 benign), with **four unresolved replay expectations**: R343/WinRM authenticated command audit, R295/Kubernetes pod-exec audit, R275/trusted IdP device-flow abuse evidence, and R163 observed maximum confidence 0.62 versus malicious fixture minimum 0.65. Enterprise alert-level confusion: TP=4, FP=0, FN=44, TN=98.

**Certification remains BLOCKED.** The new receipt verifier/correlation primitive is now xUnit-verified, **not integrated with trusted producer telemetry**. Synthetic signing is not a substitute for an authenticated source. Do not bypass issuer provisioning, independent source roles, trace binding, rule evidence requirements, policy shadow gates, or R163 confidence requirements. This file records results from distinct artifacts: the uploaded TRX proves xUnit; the replay metrics come from the separately supplied summary, not from the TRX.


## Next development increment — native Windows 4624/4688 candidate intake (UNVERIFIED)

Added WinRmSecurityAuditIntake, WinRmLocalSecurityAuditReader and WinRmSecurityAuditIntakeTests. The reader inspects only local Windows Security 4624 (network logon) and 4688 (process creation) records with strict provider/channel/host identity, a bound on records processed, freshness limits and native EventRecord/XML cross-checks. Its parser accepts only structurally valid, attributed, bounded events, confirms exact PowerShell/wsmprovhost executable names and syntactically valid UTF-16LE EncodedCommand arguments, and correlates a preceding network logon using its Windows logon ID. Command-line and decoded payload content are not returned.

**This is NOT authenticated execution attestation:** 4624+4688 can be benign or indirectly related, and the reader does not sign claims, install an event collector, elevate privileges, change audit policies, connect to R343 or alter replay. All results remain unsigned, non-authoritative *candidates*. The six new fact tests and 20 parameterized inputs were written but **not yet compiled/tested on CARTHAGE**. The last independently verified xUnit count remains 4,825/4,825 on the earlier checkpoint. The four replay-expectation failures (R343, R295, R275 and R163) are unchanged.

Next focused validation:

    dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~WinRmSecurityAuditIntakeTests"

After that passes, run the full verifier and capture exact HEAD. More Windows-specific telemetry verification and source-role governance are required before signing or considering detection promotion. No confidence floors, labels or Shadow/Alert policies changed.

## CARTHAGE verification 2026-10-29 00:15 (+01:00) — 4,851 xUnit PASS

The user-supplied local summary on checkout `290a327ab53da107867ac57fefa4a397143aa5a0` reports:

- **4,851 passed, 0 failed, 0 skipped, 0 other**; TRX modified 2026-10-28 23:15:49 UTC and benchmark modified 23:15:59 UTC.
- Benchmark stage **PASS**; **replay-expectations FAILED** for four unchanged cases:
  - R343: WINRM_COMMAND_AUDIT_UNAVAILABLE
  - R295: K8S_POD_EXEC_AUDIT_UNAVAILABLE
  - R275: TRUSTED_DEVICE_CODE_ABUSE_EVENT_UNAVAILABLE
  - R163: detected at 0.62, below malicious fixture minimum 0.65
- 146 labeled offline fixtures: 48 malicious, 98 benign. Enterprise TP=4, FP=0, FN=44, TN=98; benign critical alerts=0. Synthetic fixture figures are not production accuracy statistics.

**Verified scope:** the new Windows Security 4624/4688 candidate parser, local reader and adversarial regression tests compile and pass on CARTHAGE. The tests do not verify live Security-log permissions, actual process command audit configuration, or any authenticated WinRM command outcome. The signed producer and R343 alert integration remain absent.

### Subsequent readiness command — unverified

Added `scripts/inspect-winrm-audit-readiness.ps1` as an opt-in read-only Windows readiness check. Without flags it checks Security log metadata access and an optional 4688 include-command-line registry setting; with `-InspectRecentEvents` it only checks whether recent 4624/4688 IDs exist. The script does not output event XML, command lines or identities, enable audit policies, elevate permissions, create signed claims or feed R343.

This command has NOT been executed on CARTHAGE. The four malicious replay expectations are deliberately unchanged and certification is still blocked.


## CARTHAGE R343 Security-log readiness limitation (2026-10-29)

At HEAD `66234637fdbbceb42eb0cb362dbd679ea2f15a1a`, the operator ran both default and opt-in Windows Security audit readiness checks. The Windows Security channel metadata lookup did not succeed; the 4688 include-command-line registry value was UNKNOWN; process-creation success auditing remained unverified. The opt-in command stopped before querying event IDs, so **no absence of 4624/4688 events was demonstrated**.

Read-only diagnostic fix now published: the readiness script emits safe failure categories and Windows token/service status, distinguishes absent registry policy from denied access, and independently queries event IDs 4624/4688 if explicitly requested, even when `Get-WinEvent -ListLog Security` fails. It does not read or print event bodies, modify audit settings, elevate, or sign claims.

**Unverified new script; all four original replay failures stay open.** Previous 4,851/4,851 xUnit passed at `290a327`, and no production detector or replay fixtures were modified. Operational eligibility for Security-log reading is a separate Windows permissions decision, not proof of an R343 attack.


## CARTHAGE R343 audit readiness — access/privilege confirmed (2026-10-29)

Current operator token is not elevated; Windows Event Log service is running. The readiness check returned `ACCESS_DENIED` for Security channel metadata, and both 4624 and 4688 bounded searches returned `NOT OBSERVED` in a 30-minute window. Because metadata access is denied, the searches do **not** establish full Security log read access or absence of records. The local 4688 command-line policy registry value is not set; effective audit policies were not inspected. A read-only `auditpol /get` failed with `0x522 / ERROR_PRIVILEGE_NOT_HELD`, so process creation audit configuration remains unknown.

A diagnostic-only change to `inspect-winrm-audit-readiness.ps1` now labels such no-match cases as `NO MATCHES REPORTED (log access unverified)` and makes the final status `ACCESS UNVERIFIED`. No Windows privileges, audit policies, rule behavior, shadow policies, benchmark samples or detection thresholds were changed. The change has not been tested on CARTHAGE.

Still outstanding: authenticated R343 command and process outcome, R295 pod-exec audit, R275 IdP abuse corroboration, and R163 metadata-causality evidence. Do not count xUnit green as completion of these four replay expectations.

## CARTHAGE elevated Security-read diagnosis — Process Creation auditing disabled

The operator reran Windows checks in an authorized **elevated** PowerShell window. The Security channel was readable and enabled, with 35,528 records. `auditpol /get` for Process Creation returned **No Auditing**. Five newest combined 4624/4688 results were all 4624; the five-result limit does not rule out older 4688 records.

This confirms the key missing R343 telemetry prerequisite: **Process Creation success auditing is disabled**. The separate Include Command Line policy was also not set at the previously checked local registry value. Windows therefore cannot supply the required fresh process-creation/encoded-command audit evidence by default. This does not authorize lowering R343 evidentiary requirements or manufacturing signed receipts.

Added an optional **read-only** Process Creation audit-policy check to `scripts/inspect-winrm-audit-readiness.ps1` (`-InspectAuditPolicy`). It queries `auditpol /get /r`, returns a sanitized status and reports unsupported localized CSV formats as unknown. It changes no Windows policy, Security-log access permissions, production rules, replay fixtures, labels or confidence thresholds.

The revised script is published but untested on CARTHAGE. R343 remains blocked for authenticated remote execution/outcome evidence, along with the independent R295, R275 and R163 replay blockers. Last verified xUnit 4,851/4,851.

## CARTHAGE R343 audited readiness confirmed (2026-10-29)

The operator pulled `a23726d` and ran `inspect-winrm-audit-readiness.ps1 -InspectAuditPolicy -InspectRecentEvents` in an authorized elevated PowerShell session. Results:

- Administrator token `True`; Windows Event Log service `Running`; Security channel metadata `READABLE`.
- `auditpol.exe /get` parsed successfully: **Process Creation success-audit policy = NO AUDITING**.
- The checked local 4688 command-line policy value was **NOT SET**. This does not claim exhaustive effective policy verification.
- Security 4624 **OBSERVED** within 30 minutes; 4688 **NO MATCHING EVENTS** within that selected 30-minute window.
- The script previously ended with `STATUS: INCOMPLETE` despite an explicit `NO AUDITING` prerequisite. PowerShell 5.1 rendered a UTF-8 em dash as `â€”`.

**Confirmed blocker:** the host can be inspected with an authorized elevated identity, but currently does not audit process creation successfully. Neither a current 4688 audit event nor its command-line field can be relied upon for R343. Reading the Security channel in an elevated administrative session does not mean the standard user/desktop application's Security-log reader has equivalent access. **Do not run Carthago's entire GUI as administrator to bypass that boundary.**

**Source-only repair:** `inspect-winrm-audit-readiness.ps1` now prioritizes the `BLOCKED - Process Creation success auditing is disabled` status if the optional effective audit policy check reports no success auditing, and all user-facing status lines use ASCII-safe punctuation for Windows PowerShell 5.1. No Windows audit settings, privileges, app startup, detection rules, confidence floors, or replay fixtures were changed. The revised script is **published but awaits a CARTHAGE rerun**.

**Next operational dependency:** any decision to enable 4688 success auditing or include command lines belongs to the operator's Windows security/privacy change process. A separate least-privileged, authenticated telemetry producer would ultimately be required for an R343 signed receipt. The other replay blockers R295, R275 and R163 are independent. Last previously verified xUnit checkpoint: **4,851/4,851** at `290a327`.

## CARTHAGE R343 final read-only audit-readiness rerun (2026-10-29)

The operator fast-forwarded to checkpoint `34bd2b2d6140125f888286e54a1626b06ce7e198` and ran the published `scripts/inspect-winrm-audit-readiness.ps1 -InspectAuditPolicy -InspectRecentEvents` from an elevated Windows PowerShell session.

- `Elevated administrator token: True`; Windows Event Log service `Running`; Security channel metadata `READABLE`.
- `4688 include-command-line policy: NOT SET (local policy value absent)`.
- `Process Creation success-audit policy: NO AUDITING`.
- `Security 4624 in last 30 minutes: OBSERVED (event ID only)`.
- `Security 4688 in last 30 minutes: NO MATCHING EVENTS (selected window)`.
- Confirmed final status: `BLOCKED - Process Creation success auditing is disabled; fresh Security 4688 evidence is not expected.`
- Windows PowerShell output no longer contains the previous em-dash mojibake.

**Result:** the read-only readiness script's published status/encoding correction is now operationally verified on CARTHAGE. This verifies **the diagnostic**, not real signed WinRM execution evidence or an R343 alert. A missing 4688 within the selected 30-minute window is consistent with the separately observed disabled audit policy; it does not establish the entire historical Security log is free of 4688.

**Boundaries:** no Windows audit policy was changed; no command-line logging was enabled; no new source permissions were granted; no production R343 logic, other detection thresholds, replay fixtures or signed receipt trust rules changed. A decision to enable process creation auditing and command-line inclusion requires separate operator authorization and sensitive-data review, followed by least-privileged producer design. Existing replay blockers R343, R295, R275 and R163 remain open. Last verified xUnit run still 4,851/4,851 at `290a327`.

## CARTHAGE R343 Stage 1 approved and prepared - not executed

The operator approved Stage 1 on 2026-10-29: enable **Process Creation success auditing (Security event 4688) only**, with no command-line inclusion. The previously confirmed baseline is Process Creation `No Auditing`; Security channel is readable under an authorized elevated token. Implementation is a strictly local, opt-in Windows policy action; it was **not** remotely applied from GitHub.

Published `scripts/set-process-creation-audit-lab.ps1` with `-Mode Status`, `-Mode Enable` and `-Mode Restore`. It restricts host to CARTHAGE, requires an elevated administrator token, checks the known `No Auditing` baseline and that the inspected command-line registry setting is not enabled, applies only `auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable`, verifies the effective result, and restores by scoped `/success:disable` only from the expected `Success` state. The Failure audit setting and other categories remain untouched. A separate new operator guide documents commands and verification at `docs/development/R343_CARTHAGE_AUDIT_STAGE1_20261029.md`.

**Status:** scripts and documents published; no command executed on CARTHAGE yet; no OS settings or privilege assignments changed by this repository update. R343 still requires authenticated WinRM command/outcome telemetry and separate Stage 2 decision on potentially sensitive command-line auditing. Other replay blockers R295, R275 and R163 unchanged. Last verified xUnit remains 4,851/4,851.

## CARTHAGE R343 Stage 1 telemetry activated and verified (2026-10-29)

With explicit operator authorization, CARTHAGE ran `scripts/set-process-creation-audit-lab.ps1 -Mode Enable` at repository checkpoint `7149997`. The script confirmed effective Process Creation policy `No Auditing -> Success` and did **not** change the optional command-line inclusion setting (still not set in the checked local registry location). An authorized elevated readiness run then reported:

- Process Creation success auditing: **SUCCESS AUDITING ENABLED**.
- Security metadata: **READABLE**; event 4624: **OBSERVED**; event 4688: **OBSERVED** in the last 30 minutes.
- A harmless local `cmd.exe /d /c exit 0` test ran, followed by three 4688 event-ID/timestamp results in the queried interval. This confirms 4688 production after activation but **does not prove** those three results belong to that exact test process.
- Readiness script conclusion: **EVENT IDS OBSERVED - auditing policy, event fields and authenticated outcome remain NOT VERIFIED.**

**Milestone:** CARTHAGE's Stage 1 Windows OS telemetry prerequisite is operationally verified. The separate command-line inclusion policy, exact PID/path correlation, WinRM session attribution, execution outcome, trusted signer and R343 promotion are NOT verified. No xUnit or replay test rerun was reported for this host-policy-only change.

Next source-only increment `scripts/verify-process-creation-audit-lab.ps1` adds a read-only bounded local smoke test that launches a harmless process and correlates the returned 4688 against its PID and exact image path without printing audit payloads or changing Windows policy. **New smoke test is published but NOT YET EXECUTED on CARTHAGE.** If the test fails to find its record, treat it as inconclusive, not a reason to change detector confidence.

Rollback remains `scripts/set-process-creation-audit-lab.ps1 -Mode Restore` when the lab session ends. The other open replay blockers R295, R275 and R163 are independent; R343 still returns WINRM_COMMAND_AUDIT_UNAVAILABLE. Last reported full xUnit checkpoint remains **4,851/4,851 at 290a327**.

## CARTHAGE R343 Stage 1 lab closeout - PASS and RESTORED (2026-10-29)

The operator pulled commit `c3c0326` and executed `scripts/verify-process-creation-audit-lab.ps1` in an authorized elevated Windows PowerShell session. The result was `PASS: event 4688 matched the harmless local process ID and image path.` This confirms one bounded event-to-process correlation in the Windows Security log, not WinRM attribution or signed evidence.

The operator then executed `scripts/set-process-creation-audit-lab.ps1 -Mode Restore`. The script reported effective Process Creation policy `Success -> No Auditing`, with successful restore. This completes the Stage 1 lab change and returns CARTHAGE to the previously observed audit-policy baseline. The Stage 2 command-line inclusion setting was not enabled. Security event records from the test are not erased by policy rollback.

**Result:** Stage 1 OS telemetry and benign local identity correlation verified on CARTHAGE; **configuration restored**. The R343 alert/replay remains blocked on authenticated session, command and outcome evidence, producer trust and authorization context. The other replay blockers R295, R275 and R163 remain open. Last reported full xUnit run is 4,851/4,851 at `290a327`; no claim of an additional build or replay certification is made.

## R343 follow-on source hardening after CARTHAGE Stage 1 (2026-10-29)

CARTHAGE Stage 1 ended with real 4688 process-ID/executable-path correlation **PASS** and a verified `Success -> No Auditing` rollback. The host remains on the prior audit policy baseline; command-line inclusion was not enabled.

Subsequent source-only commits harden `WinRmSecurityAuditIntake` against `wsmprovhost.exe`/`powershell.exe` lookalikes outside expected system/install paths and against encoded-command flags carried on unrelated executable command lines. The test file now contains **18 added cases** (16 adversarial, two positive), including standard PowerShell 7 and quoted image paths. See `docs/development/R343_AUTHENTICATED_PRODUCER_BOUNDARY_20261029.md` for the separate, least-privileged producer design and explicit prohibition on converting unsigned candidates into signed receipts.

**Unverified source changes**: These C# increments are committed, but no .NET build, new focused test run or full xUnit rerun has yet been performed on CARTHAGE. Last verified baseline: **4,851/4,851**. R343, R295, R275 and R163 replay expectations are still blocked. R343 continues to return `WINRM_COMMAND_AUDIT_UNAVAILABLE`; confidence floors, signed-receipt verification and replay labels are unchanged.

On the next operator-approved test window, run `dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter 'FullyQualifiedName~WinRmSecurityAuditIntakeTests'` before the full existing verification workflow. Do not enable command-line logging or grant Security-log privileges automatically.

## R343 isolated peer-gated telemetry IPC contract (2026-10-29) - source committed, tests pending

Implemented `Carthago/Services/TrustedAudit/WinRmTelemetryIpcContract.cs` as an **internal, in-memory, transport-agnostic, unsigned metadata** consumer-side protocol gate. No named-pipe/socket listener, Windows service, installer, Security-log reader permissions, OS authenticator, signing key or trusted receipt producer was introduced. It is not wired into Carthago startup or the R343 rule; existing `WINRM_COMMAND_AUDIT_UNAVAILABLE` behavior is preserved.

Strict V1 protocol: 4-byte big-endian length prefix; total frame length <=4096 bytes; strict UTF-8; exact 13-field JSON schema; duplicate, unexpected and secret-bearing fields rejected. A future OS-authenticated transport must supply a verified peer SID, host, process ID and channel-binding identifier independently from message bytes. The gate checks an operator-pinned SID/machine on session open and **rechecks the SID/PID/machine/binding on every frame**. It enforces opaque gate-owned sessions, exact incremental sequence, bounded age and future skew, session expiry, cross-session correlation-ID replay prevention, capped caches and fail-closed errors. Accepted records are explicitly `UNSIGNED_IPC_CANDIDATE_NOT_AUTHORIZED_FOR_ALERT` and have no command line, authorization status, signing fields or outcomes.

Added `Carthago.Tests/WinRmTelemetryIpcContractTests.cs` with synthetic positive and negative scenarios: unauthorized or absent peers; wrong SID, host, process identity or channel; cross-gate/closed/reused session; malformed length, UTF-8, JSON, BOM and duplicate fields; forbidden authenticity/secret fields; wrong version, event identity or chronology; loopback IP; sequence gaps/replay across channels; stale/future records; 64-session limit and 4096-message saturation. Peer identity stubs in tests are **not production OS authentication**.

Security design and restrictions documented in `docs/development/R343_TELEMETRY_IPC_CONTRACT_20261029.md`, and the broader R343 producer boundary document updated. **These C# changes and tests have NOT been compiled/run on CARTHAGE**; no success claim for the new tests. Previously verified 4,851/4,851 xUnit at `290a327` remains the last reported full run. R343/R295/R275/R163 replay expectations remain open, as do the Windows transport authentication, source reconciliation, verified operation/outcome and permission-scoped signer prerequisites. CARTHAGE Stage 1 auditing was restored to `No Auditing` before this increment; it was not touched.

Focused test command when the operator's test window opens:

    dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~WinRmTelemetryIpcContractTests|FullyQualifiedName~WinRmSecurityAuditIntakeTests"

## CARTHAGE focused R343 IPC and WinRM intake verification - PASS (2026-10-29)

The operator pulled `80e37ed3b92918175a273b0c2d3b04b359bec3c1` on the existing `feature/carthago-reliability-hardening` branch, then executed:

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~WinRmTelemetryIpcContractTests|FullyQualifiedName~WinRmSecurityAuditIntakeTests"
```

**Observed result:** Release build succeeded; **115 tests total, 115 passed, zero failed, zero skipped**, focused test duration approximately 4.5 seconds, overall build/test command approximately 56.6 seconds. The .NET app and test project compiled successfully. This confirms the new contract and the hardened unsigned 4624/4688 intake build and pass the focused regression/negative-test suite on CARTHAGE.

The build reported **15 warning occurrences** across build targets. Seven distinct application warning sites were reported (CS8602 in `R075_WMIDCOMLateralMovementRule.cs`, `SensitiveTelemetryContracts.cs`, `NetworkBatch266270Evidence.cs`; CS8629 in `R055_ThreatFeedStaleRule.cs`, `R190_DnsShortTtlBurstRule.cs`; CS8601 in `NetworkBatch266270Evidence.cs` at two locations) and one `xUnit2009` warning in `SyntheticHoldoutContractTests.cs`. The application warnings occurred during both temporary WPF compilation and the main project build. No warning in the supplied output points to `WinRmTelemetryIpcContract.cs`, `WinRmTelemetryIpcContractTests.cs` or `WinRmSecurityAuditIntake.cs`. These are not a claim that the warning sites have been previously verified or fixed.

**Scope and limitations:** The 115 focused tests use synthetic peer descriptors and parser fixtures; **no live Windows transport peer was authenticated**, no IPC listener or service was started, and no signing keys or attested WinRM outcomes were created. No host audit settings were changed by this test. CARTHAGE Process Creation auditing was restored to `No Auditing` after the earlier Stage 1 lab, and Stage 2 command-line inclusion remains disabled. The pre-existing full-suite checkpoint is still 4,851 passing tests at `290a327`, not a newly rerun full suite. R343, R295, R275 and R163 replay expectations remain unresolved.

**Next gate:** design a Windows-specific authenticated peer adapter (actual OS-derived SID, PID and connection identity) behind the isolated protocol gate, with adversarial cross-process/reconnect tests and explicit operator review before exposing any IPC endpoint or privilege elevation.

## CARTHAGO full local verification checkpoint - 2026-10-29

**Operator-observed execution:** CARTHAGE, Windows PowerShell, `feature/carthago-reliability-hardening`, local checkout commit `498b8b0` (the supplied `git pull --ff-only` fast-forwarded `80e37ed..498b8b0`). Invoked `./verify-local.ps1 -Details -LiveOutput` on October 29, 2026. Source: operator-provided terminal transcript. This was a **local** verification, not the queued GitHub Actions job.

| Stage | Result |
| --- | --- |
| Restore .NET tests and benchmarks | PASS |
| Release build: tests | PASS, 8 warnings, 0 errors |
| Release build: benchmarks | PASS, 0 warnings, 0 errors |
| Complete xUnit suite | **PASS: 4,940 passed, 0 failed, 0 skipped** |
| Replay benchmark execution | PASS: 146 labeled synthetic samples |
| Rule-catalog contract audit | PASS: 544 rules, 0 contract issues |
| Replay expectation validation | **FAIL: four existing evidence/expectation blockers** |
| Frozen holdout (`scripts/evaluate-holdout.ps1`) | NOT RUN by `verify-local.ps1` in supplied transcript |

Compared with the earlier full-suite checkpoint of 4,851 passing xUnit tests, the current suite contains 89 additional passing tests. This observation is a **test-count delta**, not proof that every new test or rule was isolated and independently certified. No evidence indicates an IPC contract regression: Release build and all xUnit tests passed.

### Four outstanding replay expectation failures

- `ad-psremoting-encoded-command` / R343: expected match missing; maximum confidence 0.00, requirement 0.65; `InsufficientEvidence/WINRM_COMMAND_AUDIT_UNAVAILABLE`. The completed Windows 4688 local lab and source-only IPC gate do NOT satisfy authenticated WinRM outcome provenance.
- `kubernetes-pod-exec` / R295: expected match missing; maximum confidence 0.00, requirement 0.65; `InsufficientEvidence/K8S_POD_EXEC_AUDIT_UNAVAILABLE`.
- `oauth-device-code-phishing` / R275: expected match missing; maximum confidence 0.00, requirement 0.65; `InsufficientEvidence/TRUSTED_DEVICE_CODE_ABUSE_EVENT_UNAVAILABLE`.
- `ssrf-imds` / R163: maximum confidence 0.62, below the expected fixture floor 0.65. Do not lower confidence floors to bypass this gate.

### Replay scope, quality and coverage gaps

- Synthetic replay corpus: 146 samples; 48 malicious and 98 benign; 0 benign critical alerts and 0 benign false-positive alerts reported.
- Raw/detector recognition: 45 of 48 expected malicious rules (93.8%) recognized. This is **not** alert-level recall and not production detection accuracy.
- Enterprise alert-level results: TP=4 FP=0 FN=44 TN=98, precision 100% on four true-positive alerts, recall 8.3%, F1 15.4%. Other profiles have 1-5 true-positive alerts and recall 2.1%-10.4%. Do not call the small-sample precision score production precision.
- Catalog coverage: 544 registered rules, 10 with paired synthetic controls, 489 without explicit replay controls; 0 contract issues. Improve explicit negative/positive rule coverage without weakening security guards.

### Remaining status and next gates

**Build and xUnit: GREEN. Replay expectations: RED. Full certification: NOT MET.** The overall local verifier ended `FAILED stages: replay-expectations`. Existing report-only diagnostics and full xUnit success must not override this nonzero final result. The separate frozen synthetic holdout was not part of the supplied local output and should be checked as its own gate; it does not replace replay failures. No signed WinRM/Kubernetes/OAuth outcome evidence or privileged Windows transport was implemented or tested in this checkpoint. CARTHAGE Windows Process Creation auditing remains at the previously reported restored `No Auditing` baseline unless separately changed by the operator. No detector confidence floors, replay labels or signing trust rules were altered for this report.

Existing one-shot GitHub Actions workflow job `40792433511` was independently checked after the local verification and remained queued with no runner assigned, so it is not the origin of these results. The local verifier is authoritative for this checkpoint.

## CARTHAGE separate frozen synthetic holdout - FAILED (2026-10-29)

After the 4,940-passing full xUnit run, the operator ran `scripts/evaluate-holdout.ps1 -NoBuild` against the 12-sample pinned holdout v1 (6 malicious, 6 benign). Benchmark execution succeeded, but the strict holdout evaluator reported `HOLDOUT FAILED: 3 issue(s)` and threw. Four of six malicious rule-recognition expectations matched; **two R102 expectations were missing** (`holdout-r102-multistage-encoded-txt`, `holdout-r102-second-client-encoded-txt`, both maximum confidence 0.00 versus required 0.75). Aggregate detector-recognition requirement was 6/6, observed 4/6. Zero benign alerts were observed. **All profiles TP=0 FP=0 FN=6 TN=6, alert recall=0%; precision=N/A (not 100%).** This is a synthetic holdout, not field-independent accuracy.

**Read-only provenance audit:** both missing R102 fixtures declare `protocol: DNS`, `applicationProtocol: DNS`, destination port 53, `dnsQtype: TXT`, and long/high-entropy QNAMEs, **but omit both `isUdp` and `isTcp`**. The shared `NetworkBatch096100Evidence.Dns` validation requires a coherent explicit UDP or TCP attribution; it returns false for transport-unknown records, before R102 evaluates entropy or burst correlation. Existing separate development R102 controls include `isUdp: true` and are not comparable as proof of live accuracy. This explains the missing R102 detector matches without relaxing a rule or threshold.

**Disposition:** holdout v1 remains frozen and RED. Do not alter its JSON files, hash manifest, analyst labels, confidence floors or transport-validation rule to manufacture a green result. Author a separately frozen v2 holdout with independently supported transport and parser provenance if stronger evaluation is required. See `docs/development/R102_FROZEN_HOLDOUT_TELEMETRY_AUDIT_20261029.md`. The independent R102 non-holdout regression test asserts fail-closed unknown transport and accepts a separately attributed UDP candidate. **It has now passed on CARTHAGE: 8/8 focused tests at source commit `a06a848`, with zero failures and zero skips**. This does not change the frozen v1 holdout result.

**Current certification:** full build/xUnit green at 4,940/4,940 on earlier source; development replay fails four expectations (R343/R295/R275/R163); frozen synthetic holdout fails R102 provenance/recognition. Windows transport adapter introduction remains gated on quality/security review, not claimed complete.

## CARTHAGE R102 focused regression checkpoint - PASS (2026-10-29)

After pulling source commit `a06a8485370db967ec1f3c2ab4777e1161042657`, the operator executed `dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~R102AdvancedAccuracyBatchTests"`. The Release build succeeded. xUnit result: **8 total, 8 passed, 0 failed, 0 skipped** (about 3.8 seconds test duration). The output reported **8 warning occurrences**, all in existing rule files or the `SyntheticHoldoutContractTests.cs` xUnit analyzer; no new R102 test warning was reported. This is a focused checkpoint, not an additional full-suite or holdout pass.

**Gates unchanged:** frozen 12-sample holdout v1 remains failed with two missing R102 detections; main development replay still has four unresolved evidence/confidence expectations; last full xUnit checkpoint remains 4,940/4,940 at source commit `498b8b0`.

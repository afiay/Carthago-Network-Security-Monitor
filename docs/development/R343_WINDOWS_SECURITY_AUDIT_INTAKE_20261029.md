# R343 Windows Security audit intake — candidate-only contract

**Status:** source candidate; not yet compiled or tested on CARTHAGE. No R343 alerts, no signed evidence producer and no rule promotion.

## Architecture

- Carthago/Services/TrustedAudit/WinRmSecurityAuditIntake.cs: inspect Windows Security 4688 process creation and 4624 network logon event XML; return only unsigned candidate facts
- Carthago/Services/TrustedAudit/WinRmLocalSecurityAuditReader.cs: read the LOCAL Security channel using EventLogReader, with a maximum 4,096 records per request (default 512), no remote log sessions, and 30-minute freshness limit
- Carthago.Tests/WinRmSecurityAuditIntakeTests.cs: synthetic positive/negative candidate tests. XML supplied by a caller always remains untrusted.

### Supported event semantics

Event 4688 records new process creation. The command-line field requires separately enabling Windows audit policy "Include command line in process creation events"; ParentProcessName is supported in modern Windows event versions. Event 4624 with LogonType 3 records a network logon. Sources: [Microsoft Audit Process Creation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-process-creation), [Microsoft Security event 4688](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688), and [EventLogReader API](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlogreader).

A candidate requires exact provider and channel, valid timestamps and event record IDs, no duplicated XML Data fields, valid 4688 process/parent executable basenames, a syntactically valid encoded UTF-16LE command argument, nonzero process IDs, and a 4624 network-logon ID linked to the process token within ten minutes. The native reader compares native EventRecord identity and metadata with XML, and rejects a remote/mismatched machine, stale record, unsupported event type, malformed XML or event-log access failure.

The parser accepts only bounded XML without DTDs or external entities, rejects loopback and IPv4-mapped loopback source addresses, and never returns or persists the raw command line, base64 payload, log XML or user names.

### Explicit limitations

A Security 4688 process event proves only process creation, not command execution outcome or malicious intent. A preceding 4624 network logon may belong to benign remote administration. Process names, event ID, timestamps, addresses and the decoded syntax alone are insufficient to claim a verified remote operation. These are **unattested candidates**, NOT TrustedAuditReceipt instances.

The existing R343 rule continues to return WINRM_COMMAND_AUDIT_UNAVAILABLE. The local reader is opt-in and NOT wired into app startup, replay, rule evaluation, alerting or the signing verifier. The new intake requires a separate authenticated producer, strong session/actor binding, verified process and WinRM outcome, authorization context and operator-pinned signer before any future alert integration.

Security event logs are access-controlled by Windows. The collector does not elevate privileges, enable audit policies, install services, create signing keys or change system security settings. Enabling command-line auditing can expose secrets in OS logs and must be a separate operator-approved security/privacy decision. If the events or required permissions are unavailable, fail closed.

### Verification on CARTHAGE

    git fetch origin
    git switch feature/carthago-reliability-hardening
    git pull --ff-only
    dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~WinRmSecurityAuditIntakeTests"

If focused tests pass:

    .\verify-local.ps1 -Details -LiveOutput
    .\scripts\inspect-verification-summary.ps1

This increment has not yet been compiled. The last verified checkpoint was 4,825/4,825 xUnit tests. Four separate replay gates remain unresolved: R343, R295, R275 and R163. This change alters no replay labels, production thresholds, rule confidence floors or policy decisions.


## CARTHAGE operator readiness check — 2026-10-29

At commit 66234637fdbbceb42eb0cb362dbd679ea2f15a1a, the operator ran the default readiness check and the opt-in recent-event check. They reported:

- 4688 command-line registry policy: UNKNOWN
- Process Creation success auditing: NOT VERIFIED
- Security channel: UNAVAILABLE OR NOT READABLE
- No 4624/4688 events inspected; opt-in run stopped because the script required a successful metadata lookup

**Interpretation:** neither permission denial nor absent audit events is proven. `Get-WinEvent -ListLog Security` failed, but the old script masked the exception category and did not attempt event queries. The two independent audit policies may not be configured; this must be checked without automatically enabling them.

### Diagnostic-only correction

The updated `scripts/inspect-winrm-audit-readiness.ps1` now reports safe error categories (ACCESS_DENIED, LOG_NOT_FOUND, COMMAND_UNAVAILABLE or a sanitized exception type/HRESULT) without event descriptions or exception messages. It reports the Windows Event Log service status, whether the PowerShell process carries an elevated administrator token, and distinguishes an absent local include-command-line registry value from a read failure. The `-InspectRecentEvents` mode now attempts bounded 4624 and 4688 event-existence queries even if the Security channel's metadata lookup fails. `NoMatchingEventsFound` is classified differently from event-query errors.

Microsoft documents the *Process Creation* audit subcategory GUID as `{0CCE922B-69AE-11D9-BED3-505054503030}`. The following command only **reads** the policy; do not change it as part of diagnosis:

    auditpol /get /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}"

The cmdlet does not elevate or grant log access. Audit Process Creation and Include Command Line in Process Creation Events are separately controlled. Enabling the latter can expose sensitive command-line arguments in the Security log; operator approval and retention/privacy assessment would be required.

Next on CARTHAGE: pull the new HEAD, run the default script and `-InspectRecentEvents`. Share only the sanitized result. If access is denied, a Windows administrator must decide whether to grant narrowly scoped read access or perform diagnostics in an already-authorized elevated session; do not grant privileges, change ACLs or enable broad auditing automatically.

**Status:** diagnostic script updated but NOT YET TESTED on CARTHAGE. R343 remains fail-closed; the four replay-expectations remain blocked; no detection rule, replay fixture, trust anchor or Windows setting was changed.


## CARTHAGE result at 2026-10-29 00:19 Stockholm (read-only checks)

- Elevated administrator token: **False**.
- Windows Event Log service: **Running**.
- Include-command-line policy: **NOT SET** at the inspected local policy path; effective policy still unverified.
- Security channel metadata: **ACCESS_DENIED**.
- Recent 4624 and 4688 searches: **NOT OBSERVED** in the 30-minute window, but there is no independent confirmation that this token can read the channel.
- `auditpol /get /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030}` returned Windows error `0x00000522` (`ERROR_PRIVILEGE_NOT_HELD`). This blocks inspection of the effective Process Creation auditing policy using the current token.

**Interpretation:** do not conclude the Security log is empty or auditing is disabled. The metadata read is denied, and the event searches returned no matches but cannot establish comprehensive access. A read of audit policy requires permission on the audit policy security descriptor (or broader SeSecurityPrivilege); do not add privileges or change policy automatically.

The readiness script now reports `NO MATCHES REPORTED (log access unverified)` when event searches return the no-match code but Security channel metadata is inaccessible, and its final state explicitly reports `ACCESS UNVERIFIED`. This is an output classification fix, not a detection or policy change.

### Next safe operational check

Use an **already-authorized** elevated administrator PowerShell session for *read-only diagnosis only*, if such permission is available and approved. Run `Get-WinEvent -ListLog Security` and `auditpol /get /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030}`. For privacy, share only the access outcome and enabled/disabled audit status; do not share event contents or command lines. Granting Security-log read permissions or enabling auditing is a separate operator/security decision, not part of this task.

The R343 producer and R343 replay remain unavailable; R295, R275 and R163 remain independent replay blockers. The corrected script is published but NOT YET RUN on CARTHAGE.

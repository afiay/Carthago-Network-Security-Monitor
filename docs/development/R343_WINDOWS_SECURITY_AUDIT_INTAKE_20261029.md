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

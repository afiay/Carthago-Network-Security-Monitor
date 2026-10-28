# CARTHAGE R343 Windows telemetry - Stage 1 lab change

## Authorization and scope

On 2026-10-29 the operator explicitly approved Stage 1: **enable Audit Process Creation / Success** on the Windows development host CARTHAGE, while leaving **Include command line in process creation events** unchanged. Approval does not extend to command-line logging, changing Security-log ACLs, granting application elevation, signing audit receipts, modifying detection confidence, or enabling R343 alerts.

Prior read-only CARTHAGE evidence: Security log enabled/readable under an authorized elevated PowerShell session; 4624 observed; effective Process Creation audit policy `No Auditing`; `ProcessCreationIncludeCmdLine_Enabled` not set at the checked local policy location; no 4688 events returned in a bounded 30-minute window. Previously verified 4,851/4,851 xUnit tests at `290a327`; four replay blockers remain.

## Scoped local utility

`scripts/set-process-creation-audit-lab.ps1` accepts `-Mode Status` (default), `-Mode Enable`, or `-Mode Restore` and is restricted to hostname CARTHAGE and an elevated administrator token. It queries the Process Creation subcategory by its stable GUID, parses its auditpol CSV report, and fails closed on unexpected policy values or schemas. Enable requires the **exact observed `No Auditing` baseline** and absence of enabled local command-line inclusion; it only sets `/success:enable`. Restore requires the expected `Success` effective state and only sets `/success:disable`, returning to the observed baseline. It does not change `/failure`, other categories, registry, log size/retention, application privileges, or the rule engine. Both changes verify the effective auditpol setting afterward.

Microsoft syntax reference: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-set . Audit policy state reader: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-get .

## Operator execution

**First pull in the normal repository terminal:**

```powershell
git switch feature/carthago-reliability-hardening
git pull --ff-only
git rev-parse --short HEAD
```

**Then run from an already-authorized elevated Windows PowerShell:**

```powershell
cd C:\Users\afiay\Documents\Projects\Carthago-Network-Security-Monitor
.\scripts\set-process-creation-audit-lab.ps1 -Mode Status
.\scripts\set-process-creation-audit-lab.ps1 -Mode Enable
.\scripts\inspect-winrm-audit-readiness.ps1 -InspectAuditPolicy -InspectRecentEvents
```

After enabling, create a harmless local process and check only event IDs and timestamps, not XML or messages:

```powershell
$started = Get-Date
Start-Process -FilePath "$env:WINDIR\System32\cmd.exe" -ArgumentList '/d /c exit 0' -Wait -NoNewWindow
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4688; StartTime=$started.AddSeconds(-5) } -MaxEvents 3 -ErrorAction Stop |
    Select-Object Id, TimeCreated
```

Observe log growth and retention while testing, and avoid real secrets in process arguments even though command-line logging is not intentionally enabled. The change might be superseded by Group Policy or endpoint management; do not bypass those controls.

## Restore

```powershell
.\scripts\set-process-creation-audit-lab.ps1 -Mode Restore
.\scripts\set-process-creation-audit-lab.ps1 -Mode Status
```

Restoring the audit setting does **not** erase already collected 4688 records. Do not clear the Security log as part of cleanup.

## Completion boundaries

**Stage 1 ENABLED and verified on CARTHAGE at commit `7149997`:** operator executed `-Mode Status` (No Auditing), `-Mode Enable` (effective policy Success), and the read-only readiness script (`SUCCESS AUDITING ENABLED`, 4624 and 4688 observed). A harmless local `cmd.exe /d /c exit 0` was launched, and three 4688 event IDs with timestamps were returned shortly afterward. The three records were not matched by PID and image path to that specific process; that narrower correlation remains a separate test. This does **not** provide encoded command-line content, remote execution attribution, WinRM outcome, authenticated signer, or signed R343 receipts. Continue to keep R343 fail-closed. Command-line inclusion remains a separate, unapproved Stage 2 privacy/security decision.

## Subsequent identity-correlation smoke check (not yet executed)

To prove that a **particular harmless process** (rather than merely nearby unrelated events) produces a matching 4688 record, the repo now contains `scripts/verify-process-creation-audit-lab.ps1`. It is restricted to CARTHAGE and an authorized elevated Windows PowerShell session, verifies that effective Process Creation success auditing is enabled, launches a harmless built-in `cmd.exe /d /c exit 0`, then reads a bounded number of recent 4688 events and searches for a match on the test process's PID and exact image path. The event XML is processed in memory only; it is never printed or saved. Failure to match is reported as **INCONCLUSIVE**, never evidence of an attack.

```powershell
.\scripts\verify-process-creation-audit-lab.ps1
```

The smoke script does **not** enable or disable auditing, record command-line content, execute WinRM, grant Security-log permissions, or create trusted audit claims. A matching process ID/path remains candidate-quality telemetry only, not remote-execution attribution. Windows may represent an image path differently, and high event volume can exceed the bounded query: these cases are inconclusive, not grounds to lower the trust bar.

**Safety/rollback:** keep command-line inclusion disabled for this stage. Once testing is over, the operator can run the published `-Mode Restore` command; it does not erase existing Security log entries. Stage 2 requires a separate privacy decision.

# CARTHAGO Windows monitor service

SOURCE CANDIDATE — UNVERIFIED. CLI-005C1. Do not enable automatic startup
until manual service startup, packet capture, detection journal writes and
stop have been verified on the intended host.

## Prerequisites

- Windows and .NET 8 Windows Desktop runtime (framework-dependent publish).
- Npcap installed; the selected service account must have capture access.
- A dedicated, provisioned service identity with Log on as a service,
  read/execute access to deployment, read-only config access and write
  access to required CARTHAGO data directories. Do not default to LocalSystem.
- Administrator installs the service; deployment/config directories must
  not be writable by ordinary users or the service account. Avoid
  user-writable ancestors, network paths and junctions. Protect rules.json
  and all binaries/dependencies as privileged service inputs.
- Close desktop/foreground monitoring first. Cross-session capture
  exclusion is not implemented. No external sinks or remote IP lookups.

## Publish and configure

From repository root (PowerShell):

```powershell
dotnet publish .\Carthago.Monitor\Carthago.Monitor.csproj -c Release -r win-x64 --self-contained false -o .\publish\monitor
dotnet run --project .\Carthago.Monitor -c Release -- capture interfaces --json
```

Copy the complete publish output into an administrator-controlled directory
such as C:\Program Files\Carthago\Monitor. Confirm rules.json and bundled
service data are present before deployment. Store a config in a separate
administrator-controlled directory, for example
C:\ProgramData\Carthago\ServiceConfig\monitor.json:

```json
{
  "schemaVersion": 1,
  "interfaceId": "\\Device\\NPF_{REPLACE-WITH-EXACT-ID}",
  "filter": "tcp",
  "statusSeconds": 5
}
```

Use the actual identifier returned by discovery, JSON-escaped. Filter null
means unfiltered capture; invalid BPF fails startup. Config validation does
not open the interface or verify permissions or BPF syntax.

```powershell
$exe = 'C:\Program Files\Carthago\Monitor\carthago-monitor.exe'
$config = 'C:\ProgramData\Carthago\ServiceConfig\monitor.json'
& $exe service validate --config $config --json
```

## Register and operate (elevated PowerShell)

Use a dedicated account already provisioned and allowed to log on as a
service. This command prompts for credentials; do not put passwords in
scripts or command history.

```powershell
$credential = Get-Credential
$binaryPath = '"' + $exe + '" service run --config "' + $config + '"'
New-Service -Name CarthagoMonitor -DisplayName 'CARTHAGO Monitor' -BinaryPathName $binaryPath -Credential $credential -StartupType Manual
Start-Service CarthagoMonitor
Get-Service CarthagoMonitor
Stop-Service CarthagoMonitor
```

SCM running means service startup returned after Npcap start; it is not
continuous capture health, accuracy or journal proof. Verify journal files
under the configured CommonApplicationData Carthago detections directory
and real packet/detection behavior. Check the System event log for SCM
start/stop failures. Service account preferences differ from interactive
user preferences; confirm data directory access and effective rule config.

After successful manual qualification only:

```powershell
Set-Service CarthagoMonitor -StartupType Automatic
```

Recovery settings are intentionally not configured automatically; configure
SCM recovery only after testing failure and restart behavior. Do not use
foreground CLI stop against the service; it does not expose IPC.

Rollback (elevated):

```powershell
Stop-Service CarthagoMonitor
sc.exe delete CarthagoMonitor
```

Do not remove persisted journals or configuration as part of service
unregistration. If stop fails or times out, inspect SCM and the process;
do not treat it as a successful graceful shutdown.

## Service health and CLI management (CLI-005C2)

Before starting the service, provision
C:\ProgramData\Carthago\ServiceStatus with administrator-controlled ACLs:
service identity Modify (including create/replace/delete temporary files),
intended operators Read, administrators/SYSTEM Full Control. Remove
untrusted write access on this directory and ancestors. The service
requires this directory and fails if sample publication fails. No
automatic ACL changes are made. Sample contains only process/session
identity, UTC timestamps and aggregate counters, not raw evidence.

```powershell
dotnet run --project Carthago.Cli -c Release -- service status --json
dotnet run --project Carthago.Cli -c Release -- service start
dotnet run --project Carthago.Cli -c Release -- service health --json
dotnet run --project Carthago.Cli -c Release -- service doctor --json
dotnet run --project Carthago.Cli -c Release -- service stop
```

The SCM authorization boundary applies; no automatic elevation. Status
does not imply capture health. Health/doctor require a current matching
process sample (PID plus process start time); users unable to read the
process identity or sample must not interpret this as zero activity.
Stopped service may leave its previous sample on disk, which is never
accepted as current. Freshness limit 120 seconds; status interval 1–60s.
CLI transition polling is bounded, but native SCM calls can block.

## Operator qualification (CLI-005C3A)

Use actual deployed binaries and config:

```powershell
$monitor = 'C:\Program Files\Carthago\Monitor\carthago-monitor.exe'
$cli = 'C:\Program Files\Carthago\Cli\carthago.exe'
$config = 'C:\ProgramData\Carthago\ServiceConfig\monitor.json'
.\scripts\test-monitor-service-preflight.ps1 -MonitorExe $monitor -CliExe $cli -ConfigPath $config
```

Preflight is read-only. Review effective service-account permissions,
all ancestors and binary provenance manually; broad ACL screening is
not proof of effective access. Interface enumeration uses invoking account.

In a maintenance window, with service stopped and desktop/foreground
closed, run:

```powershell
.\scripts\verify-monitor-service.ps1 -MonitorExe $monitor -CliExe $cli -ConfigPath $config -RunLifecycle -ConfirmExclusiveCaptureAndPermissions -ObserveSeconds 60
```

The harness starts/stops/restarts the registered service, compares fresh
process-bound samples, inspects bounded appended journal records and
attempts final stop. Cleanup failure requires manual intervention. No
traffic injection; provide approved lab traffic yourself if needed.
Add -RequireJournalEvidence for detection counter delta and observed
persisted append. No detections is inconclusive, not accuracy proof.
Shared journal is not session-attributed; avoid UTC midnight. Report
contains hashes, counter deltas and labels, no raw detection rows.
Passing only qualifies observed scope, not recovery or full runtime
correctness. Native Windows qualification remains pending.

## Capture reservation (CLI-005C3B)

Updated desktop, foreground and service capture use one Global Windows
reservation. Close/stop another CARTHAGO capture before starting. A native
cleanup failure retains the reservation until the owning process exits;
inspect the failure and close the affected process rather than repeatedly
retrying capture. This is cooperative exclusion, not protection from old
builds, unrelated capture tools, active sensors or hostile local processes.
The previously documented operator-exclusive-capture confirmation remains
required until Windows cross-account/session qualification passes.

## Measured pipeline health (CLI-005C3C)

Update service and CLI together. Service snapshot schema 2 carries
pipeline telemetry; older CLI readers cannot read schema 2. New CLI
reads schema 1 as legacy/unknown. service health/doctor report separate
snapshot freshness and pipeline assessment. Foreground engine health
uses a new V4 Health query; status/stop keep old response shape.
Failed or unknown schema-2 assessment returns exit 3, idle/degraded
remain observable results. Legacy fresh schema-1 health remains exit 0
with unknown assessment. No fresh sample returns exit 3.

Healthy is limited to observed recent capture, rule evaluation and
absence of measured degradation. Idle does not distinguish quiet
traffic from a silently stalled source. Journal failures are cumulative
and latch failed until process restart; persistence observed does not
establish external sink delivery. Detection accuracy is not assessed.

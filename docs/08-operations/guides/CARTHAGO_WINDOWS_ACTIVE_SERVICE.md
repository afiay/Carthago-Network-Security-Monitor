# CARTHAGO active Windows service deployment

SOURCE CANDIDATE — UNVERIFIED. Manual startup only. This is a separate service
from CarthagoMonitor; the installer never changes the passive service.

1. Provision a dedicated local/domain Windows user with a standard local
   profile, Log on as a service and the minimum required network/driver rights.
   Use the G5B interactive provisioning commands under that account, then
   configure the pinned grants. No desktop credentials are copied.
2. Publish the monitor and copy the complete output into an administrator-owned
   directory below Program Files. The service account must have read/execute
   but not write permission to any executable/dependency. Review all ancestors,
   effective permissions and provenance; ACL screening is conservative, not a
   full effective-access or race-proof security analysis.

~~~powershell
dotnet publish .\Carthago.Monitor\Carthago.Monitor.csproj -c Release -r win-x64 --self-contained false -o .\publish\active-monitor
~~~

After copying the complete output, obtain the expected executable SHA256 from
the trusted publish artifact, not an unverified deployment. In elevated
PowerShell set the actual paths/account/hash:

~~~powershell
$params = @{
  MonitorExe = 'C:\Program Files\Carthago\Monitor\carthago-monitor.exe'
  ConfigPath = 'C:\Users\CarthagoSvc\AppData\Local\Carthago\active-service\active-service.json'
  Account = '.\CarthagoSvc'
  ExpectedExeSha256 = 'REPLACE_WITH_TRUSTED_64_HEX_SHA256'
}
.\scripts\manage-active-service.ps1 -Action Preflight @params
.\scripts\manage-active-service.ps1 -Action Install @params -ConfirmAuthorizedDeployment
.\scripts\manage-active-service.ps1 -Action Status
~~~

Install prompts for the account credential and registers Manual startup only.
No automatic recovery, account creation, privilege assignment or auto-start.
Do not use a redirected LocalAppData profile in this initial deployment.
Preflight validates config syntax, account SID, path/ACL screening and executable
hash; it does not prove runtime account access, all dependency hashes, grant
validity, DPAPI or Npcap functionality.

Only in an authorized maintenance window, with valid pinned grants and no
competing active scheduler:

~~~powershell
.\scripts\manage-active-service.ps1 -Action Start @params -ConfirmAuthorizedDeployment
.\scripts\manage-active-service.ps1 -Action Stop @params -ConfirmAuthorizedDeployment
.\scripts\manage-active-service.ps1 -Action Remove @params -ConfirmAuthorizedDeployment
~~~

Start/stop verify SCM state, not sensor health. Native SCM calls can block;
transition waits are bounded after those calls. Remove requires stopped state
and exact registered image/account/manual startup. Stop/remove can operate
after config loss/expiry without running the deployed binary. Removal preserves
all service data and the account. A failed registration verification requires
manual inspection; no automatic rollback that could remove a concurrent service.
No automatic startup until actual SCM qualification and recovery policy review.


## Actual SCM lifecycle qualification (AS-Q07G5E)

The service must be registered Manual, stopped, with valid pinned grants,
and the deployment must pass preflight. Close all other Carthago monitor
and scheduler processes. Confirm that every selected profile is authorized
for real probes, and allow a maintenance window for two runs.

~~~powershell
.\scripts\verify-active-service.ps1 @params -RunLifecycle -ConfirmAuthorizedTargetsAndMaintenanceWindow -ObserveSeconds 60
~~~

This starts, observes, stops, restarts, observes and stops the existing
service. It never installs, edits configuration, renews/revokes grants or
changes startup/recovery policy. It requires fresh current-process health,
advancing sample time, monotonic counters, unchanged grant windows,
no pending/blocked/failing profiles, no deferrals or storage failures,
responsive and completed aggregate counts at least the selected count,
new session/process start on restart and successful SCM stop exit codes.
Configuration and executable hashes are rechecked. Output is a JSON report;
exit 0 qualifies only observed operational scope, exit 3 is incomplete or
failed. A final cleanup failure requires manual intervention. Native SCM
calls may block independently of transition wait budgets. Use a dedicated
lab configuration; real probes and opt-in evidence persistence occur.
Aggregate counters do not prove each individual sensor's protocol accuracy.
Actual negative SCM grant tests require separately provisioned lab grants;
this harness does not invalidate existing authorization. Automatic startup
remains unqualified.


## Negative authorization SCM lab (G5F3)

Use a disposable dedicated lab account and service configuration, never
production grants. First qualify a valid configuration with the positive
lifecycle harness. Stop the service. For a replacement-grant lab, provision
the same profile again under the lab account (new grant ID) but do not run
configure; the existing pinned configuration now refers to the old grant.
For a revoked-grant lab, use revoke on the lab profile while stopped;
for expiry, wait for the lab grant to expire. Do not mutate encrypted
credentials on a production host. A separate corrupt-credential fixture
is required for SnmpCredentialUnavailable.

Run elevated with the same deployment parameters and the expected negative
configuration SHA256 from the prepared lab fixture:

~~~powershell
.\scripts\verify-active-service-negative.ps1 @params -ExpectedReason PinnedGrantMismatch -ExpectedConfigSha256 'REPLACE_WITH_64_HEX' -ConfirmIsolatedNegativeLab
~~~

The harness starts only the explicitly selected existing service, requires
Start-Service failure, nonzero SCM exit, stopped state, a fresh typed
rejection record matching the config hash and reason, and unchanged health
and evidence file hashes. Unexpected successful start is a failure and
triggers cleanup; real probes could occur if the fixture was not invalid.
No grant/configuration changes are made. NoValidGrant groups several
causes; establish the intended fixture independently. Hash checks are
not packet-level proof. After the negative run, explicitly issue/select
a valid lab grant and configure, then rerun the positive G5E harness to
establish recovery. No automatic recovery or startup changes.

G6A release audit: update monitor and management scripts together. Health schema 2 requires responsiveProfiles equal to selected profiles for qualification; aggregate probe totals alone are insufficient. Schema 1 is deliberately unavailable to the new reader. The offline lifecycle contract must pass before actual SCM runs.


## G6C/D source-bound laboratory reports

Use a clean exact release candidate checkout. The physical wrapper builds the
qualification executable and retains a sanitized report in
build-verify/active-physical/<run-id>/physical.json. Use elevated, interactive
Windows console and authorized lab equipment. Each case requires PROBE.

~~~powershell
.\scripts\verify-active-physical.ps1 -Case GatewayMatch -Adapter YOUR_GUID -Source YOUR_IPV4 -Target YOUR_GATEWAY -Expected EXPECTED_MAC -ConfirmAuthorizedPhysicalLab
~~~

Repeat with GatewayMismatch (deliberately different valid expected MAC),
GatewayNoReply (controlled configured gateway does not answer),
GatewayContention (passive Npcap owner running; no active scheduler owner),
SnmpMatch, SnmpMismatch (deliberately different valid expected OID), and
SnmpTimeout (controlled nonresponding SNMP agent). Do not disrupt production
networks to manufacture failures. Inconclusive results not matching the
designated case are not passes. These are physical observation contracts,
not attack accuracy or packet-trace proof. SCM positive/negative reports
now record source SHA; manually establish that the installed executable and
all dependencies came from that same trusted build.


## G6E/G — Observe coexistence and assemble release evidence

Start both separately authorized Manual services in the lab. Do not select a
Gateway profile for a no-deferral coexistence run while passive Npcap owns the
capture reservation. Gateway coexistence remains a known limitation, qualified
separately by the contention case. Select suitable responsive lab endpoints
and approved intervals that produce progress during the observation window.

~~~powershell
.\scripts\observe-active-service-soak.ps1 @params -Hours 12 -MaxActiveWorkingSetMiB 512 -MaxPassiveWorkingSetMiB 2048 -MaxCombinedCpuPercent 25 -MaxEvidenceMiB 256 -ConfirmAuthorizedSoak
~~~

The budget values above are illustrative, not a measured baseline. Choose
and document budgets appropriate to the hardware and intended workload.
The observer does not start, stop, renew grants or send probes. It samples
actual process working sets, combined CPU normalized to logical processors,
evidence database/journal size and both health snapshots every ten seconds.
A valid window requires capture and active probe progress and no unexpected
session change, gaps, blocked profiles, deferrals or recorded failures.
Reports are under build-verify/active-soak/<run-id>/soak.json.

The 24-hour grant cap requires separate explicitly authorized windows (1–23
hours each). Accumulate 24–72 hours, with each gap and restart documented;
do not represent this as continuous 24–72-hour service operation. Network
bytes, loss and actual probe scheduling drift require independent lab
measurements; observer counters do not prove lossless capture.

~~~powershell
.\scripts\verify-active-release.ps1 -SyntheticReport $synthetic -PhysicalReports $physical -PositiveServiceReport $recovery -NegativeServiceReports $negative -SoakReports $soak -ExpectedExeSha256 $params.ExpectedExeSha256
~~~

Use actual JSON paths, not placeholders, all from the same clean source
commit; record positive recovery after the negative runs. The synthetic
report must retain its adjacent TRX. Capture the positive/negative script
JSON outputs in separate files outside tracked source. The evidence gate
does not create a release, mark production approved or change services.
Manual review of provenance/dependency hashes, effective ACLs, cross-account
DPAPI, packet overhead/loss, individual negative fixture causes, central
detection integration limits and known Gateway contention remains required.

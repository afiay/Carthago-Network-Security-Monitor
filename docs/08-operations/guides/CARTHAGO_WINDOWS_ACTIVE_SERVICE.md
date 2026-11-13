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

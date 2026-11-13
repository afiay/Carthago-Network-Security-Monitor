# SPDX-License-Identifier: MIT
[CmdletBinding()]
param([Parameter(Mandatory)][string]$MonitorExe,[Parameter(Mandatory)][string]$ConfigPath,
    [Parameter(Mandatory)][string]$Account,[Parameter(Mandatory)][string]$ExpectedExeSha256,
    [Parameter(Mandatory)][ValidateSet('NoValidGrant','PinnedGrantMismatch','SnmpCredentialUnavailable')][string]$ExpectedReason,
    [Parameter(Mandatory)][string]$ExpectedConfigSha256,
    [switch]$ConfirmIsolatedNegativeLab)
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT' -or -not $ConfirmIsolatedNegativeLab) { throw 'Explicit isolated negative lab confirmation required.' }
Import-Module (Join-Path $PSScriptRoot 'ActiveServiceDeployment.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'ActiveServiceNegativeQualification.psm1') -Force
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
try {
    if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevated PowerShell required.' }
} finally { $identity.Dispose() }
$pre=Get-ActiveServicePreflight $MonitorExe $ConfigPath $Account $ExpectedExeSha256
if ($ExpectedConfigSha256 -notmatch '^[0-9a-fA-F]{64}$' -or $pre.configSha256 -ine $ExpectedConfigSha256) { throw 'Negative fixture configuration hash mismatch.' }
$name='CarthagoActiveMonitor'
function Registration { Get-CimInstance Win32_Service -Filter "Name='CarthagoActiveMonitor'" }
function Assert-Registered {
    $s=Registration
    Assert-ActiveRegisteredService $s $pre
    return $s
}
function Assert-Inputs {
    if ((Get-FileHash -LiteralPath $pre.configPath -Algorithm SHA256).Hash -cne $pre.configSha256 -or
        (Get-FileHash -LiteralPath $pre.monitorExe -Algorithm SHA256).Hash -cne $pre.exeSha256) { throw 'Deployment changed.' }
}
if ((Assert-Registered).State -ne 'Stopped') { throw 'Service must initially be stopped.' }
if (@(Get-Process -Name 'Carthago','carthago-monitor','Carthago.ActiveQualification' -ErrorAction SilentlyContinue).Count -ne 0) { throw 'Close other Carthago processes.' }
$root=[IO.Path]::GetDirectoryName($pre.configPath)
function Get-ArtifactHash([string]$Name) {
    $path=Join-Path $root $Name
    if (-not (Test-Path -LiteralPath $path)) { return 'absent' }
    $path=Assert-ActiveLocalPath $path
    return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
}
# No database access or repair by the supervisor; compare evidence database and
# its possible LiteDB journal independently. A preexisting marker is not proof.
$before=@{}
foreach ($file in @('health.json','evidence.db','evidence-log.db','startup-rejection.json')) { $before[$file]=Get-ArtifactHash $file }
$report=[ordered]@{schemaVersion=1;expectedReason=$ExpectedReason;configSha256=$pre.configSha256;exeSha256=$pre.exeSha256;
    startedUtc=[DateTimeOffset]::UtcNow.ToString('o');rejection='not_run';cleanup='not_run';result='incomplete_or_failed';
    recoveryValidated=$false;securityAccuracyValidated=$false;failure=$null}
$attempted=$false;$code=3
try {
    Assert-Inputs
    if ((Assert-Registered).State -ne 'Stopped') { throw 'Service changed before start.' }
    $attempt=[DateTimeOffset]::UtcNow
    $attempted=$true
    $startFailed=$false
    try { Start-Service -Name $name -ErrorAction Stop } catch { $startFailed=$true }
    if (-not $startFailed) { throw 'Unexpected successful Start-Service; stop and inspect the fixture.' }
    $controller=Get-Service -Name $name
    try { $controller.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(45)) }
    finally { $controller.Dispose() }
    $s=Assert-Registered
    if ($s.State -ne 'Stopped' -or $s.ProcessId -ne 0 -or ($s.ExitCode -eq 0 -and $s.ServiceSpecificExitCode -eq 0)) { throw 'SCM rejection not confirmed.' }
    $path=Assert-ActiveLocalPath (Join-Path $root 'startup-rejection.json')
    if ((Get-ArtifactHash 'startup-rejection.json') -eq $before['startup-rejection.json']) { throw 'No new rejection record.' }
    $record=Read-ActiveRejectionFile $path
    Assert-ActiveRejectionRecord $record $ExpectedReason $pre.configSha256 $attempt ([DateTimeOffset]::UtcNow)
    foreach ($file in @('health.json','evidence.db','evidence-log.db')) {
        if ((Get-ArtifactHash $file) -cne $before[$file]) { throw 'Health or evidence changed during rejected startup.' }
    }
    Assert-Inputs
    $report.rejection='expected_pre_readiness_rejection_confirmed'
    $report.attemptId=[string]$record.attemptId
    $report.scmExitCode=$s.ExitCode
    $report.serviceSpecificExitCode=$s.ServiceSpecificExitCode
    $code=0
} catch {
    $report.failure=$_.Exception.Message
    $code=3
} finally {
    if ($attempted) {
        try {
            $s=Assert-Registered
            $controller=Get-Service -Name $name
            try {
                if ($controller.Status -eq 'StartPending') {
                    $deadline=[DateTimeOffset]::UtcNow.AddSeconds(45)
                    do { Start-Sleep -Milliseconds 500; $controller.Refresh() }
                    while ($controller.Status -eq 'StartPending' -and [DateTimeOffset]::UtcNow -lt $deadline)
                }
                if ($controller.Status -eq 'Running') { Stop-Service -Name $name -ErrorAction Stop }
                $controller.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(45))
            } finally { $controller.Dispose() }
            $s=Assert-Registered
            if ($s.State -ne 'Stopped' -or $s.ProcessId -ne 0) { throw 'Cleanup unconfirmed.' }
            $report.cleanup='stopped_confirmed'
        } catch { $report.cleanup='manual_intervention_required';$code=3 }
    }
    $report.finishedUtc=[DateTimeOffset]::UtcNow.ToString('o')
    if ($code -eq 0) { $report.result='qualified_expected_startup_rejection' }
    [pscustomobject]$report | ConvertTo-Json -Depth 5
}
exit $code

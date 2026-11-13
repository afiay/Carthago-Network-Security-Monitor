# SPDX-License-Identifier: MIT
[CmdletBinding()]
param([Parameter(Mandatory)][string]$MonitorExe,[Parameter(Mandatory)][string]$ConfigPath,
    [Parameter(Mandatory)][string]$Account,[Parameter(Mandatory)][string]$ExpectedExeSha256,
    [switch]$RunLifecycle,[switch]$ConfirmAuthorizedTargetsAndMaintenanceWindow,
    [ValidateRange(15,300)][int]$ObserveSeconds=60)
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT' -or -not $RunLifecycle -or -not $ConfirmAuthorizedTargetsAndMaintenanceWindow) {
    throw 'Windows, explicit lifecycle and authorized target/maintenance confirmation required.'
}
Import-Module (Join-Path $PSScriptRoot 'ActiveServiceDeployment.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'ActiveServiceQualification.psm1') -Force
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
try {
    if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevated PowerShell required.' }
} finally { $identity.Dispose() }
Import-Module (Join-Path $PSScriptRoot 'ActiveReleaseSource.psm1') -Force
$repoRoot=Split-Path -Parent $PSScriptRoot
$sourceSha=Get-ActiveReleaseSource $repoRoot
$pre=Get-ActiveServicePreflight $MonitorExe $ConfigPath $Account $ExpectedExeSha256
$name='CarthagoActiveMonitor'
function Registration { Get-CimInstance Win32_Service -Filter "Name='CarthagoActiveMonitor'" }
function Assert-Unchanged {
    $s=Registration
    Assert-ActiveRegisteredService $s $pre
    if ((Get-FileHash -LiteralPath $pre.configPath -Algorithm SHA256).Hash -cne $pre.configSha256 -or
        (Get-FileHash -LiteralPath $pre.monitorExe -Algorithm SHA256).Hash -cne $pre.exeSha256) { throw 'Deployment changed.' }
    return $s
}
$s=Assert-Unchanged
if ($s.State -ne 'Stopped') { throw 'Service must initially be stopped; existing run will not be interrupted.' }
# No competing Carthago capture or scheduler should be active in the lab.
if (@(Get-Process -Name 'Carthago','carthago-monitor','Carthago.ActiveQualification' -ErrorAction SilentlyContinue).Count -ne 0) {
    throw 'Close desktop, passive and foreground monitor processes before qualification.'
}
$report=[ordered]@{schemaVersion=1;sourceSha=$sourceSha;startedUtc=[DateTimeOffset]::UtcNow.ToString('o');exeSha256=$pre.exeSha256;
    configSha256=$pre.configSha256;profiles=$pre.profileCount;firstRun='not_run';restart='not_run';
    cleanup='not_run';result='incomplete_or_failed';failure=$null;securityAccuracyValidated=$false;
    grantRejectionScmValidated=$false;physicalProtocolCoverage='not_assessed'}
$attempted=$false
$code=3

function Read-FreshSample {
    $s=Assert-Unchanged
    if ($s.State -ne 'Running' -or $s.ProcessId -le 0) { throw 'Service not running.' }
    $file=Assert-ActiveLocalPath (Join-Path ([IO.Path]::GetDirectoryName($pre.configPath)) 'health.json')
    $sample=Read-ActiveHealthFile $file
    $process=Get-Process -Id $s.ProcessId
    try {
        $start=[DateTimeOffset]($process.StartTime.ToUniversalTime())
        $valid=ConvertTo-ActiveHealthSample $sample $s.ProcessId $start ([DateTimeOffset]::UtcNow)
    } finally { $process.Dispose() }
    $again=Registration
    if ($again.State -ne 'Running' -or $again.ProcessId -ne $s.ProcessId) { throw 'Service changed.' }
    return $valid
}
function Start-Observed {
    $s=Assert-Unchanged
    if ($s.State -ne 'Stopped') { throw 'Service must be stopped.' }
    Start-Service -Name $name
    $controller=Get-Service -Name $name
    try { $controller.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(45)) }
    finally { $controller.Dispose() }
    $deadline=[DateTimeOffset]::UtcNow.AddSeconds(30)
    do {
        try { return (Read-FreshSample) } catch {
            if ((Registration).State -ne 'Running') { throw 'Service exited before health readiness.' }
            Start-Sleep -Milliseconds 500
        }
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw 'No current process-bound health sample.'
}
function Stop-Observed {
    $s=Registration
    Assert-ActiveRegisteredService $s $pre
    $controller=Get-Service -Name $name
    try {
        if ($s.State -eq 'Start Pending') { $controller.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(45)); $controller.Refresh() }
        if ($controller.Status -eq 'Running') { Stop-Service -Name $name }
        $controller.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(45))
    } finally { $controller.Dispose() }
    $final=Registration
    Assert-ActiveRegisteredService $final $pre
    if ($final.State -ne 'Stopped' -or $final.ProcessId -ne 0 -or $final.ExitCode -ne 0 -or $final.ServiceSpecificExitCode -ne 0) {
        throw 'Successful service stop not confirmed.'
    }
}
function Observe($First) {
    $last=$First
    $advanced=$false
    $deadline=[DateTimeOffset]::UtcNow.AddSeconds($ObserveSeconds)
    do {
        Start-Sleep -Seconds 2
        $sample=Read-FreshSample
        Assert-ActiveHealthProgress $last $sample $pre.profileCount
        if ([DateTimeOffset]$sample.sampleUtc -gt [DateTimeOffset]$last.sampleUtc) { $advanced=$true }
        if ($sample.storageFailures -gt 0 -or $sample.blockedProfiles -gt 0) { throw 'Blocked profile or evidence storage failure.' }
        $last=$sample
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    if (-not $advanced -or -not (Test-ActiveObservedScope $last $pre.profileCount)) { throw 'Responsive scope or heartbeat progression not established.' }
    return $last
}
try {
    # Start may fail after SCM has accepted the request; always attempt cleanup.
    $attempted=$true
    $first=Start-Observed
    $last=Observe $first
    $report.firstRun='responsive_scope_observed'
    $report.firstSessionId=$first.sessionId
    $report.firstCompleted=$last.completedProbes
    $report.firstResponsive=$last.responsiveProbes
    $report.firstResponsiveProfiles=$last.responsiveProfiles
    Stop-Observed
    $report.firstRun='start_observe_stop_confirmed'
    $second=Start-Observed
    if ($second.sessionId -ceq $first.sessionId -or
        [DateTimeOffset]$second.processStartedUtc -le [DateTimeOffset]$first.processStartedUtc) { throw 'New service process/session not established.' }
    $end=Observe $second
    $report.restart='new_session_responsive_scope_observed'
    $report.secondSessionId=$second.sessionId
    $report.secondCompleted=$end.completedProbes
    $report.secondResponsive=$end.responsiveProbes
    $report.secondResponsiveProfiles=$end.responsiveProfiles
    Stop-Observed
    $null=Assert-Unchanged
    Assert-ActiveReleaseSource $repoRoot $sourceSha
    $code=0
} catch {
    $report.failure=$_.Exception.Message
    $code=3
} finally {
    if ($attempted) {
        try { Stop-Observed; $report.cleanup='stopped_confirmed' }
        catch { $report.cleanup='manual_intervention_required'; $code=3 }
    }
    $report.finishedUtc=[DateTimeOffset]::UtcNow.ToString('o')
    if ($code -eq 0) { $report.result='qualified_for_observed_operational_scope' }
    [pscustomobject]$report | ConvertTo-Json -Depth 5
}
exit $code

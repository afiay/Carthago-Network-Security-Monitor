# SPDX-License-Identifier: MIT
[CmdletBinding()]
param([Parameter(Mandatory)][string]$MonitorExe,[Parameter(Mandatory)][string]$CliExe,[Parameter(Mandatory)][string]$ConfigPath,
    [switch]$RunLifecycle,[switch]$ConfirmExclusiveCaptureAndPermissions,[ValidateRange(10,300)][int]$ObserveSeconds=60,[switch]$RequireJournalEvidence)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'MonitorServiceQualification.psm1') -Force
if (-not $RunLifecycle -or -not $ConfirmExclusiveCaptureAndPermissions) { throw 'Explicit lifecycle and exclusive capture/permission confirmation required.' }
$pre=Get-MonitorPreflight $MonitorExe $CliExe $ConfigPath
if (-not $pre.ready) { $pre | ConvertTo-Json -Depth 8; exit 3 }
$cli=Assert-LocalPath $CliExe
$s=Get-Service CarthagoMonitor
if ($s.Status -ne 'Stopped') { throw 'Service must be stopped; existing run will not be interrupted.' }
if (@(Get-Process -Name 'Carthago','carthago-monitor' -ErrorAction SilentlyContinue).Count -ne 0) { throw 'Close desktop/foreground monitor.' }
$report=[ordered]@{schemaVersion=1;inputHashes=$pre.hashes;startedUtc=[DateTimeOffset]::UtcNow.ToString('o');lifecycle='not_run';capture='not_assessed';journal='not_assessed';restart='not_run';cleanup='not_run';recovery='not_assessed';detectorAccuracy='not_assessed';failure=$null}
$attempted=$false; $code=3
try {
    $start=[DateTimeOffset]::UtcNow
    $day=$start.ToString('yyyy-MM-dd',[Globalization.CultureInfo]::InvariantCulture)
    $journal=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) ('Carthago\detections\detections-'+$day+'.jsonl')
    $baseline=0L
    if (Test-Path -LiteralPath $journal -PathType Leaf) { $null=Assert-LocalPath $journal; $baseline=(Get-Item -LiteralPath $journal).Length }
    $attempted=$true
    $r=Invoke-MonitorJson $cli @('service','start','--json')
    if ($r.code -ne 0 -or $r.data.scmState -ne 'running') { throw 'Start unconfirmed.' }
    $report.lifecycle='start_confirmed'
    $first=$null; $last=$null
    $deadline=[DateTimeOffset]::UtcNow.AddSeconds($ObserveSeconds)
    do {
        $r=Invoke-MonitorJson $cli @('service','health','--json') -TimeoutSeconds 15
        if ($r.code -eq 0 -and $r.data.health -eq 'fresh_sample') {
            $sample=$r.data.snapshot
            if ($null -eq $first) { $first=$sample }
            if ($sample.sessionId -ne $first.sessionId -or $sample.processId -ne $first.processId -or $sample.processStartedUtc -ne $first.processStartedUtc) { throw 'Process changed.' }
            if ($null -ne $last -and ([long]$sample.counters.captured -lt [long]$last.counters.captured -or [long]$sample.counters.detections -lt [long]$last.counters.detections)) { throw 'Counter regression.' }
            $last=$sample
        }
        Start-Sleep -Seconds 2
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    if ($null -eq $first -or $null -eq $last) { throw 'No fresh samples.' }
    $report.capturedDelta=[long]$last.counters.captured-[long]$first.counters.captured
    $report.parsedDelta=[long]$last.counters.parsed-[long]$first.counters.parsed
    $report.detectionDelta=[long]$last.counters.detections-[long]$first.counters.detections
    $report.capture=if ($report.capturedDelta -gt 0 -and $report.parsedDelta -gt 0) {'counter_progress_observed'} else {'inconclusive_no_counter_progress'}
    $r=Invoke-MonitorJson $cli @('service','stop','--json')
    if ($r.code -ne 0 -or $r.data.scmState -ne 'stopped') { throw 'Stop unconfirmed.' }
    $report.lifecycle='start_stop_confirmed'
    $report.journal=if ([DateTimeOffset]::UtcNow.ToString('yyyy-MM-dd',[Globalization.CultureInfo]::InvariantCulture) -ne $day) {'inconclusive_utc_rollover'} else {Get-JournalEvidence $journal $baseline $start}
    $r=Invoke-MonitorJson $cli @('service','start','--json')
    if ($r.code -ne 0 -or $r.data.scmState -ne 'running') { throw 'Restart unconfirmed.' }
    $deadline=[DateTimeOffset]::UtcNow.AddSeconds(75)
    do {
        $r=Invoke-MonitorJson $cli @('service','health','--json') -TimeoutSeconds 15
        if ($r.code -eq 0 -and $r.data.health -eq 'fresh_sample' -and $r.data.snapshot.sessionId -ne $first.sessionId) { $report.restart='new_session_observed'; break }
        Start-Sleep -Seconds 2
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    if ($report.restart -ne 'new_session_observed') { throw 'Restart session unconfirmed.' }
    if ($report.capture -eq 'counter_progress_observed' -and (-not $RequireJournalEvidence -or ($report.journal -eq 'appended_persisted_records_observed' -and $report.detectionDelta -gt 0))) { $code=0 }
} catch { $report.failure='qualification_failed_or_incomplete'; $code=3 }
finally {
    if ($attempted) {
        try {
            $s.Refresh()
            if ($s.Status -eq 'StartPending') { $s.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(45)); $s.Refresh() }
            if ($s.Status -ne 'Stopped') {
                $r=Invoke-MonitorJson $cli @('service','stop','--json')
                if ($r.code -ne 0 -or $r.data.scmState -ne 'stopped') { throw 'Cleanup unconfirmed.' }
            }
            $s.Refresh()
            if ($s.Status -ne 'Stopped') { throw 'Cleanup unconfirmed.' }
            $report.cleanup='stopped_confirmed'
        } catch { $report.cleanup='manual_intervention_required'; $code=3 }
    }
    $report.finishedUtc=[DateTimeOffset]::UtcNow.ToString('o')
    $report.result=if ($code -eq 0) {'qualified_for_observed_scope'} else {'incomplete_or_failed'}
    [pscustomobject]$report | ConvertTo-Json -Depth 8
}
exit $code

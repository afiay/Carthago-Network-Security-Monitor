# SPDX-License-Identifier: MIT
[CmdletBinding()]
param([Parameter(Mandatory)][string]$MonitorExe,[Parameter(Mandatory)][string]$ConfigPath,
    [Parameter(Mandatory)][string]$Account,[Parameter(Mandatory)][string]$ExpectedExeSha256,
    [Parameter(Mandatory)][ValidateRange(1,23)][int]$Hours,
    [Parameter(Mandatory)][ValidateRange(1,65536)][int]$MaxActiveWorkingSetMiB,
    [Parameter(Mandatory)][ValidateRange(1,65536)][int]$MaxPassiveWorkingSetMiB,
    [Parameter(Mandatory)][ValidateRange(1,100)][double]$MaxCombinedCpuPercent,
    [Parameter(Mandatory)][ValidateRange(1,65536)][int]$MaxEvidenceMiB,
    [switch]$ConfirmAuthorizedSoak)
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT' -or -not $ConfirmAuthorizedSoak) { throw 'Explicit Windows soak authorization required.' }
Import-Module (Join-Path $PSScriptRoot 'ActiveReleaseSource.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'ActiveServiceDeployment.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'ActiveServiceQualification.psm1') -Force
$root=Split-Path -Parent $PSScriptRoot
$sha=Get-ActiveReleaseSource $root
$pre=Get-ActiveServicePreflight $MonitorExe $ConfigPath $Account $ExpectedExeSha256
$dir=Join-Path $root ('build-verify/active-soak/'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $dir -Force | Out-Null
$activeRoot=[IO.Path]::GetDirectoryName($pre.configPath)
$passivePath=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Carthago\ServiceStatus\monitor.json'
$report=[ordered]@{schemaVersion=1;sourceSha=$sha;exeSha256=$pre.exeSha256;configSha256=$pre.configSha256;
    startedUtc=[DateTimeOffset]::UtcNow.ToString('o');requestedHours=$Hours;durationSeconds=0;sampleCount=0;
    activeSessionId=$null;passiveSessionId=$null;activeCompletedDelta=0;passiveCapturedDelta=0;
    maxActiveWorkingSetMiB=0;maxPassiveWorkingSetMiB=0;maxCombinedCpuPercent=0;maxEvidenceMiB=0;
    limits=[ordered]@{activeWorkingSetMiB=$MaxActiveWorkingSetMiB;passiveWorkingSetMiB=$MaxPassiveWorkingSetMiB;
        combinedCpuPercent=$MaxCombinedCpuPercent;evidenceMiB=$MaxEvidenceMiB};
    result='incomplete_or_failed';serviceStateChanged=$false;packetLossValidated=$false;networkBytesMeasured=$false}
$code=3
function Read-Sample {
    $a=Get-CimInstance Win32_Service -Filter "Name='CarthagoActiveMonitor'"
    $p=Get-CimInstance Win32_Service -Filter "Name='CarthagoMonitor'"
    Assert-ActiveRegisteredService $a $pre
    if ($a.State -ne 'Running' -or $p.State -ne 'Running' -or $a.ProcessId -le 0 -or $p.ProcessId -le 0 -or $a.ProcessId -eq $p.ProcessId) { throw 'Both independent services must be running.' }
    # Both services must run the same reviewed executable. No changes to SCM.
    if (-not $p.PathName.StartsWith(('"' + $pre.monitorExe + '" service run --config "'),[StringComparison]::Ordinal)) { throw 'Passive deployment image mismatch.' }
    $ap=Get-Process -Id $a.ProcessId
    $pp=Get-Process -Id $p.ProcessId
    try {
        $now=[DateTimeOffset]::UtcNow
        $active=ConvertTo-ActiveHealthSample (Read-ActiveHealthFile (Assert-ActiveLocalPath (Join-Path $activeRoot 'health.json'))) $a.ProcessId ([DateTimeOffset]($ap.StartTime.ToUniversalTime())) $now
        $passive=Read-ActiveHealthFile (Assert-ActiveLocalPath $passivePath)
        $pt=[DateTimeOffset]$passive.sampledUtc
        $ps=[DateTimeOffset]$passive.processStartedUtc
        if ($passive.schemaVersion -ne 2 -or $passive.processId -ne $p.ProcessId -or [Guid]$passive.sessionId -eq [Guid]::Empty -or
            [Math]::Abs(($ps-[DateTimeOffset]($pp.StartTime.ToUniversalTime())).TotalSeconds) -gt 1 -or
            $pt -lt $ps -or $pt -gt $now -or ($now-$pt).TotalSeconds -gt 120 -or
            $passive.counters.pipeline.nativeStarted -ne $true -or $passive.counters.pipeline.workerFaults -ne 0 -or
            $passive.counters.pipeline.journalWriteFailures -ne 0 -or $passive.counters.pipeline.ruleFailures -ne 0) { throw 'Passive health unavailable or degraded.' }
        if (-not (Test-ActiveObservedScope $active $pre.profileCount)) { throw 'Active profiles not fully responsive or operationally degraded.' }
        $bytes=0L
        foreach ($name in @('evidence.db','evidence-log.db')) {
            $path=Join-Path $activeRoot $name
            if (Test-Path -LiteralPath $path) { $bytes+=(Get-Item -LiteralPath (Assert-ActiveLocalPath $path)).Length }
        }
        [pscustomobject]@{utc=$now;active=$active;passiveSession=[string]$passive.sessionId;passivePid=$p.ProcessId;
            passiveStart=$ps;passiveSample=$pt;passiveCaptured=[long]$passive.counters.captured;
            activeMiB=$ap.WorkingSet64/1MB;passiveMiB=$pp.WorkingSet64/1MB;
            cpuSeconds=$ap.TotalProcessorTime.TotalSeconds+$pp.TotalProcessorTime.TotalSeconds;evidenceMiB=$bytes/1MB}
    } finally { $ap.Dispose();$pp.Dispose() }
}
try {
    $first=Read-Sample
    $report.startedUtc=$first.utc.ToString('o')
    $report.activeSessionId=$first.active.sessionId;$report.passiveSessionId=$first.passiveSession
    if ([DateTimeOffset]$first.active.earliestGrantExpiryUtc -le $first.utc.AddHours($Hours).AddMinutes(2)) { throw 'Grant window too short; explicitly provision a fresh lab grant before starting.' }
    $timer=[Diagnostics.Stopwatch]::StartNew()
    $previous=$first
    $last=$first
    $report.sampleCount=1
    $report.maxActiveWorkingSetMiB=$first.activeMiB
    $report.maxPassiveWorkingSetMiB=$first.passiveMiB
    $report.maxEvidenceMiB=$first.evidenceMiB
    if ($first.activeMiB -gt $MaxActiveWorkingSetMiB -or $first.passiveMiB -gt $MaxPassiveWorkingSetMiB -or $first.evidenceMiB -gt $MaxEvidenceMiB) { throw 'Initial resource budget exceeded.' }
    $lastElapsed=0.0
    do {
        Start-Sleep -Seconds 10
        $last=Read-Sample
        $elapsed=$timer.Elapsed.TotalSeconds
        $gap=$elapsed-$lastElapsed
        if ($gap -le 0 -or $gap -gt 30 -or $last.utc -lt $previous.utc) { throw 'Observation gap or clock regression.' }
        Assert-ActiveHealthProgress $previous.active $last.active $pre.profileCount
        if ($last.passiveSession -cne $first.passiveSession -or $last.passivePid -ne $first.passivePid -or
            $last.passiveStart -ne $first.passiveStart -or $last.passiveSample -lt $previous.passiveSample -or
            $last.passiveCaptured -lt $previous.passiveCaptured -or $last.cpuSeconds -lt $previous.cpuSeconds) { throw 'Passive session or counter regression.' }
        $cpu=100*($last.cpuSeconds-$previous.cpuSeconds)/($gap*[Environment]::ProcessorCount)
        $report.maxActiveWorkingSetMiB=[Math]::Max($report.maxActiveWorkingSetMiB,$last.activeMiB)
        $report.maxPassiveWorkingSetMiB=[Math]::Max($report.maxPassiveWorkingSetMiB,$last.passiveMiB)
        $report.maxCombinedCpuPercent=[Math]::Max($report.maxCombinedCpuPercent,$cpu)
        $report.maxEvidenceMiB=[Math]::Max($report.maxEvidenceMiB,$last.evidenceMiB)
        $report.sampleCount++
        $report.durationSeconds=[Math]::Floor($elapsed)
        if ($report.maxActiveWorkingSetMiB -gt $MaxActiveWorkingSetMiB -or $report.maxPassiveWorkingSetMiB -gt $MaxPassiveWorkingSetMiB -or
            $report.maxCombinedCpuPercent -gt $MaxCombinedCpuPercent -or $report.maxEvidenceMiB -gt $MaxEvidenceMiB) { throw 'Resource budget exceeded.' }
        $previous=$last;$lastElapsed=$elapsed
    } while ($timer.Elapsed.TotalHours -lt $Hours)
    $report.activeCompletedDelta=$last.active.completedProbes-$first.active.completedProbes
    $report.passiveCapturedDelta=$last.passiveCaptured-$first.passiveCaptured
    if ($report.activeCompletedDelta -le 0 -or $report.passiveCapturedDelta -le 0 -or
        [DateTimeOffset]$last.active.sampleUtc -le [DateTimeOffset]$first.active.sampleUtc -or $last.passiveSample -le $first.passiveSample) { throw 'Monitoring progress not established.' }
    if ((Get-FileHash -LiteralPath $pre.configPath -Algorithm SHA256).Hash -cne $pre.configSha256 -or
        (Get-FileHash -LiteralPath $pre.monitorExe -Algorithm SHA256).Hash -cne $pre.exeSha256) { throw 'Deployment changed.' }
    Assert-ActiveReleaseSource $root $sha
    $report.result='observed_coexistence_window_passed';$code=0
} catch { Write-Warning ('Soak incomplete or failed: '+$_.Exception.Message) }
finally {
    $report.finishedUtc=[DateTimeOffset]::UtcNow.ToString('o')
    $json=[pscustomobject]$report | ConvertTo-Json -Depth 5
    $json | Set-Content -LiteralPath (Join-Path $dir 'soak.json') -Encoding UTF8
    $json
}
exit $code

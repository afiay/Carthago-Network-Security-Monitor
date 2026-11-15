# SPDX-License-Identifier: MIT
# Read-only process sampling; does not start or stop capture.
[CmdletBinding()]
param(
    [int]$TargetProcessId,
    [ValidateSet('Npcap','ETW')][string]$Backend,
    [ValidateSet('Enabled','Disabled')][string]$RemoteEnrichment,
    [ValidateRange(1,1440)][int]$DurationMinutes = 30,
    [ValidateRange(1,300)][int]$IntervalSeconds = 30,
    [switch]$SelfTest
)
$ErrorActionPreference = 'Stop'
function Get-CpuPercent([double]$PreviousCpu,[double]$CurrentCpu,[double]$Elapsed,[int]$LogicalProcessors) {
    if ($Elapsed -le 0 -or $CurrentCpu -lt $PreviousCpu -or $LogicalProcessors -le 0) { throw 'Invalid CPU sample interval' }
    return 100.0 * ($CurrentCpu - $PreviousCpu) / ($Elapsed * $LogicalProcessors)
}
if ($SelfTest) {
    if ((Get-CpuPercent 1 3 2 4) -ne 25) { throw 'CPU normalization failed' }
    if ((Get-CpuPercent 3 3 2 4) -ne 0) { throw 'Idle CPU failed' }
    foreach ($case in @(@{p=3;c=2;e=1;n=4},@{p=1;c=2;e=0;n=4})) {
        $rejected = $false
        try { Get-CpuPercent $case.p $case.c $case.e $case.n | Out-Null } catch { $rejected = $true }
        if (-not $rejected) { throw 'Invalid interval accepted' }
    }
    Write-Host 'PASS: four CPU calculation fixtures'
    return
}
if ($TargetProcessId -le 0 -or -not $Backend -or -not $RemoteEnrichment) { throw 'Specify TargetProcessId, Backend and RemoteEnrichment' }
$head = & git -C $PSScriptRoot rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot identify checkout HEAD' }
$p = Get-Process -Id $TargetProcessId
$identity = $p.StartTime.ToUniversalTime().ToString('o')
$dir = Join-Path $PSScriptRoot ('build-verify/enrichment/runtime-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $dir | Out-Null
$report = [ordered]@{ checkoutHead=$head; processId=$TargetProcessId; processName=$p.ProcessName; processStartUtc=$identity; backendDeclared=$Backend; remoteEnrichmentDeclared=$RemoteEnrichment; logicalProcessors=[Environment]::ProcessorCount; durationMinutes=$DurationMinutes; intervalSeconds=$IntervalSeconds; samples=0; status='incomplete'; diagnostic=$null; captureAccuracy='not-run'; visual='not-run'; shutdown='not-measured' }
$clock = [Diagnostics.Stopwatch]::StartNew()
$previousCpu = $null
$previousElapsed = 0.0
try {
    while ($true) {
        $p = Get-Process -Id $TargetProcessId
        if ($p.StartTime.ToUniversalTime().ToString('o') -ne $identity) { throw 'Process identity changed' }
        $elapsed = $clock.Elapsed.TotalSeconds
        $cpu = [double]$p.TotalProcessorTime.TotalSeconds
        $percent = $null
        if ($null -ne $previousCpu) { $percent = Get-CpuPercent $previousCpu $cpu ($elapsed-$previousElapsed) $report.logicalProcessors }
        [pscustomobject]@{ utc=[DateTime]::UtcNow.ToString('o'); elapsedSeconds=$elapsed; privateBytes=$p.PrivateMemorySize64; workingSetBytes=$p.WorkingSet64; threads=$p.Threads.Count; cpuSeconds=$cpu; cpuPercent=$percent } | Export-Csv -LiteralPath (Join-Path $dir 'samples.csv') -NoTypeInformation -Append
        $report.samples++
        $previousCpu=$cpu
        $previousElapsed=$elapsed
        if ($elapsed -ge ($DurationMinutes*60)) { break }
        Start-Sleep -Seconds $IntervalSeconds
    }
    $report.status='sampling-completed'
} catch {
    $report.diagnostic=$_.Exception.Message
    throw
} finally {
    $report | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $dir 'runtime.json') -Encoding UTF8
    Write-Host "Evidence: $dir"
}

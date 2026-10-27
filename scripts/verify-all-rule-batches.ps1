# SPDX-License-Identifier: MIT
# One deferred Windows acceptance run for every authored five-rule batch.
# Do not invoke until the project owner explicitly declares test time.
[CmdletBinding()]
param(
    [ValidateSet('v1','v2')][string]$HoldoutVersion='v1'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$outputDir = Join-Path $root 'build-verify/rule-batches'
$stamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$transcriptPath = Join-Path $outputDir "all-rule-batches-$stamp.txt"
$stageLogs = [ordered]@{
    'Full regression and development replay' = (Join-Path $outputDir "all-rule-batches-$stamp-regression.log")
    'Frozen synthetic holdout' = (Join-Path $outputDir "all-rule-batches-$stamp-holdout.log")
}
$transcriptStarted = $false
Push-Location $root
try {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    Start-Transcript -Path $transcriptPath -ErrorAction Stop | Out-Host
    $transcriptStarted = $true
    $started = Get-Date

    # Preflight the explicitly selected holdout before starting the expensive
    # regression. A pending v2 must not burn a full xUnit/benchmark run only
    # to discover that no reviewed PCAP evidence was ever frozen.
    if ($HoldoutVersion -eq 'v2') {
        $v2Manifest = Get-Content -LiteralPath 'docs/holdout-evaluation-v2-manifest.json' -Raw | ConvertFrom-Json
        if ($v2Manifest.schemaVersion -ne 2 -or
            $v2Manifest.approvalState -ne 'FROZEN_V2_SYNTHETIC' -or
            @($v2Manifest.samples).Count -ne 12) {
            throw 'V2 not frozen: no builds or tests started. Complete independently reviewed PCAP evidence and explicit v2 freeze first.'
        }
    }

    # Identify the authored tests from their filename contract. Never accept
    # an incomplete or skipped batch as a successful all-rules verification.
    $authored = @()
    foreach ($file in @(Get-ChildItem -LiteralPath (Join-Path $root 'Carthago.Tests') -File)) {
        if ($file.Name -match '^R(?<id>\d{3})AdvancedAccuracyBatchTests\.cs$') {
            $authored += [int]$Matches['id']
        }
    }
    $authored = @($authored | Sort-Object -Unique)
    if ($authored.Count -eq 0) { throw 'No advanced rule-batch test files were found.' }
    $lastRule = [int]$authored[-1]
    if ($lastRule -gt 544 -or ($lastRule % 5 -ne 0 -and $lastRule -ne 544)) {
        throw "Incomplete five-rule batch: last advanced test file is R$('{0:000}' -f $lastRule)."
    }
    for ($id = 1; $id -le $lastRule; $id++) {
        if ($authored -notcontains $id) {
            throw "Missing advanced test file for R$('{0:000}' -f $id)."
        }
    }
    Write-Host ("Advanced rule coverage: R001–R{0:000}, {1} authored rule files." -f
        $lastRule, $authored.Count)

    $psExe = Join-Path $PSHOME 'powershell.exe'
    if (-not (Test-Path -LiteralPath $psExe)) { $psExe = Join-Path $PSHOME 'pwsh.exe' }
    if (-not (Test-Path -LiteralPath $psExe)) { throw 'PowerShell executable not found.' }

    # The normal local verifier builds and executes the entire xUnit suite
    # once, followed by the development replay benchmark once.
    Write-Host '=== Full build, xUnit suite and development replay ==='
    $priorPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $psExe -NoProfile -File 'verify-local.ps1' -Details -LiveOutput *>&1 |
            Tee-Object -FilePath ($stageLogs['Full regression and development replay']) | Out-Host
        $regressionExit = $LASTEXITCODE
    } finally { $ErrorActionPreference = $priorPreference }
    if (-not (Test-Path -LiteralPath $stageLogs['Full regression and development replay'] -PathType Leaf)) {
        throw 'Missing full regression output log.'
    }
    if ($regressionExit -ne 0) { throw 'Full local regression failed. Do not approve batches.' }

    $trxPath = Join-Path $root 'build-verify/test-results/carthago-tests.trx'
    if (-not (Test-Path -LiteralPath $trxPath -PathType Leaf) -or
        (Get-Item -LiteralPath $trxPath).LastWriteTime -lt $started.AddSeconds(-2)) {
        throw 'Missing or stale all-tests TRX. Never accept an old test run.'
    }
    [xml]$trx = Get-Content -LiteralPath $trxPath -Raw
    $results = @($trx.SelectNodes("//*[local-name()='UnitTestResult']"))
    $notPassed = @($results | Where-Object { $_.outcome -ne 'Passed' })
    if ($results.Count -eq 0 -or $notPassed.Count -gt 0) {
        throw "All-tests TRX contains $($notPassed.Count) non-passing result(s) out of $($results.Count)."
    }

    Write-Host '=== Per-rule advanced-case acceptance ==='
    $advancedTotal = 0
    foreach ($id in $authored) {
        $pattern = '(^|\.)R{0:000}AdvancedAccuracyBatchTests\.' -f $id
        $cases = @($results | Where-Object { $_.testName -match $pattern }).Count
        Write-Host ("  R{0:000}: {1} passing advanced cases" -f $id, $cases)
        if ($cases -lt 5) { throw "R$('{0:000}' -f $id) has fewer than five passing advanced cases." }
        $advancedTotal += $cases
    }

    Write-Host "=== Separately pinned synthetic holdout ($HoldoutVersion) ==="
    $holdoutScript = if ($HoldoutVersion -eq 'v2') {
        'scripts/evaluate-holdout-v2.ps1'
    } else {
        'scripts/evaluate-holdout.ps1'
    }
    $priorPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $psExe -NoProfile -File $holdoutScript -NoBuild *>&1 |
            Tee-Object -FilePath ($stageLogs['Frozen synthetic holdout']) | Out-Host
        $holdoutExit = $LASTEXITCODE
    } finally { $ErrorActionPreference = $priorPreference }
    if (-not (Test-Path -LiteralPath $stageLogs['Frozen synthetic holdout'] -PathType Leaf)) {
        throw 'Missing synthetic holdout output log.'
    }
    if ($holdoutExit -ne 0) { throw "Frozen $HoldoutVersion holdout failed. Do not approve batches." }

    Write-Host ("PASS: one full verification; {0} xUnit results, {1} advanced cases over R001–R{2:000}, development replay and holdout $HoldoutVersion." -f
        $results.Count, $advancedTotal, $lastRule)
    Write-Host 'Synthetic results are not field precision. Keep Shadow/Disabled and approval safeguards intact.'
}
finally {
    if ($transcriptStarted) { Stop-Transcript | Out-Host }
    Pop-Location
    if ($transcriptStarted) {
        # Windows PowerShell 5.1 transcripts can omit nested process output.
        # Merge independently captured stages after releasing the TXT handle.
        $writer = $null
        try {
            $writer = [IO.StreamWriter]::new($transcriptPath, $true,
                [Text.UTF8Encoding]::new($false))
            foreach ($entry in $stageLogs.GetEnumerator()) {
                if (-not (Test-Path -LiteralPath $entry.Value -PathType Leaf)) { continue }
                $writer.WriteLine('')
                $writer.WriteLine('=== COMPLETE STAGE OUTPUT: ' + $entry.Key + ' ===')
                $reader = [IO.StreamReader]::new($entry.Value)
                try {
                    while ($null -ne ($line = $reader.ReadLine())) { $writer.WriteLine($line) }
                } finally { $reader.Dispose() }
            }
        } finally {
            if ($null -ne $writer) { $writer.Dispose() }
        }
    }
    Write-Host ("Complete all-rule-batches TXT: " + $transcriptPath)
}

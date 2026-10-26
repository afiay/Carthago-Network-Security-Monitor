# SPDX-License-Identifier: MIT
# Windows-only full development + synthetic holdout quality gate, with one
# timestamped private transcript and separate per-stage dotnet logs.
[CmdletBinding()]
param([switch]$SkipDetailedOutput)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$stamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$logRoot = Join-Path $root 'build-verify/accuracy-logs'
New-Item -Path $logRoot -ItemType Directory -Force | Out-Null
$transcriptPath = Join-Path $logRoot ("accuracy-" + $stamp + ".txt")
$psExecutable = Join-Path $PSHOME 'powershell.exe'
if (-not (Test-Path -LiteralPath $psExecutable)) {
    $psExecutable = Join-Path $PSHOME 'pwsh.exe'
}
if (-not (Test-Path -LiteralPath $psExecutable)) {
    throw 'Windows PowerShell or PowerShell 7 executable is required.'
}

Push-Location $root
$transcriptStarted = $false
try {
    Start-Transcript -Path $transcriptPath -ErrorAction Stop | Out-Host
    $transcriptStarted = $true
    Write-Host '=== Carthago development replay and unit verification ==='
    $devArgs = @('-NoProfile','-File','verify-local.ps1','-Details')
    if (-not $SkipDetailedOutput) { $devArgs += '-LiveOutput' }
    & $psExecutable @devArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Development verification failed with exit code $LASTEXITCODE."
    }

    Write-Host '=== Frozen synthetic holdout, separate scorecard ==='
    & $psExecutable -NoProfile -File 'scripts/evaluate-holdout.ps1' -NoBuild
    if ($LASTEXITCODE -ne 0) {
        throw "Synthetic holdout verification failed with exit code $LASTEXITCODE."
    }

    Write-Host '=== Benign raw-match/noisy-rule audit ==='
    $noiseArgs = @('-NoProfile','-File','scripts/inspect-noisy-rules.ps1',
        '-Top','20','-ExportCsv','build-verify/noise-audit.csv')
    & $psExecutable @noiseArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Noisy-rule audit failed with exit code $LASTEXITCODE."
    }

    Write-Host 'PASS: development build/tests, replay, frozen synthetic holdout and noisy-rule inventory.'
}
finally {
    if ($transcriptStarted) { Stop-Transcript | Out-Host }
    Pop-Location
    Write-Host "Complete private transcript: $transcriptPath"
    Write-Host ("Development report: " + (Join-Path $root 'build-verify/tuning-benchmark.md'))
    Write-Host ("Synthetic holdout report: " + (Join-Path $root 'build-verify/holdout/tuning-benchmark.md'))
}

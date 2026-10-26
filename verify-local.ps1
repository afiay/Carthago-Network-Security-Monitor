# SPDX-License-Identifier: MIT
# Local Windows verification; no GitHub Actions or paid runner required.
[CmdletBinding()]
param([switch]$Details)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_NOLOGO = '1'
$env:VSTEST_CONNECTION_TIMEOUT = '300'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $root
try {
    $outputDir = Join-Path $root 'build-verify'
    $logDir = Join-Path $outputDir 'local-logs'
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    $failures = [System.Collections.Generic.List[string]]::new()
    function Invoke-Stage([string]$Name, [string[]]$Arguments) {
        $logFile = Join-Path $logDir ($Name + '.log')
        & dotnet @Arguments *> $logFile
        if ($LASTEXITCODE -ne 0) {
            $script:failures.Add($Name)
            Write-Host "FAIL: $Name (exit $LASTEXITCODE); see build-verify/local-logs/$Name.log"
            if ($Details) { Get-Content $logFile | Select-Object -Last 40 }
            return $false
        }
        return $true
    }
    if (-not (Invoke-Stage 'restore-tests' @('restore','Carthago.Tests/Carthago.Tests.csproj','--verbosity','quiet','--nologo'))) { exit 1 }
    if (-not (Invoke-Stage 'restore-benchmarks' @('restore','Carthago.Benchmarks/Carthago.Benchmarks.csproj','--verbosity','quiet','--nologo'))) { exit 1 }
    if (-not (Invoke-Stage 'build-tests' @('build','Carthago.Tests/Carthago.Tests.csproj','-c','Release','--no-restore','-v','quiet','--nologo'))) { exit 1 }
    if (-not (Invoke-Stage 'build-benchmarks' @('build','Carthago.Benchmarks/Carthago.Benchmarks.csproj','-c','Release','--no-restore','-v','quiet','--nologo'))) { exit 1 }
    $null = Invoke-Stage 'tests' @('test','Carthago.Tests/Carthago.Tests.csproj','-c','Release','--no-build','--no-restore','-v','quiet','--logger','trx;LogFileName=carthago-tests.trx','--results-directory','build-verify/test-results')
    $benchOk = Invoke-Stage 'benchmark' @('run','--project','Carthago.Benchmarks','-c','Release','--no-build','--no-restore','--','--replay-dir','Tests/RuleReplaySamples','--output-dir','build-verify','--compare-profiles','--explain-shadow')
    if ($benchOk) {
        try {
            $report = Get-Content (Join-Path $outputDir 'tuning-benchmark.json') -Raw | ConvertFrom-Json
            if ($null -eq $report.summary -or $null -eq $report.sampleResults) { throw 'Report schema missing summary or samples' }
            if ([int]$report.summary.replaySampleCount -lt 19) {
                $failures.Add('replay-sample-count')
                Write-Host "FAIL: only $($report.summary.replaySampleCount) replay samples (minimum 19)."
            }
            $invalid = @($report.sampleResults | Where-Object { @($_.errors | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count -gt 0 })
            if ($invalid.Count -gt 0) {
                $failures.Add('replay-expectations')
                Write-Host "FAIL: $($invalid.Count) replay sample(s) have invalid expectations:"
                foreach ($sample in $invalid) {
                    Write-Host "  $($sample.name): $($sample.errors -join '; ')"
                }
            }
            Write-Host "Replay quality: $($report.summary.replaySampleCount) samples; benign critical alerts: $($report.summary.benignCriticalAlertCount)"
            if ($Details) {
                foreach ($sample in @($report.sampleResults | Where-Object { $_.classification -eq 'Benign' })) {
                    foreach ($profile in $sample.profiles.PSObject.Properties) {
                        if ([int]$profile.Value.criticalAlertCount -gt 0) {
                            Write-Host "  Benign critical: $($sample.name) / $($profile.Name): $($profile.Value.criticalAlertCount)"
                        }
                    }
                }
            }
        } catch {
            $failures.Add('replay-report')
            Write-Host "FAIL: replay report could not be validated: $($_.Exception.Message)"
        }
    }
    if ($failures.Count -gt 0) {
        Write-Host "FAILED stages: $($failures -join ', ')"
        exit 1
    }
    Write-Host 'PASS: local build, tests and replay validation.'
} finally {
    Pop-Location
}

# SPDX-License-Identifier: MIT
# Non-sensitive failure summary: local TRX test failures and benign alert rule IDs.
[CmdletBinding()]
param(
    [string]$Benchmark = (Join-Path $PSScriptRoot '..\build-verify\tuning-benchmark.json'),
    [string]$TestResults = (Join-Path $PSScriptRoot '..\build-verify\test-results\carthago-tests.trx'),
    [string]$Sample = 'r163-approved-cloud-init-install-path'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (Test-Path -LiteralPath $TestResults -PathType Leaf) {
    [xml]$trx = Get-Content -LiteralPath $TestResults -Raw
    $failed = @($trx.SelectNodes("//*[local-name()='UnitTestResult' and @outcome='Failed']"))
    Write-Host ("Failing .NET tests: {0}" -f $failed.Count)
    foreach ($entry in $failed) {
        Write-Host ("  {0}" -f $entry.testName)
        $errorInfo = $entry.SelectSingleNode("./*[local-name()='Output']/*[local-name()='ErrorInfo']")
        if ($null -ne $errorInfo) {
            $message = $errorInfo.SelectSingleNode("./*[local-name()='Message']")
            if ($null -ne $message) {
                $lines = @($message.InnerText -split '\r?\n' | Select-Object -First 9)
                foreach ($line in $lines) { Write-Host ("    {0}" -f $line) }
            }
        }
    }
} else {
    Write-Warning "Test result file is missing: $TestResults"
}

if (-not (Test-Path -LiteralPath $Benchmark -PathType Leaf)) {
    throw "Benchmark JSON is missing: $Benchmark"
}
$report = Get-Content -LiteralPath $Benchmark -Raw | ConvertFrom-Json
$benign = @($report.sampleResults | Where-Object { $_.classification -eq 'Benign' })
$problemCount = 0

Write-Host 'Benign replay alerts by sample/profile (rule IDs only):'
foreach ($sampleResult in $benign) {
    if (-not [string]::IsNullOrWhiteSpace($Sample) -and $sampleResult.name -ne $Sample)
    { continue }
    foreach ($entry in $sampleResult.profiles.PSObject.Properties) {
        $ids = @($entry.Value.alertRuleIds | Where-Object {
            -not [string]::IsNullOrWhiteSpace([string]$_)
        } | Sort-Object -Unique)
        if ($ids.Count -eq 0) { continue }
        $problemCount++
        Write-Host ("  {0} / {1}: {2}; critical={3}" -f
            $sampleResult.name, $entry.Name, ($ids -join ','),
            [int]$entry.Value.criticalAlertCount)
    }
}
if ($problemCount -eq 0) {
    Write-Host '  No simulated alerts for the selected benign fixture(s).'
}
if (-not [string]::IsNullOrWhiteSpace($Sample)) {
    $one = @($report.sampleResults | Where-Object { $_.name -eq $Sample })
    if ($one.Count -eq 1) {
        Write-Host ("Raw matched rules for {0}: {1}" -f $Sample,
            ($one[0].actualMatches -join ','))
        Write-Host ("Unexpected explicitly disallowed matches: {0}" -f
            ($one[0].unexpectedMatches -join ','))
    }
}
Write-Host 'To inspect all benign fixtures, run with -Sample "".'

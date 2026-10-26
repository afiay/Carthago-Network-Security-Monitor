# SPDX-License-Identifier: MIT
# Non-sensitive failure summary: local TRX test failures and benign alert rule IDs.
[CmdletBinding()]
param(
    [string]$Benchmark = (Join-Path $PSScriptRoot '..\build-verify\tuning-benchmark.json'),
    [string]$TestResults = (Join-Path $PSScriptRoot '..\build-verify\test-results\carthago-tests.trx'),
    [string]$BuildLog = (Join-Path $PSScriptRoot '..\build-verify\local-logs\build-tests.log'),
    [string]$Sample = ''
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (Test-Path -LiteralPath $BuildLog -PathType Leaf) {
    $compileErrors = @(Get-Content -LiteralPath $BuildLog |
        Where-Object { $_ -match '(?i)(\berror\s+(?:CS|NU|NETSDK|MSB)\d+|:\s*error\b)' } |
        Select-Object -First 15)
    if ($compileErrors.Count -gt 0) {
        Write-Host "Build errors ($($compileErrors.Count) shown):"
        foreach ($line in $compileErrors) { Write-Host "  $line" }
        if ((Test-Path -LiteralPath $TestResults -PathType Leaf) -and
            (Get-Item -LiteralPath $TestResults).LastWriteTimeUtc -lt
                (Get-Item -LiteralPath $BuildLog).LastWriteTimeUtc) {
            Write-Warning 'TRX test results predate the failed build; those test failures are STALE and do not describe the current source.'
        }
    }
}

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
Write-Host 'Malicious replay expectation failures (rule IDs, outcomes and telemetry gaps):'
$invalid = @($report.sampleResults | Where-Object {
    $_.classification -eq 'Malicious' -and @($_.missingExpectedMatches).Count -gt 0
})
if ($invalid.Count -eq 0) {
    Write-Host '  No missing malicious expected matches.'
}
foreach ($item in $invalid) {
    Write-Host ("  {0}: missing={1}" -f $item.name, ($item.missingExpectedMatches -join ','))
    foreach ($diagnostic in @($item.expectedRuleDiagnostics | Where-Object {
        $item.missingExpectedMatches -contains $_.ruleId
    })) {
        Write-Host ("    {0}: {1}; missing telemetry={2}" -f
            $diagnostic.ruleId, $diagnostic.outcome,
            ($diagnostic.missingRequiredTelemetry -join ','))
        foreach ($reason in @($diagnostic.noMatchReasons | Select-Object -First 5)) {
            Write-Host ("      {0}" -f $reason)
        }
    }
}
Write-Host 'Use -Sample r163-approved-cloud-init-install-path to inspect only that benign fixture.'

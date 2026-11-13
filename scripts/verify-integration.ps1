# SPDX-License-Identifier: MIT
# GA-IQ-01: owner-run, pinned Windows integration. No CI or active network probes.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$SourceSha,
    [switch]$AuthorizedTestTime
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $AuthorizedTestTime) { throw 'Requires owner-authorized test time for the selected SHA.' }
if ($env:OS -ne 'Windows_NT') { throw 'Windows and .NET SDK required.' }
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    function Assert-PinnedCheckout {
        $head = (& git rev-parse HEAD)
        if ($LASTEXITCODE -ne 0 -or $head -cne $SourceSha) { throw 'HEAD differs from selected SHA.' }
        $branch = (& git branch --show-current)
        if ($LASTEXITCODE -ne 0 -or $branch -cne 'feature/carthago-reliability-hardening') { throw 'Unexpected branch.' }
        $dirty = @(& git status --porcelain --untracked-files=all)
        if ($LASTEXITCODE -ne 0 -or $dirty.Count -ne 0) { throw 'Clean checkout required; preserve local edits before testing.' }
    }
    Assert-PinnedCheckout
    $runId = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + $SourceSha.Substring(0,12) + '-' + [Guid]::NewGuid().ToString('N').Substring(0,8)
    $dir = Join-Path $root ('build-verify/integration/' + $runId)
    New-Item -ItemType Directory -Path $dir | Out-Null
    $report = [ordered]@{
        schemaVersion = 1; sourceSha = $SourceSha; startedUtc = [DateTime]::UtcNow.ToString('o')
        finishedUtc = $null; status = 'NotCompleted'; stages = [ordered]@{}
        cliTests = $null; windowsTests = $null; blocker = $null; fieldAccuracyQualified = $false
    }
    function Invoke-IntegrationStage([string]$Name, [string]$Command, [string[]]$Arguments) {
        Assert-PinnedCheckout
        $logPath = Join-Path $dir ($Name + '.log')
        Write-Host "START: $Name (log: $logPath)"
        $previous = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            & $Command @Arguments *> $logPath
            $code = $LASTEXITCODE
        } finally { $ErrorActionPreference = $previous }
        $report.stages[$Name] = $code
        if ($code -ne 0) {
            # Keep the complete private log, but surface the actual failure in
            # the owner console so a copied transcript is actionable.
            if (Test-Path -LiteralPath $logPath -PathType Leaf) {
                Write-Host "--- $Name failure (last 80 lines) ---"
                Get-Content -LiteralPath $logPath -Tail 80 | ForEach-Object { Write-Host $_ }
            }
            throw "Stage $Name failed (exit $code); full log: $logPath"
        }
        Write-Host "PASS: $Name"
        Assert-PinnedCheckout
    }
    try {
        # Explicitly build all eight projects, including the Monitor host and
        # portable CLI/tests, before running the established Windows gate.
        Invoke-IntegrationStage 'solution-build' 'dotnet' @('build','DOTNET.sln','-c','Release','--nologo')
        $trx = Join-Path $dir 'cli.trx'
        Invoke-IntegrationStage 'cli-tests' 'dotnet' @('test','Carthago.Cli.Tests/Carthago.Cli.Tests.csproj','-c','Release','--no-build','--no-restore','--results-directory',$dir,'--logger','trx;LogFileName=cli.trx')
        if (-not (Test-Path -LiteralPath $trx -PathType Leaf)) { throw 'CLI TRX missing.' }
        [xml]$xml = Get-Content -LiteralPath $trx -Raw
        $counters = $xml.SelectSingleNode("//*[local-name()='ResultSummary']/*[local-name()='Counters']")
        if ($null -eq $counters) { throw 'CLI TRX counters missing.' }
        $total = [int]$counters.GetAttribute('total')
        $passed = [int]$counters.GetAttribute('passed')
        $executed = [int]$counters.GetAttribute('executed')
        $failed = [int]$counters.GetAttribute('failed')
        $report.cliTests = [ordered]@{ total=$total; passed=$passed; executed=$executed; failed=$failed }
        if ($total -le 0 -or $total -ne $passed -or $total -ne $executed -or $failed -ne 0) { throw 'CLI tests incomplete or nonpassing.' }
        Write-Host "CLI tests: $passed/$total passed; $failed failed."
        # A unique per-run TRX avoids attributing a stale standalone result to
        # this integration SHA. Preserve the original failure and exit status.
        $windowsResults = Join-Path $dir 'windows-tests'
        $windowsTrx = Join-Path $windowsResults 'carthago-tests.trx'
        $shell = (Get-Process -Id $PID).Path
        try {
            Invoke-IntegrationStage 'windows-verification' $shell @('-NoProfile','-File',(Join-Path $root 'verify-local.ps1'),'-TestResultsDirectory',$windowsResults)
        } finally {
            try {
                if (Test-Path -LiteralPath $windowsTrx -PathType Leaf) {
                    [xml]$windowsXml = Get-Content -LiteralPath $windowsTrx -Raw
                    $wc = $windowsXml.SelectSingleNode("//*[local-name()='ResultSummary']/*[local-name()='Counters']")
                    if ($null -eq $wc) { throw 'Windows TRX counters missing.' }
                    $report.windowsTests = [ordered]@{
                        total=[int]$wc.GetAttribute('total'); passed=[int]$wc.GetAttribute('passed')
                        executed=[int]$wc.GetAttribute('executed'); failed=[int]$wc.GetAttribute('failed')
                    }
                    Write-Host ("Windows tests: {0}/{1} passed; {2} failed; {3} executed." -f $report.windowsTests.passed,$report.windowsTests.total,$report.windowsTests.failed,$report.windowsTests.executed)
                    $failedRows = @($windowsXml.SelectNodes("//*[local-name()='UnitTestResult' and @outcome='Failed']"))
                    if ($failedRows.Count -gt 0) {
                        Write-Host "--- Windows failed tests ($($failedRows.Count)) ---"
                        foreach ($row in @($failedRows | Select-Object -First 40)) {
                            Write-Host ("FAIL: " + $row.GetAttribute('testName'))
                            $message = $row.SelectSingleNode("*[local-name()='Output']/*[local-name()='ErrorInfo']/*[local-name()='Message']")
                            if ($null -ne $message) {
                                $line = ($message.InnerText -replace '\s+', ' ').Trim()
                                if ($line.Length -gt 600) { $line = $line.Substring(0,600) + ' ...' }
                                Write-Host "  $line"
                            }
                        }
                        if ($failedRows.Count -gt 40) { Write-Host 'Additional failures are in the complete TRX.' }
                    }
                    Write-Host "Windows TRX: $windowsTrx"
                } else {
                    Write-Host 'No Windows TRX produced; inspect the local test log for build or test-host failure.'
                }
            } catch {
                Write-Host "Windows test diagnostics unavailable: $($_.Exception.Message)"
            }
        }
        $windowsLog = Get-Content -LiteralPath (Join-Path $dir 'windows-verification.log') -Raw
        if ($windowsLog -notmatch '(?m)^PASS: local build, tests and replay validation\.\s*$') { throw 'Windows verifier did not report final PASS.' }
        Assert-PinnedCheckout
        $report.status = 'SyntheticIntegrationPassed'
    } catch {
        $report.status = 'Failed'
        $report.blocker = $_.Exception.Message
        throw
    } finally {
        $report.finishedUtc = [DateTime]::UtcNow.ToString('o')
        $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $dir 'integration.json') -Encoding UTF8
        Write-Host "Integration report: $dir"
    }
} finally { Pop-Location }

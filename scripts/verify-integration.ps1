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
        cliTests = $null; blocker = $null; fieldAccuracyQualified = $false
    }
    function Invoke-IntegrationStage([string]$Name, [string]$Command, [string[]]$Arguments) {
        Assert-PinnedCheckout
        $previous = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            & $Command @Arguments *> (Join-Path $dir ($Name + '.log'))
            $code = $LASTEXITCODE
        } finally { $ErrorActionPreference = $previous }
        $report.stages[$Name] = $code
        if ($code -ne 0) { throw "Stage $Name failed (exit $code); inspect its log." }
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
        # Run in a child shell because verify-local.ps1 may call exit.
        $shell = (Get-Process -Id $PID).Path
        Invoke-IntegrationStage 'windows-verification' $shell @('-NoProfile','-File',(Join-Path $root 'verify-local.ps1'))
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

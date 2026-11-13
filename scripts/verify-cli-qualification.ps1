# SPDX-License-Identifier: MIT
# CLI-006E: owner-run, pinned portable qualification; optional Windows parity.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$SourceSha,
    [switch]$AuthorizedTestTime,
    [switch]$IncludeWindowsParity
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $AuthorizedTestTime) { throw 'Requires owner-authorized test time for the selected SHA.' }
if ($IncludeWindowsParity -and $env:OS -ne 'Windows_NT') { throw 'Windows parity requires Windows and the .NET SDK.' }
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
    $dir = Join-Path $root ('build-verify/cli-qualification/' + $runId)
    New-Item -ItemType Directory -Path $dir | Out-Null
    $report = [ordered]@{
        schemaVersion=1; sourceSha=$SourceSha; startedUtc=[DateTime]::UtcNow.ToString('o')
        finishedUtc=$null; status='NotCompleted'; sdkVersion=$null
        platform=[System.Environment]::OSVersion.VersionString
        windowsParityRequested=[bool]$IncludeWindowsParity; stages=[ordered]@{}; suites=[ordered]@{}
        portableSyntheticQualified=$false; windowsParityQualified=$false
        fieldAccuracyQualified=$false; liveCaptureQualified=$false; deploymentQualified=$false
        blocker=$null
    }
    function Invoke-Stage([string]$Name,[string[]]$Arguments) {
        Assert-PinnedCheckout
        $previous=$ErrorActionPreference
        $ErrorActionPreference='Continue'
        try {
            & dotnet @Arguments *> (Join-Path $dir ($Name + '.log'))
            $code=$LASTEXITCODE
        } finally { $ErrorActionPreference=$previous }
        $report.stages[$Name]=$code
        Assert-PinnedCheckout
        return $code
    }
    function Require-Stage([string]$Name,[string[]]$Arguments) {
        $code=Invoke-Stage $Name $Arguments
        if ($code -ne 0) { throw "Stage $Name failed (exit $code); inspect its log." }
    }
    function Invoke-TestSuite([string]$Name,[string]$Project,[string]$Filter,[hashtable]$RequiredClasses) {
        $trx=Join-Path $dir ($Name + '.trx')
        $arguments=@('test',$Project,'-c','Release','--no-build','--no-restore','--results-directory',$dir,'--logger',('trx;LogFileName=' + $Name + '.trx'))
        if ($Filter) { $arguments+=@('--filter',$Filter) }
        $code=Invoke-Stage $Name $arguments
        if (-not (Test-Path -LiteralPath $trx -PathType Leaf)) { throw "Suite $Name TRX missing (exit $code)." }
        [xml]$xml=Get-Content -LiteralPath $trx -Raw
        $counters=$xml.SelectSingleNode("//*[local-name()='ResultSummary']/*[local-name()='Counters']")
        if ($null -eq $counters) { throw "Suite $Name TRX counters missing." }
        $counts=[ordered]@{}
        foreach ($key in @('total','executed','passed','failed')) {
            $value=$counters.GetAttribute($key)
            if ($value -notmatch '^[0-9]+$') { throw "Suite $Name invalid TRX counter $key." }
            $counts[$key]=[int]$value
        }
        $classes=[ordered]@{}
        $report.suites[$Name]=[ordered]@{ counters=$counts; requiredClasses=$classes }
        # Map result test IDs to declared test classes, rather than inferring
        # coverage from source filenames or a passing aggregate counter.
        $byId=@{}
        foreach ($definition in $xml.SelectNodes("//*[local-name()='TestDefinitions']/*[local-name()='UnitTest']")) {
            $method=$definition.SelectSingleNode("*[local-name()='TestMethod']")
            if ($null -ne $method) { $byId[$definition.GetAttribute('id')]=$method.GetAttribute('className') }
        }
        foreach ($class in $RequiredClasses.Keys) { $classes[$class]=0 }
        foreach ($result in $xml.SelectNodes("//*[local-name()='Results']/*[local-name()='UnitTestResult']")) {
            if ($result.GetAttribute('outcome') -cne 'Passed') { continue }
            $id=$result.GetAttribute('testId')
            if (-not $byId.ContainsKey($id)) { throw "Suite $Name passed result has no test definition." }
            $className=($byId[$id] -split ',')[0].Trim()
            if ($RequiredClasses.ContainsKey($className)) { $classes[$className]++ }
        }
        if ($code -ne 0 -or $counts.total -le 0 -or $counts.total -ne $counts.executed -or
            $counts.total -ne $counts.passed -or $counts.failed -ne 0) { throw "Suite $Name incomplete or nonpassing (exit $code)." }
        foreach ($class in $RequiredClasses.Keys) {
            if ($classes[$class] -lt $RequiredClasses[$class]) { throw "Suite $Name missing required passed cases for $class." }
        }
    }
    try {
        Require-Stage 'sdk-version' @('--version')
        $report.sdkVersion=(Get-Content -LiteralPath (Join-Path $dir 'sdk-version.log') -Raw).Trim()
        Require-Stage 'portable-build' @('build','Carthago.Cli.Tests/Carthago.Cli.Tests.csproj','-c','Release','--no-incremental','--nologo')
        Invoke-TestSuite 'portable-tests' 'Carthago.Cli.Tests/Carthago.Cli.Tests.csproj' '' @{
            'Carthago.Cli.Tests.PortableReplayTests'=12
            'Carthago.Cli.Tests.PortableRuleCapabilityTests'=9
            'Carthago.Cli.Tests.PortableHttpBatchTests'=18
            'Carthago.Cli.Tests.PortableR587Tests'=7
            'Carthago.Cli.Tests.PortableR589Tests'=11
            'Carthago.Cli.Tests.PortablePcapInspectionTests'=1
            'Carthago.Cli.Tests.PortablePcapNgTests'=1
            'Carthago.Cli.Tests.CliApplicationTests'=1
        }
        # Exercise the built executable entry point, not only the in-process API.
        $cli=Join-Path $root 'Carthago.Cli/bin/Release/net8.0/carthago.dll'
        if (-not (Test-Path -LiteralPath $cli -PathType Leaf)) { throw 'Built CLI assembly missing.' }
        Require-Stage 'cli-capabilities' @($cli,'rules','capabilities','--json')
        $catalog=Get-Content -LiteralPath (Join-Path $dir 'cli-capabilities.log') -Raw | ConvertFrom-Json
        $expected=@('R586','R587','R588','R589','R590')
        $actual=@($catalog.rules | ForEach-Object { $_.ruleId })
        if ($catalog.schemaVersion -ne 1 -or $catalog.scope -cne 'compiled_portable_catalog' -or
            $catalog.detectionValidation -cne 'not_assessed' -or $catalog.supportedCount -ne $expected.Count -or
            ($actual -join ',') -cne ($expected -join ',')) { throw 'CLI capability smoke contract mismatch.' }
        Require-Stage 'cli-unsupported' @($cli,'rules','capabilities','R1000','--json')
        $unsupported=Get-Content -LiteralPath (Join-Path $dir 'cli-unsupported.log') -Raw | ConvertFrom-Json
        if (@($unsupported.rules).Count -ne 1 -or $unsupported.rules[0].ruleId -cne 'R1000' -or
            $unsupported.rules[0].status -cne 'unsupported_detector' -or
            $unsupported.rules[0].registration -cne 'not_assessed') { throw 'CLI unsupported smoke contract mismatch.' }
        $report.portableSyntheticQualified=$true
        if ($IncludeWindowsParity) {
            Require-Stage 'windows-build' @('build','Carthago.Tests/Carthago.Tests.csproj','-c','Release','--no-incremental','--nologo')
            Invoke-TestSuite 'windows-parity' 'Carthago.Tests/Carthago.Tests.csproj' 'FullyQualifiedName~PortableR587ParityTests|FullyQualifiedName~PortableR589ParityTests|FullyQualifiedName~PortableHttpBatchParityTests' @{
                'Carthago.Tests.PortableR587ParityTests'=4
                'Carthago.Tests.PortableR589ParityTests'=4
                'Carthago.Tests.PortableHttpBatchParityTests'=15
            }
            $report.windowsParityQualified=$true
        }
        Assert-PinnedCheckout
        $report.status=if ($IncludeWindowsParity) { 'SyntheticPortableAndWindowsParityPassed' } else { 'SyntheticPortablePassed' }
    } catch {
        $report.status='Failed';$report.blocker=$_.Exception.Message
        throw
    } finally {
        $report.finishedUtc=[DateTime]::UtcNow.ToString('o')
        $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $dir 'qualification.json') -Encoding UTF8
        Write-Host "CLI qualification report: $dir"
    }
} finally { Pop-Location }

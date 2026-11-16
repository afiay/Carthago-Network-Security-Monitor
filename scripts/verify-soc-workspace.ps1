# SPDX-License-Identifier: MIT
# Owner-run, non-destructive SOC WPF verification on Windows.
# After the final clean source recheck, atomically write a replayable completion
# report with pre/post checkout SHA, original TRX ID/hash, and all stage log hashes.
# Nothing is admitted as field quality; no capture or live network operations.
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_NOLOGO = '1'

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'CARTHAGO SOC WPF verification must run on Windows.'
}
foreach ($command in @('dotnet','git')) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Required command missing from PATH: $command"
    }
}

$repoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $PSScriptRoot 'SocWorkspaceCompletion.psm1') -Force
$branchRequired = 'feature/carthago-reliability-hardening'
$trackingRef = 'refs/remotes/origin/' + $branchRequired
$stamp = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')
$runLabel = $stamp + '-' + $PID + '-' + [guid]::NewGuid().ToString('N').Substring(0,8)
$resultDirectory = Join-Path $repoRoot ("TestResults/soc-workspace-$runLabel")
$testProject = Join-Path $repoRoot 'Carthago.Tests/Carthago.Tests.csproj'
$filter = 'FullyQualifiedName~NetworkInvestigation|FullyQualifiedName~IncidentTimeline|FullyQualifiedName~IncidentDetectionLinkVm'
$stageRecords = [ordered]@{}

function Get-SocCheckout {
    $branch = (& git symbolic-ref --short HEAD)
    if ($LASTEXITCODE -ne 0 -or @($branch).Count -ne 1 -or
        $branch.Trim() -cne $branchRequired) {
        throw 'SOC verification requires the existing feature branch.'
    }
    $sourceSha = (& git rev-parse HEAD)
    if ($LASTEXITCODE -ne 0 -or @($sourceSha).Count -ne 1 -or
        $sourceSha.Trim() -cnotmatch '^[a-f0-9]{40}$') {
        throw 'SOC checkout source SHA invalid.'
    }
    $trackedSha = (& git rev-parse $trackingRef)
    if ($LASTEXITCODE -ne 0 -or @($trackedSha).Count -ne 1 -or
        $trackedSha.Trim() -cnotmatch '^[a-f0-9]{40}$') {
        throw 'SOC tracking SHA unavailable.'
    }
    $dirty = @(& git status --porcelain --untracked-files=all)
    if ($LASTEXITCODE -ne 0 -or $dirty.Count -gt 0) {
        throw 'Working tree is not clean. Preserve local edits before SOC qualification.'
    }
    if ($sourceSha.Trim() -cne $trackedSha.Trim()) {
        throw 'Local source SHA differs from its origin tracking ref.'
    }
    return [ordered]@{
        branch = $branch.Trim()
        sourceSha = $sourceSha.Trim()
        originSha = $trackedSha.Trim()
    }
}

function Invoke-SocStage {
    param([Parameter(Mandatory)][string]$Name,
          [Parameter(Mandatory)][string[]]$Arguments)
    if ($stageRecords.Contains($Name)) { throw "SOC stage already executed: $Name" }
    $logPath = Join-Path $resultDirectory ($Name + '.log')
    Write-Host "SOC validation: $Name"
    # In Windows PowerShell 5.1 native stderr may surface as an ErrorRecord.
    # The stage contract is the exit code; original stdout/stderr stays in logs.
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $code = $null
    try {
        & dotnet @Arguments *>&1 | Tee-Object -FilePath $logPath | Out-Host
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $oldPreference
    }
    if ($null -eq $code -or $code -isnot [int] -or
        -not (Test-Path -LiteralPath $logPath -PathType Leaf)) {
        throw "SOC stage has no valid exit code or log: $Name"
    }
    $stageRecords[$Name] = [ordered]@{
        exitCode = [int]$code
        logFileName = ($Name + '.log')
        logSha256 = (Get-FileHash -LiteralPath $logPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    if ($code -ne 0) { throw "SOC stage $Name failed (exit code $code); log: $logPath" }
}

Push-Location $repoRoot
try {
    $preRun = Get-SocCheckout
    $startedUtc = [DateTime]::UtcNow.ToString('o')
    # Unique directory: never overwrite an earlier run or a recovered original.
    $null = New-Item -ItemType Directory -Path $resultDirectory -ErrorAction Stop
    $sourceFile = Join-Path $resultDirectory 'source-sha.txt'
    $preRun['sourceSha'] | Out-File -LiteralPath $sourceFile -Encoding Unicode

    Invoke-SocStage 'sdk-version' @('--version')
    Copy-Item -LiteralPath (Join-Path $resultDirectory 'sdk-version.log') -Destination (Join-Path $resultDirectory 'sdk-version.txt')
    Invoke-SocStage 'restore' @('restore', $testProject, '--nologo')
    Invoke-SocStage 'build-release' @('build', $testProject, '-c', 'Release', '--no-restore', '--nologo')
    Invoke-SocStage 'soc-tests' @(
        'test', $testProject, '-c', 'Release', '--no-build', '--no-restore',
        '--filter', $filter, '--logger', 'trx;LogFileName=soc-workspace-tests.trx',
        '--results-directory', $resultDirectory, '--nologo'
    )

    $trxPath = Join-Path $resultDirectory 'soc-workspace-tests.trx'
    $trxEvidence = Get-SocWorkspaceTrxEvidence -Path $trxPath
    $writtenPreSha = (Get-Content -LiteralPath $sourceFile -Raw).Trim()
    if ($writtenPreSha -cne $preRun['sourceSha']) {
        throw 'Stored pre-run source SHA changed during SOC verification.'
    }
    foreach ($stageName in @('sdk-version','restore','build-release','soc-tests')) {
        $log = Join-Path $resultDirectory ($stageName + '.log')
        $actualHash = (Get-FileHash -LiteralPath $log -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -cne $stageRecords[$stageName]['logSha256']) {
            throw "SOC stage log changed after execution: $stageName"
        }
    }

    # Critical: this check MUST complete before completion.json is created.
    $postRun = Get-SocCheckout
    if ($preRun['sourceSha'] -cne $postRun['sourceSha'] -or
        $preRun['branch'] -cne $postRun['branch'] -or
        $preRun['originSha'] -cne $postRun['originSha']) {
        throw 'Source, branch or tracking SHA changed during SOC verification.'
    }
    $finishedUtc = [DateTime]::UtcNow.ToString('o')
    $record = [ordered]@{
        schemaVersion = 1
        purpose = 'soc-workspace-final-provenance-v1'
        status = 'SyntheticSocPassed'
        branch = $preRun['branch']
        postRunBranch = $postRun['branch']
        sourceSha = $preRun['sourceSha']
        preRunSha = $preRun['sourceSha']
        postRunSha = $postRun['sourceSha']
        preRunOriginSha = $preRun['originSha']
        postRunOriginSha = $postRun['originSha']
        sourceShaFileSha256 = (Get-FileHash -LiteralPath $sourceFile -Algorithm SHA256).Hash.ToLowerInvariant()
        startedUtc = $startedUtc
        finishedUtc = $finishedUtc
        trxRunId = $trxEvidence['trxRunId']
        trxSha256 = $trxEvidence['trxSha256']
        trxStartedUtc = $trxEvidence['trxStartedUtc']
        trxFinishedUtc = $trxEvidence['trxFinishedUtc']
        testResults = $trxEvidence['testResults']
        requiredGroups = $trxEvidence['requiredGroups']
        stages = $stageRecords
        evidenceAdmitted = $false
        fieldAccuracyQualified = $false
        manualWpfValidated = $false
    }
    $completionPath = Join-Path $resultDirectory 'completion.json'
    Publish-SocWorkspaceCompletionRecord -Record $record -Path $completionPath

    Write-Host "SOURCE BUILD AND SOC TEST STAGES PASSED. Evidence: $resultDirectory"
    Write-Host "SOC source-pinned completion report: $completionPath"
    Write-Host 'Manual WPF visual, navigation, capture, export, and accessibility checks are still required.'
} finally {
    Pop-Location
}

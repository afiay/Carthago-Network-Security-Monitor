# SPDX-License-Identifier: MIT
# Local, non-destructive Windows validation. No GitHub Actions or capture start.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_NOLOGO = '1'

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'CARTHAGO SOC WPF verification must run on Windows.'
}
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw 'The .NET SDK is not available on PATH.'
}
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw 'Git is not available on PATH; source identity cannot be pinned.'
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$resultDirectory = Join-Path $repoRoot ("TestResults/soc-workspace-$stamp-$PID")
New-Item -ItemType Directory -Path $resultDirectory -Force | Out-Null
$testProject = Join-Path $repoRoot 'Carthago.Tests/Carthago.Tests.csproj'
$filter = 'FullyQualifiedName~NetworkInvestigation|FullyQualifiedName~IncidentTimeline|FullyQualifiedName~IncidentDetectionLinkVm'

function Invoke-SocStage {
    param([string]$Name, [string[]]$Arguments)
    $log = Join-Path $resultDirectory "$Name.log"
    Write-Host "SOC validation: $Name"
    # Windows PowerShell 5.1 can promote native stderr to ErrorRecords.
    # Retain all output and determine success exclusively from exit code.
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & dotnet @Arguments *>&1 | Tee-Object -FilePath $log | Out-Host
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $oldPreference
    }
    if ($exitCode -ne 0) {
        throw "$Name failed (exit code $exitCode); see $log"
    }
}

Push-Location $repoRoot
try {
    $branch = (& git symbolic-ref --short HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $branch -ne 'feature/carthago-reliability-hardening') {
        throw "Expected feature/carthago-reliability-hardening, got '$branch'."
    }
    $dirty = @(& git status --porcelain)
    if ($LASTEXITCODE -ne 0 -or $dirty.Count -gt 0) {
        throw 'Working tree is not clean. Save your changes before validating a release candidate.'
    }
    $sourceSha = (& git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $sourceSha.Length -ne 40) { throw 'Cannot resolve source SHA.' }
    $trackedSha = (& git rev-parse refs/remotes/origin/feature/carthago-reliability-hardening).Trim()
    if ($LASTEXITCODE -ne 0 -or $trackedSha -ne $sourceSha) {
        throw 'Local branch differs from origin tracking ref; pull or reconcile before validation.'
    }
    & dotnet --version | Out-File -FilePath (Join-Path $resultDirectory 'sdk-version.txt')
    $sourceSha | Out-File -FilePath (Join-Path $resultDirectory 'source-sha.txt')

    Invoke-SocStage 'restore' @('restore', $testProject, '--nologo')
    Invoke-SocStage 'build-release' @('build', $testProject, '-c', 'Release', '--no-restore', '--nologo')
    Invoke-SocStage 'soc-tests' @('test', $testProject, '-c', 'Release', '--no-build', '--no-restore',
        '--filter', $filter, '--logger', 'trx;LogFileName=soc-workspace-tests.trx',
        '--results-directory', $resultDirectory, '--nologo')

    $trxPath = Join-Path $resultDirectory 'soc-workspace-tests.trx'
    if (-not (Test-Path -LiteralPath $trxPath)) { throw "Missing xUnit TRX: $trxPath" }
    [xml]$trx = Get-Content -LiteralPath $trxPath -Raw
    $counters = $trx.SelectSingleNode("//*[local-name()='Counters']")
    if ($null -eq $counters -or [int]$counters.GetAttribute('total') -le 0 -or
        [int]$counters.GetAttribute('failed') -gt 0 -or
        [int]$counters.GetAttribute('passed') -ne [int]$counters.GetAttribute('total')) {
        throw "SOC test TRX must contain only passed tests (no skipped or failing tests): $trxPath"
    }
    $testMethods = @($trx.SelectNodes("//*[local-name()='TestMethod']"))
    foreach ($marker in @('NetworkInvestigation', 'IncidentTimeline', 'IncidentDetectionLinkVm')) {
        if (@($testMethods | Where-Object { $_.GetAttribute('className') -like "*$marker*" }).Count -eq 0) {
            throw "Expected SOC test group '$marker' is absent from TRX: $trxPath"
        }
    }

    $afterSha = (& git rev-parse HEAD).Trim()
    $afterDirty = @(& git status --porcelain)
    if ($LASTEXITCODE -ne 0 -or $afterSha -ne $sourceSha -or $afterDirty.Count -gt 0) {
        throw 'Source changed while validating; discard the result as a release gate and rerun on a pinned clean checkout.'
    }

    Write-Host "SOURCE BUILD AND SOC TEST STAGES PASSED. Evidence: $resultDirectory"
    Write-Host 'Manual WPF visual, navigation, capture, export, and accessibility checks are still required.'
}
finally {
    Pop-Location
}

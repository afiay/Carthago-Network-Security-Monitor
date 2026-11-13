# SPDX-License-Identifier: MIT
# Local-only active sensor qualification. No GitHub Actions or LAN probes.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_NOLOGO = '1'

$root = $PSScriptRoot
Push-Location $root
try {
    $expected = [ordered]@{
        TcpExposureSensorTests = 17
        DnsIntegritySensorTests = 33
        TlsInspectionSensorTests = 22
        HttpHealthSensorTests = 38
        GatewayIntegritySensorTests = 23
        SnmpInfrastructureSensorTests = 41
        ActiveEvidenceStoreTests = 16
        ActiveSensorManagerTests = 15
        ActiveChangeDetectorTests = 15
        ActiveFindingQualificationTests = 14
    }
    $branch = (& git branch --show-current).Trim()
    if ($LASTEXITCODE -ne 0 -or $branch -ne 'feature/carthago-reliability-hardening') {
        throw 'Switch to feature/carthago-reliability-hardening before qualification.'
    }
    $sha = (& git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $sha -notmatch '^[0-9a-f]{40}$') { throw 'Cannot identify source commit.' }
    $dirty = @(& git status --porcelain --untracked-files=all)
    if ($LASTEXITCODE -ne 0 -or $dirty.Count -ne 0) {
        throw 'Qualification requires a clean worktree (including untracked source files).'
    }
    $runId = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss') + '-' + $sha.Substring(0,12) + '-' + [Guid]::NewGuid().ToString('N').Substring(0,8)
    $dir = Join-Path $root ('build-verify/active-sensors/' + $runId)
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $reportPath = Join-Path $dir 'qualification.json'
    $trxPath = Join-Path $dir 'active-sensors.trx'
    $report = [ordered]@{
        schemaVersion = 1
        sourceSha = $sha
        branch = $branch
        startedUtc = [DateTime]::UtcNow.ToString('o')
        finishedUtc = $null
        status = 'NotExecuted'
        buildExitCode = $null
        testExitCode = $null
        total = 0
        passed = 0
        failedOrSkipped = 0
        suites = @()
        blocker = $null
        liveNetworkValidated = $false
    }
    function Write-Report {
        $report.finishedUtc = [DateTime]::UtcNow.ToString('o')
        $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $reportPath -Encoding UTF8
        Write-Host "Report: $reportPath"
    }
    function Invoke-Dotnet([string[]]$Arguments, [string]$LogPath) {
        $previous = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            & dotnet @Arguments *> $LogPath
            return $LASTEXITCODE
        } finally { $ErrorActionPreference = $previous }
    }
    if (-not (Get-Command dotnet -ErrorAction SilentlyContinue) -or $env:OS -ne 'Windows_NT') {
        $report.blocker = 'Windows and .NET SDK required.'
        Write-Report
        exit 1
    }
    $project = Join-Path $root 'Carthago.Tests/Carthago.Tests.csproj'
    Write-Host "AS-Q01: Release build at $sha"
    $report.buildExitCode = Invoke-Dotnet @('build', $project, '-c', 'Release', '--nologo') (Join-Path $dir 'build.log')
    if ($report.buildExitCode -ne 0) {
        $report.status = 'BuildFailed'
        $report.blocker = 'Release build failed. Tests not executed.'
        Write-Report
        Get-Content -LiteralPath (Join-Path $dir 'build.log') -Tail 35
        exit 1
    }
    $filter = ($expected.Keys | ForEach-Object { 'FullyQualifiedName~' + $_ }) -join '|'
    Write-Host 'AS-Q01: execute ten active sensor suites (synthetic and loopback only)'
    $report.testExitCode = Invoke-Dotnet @('test', $project, '-c', 'Release', '--no-build', '--no-restore',
        '--filter', $filter, '--logger', 'trx;LogFileName=active-sensors.trx', '--results-directory', $dir) (Join-Path $dir 'tests.log')
    if (-not (Test-Path -LiteralPath $trxPath)) {
        $report.status = 'Incomplete'
        $report.blocker = 'No fresh TRX was produced.'
        Write-Report
        Get-Content -LiteralPath (Join-Path $dir 'tests.log') -Tail 35
        exit 1
    }
    try {
        [xml]$trx = Get-Content -LiteralPath $trxPath -Raw
        $definitions = @{}
        foreach ($unit in $trx.SelectNodes("//*[local-name()='UnitTest']")) {
            $method = $unit.SelectSingleNode("./*[local-name()='TestMethod']")
            if ($null -ne $method) {
                $className = $method.GetAttribute('className').Split(',')[0].Trim()
                $definitions[$unit.GetAttribute('id')] = $className
            }
        }
        $counts = @{}
        foreach ($name in $expected.Keys) { $counts[$name] = [ordered]@{ total = 0; passed = 0; failedOrSkipped = 0 } }
        $unknown = 0
        $resultNodes = @($trx.SelectNodes("//*[local-name()='UnitTestResult']"))
        foreach ($result in $resultNodes) {
            $className = $definitions[$result.GetAttribute('testId')]
            $outcome = $result.GetAttribute('outcome')
            $report.total++
            if ($outcome -eq 'Passed') { $report.passed++ } else { $report.failedOrSkipped++ }
            if (-not $className -or -not $className.StartsWith('Carthago.Tests.')) { $unknown++; continue }
            $name = $className.Substring('Carthago.Tests.'.Length)
            if (-not $counts.ContainsKey($name)) { $unknown++; continue }
            $counts[$name].total++
            if ($outcome -eq 'Passed') { $counts[$name].passed++ } else { $counts[$name].failedOrSkipped++ }
        }
        $complete = $true
        foreach ($name in $expected.Keys) {
            $count = $counts[$name]
            $report.suites += [ordered]@{ name = $name; minimumExpected = $expected[$name];
                total = $count.total; passed = $count.passed; failedOrSkipped = $count.failedOrSkipped }
            if ($count.total -lt $expected[$name] -or $count.failedOrSkipped -ne 0) { $complete = $false }
            Write-Host ("{0}: {1}/{2} passed (minimum {3})" -f $name, $count.passed, $count.total, $expected[$name])
        }
        $summary = $trx.SelectSingleNode("//*[local-name()='ResultSummary']")
        $counters = $trx.SelectSingleNode("//*[local-name()='ResultSummary']/*[local-name()='Counters']")
        if ($null -eq $summary -or $null -eq $counters -or
            [int]$counters.GetAttribute('total') -ne $report.total -or
            [int]$counters.GetAttribute('passed') -ne $report.passed -or $unknown -ne 0) { $complete = $false }
        $afterSha = (& git rev-parse HEAD).Trim()
        $afterDirty = @(& git status --porcelain --untracked-files=all)
        if ($afterSha -ne $sha -or $afterDirty.Count -ne 0) {
            $report.status = 'SourceChanged'
            $report.blocker = 'Source or worktree changed during verification.'
        } elseif ($report.testExitCode -ne 0 -or $report.failedOrSkipped -ne 0) {
            $report.status = 'TestFailed'
            $report.blocker = 'Test process failed or non-passing outcomes present.'
        } elseif (-not $complete -or $report.total -eq 0) {
            $report.status = 'Incomplete'
            $report.blocker = 'Missing suites/cases, unknown test results or inconsistent TRX counters.'
        } else { $report.status = 'Passed' }
    } catch {
        $report.status = 'Incomplete'
        $report.blocker = 'TRX parsing or verification failed: ' + $_.Exception.Message
    }
    Write-Report
    Write-Host ("AS-Q01: {0} ({1}/{2} passed); live network validation NOT performed." -f $report.status, $report.passed, $report.total)
    if ($report.status -ne 'Passed') { exit 1 }
    exit 0
} finally { Pop-Location }

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
        ActiveEvidenceStoreTests = 21
        ActiveSensorManagerTests = 15
        ActiveChangeDetectorTests = 15
        ActiveFindingQualificationTests = 15
        ActiveSensorPipelineLabTests = 5
        ActiveSensorLifecycleStressTests = 7
        ActiveIncidentContextTests = 8
        ActiveSensorProfileStoreTests = 10
        ActiveSchedulerOwnershipTests = 5
        ActiveExecutionGrantTests = 9
        ActiveSensorWorkerTests = 8
        SnmpCredentialVaultTests = 7
        ScheduledSnmpAuthorizationTests = 7
        ActiveNpcapCoordinationTests = 8
        ScheduledGatewayTests = 7
        ActiveServiceLifecycleTests = 8
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
        monitorBuildExitCode = $null
        monitorHelpExitCode = $null
        monitorInvalidCommandExitCode = $null
        processQualificationBuildExitCode = $null
        processQualificationExitCode = $null
        liveLabContractExitCode = $null
        expectedTotal = ($expected.Values | Measure-Object -Sum).Sum
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
    $monitorProject = Join-Path $root 'Carthago.Monitor/Carthago.Monitor.csproj'
    $report.monitorBuildExitCode = Invoke-Dotnet @('build', $monitorProject, '-c', 'Release', '--nologo') (Join-Path $dir 'monitor-build.log')
    if ($report.monitorBuildExitCode -ne 0) {
        $report.status = 'BuildFailed'
        $report.blocker = 'Monitor Release build failed. Tests not executed.'
        Write-Report
        Get-Content -LiteralPath (Join-Path $dir 'monitor-build.log') -Tail 35
        exit 1
    }
    # Exercise the actual console entry point, not just the in-process worker.
    # Neither invocation reads saved profiles, opens Npcap or sends probes.
    $report.monitorHelpExitCode = Invoke-Dotnet @('run', '--project', $monitorProject, '-c', 'Release',
        '--no-build', '--no-restore', '--', '--help') (Join-Path $dir 'monitor-help.log')
    $report.monitorInvalidCommandExitCode = Invoke-Dotnet @('run', '--project', $monitorProject, '-c', 'Release',
        '--no-build', '--no-restore', '--', 'active', 'run', '--profile', 'invalid') (Join-Path $dir 'monitor-invalid.log')
    if ($report.monitorHelpExitCode -ne 0 -or $report.monitorInvalidCommandExitCode -ne 2 -or
        -not (Select-String -LiteralPath (Join-Path $dir 'monitor-help.log') -SimpleMatch 'carthago-monitor active status' -Quiet) -or
        -not (Select-String -LiteralPath (Join-Path $dir 'monitor-invalid.log') -SimpleMatch 'Invalid or duplicate profile ID.' -Quiet)) {
        $report.status = 'HostSmokeFailed'
        $report.blocker = 'Monitor executable help or invalid-command contract failed.'
        Write-Report
        exit 1
    }
    $processProject = Join-Path $root 'Carthago.ActiveQualification/Carthago.ActiveQualification.csproj'
    $report.processQualificationBuildExitCode = Invoke-Dotnet @('build', $processProject, '-c', 'Release', '--nologo') (Join-Path $dir 'process-build.log')
    if ($report.processQualificationBuildExitCode -ne 0) {
        $report.status = 'BuildFailed'
        $report.blocker = 'Separate-process qualification executable build failed.'
        Write-Report
        exit 1
    }
    $report.processQualificationExitCode = Invoke-Dotnet @('run', '--project', $processProject, '-c', 'Release',
        '--no-build', '--no-restore') (Join-Path $dir 'process-qualification.log')
    if ($report.processQualificationExitCode -ne 0 -or
        -not (Select-String -LiteralPath (Join-Path $dir 'process-qualification.log') -SimpleMatch 'PASS AS-Q07G3 4/4 separate-process scenarios' -Quiet)) {
        $report.status = 'ProcessQualificationFailed'
        $report.blocker = 'Separate-process ownership or authorization qualification failed.'
        Write-Report
        exit 1
    }
    $report.liveLabContractExitCode = Invoke-Dotnet @('run', '--project', $processProject, '-c', 'Release',
        '--no-build', '--no-restore', '--', '--live-contract') (Join-Path $dir 'live-lab-contract.log')
    if ($report.liveLabContractExitCode -ne 0 -or
        -not (Select-String -LiteralPath (Join-Path $dir 'live-lab-contract.log') -SimpleMatch 'PASS AS-Q07G4 offline live-lab contract' -Quiet)) {
        $report.status = 'LiveLabContractFailed'
        $report.blocker = 'Offline physical-lab argument or result-classification contract failed.'
        Write-Report
        exit 1
    }
    $filter = ($expected.Keys | ForEach-Object { 'FullyQualifiedName~' + $_ }) -join '|'
    Write-Host "AS-Q01: execute $($expected.Count) active sensor suites (synthetic and loopback only)"
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
        $duplicateDefinitions = 0
        foreach ($unit in $trx.SelectNodes("//*[local-name()='UnitTest']")) {
            $method = $unit.SelectSingleNode("./*[local-name()='TestMethod']")
            if ($null -ne $method) {
                $className = $method.GetAttribute('className').Split(',')[0].Trim()
                $id = $unit.GetAttribute('id')
                if (-not $id -or $definitions.ContainsKey($id)) { $duplicateDefinitions++ }
                else { $definitions[$id] = $className }
            }
        }
        $counts = @{}
        foreach ($name in $expected.Keys) { $counts[$name] = [ordered]@{ total = 0; passed = 0; failedOrSkipped = 0 } }
        $unknown = 0
        $executionIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $duplicateExecutions = 0
        $resultNodes = @($trx.SelectNodes("//*[local-name()='UnitTestResult']"))
        foreach ($result in $resultNodes) {
            $executionId = $result.GetAttribute('executionId')
            if (-not $executionId -or -not $executionIds.Add($executionId)) { $duplicateExecutions++ }
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
            $report.suites += [ordered]@{ name = $name; expected = $expected[$name];
                total = $count.total; passed = $count.passed; failedOrSkipped = $count.failedOrSkipped }
            if ($count.total -ne $expected[$name] -or $count.failedOrSkipped -ne 0) { $complete = $false }
            Write-Host ("{0}: {1}/{2} passed (expected {3})" -f $name, $count.passed, $count.total, $expected[$name])
        }
        $summary = $trx.SelectSingleNode("//*[local-name()='ResultSummary']")
        $counters = $trx.SelectSingleNode("//*[local-name()='ResultSummary']/*[local-name()='Counters']")
        if ($null -eq $summary -or $null -eq $counters -or
            [int]$counters.GetAttribute('total') -ne $report.total -or
            [int]$counters.GetAttribute('passed') -ne $report.passed -or
            [int]$counters.GetAttribute('executed') -ne $report.total -or
            $summary.GetAttribute('outcome') -notin @('Completed', 'Passed') -or
            $report.total -ne $report.expectedTotal -or $unknown -ne 0 -or
            $duplicateDefinitions -ne 0 -or $duplicateExecutions -ne 0) { $complete = $false }
        $afterSha = (& git rev-parse HEAD).Trim()
        $shaExit = $LASTEXITCODE
        $afterBranch = (& git branch --show-current).Trim()
        $branchExit = $LASTEXITCODE
        $afterDirty = @(& git status --porcelain --untracked-files=all)
        $dirtyExit = $LASTEXITCODE
        if ($shaExit -ne 0 -or $branchExit -ne 0 -or $dirtyExit -ne 0 -or
            $afterSha -ne $sha -or $afterBranch -ne $branch -or $afterDirty.Count -ne 0) {
            $report.status = 'SourceChanged'
            $report.blocker = 'Source or worktree changed during verification.'
        } elseif ($report.testExitCode -ne 0 -or $report.failedOrSkipped -ne 0) {
            $report.status = 'TestFailed'
            $report.blocker = 'Test process failed or non-passing outcomes present.'
        } elseif (-not $complete -or $report.total -eq 0) {
            $report.status = 'Incomplete'
            $report.blocker = 'Unexpected suite/case counts, duplicate identities, unknown results or inconsistent TRX counters.'
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

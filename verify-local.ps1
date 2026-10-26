# SPDX-License-Identifier: MIT
# Local Windows verification; no GitHub Actions or paid runner required.
[CmdletBinding()]
param([switch]$Details, [switch]$LiveOutput)
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
        $started = Get-Date
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        Write-Host ("START: {0} at {1:HH:mm:ss} (log: build-verify/local-logs/{0}.log)" -f $Name, $started)

        # Native stderr handling is different in Windows PowerShell and
        # PowerShell 7; preserve the existing exit-code and log semantics.
        $previousPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            if ($LiveOutput) {
                # Optional interactive diagnostics: also show the full output
                # while saving exactly the same per-stage log.
                & dotnet @Arguments *>&1 | Tee-Object -FilePath $logFile
            } else {
                & dotnet @Arguments *> $logFile
            }
            $exitCode = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $previousPreference
            $stopwatch.Stop()
        }

        if ($exitCode -ne 0) {
            $script:failures.Add($Name)
            Write-Host ("FAIL: {0} (exit {1}, elapsed {2:n1}s); see build-verify/local-logs/{0}.log" -f
                $Name, $exitCode, $stopwatch.Elapsed.TotalSeconds)
            if ($Details -and -not $LiveOutput) { Get-Content $logFile | Select-Object -Last 40 }
            return $false
        }
        Write-Host ("PASS: {0} (elapsed {1:n1}s)" -f $Name, $stopwatch.Elapsed.TotalSeconds)
        return $true
    }
    function Show-AlertRuleQuality([object]$Report) {
        # Each (replay sample, rule ID, profile) is counted once, even when
        # the detector emits multiple events. Shadow/raw matches are NOT alerts.
        # TP/FN: expected malicious rule alerts; FP: benign alerts plus
        # explicitly forbidden rule matches on malicious samples.
        # Unlabeled alerts on malicious samples are not scored as false positives.
        Write-Host 'Alert-rule quality by profile (labeled offline replays; TP/FP/FN, precision/recall/F1):'
        foreach ($profileName in @($Report.profileResults.PSObject.Properties.Name | Sort-Object)) {
            foreach ($ruleId in @('ALL','R118','R163','R102')) {
                $tp = 0; $fp = 0; $fn = 0
                foreach ($sample in @($Report.sampleResults)) {
                    $profileEntry = $sample.profiles.PSObject.Properties[$profileName]
                    if ($null -eq $profileEntry) { throw "Missing profile $profileName on sample $($sample.name)" }
                    $alertIds = @($profileEntry.Value.alertRuleIds)
                    if ($ruleId -ne 'ALL') {
                        $alertIds = @($alertIds | Where-Object { $_ -eq $ruleId })
                    }
                    if ($sample.classification -eq 'Malicious') {
                        $expected = @($sample.expectedMatches)
                        if ($ruleId -ne 'ALL') {
                            $expected = @($expected | Where-Object { $_ -eq $ruleId })
                        }
                        foreach ($expectedId in $expected) {
                            if ($alertIds -contains $expectedId) { $tp++ } else { $fn++ }
                        }
                        foreach ($forbiddenId in @($sample.unexpectedMatches)) {
                            if ($alertIds -contains $forbiddenId) { $fp++ }
                        }
                    } elseif ($sample.classification -eq 'Benign') {
                        $fp += $alertIds.Count
                    } else {
                        throw "Unrecognized replay classification on sample $($sample.name)"
                    }
                }
                $precision = 'N/A'; $recall = 'N/A'; $f1 = 'N/A'
                if (($tp + $fp) -gt 0) { $precision = '{0:P1}' -f ($tp / ($tp + $fp)) }
                if (($tp + $fn) -gt 0) { $recall = '{0:P1}' -f ($tp / ($tp + $fn)) }
                if ((2 * $tp + $fp + $fn) -gt 0) { $f1 = '{0:P1}' -f ((2 * $tp) / (2 * $tp + $fp + $fn)) }
                Write-Host ("  {0,-15} {1,-4} TP={2} FP={3} FN={4} precision={5} recall={6} F1={7}" -f $profileName,$ruleId,$tp,$fp,$fn,$precision,$recall,$f1)
            }
        }
        Write-Host 'Scope: unique alerted rule IDs per labeled sample, not event counts or production prevalence.'
    }
    function Show-DetectionFunnel([object]$Report) {
        $property = $Report.PSObject.Properties['detectionFunnelByProfile']
        if ($null -eq $property) { throw 'Replay report has no detectionFunnelByProfile metrics' }
        Write-Host 'Detection funnel: raw recognition vs policy gates vs simulated alerts (per expected malicious sample/rule):'
        foreach ($entry in @($property.Value.PSObject.Properties | Sort-Object Name)) {
            $funnel = $entry.Value
            $expected = [int]$funnel.expectedMaliciousRules
            $recognized = [int]$funnel.recognizedByDetector
            $missed = [int]$funnel.detectorMisses
            $alerted = [int]$funnel.simulatedAlerted
            $shadowed = [int]$funnel.policyShadowed
            $disabled = [int]$funnel.policyDisabled
            $missingPolicy = [int]$funnel.missingPolicyDecisions
            $eligibleMissing = [int]$funnel.eligibleButNotAlerted
            $mismatches = [int]$funnel.alertDecisionMismatches
            if ($expected -ne ($recognized + $missed) -or
                $recognized -ne ($alerted + $shadowed + $disabled + $missingPolicy + $eligibleMissing) -or
                $missingPolicy -ne 0 -or $eligibleMissing -ne 0 -or $mismatches -ne 0) {
                throw "Detection funnel has inconsistent policy accounting for $($entry.Name)"
            }

            $detectorRate = if ($expected -gt 0) { '{0:P1}' -f ($recognized / $expected) } else { 'N/A' }
            $alertRate = if ($expected -gt 0) { '{0:P1}' -f ($alerted / $expected) } else { 'N/A' }
            Write-Host ("  {0,-15} detected={1}/{2} ({3}) alerted={4}/{2} ({5}) shadow={6} disabled={7} eligible={8}" -f
                $entry.Name,$recognized,$expected,$detectorRate,$alerted,$alertRate,$shadowed,$disabled,$funnel.policyEligibleRules)
        }
        Write-Host 'Policy eligibility is conditional; it does not measure independent detection recall or live alert delivery.'
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
            # The runner enumerates every JSON fixture recursively. Verify the
            # report contains all checked-out fixtures, not merely an old
            # minimum that could hide silently skipped regression controls.
            $fixtureDirectory = Join-Path $root 'Tests/RuleReplaySamples'
            $fixtureCount = @(Get-ChildItem -LiteralPath $fixtureDirectory -Filter '*.json' -Recurse -File).Count
            if ([int]$report.summary.replaySampleCount -ne $fixtureCount) {
                $failures.Add('replay-sample-count')
                Write-Host "FAIL: benchmark reported $($report.summary.replaySampleCount) samples but $fixtureCount JSON fixtures exist."
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
            Show-AlertRuleQuality $report
            Show-DetectionFunnel $report
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

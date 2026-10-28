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
                # Consume tool output at the host instead of leaking it
                # into Invoke-Stage's return pipeline. Otherwise callers
                # receive [log lines, $false] and an if(-not (...)) condition
                # can mistakenly treat a failed build as successful.
                & dotnet @Arguments *>&1 | Tee-Object -FilePath $logFile | Out-Host
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
            # Always expose compiler/test failures, including under
            # -LiveOutput with quiet dotnet verbosity. A failed build must
            # not be mistaken for a failing new test or an old TRX result.
            $errorLines = @(Get-Content -LiteralPath $logFile |
                Where-Object { $_ -match '(?i)(\berror\s+(?:CS|NU|NETSDK|MSB)\d+|:\s*error\b|\berror TESTERROR\b)' } |
                Select-Object -First 20)
            if ($errorLines.Count -gt 0) {
                Write-Host "  First $($errorLines.Count) build/test error line(s):"
                foreach ($line in $errorLines) { Write-Host "  $line" }
            } elseif ($Details -and -not $LiveOutput) {
                Get-Content -LiteralPath $logFile | Select-Object -Last 40
            }
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
                    # Display reason codes separately from the summary error.
                    # This is diagnostic-only: it does not change expectations,
                    # decision thresholds, labels, or the failing exit code.
                    $missingIds = @($sample.missingExpectedMatches)
                    foreach ($diagnostic in @($sample.expectedRuleDiagnostics |
                        Where-Object { $_.ruleId -in $missingIds })) {
                        Write-Host ("    {0}: outcome={1}" -f $diagnostic.ruleId, $diagnostic.outcome)
                        $missingTelemetry = @($diagnostic.missingRequiredTelemetry |
                            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
                        if ($missingTelemetry.Count -gt 0) {
                            Write-Host ("      Missing telemetry: {0}" -f ($missingTelemetry -join ', '))
                        }
                        # NoMatchReasons can contain descriptions; bound the
                        # output and emit only category/code, not arbitrary text.
                        foreach ($reason in @($diagnostic.noMatchReasons | Select-Object -First 3)) {
                            $reasonCode = ([string]$reason -split ':', 2)[0]
                            Write-Host ("      Diagnostic: {0}" -f $reasonCode)
                        }
                    }
                }
            }
            Write-Host "Replay quality: $($report.summary.replaySampleCount) samples; benign critical alerts: $($report.summary.benignCriticalAlertCount)"
            Show-AlertRuleQuality $report
            Show-DetectionFunnel $report
            $auditProperty = $report.PSObject.Properties['ruleHardeningAudit']
            if ($null -eq $auditProperty -or $null -eq $auditProperty.Value) {
                throw 'Full rule hardening audit is missing from benchmark JSON.'
            }
            $audit = @($auditProperty.Value)
            $auditIssues = @($audit | Where-Object { @($_.contractIssues).Count -gt 0 })
            $paired = @($audit | Where-Object { $_.pairedSyntheticControls -eq $true }).Count
            $noControls = @($audit | Where-Object { $_.evidenceStatus -eq 'NoExplicitReplayControls' }).Count
            Write-Host ("Rule catalog audit: {0} rules; paired synthetic controls={1}; no explicit controls={2}; contract issues={3}" -f
                $audit.Count, $paired, $noControls, $auditIssues.Count)
            if ($audit.Count -ne 544) {
                $failures.Add('rule-catalog-count')
                Write-Host "FAIL: expected 544 registered rules, report contains $($audit.Count)."
            }
            if ($auditIssues.Count -gt 0) {
                $failures.Add('rule-catalog-contracts')
                Write-Host "FAIL: $($auditIssues.Count) rule contract(s) require repair."
                foreach ($entry in @($auditIssues | Select-Object -First 15)) {
                    Write-Host "  $($entry.ruleId): $($entry.contractIssues -join ', ')"
                }
            }
            $auditPath = Join-Path $outputDir 'rule-hardening-audit.md'
            if (-not (Test-Path -LiteralPath $auditPath -PathType Leaf)) {
                $failures.Add('rule-catalog-audit-artifact')
                Write-Host 'FAIL: the complete rule-hardening-audit.md export was not generated.'
            }
            # A successful benchmark process is not a successful detection-quality
            # result. Reject any newly alerting benign replay, and show the exact
            # offending rule IDs to prevent unrelated thresholds being loosened.
            $benignAlerts = [System.Collections.Generic.List[string]]::new()
            foreach ($sample in @($report.sampleResults | Where-Object { $_.classification -eq 'Benign' })) {
                foreach ($profile in $sample.profiles.PSObject.Properties) {
                    $alertIds = @($profile.Value.alertRuleIds | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
                        Sort-Object -Unique)
                    if ($alertIds.Count -gt 0) {
                        $detail = "{0} / {1}: rules={2}; critical={3}" -f
                            $sample.name, $profile.Name, ($alertIds -join ','),
                            [int]$profile.Value.criticalAlertCount
                        $benignAlerts.Add($detail)
                    }
                }
            }
            if ($benignAlerts.Count -gt 0) {
                $failures.Add('benign-alert-regression')
                Write-Host "FAIL: $($benignAlerts.Count) benign sample/profile combinations emitted simulated alerts:"
                foreach ($detail in $benignAlerts) { Write-Host "  $detail" }
            }
            foreach ($entry in $report.summary.sampleLevelQualityByProfile.PSObject.Properties) {
                if ([int]$entry.Value.falsePositives -gt 0 -and $benignAlerts.Count -eq 0) {
                    $failures.Add('benign-alert-accounting')
                    Write-Host "FAIL: $($entry.Name) reports $($entry.Value.falsePositives) false-positive samples without corresponding alert details."
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

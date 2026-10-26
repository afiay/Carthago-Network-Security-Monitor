# SPDX-License-Identifier: MIT
# Run isolated synthetic holdout without mixing it into development replay.
# Never use synthetic holdout outcomes to claim production accuracy.
[CmdletBinding()]
param(
    [switch]$NoBuild,
    [string]$OutputDirectory = 'build-verify/holdout'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Push-Location $root
try {
    $manifestFile = 'docs/holdout-evaluation-manifest.json'
    $manifest = Get-Content -LiteralPath $manifestFile -Raw | ConvertFrom-Json
    if ($manifest.schemaVersion -ne 1 -or @($manifest.samples).Count -ne 12) {
        throw 'The pinned holdout manifest must contain exactly twelve v1 scenarios.'
    }
    $expectedPaths = @($manifest.samples | ForEach-Object { [string]$_.file })
    $actualPaths = @(Get-ChildItem -Path 'Tests/RuleReplayHoldout' -Recurse -File -Filter '*.json' |
        ForEach-Object { $_.FullName.Substring($root.Length + 1).Replace('\', '/') } |
        Sort-Object)
    if (@(Compare-Object -ReferenceObject ($expectedPaths | Sort-Object) -DifferenceObject $actualPaths).Count -gt 0) {
        throw 'Holdout corpus has an unpinned added or missing JSON fixture.'
    }

    foreach ($entry in $manifest.samples) {
        $relative = [string]$entry.file
        if ($relative -notmatch '^Tests/RuleReplayHoldout/(benign|malicious)/[A-Za-z0-9-]+\.json$') {
            throw "Invalid holdout relative path: $relative"
        }
        if (-not (Test-Path -LiteralPath $relative -PathType Leaf)) {
            throw "Missing pinned fixture: $relative"
        }
        # Use Git's clean filters so CRLF Windows checkouts hash identically
        # to the repository object on which the manifest is pinned.
        $calculated = (& git hash-object "--path=$relative" -- "$relative" | Select-Object -Last 1).Trim()
        if ($LASTEXITCODE -ne 0 -or $calculated -ne [string]$entry.gitBlobSha) {
            throw "Holdout fixture changed from its frozen manifest: $relative"
        }
    }
    $argsForDotnet = @('run','--project','Carthago.Benchmarks/Carthago.Benchmarks.csproj','-c','Release')
    if ($NoBuild) { $argsForDotnet += '--no-build' }
    $argsForDotnet += @('--','--name','Carthago synthetic holdout (not field independent)',
        '--replay-dir','Tests/RuleReplayHoldout','--output-dir',$OutputDirectory,'--compare-profiles')
    & dotnet @argsForDotnet
    if ($LASTEXITCODE -ne 0) { throw "Holdout benchmark exited with code $LASTEXITCODE" }

    $reportPath = Join-Path $OutputDirectory 'tuning-benchmark.json'
    $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    $samples = @($report.sampleResults)
    $failures = [System.Collections.Generic.List[string]]::new()
    if ($samples.Count -ne 12 -or [int]$report.summary.benignSampleCount -ne 6 -or
        [int]$report.summary.maliciousSampleCount -ne 6) {
        $failures.Add('Holdout must have precisely six benign and six malicious cases.')
    }

    foreach ($entry in $manifest.samples) {
        $name = [IO.Path]::GetFileNameWithoutExtension([string]$entry.file)
        $sample = @($samples | Where-Object { $_.name -eq $name })
        if ($sample.Count -ne 1) { $failures.Add("Missing or duplicated holdout result: $name"); continue }
        if ($sample[0].classification -ne $entry.classification) {
            $failures.Add("Holdout label mismatch: $name")
        }
        if (@($sample[0].errors).Count -gt 0) {
            $failures.Add(("{0}: {1}" -f $name, ($sample[0].errors -join '; ')))
        }
        foreach ($p in $sample[0].profiles.PSObject.Properties) {
            if ($entry.classification -eq 'Benign' -and @($p.Value.alertRuleIds).Count -gt 0) {
                $failures.Add(("{0} / {1} emitted benign alert(s): {2}" -f
                    $name, $p.Name, ($p.Value.alertRuleIds -join ',')))
            }
        }
    }
    if ([int]$report.summary.expectedMatchCount -ne 6 -or
        [int]$report.summary.matchedExpectedCount -ne 6) {
        $failures.Add(("Expected detector recognition: {0}/{1}, required 6/6" -f
            $report.summary.matchedExpectedCount, $report.summary.expectedMatchCount))
    }
    foreach ($p in $report.summary.sampleLevelQualityByProfile.PSObject.Properties) {
        if ([int]$p.Value.falsePositives -gt 0) {
            $failures.Add("$($p.Name) produced $($p.Value.falsePositives) benign false-positive samples.")
        }
    }
    foreach ($p in $report.detectionFunnelByProfile.PSObject.Properties) {
        if ([int]$p.Value.alertDecisionMismatches -ne 0 -or
            [int]$p.Value.benignSimulatedAlerts -ne 0) {
            $failures.Add("$($p.Name) violated alert accounting or benign-alert invariant.")
        }
    }

    & (Join-Path $PSScriptRoot 'inspect-accuracy-evidence.ps1') -Report $reportPath
    if ($failures.Count -gt 0) {
        Write-Host "HOLDOUT FAILED: $($failures.Count) issue(s)"
        foreach ($item in $failures) { Write-Host "  $item" }
        throw 'Held-out replay quality gate failed.'
    }

    Write-Host 'PASS: frozen synthetic holdout; 12/12 fixtures; 6/6 rule expectations; all explicit negative assertions passed; no benign alerts.'
    Write-Host "Holdout reports: $OutputDirectory"
    Write-Host 'WARNING: This evaluates synthetic scenario transfer, not independently labeled field precision.'
}
finally {
    Pop-Location
}

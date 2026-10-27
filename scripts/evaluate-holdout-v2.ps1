# SPDX-License-Identifier: MIT
# Explicit opt-in evaluation for the separately versioned synthetic holdout v2.
# Never silently substitute v2 for failed, immutable v1 evidence.
[CmdletBinding()]
param(
    [switch]$NoBuild,
    [string]$OutputDirectory='build-verify/holdout-v2'
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Push-Location $root
$stage=$null
try {
    $manifest=Get-Content -LiteralPath 'docs/holdout-evaluation-v2-manifest.json' -Raw | ConvertFrom-Json
    $v1=Get-Content -LiteralPath 'docs/holdout-evaluation-manifest.json' -Raw | ConvertFrom-Json
    if ($manifest.schemaVersion -ne 2 -or $manifest.approvalState -ne 'FROZEN_V2_SYNTHETIC' -or
        @($manifest.samples).Count -ne 12) {
        throw 'V2 is NOT READY: all four external PCAP-backed R102 cases must be reviewed, pinned and explicitly frozen.'
    }
    $v1Lookup=@{}
    foreach ($old in $v1.samples) { $v1Lookup[[string]$old.file]=[string]$old.gitBlobSha }
    $seen=@{}
    $benign=0; $malicious=0; $external=0; $reused=0
    foreach ($entry in $manifest.samples) {
        $relative=[string]$entry.file
        $kind=[string]$entry.sourceKind
        if ($relative -notmatch '^Tests/RuleReplayHoldout(V2)?/(benign|malicious)/[A-Za-z0-9-]+\.json$' -or
            $seen.ContainsKey($relative) -or
            $entry.gitBlobSha -notmatch '^[0-9a-f]{40}$') {
            throw "V2 manifest has an invalid/unpinned or duplicate sample: $relative"
        }
        $seen[$relative]=$true
        if (-not (Test-Path -LiteralPath $relative -PathType Leaf)) {
            throw "V2 missing pinned file: $relative"
        }
        $actual=(& git hash-object "--path=$relative" -- "$relative" | Select-Object -Last 1).Trim()
        if ($LASTEXITCODE -ne 0 -or $actual -ne [string]$entry.gitBlobSha) {
            throw "V2 pinned fixture changed: $relative"
        }
        if ($entry.classification -eq 'Benign') { $benign++ }
        elseif ($entry.classification -eq 'Malicious') { $malicious++ }
        else { throw "Unexpected v2 label: $relative" }
        $fixture=Get-Content -LiteralPath $relative -Raw | ConvertFrom-Json
        if ($fixture.name -ne [IO.Path]::GetFileNameWithoutExtension($relative) -or
            $fixture.classification -ne $entry.classification -or @($fixture.records).Count -eq 0) {
            throw "V2 fixture metadata mismatch: $relative"
        }
        $expected=if ($entry.classification -eq 'Malicious') { @($fixture.expectedMatches) } else { @($fixture.expectedNonMatches) }
        if ($expected -notcontains $entry.primaryRule) { throw "V2 missing pinned primary rule: $relative" }
        if ($kind -eq 'pinned-v1-synthetic') {
            $reused++
            if ($relative -notmatch '^Tests/RuleReplayHoldout/' -or
                -not $v1Lookup.ContainsKey($relative) -or
                $v1Lookup[$relative] -ne $actual -or
                $entry.primaryRule -eq 'R102') {
                throw "V2 attempted to replace or misclassify a frozen v1 sample: $relative"
            }
        } elseif ($kind -eq 'external-pcap-reviewed') {
            $external++
            if ($relative -notmatch '^Tests/RuleReplayHoldoutV2/' -or $entry.primaryRule -ne 'R102' -or
                $entry.provenanceBlobSha -notmatch '^[0-9a-f]{40}$') {
                throw "R102 v2 capture provenance not pinned: $relative"
            }
            $provenanceRelative=[string]$entry.provenanceFile
            if ($provenanceRelative -notmatch '^docs/holdout-v2-provenance/holdout-v2-r102-[a-z0-9-]+\.json$' -or
                -not (Test-Path -LiteralPath $provenanceRelative -PathType Leaf)) {
                throw "R102 v2 provenance missing: $relative"
            }
            $provenanceHash=(& git hash-object "--path=$provenanceRelative" -- "$provenanceRelative" | Select-Object -Last 1).Trim()
            if ($LASTEXITCODE -ne 0 -or $provenanceHash -ne [string]$entry.provenanceBlobSha) {
                throw "R102 v2 provenance changed: $relative"
            }
            $p=Get-Content -LiteralPath $provenanceRelative -Raw | ConvertFrom-Json
            if ($p.sourceKind -ne 'external-pcap-reviewed' -or -not $p.analystReviewedLabel -or
                $p.captureSha256 -notmatch '^[0-9a-fA-F]{64}$' -or
                [string]::IsNullOrWhiteSpace($p.independentLabelBasis) -or
                $p.sourceLicense -notin @('Apache-2.0','CC-BY-4.0','CC0-1.0') -or
                [string]::IsNullOrWhiteSpace($p.sourceLicenseEvidenceUri) -or
                $p.sourceLicenseEvidenceUri -notmatch '^https://' -or
                $p.sourceUri -notmatch '^https://' -or
                $p.sample -ne $fixture.name -or $p.classification -ne $entry.classification -or
                @($p.frameNumbers).Count -ne @($fixture.records).Count -or
                @($p.frameNumbers | Sort-Object -Unique).Count -ne @($fixture.records).Count) {
                throw "R102 v2 missing packet or label provenance: $relative"
            }
            foreach ($record in $fixture.records) {
                if ($record.isUdp -eq $record.isTcp -or
                    ($record.isUdp -ne $true -and $record.isTcp -ne $true) -or
                    $record.destinationPort -ne 53 -or
                    $record.protocol -ne 'DNS' -or $record.applicationProtocol -ne 'DNS' -or
                    [string]::IsNullOrWhiteSpace($record.dnsQname) -or
                    [string]::IsNullOrWhiteSpace($record.dnsQtype)) {
                    throw "R102 v2 lacks explicit typed DNS packet evidence: $relative"
                }
            }
        } else { throw "Unknown v2 sample provenance category: $kind" }
    }
    if ($benign -ne 6 -or $malicious -ne 6 -or $reused -ne 8 -or $external -ne 4) {
        throw "V2 needs 6 benign + 6 malicious; eight preserved v1 cases and four new captured R102 cases."
    }
    $stage=Join-Path $root ('build-verify/holdout-v2/staging-'+[Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $stage | Out-Null
    foreach ($entry in $manifest.samples) {
        $label=([string]$entry.classification).ToLowerInvariant()
        $target=Join-Path $stage $label
        New-Item -ItemType Directory -Force -Path $target | Out-Null
        Copy-Item -LiteralPath ([string]$entry.file) -Destination $target -ErrorAction Stop
    }

    $argsDotnet=@('run','--project','Carthago.Benchmarks/Carthago.Benchmarks.csproj','-c','Release')
    if ($NoBuild) { $argsDotnet+='--no-build' }
    $argsDotnet+=@('--','--name','Carthago synthetic holdout v2 (not field independent)',
                  '--replay-dir',$stage,'--output-dir',$OutputDirectory,'--compare-profiles')
    & dotnet @argsDotnet
    if ($LASTEXITCODE -ne 0) { throw "V2 benchmark exited with code $LASTEXITCODE" }
    $reportPath=Join-Path $OutputDirectory 'tuning-benchmark.json'
    $report=Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    $failures=[System.Collections.Generic.List[string]]::new()
    if (@($report.sampleResults).Count -ne 12 -or
        [int]$report.summary.benignSampleCount -ne 6 -or
        [int]$report.summary.maliciousSampleCount -ne 6 -or
        [int]$report.summary.expectedMatchCount -ne 6 -or
        [int]$report.summary.matchedExpectedCount -ne 6) {
        $failures.Add(("Recognition $($report.summary.matchedExpectedCount)/$($report.summary.expectedMatchCount); expected 6/6 with 12 labeled cases."))
    }
    foreach ($item in $report.sampleResults) {
        if (@($item.errors).Count -gt 0) {
            $failures.Add(("{0}: {1}" -f $item.name, ($item.errors -join '; ')))
        }
        if ($item.classification -eq 'Benign') {
            foreach ($profile in $item.profiles.PSObject.Properties) {
                if (@($profile.Value.alertRuleIds).Count -gt 0) {
                    $failures.Add("$($item.name) / $($profile.Name) emitted an unexpected benign alert.")
                }
            }
        }
    }
    foreach ($profile in $report.summary.sampleLevelQualityByProfile.PSObject.Properties) {
        if ([int]$profile.Value.falsePositives -gt 0) {
            $failures.Add("$($profile.Name) has benign false positives.")
        }
    }
    foreach ($profile in $report.detectionFunnelByProfile.PSObject.Properties) {
        if ([int]$profile.Value.alertDecisionMismatches -ne 0 -or
            [int]$profile.Value.benignSimulatedAlerts -ne 0) {
            $failures.Add("$($profile.Name) violated alert accounting or benign alert gating.")
        }
    }
    if ($failures.Count -gt 0) {
        foreach ($failure in $failures) { Write-Host "FAIL: $failure" }
        throw 'V2 frozen synthetic holdout failed; v1 remains failed.'
    }
    Write-Host 'PASS: separately frozen v2 synthetic holdout; 12/12 pinned, 6/6 malicious recognitions, no benign alerts.'
    Write-Host 'WARNING: Not independently labeled field precision. Prior v1 FAILED result stays on record.'
}
finally {
    if ($null -ne $stage -and (Test-Path -LiteralPath $stage)) {
        Remove-Item -LiteralPath $stage -Recurse -Force
    }
    Pop-Location
}

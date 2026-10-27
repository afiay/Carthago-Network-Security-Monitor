# SPDX-License-Identifier: MIT
# Explicit, offline freeze only. No detector run, no build, no benchmark.
# Refuses to overwrite any pinned v1 fixture.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][switch]$ApproveFreeze,
    [Parameter(Mandatory=$true)][switch]$ReviewedSensitiveTelemetry,
    [string]$CandidateDirectory='build-verify/holdout-v2-import'
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Push-Location $root
try {
    $manifestPath='docs/holdout-evaluation-v2-manifest.json'
    $manifest=Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($manifest.schemaVersion -ne 2 -or
        $manifest.approvalState -ne 'PENDING_EXTERNAL_CAPTURE_AND_REVIEW') {
        throw 'V2 manifest is not in an unfrozen candidate state.'
    }
    $pending=@($manifest.samples | Where-Object { $_.sourceKind -eq 'external-pcap-reviewed' })
    if ($pending.Count -ne 4 -or @($manifest.samples).Count -ne 12) {
        throw 'Expected precisely four new R102 candidate fixtures and eight preserved v1 samples.'
    }
    $staging=(Resolve-Path -LiteralPath $CandidateDirectory -ErrorAction Stop).Path
    $ready=[System.Collections.Generic.List[object]]::new()
    foreach ($entry in $pending) {
        $name=[IO.Path]::GetFileNameWithoutExtension([string]$entry.file)
        $sourceSample=Join-Path $staging ($name+'.json')
        $sourceProvenance=Join-Path $staging ($name+'.provenance.json')
        if (-not (Test-Path -LiteralPath $sourceSample -PathType Leaf) -or
            -not (Test-Path -LiteralPath $sourceProvenance -PathType Leaf)) {
            throw "Missing externally reviewed R102 candidate or packet provenance: $name"
        }
        $sample=Get-Content -LiteralPath $sourceSample -Raw | ConvertFrom-Json
        $p=Get-Content -LiteralPath $sourceProvenance -Raw | ConvertFrom-Json
        if ($sample.name -ne $name -or $p.sample -ne $name -or
            $sample.classification -ne $entry.classification -or
            $p.classification -ne $entry.classification -or
            $p.sourceKind -ne 'external-pcap-reviewed' -or
            -not $p.analystReviewedLabel -or
            -not $p.capturedTransportEvidence -or
            $p.captureSha256 -notmatch '^[0-9a-fA-F]{64}$' -or
            [string]::IsNullOrWhiteSpace($p.independentLabelBasis) -or
            [string]::IsNullOrWhiteSpace($p.sourceUri) -or
            [string]::IsNullOrWhiteSpace($p.sourceLicense)) {
            throw "Missing external capture evidence or explicit independent label approval: $name"
        }
        if (@($sample.records).Count -lt 3 -or
            @($sample.records).Count -ne @($p.frameNumbers).Count -or
            @($p.frameNumbers | Sort-Object -Unique).Count -ne @($sample.records).Count) {
            throw "Insufficient unique packet frames for v2 fixture: $name"
        }
        foreach ($record in $sample.records) {
            if ($record.isUdp -eq $record.isTcp -or
                ($record.isUdp -ne $true -and $record.isTcp -ne $true) -or
                $record.destinationPort -ne 53 -or $record.protocol -ne 'DNS' -or
                $record.applicationProtocol -ne 'DNS' -or
                [string]::IsNullOrWhiteSpace($record.dnsQname) -or
                [string]::IsNullOrWhiteSpace($record.dnsQtype)) {
                throw "Transport and DNS parser attribution are incomplete: $name"
            }
        }
        if ($entry.file -notmatch '^Tests/RuleReplayHoldoutV2/(benign|malicious)/holdout-v2-r102-[a-z0-9-]+\.json$' -or
            $entry.provenanceFile -notmatch '^docs/holdout-v2-provenance/holdout-v2-r102-[a-z0-9-]+\.json$') {
            throw "Unexpected v2 destination: $name"
        }
        if ((Test-Path -LiteralPath ([string]$entry.file)) -or
            (Test-Path -LiteralPath ([string]$entry.provenanceFile))) {
            throw "Refusing to overwrite an existing frozen or staged repository path: $name"
        }
        $ready.Add([pscustomobject]@{
            entry=$entry;sample=$sourceSample;provenance=$sourceProvenance
        })
    }
    if ($ready.Count -ne 4) { throw 'V2 freeze must be all-or-nothing.' }
    foreach ($item in $ready) {
        foreach ($target in @([string]$item.entry.file,[string]$item.entry.provenanceFile)) {
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
        }
        Copy-Item -LiteralPath $item.sample -Destination ([string]$item.entry.file) -ErrorAction Stop
        Copy-Item -LiteralPath $item.provenance -Destination ([string]$item.entry.provenanceFile) -ErrorAction Stop
        $samplePath=[string]$item.entry.file
        $provenancePath=[string]$item.entry.provenanceFile
        # Git clean filters produce cross-platform blob IDs for the pinned manifest.
        $sampleHash=(& git hash-object "--path=$samplePath" -- "$samplePath" | Select-Object -Last 1).Trim()
        if ($LASTEXITCODE -ne 0) { throw "Cannot compute v2 fixture Git hash: $samplePath" }
        $provenanceHash=(& git hash-object "--path=$provenancePath" -- "$provenancePath" | Select-Object -Last 1).Trim()
        if ($LASTEXITCODE -ne 0) { throw "Cannot compute v2 provenance Git hash: $provenancePath" }
        $item.entry.gitBlobSha=$sampleHash
        $item.entry.provenanceBlobSha=$provenanceHash
    }
    $manifest.approvalState='FROZEN_V2_SYNTHETIC'
    $manifest | Add-Member -MemberType NoteProperty -Name frozenDateUtc -Value ([DateTime]::UtcNow.ToString('o')) -Force
    $manifest | Add-Member -MemberType NoteProperty -Name freezeApproval -Value 'Explicit -ApproveFreeze -ReviewedSensitiveTelemetry; classification remains synthetic' -Force
    $encoded=($manifest | ConvertTo-Json -Depth 16)+[Environment]::NewLine
    [IO.File]::WriteAllText((Join-Path $root $manifestPath), $encoded, [Text.UTF8Encoding]::new($false))
    Write-Host 'V2 corpus frozen locally: 12 manifest entries (8 v1 hashes reused, 4 separately captured R102 candidates).'
    Write-Host 'REVIEW and COMMIT candidate files, provenance and v2 manifest TOGETHER before evaluation.'
    Write-Host 'No build, benchmark, holdout run or security-rule promotion was performed.'
}
finally { Pop-Location }

# SPDX-License-Identifier: MIT
# Read-only v2 preparation and source readiness; no detector test, freeze,
# download, privacy approval or inferred transport provenance.
[CmdletBinding()]
param(
    [string]$CandidateDirectory='build-verify/holdout-v2-import',
    [string]$CaptureDirectory='',
    [switch]$AuditPackets,
    [string]$TsharkPath='tshark'
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Push-Location $root
try {
    $manifest=Get-Content -LiteralPath 'docs/holdout-evaluation-v2-manifest.json' -Raw | ConvertFrom-Json
    $v1=Get-Content -LiteralPath 'docs/holdout-evaluation-manifest.json' -Raw | ConvertFrom-Json
    if ($v1.schemaVersion -ne 1 -or $manifest.schemaVersion -ne 2 -or
        $manifest.predecessorManifest -ne 'docs/holdout-evaluation-manifest.json' -or
        @($manifest.samples).Count -ne 12) {
        throw 'V2 structural manifest verification failed.'
    }
    $old=@{}
    foreach ($item in $v1.samples) {
        $old[[string]$item.file]=[string]$item.gitBlobSha
    }
    $reused=@($manifest.samples | Where-Object { $_.sourceKind -eq 'pinned-v1-synthetic' })
    $external=@($manifest.samples | Where-Object { $_.sourceKind -eq 'external-pcap-reviewed' })
    if ($reused.Count -ne 8 -or $external.Count -ne 4) {
        throw 'V2 must reuse eight non-R102 v1 samples and reserve four external R102 slots.'
    }
    foreach ($item in $reused) {
        $relative=[string]$item.file
        if (-not $old.ContainsKey($relative) -or
            [string]$item.gitBlobSha -ne $old[$relative] -or
            $item.primaryRule -eq 'R102') {
            throw 'V2 predecessor blob identity failed.'
        }
    }

    Write-Host 'CARTHAGO HOLDOUT V2 READINESS (READ ONLY)'
    Write-Host ("Manifest: {0}" -f [string]$manifest.approvalState)
    Write-Host 'V1 predecessor: retained and historically FAILED.'
    Write-Host 'V2 schema: 12 declared slots; eight immutable non-R102 v1 references; four external R102 sources required.'

    $present=0
    foreach ($entry in $external) {
        $name=[IO.Path]::GetFileNameWithoutExtension([string]$entry.file)
        if ($name -notmatch '^holdout-v2-r102-[a-z0-9-]+$') {
            throw 'Unexpected external source slot name.'
        }
        $sample=Join-Path $CandidateDirectory ($name+'.json')
        $provenance=Join-Path $CandidateDirectory ($name+'.provenance.json')
        $both=(Test-Path -LiteralPath $sample -PathType Leaf) -and
              (Test-Path -LiteralPath $provenance -PathType Leaf)
        if ($both) { $present++ }
        Write-Host ("R102 SOURCE SLOT: {0} - {1}" -f $name,
            $(if ($both) { 'CANDIDATE FILES PRESENT, UNVERIFIED' } else { 'PENDING CAPTURE/PROVENANCE' }))
    }
    if ($manifest.approvalState -eq 'PENDING_EXTERNAL_CAPTURE_AND_REVIEW') {
        if ($present -lt 4) {
            Write-Host ("STATUS: PENDING - {0}/4 candidate source/provenance pairs are present." -f $present)
            Write-Host 'No independent packet, label, license or privacy approval can be asserted.'
            if ($AuditPackets) {
                throw 'Packet auditing requires all four reviewed source/provenance pairs.'
            }
            return
        }
        if (-not $AuditPackets) {
            Write-Host 'STATUS: CANDIDATES PRESENT, NOT VERIFIED. Run explicit -AuditPackets with the original captures.'
            return
        }
        if ([string]::IsNullOrWhiteSpace($CaptureDirectory)) {
            throw 'To audit source packets, specify -CaptureDirectory with the original PCAP/PCAPNG files.'
        }
        & (Join-Path $PSScriptRoot 'audit-holdout-v2-candidates.ps1') -CaptureDirectory $CaptureDirectory -CandidateDirectory $CandidateDirectory -TsharkPath $TsharkPath
        Write-Host 'STATUS: PACKET FIELDS AUDITED - MANUAL LABEL/RIGHTS/PRIVACY REVIEW AND FREEZE STILL PENDING.'
        return
    }
    if ($manifest.approvalState -eq 'FROZEN_V2_SYNTHETIC') {
        if ($AuditPackets) {
            throw 'Frozen v2 must be checked through the pinned evaluator; the candidate audit only supports pre-freeze status.'
        }
        Write-Host 'STATUS: FROZEN MANIFEST - use the opt-in v2 evaluator to validate pinned content.'
        Write-Host 'Do not infer external label truth or production detection accuracy from a frozen manifest.'
        return
    }
    throw 'Unknown v2 approval state. Fail closed.'
}
finally { Pop-Location }

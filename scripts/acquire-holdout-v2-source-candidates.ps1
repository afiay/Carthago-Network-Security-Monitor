# SPDX-License-Identifier: MIT
# Downloads ONE externally published PCAP candidate with its immutable Git
# content hash. Never re-labels, imports, freezes, or tests detection rules.
[CmdletBinding()]
param(
    [ValidateSet('ElasticIodine')]
    [string]$Source='ElasticIodine',
    [string]$OutputDirectory='build-verify/holdout-v2-sources'
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Push-Location $root
$temp=$null
try {
    # GitHub file metadata and repository-wide license verified by review.
    # A license notice does NOT replace case-specific privacy/redistribution
    # review, nor does a DNS tunneling PCAP prove source QNAME eligibility.
    $sources=@{
        ElasticIodine=@{
            Repository='elastic/examples'
            Commit='6d86454ebb7a850bcd7e80abe86fe683370018a6'
            Path='Security Analytics/dns_tunnel_detection/dns-tunnel-iodine.pcap'
            GitBlobSha='f43152b995d0eb9127d5a8fcaf13e5c26595ce69'
            Size=77524
            SourceLicense='Apache-2.0 repository root; review fixture provenance'
            Description='Elastic Packetbeat demo of iodine DNS tunnel traffic'
        }
    }
    $entry=$sources[$Source]
    $escapedPath=($entry.Path.Split('/') | ForEach-Object { [Uri]::EscapeDataString($_) }) -join '/'
    $url="https://raw.githubusercontent.com/$($entry.Repository)/$($entry.Commit)/$escapedPath"
    $dir=[IO.Path]::GetFullPath((Join-Path $root $OutputDirectory))
    $privateRoot=[IO.Path]::GetFullPath((Join-Path $root 'build-verify'))
    if (-not $dir.StartsWith($privateRoot+[IO.Path]::DirectorySeparatorChar,
                            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Unreviewed external PCAP downloads must remain under build-verify.'
    }
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $output=Join-Path $dir ('elastic-iodine-'+$entry.Commit.Substring(0,12)+'.pcap')
    $receipt=Join-Path $dir ('elastic-iodine-'+$entry.Commit.Substring(0,12)+'.source.json')
    if ((Test-Path -LiteralPath $output -PathType Leaf) -or
        (Test-Path -LiteralPath $receipt -PathType Leaf)) {
        throw 'Download receipt or source already present; refusing to overwrite previous evidence.'
    }
    $temp=$output+'.downloading'
    Invoke-WebRequest -Uri $url -OutFile $temp -UseBasicParsing -ErrorAction Stop
    $info=Get-Item -LiteralPath $temp
    if ($info.Length -ne $entry.Size) {
        throw "Unexpected PCAP byte count: $($info.Length); expected $($entry.Size)."
    }
    $blob=(& git hash-object -- $temp | Select-Object -Last 1).Trim()
    if ($LASTEXITCODE -ne 0 -or $blob -ne $entry.GitBlobSha) {
        throw "Git blob SHA mismatch. Expected $($entry.GitBlobSha); got $blob."
    }
    $sha256=(Get-FileHash -LiteralPath $temp -Algorithm SHA256).Hash.ToLowerInvariant()
    # Record plain source metadata, never an invented analyst label.
    $metadata=[ordered]@{
        schemaVersion=1
        status='ACQUIRED_UNREVIEWED_SOURCE_CANDIDATE'
        publisher='Elastic'
        repository=$entry.Repository
        immutableCommit=$entry.Commit
        originalPath=$entry.Path
        sourceUrl=$url
        repositoryLicense=$entry.SourceLicense
        sourceDescription=$entry.Description
        gitBlobSha=$blob
        sha256=$sha256
        bytes=$info.Length
        packetInspection='NOT_PERFORMED'
        privacyReview='PENDING'
        groundTruthLabelReview='PENDING'
        allowedHoldoutUse='NOT_APPROVED'
        receivedAtUtc=[DateTime]::UtcNow.ToString('o')
    }
    $json=($metadata | ConvertTo-Json -Depth 8)+[Environment]::NewLine
    # A receipt must never attest to a missing source file if a disk move
    # fails. Roll back files created by this invocation on either failure.
    try {
        Move-Item -LiteralPath $temp -Destination $output -ErrorAction Stop
        $temp=$null
        [IO.File]::WriteAllText($receipt,$json,[Text.UTF8Encoding]::new($false))
    } catch {
        if (Test-Path -LiteralPath $receipt -PathType Leaf) {
            Remove-Item -LiteralPath $receipt -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $output -PathType Leaf) {
            Remove-Item -LiteralPath $output -Force -ErrorAction SilentlyContinue
        }
        throw
    }
    Write-Host 'ACQUIRED, HASH-VERIFIED, NOT YET APPROVED FOR HOLDOUT:'
    Write-Host "  Capture: $output"
    Write-Host "  Receipt: $receipt"
    Write-Host "  SHA-256: $sha256"
    Write-Host 'This acquisition does not prove PCAP DNS eligibility, permission to republish'
    Write-Host 'packet data, source/client independence, nor accuracy. No tests ran.'
}
finally {
    if ($null -ne $temp -and (Test-Path -LiteralPath $temp -PathType Leaf)) {
        Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
    }
    Pop-Location
}

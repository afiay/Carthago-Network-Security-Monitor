# SPDX-License-Identifier: MIT
# Recover original Windows verification artifacts WITHOUT running builds, tests or captures.
# Source files are read-only; recovered bytes and SHA-256 manifest stay local.
[CmdletBinding()]
param(
    [string[]]$EvidenceRoot = @(),
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Destination,
    [ValidateRange(1, 100000)]
    [int]$MaximumFiles = 20000,
    [ValidateRange(1, 4294967296)]
    [long]$MaximumTotalBytes = 2147483648,
    [switch]$IncludeDiagnosticDumps
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if ($EvidenceRoot.Count -eq 0) {
    $EvidenceRoot = @(
        (Join-Path $repo 'TestResults'),
        (Join-Path $repo 'build-verify'),
        (Join-Path $repo 'Carthago.Tests\TestResults'),
        (Join-Path $repo 'Carthago.Cli.Tests\TestResults')
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Container }
}
if ($EvidenceRoot.Count -eq 0) { throw 'No evidence roots found; supply -EvidenceRoot explicitly.' }
$separator = [IO.Path]::DirectorySeparatorChar
function Normalize-Directory([string]$path) {
    return [IO.Path]::GetFullPath($path).TrimEnd([char[]]@('\', '/'))
}
function Test-WithinDirectory([string]$candidate, [string]$directory) {
    return $candidate.Equals($directory, [StringComparison]::OrdinalIgnoreCase) -or
           $candidate.StartsWith($directory + $separator, [StringComparison]::OrdinalIgnoreCase)
}
$rootPaths = [Collections.Generic.List[string]]::new()
$rootSeen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($root in $EvidenceRoot) {
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        throw "Missing evidence directory: $root"
    }
    $resolved = Normalize-Directory ((Get-Item -LiteralPath $root).FullName)
    if ($rootSeen.Add($resolved)) { $rootPaths.Add($resolved) }
}
$destinationPath = Normalize-Directory $Destination
foreach ($rootPath in $rootPaths) {
    if (Test-WithinDirectory $destinationPath $rootPath) {
        throw "Destination must be outside all evidence roots: $rootPath"
    }
}
if (Test-Path -LiteralPath $destinationPath) {
    throw 'Destination already exists. Choose a NEW output directory; old recovery bundles are immutable.'
}
$extensions = @('.trx','.json','.jsonl','.ndjson','.log','.txt','.csv',
                '.binlog','.pcap','.pcapng','.zip','.etl','.evtx','.coverage','.coveragexml','.xml')
if ($IncludeDiagnosticDumps) { $extensions += '.dmp' }
$seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$candidates = [Collections.Generic.List[object]]::new()
$sumBytes = [long]0
for ($i = 0; $i -lt $rootPaths.Count; $i++) {
    $rootPath = $rootPaths[$i]
    foreach ($f in (Get-ChildItem -LiteralPath $rootPath -File -Recurse -Force -ErrorAction Stop)) {
        if ($f.Extension.ToLowerInvariant() -notin $extensions) { continue }
        if (($f.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
        if (-not $seen.Add($f.FullName)) { continue }
        if ($candidates.Count -ge $MaximumFiles) { throw 'MaximumFiles exceeded; no files copied.' }
        $sumBytes += [long]$f.Length
        if ($sumBytes -gt $MaximumTotalBytes) { throw 'MaximumTotalBytes exceeded; no files copied.' }
        $relative = $f.FullName.Substring($rootPath.Length).TrimStart([char[]]@('\','/'))
        if ([string]::IsNullOrWhiteSpace($relative)) { throw 'Invalid relative file path' }
        $candidates.Add([pscustomobject]@{
            sourcePath = $f.FullName
            sourceRoot = $rootPath
            copyRelativePath = ('originals/root-{0:d3}/' -f ($i + 1)) + ($relative -replace '\\','/')
            sourceLength = [long]$f.Length
            sourceLastWriteUtc = $f.LastWriteTimeUtc.ToString('o')
        })
    }
}
if ($candidates.Count -eq 0) { throw 'No eligible original evidence files found; nothing copied.' }

# Do not rewrite or touch originals. A failure leaves output marked INCOMPLETE.
[IO.Directory]::CreateDirectory($destinationPath) | Out-Null
$marker = Join-Path $destinationPath 'INCOMPLETE.txt'
[IO.File]::WriteAllText($marker, 'Recovery not verified. Do not admit these files as evidence.')
$records = [Collections.Generic.List[object]]::new()
foreach ($item in ($candidates | Sort-Object -Property sourcePath)) {
    $copy = Join-Path $destinationPath ($item.copyRelativePath -replace '/', $separator)
    [IO.Directory]::CreateDirectory((Split-Path -Parent $copy)) | Out-Null
    $before = (Get-FileHash -LiteralPath $item.sourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
    Copy-Item -LiteralPath $item.sourcePath -Destination $copy -ErrorAction Stop
    $copyHash = (Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash.ToLowerInvariant()
    $after = (Get-FileHash -LiteralPath $item.sourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $copied = Get-Item -LiteralPath $copy
    if ($before -cne $copyHash -or $before -cne $after -or $copied.Length -ne $item.sourceLength) {
        throw "Source changed during copy or SHA-256 mismatch: $($item.sourcePath)"
    }
    $records.Add([pscustomobject]@{
        sourcePath = $item.sourcePath
        relativeCopy = $item.copyRelativePath
        bytes = $copied.Length
        sha256 = $copyHash
        sourceLastWriteUtc = $item.sourceLastWriteUtc
        executionSha = $null
        checkoutAttested = $false
        evidenceAdmitted = $false
        originalUnmodified = $true
    })
}
$checkoutSha = $null
try {
    $checkoutSha = (& git -C $repo rev-parse HEAD 2>$null).Trim()
    if ($LASTEXITCODE -ne 0 -or $checkoutSha -notmatch '^[a-f0-9]{40}$') { $checkoutSha = $null }
} catch { $checkoutSha = $null }
$manifest = [pscustomobject]@{
    schemaVersion = 1
    purpose = 'historical-Windows-artifact-byte-recovery'
    recoveredUtc = [DateTime]::UtcNow.ToString('o')
    inspectionCheckoutSha = $checkoutSha
    # Inspecting checkout HEAD does NOT attest historical execution SHAs.
    executionShaVerified = $false
    artifactsAdmitted = 0
    detectorTestsExecuted = 0
    sourceRoots = @($rootPaths.ToArray())
    artifactCount = $records.Count
    totalBytes = $sumBytes
    artifacts = @($records.ToArray())
}
$manifestPath = Join-Path $destinationPath 'recovery-manifest.json'
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
Remove-Item -LiteralPath $marker
[pscustomobject]@{
    result = 'bytes-copied-and-sha256-verified'
    bundle = $destinationPath
    artifactCount = $records.Count
    totalBytes = $sumBytes
    manifest = $manifestPath
    executionShaVerified = $false
    detectorTestsExecuted = 0
    artifactsAdmitted = 0
} | ConvertTo-Json

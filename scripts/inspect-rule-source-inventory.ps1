# SPDX-License-Identifier: MIT
# SOURCE CANDIDATE — UNVERIFIED. Reads Git objects only; never builds or tests.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$SourceSha,
    [string]$RepositoryRoot = (Join-Path $PSScriptRoot '..')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RuleSourceInventory.psm1') -Force
function Read-GitObject([string[]]$Arguments) {
    $lines = @(& git -C $RepositoryRoot @Arguments)
    if ($LASTEXITCODE -ne 0) { throw 'Unable to read pinned Git source objects.' }
    return ($lines -join "`n")
}
$actual = Read-GitObject @('rev-parse', '--verify', ($SourceSha + '^{commit}'))
if ($actual -cne $SourceSha) { throw 'Exact source commit required.' }
$registryPath = 'Carthago/Engine/Rules/Catalog/RuleRegistry.cs'
$registry = Read-GitObject @('show', ($SourceSha + ':' + $registryPath))
$listing = Read-GitObject @('ls-tree', '-r', $SourceSha, '--', 'Carthago/Engine/Rules', 'Carthago.Tests')
$sources = @{}
$blobs = [Collections.Generic.List[object]]::new()
foreach ($line in ($listing -split "`n")) {
    # Reject quoted/unusual paths instead of interpreting Git escapes or reading
    # working-tree substitutions. Symlink/submodule entries are not C# sources.
    if ($line -cmatch '^100644 blob (?<oid>[a-f0-9]{40})\t(?<path>[A-Za-z0-9_./-]+\.cs)$') {
        $path = $Matches['path']; $oid = $Matches['oid']
        $sources[$path] = Read-GitObject @('cat-file', 'blob', $oid)
        $blobs.Add([pscustomobject]@{path=$path; blobSha=$oid})
    } elseif ($line -match '\.cs"?$') {
        throw 'Unrecognized source path or mode; manual inventory review required.'
    }
}
$result = Get-RuleSourceInventory -RegistrySource $registry -Sources $sources -SourceSha $SourceSha
$result | Add-Member -NotePropertyName sourceBlobs -NotePropertyValue @($blobs.ToArray())
$result | ConvertTo-Json -Depth 12
# Intentionally no verifier invocation, output-file write, filter generation,
# exit-as-acceptance decision, or consumption of holdout/TRX/capture artifacts.

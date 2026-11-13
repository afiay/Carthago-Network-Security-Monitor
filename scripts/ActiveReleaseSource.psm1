# SPDX-License-Identifier: MIT
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function Get-ActiveReleaseSource([string]$Root) {
    $branch=(& git -C $Root branch --show-current).Trim()
    if ($LASTEXITCODE -ne 0 -or $branch -cne 'feature/carthago-reliability-hardening') { throw 'Qualification branch mismatch.' }
    $sha=(& git -C $Root rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $sha -notmatch '^[0-9a-f]{40}$') { throw 'Source SHA unavailable.' }
    $dirty=@(& git -C $Root status --porcelain --untracked-files=all)
    if ($LASTEXITCODE -ne 0 -or $dirty.Count -ne 0) { throw 'Clean qualification worktree required.' }
    return $sha
}
function Assert-ActiveReleaseSource([string]$Root,[string]$Expected) {
    if ((Get-ActiveReleaseSource $Root) -cne $Expected) { throw 'Qualification source changed.' }
}
Export-ModuleMember -Function Get-ActiveReleaseSource,Assert-ActiveReleaseSource

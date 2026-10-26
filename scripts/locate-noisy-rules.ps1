# SPDX-License-Identifier: MIT
# Find implementation and evidence configuration for noisy replay rules.
param(
    [string[]]$RuleIds = @("R360", "R371", "R063", "R370", "R367", "R061"),
    [string]$SourceRoot = "."
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$source = (Resolve-Path -LiteralPath $SourceRoot).Path
$files = @(Get-ChildItem -LiteralPath $source -Recurse -File -Filter "*.cs" |
    Where-Object { $_.FullName -notmatch '[\\/](bin|obj|\.git)[\\/]' })
foreach ($rule in $RuleIds) {
    Write-Host "`n=== $rule: source references ===" -ForegroundColor Cyan
    $hits = @($files | Select-String -Pattern ("\\b" + [regex]::Escape($rule) + "\\b"))
    if ($hits.Count -eq 0) {
        Write-Host "No C# references found."
        continue
    }
    $hits | Select-Object -First 25 |
        ForEach-Object {
            $relative = [System.IO.Path]::GetRelativePath($source, $_.Path)
            [pscustomobject]@{
                File = $relative
                Line = $_.LineNumber
                Text = $_.Line.Trim()
            }
        } | Format-List
    if ($hits.Count -gt 25) {
        Write-Host "Showing first 25 of $($hits.Count) matches."
    }
}

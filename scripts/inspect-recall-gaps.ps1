# SPDX-License-Identifier: MIT
# Inspect alert-level false negatives from the latest labeled offline replay.
[CmdletBinding()]
param(
    [string]$Report = (Join-Path $PSScriptRoot '..\build-verify\tuning-benchmark.json'),
    [string]$Profile,
    [ValidateRange(1, 500)]
    [int]$Top = 30,
    [switch]$Detailed
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Report -PathType Leaf)) {
    throw "Benchmark report not found: $Report. Run .\verify-local.ps1 -Details first."
}
$data = Get-Content -LiteralPath $Report -Raw | ConvertFrom-Json
if ($null -eq $data.PSObject.Properties['recallGaps']) {
    throw "This benchmark report does not have recallGaps. Fetch the latest Carthago branch and rerun verification."
}
$gaps = @($data.recallGaps | Where-Object {
    [string]::IsNullOrWhiteSpace($Profile) -or $_.profileName -eq $Profile
})
Write-Host ("Recall gaps: {0} expected malicious rule/profile alerts not emitted." -f $gaps.Count)
Write-Host 'A raw match or a Shadow decision is not an alert.'
if ($gaps.Count -eq 0) {
    Write-Host 'No recall gaps for the selected scope.'
    return
}
Write-Host "`nGap causes by profile:"
$gaps |
    Group-Object -Property profileName, cause |
    Sort-Object Name |
    Select-Object Count, Name |
    Format-Table -AutoSize |
    Out-Host

Write-Host ("`nFirst {0} gaps (of {1}):" -f ([Math]::Min($Top, $gaps.Count)), $gaps.Count)
$gaps |
    Select-Object -First $Top |
    Select-Object profileName, sampleName, ruleId, cause, effectiveMode,
        @{Name='Confidence';Expression={if ($null -eq $_.confidence) {'N/A'} else {'{0:N2}' -f $_.confidence}}},
        @{Name='Floor';Expression={if ($null -eq $_.confidenceFloor) {'N/A'} else {'{0:N2}' -f $_.confidenceFloor}}} |
    Format-Table -AutoSize |
    Out-Host

if ($Detailed) {
    foreach ($gap in @($gaps | Select-Object -First $Top)) {
        Write-Host ("`n{0} / {1} / {2}: {3} [{4}]" -f $gap.profileName, $gap.sampleName,
            $gap.ruleId, $gap.cause, $gap.detectionOutcome)
        foreach ($reason in @($gap.evidence)) {
            Write-Host ("  - {0}" -f $reason)
        }
    }
}

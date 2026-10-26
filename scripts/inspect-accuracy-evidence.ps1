# SPDX-License-Identifier: MIT
# Read-only offline replay quality inspector; reports uncertainty and class balance.
[CmdletBinding()]
param(
    [string]$Report = (Join-Path $PSScriptRoot '..\build-verify\tuning-benchmark.json')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Report -PathType Leaf)) {
    throw "No benchmark JSON at $Report. Run .\verify-local.ps1 -Details -LiveOutput first."
}
$data = Get-Content -LiteralPath $Report -Raw | ConvertFrom-Json
if ($null -eq $data.summary -or $null -eq $data.summary.sampleLevelQualityByProfile) {
    throw 'Report has no per-profile sample-level quality. Run the updated benchmark.'
}

$culture = [System.Globalization.CultureInfo]::InvariantCulture
function Format-Ratio($value) {
    if ($null -eq $value) { return 'N/A' }
    return (([double]$value * 100).ToString('F1', $culture) + '%')
}
function Format-Interval($interval) {
    if ($null -eq $interval) { return 'N/A' }
    return "$(Format-Ratio $interval.lower)-$(Format-Ratio $interval.upper)"
}

Write-Host ("Offline replay cases: {0}; malicious: {1}; benign: {2}" -f
    $data.summary.replaySampleCount, $data.summary.maliciousSampleCount,
    $data.summary.benignSampleCount)
Write-Host 'Precision and false-positive rate are alert-level, not raw detector matches.'
Write-Host '95% Wilson bounds are descriptive: related synthetic scenarios are NOT independent field samples.'
Write-Host 'Use balanced accuracy to avoid hiding malicious misses behind plentiful benign fixtures.'

$rows = foreach ($profile in @($data.summary.sampleLevelQualityByProfile.PSObject.Properties | Sort-Object Name)) {
    $q = $profile.Value
    [pscustomobject]@{
        Profile = $profile.Name
        TP = [int]$q.truePositives
        FP = [int]$q.falsePositives
        FN = [int]$q.falseNegatives
        TN = [int]$q.trueNegatives
        Precision = (Format-Ratio $q.precision)
        'P95 lower' = (Format-Ratio $q.precision95.lower)
        Recall = (Format-Ratio $q.recall)
        Balanced = (Format-Ratio $q.balancedAccuracy)
        'FP-rate' = (Format-Ratio $q.falsePositiveRate)
        'FP95 upper' = (Format-Ratio $q.falsePositiveRate95.upper)
    }
}
$rows | Format-Table -AutoSize | Out-Host
Write-Host 'Separate R118/R163/R102 scenario-matrix xUnit tests are NOT included in these replay fixture counts.'

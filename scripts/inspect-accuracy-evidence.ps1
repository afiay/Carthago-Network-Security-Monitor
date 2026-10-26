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
function Get-OptionalField($object, [string]$field) {
    if ($null -eq $object) { return $null }
    $property = $object.PSObject.Properties[$field]
    if ($null -eq $property) { return $null }
    return $property.Value
}
function Format-Ratio($value) {
    if ($null -eq $value) { return 'N/A' }
    return (([double]$value * 100).ToString('F1', $culture) + '%')
}
function Wilson95([int]$successes, [int]$observations) {
    if ($observations -le 0 -or $successes -lt 0 -or $successes -gt $observations) {
        return $null
    }
    $z = 1.959963984540054
    $n = [double]$observations
    $p = $successes / $n
    $zSquared = $z * $z
    $denominator = 1 + $zSquared / $n
    $centre = ($p + $zSquared / (2 * $n)) / $denominator
    $radius = ($z * [Math]::Sqrt($p * (1-$p) / $n +
        $zSquared / (4 * $n * $n))) / $denominator
    return [pscustomobject]@{
        lower = [Math]::Max(0.0, $centre - $radius)
        upper = [Math]::Min(1.0, $centre + $radius)
        observations = $observations
    }
}

Write-Host ("Offline replay cases: {0}; malicious: {1}; benign: {2}" -f
    $data.summary.replaySampleCount, $data.summary.maliciousSampleCount,
    $data.summary.benignSampleCount)
Write-Host 'Precision and false-positive rate are alert-level, not raw detector matches.'
Write-Host '95% Wilson bounds assume independent samples. Related synthetic scenarios are NOT independent field samples.'
Write-Host 'Wilson bounds may be recalculated from confusion counts when null properties were omitted from the JSON serializer.'
Write-Host 'Use balanced accuracy to avoid hiding malicious misses behind plentiful benign fixtures.'

$rows = foreach ($profile in @($data.summary.sampleLevelQualityByProfile.PSObject.Properties | Sort-Object Name)) {
    $q = $profile.Value
    $tp = [int]$q.truePositives
    $fp = [int]$q.falsePositives
    $fn = [int]$q.falseNegatives
    $tn = [int]$q.trueNegatives

    # System.Text.Json omits null ratios/interval objects by design. In
    # particular, 0 TP + 0 FP means precision is undefined (NOT 0%).
    $precision = if (($tp + $fp) -gt 0) { [double]$tp / ($tp + $fp) } else { $null }
    $recall = if (($tp + $fn) -gt 0) { [double]$tp / ($tp + $fn) } else { $null }
    $specificity = if (($tn + $fp) -gt 0) { [double]$tn / ($tn + $fp) } else { $null }
    $balanced = if ($null -ne $recall -and $null -ne $specificity) {
        ($recall + $specificity) / 2.0
    } else { $null }
    $fpRate = if (($fp + $tn) -gt 0) { [double]$fp / ($fp + $tn) } else { $null }

    $precision95 = Get-OptionalField $q 'precision95'
    if ($null -eq $precision95) { $precision95 = Wilson95 $tp ($tp + $fp) }
    $falsePositiveRate95 = Get-OptionalField $q 'falsePositiveRate95'
    if ($null -eq $falsePositiveRate95) {
        $falsePositiveRate95 = Wilson95 $fp ($fp + $tn)
    }
    [pscustomobject]@{
        Profile = $profile.Name
        TP = $tp
        FP = $fp
        FN = $fn
        TN = $tn
        Precision = (Format-Ratio $precision)
        'P95 lower' = (Format-Ratio (Get-OptionalField $precision95 'lower'))
        Recall = (Format-Ratio $recall)
        Balanced = (Format-Ratio $balanced)
        'FP-rate' = (Format-Ratio $fpRate)
        'FP95 upper' = (Format-Ratio (Get-OptionalField $falsePositiveRate95 'upper'))
    }
}
$rows | Format-Table -AutoSize | Out-Host
Write-Host 'Separate R118/R163/R102 scenario-matrix xUnit tests are NOT included in these replay fixture counts.'

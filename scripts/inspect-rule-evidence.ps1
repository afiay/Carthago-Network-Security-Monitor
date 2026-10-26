# SPDX-License-Identifier: MIT
# Inspect explicit per-rule positive and negative replay controls.
[CmdletBinding()]
param(
    [string]$Report = (Join-Path $PSScriptRoot '..\build-verify\tuning-benchmark.json'),
    [string[]]$RuleId = @('R102', 'R118', 'R163'),
    [switch]$AllTested,
    [switch]$MissingPaired,
    [ValidateRange(1, 544)]
    [int]$Top = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Report -PathType Leaf)) {
    throw "No benchmark report found at $Report. Run .\verify-local.ps1 -Details."
}

$reportData = Get-Content -LiteralPath $Report -Raw | ConvertFrom-Json
$property = $reportData.PSObject.Properties['ruleEvidenceCoverage']
if ($null -eq $property) {
    throw 'Report lacks ruleEvidenceCoverage. Pull the latest feature branch and rerun verification.'
}

$items = @($property.Value)
function Format-Ratio($item, [string]$name) {
    $ratio = $item.PSObject.Properties[$name]
    if ($null -eq $ratio -or $null -eq $ratio.Value) { return 'N/A' }
    return '{0:F1}%' -f (100 * [double]$ratio.Value)
}

$positiveCount = @($items | Where-Object { $_.positiveCases -gt 0 }).Count
$negativeCount = @($items | Where-Object { $_.explicitNegativeCases -gt 0 }).Count
$pairedCount = @($items | Where-Object {
    $_.positiveCases -gt 0 -and $_.explicitNegativeCases -gt 0
}).Count

Write-Host ("Rule inventory: {0}; positive controls: {1}; explicit negative controls: {2}; paired: {3}" -f
    $items.Count, $positiveCount, $negativeCount, $pairedCount)
Write-Host 'N/A indicates missing explicitly labeled control data, not a 0% or 100% success rate.'
Write-Host 'Benign raw matches can be deliberately shadowed; they are not automatically false-positive alerts.'

$selected = @(
    if ($AllTested -or $MissingPaired) {
        $items | Where-Object {
            ($_.positiveCases -gt 0 -or $_.explicitNegativeCases -gt 0) -and
            (-not $MissingPaired -or $_.positiveCases -eq 0 -or $_.explicitNegativeCases -eq 0)
        } | Sort-Object -Property @{Expression='positiveCases';Descending=$true},
            @{Expression='explicitNegativeCases';Descending=$true}, ruleId |
            Select-Object -First $Top
    } else {
        $items | Where-Object { $RuleId -contains $_.ruleId }
    }
)

if ($selected.Count -eq 0) {
    Write-Host 'No rule evidence matched the selected filters.'
    exit 0
}

$selected | ForEach-Object {
    [pscustomobject]@{
        Rule = $_.ruleId
        'Positive' = "$($_.positiveRecognized)/$($_.positiveCases)"
        'Recognition' = (Format-Ratio $_ 'positiveRecognitionRate')
        'Negative' = "$($_.explicitNegativePassed)/$($_.explicitNegativeCases)"
        'Negative pass' = (Format-Ratio $_ 'explicitNegativePassRate')
        'Benign raw' = $_.benignRawMatches
        Paired = ($_.positiveCases -gt 0 -and $_.explicitNegativeCases -gt 0)
    }
} | Format-Table -AutoSize | Out-Host

# SPDX-License-Identifier: MIT
# Examine all default catalog rules without confusing declared contracts
# with independent field validation or paired synthetic replay tests.
[CmdletBinding()]
param(
    [string]$Report = (Join-Path $PSScriptRoot '..\build-verify\tuning-benchmark.json'),
    [string]$Category,
    [string[]]$RuleId,
    [switch]$MissingPaired,
    [switch]$OnlyContractIssues,
    [ValidateRange(1, 544)]
    [int]$Top = 30
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Report -PathType Leaf)) {
    throw "Benchmark report not found: $Report. Run .\verify-local.ps1 -Details first."
}
$reportData = Get-Content -LiteralPath $Report -Raw | ConvertFrom-Json
$property = $reportData.PSObject.Properties['ruleHardeningAudit']
if ($null -eq $property -or $null -eq $property.Value) {
    throw 'No full-rule audit in this report. Pull the latest branch and rerun verification.'
}
$items = @($property.Value)
$paired = @($items | Where-Object { $_.pairedSyntheticControls -eq $true }).Count
$issues = @($items | Where-Object { @($_.contractIssues).Count -gt 0 }).Count
$untested = @($items | Where-Object { $_.evidenceStatus -eq 'NoExplicitReplayControls' }).Count

Write-Host ("Rule contracts: {0}; paired synthetic replay controls: {1}; no explicit replay controls: {2}; contract issues: {3}" -f
    $items.Count, $paired, $untested, $issues)
Write-Host 'Paired synthetic controls are NOT a production-readiness certificate.'

$selected = @(
    $items | Where-Object {
        ([string]::IsNullOrWhiteSpace($Category) -or
            $_.category -like "*$Category*") -and
        ($null -eq $RuleId -or $RuleId.Count -eq 0 -or $RuleId -contains $_.ruleId) -and
        (-not $MissingPaired -or $_.pairedSyntheticControls -ne $true) -and
        (-not $OnlyContractIssues -or @($_.contractIssues).Count -gt 0)
    } | Sort-Object -Property @{
        Expression = { if (@($_.contractIssues).Count -gt 0) { 0 } else { 1 } }
    }, @{
        Expression = {
            switch ($_.severity) {
                'Critical' { 0 }
                'High'     { 1 }
                'Medium'   { 2 }
                default    { 3 }
            }
        }
    }, ruleId | Select-Object -First $Top
)
if ($selected.Count -eq 0) {
    Write-Host 'No audit entries match the filters.'
    exit 0
}
$selected | ForEach-Object {
    [pscustomobject]@{
        Rule = $_.ruleId
        Category = $_.category
        Severity = $_.severity
        Mode = $_.precisionDefaultMode
        Floor = "$($_.minimumConfidence)%"
        Pos = "$($_.positiveRecognized)/$($_.positiveCases)"
        Neg = "$($_.explicitNegativePassed)/$($_.explicitNegativeCases)"
        Paired = if ($_.pairedSyntheticControls) { 'Yes' } else { 'No' }
        Issues = @($_.contractIssues).Count
    }
} | Format-Table -AutoSize | Out-Host

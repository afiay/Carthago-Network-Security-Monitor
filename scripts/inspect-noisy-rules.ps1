# SPDX-License-Identifier: MIT
# Summarize benign raw detector matches without mislabeling Shadow candidates
# as emitted false-positive alerts. Requires completed tuning-benchmark.json.
[CmdletBinding()]
param(
    [string]$Report = (Join-Path $PSScriptRoot '..\build-verify\tuning-benchmark.json'),
    [string[]]$RuleId,
    [ValidateRange(1,544)][int]$Top = 20,
    [string]$ExportCsv
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Report -PathType Leaf)) {
    throw "Benchmark report not found: $Report"
}
$data = Get-Content -LiteralPath $Report -Raw | ConvertFrom-Json
$benign = @($data.sampleResults | Where-Object { $_.classification -eq 'Benign' })
$raw = @{}
foreach ($sample in $benign) {
    foreach ($id in @($sample.actualMatches | Sort-Object -Unique)) {
        if ($null -eq $id -or [string]::IsNullOrWhiteSpace([string]$id)) { continue }
        $key = [string]$id
        if (-not $raw.ContainsKey($key)) {
            $raw[$key] = [pscustomobject]@{
                Rule = $key
                BenignCases = 0
                AlertDecisions = 0
                ShadowDecisions = 0
                DisabledDecisions = 0
                Examples = [System.Collections.Generic.List[string]]::new()
            }
        }
        $row = $raw[$key]
        $row.BenignCases++
        if ($row.Examples.Count -lt 4) { $row.Examples.Add([string]$sample.name) }
        foreach ($profile in $sample.profiles.PSObject.Properties) {
            if (@($profile.Value.alertRuleIds) -contains $key) { $row.AlertDecisions++ }
            elseif (@($profile.Value.shadowRuleIds) -contains $key) { $row.ShadowDecisions++ }
            elseif (@($profile.Value.suppressedRuleIds) -contains $key) { $row.DisabledDecisions++ }
        }
    }
}

$select = @($raw.Values | Where-Object {
    $null -eq $RuleId -or $RuleId.Count -eq 0 -or $RuleId -contains $_.Rule
} | Sort-Object -Property @{Expression='BenignCases';Descending=$true}, Rule)
Write-Host ("Benign fixtures: {0}; distinct benign raw-matching rules: {1}" -f
    $benign.Count, $raw.Count)
Write-Host 'A benign raw match can be an intentional Shadow observation. Only emitted alerts are false-positive alerts.'
Write-Host 'Counts under Alert/Shadow/Disabled are rule/profile decisions, not independent samples.'
$view = @($select | Select-Object -First $Top | ForEach-Object {
    [pscustomobject]@{
        Rule = $_.Rule
        'Raw benign' = $_.BenignCases
        Alert = $_.AlertDecisions
        Shadow = $_.ShadowDecisions
        Disabled = $_.DisabledDecisions
        Examples = ($_.Examples -join '; ')
    }
})
if ($view.Count -eq 0) { Write-Host 'No matching benign raw detections.' }
else { $view | Format-Table -AutoSize -Wrap | Out-Host }

if (-not [string]::IsNullOrWhiteSpace($ExportCsv)) {
    $target = [IO.Path]::GetFullPath($ExportCsv)
    $parent = [IO.Path]::GetDirectoryName($target)
    if (-not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
    $select | Select-Object Rule,BenignCases,AlertDecisions,ShadowDecisions,DisabledDecisions,
        @{Name='ExampleSampleNames';Expression={$_.Examples -join '; '}} |
        Export-Csv -LiteralPath $target -NoTypeInformation -Encoding UTF8
    Write-Host "Exported ranked noise audit: $target"
}

# SPDX-License-Identifier: MIT
[CmdletBinding()]
param([string]$Path = (Join-Path $env:TEMP 'carthago-ui-operations.csv'))

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Path)) { throw "UI operation profile not found: $Path" }

$rows = @(Import-Csv -LiteralPath $Path)
if ($rows.Count -eq 0) { throw "No operation records found: $Path" }

$latest = $rows | Group-Object operation | ForEach-Object {
    $_.Group | Sort-Object { [datetime]$_.timestampUtc } | Select-Object -Last 1
}

$latest | ForEach-Object {
    $count = [long]$_.count
    $total = [long]$_.totalMs
    [pscustomobject]@{
        Operation = $_.operation
        Calls = $count
        TotalMs = $total
        MaxMs = [long]$_.maxMs
        MeanMs = if ($count -gt 0) { [math]::Round($total / $count, 2) } else { 0 }
    }
} | Sort-Object TotalMs -Descending | Format-Table -AutoSize

Write-Host 'Timings are cumulative synchronous operation duration. They do not measure all WPF layout/render work or the complete dispatcher queue.'

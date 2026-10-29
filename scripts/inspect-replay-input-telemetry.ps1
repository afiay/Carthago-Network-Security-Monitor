# SPDX-License-Identifier: MIT
# Report-only summary of known input telemetry gaps from a benchmark JSON.
# Does not modify rule data, thresholds, approval state or the report itself.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ReportPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$path=(Resolve-Path -LiteralPath $ReportPath -ErrorAction Stop).Path
$report=Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json
$rows=0
foreach ($sample in @($report.sampleResults)) {
    # Scenario labels are output only if they are simple, bounded identifiers.
    $scenario=[string]$sample.name
    if ($scenario -notmatch '^[A-Za-z0-9_-]{1,100}$') {
        $scenario='REDACTED_SCENARIO'
    }
    foreach ($diagnostic in @($sample.expectedRuleDiagnostics)) {
        $rule=[string]$diagnostic.ruleId
        if ($rule -notmatch '^R[0-9]{3}$') { continue }
        $codes=@($diagnostic.inputTelemetryIssueCodes | Where-Object {
            $_ -is [string] -and $_ -match '^DNS_[A-Z0-9_]{1,60}$'
        } | Sort-Object -Unique)
        if ($codes.Count -eq 0) { continue }
        $seen=[int]$diagnostic.inputRecordsInspected
        $affected=[int]$diagnostic.inputRecordsWithIssues
        if ($seen -lt 0 -or $affected -lt 0 -or $affected -gt $seen) {
            throw 'Benchmark input-telemetry counters are inconsistent.'
        }
        Write-Host ("INPUT TELEMETRY: {0} / {1}: {2}; affected={3}/{4} records; outcome={5}" -f
            $scenario,$rule,($codes -join ','),$affected,$seen,
            $(if ([string]$diagnostic.outcome -match '^[A-Za-z]{1,40}$') {
                [string]$diagnostic.outcome
            } else { 'UNKNOWN' }))
        $rows++
    }
}
Write-Host ("INPUT TELEMETRY SUMMARY: {0} expected-rule diagnostic(s) with structured input issues." -f $rows)
Write-Host 'Diagnostic-only: no raw QNAME, IP, headers, command lines, inference or rule promotion.'

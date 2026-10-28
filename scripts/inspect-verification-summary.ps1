# SPDX-License-Identifier: MIT
# Read-only summary of existing local verification artifacts.
# Does not execute tests, mutate artifacts, or alter pass/fail gates.
[CmdletBinding()]
param(
    [string]$Report = (Join-Path $PSScriptRoot '..\build-verify\tuning-benchmark.json'),
    [string]$Trx = (Join-Path $PSScriptRoot '..\build-verify\test-results\carthago-tests.trx')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

function Get-OptionalProperty($Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Read-ExistingArtifact([string]$Path, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label not found at $Path. Run .\verify-local.ps1 -Details -LiveOutput."
    }
    return Get-Item -LiteralPath $Path
}

$reportFile = Read-ExistingArtifact $Report 'Replay report'
$trxFile = Read-ExistingArtifact $Trx 'xUnit TRX'
$reportData = Get-Content -LiteralPath $reportFile.FullName -Raw | ConvertFrom-Json
if ($null -eq (Get-OptionalProperty $reportData 'summary') -or
    $null -eq (Get-OptionalProperty $reportData 'sampleResults')) {
    throw 'Replay JSON is missing required summary/sampleResults fields.'
}

[xml]$trxXml = Get-Content -LiteralPath $trxFile.FullName -Raw
$counters = $trxXml.SelectSingleNode(
    "//*[local-name()='ResultSummary']/*[local-name()='Counters']")
if ($null -eq $counters) {
    throw 'TRX is missing ResultSummary/Counters.'
}
$attributes = $counters.Attributes
$total = [int]$attributes['total'].Value
$passed = [int]$attributes['passed'].Value
$failed = [int]$attributes['failed'].Value
$skipped = [int]$attributes['notExecuted'].Value
$other = $total - $passed - $failed - $skipped
if ($other -lt 0) { throw 'Inconsistent TRX counters.' }

$head = (& git -C $repoRoot rev-parse HEAD 2>$null)
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($head)) {
    $head = 'UNKNOWN (not a Git checkout)'
} else {
    $head = ([string]$head).Trim()
}

Write-Host 'CARTHAGO LOCAL VERIFICATION SUMMARY'
Write-Host ('HEAD: {0}' -f $head)
Write-Host ('TRX:  {0} (modified UTC: {1:yyyy-MM-dd HH:mm:ss})' -f
    $trxFile.Name, $trxFile.LastWriteTimeUtc)
Write-Host ('xUnit: passed={0} failed={1} skipped={2} other={3} total={4}' -f
    $passed, $failed, $skipped, $other, $total)
Write-Host ('Replay: {0} (modified UTC: {1:yyyy-MM-dd HH:mm:ss})' -f
    $reportFile.Name, $reportFile.LastWriteTimeUtc)
$artifactGap = [Math]::Abs(($trxFile.LastWriteTimeUtc -
    $reportFile.LastWriteTimeUtc).TotalMinutes)
if ($artifactGap -gt 30) {
    Write-Warning ('TRX and benchmark timestamps differ by {0:N1} minutes. These could belong to different runs.' -f $artifactGap)
}

$summary = $reportData.summary
Write-Host ('Labeled samples: total={0} malicious={1} benign={2}' -f
    $summary.replaySampleCount, $summary.maliciousSampleCount, $summary.benignSampleCount)

$invalid = @($reportData.sampleResults | Where-Object {
    @($_.errors | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count -gt 0
})
Write-Host ('Invalid replay expectations: {0}' -f $invalid.Count)
foreach ($sample in @($invalid | Sort-Object name)) {
    $missing = @($sample.missingExpectedMatches | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_)
    })
    $label = if ($missing.Count -gt 0) { $missing -join ',' } else { 'confidence/other' }
    # Avoid printing sample Info, raw URLs, credentials, or arbitrary error text.
    # The result schema does not serialize a fixture confidence minimum.
    # Never invent it or print null as 0; use the original fixture/log for
    # expected floors, and retain the observed maximum here.
    Write-Host ('  {0} [{1}] observed-max-confidence={2:N2}' -f
        $sample.name, $label, [double]$sample.maximumConfidence)
    foreach ($diagnostic in @($sample.expectedRuleDiagnostics | Where-Object {
        $_.ruleId -in $missing
    })) {
        Write-Host ('    {0}: {1}' -f $diagnostic.ruleId, $diagnostic.outcome)
        foreach ($reason in @($diagnostic.noMatchReasons | Select-Object -First 3)) {
            # Structured category/code prefix only, without free-form message.
            Write-Host ('      {0}' -f (([string]$reason -split ':', 2)[0]))
        }
    }
}

$quality = Get-OptionalProperty $summary 'sampleLevelQualityByProfile'
$enterprise = Get-OptionalProperty $quality 'Enterprise'
if ($null -ne $enterprise) {
    Write-Host ('Enterprise alert-level confusion: TP={0} FP={1} FN={2} TN={3}' -f
        $enterprise.truePositives, $enterprise.falsePositives,
        $enterprise.falseNegatives, $enterprise.trueNegatives)
}
$benignCriticalAlerts = Get-OptionalProperty $summary 'benignCriticalAlertCount'
if ($null -ne $benignCriticalAlerts) {
    Write-Host ('Benign critical alerts: {0}' -f $benignCriticalAlerts)
}

if ($failed -ne 0 -or $other -ne 0 -or $invalid.Count -ne 0) {
    Write-Host 'STATUS: NOT CERTIFIED (test failure/unknown outcome or replay expectations unresolved)'
} else {
    Write-Host 'STATUS: xUnit and replay expectations clear; remaining full verification gates are not assessed by this summary.'
}
Write-Host 'Offline synthetic metrics do NOT establish field accuracy or release certification.'

# SPDX-License-Identifier: MIT
# Compare detector recognition, profile-policy gates and simulated alert recall.
[CmdletBinding()]
param(
    [string]$Report = (Join-Path $PSScriptRoot '..\build-verify\tuning-benchmark.json'),
    [string]$Profile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Report -PathType Leaf)) {
    throw "Benchmark report not found: $Report. Run .\verify-local.ps1 -Details first."
}
$reportData = Get-Content -LiteralPath $Report -Raw | ConvertFrom-Json
if ($null -eq $reportData.PSObject.Properties['detectionFunnelByProfile']) {
    throw 'This report predates the detection funnel. Pull the latest feature branch and rerun verification.'
}

function Format-Ratio($record, [string]$propertyName) {
    # Null-valued ratio properties are omitted by JSON serialization.
    # Under StrictMode we must not dereference a missing field.
    $field = $record.PSObject.Properties[$propertyName]
    if ($null -eq $field -or $null -eq $field.Value) { return 'N/A' }
    return '{0:P1}' -f [double]$field.Value
}

$rows = @(
    foreach ($property in $reportData.detectionFunnelByProfile.PSObject.Properties) {
        $funnel = $property.Value
        if (-not [string]::IsNullOrWhiteSpace($Profile) -and
            $property.Name -ne $Profile) { continue }
        [pscustomobject]@{
            Profile = $property.Name
            Expected = $funnel.expectedMaliciousRules
            Detected = $funnel.recognizedByDetector
            Missed = $funnel.detectorMisses
            'Detector recall' = (Format-Ratio $funnel 'detectorRecognitionRate')
            Alerts = $funnel.simulatedAlerted
            'Alert recall' = (Format-Ratio $funnel 'alertLevelRecall')
            Shadow = $funnel.policyShadowed
            Disabled = $funnel.policyDisabled
            Eligible = $funnel.policyEligibleRules
            'Eligible missing' = $funnel.eligibleButNotAlerted
            'Eligible emission' = (Format-Ratio $funnel 'eligibleAlertEmissionRate')
            'No policy decision' = $funnel.missingPolicyDecisions
            'Policy mismatch' = $funnel.alertDecisionMismatches
            'Benign alerts' = $funnel.benignSimulatedAlerts
        }
    }
)
if ($rows.Count -eq 0) {
    throw "No profiles matched '$Profile'."
}

Write-Host 'Detector recognition counts raw matches, including Shadow candidates.'
Write-Host 'Eligible emission is conditional on an effective Alert decision, NOT overall recall.'
Write-Host 'Simulated replay alert decisions do not confirm live notifications or production accuracy.'
# Keep the default terminal table readable; display all counters when a
# single profile is requested.
$rows | Select-Object Profile, Expected, Detected, 'Detector recall', Alerts,
    'Alert recall', Shadow, Disabled, Eligible, 'Eligible emission' |
    Format-Table -AutoSize | Out-Host
if (-not [string]::IsNullOrWhiteSpace($Profile)) {
    $rows | Format-List | Out-Host
}

if (@($rows | Where-Object { $_.'Eligible missing' -gt 0 -or $_.'No policy decision' -gt 0 -or $_.'Policy mismatch' -gt 0 }).Count -gt 0) {
    Write-Warning 'Unexpected policy-accounting gaps detected. Inspect per-rule decisions before changing alert modes.'
}

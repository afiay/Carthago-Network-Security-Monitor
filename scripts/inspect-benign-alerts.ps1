# SPDX-License-Identifier: MIT
# Inspect alert-level false positives without modifying rule tuning.
param(
    [string]$ReportPath = ".\\build-verify\\tuning-benchmark.json",
    [string]$SamplePattern = "r163-paired-*",
    [switch]$AllBenign,
    [switch]$Detailed
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if (-not (Test-Path -LiteralPath $ReportPath)) {
    throw "Benchmark report not found: $ReportPath. Run .\\verify-local.ps1 -Details first."
}

$report = Get-Content -LiteralPath $ReportPath -Raw | ConvertFrom-Json
$samples = @($report.sampleResults | Where-Object {
    $_.classification -eq "Benign" -and ($AllBenign -or $_.name -like $SamplePattern)
})
if ($samples.Count -eq 0) {
    throw "No matching benign replay samples. Check -SamplePattern or use -AllBenign."
}

$rows = foreach ($sample in $samples) {
    foreach ($profileProperty in $sample.profiles.PSObject.Properties) {
        $profile = $profileProperty.Value
        foreach ($ruleId in @($profile.alertRuleIds)) {
            $decision = @($profile.ruleDecisions | Where-Object { $_.ruleId -eq $ruleId }) | Select-Object -First 1
            [pscustomobject]@{
                Sample = $sample.name
                Profile = $profileProperty.Name
                Rule = $ruleId
                Confidence = if ($null -ne $decision) { $decision.confidence } else { $null }
                Mode = if ($null -ne $decision) { $decision.effectiveMode } else { "Alert" }
                Reasons = if ($null -ne $decision) { @($decision.reasons) -join "; " } else { "" }
                PrecisionReasons = if ($null -ne $decision) { @($decision.runtimePrecisionReasons) -join "; " } else { "" }
            }
        }
    }
}

if (@($rows).Count -eq 0) {
    Write-Host "No alert-level false positives in $($samples.Count) matching benign samples."
} else {
    if ($Detailed) {
        $rows | Sort-Object Sample, Profile, Rule | Format-List Sample, Profile, Rule, Confidence, Mode, Reasons, PrecisionReasons
    } else {
        $rows | Sort-Object Sample, Profile, Rule | Select-Object Sample, Profile, Rule, @{Name="Confidence";Expression={ if ($null -ne $_.Confidence) { "{0:P0}" -f [double]$_.Confidence } else { "" } }} | Format-Table -AutoSize
    }
    Write-Host "`nAlert counts by rule and profile:"
    $rows | Group-Object Rule, Profile | Sort-Object Count -Descending |
        Select-Object Count, Name | Format-Table -AutoSize
}

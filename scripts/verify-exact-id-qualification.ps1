# SPDX-License-Identifier: MIT
# Read-only qualification evidence validator; does not execute detectors.
[CmdletBinding()]
param([switch]$SelfTest)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RuleSourceInventory.psm1') -Force
$root = Split-Path $PSScriptRoot -Parent
function Assert-Qualification($condition, [string]$message) {
    if (-not $condition) { throw $message }
}
function Get-ReviewedExecutionMap($manifest, $registryMap) {
    Assert-Qualification ($manifest.schemaVersion -eq 1) 'Unsupported execution manifest schema'
    $entries = @{}
    foreach ($entry in $manifest.records) {
        foreach ($field in @('ruleId','executedSha','outcome','testReference','scope','reviewReference')) {
            Assert-Qualification ($null -ne $entry.PSObject.Properties[$field] -and -not [string]::IsNullOrWhiteSpace([string]$entry.$field)) "Missing execution field: $field"
        }
        Assert-Qualification ($entry.ruleId -cmatch '^R[0-9]+$' -and $registryMap.ContainsKey($entry.ruleId)) 'Unknown execution rule'
        Assert-Qualification ($entry.executedSha -cmatch '^[a-f0-9]{40}$') 'Invalid reviewed SHA'
        Assert-Qualification ($entry.outcome -cin @('pass','fail')) 'Unknown execution outcome'
        Assert-Qualification ($entry.scope -ceq 'synthetic-detector-regression') 'Unsupported execution scope'
        Assert-Qualification ($entry.testReference -cmatch '^Carthago\.Tests/[A-Za-z0-9_/.-]+\.cs$' -and $entry.testReference -notmatch '\.\.') 'Invalid test reference'
        Assert-Qualification ($entry.reviewReference -cin @('docs/rules/DETECTION_QUALIFICATION_GATE_20261112.md','docs/DEVELOPMENT_VALIDATION_LEDGER.md')) 'Invalid review reference'
        $key = "$($entry.ruleId):$($entry.executedSha)"
        Assert-Qualification (-not $entries.ContainsKey($key)) 'Duplicate reviewed execution'
        $entries[$key] = $entry
    }
    return $entries
}
function Test-Qualification($document, $inventory, [string]$currentSha, $manifest) {
    Assert-Qualification ($document.schemaVersion -eq 1) 'Unsupported schema'
    Assert-Qualification ($document.sourceSha -cmatch '^[a-f0-9]{40}$') 'Invalid source SHA'
    Assert-Qualification ($currentSha -cmatch '^[a-f0-9]{40}$') 'Invalid current SHA'
    $map = @{}
    foreach ($rule in $inventory.rules) {
        Assert-Qualification (-not $map.ContainsKey($rule.ruleId)) 'Duplicate registry ID'
        $map[$rule.ruleId] = $rule.registeredClass
    }
    Assert-Qualification (@($inventory.diagnostics | Where-Object { $_.code -in @('DUPLICATE_CORE_ID','NONCANONICAL_CORE_ID','UNRESOLVED_REGISTRATION') }).Count -eq 0) 'Unresolved registry identity'
    $reviewed = Get-ReviewedExecutionMap $manifest $map
    $seen = @{}
    $producerGaps = @('R275','R295','R343','R437','R508','R516')
    $unsupported = 0
    $current = 0
    $historical = 0
    $failed = 0
    foreach ($row in $document.records) {
        foreach ($field in @('ruleId','registeredClass','detector','pairedReplay','captureProvenance','profileEligibility','independentValidation','limitations')) {
            Assert-Qualification ($null -ne $row.PSObject.Properties[$field] -and $null -ne $row.$field -and -not [string]::IsNullOrWhiteSpace([string]$row.$field)) "Missing field: $field"
        }
        $id = $row.ruleId
        Assert-Qualification (-not $seen.ContainsKey($id)) "Duplicate audit ID: $id"
        $seen[$id] = $true
        Assert-Qualification ($id -cmatch '^R[0-9]+$' -and $map.ContainsKey($id) -and $map[$id] -ceq $row.registeredClass -and $row.registeredClass.StartsWith($id + '_', [StringComparison]::Ordinal)) "Unknown registry identity: $id"
        Assert-Qualification ($row.pairedReplay -cin @('synthetic-lookalike','synthetic-protocol-controls','missing')) "Unknown replay claim: $id"
        # These four established rules declare Alert by default; runtime gates
        # still apply. This is source policy, not a measured effective alert.
        $isGap = $id -cin $producerGaps
        $gapField = $row.PSObject.Properties['producerQualification']
        if ($isGap) {
            Assert-Qualification ($null -ne $gapField -and $gapField.Value -ceq 'unsupported-benchmark-scenario') "Missing producer gap classification: $id"
            $unsupported++
        } else {
            Assert-Qualification ($null -eq $gapField) "Unreviewed producer gap claim: $id"
        }
        $expectedPolicy = if ($isGap) { 'producer-limited-policy-unreviewed' } elseif ($id -cin @('R102','R103','R118','R163')) { 'alert-default-gated' } else { 'candidate-shadow' }
        Assert-Qualification ($row.profileEligibility -ceq $expectedPolicy) "Unreviewed policy claim: $id"
        Assert-Qualification ($row.independentValidation -ceq 'missing') "Unreviewed independent claim: $id"
        $d = $row.detector
        foreach ($field in @('status','positiveNegative','executedSha','reference')) {
            Assert-Qualification ($null -ne $d.PSObject.Properties[$field]) "Missing detector field: $field"
        }
        Assert-Qualification ($d.status -cin @('historical-pass','authored-unexecuted','missing','failed')) "Unknown detector status: $id"
        if ($isGap) {
            Assert-Qualification ($d.status -ceq 'missing' -and $row.pairedReplay -ceq 'missing') "Unreviewed producer-gap detector or replay claim: $id"
        }
        if ($d.status -in @('historical-pass','failed')) {
            Assert-Qualification ($d.executedSha -cmatch '^[a-f0-9]{40}$') "Missing execution SHA: $id"
            $key = "$($id):$($d.executedSha)"
            Assert-Qualification ($reviewed.ContainsKey($key)) "Unreviewed execution claim: $id"
            $entry = $reviewed[$key]
            $expectedOutcome = if ($d.status -ceq 'failed') { 'fail' } else { 'pass' }
            Assert-Qualification ($entry.outcome -ceq $expectedOutcome -and $entry.testReference -ceq $d.reference) "Execution evidence mismatch: $id"
            if ($d.executedSha -ceq $currentSha) { $current++ } else { $historical++ }
        } else {
            Assert-Qualification ($null -eq $d.executedSha) "Unexecuted evidence has SHA: $id"
        }
        Assert-Qualification (-not [string]::IsNullOrWhiteSpace($d.positiveNegative) -and -not [string]::IsNullOrWhiteSpace($d.reference)) "Missing evidence description: $id"
    }
    [pscustomobject]@{ registeredCount=$map.Count; auditedCount=$seen.Count; missingCount=$map.Count-$seen.Count; historicalExecutionRecords=$historical; currentExecutionRecords=$current; unsupportedProducerRecords=$unsupported; testsExecuted=0 }
}
$sha = (git -C $root rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve checkout HEAD' }
$registry = Get-Content -Raw (Join-Path $root 'Carthago/Engine/Rules/Catalog/RuleRegistry.cs')
$inventory = Get-RuleSourceInventory -RegistrySource $registry -Sources @{} -SourceSha $sha
$file = Join-Path $root 'docs/05-detection-quality/exact-id-qualification.json'
$doc = Get-Content -Raw $file | ConvertFrom-Json
$manifestFile = Join-Path $root 'docs/05-detection-quality/reviewed-execution-evidence.json'
$manifest = Get-Content -Raw $manifestFile | ConvertFrom-Json
$result = Test-Qualification $doc $inventory $sha $manifest
if ($SelfTest) {
    function Copy-Document { Get-Content -Raw $file | ConvertFrom-Json }
    function Expect-Rejection($candidate) {
        $rejected = $false
        try { $null = Test-Qualification $candidate $inventory $sha $manifest } catch { $rejected = $true }
        Assert-Qualification $rejected 'Invalid fixture accepted'
    }
    $bad = Copy-Document; $bad.records += $bad.records[0]; Expect-Rejection $bad
    $bad = Copy-Document; $bad.records[0].PSObject.Properties.Remove('limitations'); Expect-Rejection $bad
    $bad = Copy-Document; $bad.records[0].registeredClass = 'Unknown'; Expect-Rejection $bad
    $bad = Copy-Document; $bad.records[0].detector.executedSha = 'a' * 40; Expect-Rejection $bad
    $bad = Copy-Document; $bad.records[0].independentValidation = 'passed'; Expect-Rejection $bad
    $bad = Copy-Document; ($bad.records | Where-Object ruleId -ceq 'R102').profileEligibility = 'candidate-shadow'; Expect-Rejection $bad
    $bad = Copy-Document; ($bad.records | Where-Object ruleId -ceq 'R118').detector.executedSha = $sha; Expect-Rejection $bad
    $bad = Copy-Document; $bad.records[0].profileEligibility = 'alert-default-gated'; Expect-Rejection $bad
    $bad = Copy-Document; ($bad.records | Where-Object ruleId -ceq 'R295').PSObject.Properties.Remove('producerQualification'); Expect-Rejection $bad
    $bad = Copy-Document; ($bad.records | Where-Object ruleId -ceq 'R343').detector.status = 'failed'; Expect-Rejection $bad
    $bad = Copy-Document; $bad.records[0] | Add-Member -NotePropertyName producerQualification -NotePropertyValue 'unsupported-benchmark-scenario'; Expect-Rejection $bad
    Assert-Qualification ($result.unsupportedProducerRecords -eq 6) 'Producer gap count mismatch'
    function Copy-Manifest { Get-Content -Raw $manifestFile | ConvertFrom-Json }
    function Expect-ManifestRejection($candidate) {
        $rejected = $false
        try { $null = Test-Qualification $doc $inventory $sha $candidate } catch { $rejected = $true }
        Assert-Qualification $rejected 'Invalid execution manifest accepted'
    }
    $badManifest = Copy-Manifest; $badManifest.records += $badManifest.records[0]; Expect-ManifestRejection $badManifest
    $badManifest = Copy-Manifest; $badManifest.records[0].outcome = 'fail'; Expect-ManifestRejection $badManifest
    $badManifest = Copy-Manifest; $badManifest.records[0].testReference = 'Carthago.Tests/Unreviewed.cs'; Expect-ManifestRejection $badManifest
    $badManifest = Copy-Manifest; $badManifest.records[0].scope = 'field'; Expect-ManifestRejection $badManifest
    $badManifest = Copy-Manifest; $badManifest.records[0].PSObject.Properties.Remove('reviewReference'); Expect-ManifestRejection $badManifest
    $historical = Test-Qualification $doc $inventory ('a' * 40) $manifest
    Assert-Qualification ($historical.currentExecutionRecords -eq 0 -and $historical.historicalExecutionRecords -eq 16) 'Historical evidence misclassified'
}
$result | ConvertTo-Json

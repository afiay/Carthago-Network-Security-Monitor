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
function Test-Qualification($document, $inventory, [string]$currentSha) {
    Assert-Qualification ($document.schemaVersion -eq 1) 'Unsupported schema'
    Assert-Qualification ($document.sourceSha -cmatch '^[a-f0-9]{40}$') 'Invalid source SHA'
    Assert-Qualification ($currentSha -cmatch '^[a-f0-9]{40}$') 'Invalid current SHA'
    $map = @{}
    foreach ($rule in $inventory.rules) {
        Assert-Qualification (-not $map.ContainsKey($rule.ruleId)) 'Duplicate registry ID'
        $map[$rule.ruleId] = $rule.registeredClass
    }
    Assert-Qualification (@($inventory.diagnostics | Where-Object { $_.code -in @('DUPLICATE_CORE_ID','NONCANONICAL_CORE_ID','UNRESOLVED_REGISTRATION') }).Count -eq 0) 'Unresolved registry identity'
    $seen = @{}
    $current = 0
    $historical = 0
    foreach ($row in $document.records) {
        foreach ($field in @('ruleId','registeredClass','detector','pairedReplay','captureProvenance','profileEligibility','independentValidation','limitations')) {
            Assert-Qualification ($null -ne $row.PSObject.Properties[$field] -and $null -ne $row.$field -and -not [string]::IsNullOrWhiteSpace([string]$row.$field)) "Missing field: $field"
        }
        $id = $row.ruleId
        Assert-Qualification (-not $seen.ContainsKey($id)) "Duplicate audit ID: $id"
        $seen[$id] = $true
        Assert-Qualification ($map.ContainsKey($id) -and $map[$id] -ceq $row.registeredClass) "Unknown registry identity: $id"
        Assert-Qualification ($row.pairedReplay -cin @('synthetic-lookalike','synthetic-protocol-controls','missing')) "Unknown replay claim: $id"
        Assert-Qualification ($row.profileEligibility -ceq 'candidate-shadow') "Unreviewed policy claim: $id"
        Assert-Qualification ($row.independentValidation -ceq 'missing') "Unreviewed independent claim: $id"
        $d = $row.detector
        foreach ($field in @('status','positiveNegative','executedSha','reference')) {
            Assert-Qualification ($null -ne $d.PSObject.Properties[$field]) "Missing detector field: $field"
        }
        Assert-Qualification ($d.status -cin @('historical-pass','authored-unexecuted','missing','failed')) "Unknown detector status: $id"
        if ($d.status -in @('historical-pass','failed')) {
            Assert-Qualification ($d.executedSha -cmatch '^[a-f0-9]{40}$') "Missing execution SHA: $id"
            # Only the reviewed historical checkpoints in the gate are admitted in v1.
            $expected = if ($id -in @('R903','R908','R910','R919','R942','R950')) { 'e64e2dfe40a3d087c6369d9aca75264946878d28' } else { '4cc680bc8353e0bb04d2824843f84ace8f59f28e' }
            Assert-Qualification ($d.status -ceq 'historical-pass' -and $d.executedSha -ceq $expected -and $id -in @('R903','R908','R910','R919','R942','R950','R946','R947','R949','R708','R715','R792','R819','R881','R916','R962')) "Unreviewed execution claim: $id"
            if ($d.executedSha -ceq $currentSha) { $current++ } else { $historical++ }
        } else {
            Assert-Qualification ($null -eq $d.executedSha) "Unexecuted evidence has SHA: $id"
        }
        Assert-Qualification (-not [string]::IsNullOrWhiteSpace($d.positiveNegative) -and -not [string]::IsNullOrWhiteSpace($d.reference)) "Missing evidence description: $id"
    }
    [pscustomobject]@{ registeredCount=$map.Count; auditedCount=$seen.Count; missingCount=$map.Count-$seen.Count; historicalExecutionRecords=$historical; currentExecutionRecords=$current; testsExecuted=0 }
}
$sha = (git -C $root rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve checkout HEAD' }
$registry = Get-Content -Raw (Join-Path $root 'Carthago/Engine/Rules/Catalog/RuleRegistry.cs')
$inventory = Get-RuleSourceInventory -RegistrySource $registry -Sources @{} -SourceSha $sha
$file = Join-Path $root 'docs/05-detection-quality/exact-id-qualification.json'
$doc = Get-Content -Raw $file | ConvertFrom-Json
$result = Test-Qualification $doc $inventory $sha
if ($SelfTest) {
    function Copy-Document { Get-Content -Raw $file | ConvertFrom-Json }
    function Expect-Rejection($candidate) {
        $rejected = $false
        try { $null = Test-Qualification $candidate $inventory $sha } catch { $rejected = $true }
        Assert-Qualification $rejected 'Invalid fixture accepted'
    }
    $bad = Copy-Document; $bad.records += $bad.records[0]; Expect-Rejection $bad
    $bad = Copy-Document; $bad.records[0].PSObject.Properties.Remove('limitations'); Expect-Rejection $bad
    $bad = Copy-Document; $bad.records[0].registeredClass = 'Unknown'; Expect-Rejection $bad
    $bad = Copy-Document; $bad.records[0].detector.executedSha = 'a' * 40; Expect-Rejection $bad
    $bad = Copy-Document; $bad.records[0].independentValidation = 'passed'; Expect-Rejection $bad
    $historical = Test-Qualification $doc $inventory ('a' * 40)
    Assert-Qualification ($historical.currentExecutionRecords -eq 0 -and $historical.historicalExecutionRecords -eq 16) 'Historical evidence misclassified'
}
$result | ConvertTo-Json

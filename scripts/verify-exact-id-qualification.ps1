# SPDX-License-Identifier: MIT
# Read-only qualification evidence validator; does not execute detectors.
[CmdletBinding()]
param([switch]$SelfTest, [string]$ArtifactDirectory)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RuleSourceInventory.psm1') -Force
$root = Split-Path $PSScriptRoot -Parent
function Assert-Qualification($condition, [string]$message) {
    if (-not $condition) { throw $message }
}
function Get-ReviewedExecutionMap($manifest, $registryMap) {
    Assert-Qualification ($manifest.schemaVersion -is [int] -and $manifest.schemaVersion -eq 1) 'Unsupported execution manifest schema'
    # Fail closed on absent or unbounded reviewed manifests before iterating entries.
    Assert-Qualification ($null -ne $manifest.PSObject.Properties['records'] -and $manifest.records -is [array] -and $manifest.records.Count -le 10000) 'Invalid reviewed execution record collection'
    $entries = @{}
    $claimedArtifactTests = @{}
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
        # Legacy records are reviewed ledger attestations, not artifact proof.
        $artifact = $entry.PSObject.Properties['artifact']
        if ($null -ne $artifact) {
            Assert-Qualification ($null -ne $artifact.Value) 'Missing artifact metadata'
            $a = $artifact.Value
            foreach ($field in @('file','sha256','testNames','checkoutSha','checkoutReview','casePolarity')) {
                Assert-Qualification ($null -ne $a.PSObject.Properties[$field] -and $null -ne $a.$field) "Missing artifact field: $field"
            }
            Assert-Qualification ($a.file -cmatch '^[A-Za-z0-9_-][A-Za-z0-9_.-]*\.trx$' -and $a.file -notmatch '\.\.') 'Invalid artifact filename'
            Assert-Qualification ($a.sha256 -cmatch '^[a-f0-9]{64}$') 'Invalid artifact digest'
            Assert-Qualification ($a.checkoutSha -ceq $entry.executedSha -and -not [string]::IsNullOrWhiteSpace($a.checkoutReview)) 'Missing or mismatched checkout review'
            # Test pass/fail is not detector positive/negative polarity. Require an explicit reviewed case designation.
            Assert-Qualification ($a.casePolarity -cin @('positive-detector','negative-detector')) 'Missing or unreviewed detector case polarity'
            Assert-Qualification ($a.testNames -is [array] -and $a.testNames.Count -gt 0 -and $a.testNames.Count -le 1000) 'Invalid exact test selection size'
            Assert-Qualification (@($a.testNames | Where-Object { $_ -isnot [string] -or [string]::IsNullOrWhiteSpace($_) }).Count -eq 0) 'Invalid exact test name'
            # Bound manifest selections before opening any TRX.
            Assert-Qualification (@($a.testNames | Where-Object { $_.Length -gt 4096 -or $_ -match '[\x00-\x1f\x7f]' }).Count -eq 0) 'Oversized or control-bearing exact test name'
            Assert-Qualification (@($a.testNames | Select-Object -Unique).Count -eq $a.testNames.Count) 'Duplicate exact test selection'
            # Wildcards are not exact TRX test identities; reject them before artifact admission.
            Assert-Qualification (@($a.testNames | Where-Object { $_ -match '[*?]' }).Count -eq 0) 'Wildcard exact test selection'
            Assert-Qualification (-not [string]::IsNullOrWhiteSpace($ArtifactDirectory)) 'Artifact directory required'
            # A single TRX test result cannot substantiate two distinct rule/SHA claims.
            # Key by artifact digest and exact test identity; do not trust filenames alone.
            foreach ($testName in $a.testNames) {
                $claimKey = "$($a.sha256):$testName"
                Assert-Qualification (-not $claimedArtifactTests.ContainsKey($claimKey)) 'TRX test identity claimed by multiple execution records'
                $claimedArtifactTests[$claimKey] = $entry.ruleId
            }
            $artifactPath = Join-Path $ArtifactDirectory $a.file
            $expected = if ($entry.outcome -ceq 'pass') { 'Passed' } else { 'Failed' }
            $verified = & (Join-Path $PSScriptRoot 'verify-qualification-trx.ps1') -Artifact $artifactPath -ExpectedSha256 $a.sha256 -TestName $a.testNames -Outcome $expected | ConvertFrom-Json
            Assert-Qualification ($verified.artifactSha256 -ceq $a.sha256 -and $verified.matchedTests -eq $a.testNames.Count -and $verified.outcome -ceq $expected) 'Artifact verification mismatch'
        }
        $key = "$($entry.ruleId):$($entry.executedSha)"
        Assert-Qualification (-not $entries.ContainsKey($key)) 'Duplicate reviewed execution'
        $entries[$key] = $entry
    }
    return $entries
}
function Test-Qualification($document, $inventory, [string]$currentSha, $manifest) {
    Assert-Qualification ($document.schemaVersion -is [int] -and $document.schemaVersion -eq 1) 'Unsupported schema'
    Assert-Qualification ($document.sourceSha -cmatch '^[a-f0-9]{40}$') 'Invalid source SHA'
    Assert-Qualification ($null -ne $document.PSObject.Properties['records'] -and $document.records -is [array] -and $document.records.Count -gt 0 -and $document.records.Count -le 1000) 'Invalid exact-ID inventory record collection'
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
    $authored = 0
    $missing = 0
    $referencedExecutions = @{}
    # These counters distinguish reviewed ledger attestations from actual
    # digest-verified TRX evidence, without promoting either to field accuracy.
    $artifactPositive = 0
    $artifactNegative = 0
    $legacyAttestations = 0
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
        $expectedPolicy = if ($isGap) { 'producer-limited-policy-unreviewed' } elseif ($id -ceq 'R272') { 'shadowfirst-research-alert' } elseif ($id -cin @('R102','R103','R118','R163')) { 'alert-default-gated' } else { 'candidate-shadow' }
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
            $referencedExecutions[$key] = $true
            if ($null -ne $entry.PSObject.Properties['artifact']) {
                if ($entry.artifact.casePolarity -ceq 'positive-detector') { $artifactPositive++ }
                elseif ($entry.artifact.casePolarity -ceq 'negative-detector') { $artifactNegative++ }
                else { throw "Unreviewed TRX case polarity: $id" }
            } else {
                $legacyAttestations++
            }
            $expectedOutcome = if ($d.status -ceq 'failed') { 'fail' } else { 'pass' }
            Assert-Qualification ($entry.outcome -ceq $expectedOutcome -and $entry.testReference -ceq $d.reference) "Execution evidence mismatch: $id"
            if ($d.status -ceq 'failed') { $failed++ }
            if ($d.executedSha -ceq $currentSha) { $current++ } else { $historical++ }
        } else {
            Assert-Qualification ($null -eq $d.executedSha) "Unexecuted evidence has SHA: $id"
            if ($d.status -ceq 'authored-unexecuted') { $authored++ } else { $missing++ }
        }
        Assert-Qualification (-not [string]::IsNullOrWhiteSpace($d.positiveNegative) -and -not [string]::IsNullOrWhiteSpace($d.reference)) "Missing evidence description: $id"
    }
    Assert-Qualification ($referencedExecutions.Count -eq $reviewed.Count) 'Orphaned reviewed execution manifest record'
    Assert-Qualification ($artifactPositive + $artifactNegative + $legacyAttestations -eq $historical + $current) 'Evidence provenance partition mismatch'
    [pscustomobject]@{ registeredCount=$map.Count; auditedCount=$seen.Count; missingCount=$map.Count-$seen.Count; historicalExecutionRecords=$historical; currentExecutionRecords=$current; unsupportedProducerRecords=$unsupported; failedExecutionRecords=$failed; authoredUnexecutedRecords=$authored; missingDetectorRecords=$missing; artifactPositiveCases=$artifactPositive; artifactNegativeCases=$artifactNegative; legacyExecutionAttestations=$legacyAttestations; testsExecuted=0 }
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
    # JSON booleans must not coerce to schema version 1 (PowerShell comparison pitfall).
    $bad = Copy-Document; $bad.schemaVersion = $true; Expect-Rejection $bad
    $bad = Copy-Document; $bad.schemaVersion = '1'; Expect-Rejection $bad
    $bad = Copy-Document; $bad.schemaVersion = 1.0; Expect-Rejection $bad
    $bad = Copy-Document; $bad.records += $bad.records[0]; Expect-Rejection $bad
    $bad = Copy-Document; $bad.PSObject.Properties.Remove('records'); Expect-Rejection $bad
    $bad = Copy-Document; $bad.records = $null; Expect-Rejection $bad
    $bad = Copy-Document; $bad.records = @(); Expect-Rejection $bad
    $bad = Copy-Document; $bad.records = @(1..1001 | ForEach-Object { $bad.records[0] }); Expect-Rejection $bad
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
    Assert-Qualification ($result.artifactPositiveCases -eq 0 -and $result.artifactNegativeCases -eq 0 -and $result.legacyExecutionAttestations -eq ($result.historicalExecutionRecords + $result.currentExecutionRecords)) 'Historical attestations misreported as TRX evidence'
    Assert-Qualification ($result.authoredUnexecutedRecords + $result.missingDetectorRecords + $result.historicalExecutionRecords + $result.currentExecutionRecords -eq $result.auditedCount) 'Detector status partition mismatch'
    function Copy-Manifest { Get-Content -Raw $manifestFile | ConvertFrom-Json }
    function Expect-ManifestRejection($candidate) {
        $rejected = $false
        try { $null = Test-Qualification $doc $inventory $sha $candidate } catch { $rejected = $true }
        Assert-Qualification $rejected 'Invalid execution manifest accepted'
    }
    $badManifest = Copy-Manifest; $badManifest.schemaVersion = $true; Expect-ManifestRejection $badManifest
    $badManifest = Copy-Manifest; $badManifest.schemaVersion = '1'; Expect-ManifestRejection $badManifest
    $badManifest = Copy-Manifest; $badManifest.schemaVersion = 1.0; Expect-ManifestRejection $badManifest
    $badManifest = Copy-Manifest; $badManifest.records += $badManifest.records[0]; Expect-ManifestRejection $badManifest
    $badManifest = Copy-Manifest; $badManifest.PSObject.Properties.Remove('records'); Expect-ManifestRejection $badManifest
    $badManifest = Copy-Manifest; $badManifest.records = $null; Expect-ManifestRejection $badManifest
    $badManifest = Copy-Manifest; $badManifest.records = @(1..10001 | ForEach-Object { $badManifest.records[0] }); Expect-ManifestRejection $badManifest
    $badManifest = Copy-Manifest; $badManifest.records[0].ruleId = 'R001'; Expect-ManifestRejection $badManifest
    $badManifest = Copy-Manifest; $badManifest.records[0].outcome = 'fail'; Expect-ManifestRejection $badManifest
    $badManifest = Copy-Manifest; $badManifest.records[0].testReference = 'Carthago.Tests/Unreviewed.cs'; Expect-ManifestRejection $badManifest
    $badManifest = Copy-Manifest; $badManifest.records[0].scope = 'field'; Expect-ManifestRejection $badManifest
    # No real execution is admitted by these in-memory negative fixtures.
    $badManifest = Copy-Manifest
    $badManifest.records[0] | Add-Member -NotePropertyName artifact -NotePropertyValue ([pscustomobject]@{file='fixture.trx'})
    Expect-ManifestRejection $badManifest
    $badManifest = Copy-Manifest
    $badManifest.records[0] | Add-Member -NotePropertyName artifact -NotePropertyValue ([pscustomobject]@{file='../fixture.trx';sha256=('0'*64);testNames=@('Exact.Test');checkoutSha=$badManifest.records[0].executedSha;checkoutReview='fixture only';casePolarity='positive-detector'})
    Expect-ManifestRejection $badManifest
    $badManifest = Copy-Manifest
    $badManifest.records[0] | Add-Member -NotePropertyName artifact -NotePropertyValue ([pscustomobject]@{file='fixture.trx';sha256=('0'*64);testNames=@('Exact.Test');checkoutSha=('0'*40);checkoutReview='fixture only'})
    Expect-ManifestRejection $badManifest
    $badManifest = Copy-Manifest; $badManifest.records[0].PSObject.Properties.Remove('reviewReference'); Expect-ManifestRejection $badManifest
    $bad = Copy-Document; $bad.records[0].ruleId = $bad.records[0].ruleId.ToLowerInvariant(); Expect-Rejection $bad
    $historicalSha = 'a' * 40
    Assert-Qualification (@($manifest.records | Where-Object executedSha -ceq $historicalSha).Count -eq 0) 'Fixture SHA collides with reviewed evidence'
    $historical = Test-Qualification $doc $inventory $historicalSha $manifest
    $executedCount = @($doc.records | Where-Object { $_.detector.status -cin @('historical-pass','failed') }).Count
    Assert-Qualification ($historical.currentExecutionRecords -eq 0 -and $historical.historicalExecutionRecords -eq $executedCount) 'Historical evidence misclassified'
    # In-memory only: exercise an admitted failure without writing fake evidence.
    $failureDoc = Copy-Document
    $failureManifest = Copy-Manifest
    $failureRow = $failureDoc.records[0]
    $failureEntry = $failureManifest.records | Where-Object { $_.ruleId -ceq $failureRow.ruleId -and $_.executedSha -ceq $failureRow.detector.executedSha }
    Assert-Qualification (@($failureEntry).Count -eq 1) 'Missing failure fixture evidence'
    $failureRow.detector.status = 'failed'
    $failureRow.detector.executedSha = $historicalSha
    $failureEntry.outcome = 'fail'
    $failureEntry.executedSha = $historicalSha
    $failureResult = Test-Qualification $failureDoc $inventory $historicalSha $failureManifest
    $expectedFailures = @($failureDoc.records | Where-Object { $_.detector.status -ceq 'failed' }).Count
    Assert-Qualification ($failureResult.failedExecutionRecords -eq $expectedFailures -and $failureResult.currentExecutionRecords -eq 1) 'Failed execution misclassified'

    # Exercise the actual manifest-to-TRX path with isolated temporary evidence.
    # No fixture is persisted in the reviewed manifest.
    $savedArtifactDirectory = $ArtifactDirectory
    $fixtureDirectory = Join-Path ([IO.Path]::GetTempPath()) ('carthago-qualification-' + [Guid]::NewGuid().ToString('N'))
    try {
        $null = New-Item -ItemType Directory -Path $fixtureDirectory
        $ArtifactDirectory = $fixtureDirectory
        $fixturePath = Join-Path $fixtureDirectory 'fixture.trx'
        $fixtureXml = '<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010"><Results><UnitTestResult testName="Exact.Test" outcome="Passed"/></Results><ResultSummary outcome="Completed"/></TestRun>'
        [IO.File]::WriteAllBytes($fixturePath, [Text.Encoding]::UTF8.GetBytes($fixtureXml))
        $fixtureManifest = Copy-Manifest
        $fixtureEntry = $fixtureManifest.records[0]
        Assert-Qualification ($fixtureEntry.outcome -ceq 'pass') 'Expected passing fixture source'
        $fixtureEntry | Add-Member -Force -NotePropertyName artifact -NotePropertyValue ([pscustomobject]@{
            file='fixture.trx'
            sha256=(Get-FileHash -LiteralPath $fixturePath -Algorithm SHA256).Hash.ToLowerInvariant()
            testNames=@('Exact.Test')
            checkoutSha=$fixtureEntry.executedSha
            checkoutReview='Synthetic integration fixture only'
            casePolarity='positive-detector'
        })
        $fixtureResult = Test-Qualification $doc $inventory $sha $fixtureManifest
        Assert-Qualification ($fixtureResult.artifactPositiveCases -eq 1 -and $fixtureResult.artifactNegativeCases -eq 0 -and $fixtureResult.legacyExecutionAttestations -eq ($result.legacyExecutionAttestations - 1)) 'Positive TRX provenance count mismatch'
        Assert-Qualification ($fixtureResult.auditedCount -eq $result.auditedCount -and $fixtureResult.historicalExecutionRecords -eq $result.historicalExecutionRecords -and $fixtureResult.currentExecutionRecords -eq $result.currentExecutionRecords) 'Artifact integration changed evidence accounting'
        $fixtureEntry.artifact.casePolarity = 'unknown'
        Expect-ManifestRejection $fixtureManifest
        $fixtureEntry.artifact.casePolarity = 'negative-detector'
        $negativeFixture = Test-Qualification $doc $inventory $sha $fixtureManifest
        Assert-Qualification ($negativeFixture.auditedCount -eq $result.auditedCount -and $negativeFixture.artifactNegativeCases -eq 1 -and $negativeFixture.artifactPositiveCases -eq 0) 'Negative TRX provenance count mismatch'
        $fixtureEntry.artifact.PSObject.Properties.Remove('casePolarity')
        Expect-ManifestRejection $fixtureManifest
        $fixtureEntry | Add-Member -Force -NotePropertyName artifact -NotePropertyValue ([pscustomobject]@{file='fixture.trx';sha256=(Get-FileHash -LiteralPath $fixturePath -Algorithm SHA256).Hash.ToLowerInvariant();testNames=@('Exact.Test');checkoutSha=$fixtureEntry.executedSha;checkoutReview='Synthetic integration fixture only';casePolarity='positive-detector'})
        $fixtureEntry.artifact.sha256 = '0' * 64
        Expect-ManifestRejection $fixtureManifest
        $fixtureEntry.artifact.sha256 = (Get-FileHash -LiteralPath $fixturePath -Algorithm SHA256).Hash.ToLowerInvariant()
        # The same exact test in one artifact must not qualify another rule.
        $duplicateClaim = Copy-Manifest
        $second = @($duplicateClaim.records | Where-Object { $_.ruleId -cne $fixtureEntry.ruleId -and $_.outcome -ceq 'pass' })[0]
        Assert-Qualification ($null -ne $second) 'Missing second reviewed-pass fixture'
        $second | Add-Member -Force -NotePropertyName artifact -NotePropertyValue ([pscustomobject]@{
            file='fixture.trx';sha256=$fixtureEntry.artifact.sha256;testNames=@('Exact.Test')
            checkoutSha=$second.executedSha;checkoutReview='Synthetic duplicate-claim fixture';casePolarity='positive-detector'
        })
        Expect-ManifestRejection $duplicateClaim
        $fixtureEntry.artifact.testNames = @('Exact.Test','Exact.Test')
        Expect-ManifestRejection $fixtureManifest
        $fixtureEntry.artifact.testNames = @('Exact.Test','')
        Expect-ManifestRejection $fixtureManifest
        $fixtureEntry.artifact.testNames = @('exact.test')
        Expect-ManifestRejection $fixtureManifest
        $fixtureEntry.artifact.testNames = @('Exact.*')
        Expect-ManifestRejection $fixtureManifest
        $fixtureEntry.artifact.testNames = @('Exact.Te?t')
        Expect-ManifestRejection $fixtureManifest
        $fixtureEntry.artifact.testNames = @(1..1001 | ForEach-Object { 'Exact.Test.' + $_ })
        Expect-ManifestRejection $fixtureManifest
        $fixtureEntry.artifact.testNames = @('X' * 4097)
        Expect-ManifestRejection $fixtureManifest
        $fixtureEntry.artifact.testNames = @("Exact.`nTest")
        Expect-ManifestRejection $fixtureManifest
        $fixtureEntry.artifact.testNames = @('Exact.Test')
        Remove-Item -LiteralPath $fixturePath
        Expect-ManifestRejection $fixtureManifest
    } finally {
        $ArtifactDirectory = $savedArtifactDirectory
        if (Test-Path -LiteralPath $fixtureDirectory) { Remove-Item -LiteralPath $fixtureDirectory -Recurse -Force }
    }
}
$result | ConvertTo-Json

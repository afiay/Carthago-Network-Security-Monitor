# SPDX-License-Identifier: MIT
# PARKED CONTRACT ONLY. No execution until owner explicitly says "now it's test time".
# In-memory, synthetic, private V2 provenance: no packets, source download, or network.
[CmdletBinding()]
param([switch]$AuthorizedTestTime)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $AuthorizedTestTime) {
    throw 'PARKED: owner test-time permission required before running this contract.'
}

function Assert-Contract([bool]$Condition,[string]$Code) {
    if (-not $Condition) { throw ('V2 private provenance contract: '+$Code) }
}
function Clone-Candidates([object]$value) {
    # ConvertFrom-Json emits arrays differently between Windows PowerShell
    # and newer PowerShell. Assign first, then preserve ONE flat array of
    # four PSCustomObject candidates as the function's single output value.
    $json = ConvertTo-Json -InputObject $value -Depth 24
    $decoded = ConvertFrom-Json -InputObject $json
    $items = [object[]]$decoded
    Assert-Contract ($items.Count -eq 4) 'fixture-clone-cardinality'
    foreach($item in $items) {
        Assert-Contract ($null -ne $item -and
            $null -ne $item.PSObject.Properties['sample']) 'fixture-clone-item-shape'
    }
    return ,$items
}
function New-SyntheticCandidates([object[]]$Slots) {
    $result=[Collections.Generic.List[object]]::new()
    for($i=0; $i -lt $Slots.Length; $i++) {
        $slot=$Slots[$i]
        $id=('{0:x2}' -f ($i+17)) * 32
        $result.Add([pscustomobject]@{
            schemaVersion=2
            sample=[IO.Path]::GetFileNameWithoutExtension([string]$slot.file)
            classification=[string]$slot.classification
            sourceKind='external-pcap-reviewed'
            sourceUri='https://example.org/synthetic-source-only'
            sourceLicense='CC0-1.0'
            sourceLicenseEvidenceUri='https://example.org/synthetic-rights-only'
            independentLabelBasis='Synthetic structure check only; no external ground truth.'
            analystReviewedLabel=$false
            capturedTransportEvidence=$false
            privacyReviewRequired=$true
            captureFileName=('synthetic-slot-'+$i+'.pcap')
            captureSha256=$id
            frameNumbers=[int[]]@(1,2,3)
            questionIndices=[int[]]@(0,0,0)
            selectedRecordCount=3
            sourceAddress=('192.0.2.'+(10+$i))
            queryRoot=$(if($slot.classification -eq 'Malicious'){'exfil.example'}else{'normal.example'})
            originatingClientLabel=('synthetic-client-'+$i)
            collectionSessionId=('synthetic-session-'+$i)
            collectionVantage='client'
            independentClientEvidenceUri='https://example.org/synthetic-independent-review-pending'
            dnsWireNameEncoding='labels-base64-v1'
            extractor='tshark'
            extractorVersion='TShark synthetic test fixture'
            maximumPacketsToScan=1000
            selectionMethod='selected-source-frame-question-tuples-v2'
            transformations='None: original DNS label octets preserved; ASCII-only identity comparison'
            preparedAtUtc='2026-10-29T12:00:00Z'
            reviewState='PENDING_EXTERNAL_CAPTURE_AND_REVIEW'
        })
    }
    return ,$result.ToArray()
}
function Assert-MinimalResult([object[]]$Candidates,[string]$Schema) {
    $snapshot=ConvertTo-Json -InputObject $Candidates -Depth 24 -Compress
    $items=@(Confirm-HoldoutV2ProvenanceBatch -Candidates $Candidates -SchemaPath $Schema 6>&1)
    Assert-Contract ($items.Count -eq 1 -and $items[0] -is [pscustomobject]) 'unexpected-output-shape'
    $r=$items[0]
    Assert-Contract ([int]$r.CandidateCount -eq 4) 'wrong-candidate-count'
    Assert-Contract ([bool]$r.SchemaValid) 'structurally-valid-candidates-rejected'
    Assert-Contract ([bool]$r.RequiresHumanReview) 'human-review-bypassed'
    Assert-Contract (-not [bool]$r.IsApproved) 'provenance-was-automatically-approved'
    Assert-Contract ([string]$r.ApprovalState -ceq 'PENDING_EXTERNAL_CAPTURE_AND_REVIEW') 'review-state-changed'
    $allowed=@('CandidateCount','SchemaValid','RequiresHumanReview','IsApproved','ApprovalState')
    $actual=@($r.PSObject.Properties.Name)
    Assert-Contract ($actual.Count -eq $allowed.Count -and
        @(Compare-Object ($actual | Sort-Object) ($allowed | Sort-Object)).Count -eq 0) 'output-privacy-shape'
    Assert-Contract ((ConvertTo-Json -InputObject $Candidates -Depth 24 -Compress) -ceq $snapshot) 'validator-mutated-candidates'
    $summary=ConvertTo-Json $r -Depth 8 -Compress
    foreach($c in $Candidates) {
        foreach($v in @($c.sourceAddress,$c.captureFileName,$c.originatingClientLabel,
                       $c.collectionSessionId,$c.sourceUri,$c.captureSha256)) {
            Assert-Contract (-not $summary.Contains([string]$v)) 'private-evidence-in-result'
        }
    }
}
function Assert-Rejected([object[]]$Candidates,[string]$Schema,[string]$Code) {
    $rejected=$false
    try {
        $ignored=@(Confirm-HoldoutV2ProvenanceBatch -Candidates $Candidates -SchemaPath $Schema 6>&1)
    } catch {
        $rejected=$true
        $message=[string]$_.Exception.Message
        Assert-Contract ($message.Contains($Code)) 'wrong-rejection-reason'
        foreach($c in $Candidates) {
            # Use property descriptors, not direct member access: the missing-
            # required-field mutation intentionally removes a property under
            # Set-StrictMode and must still assert the intended rejection code.
            foreach($field in @('sourceAddress','originatingClientLabel',
                                'collectionSessionId','sourceUri','captureSha256')) {
                $property=$c.PSObject.Properties[$field]
                if($null -eq $property) { continue }
                $secret=[string]$property.Value
                if(-not [string]::IsNullOrWhiteSpace($secret)) {
                    Assert-Contract (-not $message.Contains($secret)) 'private-evidence-in-error'
                }
            }
        }
    }
    Assert-Contract $rejected 'invalid-candidates-were-accepted'
}
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$schema=Join-Path $root 'docs/contracts/holdout-v2-private-provenance-v2.schema.json'
Assert-Contract (Test-Path -LiteralPath $schema -PathType Leaf) 'schema-file-not-found'
$manifest=Get-Content -LiteralPath (Join-Path $root 'docs/holdout-evaluation-v2-manifest.json') -Raw | ConvertFrom-Json
$slots=@($manifest.samples | Where-Object { $_.sourceKind -eq 'external-pcap-reviewed' })
Assert-Contract ($slots.Count -eq 4) 'manifest-slot-count-mismatch'
Assert-Contract ((@($slots | ForEach-Object { [string]$_.classification }) -join ',') -ceq
                 'Benign,Benign,Malicious,Malicious') 'manifest-order-mismatch'
$module=Join-Path $PSScriptRoot 'HoldoutV2Provenance.psm1'
Assert-Contract (Test-Path -LiteralPath $module -PathType Leaf) 'provenance-validator-not-implemented-red'
Import-Module -Name $module -Force -ErrorAction Stop
Assert-Contract ($null -ne (Get-Command Confirm-HoldoutV2ProvenanceBatch -ErrorAction SilentlyContinue)) 'provenance-validator-api-not-implemented-red'

$reference=New-SyntheticCandidates $slots
Assert-Contract ($reference.Count -eq 4) 'fixture-reference-cardinality'
# Schema-valid, still unapproved, containing deliberately unreviewed fields.
Assert-MinimalResult (Clone-Candidates $reference) $schema
# A repeated frame with a *different* DNS question ordinal is structurally
# valid; capture-level truth remains a separate offline review requirement.
$ordinalPositive=Clone-Candidates $reference
$ordinalPositive[0].frameNumbers[1]=1
$ordinalPositive[0].questionIndices[1]=1
Assert-MinimalResult $ordinalPositive $schema

$cases=@(
    @{Name='wrong-version';Code='PROV_SCHEMA_VERSION';Edit={param($a) $a[0].schemaVersion=1}},
    @{Name='unknown-field';Code='PROV_SCHEMA_EXTRA_FIELD';Edit={param($a) $a[0] | Add-Member -NotePropertyName unreviewedDebug -NotePropertyValue 'synthetic'}},
    @{Name='missing-required';Code='PROV_SCHEMA_REQUIRED_FIELD';Edit={param($a) $a[0].PSObject.Properties.Remove('collectionSessionId')}},
    @{Name='review-bool-string';Code='PROV_SCHEMA_TYPE';Edit={param($a) $a[2].analystReviewedLabel='yes'}},
    @{Name='sha-uppercase';Code='PROV_SCHEMA_CAPTURE_HASH';Edit={param($a) $a[0].captureSha256='AB'*32}},
    @{Name='negative-frame';Code='PROV_SCHEMA_FRAME_INDEX';Edit={param($a) $a[0].frameNumbers[0]=-1}},
    @{Name='negative-ordinal';Code='PROV_SCHEMA_QUESTION_INDEX';Edit={param($a) $a[0].questionIndices[0]=-1}},
    @{Name='array-misaligned';Code='PROV_SCHEMA_CARDINALITY';Edit={param($a) $a[0].questionIndices=@(0,0)}},
    @{Name='count-mismatch';Code='PROV_SCHEMA_CARDINALITY';Edit={param($a) $a[0].selectedRecordCount=4}},
    @{Name='duplicate-same-frame-question';Code='PROV_SCHEMA_DUPLICATE_QUESTION';Edit={param($a) $a[0].frameNumbers[1]=1}},
    @{Name='duplicate-across-samples';Code='PROV_BATCH_DUPLICATE_QUESTION';Edit={param($a) $a[1].captureSha256=$a[0].captureSha256}},
    @{Name='duplicate-sample';Code='PROV_BATCH_DUPLICATE_SAMPLE';Edit={param($a) $a[3].sample=$a[2].sample}},
    @{Name='same-malicious-source';Code='PROV_BATCH_IP_COLLISION';Edit={param($a) $a[3].sourceAddress=$a[2].sourceAddress}},
    @{Name='same-malicious-session';Code='PROV_BATCH_SESSION_COLLISION';Edit={param($a) $a[3].collectionSessionId=$a[2].collectionSessionId}},
    @{Name='same-malicious-origin';Code='PROV_BATCH_ORIGIN_COLLISION';Edit={param($a) $a[3].originatingClientLabel=$a[2].originatingClientLabel}},
    @{Name='invalid-vantage';Code='PROV_SCHEMA_VANTAGE';Edit={param($a) $a[0].collectionVantage='unattributed-proxy'}},
    @{Name='http-source';Code='PROV_SCHEMA_URI';Edit={param($a) $a[0].sourceUri='http://example.org/unreviewed'}},
    @{Name='wrong-license';Code='PROV_SCHEMA_LICENSE';Edit={param($a) $a[0].sourceLicense='Other'}},
    @{Name='wrong-encoding';Code='PROV_SCHEMA_ENCODING';Edit={param($a) $a[0].dnsWireNameEncoding='legacy-text-v0'}},
    @{Name='false-approval';Code='PROV_SCHEMA_REVIEW_STATE';Edit={param($a) $a[0].reviewState='APPROVED'}},
    @{Name='invalid-root';Code='PROV_SCHEMA_ROOT';Edit={param($a) $a[0].queryRoot='Invalid..Root'}},
    @{Name='unexpected-method';Code='PROV_SCHEMA_METHOD';Edit={param($a) $a[0].selectionMethod='textual-first-qname'}},
    @{Name='wrong-count-type';Code='PROV_SCHEMA_TYPE';Edit={param($a) $a[0].selectedRecordCount='3'}},
    @{Name='not-four-candidates';Code='PROV_BATCH_SHAPE';Edit={param($a) $script:removeLast=$true}}
)
foreach($case in $cases) {
    $candidate=Clone-Candidates $reference
    $script:removeLast=$false
    & $case.Edit $candidate
    if($script:removeLast) { $candidate=@($candidate[0..2]) }
    Assert-Rejected $candidate $schema ([string]$case.Code)
}
Write-Host ('Private provenance schema contract: 2 structurally-valid, pending-review controls and '+
            $cases.Count+' negative cases. All candidate identities remain synthetic.')

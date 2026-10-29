# SPDX-License-Identifier: MIT
# PARKED Stage 6E: synthetic fault-injection contract for a FUTURE private
# atomic batch publisher. Do not run without explicit owner test-time approval.
# No capture, TShark, network traffic, detector, or manifest mutation.
[CmdletBinding()]
param([switch]$AuthorizedTestTime)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $AuthorizedTestTime) {
    throw 'PARKED: owner permission required; this switch is not permission.'
}
function Assert-Contract([bool]$Condition,[string]$Code) {
    if (-not $Condition) { throw ('STAGE6E_CONTRACT: '+$Code) }
}
function New-SyntheticPairs([object[]]$Slots) {
    $pairs = [Collections.Generic.List[object]]::new()
    for($i=0;$i -lt $Slots.Count;$i++) {
        $slot = $Slots[$i]
        $name = [IO.Path]::GetFileNameWithoutExtension([string]$slot.file)
        $malicious = [string]$slot.classification -ceq 'Malicious'
        $ip = '192.0.2.'+(20+$i)
        $root = if($malicious){'exfil.example'}else{'normal.example'}
        $records = @()
        for($j=0;$j -lt 3;$j++) {
            $records += [ordered]@{
                source=$ip; destination='198.51.100.53'; ipVersion=4
                sourcePort=(53010+$i); destinationPort=53
                protocol='DNS';applicationProtocol='DNS';isUdp=$true;isTcp=$false
                dnsQname=('synthetic'+$i+$j+'.'+$root);dnsQtype='TXT'
            }
        }
        $matches=[string[]]@()
        $nonmatches=[string[]]@('R102','R118','R163')
        if($malicious) {
            $matches=[string[]]@('R102')
            $nonmatches=[string[]]@('R118','R163')
        }
        $sample=[ordered]@{
            name=$name;classification=[string]$slot.classification;records=$records
            expectedMatches=$matches;expectedNonMatches=$nonmatches
            expectedMinimumConfidence=$(if($malicious){0.75}else{0.0})
        }
        $provenance=[ordered]@{
            schemaVersion=2;sample=$name;classification=[string]$slot.classification
            sourceKind='external-pcap-reviewed'
            sourceUri='https://example.org/synthetic-source-only'
            sourceLicense='CC0-1.0'
            sourceLicenseEvidenceUri='https://example.org/synthetic-rights-only'
            independentLabelBasis='Synthetic only; no verified ground truth or source approval.'
            analystReviewedLabel=$false;capturedTransportEvidence=$false
            privacyReviewRequired=$true
            captureFileName=('synthetic-'+$i+'.pcap')
            captureSha256=(('{0:x2}' -f (30+$i))*32)
            frameNumbers=[int[]]@(1,2,3);questionIndices=[int[]]@(0,0,0)
            selectedRecordCount=3;sourceAddress=$ip;queryRoot=$root
            originatingClientLabel=('synthetic-client-'+$i)
            collectionSessionId=('synthetic-session-'+$i)
            collectionVantage='client'
            independentClientEvidenceUri='https://example.org/review-still-pending'
            dnsWireNameEncoding='labels-base64-v1'
            extractor='tshark';extractorVersion='TShark synthetic-only'
            maximumPacketsToScan=1000
            selectionMethod='selected-source-frame-question-tuples-v2'
            transformations='None: original DNS label octets preserved; ASCII-only identity comparison'
            preparedAtUtc='2026-10-29T12:00:00Z'
            reviewState='PENDING_EXTERNAL_CAPTURE_AND_REVIEW'
        }
        $pairs.Add([pscustomobject]@{
            Sample=[pscustomobject]$sample
            Provenance=[pscustomobject]$provenance
        })
    }
    return ,$pairs.ToArray()
}
function Assert-PrivateError([string]$Message,[string]$Code,[object[]]$Pairs) {
    Assert-Contract ($Message.Contains($Code)) 'wrong-error-reason'
    foreach($pair in $Pairs) {
        foreach($key in @('sourceAddress','originatingClientLabel',
                          'collectionSessionId','sourceUri','captureSha256')) {
            $property=$pair.Provenance.PSObject.Properties[$key]
            if($null -ne $property) {
                $v=[string]$property.Value
                if($v.Length -gt 0) {
                    Assert-Contract (-not $Message.Contains($v)) 'private-provenance-in-error'
                }
            }
        }
        foreach($record in @($pair.Sample.records)) {
            if($Message.Contains([string]$record.dnsQname)) {
                throw 'STAGE6E_CONTRACT: reversible-name-in-error'
            }
        }
    }
}
function Assert-FinalBatch([string]$Root,[string]$Name,[object[]]$Pairs) {
    $dir=Join-Path $Root $Name
    Assert-Contract (Test-Path -LiteralPath $dir -PathType Container) 'committed-directory-missing'
    Assert-Contract (@(Get-ChildItem -LiteralPath $dir -File -Force).Count -eq 8) 'committed-file-count'
    foreach($pair in $Pairs) {
        $id=[string]$pair.Provenance.sample
        $a=Join-Path $dir ($id+'.json')
        $b=Join-Path $dir ($id+'.provenance.json')
        Assert-Contract ((Test-Path -LiteralPath $a -PathType Leaf) -and
            (Test-Path -LiteralPath $b -PathType Leaf)) 'incomplete-published-pair'
        $sample=Get-Content -LiteralPath $a -Raw | ConvertFrom-Json
        $p=Get-Content -LiteralPath $b -Raw | ConvertFrom-Json
        Assert-Contract ([string]$sample.name -ceq $id -and
            [string]$p.sample -ceq $id -and
            [string]$sample.classification -ceq [string]$p.classification) 'cross-file-mismatch'
        Assert-Contract ([int]$p.schemaVersion -eq 2 -and
            [string]$p.reviewState -ceq 'PENDING_EXTERNAL_CAPTURE_AND_REVIEW') 'published-as-approved'
        # Compare the serialized synthetic fixture content, not just names.
        # Publisher must neither silently normalize, omit nor invent fields.
        $actualSample=ConvertTo-Json -InputObject $sample -Depth 24 -Compress
        $actualProvenance=ConvertTo-Json -InputObject $p -Depth 24 -Compress
        $expectedSample=ConvertTo-Json -InputObject $pair.Sample -Depth 24 -Compress
        $expectedProvenance=ConvertTo-Json -InputObject $pair.Provenance -Depth 24 -Compress
        Assert-Contract ($actualSample -ceq $expectedSample) 'sample-data-changed-on-publication'
        Assert-Contract ($actualProvenance -ceq $expectedProvenance) 'provenance-data-changed-on-publication'
    }
}
function Get-Hashes([string]$Root,[string]$Name) {
    $folder=Join-Path $Root $Name
    return ,@(
        Get-ChildItem -LiteralPath $folder -File -Force |
            Sort-Object Name | ForEach-Object {
                [pscustomobject]@{
                    Name=$_.Name
                    Hash=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
                }
            }
    )
}
function Assert-NoPending([string]$Root) {
    $parts=@(Get-ChildItem -LiteralPath $Root -Force |
        Where-Object { $_.Name -like '.pending-*' })
    Assert-Contract ($parts.Count -eq 0) 'orphaned-staging-directory'
}
# The future publisher exposes a safe wrapper and keeps the fault-injectable
# core PRIVATE to the module. This test accesses module scope only, not a
# publicly callable -FaultAt parameter.
function Invoke-Core([object[]]$Pairs,[string]$Schema,[string]$Root,
                     [string]$Name,[string]$Fault) {
    & $script:publisherModule {
        param($C,$S,$R,$B,$F)
        $hook={
            param([string]$Milestone)
            if($Milestone -ceq $F) { throw 'STAGE6E_SYNTHETIC_FAULT' }
        }.GetNewClosure()
        Invoke-HoldoutV2AtomicPublishCore -CandidatePairs $C -SchemaPath $S -PrivateOutputRoot $R -BatchName $B -OnMilestone $hook
    } $Pairs $Schema $Root $Name $Fault
}
function Expect-Failure([object[]]$Pairs,[string]$Schema,[string]$Root,
                        [string]$Name,[string]$Fault,[string]$Code,[bool]$Committed) {
    $before=ConvertTo-Json -InputObject $Pairs -Depth 24 -Compress
    $caught=$false
    try {
        $unexpected=@(Invoke-Core $Pairs $Schema $Root $Name $Fault 6>&1)
    } catch {
        $caught=$true
        Assert-PrivateError ([string]$_.Exception.Message) $Code $Pairs
    }
    Assert-Contract $caught 'fault-was-accepted'
    Assert-Contract ((ConvertTo-Json -InputObject $Pairs -Depth 24 -Compress) -ceq $before) 'inputs-mutated'
    if($Committed) {
        Assert-FinalBatch $Root $Name $Pairs
    } else {
        Assert-Contract (-not (Test-Path -LiteralPath (Join-Path $Root $Name))) 'partial-final-visible'
    }
    Assert-NoPending $Root
}
$repository=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$schema=Join-Path $repository 'docs/contracts/holdout-v2-private-provenance-v2.schema.json'
$manifestFile=Join-Path $repository 'docs/holdout-evaluation-v2-manifest.json'
Assert-Contract (Test-Path -LiteralPath $schema -PathType Leaf) 'schema-not-present'
$manifest=Get-Content -LiteralPath $manifestFile -Raw | ConvertFrom-Json
Assert-Contract ([int]$manifest.schemaVersion -eq 2 -and
    [string]$manifest.approvalState -ceq 'PENDING_EXTERNAL_CAPTURE_AND_REVIEW') 'manifest-boundary'
$slots=@($manifest.samples | Where-Object { $_.sourceKind -eq 'external-pcap-reviewed' })
Assert-Contract ($slots.Count -eq 4 -and
    (@($slots | ForEach-Object { [string]$_.classification }) -join ',') -ceq
    'Benign,Benign,Malicious,Malicious') 'four-slot-classification-boundary'
$module=Join-Path $PSScriptRoot 'HoldoutV2CandidatePublisher.psm1'
Assert-Contract (Test-Path -LiteralPath $module -PathType Leaf) 'atomic-publisher-not-implemented-red'
$publisherModule=Import-Module -Name $module -Force -PassThru -ErrorAction Stop
$coreExists=& $publisherModule {
    [bool](Get-Command Invoke-HoldoutV2AtomicPublishCore -ErrorAction SilentlyContinue)
}
Assert-Contract $coreExists 'atomic-core-not-implemented-red'
$nameValidatorExists=& $publisherModule {
    [bool](Get-Command Assert-HoldoutV2BatchName -ErrorAction SilentlyContinue)
}
Assert-Contract $nameValidatorExists 'atomic-private-name-validator-not-implemented-red'

# Only a uniquely owned folder under build-verify may be removed by this test.
$privateBase=Join-Path $repository 'build-verify'
$ownedRoot=Join-Path $privateBase ('stage6e-atomicity-'+[guid]::NewGuid().ToString('N'))
Assert-Contract (-not (Test-Path -LiteralPath $ownedRoot)) 'scratch-root-collision'
try {
    [void](New-Item -ItemType Directory -Path $ownedRoot -Force -ErrorAction Stop)
    $sentinel=Join-Path $ownedRoot 'sentinel.keep'
    [IO.File]::WriteAllText($sentinel,'STAGE6E_CANARY',[Text.UTF8Encoding]::new($false))
    $sentinelHash=(Get-FileHash -LiteralPath $sentinel -Algorithm SHA256).Hash
    $pairs=New-SyntheticPairs $slots
    $control=@(Invoke-Core $pairs $schema $ownedRoot 'control-complete' '' 6>&1)
    Assert-Contract ($control.Count -eq 1 -and $control[0] -is [pscustomobject]) 'control-output-shape'
    $result=$control[0]
    Assert-Contract ([int]$result.CandidateCount -eq 4 -and
        [string]$result.ReviewState -ceq 'PENDING_EXTERNAL_CAPTURE_AND_REVIEW' -and
        -not [bool]$result.IsApproved -and [bool]$result.PublishedToPrivateStaging) 'control-claimed-approval'
    Assert-FinalBatch $ownedRoot 'control-complete' $pairs
    $baselineHashes=Get-Hashes $ownedRoot 'control-complete'
    Assert-NoPending $ownedRoot

    # Faults before directory rename: no final target and no pending orphan.
    $precommit=@(
        'after-preflight',
        'after-stage-created',
        'after-sample-2-write',
        'after-provenance-3-write',
        'before-reread',
        'after-verified-before-commit',
        'before-directory-move',
        'at-directory-move'
    )
    foreach($stage in $precommit) {
        Expect-Failure $pairs $schema $ownedRoot ('fault-'+$stage) $stage 'PUBLISH_PRECOMMIT_ABORT' $false
    }
    # Rename succeeded, response failed. Keep complete final folder, report
    # uncertain outcome; never delete or overwrite based on the error.
    Expect-Failure $pairs $schema $ownedRoot 'post-commit-uncertain' 'after-directory-move' 'PUBLISH_COMMIT_UNCERTAIN' $true

    # Existing target may not be overwritten, even when the incoming batch
    # contains the same synthetic records and provenance sidecars.
    Expect-Failure $pairs $schema $ownedRoot 'control-complete' '' 'PUBLISH_TARGET_EXISTS' $true
    $afterHashes=Get-Hashes $ownedRoot 'control-complete'
    Assert-Contract ((ConvertTo-Json $baselineHashes -Compress) -ceq
        (ConvertTo-Json $afterHashes -Compress)) 'existing-batch-overwritten'

    # Check dangerous names in a PURE, module-private lexical validator.
    # NEVER pass an unsafe path to the actual publisher: if the publisher
    # were vulnerable, a traversal test could create files outside ownedRoot.
    foreach($bad in @('../escape','nested/child','CON','...')) {
        $caught=$false
        try {
            $validated=& $publisherModule {
                param($Name)
                Assert-HoldoutV2BatchName -Name $Name
            } $bad
        } catch {
            $caught=$true
            Assert-PrivateError ([string]$_.Exception.Message) 'PUBLISH_UNSAFE_BATCH_NAME' $pairs
        }
        Assert-Contract $caught 'unsafe-name-accepted'
        Assert-NoPending $ownedRoot
    }
    $incomplete=[object[]]@($pairs[0],$pairs[1],$pairs[2])
    Expect-Failure $incomplete $schema $ownedRoot 'incomplete-batch' '' 'PUBLISH_INVALID_BATCH' $false
    # A full four-slot array containing duplicated IDs or a legacy
    # provenance version must fail before writing any individual pair.
    $duplicate=ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $pairs -Depth 24)
    $duplicate[3].Provenance.sample=$duplicate[2].Provenance.sample
    $duplicate[3].Sample.name=$duplicate[2].Sample.name
    Expect-Failure $duplicate $schema $ownedRoot 'duplicate-sample' '' 'PUBLISH_INVALID_BATCH' $false
    $wrongVersion=ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $pairs -Depth 24)
    $wrongVersion[1].Provenance.schemaVersion=1
    Expect-Failure $wrongVersion $schema $ownedRoot 'legacy-schema' '' 'PUBLISH_INVALID_BATCH' $false

    # Neither a successful commit nor any fault may create arbitrary
    # top-level files outside our known control, uncertain-commit, sentinel.
    $top=@(Get-ChildItem -LiteralPath $ownedRoot -Force)
    Assert-Contract ($top.Count -eq 3 -and
        @($top | Where-Object { $_.Name -notin @('sentinel.keep','control-complete','post-commit-uncertain') }).Count -eq 0) 'unexpected-artifacts-in-owned-root'
    Assert-Contract ((Get-FileHash -LiteralPath $sentinel -Algorithm SHA256).Hash -ceq
        $sentinelHash) 'unrelated-sentinel-modified'
    Write-Host ('Stage 6E contract: 1 pending-only control, '+
        $precommit.Count+' precommit rollbacks, 1 uncertain commit, '+
        '1 existing target, 4 pure unsafe-name cases and 3 invalid batches. No approval.')
} finally {
    if(Test-Path -LiteralPath $ownedRoot) {
        $item=Get-Item -LiteralPath $ownedRoot -Force
        Assert-Contract (-not (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) 'owned-root-reparse-point'
        Remove-Item -LiteralPath $ownedRoot -Recurse -Force -ErrorAction Stop
    }
}

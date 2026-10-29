# SPDX-License-Identifier: MIT
# Private staged publication only. It never approves or freezes source evidence.
# No packet reads, capture, network calls, test execution or external uploads.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module -Name (Join-Path $PSScriptRoot 'HoldoutV2Provenance.psm1') -ErrorAction Stop

function Fail-Publisher([string]$Code) { throw $Code }

# Private, non-writing lexical validator used by the parked fault contract.
function Assert-HoldoutV2BatchName {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Name)
    if($Name.Length -gt 64 -or
       $Name -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$' -or
       $Name -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') {
        Fail-Publisher 'PUBLISH_UNSAFE_BATCH_NAME'
    }
}

function Assert-PrivatePublicationRoot([string]$RequestedRoot) {
    $canonical=[IO.Path]::GetFullPath($RequestedRoot)
    $base=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../build-verify'))
    $separator=[IO.Path]::DirectorySeparatorChar
    if(-not $canonical.StartsWith(($base+$separator),
           [StringComparison]::OrdinalIgnoreCase) -or
       -not [IO.Directory]::Exists($canonical) -or
       -not [IO.Directory]::Exists($base)) {
        Fail-Publisher 'PUBLISH_UNTRUSTED_ROOT'
    }
    $cursor=$canonical
    while($true) {
        $item=Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if(-not $item.PSIsContainer -or
           ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail-Publisher 'PUBLISH_UNTRUSTED_ROOT'
        }
        if($cursor -ieq $base) { break }
        $parent=[IO.Directory]::GetParent($cursor)
        if($null -eq $parent) { Fail-Publisher 'PUBLISH_UNTRUSTED_ROOT' }
        $cursor=$parent.FullName
    }
    return $canonical
}

function Assert-PublisherSamplePairs([object[]]$CandidatePairs) {
    if($CandidatePairs.Count -ne 4) { Fail-Publisher 'PUBLISH_INVALID_BATCH' }
    $allowedSample=@('name','classification','records','expectedMatches',
                     'expectedNonMatches','expectedMinimumConfidence')
    $allowedRecord=@('source','destination','ipVersion','sourcePort',
                     'destinationPort','protocol','applicationProtocol',
                     'isUdp','isTcp','dnsQname','dnsQtype')
    foreach($pair in $CandidatePairs) {
        if($null -eq $pair -or
           $null -eq $pair.PSObject.Properties['Sample'] -or
           $null -eq $pair.PSObject.Properties['Provenance'] -or
           @($pair.PSObject.Properties.Name).Count -ne 2) {
            Fail-Publisher 'PUBLISH_INVALID_BATCH'
        }
        $sample=$pair.Sample
        $p=$pair.Provenance
        if($null -eq $sample -or $null -eq $p) { Fail-Publisher 'PUBLISH_INVALID_BATCH' }
        $sf=@($sample.PSObject.Properties.Name)
        if($sf.Count -ne 6 -or
           @(Compare-Object ($sf | Sort-Object) ($allowedSample | Sort-Object)).Count -ne 0) {
            Fail-Publisher 'PUBLISH_INVALID_BATCH'
        }
        if([string]$sample.name -cne [string]$p.sample -or
           [string]$sample.classification -cne [string]$p.classification -or
           $null -eq $sample.records -or $sample.records -isnot [array] -or
           @($sample.records).Count -ne [int]$p.selectedRecordCount) {
            Fail-Publisher 'PUBLISH_INVALID_BATCH'
        }
        if($sample.expectedMatches -isnot [array] -or
           $sample.expectedNonMatches -isnot [array] -or
           ($sample.expectedMinimumConfidence -isnot [double] -and
            $sample.expectedMinimumConfidence -isnot [decimal] -and
            $sample.expectedMinimumConfidence -isnot [int])) {
            Fail-Publisher 'PUBLISH_INVALID_BATCH'
        }
        $positive=[string[]]@()
        $negative=[string[]]@('R102','R118','R163')
        $floor=0.0
        if([string]$p.classification -ceq 'Malicious') {
            $positive=[string[]]@('R102')
            $negative=[string[]]@('R118','R163')
            $floor=0.75
        }
        $actualPos=@($sample.expectedMatches)
        $actualNeg=@($sample.expectedNonMatches)
        if($actualPos.Count -ne $positive.Count -or
           $actualNeg.Count -ne $negative.Count -or
           @(Compare-Object ($actualPos | Sort-Object) ($positive | Sort-Object)).Count -ne 0 -or
           @(Compare-Object ($actualNeg | Sort-Object) ($negative | Sort-Object)).Count -ne 0 -or
           [double]$sample.expectedMinimumConfidence -ne $floor) {
            Fail-Publisher 'PUBLISH_INVALID_BATCH'
        }
        foreach($record in @($sample.records)) {
            if($null -eq $record) { Fail-Publisher 'PUBLISH_INVALID_BATCH' }
            $fields=@($record.PSObject.Properties.Name)
            if($fields.Count -ne 11 -or
               @(Compare-Object ($fields | Sort-Object) ($allowedRecord | Sort-Object)).Count -ne 0 -or
               $record.isUdp -isnot [bool] -or $record.isTcp -isnot [bool] -or
               $record.isUdp -eq $record.isTcp -or
               $record.dnsQname -isnot [string] -or
               [string]$record.source -cne [string]$p.sourceAddress -or
               [string]$record.protocol -cne 'DNS' -or
               [string]$record.applicationProtocol -cne 'DNS') {
                Fail-Publisher 'PUBLISH_INVALID_BATCH'
            }
        }
    }
}

function Assert-NoReparsePrivateTree([string]$Path) {
    $stack=[Collections.Generic.Stack[string]]::new()
    $stack.Push($Path)
    while($stack.Count -gt 0) {
        $folder=$stack.Pop()
        $item=Get-Item -LiteralPath $folder -Force
        if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail-Publisher 'PUBLISH_UNTRUSTED_ROOT'
        }
        foreach($child in @(Get-ChildItem -LiteralPath $folder -Force)) {
            if(($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                Fail-Publisher 'PUBLISH_UNTRUSTED_ROOT'
            }
            if($child.PSIsContainer) { $stack.Push($child.FullName) }
        }
    }
}

# Test-only milestone callback remains module-private; public wrapper below
# cannot accept any callback or fault-injection parameter.
function Invoke-HoldoutV2AtomicPublishCore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][object[]]$CandidatePairs,
        [Parameter(Mandatory=$true)][string]$SchemaPath,
        [Parameter(Mandatory=$true)][string]$PrivateOutputRoot,
        [Parameter(Mandatory=$true)][string]$BatchName,
        [scriptblock]$OnMilestone
    )
    Assert-HoldoutV2BatchName -Name $BatchName
    try {
        $privateRoot=Assert-PrivatePublicationRoot $PrivateOutputRoot
        $provenances=@($CandidatePairs | ForEach-Object {
            if($null -eq $_ -or $null -eq $_.PSObject.Properties['Provenance']) {
                Fail-Publisher 'PUBLISH_INVALID_BATCH'
            }
            $_.Provenance
        })
        $validated=Confirm-HoldoutV2ProvenanceBatch -Candidates $provenances -SchemaPath $SchemaPath
        if(-not $validated.SchemaValid -or $validated.IsApproved -or
           $validated.ApprovalState -cne 'PENDING_EXTERNAL_CAPTURE_AND_REVIEW') {
            Fail-Publisher 'PUBLISH_INVALID_BATCH'
        }
        Assert-PublisherSamplePairs $CandidatePairs
    } catch {
        # Detailed PROV_* codes are preserved by the read-only validator, but
        # never contain source values in the public publisher response.
        Fail-Publisher 'PUBLISH_INVALID_BATCH'
    }

    $target=Join-Path $privateRoot $BatchName
    if(Test-Path -LiteralPath $target) { Fail-Publisher 'PUBLISH_TARGET_EXISTS' }
    $stage=Join-Path $privateRoot ('.pending-'+[guid]::NewGuid().ToString('N'))
    if(Test-Path -LiteralPath $stage) { Fail-Publisher 'PUBLISH_PRECOMMIT_ABORT' }
    $stageCreated=$false
    $committed=$false
    try {
        if($null -ne $OnMilestone) { & $OnMilestone 'after-preflight' | Out-Null }
        [void][IO.Directory]::CreateDirectory($stage)
        $stageCreated=$true
        if($null -ne $OnMilestone) { & $OnMilestone 'after-stage-created' | Out-Null }
        $encoding=[Text.UTF8Encoding]::new($false)
        $written=0
        $expected=[Collections.Generic.List[object]]::new()
        foreach($pair in $CandidatePairs) {
            $id=[string]$pair.Provenance.sample
            $samplePath=Join-Path $stage ($id+'.json')
            $sidecarPath=Join-Path $stage ($id+'.provenance.json')
            $sampleJson=ConvertTo-Json -InputObject $pair.Sample -Depth 24
            $sidecarJson=ConvertTo-Json -InputObject $pair.Provenance -Depth 24
            $bytes=$encoding.GetBytes($sampleJson)
            $stream=[IO.File]::Open($samplePath,[IO.FileMode]::CreateNew,
                [IO.FileAccess]::Write,[IO.FileShare]::None)
            try { $stream.Write($bytes,0,$bytes.Length);$stream.Flush($true) }
            finally { $stream.Dispose() }
            $written++
            if($written -eq 2 -and $null -ne $OnMilestone) {
                & $OnMilestone 'after-sample-2-write' | Out-Null
            }
            $bytes=$encoding.GetBytes($sidecarJson)
            $stream=[IO.File]::Open($sidecarPath,[IO.FileMode]::CreateNew,
                [IO.FileAccess]::Write,[IO.FileShare]::None)
            try { $stream.Write($bytes,0,$bytes.Length);$stream.Flush($true) }
            finally { $stream.Dispose() }
            if($written -eq 3 -and $null -ne $OnMilestone) {
                & $OnMilestone 'after-provenance-3-write' | Out-Null
            }
            $expected.Add([pscustomobject]@{
                SamplePath=$samplePath;SidecarPath=$sidecarPath
                SampleJson=$sampleJson;SidecarJson=$sidecarJson
            })
        }
        if($null -ne $OnMilestone) { & $OnMilestone 'before-reread' | Out-Null }
        if(@(Get-ChildItem -LiteralPath $stage -File -Force).Count -ne 8 -or
           $expected.Count -ne 4) { throw 'staged file count invalid' }
        foreach($p in $expected) {
            $sampleContents=[IO.File]::ReadAllText($p.SamplePath,$encoding)
            $sidecarContents=[IO.File]::ReadAllText($p.SidecarPath,$encoding)
            if($sampleContents -cne $p.SampleJson -or
               $sidecarContents -cne $p.SidecarJson) { throw 'staged bytes differ' }
            $a=ConvertFrom-Json -InputObject $sampleContents
            $b=ConvertFrom-Json -InputObject $sidecarContents
            if([string]$a.name -cne [string]$b.sample -or
               [string]$a.classification -cne [string]$b.classification -or
               [int]$b.schemaVersion -ne 2 -or
               [string]$b.reviewState -cne 'PENDING_EXTERNAL_CAPTURE_AND_REVIEW') {
                throw 'staged identity mismatch'
            }
        }
        if($null -ne $OnMilestone) { & $OnMilestone 'after-verified-before-commit' | Out-Null }
        if($null -ne $OnMilestone) { & $OnMilestone 'before-directory-move' | Out-Null }
        if($null -ne $OnMilestone) { & $OnMilestone 'at-directory-move' | Out-Null }
        # Same-volume sibling move. Directory.Move refuses to replace an
        # existing target: no copy-into-visible-final or overwrite flag.
        [IO.Directory]::Move($stage,$target)
        $committed=$true
        if($null -ne $OnMilestone) { & $OnMilestone 'after-directory-move' | Out-Null }
        return [pscustomobject][ordered]@{
            CandidateCount=4
            ReviewState='PENDING_EXTERNAL_CAPTURE_AND_REVIEW'
            IsApproved=$false
            PublishedToPrivateStaging=$true
        }
    } catch {
        if($committed) { Fail-Publisher 'PUBLISH_COMMIT_UNCERTAIN' }
        if(Test-Path -LiteralPath $target) {
            Fail-Publisher 'PUBLISH_TARGET_EXISTS'
        }
        Fail-Publisher 'PUBLISH_PRECOMMIT_ABORT'
    } finally {
        if($stageCreated -and -not $committed -and
           (Test-Path -LiteralPath $stage -PathType Container)) {
            # Only this uniquely owned uncommitted stage can be removed.
            # A nested reparse point blocks recursive deletion.
            Assert-NoReparsePrivateTree $stage
            [IO.Directory]::Delete($stage,$true)
        }
    }
}

# Module-private, path-free recovery classification. It is a decision aid,
# not a filesystem scanner. This function MUST NOT delete, move, approve or
# publish anything, and must never treat an inventory claim as verified truth.
function Get-HoldoutV2PrivateRecoveryPlan {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][object[]]$Entries)
    if($Entries.Count -lt 1 -or $Entries.Count -gt 500) {
        Fail-Publisher 'RECOVERY_INPUT_INVALID'
    }
    $fields=@('Key','Kind','OwnedByInvocation','HasOwnershipMarker',
              'IsReparsePoint','WriterActive','AgeMinutes','PairCount',
              'HashesVerified','ProvenanceSchemaVersion','CommitOutcome',
              'DestinationExists','NameCollision')
    $decisions=[Collections.Generic.List[object]]::new()
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($entry in $Entries) {
        if($null -eq $entry) { Fail-Publisher 'RECOVERY_INPUT_INVALID' }
        $keys=@($entry.PSObject.Properties.Name)
        if($keys.Count -ne $fields.Count -or
           @(Compare-Object ($keys | Sort-Object) ($fields | Sort-Object)).Count -ne 0) {
            Fail-Publisher 'RECOVERY_INPUT_INVALID'
        }
        if($entry.Key -isnot [string] -or
           $entry.Key -cnotmatch '^[A-Za-z][A-Za-z0-9_-]{1,40}
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][object[]]$CandidatePairs,
        [Parameter(Mandatory=$true)][string]$SchemaPath,
        [Parameter(Mandatory=$true)][string]$PrivateOutputRoot,
        [Parameter(Mandatory=$true)][string]$BatchName
    )
    Invoke-HoldoutV2AtomicPublishCore -CandidatePairs $CandidatePairs -SchemaPath $SchemaPath -PrivateOutputRoot $PrivateOutputRoot -BatchName $BatchName
}
Export-ModuleMember -Function Publish-HoldoutV2CandidateBatch
 -or
           -not $seen.Add([string]$entry.Key) -or
           $entry.Kind -isnot [string] -or
           $entry.CommitOutcome -isnot [string] -or
           $entry.OwnedByInvocation -isnot [bool] -or
           $entry.HasOwnershipMarker -isnot [bool] -or
           $entry.IsReparsePoint -isnot [bool] -or
           $entry.WriterActive -isnot [bool] -or
           $entry.HashesVerified -isnot [bool] -or
           $entry.DestinationExists -isnot [bool] -or
           $entry.NameCollision -isnot [bool] -or
           $entry.AgeMinutes -isnot [int] -or
           $entry.PairCount -isnot [int] -or
           $entry.ProvenanceSchemaVersion -isnot [int] -or
           $entry.AgeMinutes -lt 0 -or
           $entry.PairCount -lt 0 -or $entry.PairCount -gt 4) {
            Fail-Publisher 'RECOVERY_INPUT_INVALID'
        }
        $disposition='BLOCK_REVIEW'
        $reason='RECOVERY_UNKNOWN_KIND'
        if($entry.IsReparsePoint) {
            $reason='RECOVERY_REPARSE_POINT'
        } elseif(-not $entry.OwnedByInvocation) {
            $disposition='LEAVE_UNTOUCHED'
            $reason='RECOVERY_UNOWNED_ENTRY'
        } elseif(-not $entry.HasOwnershipMarker) {
            $reason='RECOVERY_OWNER_UNVERIFIED'
        } elseif($entry.WriterActive) {
            $disposition='LEAVE_UNTOUCHED'
            $reason='RECOVERY_ACTIVE_WRITER'
        } elseif($entry.NameCollision) {
            $reason='RECOVERY_TARGET_COLLISION'
        } elseif($entry.Kind -notin @('Pending','Committed')) {
            $reason='RECOVERY_UNKNOWN_KIND'
        } elseif($entry.ProvenanceSchemaVersion -ne 2) {
            $disposition='QUARANTINE_REVIEW'
            $reason='RECOVERY_SCHEMA_UNSUPPORTED'
        } elseif($entry.CommitOutcome -ceq 'Unknown' -and
                 $entry.Kind -ceq 'Pending' -and
                 -not $entry.DestinationExists) {
            $reason='RECOVERY_COMMIT_UNCERTAIN_FINAL_ABSENT'
        } elseif($entry.Kind -ceq 'Committed') {
            if(-not $entry.DestinationExists -or $entry.PairCount -ne 4) {
                $disposition='QUARANTINE_REVIEW'
                $reason='RECOVERY_PARTIAL_FINAL'
            } elseif(-not $entry.HashesVerified) {
                $disposition='QUARANTINE_REVIEW'
                $reason='RECOVERY_UNVERIFIED_FINAL'
            } elseif($entry.CommitOutcome -ceq 'Unknown') {
                $disposition='RECONCILE_COMMITTED'
                $reason='RECOVERY_COMMIT_UNCERTAIN_FINAL_PRESENT'
            } elseif($entry.CommitOutcome -ceq 'Succeeded') {
                $disposition='RETAIN_COMMITTED'
                $reason='RECOVERY_COMMITTED_PENDING_REVIEW'
            }
        } elseif($entry.Kind -ceq 'Pending') {
            if($entry.AgeMinutes -lt 60) {
                $disposition='REVIEW_PENDING'
                $reason='RECOVERY_UNCOMMITTED_STAGE'
            } elseif($entry.PairCount -eq 4 -and $entry.HashesVerified) {
                $disposition='QUARANTINE_REVIEW'
                $reason='RECOVERY_ORPHAN_COMPLETE'
            } else {
                $disposition='QUARANTINE_REVIEW'
                $reason='RECOVERY_ORPHAN_PARTIAL'
            }
        }
        $decisions.Add([pscustomobject][ordered]@{
            Key=[string]$entry.Key
            Disposition=$disposition
            Reason=$reason
        })
    }
    return [pscustomobject][ordered]@{
        EntryCount=$Entries.Count
        RequiresManualReview=$true
        AutoDeleteAllowed=$false
        Decisions=@($decisions.ToArray())
    }
}

function Publish-HoldoutV2CandidateBatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][object[]]$CandidatePairs,
        [Parameter(Mandatory=$true)][string]$SchemaPath,
        [Parameter(Mandatory=$true)][string]$PrivateOutputRoot,
        [Parameter(Mandatory=$true)][string]$BatchName
    )
    Invoke-HoldoutV2AtomicPublishCore -CandidatePairs $CandidatePairs -SchemaPath $SchemaPath -PrivateOutputRoot $PrivateOutputRoot -BatchName $BatchName
}
Export-ModuleMember -Function Publish-HoldoutV2CandidateBatch

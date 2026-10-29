# SPDX-License-Identifier: MIT
# Stage 6F (PARKED): pure, in-memory orphan/commit recovery decision contract.
# Do NOT run until explicit owner permission: "now it's test time".
# No paths, PCAPs, file writes, networking, deletion or process launch.
[CmdletBinding()]
param([switch]$AuthorizedTestTime)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $AuthorizedTestTime) {
    throw 'PARKED: explicit owner test-time authorization required.'
}

function Assert-Contract([bool]$Condition,[string]$Code) {
    if (-not $Condition) { throw ('STAGE6F_RECOVERY_CONTRACT: '+$Code) }
}

# Artificial inventory metadata is intentionally path-free. The planner is
# advisory only; it must never delete, approve, freeze, rename or publish.
function New-InventoryEntry([string]$Key) {
    return [pscustomobject]@{
        Key = $Key
        Kind = 'Pending'
        OwnedByInvocation = $true
        HasOwnershipMarker = $true
        IsReparsePoint = $false
        WriterActive = $false
        AgeMinutes = 90
        PairCount = 0
        HashesVerified = $false
        ProvenanceSchemaVersion = 2
        CommitOutcome = 'NotStarted'
        DestinationExists = $false
        NameCollision = $false
    }
}

function Clone-Entry([object]$Value) {
    return ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $Value -Depth 12)
}

function Assert-Result([object]$Entry,[string]$ExpectedDisposition,
                       [string]$ExpectedReason) {
    $snapshot = ConvertTo-Json -InputObject $Entry -Compress -Depth 12
    $results = @(& $script:publisher { param($items) Get-HoldoutV2PrivateRecoveryPlan -Entries $items } @($Entry) 6>&1)
    Assert-Contract ($results.Count -eq 1 -and $results[0] -is [pscustomobject]) 'one-metadata-result-required'
    $response = $results[0]
    $allowed = @('EntryCount','RequiresManualReview','AutoDeleteAllowed','Decisions')
    $actual = @($response.PSObject.Properties.Name)
    Assert-Contract ($actual.Count -eq $allowed.Count -and
        @(Compare-Object ($allowed | Sort-Object) ($actual | Sort-Object)).Count -eq 0) 'unexpected-plan-fields'
    Assert-Contract ([int]$response.EntryCount -eq 1 -and
        [bool]$response.RequiresManualReview -and
        -not [bool]$response.AutoDeleteAllowed) 'unsafe-recovery-policy'
    $decision = @($response.Decisions)
    Assert-Contract ($decision.Count -eq 1) 'one-decision-per-entry'
    $decisionFields = @($decision[0].PSObject.Properties.Name)
    $validFields = @('Key','Disposition','Reason')
    Assert-Contract ($decisionFields.Count -eq $validFields.Count -and
        @(Compare-Object ($validFields | Sort-Object) ($decisionFields | Sort-Object)).Count -eq 0) 'decision-disclosed-private-data'
    Assert-Contract ([string]$decision[0].Key -ceq [string]$Entry.Key) 'decision-identity-mismatch'
    Assert-Contract ([string]$decision[0].Disposition -ceq $ExpectedDisposition -and
        [string]$decision[0].Reason -ceq $ExpectedReason) 'wrong-recovery-classification'
    Assert-Contract ((ConvertTo-Json -InputObject $Entry -Compress -Depth 12) -ceq
        $snapshot) 'planner-mutated-inventory'
    $public = ConvertTo-Json -InputObject $response -Depth 8 -Compress
    Assert-Contract (-not ($public -match '(?i)\b(delete|remove-item|approved|frozen|promoted)\b')) 'unsafe-plan-output'
    Write-Host ('STAGE6F RECOVERY CASE '+$Entry.Key+': expected advisory disposition prepared.')
}

$modulePath = Join-Path $PSScriptRoot 'HoldoutV2CandidatePublisher.psm1'
Assert-Contract (Test-Path -LiteralPath $modulePath -PathType Leaf) 'recovery-module-not-implemented-red'
$publisher = Import-Module -Name $modulePath -Force -PassThru -ErrorAction Stop
$hasPlanner = & $publisher {
    [bool](Get-Command Get-HoldoutV2PrivateRecoveryPlan -ErrorAction SilentlyContinue)
}
Assert-Contract $hasPlanner 'recovery-planner-not-implemented-red'

# Each case is derived afresh from the same path-free reference, so a prior
# case cannot alter the next. Predicted outcomes are requirements, not results.
$cases = @(
    @{ Id='R01'; Label='active-owner'; Disposition='LEAVE_UNTOUCHED'; Reason='RECOVERY_ACTIVE_WRITER'; Change={param($x) $x.WriterActive=$true} },
    @{ Id='R02'; Label='recent-pending'; Disposition='REVIEW_PENDING'; Reason='RECOVERY_UNCOMMITTED_STAGE'; Change={param($x) $x.AgeMinutes=1} },
    @{ Id='R03'; Label='old-pending-complete'; Disposition='QUARANTINE_REVIEW'; Reason='RECOVERY_ORPHAN_COMPLETE'; Change={param($x) $x.PairCount=4;$x.HashesVerified=$true;$x.AgeMinutes=10080} },
    @{ Id='R04'; Label='old-pending-partial'; Disposition='QUARANTINE_REVIEW'; Reason='RECOVERY_ORPHAN_PARTIAL'; Change={param($x) $x.PairCount=2;$x.AgeMinutes=10080} },
    @{ Id='R05'; Label='foreign-owned'; Disposition='LEAVE_UNTOUCHED'; Reason='RECOVERY_UNOWNED_ENTRY'; Change={param($x) $x.OwnedByInvocation=$false} },
    @{ Id='R06'; Label='no-ownership-marker'; Disposition='BLOCK_REVIEW'; Reason='RECOVERY_OWNER_UNVERIFIED'; Change={param($x) $x.HasOwnershipMarker=$false} },
    @{ Id='R07'; Label='reparse-point'; Disposition='BLOCK_REVIEW'; Reason='RECOVERY_REPARSE_POINT'; Change={param($x) $x.IsReparsePoint=$true} },
    @{ Id='R08'; Label='complete-committed'; Disposition='RETAIN_COMMITTED'; Reason='RECOVERY_COMMITTED_PENDING_REVIEW'; Change={param($x) $x.Kind='Committed';$x.PairCount=4;$x.HashesVerified=$true;$x.DestinationExists=$true;$x.CommitOutcome='Succeeded'} },
    @{ Id='R09'; Label='partial-committed'; Disposition='QUARANTINE_REVIEW'; Reason='RECOVERY_PARTIAL_FINAL'; Change={param($x) $x.Kind='Committed';$x.PairCount=2;$x.DestinationExists=$true;$x.CommitOutcome='Succeeded'} },
    @{ Id='R10'; Label='unverified-committed'; Disposition='QUARANTINE_REVIEW'; Reason='RECOVERY_UNVERIFIED_FINAL'; Change={param($x) $x.Kind='Committed';$x.PairCount=4;$x.DestinationExists=$true;$x.CommitOutcome='Succeeded'} },
    @{ Id='R11'; Label='post-move-response-lost'; Disposition='RECONCILE_COMMITTED'; Reason='RECOVERY_COMMIT_UNCERTAIN_FINAL_PRESENT'; Change={param($x) $x.Kind='Committed';$x.PairCount=4;$x.HashesVerified=$true;$x.DestinationExists=$true;$x.CommitOutcome='Unknown'} },
    @{ Id='R12'; Label='commit-uncertain-final-absent'; Disposition='BLOCK_REVIEW'; Reason='RECOVERY_COMMIT_UNCERTAIN_FINAL_ABSENT'; Change={param($x) $x.CommitOutcome='Unknown'} },
    @{ Id='R13'; Label='schema-downgrade'; Disposition='QUARANTINE_REVIEW'; Reason='RECOVERY_SCHEMA_UNSUPPORTED'; Change={param($x) $x.ProvenanceSchemaVersion=1;$x.PairCount=4;$x.HashesVerified=$true} },
    @{ Id='R14'; Label='destination-collision'; Disposition='BLOCK_REVIEW'; Reason='RECOVERY_TARGET_COLLISION'; Change={param($x) $x.NameCollision=$true} },
    @{ Id='R15'; Label='unexpected-state'; Disposition='BLOCK_REVIEW'; Reason='RECOVERY_UNKNOWN_KIND'; Change={param($x) $x.Kind='Unknown' } }
)

foreach($case in $cases) {
    $entry = New-InventoryEntry $case.Id
    & $case.Change $entry
    Assert-Result $entry ([string]$case.Disposition) ([string]$case.Reason)
}
Write-Host ('Stage 6F recovery contract contains '+$cases.Count+' in-memory, review-only scenarios. No filesystem action authorized.')

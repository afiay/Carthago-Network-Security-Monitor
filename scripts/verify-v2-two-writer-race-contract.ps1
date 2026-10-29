# SPDX-License-Identifier: MIT
# Stage 6F (PARKED): two-process contention for a private V2 batch name.
# NO execution unless the owner explicitly says "now it's test time".
# Synthetic records, documentation IPs, fixed safe names, no capture/TShark.
# Requires a future publisher module and an explicitly trusted local test root.
[CmdletBinding()]
param([switch]$AuthorizedTestTime)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $AuthorizedTestTime) {
    throw 'PARKED: explicit owner test-time authorization required.'
}

function Assert-Contract([bool]$Condition,[string]$Code) {
    if (-not $Condition) { throw ('STAGE6F_RACE_CONTRACT: '+$Code) }
}

function New-PrivateSyntheticPairs([object[]]$Slots) {
    $result=[Collections.Generic.List[object]]::new()
    for($i=0;$i -lt $Slots.Count;$i++) {
        $item=$Slots[$i]
        $name=[IO.Path]::GetFileNameWithoutExtension([string]$item.file)
        $malicious=[string]$item.classification -ceq 'Malicious'
        $matches=[string[]]@()
        $nonMatches=[string[]]@('R102','R118','R163')
        if($malicious) {
            $matches=[string[]]@('R102')
            $nonMatches=[string[]]@('R118','R163')
        }
        $root=if($malicious){'exfil.example'}else{'normal.example'}
        $ip='192.0.2.'+(60+$i)
        $records=@()
        for($j=0;$j -lt 3;$j++) {
            $records += [pscustomobject]@{
                source=$ip;destination='198.51.100.53';ipVersion=4
                sourcePort=(53100+$i);destinationPort=53
                protocol='DNS';applicationProtocol='DNS';isUdp=$true;isTcp=$false
                dnsQname=('synthetic'+$i+$j+'.'+$root);dnsQtype='TXT'
            }
        }
        $sample=[pscustomobject]@{
            name=$name;classification=[string]$item.classification
            records=$records;expectedMatches=$matches
            expectedNonMatches=$nonMatches
            expectedMinimumConfidence=$(if($malicious){0.75}else{0.0})
        }
        $provenance=[pscustomobject]@{
            schemaVersion=2
            sample=$name
            classification=[string]$item.classification
            sourceKind='external-pcap-reviewed'
            sourceUri='https://example.org/synthetic-source'
            sourceLicense='CC0-1.0'
            sourceLicenseEvidenceUri='https://example.org/synthetic-license'
            independentLabelBasis='Synthetic-only source; no ground truth or approval.'
            analystReviewedLabel=$false
            capturedTransportEvidence=$false
            privacyReviewRequired=$true
            captureFileName=('synthetic-'+$i+'.pcap')
            captureSha256=(('{0:x2}' -f (55+$i))*32)
            frameNumbers=[int[]]@(1,2,3)
            questionIndices=[int[]]@(0,0,0)
            selectedRecordCount=3
            sourceAddress=$ip
            queryRoot=$root
            originatingClientLabel=('synthetic-client-'+$i)
            collectionSessionId=('synthetic-session-'+$i)
            collectionVantage='client'
            independentClientEvidenceUri='https://example.org/independence-still-pending'
            dnsWireNameEncoding='labels-base64-v1'
            extractor='tshark'
            extractorVersion='Synthetic-only'
            maximumPacketsToScan=1000
            selectionMethod='selected-source-frame-question-tuples-v2'
            transformations='None: original DNS label octets preserved; ASCII-only identity comparison'
            preparedAtUtc='2026-10-29T12:00:00Z'
            reviewState='PENDING_EXTERNAL_CAPTURE_AND_REVIEW'
        }
        $result.Add([pscustomobject]@{Sample=$sample;Provenance=$provenance})
    }
    return ,$result.ToArray()
}

function Assert-CompletePendingBatch([string]$Root,[string]$Name,[object[]]$Pairs) {
    $target=Join-Path $Root $Name
    Assert-Contract (Test-Path -LiteralPath $target -PathType Container) 'winner-final-missing'
    $files=@(Get-ChildItem -LiteralPath $target -File -Force)
    Assert-Contract ($files.Count -eq 8) 'race-produced-incomplete-final'
    foreach($pair in $Pairs) {
        $id=[string]$pair.Provenance.sample
        $samplePath=Join-Path $target ($id+'.json')
        $provenancePath=Join-Path $target ($id+'.provenance.json')
        Assert-Contract ((Test-Path -LiteralPath $samplePath -PathType Leaf) -and
            (Test-Path -LiteralPath $provenancePath -PathType Leaf)) 'race-lost-file-pair'
        $sample=Get-Content -LiteralPath $samplePath -Raw | ConvertFrom-Json
        $p=Get-Content -LiteralPath $provenancePath -Raw | ConvertFrom-Json
        Assert-Contract ([string]$sample.name -ceq $id -and
            [string]$p.sample -ceq $id -and
            [string]$sample.classification -ceq [string]$p.classification) 'race-mismatched-pair'
        Assert-Contract ([int]$p.schemaVersion -eq 2 -and
            [string]$p.reviewState -ceq 'PENDING_EXTERNAL_CAPTURE_AND_REVIEW') 'race-auto-approved-candidate'
        # Check content, not just a successful rename or file count.
        Assert-Contract ((ConvertTo-Json -InputObject $sample -Depth 24 -Compress) -ceq
            (ConvertTo-Json -InputObject $pair.Sample -Depth 24 -Compress)) 'race-changed-sample'
        Assert-Contract ((ConvertTo-Json -InputObject $p -Depth 24 -Compress) -ceq
            (ConvertTo-Json -InputObject $pair.Provenance -Depth 24 -Compress)) 'race-changed-provenance'
    }
}

function Assert-NoReparseInOwnedTree([string]$Root) {
    # Inspect directories one level at a time and refuse to enter a reparse
    # point. Never recursively follow symlinks before a cleanup decision.
    $stack=[Collections.Generic.Stack[string]]::new()
    $stack.Push($Root)
    while($stack.Count -gt 0) {
        $current=$stack.Pop()
        $folder=Get-Item -LiteralPath $current -Force
        Assert-Contract (-not (($folder.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) 'cleanup-root-or-nested-reparse-point'
        foreach($item in @(Get-ChildItem -LiteralPath $current -Force -ErrorAction Stop)) {
            Assert-Contract (-not (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) 'cleanup-nested-reparse-point'
            if($item.PSIsContainer) { $stack.Push($item.FullName) }
        }
    }
}

function Invoke-ContentionRound([string]$OwnedRoot,[string]$Name,
                                [object[]]$Pairs,[string]$Schema,
                                [string]$PublisherPath) {
    # Start-Job launches separate Windows PowerShell job processes. Workers
    # import the same module and wait behind a local, private file barrier.
    # Only sanitized outcome codes and numeric PIDs are returned to the parent.
    $signal=Join-Path $OwnedRoot ($Name+'.go')
    $jobs=@()
    try {
        for($i=0;$i -lt 2;$i++) {
            $ready=Join-Path $OwnedRoot ($Name+'.ready'+$i)
            $job=Start-Job -ScriptBlock {
                param($Module,$CandidatePairs,$SchemaPath,$OutputRoot,$Batch,$Ready,$Go)
                $ErrorActionPreference='Stop'
                $WarningPreference='SilentlyContinue'
                $InformationPreference='SilentlyContinue'
                $VerbosePreference='SilentlyContinue'
                # Synthetic fixture only; never emit private payload or errors.
                try {
                    Import-Module -Name $Module -Force -ErrorAction Stop
                    $readyFile=[IO.File]::Open($Ready,[IO.FileMode]::CreateNew,
                        [IO.FileAccess]::Write,[IO.FileShare]::None)
                    $readyFile.Close()
                    $timer=[Diagnostics.Stopwatch]::StartNew()
                    while(-not [IO.File]::Exists($Go)) {
                        if($timer.Elapsed.TotalSeconds -ge 30) {
                            return [pscustomobject]@{Code='BARRIER_TIMEOUT';ProcessId=$PID}
                        }
                        Start-Sleep -Milliseconds 20
                    }
                    $items=@(Publish-HoldoutV2CandidateBatch -CandidatePairs $CandidatePairs -SchemaPath $SchemaPath -PrivateOutputRoot $OutputRoot -BatchName $Batch 6>&1)
                    if($items.Count -ne 1 -or
                       [int]$items[0].CandidateCount -ne 4 -or
                       [bool]$items[0].IsApproved -or
                       [string]$items[0].ReviewState -cne 'PENDING_EXTERNAL_CAPTURE_AND_REVIEW') {
                        return [pscustomobject]@{Code='BAD_SUCCESS_SHAPE';ProcessId=$PID}
                    }
                    return [pscustomobject]@{Code='WIN';ProcessId=$PID}
                } catch {
                    $message=[string]$_.Exception.Message
                    if($message.Contains('PUBLISH_TARGET_EXISTS')) {
                        return [pscustomobject]@{Code='TARGET_EXISTS';ProcessId=$PID}
                    }
                    return [pscustomobject]@{Code='UNEXPECTED_ERROR';ProcessId=$PID}
                }
            } -ArgumentList @($PublisherPath, (,$Pairs), $Schema, $OwnedRoot, $Name, $ready, $signal)
            $jobs+=,$job
        }
        # A fixed upper bound prevents waiting forever if a worker fails.
        $watch=[Diagnostics.Stopwatch]::StartNew()
        $allReady=$false
        while($watch.Elapsed.TotalSeconds -lt 35) {
            $allReady=(Test-Path -LiteralPath (Join-Path $OwnedRoot ($Name+'.ready0'))) -and
                      (Test-Path -LiteralPath (Join-Path $OwnedRoot ($Name+'.ready1')))
            if($allReady) { break }
            if(@($jobs | Where-Object { $_.State -in @('Failed','Stopped') }).Count -gt 0) { break }
            Start-Sleep -Milliseconds 25
        }
        Assert-Contract $allReady 'workers-did-not-reach-barrier'
        # This file is local IPC only. No network source is contacted.
        [IO.File]::WriteAllText($signal,'GO',[Text.Encoding]::ASCII)
        $done=@(Wait-Job -Job $jobs -Timeout 60)
        Assert-Contract ($done.Count -eq 2) 'two-writers-did-not-terminate'
        $outcomes=@(Receive-Job -Job $jobs -ErrorAction Stop)
        Assert-Contract ($outcomes.Count -eq 2) 'two-outcomes-required'
        $codes=@($outcomes | ForEach-Object { [string]$_.Code })
        Assert-Contract (@($codes | Where-Object { $_ -ceq 'WIN' }).Count -eq 1 -and
                         @($codes | Where-Object { $_ -ceq 'TARGET_EXISTS' }).Count -eq 1) 'race-did-not-have-exactly-one-winner'
        $ids=@($outcomes | ForEach-Object { [int]$_.ProcessId } | Sort-Object -Unique)
        Assert-Contract ($ids.Count -eq 2) 'workers-not-independent-processes'
        Assert-CompletePendingBatch $OwnedRoot $Name $Pairs
        $stages=@(Get-ChildItem -LiteralPath $OwnedRoot -Force |
            Where-Object { $_.Name -like '.pending-*' })
        Assert-Contract ($stages.Count -eq 0) 'losing-writer-left-pending-stage'
        Write-Host ('STAGE6F RACE '+$Name+': one private writer won; one received target-exists; no approval.')
    } finally {
        foreach($job in $jobs) {
            if($job.State -in @('Running','NotStarted')) {
                Stop-Job -Job $job -ErrorAction SilentlyContinue
            }
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
        foreach($suffix in @('.go','.ready0','.ready1')) {
            $file=Join-Path $OwnedRoot ($Name+$suffix)
            if(Test-Path -LiteralPath $file -PathType Leaf) {
                Remove-Item -LiteralPath $file -Force
            }
        }
    }
}

$repository=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$modulePath=Join-Path $PSScriptRoot 'HoldoutV2CandidatePublisher.psm1'
Assert-Contract (Test-Path -LiteralPath $modulePath -PathType Leaf) 'race-publisher-not-implemented-red'
Import-Module -Name $modulePath -Force -ErrorAction Stop
Assert-Contract ($null -ne (Get-Command Publish-HoldoutV2CandidateBatch -ErrorAction SilentlyContinue)) 'race-public-wrapper-not-implemented-red'
$schema=Join-Path $repository 'docs/contracts/holdout-v2-private-provenance-v2.schema.json'
$manifest=Get-Content -LiteralPath (Join-Path $repository 'docs/holdout-evaluation-v2-manifest.json') -Raw | ConvertFrom-Json
Assert-Contract ([int]$manifest.schemaVersion -eq 2 -and
    [string]$manifest.approvalState -ceq 'PENDING_EXTERNAL_CAPTURE_AND_REVIEW') 'manifest-freeze-boundary'
$slots=@($manifest.samples | Where-Object { $_.sourceKind -eq 'external-pcap-reviewed' })
Assert-Contract ($slots.Count -eq 4 -and
    (@($slots | ForEach-Object { [string]$_.classification }) -join ',') -ceq
     'Benign,Benign,Malicious,Malicious') 'manifest-four-slot-boundary'
Assert-Contract (Test-Path -LiteralPath $schema -PathType Leaf) 'provenance-schema-missing'
$pairs=New-PrivateSyntheticPairs $slots
# Distinct, newly owned local scratch: no production data or existing fixture
# directory is ever targeted. The process race tests only safe generated names.
$privateRoot=Join-Path $repository 'build-verify'
$owned=Join-Path $privateRoot ('stage6f-race-'+[guid]::NewGuid().ToString('N'))
Assert-Contract (-not (Test-Path -LiteralPath $owned)) 'test-scratch-collision'
try {
    [void](New-Item -Path $owned -ItemType Directory -Force -ErrorAction Stop)
    $marker=Join-Path $owned 'sentinel.keep'
    [IO.File]::WriteAllText($marker,'STAGE6F_CANARY',[Text.Encoding]::ASCII)
    $markerHash=(Get-FileHash -LiteralPath $marker -Algorithm SHA256).Hash
    foreach($round in @('race-01','race-02','race-03')) {
        Invoke-ContentionRound $owned $round $pairs $schema $modulePath
    }
    Assert-Contract ((Get-FileHash -LiteralPath $marker -Algorithm SHA256).Hash -ceq
        $markerHash) 'unrelated-sentinel-modified'
    $top=@(Get-ChildItem -LiteralPath $owned -Force | Sort-Object Name)
    Assert-Contract ($top.Count -eq 4 -and
        @($top | Where-Object { $_.Name -notin @('sentinel.keep','race-01','race-02','race-03') }).Count -eq 0) 'unexpected-test-root-entry'
    Write-Host 'Stage 6F race contract: three two-process contention rounds prepared; results do not certify crash durability or source review.'
} finally {
    if(Test-Path -LiteralPath $owned) {
        Assert-NoReparseInOwnedTree $owned
        Remove-Item -LiteralPath $owned -Recurse -Force -ErrorAction Stop
    }
}

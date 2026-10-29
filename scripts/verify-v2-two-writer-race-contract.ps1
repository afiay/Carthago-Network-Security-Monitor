# SPDX-License-Identifier: MIT
# Stage 6F (PARKED): two-process contention for a private V2 batch name.
# NO execution unless the owner explicitly says "now it's test time".
# Synthetic records, documentation IPs, fixed safe names, no capture/TShark.
# Requires a future publisher module and an explicitly trusted local test root.
[CmdletBinding()]
param(
    [switch]$AuthorizedTestTime,
    [switch]$IncludeReaderVisibility,
    [ValidateRange(3,12)][int]$ReaderStressRounds=6,
    [switch]$OnlyReaderNegativeControl
)

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

# Shared test-only observer. Both the 2-writer/1-reader race and the
# deterministic Stage 6H negative controls run this *same scriptblock*.
# It has no publisher access and reads only the supplied safe final folder.
$script:PrivateBatchReaderJob = {
                param($Target,$Ready,$Go,$Stop,$NamesJson,$AbsenceProof,$FailureProof)
                $ErrorActionPreference='Stop'
                $WarningPreference='SilentlyContinue'
                $InformationPreference='SilentlyContinue'
                $VerbosePreference='SilentlyContinue'
                $counts=@{Polls=0;Absent=0;Complete=0;Partial=0;IoErrors=0}
                try {
                    $Names=[string[]]@(ConvertFrom-Json -InputObject $NamesJson)
                    if($Names.Count -ne 4) {
                        return [pscustomobject]@{Code='READER_NAMES_INVALID';ProcessId=$PID;
                            Polls=0;Absent=0;Complete=0;Partial=0;IoErrors=0}
                    }
                    # Parent will not release competing writers until it
                    # observes this reader-ready marker.
                    if([IO.Directory]::Exists($Target)) {
                        return [pscustomobject]@{Code='EARLY_VISIBLE';ProcessId=$PID;
                            Polls=0;Absent=0;Complete=0;Partial=1;IoErrors=0}
                    }
                    [IO.File]::WriteAllText($Ready,'READY',[Text.Encoding]::ASCII)
                    $timer=[Diagnostics.Stopwatch]::StartNew()
                    while(-not [IO.File]::Exists($Go)) {
                        if($timer.Elapsed.TotalSeconds -ge 30) {
                            return [pscustomobject]@{Code='READER_BARRIER_TIMEOUT';ProcessId=$PID;
                                Polls=0;Absent=1;Complete=0;Partial=0;IoErrors=0}
                        }
                        Start-Sleep -Milliseconds 10
                    }
                    $counts.Absent=1 # Just-verified absence before go.
                    $timer.Restart()
                    while(-not [IO.File]::Exists($Stop)) {
                        if($timer.Elapsed.TotalSeconds -gt 75) {
                            return [pscustomobject]@{Code='READER_DEADLINE';ProcessId=$PID;
                                Polls=$counts.Polls;Absent=$counts.Absent;
                                Complete=$counts.Complete;Partial=$counts.Partial;IoErrors=$counts.IoErrors}
                        }
                        $counts.Polls++
                        if(-not [IO.Directory]::Exists($Target)) {
                            $counts.Absent++
                            if(-not [string]::IsNullOrWhiteSpace($AbsenceProof) -and
                               -not [IO.File]::Exists($AbsenceProof)) {
                                [IO.File]::WriteAllText($AbsenceProof,'ABSENT',[Text.Encoding]::ASCII)
                            }
                            Start-Sleep -Milliseconds 4
                            continue
                        }
                        try {
                            $files=[IO.Directory]::GetFiles($Target,'*',[IO.SearchOption]::TopDirectoryOnly)
                            $expected=@()
                            foreach($id in @($Names)) {
                                $expected+=($id+'.json')
                                $expected+=($id+'.provenance.json')
                            }
                            $actual=@($files | ForEach-Object { [IO.Path]::GetFileName($_) })
                            $valid=$actual.Count -eq 8 -and
                                @(Compare-Object -ReferenceObject ($expected | Sort-Object) -DifferenceObject ($actual | Sort-Object)).Count -eq 0
                            if($valid) {
                                foreach($id in @($Names)) {
                                    $a=Get-Content -LiteralPath (Join-Path $Target ($id+'.json')) -Raw | ConvertFrom-Json
                                    $b=Get-Content -LiteralPath (Join-Path $Target ($id+'.provenance.json')) -Raw | ConvertFrom-Json
                                    if([string]$a.name -cne $id -or
                                       [string]$b.sample -cne $id -or
                                       [int]$b.schemaVersion -ne 2 -or
                                       [string]$a.classification -cne [string]$b.classification -or
                                       [string]$b.reviewState -cne 'PENDING_EXTERNAL_CAPTURE_AND_REVIEW') {
                                        $valid=$false
                                        break
                                    }
                                }
                            }
                            if($valid) {
                                $counts.Complete++
                            } else {
                                $counts.Partial++
                                if(-not [string]::IsNullOrWhiteSpace($FailureProof) -and
                                   -not [IO.File]::Exists($FailureProof)) {
                                    [IO.File]::WriteAllText($FailureProof,'PARTIAL',[Text.Encoding]::ASCII)
                                }
                            }
                        } catch {
                            # Do not leak the reader exception: its payload
                            # may include private paths or serialized data.
                            $counts.IoErrors++
                            if(-not [string]::IsNullOrWhiteSpace($FailureProof) -and
                               -not [IO.File]::Exists($FailureProof)) {
                                [IO.File]::WriteAllText($FailureProof,'IOERROR',[Text.Encoding]::ASCII)
                            }
                        }
                        Start-Sleep -Milliseconds 4
                    }
                    return [pscustomobject]@{Code='READER_DONE';ProcessId=$PID;
                        Polls=$counts.Polls;Absent=$counts.Absent;Complete=$counts.Complete;
                        Partial=$counts.Partial;IoErrors=$counts.IoErrors}
                } catch {
                    return [pscustomobject]@{Code='READER_UNEXPECTED';ProcessId=$PID;
                        Polls=$counts.Polls;Absent=$counts.Absent;Complete=$counts.Complete;
                        Partial=$counts.Partial;IoErrors=$counts.IoErrors}
                }
            }

function Invoke-ContentionRound([string]$OwnedRoot,[string]$Name,
                                [object[]]$Pairs,[string]$Schema,
                                [string]$PublisherPath,[switch]$WithReader) {
    # Start-Job launches separate Windows PowerShell job processes. Workers
    # import the same module and wait behind a local, private file barrier.
    # Only sanitized outcome codes and numeric PIDs are returned to the parent.
    $signal=Join-Path $OwnedRoot ($Name+'.go')
    $readerReady=Join-Path $OwnedRoot ($Name+'.reader-ready')
    $readerStop=Join-Path $OwnedRoot ($Name+'.reader-stop')
    $jobs=@()
    $readerJob=$null
    try {
        if($WithReader) {
            # Third process reads the FINAL safe name only. It never scans
            # .pending-* or opens source captures. A writer that publishes a
            # directory before its eight JSON files are valid must be caught.
            $names=[string[]]@($Pairs | ForEach-Object { [string]$_.Provenance.sample })
            # Pass a single JSON string through Start-Job: positional array
            # flattening varies by PowerShell binding/serialization behavior.
            $namesJson=ConvertTo-Json -InputObject $names -Compress
            $target=Join-Path $OwnedRoot $Name
            $readerJob=Start-Job -ScriptBlock $script:PrivateBatchReaderJob -ArgumentList @(
                $target,$readerReady,$signal,$readerStop,$namesJson,'','')
        }
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
            if($WithReader) {
                $allReady=$allReady -and (Test-Path -LiteralPath $readerReady -PathType Leaf)
            }
            if($allReady) { break }
            if(@($jobs | Where-Object { $_.State -in @('Failed','Stopped') }).Count -gt 0) { break }
            if($WithReader -and $readerJob.State -in @('Failed','Stopped')) { break }
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
        if($WithReader) {
            # Keep the observer alive after both writers finish so it must
            # see at least one complete committed view, not only absence.
            Start-Sleep -Milliseconds 100
            [IO.File]::WriteAllText($readerStop,'STOP',[Text.Encoding]::ASCII)
            $readerDone=@(Wait-Job -Job $readerJob -Timeout 15)
            Assert-Contract ($readerDone.Count -eq 1) 'reader-did-not-stop'
            $readerOutputs=@(Receive-Job -Job $readerJob -ErrorAction Stop)
            Assert-Contract ($readerOutputs.Count -eq 1 -and
                $readerOutputs[0] -is [pscustomobject]) 'reader-invalid-output-shape'
            $rv=$readerOutputs[0]
            Assert-Contract ([string]$rv.Code -ceq 'READER_DONE') 'reader-did-not-complete'
            Assert-Contract ([int]$rv.Polls -ge 1 -and [int]$rv.Absent -ge 1 -and
                [int]$rv.Complete -ge 1) 'reader-did-not-observe-both-states'
            Assert-Contract ([int]$rv.Partial -eq 0) 'reader-observed-partial-visible-batch'
            Assert-Contract ([int]$rv.IoErrors -eq 0) 'reader-view-unreadable-or-io-error'
            Assert-Contract ([int]$rv.ProcessId -notin $ids) 'observer-not-independent-process'
            Write-Host ('STAGE6G READER: '+$Name+' saw absent/complete states only; no partial view.')
        }
        $stages=@(Get-ChildItem -LiteralPath $OwnedRoot -Force |
            Where-Object { $_.Name -like '.pending-*' })
        Assert-Contract ($stages.Count -eq 0) 'losing-writer-left-pending-stage'
        Write-Host ('STAGE6F RACE '+$Name+': one private writer won; one received target-exists; no approval.')
    } finally {
        # Signal the observer before terminating workers, including after an
        # assertion failure. Stop/Remove-Job never targets arbitrary jobs.
        if($null -ne $readerJob) {
            if(-not [IO.File]::Exists($readerStop)) {
                [IO.File]::WriteAllText($readerStop,'STOP',[Text.Encoding]::ASCII)
            }
            if($readerJob.State -in @('Running','NotStarted')) {
                Stop-Job -Job $readerJob -ErrorAction SilentlyContinue
            }
            Remove-Job -Job $readerJob -Force -ErrorAction SilentlyContinue
        }
        foreach($job in $jobs) {
            if($job.State -in @('Running','NotStarted')) {
                Stop-Job -Job $job -ErrorAction SilentlyContinue
            }
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
        foreach($suffix in @('.go','.ready0','.ready1','.reader-ready','.reader-stop')) {
            $file=Join-Path $OwnedRoot ($Name+$suffix)
            if(Test-Path -LiteralPath $file -PathType Leaf) {
                Remove-Item -LiteralPath $file -Force
            }
        }
    }
}


function Wait-ForPrivateReaderMarker([string]$Path,[object]$Reader,[string]$Reason) {
    $watch=[Diagnostics.Stopwatch]::StartNew()
    while($watch.Elapsed.TotalSeconds -lt 12) {
        if(Test-Path -LiteralPath $Path -PathType Leaf) { return }
        if($Reader.State -in @('Failed','Stopped','Completed')) {
            throw ('STAGE6H_NEGATIVE_CONTRACT: '+$Reason+'-reader-exited-early')
        }
        Start-Sleep -Milliseconds 20
    }
    throw ('STAGE6H_NEGATIVE_CONTRACT: '+$Reason+'-marker-timeout')
}

function Write-PrivateNegativeFixture(
    [string]$Stage,[object[]]$Pairs,[string]$Fault
) {
    # Create only a new stage owned by the current synthetic test.
    Assert-Contract (-not (Test-Path -LiteralPath $Stage)) 'probe-stage-collision'
    [void](New-Item -Path $Stage -ItemType Directory -ErrorAction Stop)
    if($Fault -ceq 'EMPTY') { return }
    for($i=0;$i -lt $Pairs.Count;$i++) {
        $pair=$Pairs[$i]
        $name=[string]$pair.Provenance.sample
        $sample=ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $pair.Sample -Depth 24)
        $prov=ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $pair.Provenance -Depth 24)
        if($Fault -ceq 'CLASSIFICATION_MISMATCH' -and $i -eq 1) {
            $sample.classification='Malicious'
        }
        if($Fault -ceq 'FALSE_APPROVAL' -and $i -eq 2) {
            $prov.reviewState='APPROVED'
        }
        $sampleData=ConvertTo-Json -InputObject $sample -Depth 24
        if($Fault -ceq 'MALFORMED_JSON' -and $i -eq 1) {
            $sampleData='{ "name": "not-closed" '
        }
        [IO.File]::WriteAllText((Join-Path $Stage ($name+'.json')),
            $sampleData,[Text.UTF8Encoding]::new($false))
        if($Fault -ceq 'MISSING_SIDECAR' -and $i -eq 3) { continue }
        [IO.File]::WriteAllText((Join-Path $Stage ($name+'.provenance.json')),
            (ConvertTo-Json -InputObject $prov -Depth 24),[Text.UTF8Encoding]::new($false))
    }
    if($Fault -ceq 'EXTRA_FILE') {
        [IO.File]::WriteAllText((Join-Path $Stage 'unexpected.debug.txt'),
            'SYNTHETIC_ONLY',[Text.Encoding]::ASCII)
    }
}

function Invoke-ReaderNegativeCase(
    [string]$OwnedRoot,[object[]]$Pairs,[string]$Id,
    [string]$Fault,[string]$ExpectedSignal
) {
    # Inject invalid, already-staged content with one same-volume move.
    # Never invoke the real publisher or touch a non-owned destination.
    $name='negative-'+$Id
    $target=Join-Path $OwnedRoot $name
    $stage=Join-Path $OwnedRoot ('.pending-probe-'+$Id)
    $ready=Join-Path $OwnedRoot ($name+'.ready')
    $go=Join-Path $OwnedRoot ($name+'.go')
    $stop=Join-Path $OwnedRoot ($name+'.stop')
    $absenceProof=Join-Path $OwnedRoot ($name+'.absent')
    $failureProof=Join-Path $OwnedRoot ($name+'.failure')
    foreach($x in @($target,$stage,$ready,$go,$stop,$absenceProof,$failureProof)) {
        Assert-Contract (-not (Test-Path -LiteralPath $x)) 'probe-artifact-collision'
    }
    $names=[string[]]@($Pairs | ForEach-Object { [string]$_.Provenance.sample })
    $namesJson=ConvertTo-Json -InputObject $names -Compress
    $reader=$null
    try {
        $reader=Start-Job -ScriptBlock $script:PrivateBatchReaderJob -ArgumentList @(
            $target,$ready,$go,$stop,$namesJson,$absenceProof,$failureProof)
        Wait-ForPrivateReaderMarker $ready $reader 'ready'
        [IO.File]::WriteAllText($go,'GO',[Text.Encoding]::ASCII)
        # Evidence of a real absent poll after GO, not a guessed delay.
        Wait-ForPrivateReaderMarker $absenceProof $reader 'absent'
        Write-PrivateNegativeFixture $stage $Pairs $Fault
        Assert-Contract (-not (Test-Path -LiteralPath $target)) 'probe-target-not-absent'
        [IO.Directory]::Move($stage,$target)
        Wait-ForPrivateReaderMarker $failureProof $reader 'fault'
        $observed=[IO.File]::ReadAllText($failureProof,[Text.Encoding]::ASCII)
        Assert-Contract ($observed -ceq $ExpectedSignal) 'negative-wrong-fault-signal'
        [IO.File]::WriteAllText($stop,'STOP',[Text.Encoding]::ASCII)
        $finished=@(Wait-Job -Job $reader -Timeout 15)
        Assert-Contract ($finished.Count -eq 1) 'negative-reader-join-timeout'
        $messages=@(Receive-Job -Job $reader -ErrorAction Stop)
        Assert-Contract ($messages.Count -eq 1 -and
            $messages[0] -is [pscustomobject]) 'negative-reader-output-shape'
        $result=$messages[0]
        $allowed=@('Code','ProcessId','Polls','Absent','Complete','Partial','IoErrors')
        $actual=@($result.PSObject.Properties.Name)
        Assert-Contract ($actual.Count -eq $allowed.Count -and
            @(Compare-Object ($actual | Sort-Object) ($allowed | Sort-Object)).Count -eq 0) 'negative-leaked-output-fields'
        Assert-Contract ([string]$result.Code -ceq 'READER_DONE' -and
            [int]$result.ProcessId -ne $PID) 'negative-reader-wrong-process'
        Assert-Contract ([int]$result.Absent -ge 1 -and
            [int]$result.Complete -eq 0 -and
            [int]$result.Polls -ge 2) 'negative-insufficient-observation'
        if($ExpectedSignal -ceq 'PARTIAL') {
            Assert-Contract ([int]$result.Partial -ge 1 -and
                [int]$result.IoErrors -eq 0) 'negative-partial-undetected'
        } else {
            Assert-Contract ([int]$result.IoErrors -ge 1 -and
                [int]$result.Partial -eq 0) 'negative-malformed-undetected'
        }
        Write-Host ('STAGE6H '+$Id+': synthetic '+$ExpectedSignal+' detected.')
    } finally {
        # Stop only the owned reader job and clean only the known generated
        # files. Fail closed if any created path is redirected.
        if($null -ne $reader) {
            if($reader.State -in @('Running','NotStarted')) {
                Stop-Job -Job $reader -ErrorAction SilentlyContinue
            }
            Remove-Job -Job $reader -Force -ErrorAction SilentlyContinue
        }
        foreach($folder in @($stage,$target)) {
            if(Test-Path -LiteralPath $folder -PathType Container) {
                Assert-NoReparseInOwnedTree $folder
                Remove-Item -LiteralPath $folder -Recurse -Force -ErrorAction Stop
            }
        }
        foreach($marker in @($ready,$go,$stop,$absenceProof,$failureProof)) {
            if(Test-Path -LiteralPath $marker -PathType Leaf) {
                $item=Get-Item -LiteralPath $marker -Force
                Assert-Contract (-not (($item.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0)) 'probe-marker-reparse-point'
                Remove-Item -LiteralPath $marker -Force -ErrorAction Stop
            }
        }
    }
}

$repository=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$modulePath=Join-Path $PSScriptRoot 'HoldoutV2CandidatePublisher.psm1'
# A standalone observer-negative control needs no publisher module. It must
# be possible to establish sensitivity BEFORE implementing a future writer.
Assert-Contract (-not ($OnlyReaderNegativeControl -and $IncludeReaderVisibility)) 'ambiguous-test-mode'
if(-not $OnlyReaderNegativeControl) {
    Assert-Contract (Test-Path -LiteralPath $modulePath -PathType Leaf) 'race-publisher-not-implemented-red'
    Import-Module -Name $modulePath -Force -ErrorAction Stop
    Assert-Contract ($null -ne (Get-Command Publish-HoldoutV2CandidateBatch -ErrorAction SilentlyContinue)) 'race-public-wrapper-not-implemented-red'
}
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
Assert-Contract (Test-Path -LiteralPath $privateRoot -PathType Container) 'private-build-verify-root-missing'
$prefix=if($OnlyReaderNegativeControl){'stage6h-negative-'}else{'stage6f-race-'}
$owned=Join-Path $privateRoot ($prefix+[guid]::NewGuid().ToString('N'))
Assert-Contract (-not (Test-Path -LiteralPath $owned)) 'test-scratch-collision'
try {
    [void](New-Item -Path $owned -ItemType Directory -Force -ErrorAction Stop)
    $marker=Join-Path $owned 'sentinel.keep'
    [IO.File]::WriteAllText($marker,'STAGE6F_CANARY',[Text.Encoding]::ASCII)
    $markerHash=(Get-FileHash -LiteralPath $marker -Algorithm SHA256).Hash
    if($OnlyReaderNegativeControl) {
        # No publisher module or writer is required for the six sensitivity
        # controls. Every faulty final folder is synthetic and scratch-owned.
        $cases=@(
            @{Id='h01';Fault='EMPTY';Expected='PARTIAL'},
            @{Id='h02';Fault='MISSING_SIDECAR';Expected='PARTIAL'},
            @{Id='h03';Fault='MALFORMED_JSON';Expected='IOERROR'},
            @{Id='h04';Fault='FALSE_APPROVAL';Expected='PARTIAL'},
            @{Id='h05';Fault='EXTRA_FILE';Expected='PARTIAL'},
            @{Id='h06';Fault='CLASSIFICATION_MISMATCH';Expected='PARTIAL'}
        )
        foreach($case in $cases) {
            Invoke-ReaderNegativeCase $owned $pairs ([string]$case.Id) ([string]$case.Fault) ([string]$case.Expected)
        }
        Assert-Contract (@(Get-ChildItem -LiteralPath $owned -Force).Count -eq 1) 'negative-probe-left-unexpected-artifacts'
        Write-Host ('Stage 6H: '+$cases.Count+' synthetic reader sensitivity cases completed. No publisher or source approved.')
    } else {
        # Stage 6F preserves three rounds; Stage 6G opt-in uses 3..12.
        $roundCount=if($IncludeReaderVisibility){$ReaderStressRounds}else{3}
        $roundNames=@(for($number=1;$number -le $roundCount;$number++){
            'race-{0:D2}' -f $number
        })
        foreach($round in $roundNames) {
            Invoke-ContentionRound $owned $round $pairs $schema $modulePath -WithReader:$IncludeReaderVisibility
        }
        $top=@(Get-ChildItem -LiteralPath $owned -Force | Sort-Object Name)
        $expectedTop=@('sentinel.keep')+@($roundNames)
        Assert-Contract ($top.Count -eq ($roundCount+1) -and
            @($top | Where-Object { $_.Name -notin $expectedTop }).Count -eq 0) 'unexpected-test-root-entry'
        if($IncludeReaderVisibility) {
            Write-Host ('Stage 6G opt-in: '+$roundCount+' 2-writer/1-reader visibility rounds completed; no durability or source approval.')
        } else {
            Write-Host 'Stage 6F race contract: three two-process contention rounds prepared; results do not certify crash durability or source review.'
        }
    }
    Assert-Contract ((Get-FileHash -LiteralPath $marker -Algorithm SHA256).Hash -ceq
        $markerHash) 'unrelated-sentinel-modified'
} finally {
    if(Test-Path -LiteralPath $owned) {
        Assert-NoReparseInOwnedTree $owned
        Remove-Item -LiteralPath $owned -Recurse -Force -ErrorAction Stop
    }
}
